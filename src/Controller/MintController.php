<?php

declare(strict_types=1);

namespace Drupal\file_gate\Controller;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Url;
use Drupal\file\FileInterface;
use Drupal\file\FileReferenceResolver;
use Drupal\file_gate\ActiveSecret;
use Drupal\file_gate\ContextualMintInterface;
use Drupal\file_gate\Exception\GrantWindowClosedException;
use Drupal\file_gate\FileGateResolver;
use Drupal\file_gate\GateMethodManager;
use Drupal\file_gate\SecretRegistryInterface;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Mints short-lived signed download URLs for gated files.
 *
 * Called server-to-server by a trusted back end (typically a decoupled front
 * end, after it has run its own gate — a lead form, a login, …). The endpoint:
 * - refuses (503) when no secret is configured (fail closed);
 * - authenticates the caller with the shared secret (constant-time);
 * - resolves the requested file (by file UUID, or by media UUID when the Media
 *   module is installed; the media path additionally requires the host media
 *   entity to be published — the direct file path trusts the secret-holding
 *   caller, consistent with the mint trust model below);
 * - returns a relative, host-agnostic signed path the front end prepends its
 *   own public origin to.
 * - optionally, when the body includes an acting account (uuid or uid), fails
 *   closed unless that account may download the file (and view referencing
 *   entities when present) — defense in depth for authenticated mint paths.
 *
 * The gate the front end runs (email capture, form, login) is NOT re-verified
 * here — trust is delegated to the secret-holding caller. Keep the endpoint on
 * a trusted network and keep the secret secret. The secret doubles as the mint
 * credential and the HMAC signing key; it never reaches the browser (only the
 * derived signature does).
 */
final class MintController implements ContainerInjectionInterface {

  use SharedSecretAuthTrait;

  /**
   * Constructs the mint controller.
   *
   * @param \Drupal\Core\Entity\EntityRepositoryInterface $entityRepository
   *   The entity repository (resolves file/media UUIDs).
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\file_gate\FileGateResolver $resolver
   *   The gate resolver.
   * @param \Drupal\file_gate\GateMethodManager $gateMethodManager
   *   The gate method plugin manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service (mint rate limiting).
   * @param \Psr\Log\LoggerInterface $logger
   *   The File Gate logger channel.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service (to report the grant's real remaining TTL).
   * @param \Drupal\file_gate\SecretRegistryInterface $secrets
   *   Secret registry (auth + field scope).
   * @param \Drupal\file_gate\ActiveSecret $activeSecret
   *   Request-cycle authenticated secret id for mint signing.
   * @param \Drupal\file\FileReferenceResolver $fileReferenceResolver
   *   Core file→host resolver (identity-aware mint host checks).
   */
  public function __construct(
    private readonly EntityRepositoryInterface $entityRepository,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly FileGateResolver $resolver,
    private readonly GateMethodManager $gateMethodManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly FloodInterface $flood,
    private readonly LoggerInterface $logger,
    private readonly TimeInterface $time,
    private readonly SecretRegistryInterface $secrets,
    private readonly ActiveSecret $activeSecret,
    private readonly FileReferenceResolver $fileReferenceResolver,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity.repository'),
      $container->get('entity_type.manager'),
      $container->get('file_gate.resolver'),
      $container->get('plugin.manager.file_gate.gate_method'),
      $container->get('config.factory'),
      $container->get('flood'),
      $container->get('logger.channel.file_gate'),
      $container->get('datetime.time'),
      $container->get('file_gate.secret_registry'),
      $container->get('file_gate.active_secret'),
      $container->get(FileReferenceResolver::class),
    );
  }

  /**
   * Mints a signed URL for the requested file.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request. Basic-auth password (or X-File-Gate-Secret header) carries
   *   the shared secret; the JSON body is {"file": "<uuid>"} or
   *   {"media": "<uuid>"}.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   {path, expires, ttl} on success, or an error with the appropriate status.
   */
  public function mint(Request $request): JsonResponse {
    // Authenticate the server-to-server caller: fails closed with no secret
    // (503), rejects a bad/absent secret (401), and rate-limits per IP (429).
    // Sets file_gate.secret_id on the request (NULL = legacy whole-corpus).
    $config = $this->configFactory->get('file_gate.settings');
    $this->activeSecret->clear();
    $denied = $this->authenticateSharedSecret(
      $request,
      $this->secrets,
      $this->flood,
      $this->logger,
      'file_gate.mint',
      (int) ($config->get('flood_limit') ?: 50),
      (int) ($config->get('flood_window') ?: 60),
      $this->activeSecret,
    );
    if ($denied !== NULL) {
      return $denied;
    }

    $data = json_decode($request->getContent(), TRUE);
    if (!is_array($data)) {
      return new JsonResponse(['error' => 'Invalid JSON body.'], Response::HTTP_BAD_REQUEST);
    }

    // Resolve the target file. Returns a JsonResponse (error) or the file.
    $file = $this->resolveFile($data);
    if ($file instanceof JsonResponse) {
      return $file;
    }

    $gate = $this->resolver->getGateForFile($file);
    if ($gate === NULL) {
      return new JsonResponse(['error' => 'The requested file is not gated.'], Response::HTTP_UNPROCESSABLE_ENTITY);
    }

    // Field scope: named secrets may only mint fields in their allowlist.
    $secret_id = $request->attributes->get(SecretRegistryInterface::REQUEST_ATTR_SECRET_ID);
    $secret_id = is_string($secret_id) && $secret_id !== '' ? $secret_id : NULL;
    if (!$this->secrets->allowsField($secret_id, $gate['field'])) {
      $this->logger->warning('Mint refused: secret @id is not allowed to mint field @field (file @uuid) from @ip.', [
        '@id' => $secret_id ?? 'legacy',
        '@field' => $gate['field'],
        '@uuid' => $file->uuid(),
        '@ip' => $request->getClientIp() ?? 'unknown',
      ]);
      return new JsonResponse([
        'error' => 'This credential is not allowed to mint that file.',
      ], Response::HTTP_FORBIDDEN);
    }

    // Optional identity-aware mint (#31): when the caller names an acting
    // account, the mint must not exceed what that account could download.
    $identity_denied = $this->assertActingAccountAccess($file, $data);
    if ($identity_denied !== NULL) {
      return $identity_denied;
    }

    $method = $this->gateMethodManager->createInstance($gate['method'], $gate['settings']);
    // A method that binds request-scoped claims (e.g. a caller-asserted
    // subject) receives the request; all others use the plain mint() contract.
    try {
      $params = $method instanceof ContextualMintInterface
        ? $method->mintWithContext($file, $request)
        : $method->mint($file);
    }
    catch (GrantWindowClosedException $e) {
      // The field's availability window has already closed; there is no live
      // grant to issue.
      return new JsonResponse(['error' => $e->getMessage()], Response::HTTP_GONE);
    }
    if ($params === NULL) {
      return new JsonResponse([
        'error' => sprintf('Gate method "%s" does not support minted URLs.', $gate['method']),
      ], Response::HTTP_BAD_REQUEST);
    }

    // Build a root-relative, host-agnostic path. The front end prepends its own
    // public origin (the internal mint host must never leak into this URL).
    $query = ['f' => $file->uuid()] + $params;
    $path = Url::fromRoute('file_gate.download', [], ['query' => $query, 'absolute' => FALSE])->toString();

    // Usage/stats event: a grant was minted (the gate on the caller's side
    // passed). Redemption is logged separately by the download controller.
    $this->logger->info('Minted @method grant for file @uuid to @ip.', [
      '@method' => $gate['method'],
      '@uuid' => $file->uuid(),
      '@ip' => $request->getClientIp() ?? 'unknown',
    ]);

    // Report the grant's real expiry and remaining lifetime. Both derive from
    // the minted claim, so a field-specific TTL (or an availability-window cap)
    // is reflected accurately rather than the global default.
    $expires = isset($params['exp']) ? (int) $params['exp'] : NULL;
    return new JsonResponse([
      'path' => $path,
      'expires' => $expires,
      'ttl' => $expires !== NULL ? max(0, $expires - $this->time->getRequestTime()) : NULL,
    ]);
  }

  /**
   * Resolves the request payload to a managed file.
   *
   * @param array $data
   *   The decoded JSON body: {"file": "<uuid>"} or {"media": "<uuid>"}.
   *
   * @return \Drupal\file\FileInterface|\Symfony\Component\HttpFoundation\JsonResponse
   *   The resolved file, or a JsonResponse describing why it could not be
   *   resolved (404 unknown, 409 unpublished host, 422 no file, 400 bad input).
   */
  private function resolveFile(array $data): FileInterface|JsonResponse {
    // By file UUID (media-agnostic path).
    if (!empty($data['file']) && is_string($data['file'])) {
      $file = $this->entityRepository->loadEntityByUuid('file', $data['file']);
      return $file instanceof FileInterface
        ? $file
        : new JsonResponse(['error' => 'File not found.'], Response::HTTP_NOT_FOUND);
    }

    // By media UUID — only when the Media module is installed. Duck-typed so
    // the module never hard-depends on Media.
    if (!empty($data['media']) && is_string($data['media']) && $this->entityTypeManager->hasDefinition('media')) {
      $media = $this->entityRepository->loadEntityByUuid('media', $data['media']);
      if ($media === NULL || !method_exists($media, 'getSource')) {
        return new JsonResponse(['error' => 'Media not found.'], Response::HTTP_NOT_FOUND);
      }
      // Never mint for unpublished host content — the URL would be handed to
      // the public for something that is not yet public.
      if (method_exists($media, 'isPublished') && !$media->isPublished()) {
        return new JsonResponse(['error' => 'Media is not published.'], Response::HTTP_CONFLICT);
      }
      $fid = $media->getSource()->getSourceFieldValue($media);
      $file = $fid ? $this->entityTypeManager->getStorage('file')->load($fid) : NULL;
      return $file instanceof FileInterface
        ? $file
        : new JsonResponse(['error' => 'Media has no file.'], Response::HTTP_UNPROCESSABLE_ENTITY);
    }

    return new JsonResponse(['error' => 'Provide a "file" or "media" UUID.'], Response::HTTP_BAD_REQUEST);
  }

  /**
   * Optional acting-account access check for identity-aware mint.
   *
   * When the payload includes account (uuid) or uid, resolve the user and
   * require file download access (and view access on referencing entities).
   * Unresolvable accounts fail closed. Omitted parameters skip this check.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file being minted.
   * @param array $data
   *   Decoded mint JSON body.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse|null
   *   403 when the check fails; NULL when not requested or when allowed.
   */
  private function assertActingAccountAccess(FileInterface $file, array $data): ?JsonResponse {
    $has_uuid = !empty($data['account']) && is_string($data['account']);
    $has_uid = array_key_exists('uid', $data) && $data['uid'] !== NULL && $data['uid'] !== '';
    if (!$has_uuid && !$has_uid) {
      return NULL;
    }

    $account = $this->resolveActingAccount($data);
    if (!$account instanceof AccountInterface) {
      $this->logger->warning('Mint refused: acting account could not be resolved for file @uuid.', [
        '@uuid' => $file->uuid(),
      ]);
      return new JsonResponse([
        'error' => 'Acting account could not be resolved.',
      ], Response::HTTP_FORBIDDEN);
    }

    if (!$file->access('download', $account)) {
      $this->logger->warning('Mint refused: acting account @uid cannot download file @uuid.', [
        '@uid' => (string) $account->id(),
        '@uuid' => $file->uuid(),
      ]);
      return new JsonResponse([
        'error' => 'Acting account is not allowed to download that file.',
      ], Response::HTTP_FORBIDDEN);
    }

    // Require view access on every host entity core knows about (same graph as
    // FileAccessControlHandler). Any forbidden host fails the mint closed.
    $saw_host = FALSE;
    foreach ($this->fileReferenceResolver->getReferences($file) as $usage) {
      $entity = $this->fileReferenceResolver->loadEntityFromUsage($usage);
      if ($entity === NULL) {
        continue;
      }
      $saw_host = TRUE;
      if (!$entity->access('view', $account)) {
        $this->logger->warning('Mint refused: acting account @uid cannot view @type @id hosting file @uuid.', [
          '@uid' => (string) $account->id(),
          '@type' => $entity->getEntityTypeId(),
          '@id' => (string) $entity->id(),
          '@uuid' => $file->uuid(),
        ]);
        return new JsonResponse([
          'error' => 'Acting account is not allowed to access the host content for that file.',
        ], Response::HTTP_FORBIDDEN);
      }
    }
    // Detached files: download already passed (owner path). No host to recheck.
    if (!$saw_host) {
      return NULL;
    }

    return NULL;
  }

  /**
   * Resolves an acting account from mint payload account (uuid) or uid.
   *
   * Prefer uuid (account). uid is accepted for back ends that already hold one.
   *
   * @param array $data
   *   Decoded mint JSON body.
   *
   * @return \Drupal\Core\Session\AccountInterface|null
   *   The user account, or NULL if unresolvable.
   */
  private function resolveActingAccount(array $data): ?AccountInterface {
    if (!empty($data['account']) && is_string($data['account'])) {
      $user = $this->entityRepository->loadEntityByUuid('user', $data['account']);
      return $user instanceof UserInterface ? $user : NULL;
    }
    if (array_key_exists('uid', $data) && $data['uid'] !== NULL && $data['uid'] !== '') {
      if (!is_numeric($data['uid'])) {
        return NULL;
      }
      $user = $this->entityTypeManager->getStorage('user')->load((int) $data['uid']);
      return $user instanceof UserInterface ? $user : NULL;
    }
    return NULL;
  }

}
