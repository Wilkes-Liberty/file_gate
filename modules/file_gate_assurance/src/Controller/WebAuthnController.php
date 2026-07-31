<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\Controller;

use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Site\Settings;
use Drupal\Core\Url;
use Drupal\file\FileInterface;
use Drupal\file_gate\FileGateResolver;
use Drupal\file_gate\GateMethodManager;
use Drupal\file_gate_assurance\Plugin\GateMethod\Assurance;
use Drupal\file_gate_assurance\SessionBridge;
use Drupal\file_gate_assurance\WebAuthn\WebAuthnCeremony;
use Drupal\file_gate_assurance\WebAuthn\WebAuthnCredentialStorage;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Native WebAuthn registration and grant-bound assertion endpoints.
 */
final class WebAuthnController implements ContainerInjectionInterface {

  /**
   * Constructs the controller.
   */
  public function __construct(
    private readonly EntityRepositoryInterface $entityRepository,
    private readonly FileGateResolver $resolver,
    private readonly GateMethodManager $gateMethodManager,
    private readonly WebAuthnCeremony $ceremony,
    private readonly WebAuthnCredentialStorage $storage,
    private readonly SessionBridge $bridge,
    private readonly AccountProxyInterface $currentUser,
    private readonly Settings $settings,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity.repository'),
      $container->get('file_gate.resolver'),
      $container->get('plugin.manager.file_gate.gate_method'),
      $container->get('file_gate_assurance.webauthn_ceremony'),
      $container->get('file_gate_assurance.webauthn_storage'),
      $container->get('file_gate_assurance.session_bridge'),
      $container->get('current_user'),
      $container->get('settings'),
      $container->get('logger.channel.file_gate'),
    );
  }

  /**
   * Registration options for the current user.
   */
  public function registerOptions(Request $request): JsonResponse {
    if ($this->currentUser->isAnonymous()) {
      return new JsonResponse(['error' => 'Authentication required.'], Response::HTTP_FORBIDDEN);
    }
    if (!$this->currentUser->hasPermission('register file gate webauthn')
      && !$this->currentUser->hasPermission('administer file gate')) {
      return new JsonResponse(['error' => 'Permission denied.'], Response::HTTP_FORBIDDEN);
    }
    $config = $this->rpConfigFromRequest($request);
    if ($config === NULL) {
      return new JsonResponse(['error' => 'WebAuthn RP is not configured (rp_id + origins).'], Response::HTTP_BAD_REQUEST);
    }
    $handle = (string) $this->currentUser->id();
    $name = $this->currentUser->getAccountName() ?: $handle;
    $result = $this->ceremony->registrationOptions($handle, $name, $config);
    if ($result === NULL) {
      return new JsonResponse(['error' => 'Could not create registration options.'], Response::HTTP_SERVICE_UNAVAILABLE);
    }
    return new JsonResponse($result);
  }

  /**
   * Completes registration for the current user.
   */
  public function registerComplete(Request $request): JsonResponse {
    if ($this->currentUser->isAnonymous()) {
      return new JsonResponse(['error' => 'Authentication required.'], Response::HTTP_FORBIDDEN);
    }
    if (!$this->currentUser->hasPermission('register file gate webauthn')
      && !$this->currentUser->hasPermission('administer file gate')) {
      return new JsonResponse(['error' => 'Permission denied.'], Response::HTTP_FORBIDDEN);
    }
    $body = json_decode($request->getContent(), TRUE);
    if (!is_array($body) || empty($body['challenge_id']) || empty($body['credential'])) {
      return new JsonResponse(['error' => 'challenge_id and credential required.'], Response::HTTP_BAD_REQUEST);
    }
    $config = $this->rpConfigFromRequest($request);
    if ($config === NULL) {
      return new JsonResponse(['error' => 'WebAuthn RP is not configured.'], Response::HTTP_BAD_REQUEST);
    }
    $credential_json = is_string($body['credential'])
      ? $body['credential']
      : json_encode($body['credential'], JSON_THROW_ON_ERROR);
    $ok = $this->ceremony->completeRegistration(
      (string) $body['challenge_id'],
      $credential_json,
      $config,
      (int) $this->currentUser->id(),
      (string) ($body['label'] ?? ''),
    );
    if (!$ok) {
      return new JsonResponse(['error' => 'Registration failed.'], Response::HTTP_FORBIDDEN);
    }
    $this->logger->info('WebAuthn credential registered for uid @uid.', [
      '@uid' => (string) $this->currentUser->id(),
    ]);
    return new JsonResponse(['ok' => TRUE]);
  }

  /**
   * Assertion options bound to a signed grant (download query).
   */
  public function assertOptions(Request $request): JsonResponse {
    $file = $this->loadAssuranceFile($request);
    if ($file instanceof JsonResponse) {
      return $file;
    }
    [$method, $settings] = $this->assuranceMethod($file);
    if ($method === NULL) {
      return new JsonResponse(['error' => 'Not assurance-gated.'], Response::HTTP_UNPROCESSABLE_ENTITY);
    }
    if (!$method->signatureValid($file, $request)) {
      return new JsonResponse(['error' => 'Invalid grant.'], Response::HTTP_FORBIDDEN);
    }
    $config = $this->rpConfigFromSettings($settings);
    if ($config === NULL) {
      return new JsonResponse(['error' => 'WebAuthn RP is not configured on the field.'], Response::HTTP_BAD_REQUEST);
    }
    $handle = $this->userHandleFromGrant($request, $settings);
    if ($handle === NULL) {
      return new JsonResponse([
        'error' => 'No user handle: mint with subject, or bind credentials to a Drupal uid.',
      ], Response::HTTP_BAD_REQUEST);
    }
    $fp = $this->grantFingerprint($request);
    $result = $this->ceremony->assertionOptions($handle, $config, $fp);
    if ($result === NULL) {
      return new JsonResponse([
        'error' => 'No WebAuthn credentials registered for this handle.',
      ], Response::HTTP_NOT_FOUND);
    }
    return new JsonResponse($result);
  }

  /**
   * Completes assertion and sets the session bridge cookie.
   */
  public function assertComplete(Request $request): JsonResponse {
    $file = $this->loadAssuranceFile($request);
    if ($file instanceof JsonResponse) {
      return $file;
    }
    [$method, $settings] = $this->assuranceMethod($file);
    if ($method === NULL || !$method->signatureValid($file, $request)) {
      return new JsonResponse(['error' => 'Invalid grant.'], Response::HTTP_FORBIDDEN);
    }
    $config = $this->rpConfigFromSettings($settings);
    if ($config === NULL) {
      return new JsonResponse(['error' => 'WebAuthn RP is not configured.'], Response::HTTP_BAD_REQUEST);
    }
    $body = json_decode($request->getContent(), TRUE);
    if (!is_array($body) || empty($body['challenge_id']) || empty($body['credential'])) {
      return new JsonResponse(['error' => 'challenge_id and credential required.'], Response::HTTP_BAD_REQUEST);
    }
    $credential_json = is_string($body['credential'])
      ? $body['credential']
      : json_encode($body['credential'], JSON_THROW_ON_ERROR);
    $fp = $this->grantFingerprint($request);
    $ok = $this->ceremony->completeAssertion(
      (string) $body['challenge_id'],
      $credential_json,
      $config,
      $fp,
    );
    if (!$ok) {
      $this->logger->warning('WebAuthn assertion failed for file @uuid from @ip.', [
        '@uuid' => $file->uuid(),
        '@ip' => $request->getClientIp() ?? 'unknown',
      ]);
      return new JsonResponse(['error' => 'Assertion failed.'], Response::HTTP_FORBIDDEN);
    }
    $ttl = (int) ($settings['bridge_ttl'] ?? SessionBridge::DEFAULT_TTL);
    $cookie = $this->bridge->mintCookie($request, $file->uuid(), $ttl, $request->isSecure());
    if ($cookie === NULL) {
      return new JsonResponse(['error' => 'Could not mint bridge cookie.'], Response::HTTP_SERVICE_UNAVAILABLE);
    }
    $path = Url::fromRoute('file_gate.download', [], [
      'query' => $request->query->all(),
      'absolute' => FALSE,
    ])->toString();
    $this->logger->info('WebAuthn assertion OK for file @uuid from @ip.', [
      '@uuid' => $file->uuid(),
      '@ip' => $request->getClientIp() ?? 'unknown',
    ]);
    $response = new JsonResponse(['ok' => TRUE, 'path' => $path]);
    $this->bridge->attach($response, $cookie);
    $response->headers->set('Cache-Control', 'private, no-store');
    return $response;
  }

  /**
   * Lists the current user's credentials (label + id prefix).
   */
  public function listCredentials(): JsonResponse {
    if ($this->currentUser->isAnonymous()) {
      return new JsonResponse(['error' => 'Authentication required.'], Response::HTTP_FORBIDDEN);
    }
    $rows = $this->storage->loadByUserHandle((string) $this->currentUser->id());
    $out = [];
    foreach ($rows as $row) {
      $out[] = [
        'credential_id' => $row['credential_id'],
        'label' => $row['label'],
        'created' => (int) $row['created'],
      ];
    }
    return new JsonResponse(['credentials' => $out]);
  }

  /**
   * Deletes one of the current user's credentials.
   */
  public function deleteCredential(Request $request): JsonResponse {
    if ($this->currentUser->isAnonymous()) {
      return new JsonResponse(['error' => 'Authentication required.'], Response::HTTP_FORBIDDEN);
    }
    $body = json_decode($request->getContent(), TRUE);
    $id = is_array($body) ? (string) ($body['credential_id'] ?? '') : '';
    if ($id === '') {
      return new JsonResponse(['error' => 'credential_id required.'], Response::HTTP_BAD_REQUEST);
    }
    $row = $this->storage->loadByCredentialId($id);
    if ($row === NULL || (string) $row['user_handle'] !== (string) $this->currentUser->id()) {
      return new JsonResponse(['error' => 'Not found.'], Response::HTTP_NOT_FOUND);
    }
    $this->storage->delete($id);
    return new JsonResponse(['ok' => TRUE]);
  }

  /**
   * Loads the file and ensures it is gated.
   *
   * @return \Drupal\file\FileInterface|\Symfony\Component\HttpFoundation\JsonResponse
   *   File or error response.
   */
  private function loadAssuranceFile(Request $request): FileInterface|JsonResponse {
    $uuid = (string) $request->query->get('f', '');
    if ($uuid === '') {
      return new JsonResponse(['error' => 'Missing file parameter.'], Response::HTTP_BAD_REQUEST);
    }
    $file = $this->entityRepository->loadEntityByUuid('file', $uuid);
    if (!$file instanceof FileInterface) {
      return new JsonResponse(['error' => 'Unknown file.'], Response::HTTP_NOT_FOUND);
    }
    return $file;
  }

  /**
   * Loads the assurance gate method for a file.
   *
   * @return array{0: ?\Drupal\file_gate_assurance\Plugin\GateMethod\Assurance, 1: array}
   *   Method instance and settings.
   */
  private function assuranceMethod(FileInterface $file): array {
    $gate = $this->resolver->getGateForFile($file);
    if ($gate === NULL || $gate['method'] !== 'assurance') {
      return [NULL, []];
    }
    $method = $this->gateMethodManager->createInstance($gate['method'], $gate['settings']);
    if (!$method instanceof Assurance) {
      return [NULL, []];
    }
    return [$method, $gate['settings']];
  }

  /**
   * RP config from JSON body (registration) or empty.
   *
   * @return array<string, mixed>|null
   *   Config or NULL.
   */
  private function rpConfigFromRequest(Request $request): ?array {
    $body = json_decode($request->getContent(), TRUE);
    $cfg = is_array($body) && isset($body['rp']) && is_array($body['rp']) ? $body['rp'] : [];
    // Prefer site settings override for admin registration UI.
    $from_settings = $this->settings->get('file_gate.webauthn');
    if (is_array($from_settings)) {
      $cfg = $from_settings + $cfg;
    }
    return $this->ceremony->configReady($cfg) ? $cfg : NULL;
  }

  /**
   * RP config from field method settings.
   *
   * @return array<string, mixed>|null
   *   Config or NULL.
   */
  private function rpConfigFromSettings(array $settings): ?array {
    $cfg = [
      'rp_id' => $settings['rp_id'] ?? '',
      'rp_name' => $settings['rp_name'] ?? 'File Gate',
      'origins' => $settings['origins'] ?? [],
      'timeout' => $settings['timeout'] ?? 60000,
    ];
    $from_settings = $this->settings->get('file_gate.webauthn');
    if (is_array($from_settings)) {
      $cfg = array_filter($from_settings, static fn ($v) => $v !== NULL && $v !== '') + $cfg;
    }
    return $this->ceremony->configReady($cfg) ? $cfg : NULL;
  }

  /**
   * Resolves the WebAuthn user handle for this grant.
   *
   * When the grant carries sh= (subject hash from mint), the handle must hash
   * to that value so an unsigned wh= cannot open another user's credentials.
   */
  private function userHandleFromGrant(Request $request, array $settings): ?string {
    $candidates = [];
    $fixed = trim((string) ($settings['webauthn_user_handle'] ?? ''));
    if ($fixed !== '') {
      $candidates[] = $fixed;
    }
    $subject = trim((string) ($settings['webauthn_subject'] ?? ''));
    if ($subject !== '') {
      $candidates[] = $subject;
    }
    $wh = trim((string) $request->query->get('wh', ''));
    if ($wh !== '' && strlen($wh) <= 64) {
      $candidates[] = $wh;
    }
    $sh = (string) $request->query->get('sh', '');
    foreach ($candidates as $handle) {
      // When the grant binds a subject hash, the handle must match it.
      if ($sh !== '' && !hash_equals($sh, hash('sha256', $handle))) {
        continue;
      }
      return $handle;
    }
    return NULL;
  }

  /**
   * Stable fingerprint of the grant query for challenge binding.
   */
  private function grantFingerprint(Request $request): string {
    $parts = [];
    foreach (['f', 'exp', 'sig', 'jti', 'aal', 'sh', 'k', 'max', 'nbf'] as $key) {
      if ($request->query->has($key)) {
        $parts[] = $key . '=' . $request->query->get($key);
      }
    }
    return hash('sha256', implode('&', $parts));
  }

}
