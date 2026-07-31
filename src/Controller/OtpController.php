<?php

declare(strict_types=1);

namespace Drupal\file_gate\Controller;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Mail\MailManagerInterface;
use Drupal\file\FileInterface;
use Drupal\file_gate\FileGateResolver;
use Drupal\file_gate\Plugin\GateMethod\Otp;
use Drupal\file_gate\SecretRegistryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issues a one-time passcode for an OTP-gated file.
 *
 * Server-to-server companion to the download route for the `otp` gate method:
 * a trusted back end (after capturing a self-identified email) requests a code
 * bound to (file, email); File Gate stores its hash and e-mails it. The visitor
 * then redeems the download with that email and code. Authenticated with the
 * same shared secret as mint (constant-time), rate-limited per IP and per
 * (file, email) to bound mailbombing and brute force, and failing closed when
 * no secret is configured.
 */
final class OtpController implements ContainerInjectionInterface {

  use SharedSecretAuthTrait;

  /**
   * The per-(file+email) send throttle: max sends within the window.
   */
  private const SEND_LIMIT = 3;

  /**
   * The per-(file+email) send throttle window, in seconds.
   */
  private const SEND_WINDOW = 600;

  /**
   * Constructs the OTP controller.
   *
   * @param \Drupal\Core\Entity\EntityRepositoryInterface $entityRepository
   *   The entity repository (resolves file/media UUIDs).
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\file_gate\FileGateResolver $resolver
   *   The gate resolver.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service.
   * @param \Drupal\Core\Mail\MailManagerInterface $mailManager
   *   The mail manager.
   * @param \Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface $keyValueExpirableFactory
   *   The expirable key/value factory (stores outstanding codes).
   * @param \Drupal\Core\Language\LanguageManagerInterface $languageManager
   *   The language manager (message language).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The File Gate logger channel.
   * @param \Drupal\file_gate\SecretRegistryInterface $secrets
   *   Secret registry (auth).
   */
  public function __construct(
    private readonly EntityRepositoryInterface $entityRepository,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly FileGateResolver $resolver,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly FloodInterface $flood,
    private readonly MailManagerInterface $mailManager,
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly LanguageManagerInterface $languageManager,
    private readonly TimeInterface $time,
    private readonly LoggerInterface $logger,
    private readonly SecretRegistryInterface $secrets,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity.repository'),
      $container->get('entity_type.manager'),
      $container->get('file_gate.resolver'),
      $container->get('config.factory'),
      $container->get('flood'),
      $container->get('plugin.manager.mail'),
      $container->get('keyvalue.expirable'),
      $container->get('language_manager'),
      $container->get('datetime.time'),
      $container->get('logger.channel.file_gate'),
      $container->get('file_gate.secret_registry'),
    );
  }

  /**
   * Issues (stores + e-mails) a one-time passcode for the requested file.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request. Basic-auth password (or X-File-Gate-Secret header) carries
   *   the shared secret; the JSON body is {"file"|"media": "<uuid>", "email":
   *   "<address>"}.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   204 when a code was sent; 400/401/404/409/422/429/503 otherwise.
   */
  public function request(Request $request): Response {
    $config = $this->configFactory->get('file_gate.settings');
    $denied = $this->authenticateSharedSecret(
      $request,
      $this->secrets,
      $this->flood,
      $this->logger,
      'file_gate.otp',
      (int) ($config->get('flood_limit') ?: 50),
      (int) ($config->get('flood_window') ?: 60),
    );
    if ($denied !== NULL) {
      return $denied;
    }

    $data = json_decode($request->getContent(), TRUE);
    if (!is_array($data)) {
      return new JsonResponse(['error' => 'Invalid JSON body.'], Response::HTTP_BAD_REQUEST);
    }
    $email = Otp::normalizeEmail((string) ($data['email'] ?? ''));
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
      return new JsonResponse(['error' => 'Provide a valid "email".'], Response::HTTP_BAD_REQUEST);
    }

    $file = $this->resolveFile($data);
    if ($file instanceof JsonResponse) {
      return $file;
    }

    // The file must be gated with the OTP method.
    $gate = $this->resolver->getGateForFile($file);
    if ($gate === NULL || $gate['method'] !== 'otp') {
      return new JsonResponse(['error' => 'The requested file is not OTP-gated.'], Response::HTTP_UNPROCESSABLE_ENTITY);
    }
    $secret_id = $request->attributes->get(SecretRegistryInterface::REQUEST_ATTR_SECRET_ID);
    $secret_id = is_string($secret_id) && $secret_id !== '' ? $secret_id : NULL;
    if (!$this->secrets->allowsField($secret_id, $gate['field'])) {
      return new JsonResponse([
        'error' => 'This credential is not allowed to mint that file.',
      ], Response::HTTP_FORBIDDEN);
    }

    // Throttle per (file, email) to bound mailbombing and brute force.
    $throttle_id = Otp::storeKey($file->uuid(), $email);
    if (!$this->flood->isAllowed('file_gate.otp_send', self::SEND_LIMIT, self::SEND_WINDOW, $throttle_id)) {
      return new JsonResponse(['error' => 'Too many requests.'], Response::HTTP_TOO_MANY_REQUESTS);
    }
    $this->flood->register('file_gate.otp_send', self::SEND_WINDOW, $throttle_id);

    // A failed delivery sent nothing, so it must not spend the caller's send
    // budget. Clear the slot we just registered for this (file, email) — safe
    // because no code went out, so this cannot aid mailbombing or brute force.
    if (!$this->issueAndSend($file, $email, (array) $gate['settings'])) {
      $this->flood->clear('file_gate.otp_send', $throttle_id);
    }

    return new Response('', Response::HTTP_NO_CONTENT);
  }

  /**
   * Generates a code, stores its hash, and e-mails it.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   * @param string $email
   *   The normalized recipient email.
   * @param array $settings
   *   The field's OTP method settings.
   *
   * @return bool
   *   TRUE when the code was stored and the email was accepted for delivery;
   *   FALSE when delivery failed (and the stored code was rolled back).
   */
  private function issueAndSend(FileInterface $file, string $email, array $settings): bool {
    $ttl = max(30, (int) ($settings['ttl'] ?? Otp::DEFAULT_TTL));
    $max = max(1, (int) ($settings['max_attempts'] ?? Otp::DEFAULT_MAX_ATTEMPTS));
    $length = min(10, max(4, (int) ($settings['code_length'] ?? Otp::DEFAULT_CODE_LENGTH)));

    // A CSPRNG numeric code, built digit-by-digit to avoid a large power that
    // could overflow the integer range (e.g. 10 ** 10 on 32-bit PHP).
    $code = '';
    for ($i = 0; $i < $length; $i++) {
      $code .= random_int(0, 9);
    }
    $secret = (string) $this->configFactory->get('file_gate.settings')->get('download_secret');

    $this->keyValueExpirableFactory->get(Otp::STORE_COLLECTION)->setWithExpire(
      Otp::storeKey($file->uuid(), $email),
      [
        'hash' => Otp::codeHash($code, $secret),
        'attempts' => 0,
        'max' => $max,
        'exp' => $this->time->getRequestTime() + $ttl,
      ],
      $ttl,
    );

    $result = $this->mailManager->mail('file_gate', 'otp', $email, $this->languageManager->getDefaultLanguage()->getId(), [
      'code' => $code,
      'filename' => $file->getFilename() ?? 'your download',
      'ttl_minutes' => (int) ceil($ttl / 60),
    ]);

    if (empty($result['result'])) {
      // Avoid leaving an outstanding code when the email could not be sent.
      $this->keyValueExpirableFactory->get(Otp::STORE_COLLECTION)->delete(Otp::storeKey($file->uuid(), $email));
      $this->logger->error('Failed to send an OTP email for file @uuid.', ['@uuid' => $file->uuid()]);
      return FALSE;
    }

    // Usage event: a code was issued (never log the code itself).
    $this->logger->info('Issued an OTP for file @uuid.', ['@uuid' => $file->uuid()]);
    return TRUE;
  }

  /**
   * Resolves the request payload to a managed file.
   *
   * @param array $data
   *   The decoded JSON body: {"file": "<uuid>"} or {"media": "<uuid>"}.
   *
   * @return \Drupal\file\FileInterface|\Symfony\Component\HttpFoundation\JsonResponse
   *   The resolved file, or a JsonResponse error (404/409/422/400).
   */
  private function resolveFile(array $data): FileInterface|JsonResponse {
    if (!empty($data['file']) && is_string($data['file'])) {
      $file = $this->entityRepository->loadEntityByUuid('file', $data['file']);
      return $file instanceof FileInterface
        ? $file
        : new JsonResponse(['error' => 'File not found.'], Response::HTTP_NOT_FOUND);
    }

    if (!empty($data['media']) && is_string($data['media']) && $this->entityTypeManager->hasDefinition('media')) {
      $media = $this->entityRepository->loadEntityByUuid('media', $data['media']);
      if ($media === NULL || !method_exists($media, 'getSource')) {
        return new JsonResponse(['error' => 'Media not found.'], Response::HTTP_NOT_FOUND);
      }
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

}
