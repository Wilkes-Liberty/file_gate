<?php

declare(strict_types=1);

namespace Drupal\file_gate\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\file_gate\GrantLockTrait;
use Drupal\file_gate\SecretRegistryInterface;
use Drupal\file_gate\Service\FileGateAudit;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Revokes a minted token grant.
 *
 * Server-to-server companion to the mint endpoint: a trusted back end that
 * minted a "token"-method grant can invalidate it before its natural expiry by
 * deleting the token's stored hash — without rotating the site secret (which
 * would break every other live link). Authenticated with the same shared secret
 * as mint (constant-time), and fails closed when no secret is configured.
 *
 * The delete runs under a lock keyed on the token hash, the same lock a
 * redemption takes: this prevents a redemption that read the row just before
 * the delete from writing an incremented row back after it (which would
 * resurrect a revoked token). See GrantLockTrait.
 *
 * Only minted tokens live in the store; pre-shared campaign tokens are revoked
 * by removing their hash from the field's "tokens" configuration, not here.
 *
 * Signed-URL grants may be revoked by jti (marks the jti as fully spent in the
 * redemption counter). Token-method grants are deleted from the token store
 * when the revoking secret is allowed for the token's field (when known).
 */
final class RevokeController implements ContainerInjectionInterface {

  use SharedSecretAuthTrait;
  use GrantLockTrait;

  /**
   * The token store collection name (keyed by the SHA-256 hash of the token).
   */
  private const TOKEN_COLLECTION = 'file_gate_tokens';

  /**
   * Signed-URL usage counter collection (same as SignedUrl).
   */
  private const REDEMPTION_COLLECTION = 'file_gate_redemptions';

  /**
   * Constructs the revoke controller.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service (revoke rate limiting).
   * @param \Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface $keyValueExpirableFactory
   *   The expirable key/value factory (holds minted token hashes).
   * @param \Psr\Log\LoggerInterface $logger
   *   The File Gate logger channel.
   * @param \Drupal\Core\Lock\LockBackendInterface $lock
   *   The lock backend (serializes revocation against redemption).
   * @param \Drupal\file_gate\SecretRegistryInterface $secrets
   *   Secret registry.
   * @param \Drupal\file_gate\Service\FileGateAudit $audit
   *   Durable audit logger.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly FloodInterface $flood,
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly LoggerInterface $logger,
    private readonly LockBackendInterface $lock,
    private readonly SecretRegistryInterface $secrets,
    private readonly FileGateAudit $audit,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('flood'),
      $container->get('keyvalue.expirable'),
      $container->get('logger.channel.file_gate'),
      $container->get('lock'),
      $container->get('file_gate.secret_registry'),
      $container->get('file_gate.audit'),
    );
  }

  /**
   * Revokes the token supplied in the request body.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request. Basic-auth password (or X-File-Gate-Secret header) carries
   *   the shared secret; the JSON body is {"token": "<plaintext>"}.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   204 when the token was found and deleted; 400 (no token), 401 (bad
   *   secret), 404 (unknown/already-gone token), 429 (rate limited), or 503 (no
   *   secret configured, or the token is momentarily locked by a concurrent
   *   redemption — retry) otherwise.
   */
  public function revoke(Request $request): Response {
    // Authenticate the server-to-server caller (fails closed, constant-time,
    // flood-limited). Returns an error response to send as-is, or NULL.
    $config = $this->configFactory->get('file_gate.settings');
    $denied = $this->authenticateSharedSecret(
      $request,
      $this->secrets,
      $this->flood,
      $this->logger,
      'file_gate.revoke',
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

    $secret_id = $request->attributes->get(SecretRegistryInterface::REQUEST_ATTR_SECRET_ID);
    $secret_id = is_string($secret_id) && $secret_id !== '' ? $secret_id : NULL;

    // Signed-URL inventory kill: {"jti": "…", "ttl": 3600} marks the jti spent.
    if (!empty($data['jti']) && is_string($data['jti'])) {
      return $this->revokeSignedJti($data['jti'], $secret_id, $request);
    }

    if (empty($data['token']) || !is_string($data['token'])) {
      return new JsonResponse([
        'error' => 'Provide a "token" (token method) or "jti" (signed_url grant) to revoke.',
      ], Response::HTTP_BAD_REQUEST);
    }

    $token_hash = hash('sha256', $data['token']);
    // Delete under the token lock so a concurrent redemption cannot resurrect
    // the row after we remove it. On lock contention we return NULL and answer
    // 503 (retryable) rather than delete outside the lock — deleting outside it
    // would reopen the resurrection race for that one interleaving.
    $result = $this->runLocked($this->tokenLockName($token_hash), function () use ($token_hash, $secret_id): string {
      $store = $this->keyValueExpirableFactory->get(self::TOKEN_COLLECTION);
      if (!$store->has($token_hash)) {
        return 'missing';
      }
      $record = $store->get($token_hash);
      $field = is_array($record) && isset($record['field']) && is_string($record['field'])
        ? $record['field']
        : NULL;
      // When the field is known, the revoking secret must be allowed for it.
      if ($field !== NULL && !$this->secrets->allowsField($secret_id, $field)) {
        return 'scope';
      }
      $store->delete($token_hash);
      return 'ok';
    }, NULL);

    if ($result === NULL) {
      return new JsonResponse(['error' => 'Token is momentarily locked; retry.'], Response::HTTP_SERVICE_UNAVAILABLE);
    }
    if ($result === 'missing') {
      return new JsonResponse(['error' => 'Token not found.'], Response::HTTP_NOT_FOUND);
    }
    if ($result === 'scope') {
      return new JsonResponse([
        'error' => 'This credential is not allowed to revoke that token.',
      ], Response::HTTP_FORBIDDEN);
    }

    // Usage event: a minted grant was revoked ahead of its expiry.
    $this->logger->info('Revoked a token grant from @ip.', [
      '@ip' => $request->getClientIp() ?? 'unknown',
    ]);
    $this->audit->log('revoke', [
      'kind' => 'token',
      'secret_id' => $secret_id ?? 'legacy',
    ]);

    return new Response('', Response::HTTP_NO_CONTENT);
  }

  /**
   * Marks a signed_url jti as fully used so outstanding links fail.
   *
   * @param string $jti
   *   The grant jti claim.
   * @param string|null $secret_id
   *   Authenticated secret id (logged only; jti store is not field-scoped).
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request (for audit IP context via logger).
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   204 on success; 400 when jti empty.
   */
  private function revokeSignedJti(string $jti, ?string $secret_id, Request $request): Response {
    $jti = trim($jti);
    if ($jti === '') {
      return new JsonResponse(['error' => 'Provide a non-empty "jti".'], Response::HTTP_BAD_REQUEST);
    }
    // Optional ttl for how long to keep the kill mark (default 24h).
    $data = json_decode($request->getContent(), TRUE);
    $ttl = is_array($data) ? max(60, (int) ($data['ttl'] ?? 86400)) : 86400;
    // Use a high counter so any positive max_uses fails.
    $this->keyValueExpirableFactory->get(self::REDEMPTION_COLLECTION)
      ->setWithExpire($jti, PHP_INT_MAX, $ttl);
    $this->logger->info('Revoked signed_url jti from @ip.', [
      '@ip' => $request->getClientIp() ?? 'unknown',
    ]);
    $this->audit->log('revoke', [
      'kind' => 'jti',
      'jti_prefix' => substr(hash('sha256', $jti), 0, 16),
      'secret_id' => $secret_id ?? 'legacy',
    ]);
    return new Response('', Response::HTTP_NO_CONTENT);
  }

}
