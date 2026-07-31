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
 */
final class RevokeController implements ContainerInjectionInterface {

  use SharedSecretAuthTrait;
  use GrantLockTrait;

  /**
   * The token store collection name (keyed by the SHA-256 hash of the token).
   */
  private const TOKEN_COLLECTION = 'file_gate_tokens';

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
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly FloodInterface $flood,
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly LoggerInterface $logger,
    private readonly LockBackendInterface $lock,
    private readonly SecretRegistryInterface $secrets,
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
    if (!is_array($data) || empty($data['token']) || !is_string($data['token'])) {
      return new JsonResponse(['error' => 'Provide a "token" to revoke.'], Response::HTTP_BAD_REQUEST);
    }

    $token_hash = hash('sha256', $data['token']);
    // Delete under the token lock so a concurrent redemption cannot resurrect
    // the row after we remove it. On lock contention we return NULL and answer
    // 503 (retryable) rather than delete outside the lock — deleting outside it
    // would reopen the resurrection race for that one interleaving.
    $deleted = $this->runLocked($this->tokenLockName($token_hash), function () use ($token_hash): bool {
      $store = $this->keyValueExpirableFactory->get(self::TOKEN_COLLECTION);
      // FALSE for a token that is unknown or already gone (expired or revoked).
      if (!$store->has($token_hash)) {
        return FALSE;
      }
      $store->delete($token_hash);
      return TRUE;
    }, NULL);

    if ($deleted === NULL) {
      return new JsonResponse(['error' => 'Token is momentarily locked; retry.'], Response::HTTP_SERVICE_UNAVAILABLE);
    }
    if ($deleted === FALSE) {
      return new JsonResponse(['error' => 'Token not found.'], Response::HTTP_NOT_FOUND);
    }

    // Usage event: a minted grant was revoked ahead of its expiry.
    $this->logger->info('Revoked a token grant from @ip.', [
      '@ip' => $request->getClientIp() ?? 'unknown',
    ]);

    return new Response('', Response::HTTP_NO_CONTENT);
  }

}
