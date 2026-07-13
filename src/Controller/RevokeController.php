<?php

declare(strict_types=1);

namespace Drupal\file_gate\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
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
 * Only minted tokens live in the store; pre-shared campaign tokens are revoked
 * by removing their hash from the field's "tokens" configuration, not here.
 */
final class RevokeController implements ContainerInjectionInterface {

  use SharedSecretAuthTrait;

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
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly FloodInterface $flood,
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly LoggerInterface $logger,
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
   *   secret configured) otherwise.
   */
  public function revoke(Request $request): Response {
    // Authenticate the server-to-server caller (fails closed, constant-time,
    // flood-limited). Returns an error response to send as-is, or NULL.
    $denied = $this->authenticateSharedSecret($request, $this->configFactory, $this->flood, $this->logger, 'file_gate.revoke');
    if ($denied !== NULL) {
      return $denied;
    }

    $data = json_decode($request->getContent(), TRUE);
    if (!is_array($data) || empty($data['token']) || !is_string($data['token'])) {
      return new JsonResponse(['error' => 'Provide a "token" to revoke.'], Response::HTTP_BAD_REQUEST);
    }

    $token_hash = hash('sha256', $data['token']);
    $store = $this->keyValueExpirableFactory->get(self::TOKEN_COLLECTION);
    // 404 for a token that is unknown or already gone (expired or revoked). The
    // presence check is a tiny race against a concurrent redemption, harmless
    // given the caller is already fully trusted.
    if (!$store->has($token_hash)) {
      return new JsonResponse(['error' => 'Token not found.'], Response::HTTP_NOT_FOUND);
    }
    $store->delete($token_hash);

    // Usage event: a minted grant was revoked ahead of its expiry.
    $this->logger->info('Revoked a token grant from @ip.', [
      '@ip' => $request->getClientIp() ?? 'unknown',
    ]);

    return new Response('', Response::HTTP_NO_CONTENT);
  }

}
