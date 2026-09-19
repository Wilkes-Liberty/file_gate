<?php

declare(strict_types=1);

namespace Drupal\file_gate\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\file_gate\GrantLockTrait;
use Drupal\file_gate\GrantRevokeLockException;
use Drupal\file_gate\Plugin\GateMethod\Token;
use Drupal\file_gate\SecretRegistryInterface;
use Drupal\file_gate\Service\FileGateAudit;
use Drupal\file_gate\Service\GrantInventory;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Revokes a minted token grant.
 *
 * Fails closed when no secret is configured. Delete runs under the same token
 * lock as redemption so a concurrent redeem cannot resurrect a revoked row.
 */
final class RevokeController implements ContainerInjectionInterface {

  use SharedSecretAuthTrait;
  use GrantLockTrait;

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
   * @param \Drupal\file_gate\Service\GrantInventory $inventory
   *   Signed-URL jti inventory (spend + forget on single-jti revoke).
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly FloodInterface $flood,
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly LoggerInterface $logger,
    private readonly LockBackendInterface $lock,
    private readonly SecretRegistryInterface $secrets,
    private readonly FileGateAudit $audit,
    private readonly GrantInventory $inventory,
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
      $container->get('file_gate.grant_inventory'),
    );
  }

  /**
   * Revokes the token supplied in the request body.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request. Basic-auth password (or X-File-Gate-Secret header) carries
   *   the shared secret; the JSON body is {"token": "<plaintext>"} or
   *   {"jti": "<jti>"}.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   204 when the token or jti was revoked; 400 (no token/jti), 401 (bad
   *   secret), 403 (credential not allowed for that grant's field / k), 404
   *   (unknown/already-gone token or missing inventory meta), 429 (rate
   *   limited), or 503 (no secret configured, or the token is momentarily
   *   locked by a concurrent redemption — retry) otherwise.
   */
  public function revoke(Request $request): Response {
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
      $store = $this->keyValueExpirableFactory->get(Token::TOKEN_COLLECTION);
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
   * Marks a signed_url jti fully spent and drops it from inventory.
   *
   * Privilege matches list and bulk revoke: the secret must be allowed for
   * the grant's stored field, and a named secret must match stored k.
   * Missing inventory meta is 404 so a foreign or unknown jti is not
   * confirmed and is not spent.
   *
   * @param string $jti
   *   The grant jti claim.
   * @param string|null $secret_id
   *   Authenticated secret id (legacy NULL is whole-corpus).
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request (for audit IP context via logger).
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   204 on success; 400 when jti empty; 403 when the secret is out of
   *   scope for the grant's field or k; 404 when inventory meta is missing.
   */
  private function revokeSignedJti(string $jti, ?string $secret_id, Request $request): Response {
    $jti = trim($jti);
    if ($jti === '') {
      return new JsonResponse(['error' => 'Provide a non-empty "jti".'], Response::HTTP_BAD_REQUEST);
    }
    $meta = $this->inventory->meta($jti);
    $field = is_array($meta) && isset($meta['field']) && is_string($meta['field']) && $meta['field'] !== ''
      ? $meta['field']
      : NULL;
    if ($meta === NULL || $field === NULL) {
      return new JsonResponse(['error' => 'Grant not found.'], Response::HTTP_NOT_FOUND);
    }
    $row_k = $meta['k'] ?? NULL;
    $row_k = (is_string($row_k) && $row_k !== '') ? $row_k : NULL;
    // Named secrets must be allowed for the stored field and match k so one
    // tenant cannot spend another field's grant (token revoke uses the same
    // allowsField() check; list/bulk also require matching k).
    if (!$this->secrets->allowsField($secret_id, $field) || ($secret_id !== NULL && $row_k !== $secret_id)) {
      return new JsonResponse([
        'error' => 'This credential is not allowed to revoke that grant.',
      ], Response::HTTP_FORBIDDEN);
    }
    $data = json_decode($request->getContent(), TRUE);
    $ttl = is_array($data) && array_key_exists('ttl', $data)
      ? (int) $data['ttl']
      : NULL;
    try {
      $this->inventory->revokeJti($jti, $field, $ttl);
    }
    catch (GrantRevokeLockException) {
      $response = new JsonResponse(['error' => 'Grant is momentarily locked; retry.'], Response::HTTP_SERVICE_UNAVAILABLE);
      $response->headers->set('Retry-After', '5');
      return $response;
    }
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
