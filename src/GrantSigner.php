<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;

/**
 * Default HMAC implementation of the grant signer.
 *
 * @see \Drupal\file_gate\GrantSignerInterface
 */
final class GrantSigner implements GrantSignerInterface {

  /**
   * Safe fallback TTL (seconds) used when configuration is missing/invalid.
   */
  private const FALLBACK_TTL = 120;

  /**
   * Constructs the grant signer.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory (default TTL).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\file_gate\SecretRegistryInterface $secrets
   *   Secret registry (legacy + named materials).
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
    private readonly SecretRegistryInterface $secrets,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function hasSecret(): bool {
    return $this->secrets->hasAnySecret();
  }

  /**
   * {@inheritdoc}
   */
  public function defaultTtl(): int {
    $ttl = (int) $this->configFactory->get('file_gate.settings')->get('ttl');
    return $ttl > 0 ? $ttl : self::FALLBACK_TTL;
  }

  /**
   * {@inheritdoc}
   */
  public function sign(string $resource_id, array $claims, ?string $secret_id = NULL): string {
    $secret = $this->secrets->secretMaterial($secret_id);
    if ($secret === '') {
      throw new \LogicException('Cannot mint a grant: no File Gate signing secret is configured for this credential.');
    }
    if (!isset($claims[self::CLAIM_EXPIRES])) {
      throw new \LogicException('A grant must include an expiry (exp) claim.');
    }
    return $this->compute($resource_id, $claims, $secret);
  }

  /**
   * {@inheritdoc}
   */
  public function validate(string $resource_id, array $claims, string $sig, ?string $secret_id = NULL): bool {
    $secret = $this->secrets->secretMaterial($secret_id);
    // Fail closed: missing/deleted secret ⇒ unverifiable.
    if ($secret === '') {
      return FALSE;
    }
    $now = $this->time->getRequestTime();
    $exp = (int) ($claims[self::CLAIM_EXPIRES] ?? 0);
    if ($exp <= 0 || $exp < $now) {
      return FALSE;
    }
    if (isset($claims[self::CLAIM_NOT_BEFORE]) && (int) $claims[self::CLAIM_NOT_BEFORE] > $now) {
      return FALSE;
    }
    $expected = $this->compute($resource_id, $claims, $secret);
    return hash_equals($expected, $sig);
  }

  /**
   * Computes the HMAC signature binding a resource id to its claims.
   *
   * @param string $resource_id
   *   The opaque resource identifier.
   * @param array $claims
   *   The claims to bind.
   * @param string $secret
   *   The signing secret.
   *
   * @return string
   *   The lowercase hexadecimal HMAC-SHA256 signature.
   */
  private function compute(string $resource_id, array $claims, string $secret): string {
    return hash_hmac('sha256', $resource_id . '|' . $this->canonical($claims), $secret);
  }

  /**
   * Canonicalises a claims bag into a deterministic string.
   *
   * Every key and value is rawurlencode()d before joining so the claims →
   * string mapping is injective (claim-folding bypass defense).
   *
   * @param array $claims
   *   The claims (scalar values).
   *
   * @return string
   *   The canonical representation.
   */
  private function canonical(array $claims): string {
    ksort($claims);
    $parts = [];
    foreach ($claims as $key => $value) {
      $parts[] = rawurlencode((string) $key) . '=' . rawurlencode((string) $value);
    }
    return implode('&', $parts);
  }

}
