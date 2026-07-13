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
   *   The config factory (reads the secret and default TTL).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service (single request-time source, testable).
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function hasSecret(): bool {
    return $this->secret() !== '';
  }

  /**
   * {@inheritdoc}
   */
  public function defaultTtl(): int {
    $ttl = (int) $this->configFactory->get('file_gate.settings')->get('ttl');
    // Guard against a missing or non-positive configured TTL.
    return $ttl > 0 ? $ttl : self::FALLBACK_TTL;
  }

  /**
   * {@inheritdoc}
   */
  public function sign(string $resource_id, array $claims): string {
    $secret = $this->secret();
    // Defensive: callers (e.g. the mint controller) must reject the request
    // before reaching this point when no secret is configured. Refuse rather
    // than emit an unverifiable signature.
    if ($secret === '') {
      throw new \LogicException('Cannot mint a grant: no File Gate signing secret is configured.');
    }
    if (!isset($claims[self::CLAIM_EXPIRES])) {
      throw new \LogicException('A grant must include an expiry (exp) claim.');
    }
    return $this->compute($resource_id, $claims, $secret);
  }

  /**
   * {@inheritdoc}
   */
  public function validate(string $resource_id, array $claims, string $sig): bool {
    $secret = $this->secret();
    // Fail closed: no secret ⇒ nothing can ever be valid. Checked BEFORE any
    // comparison so an unconfigured site denies every gated request.
    if ($secret === '') {
      return FALSE;
    }
    $now = $this->time->getRequestTime();
    // Reject expired (or malformed) grants before any cryptographic work.
    $exp = (int) ($claims[self::CLAIM_EXPIRES] ?? 0);
    if ($exp <= 0 || $exp < $now) {
      return FALSE;
    }
    // Honour an optional "not before" window.
    if (isset($claims[self::CLAIM_NOT_BEFORE]) && (int) $claims[self::CLAIM_NOT_BEFORE] > $now) {
      return FALSE;
    }
    $expected = $this->compute($resource_id, $claims, $secret);
    // Constant-time comparison: never leak, via timing, how much of the
    // signature matched.
    return hash_equals($expected, $sig);
  }

  /**
   * Computes the HMAC signature binding a resource id to its claims.
   *
   * The resource id and the canonicalised claims are joined with a literal "|"
   * so the two cannot be confused for one another (a field-splitting guard).
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
   * Claims are sorted by key and rendered as "key=value" pairs joined by "&",
   * so the same claims always produce the same signable payload regardless of
   * the order the client presents them in.
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
      $parts[] = $key . '=' . $value;
    }
    return implode('&', $parts);
  }

  /**
   * Reads the configured signing secret.
   *
   * @return string
   *   The secret, or an empty string when none is configured.
   */
  private function secret(): string {
    return (string) $this->configFactory->get('file_gate.settings')->get('download_secret');
  }

}
