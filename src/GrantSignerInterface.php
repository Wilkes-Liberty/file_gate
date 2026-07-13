<?php

declare(strict_types=1);

namespace Drupal\file_gate;

/**
 * Signs and validates short-lived HMAC grants for opaque resources.
 *
 * The signer is deliberately target-agnostic: it operates on an arbitrary
 * "resource id" string (a file URI, an entity UUID, …) plus a bag of claims,
 * and never inspects what the id refers to. This keeps the signing / mint core
 * reusable — a future content_gate or entity_gate could sign its own resource
 * ids with the same service, with no file-specific assumptions to unwind.
 *
 * A grant is a set of claims (at minimum an "exp" expiry; optionally "nbf" a
 * not-before time, and any custom claims such as a usage-limit token) plus an
 * HMAC-SHA256 signature over the resource id and the canonicalised claims:
 * @code
 *   sig = HMAC-SHA256(resource_id . "|" . canonical(claims), secret)
 * @endcode
 * Every claim is bound by the signature, so a client cannot alter the expiry,
 * the usage cap, or any other claim without invalidating the grant.
 */
interface GrantSignerInterface {

  /**
   * The "expiry timestamp" claim key (Unix time; required on every grant).
   */
  public const string CLAIM_EXPIRES = 'exp';

  /**
   * The "not before" claim key (optional; Unix time the grant becomes valid).
   */
  public const string CLAIM_NOT_BEFORE = 'nbf';

  /**
   * Whether a signing secret is configured.
   *
   * @return bool
   *   TRUE if a non-empty secret is available; FALSE otherwise. When FALSE the
   *   module fails closed — nothing can be signed or validated.
   */
  public function hasSecret(): bool;

  /**
   * Signs a set of claims for a resource.
   *
   * @param string $resource_id
   *   The opaque resource identifier to bind the grant to.
   * @param array $claims
   *   The claims to bind. Must include self::CLAIM_EXPIRES. Values must be
   *   scalars.
   *
   * @return string
   *   The HMAC signature.
   *
   * @throws \LogicException
   *   If called with no signing secret configured, or with no expiry claim.
   */
  public function sign(string $resource_id, array $claims): string;

  /**
   * Validates a presented grant against a resource.
   *
   * @param string $resource_id
   *   The opaque resource identifier the grant must be bound to.
   * @param array $claims
   *   The claims presented by the client (as reconstructed from the request).
   * @param string $sig
   *   The signature presented by the client.
   *
   * @return bool
   *   TRUE only if a secret is configured, the "exp" claim is in the future,
   *   any "nbf" claim is in the past, and the signature matches. Fails closed
   *   (FALSE) in every other case. Note: this does NOT enforce usage limits —
   *   that is stateful and handled by the gate method.
   */
  public function validate(string $resource_id, array $claims, string $sig): bool;

  /**
   * The default grant lifetime in seconds.
   *
   * @return int
   *   The configured default TTL (falls back to a safe built-in default).
   */
  public function defaultTtl(): int;

}
