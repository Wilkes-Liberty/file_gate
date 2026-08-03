<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance;

/**
 * One trusted OIDC issuer with its own audience and acceptable acr values.
 *
 * An immutable value object: verification always evaluates the token against
 * exactly one of these (matched by the token's `iss`), so an audience or acr
 * accepted for one issuer can never satisfy a token from another.
 *
 * @see \Drupal\file_gate_assurance\TrustedIssuerSet
 */
final class TrustedIssuer {

  /**
   * Constructs a trusted issuer entry.
   *
   * @param string $issuer
   *   The OIDC issuer URL (matched byte-exactly against the token's `iss`).
   * @param string $audience
   *   The audience the token's `aud` must contain for this issuer.
   * @param list<string> $requiredAcr
   *   The acceptable `acr` values for this issuer. Empty denies every token.
   */
  public function __construct(
    public readonly string $issuer,
    public readonly string $audience,
    public readonly array $requiredAcr,
  ) {}

}
