<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance;

use Symfony\Component\HttpFoundation\Request;

/**
 * Verifies an OIDC assertion (and optional DPoP proof) presented at redemption.
 *
 * File Gate is an OIDC Relying Party: it verifies the IdP's signature + claims
 * on a token the IdP issued after phishing-resistant, hardware-backed
 * authentication (PIV/CAC or FIDO2/WebAuthn). It never re-does the hardware
 * crypto. This is federation (NIST SP 800-63C) — an *asserted* assurance level.
 *
 * The verifier is provider-agnostic: it is configured only with an issuer URL
 * and an expected audience, discovers the IdP's JWKS via OIDC discovery, and
 * pins the signing algorithm to the published keys. No IdP is assumed.
 */
interface AssuranceVerifierInterface {

  /**
   * Verifies a presented bearer token and (optionally) a DPoP proof.
   *
   * @param string $token
   *   The bearer JWT (access or ID token) presented by the client.
   * @param array $config
   *   The gate method settings: at least "issuer" and "audience"; optionally
   *   "leeway" (seconds), "dpop" (bool). See the module README.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The redemption request (source of the DPoP header and the htu/htm the
   *   DPoP proof is bound to).
   *
   * @return array|null
   *   The verified claims — ['sub' => string|null, 'acr' => string|null,
   *   'amr' => string[]] — or NULL when the token (or a required DPoP proof) is
   *   missing, malformed, or fails any check. Fails closed.
   */
  public function verify(string $token, array $config, Request $request): ?array;

  /**
   * Checks a token's live status at the IdP introspection endpoint (RFC 7662).
   *
   * Opt-in: closes the gap where a JWT stays valid until its own expiry even
   * after the IdP session is revoked. Adds a network round-trip per redemption.
   *
   * @param string $token
   *   The bearer token to introspect.
   * @param array $config
   *   The method settings: at least "introspection_endpoint"; optionally
   *   "introspection_client_id" / "introspection_client_secret".
   *
   * @return bool
   *   TRUE only if the endpoint reports the token active. Fails closed (FALSE)
   *   when unconfigured or on any error.
   */
  public function introspect(string $token, array $config): bool;

}
