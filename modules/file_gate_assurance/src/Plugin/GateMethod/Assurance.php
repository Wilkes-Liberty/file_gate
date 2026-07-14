<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\Plugin\GateMethod;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\Plugin\GateMethod\SignedUrl;
use Drupal\file_gate_assurance\AssuranceVerifierInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Signed URL gated on a hardware-backed, phishing-resistant OIDC assurance.
 *
 * A signed URL (all of signed_url's TTL / availability / usage machinery) whose
 * delivery additionally requires a NIST SP 800-63 assurance level proven at an
 * OIDC IdP through PIV/CAC (HSPD-12 / FIPS 201) or FIDO2/WebAuthn (e.g. a
 * YubiKey). File Gate is the Relying Party — it verifies the IdP's assertion,
 * never the hardware crypto. Provider-agnostic: any OIDC IdP works.
 *
 * This is federation (SP 800-63C) — an *asserted* level — not File Gate acting
 * as an AAL3 verifier under 800-63B; see docs/design/piv-cac-webauthn.md. Two
 * modes, chosen by `verify_at`:
 * - "redeem" (default, Model B): the browser presents a live OIDC token at the
 *   download endpoint (a JS fetch, not a plain navigation) and grants() checks
 *   its signature, issuer, audience, and `acr` — optionally sender-constrained
 *   with a DPoP proof (RFC 9449) so a stolen token is useless. Real, live,
 *   per-request enforcement.
 * - "mint" (Model A): the trusted mint caller already stepped the user up to
 *   the level; File Gate binds it as an audit claim and trusts the caller
 *   (consistent with the mint trust model). The delivery URL is a bearer
 *   capability — not itself AAL3-bound.
 *
 * The assurance is checked BEFORE the inherited signature/usage check, so a
 * request that fails assurance never spends a usage-limited grant's use.
 *
 * Per-field method settings (beyond signed_url's ttl / available_until /
 * max_uses):
 * - verify_at: "redeem" (default) or "mint";
 * - aal: the assurance level to bind into the signed grant (audit + tamper
 *   binding), e.g. 3;
 * - issuer: the OIDC issuer URL (required for "redeem");
 * - audience: the expected token audience (required for "redeem");
 * - required_acr: the acceptable `acr` values, exactly as your IdP emits them
 *   (required for "redeem"); empty denies;
 * - required_amr: optional advisory `amr` values to also require (off by
 *   default);
 * - dpop: TRUE to require an RFC 9449 DPoP proof (opt-in hardening);
 * - leeway: clock-skew tolerance in seconds (default 60).
 */
#[GateMethod(
  id: 'assurance',
  label: new TranslatableMarkup('Assurance (PIV/CAC + FIDO2/WebAuthn via OIDC)'),
  description: new TranslatableMarkup('A signed URL whose delivery also requires a hardware-backed, phishing-resistant assurance level (PIV/CAC or FIDO2/WebAuthn) proven at any OIDC IdP. Verifies the IdP assertion live at redemption (or trusts a stepped-up mint caller), optionally sender-constrained with DPoP. Federation (asserted level), not an AAL3 verifier.'),
)]
final class Assurance extends SignedUrl {

  /**
   * The assurance verifier.
   */
  private AssuranceVerifierInterface $verifier;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    // parent::create() wires signed_url's services onto the new instance (via
    // new static()); we add only the verifier.
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->verifier = $container->get('file_gate_assurance.verifier');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function grants(FileInterface $file, Request $request): bool {
    // Assurance layer first — like referrer_lock, so a failed check never burns
    // a usage-limited grant. The inherited signature check (which also binds
    // the asserted `aal`) is the tamper-proofing underneath.
    if (!$this->assuranceSatisfied($request)) {
      return FALSE;
    }
    return parent::grants($file, $request);
  }

  /**
   * {@inheritdoc}
   */
  protected function signedClaimKeys(): array {
    // Bind the asserted level into the signature so it cannot be downgraded.
    return array_merge(parent::signedClaimKeys(), ['aal']);
  }

  /**
   * {@inheritdoc}
   */
  protected function extraMintClaims(FileInterface $file): array {
    $aal = (int) ($this->configuration['aal'] ?? 0);
    return $aal > 0 ? ['aal' => $aal] : [];
  }

  /**
   * Whether the request satisfies the configured assurance.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The redemption request.
   *
   * @return bool
   *   TRUE when the assurance is satisfied. Fails closed on any missing or
   *   invalid token, insufficient `acr`, or (when required) DPoP failure.
   */
  private function assuranceSatisfied(Request $request): bool {
    // Model A: the trusted mint caller asserted the level; it is bound into the
    // signature (verified by parent::grants). No live check here.
    if (($this->configuration['verify_at'] ?? 'redeem') === 'mint') {
      return TRUE;
    }

    // Model B: verify a live OIDC token presented at redemption.
    $token = $this->bearerToken($request);
    if ($token === NULL) {
      return FALSE;
    }
    $claims = $this->verifier->verify($token, $this->configuration, $request);
    if ($claims === NULL) {
      return FALSE;
    }

    // The decision is driven by `acr` (IdP policy). Empty allowlist ⇒ deny.
    $required_acr = array_map('strval', (array) ($this->configuration['required_acr'] ?? []));
    if ($required_acr === [] || !in_array((string) $claims['acr'], $required_acr, TRUE)) {
      return FALSE;
    }

    // `amr` is advisory: enforced only when the field explicitly requires some.
    $required_amr = array_map('strval', (array) ($this->configuration['required_amr'] ?? []));
    if ($required_amr !== [] && array_diff($required_amr, $claims['amr']) !== []) {
      return FALSE;
    }

    return TRUE;
  }

  /**
   * Extracts the presented token from the Authorization header.
   *
   * Accepts both the "Bearer" and (DPoP-bound) "DPoP" auth schemes.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return string|null
   *   The token, or NULL when absent.
   */
  private function bearerToken(Request $request): ?string {
    $authorization = (string) $request->headers->get('Authorization', '');
    foreach (['Bearer ', 'DPoP '] as $scheme) {
      if (stripos($authorization, $scheme) === 0) {
        $token = trim(substr($authorization, strlen($scheme)));
        return $token !== '' ? $token : NULL;
      }
    }
    return NULL;
  }

}
