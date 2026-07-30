<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\Plugin\GateMethod;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\ContextualMintInterface;
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
 * as an AAL3 verifier under 800-63B; see docs/design/piv-cac-webauthn.md. Three
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
 * - "client_cert" (edge mTLS): an mTLS-terminating reverse proxy validates a
 *   PIV/CAC client certificate against the Federal PKI and passes the subject
 *   in a trusted header; File Gate accepts it against a required subject
 *   allowlist. Only safe when File Gate is reachable *solely* through the
 *   proxy (the header is otherwise spoofable) — see clientCertSatisfied().
 *
 * The assurance is checked BEFORE the inherited signature/usage check, so a
 * request that fails assurance never spends a usage-limited grant's use.
 *
 * Per-field method settings (beyond signed_url's ttl / available_until /
 * max_uses):
 * - verify_at: "redeem" (default), "mint", or "client_cert";
 * - aal: the assurance level to bind into the signed grant (audit + tamper
 *   binding), e.g. 3;
 * - issuer: the OIDC issuer URL (required for "redeem");
 * - audience: the expected token audience (required for "redeem");
 * - required_acr: the acceptable `acr` values, exactly as your IdP emits them
 *   (required for "redeem"); empty denies;
 * - required_amr: optional advisory `amr` values to also require (off by
 *   default);
 * - dpop: TRUE to require an RFC 9449 DPoP proof (opt-in hardening);
 * - introspect / introspection_endpoint / introspection_client_id: opt-in live
 *   revocation via RFC 7662 (the client secret is injected from the
 *   environment, never stored here);
 * - trusted_proxy_header: the header the mTLS proxy sets to the validated
 *   certificate subject (required for "client_cert");
 * - allowed_subjects: the accepted certificate subjects/DNs (required for
 *   "client_cert" — empty denies);
 * - leeway: clock-skew tolerance in seconds (default 60).
 */
#[GateMethod(
  id: 'assurance',
  label: new TranslatableMarkup('Assurance (PIV/CAC + FIDO2/WebAuthn via OIDC)'),
  description: new TranslatableMarkup('A signed URL whose delivery also requires a hardware-backed, phishing-resistant assurance level (PIV/CAC or FIDO2/WebAuthn) proven at any OIDC IdP. Verifies the IdP assertion live at redemption (or trusts a stepped-up mint caller), optionally sender-constrained with DPoP. Federation (asserted level), not an AAL3 verifier.'),
)]
final class Assurance extends SignedUrl implements ContextualMintInterface {

  /**
   * The assurance verifier.
   */
  protected AssuranceVerifierInterface $verifier;

  /**
   * The caller-asserted subject for the grant being minted, if any.
   */
  protected ?string $mintSubject = NULL;

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
  public function mintWithContext(FileInterface $file, Request $request): ?array {
    // The trusted mint caller may assert the subject the grant is for; File
    // Gate binds only its hash, and Model B enforces at redemption that the
    // presented token belongs to that subject (per-user binding). A wrong
    // subject gains nothing — redemption still needs a valid token for it.
    $data = json_decode($request->getContent(), TRUE);
    $subject = is_array($data) && isset($data['subject']) && is_string($data['subject'])
      ? $data['subject']
      : '';
    $this->mintSubject = $subject !== '' ? $subject : NULL;
    return $this->mint($file);
  }

  /**
   * {@inheritdoc}
   */
  protected function signedClaimKeys(): array {
    // Bind the asserted level and the optional subject hash into the signature,
    // so neither can be downgraded nor swapped.
    return array_merge(parent::signedClaimKeys(), ['aal', 'sh']);
  }

  /**
   * {@inheritdoc}
   */
  protected function extraMintClaims(FileInterface $file): array {
    $claims = [];
    $aal = (int) ($this->configuration['aal'] ?? 0);
    if ($aal > 0) {
      $claims['aal'] = $aal;
    }
    if ($this->mintSubject !== NULL) {
      $claims['sh'] = hash('sha256', $this->mintSubject);
    }
    return $claims;
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
    $mode = $this->configuration['verify_at'] ?? 'redeem';

    // Model A: the trusted mint caller asserted the level; it is bound into the
    // signature (verified by parent::grants). No live check here.
    if ($mode === 'mint') {
      return TRUE;
    }

    // Edge mTLS: trust a validated PIV client-certificate identity that an
    // mTLS-terminating proxy passes in a configured, trusted header.
    if ($mode === 'client_cert') {
      return $this->clientCertSatisfied($request);
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

    // Per-user binding: when the grant carries a subject hash (bound at mint
    // from a caller-asserted subject), the token's subject must match it.
    $sub_hash = (string) $request->query->get('sh', '');
    if ($sub_hash !== '' && !hash_equals($sub_hash, hash('sha256', (string) $claims['sub']))) {
      return FALSE;
    }

    // Optional live revocation check (RFC 7662).
    if (!empty($this->configuration['introspect']) && !$this->verifier->introspect($token, $this->configuration)) {
      return FALSE;
    }

    return TRUE;
  }

  /**
   * Whether a validated client-certificate identity from the edge is accepted.
   *
   * SECURITY: this trusts a request header, which is only safe when File Gate
   * is reachable exclusively through the mTLS-terminating proxy that sets it
   * (and strips any client-supplied copy). The proxy plus its trust store (e.g.
   * the Federal PKI) is the verifier — File Gate only consumes the result.
   * Because the header is spoofable off-proxy, this mode fails closed without
   * an explicit subject allowlist: requiring a configured subject means a
   * forged header alone is not enough. Network isolation remains the primary
   * control; a future hardening could add a proxy-shared secret header as a
   * second server-verified factor.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The redemption request.
   *
   * @return bool
   *   TRUE only when a non-empty subject allowlist is configured and the header
   *   subject is on it; fails closed otherwise.
   */
  private function clientCertSatisfied(Request $request): bool {
    $header = (string) ($this->configuration['trusted_proxy_header'] ?? '');
    if ($header === '') {
      return FALSE;
    }
    $subject = trim((string) $request->headers->get($header, ''));
    if ($subject === '') {
      return FALSE;
    }
    // Fail closed without an explicit allowlist. "Accept any subject the proxy
    // validated" would grant to anyone able to reach File Gate off-proxy and
    // forge the header; a required allowlist is a second barrier.
    $allowed = array_map('strval', (array) ($this->configuration['allowed_subjects'] ?? []));
    if ($allowed === []) {
      return FALSE;
    }
    return in_array($subject, $allowed, TRUE);
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

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $settings): array {
    $lines = static fn (array $v): string => implode("\n", $v);
    $verify_at = (string) ($settings['verify_at'] ?? 'redeem');
    if (!in_array($verify_at, ['redeem', 'mint', 'client_cert'], TRUE)) {
      $verify_at = 'redeem';
    }
    return parent::fieldSettingsForm($settings) + [
      'verify_at' => [
        '#type' => 'select',
        '#title' => $this->t('Verify'),
        '#options' => [
          'redeem' => $this->t('At redemption — live OIDC token (Model B)'),
          'mint' => $this->t('At mint — trust the stepped-up caller (Model A)'),
          'client_cert' => $this->t('Edge mTLS — trust a validated client certificate'),
        ],
        '#default_value' => $verify_at,
      ],
      'aal' => [
        '#type' => 'number',
        '#title' => $this->t('Assurance level to bind'),
        '#min' => 0,
        '#default_value' => (int) ($settings['aal'] ?? 0),
        '#description' => $this->t('Bound into the signed grant (audit + downgrade protection), e.g. 3. 0 = none.'),
      ],
      'issuer' => [
        '#type' => 'textfield',
        '#title' => $this->t('OIDC issuer URL'),
        '#default_value' => $settings['issuer'] ?? '',
        '#description' => $this->t('Redemption mode. The JWKS is found via OIDC discovery on this issuer.'),
      ],
      'audience' => [
        '#type' => 'textfield',
        '#title' => $this->t('Expected token audience'),
        '#default_value' => $settings['audience'] ?? '',
        '#description' => $this->t('Redemption mode. The token’s <code>aud</code> must contain this value.'),
      ],
      'required_acr' => [
        '#type' => 'textarea',
        '#title' => $this->t('Accepted acr values'),
        '#default_value' => $lines((array) ($settings['required_acr'] ?? [])),
        '#description' => $this->t('Redemption mode. One <code>acr</code> value per line, exactly as your IdP emits. Empty denies.'),
      ],
      'required_amr' => [
        '#type' => 'textarea',
        '#title' => $this->t('Required amr values (advisory)'),
        '#default_value' => $lines((array) ($settings['required_amr'] ?? [])),
        '#description' => $this->t('Optional. One per line; enforced only when set. <code>amr</code> is advisory.'),
      ],
      'dpop' => [
        '#type' => 'checkbox',
        '#title' => $this->t('Require a DPoP proof (RFC 9449)'),
        '#default_value' => !empty($settings['dpop']),
        '#description' => $this->t('Sender-constrains the token to a key the client proves possession of, and binds the proof to this exact access token.'),
      ],
      'htu_origin' => [
        '#type' => 'textfield',
        '#title' => $this->t('DPoP htu origin override'),
        '#default_value' => $settings['htu_origin'] ?? '',
        '#description' => $this->t('Optional (DPoP). Behind a TLS-terminating or Host-rewriting proxy, set the public origin (e.g. <code>https://files.example.gov</code>) so the <code>htu</code> the client signs matches what File Gate computes. Empty derives it from the request (which honours Drupal’s reverse-proxy settings).'),
      ],
      'introspect' => [
        '#type' => 'checkbox',
        '#title' => $this->t('Introspect the token (RFC 7662)'),
        '#default_value' => !empty($settings['introspect']),
        '#description' => $this->t('Live revocation check at redemption. Adds a network round-trip.'),
      ],
      'introspection_endpoint' => [
        '#type' => 'textfield',
        '#title' => $this->t('Introspection endpoint'),
        '#default_value' => $settings['introspection_endpoint'] ?? '',
      ],
      'introspection_client_id' => [
        '#type' => 'textfield',
        '#title' => $this->t('Introspection client id'),
        '#default_value' => $settings['introspection_client_id'] ?? '',
        '#description' => $this->t('The client secret is injected globally from the environment, never stored here.'),
      ],
      'trusted_proxy_header' => [
        '#type' => 'textfield',
        '#title' => $this->t('Trusted client-cert header'),
        '#default_value' => $settings['trusted_proxy_header'] ?? '',
        '#description' => $this->t('Edge mTLS mode. The header your reverse proxy sets to the validated certificate subject, e.g. <code>X-Client-Cert-Dn</code>. Only safe if File Gate is reachable solely through that proxy.'),
      ],
      'allowed_subjects' => [
        '#type' => 'textarea',
        '#title' => $this->t('Allowed certificate subjects'),
        '#default_value' => $lines((array) ($settings['allowed_subjects'] ?? [])),
        '#description' => $this->t('Edge mTLS mode, required. One subject (DN) per line. Empty denies (the header is spoofable off-proxy, so an allowlist is mandatory).'),
      ],
      'leeway' => [
        '#type' => 'number',
        '#title' => $this->t('Clock-skew tolerance'),
        '#field_suffix' => $this->t('seconds'),
        '#min' => 0,
        '#default_value' => (int) ($settings['leeway'] ?? 60),
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsSubmit(array $values): array {
    // Inherit ttl / available_until / max_uses.
    $settings = parent::fieldSettingsSubmit($values);

    $mode = $values['verify_at'] ?? 'redeem';
    $settings['verify_at'] = in_array($mode, ['redeem', 'mint', 'client_cert'], TRUE) ? $mode : 'redeem';
    $settings['aal'] = (int) ($values['aal'] ?? 0);
    $settings['dpop'] = !empty($values['dpop']);
    $settings['introspect'] = !empty($values['introspect']);
    $settings['leeway'] = (int) ($values['leeway'] ?? 60);

    $string_keys = [
      'issuer',
      'audience',
      'introspection_endpoint',
      'introspection_client_id',
      'trusted_proxy_header',
      'htu_origin',
    ];
    foreach ($string_keys as $key) {
      $value = trim((string) ($values[$key] ?? ''));
      if ($value !== '') {
        $settings[$key] = $value;
      }
    }
    foreach (['required_acr', 'required_amr', 'allowed_subjects'] as $key) {
      $list = array_filter(array_map('trim', preg_split('/\R/', (string) ($values[$key] ?? ''))));
      if ($list) {
        $settings[$key] = array_values($list);
      }
    }
    return $settings;
  }

}
