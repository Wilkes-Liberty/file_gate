<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\Plugin\GateMethod;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\Core\Url;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\ChallengeAwareGateMethodInterface;
use Drupal\file_gate\ContextualMintInterface;
use Drupal\file_gate\MintTimeOidcInterface;
use Drupal\file_gate\Plugin\GateMethod\SignedUrl;
use Drupal\file_gate\StackMiddleware\AuthorizationShield;
use Drupal\file_gate_assurance\AssuranceVerifierInterface;
use Drupal\file_gate_assurance\SessionBridge;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

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
 * - "webauthn" (native RP): File Gate runs the WebAuthn assertion ceremony for
 *   a registered authenticator, then sets the same session bridge cookie used
 *   by the plain-link path. Federation is not required for this mode.
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
final class Assurance extends SignedUrl implements ContextualMintInterface, ChallengeAwareGateMethodInterface, MintTimeOidcInterface {

  /**
   * The assurance verifier.
   */
  protected AssuranceVerifierInterface $verifier;

  /**
   * Session bridge (plain-link primary path after step-up).
   */
  protected SessionBridge $sessionBridge;

  /**
   * The caller-asserted subject for the grant being minted, if any.
   */
  protected ?string $mintSubject = NULL;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    // parent::create() wires signed_url's services onto the new instance (via
    // new static()); we add the verifier and session bridge.
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->verifier = $container->get('file_gate_assurance.verifier');
    $instance->sessionBridge = $container->get('file_gate_assurance.session_bridge');
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
    // When verify_oidc_at_mint (A2) succeeded, prefer the verified token sub.
    $data = json_decode($request->getContent(), TRUE);
    $subject = is_array($data) && isset($data['subject']) && is_string($data['subject'])
      ? $data['subject']
      : '';
    if ($subject === '' && is_string($request->attributes->get('file_gate.mint_oidc_sub'))) {
      $subject = (string) $request->attributes->get('file_gate.mint_oidc_sub');
    }
    $this->mintSubject = $subject !== '' ? $subject : NULL;
    return $this->mint($file);
  }

  /**
   * {@inheritdoc}
   *
   * A2 (mint-time OIDC): when verify_oidc_at_mint is enabled, the mint caller
   * must present a Bearer (or DPoP) token whose aud is this field's audience
   * (File Gate API client after RFC 8693 token exchange or IdP mapper). Fail
   * closed on missing/invalid token, wrong aud, or low acr. Disabled by default
   * (A1 trusts the secret-holder only).
   */
  public function assertMintTimeOidc(Request $request): ?JsonResponse {
    if (empty($this->configuration['verify_oidc_at_mint'])) {
      return NULL;
    }
    $token = $this->bearerToken($request);
    if ($token === NULL || $token === '') {
      return new JsonResponse([
        'error' => 'Mint-time OIDC token required (Authorization: Bearer or DPoP).',
      ], Response::HTTP_UNAUTHORIZED, [
        'WWW-Authenticate' => 'Bearer realm="file-gate-mint"',
      ]);
    }
    $claims = $this->verifier->verify($token, $this->configuration, $request);
    if ($claims === NULL) {
      return new JsonResponse([
        'error' => 'Mint-time OIDC token failed verification.',
      ], Response::HTTP_FORBIDDEN);
    }
    // Same rule as redeem: empty acr allowlist denies (fail closed).
    $required_acr = $this->requiredAcrList();
    $acr = isset($claims['acr']) ? (string) $claims['acr'] : '';
    if ($required_acr === [] || $acr === '' || !in_array($acr, $required_acr, TRUE)) {
      return new JsonResponse([
        'error' => 'Mint-time OIDC token acr is insufficient.',
        'acr_values' => $required_acr,
      ], Response::HTTP_FORBIDDEN);
    }
    if (!empty($this->configuration['introspect']) && !$this->verifier->introspect($token, $this->configuration)) {
      return new JsonResponse([
        'error' => 'Mint-time OIDC token is not active (introspection).',
      ], Response::HTTP_FORBIDDEN);
    }
    $sub = isset($claims['sub']) ? (string) $claims['sub'] : '';
    if ($sub !== '') {
      $request->attributes->set('file_gate.mint_oidc_sub', $sub);
    }
    return NULL;
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
   * {@inheritdoc}
   */
  public function challenge(FileInterface $file, Request $request): ?Response {
    $mode = $this->configuration['verify_at'] ?? 'redeem';
    // Step-up for redeem (OIDC) or webauthn (native RP).
    if (!in_array($mode, ['redeem', 'webauthn'], TRUE)) {
      return NULL;
    }
    // Invalid/spent signature → hard deny (NULL → 403).
    if (!$this->signatureValid($file, $request)) {
      return NULL;
    }
    // OIDC redeem: a presented Bearer/DPoP that failed is a failed attempt.
    if ($mode === 'redeem' && $this->bearerToken($request) !== NULL) {
      return NULL;
    }

    // Never put login_url in the step-up query: the step-up page reads
    // step_up_login_url from field settings only (open-redirect defense).
    $query = $request->query->all();
    unset($query['login_url']);
    if ($mode === 'webauthn') {
      $query['mode'] = 'webauthn';
    }
    $step_up = Url::fromRoute('file_gate_assurance.step_up', [], [
      'query' => $query,
      'absolute' => FALSE,
    ])->toString();

    // API clients (Accept: application/json or XHR) get a structured challenge.
    $accept = (string) $request->headers->get('Accept', '');
    $xhr = $request->headers->get('X-Requested-With') === 'XMLHttpRequest';
    if (str_contains($accept, 'application/json') || $xhr) {
      if ($mode === 'webauthn') {
        return $this->buildWebauthnApiChallenge($request, $step_up);
      }
      return $this->buildApiChallenge($request, $step_up);
    }

    // Plain-link primary: send the browser to the step-up page.
    return new RedirectResponse($step_up, Response::HTTP_FOUND);
  }

  /**
   * Required acr values from field configuration.
   *
   * @return list<string>
   *   Accepted acr strings.
   */
  public function requiredAcrList(): array {
    return array_values(array_filter(array_map('strval', (array) ($this->configuration['required_acr'] ?? []))));
  }

  /**
   * Live OIDC (+ DPoP/introspection) check without session-bridge fallback.
   *
   * Used by the bridge controller when establishing the plain-link cookie.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request presenting Authorization.
   *
   * @return bool
   *   TRUE when live assurance passes.
   */
  public function liveAssuranceSatisfied(Request $request): bool {
    return $this->liveOidcSatisfied($request);
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

    // Plain-link primary: a short-lived bridge cookie set after step-up
    // (OIDC redeem or native WebAuthn). Bridge is on by default.
    $bridge_enabled = !array_key_exists('bridge', $this->configuration)
      || !empty($this->configuration['bridge']);
    if ($bridge_enabled) {
      $uuid = (string) $request->query->get('f', '');
      if ($uuid !== '' && $this->sessionBridge->isSatisfied($request, $uuid)) {
        return TRUE;
      }
    }

    // Native WebAuthn: only the bridge (or a future inline assertion) satisfies
    // the gate — a plain download without step-up never passes.
    if ($mode === 'webauthn') {
      return FALSE;
    }

    // Model B: verify a live OIDC token presented at redemption.
    return $this->liveOidcSatisfied($request);
  }

  /**
   * JSON challenge for native WebAuthn step-up.
   */
  private function buildWebauthnApiChallenge(Request $request, string $step_up): JsonResponse {
    $assert_options = Url::fromRoute('file_gate_assurance.webauthn_assert_options', [], [
      'query' => $request->query->all(),
      'absolute' => FALSE,
    ])->toString();
    $assert = Url::fromRoute('file_gate_assurance.webauthn_assert', [], [
      'query' => $request->query->all(),
      'absolute' => FALSE,
    ])->toString();
    $response = new JsonResponse([
      'error' => 'webauthn_required',
      'error_description' => 'Complete a WebAuthn assertion for a registered authenticator, then retry the download with the session bridge cookie.',
      'step_up' => $step_up,
      'assert_options' => $assert_options,
      'assert' => $assert,
    ], Response::HTTP_UNAUTHORIZED);
    $response->headers->set('Cache-Control', 'private, no-store');
    return $response;
  }

  /**
   * Live token path for verify_at=redeem.
   */
  private function liveOidcSatisfied(Request $request): bool {
    $token = $this->bearerToken($request);
    if ($token === NULL) {
      return FALSE;
    }
    $claims = $this->verifier->verify($token, $this->configuration, $request);
    if ($claims === NULL) {
      return FALSE;
    }

    // The decision is driven by `acr` (IdP policy). Empty allowlist ⇒ deny.
    $required_acr = $this->requiredAcrList();
    if ($required_acr === [] || !in_array((string) $claims['acr'], $required_acr, TRUE)) {
      return FALSE;
    }

    // `amr` is advisory: enforced only when the field explicitly requires some.
    $required_amr = array_map('strval', (array) ($this->configuration['required_amr'] ?? []));
    $token_amr = array_map('strval', (array) ($claims['amr'] ?? []));
    if ($required_amr !== [] && array_diff($required_amr, $token_amr) !== []) {
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
   * Builds a 401 JSON challenge (RFC 9470-style WWW-Authenticate).
   */
  private function buildApiChallenge(Request $request, ?string $step_up = NULL): JsonResponse {
    $acr = $this->requiredAcrList();
    $acr_values = implode(' ', $acr);
    $www = 'Bearer error="insufficient_user_authentication"';
    if ($acr_values !== '') {
      $www .= ', acr_values="' . addcslashes($acr_values, '"\\') . '"';
    }
    $step_up ??= Url::fromRoute('file_gate_assurance.step_up', [], [
      'query' => $request->query->all(),
      'absolute' => FALSE,
    ])->toString();
    $bridge = Url::fromRoute('file_gate_assurance.bridge', [], [
      'query' => $request->query->all(),
      'absolute' => FALSE,
    ])->toString();
    $response = new JsonResponse([
      'error' => 'insufficient_user_authentication',
      'error_description' => 'Present a live OIDC access token meeting the required acr, then call the bridge endpoint (or use the step-up page) so a plain-link download can proceed.',
      'acr_values' => $acr,
      'step_up' => $step_up,
      'bridge' => $bridge,
    ], Response::HTTP_UNAUTHORIZED);
    $response->headers->set('WWW-Authenticate', $www);
    $response->headers->set('Cache-Control', 'private, no-store');
    return $response;
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
    // Read via the shield: on stacks with a global authentication provider
    // the raw header was stashed into an attribute pre-routing (GH #56).
    $authorization = AuthorizationShield::authorization($request);
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
    if (!in_array($verify_at, ['redeem', 'mint', 'client_cert', 'webauthn'], TRUE)) {
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
          'webauthn' => $this->t('Native WebAuthn — File Gate is the RP'),
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
      'bridge' => [
        '#type' => 'checkbox',
        '#title' => $this->t('Plain-link session bridge (primary path)'),
        '#default_value' => ($settings['bridge'] ?? TRUE) !== FALSE && ($settings['bridge'] ?? TRUE) !== 0 && ($settings['bridge'] ?? TRUE) !== '0',
        '#description' => $this->t('After a successful OIDC step-up, set a short-lived HttpOnly cookie so the same signed URL works as a normal browser download (Range, Save as…). Recommended on. Disable only if every redeem must present Authorization.'),
      ],
      'bridge_ttl' => [
        '#type' => 'number',
        '#title' => $this->t('Bridge cookie lifetime'),
        '#field_suffix' => $this->t('seconds'),
        '#min' => 15,
        '#max' => 600,
        '#default_value' => (int) ($settings['bridge_ttl'] ?? 120),
      ],
      'step_up_login_url' => [
        '#type' => 'textfield',
        '#title' => $this->t('Step-up login URL (optional)'),
        '#default_value' => $settings['step_up_login_url'] ?? '',
        '#description' => $this->t('Absolute http(s) IdP authorize or front-end login URL (field only — never from the query). Prefer the IdP authorize endpoint so ACR can be requested (GH #42). The step-up page may append <code>return_to</code>.'),
      ],
      'step_up_append_acr' => [
        '#type' => 'checkbox',
        '#title' => $this->t('Append required ACR to step-up URL'),
        '#default_value' => !array_key_exists('step_up_append_acr', $settings) || !empty($settings['step_up_append_acr']),
        '#description' => $this->t('When set, appends accepted <code>acr</code> values as a query parameter so Keycloak (and similar IdPs) prompt for WebAuthn/PIV when the session lacks them.'),
      ],
      'step_up_acr_param' => [
        '#type' => 'textfield',
        '#title' => $this->t('ACR query parameter name'),
        '#default_value' => $settings['step_up_acr_param'] ?? 'acr_values',
        '#description' => $this->t('Keycloak uses <code>acr_values</code>. Other IdPs may use <code>acr_values</code> or a custom claim parameter.'),
      ],
      'session_bridge_sso' => [
        '#type' => 'checkbox',
        '#title' => $this->t('Use Drupal SSO session token for bridge (same-origin)'),
        '#default_value' => !array_key_exists('session_bridge_sso', $settings) || !empty($settings['session_bridge_sso']),
        '#description' => $this->t('When openid_connect is installed, establish the plain-link bridge from the saved access token without browser sessionStorage (GH #41). Still verifies issuer/aud/acr. Disable if access tokens are never File-Gate-audienced.'),
      ],
      'verify_oidc_at_mint' => [
        '#type' => 'checkbox',
        '#title' => $this->t('Verify OIDC token at mint (A2)'),
        '#default_value' => !empty($settings['verify_oidc_at_mint']),
        '#description' => $this->t('Stronger than A1: mint must present a Bearer/DPoP token whose <code>aud</code> is this field’s audience (use RFC 8693 token exchange or an IdP audience mapper). Fail closed when missing or insufficient <code>acr</code>. Requires issuer, audience, and accepted acr values.'),
      ],
      'require_identity_mint' => [
        '#type' => 'checkbox',
        '#title' => $this->t('Require acting account on mint'),
        '#default_value' => !empty($settings['require_identity_mint']),
        '#description' => $this->t('Mint body must include <code>account</code> (user UUID) or <code>uid</code>, and that user must be allowed to download the file. Use for authenticated products so a secret-holding BFF cannot mint without naming a subject.'),
      ],
      'rp_id' => [
        '#type' => 'textfield',
        '#title' => $this->t('WebAuthn RP ID'),
        '#default_value' => $settings['rp_id'] ?? '',
        '#description' => $this->t('Native WebAuthn mode. Effective domain (e.g. <code>files.example.gov</code>). Must match the download host.'),
      ],
      'rp_name' => [
        '#type' => 'textfield',
        '#title' => $this->t('WebAuthn RP name'),
        '#default_value' => $settings['rp_name'] ?? 'File Gate',
      ],
      'origins' => [
        '#type' => 'textarea',
        '#title' => $this->t('WebAuthn allowed origins'),
        '#default_value' => $lines(is_array($settings['origins'] ?? NULL) ? $settings['origins'] : []),
        '#description' => $this->t('One absolute origin per line (e.g. <code>https://files.example.gov</code>). Required for native WebAuthn.'),
      ],
      'webauthn_user_handle' => [
        '#type' => 'textfield',
        '#title' => $this->t('WebAuthn user handle (optional fixed)'),
        '#default_value' => $settings['webauthn_user_handle'] ?? '',
        '#description' => $this->t('If set, only credentials registered under this handle may assert. Otherwise pass <code>wh=</code> matching the mint <code>subject</code> (and grant <code>sh</code>).'),
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
    $settings['verify_at'] = in_array($mode, ['redeem', 'mint', 'client_cert', 'webauthn'], TRUE) ? $mode : 'redeem';
    $settings['aal'] = (int) ($values['aal'] ?? 0);
    $settings['bridge'] = !empty($values['bridge']);
    $settings['bridge_ttl'] = (int) ($values['bridge_ttl'] ?? 120);
    $settings['dpop'] = !empty($values['dpop']);
    $settings['introspect'] = !empty($values['introspect']);
    $settings['leeway'] = (int) ($values['leeway'] ?? 60);
    $settings['verify_oidc_at_mint'] = !empty($values['verify_oidc_at_mint']);
    $settings['require_identity_mint'] = !empty($values['require_identity_mint']);
    $settings['step_up_append_acr'] = !empty($values['step_up_append_acr']);
    $settings['session_bridge_sso'] = !empty($values['session_bridge_sso']);

    $string_keys = [
      'issuer',
      'audience',
      'step_up_login_url',
      'step_up_acr_param',
      'rp_id',
      'rp_name',
      'webauthn_user_handle',
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
    foreach (['required_acr', 'required_amr', 'allowed_subjects', 'origins'] as $key) {
      $list = array_filter(array_map('trim', preg_split('/\R/', (string) ($values[$key] ?? ''))));
      if ($list) {
        $settings[$key] = array_values($list);
      }
    }
    return $settings;
  }

}
