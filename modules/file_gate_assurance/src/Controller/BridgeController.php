<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\Controller;

use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Url;
use Drupal\file\FileInterface;
use Drupal\file_gate\FileGateResolver;
use Drupal\file_gate\GateMethodManager;
use Drupal\file_gate\StackMiddleware\AuthorizationShield;
use Drupal\file_gate_assurance\Plugin\GateMethod\Assurance;
use Drupal\file_gate_assurance\SessionBridge;
use Drupal\file_gate_assurance\SessionOidcToken;
use Drupal\file_gate_assurance\StepUpAuthorizeUrl;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Establishes the assurance session bridge after a live OIDC step-up.
 *
 * Primary plain-link path:
 * 1. Browser GET download without Bearer → 401 / step-up HTML.
 * 2. Client presents OIDC (+ optional DPoP) here with the same grant query,
 *    or same-origin Drupal SSO supplies a session access token (GH #41).
 * 3. Cookie set; client navigates to the same download URL (plain link).
 *
 * Does not stream bytes and does not burn max_uses.
 */
final class BridgeController implements ContainerInjectionInterface {

  /**
   * Constructs the controller.
   */
  public function __construct(
    private readonly EntityRepositoryInterface $entityRepository,
    private readonly FileGateResolver $resolver,
    private readonly GateMethodManager $gateMethodManager,
    private readonly SessionBridge $bridge,
    private readonly LoggerInterface $logger,
    private readonly SessionOidcToken $sessionOidcToken,
    private readonly StepUpAuthorizeUrl $stepUpAuthorizeUrl,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity.repository'),
      $container->get('file_gate.resolver'),
      $container->get('plugin.manager.file_gate.gate_method'),
      $container->get('file_gate_assurance.session_bridge'),
      $container->get('logger.channel.file_gate'),
      $container->get('file_gate_assurance.session_oidc_token'),
      $container->get('file_gate_assurance.step_up_authorize_url'),
    );
  }

  /**
   * Completes step-up and sets the bridge cookie.
   */
  public function establish(Request $request): Response {
    $uuid = (string) $request->query->get('f', '');
    if ($uuid === '') {
      return $this->error('Missing file parameter.', Response::HTTP_BAD_REQUEST);
    }
    $file = $this->entityRepository->loadEntityByUuid('file', $uuid);
    if (!$file instanceof FileInterface) {
      return $this->error('Unknown file.', Response::HTTP_NOT_FOUND);
    }
    $gate = $this->resolver->getGateForFile($file);
    if ($gate === NULL || $gate['method'] !== 'assurance') {
      return $this->error('File is not assurance-gated.', Response::HTTP_UNPROCESSABLE_ENTITY);
    }

    $method = $this->gateMethodManager->createInstance($gate['method'], $gate['settings']);
    if (!$method instanceof Assurance) {
      return $this->error('Assurance method unavailable.', Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    // Cryptographic grant must be valid first (no usage burn).
    if (!$method->signatureValid($file, $request)) {
      $this->logger->warning(
        'Assurance bridge refused: invalid grant for file @uuid from @ip.',
        [
          '@uuid' => $uuid,
          '@ip' => $request->getClientIp() ?? 'unknown',
        ],
      );
      return $this->error('Invalid or expired grant.', Response::HTTP_FORBIDDEN);
    }

    // Live OIDC (+ optional DPoP). Prefer Authorization (raw, or stashed by
    // the AuthorizationShield middleware on stacks with a global provider,
    // GH #56); else same-origin SSO session token from openid_connect when
    // allowed (GH #41).
    $auth_request = $this->requestWithSessionToken($request, $gate['settings']);
    if (!$method->liveAssuranceSatisfied($auth_request)) {
      $this->logger->warning(
        'Assurance bridge refused: OIDC check failed for file @uuid from @ip.',
        [
          '@uuid' => $uuid,
          '@ip' => $request->getClientIp() ?? 'unknown',
        ],
      );
      return $this->challengeJson($request, $method);
    }

    $ttl = (int) ($gate['settings']['bridge_ttl'] ?? SessionBridge::DEFAULT_TTL);
    $cookie = $this->bridge->mintCookie(
      $request,
      $uuid,
      $ttl,
      $request->isSecure(),
    );
    if ($cookie === NULL) {
      return $this->error(
        'Could not mint bridge cookie (no signing secret).',
        Response::HTTP_SERVICE_UNAVAILABLE,
      );
    }

    $download = Url::fromRoute('file_gate.download', [], [
      'query' => $request->query->all(),
      'absolute' => FALSE,
    ])->toString();

    $this->logger->info('Assurance bridge established for file @uuid from @ip.', [
      '@uuid' => $uuid,
      '@ip' => $request->getClientIp() ?? 'unknown',
    ]);

    $response = new JsonResponse([
      'ok' => TRUE,
      'path' => $download,
      'bridge_ttl' => $ttl,
    ]);
    $this->bridge->attach($response, $cookie);
    $response->headers->set('Cache-Control', 'private, no-store');
    return $response;
  }

  /**
   * Minimal HTML step-up page for plain-link browser navigation.
   */
  public function stepUpPage(Request $request): Response {
    $uuid = (string) $request->query->get('f', '');
    // Drop login_url from any query forwarded into bridge/download URLs so a
    // crafted step-up link cannot launder an open redirect into later hops.
    $safe_query = $request->query->all();
    unset($safe_query['login_url']);
    $bridge_path = Url::fromRoute('file_gate_assurance.bridge', [], [
      'query' => $safe_query,
      'absolute' => FALSE,
    ])->toString();
    $download_path = Url::fromRoute('file_gate.download', [], [
      'query' => $safe_query,
      'absolute' => FALSE,
    ])->toString();

    // Integrator injects the access token after IdP login (sessionStorage or
    // window.fileGateAccessToken). login_url is loaded ONLY from the field's
    // step_up_login_url setting — never from the query string (open-redirect
    // defense; GH #40 / d.o #3614254). mode=webauthn uses the WebAuthn API.
    $login = $this->trustedStepUpLoginUrl($uuid);
    $mode = (string) $request->query->get('mode', 'oidc');
    $assert_options = Url::fromRoute('file_gate_assurance.webauthn_assert_options', [], [
      'query' => $safe_query,
      'absolute' => FALSE,
    ])->toString();
    $assert_path = Url::fromRoute('file_gate_assurance.webauthn_assert', [], [
      'query' => $safe_query,
      'absolute' => FALSE,
    ])->toString();
    $bridge_js = json_encode($bridge_path, JSON_THROW_ON_ERROR);
    $download_js = json_encode($download_path, JSON_THROW_ON_ERROR);
    $login_js = json_encode($login !== '' ? $login : NULL, JSON_THROW_ON_ERROR);
    $mode_js = json_encode($mode, JSON_THROW_ON_ERROR);
    $assert_opt_js = json_encode($assert_options, JSON_THROW_ON_ERROR);
    $assert_js = json_encode($assert_path, JSON_THROW_ON_ERROR);

    $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>File Gate — step up</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#111}
    code{background:#f4f4f5;padding:.1rem .3rem;border-radius:3px}
    .err{color:#b91c1c;margin-top:1rem}
    .ok{color:#047857}
    button{font:inherit;padding:.5rem 1rem;cursor:pointer}
  </style>
</head>
<body>
  <h1>Confirm hardware-backed access</h1>
  <p id="blurb">This download requires phishing-resistant authentication. Completing step-up sets a short-lived cookie so the same link opens as a normal download.</p>
  <p id="status">Preparing…</p>
  <p id="error" class="err" hidden></p>
  <p><button type="button" id="retry" hidden>Retry</button></p>
  <script>
(function () {
  const JWS_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
  const bridgePath = {$bridge_js};
  const downloadPath = {$download_js};
  const loginUrl = {$login_js};
  const mode = {$mode_js};
  const assertOptionsPath = {$assert_opt_js};
  const assertPath = {$assert_js};
  const status = document.getElementById('status');
  const err = document.getElementById('error');
  const retry = document.getElementById('retry');
  const blurb = document.getElementById('blurb');

  function showError(msg) {
    err.hidden = false;
    err.textContent = msg;
    status.textContent = 'Step-up failed.';
    retry.hidden = false;
  }

  function b64urlToBuffer(b64) {
    const pad = '='.repeat((4 - (b64.length % 4)) % 4);
    const str = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
    return buf.buffer;
  }

  function bufferToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }

  // Prefer same-origin SSO session (credentials include cookies) so a Drupal
  // openid_connect login can satisfy bridge without sessionStorage (GH #41).
  async function trySessionBridge() {
    const res = await fetch(bridgePath, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' },
    });
    return res;
  }

  function token() {
    if (typeof window.fileGateAccessToken === 'string' && window.fileGateAccessToken) {
      return window.fileGateAccessToken;
    }
    try {
      return sessionStorage.getItem('file_gate_access_token') || '';
    } catch (e) {
      return '';
    }
  }

  async function runOidc() {
    status.textContent = 'Checking signed-in session…';
    let res = await trySessionBridge();
    let data = await res.json().catch(function () { return {}; });
    if (res.ok) {
      status.textContent = 'Opening download…';
      status.className = 'ok';
      location.replace(data.path || downloadPath);
      return;
    }
    const t = token();
    // A malformed stored value (for example a pasted JSON blob or a value with
    // non-Latin-1 characters) would make fetch throw a cryptic TypeError when
    // the Authorization header is built. Fail early with a useful message.
    if (t && !JWS_RE.test(t)) {
      console.error('file_gate: the stored access token is not compact-JWS shaped (expected three dot-separated base64url segments); refusing to build the Authorization header.');
      showError('The provided access token is not a valid compact JWS (expected xxxxx.yyyyy.zzzzz). Sign in again, or clear the stored token (window.fileGateAccessToken or sessionStorage.file_gate_access_token) and retry.');
      return;
    }
    if (!t) {
      if (loginUrl) {
        status.textContent = 'Redirecting to sign in…';
        const ret = location.href;
        // loginUrl may already include acr_values (field-built authorize URL).
        location.href = loginUrl + (loginUrl.indexOf('?') >= 0 ? '&' : '?') + 'return_to=' + encodeURIComponent(ret);
        return;
      }
      showError('No access token and no SSO session. After IdP login, set sessionStorage.file_gate_access_token or window.fileGateAccessToken, then retry. See docs/assurance-redeem.md.');
      return;
    }
    status.textContent = 'Verifying assurance…';
    const headers = { 'Authorization': 'Bearer ' + t, 'Accept': 'application/json' };
    if (typeof window.fileGateDpopProof === 'string' && window.fileGateDpopProof) {
      // DPoP proofs are compact JWS too — apply the same shape gate.
      if (!JWS_RE.test(window.fileGateDpopProof)) {
        console.error('file_gate: window.fileGateDpopProof is not compact-JWS shaped (expected three dot-separated base64url segments); refusing to build the DPoP headers.');
        showError('The provided DPoP proof is not a valid compact JWS (expected xxxxx.yyyyy.zzzzz). Set window.fileGateDpopProof to a freshly signed proof and retry.');
        return;
      }
      headers['Authorization'] = 'DPoP ' + t;
      headers['DPoP'] = window.fileGateDpopProof;
    }
    res = await fetch(bridgePath, { method: 'POST', headers, credentials: 'same-origin' });
    data = await res.json().catch(function () { return {}; });
    if (!res.ok) {
      showError(data.error || ('HTTP ' + res.status));
      return;
    }
    status.textContent = 'Opening download…';
    status.className = 'ok';
    location.replace(data.path || downloadPath);
  }

  async function runWebauthn() {
    if (!window.PublicKeyCredential) {
      showError('This browser does not support WebAuthn.');
      return;
    }
    blurb.textContent = 'Use your security key or platform authenticator. Completing the check sets a short-lived cookie so this link downloads normally.';
    status.textContent = 'Requesting challenge…';
    const optRes = await fetch(assertOptionsPath, { method: 'POST', credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
    const optBody = await optRes.json().catch(function () { return {}; });
    if (!optRes.ok) {
      showError(optBody.error || ('HTTP ' + optRes.status));
      return;
    }
    const options = optBody.options || {};
    if (options.challenge) options.challenge = b64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(function (c) {
        c.id = b64urlToBuffer(c.id);
        return c;
      });
    }
    status.textContent = 'Touch your authenticator…';
    const cred = await navigator.credentials.get({ publicKey: options });
    if (!cred) {
      showError('No credential returned.');
      return;
    }
    const payload = {
      challenge_id: optBody.challenge_id,
      credential: {
        id: cred.id,
        rawId: bufferToB64url(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
          authenticatorData: bufferToB64url(cred.response.authenticatorData),
          signature: bufferToB64url(cred.response.signature),
          userHandle: cred.response.userHandle ? bufferToB64url(cred.response.userHandle) : null
        }
      }
    };
    status.textContent = 'Verifying…';
    const res = await fetch(assertPath, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json().catch(function () { return {}; });
    if (!res.ok) {
      showError(data.error || ('HTTP ' + res.status));
      return;
    }
    status.textContent = 'Opening download…';
    status.className = 'ok';
    location.replace(data.path || downloadPath);
  }

  async function run() {
    try {
      if (mode === 'webauthn') {
        await runWebauthn();
      } else {
        await runOidc();
      }
    } catch (e) {
      // Raw exception detail belongs in the console, not the page.
      console.error(e);
      showError('Step-up failed — see the browser console for details.');
    }
  }

  retry.addEventListener('click', function () {
    err.hidden = true;
    retry.hidden = true;
    run();
  });
  run();
})();
  </script>
</body>
</html>
HTML;

    $response = new Response($html, Response::HTTP_OK, [
      'Content-Type' => 'text/html; charset=UTF-8',
      'Cache-Control' => 'private, no-store',
      'X-Robots-Tag' => 'noindex',
    ]);
    // If file unknown, still show page but bridge will fail closed.
    if ($uuid === '') {
      $response->setStatusCode(Response::HTTP_BAD_REQUEST);
    }
    return $response;
  }

  /**
   * Field-configured IdP login URL for the gated file, or empty.
   *
   * Only http(s) absolute URLs or site-relative paths (a single leading
   * slash; same-origin by construction) from gate method settings are
   * accepted (GH #62). Query parameters named login_url are intentionally
   * ignored.
   *
   * @param string $uuid
   *   File UUID from the step-up query.
   *
   * @return string
   *   Trusted login URL or ''.
   */
  private function trustedStepUpLoginUrl(string $uuid): string {
    if ($uuid === '') {
      return '';
    }
    $file = $this->entityRepository->loadEntityByUuid('file', $uuid);
    if (!$file instanceof FileInterface) {
      return '';
    }
    $gate = $this->resolver->getGateForFile($file);
    if ($gate === NULL || $gate['method'] !== 'assurance') {
      return '';
    }
    $login = trim((string) ($gate['settings']['step_up_login_url'] ?? ''));
    if ($login === '') {
      return '';
    }
    // Absolute http(s), or a site-relative path with a single leading slash —
    // blocks javascript:, //network-path references, and other open
    // redirects (GH #62).
    if (!$this->stepUpAuthorizeUrl->isTrustedBase($login)) {
      $this->logger->warning('Ignored untrusted step_up_login_url for file @uuid.', [
        '@uuid' => $uuid,
      ]);
      return '';
    }
    $settings = $gate['settings'];
    $acr = array_values(array_filter(array_map('strval', (array) ($settings['required_acr'] ?? []))));
    // Append acr_values by default for Keycloak hardware ACR prompts (GH #42).
    $append_acr = !array_key_exists('step_up_append_acr', $settings)
      || !empty($settings['step_up_append_acr']);
    $acr_param = trim((string) ($settings['step_up_acr_param'] ?? 'acr_values'));
    if ($acr_param === '') {
      $acr_param = 'acr_values';
    }
    // Fail closed: a base that passes isTrustedBase() but fails build()'s
    // parsing must not leak through as the raw setting — the built value is
    // the only thing ever embedded in the page (GH #63 review).
    return $this->stepUpAuthorizeUrl->build($login, $acr, '', [
      'append_acr' => $append_acr,
      'append_return' => FALSE,
      'acr_param' => $acr_param,
    ]);
  }

  /**
   * Uses openid_connect session token when Authorization is absent (GH #41).
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   Incoming bridge request.
   * @param array<string, mixed> $settings
   *   Assurance field settings.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   Same request, or a duplicate with Bearer from the SSO session.
   */
  private function requestWithSessionToken(Request $request, array $settings): Request {
    // Read via the shield: a stashed Bearer/DPoP value counts as presented
    // Authorization even though the raw header was removed pre-routing
    // (GH #56).
    $authorization = AuthorizationShield::authorization($request);
    if ($authorization !== '') {
      return $request;
    }
    // Opt-out: session_bridge_sso: false disables SSO token pickup.
    if (array_key_exists('session_bridge_sso', $settings) && empty($settings['session_bridge_sso'])) {
      return $request;
    }
    $token = $this->sessionOidcToken->accessToken();
    if ($token === NULL) {
      return $request;
    }
    $dup = $request->duplicate();
    $dup->headers->set('Authorization', 'Bearer ' . $token);
    return $dup;
  }

  /**
   * JSON error helper.
   */
  private function error(string $message, int $status): JsonResponse {
    $response = new JsonResponse(['error' => $message], $status);
    $response->headers->set('Cache-Control', 'private, no-store');
    return $response;
  }

  /**
   * RFC 9470-style challenge when token is missing/low assurance.
   */
  private function challengeJson(Request $request, Assurance $method): JsonResponse {
    $acr = $method->requiredAcrList();
    $acr_values = implode(' ', $acr);
    $www = 'Bearer error="insufficient_user_authentication"';
    if ($acr_values !== '') {
      $www .= ', acr_values="' . addcslashes($acr_values, '"\\') . '"';
    }
    $response = new JsonResponse([
      'error' => 'insufficient_user_authentication',
      'error_description' => 'Present a live OIDC access token meeting the required acr (and DPoP if configured).',
      'acr_values' => $acr,
      'bridge' => Url::fromRoute('file_gate_assurance.bridge', [], [
        'query' => $request->query->all(),
        'absolute' => FALSE,
      ])->toString(),
    ], Response::HTTP_UNAUTHORIZED);
    $response->headers->set('WWW-Authenticate', $www);
    $response->headers->set('Cache-Control', 'private, no-store');
    return $response;
  }

}
