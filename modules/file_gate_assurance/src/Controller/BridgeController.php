<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\Controller;

use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Url;
use Drupal\file\FileInterface;
use Drupal\file_gate\FileGateResolver;
use Drupal\file_gate\GateMethodManager;
use Drupal\file_gate_assurance\Plugin\GateMethod\Assurance;
use Drupal\file_gate_assurance\SessionBridge;
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
 * 2. Client presents OIDC (+ optional DPoP) here with the same grant query.
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

    // Live OIDC (+ optional DPoP): same as redeem, no cookie fallback.
    if (!$method->liveAssuranceSatisfied($request)) {
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
    $bridge_path = Url::fromRoute('file_gate_assurance.bridge', [], [
      'query' => $request->query->all(),
      'absolute' => FALSE,
    ])->toString();
    $download_path = Url::fromRoute('file_gate.download', [], [
      'query' => $request->query->all(),
      'absolute' => FALSE,
    ])->toString();

    // Integrator injects the access token after IdP login (sessionStorage or
    // window.fileGateAccessToken). Optional login_url in query from challenge.
    // mode=webauthn uses navigator.credentials.get() instead of OIDC.
    $login = htmlspecialchars((string) $request->query->get('login_url', ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $mode = (string) $request->query->get('mode', 'oidc');
    $assert_options = Url::fromRoute('file_gate_assurance.webauthn_assert_options', [], [
      'query' => $request->query->all(),
      'absolute' => FALSE,
    ])->toString();
    $assert_path = Url::fromRoute('file_gate_assurance.webauthn_assert', [], [
      'query' => $request->query->all(),
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
    const t = token();
    if (!t) {
      if (loginUrl) {
        status.textContent = 'Redirecting to sign in…';
        const ret = location.href;
        location.href = loginUrl + (loginUrl.indexOf('?') >= 0 ? '&' : '?') + 'return_to=' + encodeURIComponent(ret);
        return;
      }
      showError('No access token. After IdP login, set sessionStorage.file_gate_access_token or window.fileGateAccessToken, then retry. See docs/assurance-redeem.md.');
      return;
    }
    status.textContent = 'Verifying assurance…';
    const headers = { 'Authorization': 'Bearer ' + t, 'Accept': 'application/json' };
    if (typeof window.fileGateDpopProof === 'string' && window.fileGateDpopProof) {
      headers['Authorization'] = 'DPoP ' + t;
      headers['DPoP'] = window.fileGateDpopProof;
    }
    const res = await fetch(bridgePath, { method: 'POST', headers, credentials: 'same-origin' });
    const data = await res.json().catch(function () { return {}; });
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
      showError(e && e.message ? e.message : String(e));
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
