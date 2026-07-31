<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\file_gate\SecretRegistryInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Short-lived HttpOnly cookie proving OIDC assurance for a plain-link download.
 *
 * Primary high-assurance path: browser opens the signed download URL → step-up
 * establishes this cookie (after live OIDC/DPoP) → same plain URL streams the
 * file. The cookie does not replace the HMAC grant; it only satisfies the
 * assurance layer so Authorization headers are not required on the GET.
 *
 * Cookie value is payload.hmac (base64url), signed with the site download
 * secret (or named secret from k=). Fail closed without secret material.
 */
final class SessionBridge {

  /**
   * Cookie name (short; sent only under /api/file-gate).
   */
  public const COOKIE_NAME = 'FG_AB';

  /**
   * Default bridge lifetime in seconds.
   */
  public const DEFAULT_TTL = 120;

  /**
   * Constructs the bridge service.
   *
   * @param \Drupal\file_gate\SecretRegistryInterface $secrets
   *   Secret registry (HMAC material).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   Time service.
   */
  public function __construct(
    private readonly SecretRegistryInterface $secrets,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Whether the request carries a valid bridge cookie for this file + grant.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The download request (query carries f, exp, aal, sh, jti, k, …).
   * @param string $file_uuid
   *   Expected file UUID.
   *
   * @return bool
   *   TRUE when the cookie is present, unexpired, bound, and HMAC-valid.
   */
  public function isSatisfied(Request $request, string $file_uuid): bool {
    $raw = (string) $request->cookies->get(self::COOKIE_NAME, '');
    $payload = $this->decodeAndVerify($raw, $this->secretIdFromRequest($request));
    if ($payload === NULL) {
      return FALSE;
    }
    if (($payload['f'] ?? '') !== $file_uuid) {
      return FALSE;
    }
    if ((int) ($payload['exp'] ?? 0) <= $this->time->getRequestTime()) {
      return FALSE;
    }
    // Bind to the same grant identity the URL carries (anti-swap).
    if (!$this->queryMatchesPayload($request, $payload)) {
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Builds a Set-Cookie for a successful step-up.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The bridge request (grant query + authenticated secret context).
   * @param string $file_uuid
   *   File UUID.
   * @param int $ttl
   *   Bridge lifetime seconds (clamped 15–600).
   * @param bool $secure
   *   Whether the cookie requires HTTPS.
   *
   * @return \Symfony\Component\HttpFoundation\Cookie|null
   *   The cookie, or NULL when no signing material is available.
   */
  public function mintCookie(Request $request, string $file_uuid, int $ttl = self::DEFAULT_TTL, bool $secure = TRUE): ?Cookie {
    $ttl = max(15, min(600, $ttl));
    $now = $this->time->getRequestTime();
    $grant_exp = (int) $request->query->get('exp', 0);
    $exp = $now + $ttl;
    if ($grant_exp > 0) {
      $exp = min($exp, $grant_exp);
    }
    if ($exp <= $now) {
      return NULL;
    }
    $payload = [
      'v' => 1,
      'f' => $file_uuid,
      'exp' => $exp,
      'gexp' => $grant_exp,
      'aal' => (string) $request->query->get('aal', ''),
      'sh' => (string) $request->query->get('sh', ''),
      'jti' => (string) $request->query->get('jti', ''),
      'sig' => (string) $request->query->get('sig', ''),
    ];
    $secret_id = $this->secretIdFromRequest($request);
    $encoded = $this->encodeAndSign($payload, $secret_id);
    if ($encoded === NULL) {
      return NULL;
    }
    return Cookie::create(self::COOKIE_NAME)
      ->withValue($encoded)
      ->withExpires($exp)
      ->withPath('/api/file-gate')
      ->withSecure($secure)
      ->withHttpOnly(TRUE)
      ->withSameSite('lax');
  }

  /**
   * Attaches a bridge cookie to a response.
   */
  public function attach(Response $response, Cookie $cookie): Response {
    $response->headers->setCookie($cookie);
    return $response;
  }

  /**
   * Clears the bridge cookie.
   */
  public function clearCookie(bool $secure = TRUE): Cookie {
    return Cookie::create(self::COOKIE_NAME)
      ->withValue('')
      ->withExpires(1)
      ->withPath('/api/file-gate')
      ->withSecure($secure)
      ->withHttpOnly(TRUE)
      ->withSameSite('lax');
  }

  /**
   * Encodes and HMACs a bridge payload.
   *
   * @param array<string, mixed> $payload
   *   Bridge claims.
   * @param string|null $secret_id
   *   Named secret id or NULL for legacy.
   *
   * @return string|null
   *   payload.hmac or NULL.
   */
  private function encodeAndSign(array $payload, ?string $secret_id): ?string {
    $secret = $this->secrets->secretMaterial($secret_id);
    if ($secret === '') {
      $secret = $this->secrets->secretMaterial(NULL);
    }
    if ($secret === '') {
      return NULL;
    }
    $body = $this->b64(json_encode($payload, JSON_THROW_ON_ERROR));
    $mac = $this->b64(hash_hmac('sha256', $body, $secret, TRUE));
    return $body . '.' . $mac;
  }

  /**
   * Decodes and verifies a bridge cookie value.
   *
   * @param string $raw
   *   Cookie value.
   * @param string|null $secret_id
   *   Named secret id or NULL for legacy.
   *
   * @return array<string, mixed>|null
   *   Decoded payload or NULL.
   */
  private function decodeAndVerify(string $raw, ?string $secret_id): ?array {
    if ($raw === '' || !str_contains($raw, '.')) {
      return NULL;
    }
    [$body, $mac] = explode('.', $raw, 2);
    if ($body === '' || $mac === '') {
      return NULL;
    }
    $secret = $this->secrets->secretMaterial($secret_id);
    if ($secret === '') {
      $secret = $this->secrets->secretMaterial(NULL);
    }
    if ($secret === '') {
      return NULL;
    }
    $expected = $this->b64(hash_hmac('sha256', $body, $secret, TRUE));
    if (!hash_equals($expected, $mac)) {
      return NULL;
    }
    try {
      $json = $this->ub64($body);
      $payload = json_decode($json, TRUE, 16, JSON_THROW_ON_ERROR);
    }
    catch (\JsonException) {
      return NULL;
    }
    return is_array($payload) ? $payload : NULL;
  }

  /**
   * Ensures the cookie was issued for this exact grant URL (anti-swap).
   */
  private function queryMatchesPayload(Request $request, array $payload): bool {
    $checks = [
      'sig' => (string) $request->query->get('sig', ''),
      'jti' => (string) $request->query->get('jti', ''),
      'aal' => (string) $request->query->get('aal', ''),
      'sh' => (string) $request->query->get('sh', ''),
    ];
    foreach ($checks as $key => $query_value) {
      $bound = (string) ($payload[$key] ?? '');
      // Empty on both sides is fine (claim not used); mismatch is not.
      if ($bound !== $query_value) {
        return FALSE;
      }
    }
    return TRUE;
  }

  /**
   * Reads k= from the grant query.
   */
  private function secretIdFromRequest(Request $request): ?string {
    if (!$request->query->has('k')) {
      return NULL;
    }
    $k = (string) $request->query->get('k');
    return $k !== '' ? $k : NULL;
  }

  /**
   * Base64url-encodes without padding.
   */
  private function b64(string $bin): string {
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
  }

  /**
   * Base64url-decodes.
   */
  private function ub64(string $b64): string {
    $pad = 4 - (strlen($b64) % 4);
    if ($pad < 4) {
      $b64 .= str_repeat('=', $pad);
    }
    $raw = base64_decode(strtr($b64, '-_', '+/'), TRUE);
    if ($raw === FALSE) {
      throw new \JsonException('Invalid base64');
    }
    return $raw;
  }

}
