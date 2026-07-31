<?php

declare(strict_types=1);

namespace Drupal\file_gate\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\file_gate\SecretRegistryInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;

/**
 * Short-lived HttpOnly cookie for OTP redeem without query secrets (GH #43).
 *
 * After POST /api/file-gate/otp/session validates email+code, the cookie binds
 * file UUID + normalized email for a brief window so GET download need not put
 * otp/email in the query string (logs, Referer, history).
 */
final class OtpSession {

  public const COOKIE_NAME = 'FG_OTP';

  public const DEFAULT_TTL = 120;

  /**
   * Constructs the OTP session helper.
   */
  public function __construct(
    private readonly SecretRegistryInterface $secrets,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Whether the request cookie proves OTP for this file (and optional email).
   */
  public function isSatisfied(Request $request, string $file_uuid, string $email = ''): bool {
    $payload = $this->decode((string) $request->cookies->get(self::COOKIE_NAME, ''));
    if ($payload === NULL) {
      return FALSE;
    }
    if (($payload['f'] ?? '') !== $file_uuid) {
      return FALSE;
    }
    if ((int) ($payload['exp'] ?? 0) <= $this->time->getRequestTime()) {
      return FALSE;
    }
    if ($email !== '' && ($payload['e'] ?? '') !== $email) {
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Email bound into a valid cookie for this file, or empty.
   */
  public function boundEmail(Request $request, string $file_uuid): string {
    $payload = $this->decode((string) $request->cookies->get(self::COOKIE_NAME, ''));
    if ($payload === NULL || ($payload['f'] ?? '') !== $file_uuid) {
      return '';
    }
    if ((int) ($payload['exp'] ?? 0) <= $this->time->getRequestTime()) {
      return '';
    }
    return (string) ($payload['e'] ?? '');
  }

  /**
   * Mints a cookie after a successful OTP check.
   */
  public function mintCookie(string $file_uuid, string $email, int $ttl = self::DEFAULT_TTL, bool $secure = TRUE): ?Cookie {
    $ttl = max(30, min(600, $ttl));
    $exp = $this->time->getRequestTime() + $ttl;
    $payload = [
      'v' => 1,
      'f' => $file_uuid,
      'e' => $email,
      'exp' => $exp,
    ];
    $encoded = $this->encode($payload);
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
   * Signs a payload for the cookie value.
   *
   * @param array<string, mixed> $payload
   *   Cookie claims.
   *
   * @return string|null
   *   Encoded value, or NULL without secret material.
   */
  private function encode(array $payload): ?string {
    $secret = $this->secrets->secretMaterial(NULL);
    $materials = $this->secrets->validationMaterials(NULL);
    if ($secret === '' && $materials !== []) {
      $secret = $materials[0];
    }
    // Prefer any available secret (named-only deploys).
    if ($secret === '') {
      foreach ($this->secrets->namedSecretIds() as $id) {
        $secret = $this->secrets->secretMaterial($id);
        if ($secret !== '') {
          break;
        }
      }
    }
    if ($secret === '') {
      return NULL;
    }
    $body = $this->b64(json_encode($payload, JSON_THROW_ON_ERROR));
    $mac = $this->b64(hash_hmac('sha256', $body, $secret, TRUE));
    return $body . '.' . $mac;
  }

  /**
   * Verifies and decodes a cookie value.
   *
   * @param string $raw
   *   Cookie raw value.
   *
   * @return array<string, mixed>|null
   *   Payload or NULL.
   */
  private function decode(string $raw): ?array {
    if ($raw === '' || !str_contains($raw, '.')) {
      return NULL;
    }
    [$body, $mac] = explode('.', $raw, 2);
    $materials = $this->secrets->validationMaterials(NULL);
    foreach ($this->secrets->namedSecretIds() as $id) {
      foreach ($this->secrets->validationMaterials($id) as $m) {
        $materials[] = $m;
      }
    }
    $materials = array_values(array_unique(array_filter($materials)));
    if ($materials === []) {
      return NULL;
    }
    $ok = FALSE;
    foreach ($materials as $secret) {
      $expected = $this->b64(hash_hmac('sha256', $body, $secret, TRUE));
      if (hash_equals($expected, $mac)) {
        $ok = TRUE;
        break;
      }
    }
    if (!$ok) {
      return NULL;
    }
    try {
      $payload = json_decode($this->ub64($body), TRUE, 16, JSON_THROW_ON_ERROR);
    }
    catch (\JsonException) {
      return NULL;
    }
    return is_array($payload) ? $payload : NULL;
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
