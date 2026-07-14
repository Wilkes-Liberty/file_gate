<?php

declare(strict_types=1);

namespace Drupal\file_gate\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Flood\FloodInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Shared-secret authentication for File Gate's server-to-server endpoints.
 *
 * The mint and revoke endpoints are both called server-to-server by a trusted
 * back end and authenticate the caller with the same shared secret (the one
 * that doubles as the HMAC signing key). This trait single-sources that
 * security-sensitive decision so the two controllers cannot drift: it fails
 * closed when no secret is configured, compares the presented secret in
 * constant time, and applies the per-IP flood limit.
 */
trait SharedSecretAuthTrait {

  /**
   * Per-IP limit for failed shared-secret authentication attempts.
   */
  private const FAILED_AUTH_LIMIT = 10;

  /**
   * Per-IP window (seconds) for failed shared-secret authentication attempts.
   */
  private const FAILED_AUTH_WINDOW = 60;

  /**
   * Authenticates a server-to-server request and applies the flood limit.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming request.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory (reads the secret and flood settings).
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The File Gate logger channel (records fail-closed and auth failures).
   * @param string $flood_event
   *   The flood event name that scopes the rate limit (and labels the log
   *   entries) for this endpoint, e.g. "file_gate.mint".
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse|null
   *   An error response to return as-is (503 when no secret is configured, 401
   *   for a bad/absent secret, 429 when rate limited), or NULL when the caller
   *   is authenticated and within the flood limit.
   */
  protected function authenticateSharedSecret(Request $request, ConfigFactoryInterface $config_factory, FloodInterface $flood, LoggerInterface $logger, string $flood_event): ?JsonResponse {
    $config = $config_factory->get('file_gate.settings');
    $secret = (string) $config->get('download_secret');
    $ip = $request->getClientIp() ?? '0.0.0.0';

    // Fail closed: with no secret nothing can be authenticated or signed, so
    // refuse outright rather than accept an unverifiable caller.
    if ($secret === '') {
      $logger->warning('@event refused: no File Gate secret is configured (failing closed).', [
        '@event' => $flood_event,
      ]);
      return new JsonResponse(['error' => 'File Gate is not configured.'], Response::HTTP_SERVICE_UNAVAILABLE);
    }

    // Authenticate the caller (constant-time comparison).
    $provided = $this->providedSecret($request);
    if ($provided === NULL || !hash_equals($secret, $provided)) {
      $failed_auth_event = $flood_event . '.auth_fail';
      if (!$flood->isAllowed($failed_auth_event, self::FAILED_AUTH_LIMIT, self::FAILED_AUTH_WINDOW, $ip)) {
        return new JsonResponse(['error' => 'Too many requests.'], Response::HTTP_TOO_MANY_REQUESTS);
      }
      $flood->register($failed_auth_event, self::FAILED_AUTH_WINDOW, $ip);

      // Security event: someone hit a server-to-server endpoint with a
      // bad/absent secret.
      $logger->warning('@event authentication failed from @ip.', [
        '@event' => $flood_event,
        '@ip' => $ip,
      ]);
      return new JsonResponse(['error' => 'Unauthorized.'], Response::HTTP_UNAUTHORIZED, [
        'WWW-Authenticate' => 'Basic realm="file-gate"',
      ]);
    }

    // Basic abuse resistance on a publicly reachable path.
    $limit = (int) ($config->get('flood_limit') ?: 50);
    $window = (int) ($config->get('flood_window') ?: 60);
    if (!$flood->isAllowed($flood_event, $limit, $window, $ip)) {
      return new JsonResponse(['error' => 'Too many requests.'], Response::HTTP_TOO_MANY_REQUESTS);
    }
    $flood->register($flood_event, $window, $ip);

    return NULL;
  }

  /**
   * Extracts the caller-provided secret from the request.
   *
   * Accepts either an HTTP Basic Authorization password (so the secret stays
   * out of the URL and access logs) or an X-File-Gate-Secret header.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return string|null
   *   The provided secret, or NULL if none was supplied.
   */
  protected function providedSecret(Request $request): ?string {
    $authorization = (string) $request->headers->get('Authorization', '');
    if (str_starts_with($authorization, 'Basic ')) {
      $decoded = base64_decode(substr($authorization, 6), TRUE);
      if ($decoded !== FALSE && str_contains($decoded, ':')) {
        [, $password] = explode(':', $decoded, 2);
        return $password;
      }
    }
    $header = $request->headers->get('X-File-Gate-Secret');
    return $header !== NULL ? (string) $header : NULL;
  }

}
