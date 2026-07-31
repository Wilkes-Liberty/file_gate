<?php

declare(strict_types=1);

namespace Drupal\file_gate\Controller;

use Drupal\Core\Flood\FloodInterface;
use Drupal\file_gate\ActiveSecret;
use Drupal\file_gate\SecretRegistryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Shared-secret authentication for File Gate's server-to-server endpoints.
 *
 * Mint, revoke, and OTP authenticate with the same credential resolution:
 * legacy download_secret (whole corpus) or a named secret (field-scoped).
 * On success the request attribute file_gate.secret_id is set (NULL = legacy).
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
   * @param \Drupal\file_gate\SecretRegistryInterface $secrets
   *   The secret registry.
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The File Gate logger channel.
   * @param string $flood_event
   *   Flood event name, e.g. "file_gate.mint".
   * @param int $flood_limit
   *   Successful-request flood limit (from config).
   * @param int $flood_window
   *   Successful-request flood window in seconds.
   * @param \Drupal\file_gate\ActiveSecret|null $active_secret
   *   Optional request-cycle holder for the secret id (for mint signing).
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse|null
   *   Error response, or NULL when authenticated (secret id on the request).
   */
  protected function authenticateSharedSecret(
    Request $request,
    SecretRegistryInterface $secrets,
    FloodInterface $flood,
    LoggerInterface $logger,
    string $flood_event,
    int $flood_limit = 50,
    int $flood_window = 60,
    ?ActiveSecret $active_secret = NULL,
  ): ?JsonResponse {
    $ip = $request->getClientIp() ?? '0.0.0.0';

    // Fail closed: with no secret material nothing can be authenticated.
    if (!$secrets->hasAnySecret()) {
      $logger->warning('@event refused: no File Gate secret is configured (failing closed).', [
        '@event' => $flood_event,
      ]);
      return new JsonResponse(['error' => 'File Gate is not configured.'], Response::HTTP_SERVICE_UNAVAILABLE);
    }

    $credentials = $secrets->resolveCredentials($request);
    if ($credentials === NULL) {
      $failed_auth_event = $flood_event . '.auth_fail';
      if (!$flood->isAllowed($failed_auth_event, self::FAILED_AUTH_LIMIT, self::FAILED_AUTH_WINDOW, $ip)) {
        return new JsonResponse(['error' => 'Too many requests.'], Response::HTTP_TOO_MANY_REQUESTS);
      }
      $flood->register($failed_auth_event, self::FAILED_AUTH_WINDOW, $ip);

      $logger->warning('@event authentication failed from @ip.', [
        '@event' => $flood_event,
        '@ip' => $ip,
      ]);
      return new JsonResponse(['error' => 'Unauthorized.'], Response::HTTP_UNAUTHORIZED, [
        'WWW-Authenticate' => 'Basic realm="file-gate"',
      ]);
    }

    // Stash the secret id for mint scope checks and HMAC key selection.
    // NULL = legacy download_secret (unscoped whole-corpus credential).
    $request->attributes->set(SecretRegistryInterface::REQUEST_ATTR_SECRET_ID, $credentials['id']);
    $active_secret?->set($credentials['id']);

    $limit = $flood_limit > 0 ? $flood_limit : 50;
    $window = $flood_window > 0 ? $flood_window : 60;
    if (!$flood->isAllowed($flood_event, $limit, $window, $ip)) {
      return new JsonResponse(['error' => 'Too many requests.'], Response::HTTP_TOO_MANY_REQUESTS);
    }
    $flood->register($flood_event, $window, $ip);

    return NULL;
  }

}
