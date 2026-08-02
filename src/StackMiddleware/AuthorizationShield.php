<?php

declare(strict_types=1);

namespace Drupal\file_gate\StackMiddleware;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Shields File Gate token endpoints from global authentication providers.
 *
 * Drupal authenticates global providers (simple_oauth's is registered
 * global: TRUE) at KernelEvents::REQUEST priority 300 — before routing — so a
 * foreign IdP Bearer token on a File Gate endpoint is 401'd by the provider
 * before the route's controller can validate it. A route _auth option cannot
 * help: it is consulted only after routing (GH #56 / d.o #3614535).
 *
 * Middlewares run before all kernel event subscribers, so this stashes the
 * Bearer/DPoP Authorization value into a request attribute and removes the
 * header — for File Gate's own token endpoints only. Handlers read the token
 * via static::authorization(), which falls back to the live header on stacks
 * where no interceptor exists. Basic credentials (the service-secret form) and
 * every other route pass through untouched.
 */
final class AuthorizationShield implements HttpKernelInterface {

  /**
   * Request attribute holding the stashed Authorization header value.
   */
  public const ATTRIBUTE = 'file_gate.authorization';

  /**
   * Exact paths whose handlers validate IdP Bearer/DPoP tokens themselves.
   *
   * Deliberately excludes permission-gated routes (webauthn/register*,
   * credentials) where a provider-authenticated Drupal account is legitimate.
   */
  private const PATHS = [
    '/api/file-gate/download',
    '/api/file-gate/assurance/bridge',
  ];

  public function __construct(
    private readonly HttpKernelInterface $httpKernel,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = TRUE): Response {
    if (in_array($request->getPathInfo(), self::PATHS, TRUE)) {
      $authorization = (string) $request->headers->get('Authorization', '');
      // Case-insensitive: RFC 7235 auth schemes are case-insensitive and the
      // downstream reader accepts any case, so the shield must be as broad.
      if (stripos($authorization, 'Bearer ') === 0 || stripos($authorization, 'DPoP ') === 0) {
        $request->attributes->set(self::ATTRIBUTE, $authorization);
        $request->headers->remove('Authorization');
      }
    }
    return $this->httpKernel->handle($request, $type, $catch);
  }

  /**
   * The effective Authorization value: stashed by the shield, or live header.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return string
   *   The Authorization value, or an empty string when absent.
   */
  public static function authorization(Request $request): string {
    $stashed = $request->attributes->get(self::ATTRIBUTE);
    if (is_string($stashed) && $stashed !== '') {
      return $stashed;
    }
    return (string) $request->headers->get('Authorization', '');
  }

}
