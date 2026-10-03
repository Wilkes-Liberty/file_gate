<?php

declare(strict_types=1);

namespace Drupal\file_gate\StackMiddleware;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\language\Plugin\LanguageNegotiation\LanguageNegotiationUrl;
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
 * header — for File Gate's own token endpoints only (download, assurance
 * bridge, and mint). The exact path matches, and so does that path with one
 * configured language prefix when path-prefix negotiation is on. A longer or
 * unknown prefix is left alone. Handlers read the token via
 * static::authorization(), which falls back to the live header on stacks
 * where no interceptor exists. Basic credentials and X-File-Gate-Secret
 * (the mint/service-secret form) and every other route pass through
 * untouched.
 */
final class AuthorizationShield implements HttpKernelInterface {

  /**
   * Request attribute holding the stashed Authorization header value.
   */
  public const ATTRIBUTE = 'file_gate.authorization';

  /**
   * Token endpoints whose handlers validate IdP Bearer/DPoP themselves.
   *
   * Matched exactly, or with one configured language prefix. Deliberately
   * excludes permission-gated routes (webauthn/register*, credentials) where
   * a provider-authenticated Drupal account is legitimate.
   */
  private const PATHS = [
    '/api/file-gate/download',
    '/api/file-gate/assurance/bridge',
    '/api/file-gate/mint',
  ];

  /**
   * Constructs the shield.
   *
   * @param \Symfony\Component\HttpKernel\HttpKernelInterface $httpKernel
   *   The wrapped kernel. StackedKernelPass injects this.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory (language.negotiation prefixes).
   */
  public function __construct(
    private readonly HttpKernelInterface $httpKernel,
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = TRUE): Response {
    if ($this->shieldsPath($request->getPathInfo())) {
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

  /**
   * Whether this request path is a File Gate token endpoint.
   *
   * @param string $path
   *   The request path info.
   *
   * @return bool
   *   TRUE when Bearer/DPoP Authorization should be stashed.
   */
  private function shieldsPath(string $path): bool {
    if (in_array($path, self::PATHS, TRUE)) {
      return TRUE;
    }
    foreach (self::PATHS as $route_path) {
      if (!str_ends_with($path, $route_path)) {
        continue;
      }
      $prefix = substr($path, 0, -strlen($route_path));
      // One leading segment only. "/custom/admin/…" is not a language prefix.
      if (!str_starts_with($prefix, '/') || str_contains(substr($prefix, 1), '/')) {
        continue;
      }
      $segment = substr($prefix, 1);
      if ($segment !== '' && $this->isConfiguredLanguagePrefix($segment)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Whether $prefix is a configured path-prefix negotiation value.
   *
   * Empty prefixes (the usual default language) are not a path segment.
   * Domain negotiation has no path prefix, so it never matches.
   *
   * @param string $prefix
   *   One leading path segment, without slashes.
   *
   * @return bool
   *   TRUE when language.negotiation uses that path prefix.
   */
  private function isConfiguredLanguagePrefix(string $prefix): bool {
    $url = $this->configFactory->get('language.negotiation')->get('url');
    if (!is_array($url)) {
      return FALSE;
    }
    if (($url['source'] ?? NULL) !== LanguageNegotiationUrl::CONFIG_PATH_PREFIX) {
      return FALSE;
    }
    $prefixes = $url['prefixes'] ?? NULL;
    if (!is_array($prefixes)) {
      return FALSE;
    }
    foreach ($prefixes as $configured) {
      if (is_string($configured) && $configured !== '' && $configured === $prefix) {
        return TRUE;
      }
    }
    return FALSE;
  }

}
