<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance;

/**
 * Builds IdP authorize URLs for assurance step-up (GH #42).
 *
 * Only absolute http(s) bases or site-relative paths from field config are
 * accepted (same open redirect rule as BridgeController; GH #62). Optional
 * query params append acr_values and a return_to so Keycloak (or any OIDC
 * IdP) can force WebAuthn/PIV when the current SSO session lacks sufficient
 * ACR.
 */
final class StepUpAuthorizeUrl {

  /**
   * Decides whether a base URL is trusted as a step-up login target.
   *
   * Accepted: an absolute http(s) URL, or a site-relative path with exactly
   * one leading slash. Network-path references (//host), backslashes, and
   * control characters are rejected — a single-slash relative path is
   * same-origin by construction, so it cannot become an open redirect.
   *
   * @param string $base
   *   The candidate base from field settings.
   *
   * @return bool
   *   TRUE when the base may be used as a step-up login target.
   */
  public function isTrustedBase(string $base): bool {
    $base = trim($base);
    if ($base === '') {
      return FALSE;
    }
    if (preg_match('#^https?://#i', $base)) {
      return TRUE;
    }
    // Site-relative: exactly one leading "/" (reject //network-path), and no
    // backslash or control characters (mirrors sanitizeReturnTo()).
    if (!str_starts_with($base, '/') || str_starts_with($base, '//')) {
      return FALSE;
    }
    if (str_contains($base, '\\') || preg_match('/[\x00-\x1F\x7F]/', $base)) {
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Builds a step-up URL from a trusted field-configured base.
   *
   * @param string $base
   *   Absolute http(s) authorize or login URL, or a site-relative path with a
   *   single leading slash, from field settings only.
   * @param list<string> $required_acr
   *   ACR values to request (empty skips the acr query param).
   * @param string $return_to
   *   Same-origin path/URL to return to after IdP login (relative preferred).
   * @param array<string, mixed> $options
   *   Keys: acr_param, return_param, append_acr, append_return.
   *
   * @return string
   *   Built URL (absolute, or site-relative when the base was), or empty
   *   string when base is untrusted/empty.
   */
  public function build(string $base, array $required_acr = [], string $return_to = '', array $options = []): string {
    $base = trim($base);
    if (!$this->isTrustedBase($base)) {
      return '';
    }
    $relative = !preg_match('#^https?://#i', $base);
    $parts = parse_url($base);
    if (!is_array($parts)) {
      return '';
    }
    if (!$relative && (empty($parts['scheme']) || empty($parts['host']))) {
      return '';
    }

    $query = [];
    if (!empty($parts['query'])) {
      parse_str($parts['query'], $query);
    }

    $append_acr = !array_key_exists('append_acr', $options) || !empty($options['append_acr']);
    $append_return = !array_key_exists('append_return', $options) || !empty($options['append_return']);
    $acr_param = (string) ($options['acr_param'] ?? 'acr_values');
    $return_param = (string) ($options['return_param'] ?? 'return_to');

    if ($append_acr && $required_acr !== [] && $acr_param !== '') {
      $query[$acr_param] = implode(' ', array_values(array_filter(array_map('strval', $required_acr))));
    }
    if ($append_return && $return_to !== '' && $return_param !== '') {
      // Only allow relative paths or same-host absolute URLs as return
      // targets. A relative base has no host, so only relative return targets
      // can match it.
      $safe_return = $this->sanitizeReturnTo($return_to, (string) ($parts['host'] ?? ''));
      if ($safe_return !== '') {
        $query[$return_param] = $safe_return;
      }
    }

    $path = $parts['path'] ?? '';
    $fragment = isset($parts['fragment']) ? '#' . $parts['fragment'] : '';
    $qs = $query !== [] ? '?' . http_build_query($query) : '';
    if ($relative) {
      return $path . $qs . $fragment;
    }
    $scheme = strtolower((string) $parts['scheme']);
    $host = (string) $parts['host'];
    $port = isset($parts['port']) ? ':' . (int) $parts['port'] : '';
    return $scheme . '://' . $host . $port . $path . $qs . $fragment;
  }

  /**
   * Restricts return_to to relative site paths or same-host absolute URLs.
   */
  private function sanitizeReturnTo(string $return_to, string $base_host): string {
    $return_to = trim($return_to);
    if ($return_to === '') {
      return '';
    }
    // Relative path (preferred for Drupal step-up pages).
    if (str_starts_with($return_to, '/') && !str_starts_with($return_to, '//')) {
      return $return_to;
    }
    if (!preg_match('#^https?://#i', $return_to)) {
      return '';
    }
    $p = parse_url($return_to);
    if (!is_array($p) || empty($p['host'])) {
      return '';
    }
    if (strcasecmp((string) $p['host'], $base_host) !== 0) {
      return '';
    }
    return $return_to;
  }

}
