<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance;

/**
 * Builds IdP authorize URLs for assurance step-up (GH #42).
 *
 * Only absolute http(s) bases from field config are accepted (same open
 * redirect rule as BridgeController). Optional query params append acr_values
 * and a return_to so Keycloak (or any OIDC IdP) can force WebAuthn/PIV when
 * the current SSO session lacks sufficient ACR.
 */
final class StepUpAuthorizeUrl {

  /**
   * Builds a step-up URL from a trusted field-configured base.
   *
   * @param string $base
   *   Absolute http(s) authorize or login URL from field settings only.
   * @param list<string> $required_acr
   *   ACR values to request (empty skips the acr query param).
   * @param string $return_to
   *   Same-origin path/URL to return to after IdP login (relative preferred).
   * @param array<string, mixed> $options
   *   Keys: acr_param, return_param, append_acr, append_return.
   *
   * @return string
   *   Absolute URL, or empty string when base is untrusted/empty.
   */
  public function build(string $base, array $required_acr = [], string $return_to = '', array $options = []): string {
    $base = trim($base);
    if ($base === '' || !preg_match('#^https?://#i', $base)) {
      return '';
    }
    $parts = parse_url($base);
    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
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
      // Only allow relative paths or same-host absolute URLs as return targets.
      $safe_return = $this->sanitizeReturnTo($return_to, $parts['host']);
      if ($safe_return !== '') {
        $query[$return_param] = $safe_return;
      }
    }

    $scheme = strtolower((string) $parts['scheme']);
    $host = (string) $parts['host'];
    $port = isset($parts['port']) ? ':' . (int) $parts['port'] : '';
    $path = $parts['path'] ?? '';
    $fragment = isset($parts['fragment']) ? '#' . $parts['fragment'] : '';
    $qs = $query !== [] ? '?' . http_build_query($query) : '';
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
