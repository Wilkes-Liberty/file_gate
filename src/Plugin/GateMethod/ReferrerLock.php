<?php

declare(strict_types=1);

namespace Drupal\file_gate\Plugin\GateMethod;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Symfony\Component\HttpFoundation\Request;

/**
 * Signed URL plus an origin/referrer allowlist (defense in depth).
 *
 * This behaves exactly like signed_url — it mints and validates the same
 * short-lived HMAC grant, with the same TTL, availability window, and usage
 * limits — and additionally requires the redemption to arrive from an allowed
 * origin. The signed grant is the real authorization; the origin check is a
 * lightweight hardening layer that raises the bar against casual link-sharing
 * and hotlinking.
 *
 * IMPORTANT — hardening, NOT authorization. The `Origin` / `Referer` header is
 * trivially spoofable by any non-browser client, and privacy setups routinely
 * strip it. This method must never be relied on as an access boundary: its
 * value comes entirely from the inherited signature. Use it to discourage a
 * leaked link from working when embedded on someone else's site, not to protect
 * anything that the signature alone should not already protect.
 *
 * The origin is checked first, so a request from a disallowed origin is denied
 * before the signed grant is validated — and, crucially, before a usage-limited
 * grant would burn one of its uses.
 *
 * Per-field method settings (in addition to all of signed_url's — ttl,
 * available_until, max_uses):
 * - allowed_origins: a list of allowed origins, e.g. "https://app.example.com".
 *   Compared as scheme + host + (non-default) port against the request's Origin
 *   header, falling back to the origin of the Referer. An empty list denies
 *   every request (fail closed) — configure at least one origin.
 * - on_missing_referrer: what to do when neither header is present — "deny"
 *   (the default; the lock cannot be verified) or "allow" (tolerate privacy
 *   setups that strip the header, leaning on the signature alone).
 */
#[GateMethod(
  id: 'referrer_lock',
  label: new TranslatableMarkup('Referrer lock (signed URL + origin allowlist)'),
  description: new TranslatableMarkup('A signed URL that is additionally only redeemable from an allowed origin/referrer. Defense in depth against casual link-sharing and hotlinking — the Referer/Origin header is spoofable, so this is hardening, not authentication. Inherits the signed URL TTL, availability window, and usage limits.'),
)]
final class ReferrerLock extends SignedUrl {

  /**
   * {@inheritdoc}
   */
  public function grants(FileInterface $file, Request $request): bool {
    // Hardening layer first: reject a disallowed (or unverifiable) origin
    // before validating the signed grant — and before a usage-limited grant
    // would spend one of its uses. The inherited signature check is the gate.
    if (!$this->originAllowed($request)) {
      return FALSE;
    }
    return parent::grants($file, $request);
  }

  /**
   * Whether the request's origin is in the configured allowlist.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The redemption request.
   *
   * @return bool
   *   TRUE when the request's origin matches an allowed origin. When no origin
   *   can be determined (no parseable Origin/Referer header), the configured
   *   "on_missing_referrer" behaviour decides. An empty allowlist denies.
   */
  private function originAllowed(Request $request): bool {
    $allowed = $this->normalizedAllowlist();
    if ($allowed === []) {
      // No allowlist configured ⇒ nothing can match. Fail closed.
      return FALSE;
    }

    $origin = $this->requestOrigin($request);
    if ($origin === NULL) {
      // Header absent or unparseable: honour the configured policy.
      return ($this->configuration['on_missing_referrer'] ?? 'deny') === 'allow';
    }

    return in_array($origin, $allowed, TRUE);
  }

  /**
   * The request's origin, taken from the Origin header or the Referer.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return string|null
   *   The normalized origin (scheme + host + non-default port), or NULL when
   *   neither header yields a parseable origin. An opaque "Origin: null" is
   *   treated as absent.
   */
  private function requestOrigin(Request $request): ?string {
    foreach (['Origin', 'Referer'] as $header) {
      $value = (string) $request->headers->get($header, '');
      if ($value === '' || $value === 'null') {
        continue;
      }
      $normalized = $this->normalizeOrigin($value);
      if ($normalized !== NULL) {
        return $normalized;
      }
    }
    return NULL;
  }

  /**
   * The configured allowlist, normalized to comparable origins.
   *
   * @return string[]
   *   The normalized allowed origins (unparseable entries dropped).
   */
  private function normalizedAllowlist(): array {
    $out = [];
    foreach ((array) ($this->configuration['allowed_origins'] ?? []) as $entry) {
      $normalized = $this->normalizeOrigin((string) $entry);
      if ($normalized !== NULL) {
        $out[] = $normalized;
      }
    }
    return $out;
  }

  /**
   * Normalizes a URL or origin string to "scheme://host[:port]".
   *
   * Host and scheme are lower-cased and a default port (80 for http, 443 for
   * https) is dropped, so the allowlist and the request headers compare equal
   * regardless of trailing paths or redundant default ports.
   *
   * @param string $url
   *   A URL or origin string (e.g. "https://example.com/page" or
   *   "https://example.com:443").
   *
   * @return string|null
   *   The normalized origin, or NULL when no scheme+host could be parsed.
   */
  private function normalizeOrigin(string $url): ?string {
    $parts = parse_url($url);
    if (empty($parts['scheme']) || empty($parts['host'])) {
      return NULL;
    }
    $scheme = strtolower($parts['scheme']);
    $origin = $scheme . '://' . strtolower($parts['host']);
    $default_ports = ['http' => 80, 'https' => 443];
    if (isset($parts['port']) && ($default_ports[$scheme] ?? NULL) !== $parts['port']) {
      $origin .= ':' . $parts['port'];
    }
    return $origin;
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $settings): array {
    // Inherit signed_url's ttl / available_until / max_uses, then add the lock.
    return parent::fieldSettingsForm($settings) + [
      'allowed_origins' => [
        '#type' => 'textarea',
        '#title' => $this->t('Allowed origins'),
        '#default_value' => implode("\n", (array) ($settings['allowed_origins'] ?? [])),
        '#description' => $this->t('One origin per line, e.g. <code>https://app.example.com</code>. An empty list denies every request (fail closed).'),
      ],
      'on_missing_referrer' => [
        '#type' => 'select',
        '#title' => $this->t('When no Origin/Referer is present'),
        '#options' => [
          'deny' => $this->t('Deny (default)'),
          'allow' => $this->t('Allow (lean on the signature alone)'),
        ],
        '#default_value' => ($settings['on_missing_referrer'] ?? 'deny') === 'allow' ? 'allow' : 'deny',
        '#description' => $this->t('“Allow” tolerates privacy setups that strip the header.'),
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsSubmit(array $values): array {
    $settings = parent::fieldSettingsSubmit($values);
    $origins = array_filter(array_map('trim', preg_split('/\R/', (string) ($values['allowed_origins'] ?? ''))));
    if ($origins) {
      $settings['allowed_origins'] = array_values($origins);
    }
    $settings['on_missing_referrer'] = ($values['on_missing_referrer'] ?? 'deny') === 'allow' ? 'allow' : 'deny';
    return $settings;
  }

}
