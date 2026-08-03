<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance;

/**
 * The set of trusted issuers configured on an assurance-gated field.
 *
 * Built from the field's method settings, which accept either shape:
 * - `trusted_issuers`: a list of entries, each with `issuer`, `audience`, and
 *   `required_acr` (a list, or a newline-separated string as the settings form
 *   submits it);
 * - the legacy single keys `issuer`, `audience`, and `required_acr`, which
 *   behave exactly as a one-entry list (kept working forever — no update hook).
 *
 * When both shapes are present, `trusted_issuers` wins. A set that is empty,
 * has an entry missing its issuer or audience, or lists the same issuer twice
 * (ambiguous — which audience/acr applies?) is invalid, and every caller fails
 * closed on an invalid set.
 */
final class TrustedIssuerSet {

  /**
   * Constructs the set.
   *
   * @param list<\Drupal\file_gate_assurance\TrustedIssuer> $entries
   *   The parsed entries, in configuration order.
   */
  private function __construct(
    private readonly array $entries,
  ) {}

  /**
   * Builds the set from an assurance field's method settings.
   *
   * @param array $settings
   *   The gate method settings.
   *
   * @return self
   *   The parsed set. Never throws — malformed configuration parses into an
   *   invalid set so callers fail closed rather than fall back.
   */
  public static function fromSettings(array $settings): self {
    $raw = $settings['trusted_issuers'] ?? NULL;
    if (is_array($raw) && $raw !== []) {
      $entries = [];
      foreach (array_values($raw) as $entry) {
        if (!is_array($entry)) {
          // A malformed entry keeps its slot so the set is invalid (fail
          // closed) instead of silently shrinking to the well-formed rows.
          $entries[] = new TrustedIssuer('', '', []);
          continue;
        }
        $entries[] = new TrustedIssuer(
          trim((string) ($entry['issuer'] ?? '')),
          trim((string) ($entry['audience'] ?? '')),
          self::normalizeAcr($entry['required_acr'] ?? []),
        );
      }
      return new self($entries);
    }

    // Legacy single-issuer shape: a one-entry list, only when configured.
    $issuer = trim((string) ($settings['issuer'] ?? ''));
    if ($issuer === '') {
      return new self([]);
    }
    return new self([
      new TrustedIssuer(
        $issuer,
        trim((string) ($settings['audience'] ?? '')),
        self::normalizeAcr($settings['required_acr'] ?? []),
      ),
    ]);
  }

  /**
   * Whether the set is complete and unambiguous.
   *
   * @return bool
   *   FALSE when the set is empty, when any entry lacks an issuer or an
   *   audience, or when two entries share a byte-identical issuer (which entry
   *   applies would be ambiguous, so the whole set is rejected and callers
   *   fail closed).
   */
  public function isValid(): bool {
    if ($this->entries === []) {
      return FALSE;
    }
    $seen = [];
    foreach ($this->entries as $entry) {
      if ($entry->issuer === '' || $entry->audience === '') {
        return FALSE;
      }
      if (isset($seen[$entry->issuer])) {
        return FALSE;
      }
      $seen[$entry->issuer] = TRUE;
    }
    return TRUE;
  }

  /**
   * The single entry whose issuer byte-exactly equals the token's `iss`.
   *
   * @param string $iss
   *   The issuer to match.
   *
   * @return \Drupal\file_gate_assurance\TrustedIssuer|null
   *   The matched entry, or NULL when the set is invalid or no entry matches.
   *   There is never a fallback to another entry's audience or acr.
   */
  public function match(string $iss): ?TrustedIssuer {
    if (!$this->isValid()) {
      return NULL;
    }
    foreach ($this->entries as $entry) {
      if ($entry->issuer === $iss) {
        return $entry;
      }
    }
    return NULL;
  }

  /**
   * The deduplicated union of every entry's acceptable acr values.
   *
   * For challenge advertisement only (WWW-Authenticate acr_values, step-up
   * URLs): enforcement always uses the matched entry's own list, never this
   * union.
   *
   * @return list<string>
   *   The union, in configuration order.
   */
  public function acrUnion(): array {
    $union = [];
    foreach ($this->entries as $entry) {
      foreach ($entry->requiredAcr as $acr) {
        // Not keyed dedup: PHP array keys would coerce a numeric acr like "3"
        // to an integer, breaking the strict string comparisons downstream.
        if (!in_array($acr, $union, TRUE)) {
          $union[] = $acr;
        }
      }
    }
    return $union;
  }

  /**
   * The parsed entries, in configuration order.
   *
   * @return list<\Drupal\file_gate_assurance\TrustedIssuer>
   *   The entries (also returned while the set is invalid, e.g. to prefill the
   *   settings form).
   */
  public function entries(): array {
    return $this->entries;
  }

  /**
   * Normalizes an acr configuration value to a clean list of strings.
   *
   * Accepts either a list or a newline-separated string (the settings form's
   * textarea), trimming each value and dropping empties — the same
   * normalization the form submit applies.
   *
   * @param mixed $value
   *   The raw configured value.
   *
   * @return list<string>
   *   The normalized acr values.
   */
  private static function normalizeAcr(mixed $value): array {
    if (is_string($value)) {
      $value = preg_split('/\R/', $value) ?: [];
    }
    $list = [];
    foreach ((array) $value as $acr) {
      $acr = trim((string) $acr);
      if ($acr !== '') {
        $list[] = $acr;
      }
    }
    return $list;
  }

}
