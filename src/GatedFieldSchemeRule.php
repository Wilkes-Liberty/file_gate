<?php

declare(strict_types=1);

namespace Drupal\file_gate;

/**
 * The one statement of "a gated field must store files privately".
 *
 * Every guard asks this class: the entity presave hook, the raw config save
 * subscriber, the import validator, the config schema constraint and the
 * status report. One implementation, so they cannot drift apart.
 */
final class GatedFieldSchemeRule {

  /**
   * The only scheme a gated field may use.
   */
  public const string REQUIRED_SCHEME = 'private';

  /**
   * The scheme that breaks the rule, from raw field storage config data.
   *
   * @param array<string, mixed> $data
   *   A field.storage.*.* config array.
   *
   * @return string|null
   *   The offending scheme, or NULL when the data is fine.
   */
  public static function offendingSchemeInData(array $data): ?string {
    $third_party = $data['third_party_settings']['file_gate'] ?? [];
    $settings = $data['settings'] ?? [];
    return self::offendingScheme(
      is_array($third_party) && !empty($third_party['gated']),
      is_array($settings) ? $settings : [],
    );
  }

  /**
   * The scheme that breaks the rule.
   *
   * A storage with no uri_scheme key has no file system at all, so gating it
   * is meaningless rather than unsafe. A key that is present with any value
   * other than "private", including NULL, is unsafe: fail closed.
   *
   * @param bool $gated
   *   The file_gate.gated third-party setting.
   * @param array<string, mixed> $settings
   *   The field storage settings.
   *
   * @return string|null
   *   The offending scheme, or NULL when the combination is fine.
   */
  public static function offendingScheme(bool $gated, array $settings): ?string {
    if (!$gated || !array_key_exists('uri_scheme', $settings)) {
      return NULL;
    }
    $scheme = $settings['uri_scheme'];
    if ($scheme === self::REQUIRED_SCHEME) {
      return NULL;
    }
    return is_scalar($scheme) ? (string) $scheme : '';
  }

  /**
   * Whether a write creates the offending combination or changes it.
   *
   * A site that was already in the state before this guard existed must still
   * be able to save the storage for unrelated reasons: a core update hook that
   * re-saves every field storage, a module uninstall that strips its own
   * third-party settings, or the field form, which saves the storage before
   * this module's submit handler repairs it. Refusing those would break
   * updates and block the repair. So a write is refused only when it produces
   * the combination or moves it to another non-private scheme; the unchanged
   * case stays an error on the status report.
   *
   * @param string|null $new
   *   The offending scheme after the write, or NULL.
   * @param string|null $original
   *   The offending scheme before the write, or NULL (also for a new storage).
   *
   * @return bool
   *   TRUE when the write must be refused.
   */
  public static function isRefused(?string $new, ?string $original): bool {
    return $new !== NULL && $new !== $original;
  }

  /**
   * The untranslated message, with @name and @scheme placeholders.
   */
  public static function message(): string {
    return 'File Gate: @name is marked as gated but stores files in the "@scheme" file system. Gating only applies to private files — public files are served directly by the web server and never reach Drupal, so the gate would silently not apply and the files would remain publicly readable. Set settings.uri_scheme to "private", or remove the file_gate.gated third-party setting.';
  }

}
