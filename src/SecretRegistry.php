<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Site\Settings;
use Symfony\Component\HttpFoundation\Request;

/**
 * Default secret registry: legacy env secret plus optional named secrets.
 *
 * Values live only in settings / env-injected config — never export them.
 *
 * Dual-key rotation (grace period for outstanding grants):
 * - Named: $settings['file_gate.previous_secrets'] = ['id' => 'old_value', …]
 *   or ['id' => ['old1', 'old2']] for multiple retired values.
 * - Legacy: $settings['file_gate.previous_download_secrets'] = ['old', …]
 * Mint/sign always uses the current material; validate tries current then
 * previous so rotation does not mass-invalidate live links.
 *
 * @see \Drupal\file_gate\SecretRegistryInterface
 * @see docs/SECRET_ROTATION.md
 */
final class SecretRegistry implements SecretRegistryInterface {

  /**
   * Constructs the registry.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Config factory (legacy secret override + secret_scopes).
   * @param \Drupal\Core\Site\Settings $settings
   *   Site settings (named secret values under file_gate.secrets).
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly Settings $settings,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function hasAnySecret(): bool {
    if ($this->legacySecret() !== '') {
      return TRUE;
    }
    foreach ($this->namedSecretValues() as $value) {
      if ($value !== '') {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function resolveCredentials(Request $request): ?array {
    $provided = $this->providedSecret($request);
    if ($provided === NULL) {
      return NULL;
    }

    $secret_id = $this->providedSecretId($request);

    // Named credential: Basic username or X-File-Gate-Secret-Id, when that id
    // has material in settings. Unknown ids fall through to legacy so older
    // clients that used Basic with an arbitrary username (password = secret)
    // keep working.
    if ($secret_id !== NULL && $secret_id !== '') {
      $material = $this->namedSecretValues()[$secret_id] ?? '';
      if ($material !== '') {
        if (!hash_equals($material, $provided)) {
          return NULL;
        }
        return ['id' => $secret_id, 'secret' => $material];
      }
    }

    // Legacy: password/header matches download_secret (whole corpus).
    $legacy = $this->legacySecret();
    if ($legacy === '' || !hash_equals($legacy, $provided)) {
      return NULL;
    }
    return ['id' => NULL, 'secret' => $legacy];
  }

  /**
   * {@inheritdoc}
   */
  public function secretMaterial(?string $secret_id): string {
    if ($secret_id === NULL || $secret_id === '') {
      return $this->legacySecret();
    }
    return $this->namedSecretValues()[$secret_id] ?? '';
  }

  /**
   * {@inheritdoc}
   */
  public function validationMaterials(?string $secret_id): array {
    $out = [];
    $current = $this->secretMaterial($secret_id);
    if ($current !== '') {
      $out[] = $current;
    }
    foreach ($this->previousMaterials($secret_id) as $previous) {
      if ($previous !== '' && !in_array($previous, $out, TRUE)) {
        $out[] = $previous;
      }
    }
    return $out;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsField(?string $secret_id, string $field_key): bool {
    // Legacy single secret: whole corpus (backward compatibility).
    if ($secret_id === NULL || $secret_id === '') {
      return TRUE;
    }
    $scope = $this->scopeFields($secret_id);
    // Named secret with empty/missing scope grants nothing (fail closed).
    if ($scope === []) {
      return FALSE;
    }
    return in_array($field_key, $scope, TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function namedSecretIds(): array {
    $ids = array_keys($this->namedSecretValues() + $this->secretScopes());
    sort($ids);
    return $ids;
  }

  /**
   * {@inheritdoc}
   */
  public function scopeFields(string $secret_id): array {
    $scopes = $this->secretScopes();
    $fields = $scopes[$secret_id] ?? [];
    $out = [];
    foreach ($fields as $field) {
      if (is_scalar($field) && (string) $field !== '') {
        $out[] = (string) $field;
      }
    }
    $out = array_values(array_unique($out));
    sort($out);
    return $out;
  }

  /**
   * {@inheritdoc}
   */
  public function isNamedSecretUnscoped(string $secret_id): bool {
    $has_value = ($this->namedSecretValues()[$secret_id] ?? '') !== '';
    if (!$has_value) {
      return FALSE;
    }
    return $this->scopeFields($secret_id) === [];
  }

  /**
   * Legacy download_secret from config (env-injected via settings.php).
   */
  private function legacySecret(): string {
    return (string) $this->configFactory->get('file_gate.settings')->get('download_secret');
  }

  /**
   * Named secret values from settings.php ($settings['file_gate.secrets']).
   *
   * @return array<string, string>
   *   id => secret value (empty strings filtered only at use sites).
   */
  private function namedSecretValues(): array {
    $raw = $this->settings->get('file_gate.secrets', []);
    if (!is_array($raw)) {
      return [];
    }
    $out = [];
    foreach ($raw as $id => $value) {
      if (is_string($id) && $id !== '' && is_scalar($value)) {
        $out[$id] = (string) $value;
      }
    }
    return $out;
  }

  /**
   * Returns the secret_scopes map from configuration.
   *
   * @return array<string, array<int|string, mixed>>
   *   id => raw field key list from config.
   */
  private function secretScopes(): array {
    $raw = $this->configFactory->get('file_gate.settings')->get('secret_scopes');
    if (!is_array($raw)) {
      return [];
    }
    $out = [];
    foreach ($raw as $id => $fields) {
      if (!is_string($id) || $id === '') {
        continue;
      }
      $out[$id] = is_array($fields) ? $fields : [];
    }
    return $out;
  }

  /**
   * Previous (retired) materials for a secret id.
   *
   * @param string|null $secret_id
   *   NULL for legacy download_secret.
   *
   * @return list<string>
   *   Retired values (may be empty).
   */
  private function previousMaterials(?string $secret_id): array {
    if ($secret_id === NULL || $secret_id === '') {
      $raw = $this->settings->get('file_gate.previous_download_secrets', []);
      if (!is_array($raw)) {
        return [];
      }
      $out = [];
      foreach ($raw as $value) {
        if (is_scalar($value) && (string) $value !== '') {
          $out[] = (string) $value;
        }
      }
      return $out;
    }
    $raw = $this->settings->get('file_gate.previous_secrets', []);
    if (!is_array($raw) || !array_key_exists($secret_id, $raw)) {
      return [];
    }
    $entry = $raw[$secret_id];
    if (is_scalar($entry) && (string) $entry !== '') {
      return [(string) $entry];
    }
    if (!is_array($entry)) {
      return [];
    }
    $out = [];
    foreach ($entry as $value) {
      if (is_scalar($value) && (string) $value !== '') {
        $out[] = (string) $value;
      }
    }
    return $out;
  }

  /**
   * Secret material from Basic password or X-File-Gate-Secret.
   */
  private function providedSecret(Request $request): ?string {
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

  /**
   * Secret id from Basic username or X-File-Gate-Secret-Id.
   */
  private function providedSecretId(Request $request): ?string {
    $header = $request->headers->get('X-File-Gate-Secret-Id');
    if ($header !== NULL && (string) $header !== '') {
      return (string) $header;
    }
    $authorization = (string) $request->headers->get('Authorization', '');
    if (str_starts_with($authorization, 'Basic ')) {
      $decoded = base64_decode(substr($authorization, 6), TRUE);
      if ($decoded !== FALSE && str_contains($decoded, ':')) {
        [$username] = explode(':', $decoded, 2);
        return $username !== '' ? $username : NULL;
      }
    }
    return NULL;
  }

}
