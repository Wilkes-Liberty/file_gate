<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Symfony\Component\HttpFoundation\Request;

/**
 * Resolves File Gate mint/signing secrets and their field scopes.
 *
 * Secrets stay out of exported configuration. Config holds only
 * secret_id → field-key allowlists. Values come from the legacy
 * download_secret override and/or $settings['file_gate.secrets'].
 *
 * @see \Drupal\file_gate\SecretRegistry
 */
interface SecretRegistryInterface {

  /**
   * Request attribute set after successful shared-secret authentication.
   *
   * Value is NULL for the legacy single secret, or the opaque named secret id.
   */
  public const string REQUEST_ATTR_SECRET_ID = 'file_gate.secret_id';

  /**
   * Whether any usable signing material is configured (legacy or named).
   */
  public function hasAnySecret(): bool;

  /**
   * Resolves credentials presented on a server-to-server request.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request (Basic auth and/or secret headers).
   *
   * @return array{id: string|null, secret: string}|null
   *   id NULL means the legacy download_secret. NULL return means the request
   *   did not present valid credentials for any configured secret.
   */
  public function resolveCredentials(Request $request): ?array;

  /**
   * HMAC material for a secret id (current value only — for mint signing).
   *
   * @param string|null $secret_id
   *   NULL for the legacy download_secret; a named id otherwise.
   *
   * @return string
   *   The secret value, or '' when missing/deleted.
   */
  public function secretMaterial(?string $secret_id): string;

  /**
   * Materials to try when validating an outstanding grant or OTP (rotation).
   *
   * Order: current material first, then previous keys from
   * $settings['file_gate.previous_secrets'] (named) or
   * $settings['file_gate.previous_download_secrets'] (legacy list).
   * Minting always uses secretMaterial() (current only).
   *
   * @param string|null $secret_id
   *   NULL for legacy; named id otherwise.
   *
   * @return list<string>
   *   Non-empty secret strings (may be empty list when none configured).
   */
  public function validationMaterials(?string $secret_id): array;

  /**
   * Whether the secret may mint/redeem for a gated field storage key.
   *
   * @param string|null $secret_id
   *   NULL for the legacy secret (always TRUE — whole corpus).
   * @param string $field_key
   *   Field storage id, e.g. "node.field_whitepaper".
   *
   * @return bool
   *   TRUE when allowed. Named secrets with empty/missing scope: FALSE.
   */
  public function allowsField(?string $secret_id, string $field_key): bool;

  /**
   * Named secret ids known from scopes and/or settings values.
   *
   * @return list<string>
   *   Sorted opaque ids (no secret material).
   */
  public function namedSecretIds(): array;

  /**
   * Field keys in the scope map for a named secret.
   *
   * @param string $secret_id
   *   The opaque secret id.
   *
   * @return list<string>
   *   Field storage keys; empty when unscoped.
   */
  public function scopeFields(string $secret_id): array;

  /**
   * Whether a named secret has material but no usable scope (misconfiguration).
   *
   * @param string $secret_id
   *   The opaque secret id.
   *
   * @return bool
   *   TRUE when the secret would authenticate but can mint nothing.
   */
  public function isNamedSecretUnscoped(string $secret_id): bool;

}
