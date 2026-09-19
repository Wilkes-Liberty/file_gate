<?php

declare(strict_types=1);

namespace Drupal\file_gate\Hook;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\Requirement\RequirementSeverity;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\file_gate\GatedFieldSchemeRule;
use Drupal\file_gate\SecretRegistryInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Status report findings for File Gate.
 *
 * Both findings describe a gate that reads as configured and protects
 * nothing, so both are errors. They live on hook_runtime_requirements():
 * Drupal 13 stops calling the procedural hook_requirements(), and a security
 * finding must not be able to leave the status report without an error.
 */
final class FileGateRequirements {

  use StringTranslationTrait;

  /**
   * Constructs the hook class.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    #[Autowire(service: 'file_gate.secret_registry')]
    private readonly SecretRegistryInterface $secrets,
  ) {}

  /**
   * Implements hook_runtime_requirements().
   *
   * @return array<string, array<string, mixed>>
   *   Requirements keyed by id.
   */
  #[Hook('runtime_requirements')]
  public function runtime(): array {
    return $this->publicGatedFields() + $this->unscopedNamedSecrets();
  }

  /**
   * Gated fields that are not on the private file system.
   *
   * A public scheme is not a gate, so those files stay world-readable.
   *
   * @return array<string, array<string, mixed>>
   *   The finding, or nothing.
   */
  private function publicGatedFields(): array {
    $offenders = [];
    $storages = $this->entityTypeManager
      ->getStorage('field_storage_config')
      ->loadMultiple();

    foreach ($storages as $storage) {
      // Saves that create this state are refused; what is found here predates
      // that guard, and an unchanged re-save of it is still allowed.
      $scheme = GatedFieldSchemeRule::offendingScheme(
        (bool) $storage->getThirdPartySetting('file_gate', 'gated', FALSE),
        $storage->getSettings(),
      );
      if ($scheme === NULL) {
        continue;
      }
      $offenders[] = $storage->id() . ' (' . $scheme . ')';
    }
    if ($offenders === []) {
      return [];
    }
    return [
      'file_gate_public_gated_fields' => [
        'title' => $this->t('File Gate: gated fields are not on the private file system'),
        'value' => $this->t('@list', ['@list' => implode(', ', $offenders)]),
        'severity' => RequirementSeverity::Error,
        'description' => $this->t('These fields are marked as gated but store files publicly, so the gate never runs and the files are readable by anyone with the URL. The configuration says they are protected and they are not. Change the field to the private file system — note that existing files are not moved by that change, so they must be re-uploaded or migrated before the gate covers them.'),
      ],
    ];
  }

  /**
   * Named secrets with material but no field scope.
   *
   * They can authenticate and still mint nothing; an error keeps that from
   * being a silent dead credential.
   *
   * @return array<string, array<string, mixed>>
   *   The finding, or nothing.
   */
  private function unscopedNamedSecrets(): array {
    $unscoped = [];
    foreach ($this->secrets->namedSecretIds() as $id) {
      if ($this->secrets->isNamedSecretUnscoped($id)) {
        $unscoped[] = $id;
      }
    }
    if ($unscoped === []) {
      return [];
    }
    return [
      'file_gate_unscoped_named_secrets' => [
        'title' => $this->t('File Gate: named secrets with no field scope'),
        'value' => $this->t('@list', ['@list' => implode(', ', $unscoped)]),
        'severity' => RequirementSeverity::Error,
        'description' => $this->t('These secret ids have values in <code>$settings["file_gate.secrets"]</code> but no (or empty) entry under <code>secret_scopes</code>. A named secret with no scope can mint nothing (fail closed). Add field storage keys (entity_type.field_name) for each id, or remove the unused secret. The legacy <code>download_secret</code> without a key id remains whole-corpus for older installs.'),
      ],
    ];
  }

}
