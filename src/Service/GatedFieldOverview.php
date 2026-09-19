<?php

declare(strict_types=1);

namespace Drupal\file_gate\Service;

use Drupal\Core\Config\Entity\ThirdPartySettingsInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;

/**
 * Lists the fields whose storage is marked as gated.
 *
 * Shared by the settings form and by status reporting, so both describe the
 * same set. Returns data only; callers decide how to render it.
 */
final class GatedFieldOverview {

  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * Every field instance whose storage is gated.
   *
   * @return list<array{config_id: string, field_name: string, storage: string, entity_type: string, bundle: string, method: string, scheme: string}>
   *   One row per field instance, ordered by field config id. "scheme"
   *   is the storage's uri_scheme, or an empty string when the field type has
   *   none. Anything other than "private" means the gate never runs.
   */
  public function fields(): array {
    $rows = [];
    if (!$this->entityTypeManager->hasDefinition('field_config')) {
      return $rows;
    }
    /** @var \Drupal\field\FieldConfigInterface $field_config */
    foreach ($this->entityTypeManager->getStorage('field_config')->loadMultiple() as $field_config) {
      $storage = $field_config->getFieldStorageDefinition();
      // Gating lives on the field storage; skip fields whose storage is not
      // gated (and base fields, which are not third-party-settings-aware).
      if (!$storage instanceof ThirdPartySettingsInterface || !$storage->getThirdPartySetting('file_gate', 'gated', FALSE)) {
        continue;
      }
      $rows[] = [
        'config_id' => (string) $field_config->id(),
        'field_name' => (string) $field_config->getName(),
        'storage' => $field_config->getTargetEntityTypeId() . '.' . $field_config->getName(),
        'entity_type' => (string) $field_config->getTargetEntityTypeId(),
        'bundle' => (string) $field_config->getTargetBundle(),
        'method' => (string) ($storage->getThirdPartySetting('file_gate', 'method') ?: 'signed_url'),
        'scheme' => (string) ($storage->getSetting('uri_scheme') ?? ''),
      ];
    }
    usort($rows, static fn (array $a, array $b): int => $a['config_id'] <=> $b['config_id']);
    return $rows;
  }

}
