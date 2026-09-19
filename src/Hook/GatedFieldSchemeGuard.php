<?php

declare(strict_types=1);

namespace Drupal\file_gate\Hook;

use Drupal\Core\Hook\Attribute\Hook;
use Drupal\field\FieldStorageConfigInterface;
use Drupal\file_gate\Exception\GatedPublicSchemeException;
use Drupal\file_gate\GatedFieldSchemeRule;

/**
 * Refuses an entity save that gates a field stored outside private.
 *
 * Covers every write that loads the entity: the entity API, recipes, update
 * hooks, the field form and config import. Writes that skip the entity are
 * caught by GatedFieldSchemeSaveSubscriber.
 */
final class GatedFieldSchemeGuard {

  /**
   * Implements hook_ENTITY_TYPE_presave() for field_storage_config.
   */
  #[Hook('field_storage_config_presave')]
  public function presave(FieldStorageConfigInterface $storage): void {
    $new = self::offendingScheme($storage);
    $original = $storage->isNew() ? NULL : $storage->getOriginal();
    $before = $original instanceof FieldStorageConfigInterface ? self::offendingScheme($original) : NULL;

    if (GatedFieldSchemeRule::isRefused($new, $before)) {
      throw GatedPublicSchemeException::forStorage('field.storage.' . $storage->id(), (string) $new);
    }
  }

  /**
   * Applies the rule to a field storage entity.
   */
  private static function offendingScheme(FieldStorageConfigInterface $storage): ?string {
    return GatedFieldSchemeRule::offendingScheme(
      (bool) $storage->getThirdPartySetting('file_gate', 'gated', FALSE),
      $storage->getSettings(),
    );
  }

}
