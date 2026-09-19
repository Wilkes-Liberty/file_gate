<?php

declare(strict_types=1);

namespace Drupal\file_gate\EventSubscriber;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigCrudEvent;
use Drupal\Core\Config\ConfigEvents;
use Drupal\file_gate\Exception\GatedPublicSchemeException;
use Drupal\file_gate\GatedFieldSchemeRule;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Undoes a raw config write that gates a field stored outside private.
 *
 * `drush config:set` and config tools save through the config factory and
 * never load the entity, so no entity hook runs. Core has no event before a
 * raw config write; ConfigEvents::SAVE fires once the data is in storage. The
 * write is therefore put back and the save fails, which is the closest a raw
 * write can get to being refused.
 */
final class GatedFieldSchemeSaveSubscriber implements EventSubscriberInterface {

  /**
   * TRUE while this subscriber is putting a refused write back.
   */
  private bool $restoring = FALSE;

  /**
   * Restores the previous data and throws when a write breaks the rule.
   */
  public function onSave(ConfigCrudEvent $event): void {
    $config = $event->getConfig();
    if ($this->restoring || !$config instanceof Config || !str_starts_with($config->getName(), 'field.storage.')) {
      return;
    }
    $original = $config->getOriginal('', FALSE);
    $original = is_array($original) ? $original : [];
    $new = GatedFieldSchemeRule::offendingSchemeInData($config->getRawData());

    if (!GatedFieldSchemeRule::isRefused($new, GatedFieldSchemeRule::offendingSchemeInData($original))) {
      return;
    }

    // The nested save dispatches this event again so other subscribers see
    // the restore. The flag keeps that dispatch from being judged a second
    // time, whatever the rule says about it.
    $this->restoring = TRUE;
    try {
      if ($original === []) {
        $config->delete();
      }
      else {
        $config->setData($original)->save();
      }
    }
    finally {
      $this->restoring = FALSE;
    }
    throw GatedPublicSchemeException::forStorage($config->getName(), (string) $new);
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Ahead of subscribers that act on the saved value (audit, cache, sync):
    // they should never see a write that does not stand.
    return [ConfigEvents::SAVE => ['onSave', 1000]];
  }

}
