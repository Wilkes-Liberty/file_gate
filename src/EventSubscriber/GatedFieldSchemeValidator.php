<?php

declare(strict_types=1);

namespace Drupal\file_gate\EventSubscriber;

use Drupal\Core\Config\ConfigImporterEvent;
use Drupal\Core\Config\ConfigEvents;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\file_gate\GatedFieldSchemeRule;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Refuses a configuration import that would gate a public-scheme field.
 *
 * A public scheme is not a gate (bytes never reach Drupal). Rejected at import
 * rather than rewritten, so exported config stays the source of truth.
 */
final class GatedFieldSchemeValidator implements EventSubscriberInterface {

  use StringTranslationTrait;

  /**
   * Validates the incoming field storage configuration.
   *
   * @param \Drupal\Core\Config\ConfigImporterEvent $event
   *   The import event.
   */
  public function onImportValidate(ConfigImporterEvent $event): void {
    $importer = $event->getConfigImporter();
    $storage = $importer->getStorageComparer()->getSourceStorage();

    foreach (['create', 'update'] as $op) {
      foreach ($importer->getUnprocessedConfiguration($op) as $name) {
        if (!str_starts_with($name, 'field.storage.')) {
          continue;
        }
        $data = $storage->read($name);
        if (!is_array($data)) {
          continue;
        }
        // The whole combination is refused here, changed or not: an import
        // that lists this name is about to write it, and the exported file is
        // what needs fixing. A site already in the state is not blocked from
        // unrelated imports, because an unchanged name is not in the list.
        $scheme = GatedFieldSchemeRule::offendingSchemeInData($data);
        if ($scheme === NULL) {
          continue;
        }

        // logError() takes a plain string, so the translated message is cast
        // rather than handed over as TranslatableMarkup. The text is the
        // rule's own, so import, save and validation say the same thing.
        // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
        $importer->logError((string) $this->t(GatedFieldSchemeRule::message(), [
          '@name' => $name,
          '@scheme' => $scheme,
        ]));
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [ConfigEvents::IMPORT_VALIDATE => ['onImportValidate', 0]];
  }

}
