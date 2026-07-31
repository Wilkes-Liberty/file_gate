<?php

declare(strict_types=1);

namespace Drupal\file_gate\EventSubscriber;

use Drupal\Core\Config\ConfigImporterEvent;
use Drupal\Core\Config\ConfigEvents;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Refuses a configuration import that would gate a public-scheme field.
 *
 * Gating only works on the private file system. Public files are served
 * straight off disk by the web server or a CDN and never reach Drupal, so
 * there is no request to gate — `FileGateResolver::getGateForFile()` returns
 * NULL for them.
 *
 * The field edit form already forces the private scheme when gating is turned
 * on, and says so ("forces and locks the private file system"). But that is a
 * *form* alter, and a config-import-authoritative deploy never runs it. So
 * `drush config:import` could install a field storage carrying
 * `third_party_settings.file_gate.gated: true` alongside
 * `settings.uri_scheme: public`, and the result is the worst kind of failure
 * this module can have: the configuration asserts the files are gated, the
 * admin UI shows them as gated, and they are world-readable at a predictable
 * path. Nothing errors, because nothing is broken — the gate simply never
 * engages.
 *
 * Rejected at import rather than repaired on the fly. Silently rewriting
 * `uri_scheme` would make the site disagree with its own exported
 * configuration, so the next export would flip it back and the two would
 * oscillate. The exported configuration is where the truth belongs, so the
 * import fails and names the field to fix.
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
        if (empty($data['third_party_settings']['file_gate']['gated'])) {
          continue;
        }
        // Absent uri_scheme means the field type has no file system at all, so
        // gating it is meaningless rather than unsafe; the form alter skips
        // those fields for the same reason.
        $scheme = $data['settings']['uri_scheme'] ?? NULL;
        if ($scheme === NULL || $scheme === 'private') {
          continue;
        }

        // logError() takes a plain string, so the translated message is cast
        // rather than handed over as TranslatableMarkup.
        $importer->logError((string) $this->t('File Gate: @name is marked as gated but stores files in the "@scheme" file system. Gating only applies to private files — public files are served directly by the web server and never reach Drupal, so the gate would silently not apply and the files would remain publicly readable. Set settings.uri_scheme to "private" in the exported configuration, or remove the file_gate.gated third-party setting.', [
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
