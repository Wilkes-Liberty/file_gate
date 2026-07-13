<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\StreamWrapper\StreamWrapperManagerInterface;
use Drupal\file\FileInterface;
use Drupal\file\FileReferenceResolver;

/**
 * Resolves whether (and how) a managed file is gated.
 *
 * A file is gated when at least one field that references it is marked "gated"
 * in its File Gate third-party settings. This is the file-specific half of the
 * module: it reads per-field configuration and maps a file to a gate method.
 * Everything downstream (the download route, the deny hook, the mint endpoint)
 * asks this service and otherwise stays file-agnostic.
 */
final class FileGateResolver {

  /**
   * Constructs the resolver.
   *
   * @param \Drupal\file\FileReferenceResolver $fileReferenceResolver
   *   Core's file reference resolver (Drupal 11.4+).
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager (loads field storage configs).
   * @param \Drupal\Core\StreamWrapper\StreamWrapperManagerInterface $streamWrapperManager
   *   The stream wrapper manager (scheme detection).
   */
  public function __construct(
    private readonly FileReferenceResolver $fileReferenceResolver,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly StreamWrapperManagerInterface $streamWrapperManager,
  ) {}

  /**
   * Returns the gate configuration for a file, or NULL if it is not gated.
   *
   * Walks every field that references the file and returns the gate config of
   * the first one whose File Gate third-party settings enable gating.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file to inspect.
   *
   * @return array{method: string, field: string, settings: array}|null
   *   The resolved gate (method plugin id, "entity_type.field_name", and the
   *   method's settings), or NULL when no gated field references the file.
   */
  public function getGateForFile(FileInterface $file): ?array {
    // Only private-scheme files can ever be gated — public files are served
    // straight off disk by the web server/CDN and never reach Drupal, so there
    // is no request to gate.
    if ($this->streamWrapperManager->getScheme((string) $file->getFileUri()) !== 'private') {
      return NULL;
    }

    $field_storage_storage = $this->entityTypeManager->getStorage('field_storage_config');
    foreach ($this->fileReferenceResolver->getReferences($file) as $usage) {
      // The gate flag lives on the field storage (alongside uri_scheme), keyed
      // "entity_type.field_name".
      $field_storage = $field_storage_storage->load($usage->entityTypeId . '.' . $usage->fieldName);
      if ($field_storage === NULL) {
        continue;
      }
      if (!$field_storage->getThirdPartySetting('file_gate', 'gated', FALSE)) {
        continue;
      }
      return [
        'method' => (string) ($field_storage->getThirdPartySetting('file_gate', 'method') ?: 'signed_url'),
        'field' => $usage->entityTypeId . '.' . $usage->fieldName,
        'settings' => (array) $field_storage->getThirdPartySetting('file_gate', 'method_settings', []),
      ];
    }
    return NULL;
  }

  /**
   * Whether the file is gated.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return bool
   *   TRUE if any referencing field gates the file.
   */
  public function isGated(FileInterface $file): bool {
    return $this->getGateForFile($file) !== NULL;
  }

}
