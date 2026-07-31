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
 *
 * Multi-field determinism: the same private file may be referenced by more than
 * one gated field (e.g. a public whitepaper field and an NDA field). Callers
 * may pass an explicit field storage key ("entity_type.field_name"). When no
 * field is requested, the strictest matching gate wins (not reference order).
 */
final class FileGateResolver {

  /**
   * Method ids ordered from strictest to loosest (higher index = looser).
   *
   * Used when multiple gated fields reference the same file and mint/download
   * did not pin a field key. Prefer assurance over signed_url, etc.
   */
  private const METHOD_STRICTNESS = [
    'assurance' => 100,
    'otp' => 80,
    'token' => 70,
    'form' => 60,
    'commerce' => 55,
    'authenticated' => 40,
    'referrer_lock' => 30,
    'signed_url' => 10,
  ];

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
   * @param \Drupal\file\FileInterface $file
   *   The file to inspect.
   * @param string|null $field_key
   *   Optional field storage id ("entity_type.field_name"). When set, only that
   *   field is considered (must be gated and must reference the file). When
   *   NULL, the strictest gated field wins among all references.
   *
   * @return array{method: string, field: string, settings: array}|null
   *   The resolved gate (method plugin id, "entity_type.field_name", and the
   *   method's settings), or NULL when no gated field references the file.
   */
  public function getGateForFile(FileInterface $file, ?string $field_key = NULL): ?array {
    // Only private-scheme files can ever be gated — public files are served
    // straight off disk by the web server/CDN and never reach Drupal, so there
    // is no request to gate.
    //
    // Returning NULL here is correct but says nothing, and a field marked
    // gated whose files are public is the module's worst state: the config
    // claims protection that does not exist. Detecting it is deliberately not
    // done on this hot path — GatedFieldSchemeValidator rejects the
    // combination at config import, and file_gate_requirements() reports any
    // site already in it. Both look at field storages directly, so neither
    // costs a per-request query.
    if ($this->streamWrapperManager->getScheme((string) $file->getFileUri()) !== 'private') {
      return NULL;
    }

    $candidates = $this->collectGates($file);
    if ($candidates === []) {
      return NULL;
    }

    if ($field_key !== NULL && $field_key !== '') {
      foreach ($candidates as $gate) {
        if ($gate['field'] === $field_key) {
          return $gate;
        }
      }
      // Explicit field requested but not gated / not referencing this file.
      return NULL;
    }

    // Strictest-wins among all gated references (deterministic multi-field).
    usort($candidates, function (array $a, array $b): int {
      $sa = self::METHOD_STRICTNESS[$a['method']] ?? 0;
      $sb = self::METHOD_STRICTNESS[$b['method']] ?? 0;
      if ($sa !== $sb) {
        return $sb <=> $sa;
      }
      // Stable tie-break: field key string.
      return $a['field'] <=> $b['field'];
    });
    return $candidates[0];
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

  /**
   * All gated field keys that reference the file.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return list<string>
   *   Field storage ids (entity_type.field_name).
   */
  public function gatedFieldKeys(FileInterface $file): array {
    if ($this->streamWrapperManager->getScheme((string) $file->getFileUri()) !== 'private') {
      return [];
    }
    $keys = [];
    foreach ($this->collectGates($file) as $gate) {
      $keys[] = $gate['field'];
    }
    sort($keys);
    return $keys;
  }

  /**
   * Collects all gated field configs that reference the file.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return list<array{method: string, field: string, settings: array}>
   *   Zero or more gate configs.
   */
  private function collectGates(FileInterface $file): array {
    $field_storage_storage = $this->entityTypeManager->getStorage('field_storage_config');
    $out = [];
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
      $out[] = [
        'method' => (string) ($field_storage->getThirdPartySetting('file_gate', 'method') ?: 'signed_url'),
        'field' => $usage->entityTypeId . '.' . $usage->fieldName,
        'settings' => (array) $field_storage->getThirdPartySetting('file_gate', 'method_settings', []),
      ];
    }
    return $out;
  }

}
