<?php

declare(strict_types=1);

namespace Drupal\file_gate\Compatibility;

/**
 * Drupal 11.4.7 core backport for supported older core releases (GPL-2.0+).
 *
 * @see https://git.drupalcode.org/project/drupal/-/blob/11.4.7/core/modules/file/src/FileReferenceUsage.php
 *
 * Provides information which field on a given entity uses a file.
 *
 * @see \Drupal\file_gate\Compatibility\FileReferenceResolver::loadEntityFromUsage()
 */
readonly class FileReferenceUsage {

  /**
   * Constructs a FileReferenceUsage object.
   *
   * @param string $entityTypeId
   *   The entity type.
   * @param string $fieldName
   *   The name of the field that contains the reference.
   * @param string|int|null $id
   *   The entity ID.
   * @param int|string|null $revisionId
   *   The revision ID.
   */
  public function __construct(
    public string $entityTypeId,
    public string $fieldName,
    public int|string|null $id = NULL,
    public int|string|null $revisionId = NULL,
  ) {
    if (is_null($id) && is_null($revisionId)) {
      throw new \InvalidArgumentException('$id and $revisionId cannot both be null.');
    }
  }

}
