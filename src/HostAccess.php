<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\Entity\FieldableEntityInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\file\FileInterface;
use Drupal\file\FileReferenceResolver;

/**
 * Identity-aware mint host checks.
 *
 * Core FileAccessControlHandler grants download when any referencing host
 * is viewable. That is too coarse for a gated personnel file: an account
 * that can view a User (or a paragraph parent) must still be denied when
 * they cannot view the referencing *field*, and a child-entity usage must
 * not skip the parent.
 */
final class HostAccess {

  public function __construct(
    private readonly FileReferenceResolver $fileReferenceResolver,
    private readonly ParentWalker $parentWalker,
  ) {}

  /**
   * Whether $account may be the acting identity for minting $file.
   */
  public function actingAccountMayReach(FileInterface $file, AccountInterface $account): bool {
    if (!$file->access('download', $account)) {
      return FALSE;
    }

    $saw_host = FALSE;
    foreach ($this->fileReferenceResolver->getReferences($file) as $usage) {
      $entity = $this->fileReferenceResolver->loadEntityFromUsage($usage);
      if (!$entity instanceof FieldableEntityInterface) {
        return FALSE;
      }
      $saw_host = TRUE;
      if (!$entity->access('view', $account)) {
        return FALSE;
      }
      if ($entity->hasField($usage->fieldName)) {
        $items = $entity->get($usage->fieldName);
        if (!$items->access('view', $account)) {
          return FALSE;
        }
      }
      foreach ($this->parentWalker->chain($entity) as $ancestor) {
        if (!$ancestor->access('view', $account)) {
          return FALSE;
        }
      }
    }

    // A gated file with no resolvable host is not mintable under identity
    // mint: there is no entity to authorize against.
    return $saw_host;
  }

}
