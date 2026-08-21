<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\Entity\EntityInterface;

/**
 * Walks nested entity hosts (paragraphs, inline entities) up to the parent.
 *
 * File usage often records the child that holds the file field, not the
 * parent the visitor is actually authorized against. Identity-aware mint
 * must require view access on every ancestor as well.
 *
 * Duck-typed on getParentEntity() so this module does not depend on
 * Paragraphs or Inline Entity Form.
 */
final class ParentWalker {

  /**
   * Maximum ancestors walked (cycle guard).
   */
  private const MAX_DEPTH = 8;

  /**
   * Returns $entity followed by each getParentEntity() ancestor.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The usage host.
   *
   * @return list<\Drupal\Core\Entity\EntityInterface>
   *   The chain, starting with $entity. Never empty.
   */
  public function chain(EntityInterface $entity): array {
    $chain = [$entity];
    $current = $entity;
    $seen = [$this->key($entity) => TRUE];
    $depth = 0;
    while ($depth++ < self::MAX_DEPTH && method_exists($current, 'getParentEntity')) {
      $parent = $current->getParentEntity();
      if (!$parent instanceof EntityInterface) {
        break;
      }
      $key = $this->key($parent);
      if (isset($seen[$key])) {
        break;
      }
      $seen[$key] = TRUE;
      $chain[] = $parent;
      $current = $parent;
    }
    return $chain;
  }

  /**
   * Stable identity for cycle detection.
   */
  private function key(EntityInterface $entity): string {
    return $entity->getEntityTypeId() . ':' . (string) $entity->id();
  }

}
