<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Unit;

use Drupal\Core\Entity\EntityInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\file_gate\ParentWalker;
use PHPUnit\Framework\Attributes\Group;

/**
 * Unit tests for nested-host parent walking.
 */
#[Group('file_gate')]
final class ParentWalkerTest extends UnitTestCase {

  /**
   * An entity without getParentEntity is a one-item chain.
   */
  public function testEntityWithoutParentMethodIsItself(): void {
    $entity = $this->createMock(EntityInterface::class);
    $entity->method('getEntityTypeId')->willReturn('user');
    $entity->method('id')->willReturn('4');

    $chain = (new ParentWalker())->chain($entity);
    $this->assertSame([$entity], $chain);
  }

}
