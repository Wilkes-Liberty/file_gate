<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\Session\AnonymousUserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\entity_test\Entity\EntityTestRev;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file_gate\Compatibility\FileReferenceResolver;
use Drupal\file_gate\FileGateResolver;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Historical references remain gated when older core lacks the native resolver.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class LegacyFileReferencesTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'field', 'file', 'file_gate', 'entity_test'];

  /**
   * A current reference becomes revision-only without losing its gate.
   */
  public function testRevisionReferenceAndFreshUsage(): void {
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installEntitySchema('entity_test_rev');
    $this->installSchema('file', ['file_usage']);
    $this->installConfig(['field', 'file', 'file_gate']);
    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
    FieldStorageConfig::create([
      'entity_type' => 'entity_test_rev',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'signed_url')->save();
    FieldConfig::create([
      'entity_type' => 'entity_test_rev',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test_rev',
    ])->save();
    $file = File::create(['uri' => 'private://qualification.txt', 'status' => 1]);
    $file->save();
    $references = new FileReferenceResolver(
      $this->container->get('entity_type.manager'),
      $this->container->get('file.usage'),
    );
    $this->assertSame([], iterator_to_array($references->getReferences($file)));
    $host = EntityTestRev::create(['name' => 'Synthetic host', 'field_gated' => ['target_id' => $file->id()]]);
    $host->save();
    $original_revision = $host->getRevisionId();
    $this->container->get('file.usage')->add($file, 'file', 'entity_test_rev', (string) $host->id());
    $current = iterator_to_array($references->getReferences($file));
    $this->assertCount(1, $current);
    $this->assertSame((string) $host->id(), (string) $current[0]->id);
    $host->setNewRevision(TRUE);
    $host->set('field_gated', []);
    $host->save();
    $historical = iterator_to_array($references->getReferences($file));
    $this->assertCount(1, $historical);
    $this->assertNull($historical[0]->id);
    $this->assertSame((string) $original_revision, (string) $historical[0]->revisionId);
    $loaded = $references->loadEntityFromUsage($historical[0]);
    $this->assertSame((string) $file->id(), (string) $loaded->get('field_gated')->target_id);
    $resolver = new FileGateResolver(
      $references,
      $this->container->get('entity_type.manager'),
      $this->container->get('stream_wrapper_manager'),
    );
    $this->assertTrue($resolver->isGated($file));
    $this->container->set('file_gate.resolver', $resolver);
    $this->assertSame(-1, file_gate_file_download($file->getFileUri()));
  }

}
