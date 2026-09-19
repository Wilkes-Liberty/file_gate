<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\Config\ConfigCrudEvent;
use Drupal\Core\Config\ConfigEvents;
use Drupal\Core\Config\ConfigImporter;
use Drupal\Core\Config\ConfigImporterException;
use Drupal\Core\Config\StorageComparer;
use Drupal\Core\Extension\Requirement\RequirementSeverity;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file_gate\Exception\GatedPublicSchemeException;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * A gated field on a public scheme is refused at save, on every write path.
 *
 * The form and the import validator were the only two guards. Anything else
 * that saved a field storage wrote the combination and left files public.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class GatedFieldSchemeSaveTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'field', 'file', 'file_gate'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installSchema('user', ['users_data']);
    $this->installConfig(['system']);
  }

  /**
   * Creates and saves a file field storage that is allowed to exist.
   */
  private function makeStorage(string $name, string $scheme, bool $gated): FieldStorageConfig {
    $storage = FieldStorageConfig::create([
      'field_name' => $name,
      'entity_type' => 'user',
      'type' => 'file',
      'settings' => ['uri_scheme' => $scheme],
    ]);
    if ($gated) {
      $storage->setThirdPartySetting('file_gate', 'gated', TRUE);
      $storage->setThirdPartySetting('file_gate', 'method', 'signed_url');
    }
    $storage->save();
    return $storage;
  }

  /**
   * Puts a storage into the offending state the way an older site got there.
   *
   * Written straight to the active storage: no entity hook and no config
   * event runs, which is what "already in this state before the guard
   * existed" means.
   */
  private function makeLegacyOffender(string $name, string $scheme = 'public'): void {
    $this->makeStorage($name, $scheme, FALSE);
    $active = $this->container->get('config.storage');
    $data = $active->read('field.storage.user.' . $name);
    $data['third_party_settings']['file_gate'] = ['gated' => TRUE, 'method' => 'signed_url'];
    // The entity save that really produced this state recorded the dependency.
    $data['dependencies']['module'][] = 'file_gate';
    sort($data['dependencies']['module']);
    $active->write('field.storage.user.' . $name, $data);
    $this->container->get('config.factory')->reset('field.storage.user.' . $name);
    $this->container->get('entity_type.manager')->getStorage('field_storage_config')->resetCache();
  }

  /**
   * Reads the active third-party gated flag and scheme, bypassing caches.
   *
   * @return array{0: bool, 1: ?string}
   *   The gated flag and the scheme.
   */
  private function activeState(string $name): array {
    $data = $this->container->get('config.storage')->read('field.storage.user.' . $name);
    $this->assertIsArray($data);
    return [
      !empty($data['third_party_settings']['file_gate']['gated']),
      $data['settings']['uri_scheme'] ?? NULL,
    ];
  }

  /**
   * Creating the combination through the entity API is refused.
   */
  public function testCreatingGatedPublicStorageIsRefused(): void {
    try {
      $this->makeStorage('field_leaky', 'public', TRUE);
      $this->fail('A gated public field storage was saved.');
    }
    catch (GatedPublicSchemeException $e) {
      $this->assertStringContainsString('user.field_leaky', $e->getMessage());
      $this->assertStringContainsString('private', $e->getMessage());
    }
    $this->assertFalse($this->container->get('config.storage')->exists('field.storage.user.field_leaky'));
  }

  /**
   * A refused entity save reaches neither config storage nor a subscriber.
   *
   * The raw config subscriber would also stop this save, but only after the
   * write. The entity hook refuses first, so nothing is written, nothing is
   * put back, and no other subscriber (audit, cache) sees a write at all.
   */
  public function testRefusedEntitySaveWritesNothing(): void {
    $storage = $this->makeStorage('field_doc', 'private', TRUE);
    $writes = 0;
    $this->container->get('event_dispatcher')->addListener(ConfigEvents::SAVE, function (ConfigCrudEvent $event) use (&$writes): void {
      if ($event->getConfig()->getName() === 'field.storage.user.field_doc') {
        $writes++;
      }
    }, 2000);
    $storage->setSetting('uri_scheme', 'public');

    try {
      $storage->save();
      $this->fail('A gated field storage was moved to the public scheme.');
    }
    catch (GatedPublicSchemeException) {
    }
    $this->assertSame(0, $writes, 'The refusal came before any config write.');
  }

  /**
   * A refused create can be corrected and saved under the same name.
   */
  public function testRefusedCreateCanBeRetriedWithPrivateScheme(): void {
    try {
      $this->makeStorage('field_retry', 'public', TRUE);
      $this->fail('A gated public field storage was saved.');
    }
    catch (GatedPublicSchemeException) {
    }

    $this->makeStorage('field_retry', 'private', TRUE);
    $this->assertSame([TRUE, 'private'], $this->activeState('field_retry'));
  }

  /**
   * Marking an existing public storage gated is refused.
   */
  public function testGatingAnExistingPublicStorageIsRefused(): void {
    $storage = $this->makeStorage('field_doc', 'public', FALSE);
    $storage->setThirdPartySetting('file_gate', 'gated', TRUE);

    try {
      $storage->save();
      $this->fail('A public field storage was marked gated.');
    }
    catch (GatedPublicSchemeException) {
    }
    $this->assertSame([FALSE, 'public'], $this->activeState('field_doc'));
  }

  /**
   * Moving a gated private storage to a public scheme is refused.
   */
  public function testMovingGatedStorageOffPrivateIsRefused(): void {
    $storage = $this->makeStorage('field_doc', 'private', TRUE);
    $storage->setSetting('uri_scheme', 'public');

    try {
      $storage->save();
      $this->fail('A gated field storage was moved to the public scheme.');
    }
    catch (GatedPublicSchemeException) {
    }
    $this->assertSame([TRUE, 'private'], $this->activeState('field_doc'));
  }

  /**
   * The allowed combinations still save.
   */
  public function testAllowedCombinationsSave(): void {
    $this->makeStorage('field_gated_private', 'private', TRUE);
    $this->makeStorage('field_plain_public', 'public', FALSE);
    $this->assertSame([TRUE, 'private'], $this->activeState('field_gated_private'));
    $this->assertSame([FALSE, 'public'], $this->activeState('field_plain_public'));
  }

  /**
   * A raw config write (drush config:set, a config tool) is undone and fails.
   *
   * These never load the entity, so no entity hook runs. The write has already
   * reached storage when the config event fires, so it is put back.
   */
  public function testRawConfigWriteThatGatesPublicStorageIsUndone(): void {
    $this->makeStorage('field_doc', 'public', FALSE);
    $config = $this->container->get('config.factory')->getEditable('field.storage.user.field_doc');
    $config->set('third_party_settings.file_gate.gated', TRUE);

    try {
      $config->save();
      $this->fail('A raw config write gated a public field storage.');
    }
    catch (GatedPublicSchemeException) {
    }
    $this->assertSame([FALSE, 'public'], $this->activeState('field_doc'));
  }

  /**
   * A raw config write that moves a gated storage off private is undone.
   */
  public function testRawConfigWriteThatMovesGatedStorageIsUndone(): void {
    $this->makeStorage('field_doc', 'private', TRUE);
    $config = $this->container->get('config.factory')->getEditable('field.storage.user.field_doc');
    $config->set('settings.uri_scheme', 'public');

    try {
      $config->save();
      $this->fail('A raw config write moved a gated field storage to public.');
    }
    catch (GatedPublicSchemeException) {
    }
    $this->assertSame([TRUE, 'private'], $this->activeState('field_doc'));
  }

  /**
   * A raw write that creates the combination from nothing is removed.
   */
  public function testRawConfigWriteThatCreatesTheCombinationIsRemoved(): void {
    $this->makeStorage('field_template', 'public', FALSE);
    $data = $this->container->get('config.storage')->read('field.storage.user.field_template');
    $data['id'] = 'user.field_raw';
    $data['field_name'] = 'field_raw';
    unset($data['uuid']);
    $data['third_party_settings']['file_gate'] = ['gated' => TRUE, 'method' => 'signed_url'];

    try {
      $this->container->get('config.factory')->getEditable('field.storage.user.field_raw')->setData($data)->save();
      $this->fail('A raw config write created a gated public field storage.');
    }
    catch (GatedPublicSchemeException) {
    }
    $this->assertFalse($this->container->get('config.storage')->exists('field.storage.user.field_raw'));
  }

  /**
   * A field type with no uri_scheme is not this rule's business.
   */
  public function testFieldTypeWithoutSchemeIsUnaffected(): void {
    $storage = FieldStorageConfig::create([
      'field_name' => 'field_flag',
      'entity_type' => 'user',
      'type' => 'boolean',
    ]);
    $storage->setThirdPartySetting('file_gate', 'gated', TRUE);
    $storage->save();

    $this->assertTrue(FieldStorageConfig::loadByName('user', 'field_flag')->getThirdPartySetting('file_gate', 'gated'));
  }

  /**
   * A site already in the state can still load, re-save and repair the field.
   *
   * An unrelated re-save (a core update hook, a module uninstall that strips
   * its third-party settings, the field form's own storage save) must not
   * start failing because of a state this save did not create.
   */
  public function testLegacyOffenderCanBeResavedAndRepaired(): void {
    $this->makeLegacyOffender('field_legacy');

    $storage = FieldStorageConfig::loadByName('user', 'field_legacy');
    $this->assertTrue($storage->getThirdPartySetting('file_gate', 'gated'));
    $storage->setCardinality(3);
    $storage->save();
    $this->assertSame([TRUE, 'public'], $this->activeState('field_legacy'));

    // It stays on the status report: allowed to save is not the same as fine.
    $requirements = $this->container->get('module_handler')->invoke('file_gate', 'runtime_requirements');
    $this->assertSame(RequirementSeverity::Error, $requirements['file_gate_public_gated_fields']['severity']);
    $this->assertStringContainsString('field_legacy', (string) $requirements['file_gate_public_gated_fields']['value']);

    $storage = FieldStorageConfig::loadByName('user', 'field_legacy');
    $storage->setSetting('uri_scheme', 'private');
    $storage->save();
    $this->assertSame([TRUE, 'private'], $this->activeState('field_legacy'));
  }

  /**
   * A legacy offender cannot be moved to a different non-private scheme.
   */
  public function testLegacyOffenderCannotChangeToAnotherPublicScheme(): void {
    $this->makeLegacyOffender('field_legacy');
    $storage = FieldStorageConfig::loadByName('user', 'field_legacy');
    $storage->setSetting('uri_scheme', 'temporary');

    try {
      $storage->save();
      $this->fail('A legacy offender changed scheme and stayed off private.');
    }
    catch (GatedPublicSchemeException) {
    }
    $this->assertSame([TRUE, 'public'], $this->activeState('field_legacy'));
  }

  /**
   * A legacy offender can be ungated, and a raw unrelated write is left alone.
   */
  public function testLegacyOffenderAcceptsUnrelatedRawWritesAndUngating(): void {
    $this->makeLegacyOffender('field_legacy');

    $config = $this->container->get('config.factory')->getEditable('field.storage.user.field_legacy');
    $config->set('cardinality', 2)->save();
    $this->assertSame(2, $this->container->get('config.storage')->read('field.storage.user.field_legacy')['cardinality']);

    $this->container->get('entity_type.manager')->getStorage('field_storage_config')->resetCache();
    $storage = FieldStorageConfig::loadByName('user', 'field_legacy');
    $storage->unsetThirdPartySetting('file_gate', 'gated');
    $storage->save();
    $this->assertSame([FALSE, 'public'], $this->activeState('field_legacy'));
  }

  /**
   * Uninstalling the module on a site in the state does not fail.
   */
  public function testUninstallWithLegacyOffender(): void {
    $this->makeLegacyOffender('field_legacy');

    $this->container->get('module_installer')->uninstall(['file_gate']);

    $data = $this->container->get('config.storage')->read('field.storage.user.field_legacy');
    $this->assertArrayNotHasKey('file_gate', $data['third_party_settings'] ?? []);
  }

  /**
   * Validating callers get a violation with a property path before any save.
   */
  public function testSchemaConstraintReportsTheCombination(): void {
    $this->makeStorage('field_doc', 'public', FALSE);
    $typed = $this->container->get('config.typed');
    $data = $this->container->get('config.storage')->read('field.storage.user.field_doc');

    $this->assertCount(0, $this->fileGateViolations($typed->createFromNameAndData('field.storage.user.field_doc', $data)->validate()));

    $data['third_party_settings']['file_gate'] = ['gated' => TRUE, 'method' => 'signed_url'];
    $violations = $this->fileGateViolations($typed->createFromNameAndData('field.storage.user.field_doc', $data)->validate());
    $this->assertCount(1, $violations);
    $this->assertSame('third_party_settings.file_gate.gated', $violations[0]->getPropertyPath());
    $this->assertStringContainsString('private', (string) $violations[0]->getMessage());

    $data['settings']['uri_scheme'] = 'private';
    $this->assertCount(0, $this->fileGateViolations($typed->createFromNameAndData('field.storage.user.field_doc', $data)->validate()));
  }

  /**
   * Keeps only this module's violations.
   *
   * @return list<\Symfony\Component\Validator\ConstraintViolationInterface>
   *   Violations under the file_gate third-party settings.
   */
  private function fileGateViolations(iterable $violations): array {
    $own = [];
    foreach ($violations as $violation) {
      if (str_starts_with($violation->getPropertyPath(), 'third_party_settings.file_gate')) {
        $own[] = $violation;
      }
    }
    return $own;
  }

  /**
   * The import validator still refuses the combination, with the same text.
   */
  public function testImportIsStillRefused(): void {
    $this->makeStorage('field_doc', 'public', FALSE);
    $sync = $this->container->get('config.storage.sync');
    $this->copyConfig($this->container->get('config.storage'), $sync);
    $data = $sync->read('field.storage.user.field_doc');
    $data['third_party_settings']['file_gate'] = ['gated' => TRUE, 'method' => 'signed_url'];
    $sync->write('field.storage.user.field_doc', $data);

    $importer = $this->importer();
    try {
      $importer->import();
      $this->fail('The import of a gated public field storage was accepted.');
    }
    catch (ConfigImporterException) {
      $errors = implode("\n", $importer->getErrors());
      $this->assertStringContainsString('field.storage.user.field_doc', $errors);
      $this->assertStringContainsString('"public"', $errors);
    }
    $this->assertSame([FALSE, 'public'], $this->activeState('field_doc'));
  }

  /**
   * An unrelated import on a site already in the state is not blocked.
   */
  public function testUnrelatedImportWithLegacyOffender(): void {
    $this->makeLegacyOffender('field_legacy');
    $sync = $this->container->get('config.storage.sync');
    $this->copyConfig($this->container->get('config.storage'), $sync);
    $site = $sync->read('system.site');
    $site['slogan'] = 'Unrelated change';
    $sync->write('system.site', $site);

    $this->importer()->import();

    $this->assertSame('Unrelated change', $this->config('system.site')->get('slogan'));
  }

  /**
   * Builds a config importer over the sync storage.
   */
  private function importer(): ConfigImporter {
    $comparer = new StorageComparer(
      $this->container->get('config.storage.sync'),
      $this->container->get('config.storage'),
    );
    $comparer->createChangelist();
    return new ConfigImporter(
      $comparer,
      $this->container->get('event_dispatcher'),
      $this->container->get('config.manager'),
      $this->container->get('lock'),
      $this->container->get('config.typed'),
      $this->container->get('module_handler'),
      $this->container->get('module_installer'),
      $this->container->get('theme_handler'),
      $this->container->get('string_translation'),
      $this->container->get('extension.list.module'),
      $this->container->get('extension.list.theme'),
    );
  }

}
