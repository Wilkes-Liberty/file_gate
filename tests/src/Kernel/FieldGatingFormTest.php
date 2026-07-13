<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\field\Entity\FieldStorageConfig;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the field-gating persistence helper behind the field settings form.
 *
 * The form wiring (hook_form_FORM_ID_alter, validation, submit) is thin glue
 * around _file_gate_apply_field_gating(); this exercises that logic directly.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class FieldGatingFormTest extends KernelTestBase {

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
  }

  /**
   * Enabling gating forces private storage and records the method.
   */
  public function testEnableGatingForcesPrivateAndRecordsMethod(): void {
    $storage = FieldStorageConfig::create([
      'entity_type' => 'user',
      'field_name' => 'field_doc',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'public'],
    ]);
    $storage->save();

    $this->assertTrue(_file_gate_apply_field_gating($storage, TRUE, 'token'));
    $this->assertSame('private', $storage->getSetting('uri_scheme'));
    $this->assertTrue($storage->getThirdPartySetting('file_gate', 'gated', FALSE));
    $this->assertSame('token', $storage->getThirdPartySetting('file_gate', 'method'));
  }

  /**
   * Disabling gating removes the settings and leaves the scheme untouched.
   */
  public function testDisableGatingRemovesSettings(): void {
    $storage = FieldStorageConfig::create([
      'entity_type' => 'user',
      'field_name' => 'field_doc',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'token');
    $storage->save();

    $this->assertTrue(_file_gate_apply_field_gating($storage, FALSE, 'signed_url'));
    $this->assertFalse($storage->getThirdPartySetting('file_gate', 'gated', FALSE));
    $this->assertNull($storage->getThirdPartySetting('file_gate', 'method'));
    $this->assertSame('private', $storage->getSetting('uri_scheme'));
  }

  /**
   * Re-applying identical gating reports no change (idempotent).
   */
  public function testNoChangeIsIdempotent(): void {
    $storage = FieldStorageConfig::create([
      'entity_type' => 'user',
      'field_name' => 'field_doc',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'token');
    $storage->save();

    $this->assertFalse(_file_gate_apply_field_gating($storage, TRUE, 'token'));
  }

}
