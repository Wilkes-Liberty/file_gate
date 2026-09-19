<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\Form\FormState;
use Drupal\Core\Form\FormStateInterface;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\KernelTests\KernelTestBase;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * The real field edit form still saves with the save guard in place.
 *
 * Core saves the field storage from its subform before this module's submit
 * handler runs, so the guard sees that save first. These tests submit the core
 * form itself rather than the helper behind it.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class FieldGatingFormSubmitTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'field_ui',
    'file',
    'file_gate',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installSchema('file', ['file_usage']);
    $this->installConfig(['system', 'field', 'file']);
  }

  /**
   * Creates a file field on the user entity.
   */
  private function makeField(string $scheme, bool $gated): FieldConfig {
    $storage = FieldStorageConfig::create([
      'field_name' => 'field_doc',
      'entity_type' => 'user',
      'type' => 'file',
      'settings' => ['uri_scheme' => $scheme],
    ]);
    if ($gated) {
      $storage->setThirdPartySetting('file_gate', 'gated', TRUE);
      $storage->setThirdPartySetting('file_gate', 'method', 'signed_url');
    }
    $storage->save();
    $field = FieldConfig::create([
      'field_storage' => $storage,
      'bundle' => 'user',
      'label' => 'Document',
    ]);
    $field->save();
    return $field;
  }

  /**
   * Submits the core field edit form with the given File Gate values.
   *
   * @return \Drupal\Core\Form\FormStateInterface
   *   The submitted form state.
   */
  private function submit(FieldConfig $field, bool $gated, string $scheme): FormStateInterface {
    $form_object = $this->container->get('entity_type.manager')->getFormObject('field_config', 'edit');
    $form_object->setEntity($field);
    $form_state = (new FormState())->setValues([
      'label' => 'Document',
      // A browser leaves an unticked checkbox out of the post. Any value that
      // is present, 0 included, reads as ticked.
      'file_gate_gated' => $gated ? 1 : NULL,
      'file_gate_method' => 'signed_url',
      'field_storage' => [
        'subform' => [
          'settings' => ['uri_scheme' => $scheme],
          'cardinality' => 'number',
          'cardinality_number' => 1,
        ],
      ],
      'op' => 'Save settings',
    ]);
    $this->container->get('form_builder')->submitForm($form_object, $form_state);
    return $form_state;
  }

  /**
   * Reads the saved gated flag and scheme.
   *
   * @return array{0: bool, 1: ?string}
   *   The gated flag and the scheme.
   */
  private function saved(): array {
    $data = $this->container->get('config.storage')->read('field.storage.user.field_doc');
    $this->assertIsArray($data);
    return [
      !empty($data['third_party_settings']['file_gate']['gated']),
      $data['settings']['uri_scheme'] ?? NULL,
    ];
  }

  /**
   * Enabling gating on a public field saves it as gated and private.
   */
  public function testEnablingGatingThroughTheFormForcesPrivate(): void {
    $form_state = $this->submit($this->makeField('public', FALSE), TRUE, 'public');

    $this->assertSame([], $form_state->getErrors());
    $this->assertSame([TRUE, 'private'], $this->saved());
  }

  /**
   * Ungating and moving to public in one submit is not refused.
   */
  public function testUngatingAndMovingToPublicInOneSubmit(): void {
    $form_state = $this->submit($this->makeField('private', TRUE), FALSE, 'public');

    $this->assertSame([], $form_state->getErrors());
    $this->assertSame([FALSE, 'public'], $this->saved());
    $this->assertSame([], $this->container->get('messenger')->messagesByType('error'));
  }

  /**
   * A public field that already holds files still cannot be gated.
   *
   * Gating it would mark the field protected while its existing files stay
   * public. The entity builder forces the private scheme on the storage being
   * built, so this proves the validator still sees the stored scheme.
   */
  public function testPublicFieldWithDataStillCannotBeGated(): void {
    $field = $this->makeField('public', FALSE);
    $file = File::create(['uri' => 'public://existing.pdf', 'filename' => 'existing.pdf']);
    $file->save();
    $account = User::create(['name' => 'holder', 'field_doc' => ['target_id' => $file->id()]]);
    $account->save();
    $stored = FieldStorageConfig::loadByName('user', 'field_doc');
    $this->assertInstanceOf(FieldStorageConfig::class, $stored);
    $this->assertTrue($stored->hasData());

    $form_state = $this->submit($field, TRUE, 'public');

    $this->assertArrayHasKey('file_gate_gated', $form_state->getErrors());
    $this->assertSame([FALSE, 'public'], $this->saved());
  }

  /**
   * A gated field cannot be moved to public by posting the scheme directly.
   *
   * The scheme select is only disabled in the browser; a crafted post still
   * carries it.
   */
  public function testGatedFieldPostedWithPublicSchemeStaysPrivate(): void {
    $this->submit($this->makeField('private', TRUE), TRUE, 'public');

    $this->assertSame([TRUE, 'private'], $this->saved());
  }

}
