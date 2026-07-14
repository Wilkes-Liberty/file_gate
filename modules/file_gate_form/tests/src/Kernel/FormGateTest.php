<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate_form\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\Form\FormState;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\entity_test\Entity\EntityTest;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file\FileInterface;
use Drupal\file_gate\Controller\DownloadController;
use Drupal\file_gate_form\Form\FileGateForm;
use Drupal\file_gate_form\Plugin\GateMethod\FormGate;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Tests the coupled form-capture gate method and its form.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class FormGateTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'file',
    'file_gate',
    'file_gate_form',
    'entity_test',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installEntitySchema('entity_test');
    $this->installSchema('file', ['file_usage']);
    $this->installConfig(['field', 'file', 'file_gate']);

    $this->setSetting('file_private_path', $this->siteDirectory . '/private');
    $this->container->get('stream_wrapper_manager')
      ->registerWrapper('private', PrivateStream::class, StreamWrapperInterface::WRITE_VISIBLE);
    $this->config('file_gate.settings')->set('download_secret', 'file-gate-test-secret')->save();

    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'form')
      ->setThirdPartySetting('file_gate', 'method_settings', ['ttl' => 3600])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    // Use an authenticated user so the per-session grant (private tempstore)
    // has a stable owner in the kernel context.
    $this->setUpCurrentUser(['uid' => 2]);
  }

  /**
   * Submitting the form records a grant and the download then streams.
   */
  public function testSubmitGrantsDownload(): void {
    $file = $this->createFile('doc.pdf');
    $this->submitForm($file, 'lead@example.com');

    // The grant was recorded for this session.
    $this->assertNotEmpty($this->grantStore()->get($file->uuid()));

    $response = $this->download($file);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * Without a submission, the download is denied.
   */
  public function testNoSubmissionDenied(): void {
    $file = $this->createFile('doc.pdf');
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($file);
  }

  /**
   * A grant older than the TTL is denied.
   */
  public function testExpiredGrantDenied(): void {
    $file = $this->createFile('doc.pdf');
    // Simulate a grant recorded well beyond the 3600s TTL.
    $old = $this->container->get('datetime.time')->getRequestTime() - 4000;
    $this->grantStore()->set($file->uuid(), $old);

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($file);
  }

  /**
   * A honeypot-tripped submission is rejected and grants nothing.
   */
  public function testHoneypotRejected(): void {
    $file = $this->createFile('doc.pdf');
    $form_object = FileGateForm::create($this->container);
    $form_state = new FormState();
    $form_state->setValues(['email' => 'bot@example.com', 'hp_url' => 'http://spam.example']);
    $form = $form_object->buildForm([], $form_state, $file->uuid());
    $form_object->validateForm($form, $form_state);

    $this->assertNotEmpty($form_state->getErrors());
    $this->assertEmpty($this->grantStore()->get($file->uuid()));
  }

  /**
   * The method decides live: mint returns NULL.
   */
  public function testMintReturnsNull(): void {
    $file = $this->createFile('doc.pdf');
    $method = $this->container->get('plugin.manager.file_gate.gate_method')->createInstance('form', ['ttl' => 3600]);
    $this->assertNull($method->mint($file));
  }

  /**
   * The settings form builds and round-trips its values.
   */
  public function testSettingsForm(): void {
    $method = $this->container->get('plugin.manager.file_gate.gate_method')->createInstance('form', []);
    $form = $method->fieldSettingsForm(['ttl' => 1800]);
    $this->assertArrayHasKey('ttl', $form);
    $this->assertArrayHasKey('require_consent', $form);

    $settings = $method->fieldSettingsSubmit([
      'ttl' => '1800',
      'require_consent' => 1,
      'consent_text' => ' Yes ',
      'intro_text' => '',
    ]);
    $this->assertSame(1800, $settings['ttl']);
    $this->assertTrue($settings['require_consent']);
    $this->assertSame('Yes', $settings['consent_text']);
    $this->assertArrayNotHasKey('intro_text', $settings);
  }

  /**
   * Builds and submits the capture form for a file.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   * @param string $email
   *   The email to submit.
   */
  private function submitForm(FileInterface $file, string $email): void {
    $form_object = FileGateForm::create($this->container);
    $form_state = new FormState();
    $form_state->setValues(['email' => $email, 'hp_url' => '', 'consent' => FALSE]);
    $form = $form_object->buildForm([], $form_state, $file->uuid());
    $form_object->validateForm($form, $form_state);
    $this->assertEmpty($form_state->getErrors());
    $form_object->submitForm($form, $form_state);
  }

  /**
   * The private-tempstore collection holding grants.
   *
   * @return \Drupal\Core\TempStore\PrivateTempStore
   *   The store.
   */
  private function grantStore() {
    return $this->container->get('tempstore.private')->get(FormGate::GRANT_COLLECTION);
  }

  /**
   * Redeems the download for a file.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  private function download(FileInterface $file) {
    return DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', ['f' => $file->uuid()]));
  }

  /**
   * Creates a private file referenced by an entity_test via the gated field.
   *
   * @param string $filename
   *   The file name.
   *
   * @return \Drupal\file\FileInterface
   *   The referenced file.
   */
  private function createFile(string $filename): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);
    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();
    $entity = EntityTest::create(['name' => 'host', 'field_gated' => ['target_id' => $file->id()]]);
    $entity->save();
    \Drupal::service('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());
    return $file;
  }

}
