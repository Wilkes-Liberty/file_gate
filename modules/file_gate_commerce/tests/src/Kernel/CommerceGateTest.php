<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate_commerce\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Session\AnonymousUserSession;
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
use Drupal\file_gate_commerce\CommerceEntitlementChecker;
use Drupal\file_gate_commerce\EntitlementCheckerInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Tests the commerce (purchase / entitlement) gate method.
 *
 * The gate delegation is exercised with a fake entitlement checker; the bundled
 * Commerce checker's fail-closed paths (no Commerce installed, anonymous user)
 * are tested directly. The live Commerce order query needs a Commerce
 * environment and is not exercised here.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class CommerceGateTest extends KernelTestBase {

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
    'file_gate_commerce',
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
      ->setThirdPartySetting('file_gate', 'method', 'commerce')
      ->setThirdPartySetting('file_gate', 'method_settings', ['sku' => 'SKU-1'])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    $this->setUpCurrentUser(['uid' => 2]);
  }

  /**
   * An entitled account is served.
   */
  public function testEntitledGrants(): void {
    $this->setChecker(TRUE);
    $file = $this->createFile('doc.pdf');
    $response = $this->download($file);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A non-entitled account is denied.
   */
  public function testNotEntitledDenied(): void {
    $this->setChecker(FALSE);
    $file = $this->createFile('doc.pdf');
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($file);
  }

  /**
   * With no SKU configured, the method fails closed without asking the checker.
   */
  public function testNoSkuFailsClosed(): void {
    // A checker that would grant — but the empty SKU short-circuits first.
    $this->setChecker(TRUE);
    FieldStorageConfig::loadByName('entity_test', 'field_gated')
      ->setThirdPartySetting('file_gate', 'method_settings', [])
      ->save();
    $file = $this->createFile('doc.pdf');

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($file);
  }

  /**
   * The bundled Commerce checker fails closed without Commerce and for anon.
   */
  public function testCommerceCheckerFailsClosed(): void {
    $checker = new CommerceEntitlementChecker(
      $this->container->get('entity_type.manager'),
      $this->container->get('logger.channel.file_gate'),
    );
    $file = $this->createFile('doc.pdf');
    $account = $this->createUser();

    // Commerce is not installed in this test, so nothing can be entitled.
    $this->assertFalse($checker->isEntitled($account, 'SKU-1', $file));
    // Anonymous is always denied (orders are tied to an account).
    $this->assertFalse($checker->isEntitled(new AnonymousUserSession(), 'SKU-1', $file));
  }

  /**
   * The method decides live: mint returns NULL.
   */
  public function testMintReturnsNull(): void {
    $file = $this->createFile('doc.pdf');
    $method = $this->container->get('plugin.manager.file_gate.gate_method')->createInstance('commerce', ['sku' => 'SKU-1']);
    $this->assertNull($method->mint($file));
  }

  /**
   * The settings form builds and round-trips the SKU.
   */
  public function testSettingsForm(): void {
    $method = $this->container->get('plugin.manager.file_gate.gate_method')->createInstance('commerce', []);
    $form = $method->fieldSettingsForm(['sku' => 'SKU-9']);
    $this->assertArrayHasKey('sku', $form);
    $this->assertSame('SKU-9', $form['sku']['#default_value']);

    $this->assertSame(['sku' => 'ABC'], $method->fieldSettingsSubmit(['sku' => ' ABC ']));
    $this->assertSame([], $method->fieldSettingsSubmit(['sku' => '  ']));
  }

  /**
   * Swaps in a fake entitlement checker returning the given result.
   *
   * @param bool $result
   *   What the checker should return.
   */
  private function setChecker(bool $result): void {
    $this->container->set('file_gate_commerce.entitlement_checker', new class($result) implements EntitlementCheckerInterface {

      /**
       * Constructs the fake checker.
       *
       * @param bool $result
       *   The fixed entitlement result to return.
       */
      public function __construct(private readonly bool $result) {}

      /**
       * {@inheritdoc}
       */
      public function isEntitled(AccountInterface $account, string $entitlement, FileInterface $file): bool {
        return $this->result;
      }

    });
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
