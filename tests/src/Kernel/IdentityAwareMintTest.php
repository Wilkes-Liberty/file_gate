<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\entity_test\Entity\EntityTest;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file\FileInterface;
use Drupal\file_gate\Controller\MintController;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Kernel tests for optional identity-aware mint (#31).
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class IdentityAwareMintTest extends KernelTestBase {

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
    'entity_test',
  ];

  /**
   * Shared mint secret.
   */
  private const SECRET = 'identity-mint-secret';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installEntitySchema('entity_test');
    $this->installSchema('file', ['file_usage']);
    $this->installConfig(['field', 'file', 'file_gate', 'user']);

    $this->setSetting('file_private_path', $this->siteDirectory . '/private');
    $this->container->get('stream_wrapper_manager')
      ->registerWrapper('private', PrivateStream::class, StreamWrapperInterface::WRITE_VISIBLE);

    $this->config('file_gate.settings')->set('download_secret', self::SECRET)->save();

    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'signed_url')
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();
  }

  /**
   * Creates a gated private file on entity_test.
   */
  private function createFile(): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/id-aware.pdf';
    file_put_contents($uri, 'BYTES');
    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();
    $entity = EntityTest::create(['name' => 'host', 'field_gated' => ['target_id' => $file->id()]]);
    $entity->save();
    \Drupal::service('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());
    return $file;
  }

  /**
   * Builds a mint request.
   */
  private function mintRequest(array $body): Request {
    $request = Request::create('/api/file-gate/mint', 'POST', [], [], [], [], (string) json_encode($body));
    $request->headers->set('Content-Type', 'application/json');
    $request->headers->set('Authorization', 'Basic ' . base64_encode(':' . self::SECRET));
    return $request;
  }

  /**
   * Omitting account/uid still mints (optional).
   */
  public function testMintWithoutActingAccountStillWorks(): void {
    $file = $this->createFile();
    $response = MintController::create($this->container)
      ->mint($this->mintRequest(['file' => $file->uuid()]));
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * Unknown account uuid fails closed.
   */
  public function testUnknownAccountUuidFailsClosed(): void {
    $file = $this->createFile();
    $response = MintController::create($this->container)->mint($this->mintRequest([
      'file' => $file->uuid(),
      'account' => '00000000-0000-0000-0000-000000000099',
    ]));
    $this->assertSame(403, $response->getStatusCode());
  }

  /**
   * User without download access is refused.
   */
  public function testUserWithoutDownloadAccessRefused(): void {
    $file = $this->createFile();
    // Anonymous-equivalent authenticated user without special rights.
    $user = $this->createUser([]);
    $this->assertInstanceOf(User::class, $user);

    // entity_test is typically viewable; file download may still be allowed for
    // owners — force deny via file access by using a blocked user.
    $user->block();
    $user->save();

    $response = MintController::create($this->container)->mint($this->mintRequest([
      'file' => $file->uuid(),
      'uid' => (int) $user->id(),
    ]));
    // Blocked users cannot download in core.
    $this->assertSame(403, $response->getStatusCode());
  }

  /**
   * File owner with host view access can mint when named by uuid.
   */
  public function testUserWithAccessMintsByUuid(): void {
    $file = $this->createFile();
    $user = $this->createUser(['access content', 'view test entity']);
    $this->assertInstanceOf(User::class, $user);
    $file->setOwnerId((int) $user->id());
    $file->save();

    $response = MintController::create($this->container)->mint($this->mintRequest([
      'file' => $file->uuid(),
      'account' => $user->uuid(),
    ]));
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getContent());
    $data = json_decode((string) $response->getContent(), TRUE);
    $this->assertIsArray($data);
    $this->assertStringContainsString('sig=', (string) $data['path']);
  }

}
