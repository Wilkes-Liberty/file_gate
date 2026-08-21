<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperManagerInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\entity_test\Entity\EntityTest;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file\FileInterface;
use Drupal\file_gate\Controller\MintController;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Identity-aware mint honors field-level view access on the referencing field.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class FieldAccessIdentityMintTest extends KernelTestBase {

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
    'file_gate_test_field_access',
  ];

  /**
   * Shared mint secret.
   */
  private const SECRET = 'field-access-mint-secret';

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
      ->registerWrapper('private', PrivateStream::class, StreamWrapperManagerInterface::WRITE_VISIBLE);

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
   * Host view without field view is not enough.
   */
  public function testHostViewWithoutFieldViewIsDenied(): void {
    $user = $this->createUser(['access content', 'view test entity']);
    $this->assertInstanceOf(UserInterface::class, $user);
    $file = $this->createFile($user);

    $response = MintController::create($this->container)->mint($this->mintRequest([
      'file' => $file->uuid(),
      'account' => $user->uuid(),
    ]));
    $this->assertSame(403, $response->getStatusCode(), (string) $response->getContent());
  }

  /**
   * Named field-view permission allows mint.
   */
  public function testFieldViewPermissionAllowsMint(): void {
    $user = $this->createUser([
      'access content',
      'view test entity',
      'view gated test field',
    ]);
    $this->assertInstanceOf(UserInterface::class, $user);
    $file = $this->createFile($user);

    $response = MintController::create($this->container)->mint($this->mintRequest([
      'file' => $file->uuid(),
      'account' => $user->uuid(),
    ]));
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getContent());
  }

  /**
   * Creates a gated private file on entity_test owned by $user.
   */
  private function createFile(UserInterface $user): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/field-access-' . $user->id() . '.pdf';
    file_put_contents($uri, 'BYTES');
    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->setOwnerId((int) $user->id());
    $file->save();
    $entity = EntityTest::create([
      'name' => 'open-host',
      'field_gated' => ['target_id' => $file->id()],
    ]);
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

}
