<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file\FileInterface;
use Drupal\file_gate\Controller\MintController;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Identity-aware mint when the referencing host is a user entity.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class UserHostIdentityMintTest extends KernelTestBase {

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
  ];

  /**
   * Shared mint secret.
   */
  private const SECRET = 'user-host-mint-secret';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installSchema('file', ['file_usage']);
    $this->installConfig(['field', 'file', 'file_gate', 'user']);

    $this->setSetting('file_private_path', $this->siteDirectory . '/private');
    $this->container->get('stream_wrapper_manager')
      ->registerWrapper('private', PrivateStream::class, StreamWrapperInterface::WRITE_VISIBLE);

    $this->config('file_gate.settings')->set('download_secret', self::SECRET)->save();

    FieldStorageConfig::create([
      'entity_type' => 'user',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'signed_url')
      ->save();
    FieldConfig::create([
      'entity_type' => 'user',
      'field_name' => 'field_gated',
      'bundle' => 'user',
    ])->save();
  }

  /**
   * The user who owns the host account can mint.
   */
  public function testOwnerMintsOwnUserFile(): void {
    $owner = $this->createUser([]);
    $file = $this->attachFileToUser($owner);

    $response = MintController::create($this->container)->mint($this->mintRequest([
      'file' => $file->uuid(),
      'account' => $owner->uuid(),
    ]));
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getContent());
  }

  /**
   * A different account without administer-users cannot mint that file.
   */
  public function testOtherUserCannotMint(): void {
    $owner = $this->createUser([]);
    $other = $this->createUser([]);
    $file = $this->attachFileToUser($owner);

    $response = MintController::create($this->container)->mint($this->mintRequest([
      'file' => $file->uuid(),
      'account' => $other->uuid(),
    ]));
    $this->assertSame(403, $response->getStatusCode(), (string) $response->getContent());
  }

  /**
   * Attaches a gated private file to a user account.
   */
  private function attachFileToUser(UserInterface $user): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/user-host-' . $user->id() . '.pdf';
    file_put_contents($uri, 'BYTES');
    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->setOwnerId((int) $user->id());
    $file->save();

    $account = User::load($user->id());
    $this->assertInstanceOf(User::class, $account);
    $account->set('field_gated', ['target_id' => $file->id()]);
    $account->save();
    \Drupal::service('file.usage')->add($file, 'file', 'user', (string) $account->id());
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
