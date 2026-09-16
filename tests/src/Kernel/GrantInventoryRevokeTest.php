<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\entity_test\Entity\EntityTest;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file_gate\Controller\DownloadController;
use Drupal\file_gate\Controller\GrantInventoryController;
use Drupal\file_gate\Controller\MintController;
use Drupal\file_gate\Controller\RevokeController;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Pins that single-jti revoke spends the grant and drops inventory.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class GrantInventoryRevokeTest extends KernelTestBase {

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
   * The signing / mint secret used in the tests.
   */
  private const SECRET = 'file-gate-test-secret';

  /**
   * Field storage key for the gated test field.
   */
  private const FIELD = 'entity_test.field_gated';

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

    $this->config('file_gate.settings')->set('download_secret', self::SECRET)->save();

    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'signed_url')
      ->setThirdPartySetting('file_gate', 'method_settings', ['max_uses' => 1])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * Revoking by jti empties the inventory list and denies later download.
   */
  public function testSingleJtiRevokeDropsInventoryAndDeniesDownload(): void {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/once.pdf';
    file_put_contents($uri, 'BYTES:once.pdf');

    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();
    $entity = EntityTest::create(['name' => 'host', 'field_gated' => ['target_id' => $file->id()]]);
    $entity->save();
    \Drupal::service('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());

    $mint = MintController::create($this->container)
      ->mint($this->secretRequest('POST', '/api/file-gate/mint', json_encode(['file' => $file->uuid()])));
    $this->assertSame(Response::HTTP_OK, $mint->getStatusCode());
    $path = json_decode((string) $mint->getContent(), TRUE)['path'];
    $query = [];
    parse_str((string) parse_url($path, PHP_URL_QUERY), $query);
    $this->assertNotEmpty($query['jti']);

    $listed = GrantInventoryController::create($this->container)
      ->list($this->secretRequest('GET', '/api/file-gate/grants', NULL, ['field' => self::FIELD]));
    $this->assertSame(Response::HTTP_OK, $listed->getStatusCode());
    $before = json_decode((string) $listed->getContent(), TRUE);
    $this->assertSame(1, $before['count']);
    $this->assertSame($query['jti'], $before['grants'][0]['jti']);

    $revoked = RevokeController::create($this->container)
      ->revoke($this->secretRequest('POST', '/api/file-gate/revoke', json_encode(['jti' => $query['jti']])));
    $this->assertSame(Response::HTTP_NO_CONTENT, $revoked->getStatusCode());

    $after = GrantInventoryController::create($this->container)
      ->list($this->secretRequest('GET', '/api/file-gate/grants', NULL, ['field' => self::FIELD]));
    $this->assertSame(Response::HTTP_OK, $after->getStatusCode());
    $payload = json_decode((string) $after->getContent(), TRUE);
    $this->assertSame(0, $payload['count']);
    $this->assertSame([], $payload['grants']);

    $this->expectException(AccessDeniedHttpException::class);
    DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
  }

  /**
   * Builds an authenticated mint/revoke/list request.
   *
   * @param string $method
   *   HTTP method.
   * @param string $path
   *   Request path.
   * @param string|null $body
   *   JSON body, or NULL for none.
   * @param array<string, string> $query
   *   Query parameters.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The request.
   */
  private function secretRequest(string $method, string $path, ?string $body = NULL, array $query = []): Request {
    $request = Request::create($path, $method, $query, [], [], [], $body ?? '');
    $request->headers->set('Authorization', 'Basic ' . base64_encode('file-gate:' . self::SECRET));
    return $request;
  }

}
