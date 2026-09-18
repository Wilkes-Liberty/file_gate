<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\entity_test\Entity\EntityTest;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file\FileInterface;
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
 * Pins that single-jti revoke honours named-secret field / k scope.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class GrantInventoryRevokeScopeTest extends KernelTestBase {

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
   * Named secret for the whitepaper field.
   */
  private const PUBLIC_ID = 's_public';

  /**
   * Named secret for the NDA field.
   */
  private const NDA_ID = 's_nda';

  /**
   * Named public secret value.
   */
  private const PUBLIC_SECRET = 'public-tier-secret-value';

  /**
   * Named NDA secret value.
   */
  private const NDA_SECRET = 'nda-tier-secret-value';

  /**
   * Whitepaper field storage key.
   */
  private const PUBLIC_FIELD = 'entity_test.field_whitepaper';

  /**
   * NDA field storage key.
   */
  private const NDA_FIELD = 'entity_test.field_nda';

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

    $this->setSetting('file_gate.secrets', [
      self::PUBLIC_ID => self::PUBLIC_SECRET,
      self::NDA_ID => self::NDA_SECRET,
    ]);

    $this->config('file_gate.settings')
      ->set('secret_scopes', [
        self::PUBLIC_ID => [self::PUBLIC_FIELD],
        self::NDA_ID => [self::NDA_FIELD],
      ])
      ->save();

    $this->createGatedField('field_whitepaper');
    $this->createGatedField('field_nda');
  }

  /**
   * Creates a usage-limited gated private file field on entity_test.
   */
  private function createGatedField(string $field_name): void {
    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => $field_name,
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'signed_url')
      ->setThirdPartySetting('file_gate', 'method_settings', ['max_uses' => 2])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => $field_name,
      'bundle' => 'entity_test',
    ])->save();
  }

  /**
   * Creates a private file on the given gated field.
   */
  private function createFile(string $field_name, string $filename): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);
    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();
    $entity = EntityTest::create(['name' => 'host', $field_name => ['target_id' => $file->id()]]);
    $entity->save();
    \Drupal::service('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());
    return $file;
  }

  /**
   * Authenticated request (Basic username = secret id).
   *
   * @param string $method
   *   HTTP method.
   * @param string $path
   *   Request path.
   * @param string $secret_id
   *   Named secret id.
   * @param string $secret
   *   Named secret value.
   * @param string|null $body
   *   JSON body, or NULL for none.
   * @param array<string, string> $query
   *   Query parameters.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The request.
   */
  private function secretRequest(string $method, string $path, string $secret_id, string $secret, ?string $body = NULL, array $query = []): Request {
    $request = Request::create($path, $method, $query, [], [], [], $body ?? '');
    $request->headers->set('Content-Type', 'application/json');
    $request->headers->set('Authorization', 'Basic ' . base64_encode($secret_id . ':' . $secret));
    return $request;
  }

  /**
   * Mints a usage-limited grant with a named secret and returns the query.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   * @param string $secret_id
   *   Named secret id.
   * @param string $secret
   *   Named secret value.
   *
   * @return array<string, mixed>
   *   Download query parameters, including jti.
   */
  private function mintQuery(FileInterface $file, string $secret_id, string $secret): array {
    $mint = MintController::create($this->container)->mint(
      $this->secretRequest('POST', '/api/file-gate/mint', $secret_id, $secret, json_encode(['file' => $file->uuid()])),
    );
    $this->assertSame(Response::HTTP_OK, $mint->getStatusCode());
    $path = json_decode((string) $mint->getContent(), TRUE)['path'];
    $query = [];
    parse_str((string) parse_url($path, PHP_URL_QUERY), $query);
    $this->assertNotEmpty($query['jti']);
    return $query;
  }

  /**
   * Lists outstanding grants for a field using a named secret.
   *
   * @param string $field
   *   Field storage key.
   * @param string $secret_id
   *   Named secret id.
   * @param string $secret
   *   Named secret value.
   *
   * @return array<string, mixed>
   *   Decoded list payload.
   */
  private function listGrants(string $field, string $secret_id, string $secret): array {
    $listed = GrantInventoryController::create($this->container)
      ->list($this->secretRequest('GET', '/api/file-gate/grants', $secret_id, $secret, NULL, ['field' => $field]));
    $this->assertSame(Response::HTTP_OK, $listed->getStatusCode());
    return json_decode((string) $listed->getContent(), TRUE);
  }

  /**
   * In-scope jti revoke succeeds; a foreign scoped secret cannot spend it.
   */
  public function testOutOfScopeSecretCannotRevokeOtherFieldJti(): void {
    $whitepaper = $this->createFile('field_whitepaper', 'wp.pdf');
    $nda = $this->createFile('field_nda', 'secret.pdf');

    $public_query = $this->mintQuery($whitepaper, self::PUBLIC_ID, self::PUBLIC_SECRET);
    $nda_query = $this->mintQuery($nda, self::NDA_ID, self::NDA_SECRET);

    $this->assertSame(1, $this->listGrants(self::PUBLIC_FIELD, self::PUBLIC_ID, self::PUBLIC_SECRET)['count']);
    $this->assertSame(1, $this->listGrants(self::NDA_FIELD, self::NDA_ID, self::NDA_SECRET)['count']);

    $cross = RevokeController::create($this->container)->revoke(
      $this->secretRequest('POST', '/api/file-gate/revoke', self::PUBLIC_ID, self::PUBLIC_SECRET, json_encode(['jti' => $nda_query['jti']])),
    );
    $this->assertSame(Response::HTTP_FORBIDDEN, $cross->getStatusCode());
    $this->assertSame(
      'This credential is not allowed to revoke that grant.',
      json_decode((string) $cross->getContent(), TRUE)['error'],
    );

    $nda_after_cross = $this->listGrants(self::NDA_FIELD, self::NDA_ID, self::NDA_SECRET);
    $this->assertSame(1, $nda_after_cross['count']);
    $this->assertSame($nda_query['jti'], $nda_after_cross['grants'][0]['jti']);
    $still_live = DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $nda_query));
    $this->assertSame(Response::HTTP_OK, $still_live->getStatusCode());

    $revoked = RevokeController::create($this->container)->revoke(
      $this->secretRequest('POST', '/api/file-gate/revoke', self::NDA_ID, self::NDA_SECRET, json_encode(['jti' => $nda_query['jti']])),
    );
    $this->assertSame(Response::HTTP_NO_CONTENT, $revoked->getStatusCode());
    $this->assertSame(0, $this->listGrants(self::NDA_FIELD, self::NDA_ID, self::NDA_SECRET)['count']);

    $in_scope = RevokeController::create($this->container)->revoke(
      $this->secretRequest('POST', '/api/file-gate/revoke', self::PUBLIC_ID, self::PUBLIC_SECRET, json_encode(['jti' => $public_query['jti']])),
    );
    $this->assertSame(Response::HTTP_NO_CONTENT, $in_scope->getStatusCode());
    $this->assertSame(0, $this->listGrants(self::PUBLIC_FIELD, self::PUBLIC_ID, self::PUBLIC_SECRET)['count']);

    $this->expectException(AccessDeniedHttpException::class);
    DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $nda_query));
  }

  /**
   * Unknown jti is 404 and is not spent (do not confirm foreign identifiers).
   */
  public function testUnknownJtiIsNotFound(): void {
    $missing = RevokeController::create($this->container)->revoke(
      $this->secretRequest('POST', '/api/file-gate/revoke', self::PUBLIC_ID, self::PUBLIC_SECRET, json_encode(['jti' => 'does-not-exist'])),
    );
    $this->assertSame(Response::HTTP_NOT_FOUND, $missing->getStatusCode());
    $this->assertSame('Grant not found.', json_decode((string) $missing->getContent(), TRUE)['error']);
  }

}
