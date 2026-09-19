<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\file_gate\AdvanceableTime;
use Drupal\entity_test\Entity\EntityTest;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file_gate\Controller\DownloadController;
use Drupal\file_gate\Controller\GrantInventoryController;
use Drupal\file_gate\Controller\MintController;
use Drupal\file_gate\Controller\RevokeController;
use Drupal\file_gate\GrantRevokeLockException;
use Drupal\file_gate\Service\GrantInventory;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * A revoked grant stays revoked for as long as its signature is valid.
 *
 * The kill mark is an expiring redemption counter. When it lapsed before the
 * grant did, the counter restarted from zero and the signed URL worked again.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class GrantRevokeKillMarkTest extends KernelTestBase {

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

  private const SECRET = 'file-gate-test-secret';

  private const FIELD = 'entity_test.field_gated';

  private const DAY = 86400;

  /**
   * The grant lifetime: three times the old 30-day kill mark.
   */
  private const GRANT_TTL = 90 * self::DAY;

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    parent::register($container);
    $container->getDefinition('datetime.time')->setClass(AdvanceableTime::class);
  }

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    AdvanceableTime::$offset = 0;
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
      ->setThirdPartySetting('file_gate', 'method_settings', ['max_uses' => 2, 'ttl' => self::GRANT_TTL])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * The test clock really is the clock the module reads.
   *
   * Without this, a later "still refused" could pass only because time never
   * moved.
   */
  public function testUnrevokedGrantSurvivesTheClockMove(): void {
    $query = $this->mintGrant('kept.pdf');

    AdvanceableTime::$offset = 31 * self::DAY;
    $this->assertSame(Response::HTTP_OK, $this->download($query)->getStatusCode());

    AdvanceableTime::$offset = self::GRANT_TTL + self::DAY;
    $this->assertDownloadRefused($query);
  }

  /**
   * Revoked with no ttl: refused after the old 30-day mark would have lapsed.
   */
  public function testRevokeWithNoTtlOutlivesTheGrant(): void {
    $query = $this->mintGrant('no-ttl.pdf');
    $this->revoke(['jti' => $query['jti']]);

    // Redemption first: it is the defect. The stored expiry explains it.
    AdvanceableTime::$offset = 31 * self::DAY;
    $this->assertDownloadRefused($query);
    AdvanceableTime::$offset = self::GRANT_TTL - 60;
    $this->assertDownloadRefused($query);

    $this->assertGreaterThanOrEqual((int) $query['exp'] + GrantInventory::KILL_MARGIN, $this->killMarkExpiry($query['jti']));
  }

  /**
   * A caller ttl shorter than the grant's remaining life is raised to it.
   */
  public function testShortCallerTtlCannotShortenTheMark(): void {
    $query = $this->mintGrant('short-ttl.pdf');
    $this->revoke(['jti' => $query['jti'], 'ttl' => 3600]);

    AdvanceableTime::$offset = 2 * 3600;
    $this->assertDownloadRefused($query);
    AdvanceableTime::$offset = 31 * self::DAY;
    $this->assertDownloadRefused($query);

    $this->assertGreaterThanOrEqual((int) $query['exp'] + GrantInventory::KILL_MARGIN, $this->killMarkExpiry($query['jti']));
  }

  /**
   * A caller ttl longer than the grant's remaining life is honoured.
   */
  public function testLongerCallerTtlExtendsTheMark(): void {
    $query = $this->mintGrant('long-ttl.pdf');
    $ttl = 200 * self::DAY;
    $before = $this->container->get('datetime.time')->getRequestTime();
    $this->revoke(['jti' => $query['jti'], 'ttl' => $ttl]);

    $this->assertGreaterThanOrEqual($before + $ttl, $this->killMarkExpiry($query['jti']));
  }

  /**
   * Bulk revoke follows the same rule, with and without a short ttl.
   */
  public function testBulkRevokeOutlivesTheGrant(): void {
    $first = $this->mintGrant('bulk-a.pdf');
    $second = $this->mintGrant('bulk-b.pdf');

    $response = GrantInventoryController::create($this->container)->revokeBulk(
      $this->secretRequest('POST', '/api/file-gate/grants/revoke-bulk', json_encode([
        'field' => self::FIELD,
        'jtis' => [$first['jti']],
      ])),
    );
    $this->assertSame(1, json_decode((string) $response->getContent(), TRUE)['revoked']);
    $response = GrantInventoryController::create($this->container)->revokeBulk(
      $this->secretRequest('POST', '/api/file-gate/grants/revoke-bulk', json_encode([
        'field' => self::FIELD,
        'all' => TRUE,
        'ttl' => 3600,
      ])),
    );
    $this->assertSame(1, json_decode((string) $response->getContent(), TRUE)['revoked']);

    AdvanceableTime::$offset = 31 * self::DAY;
    $this->assertDownloadRefused($first);
    $this->assertDownloadRefused($second);

    foreach ([$first, $second] as $query) {
      $this->assertGreaterThanOrEqual((int) $query['exp'] + GrantInventory::KILL_MARGIN, $this->killMarkExpiry($query['jti']));
    }
  }

  /**
   * A second revoke with a short ttl cannot shorten the first mark.
   *
   * The first revoke forgets the inventory row, so the second finds no expiry
   * to read. It must not replace the long mark with a short one.
   */
  public function testSecondRevokeCannotShortenTheMark(): void {
    $query = $this->mintGrant('twice.pdf');
    $inventory = $this->container->get('file_gate.grant_inventory');
    $inventory->revokeJti($query['jti']);
    $first = $this->killMarkExpiry($query['jti']);

    $inventory->revokeJti($query['jti'], '', 60);

    AdvanceableTime::$offset = 31 * self::DAY;
    $this->assertDownloadRefused($query);
    AdvanceableTime::$offset = 0;
    $this->assertGreaterThanOrEqual($first, $this->killMarkExpiry($query['jti']));
  }

  /**
   * A lock that cannot be taken makes revoke fail instead of reporting success.
   *
   * ConsumeUse holds file_gate_redemption:<jti> for its read-modify-write.
   * revokeJti takes the same lock. Same-process lock backends are re-entrant,
   * so contention is injected with a lock that never acquires.
   */
  public function testRevokeFailsWhenTheRedemptionLockIsHeld(): void {
    $query = $this->mintGrant('locked.pdf');
    $this->installContendingInventory();
    try {
      $this->container->get('file_gate.grant_inventory')->revokeJti($query['jti'], self::FIELD);
      $this->fail('Revoke must not succeed while a redemption holds the lock.');
    }
    catch (GrantRevokeLockException) {
      // Expected.
    }
    $response = RevokeController::create($this->container)
      ->revoke($this->secretRequest('POST', '/api/file-gate/revoke', json_encode(['jti' => $query['jti']])));
    $this->assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
    $this->assertSame('5', $response->headers->get('Retry-After'));
    $this->assertSame(Response::HTTP_OK, $this->download($query)->getStatusCode(), 'A failed revoke must not spend the grant.');
  }

  /**
   * Bulk revoke takes the redemption lock per grant and fails closed.
   */
  public function testBulkRevokeFailsWhenRedemptionLockIsHeld(): void {
    $held = $this->mintGrant('bulk-held.pdf');
    $free = $this->mintGrant('bulk-free.pdf');
    $this->installContendingInventory();
    $response = GrantInventoryController::create($this->container)->revokeBulk(
      $this->secretRequest('POST', '/api/file-gate/grants/revoke-bulk', json_encode([
        'field' => self::FIELD,
        'jtis' => [$held['jti'], $free['jti']],
      ])),
    );
    $this->assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
    $this->assertSame('5', $response->headers->get('Retry-After'));
    $this->assertSame(Response::HTTP_OK, $this->download($free)->getStatusCode(), 'A failed bulk revoke must not spend later grants.');
  }

  /**
   * With no inventory record the default mark is kept, and a ttl is honoured.
   */
  public function testUnknownGrantKeepsTheDefault(): void {
    $inventory = $this->container->get('file_gate.grant_inventory');
    $now = $this->container->get('datetime.time')->getRequestTime();

    $inventory->revokeJti('unknown-default');
    $this->assertSame($now + GrantInventory::DEFAULT_KILL_TTL, $this->killMarkExpiry('unknown-default'));

    $inventory->revokeJti('unknown-short', '', 3600);
    $this->assertSame($now + 3600, $this->killMarkExpiry('unknown-short'));
  }

  /**
   * Mints a grant through the mint endpoint and the real gate method.
   *
   * @return array<string, string>
   *   The query of the minted download path.
   */
  private function mintGrant(string $filename): array {
    $directory = 'private://docs';
    $this->container->get('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = $directory . '/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);
    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();
    $entity = EntityTest::create(['name' => $filename, 'field_gated' => ['target_id' => $file->id()]]);
    $entity->save();
    $this->container->get('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());

    $mint = MintController::create($this->container)
      ->mint($this->secretRequest('POST', '/api/file-gate/mint', json_encode(['file' => $file->uuid()])));
    $this->assertSame(Response::HTTP_OK, $mint->getStatusCode());
    $query = [];
    parse_str((string) parse_url(json_decode((string) $mint->getContent(), TRUE)['path'], PHP_URL_QUERY), $query);
    $this->assertNotEmpty($query['jti']);
    $this->assertGreaterThan(
      $this->container->get('datetime.time')->getRequestTime() + GrantInventory::DEFAULT_KILL_TTL,
      (int) $query['exp'],
      'The grant must outlive the old default kill mark for these tests to mean anything.',
    );
    return $query;
  }

  /**
   * Revokes one grant through the revoke endpoint.
   *
   * @param array<string, mixed> $body
   *   The request body.
   */
  private function revoke(array $body): void {
    $response = RevokeController::create($this->container)
      ->revoke($this->secretRequest('POST', '/api/file-gate/revoke', json_encode($body)));
    $this->assertSame(Response::HTTP_NO_CONTENT, $response->getStatusCode());
  }

  /**
   * Redeems a grant through the download endpoint.
   *
   * @param array<string, string> $query
   *   The minted query.
   */
  private function download(array $query): Response {
    return DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
  }

  /**
   * Asserts the download endpoint refuses the grant.
   *
   * @param array<string, string> $query
   *   The minted query.
   */
  private function assertDownloadRefused(array $query): void {
    $refused = FALSE;
    try {
      $this->download($query);
    }
    catch (AccessDeniedHttpException) {
      $refused = TRUE;
    }
    $this->assertTrue($refused, 'A revoked or expired grant was redeemed.');
  }

  /**
   * The stored expiry of a kill mark, read from the expirable store's table.
   */
  private function killMarkExpiry(string $jti): int {
    $expire = $this->container->get('database')->select('key_value_expire', 'k')
      ->fields('k', ['expire'])
      ->condition('collection', GrantInventory::REDEMPTION_COLLECTION)
      ->condition('name', $jti)
      ->execute()
      ->fetchField();
    $this->assertNotFalse($expire, 'The kill mark exists.');
    return (int) $expire;
  }

  /**
   * Replaces grant inventory with one whose lock never acquires.
   */
  private function installContendingInventory(): void {
    $lock = $this->createMock(LockBackendInterface::class);
    $lock->method('acquire')->willReturn(FALSE);
    $lock->method('wait');
    $inventory = new GrantInventory(
      $this->container->get('keyvalue.expirable'),
      $this->container->get('datetime.time'),
      $lock,
    );
    $this->container->set('file_gate.grant_inventory', $inventory);
  }

  /**
   * Builds an authenticated server-to-server request.
   */
  private function secretRequest(string $method, string $path, ?string $body = NULL): Request {
    $request = Request::create($path, $method, [], [], [], [], $body ?? '');
    $request->headers->set('Authorization', 'Basic ' . base64_encode('file-gate:' . self::SECRET));
    return $request;
  }

}
