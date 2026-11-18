<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\KeyValueStore\DatabaseStorageExpirable;
use Drupal\Core\Lock\DatabaseLockBackend;
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
use Drupal\file_gate\Exception\GrantParticipationException;
use Drupal\file_gate\Service\GrantInventory;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Verifies transaction participation across real signed grant entry points.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class GrantParticipationTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'field', 'file', 'file_gate', 'entity_test'];

  private const FIELD = 'entity_test.field_gated';
  private const SECRET = 'file-gate-fixture-secret';
  private const GRANT_CLASS = 'fixture';

  /**
   * The participant fixture.
   */
  private TestGrantParticipant $participant;

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    parent::register($container);
    $container->register('lock', DatabaseLockBackend::class)->addArgument(new Reference('database'));
    $container->register('file_gate.grant_participant', TestGrantParticipant::class);
  }

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
    $this->setSetting('file_gate.secrets', [self::GRANT_CLASS => self::SECRET]);
    $this->config('file_gate.settings')
      ->set('secret_scopes', [self::GRANT_CLASS => [self::FIELD]])
      ->save();

    $database = $this->container->get('database');
    $database->schema()->createTable('key_value_expire', DatabaseStorageExpirable::schemaDefinition());
    $lock = $this->container->get('lock');
    $lock->acquire('test-grant-schema');
    $lock->release('test-grant-schema');
    $database->schema()->createTable('file_gate_test_host', [
      'fields' => [
        'operation' => ['type' => 'varchar_ascii', 'length' => 24, 'not null' => TRUE],
        'jti' => ['type' => 'varchar_ascii', 'length' => 128, 'not null' => TRUE],
      ],
    ]);
    $this->participant = $this->container->get('file_gate.grant_participant');
  }

  /**
   * A configured provider has no effect on an unenrolled field.
   */
  public function testDefaultPathsRemainIndependent(): void {
    $file = $this->file();
    $query = $this->mintQuery($file);
    $this->assertSame(200, $this->download($query)->getStatusCode());
    $this->assertSame(204, $this->revoke($query['jti'])->getStatusCode());
    $this->assertNull($this->participant->seen);
  }

  /**
   * Native grant and host writes roll back together for each operation.
   */
  public function testEnrolledRollbackAndSuccess(): void {
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $file = $this->file();
    $this->participant->rejectCommit = TRUE;
    $this->assertSame(503, $this->mint($file)->getStatusCode());
    $this->assertSame('mint', $this->participant->operation);
    $this->assertSame($file->uuid(), $this->participant->seen->fileUuid);
    $this->assertNull($this->inventory()->meta($this->participant->seen->jti));
    $this->assertSame([], $this->inventory()->listForField(self::FIELD));
    $this->assertSame(0, $this->hostWriteCount());

    $this->participant->rejectCommit = FALSE;
    $query = $this->mintQuery($file);
    $grant = $this->participant->seen;
    $this->assertSame($query['jti'], $grant->jti);
    $this->assertSame((int) $query['exp'], $grant->expiresAt);
    $this->assertSame((int) $query['max'], $grant->maxUses);
    $this->assertSame(1, $this->hostWriteCount());

    $this->participant->rejectCommit = TRUE;
    $this->assertDownloadDenied($query);
    $this->assertSame('redeem', $this->participant->operation);
    $this->assertSame(0, $this->inventory()->scopedState($grant)->uses);
    $this->assertSame(1, $this->hostWriteCount());

    $this->participant->rejectCommit = FALSE;
    $this->assertSame(200, $this->download($query)->getStatusCode());
    $this->assertSame(1, $this->inventory()->scopedState($grant)->uses);
    $this->assertSame(2, $this->hostWriteCount());

    $this->participant->rejectCommit = TRUE;
    $this->assertSame(503, $this->revoke($grant->jti)->getStatusCode());
    $this->assertSame('revoke', $this->participant->operation);
    $this->assertNotNull($this->inventory()->meta($grant->jti));
    $this->assertFalse($this->inventory()->scopedState($grant)->killed);
    $this->assertSame(2, $this->hostWriteCount());

    $this->participant->rejectCommit = FALSE;
    $this->assertSame(204, $this->revoke($grant->jti)->getStatusCode());
    $this->assertTrue($this->inventory()->scopedState($grant)->killed);
    $this->assertNull($this->inventory()->meta($grant->jti));
    $this->assertSame(3, $this->hostWriteCount());
    $this->assertDownloadDenied($query);
  }

  /**
   * The primary metadata remains observable after losing its secondary index.
   */
  public function testScopedRevokeInHostRootWithMissingIndex(): void {
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $file = $this->file();
    $query = $this->mintQuery($file);
    $grant = $this->participant->seen;
    $this->container->get('keyvalue.expirable')
      ->get(GrantInventory::FIELD_INDEX_COLLECTION)
      ->delete(self::FIELD);
    $this->assertSame([$grant->jti], array_column($this->inventory()->listForField(self::FIELD), 'jti'));
    $this->assertEquals([$grant], $this->inventory()->scopedGrants(self::FIELD, $file->uuid()));
    $this->assertFalse($this->inventory()->scopedState($grant)->killed);

    $database = $this->container->get('database');
    $root = $database->startTransaction();
    $state = $this->inventory()->revokeScoped($grant);
    $this->assertTrue($state->killed);
    $this->assertGreaterThanOrEqual($grant->expiresAt + GrantInventory::KILL_MARGIN, $state->killExpiresAt);
    $root->rollBack();
    unset($root);
    $this->assertFalse($database->inTransaction());
    $rolled_back = $this->inventory()->scopedState($grant);
    $this->assertFalse($rolled_back->killed);
    $this->assertTrue($rolled_back->metadataPresent);
    $this->assertTrue($rolled_back->enrolledMint);
    $this->assertSame(0, $rolled_back->uses);
    $this->assertSame(200, $this->download($query)->getStatusCode());
  }

  /**
   * An enrolled field cannot issue untracked unlimited grants.
   */
  public function testEnrolledUnlimitedIsRejected(): void {
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $this->assertSame(503, $this->mint($this->file(0))->getStatusCode());
    $this->assertNull($this->participant->seen);
  }

  /**
   * A failed native metadata write cannot leave a successful host write.
   */
  public function testNativeStoreFailureRollsBackHostWrite(): void {
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $file = $this->file();
    $database = $this->container->get('database');
    $driver = $database->databaseType();
    $collection = GrantInventory::PRIMARY_FIELDS_COLLECTION;
    if ($driver === 'pgsql') {
      $database->query("CREATE FUNCTION {file_gate_fixture_reject}() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN IF NEW.collection = ''$collection'' THEN RAISE EXCEPTION ''fixture write failure''; END IF; RETURN NEW; END;'", [], ['allow_delimiter_in_query' => TRUE]);
      $database->query("CREATE TRIGGER file_gate_fixture_reject BEFORE INSERT ON {key_value_expire} FOR EACH ROW EXECUTE FUNCTION {file_gate_fixture_reject}()");
    }
    elseif ($driver === 'mysql') {
      $database->query("ALTER TABLE {key_value_expire} ADD CONSTRAINT {file_gate_fixture_reject} CHECK ([collection] <> '$collection')");
    }
    else {
      $database->query("CREATE TEMP TRIGGER file_gate_fixture_reject BEFORE INSERT ON {key_value_expire} WHEN NEW.collection = '$collection' BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END", [], ['allow_delimiter_in_query' => TRUE]);
    }
    try {
      $this->assertSame(503, $this->mint($file)->getStatusCode());
      $this->assertNotNull($this->participant->seen);
      $this->assertNull($this->inventory()->meta($this->participant->seen->jti));
      $this->assertSame(0, $this->hostWriteCount());
      $this->assertSame([], $this->inventory()->listForField(self::FIELD));
    }
    finally {
      if ($driver === 'pgsql') {
        $database->query('DROP TRIGGER file_gate_fixture_reject ON {key_value_expire}');
        $database->query('DROP FUNCTION {file_gate_fixture_reject}()');
      }
      elseif ($driver === 'mysql') {
        $database->query('ALTER TABLE {key_value_expire} DROP CONSTRAINT {file_gate_fixture_reject}');
      }
      else {
        $database->query('DROP TRIGGER file_gate_fixture_reject');
      }
    }
    $this->assertSame(200, $this->mint($file)->getStatusCode());
  }

  /**
   * A rolled back participant savepoint cannot acknowledge a grant operation.
   */
  public function testForeignSavepointCannotAcknowledgeEffect(): void {
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $file = $this->file();
    $this->participant->foreignSavepoint = TRUE;
    $this->assertSame(503, $this->mint($file)->getStatusCode());
    $this->assertSame([], $this->inventory()->scopedGrants(self::FIELD));

    $this->participant->foreignSavepoint = FALSE;
    $query = $this->mintQuery($file);
    $grant = $this->participant->seen;
    $this->participant->foreignSavepoint = TRUE;
    $this->assertDownloadDenied($query);
    $this->assertSame(0, $this->inventory()->scopedState($grant)->uses);
    $this->assertSame(503, $this->revoke($grant->jti)->getStatusCode());
    $this->assertFalse($this->inventory()->scopedState($grant)->killed);
  }

  /**
   * Duplicate and deferred dispatches cannot commit a native effect.
   */
  public function testInvalidDispatchRollsBackNativeAndHostWrites(): void {
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $file = $this->file();
    $this->participant->duplicateDispatch = TRUE;
    $this->assertSame(503, $this->mint($file)->getStatusCode());
    $this->assertSame([], $this->inventory()->scopedGrants(self::FIELD));
    $this->assertSame(0, $this->hostWriteCount());

    $this->participant->duplicateDispatch = FALSE;
    $this->participant->deferredDispatch = TRUE;
    $this->assertSame(503, $this->mint($file)->getStatusCode());
    $this->assertSame([], $this->inventory()->scopedGrants(self::FIELD));
    $this->assertSame(0, $this->hostWriteCount());
  }

  /**
   * An existing capped grant can continue under a qualified baseline.
   */
  public function testEnrolledRedemptionPreservesAnExactBaselineGrant(): void {
    $file = $this->file(1);
    $query = $this->mintQuery($file);
    $this->assertArrayNotHasKey('txg', $query);
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    [$grant] = $this->inventory()->scopedGrants(self::FIELD, $file->uuid());
    $this->assertNull($grant->gateMethod);
    $this->assertDownloadDenied($query);
    $this->assertSame(0, $this->inventory()->scopedState($grant)->uses);

    $this->participant->baseline = $grant->jti;
    $this->assertSame(200, $this->download($query)->getStatusCode());
    $this->assertSame($query['jti'], $this->participant->seen->jti);
    $this->assertSame(1, $this->inventory()->scopedState($grant)->uses);
    $this->assertDownloadDenied($query);
    $this->assertSame(204, $this->revoke($query['jti'])->getStatusCode());
    $this->assertTrue($this->inventory()->scopedState($grant)->killed);
  }

  /**
   * Scoped URLs stay gated and listed after enrollment is removed.
   */
  public function testUnenrollmentPreservesInventoryAndBulkRevoke(): void {
    $file = $this->file();
    $legacy = $this->mintQuery($file);
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $query = $this->mintQuery($file);
    $this->assertCount(2, $this->inventory()->scopedGrants(self::FIELD));

    $this->setSetting('file_gate.transactional_grant_fields', []);
    $this->assertEqualsCanonicalizing([$legacy['jti'], $query['jti']], array_column($this->inventory()->listForField(self::FIELD), 'jti'));
    $this->assertSame(422, $this->mint($file)->getStatusCode());
    try {
      $this->download($query);
      $this->fail('A protected field became available without enrollment.');
    }
    catch (NotFoundHttpException $error) {
      $this->assertSame(404, $error->getStatusCode());
    }
    $response = GrantInventoryController::create($this->container)
      ->revokeBulk($this->secretRequest('grants/revoke-bulk', ['field' => self::FIELD, 'jtis' => [$query['jti']]]));
    $this->assertSame(200, $response->getStatusCode());
    $this->assertNull($this->inventory()->meta($query['jti']));
    $this->assertSame([$legacy['jti']], array_column($this->inventory()->listForField(self::FIELD), 'jti'));
  }

  /**
   * Bounded inspection refuses instead of returning partial coverage.
   */
  public function testPrimaryCoverageLimitsNeverTruncate(): void {
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $file = $this->file();
    $this->mintQuery($file);
    $this->mintQuery($file);
    $this->assertCount(2, $this->inventory()->scopedGrants(self::FIELD, max_grants: 2, max_primary_rows: 2));

    try {
      $this->inventory()->scopedGrants(self::FIELD, max_grants: 1);
      $this->fail('The matching grant slice was accepted as complete.');
    }
    catch (GrantParticipationException) {
      $this->assertCount(2, $this->inventory()->scopedGrants(self::FIELD));
    }
    $this->expectException(GrantParticipationException::class);
    $this->inventory()->scopedGrants(self::FIELD, max_primary_rows: 1);
  }

  /**
   * A field can be durably protected before the first mint.
   */
  public function testActivationClosesTheFirstMintGap(): void {
    $file = $this->file();
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $database = $this->container->get('database');
    $root = $database->startTransaction();
    $this->inventory()->protectField(self::FIELD);
    unset($root);

    $this->setSetting('file_gate.transactional_grant_fields', []);
    $this->assertSame(422, $this->mint($file)->getStatusCode());
    $this->assertNull($this->participant->seen);
  }

  /**
   * A kill whose actual counter expires early is insufficient coverage.
   */
  public function testActualKillExpiryIsRequired(): void {
    $this->setSetting('file_gate.transactional_grant_fields', [self::FIELD => self::GRANT_CLASS]);
    $query = $this->mintQuery($this->file());
    $grant = $this->participant->seen;
    $this->assertSame(204, $this->revoke($query['jti'])->getStatusCode());
    $this->assertTrue($this->inventory()->scopedState($grant)->killed);

    $database = $this->container->get('database');
    $database->update('key_value_expire')
      ->fields(['expire' => $grant->expiresAt + GrantInventory::KILL_MARGIN - 1])
      ->condition('collection', GrantInventory::REDEMPTION_COLLECTION)
      ->condition('name', $grant->jti)
      ->execute();
    $this->assertFalse($this->inventory()->scopedState($grant)->killed);
    $this->assertNull($this->inventory()->scopedState($grant)->killExpiresAt);
    $root = $database->startTransaction();
    try {
      $this->expectException(GrantParticipationException::class);
      $this->inventory()->revokeScoped($grant);
    }
    finally {
      $root->rollBack();
    }
  }

  /**
   * Builds a private file and a single gated reference.
   */
  private function file(int $max = 2): File {
    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'signed_url')
      ->setThirdPartySetting('file_gate', 'method_settings', ['max_uses' => $max])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    $directory = 'private://fixtures';
    $this->container->get('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = $directory . '/sample.pdf';
    file_put_contents($uri, 'synthetic file bytes');
    $file = File::create(['uri' => $uri, 'status' => 1]);
    $file->save();
    $host = EntityTest::create(['name' => 'fixture', 'field_gated' => ['target_id' => $file->id()]]);
    $host->save();
    $this->container->get('file.usage')->add($file, 'file', 'entity_test', (string) $host->id());
    return $file;
  }

  /**
   * Mints a grant using the normal controller.
   */
  private function mint(File $file): Response {
    return MintController::create($this->container)->mint($this->secretRequest('mint', ['file' => $file->uuid()]));
  }

  /**
   * Returns the signed query after a successful mint.
   */
  private function mintQuery(File $file): array {
    $response = $this->mint($file);
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getContent());
    $path = json_decode((string) $response->getContent(), TRUE, 512, JSON_THROW_ON_ERROR)['path'];
    parse_str((string) parse_url($path, PHP_URL_QUERY), $query);
    return $query;
  }

  /**
   * Redeems a signed query using the normal download controller.
   */
  private function download(array $query): Response {
    return DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
  }

  /**
   * Confirms a denial without accepting a different request failure.
   */
  private function assertDownloadDenied(array $query): void {
    try {
      $this->download($query);
      $this->fail('The credential was redeemed.');
    }
    catch (AccessDeniedHttpException $exception) {
      $this->assertSame(403, $exception->getStatusCode());
    }
  }

  /**
   * Revokes a grant using the normal controller.
   */
  private function revoke(string $jti): Response {
    return RevokeController::create($this->container)->revoke($this->secretRequest('revoke', ['jti' => $jti]));
  }

  /**
   * Builds the authenticated request used for mint and revoke.
   */
  private function secretRequest(string $action, array $payload): Request {
    $request = Request::create('/api/file-gate/' . $action, 'POST', [], [], [], [], json_encode($payload, JSON_THROW_ON_ERROR));
    $request->headers->set('Authorization', 'Basic ' . base64_encode(self::GRANT_CLASS . ':' . self::SECRET));
    return $request;
  }

  /**
   * Returns the production inventory service.
   */
  private function inventory(): GrantInventory {
    return $this->container->get('file_gate.grant_inventory');
  }

  /**
   * Counts committed fixture host writes.
   */
  private function hostWriteCount(): int {
    return (int) $this->container->get('database')->select('file_gate_test_host')->countQuery()->execute()->fetchField();
  }

}
