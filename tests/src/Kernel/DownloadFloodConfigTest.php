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
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Pins download_flood_limit: stored 0 disables, NULL/missing still means 120.
 *
 * SettingsForm and the schema already treat 0 as off (`??`, "#min: 0").
 * The controller used `?:`, which treated stored 0 as missing and fell back
 * to 120. Window stays on `?:`.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class DownloadFloodConfigTest extends KernelTestBase {

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
   * The signing secret used in the tests.
   */
  private const SECRET = 'file-gate-test-secret';

  /**
   * Fixed client IP so flood events are attributable.
   */
  private const IP = '203.0.113.9';

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
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();
  }

  /**
   * Stored 0 must not register file_gate.download_deny (0 means off).
   */
  public function testStoredZeroDoesNotRegisterDownloadDeny(): void {
    $this->config('file_gate.settings')->set('download_flood_limit', 0)->save();
    $file = $this->createReferencedFile('zero.pdf');

    $this->denyDownload($file);
    $this->assertTrue(
      $this->isDenyAllowed(1),
      'Stored 0 must not register file_gate.download_deny.',
    );

    // A full bucket must not trip the controller when the limit is off.
    $flood = $this->container->get('flood');
    for ($i = 0; $i < 120; $i++) {
      $flood->register('file_gate.download_deny', 60, self::IP);
    }
    $this->denyDownload($file);
    $this->assertFalse($this->isDenyAllowed(120));
    $this->assertTrue(
      $this->isDenyAllowed(121),
      'Stored 0 must not register even when the bucket is already full.',
    );
  }

  /**
   * NULL / missing download_flood_limit still falls back to 120.
   */
  public function testMissingLimitFallsBackTo120(): void {
    $this->config('file_gate.settings')->clear('download_flood_limit')->save();
    $this->assertNull($this->config('file_gate.settings')->get('download_flood_limit'));

    $file = $this->createReferencedFile('missing.pdf');
    $flood = $this->container->get('flood');
    for ($i = 0; $i < 119; $i++) {
      $flood->register('file_gate.download_deny', 60, self::IP);
    }

    // 119 events: the deny still reaches the grant check and registers #120.
    $this->denyDownload($file);
    $this->assertFalse(
      $this->isDenyAllowed(120),
      'NULL/missing must fall back to 120 and still register a denial.',
    );
    $this->assertTrue($this->isDenyAllowed(121));

    // 120 events: the next request is flood-blocked (same as default 120).
    $this->expectException(AccessDeniedHttpException::class);
    $this->downloadValid($file);
  }

  /**
   * The shipped default of 120 still floods after 120 denials.
   */
  public function testDefault120StillFloods(): void {
    $this->assertSame(
      120,
      $this->config('file_gate.settings')->get('download_flood_limit'),
    );

    $file = $this->createReferencedFile('default.pdf');
    $flood = $this->container->get('flood');
    for ($i = 0; $i < 119; $i++) {
      $flood->register('file_gate.download_deny', 60, self::IP);
    }

    $this->denyDownload($file);
    $this->assertFalse($this->isDenyAllowed(120));
    $this->assertTrue($this->isDenyAllowed(121));

    $this->expectException(AccessDeniedHttpException::class);
    $this->downloadValid($file);
  }

  /**
   * Creates a private file referenced by the gated field.
   */
  private function createReferencedFile(string $filename): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);

    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();

    $entity = EntityTest::create([
      'name' => 'host',
      'field_gated' => ['target_id' => $file->id()],
    ]);
    $entity->save();
    \Drupal::service('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());

    return $file;
  }

  /**
   * Hits the download route with an expired grant from the pinned IP.
   */
  private function denyDownload(FileInterface $file): void {
    $resource = $this->container->get('stream_wrapper_manager')->normalizeUri($file->getFileUri());
    $claims = ['exp' => $this->container->get('datetime.time')->getRequestTime() - 10];
    $sig = $this->container->get('file_gate.grant_signer')->sign($resource, $claims);

    $request = Request::create('/api/file-gate/download', 'GET', [
      'f' => $file->uuid(),
      'exp' => $claims['exp'],
      'sig' => $sig,
    ]);
    $request->server->set('REMOTE_ADDR', self::IP);

    try {
      DownloadController::create($this->container)->download($request);
      $this->fail('Expected a denied download.');
    }
    catch (AccessDeniedHttpException) {
      // Grant rejected (or flood-blocked). Caller asserts which.
    }
  }

  /**
   * Hits the download route with a valid grant from the pinned IP.
   */
  private function downloadValid(FileInterface $file) {
    $params = $this->container
      ->get('plugin.manager.file_gate.gate_method')
      ->createInstance('signed_url', [])
      ->mint($file);
    $request = Request::create('/api/file-gate/download', 'GET', ['f' => $file->uuid()] + $params);
    $request->server->set('REMOTE_ADDR', self::IP);
    return DownloadController::create($this->container)->download($request);
  }

  /**
   * Whether file_gate.download_deny is still allowed at the given threshold.
   */
  private function isDenyAllowed(int $threshold): bool {
    return $this->container->get('flood')->isAllowed(
      'file_gate.download_deny',
      $threshold,
      60,
      self::IP,
    );
  }

}
