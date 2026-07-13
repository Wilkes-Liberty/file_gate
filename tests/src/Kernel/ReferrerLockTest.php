<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\File\FileSystemInterface;
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
use Drupal\file_gate\Controller\MintController;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Tests the referrer_lock gate method (signed URL + origin allowlist).
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class ReferrerLockTest extends KernelTestBase {

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
   * The signing / mint secret used in the tests.
   */
  private const SECRET = 'file-gate-test-secret';

  /**
   * The allowed front-end origin used across the tests.
   */
  private const ORIGIN = 'https://app.example.com';

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

    // A gated private file field using the referrer_lock method, allowing one
    // front-end origin by default.
    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'referrer_lock')
      ->setThirdPartySetting('file_gate', 'method_settings', ['allowed_origins' => [self::ORIGIN]])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * A request from the allowed origin (via Referer) is served.
   */
  public function testAllowedOriginViaReferer(): void {
    $file = $this->createReferencedFile('doc.pdf');
    $response = $this->download($this->mintQuery($file), ['Referer' => self::ORIGIN . '/downloads']);

    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A request from the allowed origin (via the Origin header) is served.
   */
  public function testAllowedOriginViaOriginHeader(): void {
    $file = $this->createReferencedFile('doc.pdf');
    $response = $this->download($this->mintQuery($file), ['Origin' => self::ORIGIN]);

    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A default port on the request origin still matches a portless allowlist.
   */
  public function testDefaultPortIsNormalized(): void {
    $file = $this->createReferencedFile('doc.pdf');
    $response = $this->download($this->mintQuery($file), ['Referer' => 'https://app.example.com:443/x']);

    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A request from a disallowed origin is denied.
   */
  public function testDisallowedOriginDenied(): void {
    $file = $this->createReferencedFile('doc.pdf');

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), ['Referer' => 'https://evil.example.org/hotlink']);
  }

  /**
   * With no Origin/Referer header, the default policy denies.
   */
  public function testMissingHeaderDeniedByDefault(): void {
    $file = $this->createReferencedFile('doc.pdf');

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file));
  }

  /**
   * With on_missing_referrer=allow, a header-less request is served.
   */
  public function testMissingHeaderAllowedWhenConfigured(): void {
    $this->configureField([
      'allowed_origins' => [self::ORIGIN],
      'on_missing_referrer' => 'allow',
    ]);
    $file = $this->createReferencedFile('doc.pdf');

    $response = $this->download($this->mintQuery($file));
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * An empty allowlist denies every request (fail closed).
   */
  public function testEmptyAllowlistFailsClosed(): void {
    $this->configureField(['allowed_origins' => []]);
    $file = $this->createReferencedFile('doc.pdf');

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), ['Referer' => self::ORIGIN . '/x']);
  }

  /**
   * The signature is still enforced regardless of a valid origin.
   */
  public function testStillEnforcesSignature(): void {
    $file = $this->createReferencedFile('doc.pdf');
    $query = $this->mintQuery($file);
    $query['sig'] .= 'deadbeef';

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query, ['Referer' => self::ORIGIN . '/x']);
  }

  /**
   * A disallowed origin does not consume a usage-limited grant's use.
   */
  public function testDisallowedOriginDoesNotConsumeUse(): void {
    $this->configureField(['allowed_origins' => [self::ORIGIN], 'max_uses' => 1]);
    $file = $this->createReferencedFile('once.pdf');
    $query = $this->mintQuery($file);

    // A hotlink attempt from a disallowed origin is rejected before the use is
    // spent...
    try {
      $this->download($query, ['Referer' => 'https://evil.example.org/']);
      $this->fail('Expected the disallowed origin to be denied.');
    }
    catch (AccessDeniedHttpException) {
      // Expected.
    }

    // ...so the one legitimate redemption from the allowed origin still works.
    $this->assertSame(200, $this->download($query, ['Referer' => self::ORIGIN . '/x'])->getStatusCode());

    // And the second legitimate redemption is now spent.
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query, ['Referer' => self::ORIGIN . '/x']);
  }

  /**
   * Sets the gated field's referrer_lock method settings.
   *
   * @param array $settings
   *   The method_settings to store.
   */
  private function configureField(array $settings): void {
    FieldStorageConfig::loadByName('entity_test', 'field_gated')
      ->setThirdPartySetting('file_gate', 'method_settings', $settings)
      ->save();
  }

  /**
   * Creates a private file referenced by an entity_test via the gated field.
   *
   * @param string $filename
   *   The file name under private://.
   *
   * @return \Drupal\file\FileInterface
   *   The saved, referenced, permanent file.
   */
  private function createReferencedFile(string $filename): FileInterface {
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

  /**
   * Mints a grant through the controller and returns the URL query.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file to mint for.
   *
   * @return array
   *   The download URL query (f, exp, sig, and jti/max when usage-limited).
   */
  private function mintQuery(FileInterface $file): array {
    $request = Request::create('/api/file-gate/mint', 'POST', [], [], [], [], json_encode(['file' => $file->uuid()]));
    $request->headers->set('Authorization', 'Basic ' . base64_encode('file-gate:' . self::SECRET));
    $response = MintController::create($this->container)->mint($request);
    $this->assertSame(200, $response->getStatusCode());
    $data = json_decode((string) $response->getContent(), TRUE);
    $query = [];
    parse_str((string) parse_url($data['path'], PHP_URL_QUERY), $query);
    return $query;
  }

  /**
   * Redeems a download request with the given query and request headers.
   *
   * @param array $query
   *   The download URL query parameters.
   * @param array $headers
   *   Request headers to set (e.g. ['Referer' => 'https://…']).
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The download response.
   */
  private function download(array $query, array $headers = []) {
    $request = Request::create('/api/file-gate/download', 'GET', $query);
    foreach ($headers as $name => $value) {
      $request->headers->set($name, $value);
    }
    return DownloadController::create($this->container)->download($request);
  }

}
