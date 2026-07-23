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
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Integration tests for the File Gate deny hook, delivery, and mint endpoint.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class FileGateTest extends KernelTestBase {

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
   * The signing secret used in the tests.
   */
  private const SECRET = 'file-gate-test-secret';

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

    // Register a writable private filesystem for the test. Setting the path is
    // not enough in a kernel test — the private wrapper must be (re)registered
    // now that a path exists.
    $this->setSetting('file_private_path', $this->siteDirectory . '/private');
    $this->container->get('stream_wrapper_manager')
      ->registerWrapper('private', PrivateStream::class, StreamWrapperInterface::WRITE_VISIBLE);

    // A signing secret makes gating active.
    $this->config('file_gate.settings')->set('download_secret', self::SECRET)->save();

    // A gated private file field.
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

    // An ungated private file field (to prove non-regression: File Gate must
    // leave ordinary private files alone).
    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_ungated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_ungated',
      'bundle' => 'entity_test',
    ])->save();

    // Explicitly run as anonymous for the deny-path assertions.
    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * Creates a private file referenced by an entity_test via the given field.
   *
   * @param string $field_name
   *   The referencing field.
   * @param string $filename
   *   The file name under private://.
   *
   * @return \Drupal\file\FileInterface
   *   The saved, referenced, permanent file.
   */
  private function createReferencedFile(string $field_name, string $filename): FileInterface {
    // Use a real subdirectory: passing the scheme root ('private://') to
    // prepareDirectory() rtrims to the invalid 'private:' and fails to create
    // the base dir. Build the file URI independently of the mutated $directory.
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);

    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();

    $entity = EntityTest::create(['name' => 'host', $field_name => ['target_id' => $file->id()]]);
    $entity->save();
    // Record file usage explicitly so the reference resolver can find it
    // (widget saves do this automatically; programmatic saves do not).
    \Drupal::service('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());

    return $file;
  }

  /**
   * The deny hook returns -1 for a gated file requested anonymously.
   */
  public function testHookDeniesGatedFileForAnonymous(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $this->assertSame(-1, file_gate_file_download($file->getFileUri()));
  }

  /**
   * A user with the bypass permission defers to core (NULL, not -1).
   */
  public function testHookAllowsBypassPermission(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $this->container->get('current_user')->setAccount($this->createUser(['bypass file gate']));
    $this->assertNull(file_gate_file_download($file->getFileUri()));
  }

  /**
   * An ungated private file is left entirely to core (non-regression).
   */
  public function testHookIgnoresUngatedPrivateFile(): void {
    $file = $this->createReferencedFile('field_ungated', 'ungated.pdf');
    $this->assertNull(file_gate_file_download($file->getFileUri()));
  }

  /**
   * The download route streams a gated file for a valid grant.
   */
  public function testDownloadStreamsWithValidGrant(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $params = $this->mintParams($file);

    $request = Request::create('/api/file-gate/download', 'GET', ['f' => $file->uuid()] + $params);
    $response = DownloadController::create($this->container)->download($request);

    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
    $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
  }

  /**
   * The download route rejects an expired grant.
   */
  public function testDownloadRejectsExpiredGrant(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $resource = $this->container->get('stream_wrapper_manager')->normalizeUri($file->getFileUri());
    // A correctly signed grant whose expiry is already in the past.
    $claims = ['exp' => $this->container->get('datetime.time')->getRequestTime() - 10];
    $sig = $this->container->get('file_gate.grant_signer')->sign($resource, $claims);

    $request = Request::create('/api/file-gate/download', 'GET', [
      'f' => $file->uuid(),
      'exp' => $claims['exp'],
      'sig' => $sig,
    ]);

    $this->expectException(AccessDeniedHttpException::class);
    DownloadController::create($this->container)->download($request);
  }

  /**
   * The download route rejects a tampered signature.
   */
  public function testDownloadRejectsTamperedSignature(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $params = $this->mintParams($file);
    $params['sig'] .= 'deadbeef';

    $request = Request::create('/api/file-gate/download', 'GET', ['f' => $file->uuid()] + $params);

    $this->expectException(AccessDeniedHttpException::class);
    DownloadController::create($this->container)->download($request);
  }

  /**
   * The download route 404s for an unknown file.
   */
  public function testDownloadRejectsUnknownFile(): void {
    $request = Request::create('/api/file-gate/download', 'GET', [
      'f' => '00000000-0000-0000-0000-000000000000',
      'exp' => \Drupal::time()->getRequestTime() + 100,
      'sig' => 'x',
    ]);

    $this->expectException(NotFoundHttpException::class);
    DownloadController::create($this->container)->download($request);
  }

  /**
   * Mint returns a signed, host-relative path for a gated file.
   */
  public function testMintReturnsSignedPathForGatedFile(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');

    $response = MintController::create($this->container)
      ->mint($this->mintRequest(json_encode(['file' => $file->uuid()]), self::SECRET));

    $this->assertSame(200, $response->getStatusCode());
    $data = json_decode((string) $response->getContent(), TRUE);
    $this->assertStringStartsWith('/api/file-gate/download', $data['path']);
    $this->assertStringContainsString('f=' . $file->uuid(), $data['path']);
    $this->assertStringContainsString('sig=', $data['path']);
    $this->assertGreaterThan(\Drupal::time()->getRequestTime(), $data['expires']);
    $this->assertSame(120, $data['ttl']);
  }

  /**
   * Mint fails closed (503) when no secret is configured.
   */
  public function testMintFailsClosedWithoutSecret(): void {
    $this->config('file_gate.settings')->set('download_secret', '')->save();
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');

    $response = MintController::create($this->container)
      ->mint($this->mintRequest(json_encode(['file' => $file->uuid()]), self::SECRET));

    $this->assertSame(503, $response->getStatusCode());
  }

  /**
   * Mint rejects a wrong secret (401).
   */
  public function testMintRejectsBadSecret(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');

    $response = MintController::create($this->container)
      ->mint($this->mintRequest(json_encode(['file' => $file->uuid()]), 'wrong-secret'));

    $this->assertSame(401, $response->getStatusCode());
  }

  /**
   * Mint refuses an ungated file (422).
   */
  public function testMintRejectsUngatedFile(): void {
    $file = $this->createReferencedFile('field_ungated', 'ungated.pdf');

    $response = MintController::create($this->container)
      ->mint($this->mintRequest(json_encode(['file' => $file->uuid()]), self::SECRET));

    $this->assertSame(422, $response->getStatusCode());
  }

  /**
   * A usage-limited grant (max_uses = 1) is a one-time link.
   */
  public function testUsageLimitedGrantIsSingleUse(): void {
    // Turn the gated field into a one-time-download field.
    $storage = FieldStorageConfig::loadByName('entity_test', 'field_gated');
    $storage->setThirdPartySetting('file_gate', 'method_settings', ['max_uses' => 1])->save();

    $file = $this->createReferencedFile('field_gated', 'once.pdf');

    // Mint through the controller so the field's method settings apply.
    $mint = MintController::create($this->container)
      ->mint($this->mintRequest(json_encode(['file' => $file->uuid()]), self::SECRET));
    $data = json_decode((string) $mint->getContent(), TRUE);
    $this->assertStringContainsString('max=1', $data['path']);

    $query = [];
    parse_str((string) parse_url($data['path'], PHP_URL_QUERY), $query);

    // First redemption succeeds.
    $first = DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
    $this->assertSame(200, $first->getStatusCode());

    // Second redemption of the same link is denied (cap reached).
    $this->expectException(AccessDeniedHttpException::class);
    DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
  }

  /**
   * Gated responses always send nosniff; inline is forced off for unsafe MIME.
   */
  public function testDownloadHardensContentTypeHandling(): void {
    $this->config('file_gate.settings')->set('disposition', 'inline')->save();

    // An SVG can carry script: even in inline mode it must be an attachment.
    $svg = $this->createReferencedFile('field_gated', 'logo.svg');
    $svg->setMimeType('image/svg+xml');
    $svg->save();
    $svgResponse = $this->downloadFile($svg);
    $this->assertSame('nosniff', $svgResponse->headers->get('X-Content-Type-Options'));
    $this->assertStringStartsWith('attachment', (string) $svgResponse->headers->get('Content-Disposition'));

    // A PDF is safe to render inline when the site asks for inline.
    $pdf = $this->createReferencedFile('field_gated', 'safe.pdf');
    $pdf->setMimeType('application/pdf');
    $pdf->save();
    $pdfResponse = $this->downloadFile($pdf);
    $this->assertSame('nosniff', $pdfResponse->headers->get('X-Content-Type-Options'));
    $this->assertStringStartsWith('inline', (string) $pdfResponse->headers->get('Content-Disposition'));
  }

  /**
   * A closed availability window returns 410 at mint, not a dead 200.
   */
  public function testMintPastAvailabilityWindowReturns410(): void {
    FieldStorageConfig::loadByName('entity_test', 'field_gated')
      ->setThirdPartySetting('file_gate', 'method_settings', [
        'available_until' => \Drupal::time()->getRequestTime() - 60,
      ])->save();
    $file = $this->createReferencedFile('field_gated', 'expired.pdf');

    $response = MintController::create($this->container)
      ->mint($this->mintRequest(json_encode(['file' => $file->uuid()]), self::SECRET));
    $this->assertSame(410, $response->getStatusCode());
  }

  /**
   * A 404 (bytes gone) does not consume a one-time link's single use.
   */
  public function testMissingBytesDoesNotBurnOneTimeUse(): void {
    FieldStorageConfig::loadByName('entity_test', 'field_gated')
      ->setThirdPartySetting('file_gate', 'method_settings', ['max_uses' => 1])
      ->save();
    $file = $this->createReferencedFile('field_gated', 'once.pdf');
    $uri = $file->getFileUri();

    $mint = MintController::create($this->container)
      ->mint($this->mintRequest(json_encode(['file' => $file->uuid()]), self::SECRET));
    $query = [];
    parse_str((string) parse_url(json_decode((string) $mint->getContent(), TRUE)['path'], PHP_URL_QUERY), $query);

    // Bytes gone → 404, and (crucially) the single use is NOT consumed.
    unlink($uri);
    try {
      DownloadController::create($this->container)
        ->download(Request::create('/api/file-gate/download', 'GET', $query));
      $this->fail('Expected a 404 for missing bytes.');
    }
    catch (NotFoundHttpException) {
      // Expected.
    }

    // Restore the bytes: the same link still works, proving the use survived.
    file_put_contents($uri, 'BYTES:once.pdf');
    $response = DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * The authenticated method serves logged-in users and denies anonymous.
   */
  public function testAuthenticatedMethodGrantsOnlyLoggedIn(): void {
    // Gate the field with the live "authenticated" method (no minted URL).
    FieldStorageConfig::loadByName('entity_test', 'field_gated')
      ->setThirdPartySetting('file_gate', 'method', 'authenticated')
      ->save();
    $file = $this->createReferencedFile('field_gated', 'members.pdf');
    $query = ['f' => $file->uuid()];

    // Anonymous is denied.
    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
    try {
      DownloadController::create($this->container)
        ->download(Request::create('/api/file-gate/download', 'GET', $query));
      $this->fail('Anonymous download of an authenticated-gated file was not denied.');
    }
    catch (AccessDeniedHttpException) {
      // Expected.
    }

    // An authenticated user is served the file.
    $this->setCurrentUser($this->createUser());
    $response = DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * Mints signed query parameters for a file via the signed_url method.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return array
   *   The signed claims plus 'sig'.
   */
  private function mintParams(FileInterface $file): array {
    return $this->container
      ->get('plugin.manager.file_gate.gate_method')
      ->createInstance('signed_url', [])
      ->mint($file);
  }

  /**
   * Mints and redeems a signed_url download for a file.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The download response.
   */
  private function downloadFile(FileInterface $file) {
    $params = $this->mintParams($file);
    return DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', ['f' => $file->uuid()] + $params));
  }

  /**
   * Builds a mint request with an optional Basic-auth secret.
   *
   * @param string $body
   *   The JSON body.
   * @param string|null $secret
   *   The secret to present, or NULL for none.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The request.
   */
  private function mintRequest(string $body, ?string $secret): Request {
    $request = Request::create('/api/file-gate/mint', 'POST', [], [], [], [], $body);
    if ($secret !== NULL) {
      $request->headers->set('Authorization', 'Basic ' . base64_encode('mint:' . $secret));
    }
    return $request;
  }

}
