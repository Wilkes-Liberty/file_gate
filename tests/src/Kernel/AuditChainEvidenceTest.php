<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\file_gate\RecordingAuditChain;
use Drupal\entity_test\Entity\EntityTest;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file\FileInterface;
use Drupal\file_gate\Controller\DownloadController;
use Drupal\file_gate\Controller\MintController;
use Drupal\file_gate\Controller\OtpController;
use Drupal\file_gate\Controller\RevokeController;
use Drupal\file_gate\Service\FileGateAudit;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Audit rows omit filenames; optional keyed evidence can refuse delivery.
 *
 * Covers gaps G3 (filename in entity_label) and G5 (best-effort vs keyed
 * append) from the personnel confidential-files audit.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class AuditChainEvidenceTest extends KernelTestBase {

  /**
   * Seeded filename that must never appear in an audit row.
   */
  private const CANARY = 'CANARY_NDA_ALICE_SMITH';

  /**
   * Legacy whole-corpus mint secret.
   */
  private const SECRET = 'file-gate-test-secret';

  /**
   * Named secret used only to trigger a scope denial.
   */
  private const OTHER_ID = 's_other';

  /**
   * Named secret material (not the canary).
   */
  private const OTHER_SECRET = 'other-tier-secret-value';

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
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    parent::register($container);
    $container->register('audit_chain.logger', RecordingAuditChain::class)->setPublic(TRUE);
  }

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    RecordingAuditChain::reset();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installEntitySchema('entity_test');
    $this->installSchema('file', ['file_usage']);
    $this->installConfig(['field', 'file', 'file_gate', 'system']);

    $this->setSetting('file_private_path', $this->siteDirectory . '/private');
    $this->container->get('stream_wrapper_manager')
      ->registerWrapper('private', PrivateStream::class, StreamWrapperInterface::WRITE_VISIBLE);

    $this->setSetting('file_gate.secrets', [
      self::OTHER_ID => self::OTHER_SECRET,
    ]);
    $this->config('file_gate.settings')
      ->set('download_secret', self::SECRET)
      ->set('secret_scopes', [
        self::OTHER_ID => ['entity_test.field_otp'],
      ])
      ->save();
    $this->config('system.mail')->set('interface.default', 'test_mail_collector')->save();

    $this->createGatedField('field_gated', 'signed_url');
    $this->createGatedField('field_otp', 'otp', [
      'ttl' => 600,
      'max_attempts' => 3,
      'code_length' => 6,
    ]);
    $this->createGatedField('field_token', 'token');

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * Install config leaves audit_require_keyed off.
   */
  public function testRequireKeyedDefaultsOff(): void {
    $this->assertFalse((bool) $this->config('file_gate.settings')->get('audit_require_keyed'));
    $this->assertFalse($this->container->get('file_gate.audit')->requireKeyed());
  }

  /**
   * Opaque label is file:<id>, never the original filename.
   */
  public function testFileLabelIsOpaque(): void {
    $file = $this->createReferencedFile('field_gated', self::CANARY . '.pdf');
    $this->assertSame('file:' . $file->id(), FileGateAudit::fileLabel($file));
    $this->assertStringNotContainsString(self::CANARY, FileGateAudit::fileLabel($file));
  }

  /**
   * Mint, deny, download, OTP, and revoke rows never contain the filename.
   */
  public function testAuditRowsNeverContainFilename(): void {
    $file = $this->createReferencedFile('field_gated', self::CANARY . '.pdf');

    $mint = MintController::create($this->container)
      ->mint($this->secretRequest('/api/file-gate/mint', json_encode(['file' => $file->uuid()]), self::SECRET));
    $this->assertSame(200, $mint->getStatusCode());
    $query = [];
    parse_str((string) parse_url(json_decode((string) $mint->getContent(), TRUE)['path'], PHP_URL_QUERY), $query);

    $download = DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
    $this->assertInstanceOf(BinaryFileResponse::class, $download);
    $this->assertSame(200, $download->getStatusCode());

    $claims = ['exp' => $this->container->get('datetime.time')->getRequestTime() - 10];
    $resource = $this->container->get('stream_wrapper_manager')->normalizeUri($file->getFileUri());
    $sig = $this->container->get('file_gate.grant_signer')->sign($resource, $claims);
    try {
      DownloadController::create($this->container)->download(Request::create('/api/file-gate/download', 'GET', [
        'f' => $file->uuid(),
        'exp' => $claims['exp'],
        'sig' => $sig,
      ]));
      $this->fail('Expired grant must be denied.');
    }
    catch (AccessDeniedHttpException) {
      // Expected download_denied row.
    }

    $denied = MintController::create($this->container)->mint(
      $this->secretRequest(
        '/api/file-gate/mint',
        json_encode(['file' => $file->uuid()]),
        self::OTHER_SECRET,
        self::OTHER_ID,
      ),
    );
    $this->assertSame(403, $denied->getStatusCode());

    $otp_file = $this->createReferencedFile('field_otp', self::CANARY . '-otp.pdf');
    $otp = OtpController::create($this->container)->request(
      $this->secretRequest('/api/file-gate/otp', json_encode([
        'file' => $otp_file->uuid(),
        'email' => 'requester@example.com',
      ]), self::SECRET),
    );
    $this->assertSame(204, $otp->getStatusCode());

    $token_file = $this->createReferencedFile('field_token', self::CANARY . '-token.pdf');
    $token_mint = MintController::create($this->container)
      ->mint($this->secretRequest('/api/file-gate/mint', json_encode(['file' => $token_file->uuid()]), self::SECRET));
    $this->assertSame(200, $token_mint->getStatusCode());
    $token_query = [];
    parse_str((string) parse_url(json_decode((string) $token_mint->getContent(), TRUE)['path'], PHP_URL_QUERY), $token_query);
    $revoked = RevokeController::create($this->container)->revoke(
      $this->secretRequest('/api/file-gate/revoke', json_encode(['token' => $token_query['token']]), self::SECRET),
    );
    $this->assertSame(204, $revoked->getStatusCode());

    $ops = array_column(RecordingAuditChain::$events, 1);
    foreach (['mint', 'mint_denied', 'download', 'download_denied', 'otp_issue', 'revoke'] as $op) {
      $this->assertContains($op, $ops, "Expected a $op audit row.");
    }

    $encoded = json_encode(RecordingAuditChain::$events);
    $this->assertIsString($encoded);
    $this->assertStringNotContainsString(self::CANARY, $encoded);
    $this->assertStringNotContainsString('.pdf', $encoded);

    foreach (RecordingAuditChain::$events as $event) {
      $this->assertSame('file_gate', $event[0]);
      $meta = $event[2];
      if (isset($meta['label'])) {
        $this->assertStringStartsWith('file:', (string) $meta['label']);
        $this->assertDoesNotMatchRegularExpression('/[A-Za-z0-9._-]+\.(pdf|docx?|txt)$/i', (string) $meta['label']);
      }
    }
  }

  /**
   * With require-keyed off, a missing signing key does not block download.
   */
  public function testRequireKeyedOffDownloadProceedsWhenKeyMissing(): void {
    $this->config('file_gate.settings')->set('audit_require_keyed', FALSE)->save();
    RecordingAuditChain::$keyedAvailable = FALSE;
    $file = $this->createReferencedFile('field_gated', self::CANARY . '.pdf');
    $query = $this->mintQuery($file);

    $response = DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));

    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
    $this->assertEventsHaveNoCanary();
  }

  /**
   * With require-keyed on and the key missing, download is 503.
   */
  public function testRequireKeyedOnDownloadRefusedWhenKeyMissing(): void {
    $file = $this->createReferencedFile('field_gated', self::CANARY . '.pdf');
    // Mint while keyed writes still succeed so we have a live grant.
    $query = $this->mintQuery($file);
    $this->config('file_gate.settings')->set('audit_require_keyed', TRUE)->save();
    RecordingAuditChain::reset();
    RecordingAuditChain::$keyedAvailable = FALSE;

    $response = DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));

    $this->assertNotInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
    $this->assertSame(FileGateAudit::REFUSAL_MESSAGE, $response->getContent());
    $this->assertStringNotContainsString(self::CANARY, (string) $response->getContent());
    $this->assertSame([], RecordingAuditChain::$events);
  }

  /**
   * With require-keyed on and the key missing, mint is 503.
   */
  public function testRequireKeyedOnMintRefusedWhenKeyMissing(): void {
    $this->config('file_gate.settings')->set('audit_require_keyed', TRUE)->save();
    RecordingAuditChain::$keyedAvailable = FALSE;
    $file = $this->createReferencedFile('field_gated', self::CANARY . '.pdf');

    $response = MintController::create($this->container)
      ->mint($this->secretRequest('/api/file-gate/mint', json_encode(['file' => $file->uuid()]), self::SECRET));

    $this->assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
    $data = json_decode((string) $response->getContent(), TRUE);
    $this->assertSame(FileGateAudit::REFUSAL_MESSAGE, $data['error']);
    $this->assertArrayNotHasKey('path', $data);
    $this->assertEventsHaveNoCanary();
    $this->assertSame([], RecordingAuditChain::$events);
  }

  /**
   * With require-keyed on and a key present, download streams and records.
   */
  public function testRequireKeyedOnDownloadSucceedsWhenKeyPresent(): void {
    $this->config('file_gate.settings')->set('audit_require_keyed', TRUE)->save();
    RecordingAuditChain::$keyedAvailable = TRUE;
    $file = $this->createReferencedFile('field_gated', self::CANARY . '.pdf');
    $query = $this->mintQuery($file);

    $response = DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));

    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
    $ops = array_column(RecordingAuditChain::$events, 1);
    $this->assertContains('download', $ops);
    $this->assertEventsHaveNoCanary();
  }

  /**
   * Creates a gated private file field on entity_test.
   *
   * @param string $field_name
   *   Field name.
   * @param string $method
   *   Gate method plugin id.
   * @param array<string, mixed> $settings
   *   Method settings.
   */
  private function createGatedField(string $field_name, string $method, array $settings = []): void {
    $storage = FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => $field_name,
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ]);
    $storage->setThirdPartySetting('file_gate', 'gated', TRUE);
    $storage->setThirdPartySetting('file_gate', 'method', $method);
    if ($settings !== []) {
      $storage->setThirdPartySetting('file_gate', 'method_settings', $settings);
    }
    $storage->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => $field_name,
      'bundle' => 'entity_test',
    ])->save();
  }

  /**
   * Creates a private file referenced by an entity_test via the given field.
   *
   * @param string $field_name
   *   The referencing field.
   * @param string $filename
   *   The file name under private:// (includes the canary).
   *
   * @return \Drupal\file\FileInterface
   *   The saved, referenced, permanent file.
   */
  private function createReferencedFile(string $field_name, string $filename): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);
    $file = File::create([
      'uri' => $uri,
      'filename' => $filename,
    ]);
    $file->setPermanent();
    $file->save();
    $entity = EntityTest::create(['name' => 'host', $field_name => ['target_id' => $file->id()]]);
    $entity->save();
    \Drupal::service('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());
    return $file;
  }

  /**
   * Mints a signed_url grant and returns the download query.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   *
   * @return array<string, string>
   *   Download query parameters.
   */
  private function mintQuery(FileInterface $file): array {
    $response = MintController::create($this->container)
      ->mint($this->secretRequest('/api/file-gate/mint', json_encode(['file' => $file->uuid()]), self::SECRET));
    $this->assertSame(200, $response->getStatusCode());
    $query = [];
    parse_str((string) parse_url(json_decode((string) $response->getContent(), TRUE)['path'], PHP_URL_QUERY), $query);
    return $query;
  }

  /**
   * Builds an authenticated POST request.
   *
   * @param string $path
   *   Request path.
   * @param string $body
   *   JSON body.
   * @param string $secret
   *   Basic-auth password.
   * @param string $username
   *   Basic-auth username (named secret id, or empty for legacy).
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The request.
   */
  private function secretRequest(string $path, string $body, string $secret, string $username = ''): Request {
    $request = Request::create($path, 'POST', [], [], [], [], $body);
    $request->headers->set('Content-Type', 'application/json');
    $request->headers->set('Authorization', 'Basic ' . base64_encode($username . ':' . $secret));
    return $request;
  }

  /**
   * Asserts no recorded audit event contains the seeded filename.
   */
  private function assertEventsHaveNoCanary(): void {
    $encoded = json_encode(RecordingAuditChain::$events);
    $this->assertIsString($encoded);
    $this->assertStringNotContainsString(self::CANARY, $encoded);
  }

}
