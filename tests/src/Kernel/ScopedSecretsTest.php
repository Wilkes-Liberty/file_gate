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
use Drupal\file_gate\Controller\MintController;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Kernel tests for scoped named signing secrets (#30).
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class ScopedSecretsTest extends KernelTestBase {

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
   * Legacy whole-corpus secret.
   */
  private const LEGACY = 'legacy-site-secret';

  /**
   * Named secret for the whitepaper field.
   */
  private const PUBLIC_ID = 's_public';

  /**
   * Named secret for the NDA field.
   */
  private const NDA_ID = 's_nda';

  /**
   * Named secret values.
   */
  private const PUBLIC_SECRET = 'public-tier-secret-value';

  /**
   * Named NDA secret value.
   */
  private const NDA_SECRET = 'nda-tier-secret-value';

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

    // Named secret values (settings.php equivalent). Settings is read when
    // the registry is constructed; set before services that depend on it.
    $this->setSetting('file_gate.secrets', [
      self::PUBLIC_ID => self::PUBLIC_SECRET,
      self::NDA_ID => self::NDA_SECRET,
    ]);

    $this->config('file_gate.settings')
      ->set('download_secret', self::LEGACY)
      ->set('secret_scopes', [
        self::PUBLIC_ID => ['entity_test.field_whitepaper'],
        self::NDA_ID => ['entity_test.field_nda'],
      ])
      ->save();

    $this->createGatedField('field_whitepaper');
    $this->createGatedField('field_nda');
  }

  /**
   * Creates a gated private file field on entity_test.
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
   * Mint request with Basic auth (optional username = secret id).
   */
  private function mintRequest(string $body, string $password, ?string $username = NULL): Request {
    $request = Request::create('/api/file-gate/mint', 'POST', [], [], [], [], $body);
    $request->headers->set('Content-Type', 'application/json');
    $user = $username ?? '';
    $request->headers->set('Authorization', 'Basic ' . base64_encode($user . ':' . $password));
    return $request;
  }

  /**
   * Legacy secret still mints and redeems without k=.
   */
  public function testLegacySecretUnscopedMintAndRedeem(): void {
    $file = $this->createFile('field_nda', 'nda.pdf');
    $response = MintController::create($this->container)
      ->mint($this->mintRequest(json_encode(['file' => $file->uuid()]), self::LEGACY));
    $this->assertSame(200, $response->getStatusCode());
    $data = json_decode((string) $response->getContent(), TRUE);
    $this->assertStringNotContainsString('k=', $data['path']);

    parse_str(parse_url($data['path'], PHP_URL_QUERY) ?: '', $query);
    $request = Request::create('/api/file-gate/download', 'GET', $query);
    $download = DownloadController::create($this->container)->download($request);
    $this->assertSame(200, $download->getStatusCode());
  }

  /**
   * Named secret mints only in-scope fields.
   */
  public function testNamedSecretMintsOnlyScopedField(): void {
    $whitepaper = $this->createFile('field_whitepaper', 'wp.pdf');
    $nda = $this->createFile('field_nda', 'secret.pdf');

    $ok = MintController::create($this->container)->mint(
      $this->mintRequest(json_encode(['file' => $whitepaper->uuid()]), self::PUBLIC_SECRET, self::PUBLIC_ID),
    );
    $this->assertSame(200, $ok->getStatusCode());
    $path = json_decode((string) $ok->getContent(), TRUE)['path'];
    $this->assertStringContainsString('k=' . self::PUBLIC_ID, $path);

    $denied = MintController::create($this->container)->mint(
      $this->mintRequest(json_encode(['file' => $nda->uuid()]), self::PUBLIC_SECRET, self::PUBLIC_ID),
    );
    $this->assertSame(403, $denied->getStatusCode());
  }

  /**
   * Redemption re-checks scope after a secret is narrowed.
   */
  public function testNarrowingScopeDeniesOutstandingGrant(): void {
    $file = $this->createFile('field_whitepaper', 'wp2.pdf');
    $mint = MintController::create($this->container)->mint(
      $this->mintRequest(json_encode(['file' => $file->uuid()]), self::PUBLIC_SECRET, self::PUBLIC_ID),
    );
    $this->assertSame(200, $mint->getStatusCode());
    parse_str(parse_url(json_decode((string) $mint->getContent(), TRUE)['path'], PHP_URL_QUERY) ?: '', $query);

    // Narrow: remove the field from the public secret's scope.
    $this->config('file_gate.settings')
      ->set('secret_scopes', [
        self::PUBLIC_ID => [],
        self::NDA_ID => ['entity_test.field_nda'],
      ])
      ->save();

    $request = Request::create('/api/file-gate/download', 'GET', $query);
    $this->expectException(AccessDeniedHttpException::class);
    DownloadController::create($this->container)->download($request);
  }

  /**
   * Deleted named secret material makes outstanding grants unverifiable.
   */
  public function testDeletedSecretDeniesOutstandingGrant(): void {
    $file = $this->createFile('field_nda', 'nda2.pdf');
    $mint = MintController::create($this->container)->mint(
      $this->mintRequest(json_encode(['file' => $file->uuid()]), self::NDA_SECRET, self::NDA_ID),
    );
    $this->assertSame(200, $mint->getStatusCode());
    parse_str(parse_url(json_decode((string) $mint->getContent(), TRUE)['path'], PHP_URL_QUERY) ?: '', $query);

    // Remove NDA material without rebuilding $this->container (phpstan).
    $this->setSetting('file_gate.secrets', [
      self::PUBLIC_ID => self::PUBLIC_SECRET,
    ]);
    // Force a new registry instance that re-reads Settings.
    $this->container->set('file_gate.secret_registry', new \Drupal\file_gate\SecretRegistry(
      $this->container->get('config.factory'),
      $this->container->get('settings'),
    ));
    $this->container->set('file_gate.grant_signer', new \Drupal\file_gate\GrantSigner(
      $this->container->get('config.factory'),
      $this->container->get('datetime.time'),
      $this->container->get('file_gate.secret_registry'),
    ));

    $request = Request::create('/api/file-gate/download', 'GET', $query);
    $this->expectException(AccessDeniedHttpException::class);
    DownloadController::create($this->container)->download($request);
  }

  /**
   * Named secret with value but empty scope is flagged unscoped.
   */
  public function testUnscopedNamedSecretReported(): void {
    $this->config('file_gate.settings')
      ->set('secret_scopes', [
        self::PUBLIC_ID => ['entity_test.field_whitepaper'],
        // NDA id missing from scopes entirely.
      ])
      ->save();

    /** @var \Drupal\file_gate\SecretRegistryInterface $registry */
    $registry = $this->container->get('file_gate.secret_registry');
    $this->assertTrue($registry->isNamedSecretUnscoped(self::NDA_ID));

    $this->container->get('module_handler')->loadInclude('file_gate', 'install');
    $requirements = file_gate_requirements('runtime');
    $this->assertArrayHasKey('file_gate_unscoped_named_secrets', $requirements);
    $this->assertSame(REQUIREMENT_ERROR, $requirements['file_gate_unscoped_named_secrets']['severity']);
  }

  /**
   * Wrong password for a named secret is 401.
   */
  public function testNamedSecretBadPassword(): void {
    $file = $this->createFile('field_whitepaper', 'wp3.pdf');
    $response = MintController::create($this->container)->mint(
      $this->mintRequest(json_encode(['file' => $file->uuid()]), 'wrong', self::PUBLIC_ID),
    );
    $this->assertSame(401, $response->getStatusCode());
  }

  /**
   * Swapping k= to another configured key fails HMAC verification.
   */
  public function testKeyIdSwapFailsHmac(): void {
    $file = $this->createFile('field_whitepaper', 'wp4.pdf');
    $mint = MintController::create($this->container)->mint(
      $this->mintRequest(json_encode(['file' => $file->uuid()]), self::PUBLIC_SECRET, self::PUBLIC_ID),
    );
    parse_str(parse_url(json_decode((string) $mint->getContent(), TRUE)['path'], PHP_URL_QUERY) ?: '', $query);
    $query['k'] = self::NDA_ID;

    $request = Request::create('/api/file-gate/download', 'GET', $query);
    $this->expectException(AccessDeniedHttpException::class);
    DownloadController::create($this->container)->download($request);
  }

  /**
   * Registry allowsField semantics match the settled design.
   */
  public function testAllowsFieldSemantics(): void {
    /** @var \Drupal\file_gate\SecretRegistryInterface $registry */
    $registry = $this->container->get('file_gate.secret_registry');
    $this->assertTrue($registry->allowsField(NULL, 'entity_test.field_nda'));
    $this->assertTrue($registry->allowsField(self::PUBLIC_ID, 'entity_test.field_whitepaper'));
    $this->assertFalse($registry->allowsField(self::PUBLIC_ID, 'entity_test.field_nda'));
    $this->assertFalse($registry->allowsField(self::NDA_ID, 'entity_test.field_whitepaper'));
  }

}
