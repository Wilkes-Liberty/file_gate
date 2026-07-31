<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate_assurance\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\Session\AnonymousUserSession;
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

/**
 * Kernel tests for native WebAuthn verify_at mode (challenge path).
 *
 * Full authenticator ceremonies need a browser; this suite locks the gate
 * contract: valid grant without proof → step-up challenge, not 403.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class WebAuthnModeTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'file',
    'file_gate',
    'file_gate_assurance',
    'entity_test',
  ];

  private const SECRET = 'file-gate-webauthn-secret';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installEntitySchema('entity_test');
    $this->installSchema('file', ['file_usage']);
    $this->installSchema('file_gate_assurance', ['file_gate_webauthn_credential']);
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
      ->setThirdPartySetting('file_gate', 'method', 'assurance')
      ->setThirdPartySetting('file_gate', 'method_settings', [
        'verify_at' => 'webauthn',
        'aal' => 3,
        'rp_id' => 'localhost',
        'rp_name' => 'File Gate Test',
        'origins' => ['http://localhost'],
        'bridge' => TRUE,
      ])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * Plain GET without WebAuthn proof is redirected to step-up.
   */
  public function testMissingProofChallengesStepUp(): void {
    $file = $this->createFile();
    $query = $this->mintQuery($file);
    $request = Request::create('/api/file-gate/download', 'GET', $query);
    $response = DownloadController::create($this->container)->download($request);
    $this->assertSame(302, $response->getStatusCode());
    $location = (string) $response->headers->get('Location');
    $this->assertStringContainsString('/api/file-gate/assurance/step-up', $location);
    $this->assertStringContainsString('mode=webauthn', $location);
  }

  /**
   * JSON clients receive a webauthn_required challenge payload.
   */
  public function testMissingProofJsonChallenge(): void {
    $file = $this->createFile();
    $query = $this->mintQuery($file);
    $request = Request::create('/api/file-gate/download', 'GET', $query);
    $request->headers->set('Accept', 'application/json');
    $response = DownloadController::create($this->container)->download($request);
    $this->assertSame(401, $response->getStatusCode());
    $data = json_decode((string) $response->getContent(), TRUE);
    $this->assertSame('webauthn_required', $data['error'] ?? NULL);
    $this->assertNotEmpty($data['assert_options'] ?? NULL);
    $this->assertNotEmpty($data['assert'] ?? NULL);
  }

  /**
   * Mints a signed grant for the gated file.
   *
   * @return array<string, mixed>
   *   Download query parameters.
   */
  private function mintQuery(FileInterface $file): array {
    $request = Request::create('/api/file-gate/mint', 'POST', [], [], [], [], (string) json_encode([
      'file' => $file->uuid(),
      'subject' => 'user-subject-1',
    ]));
    $request->headers->set('Content-Type', 'application/json');
    $request->headers->set('Authorization', 'Basic ' . base64_encode(':' . self::SECRET));
    $response = MintController::create($this->container)->mint($request);
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getContent());
    $data = json_decode((string) $response->getContent(), TRUE);
    $path = (string) ($data['path'] ?? '');
    $query = [];
    parse_str(parse_url($path, PHP_URL_QUERY) ?: '', $query);
    return $query;
  }

  /**
   * Creates a gated private file.
   */
  private function createFile(): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/webauthn.pdf';
    file_put_contents($uri, 'BYTES');
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

}
