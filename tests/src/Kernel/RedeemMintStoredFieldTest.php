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
use Symfony\Component\HttpFoundation\Response;

/**
 * Redeem pins the mint-stored field when two signed_url fields share a file.
 *
 * Unpinned getGateForFile() picks field_nda. A named secret scoped only to
 * field_whitepaper then fails allowsField() unless redeem reads the grant
 * row stored at mint.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class RedeemMintStoredFieldTest extends KernelTestBase {

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
   * Named secret id scoped to the whitepaper field.
   */
  private const PUBLIC_ID = 's_public';

  /**
   * Named secret value.
   */
  private const PUBLIC_SECRET = 'public-tier-secret-value';

  /**
   * Lexicographic winner when both fields are signed_url.
   */
  private const NDA_FIELD = 'entity_test.field_nda';

  /**
   * Mint target: loses the unpinned resolver tie-break to field_nda.
   */
  private const WHITEPAPER_FIELD = 'entity_test.field_whitepaper';

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
    ]);
    $this->config('file_gate.settings')
      ->set('download_secret', 'legacy-unused-in-this-test')
      ->set('secret_scopes', [
        self::PUBLIC_ID => [self::WHITEPAPER_FIELD],
      ])
      ->save();

    $this->createGatedField('field_nda');
    $this->createGatedField('field_whitepaper');
  }

  /**
   * Named-secret redeem of field_whitepaper succeeds despite unpinned nda.
   */
  public function testRedeemUsesMintStoredWhitepaperNotUnpinnedNda(): void {
    $file = $this->createFileOnBothFields('shared.pdf');

    $unpinned = $this->container->get('file_gate.resolver')->getGateForFile($file);
    $this->assertSame(self::NDA_FIELD, $unpinned['field']);

    $registry = $this->container->get('file_gate.secret_registry');
    $this->assertTrue($registry->allowsField(self::PUBLIC_ID, self::WHITEPAPER_FIELD));
    $this->assertFalse($registry->allowsField(self::PUBLIC_ID, self::NDA_FIELD));

    $query = $this->mintQuery($file, self::WHITEPAPER_FIELD);
    $this->assertNotEmpty($query['jti']);
    $this->assertSame(self::PUBLIC_ID, $query['k']);

    $meta = $this->container->get('file_gate.grant_inventory')->meta((string) $query['jti']);
    $this->assertIsArray($meta);
    $this->assertSame(self::WHITEPAPER_FIELD, $meta['field']);

    $request = Request::create('/api/file-gate/download', 'GET', $query);
    $download = DownloadController::create($this->container)->download($request);
    $this->assertSame(Response::HTTP_OK, $download->getStatusCode());
  }

  /**
   * Creates a usage-limited signed_url private file field on entity_test.
   *
   * @param string $field_name
   *   The field name.
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
      ->setThirdPartySetting('file_gate', 'method_settings', ['max_uses' => 1])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => $field_name,
      'bundle' => 'entity_test',
    ])->save();
  }

  /**
   * Creates one private file referenced by both gated fields.
   *
   * @param string $filename
   *   The file name under private://docs.
   *
   * @return \Drupal\file\FileInterface
   *   The saved, referenced, permanent file.
   */
  private function createFileOnBothFields(string $filename): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory(
      $directory,
      FileSystemInterface::CREATE_DIRECTORY,
    );
    $uri = 'private://docs/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);
    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();

    $whitepaper = EntityTest::create([
      'name' => 'wp-host',
      'field_whitepaper' => ['target_id' => $file->id()],
    ]);
    $whitepaper->save();
    \Drupal::service('file.usage')->add(
      $file,
      'file',
      'entity_test',
      (string) $whitepaper->id(),
    );

    $nda = EntityTest::create([
      'name' => 'nda-host',
      'field_nda' => ['target_id' => $file->id()],
    ]);
    $nda->save();
    \Drupal::service('file.usage')->add(
      $file,
      'file',
      'entity_test',
      (string) $nda->id(),
    );

    return $file;
  }

  /**
   * Mints a usage-limited grant pinned to one field and returns the query.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   * @param string $field
   *   Field storage key (entity_type.field_name).
   *
   * @return array<string, mixed>
   *   Download query parameters, including jti and k.
   */
  private function mintQuery(FileInterface $file, string $field): array {
    $mint = MintController::create($this->container)->mint(
      $this->namedSecretRequest(json_encode([
        'file' => $file->uuid(),
        'field' => $field,
      ])),
    );
    $this->assertSame(Response::HTTP_OK, $mint->getStatusCode());
    $data = json_decode((string) $mint->getContent(), TRUE);
    $this->assertSame($field, $data['field']);
    $query = [];
    parse_str((string) parse_url($data['path'], PHP_URL_QUERY), $query);
    return $query;
  }

  /**
   * Authenticated mint request using the whitepaper-scoped named secret.
   *
   * @param string $body
   *   JSON body.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The request.
   */
  private function namedSecretRequest(string $body): Request {
    $request = Request::create(
      '/api/file-gate/mint',
      'POST',
      [],
      [],
      [],
      [],
      $body,
    );
    $request->headers->set('Content-Type', 'application/json');
    $request->headers->set(
      'Authorization',
      'Basic ' . base64_encode(self::PUBLIC_ID . ':' . self::PUBLIC_SECRET),
    );
    return $request;
  }

}
