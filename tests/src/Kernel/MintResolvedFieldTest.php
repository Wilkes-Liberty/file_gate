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
use Drupal\file_gate\Controller\MintController;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Pins mint-resolved field persistence for two signed_url fields on one file.
 *
 * Unpinned getGateForFile() picks the lexicographic winner among
 * equal-strictness methods. Re-resolving inside SignedUrl::mint() would store
 * that winner instead of the field the mint controller already pinned.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class MintResolvedFieldTest extends KernelTestBase {

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

    $this->config('file_gate.settings')->set('download_secret', self::SECRET)->save();

    $this->createGatedField('field_nda');
    $this->createGatedField('field_whitepaper');
  }

  /**
   * Minting the lexicographic loser stores that field, not the unpinned winner.
   */
  public function testMintPersistsPinnedSignedUrlFieldOnSharedFile(): void {
    $file = $this->createFileOnBothFields('shared.pdf');

    $unpinned = $this->container->get('file_gate.resolver')->getGateForFile($file);
    $this->assertSame(self::NDA_FIELD, $unpinned['field']);

    $query = $this->mintQuery($file, self::WHITEPAPER_FIELD);
    $this->assertNotEmpty($query['jti']);

    $inventory = $this->container->get('file_gate.grant_inventory');
    $meta = $inventory->meta((string) $query['jti']);
    $this->assertIsArray($meta);
    $this->assertSame(self::WHITEPAPER_FIELD, $meta['field']);

    $on_whitepaper = $inventory->listForField(self::WHITEPAPER_FIELD);
    $this->assertCount(1, $on_whitepaper);
    $this->assertSame($query['jti'], $on_whitepaper[0]['jti']);
    $this->assertSame(self::WHITEPAPER_FIELD, $on_whitepaper[0]['field']);
    $this->assertSame([], $inventory->listForField(self::NDA_FIELD));
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
   *   Download query parameters, including jti.
   */
  private function mintQuery(FileInterface $file, string $field): array {
    $mint = MintController::create($this->container)->mint(
      $this->secretRequest(json_encode([
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
   * Authenticated mint request.
   *
   * @param string $body
   *   JSON body.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The request.
   */
  private function secretRequest(string $body): Request {
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
      'Basic ' . base64_encode('file-gate:' . self::SECRET),
    );
    return $request;
  }

}
