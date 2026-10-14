<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface;
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
use Drupal\file_gate\Plugin\GateMethod\Token;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Token redeem pins the mint-stored field and ignores an unsigned body fld.
 *
 * Token::grants() must use MintStoredField::pin() like download / signed_url
 * / the assurance bridge. fromRequest() would treat a JSON body field as a
 * pin when the token-store row has no field. An unsigned body field or fld
 * must not select another field's scope.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class TokenRedeemMintStoredFieldTest extends KernelTestBase {

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
   * Lexicographic winner when both fields are token.
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

    $this->createGatedTokenField('field_nda');
    $this->createGatedTokenField('field_whitepaper');
  }

  /**
   * Unsigned body field/fld cannot override the mint-stored token pin.
   */
  public function testTokenRedeemIgnoresUnsignedBodyFld(): void {
    $file = $this->createFileOnBothFields('shared.pdf');

    $unpinned = $this->container->get('file_gate.resolver')->getGateForFile($file);
    $this->assertSame(self::NDA_FIELD, $unpinned['field']);

    $registry = $this->container->get('file_gate.secret_registry');
    $this->assertTrue($registry->allowsField(self::PUBLIC_ID, self::WHITEPAPER_FIELD));
    $this->assertFalse($registry->allowsField(self::PUBLIC_ID, self::NDA_FIELD));

    $query = $this->mintQuery($file, self::WHITEPAPER_FIELD);
    $this->assertArrayHasKey('token', $query);
    $this->assertArrayNotHasKey('fld', $query);
    $this->assertSame(self::PUBLIC_ID, $query['k']);

    $record = $this->tokenStore()->get(hash('sha256', (string) $query['token']));
    $this->assertIsArray($record);
    $this->assertSame(self::WHITEPAPER_FIELD, $record['field']);

    // The stored pin must win. Treating the unsigned body as the pin would
    // run allowsField() against field_nda and deny this grant.
    $body = json_encode([
      'field' => self::NDA_FIELD,
      'fld' => self::NDA_FIELD,
    ]);
    $download = $this->download($query, $body);
    $this->assertSame(Response::HTTP_OK, $download->getStatusCode());
  }

  /**
   * An unsigned body fld cannot pin when the token-store field is absent.
   */
  public function testUnsignedBodyFldCannotPinWhenStoreFieldAbsent(): void {
    $file = $this->createFileOnBothFields('legacy.pdf');
    $query = $this->mintQuery($file, self::WHITEPAPER_FIELD);

    $store = $this->tokenStore();
    $hash = hash('sha256', (string) $query['token']);
    $record = $store->get($hash);
    $this->assertIsArray($record);
    unset($record['field']);
    $store->setWithExpire(
      $hash,
      $record,
      max(1, (int) $query['exp'] - $this->container->get('datetime.time')->getRequestTime()),
    );

    // fromRequest() would accept this unsigned body as the pin and pass
    // allowsField() against field_whitepaper. pin() ignores it.
    $body = json_encode([
      'field' => self::WHITEPAPER_FIELD,
      'fld' => self::WHITEPAPER_FIELD,
    ]);
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query, $body);
  }

  /**
   * Creates a token-method private file field on entity_test.
   *
   * @param string $field_name
   *   The field name.
   */
  private function createGatedTokenField(string $field_name): void {
    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => $field_name,
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'token')
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
   * Mints a token grant pinned to one field and returns the query.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   * @param string $field
   *   Field storage key (entity_type.field_name).
   *
   * @return array<string, mixed>
   *   Download query parameters, including token and k.
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
   * Redeems a download request with an optional unsigned JSON body.
   *
   * @param array<string, mixed> $query
   *   Download query parameters.
   * @param string $body
   *   Raw JSON body.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The download response.
   */
  private function download(array $query, string $body): Response {
    $request = Request::create(
      '/api/file-gate/download',
      'GET',
      $query,
      [],
      [],
      [],
      $body,
    );
    $request->headers->set('Content-Type', 'application/json');
    return DownloadController::create($this->container)->download($request);
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

  /**
   * The token store.
   *
   * @return \Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface
   *   The expirable key/value store holding minted token hashes.
   */
  private function tokenStore(): KeyValueStoreExpirableInterface {
    return $this->container->get('keyvalue.expirable')->get(Token::TOKEN_COLLECTION);
  }

}
