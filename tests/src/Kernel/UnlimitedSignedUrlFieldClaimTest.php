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
use Drupal\file_gate\Plugin\GateMethod\Token;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Unlimited signed_url pins the mint field as a signed claim at redeem.
 *
 * Same class as #100, but max_uses=0 writes no inventory row. Unpinned
 * getGateForFile() picks field_nda. A named secret scoped only to
 * field_whitepaper then fails allowsField() unless redeem uses HMAC-validated
 * fld. An unsigned field= query, JSON body field, or token query is not a pin
 * when fld is present: those must not select the other field's settings.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class UnlimitedSignedUrlFieldClaimTest extends KernelTestBase {

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
   * Lexicographic winner when both fields share a method.
   */
  private const NDA_FIELD = 'entity_test.field_nda';

  /**
   * Mint target: loses the unpinned resolver tie-break to field_nda.
   */
  private const WHITEPAPER_FIELD = 'entity_test.field_whitepaper';

  /**
   * Allowed origin for the whitepaper referrer_lock field.
   */
  private const WHITEPAPER_ORIGIN = 'https://app.example.com';

  /**
   * Allowed origin for the nda referrer_lock field (unpinned winner).
   */
  private const NDA_ORIGIN = 'https://nda.example.com';

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
  }

  /**
   * Named-secret redeem of unlimited field_whitepaper uses signed fld.
   */
  public function testUnlimitedRedeemUsesSignedFieldClaimNotUnpinnedNda(): void {
    $this->createGatedField('field_nda', 'signed_url', ['max_uses' => 0]);
    $this->createGatedField('field_whitepaper', 'signed_url', ['max_uses' => 0]);
    $file = $this->createFileOnBothFields('shared.pdf');

    $unpinned = $this->container->get('file_gate.resolver')->getGateForFile($file);
    $this->assertSame(self::NDA_FIELD, $unpinned['field']);

    $registry = $this->container->get('file_gate.secret_registry');
    $this->assertTrue($registry->allowsField(self::PUBLIC_ID, self::WHITEPAPER_FIELD));
    $this->assertFalse($registry->allowsField(self::PUBLIC_ID, self::NDA_FIELD));

    $query = $this->mintQuery($file, self::WHITEPAPER_FIELD);
    $this->assertSame(self::WHITEPAPER_FIELD, $query['fld'] ?? NULL);
    $this->assertArrayNotHasKey('jti', $query);
    $this->assertSame(self::PUBLIC_ID, $query['k']);
    $this->assertSame([], $this->container->get('file_gate.grant_inventory')->listForField(self::WHITEPAPER_FIELD));
    $this->assertSame([], $this->container->get('file_gate.grant_inventory')->listForField(self::NDA_FIELD));

    $request = Request::create('/api/file-gate/download', 'GET', $query);
    $download = DownloadController::create($this->container)->download($request);
    $this->assertSame(Response::HTTP_OK, $download->getStatusCode());
  }

  /**
   * Tampering with signed fld fails closed; unsigned field= is ignored.
   */
  public function testTamperedFldFailsAndUnsignedFieldQueryIsIgnored(): void {
    $this->createGatedField('field_nda', 'signed_url', ['max_uses' => 0]);
    $this->createGatedField('field_whitepaper', 'signed_url', ['max_uses' => 0]);
    $file = $this->createFileOnBothFields('shared.pdf');

    $query = $this->mintQuery($file, self::WHITEPAPER_FIELD);
    $this->assertSame(self::WHITEPAPER_FIELD, $query['fld'] ?? NULL);

    $ignored = $query + ['field' => self::NDA_FIELD];
    $ok = DownloadController::create($this->container)->download(
      Request::create('/api/file-gate/download', 'GET', $ignored),
    );
    $this->assertSame(Response::HTTP_OK, $ok->getStatusCode());

    $tampered = $query;
    $tampered['fld'] = self::NDA_FIELD;
    $this->expectException(AccessDeniedHttpException::class);
    DownloadController::create($this->container)->download(
      Request::create('/api/file-gate/download', 'GET', $tampered),
    );
  }

  /**
   * ReferrerLock inherits the signed fld claim and uses it at redeem.
   */
  public function testReferrerLockInheritsSignedFieldClaim(): void {
    $this->createGatedField('field_nda', 'referrer_lock', [
      'max_uses' => 0,
      'allowed_origins' => [self::NDA_ORIGIN],
    ]);
    $this->createGatedField('field_whitepaper', 'referrer_lock', [
      'max_uses' => 0,
      'allowed_origins' => [self::WHITEPAPER_ORIGIN],
    ]);
    $file = $this->createFileOnBothFields('lock.pdf');

    $unpinned = $this->container->get('file_gate.resolver')->getGateForFile($file);
    $this->assertSame(self::NDA_FIELD, $unpinned['field']);

    $query = $this->mintQuery($file, self::WHITEPAPER_FIELD);
    $this->assertSame(self::WHITEPAPER_FIELD, $query['fld'] ?? NULL);
    $this->assertArrayNotHasKey('jti', $query);
    $this->assertSame([], $this->container->get('file_gate.grant_inventory')->listForField(self::WHITEPAPER_FIELD));

    $request = Request::create('/api/file-gate/download', 'GET', $query);
    $request->headers->set('Origin', self::WHITEPAPER_ORIGIN);
    $download = DownloadController::create($this->container)->download($request);
    $this->assertSame(Response::HTTP_OK, $download->getStatusCode());
  }

  /**
   * A weaker field's settings cannot be selected by an unsigned pin.
   *
   * ReferrerLock checks origin on the controller-selected instance before
   * the HMAC. Body field and a token-store row are not signed_url claims,
   * so either one used to apply field_nda's allowlist to a field_whitepaper
   * grant while signatureValid() still trusted fld.
   */
  public function testUnsignedPinCannotSelectWeakerReferrerSettings(): void {
    $this->createGatedField('field_nda', 'referrer_lock', [
      'max_uses' => 0,
      'allowed_origins' => [self::NDA_ORIGIN],
    ]);
    $this->createGatedField('field_whitepaper', 'referrer_lock', [
      'max_uses' => 0,
      'allowed_origins' => [self::WHITEPAPER_ORIGIN],
    ]);
    $file = $this->createFileOnBothFields('lock.pdf');
    $query = $this->mintQuery($file, self::WHITEPAPER_FIELD);
    $this->assertSame(self::WHITEPAPER_FIELD, $query['fld'] ?? NULL);
    $this->assertArrayNotHasKey('jti', $query);

    $body = json_encode(['field' => self::NDA_FIELD]);
    $this->assertSame(Response::HTTP_OK, $this->downloadWithOrigin(
      $query,
      self::WHITEPAPER_ORIGIN,
      $body,
    )->getStatusCode());
    $this->assertDownloadDenied($query, self::NDA_ORIGIN, $body);

    $token = 'unsigned-token-pin';
    $factory = $this->container->get('keyvalue.expirable');
    /** @var \Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface $store */
    $store = $factory->get(Token::TOKEN_COLLECTION);
    $store->setWithExpire(hash('sha256', $token), [
      'uses' => 0,
      'max' => 0,
      'field' => self::NDA_FIELD,
    ], 3600);
    $with_token = $query + ['token' => $token];
    $this->assertSame(Response::HTTP_OK, $this->downloadWithOrigin(
      $with_token,
      self::WHITEPAPER_ORIGIN,
    )->getStatusCode());
    $this->assertDownloadDenied($with_token, self::NDA_ORIGIN);
  }

  /**
   * Downloads with an Origin header and an optional raw body.
   *
   * @param array<string, mixed> $query
   *   Download query, including the signed grant.
   * @param string $origin
   *   Origin header value.
   * @param string|null $body
   *   Raw request body, or NULL.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The download response.
   */
  private function downloadWithOrigin(
    array $query,
    string $origin,
    ?string $body = NULL,
  ): Response {
    $request = Request::create(
      '/api/file-gate/download',
      'GET',
      $query,
      [],
      [],
      [],
      $body,
    );
    $request->headers->set('Origin', $origin);
    return DownloadController::create($this->container)->download($request);
  }

  /**
   * Asserts the download is denied for this origin.
   *
   * @param array<string, mixed> $query
   *   Download query, including the signed grant.
   * @param string $origin
   *   Origin header value.
   * @param string|null $body
   *   Raw request body, or NULL.
   */
  private function assertDownloadDenied(
    array $query,
    string $origin,
    ?string $body = NULL,
  ): void {
    try {
      $this->downloadWithOrigin($query, $origin, $body);
      $this->fail('Weaker-field origin must not redeem the signed grant.');
    }
    catch (AccessDeniedHttpException) {
      // The other field's allowlist must not apply to this grant.
    }
  }

  /**
   * Creates an unlimited (or configured) private file field on entity_test.
   *
   * @param string $field_name
   *   The field name.
   * @param string $method
   *   Gate method id.
   * @param array<string, mixed> $settings
   *   Method settings.
   */
  private function createGatedField(string $field_name, string $method, array $settings): void {
    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => $field_name,
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', $method)
      ->setThirdPartySetting('file_gate', 'method_settings', $settings)
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
   * Mints a grant pinned to one field and returns the query.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   * @param string $field
   *   Field storage key (entity_type.field_name).
   *
   * @return array<string, mixed>
   *   Download query parameters.
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
