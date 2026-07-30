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
use Drupal\file_gate\Controller\RevokeController;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Tests the token gate method (minted + pre-shared) and the revoke endpoint.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class TokenGateTest extends KernelTestBase {

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
   * The token store collection name.
   */
  private const TOKEN_COLLECTION = 'file_gate_tokens';

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

    // Register a writable private filesystem for the test.
    $this->setSetting('file_private_path', $this->siteDirectory . '/private');
    $this->container->get('stream_wrapper_manager')
      ->registerWrapper('private', PrivateStream::class, StreamWrapperInterface::WRITE_VISIBLE);

    // A signing secret makes gating active.
    $this->config('file_gate.settings')->set('download_secret', self::SECRET)->save();

    // A gated private file field using the token method.
    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'token')
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    // Anonymous, for the delivery assertions.
    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * Mint records the token hash and returns token/exp/sig in the path.
   */
  public function testMintStoresTokenHashAndReturnsParams(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $query = $this->mintQuery($file);

    $this->assertArrayHasKey('token', $query);
    $this->assertArrayHasKey('exp', $query);
    $this->assertArrayHasKey('sig', $query);
    $this->assertSame($file->uuid(), $query['f']);

    $record = $this->tokenStore()->get(hash('sha256', $query['token']));
    $this->assertSame(['uses' => 0, 'max' => 0], $record);
  }

  /**
   * The happy path: mint, then redeem the signed token link, and count the use.
   */
  public function testHappyPathMintThenRedeem(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $query = $this->mintQuery($file);

    $response = $this->download($query);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());

    $record = $this->tokenStore()->get(hash('sha256', $query['token']));
    $this->assertSame(1, $record['uses']);
  }

  /**
   * A revoked token is denied even though its signature is still valid.
   */
  public function testRevokedTokenDenied(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $query = $this->mintQuery($file);

    // Revoke by deleting the stored hash (what the revoke endpoint does).
    $this->tokenStore()->delete(hash('sha256', $query['token']));

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query);
  }

  /**
   * A correctly signed token that was never minted (no store row) is denied.
   */
  public function testUnknownTokenDenied(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $token = 'never-minted-token';
    $exp = $this->container->get('datetime.time')->getRequestTime() + 300;

    $query = [
      'f' => $file->uuid(),
      'token' => $token,
      'exp' => $exp,
      'sig' => $this->signTokenGrant($file, $token, $exp),
    ];

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query);
  }

  /**
   * A tampered signature is denied.
   */
  public function testTamperedSignatureDenied(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $query = $this->mintQuery($file);
    $query['sig'] .= 'deadbeef';

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query);
  }

  /**
   * An expired token is denied (rejected before any store lookup).
   */
  public function testExpiredTokenDenied(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $token = 'expired-token';
    $exp = $this->container->get('datetime.time')->getRequestTime() - 10;

    $query = [
      'f' => $file->uuid(),
      'token' => $token,
      'exp' => $exp,
      'sig' => $this->signTokenGrant($file, $token, $exp),
    ];

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query);
  }

  /**
   * A request with no token is denied.
   */
  public function testMissingCredentialDenied(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');

    $this->expectException(AccessDeniedHttpException::class);
    $this->download(['f' => $file->uuid()]);
  }

  /**
   * A one-time token (max_uses = 1) is spent after a single redemption.
   */
  public function testOneTimeToken(): void {
    $this->setMethodSettings(['max_uses' => 1]);
    $file = $this->createReferencedFile('field_gated', 'once.pdf');
    $query = $this->mintQuery($file);

    $this->assertSame(200, $this->download($query)->getStatusCode());

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query);
  }

  /**
   * An unlimited-use token still redeems repeatedly and stays revocable.
   */
  public function testUnlimitedTokenStillRevocable(): void {
    $file = $this->createReferencedFile('field_gated', 'many.pdf');
    $query = $this->mintQuery($file);

    // max_uses defaults to 0 (unlimited): both redemptions succeed.
    $this->assertSame(200, $this->download($query)->getStatusCode());
    $this->assertSame(200, $this->download($query)->getStatusCode());

    // Revoking (deleting the stored hash) denies it whatever the use count.
    $this->tokenStore()->delete(hash('sha256', $query['token']));
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query);
  }

  /**
   * A pre-shared token whose hash is in the field allowlist grants (no mint).
   */
  public function testPresharedTokenGrants(): void {
    $this->setMethodSettings(['tokens' => [hash('sha256', 'campaign-secret')]]);
    $file = $this->createReferencedFile('field_gated', 'campaign.pdf');

    // A static link: only the plaintext token, no exp/sig.
    $response = $this->download(['f' => $file->uuid(), 'token' => 'campaign-secret']);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A pre-shared token not in the allowlist is denied.
   */
  public function testPresharedTokenNotInAllowlistDenied(): void {
    $this->setMethodSettings(['tokens' => [hash('sha256', 'campaign-secret')]]);
    $file = $this->createReferencedFile('field_gated', 'campaign.pdf');

    $this->expectException(AccessDeniedHttpException::class);
    $this->download(['f' => $file->uuid(), 'token' => 'wrong-token']);
  }

  /**
   * With no allowlist configured, an unsigned token is denied (fail closed).
   */
  public function testPresharedDeniedWhenNoAllowlist(): void {
    $file = $this->createReferencedFile('field_gated', 'campaign.pdf');

    $this->expectException(AccessDeniedHttpException::class);
    $this->download(['f' => $file->uuid(), 'token' => 'anything']);
  }

  /**
   * Minted and pre-shared token shapes do not cross at redemption time.
   */
  public function testTokenShapesDoNotCross(): void {
    $this->setMethodSettings(['tokens' => [hash('sha256', 'campaign-secret')]]);
    $file = $this->createReferencedFile('field_gated', 'campaign.pdf');
    $minted = $this->mintQuery($file);

    // A minted token presented without a signature must not fall back to the
    // pre-shared allowlist path.
    try {
      $this->download(['f' => $file->uuid(), 'token' => $minted['token']]);
      $this->fail('Expected minted token without signature to be denied.');
    }
    catch (AccessDeniedHttpException $e) {
      // Expected.
    }

    // An allowlisted pre-shared token presented with a valid signature must not
    // be treated as minted.
    $exp = $this->container->get('datetime.time')->getRequestTime() + 300;
    try {
      $this->download([
        'f' => $file->uuid(),
        'token' => 'campaign-secret',
        'exp' => $exp,
        'sig' => $this->signTokenGrant($file, 'campaign-secret', $exp),
      ]);
      $this->fail('Expected pre-shared token presented with a signature to be denied.');
    }
    catch (AccessDeniedHttpException $e) {
      // Expected.
    }
  }

  /**
   * The revoke endpoint deletes a minted token and denies later redemption.
   */
  public function testRevokeDeletesMintedToken(): void {
    $file = $this->createReferencedFile('field_gated', 'gated.pdf');
    $query = $this->mintQuery($file);

    $response = $this->revoke($query['token'], self::SECRET);
    $this->assertSame(204, $response->getStatusCode());
    $this->assertFalse($this->tokenStore()->has(hash('sha256', $query['token'])));

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query);
  }

  /**
   * Revoking an unknown token returns 404.
   */
  public function testRevokeUnknownToken404(): void {
    $response = $this->revoke('never-minted-token', self::SECRET);
    $this->assertSame(404, $response->getStatusCode());
  }

  /**
   * Revoke rejects a wrong secret (401).
   */
  public function testRevokeRejectsBadSecret401(): void {
    $response = $this->revoke('any-token', 'wrong-secret');
    $this->assertSame(401, $response->getStatusCode());
  }

  /**
   * Revoke fails closed (503) when no secret is configured.
   */
  public function testRevokeFailsClosedWithoutSecret503(): void {
    $this->config('file_gate.settings')->set('download_secret', '')->save();
    $response = $this->revoke('any-token', self::SECRET);
    $this->assertSame(503, $response->getStatusCode());
  }

  /**
   * A serialised and unserialised Token plugin can still use its injected services.
   *
   * Regression guard: DependencySerializationTrait's __wakeup() cannot reach a
   * private property on a child class, so a round-tripped plugin would come back
   * with uninitialised typed properties and throw on the first service call. This
   * test catches any future regression back to private.
   */
  public function testSerializeRoundTripRestoresServices(): void {
    $file = $this->createReferencedFile('field_gated', 'roundtrip.pdf');

    /** @var \Drupal\file_gate\Plugin\GateMethod\Token $plugin */
    $plugin = $this->container->get('plugin.manager.file_gate.gate_method')
      ->createInstance('token', []);

    $restored = unserialize(serialize($plugin));

    // mint() exercises every injected service: the time service (expiry
    // calculation), the key/value factory (token store), the grant signer
    // (signing), and the stream wrapper manager (resource ID). A typed-property
    // access error on any of these means the service was not restored on
    // __wakeup().
    $params = $restored->mint($file);

    $this->assertArrayHasKey('token', $params);
    $this->assertArrayHasKey('exp', $params);
    $this->assertArrayHasKey('sig', $params);
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
   * Sets the gated field's token method settings.
   *
   * @param array $settings
   *   The method_settings to store (e.g. ['max_uses' => 1] or ['tokens' => …]).
   */
  private function setMethodSettings(array $settings): void {
    FieldStorageConfig::loadByName('entity_test', 'field_gated')
      ->setThirdPartySetting('file_gate', 'method_settings', $settings)
      ->save();
  }

  /**
   * Mints a token grant through the controller and returns the URL query.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file to mint for.
   *
   * @return array
   *   The download URL query: f, token, exp, sig.
   */
  private function mintQuery(FileInterface $file): array {
    $response = MintController::create($this->container)
      ->mint($this->postRequest('/api/file-gate/mint', json_encode(['file' => $file->uuid()]), self::SECRET));
    $this->assertSame(200, $response->getStatusCode());
    $data = json_decode((string) $response->getContent(), TRUE);
    $query = [];
    parse_str((string) parse_url($data['path'], PHP_URL_QUERY), $query);
    return $query;
  }

  /**
   * Signs a token grant directly (for never-minted / expired cases).
   *
   * @param \Drupal\file\FileInterface $file
   *   The file the grant is bound to.
   * @param string $token
   *   The plaintext token.
   * @param int $exp
   *   The expiry timestamp.
   *
   * @return string
   *   The HMAC signature.
   */
  private function signTokenGrant(FileInterface $file, string $token, int $exp): string {
    $resource = $this->container->get('stream_wrapper_manager')->normalizeUri($file->getFileUri());
    $claims = ['exp' => $exp, 'th' => hash('sha256', $token)];
    return $this->container->get('file_gate.grant_signer')->sign($resource, $claims);
  }

  /**
   * Redeems a download request with the given query.
   *
   * @param array $query
   *   The download URL query parameters.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The download response.
   */
  private function download(array $query) {
    return DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
  }

  /**
   * Revokes a token through the revoke controller.
   *
   * @param string $token
   *   The plaintext token to revoke.
   * @param string|null $secret
   *   The secret to present, or NULL for none.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The revoke response.
   */
  private function revoke(string $token, ?string $secret) {
    return RevokeController::create($this->container)
      ->revoke($this->postRequest('/api/file-gate/revoke', json_encode(['token' => $token]), $secret));
  }

  /**
   * Builds a POST request with an optional Basic-auth secret.
   *
   * @param string $path
   *   The request path.
   * @param string $body
   *   The JSON body.
   * @param string|null $secret
   *   The secret to present as the Basic-auth password, or NULL for none.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The request.
   */
  private function postRequest(string $path, string $body, ?string $secret): Request {
    $request = Request::create($path, 'POST', [], [], [], [], $body);
    if ($secret !== NULL) {
      $request->headers->set('Authorization', 'Basic ' . base64_encode('file-gate:' . $secret));
    }
    return $request;
  }

  /**
   * The token store.
   *
   * @return \Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface
   *   The expirable key/value store holding minted token hashes.
   */
  private function tokenStore() {
    return $this->container->get('keyvalue.expirable')->get(self::TOKEN_COLLECTION);
  }

}
