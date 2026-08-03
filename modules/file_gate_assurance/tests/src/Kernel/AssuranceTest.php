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
use Drupal\file_gate\StackMiddleware\AuthorizationShield;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Drupal\file_gate_assurance\Controller\BridgeController;
use Drupal\file_gate_assurance\SessionBridge;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Tests the assurance gate method (OIDC verification + DPoP), IdP-agnostic.
 *
 * A throwaway IdP RSA key signs the tokens and its JWKS is seeded into the
 * verifier's cache, so no network is touched. Client DPoP proofs are signed by
 * an ephemeral EC key.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class AssuranceTest extends KernelTestBase {

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

  private const SECRET = 'file-gate-test-secret';
  private const ISSUER = 'https://idp.example.test';
  private const AUDIENCE = 'file-gate-api';
  private const ACR = 'aal3';
  private const HTU = 'http://localhost/api/file-gate/download';

  /**
   * The IdP's RSA private key (PEM) used to sign test tokens.
   */
  private string $idpKey;

  /**
   * The current field method settings (mirrored onto the gated field).
   */
  private array $settings;

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

    $this->seedIdp();

    $this->settings = [
      'verify_at' => 'redeem',
      'aal' => 3,
      'issuer' => self::ISSUER,
      'audience' => self::AUDIENCE,
      'required_acr' => [self::ACR],
    ];
    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'assurance')
      ->setThirdPartySetting('file_gate', 'method_settings', $this->settings)
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * A valid, sufficiently-assured token is served (Model B, no DPoP).
   */
  public function testValidTokenGrants(): void {
    $file = $this->createFile('doc.pdf');
    $response = $this->download($this->mintQuery($file), $this->bearer($this->idpToken()));

    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A plain GET with no token is challenged (redirect to step-up), not 403.
   */
  public function testMissingTokenChallengesStepUp(): void {
    $file = $this->createFile('doc.pdf');
    $response = $this->download($this->mintQuery($file));
    $this->assertSame(302, $response->getStatusCode());
    $this->assertStringContainsString('/api/file-gate/assurance/step-up', (string) $response->headers->get('Location'));
  }

  /**
   * JSON clients get a 401 challenge with WWW-Authenticate (RFC 9470-style).
   */
  public function testMissingTokenJsonChallenge(): void {
    $file = $this->createFile('doc.pdf');
    $response = $this->download($this->mintQuery($file), [
      'Accept' => 'application/json',
    ]);
    $this->assertSame(401, $response->getStatusCode());
    $this->assertStringContainsString('insufficient_user_authentication', (string) $response->headers->get('WWW-Authenticate'));
    $data = json_decode((string) $response->getContent(), TRUE);
    $this->assertSame('insufficient_user_authentication', $data['error'] ?? NULL);
    $this->assertNotEmpty($data['bridge'] ?? NULL);
  }

  /**
   * Bridge POST then plain GET with cookie streams the file.
   */
  public function testSessionBridgePlainLinkPrimary(): void {
    $file = $this->createFile('bridge.pdf');
    $query = $this->mintQuery($file);
    $token = $this->idpToken();

    $bridge_request = Request::create('/api/file-gate/assurance/bridge?' . http_build_query($query), 'POST');
    $bridge_request->headers->set('Authorization', 'Bearer ' . $token);
    $bridge_request->headers->set('Accept', 'application/json');
    $bridge_response = BridgeController::create($this->container)->establish($bridge_request);
    $this->assertSame(200, $bridge_response->getStatusCode(), (string) $bridge_response->getContent());
    $cookies = $bridge_response->headers->getCookies();
    $this->assertNotEmpty($cookies);
    $bridge_cookie = $cookies[0];
    $this->assertSame(SessionBridge::COOKIE_NAME, $bridge_cookie->getName());

    // Plain download with only the bridge cookie (no Authorization).
    $download_request = Request::create('/api/file-gate/download', 'GET', $query);
    $download_request->cookies->set($bridge_cookie->getName(), $bridge_cookie->getValue());
    $response = DownloadController::create($this->container)->download($download_request);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A token stashed by the Authorization shield redeems like the header.
   *
   * On stacks with a global authentication provider (simple_oauth) the shield
   * middleware removes the Authorization header pre-routing and stashes it in
   * a request attribute (GH #56). Both the bridge and the direct download must
   * honor the stash exactly as they would the live header.
   */
  public function testShieldedAuthorizationRedeems(): void {
    $file = $this->createFile('shielded.pdf');
    $query = $this->mintQuery($file);
    $token = $this->idpToken();

    // Bridge POST with the stashed attribute and NO Authorization header.
    $bridge_request = Request::create('/api/file-gate/assurance/bridge?' . http_build_query($query), 'POST');
    $bridge_request->attributes->set(AuthorizationShield::ATTRIBUTE, 'Bearer ' . $token);
    $bridge_request->headers->set('Accept', 'application/json');
    $bridge_response = BridgeController::create($this->container)->establish($bridge_request);
    $this->assertSame(200, $bridge_response->getStatusCode(), (string) $bridge_response->getContent());
    $this->assertNotEmpty($bridge_response->headers->getCookies());

    // Direct Bearer download through the stash as well.
    $download_request = Request::create('/api/file-gate/download', 'GET', $this->mintQuery($this->createFile('shielded2.pdf')));
    $download_request->attributes->set(AuthorizationShield::ATTRIBUTE, 'Bearer ' . $this->idpToken());
    $response = DownloadController::create($this->container)->download($download_request);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A token whose acr is below the field's requirement is denied.
   */
  public function testInsufficientAcrDenied(): void {
    $file = $this->createFile('doc.pdf');
    $token = $this->idpToken(['acr' => 'aal2']);
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $this->bearer($token));
  }

  /**
   * A token minted for another audience is denied.
   */
  public function testWrongAudienceDenied(): void {
    $file = $this->createFile('doc.pdf');
    $token = $this->idpToken(['aud' => 'some-other-client']);
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $this->bearer($token));
  }

  /**
   * A token from another issuer is denied.
   */
  public function testWrongIssuerDenied(): void {
    $file = $this->createFile('doc.pdf');
    $token = $this->idpToken(['iss' => 'https://evil.example.test']);
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $this->bearer($token));
  }

  /**
   * An expired token is denied.
   */
  public function testExpiredTokenDenied(): void {
    $file = $this->createFile('doc.pdf');
    $now = $this->container->get('datetime.time')->getRequestTime();
    $token = $this->idpToken(['iat' => $now - 1000, 'nbf' => $now - 1000, 'exp' => $now - 500]);
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $this->bearer($token));
  }

  /**
   * A token signed by a key the IdP never published is denied.
   */
  public function testForeignSignatureDenied(): void {
    $file = $this->createFile('doc.pdf');
    $forged = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($forged, $pem);
    $now = $this->container->get('datetime.time')->getRequestTime();
    $token = JWT::encode([
      'iss' => self::ISSUER,
      'aud' => self::AUDIENCE,
      'sub' => 'user-123',
      'acr' => self::ACR,
      'iat' => $now,
      'exp' => $now + 300,
    ], $pem, 'RS256', 'test-1');
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $this->bearer($token));
  }

  /**
   * Tampering with the bound aal query parameter breaks the signature.
   */
  public function testTamperedAalDenied(): void {
    $file = $this->createFile('doc.pdf');
    $query = $this->mintQuery($file);
    $query['aal'] = 1;
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query, $this->bearer($this->idpToken()));
  }

  /**
   * An advisory amr requirement is enforced when configured.
   */
  public function testRequiredAmrEnforced(): void {
    $this->configure(['required_amr' => ['hwk']]);
    $file = $this->createFile('doc.pdf');
    // Token carries amr=[sc] only, so the hwk requirement is unmet.
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $this->bearer($this->idpToken()));
  }

  /**
   * Model A (verify_at=mint) trusts the caller: no token needed.
   */
  public function testAssertedModeNeedsNoToken(): void {
    $this->configure(['verify_at' => 'mint']);
    $file = $this->createFile('doc.pdf');
    $response = $this->download($this->mintQuery($file));
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * DPoP: a proof-bound token from the proving key is served.
   */
  public function testDpopBoundTokenGrants(): void {
    $this->configure(['dpop' => TRUE]);
    $client = $this->clientKey();
    $file = $this->createFile('doc.pdf');
    $token = $this->idpToken(['cnf' => ['jkt' => $client['jkt']]]);

    $headers = [
      'Authorization' => 'DPoP ' . $token,
      'DPoP' => $this->dpopProof($client, $token),
    ];
    $response = $this->download($this->mintQuery($file), $headers);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * DPoP: a proof whose ath does not match the presented token is denied.
   */
  public function testDpopWrongAthDenied(): void {
    $this->configure(['dpop' => TRUE]);
    $client = $this->clientKey();
    $file = $this->createFile('doc.pdf');
    $token = $this->idpToken(['cnf' => ['jkt' => $client['jkt']]]);
    $headers = [
      'Authorization' => 'DPoP ' . $token,
      // A proof bound to a different token's hash must not be accepted.
      'DPoP' => $this->dpopProof($client, $token, ['ath' => 'not-the-right-hash']),
    ];
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $headers);
  }

  /**
   * DPoP required but no proof presented: denied.
   */
  public function testDpopMissingProofDenied(): void {
    $this->configure(['dpop' => TRUE]);
    $client = $this->clientKey();
    $file = $this->createFile('doc.pdf');
    $token = $this->idpToken(['cnf' => ['jkt' => $client['jkt']]]);
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $this->bearer($token));
  }

  /**
   * DPoP: a proof from a different key than the token is bound to is denied.
   */
  public function testDpopThumbprintMismatchDenied(): void {
    $this->configure(['dpop' => TRUE]);
    $bound = $this->clientKey();
    $attacker = $this->clientKey();
    $file = $this->createFile('doc.pdf');
    // Token is bound to $bound, but the proof is signed by $attacker.
    $token = $this->idpToken(['cnf' => ['jkt' => $bound['jkt']]]);
    $headers = [
      'Authorization' => 'DPoP ' . $token,
      'DPoP' => $this->dpopProof($attacker, $token),
    ];
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $headers);
  }

  /**
   * DPoP: a proof bound to a different URL is denied.
   */
  public function testDpopWrongHtuDenied(): void {
    $this->configure(['dpop' => TRUE]);
    $client = $this->clientKey();
    $file = $this->createFile('doc.pdf');
    $token = $this->idpToken(['cnf' => ['jkt' => $client['jkt']]]);
    $headers = [
      'Authorization' => 'DPoP ' . $token,
      'DPoP' => $this->dpopProof($client, $token, ['htu' => 'https://elsewhere.example/x']),
    ];
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $headers);
  }

  /**
   * DPoP: replaying the same proof (same jti) is denied the second time.
   */
  public function testDpopReplayDenied(): void {
    $this->configure(['dpop' => TRUE]);
    $client = $this->clientKey();
    $file = $this->createFile('doc.pdf');
    $token = $this->idpToken(['cnf' => ['jkt' => $client['jkt']]]);
    $proof = $this->dpopProof($client, $token);
    $headers = ['Authorization' => 'DPoP ' . $token, 'DPoP' => $proof];

    $this->assertSame(200, $this->download($this->mintQuery($file), $headers)->getStatusCode());
    // Same proof again → replay.
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $headers);
  }

  /**
   * The assurance settings form builds and round-trips its values.
   */
  public function testAssuranceSettingsForm(): void {
    $method = $this->container->get('plugin.manager.file_gate.gate_method')
      ->createInstance('assurance', []);

    $form = $method->fieldSettingsForm(['verify_at' => 'redeem']);
    $this->assertArrayHasKey('verify_at', $form);
    $this->assertArrayHasKey('issuer', $form);
    $this->assertArrayHasKey('dpop', $form);
    // Inherited from signed_url.
    $this->assertArrayHasKey('ttl', $form);

    $settings = $method->fieldSettingsSubmit([
      'ttl' => '0',
      'available_until' => '0',
      'max_uses' => '0',
      'verify_at' => 'client_cert',
      'aal' => '3',
      'issuer' => ' https://idp.example ',
      'audience' => 'file-gate',
      'required_acr' => "aal3\naal2",
      'dpop' => 1,
      'introspect' => 0,
      'leeway' => '30',
      'trusted_proxy_header' => 'X-Client-Cert-Dn',
      'allowed_subjects' => 'CN=Jane Doe',
    ]);
    $this->assertSame('client_cert', $settings['verify_at']);
    $this->assertSame(3, $settings['aal']);
    $this->assertSame('https://idp.example', $settings['issuer']);
    $this->assertSame(['aal3', 'aal2'], $settings['required_acr']);
    $this->assertTrue($settings['dpop']);
    $this->assertFalse($settings['introspect']);
    $this->assertSame(30, $settings['leeway']);
    $this->assertSame(['CN=Jane Doe'], $settings['allowed_subjects']);
  }

  /**
   * A caller-asserted subject binds the grant to that user (per-user binding).
   */
  public function testSubjectBindingEnforced(): void {
    $file = $this->createFile('doc.pdf');
    $query = $this->mintViaController($file, 'user-123');
    $this->assertArrayHasKey('sh', $query);

    // The matching subject is served.
    $ok = $this->download($query, $this->bearer($this->idpToken(['sub' => 'user-123'])));
    $this->assertSame(200, $ok->getStatusCode());

    // A different (but otherwise valid, sufficiently-assured) user is denied.
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($query, $this->bearer($this->idpToken(['sub' => 'someone-else'])));
  }

  /**
   * Edge mTLS: a validated client-cert identity on the allowlist grants.
   */
  public function testClientCertModeGrants(): void {
    $this->configure([
      'verify_at' => 'client_cert',
      'trusted_proxy_header' => 'X-Client-Cert-Dn',
      'allowed_subjects' => ['CN=Jane Doe,OU=Agency'],
    ]);
    $file = $this->createFile('doc.pdf');
    $query = $this->mintQuery($file);

    $ok = $this->download($query, ['X-Client-Cert-Dn' => 'CN=Jane Doe,OU=Agency']);
    $this->assertSame(200, $ok->getStatusCode());
  }

  /**
   * Edge mTLS: no client-cert header is denied.
   */
  public function testClientCertModeMissingHeaderDenied(): void {
    $this->configure([
      'verify_at' => 'client_cert',
      'trusted_proxy_header' => 'X-Client-Cert-Dn',
      'allowed_subjects' => ['CN=Jane Doe,OU=Agency'],
    ]);
    $file = $this->createFile('doc.pdf');
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file));
  }

  /**
   * Edge mTLS fails closed without a subject allowlist.
   *
   * The trusted header is spoofable off-proxy, so "accept any validated
   * subject" is refused: an empty allowlist denies even a well-formed value.
   */
  public function testClientCertModeNoAllowlistDenied(): void {
    $this->configure(['verify_at' => 'client_cert', 'trusted_proxy_header' => 'X-Client-Cert-Dn']);
    $file = $this->createFile('doc.pdf');
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), ['X-Client-Cert-Dn' => 'CN=Jane Doe,OU=Agency']);
  }

  /**
   * Edge mTLS: a subject outside the allowlist is denied.
   */
  public function testClientCertModeSubjectNotAllowedDenied(): void {
    $this->configure([
      'verify_at' => 'client_cert',
      'trusted_proxy_header' => 'X-Client-Cert-Dn',
      'allowed_subjects' => ['CN=Jane Doe,OU=Agency'],
    ]);
    $file = $this->createFile('doc.pdf');
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), ['X-Client-Cert-Dn' => 'CN=Bob Roe,OU=Agency']);
  }

  /**
   * Introspection: an active token is served.
   */
  public function testIntrospectionActiveGrants(): void {
    $this->mockHttpClient([new GuzzleResponse(200, [], (string) json_encode(['active' => TRUE]))]);
    $this->configure([
      'introspect' => TRUE,
      'introspection_endpoint' => 'https://idp.example.test/introspect',
    ]);
    $file = $this->createFile('doc.pdf');
    $response = $this->download($this->mintQuery($file), $this->bearer($this->idpToken()));
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * Introspection: a token the IdP reports inactive (revoked) is denied.
   */
  public function testIntrospectionRevokedDenied(): void {
    $this->mockHttpClient([new GuzzleResponse(200, [], (string) json_encode(['active' => FALSE]))]);
    $this->configure([
      'introspect' => TRUE,
      'introspection_endpoint' => 'https://idp.example.test/introspect',
    ]);
    $file = $this->createFile('doc.pdf');
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($this->mintQuery($file), $this->bearer($this->idpToken()));
  }

  /**
   * Replaces the http_client service with a Guzzle mock (queued responses).
   *
   * Must run before the verifier is first instantiated. JWKS comes from the
   * seeded cache, so the queue only needs the introspection response(s).
   *
   * @param array $responses
   *   The queued Guzzle responses.
   */
  private function mockHttpClient(array $responses): void {
    $handler = HandlerStack::create(new MockHandler($responses));
    $this->container->set('http_client', new Client(['handler' => $handler]));
  }

  /**
   * Mints through the mint controller, optionally asserting a subject.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   * @param string|null $subject
   *   A caller-asserted subject to bind, or NULL.
   *
   * @return array
   *   The download URL query.
   */
  private function mintViaController(FileInterface $file, ?string $subject = NULL): array {
    $body = ['file' => $file->uuid()];
    if ($subject !== NULL) {
      $body['subject'] = $subject;
    }
    $request = Request::create('/api/file-gate/mint', 'POST', [], [], [], [], (string) json_encode($body));
    $request->headers->set('Authorization', 'Basic ' . base64_encode('file-gate:' . self::SECRET));
    $response = MintController::create($this->container)->mint($request);
    $this->assertSame(200, $response->getStatusCode());
    $data = json_decode((string) $response->getContent(), TRUE);
    $query = [];
    parse_str((string) parse_url($data['path'], PHP_URL_QUERY), $query);
    return $query;
  }

  /**
   * Generates the IdP RSA key and seeds its JWKS into the verifier cache.
   */
  private function seedIdp(): void {
    $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($res, $pem);
    $this->idpKey = $pem;
    $details = openssl_pkey_get_details($res);
    $jwks = [
      'keys' => [
        [
          'kty' => 'RSA',
          'kid' => 'test-1',
          'alg' => 'RS256',
          'use' => 'sig',
          'n' => $this->b64u($details['rsa']['n']),
          'e' => $this->b64u($details['rsa']['e']),
        ],
      ],
    ];
    $this->container->get('cache.default')
      ->set('file_gate_assurance:jwks:' . hash('sha256', self::ISSUER), $jwks);
  }

  /**
   * Merges settings onto the gated field (and the local mint settings).
   *
   * @param array $overrides
   *   Method settings to add/override.
   */
  private function configure(array $overrides): void {
    $this->settings = array_merge($this->settings, $overrides);
    FieldStorageConfig::loadByName('entity_test', 'field_gated')
      ->setThirdPartySetting('file_gate', 'method_settings', $this->settings)
      ->save();
  }

  /**
   * Mints a grant with the current settings and returns the URL query.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return array
   *   The download URL query (f, exp, aal, sig, …).
   */
  private function mintQuery(FileInterface $file): array {
    $params = $this->container->get('plugin.manager.file_gate.gate_method')
      ->createInstance('assurance', $this->settings)
      ->mint($file);
    return ['f' => $file->uuid()] + $params;
  }

  /**
   * Builds a signed IdP token with the given claim overrides.
   *
   * @param array $overrides
   *   Claims to override on the default token.
   *
   * @return string
   *   The encoded JWT.
   */
  private function idpToken(array $overrides = []): string {
    $now = $this->container->get('datetime.time')->getRequestTime();
    $payload = array_merge([
      'iss' => self::ISSUER,
      'aud' => self::AUDIENCE,
      'sub' => 'user-123',
      'acr' => self::ACR,
      'amr' => ['sc'],
      'iat' => $now,
      'nbf' => $now,
      'exp' => $now + 300,
    ], $overrides);
    return JWT::encode($payload, $this->idpKey, 'RS256', 'test-1');
  }

  /**
   * A "Bearer" Authorization header array for a token.
   *
   * @param string $token
   *   The token.
   *
   * @return array
   *   The headers.
   */
  private function bearer(string $token): array {
    return ['Authorization' => 'Bearer ' . $token];
  }

  /**
   * Generates an ephemeral EC client key with its JWK and RFC 7638 thumbprint.
   *
   * @return array
   *   ['pem' => string, 'jwk' => array, 'jkt' => string].
   */
  private function clientKey(): array {
    $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_pkey_export($res, $pem);
    $details = openssl_pkey_get_details($res);
    $jwk = [
      'crv' => 'P-256',
      'kty' => 'EC',
      'x' => $this->b64u($details['ec']['x']),
      'y' => $this->b64u($details['ec']['y']),
    ];
    $canonical = ['crv' => $jwk['crv'], 'kty' => 'EC', 'x' => $jwk['x'], 'y' => $jwk['y']];
    $jkt = $this->b64u(hash('sha256', (string) json_encode($canonical, JSON_UNESCAPED_SLASHES), TRUE));
    return ['pem' => $pem, 'jwk' => $jwk, 'jkt' => $jkt];
  }

  /**
   * Builds a DPoP proof JWT for a client key, bound to an access token.
   *
   * @param array $client
   *   The client key from clientKey().
   * @param string $access_token
   *   The access token the proof accompanies; its base64url SHA-256 is bound
   *   into the proof as the `ath` claim (RFC 9449 §4.3).
   * @param array $overrides
   *   Claim overrides (e.g. a wrong htu or a wrong ath).
   *
   * @return string
   *   The encoded proof.
   */
  private function dpopProof(array $client, string $access_token, array $overrides = []): string {
    $now = $this->container->get('datetime.time')->getRequestTime();
    $ath = rtrim(strtr(base64_encode(hash('sha256', $access_token, TRUE)), '+/', '-_'), '=');
    $claims = array_merge([
      'htu' => self::HTU,
      'htm' => 'GET',
      'iat' => $now,
      'jti' => bin2hex(random_bytes(8)),
      'ath' => $ath,
    ], $overrides);
    return JWT::encode($claims, $client['pem'], 'ES256', NULL, [
      'typ' => 'dpop+jwt',
      'jwk' => $client['jwk'],
    ]);
  }

  /**
   * Redeems a download request with the given query and headers.
   *
   * @param array $query
   *   The URL query.
   * @param array $headers
   *   Request headers.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  private function download(array $query, array $headers = []) {
    $request = Request::create('/api/file-gate/download', 'GET', $query);
    foreach ($headers as $name => $value) {
      $request->headers->set($name, $value);
    }
    return DownloadController::create($this->container)->download($request);
  }

  /**
   * Query login_url is ignored; only field step_up_login_url is trusted.
   */
  public function testStepUpIgnoresQueryLoginUrl(): void {
    $this->configure(['step_up_login_url' => 'https://idp.example.test/login']);
    $file = $this->createFile('stepup.pdf');
    $query = $this->mintViaController($file);
    // Attacker-controlled query param must not become the redirect target.
    $query['login_url'] = 'https://evil.example/phish';
    $request = Request::create('/api/file-gate/assurance/step-up', 'GET', $query);
    $response = BridgeController::create($this->container)->stepUpPage($request);
    $html = (string) $response->getContent();
    $this->assertStringNotContainsString('evil.example', $html);
    // loginUrl is json_encode'd into the page (slashes may be escaped).
    $this->assertStringContainsString('idp.example.test', $html);
    $this->assertMatchesRegularExpression('#loginUrl\s*=\s*"[^"]*idp\.example\.test[^"]*"#', $html);
  }

  /**
   * The step-up page gates stored token shapes before building headers.
   *
   * A malformed sessionStorage value (non-Latin-1 characters being the worst
   * case) used to reach the Authorization header build, where fetch throws a
   * cryptic TypeError (GH #53). The page must ship the compact-JWS shape
   * guard for both the Bearer token and the DPoP proof, surface an actionable
   * message, and keep raw exception detail out of the UI.
   */
  public function testStepUpPageValidatesTokenShape(): void {
    $file = $this->createFile('stepup-shape.pdf');
    $query = $this->mintViaController($file);
    $request = Request::create('/api/file-gate/assurance/step-up', 'GET', $query);
    $response = BridgeController::create($this->container)->stepUpPage($request);
    $html = (string) $response->getContent();
    // The compact-JWS shape regex and its application to the stored token.
    $this->assertStringContainsString('const JWS_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;', $html);
    $this->assertStringContainsString('if (t && !JWS_RE.test(t))', $html);
    $this->assertStringContainsString('The stored access token is not a valid compact JWS (expected xxxxx.yyyyy.zzzzz). Sign in again, or clear sessionStorage.file_gate_access_token and retry.', $html);
    // The DPoP proof goes through the same gate.
    $this->assertStringContainsString('!JWS_RE.test(window.fileGateDpopProof)', $html);
    $this->assertStringContainsString('The provided DPoP proof is not a valid compact JWS', $html);
    // Raw exception detail goes to the console, not the page.
    $this->assertStringContainsString('Step-up failed — see the browser console for details.', $html);
    $this->assertStringNotContainsString('e && e.message ? e.message : String(e)', $html);
  }

  /**
   * Creates a private file referenced by an entity_test via the gated field.
   *
   * @param string $filename
   *   The file name.
   *
   * @return \Drupal\file\FileInterface
   *   The referenced file.
   */
  private function createFile(string $filename): FileInterface {
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
   * Base64url-encodes raw bytes without padding.
   *
   * @param string $data
   *   The bytes.
   *
   * @return string
   *   The base64url string.
   */
  private function b64u(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

}
