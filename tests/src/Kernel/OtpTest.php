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
use Drupal\file_gate\Controller\OtpController;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Tests the OTP (one-time passcode by email) gate method and its endpoint.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class OtpTest extends KernelTestBase {

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

  private const SECRET = 'file-gate-test-secret';
  private const EMAIL = 'requester@example.com';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installEntitySchema('entity_test');
    $this->installSchema('file', ['file_usage']);
    $this->installConfig(['field', 'file', 'file_gate', 'system']);

    $this->setSetting('file_private_path', $this->siteDirectory . '/private');
    $this->container->get('stream_wrapper_manager')
      ->registerWrapper('private', PrivateStream::class, StreamWrapperInterface::WRITE_VISIBLE);
    $this->config('file_gate.settings')->set('download_secret', self::SECRET)->save();
    // Collect mail instead of sending it.
    $this->config('system.mail')->set('interface.default', 'test_mail_collector')->save();

    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'otp')
      ->setThirdPartySetting('file_gate', 'method_settings', ['ttl' => 600, 'max_attempts' => 3, 'code_length' => 6])
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_gated',
      'bundle' => 'entity_test',
    ])->save();

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * Requesting a code stores it and emails it; the code redeems the file.
   */
  public function testRequestThenRedeem(): void {
    $file = $this->createFile('doc.pdf');
    $this->assertSame(204, $this->requestOtp($file, self::EMAIL)->getStatusCode());

    $code = $this->lastMailCode();
    $this->assertMatchesRegularExpression('/^\d{6}$/', $code);

    $response = $this->redeemWithSession($file, self::EMAIL, $code);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A code is single-use: the second session exchange is denied.
   */
  public function testCodeIsSingleUse(): void {
    $file = $this->createFile('doc.pdf');
    $this->requestOtp($file, self::EMAIL);
    $code = $this->lastMailCode();

    $this->assertSame(200, $this->redeemWithSession($file, self::EMAIL, $code)->getStatusCode());
    $this->assertSame(403, $this->establishSession($file, self::EMAIL, $code)->getStatusCode());
  }

  /**
   * A wrong code is denied at the session exchange.
   */
  public function testWrongCodeDenied(): void {
    $file = $this->createFile('doc.pdf');
    $this->requestOtp($file, self::EMAIL);

    $this->assertSame(403, $this->establishSession($file, self::EMAIL, '000000')->getStatusCode());
  }

  /**
   * Too many wrong tries lock the code out (even the correct code then fails).
   */
  public function testAttemptLockout(): void {
    $file = $this->createFile('doc.pdf');
    $this->requestOtp($file, self::EMAIL);
    $code = $this->lastMailCode();
    $wrong = $code === '111111' ? '222222' : '111111';

    // max_attempts = 3: three wrong session tries lock it out.
    for ($i = 0; $i < 3; $i++) {
      $this->assertSame(403, $this->establishSession($file, self::EMAIL, $wrong)->getStatusCode());
    }

    // The correct code no longer works — the code was locked out.
    $this->assertSame(403, $this->establishSession($file, self::EMAIL, $code)->getStatusCode());
  }

  /**
   * A session without a code, or a download without the cookie, is denied.
   */
  public function testMissingCredentialsDenied(): void {
    $file = $this->createFile('doc.pdf');
    $this->requestOtp($file, self::EMAIL);

    $this->assertSame(400, $this->establishSession($file, self::EMAIL, '')->getStatusCode());

    $this->expectException(AccessDeniedHttpException::class);
    $this->downloadBare($file);
  }

  /**
   * A valid passcode in the query string is not a credential.
   *
   * Fails if download honors ?otp= or if /otp/session falls back to the
   * query string. The code must remain unused so a body-only session still
   * redeems afterward.
   */
  public function testQueryStringOtpDenied(): void {
    $file = $this->createFile('doc.pdf');
    $this->requestOtp($file, self::EMAIL);
    $code = $this->lastMailCode();

    try {
      $this->downloadWithQueryOtp($file, self::EMAIL, $code);
      $this->fail('Query-string OTP must be denied.');
    }
    catch (AccessDeniedHttpException) {
      // Expected: grants() ignores query email/otp.
    }

    // Session POST with otp in the URL is refused even when the JSON body
    // is valid, so the passcode cannot travel in the query string.
    $request = Request::create(
      '/api/file-gate/otp/session?otp=' . rawurlencode($code),
      'POST',
      [],
      [],
      [],
      [],
      (string) json_encode([
        'file' => $file->uuid(),
        'email' => self::EMAIL,
        'otp' => $code,
      ]),
    );
    $this->assertSame(400, OtpController::create($this->container)->establishSession($request)->getStatusCode());

    // Body-only session still works: neither deny path consumed the code.
    $response = $this->redeemWithSession($file, self::EMAIL, $code);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * The send endpoint rejects a bad secret (401) and a bad email (400).
   */
  public function testEndpointGuards(): void {
    $file = $this->createFile('doc.pdf');
    $this->assertSame(401, $this->requestOtp($file, self::EMAIL, 'wrong-secret')->getStatusCode());
    $this->assertSame(400, $this->requestOtpRaw(json_encode(['file' => $file->uuid(), 'email' => 'not-an-email']))->getStatusCode());
  }

  /**
   * Repeated failed shared-secret authentication attempts are throttled.
   */
  public function testEndpointFailedAuthThrottle(): void {
    $file = $this->createFile('doc.pdf');
    for ($i = 0; $i < 10; $i++) {
      $this->assertSame(401, $this->requestOtp($file, self::EMAIL, 'wrong-secret')->getStatusCode());
    }
    $this->assertSame(429, $this->requestOtp($file, self::EMAIL, 'wrong-secret')->getStatusCode());
  }

  /**
   * The send endpoint refuses a file that is not OTP-gated (422).
   */
  public function testEndpointRefusesNonOtpFile(): void {
    // A signed_url field, not otp.
    FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_signed',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'signed_url')
      ->save();
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => 'field_signed',
      'bundle' => 'entity_test',
    ])->save();
    $file = $this->createFile('signed.pdf', 'field_signed');

    $this->assertSame(422, $this->requestOtp($file, self::EMAIL)->getStatusCode());
  }

  /**
   * The send endpoint throttles repeated requests for the same file + email.
   */
  public function testSendThrottle(): void {
    $file = $this->createFile('doc.pdf');
    // SEND_LIMIT = 3 within the window.
    for ($i = 0; $i < 3; $i++) {
      $this->assertSame(204, $this->requestOtp($file, self::EMAIL)->getStatusCode());
    }
    $this->assertSame(429, $this->requestOtp($file, self::EMAIL)->getStatusCode());
  }

  /**
   * The OTP method does not support minted URLs (mint endpoint returns 400).
   */
  public function testMintNotSupported(): void {
    $file = $this->createFile('doc.pdf');
    $request = Request::create('/api/file-gate/mint', 'POST', [], [], [], [], (string) json_encode(['file' => $file->uuid()]));
    $request->headers->set('Authorization', 'Basic ' . base64_encode('file-gate:' . self::SECRET));
    $this->assertSame(400, MintController::create($this->container)->mint($request)->getStatusCode());
  }

  /**
   * Named-secrets-only deploy: OTP issue + redeem work without legacy secret.
   */
  public function testNamedSecretOnlyOtp(): void {
    $this->config('file_gate.settings')
      ->set('download_secret', '')
      ->set('secret_scopes', ['otp_s' => ['entity_test.field_gated']])
      ->save();
    $this->setSetting('file_gate.secrets', ['otp_s' => 'named-otp-material-xyz']);

    $file = $this->createFile('named.pdf');
    $request = Request::create(
      '/api/file-gate/otp',
      'POST',
      [],
      [],
      [],
      [],
      (string) json_encode(['file' => $file->uuid(), 'email' => self::EMAIL]),
    );
    $request->headers->set('Authorization', 'Basic ' . base64_encode('otp_s:named-otp-material-xyz'));
    $this->assertSame(204, OtpController::create($this->container)->request($request)->getStatusCode());

    $code = $this->lastMailCode();
    $this->assertMatchesRegularExpression('/^\d{6}$/', $code);
    $response = $this->redeemWithSession($file, self::EMAIL, $code);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * Requests an OTP through the controller.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   * @param string $email
   *   The recipient email.
   * @param string|null $secret
   *   The secret to present (defaults to the valid one).
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  private function requestOtp(FileInterface $file, string $email, ?string $secret = self::SECRET) {
    return $this->requestOtpRaw(json_encode(['file' => $file->uuid(), 'email' => $email]), $secret);
  }

  /**
   * Requests an OTP with a raw JSON body.
   *
   * @param string $body
   *   The JSON body.
   * @param string|null $secret
   *   The secret to present.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  private function requestOtpRaw(string $body, ?string $secret = self::SECRET) {
    $request = Request::create('/api/file-gate/otp', 'POST', [], [], [], [], $body);
    if ($secret !== NULL) {
      $request->headers->set('Authorization', 'Basic ' . base64_encode('file-gate:' . $secret));
    }
    return OtpController::create($this->container)->request($request);
  }

  /**
   * Exchanges email + otp for an FG_OTP cookie (JSON body, no query).
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   * @param string $email
   *   The email.
   * @param string $code
   *   The passcode.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The session response.
   */
  private function establishSession(FileInterface $file, string $email, string $code) {
    $request = Request::create(
      '/api/file-gate/otp/session',
      'POST',
      [],
      [],
      [],
      [],
      (string) json_encode([
        'file' => $file->uuid(),
        'email' => $email,
        'otp' => $code,
      ]),
    );
    return OtpController::create($this->container)->establishSession($request);
  }

  /**
   * Redeems via POST /otp/session then GET download with the FG_OTP cookie.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   * @param string $email
   *   The email.
   * @param string $code
   *   The passcode.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The session error, or the download response after a 200 session.
   */
  private function redeemWithSession(FileInterface $file, string $email, string $code) {
    $session = $this->establishSession($file, $email, $code);
    if ($session->getStatusCode() !== 200) {
      return $session;
    }
    $cookies = [];
    foreach ($session->headers->getCookies() as $cookie) {
      $cookies[$cookie->getName()] = $cookie->getValue();
    }
    $request = Request::create('/api/file-gate/download', 'GET', [
      'f' => $file->uuid(),
    ], $cookies);
    return DownloadController::create($this->container)->download($request);
  }

  /**
   * Attempts to redeem with email and otp in the download query string.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   * @param string $email
   *   The email.
   * @param string $code
   *   The passcode.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  private function downloadWithQueryOtp(FileInterface $file, string $email, string $code) {
    $request = Request::create('/api/file-gate/download', 'GET', [
      'f' => $file->uuid(),
      'email' => $email,
      'otp' => $code,
    ]);
    return DownloadController::create($this->container)->download($request);
  }

  /**
   * Downloads with only the file UUID (no cookie, no query secrets).
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  private function downloadBare(FileInterface $file) {
    $request = Request::create('/api/file-gate/download', 'GET', [
      'f' => $file->uuid(),
    ]);
    return DownloadController::create($this->container)->download($request);
  }

  /**
   * Extracts the 6-digit code from the most recently collected email.
   *
   * @return string
   *   The code, or '' if none.
   */
  private function lastMailCode(): string {
    $mails = $this->container->get('state')->get('system.test_mail_collector', []);
    $last = end($mails);
    if ($last === FALSE) {
      return '';
    }
    $body = is_array($last['body'] ?? NULL) ? implode(' ', $last['body']) : (string) ($last['body'] ?? '');
    return preg_match('/\b(\d{6})\b/', $body, $m) ? $m[1] : '';
  }

  /**
   * Creates a private file referenced by an entity_test via a gated field.
   *
   * @param string $filename
   *   The file name.
   * @param string $field
   *   The referencing field name.
   *
   * @return \Drupal\file\FileInterface
   *   The referenced file.
   */
  private function createFile(string $filename, string $field = 'field_gated'): FileInterface {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);
    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();
    $entity = EntityTest::create(['name' => 'host', $field => ['target_id' => $file->id()]]);
    $entity->save();
    \Drupal::service('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());
    return $file;
  }

}
