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
   * Requesting a code stores it and e-mails it; the code redeems the file.
   */
  public function testRequestThenRedeem(): void {
    $file = $this->createFile('doc.pdf');
    $this->assertSame(204, $this->requestOtp($file, self::EMAIL)->getStatusCode());

    $code = $this->lastMailCode();
    $this->assertMatchesRegularExpression('/^\d{6}$/', $code);

    $response = $this->download($file, self::EMAIL, $code);
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * A code is single-use: the second redemption is denied.
   */
  public function testCodeIsSingleUse(): void {
    $file = $this->createFile('doc.pdf');
    $this->requestOtp($file, self::EMAIL);
    $code = $this->lastMailCode();

    $this->assertSame(200, $this->download($file, self::EMAIL, $code)->getStatusCode());

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($file, self::EMAIL, $code);
  }

  /**
   * A wrong code is denied.
   */
  public function testWrongCodeDenied(): void {
    $file = $this->createFile('doc.pdf');
    $this->requestOtp($file, self::EMAIL);

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($file, self::EMAIL, '000000');
  }

  /**
   * Too many wrong tries lock the code out (even the correct code then fails).
   */
  public function testAttemptLockout(): void {
    $file = $this->createFile('doc.pdf');
    $this->requestOtp($file, self::EMAIL);
    $code = $this->lastMailCode();
    $wrong = $code === '111111' ? '222222' : '111111';

    // max_attempts = 3: three wrong tries lock it out.
    for ($i = 0; $i < 3; $i++) {
      try {
        $this->download($file, self::EMAIL, $wrong);
        $this->fail('Expected the wrong code to be denied.');
      }
      catch (AccessDeniedHttpException) {
        // Expected.
      }
    }

    // The correct code no longer works — the code was locked out.
    $this->expectException(AccessDeniedHttpException::class);
    $this->download($file, self::EMAIL, $code);
  }

  /**
   * A request with no email or no code is denied at redemption.
   */
  public function testMissingCredentialsDenied(): void {
    $file = $this->createFile('doc.pdf');
    $this->requestOtp($file, self::EMAIL);

    $this->expectException(AccessDeniedHttpException::class);
    $this->download($file, self::EMAIL, '');
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
    $request->headers->set('Authorization', 'Basic ' . base64_encode('x:' . self::SECRET));
    $this->assertSame(400, MintController::create($this->container)->mint($request)->getStatusCode());
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
   * Redeems the download with an email and code.
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
  private function download(FileInterface $file, string $email, string $code) {
    $request = Request::create('/api/file-gate/download', 'GET', [
      'f' => $file->uuid(),
      'email' => $email,
      'otp' => $code,
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
