<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\file_gate\GrantSignerInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the target-agnostic HMAC grant signer.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class GrantSignerTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'file', 'file_gate'];

  /**
   * A resource id used throughout the tests.
   */
  private const RESOURCE = 'private://2026-07/report.pdf';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['file_gate']);
  }

  /**
   * The signer under test.
   */
  private function signer(): GrantSignerInterface {
    return $this->container->get('file_gate.grant_signer');
  }

  /**
   * The current request time.
   */
  private function now(): int {
    return $this->container->get('datetime.time')->getRequestTime();
  }

  /**
   * Sets a signing secret.
   */
  private function setSecret(string $secret): void {
    $this->config('file_gate.settings')->set('download_secret', $secret)->save();
  }

  /**
   * With no secret the signer reports absence and validates nothing.
   */
  public function testFailsClosedWithoutSecret(): void {
    $signer = $this->signer();
    $this->assertFalse($signer->hasSecret());
    // Even a syntactically plausible grant must be rejected — fail closed.
    $this->assertFalse($signer->validate(self::RESOURCE, ['exp' => $this->now() + 100], str_repeat('a', 64)));
  }

  /**
   * A freshly minted grant validates.
   */
  public function testSignAndValidateRoundTrip(): void {
    $this->setSecret('s3cr3t-key');
    $signer = $this->signer();
    $this->assertTrue($signer->hasSecret());

    $claims = ['exp' => $this->now() + 300];
    $sig = $signer->sign(self::RESOURCE, $claims);
    $this->assertNotEmpty($sig);
    $this->assertTrue($signer->validate(self::RESOURCE, $claims, $sig));
  }

  /**
   * A correctly signed but expired grant is rejected.
   */
  public function testExpiredGrantIsRejected(): void {
    $this->setSecret('s3cr3t-key');
    $signer = $this->signer();
    $claims = ['exp' => $this->now() - 10];
    $sig = $signer->sign(self::RESOURCE, $claims);
    $this->assertFalse($signer->validate(self::RESOURCE, $claims, $sig));
  }

  /**
   * A grant that is not yet valid (nbf in the future) is rejected.
   */
  public function testNotBeforeGrantIsRejected(): void {
    $this->setSecret('s3cr3t-key');
    $signer = $this->signer();
    $claims = ['exp' => $this->now() + 300, 'nbf' => $this->now() + 100];
    $sig = $signer->sign(self::RESOURCE, $claims);
    $this->assertFalse($signer->validate(self::RESOURCE, $claims, $sig));
  }

  /**
   * A grant for one resource cannot validate another (URI binding).
   */
  public function testTamperedResourceIsRejected(): void {
    $this->setSecret('s3cr3t-key');
    $signer = $this->signer();
    $claims = ['exp' => $this->now() + 300];
    $sig = $signer->sign(self::RESOURCE, $claims);
    $this->assertFalse($signer->validate('private://2026-07/other.pdf', $claims, $sig));
  }

  /**
   * Tampering with the signature or any claim is rejected.
   */
  public function testTamperedGrantIsRejected(): void {
    $this->setSecret('s3cr3t-key');
    $signer = $this->signer();
    $claims = ['exp' => $this->now() + 300, 'max' => 1, 'jti' => 'abc123'];
    $sig = $signer->sign(self::RESOURCE, $claims);

    // Mangled signature.
    $this->assertFalse($signer->validate(self::RESOURCE, $claims, $sig . 'ff'));
    // Raising the usage cap invalidates the signature.
    $this->assertFalse($signer->validate(self::RESOURCE, ['exp' => $claims['exp'], 'max' => 99, 'jti' => 'abc123'], $sig));
    // Extending the expiry invalidates the signature.
    $this->assertFalse($signer->validate(self::RESOURCE, ['exp' => $claims['exp'] + 1, 'max' => 1, 'jti' => 'abc123'], $sig));
  }

  /**
   * A claim cannot be dropped by folding it into an adjacent claim value.
   *
   * Regression test for the canonicalisation-injection bypass: because the
   * canonical form rawurlencode()s every key and value, a value containing a
   * literal "&"/"=" can no longer impersonate a claim delimiter. An attacker
   * who holds a URL minted with {jti, max} cannot rebuild it as
   * {jti: "abc&max=1"} to drop "max" (defeating a one-time link), nor fold the
   * assurance "sh" claim away — the reshaped payload no longer matches the
   * signature.
   */
  public function testClaimFoldingIsRejected(): void {
    $this->setSecret('s3cr3t-key');
    $signer = $this->signer();
    $exp = $this->now() + 300;

    // A legitimately minted one-time grant.
    $sig = $signer->sign(self::RESOURCE, ['exp' => $exp, 'jti' => 'abc123', 'max' => 1]);
    // The attack: fold "&max=1" into jti and omit the real "max" claim. Under a
    // naive "key=value" join this collided with the original; encoding rejects
    // it, so the dropped usage cap can never be bypassed.
    $this->assertFalse($signer->validate(self::RESOURCE, ['exp' => $exp, 'jti' => 'abc123&max=1'], $sig));

    // The same shape against a bound subject hash (assurance per-user binding).
    $sig = $signer->sign(self::RESOURCE, ['aal' => 3, 'exp' => $exp, 'sh' => 'victimhash']);
    $this->assertFalse($signer->validate(self::RESOURCE, ['aal' => 3, 'exp' => $exp . '&sh=victimhash'], $sig));
  }

  /**
   * Sign() refuses when no secret is configured.
   */
  public function testSignThrowsWithoutSecret(): void {
    $this->expectException(\LogicException::class);
    $this->signer()->sign(self::RESOURCE, ['exp' => $this->now() + 100]);
  }

  /**
   * Sign() refuses a grant with no expiry claim.
   */
  public function testSignThrowsWithoutExpiry(): void {
    $this->setSecret('s3cr3t-key');
    $this->expectException(\LogicException::class);
    $this->signer()->sign(self::RESOURCE, ['max' => 1]);
  }

}
