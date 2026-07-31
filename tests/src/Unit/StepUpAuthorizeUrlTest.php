<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Unit;

use Drupal\file_gate_assurance\StepUpAuthorizeUrl;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for IdP step-up authorize URL builder (GH #42).
 *
 * @group file_gate
 * @coversDefaultClass \Drupal\file_gate_assurance\StepUpAuthorizeUrl
 */
final class StepUpAuthorizeUrlTest extends UnitTestCase {

  /**
   * @covers ::build
   */
  public function testRejectsNonHttpBase(): void {
    $b = new StepUpAuthorizeUrl();
    $this->assertSame('', $b->build('javascript:alert(1)', ['aal3']));
    $this->assertSame('', $b->build('/relative', ['aal3']));
  }

  /**
   * @covers ::build
   */
  public function testAppendsAcrValues(): void {
    $b = new StepUpAuthorizeUrl();
    $url = $b->build('https://idp.example/realms/x/protocol/openid-connect/auth', [
      'gold',
      'silver',
    ]);
    $this->assertStringContainsString('https://idp.example/', $url);
    $this->assertStringContainsString('acr_values=', $url);
    $this->assertStringContainsString('gold', $url);
  }

  /**
   * @covers ::build
   */
  public function testReturnToSameHostOnly(): void {
    $b = new StepUpAuthorizeUrl();
    $url = $b->build(
      'https://idp.example/auth',
      [],
      'https://evil.example/phish',
      ['append_return' => TRUE, 'return_param' => 'return_to'],
    );
    $this->assertStringNotContainsString('evil.example', $url);
    $url2 = $b->build(
      'https://idp.example/auth',
      [],
      '/api/file-gate/assurance/step-up?f=x',
      ['append_return' => TRUE],
    );
    $this->assertStringContainsString('return_to=', $url2);
    $this->assertStringContainsString('%2Fapi%2Ffile-gate', $url2);
  }

}
