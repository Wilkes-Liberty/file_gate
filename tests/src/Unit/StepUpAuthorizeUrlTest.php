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
    $this->assertSame('', $b->build('data:text/html,x', ['aal3']));
    $this->assertSame('', $b->build('idp.example/auth', ['aal3']));
  }

  /**
   * A site-relative base is accepted and gets acr appended (GH #62).
   *
   * @covers ::build
   */
  public function testRelativeBaseAccepted(): void {
    $b = new StepUpAuthorizeUrl();
    $this->assertSame('/oidc/step-up?acr_values=aal3', $b->build('/oidc/step-up', ['aal3']));
    // An existing query string is preserved and merged.
    $this->assertSame(
      '/oidc/step-up?client_id=x&acr_values=aal3',
      $b->build('/oidc/step-up?client_id=x', ['aal3']),
    );
    // A relative return_to appends to a relative base like an absolute one.
    $url = $b->build('/oidc/step-up', [], '/api/file-gate/assurance/step-up?f=x', ['append_return' => TRUE]);
    $this->assertStringStartsWith('/oidc/step-up?', $url);
    $this->assertStringContainsString('return_to=%2Fapi%2Ffile-gate', $url);
    // An absolute return_to has no base host to match against — dropped.
    $url = $b->build('/oidc/step-up', [], 'https://evil.example/phish', ['append_return' => TRUE]);
    $this->assertSame('/oidc/step-up', $url);
  }

  /**
   * Network-path, backslash, and control-character bases are rejected.
   *
   * @covers ::build
   */
  public function testRejectsMalformedRelativeBases(): void {
    $b = new StepUpAuthorizeUrl();
    // Network-path reference resolves to another origin — open redirect.
    $this->assertSame('', $b->build('//evil.example', ['aal3']));
    $this->assertSame('', $b->build('//evil.example/phish', ['aal3']));
    // Backslashes (browser slash-normalization tricks) and embedded control
    // characters. (Leading/trailing whitespace and NUL are trimmed first, so
    // only embedded ones are meaningful here.)
    $this->assertSame('', $b->build('/\\evil.example', ['aal3']));
    $this->assertSame('', $b->build("/oidc/\rstep-up", ['aal3']));
    $this->assertSame('', $b->build("/oidc/step\x00-up", ['aal3']));
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
