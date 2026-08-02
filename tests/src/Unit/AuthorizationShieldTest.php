<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Unit;

use Drupal\Tests\UnitTestCase;
use Drupal\file_gate\StackMiddleware\AuthorizationShield;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Tests the Authorization shield middleware (GH #56).
 */
#[Group('file_gate')]
final class AuthorizationShieldTest extends UnitTestCase {

  /**
   * The request as the inner kernel received it.
   */
  private ?Request $inner = NULL;

  /**
   * Builds the middleware around a capturing inner kernel.
   */
  private function shield(): AuthorizationShield {
    $kernel = $this->createMock(HttpKernelInterface::class);
    $kernel->method('handle')->willReturnCallback(function (Request $request, int $type = HttpKernelInterface::MAIN_REQUEST, bool $catch = TRUE): Response {
      $this->inner = $request;
      return new Response();
    });
    return new AuthorizationShield($kernel);
  }

  /**
   * Bearer on a File Gate token endpoint is stashed and stripped.
   */
  public function testBearerStrippedOnTokenEndpoints(): void {
    foreach (['/api/file-gate/download', '/api/file-gate/assurance/bridge'] as $path) {
      $request = Request::create($path, 'POST');
      $request->headers->set('Authorization', 'Bearer token-value');
      $this->shield()->handle($request);
      $this->assertFalse($this->inner->headers->has('Authorization'), $path);
      $this->assertSame('Bearer token-value', $this->inner->attributes->get(AuthorizationShield::ATTRIBUTE), $path);
      $this->assertSame('Bearer token-value', AuthorizationShield::authorization($this->inner), $path);
    }
  }

  /**
   * Scheme matching is case-insensitive (RFC 7235).
   */
  public function testLowercaseSchemeStripped(): void {
    $request = Request::create('/api/file-gate/download', 'GET');
    $request->headers->set('Authorization', 'bearer token-value');
    $this->shield()->handle($request);
    $this->assertFalse($this->inner->headers->has('Authorization'));
    $this->assertSame('bearer token-value', AuthorizationShield::authorization($this->inner));
  }

  /**
   * The DPoP scheme is shielded the same way.
   */
  public function testDpopStripped(): void {
    $request = Request::create('/api/file-gate/assurance/bridge', 'POST');
    $request->headers->set('Authorization', 'DPoP token-value');
    $request->headers->set('DPoP', 'proof-jwt');
    $this->shield()->handle($request);
    $this->assertFalse($this->inner->headers->has('Authorization'));
    $this->assertSame('DPoP token-value', AuthorizationShield::authorization($this->inner));
    $this->assertSame('proof-jwt', $this->inner->headers->get('DPoP'), 'The DPoP proof header must pass through untouched.');
  }

  /**
   * Basic credentials (service-secret form) pass through untouched.
   */
  public function testBasicPassesThrough(): void {
    $request = Request::create('/api/file-gate/download', 'GET');
    $request->headers->set('Authorization', 'Basic dTpw');
    $this->shield()->handle($request);
    $this->assertSame('Basic dTpw', $this->inner->headers->get('Authorization'));
    $this->assertFalse($this->inner->attributes->has(AuthorizationShield::ATTRIBUTE));
  }

  /**
   * Bearer on any other route passes through untouched — the negative proof.
   */
  public function testOtherRoutesUntouched(): void {
    foreach (['/', '/api/file-gate/mint', '/api/file-gate/webauthn/register', '/jsonapi/node/page'] as $path) {
      $request = Request::create($path, 'POST');
      $request->headers->set('Authorization', 'Bearer token-value');
      $this->shield()->handle($request);
      $this->assertSame('Bearer token-value', $this->inner->headers->get('Authorization'), $path);
      $this->assertFalse($this->inner->attributes->has(AuthorizationShield::ATTRIBUTE), $path);
    }
  }

  /**
   * The authorization() helper falls back to the live header when unstashed.
   */
  public function testAuthorizationFallsBackToHeader(): void {
    $request = Request::create('/api/file-gate/download', 'GET');
    $request->headers->set('Authorization', 'Bearer live-header');
    $this->assertSame('Bearer live-header', AuthorizationShield::authorization($request));
    $this->assertSame('', AuthorizationShield::authorization(Request::create('/x', 'GET')));
  }

}
