<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Unit;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Tests\UnitTestCase;
use Drupal\file_gate\StackMiddleware\AuthorizationShield;
use Drupal\language\Plugin\LanguageNegotiation\LanguageNegotiationUrl;
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
   * Builds the middleware with the default path-prefix negotiation.
   *
   * Prefixes: en, es, zh-hans, and a custom english prefix.
   */
  private function shield(): AuthorizationShield {
    return $this->shieldWith([
      'source' => LanguageNegotiationUrl::CONFIG_PATH_PREFIX,
      'prefixes' => [
        'en' => 'en',
        'es' => 'es',
        'zh-hans' => 'zh-hans',
        'english' => 'english',
      ],
    ]);
  }

  /**
   * Builds the middleware around a capturing inner kernel.
   *
   * @param array<string, mixed>|null $url_negotiation
   *   language.negotiation `url` config. NULL means the config is absent.
   */
  private function shieldWith(?array $url_negotiation): AuthorizationShield {
    $kernel = $this->createMock(HttpKernelInterface::class);
    $kernel->method('handle')->willReturnCallback(function (Request $request): Response {
      $this->inner = $request;
      return new Response();
    });
    $config = $this->getMockBuilder(ImmutableConfig::class)
      ->disableOriginalConstructor()
      ->onlyMethods(['get'])
      ->getMock();
    $config->method('get')->willReturnCallback(
      function (string $key) use ($url_negotiation): mixed {
        return $key === 'url' ? $url_negotiation : NULL;
      },
    );
    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->with('language.negotiation')->willReturn($config);
    return new AuthorizationShield($kernel, $factory);
  }

  /**
   * Token-endpoint paths, including language-prefixed variants.
   *
   * @return list<string>
   *   Paths that must stash Bearer/DPoP.
   */
  private function tokenEndpointPaths(): array {
    $suffixes = [
      '/api/file-gate/download',
      '/api/file-gate/assurance/bridge',
      '/api/file-gate/mint',
    ];
    $paths = $suffixes;
    foreach (['/en', '/es', '/zh-hans'] as $prefix) {
      foreach ($suffixes as $suffix) {
        $paths[] = $prefix . $suffix;
      }
    }
    return $paths;
  }

  /**
   * Bearer on a File Gate token endpoint is stashed and stripped.
   */
  public function testBearerStrippedOnTokenEndpoints(): void {
    foreach ($this->tokenEndpointPaths() as $path) {
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
    foreach (['/api/file-gate/download', '/en/api/file-gate/mint'] as $path) {
      $request = Request::create($path, 'POST');
      $request->headers->set('Authorization', 'Basic dTpw');
      $this->shield()->handle($request);
      $this->assertSame('Basic dTpw', $this->inner->headers->get('Authorization'), $path);
      $this->assertFalse($this->inner->attributes->has(AuthorizationShield::ATTRIBUTE), $path);
    }
  }

  /**
   * Stashing mint Bearer leaves the mint secret headers on the request.
   */
  public function testMintSecretHeaderUntouchedWhenBearerStashed(): void {
    foreach (['/api/file-gate/mint', '/en/api/file-gate/mint'] as $path) {
      $request = Request::create($path, 'POST');
      $request->headers->set('Authorization', 'Bearer token-value');
      $request->headers->set('X-File-Gate-Secret', 'mint-secret');
      $request->headers->set('X-File-Gate-Secret-Id', 'named');
      $this->shield()->handle($request);
      $this->assertFalse($this->inner->headers->has('Authorization'), $path);
      $this->assertSame('Bearer token-value', AuthorizationShield::authorization($this->inner), $path);
      $this->assertSame('mint-secret', $this->inner->headers->get('X-File-Gate-Secret'), $path);
      $this->assertSame('named', $this->inner->headers->get('X-File-Gate-Secret-Id'), $path);
    }
  }

  /**
   * Bearer on any other route passes through untouched — the negative proof.
   */
  public function testOtherRoutesUntouched(): void {
    foreach ([
      '/',
      '/api/file-gate/revoke',
      '/api/file-gate/webauthn/register',
      '/en/api/file-gate/webauthn/register',
      '/jsonapi/node/page',
      // A longer prefix is not a language prefix.
      '/custom/admin/api/file-gate/mint',
      '/en/es/api/file-gate/download',
      // One segment that is not a configured prefix.
      '/custom/api/file-gate/mint',
      '/fr/api/file-gate/download',
    ] as $path) {
      $request = Request::create($path, 'POST');
      $request->headers->set('Authorization', 'Bearer token-value');
      $this->shield()->handle($request);
      $this->assertSame('Bearer token-value', $this->inner->headers->get('Authorization'), $path);
      $this->assertFalse($this->inner->attributes->has(AuthorizationShield::ATTRIBUTE), $path);
    }
  }

  /**
   * Configured path prefixes shield; other prefixes do not.
   */
  public function testOnlyConfiguredPathPrefixShields(): void {
    $bearer = 'Bearer token-value';

    $custom = Request::create('/english/api/file-gate/mint', 'POST');
    $custom->headers->set('Authorization', $bearer);
    $this->shield()->handle($custom);
    $this->assertFalse($this->inner->headers->has('Authorization'));
    $this->assertSame($bearer, AuthorizationShield::authorization($this->inner));

    $domain = Request::create('/en/api/file-gate/download', 'GET');
    $domain->headers->set('Authorization', $bearer);
    $this->shieldWith([
      'source' => LanguageNegotiationUrl::CONFIG_DOMAIN,
      'prefixes' => ['en' => 'en'],
    ])->handle($domain);
    $this->assertSame($bearer, $this->inner->headers->get('Authorization'));
    $this->assertFalse($this->inner->attributes->has(AuthorizationShield::ATTRIBUTE));

    $exact = Request::create('/api/file-gate/download', 'GET');
    $exact->headers->set('Authorization', $bearer);
    $this->shieldWith(NULL)->handle($exact);
    $this->assertFalse($this->inner->headers->has('Authorization'));
    $this->assertSame($bearer, AuthorizationShield::authorization($this->inner));

    $prefixed = Request::create('/en/api/file-gate/mint', 'POST');
    $prefixed->headers->set('Authorization', $bearer);
    $this->shieldWith(NULL)->handle($prefixed);
    $this->assertSame($bearer, $this->inner->headers->get('Authorization'));
    $this->assertFalse($this->inner->attributes->has(AuthorizationShield::ATTRIBUTE));
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
