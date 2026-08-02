<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate_assurance\Kernel;

use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Guards the _auth pin on open-by-design token endpoints (GH #54).
 *
 * The bridge and assertion routes carry external IdP credentials in the
 * Authorization header. Without an _auth pin, any global authentication
 * provider that consumes Authorization (simple_oauth being the common case)
 * rejects the request during authentication and the controllers never run.
 */
#[Group('file_gate')]
final class RouteAuthPinTest extends KernelTestBase {

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
  ];

  /**
   * Open-by-design routes must restrict provider authentication to cookie.
   */
  public function testOpenRoutesPinCookieAuth(): void {
    $provider = $this->container->get('router.route_provider');
    $pinned = [
      'file_gate_assurance.bridge',
      'file_gate_assurance.webauthn_assert_options',
      'file_gate_assurance.webauthn_assert',
    ];
    foreach ($pinned as $name) {
      $route = $provider->getRouteByName($name);
      $this->assertSame(['cookie'], $route->getOption('_auth'), sprintf('Route %s must pin _auth to cookie so foreign Authorization headers reach the controller.', $name));
    }
  }

}
