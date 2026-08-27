<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\file_gate\Controller\GrantInventoryController;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Pins that the inventory routes honour the configured flood settings.
 *
 * Regression test for drupal.org issue 3619535: the controller read
 * mint_flood_limit / mint_flood_window — keys that do not exist in the
 * schema — so every configured value was silently ignored in favour of the
 * hard-coded 50/60 fallback. The real keys are flood_limit / flood_window,
 * shared with the mint route.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class GrantInventoryFloodConfigTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'field', 'file', 'file_gate'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['file_gate']);

    $this->config('file_gate.settings')
      ->set('download_secret', 'test-secret-material')
      ->set('flood_limit', 1)
      ->set('flood_window', 60)
      ->save();
  }

  /**
   * Builds an authenticated inventory request from a fixed client IP.
   */
  private function request(): Request {
    $request = Request::create('/api/file-gate/grants', 'GET', ['field' => 'file.field_gated']);
    $request->headers->set('X-File-Gate-Secret', 'test-secret-material');
    $request->server->set('REMOTE_ADDR', '203.0.113.7');
    return $request;
  }

  /**
   * A configured flood_limit of 1 throttles the second authenticated call.
   *
   * Before the fix this test fails: the controller consulted nonexistent
   * config keys and fell back to 50/60, so the second call was allowed.
   */
  public function testConfiguredFloodLimitIsHonoured(): void {
    $controller = GrantInventoryController::create($this->container);

    $first = $controller->list($this->request());
    $this->assertNotSame(
      Response::HTTP_TOO_MANY_REQUESTS,
      $first->getStatusCode(),
      'The first authenticated call is within the budget.',
    );

    $second = $controller->list($this->request());
    $this->assertSame(
      Response::HTTP_TOO_MANY_REQUESTS,
      $second->getStatusCode(),
      'The configured flood_limit of 1 must throttle the second call.',
    );
  }

}
