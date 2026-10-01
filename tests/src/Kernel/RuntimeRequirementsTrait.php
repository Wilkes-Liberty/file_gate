<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

/**
 * Exercises the runtime hook the installed core uses for its status report.
 */
trait RuntimeRequirementsTrait {

  /**
   * Reads requirements through the module handler, asserting hook discovery.
   *
   * @return array<string, array<string, mixed>>
   *   Runtime findings keyed by requirement ID.
   */
  private function runtimeRequirements(): array {
    $module_handler = $this->container->get('module_handler');
    $legacy = version_compare(\Drupal::VERSION, '11.2', '<');
    if ($legacy) {
      $module_handler->loadInclude('file_gate', 'install');
    }
    $hook = $legacy ? 'requirements' : 'runtime_requirements';
    $this->assertTrue($module_handler->hasImplementations($hook, 'file_gate'));
    $requirements = $module_handler->invoke('file_gate', $hook, $legacy ? ['runtime'] : []);
    $this->assertIsArray($requirements);
    return $requirements;
  }

}
