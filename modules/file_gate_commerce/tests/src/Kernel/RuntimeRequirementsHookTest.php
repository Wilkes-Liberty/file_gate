<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate_commerce\Kernel;

use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Pins hook_runtime_requirements discovery for File Gate Commerce.
 *
 * A procedural implementation in .install is never registered, so the
 * status report would stay silent if this hook left the OOP collector.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class RuntimeRequirementsHookTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'file',
    'file_gate',
    'file_gate_commerce',
  ];

  /**
   * The module handler reports the runtime implementation.
   */
  public function testHasImplementations(): void {
    $module_handler = $this->container->get('module_handler');
    $hook = 'runtime_requirements';
    $this->assertTrue(
      $module_handler->hasImplementations($hook, 'file_gate_commerce')
    );
    $requirements = $module_handler->invoke('file_gate_commerce', $hook);
    $this->assertIsArray($requirements);
    $this->assertArrayHasKey('file_gate_commerce_commerce', $requirements);
    $this->assertFalse(function_exists('file_gate_commerce_requirements'));
  }

}
