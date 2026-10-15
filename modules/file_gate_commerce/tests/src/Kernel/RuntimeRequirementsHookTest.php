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
   * The module handler reports the runtime (or D10 legacy) implementation.
   */
  public function testHasImplementations(): void {
    $module_handler = $this->container->get('module_handler');
    $legacy = version_compare(\Drupal::VERSION, '11.2', '<');
    if ($legacy) {
      $module_handler->loadInclude('file_gate_commerce', 'install');
    }
    $hook = $legacy ? 'requirements' : 'runtime_requirements';
    $this->assertTrue($module_handler->hasImplementations($hook, 'file_gate_commerce'));
    $requirements = $module_handler->invoke('file_gate_commerce', $hook, $legacy ? ['runtime'] : []);
    $this->assertIsArray($requirements);
    if (!$legacy) {
      $this->assertArrayHasKey('file_gate_commerce_commerce', $requirements);
    }
  }

  /**
   * The legacy bridge is silent on modern core and outside runtime.
   */
  public function testLegacyBridgeDoesNotDuplicateRuntimeFindings(): void {
    $this->container->get('module_handler')->loadInclude('file_gate_commerce', 'install');
    $this->assertTrue(function_exists('file_gate_commerce_requirements'));
    $this->assertFalse(function_exists('file_gate_commerce_runtime_requirements'));
    $this->assertSame([], file_gate_commerce_requirements('install'));
    if (version_compare(\Drupal::VERSION, '11.2', '>=')) {
      $this->assertSame([], file_gate_commerce_requirements('runtime'));
      $this->assertTrue($this->container->get('module_handler')->hasImplementations('runtime_requirements', 'file_gate_commerce'));
    }
  }

}
