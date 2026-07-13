<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Plugin\DefaultPluginManager;
use Drupal\file_gate\Attribute\GateMethod;

/**
 * Plugin manager for gate methods.
 *
 * Discovers Plugin/GateMethod/* classes carrying the #[GateMethod] attribute.
 */
final class GateMethodManager extends DefaultPluginManager {

  /**
   * Constructs the gate method plugin manager.
   *
   * @param \Traversable $namespaces
   *   An object that implements \Traversable which contains the root paths
   *   keyed by the corresponding namespace to look for plugin implementations.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache_backend
   *   Cache backend instance to use.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler.
   */
  public function __construct(\Traversable $namespaces, CacheBackendInterface $cache_backend, ModuleHandlerInterface $module_handler) {
    parent::__construct(
      'Plugin/GateMethod',
      $namespaces,
      $module_handler,
      GateMethodInterface::class,
      GateMethod::class,
    );
    $this->alterInfo('file_gate_gate_method_info');
    $this->setCacheBackend($cache_backend, 'file_gate_gate_method_plugins');
  }

}
