<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Plugin\PluginBase;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Base class for gate method plugins.
 *
 * Provides label()/description() from the plugin definition and a default
 * create() so subclasses only override what they need. Subclasses that require
 * services override create() to inject them.
 */
abstract class GateMethodBase extends PluginBase implements GateMethodInterface, ContainerFactoryPluginInterface {

  use StringTranslationTrait;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    return new static($configuration, $plugin_id, $plugin_definition);
  }

  /**
   * {@inheritdoc}
   */
  public function label(): string {
    $label = $this->pluginDefinition['label'] ?? $this->getPluginId();
    return (string) $label;
  }

  /**
   * {@inheritdoc}
   */
  public function description(): string {
    return (string) ($this->pluginDefinition['description'] ?? '');
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $settings): array {
    // Methods with no settings expose no form.
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsSubmit(array $values): array {
    // By default persist the submitted values verbatim.
    return $values;
  }

}
