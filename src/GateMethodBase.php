<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\Form\FormStateInterface;
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
   * Validates this method's submitted settings-form values.
   *
   * Called from the field config edit form's validation for the selected
   * method. The default is no validation. Deliberately on the base class, not
   * GateMethodInterface, so existing third-party implementations of the
   * interface keep working unchanged; the form handler feature-detects it.
   *
   * @param array $values
   *   The submitted values from this method's fieldSettingsForm().
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state, for setting validation errors.
   */
  public function fieldSettingsValidate(array $values, FormStateInterface $form_state): void {
    // No validation by default.
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsSubmit(array $values): array {
    // By default persist the submitted values verbatim.
    return $values;
  }

}
