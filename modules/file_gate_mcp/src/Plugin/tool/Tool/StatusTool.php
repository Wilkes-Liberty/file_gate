<?php

declare(strict_types=1);

namespace Drupal\file_gate_mcp\Plugin\tool\Tool;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file_gate\Hook\FileGateRequirements;
use Drupal\file_gate\SecretRegistryInterface;
use Drupal\file_gate\Service\GatedFieldOverview;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reports whether the gate is real on this site.
 */
#[Tool(
  id: 'file_gate_status',
  label: new TranslatableMarkup('File Gate status'),
  description: new TranslatableMarkup('Report whether File Gate protects what its configuration claims: runtime findings, whether any signing secret is configured, named secret ids and whether each has a field scope, and every gated field with its method and storage scheme. A gated field on any scheme other than private is not protected. Returns secret ids only, never secret material.'),
  operation: ToolOperation::Read,
  input_definitions: [],
)]
final class StatusTool extends FileGateToolBase {

  /**
   * Runtime requirements.
   */
  protected FileGateRequirements $requirements;

  /**
   * Secret registry.
   */
  protected SecretRegistryInterface $secrets;

  /**
   * Gated field overview.
   */
  protected GatedFieldOverview $gatedFields;

  /**
   * Config factory.
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->requirements = $container->get(FileGateRequirements::class);
    $instance->secrets = $container->get('file_gate.secret_registry');
    $instance->gatedFields = $container->get('file_gate.gated_field_overview');
    $instance->configFactory = $container->get('config.factory');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function inputNames(): array {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $findings = [];
    foreach ($this->requirements->runtime() as $id => $requirement) {
      $severity = $requirement['severity'] ?? NULL;
      $findings[] = [
        'id' => (string) $id,
        'severity' => $severity instanceof \UnitEnum ? strtolower($severity->name) : (string) $severity,
        'title' => (string) ($requirement['title'] ?? ''),
        'value' => (string) ($requirement['value'] ?? ''),
      ];
    }
    $named = [];
    foreach ($this->secrets->namedSecretIds() as $id) {
      $named[] = [
        'id' => (string) $id,
        'has_field_scope' => !$this->secrets->isNamedSecretUnscoped((string) $id),
      ];
    }
    $fields = [];
    foreach ($this->gatedFields->fields() as $field) {
      unset($field['config_id']);
      $field['protected'] = $field['scheme'] === 'private';
      $fields[] = $field;
    }
    $config = $this->configFactory->get('file_gate.settings');
    return [
      'findings' => $findings,
      'any_secret_configured' => $this->secrets->hasAnySecret(),
      'named_secrets' => $named,
      'gated_fields' => $fields,
      'settings' => [
        'ttl' => (int) $config->get('ttl'),
        'disposition' => (string) $config->get('disposition'),
        'require_acting_account' => (bool) $config->get('require_acting_account'),
      ],
    ];
  }

}
