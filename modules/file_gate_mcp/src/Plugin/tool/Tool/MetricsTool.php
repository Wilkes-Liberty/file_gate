<?php

declare(strict_types=1);

namespace Drupal\file_gate_mcp\Plugin\tool\Tool;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file_gate\Service\FileGateMetrics;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reports mint, delivery and denial counts.
 */
#[Tool(
  id: 'file_gate_metrics',
  label: new TranslatableMarkup('File Gate metrics'),
  description: new TranslatableMarkup('Report mints, deliveries, denials and authentication failures for the last 1 to 90 days, per day and per method, with the ten most requested file UUIDs. Counts come from the database log and cover at most the 5000 newest entries. "available: false" means Database Logging is not installed, not that nothing happened.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'days' => new InputDefinition(
      data_type: 'integer',
      label: new TranslatableMarkup('Days'),
      description: new TranslatableMarkup('Lookback window, 1 to 90.'),
      required: FALSE,
      default_value: 14,
      constraints: ['Range' => ['min' => 1, 'max' => 90]],
    ),
  ],
)]
final class MetricsTool extends FileGateToolBase {

  /**
   * Metrics service.
   */
  protected FileGateMetrics $metrics;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->metrics = $container->get('file_gate.metrics');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function inputNames(): array {
    return ['days'];
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $days = (int) ($values['days'] ?? 14);
    if ($days < 1 || $days > 90) {
      throw new \InvalidArgumentException('Days out of range.');
    }
    return ['metrics' => $this->metrics->summary($days)];
  }

}
