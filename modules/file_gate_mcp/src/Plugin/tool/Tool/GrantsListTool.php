<?php

declare(strict_types=1);

namespace Drupal\file_gate_mcp\Plugin\tool\Tool;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file_gate\Service\GatedFieldOverview;
use Drupal\file_gate\Service\GrantInventory;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Lists active usage-limited grants for one gated field.
 */
#[Tool(
  id: 'file_gate_grants_list',
  label: new TranslatableMarkup('File Gate grants for a field'),
  description: new TranslatableMarkup('List grants that have not expired for one gated field: grant id, file UUID, expiry, maximum uses, subject hash and the id of the secret that minted it. At most 200 rows. A grant id identifies a grant for revocation; it is not a download token. Only usage-limited grants are recorded, so an empty list does not mean no link is live.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'field' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Field'),
      description: new TranslatableMarkup('Field storage key, entity_type.field_name. Must be a gated field.'),
      required: TRUE,
      constraints: ['Regex' => ['pattern' => '/^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$/D']],
    ),
  ],
)]
final class GrantsListTool extends FileGateToolBase {

  private const MAX_ROWS = 200;

  /**
   * Grant inventory.
   */
  protected GrantInventory $inventory;

  /**
   * Gated field overview.
   */
  protected GatedFieldOverview $gatedFields;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->inventory = $container->get('file_gate.grant_inventory');
    $instance->gatedFields = $container->get('file_gate.gated_field_overview');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function inputNames(): array {
    return ['field'];
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $field = $this->fieldKey($values['field'] ?? NULL);
    if (!in_array($field, array_column($this->gatedFields->fields(), 'storage'), TRUE)) {
      throw new \InvalidArgumentException('Not a gated field.');
    }
    $rows = [];
    foreach ($this->inventory->listForField($field) as $row) {
      $rows[] = [
        'grant_id' => (string) $row['jti'],
        'file' => (string) $row['f'],
        'expires' => (int) $row['exp'],
        'max_uses' => (int) $row['max'],
        'subject_hash' => (string) $row['sh'],
        'secret_id' => $row['k'],
        'created' => (int) $row['created'],
      ];
    }
    usort($rows, static fn (array $a, array $b): int => $b['created'] <=> $a['created']);
    return [
      'field' => $field,
      'total' => count($rows),
      'truncated' => count($rows) > self::MAX_ROWS,
      'grants' => array_slice($rows, 0, self::MAX_ROWS),
    ];
  }

}
