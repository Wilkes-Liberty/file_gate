<?php

declare(strict_types=1);

namespace Drupal\file_gate_mcp\Plugin\tool\Tool;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file_gate\Service\FileGateAudit;
use Drupal\file_gate\Service\GatedFieldOverview;
use Drupal\file_gate\Service\GrantInventory;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Revokes one grant, for incident response.
 */
#[Tool(
  id: 'file_gate_grant_revoke',
  label: new TranslatableMarkup('Revoke one File Gate grant'),
  description: new TranslatableMarkup('Revoke one grant by field and grant id so it can no longer be redeemed. Acts with site-operator reach: the grant may have been minted by any secret. The grant must be recorded against that exact field; a grant id from another field is refused. Cannot be undone: the holder needs a new grant. Revokes one grant per call; there is no bulk form. Written to the audit log when Audit Chain is installed.'),
  operation: ToolOperation::Write,
  input_definitions: [
    'field' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Field'),
      description: new TranslatableMarkup('Field storage key the grant was minted for, entity_type.field_name.'),
      required: TRUE,
      constraints: ['Regex' => ['pattern' => '/^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$/D']],
    ),
    'grant_id' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Grant id'),
      description: new TranslatableMarkup('The grant id from file_gate_grants_list.'),
      required: TRUE,
      constraints: ['Regex' => ['pattern' => '/^[A-Za-z0-9_-]{8,128}$/D']],
    ),
  ],
)]
final class GrantRevokeTool extends FileGateToolBase {

  /**
   * Grant inventory.
   */
  protected GrantInventory $inventory;

  /**
   * Gated field overview.
   */
  protected GatedFieldOverview $gatedFields;

  /**
   * Audit writer.
   */
  protected FileGateAudit $audit;

  /**
   * Clock.
   */
  protected TimeInterface $time;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->inventory = $container->get('file_gate.grant_inventory');
    $instance->gatedFields = $container->get('file_gate.gated_field_overview');
    $instance->audit = $container->get('file_gate.audit');
    $instance->time = $container->get('datetime.time');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function extraPermissions(): array {
    return ['revoke file gate grants via mcp'];
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $field = $this->fieldKey($values['field'] ?? NULL);
    $jti = is_string($values['grant_id'] ?? NULL) ? trim($values['grant_id']) : '';
    if (!preg_match('/^[A-Za-z0-9_-]{8,128}$/D', $jti)) {
      throw new \InvalidArgumentException('Invalid grant id.');
    }
    if (!in_array($field, array_column($this->gatedFields->fields(), 'storage'), TRUE)) {
      throw new \InvalidArgumentException('Not a gated field.');
    }
    // The stored field decides scope, so a guessed or copied id from another
    // field cannot be spent here. The HTTP route also binds a named secret to
    // its own grants; this tool acts for the site operator and does not.
    $meta = $this->inventory->meta($jti);
    if ($meta === NULL || ($meta['field'] ?? NULL) !== $field) {
      throw new \InvalidArgumentException('Unknown grant for this field.');
    }
    // The kill mark must outlive the grant, or a long-lived grant becomes
    // redeemable again once the default 30-day mark expires.
    $remaining = (int) ($meta['exp'] ?? 0) - $this->time->getRequestTime();
    $this->inventory->revokeJti($jti, $field, max(GrantInventory::DEFAULT_KILL_TTL, $remaining + 3600));
    $this->logger->info('Revoked one File Gate grant through MCP for uid @uid.', [
      '@uid' => (int) $this->currentUser->id(),
    ]);
    $this->audit->log('revoke', [
      'kind' => 'jti',
      'jti_prefix' => substr(hash('sha256', $jti), 0, 16),
      'secret_id' => 'mcp',
      'uid' => (string) $this->currentUser->id(),
    ]);
    return ['revoked' => TRUE, 'field' => $field];
  }

}
