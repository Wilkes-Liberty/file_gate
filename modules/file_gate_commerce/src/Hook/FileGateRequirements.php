<?php

declare(strict_types=1);

namespace Drupal\file_gate_commerce\Hook;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\Requirement\RequirementSeverity;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\StringTranslation\StringTranslationTrait;

/**
 * Status report findings for File Gate Commerce.
 *
 * The bundled entitlement checker needs Drupal Commerce. This is a warning,
 * not an error: a site may instead override the entitlement checker service
 * to check an external entitlement source, in which case Commerce is not
 * required. They live on hook_runtime_requirements(): Drupal 13 stops
 * calling the procedural hook_requirements(), and a missing Commerce
 * install must not be able to leave the status report without a finding.
 */
final class FileGateRequirements {

  use StringTranslationTrait;

  /**
   * Constructs the hook class.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * Implements hook_runtime_requirements().
   *
   * @return array<string, array<string, mixed>>
   *   Requirements keyed by id.
   */
  #[Hook('runtime_requirements')]
  public function runtime(): array {
    if ($this->entityTypeManager->hasDefinition('commerce_order')) {
      return [];
    }
    return [
      'file_gate_commerce_commerce' => [
        'title' => $this->t('File Gate Commerce'),
        'description' => $this->t('The bundled entitlement checker needs Drupal Commerce (<code>commerce_order</code>). Install Commerce, or override the <code>file_gate_commerce.entitlement_checker</code> service to check an external entitlement source.'),
        'severity' => RequirementSeverity::Warning,
      ],
    ];
  }

}
