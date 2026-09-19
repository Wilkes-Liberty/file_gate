<?php

declare(strict_types=1);

namespace Drupal\file_gate\Plugin\Validation\Constraint;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\Core\Validation\Attribute\Constraint;
use Drupal\file_gate\GatedFieldSchemeRule;
use Symfony\Component\Validator\Attribute\HasNamedArguments;
use Symfony\Component\Validator\Constraint as SymfonyConstraint;

/**
 * A gated field storage must use the private file system.
 *
 * Set on the file_gate third-party settings mapping. The rule spans two parts
 * of the config object, so the validator reads the scheme from the root.
 */
#[Constraint(
  id: 'FileGateGatedFieldScheme',
  label: new TranslatableMarkup('Gated field uses the private file system', [], ['context' => 'Validation']),
)]
final class GatedFieldSchemeConstraint extends SymfonyConstraint {

  /**
   * The violation message.
   */
  public string $message;

  #[HasNamedArguments]
  public function __construct(
    mixed $options = NULL,
    ?string $message = NULL,
    ?array $groups = NULL,
    mixed $payload = NULL,
  ) {
    parent::__construct($options, $groups, $payload);
    $this->message = $message ?? GatedFieldSchemeRule::message();
  }

}
