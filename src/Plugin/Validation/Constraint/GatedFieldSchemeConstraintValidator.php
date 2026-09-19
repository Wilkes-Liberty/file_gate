<?php

declare(strict_types=1);

namespace Drupal\file_gate\Plugin\Validation\Constraint;

use Drupal\Core\TypedData\TraversableTypedDataInterface;
use Drupal\file_gate\GatedFieldSchemeRule;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

/**
 * Validates the FileGateGatedFieldScheme constraint.
 */
final class GatedFieldSchemeConstraintValidator extends ConstraintValidator {

  /**
   * {@inheritdoc}
   */
  public function validate(mixed $value, Constraint $constraint): void {
    assert($constraint instanceof GatedFieldSchemeConstraint);
    $root = $this->context->getRoot();
    if (!$root instanceof TraversableTypedDataInterface) {
      return;
    }
    $data = $root->getValue();
    if (!is_array($data)) {
      return;
    }
    $scheme = GatedFieldSchemeRule::offendingSchemeInData($data);
    if ($scheme === NULL) {
      return;
    }
    $this->context->buildViolation($constraint->message)
      ->setParameter('@name', (string) $root->getName())
      ->setParameter('@scheme', $scheme)
      ->atPath('gated')
      ->addViolation();
  }

}
