<?php

declare(strict_types=1);

namespace Drupal\file_gate\Exception;

use Drupal\Core\Entity\EntityStorageException;
use Drupal\file_gate\GatedFieldSchemeRule;

/**
 * A save would leave a gated field storing files outside the private scheme.
 *
 * Extends EntityStorageException so the core field form, which catches that
 * type around its storage save, reports it as a form error.
 */
final class GatedPublicSchemeException extends EntityStorageException {

  /**
   * Builds the exception for a field storage config name and its scheme.
   */
  public static function forStorage(string $name, string $scheme): self {
    return new self(strtr(GatedFieldSchemeRule::message(), [
      '@name' => $name,
      '@scheme' => $scheme,
    ]));
  }

}
