<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\Hook;

use Drupal\Core\Extension\Requirement\RequirementSeverity;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\StringTranslation\StringTranslationTrait;

/**
 * Status report findings for File Gate Assurance.
 *
 * OIDC needs firebase/php-jwt; native WebAuthn needs web-auth/webauthn-lib.
 * Both are declared in the submodule composer.json. They live on
 * hook_runtime_requirements(): Drupal 13 stops calling the procedural
 * hook_requirements(), and a missing library must not be able to leave the
 * status report without a finding.
 */
final class FileGateRequirements {

  use StringTranslationTrait;

  /**
   * Implements hook_runtime_requirements().
   *
   * @return array<string, array<string, mixed>>
   *   Requirements keyed by id.
   */
  #[Hook('runtime_requirements')]
  public function runtime(): array {
    $requirements = [];
    if (!class_exists('Firebase\JWT\JWT')) {
      $requirements['file_gate_assurance_jwt'] = [
        'title' => $this->t('File Gate Assurance (OIDC)'),
        'description' => $this->t('Install <code>firebase/php-jwt</code> for OIDC verification: <code>composer require firebase/php-jwt</code>.'),
        'severity' => (enum_exists(RequirementSeverity::class) ? RequirementSeverity::Error : 2),
      ];
    }
    if (!class_exists('Webauthn\CeremonyStep\CeremonyStepManagerFactory')) {
      $requirements['file_gate_assurance_webauthn'] = [
        'title' => $this->t('File Gate Assurance (WebAuthn)'),
        'description' => $this->t('Install <code>web-auth/webauthn-lib</code> for native WebAuthn: <code>composer require web-auth/webauthn-lib</code>.'),
        'severity' => (enum_exists(RequirementSeverity::class) ? RequirementSeverity::Warning : 1),
      ];
    }
    return $requirements;
  }

}
