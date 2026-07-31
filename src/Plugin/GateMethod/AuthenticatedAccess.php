<?php

declare(strict_types=1);

namespace Drupal\file_gate\Plugin\GateMethod;

use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\GateMethodBase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Grants access to authenticated users (optionally restricted by role).
 *
 * A live-decision method (no minted URL): the file is delivered if the current
 * session belongs to a logged-in user. Optional role allowlist prevents the
 * common misconfiguration of treating "any account on the site" as
 * "member-only NDA" access.
 *
 * Per-field method settings:
 * - roles: list of role ids; when non-empty the user must have at least one.
 */
#[GateMethod(
  id: 'authenticated',
  label: new TranslatableMarkup('Authenticated access'),
  description: new TranslatableMarkup('Deliver the file to authenticated users. Optional role allowlist. No minted URL — access is decided live from the session.'),
)]
final class AuthenticatedAccess extends GateMethodBase {

  /**
   * The current user.
   */
  protected AccountInterface $currentUser;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    $instance = new static($configuration, $plugin_id, $plugin_definition);
    $instance->currentUser = $container->get('current_user');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function grants(FileInterface $file, Request $request): bool {
    if (!$this->currentUser->isAuthenticated()) {
      return FALSE;
    }
    $roles = array_values(array_filter(array_map('strval', (array) ($this->configuration['roles'] ?? []))));
    if ($roles === []) {
      // No allowlist: any logged-in account (documented enterprise footgun).
      return TRUE;
    }
    $user_roles = $this->currentUser->getRoles();
    foreach ($roles as $role) {
      if (in_array($role, $user_roles, TRUE)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function mint(FileInterface $file): ?array {
    // Nothing to pre-issue; access is decided live in grants().
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $settings): array {
    return [
      'roles' => [
        '#type' => 'textarea',
        '#title' => $this->t('Required roles (optional)'),
        '#default_value' => implode("\n", array_map('strval', (array) ($settings['roles'] ?? []))),
        '#description' => $this->t('One role machine name per line (e.g. <code>member</code>). When set, the user must have at least one listed role. Empty = any authenticated account — prefer an allowlist for sensitive files.'),
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsSubmit(array $values): array {
    $list = array_filter(array_map('trim', preg_split('/\R/', (string) ($values['roles'] ?? ''))));
    return ['roles' => array_values($list)];
  }

}
