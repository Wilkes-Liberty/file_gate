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
 * Grants access to any authenticated user.
 *
 * A live-decision method (no minted URL): the file is delivered if the current
 * session belongs to a logged-in user. Useful for member-only downloads where
 * the front end authenticates the visitor against Drupal (e.g. via OAuth) and
 * calls the download route with that session/token. Returns NULL from mint()
 * because there is nothing to pre-issue.
 */
#[GateMethod(
  id: 'authenticated',
  label: new TranslatableMarkup('Authenticated access'),
  description: new TranslatableMarkup('Deliver the file to any authenticated user. No minted URL — access is decided live from the session. Use when the front end authenticates the visitor against Drupal.'),
)]
final class AuthenticatedAccess extends GateMethodBase {

  /**
   * The current user.
   */
  private AccountInterface $currentUser;

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
    return $this->currentUser->isAuthenticated();
  }

  /**
   * {@inheritdoc}
   */
  public function mint(FileInterface $file): ?array {
    // Nothing to pre-issue; access is decided live in grants().
    return NULL;
  }

}
