<?php

declare(strict_types=1);

namespace Drupal\file_gate_commerce\Plugin\GateMethod;

use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\GateMethodBase;
use Drupal\file_gate_commerce\EntitlementCheckerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Grants delivery to a buyer / licensee (purchase or entitlement gate).
 *
 * Delivers the file only to an account that is currently entitled to it. The
 * decision is delegated to a swappable entitlement checker — the bundled one
 * queries Drupal Commerce completed orders by SKU, but a site can override the
 * `file_gate_commerce.entitlement_checker` service to check licences or an
 * external entitlement API instead of hardcoding one store.
 *
 * A live-decision method: mint() returns NULL, so the entitlement is re-checked
 * on every download. An expired or revoked entitlement stops delivery
 * immediately — the gate never trusts a long-lived signed URL.
 *
 * NOTE — this is access gating, not DRM. Once the bytes are delivered they are
 * out of File Gate's control; combine with a short-lived flow if you need to
 * limit re-download, and do not rely on it for hard licence enforcement. Since
 * orders are tied to an account, the visitor must be authenticated to Drupal at
 * download time (or a custom checker must resolve entitlement another way).
 *
 * Per-field method settings:
 * - sku: the product variation SKU whose purchase grants the file.
 */
#[GateMethod(
  id: 'commerce',
  label: new TranslatableMarkup('Commerce (purchase / entitlement)'),
  description: new TranslatableMarkup('Deliver only to a buyer or licensee. Delegates to a swappable entitlement checker (Drupal Commerce orders by default; override the service for licences or an external API). Re-checks live on every download, so expiry/revocation take effect immediately. Access gating, not DRM.'),
)]
final class CommerceGate extends GateMethodBase {

  /**
   * The entitlement checker.
   */
  protected EntitlementCheckerInterface $entitlementChecker;

  /**
   * The current user.
   */
  protected AccountInterface $currentUser;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    $instance = new static($configuration, $plugin_id, $plugin_definition);
    $instance->entitlementChecker = $container->get('file_gate_commerce.entitlement_checker');
    $instance->currentUser = $container->get('current_user');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function grants(FileInterface $file, Request $request): bool {
    $sku = trim((string) ($this->configuration['sku'] ?? ''));
    if ($sku === '') {
      // No entitlement configured ⇒ nothing to check. Fail closed.
      return FALSE;
    }
    return $this->entitlementChecker->isEntitled($this->currentUser, $sku, $file);
  }

  /**
   * {@inheritdoc}
   */
  public function mint(FileInterface $file): ?array {
    // Access is decided live so entitlement is re-checked every request.
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $settings): array {
    return [
      'sku' => [
        '#type' => 'textfield',
        '#title' => $this->t('Entitlement SKU'),
        '#default_value' => $settings['sku'] ?? '',
        '#description' => $this->t('The product variation SKU whose purchase (or, with a custom checker, whose entitlement) grants this file. Empty denies.'),
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsSubmit(array $values): array {
    $sku = trim((string) ($values['sku'] ?? ''));
    return $sku !== '' ? ['sku' => $sku] : [];
  }

}
