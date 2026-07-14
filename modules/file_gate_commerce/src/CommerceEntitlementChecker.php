<?php

declare(strict_types=1);

namespace Drupal\file_gate_commerce;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\file\FileInterface;
use Psr\Log\LoggerInterface;

/**
 * Entitlement checker backed by Drupal Commerce completed orders.
 *
 * Grants when the account has a completed order containing a product variation
 * whose SKU matches the configured entitlement. It reaches Commerce only via
 * the entity API by machine name (never Commerce PHP classes), so the submodule
 * loads and this service resolves even where Commerce is not installed — in
 * which case it simply fails closed (and hook_requirements flags it).
 *
 * This is deliberately the simple case. Sites needing licences
 * (commerce_license), custom order states, guest-by-email orders, or external
 * entitlement API override the `file_gate_commerce.entitlement_checker` service
 * with their own implementation.
 */
final class CommerceEntitlementChecker implements EntitlementCheckerInterface {

  /**
   * Order states that count as a completed purchase.
   */
  private const COMPLETED_STATES = ['completed', 'fulfillment'];

  /**
   * Constructs the checker.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager (reaches Commerce orders by machine name).
   * @param \Psr\Log\LoggerInterface $logger
   *   The File Gate logger channel.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function isEntitled(AccountInterface $account, string $entitlement, FileInterface $file): bool {
    // Fail closed: orders are tied to an account, and there is nothing to check
    // without Commerce or an entitlement identifier.
    if ($account->isAnonymous() || $entitlement === '' || !$this->entityTypeManager->hasDefinition('commerce_order')) {
      return FALSE;
    }

    try {
      $order_storage = $this->entityTypeManager->getStorage('commerce_order');
      $ids = $order_storage->getQuery()
        ->accessCheck(FALSE)
        ->condition('uid', $account->id())
        ->condition('state', self::COMPLETED_STATES, 'IN')
        ->execute();
      foreach ($order_storage->loadMultiple($ids) as $order) {
        if ($this->orderGrants($order, $entitlement)) {
          return TRUE;
        }
      }
    }
    catch (\Throwable $e) {
      // A malformed query or a Commerce API mismatch must never grant access.
      $this->logger->warning('Commerce entitlement check failed: @msg', ['@msg' => $e->getMessage()]);
    }
    return FALSE;
  }

  /**
   * Whether an order contains a purchased variation with the given SKU.
   *
   * Duck-typed against the Commerce order/order-item/variation API so this file
   * carries no compile-time Commerce dependency.
   *
   * @param object $order
   *   A commerce_order entity.
   * @param string $sku
   *   The product variation SKU that grants access.
   *
   * @return bool
   *   TRUE if a matching purchased entity is found.
   */
  private function orderGrants(object $order, string $sku): bool {
    if (!method_exists($order, 'getItems')) {
      return FALSE;
    }
    foreach ($order->getItems() as $item) {
      $purchased = method_exists($item, 'getPurchasedEntity') ? $item->getPurchasedEntity() : NULL;
      if ($purchased !== NULL && method_exists($purchased, 'getSku') && $purchased->getSku() === $sku) {
        return TRUE;
      }
    }
    return FALSE;
  }

}
