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
 * whose SKU matches the configured entitlement. Uses order-item / variation
 * queries scoped by SKU and order owner (GH #45) instead of loading every
 * completed order for the user.
 *
 * Duck-typed against Commerce entity APIs so the submodule loads without
 * Commerce PHP classes. Fail closed when Commerce is absent.
 */
final class CommerceEntitlementChecker implements EntitlementCheckerInterface {

  /**
   * Order states that count as a completed purchase.
   */
  private const COMPLETED_STATES = ['completed', 'fulfillment'];

  /**
   * Constructs the checker.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function isEntitled(AccountInterface $account, string $entitlement, FileInterface $file): bool {
    if ($account->isAnonymous() || $entitlement === '' || !$this->entityTypeManager->hasDefinition('commerce_order')) {
      return FALSE;
    }

    try {
      // Prefer SKU-scoped query when order items + variations exist (GH #45).
      if ($this->entityTypeManager->hasDefinition('commerce_product_variation')
        && $this->entityTypeManager->hasDefinition('commerce_order_item')) {
        if ($this->entitledViaSkuIndex($account, $entitlement)) {
          return TRUE;
        }
        // Fall through to legacy scan only when the SKU index path found no
        // variation rows (e.g. custom purchased entities without sku field).
      }
      return $this->entitledViaOrderScan($account, $entitlement);
    }
    catch (\Throwable $e) {
      $this->logger->warning('Commerce entitlement check failed: @msg', ['@msg' => $e->getMessage()]);
    }
    return FALSE;
  }

  /**
   * SKU → variations → order items → parent orders (bounded by matching SKU).
   */
  private function entitledViaSkuIndex(AccountInterface $account, string $sku): bool {
    $variation_storage = $this->entityTypeManager->getStorage('commerce_product_variation');
    $variation_ids = $variation_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('sku', $sku)
      ->range(0, 100)
      ->execute();
    if ($variation_ids === []) {
      return FALSE;
    }

    $item_storage = $this->entityTypeManager->getStorage('commerce_order_item');
    $item_ids = $item_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('purchased_entity', array_values($variation_ids), 'IN')
      ->range(0, 500)
      ->execute();
    if ($item_ids === []) {
      return FALSE;
    }

    $order_ids = [];
    foreach ($item_storage->loadMultiple($item_ids) as $item) {
      if (method_exists($item, 'getOrderId')) {
        $oid = $item->getOrderId();
        if ($oid) {
          $order_ids[(int) $oid] = TRUE;
        }
      }
      elseif (method_exists($item, 'getOrder')) {
        $order = $item->getOrder();
        if ($order && method_exists($order, 'id')) {
          $order_ids[(int) $order->id()] = TRUE;
        }
      }
    }
    if ($order_ids === []) {
      return FALSE;
    }

    $order_storage = $this->entityTypeManager->getStorage('commerce_order');
    $matching = $order_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('order_id', array_keys($order_ids), 'IN')
      ->condition('uid', $account->id())
      ->condition('state', self::COMPLETED_STATES, 'IN')
      ->range(0, 1)
      ->execute();
    return $matching !== [];
  }

  /**
   * Legacy path: scan completed orders (bounded) when SKU index is unavailable.
   */
  private function entitledViaOrderScan(AccountInterface $account, string $entitlement): bool {
    $order_storage = $this->entityTypeManager->getStorage('commerce_order');
    $ids = $order_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('uid', $account->id())
      ->condition('state', self::COMPLETED_STATES, 'IN')
      // Cap blast radius for large B2B accounts (GH #45).
      ->range(0, 50)
      ->sort('order_id', 'DESC')
      ->execute();
    foreach ($order_storage->loadMultiple($ids) as $order) {
      if ($this->orderGrants($order, $entitlement)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Whether an order contains a purchased variation with the given SKU.
   *
   * @param object $order
   *   A commerce_order entity.
   * @param string $sku
   *   The product variation SKU that grants access.
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
