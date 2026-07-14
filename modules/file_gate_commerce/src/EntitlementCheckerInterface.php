<?php

declare(strict_types=1);

namespace Drupal\file_gate_commerce;

use Drupal\Core\Session\AccountInterface;
use Drupal\file\FileInterface;

/**
 * Decides whether an account is currently entitled to a gated file.
 *
 * The `commerce` gate method delegates its decision here so the entitlement
 * source is swappable rather than hardcoded to one store. The bundled
 * implementation checks Drupal Commerce orders; a site with an external
 * entitlement API (a SaaS, a licence server) can override the
 * `file_gate_commerce.entitlement_checker` service with its own.
 *
 * The check runs live on every download, so an expired or revoked entitlement
 * stops delivery immediately (the gate never trusts a long-lived signed URL).
 * Implementations MUST fail closed.
 */
interface EntitlementCheckerInterface {

  /**
   * Whether the account is entitled to the file.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account requesting delivery.
   * @param string $entitlement
   *   The configured entitlement identifier — a product SKU for the bundled
   *   Commerce checker; opaque to a custom implementation.
   * @param \Drupal\file\FileInterface $file
   *   The gated file (context; the entitlement identifier is authoritative).
   *
   * @return bool
   *   TRUE only if the account is currently entitled. Fails closed.
   */
  public function isEntitled(AccountInterface $account, string $entitlement, FileInterface $file): bool;

}
