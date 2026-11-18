<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\Database\Connection;

/**
 * Coordinates scoped File Gate operations with a host's resource authority.
 */
interface GrantParticipantInterface {

  /**
   * Runs one native operation under the host's writer locks and transaction.
   *
   * The implementation acquires or proves ownership of the authority writer
   * first, then the scoped resource writer, and calls the effect synchronously
   * exactly once. File Gate takes its per-JTI lock inside the effect. The host
   * must hold exclusive writer ownership until the root completes.
   *
   * File Gate starts and finishes the transaction for standalone operations.
   * For a scoped revoke it opens a savepoint in the caller's transaction.
   * The participant joins that supplied transaction scope. It does not start,
   * release, commit, or roll back the transaction or register work to run at
   * transaction completion. An effect exception must
   * propagate. The scoped caller publishes results after its root commits.
   *
   * A NULL gateMethod identifies primary metadata from before enrollment.
   * The participant must establish that exact grant's issuance provenance
   * before an enrolled redemption. A primary row alone is insufficient.
   *
   * @param string $operation
   *   One of 'mint', 'redeem', or 'revoke'.
   * @param \Drupal\file_gate\ScopedGrant $grant
   *   Verified grant coordinates. Contains no redeemable credential.
   * @param \Drupal\Core\Database\Connection $database
   *   The exact Drupal connection the host and File Gate must share.
   * @param \Closure(): bool $effect
   *   The synchronous native operation. FALSE indicates a denied mutation.
   * @param bool $existing_host_root
   *   TRUE when scoped revoke joins a root already owned by the caller.
   */
  public function participate(string $operation, ScopedGrant $grant, Connection $database, \Closure $effect, bool $existing_host_root): void;

}
