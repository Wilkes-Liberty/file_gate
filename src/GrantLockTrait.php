<?php

declare(strict_types=1);

namespace Drupal\file_gate;

/**
 * Serializes a read-modify-write against the grant stores with a named lock.
 *
 * The token and redemption stores are fast expirable key/value stores, not
 * locks, so a bare get→check→set can interleave with a concurrent redemption or
 * a manual revocation. Without serialization two failures are possible:
 * - a "one-time" (max_uses = 1) link redeemed several times in a concurrent
 *   burst, because every request reads the same pre-increment counter; and
 * - a revoked token resurrected, because a redemption that read the row before
 *   the revoke's delete writes an incremented row back after it.
 *
 * Wrapping both the redemption read-modify-write and the revoke delete in a
 * lock keyed on the same token hash makes the operations mutually exclusive, so
 * neither can happen. Consumers must expose the lock backend as $this->lock.
 */
trait GrantLockTrait {

  /**
   * Runs a critical section under a named lock, failing closed on contention.
   *
   * @param string $name
   *   The lock name. Operations that must exclude each other (a redemption and
   *   a revocation of the same token) MUST pass the identical name.
   * @param callable $critical
   *   The critical section to run while the lock is held.
   * @param mixed $on_contention
   *   The value to return when the lock cannot be acquired (fail closed).
   *
   * @return mixed
   *   The critical section's return value, or $on_contention if the lock could
   *   not be acquired.
   */
  protected function runLocked(string $name, callable $critical, mixed $on_contention = FALSE): mixed {
    if (!$this->lock->acquire($name)) {
      // Give the current holder a moment to finish, then try once more.
      $this->lock->wait($name, 5);
      if (!$this->lock->acquire($name)) {
        return $on_contention;
      }
    }
    try {
      return $critical();
    }
    finally {
      $this->lock->release($name);
    }
  }

  /**
   * The lock name for a token hash, shared by redemption and revocation.
   *
   * @param string $token_hash
   *   The SHA-256 hash of the token (the token store key).
   *
   * @return string
   *   The lock name.
   */
  protected function tokenLockName(string $token_hash): string {
    return 'file_gate_token:' . $token_hash;
  }

}
