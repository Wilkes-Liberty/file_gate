<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\Database\Connection;
use Drupal\file_gate\Exception\GrantParticipationException;
use Drupal\file_gate\GrantParticipantInterface;
use Drupal\file_gate\ScopedGrant;

/**
 * Provides a root transaction and one host write for the qualification test.
 */
final class TestGrantParticipant implements GrantParticipantInterface {

  /**
   * The most recent grant observed by the fixture.
   */
  public ?ScopedGrant $seen = NULL;
  /**
   * The most recent operation observed by the fixture.
   */
  public string $operation = '';
  /**
   * Whether to fail after the grant effect and before completion.
   */
  public bool $rejectCommit = FALSE;
  /**
   * Whether to discard the effect in an unqualified extra savepoint.
   */
  public bool $foreignSavepoint = FALSE;

  /**
   * Whether the fixture attempts to run the native effect a second time.
   */
  public bool $duplicateDispatch = FALSE;

  /**
   * Whether the fixture attempts to schedule the effect after completion.
   */
  public bool $deferredDispatch = FALSE;

  /**
   * Whether the fixture ends the native root before dispatching.
   */
  public bool $endNativeRoot = FALSE;

  /**
   * The exact legacy JTI admitted by the fixture's baseline.
   */
  public ?string $baseline = NULL;

  /**
   * Returns the last grant that reached the host.
   */
  public function lastGrant(): ?ScopedGrant {
    return $this->seen;
  }

  /**
   * {@inheritdoc}
   */
  public function participate(string $operation, ScopedGrant $grant, Connection $database, \Closure $effect, bool $existing_host_root): void {
    $this->seen = $grant;
    $this->operation = $operation;
    if ($this->endNativeRoot) {
      $client = $database->getClientConnection();
      if (!$client instanceof \PDO) {
        throw new \LogicException('The transaction fixture requires a native PDO connection.');
      }
      $client->rollBack();
      $effect();
      return;
    }
    if ($operation === 'redeem' && $grant->gateMethod === NULL && $grant->jti !== $this->baseline) {
      throw new GrantParticipationException('The fixture has no matching issuance provenance.');
    }
    $database->insert('file_gate_test_host')
      ->fields(['operation' => $operation, 'jti' => $grant->jti])
      ->execute();
    if ($this->foreignSavepoint) {
      $savepoint = $database->startTransaction();
      try {
        $effect();
      }
      catch (GrantParticipationException) {
        // Simulate a participant that hides a rejected native dispatch.
      }
      $savepoint->rollBack();
      return;
    }
    $effect();
    if ($this->duplicateDispatch) {
      try {
        $effect();
      }
      catch (GrantParticipationException) {
        // The File Gate boundary must still refuse this dispatch.
      }
    }
    if ($this->deferredDispatch) {
      $database->transactionManager()->addPostTransactionCallback(static function (bool $success) use ($effect): void {
        if ($success) {
          $effect();
        }
      });
    }
    if ($this->rejectCommit) {
      // A transaction owned independently by the participant would already
      // have committed its native effects if it ended here before throwing.
      throw new GrantParticipationException('The host rejected the write after the native effect.');
    }
  }

}
