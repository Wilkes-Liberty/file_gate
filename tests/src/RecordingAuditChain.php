<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate;

/**
 * Stands in for audit_chain.logger and keeps what it is given.
 */
final class RecordingAuditChain {

  /**
   * Recorded events, as [channel, operation, metadata].
   *
   * @var list<array{0: string, 1: string, 2: array<string, mixed>}>
   */
  public static array $events = [];

  /**
   * When FALSE, logKeyed() throws (missing signing key).
   */
  public static bool $keyedAvailable = TRUE;

  /**
   * Resets recorded events and the keyed-available flag.
   */
  public static function reset(): void {
    self::$events = [];
    self::$keyedAvailable = TRUE;
  }

  /**
   * Matches the audit_chain logger's log() signature.
   *
   * @param string $channel
   *   The audit channel.
   * @param string $operation
   *   The operation name.
   * @param array<string, mixed> $metadata
   *   Event metadata.
   */
  public function log(string $channel, string $operation, array $metadata = []): void {
    self::$events[] = [$channel, $operation, $metadata];
  }

  /**
   * Matches the audit_chain logger's logKeyed() signature.
   *
   * Throws when $keyedAvailable is FALSE so evidence-required callers can
   * exercise fail-closed delivery (AuditChainSigningUnavailableException
   * is not imported: audit_chain is a soft dependency).
   *
   * @param string $channel
   *   The audit channel.
   * @param string $operation
   *   The operation name.
   * @param array<string, mixed> $metadata
   *   Event metadata.
   */
  public function logKeyed(string $channel, string $operation, array $metadata = []): void {
    if (!self::$keyedAvailable) {
      throw new \RuntimeException('Signing key is not available.');
    }
    self::$events[] = [$channel, $operation, $metadata];
  }

}
