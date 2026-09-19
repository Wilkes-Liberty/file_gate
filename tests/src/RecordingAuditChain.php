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

}
