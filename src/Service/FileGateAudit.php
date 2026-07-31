<?php

declare(strict_types=1);

namespace Drupal\file_gate\Service;

use Psr\Log\LoggerInterface;

/**
 * Optional durable audit trail for File Gate security events.
 *
 * When the sibling module audit_chain is enabled, events are appended to its
 * hash-chained table (channel "file_gate") for SIEM export and tamper evidence.
 * When audit_chain is absent, calls are no-ops beyond the existing dblog
 * logger channel — File Gate must not hard-require Key/Encrypt for every site.
 *
 * The chain service is intentionally untyped so this class loads when
 * audit_chain is not installed (no hard use of AuditChainLoggerInterface).
 *
 * Do not put raw secrets, full tokens, or OTP codes in metadata.
 *
 * @see docs/AUDIT.md
 */
final class FileGateAudit {

  /**
   * Audit_chain channel name (bound into row hashes — do not rename).
   */
  public const CHANNEL = 'file_gate';

  /**
   * Constructs the audit helper.
   *
   * @param object|null $chain
   *   Optional audit_chain.logger service (has log($channel, $op, $meta)).
   * @param \Psr\Log\LoggerInterface $logger
   *   Always-on File Gate logger (dblog / syslog).
   */
  public function __construct(
    private readonly ?object $chain,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Records a security-relevant operation.
   *
   * @param string $operation
   *   Short verb: mint, mint_denied, download, download_denied, revoke,
   *   otp_issue, bridge, webauthn_register, and similar.
   * @param array<string, mixed> $metadata
   *   Prefer entity_type/id/label for promotion; free keys stay in JSON.
   *   Do not include secrets or full tokens.
   */
  public function log(string $operation, array $metadata = []): void {
    if ($this->chain === NULL || !method_exists($this->chain, 'log')) {
      return;
    }
    try {
      $this->chain->log(self::CHANNEL, $operation, $metadata);
    }
    catch (\Throwable $e) {
      // Never break delivery because the audit write failed; surface ops noise.
      $this->logger->error('audit_chain log failed for @op: @msg', [
        '@op' => $operation,
        '@msg' => $e->getMessage(),
      ]);
    }
  }

  /**
   * Whether audit_chain is available for this request.
   */
  public function isAvailable(): bool {
    return $this->chain !== NULL && method_exists($this->chain, 'log');
  }

}
