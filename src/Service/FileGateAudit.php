<?php

declare(strict_types=1);

namespace Drupal\file_gate\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\file\FileInterface;
use Psr\Log\LoggerInterface;

/**
 * Optional durable audit trail for File Gate security events.
 *
 * This service is chain-only. When the sibling module audit_chain is enabled,
 * events are appended to its hash-chained table (channel "file_gate") for SIEM
 * export and tamper evidence. When audit_chain is absent, log() is a no-op.
 * Operational dblog comes from controllers and logger.channel.file_gate, not
 * from this class — File Gate must not hard-require Key/Encrypt for every site.
 *
 * The chain service is intentionally untyped so this class loads when
 * audit_chain is not installed (no hard use of AuditChainLoggerInterface).
 *
 * Do not put raw secrets, full tokens, OTP codes, or original filenames in
 * metadata. Identify a file with fileLabel() (opaque file:<id>), never
 * FileInterface::getFilename().
 *
 * @see docs/AUDIT.md
 */
final class FileGateAudit {

  /**
   * Audit_chain channel name (bound into row hashes — do not rename).
   */
  public const CHANNEL = 'file_gate';

  /**
   * Generic body when a required keyed append fails and delivery is refused.
   */
  public const REFUSAL_MESSAGE = 'Service unavailable.';

  /**
   * Constructs the audit helper.
   *
   * @param object|null $chain
   *   Optional audit_chain.logger service (has log() / logKeyed()).
   * @param \Psr\Log\LoggerInterface $logger
   *   Always-on File Gate logger (dblog / syslog).
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Config factory (reads audit_require_keyed).
   */
  public function __construct(
    private readonly ?object $chain,
    private readonly LoggerInterface $logger,
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * Opaque Audit Chain label for a file (never the original filename).
   *
   * Audit_chain promotes `label` to the indexed entity_label column; a
   * filename there cannot be redacted without breaking the hash chain.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file being recorded.
   *
   * @return string
   *   "file:<id>" when the file is saved; "file:unknown" otherwise.
   */
  public static function fileLabel(FileInterface $file): string {
    $id = $file->id();
    return $id !== NULL && $id !== '' ? 'file:' . $id : 'file:unknown';
  }

  /**
   * Records a security-relevant operation (best-effort).
   *
   * Failures are logged and swallowed. Use logDelivery() on mint and download
   * success paths so audit_require_keyed can refuse delivery.
   *
   * @param string $operation
   *   Short verb: mint, mint_denied, download, download_denied, revoke,
   *   otp_issue, bridge, webauthn_register, and similar.
   * @param array<string, mixed> $metadata
   *   Prefer entity_type/id/label for promotion; free keys stay in JSON.
   *   Do not include secrets, full tokens, or original filenames.
   */
  public function log(string $operation, array $metadata = []): void {
    if ($this->chain === NULL || !method_exists($this->chain, 'log')) {
      return;
    }
    try {
      $this->chain->log(self::CHANNEL, $operation, $metadata);
    }
    catch (\Throwable $e) {
      // Best-effort path: never break the caller because the audit write
      // failed; surface ops noise only.
      $this->logger->error('audit_chain log failed for @op: @msg', [
        '@op' => $operation,
        '@msg' => $e->getMessage(),
      ]);
    }
  }

  /**
   * Records a mint or download success, optionally requiring a signed row.
   *
   * When file_gate.settings.audit_require_keyed is FALSE (default), this is
   * best-effort log() and always returns TRUE so today's delivery holds.
   * When TRUE, uses audit_chain logKeyed() and returns FALSE if the append
   * cannot be HMAC-signed (missing module, missing method, missing key, or
   * thrown failure). Callers must refuse delivery with HTTP 503.
   *
   * @param string $operation
   *   Short verb: mint or download.
   * @param array<string, mixed> $metadata
   *   Identifier-only metadata (no filenames).
   *
   * @return bool
   *   TRUE when delivery may proceed; FALSE when keyed evidence was required
   *   and the signed append failed.
   */
  public function logDelivery(string $operation, array $metadata = []): bool {
    if (!$this->requireKeyed()) {
      $this->log($operation, $metadata);
      return TRUE;
    }
    return $this->logKeyed($operation, $metadata);
  }

  /**
   * Appends a keyed (HMAC-signed) audit row.
   *
   * @param string $operation
   *   Short verb.
   * @param array<string, mixed> $metadata
   *   Identifier-only metadata (no filenames).
   *
   * @return bool
   *   TRUE when the signed row was written; FALSE otherwise.
   */
  public function logKeyed(string $operation, array $metadata = []): bool {
    if ($this->chain === NULL || !method_exists($this->chain, 'logKeyed')) {
      $this->logger->error('audit_chain keyed log unavailable for @op.', [
        '@op' => $operation,
      ]);
      return FALSE;
    }
    try {
      $this->chain->logKeyed(self::CHANNEL, $operation, $metadata);
      return TRUE;
    }
    catch (\Throwable $e) {
      $this->logger->error('audit_chain keyed log failed for @op: @msg', [
        '@op' => $operation,
        '@msg' => $e->getMessage(),
      ]);
      return FALSE;
    }
  }

  /**
   * Whether mint/download must refuse delivery if a keyed append fails.
   *
   * @return bool
   *   TRUE when audit_require_keyed is enabled.
   */
  public function requireKeyed(): bool {
    return (bool) $this->configFactory->get('file_gate.settings')->get('audit_require_keyed');
  }

}
