<?php

declare(strict_types=1);

namespace Drupal\file_gate\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface;

/**
 * Secondary index of usage-limited signed_url grants (jti inventory, GH #44).
 *
 * Key-value expirable store holds metadata per jti and a per-field index list.
 * Used for operator list/revoke; not a substitute for HMAC validation.
 */
final class GrantInventory {

  public const META_COLLECTION = 'file_gate_grant_meta';

  public const FIELD_INDEX_COLLECTION = 'file_gate_grant_field_index';

  /**
   * Usage-counter / revoke kill-mark collection (same store SignedUrl reads).
   */
  public const REDEMPTION_COLLECTION = 'file_gate_redemptions';

  /**
   * Default TTL for a revoke kill mark, in seconds.
   *
   * Single-jti revoke used 86400; bulk used 86400 * 30. The longer window is
   * the safer pin: a kill mark that expires while the HMAC is still valid
   * would resurrect the grant.
   */
  public const DEFAULT_KILL_TTL = 86400 * 30;

  /**
   * Floor applied to an explicit kill-mark TTL.
   */
  public const MIN_KILL_TTL = 60;

  public function __construct(
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Records a newly minted usage-limited grant.
   *
   * @param string $jti
   *   Grant jti claim value.
   * @param string $file_uuid
   *   File UUID.
   * @param string $field
   *   Field storage key (entity_type.field_name).
   * @param int $exp
   *   Unix expiry timestamp.
   * @param string|null $secret_id
   *   Named secret id or NULL.
   * @param int $max
   *   Maximum redemptions.
   * @param string $subject_hash
   *   Optional sh claim (empty if unbound).
   */
  public function record(
    string $jti,
    string $file_uuid,
    string $field,
    int $exp,
    ?string $secret_id,
    int $max,
    string $subject_hash = '',
  ): void {
    if ($jti === '' || $field === '') {
      return;
    }
    $now = $this->time->getRequestTime();
    $ttl = max(1, $exp - $now);
    $meta = [
      'jti' => $jti,
      'f' => $file_uuid,
      'field' => $field,
      'exp' => $exp,
      'k' => $secret_id,
      'max' => $max,
      'sh' => $subject_hash,
      'created' => $now,
    ];
    $this->metaStore()->setWithExpire($jti, $meta, $ttl);

    $index = $this->fieldIndexStore()->get($field, []);
    if (!is_array($index)) {
      $index = [];
    }
    $index[$jti] = $exp;
    // Drop expired index entries opportunistically.
    foreach ($index as $id => $iexp) {
      if ((int) $iexp <= $now) {
        unset($index[$id]);
      }
    }
    $this->fieldIndexStore()->setWithExpire($field, $index, max($ttl, 86400));
  }

  /**
   * Lists non-expired grants for a field (optionally filtered by secret scope).
   *
   * @param string $field
   *   Field storage key.
   * @param string|null $secret_id
   *   When non-null, only rows with matching k (callers enforce allowsField).
   * @param string $subject_hash
   *   When non-empty, only matching sh.
   *
   * @return list<array<string, mixed>>
   *   Public-safe rows (no secrets).
   */
  public function listForField(string $field, ?string $secret_id = NULL, string $subject_hash = ''): array {
    $now = $this->time->getRequestTime();
    $index = $this->fieldIndexStore()->get($field, []);
    if (!is_array($index)) {
      return [];
    }
    $out = [];
    foreach (array_keys($index) as $jti) {
      $jti = (string) $jti;
      $meta = $this->metaStore()->get($jti);
      if (!is_array($meta)) {
        continue;
      }
      if ((int) ($meta['exp'] ?? 0) <= $now) {
        continue;
      }
      if ($subject_hash !== '' && (string) ($meta['sh'] ?? '') !== $subject_hash) {
        continue;
      }
      // When filtering by named secret, skip other tenants' rows.
      if ($secret_id !== NULL) {
        $row_k = $meta['k'] ?? NULL;
        $row_k = (is_string($row_k) && $row_k !== '') ? $row_k : NULL;
        if ($row_k !== $secret_id) {
          continue;
        }
      }
      $out[] = [
        'jti' => (string) ($meta['jti'] ?? $jti),
        'f' => (string) ($meta['f'] ?? ''),
        'field' => (string) ($meta['field'] ?? $field),
        'exp' => (int) ($meta['exp'] ?? 0),
        'max' => (int) ($meta['max'] ?? 0),
        'sh' => (string) ($meta['sh'] ?? ''),
        'k' => isset($meta['k']) && is_string($meta['k']) && $meta['k'] !== '' ? $meta['k'] : NULL,
        'created' => (int) ($meta['created'] ?? 0),
      ];
    }
    return $out;
  }

  /**
   * Marks a jti fully spent and drops it from inventory.
   *
   * Writes PHP_INT_MAX to the redemption counter so any positive max_uses
   * fails, then forget()s the operator list row. Used by both
   * POST /api/file-gate/revoke {jti} and bulk revoke.
   *
   * @param string $jti
   *   Grant jti claim value.
   * @param string $field
   *   Field storage key when known; empty lets forget() read it from meta.
   * @param int|null $ttl
   *   Kill-mark TTL in seconds, or NULL for DEFAULT_KILL_TTL.
   */
  public function revokeJti(string $jti, string $field = '', ?int $ttl = NULL): void {
    if ($jti === '') {
      return;
    }
    $ttl = max(self::MIN_KILL_TTL, $ttl ?? self::DEFAULT_KILL_TTL);
    $this->redemptionStore()->setWithExpire($jti, PHP_INT_MAX, $ttl);
    $this->forget($jti, $field);
  }

  /**
   * Removes inventory metadata for a jti (after revoke).
   */
  public function forget(string $jti, string $field = ''): void {
    if ($jti === '') {
      return;
    }
    $meta = $this->metaStore()->get($jti);
    $this->metaStore()->delete($jti);
    $field = $field !== '' ? $field : (is_array($meta) ? (string) ($meta['field'] ?? '') : '');
    if ($field === '') {
      return;
    }
    $index = $this->fieldIndexStore()->get($field, []);
    if (is_array($index) && isset($index[$jti])) {
      unset($index[$jti]);
      $this->fieldIndexStore()->set($field, $index);
    }
  }

  /**
   * Redemption-counter / kill-mark store.
   */
  private function redemptionStore(): KeyValueStoreExpirableInterface {
    return $this->keyValueExpirableFactory->get(self::REDEMPTION_COLLECTION);
  }

  /**
   * Per-jti metadata store.
   */
  private function metaStore(): KeyValueStoreExpirableInterface {
    return $this->keyValueExpirableFactory->get(self::META_COLLECTION);
  }

  /**
   * Per-field jti index store.
   */
  private function fieldIndexStore(): KeyValueStoreExpirableInterface {
    return $this->keyValueExpirableFactory->get(self::FIELD_INDEX_COLLECTION);
  }

}
