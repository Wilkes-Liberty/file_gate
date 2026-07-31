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
 * Used for operator list/bulk-revoke; not a substitute for HMAC validation.
 */
final class GrantInventory {

  public const META_COLLECTION = 'file_gate_grant_meta';

  public const FIELD_INDEX_COLLECTION = 'file_gate_grant_field_index';

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
