<?php

declare(strict_types=1);

namespace Drupal\file_gate\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\file_gate\Exception\GrantParticipationException;
use Drupal\file_gate\GrantLockTrait;
use Drupal\file_gate\GrantRevokeLockException;
use Drupal\file_gate\ScopedGrant;
use Drupal\file_gate\ScopedGrantState;

/**
 * Stores usage-limited signed grant state and operator inventory.
 *
 * The expirable store holds primary metadata per JTI. Ordinary fields use a
 * secondary per-field index. Protected fields inspect primary state directly.
 * Inventory does not replace HMAC validation.
 */
final class GrantInventory {

  use GrantLockTrait;

  public const META_COLLECTION = 'file_gate_grant_meta';

  public const FIELD_INDEX_COLLECTION = 'file_gate_grant_field_index';

  /**
   * Fields that have used primary inventory, including after unenrollment.
   */
  public const PRIMARY_FIELDS_COLLECTION = 'file_gate_grant_primary_fields';

  /**
   * Usage-counter / revoke kill-mark collection (same store SignedUrl reads).
   */
  public const REDEMPTION_COLLECTION = 'file_gate_redemptions';

  /**
   * Lock name prefix shared with SignedUrl::consumeUse().
   */
  public const REDEMPTION_LOCK_PREFIX = 'file_gate_redemption:';

  /**
   * When each kill mark ends, keyed by jti.
   *
   * The expirable store cannot be asked when a row expires, and revoke deletes
   * the inventory row that held the grant's expiry. Without this record a
   * second revoke of the same jti would have nothing to measure against and
   * could replace a long mark with a short one.
   */
  public const KILL_EXPIRY_COLLECTION = 'file_gate_kill_expiry';

  /**
   * Default TTL for a revoke kill mark, in seconds.
   *
   * Single-jti revoke used 86400; bulk used 86400 * 30. The longer window is
   * the safer pin: a kill mark that expires while the HMAC is still valid
   * would resurrect the grant. It is a default, not a ceiling: killTtl() keeps
   * the mark of a recorded grant past that grant's own expiry.
   */
  public const DEFAULT_KILL_TTL = 86400 * 30;

  /**
   * Seconds a kill mark is kept past the grant's own expiry.
   *
   * The mark and the signature are judged against the request time of whichever
   * request is in flight, on whichever web head serves it. The margin covers
   * clock differences between heads and a request that started before the
   * expiry and redeems after it.
   */
  public const KILL_MARGIN = 3600;

  /**
   * Floor applied to an explicit kill-mark TTL.
   */
  public const MIN_KILL_TTL = 60;

  public function __construct(
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly TimeInterface $time,
    protected readonly LockBackendInterface $lock,
    private readonly ?GrantParticipation $participation = NULL,
  ) {}

  /**
   * The lock name consumeUse and revokeJti must share for one jti.
   */
  public static function redemptionLockName(string $jti): string {
    return self::REDEMPTION_LOCK_PREFIX . $jti;
  }

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
    if ($this->participation?->protectsField($field)) {
      throw new GrantParticipationException('This field requires scoped minting.');
    }
    $grant = new ScopedGrant($jti, $file_uuid, $field, $secret_id, $exp, $max);
    $this->writeMetadata($grant, $subject_hash);

    $now = $this->time->getRequestTime();
    $ttl = max(1, $exp - $now);
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
    if ($this->usesPrimaryInventory($field)) {
      $this->participation->assertNativeStorage();
      $primary = $this->participation->read(self::META_COLLECTION);
      $rows = [];
      foreach ($primary as $jti => $row) {
        if (is_array($row['value']) && ($row['value']['field'] ?? NULL) === $field) {
          $rows[$jti] = $row['value'];
        }
      }
    }
    else {
      $index = $this->fieldIndexStore()->get($field, []);
      if (!is_array($index)) {
        return [];
      }
      $rows = [];
      foreach (array_keys($index) as $jti) {
        $rows[$jti] = $this->metaStore()->get((string) $jti);
      }
    }
    $out = [];
    foreach ($rows as $jti => $meta) {
      $jti = (string) $jti;
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
   * Returns inventory metadata for a jti, or NULL when unknown.
   *
   * Used by single-jti revoke to enforce field / k scope before spend.
   *
   * @param string $jti
   *   Grant jti claim value.
   *
   * @return array<string, mixed>|null
   *   Stored row (jti, f, field, exp, k, max, sh, created), or NULL.
   */
  public function meta(string $jti): ?array {
    if ($jti === '') {
      return NULL;
    }
    $meta = $this->metaStore()->get($jti);
    return is_array($meta) ? $meta : NULL;
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
   *   Kill-mark TTL in seconds, or NULL for DEFAULT_KILL_TTL. It can lengthen
   *   the mark. It cannot shorten it below the recorded grant's remaining life
   *   plus KILL_MARGIN; see killTtl().
   */
  public function revokeJti(string $jti, string $field = '', ?int $ttl = NULL): void {
    if ($jti === '') {
      return;
    }
    if ($this->participation !== NULL && ($this->participation->enabled() || $this->usesPrimaryInventory($field))) {
      $meta = $this->meta($jti);
      $stored_field = $meta['field'] ?? '';
      if (($stored_field === '' && ($field === '' || $this->participation->enrolled($field)))
        || ($stored_field !== '' && $this->participation->enrolled($stored_field))) {
        if (!is_array($meta) || ($field !== '' && $field !== $stored_field)) {
          throw new GrantParticipationException('The enrolled grant could not be identified.');
        }
        $this->revokeParticipating($this->grantFromMetadata($jti, $meta), $ttl, FALSE);
        return;
      }
    }
    $ok = $this->runLocked(self::redemptionLockName($jti), function () use ($jti, $field, $ttl): bool {
      // Read the expiry before forget() deletes the row that holds it.
      $ttl = $this->killTtl($jti, $ttl);
      $this->redemptionStore()->setWithExpire($jti, PHP_INT_MAX, $ttl);
      $this->killExpiryStore()->setWithExpire($jti, $this->time->getRequestTime() + $ttl, $ttl);
      $this->forget($jti, $field);
      return TRUE;
    }, FALSE);
    if ($ok !== TRUE) {
      throw new GrantRevokeLockException('Revoke could not take the redemption lock.');
    }
  }

  /**
   * Signs and records a qualified grant while both writer locks are held.
   *
   * @param \Drupal\file_gate\ScopedGrant $grant
   *   The verified new grant identity.
   * @param string $subject_hash
   *   An optional existing File Gate subject binding.
   * @param \Closure(): string $sign
   *   File Gate's signer, unavailable to the host adapter.
   */
  public function mintScoped(ScopedGrant $grant, string $subject_hash, \Closure $sign): string {
    $signature = NULL;
    $participation = $this->requireParticipation();
    $ok = $participation->run('mint', $grant, function () use ($grant, $subject_hash, $sign, &$signature): bool {
      return $this->runLocked(self::redemptionLockName($grant->jti), function () use ($grant, $subject_hash, $sign, &$signature): bool {
        $state = $this->readState($grant);
        if ($state->metadataPresent || $state->uses > 0 || $state->killed || $grant->expiresAt <= $this->time->getCurrentTime()) {
          return FALSE;
        }
        $signature = $sign();
        $this->writeMetadata($grant, $subject_hash, TRUE);
        if (!$this->readState($grant)->enrolledMint) {
          throw new GrantParticipationException('The minted grant could not be verified.');
        }
        return TRUE;
      });
    });
    if (!$ok || $signature === NULL) {
      throw new GrantParticipationException('The enrolled grant could not be minted.');
    }
    return $signature;
  }

  /**
   * Burns one use of a verified, enrolled grant.
   */
  public function consumeScoped(ScopedGrant $grant): bool {
    return $this->requireParticipation()->run('redeem', $grant, function () use ($grant): bool {
      return $this->runLocked(self::redemptionLockName($grant->jti), function () use ($grant): bool {
        $now = $this->time->getRequestTime();
        $state = $this->readState($grant);
        if (!$state->metadataPresent || $state->enrolledMint !== ($grant->gateMethod !== NULL) || $state->killed || $state->uses >= $grant->maxUses || $grant->expiresAt <= $this->time->getCurrentTime()) {
          return FALSE;
        }
        $this->redemptionStore()->setWithExpire($grant->jti, $state->uses + 1, $grant->expiresAt - $now);
        if ($this->readState($grant)->uses !== $state->uses + 1) {
          throw new GrantParticipationException('The redeemed use could not be verified.');
        }
        return TRUE;
      });
    });
  }

  /**
   * Activates durable protection before the first grant operation.
   *
   * Call in the same native root as the host's enrollment decision.
   */
  public function protectField(string $field): void {
    $this->requireParticipation()->protectField($field);
  }

  /**
   * Inspects native state for an exact, server-known grant identity.
   *
   * Use the host writer fence for decisions spanning multiple reads. Absence
   * of metadata or an index entry does not prove revocation.
   */
  public function scopedState(ScopedGrant $grant): ScopedGrantState {
    $participation = $this->requireParticipation();
    $participation->assertEnrolledGrant($grant);
    $participation->assertNativeStorage();
    return $this->readState($grant);
  }

  /**
   * Finds live primary records for a field and file, independent of its index.
   *
   * Include records issued before enrollment and under other named classes.
   * Call while holding the host writer fence when using this as coverage proof.
   * Optional limits refuse the scan on overflow.
   *
   * @param string $field
   *   The enrolled field storage ID.
   * @param string|null $file_uuid
   *   Optional UUID of a specific file.
   * @param int|null $max_grants
   *   Maximum matching grants to return.
   * @param int|null $max_primary_rows
   *   Maximum native primary rows to scan, including unrelated fields.
   *
   * @return list<\Drupal\file_gate\ScopedGrant>
   *   Non-secret grant identities, including every class found in scope.
   */
  public function scopedGrants(string $field, ?string $file_uuid = NULL, ?int $max_grants = NULL, ?int $max_primary_rows = NULL): array {
    $participation = $this->requireParticipation();
    if (!$participation->enrolled($field) || $file_uuid === '' || ($max_grants !== NULL && $max_grants < 1)) {
      throw new GrantParticipationException('The requested resource is outside the qualified enrollment.');
    }
    $participation->assertNativeStorage();
    $out = [];
    foreach ($participation->read(self::META_COLLECTION, current: TRUE, max_rows: $max_primary_rows) as $jti => $row) {
      $meta = $row['value'];
      if (!is_array($meta) || !is_string($meta['field'] ?? NULL) || !is_string($meta['f'] ?? NULL)) {
        throw new GrantParticipationException('Primary grant coverage could not be established.');
      }
      if ($meta['field'] === $field && ($file_uuid === NULL || $meta['f'] === $file_uuid)) {
        if ($max_grants !== NULL && count($out) === $max_grants) {
          throw new GrantParticipationException('The matching grants exceeded their qualified limit.');
        }
        $out[] = $this->grantFromMetadata((string) $jti, $meta);
      }
    }
    return $out;
  }

  /**
   * Revokes inside the host's already-open transaction.
   *
   * The result is provisional until the host commits its authority change.
   */
  public function revokeScoped(ScopedGrant $grant): ScopedGrantState {
    return $this->revokeParticipating($grant, NULL, TRUE);
  }

  /**
   * Writes and verifies the full kill horizon before returning.
   */
  private function revokeParticipating(ScopedGrant $grant, ?int $ttl, bool $nested): ScopedGrantState {
    $verified = NULL;
    $verify = $nested ? function () use ($grant, &$verified): bool {
      $verified = $this->readState($grant);
      return $verified->killed && !$verified->metadataPresent;
    } : NULL;
    $ok = $this->requireParticipation()->run('revoke', $grant, function () use ($grant, $ttl, &$verified): bool {
      return $this->runLocked(self::redemptionLockName($grant->jti), function () use ($grant, $ttl, &$verified): bool {
        $state = $this->readState($grant);
        if (!$state->metadataPresent && !$state->killed) {
          return FALSE;
        }
        $now = $this->time->getRequestTime();
        $horizon = max(
          $grant->expiresAt + self::KILL_MARGIN,
          $state->killExpiresAt ?? 0,
          $now + min(GrantParticipation::MAX_STORE_EXPIRY - $now, max(self::MIN_KILL_TTL, $ttl ?? self::DEFAULT_KILL_TTL)),
        );
        $this->redemptionStore()->setWithExpire($grant->jti, PHP_INT_MAX, $horizon - $now);
        $this->killExpiryStore()->setWithExpire($grant->jti, [
          'expires_at' => $horizon,
          'grant' => $grant->coordinates(),
        ], $horizon - $now);
        $this->metaStore()->delete($grant->jti);
        $verified = $this->readState($grant);
        if (!$verified->killed || $verified->metadataPresent || $verified->killExpiresAt < $horizon) {
          throw new GrantParticipationException('The full grant kill horizon could not be verified.');
        }
        return TRUE;
      });
    }, $nested, $verify);
    if (!$ok || $verified === NULL) {
      throw new GrantParticipationException('The enrolled grant could not be revoked.');
    }
    return $verified;
  }

  /**
   * Reads exact identity, usage and both actual kill row horizons.
   */
  private function readState(ScopedGrant $grant): ScopedGrantState {
    $participation = $this->requireParticipation();
    $jti = $grant->jti;
    $primary = $participation->read(self::META_COLLECTION, $jti, TRUE)[$jti] ?? NULL;
    if ($primary !== NULL && (!is_array($primary['value']) || $this->grantFromMetadata($jti, $primary['value'])->coordinates() !== $grant->coordinates()
      || $primary['expires'] < $grant->expiresAt)) {
      throw new GrantParticipationException('The primary grant identity could not be verified.');
    }
    $redemption = $participation->read(self::REDEMPTION_COLLECTION, $jti, TRUE)[$jti] ?? NULL;
    $uses = $redemption['value'] ?? 0;
    if (!is_int($uses) || $uses < 0 || ($redemption !== NULL && $redemption['expires'] < $grant->expiresAt)) {
      throw new GrantParticipationException('The grant counter could not be verified.');
    }
    $mark = $participation->read(self::KILL_EXPIRY_COLLECTION, $jti, TRUE)[$jti] ?? NULL;
    $expiry = $mark['value']['expires_at'] ?? NULL;
    $killed = $uses === PHP_INT_MAX && is_int($expiry)
      && ($mark['value']['grant'] ?? NULL) === $grant->coordinates()
      && $expiry >= $grant->expiresAt + self::KILL_MARGIN
      && $mark['expires'] >= $expiry && $redemption['expires'] >= $expiry;
    return new ScopedGrantState(
      $primary !== NULL,
      $uses,
      $killed,
      $killed ? $expiry : NULL,
      ($primary['value']['transactional'] ?? FALSE) === TRUE,
    );
  }

  /**
   * Chooses primary inventory for enrolled or previously enrolled fields.
   */
  private function usesPrimaryInventory(string $field): bool {
    return $this->participation?->protectsField($field) ?? FALSE;
  }

  /**
   * Converts primary metadata to non-secret coordinates without coercion.
   */
  private function grantFromMetadata(string $jti, array $meta): ScopedGrant {
    if (($meta['jti'] ?? NULL) !== $jti || !is_string($meta['f'] ?? NULL) || !is_string($meta['field'] ?? NULL)
      || !array_key_exists('k', $meta) || ($meta['k'] !== NULL && !is_string($meta['k']))
      || !is_int($meta['exp'] ?? NULL) || !is_int($meta['max'] ?? NULL)
      || (array_key_exists('method', $meta) && !is_string($meta['method']))) {
      throw new GrantParticipationException('The primary grant identity is invalid.');
    }
    return new ScopedGrant($jti, $meta['f'], $meta['field'], $meta['k'], $meta['exp'], $meta['max'], $meta['method'] ?? NULL);
  }

  /**
   * Writes per-JTI metadata with its original expiry.
   */
  private function writeMetadata(ScopedGrant $grant, string $subject_hash, bool $enrolled = FALSE): void {
    $now = $this->time->getRequestTime();
    $meta = $grant->coordinates() + ['sh' => $subject_hash, 'created' => $now];
    if ($enrolled) {
      $meta['transactional'] = TRUE;
    }
    $this->metaStore()->setWithExpire($grant->jti, $meta, max(1, $grant->expiresAt - $now));
  }

  /**
   * Returns the required service without permitting fallback.
   */
  private function requireParticipation(): GrantParticipation {
    return $this->participation ?? throw new GrantParticipationException('The native grant participant is unavailable.');
  }

  /**
   * How long a kill mark for a jti must last, in seconds.
   *
   * The mark is an expiring redemption counter. If it lapses while the grant's
   * signature is still valid, the counter restarts from zero and the revoked
   * URL works again, with the grant already gone from the operator's list. So
   * the mark of a recorded grant always outlives the grant. With no record
   * there is no expiry to read, and the requested or default TTL stands. A
   * mark that already exists is never shortened: the first revoke removed the
   * record, so a repeat revoke is measured against the mark it left.
   *
   * @param string $jti
   *   Grant jti claim value.
   * @param int|null $requested
   *   Caller TTL in seconds, or NULL for DEFAULT_KILL_TTL.
   *
   * @return int
   *   The TTL to store.
   */
  private function killTtl(string $jti, ?int $requested): int {
    $now = $this->time->getRequestTime();
    $ttl = max(self::MIN_KILL_TTL, $requested ?? self::DEFAULT_KILL_TTL);
    $previous = $this->killExpiryStore()->get($jti, 0);
    $ttl = max($ttl, (int) (is_array($previous) ? ($previous['expires_at'] ?? 0) : $previous) - $now);
    $meta = $this->meta($jti);
    $exp = is_array($meta) ? (int) ($meta['exp'] ?? 0) : 0;
    $remaining = $exp - $now;
    if ($remaining <= 0) {
      return $ttl;
    }
    return max($ttl, $remaining + self::KILL_MARGIN);
  }

  /**
   * Removes inventory metadata for a jti (after revoke).
   */
  private function forget(string $jti, string $field = ''): void {
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
   * Kill-mark expiry store.
   */
  private function killExpiryStore(): KeyValueStoreExpirableInterface {
    return $this->keyValueExpirableFactory->get(self::KILL_EXPIRY_COLLECTION);
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
