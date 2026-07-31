<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\WebAuthn;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;

/**
 * Persistence for native WebAuthn credentials.
 *
 * Credentials are keyed by a stable user_handle (Drupal uid as string, or an
 * external subject the mint caller asserts). The credential public key and
 * signature counter are stored for assertion verification.
 */
final class WebAuthnCredentialStorage {

  /**
   * Table name.
   */
  public const TABLE = 'file_gate_webauthn_credential';

  /**
   * Constructs the storage.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Lists credentials for a user handle.
   *
   * @param string $user_handle
   *   Opaque handle (uid string or subject).
   *
   * @return list<array<string, mixed>>
   *   Credential rows.
   */
  public function loadByUserHandle(string $user_handle): array {
    if ($user_handle === '') {
      return [];
    }
    $result = $this->database->select(self::TABLE, 'c')
      ->fields('c')
      ->condition('user_handle', $user_handle)
      ->orderBy('id')
      ->execute();
    $rows = [];
    while ($row = $result->fetchAssoc()) {
      $rows[] = $row;
    }
    return $rows;
  }

  /**
   * Loads one credential by base64url credential id.
   *
   * @return array<string, mixed>|null
   *   Row or NULL.
   */
  public function loadByCredentialId(string $credential_id): ?array {
    if ($credential_id === '') {
      return NULL;
    }
    $row = $this->database->select(self::TABLE, 'c')
      ->fields('c')
      ->condition('credential_id', $credential_id)
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    return $row ? (array) $row : NULL;
  }

  /**
   * Inserts a newly registered credential.
   *
   * @param array $record
   *   Fields: user_handle, credential_id, public_key, counter, optional
   *   transports, label, uid.
   *
   * @return int
   *   Insert id.
   */
  public function insert(array $record): int {
    $now = $this->time->getRequestTime();
    return (int) $this->database->insert(self::TABLE)
      ->fields([
        'user_handle' => $record['user_handle'],
        'credential_id' => $record['credential_id'],
        'public_key' => $record['public_key'],
        'counter' => (int) $record['counter'],
        'transports' => $record['transports'] ?? '[]',
        'label' => $record['label'] ?? '',
        'uid' => $record['uid'] ?? NULL,
        'created' => $now,
        'changed' => $now,
      ])
      ->execute();
  }

  /**
   * Updates the signature counter after a successful assertion.
   */
  public function updateCounter(string $credential_id, int $counter): void {
    $this->database->update(self::TABLE)
      ->fields([
        'counter' => $counter,
        'changed' => $this->time->getRequestTime(),
      ])
      ->condition('credential_id', $credential_id)
      ->execute();
  }

  /**
   * Deletes a credential.
   */
  public function delete(string $credential_id): void {
    $this->database->delete(self::TABLE)
      ->condition('credential_id', $credential_id)
      ->execute();
  }

}
