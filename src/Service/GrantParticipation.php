<?php

declare(strict_types=1);

namespace Drupal\file_gate\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Serialization\SerializationInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Transaction;
use Drupal\Core\Database\Transaction\ClientConnectionTransactionState;
use Drupal\Core\Database\Transaction\TransactionManagerBase;
use Drupal\Core\KeyValueStore\DatabaseStorage;
use Drupal\Core\KeyValueStore\DatabaseStorageExpirable;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\Lock\DatabaseLockBackend;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\Core\ProxyClass\Lock\DatabaseLockBackend as DatabaseLockProxy;
use Drupal\Core\Site\Settings;
use Drupal\file_gate\Exception\GrantParticipationException;
use Drupal\file_gate\GrantParticipantInterface;
use Drupal\file_gate\Plugin\GateMethod\SignedUrl;
use Drupal\file_gate\ScopedGrant;
use Drupal\file_gate_assurance\Plugin\GateMethod\Assurance;

/**
 * Qualifies native grant storage and verifies host transaction participation.
 *
 * @internal
 */
final class GrantParticipation {

  public const SETTINGS_KEY = 'file_gate.transactional_grant_fields';
  public const MAX_STORE_EXPIRY = 2147483647;
  private const TABLE = 'key_value_expire';
  private const METHOD_CLASSES = [
    'signed_url' => SignedUrl::class,
    'assurance' => Assurance::class,
  ];

  /**
   * Constructs the participation service.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly KeyValueExpirableFactoryInterface $factory,
    private readonly TimeInterface $time,
    private readonly SerializationInterface $serializer,
    private readonly LockBackendInterface $lock,
    private readonly ?GrantParticipantInterface $participant = NULL,
  ) {}

  /**
   * Returns whether this field requires transactional grant operations.
   */
  public function enrolled(string $field): bool {
    return array_key_exists($field, $this->enrollment());
  }

  /**
   * Returns whether active settings or a native marker protect the field.
   */
  public function protectsField(string $field): bool {
    if ($field === '' || $this->enrolled($field)) {
      return $field !== '';
    }
    try {
      // Use the same native table even when the site's active factory was
      // replaced. Losing a backend cannot make a protected field ordinary.
      return $this->read(GrantInventory::PRIMARY_FIELDS_COLLECTION, $field) !== [];
    }
    catch (GrantParticipationException $exception) {
      if ($this->database->schema()->tableExists(self::TABLE)) {
        throw $exception;
      }
      // A fresh site with no expirable storage has never persisted a marker.
      return FALSE;
    }
  }

  /**
   * Activates durable fail-closed protection in a caller-owned transaction.
   */
  public function protectField(string $field): void {
    if ($this->participant === NULL || $this->method($field) === NULL || !$this->database->inTransaction()) {
      throw new GrantParticipationException('Field activation requires the enrolled host transaction.');
    }
    $this->assertNativeStorage();
    $this->persistProtection($field);
  }

  /**
   * Returns whether any fields require transactional grant operations.
   */
  public function enabled(): bool {
    return $this->enrollment() !== [];
  }

  /**
   * Returns the exact method configured for an enrolled field.
   */
  public function method(string $field): ?string {
    return $this->qualifiedScope($field)['method'] ?? NULL;
  }

  /**
   * Checks both the plugin ID and the exact qualified PHP implementation.
   */
  public function supportsPlugin(string $method, string $class): bool {
    return (self::METHOD_CLASSES[$method] ?? NULL) === $class;
  }

  /**
   * Validates exact named class and representable original expiry.
   */
  public function assertEnrolledGrant(ScopedGrant $grant): void {
    $this->assertGrantScope($grant, $this->qualifiedScope($grant->field));
  }

  /**
   * Validates coordinates against an active or durable field scope.
   */
  private function assertGrantScope(ScopedGrant $grant, ?array $scope): void {
    if (!is_string($scope['class'] ?? NULL) || $scope['class'] === '' || $scope['class'] !== $grant->grantClass
      || !is_string($scope['method'] ?? NULL) || !isset(self::METHOD_CLASSES[$scope['method']])
      || ($grant->gateMethod !== NULL && $grant->gateMethod !== $scope['method'])
      || $grant->jti === '' || $grant->fileUuid === '' || $grant->maxUses <= 0
      || $grant->expiresAt <= 0 || $grant->expiresAt > self::MAX_STORE_EXPIRY - GrantInventory::KILL_MARGIN) {
      throw new GrantParticipationException('Grant scope is outside the qualified enrollment.');
    }
  }

  /**
   * Verifies an operation joined exactly one live root.
   *
   * @param string $operation
   *   The native operation.
   * @param \Drupal\file_gate\ScopedGrant $grant
   *   The scoped grant.
   * @param \Closure(): bool $effect
   *   The native effect.
   * @param bool $nested
   *   Whether this explicitly provisional revoke joins an existing root.
   * @param \Closure(): bool|null $verify
   *   Optional evidence to verify before a provisional operation returns.
   */
  public function run(string $operation, ScopedGrant $grant, \Closure $effect, bool $nested = FALSE, ?\Closure $verify = NULL): bool {
    $cleanup = $operation === 'cleanup_revoke';
    $participant = $this->participant;
    if ($this->database->inTransaction() !== $nested || (!$cleanup && $participant === NULL)) {
      throw new GrantParticipationException('The native grant transaction is unavailable.');
    }
    $this->assertNativeStorage();
    if ($cleanup) {
      if ($nested || $this->enrolled($grant->field)) {
        throw new GrantParticipationException('Cleanup requires a previously enrolled field.');
      }
      $marker = $this->read(GrantInventory::PRIMARY_FIELDS_COLLECTION, $grant->field)[$grant->field] ?? NULL;
      if ($marker === NULL || $marker['expires'] !== self::MAX_STORE_EXPIRY || !is_array($marker['value'])) {
        throw new GrantParticipationException('Cleanup requires a durable field scope.');
      }
      $this->assertGrantScope($grant, $marker['value']);
    }
    else {
      $this->assertEnrolledGrant($grant);
      if ($operation === 'mint' && $grant->gateMethod === NULL) {
        throw new GrantParticipationException('A qualified grant method is required.');
      }
    }

    $manager = $this->database->transactionManager();
    $client = $this->database->getClientConnection();
    if (!$manager instanceof TransactionManagerBase || !$client instanceof \PDO) {
      throw new GrantParticipationException('The native transaction manager is unavailable.');
    }

    // The participant owns authority and resource locks. File Gate alone
    // owns completion of this root or savepoint, including host writes.
    $boundary = $this->database->startTransaction();
    $stack = array_keys($this->transactionStack($manager));
    $called = FALSE;
    $invalid = FALSE;
    $result = NULL;
    $callbacks = NULL;
    $callback_property = new \ReflectionProperty(TransactionManagerBase::class, 'postTransactionCallbacks');
    try {
      $callbacks = $callback_property->getValue($manager);
      $apply = function () use ($effect, $grant, $cleanup, $manager, $client, $stack, &$called, &$invalid, &$result): bool {
        if ($called || !$client->inTransaction() || array_keys($this->transactionStack($manager)) !== $stack) {
          $invalid = TRUE;
          throw new GrantParticipationException('The native effect requires one active host dispatch.');
        }
        $called = TRUE;
        try {
          $result = $effect();
          if ($result && !$cleanup) {
            $this->persistProtection($grant->field);
          }
          return $result;
        }
        catch (\Throwable $error) {
          $invalid = TRUE;
          throw $error;
        }
      };
      if ($cleanup) {
        $apply();
      }
      else {
        $participant->participate($operation, $grant, $this->database, $apply, $nested);
      }
      if (!$called || $invalid || $result === NULL || !$client->inTransaction()
        || array_keys($this->transactionStack($manager)) !== $stack
        || $callback_property->getValue($manager) !== $callbacks) {
        throw new GrantParticipationException('The native grant operation was not acknowledged.');
      }
      if (!$result) {
        $boundary->rollBack();
        return FALSE;
      }
      if ($verify !== NULL && !$verify()) {
        throw new GrantParticipationException('The native operation did not survive participation.');
      }
      unset($boundary);
      if (!$nested && !$this->nativeCommitSucceeded($manager, $client)) {
        throw new GrantParticipationException('The native grant commit could not be verified.');
      }
      return TRUE;
    }
    catch (\Throwable) {
      if (isset($boundary)) {
        $active = array_keys($this->transactionStack($manager));
        if (array_slice($active, 0, count($stack)) === $stack) {
          if ($callbacks !== NULL) {
            // Refused deferred work must not run when this scope ends.
            $callback_property->setValue($manager, $callbacks);
          }
          if ($client->inTransaction()) {
            $this->rollbackBoundary($manager, $stack, $boundary);
          }
          else {
            $manager->voidClientTransaction();
          }
        }
      }
      throw new GrantParticipationException('The host could not complete the native grant operation.');
    }
  }

  /**
   * Checks the client and core state after the root transaction handle ends.
   */
  private function nativeCommitSucceeded(TransactionManagerBase $manager, \PDO $client): bool {
    // Drupal's transaction-end callback reports TRUE even for an implicit
    // commit. Only a native committed state acknowledges work.
    $state = (new \ReflectionProperty(TransactionManagerBase::class, 'connectionTransactionState'))->getValue($manager);
    return $state === ClientConnectionTransactionState::Committed && !$client->inTransaction();
  }

  /**
   * Identifies live transaction scopes by ID rather than reusable names.
   *
   * @return array<string, \Drupal\Core\Database\Transaction\StackItem>
   *   The exact native root and savepoint stack.
   */
  private function transactionStack(TransactionManagerBase $manager): array {
    return (new \ReflectionMethod(TransactionManagerBase::class, 'stack'))->invoke($manager);
  }

  /**
   * Rolls back this operation, including any savepoint left by the adapter.
   *
   * @param \Drupal\Core\Database\Transaction\TransactionManagerBase $manager
   *   The native transaction manager.
   * @param list<string> $expected
   *   The original transaction stack IDs, through the operation boundary.
   * @param \Drupal\Core\Database\Transaction $boundary
   *   This operation's root or savepoint.
   */
  private function rollbackBoundary(TransactionManagerBase $manager, array $expected, Transaction $boundary): void {
    $stack = $this->transactionStack($manager);
    if (array_slice(array_keys($stack), 0, count($expected)) !== $expected) {
      return;
    }
    foreach (array_reverse(array_slice($stack, count($expected), preserve_keys: TRUE), preserve_keys: TRUE) as $id => $item) {
      $manager->rollback($item->name, $id);
    }
    $boundary->rollBack();
  }

  /**
   * Proves the exact active stores use the qualified native connection.
   *
   * Drupal's native store provides no public connection accessor. An exact
   * class check and the inherited storage properties fail closed on any
   * replacement whose connection, table, serialization or time is uncertain.
   */
  public function assertNativeStorage(): void {
    try {
      foreach ([
        GrantInventory::META_COLLECTION,
        GrantInventory::REDEMPTION_COLLECTION,
        GrantInventory::KILL_EXPIRY_COLLECTION,
        GrantInventory::PRIMARY_FIELDS_COLLECTION,
      ] as $collection) {
        $store = $this->factory->get($collection);
        if ($store::class !== DatabaseStorageExpirable::class || $store->getCollectionName() !== $collection
          || (new \ReflectionProperty(DatabaseStorage::class, 'connection'))->getValue($store) !== $this->database
          || (new \ReflectionProperty(DatabaseStorage::class, 'table'))->getValue($store) !== self::TABLE
          || (new \ReflectionProperty(DatabaseStorage::class, 'serializer'))->getValue($store) !== $this->serializer
          || (new \ReflectionProperty(DatabaseStorageExpirable::class, 'time'))->getValue($store) !== $this->time) {
          throw new GrantParticipationException('The active grant store is not the qualified native store.');
        }
      }
      $lock = $this->lock;
      if ($lock::class === DatabaseLockProxy::class) {
        $lock = (new \ReflectionMethod(DatabaseLockProxy::class, 'lazyLoadItself'))->invoke($lock);
      }
      if ($lock::class !== DatabaseLockBackend::class
        || (new \ReflectionProperty(DatabaseLockBackend::class, 'database'))->getValue($lock) !== $this->database) {
        throw new GrantParticipationException('The per-grant lock must use the native grant connection.');
      }
      $driver = $this->database->databaseType();
      if (!in_array($driver, ['sqlite', 'pgsql', 'mysql'], TRUE)
        || !$this->database->schema()->tableExists(self::TABLE)
        || !$this->database->schema()->tableExists('semaphore')) {
        throw new GrantParticipationException('The grant database or required storage tables are unavailable.');
      }
      if ($driver === 'mysql') {
        $options = $this->database->getConnectionOptions();
        foreach ([self::TABLE, 'semaphore'] as $table) {
          $engine = $this->database->query('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = :schema AND TABLE_NAME = :table', [
            ':schema' => $options['database'],
            ':table' => $this->database->getPrefix() . $table,
          ])->fetchField();
          if ($engine !== 'InnoDB') {
            throw new GrantParticipationException('The native grant storage is not transactional.');
          }
        }
      }
    }
    catch (GrantParticipationException $exception) {
      throw $exception;
    }
    catch (\Throwable) {
      throw new GrantParticipationException('The active grant stores could not be qualified.');
    }
  }

  /**
   * Reads native expirable rows and propagates unreadable or corrupt state.
   *
   * Native key/value methods may treat a missing table as empty. A strict
   * read also returns the actual storage expiry of each counter and mark.
   *
   * @return array<string, array{value: mixed, expires: int}>
   *   The rows, keyed by their exact name.
   */
  public function read(string $collection, ?string $name = NULL, bool $current = FALSE, ?int $max_rows = NULL): array {
    try {
      $query = $this->database->select(self::TABLE, 'kv')
        ->fields('kv', ['collection', 'name', 'value', 'expire'])
        ->condition('collection', $collection)
        ->condition('expire', $this->time->getRequestTime(), '>');
      if ($name !== NULL) {
        $query->condition('name', $name);
      }
      // A MySQL root may already have established a repeatable-read snapshot
      // before waiting on the host fence. Read the current rows under it.
      if ($current && $this->database->inTransaction()) {
        $query->forUpdate();
      }
      if ($max_rows !== NULL) {
        if ($max_rows < 1 || $max_rows === PHP_INT_MAX) {
          throw new GrantParticipationException('The primary scan limit is invalid.');
        }
        $query->range(0, $max_rows + 1);
      }
      $rows = [];
      foreach ($query->execute() as $row) {
        if ($max_rows !== NULL && count($rows) === $max_rows) {
          throw new GrantParticipationException('The primary scan exceeded its qualified limit.');
        }
        if ($row->collection !== $collection || ($name !== NULL && $row->name !== $name)) {
          throw new GrantParticipationException('A stored grant key differs from the requested key.');
        }
        $value = is_resource($row->value) ? stream_get_contents($row->value) : $row->value;
        $rows[$row->name] = [
          'value' => $this->serializer->decode($value),
          'expires' => (int) $row->expire,
        ];
      }
      return $rows;
    }
    catch (GrantParticipationException $exception) {
      throw $exception;
    }
    catch (\Throwable) {
      throw new GrantParticipationException('The native grant state could not be read.');
    }
  }

  /**
   * Keeps the field fail closed after an enrollment change.
   */
  private function persistProtection(string $field): void {
    $collection = GrantInventory::PRIMARY_FIELDS_COLLECTION;
    $scope = $this->qualifiedScope($field);
    $marker = $this->factory->get($collection);
    if (!$marker->has($field)) {
      $marker->setWithExpireIfNotExists($field, $scope, self::MAX_STORE_EXPIRY - $this->time->getRequestTime());
    }
    $row = $this->read($collection, $field)[$field] ?? NULL;
    if ($scope === NULL || $row === NULL || $row['value'] !== $scope || $row['expires'] < self::MAX_STORE_EXPIRY) {
      throw new GrantParticipationException('The durable field protection could not be verified.');
    }
  }

  /**
   * Returns the qualified named class and exact gate method for a field.
   *
   * @return array{class: string, method: string}|null
   *   The scope, or NULL when it is missing or unsupported.
   */
  private function qualifiedScope(string $field): ?array {
    $scope = $this->enrollment()[$field] ?? NULL;
    if (is_string($scope)) {
      $scope = ['class' => $scope, 'method' => 'signed_url'];
    }
    $class = $scope['class'] ?? NULL;
    $method = $scope['method'] ?? NULL;
    if (!is_string($class) || $class === '' || !is_string($method) || !isset(self::METHOD_CLASSES[$method])) {
      return NULL;
    }
    return ['class' => $class, 'method' => $method];
  }

  /**
   * Returns enrollment as configured in trusted server settings.
   */
  private function enrollment(): array {
    $enrollment = Settings::get(self::SETTINGS_KEY, []);
    if (!is_array($enrollment)) {
      throw new GrantParticipationException('Grant enrollment must map fields to named grant classes.');
    }
    return $enrollment;
  }

}
