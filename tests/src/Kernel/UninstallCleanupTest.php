<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\file_gate\Plugin\GateMethod\Otp;
use Drupal\file_gate\Plugin\GateMethod\Token;
use Drupal\file_gate\Service\GrantInventory;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Pins that uninstall deletes this module's leftover grant stores.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class UninstallCleanupTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'file',
    'file_gate',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    // Core module-uninstall hooks delete from these tables.
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installSchema('user', ['users_data']);
    $this->installSchema('file', ['file_usage']);
  }

  /**
   * A token, jti, and OTP row are gone after uninstall.
   */
  public function testUninstallDeletesOwnedCollections(): void {
    $this->expirable(Token::TOKEN_COLLECTION)->setWithExpire('token-row', ['v' => 1], 3600);
    $this->expirable(GrantInventory::META_COLLECTION)->setWithExpire('jti-row', ['jti' => 'jti-row'], 3600);
    $this->expirable(GrantInventory::FIELD_INDEX_COLLECTION)->setWithExpire('field-row', ['jti-row' => 1], 3600);
    $this->expirable(GrantInventory::REDEMPTION_COLLECTION)->setWithExpire('jti-row', 1, 3600);
    $this->expirable(GrantInventory::KILL_EXPIRY_COLLECTION)->setWithExpire('jti-row', 1, 3600);
    $this->expirable(Otp::STORE_COLLECTION)->setWithExpire('otp-row', ['attempts' => 0], 3600);

    // Snapshot names before uninstall: the module PSR-4 is unregistered.
    $collections = $this->ownedCollections();
    foreach ($collections as $collection) {
      $this->assertTrue($this->collectionHasRows($collection), $collection . ' was written.');
    }

    $this->container->get('module_installer')->uninstall(['file_gate']);

    foreach ($collections as $collection) {
      $this->assertFalse($this->collectionHasRows($collection), $collection . ' survived uninstall.');
      $this->assertSame([], $this->expirable($collection)->getAll());
    }
  }

  /**
   * Collections hook_uninstall() is responsible for.
   *
   * @return list<string>
   *   Expirable key-value collection names owned by file_gate.
   */
  private function ownedCollections(): array {
    return [
      Token::TOKEN_COLLECTION,
      GrantInventory::META_COLLECTION,
      GrantInventory::FIELD_INDEX_COLLECTION,
      GrantInventory::REDEMPTION_COLLECTION,
      GrantInventory::KILL_EXPIRY_COLLECTION,
      Otp::STORE_COLLECTION,
    ];
  }

  /**
   * The expirable key/value store for a collection.
   *
   * @param string $collection
   *   The collection name.
   *
   * @return \Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface
   *   The store.
   */
  private function expirable(string $collection): KeyValueStoreExpirableInterface {
    /** @var \Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface $store */
    $store = \Drupal::service('keyvalue.expirable')->get($collection);
    return $store;
  }

  /**
   * Whether key_value_expire still has rows for a collection.
   *
   * @param string $collection
   *   The collection name.
   *
   * @return bool
   *   TRUE when at least one row remains.
   */
  private function collectionHasRows(string $collection): bool {
    $count = (int) \Drupal::database()
      ->select('key_value_expire', 'k')
      ->condition('collection', $collection)
      ->countQuery()
      ->execute()
      ->fetchField();
    return $count > 0;
  }

}
