<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate_mcp\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\entity_test\Entity\EntityTest;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file\FileInterface;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\tool\Tool\ToolBase;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Exercises discovery and direct execution against source governance.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class FileGateToolsKernelTest extends KernelTestBase {

  use UserCreationTrait;

  private const SECRET_ID = 's_public';

  private const SECRET_VALUE = 'material-that-must-never-leave-7Q';

  private const FIELD = 'entity_test.field_whitepaper';

  private const OTHER_FIELD = 'entity_test.field_nda';

  private const READ_TOOLS = ['file_gate_status', 'file_gate_metrics'];

  private const SUBJECT_HASH = '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'audit_chain',
    'mcp_sentinel', 'entity_test', 'file_gate', 'file_gate_mcp',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    // Tool API and MCP Sentinel are optional. A pipeline that does not install
    // them skips here; the GitHub workflow installs both and fails unless
    // these tests ran.
    if (!class_exists(ToolBase::class) || !class_exists(McpGovernedToolBase::class)) {
      $this->markTestSkipped('Tool API and MCP Sentinel are not installed.');
    }
    parent::setUp();
    $this->installSchema('audit_chain', ['audit_chain_log', 'audit_chain_mutex']);
    $this->container->get('database')->insert('audit_chain_mutex')
      ->fields(['id' => 1, 'locked' => 1])->execute();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installEntitySchema('entity_test');
    $this->installSchema('file', ['file_usage']);
    $this->installConfig(['system', 'user', 'field', 'file', 'mcp_sentinel', 'file_gate']);

    $this->setSetting('file_private_path', $this->siteDirectory . '/private');
    $this->container->get('stream_wrapper_manager')
      ->registerWrapper('private', PrivateStream::class, StreamWrapperInterface::WRITE_VISIBLE);
    $this->setSetting('file_gate.secrets', [self::SECRET_ID => self::SECRET_VALUE]);
    $this->config('file_gate.settings')
      ->set('secret_scopes', [self::SECRET_ID => [self::FIELD]])
      ->save();
    $this->createField('field_whitepaper', 'private', TRUE);
    $this->createField('field_nda', 'private', TRUE);
    $this->createField('field_plain', 'private', FALSE);

    $role = Role::load('mcp_api') ?? Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context')
      ->grantPermission('use file gate mcp tools')
      ->save();
    $this->config('mcp_sentinel.settings')->set('governed_role_fallback', TRUE)->save();
    $this->setUpCurrentUser(['roles' => ['mcp_api']]);
  }

  /**
   * Read tools run for a governed account and refuse an anonymous one.
   */
  public function testGovernedToolsAndAnonymousDenial(): void {
    $account = $this->container->get('current_user')->getAccount();
    foreach (self::READ_TOOLS as $id) {
      $this->container->get('current_user')->setAccount($account);
      $tool = $this->tool($id);
      self::assertTrue($tool->discoveryAccess($account)->isAllowed(), $id);
      self::assertTrue($tool->access(), $id);
      $tool->execute();
      self::assertTrue($tool->getResultStatus(), $id . ': ' . $tool->getResultMessage());
      self::assertNotEmpty($tool->getResult()->getContextValues(), $id);

      $this->container->get('current_user')->setAccount(new AnonymousUserSession());
      $denied = $this->tool($id);
      self::assertFalse($denied->discoveryAccess(new AnonymousUserSession())->isAllowed(), $id);
      self::assertFalse($denied->access(), $id);
      $denied->execute();
      self::assertFalse($denied->getResultStatus(), $id);
      self::assertEmpty($denied->getResult()->getContextValues(), $id);
    }
  }

  /**
   * Sentinel access alone does not grant the module's tools.
   */
  public function testModulePermissionIsRequired(): void {
    Role::load('mcp_api')->revokePermission('use file gate mcp tools')
      ->grantPermission('revoke file gate grants via mcp')->save();
    $account = $this->container->get('current_user');
    foreach ([...self::READ_TOOLS, 'file_gate_file_gate', 'file_gate_grants_list', 'file_gate_grant_revoke'] as $id) {
      $tool = $this->tool($id);
      self::assertFalse($tool->discoveryAccess($account)->isAllowed(), $id);
      self::assertFalse($tool->access(), $id);
      $tool->execute();
      self::assertFalse($tool->getResultStatus(), $id);
      self::assertEmpty($tool->getResult()->getContextValues(), $id);
    }
  }

  /**
   * Disabled auditing makes governance not ready, so every tool refuses.
   */
  public function testGovernanceNotReadyRefusesDirectExecution(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $tool = $this->tool('file_gate_status');
    self::assertFalse($tool->discoveryAccess($this->container->get('current_user'))->isAllowed());
    self::assertFalse($tool->access());
    $tool->execute();
    self::assertFalse($tool->getResultStatus());
    self::assertEmpty($tool->getResult()->getContextValues());
  }

  /**
   * Status names secrets by id, flags an unprotected field, leaks no material.
   */
  public function testStatusReportsFieldsAndNeverSecretMaterial(): void {
    $this->createField('field_leaky', 'public', TRUE);
    $tool = $this->tool('file_gate_status');
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $values = $tool->getResult()->getContextValues();

    self::assertTrue($values['any_secret_configured']);
    self::assertSame([['id' => self::SECRET_ID, 'has_field_scope' => TRUE]], $values['named_secrets']);
    $by_storage = array_column($values['gated_fields'], NULL, 'storage');
    self::assertTrue($by_storage[self::FIELD]['protected']);
    self::assertSame('signed_url', $by_storage[self::FIELD]['method']);
    self::assertFalse($by_storage['entity_test.field_leaky']['protected']);
    self::assertArrayNotHasKey('entity_test.field_plain', $by_storage);
    self::assertArrayNotHasKey('config_id', $by_storage[self::FIELD]);
    self::assertTrue($values['findings_available']);
    self::assertContains('file_gate_public_gated_fields', array_column($values['findings'], 'id'));
    self::assertStringNotContainsString(self::SECRET_VALUE, json_encode($values));
  }

  /**
   * Lookup explains the gate without a path, a URL or method settings.
   */
  public function testLookupExplainsTheGateWithoutPaths(): void {
    $gated = $this->createFile('field_whitepaper', 'board-minutes-7Q.pdf');
    $plain = $this->createFile('field_plain', 'open-7Q.pdf');

    $tool = $this->tool('file_gate_file_gate');
    $tool->setInputValue('file', $gated->uuid());
    self::assertTrue($tool->access());
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $values = $tool->getResult()->getContextValues();
    self::assertTrue($values['found']);
    self::assertTrue($values['gated']);
    self::assertSame(self::FIELD, $values['field']);
    self::assertSame('signed_url', $values['method']);
    self::assertFalse($values['system_files_url_serves_it']);
    $json = json_encode($values);
    foreach (['7Q', 'private://', 'system/files/', 'max_uses', 'settings'] as $forbidden) {
      self::assertStringNotContainsString($forbidden, $json, $forbidden);
    }

    $tool = $this->tool('file_gate_file_gate');
    $tool->setInputValue('file', $plain->uuid());
    $tool->execute();
    $values = $tool->getResult()->getContextValues();
    self::assertFalse($values['gated']);
    self::assertTrue($values['system_files_url_serves_it']);

    $tool = $this->tool('file_gate_file_gate');
    $tool->setInputValue('file', '00000000-0000-4000-8000-000000000000');
    $tool->execute();
    self::assertTrue($tool->getResultStatus());
    self::assertSame(['found' => FALSE], $tool->getResult()->getContextValues());
  }

  /**
   * Lookup needs exactly one well-formed target.
   */
  public function testLookupRefusesBadTargets(): void {
    $file = $this->createFile('field_whitepaper', 'one.pdf');
    $cases = [
      [],
      ['file' => $file->uuid(), 'media' => $file->uuid()],
      ['file' => 'not-a-uuid-7Q'],
    ];
    foreach ($cases as $inputs) {
      $tool = $this->tool('file_gate_file_gate');
      try {
        foreach ($inputs as $name => $value) {
          $tool->setInputValue($name, $value);
        }
        $tool->execute();
      }
      catch (\Throwable) {
        // A typed-data refusal at input time is as good as one at execute.
        continue;
      }
      self::assertFalse($tool->getResultStatus(), json_encode($inputs));
      self::assertStringNotContainsString('7Q', (string) $tool->getResultMessage());
      self::assertEmpty($tool->getResult()->getContextValues());
    }
  }

  /**
   * Grants are listed for a gated field only.
   */
  public function testGrantsListIsScopedToGatedFields(): void {
    $this->recordGrant('aaaaaaaaaaaaaaaaaaaaaaaa', self::FIELD);
    $this->recordGrant('bbbbbbbbbbbbbbbbbbbbbbbb', self::OTHER_FIELD);

    $tool = $this->tool('file_gate_grants_list');
    $tool->setInputValue('field', self::FIELD);
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $values = $tool->getResult()->getContextValues();
    self::assertSame(1, $values['total']);
    self::assertFalse($values['truncated']);
    self::assertSame('aaaaaaaaaaaaaaaaaaaaaaaa', $values['grants'][0]['grant_id']);
    self::assertSame(self::SECRET_ID, $values['grants'][0]['secret_id']);
    self::assertTrue($values['grants'][0]['subject_bound']);
    self::assertArrayNotHasKey('subject_hash', $values['grants'][0]);
    self::assertStringNotContainsString(self::SUBJECT_HASH, json_encode($values));
    self::assertStringNotContainsString(self::SECRET_VALUE, json_encode($values));

    $tool = $this->tool('file_gate_grants_list');
    $tool->setInputValue('field', 'entity_test.field_plain');
    $tool->execute();
    self::assertFalse($tool->getResultStatus());
    self::assertEmpty($tool->getResult()->getContextValues());
  }

  /**
   * Revoke needs its own permission and the grant's own field.
   */
  public function testRevokeNeedsPermissionAndMatchingField(): void {
    $jti = 'cccccccccccccccccccccccc';
    $this->recordGrant($jti, self::FIELD);
    $inventory = $this->container->get('file_gate.grant_inventory');
    $account = $this->container->get('current_user');

    $tool = $this->revokeTool(self::FIELD, $jti);
    self::assertFalse($tool->discoveryAccess($account)->isAllowed());
    self::assertFalse($tool->access());
    $tool->execute();
    self::assertFalse($tool->getResultStatus());
    self::assertNotNull($inventory->meta($jti));

    Role::load('mcp_api')->grantPermission('revoke file gate grants via mcp')->save();

    $tool = $this->revokeTool(self::OTHER_FIELD, $jti);
    self::assertTrue($tool->access());
    $tool->execute();
    self::assertFalse($tool->getResultStatus(), 'A grant from another field must be refused.');
    self::assertNotNull($inventory->meta($jti));

    $tool = $this->revokeTool(self::FIELD, 'dddddddddddddddddddddddd');
    $tool->execute();
    self::assertFalse($tool->getResultStatus(), 'An unknown grant must be refused.');

    $tool = $this->revokeTool(self::FIELD, $jti);
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    self::assertSame(['revoked' => TRUE, 'field' => self::FIELD], $tool->getResult()->getContextValues());
    self::assertNull($inventory->meta($jti));
    self::assertSame([], $inventory->listForField(self::FIELD));
  }

  /**
   * The kill mark outlives a grant that expires after the default 30 days.
   */
  public function testRevokeKillMarkOutlivesLongGrant(): void {
    Role::load('mcp_api')->grantPermission('revoke file gate grants via mcp')->save();
    $jti = 'eeeeeeeeeeeeeeeeeeeeeeee';
    $lifetime = 86400 * 90;
    $this->recordGrant($jti, self::FIELD, $lifetime);
    $tool = $this->revokeTool(self::FIELD, $jti);
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());

    // The redemption store is the only expirable collection holding the id
    // after revoke: revoke forgets the inventory row.
    $row = $this->container->get('database')->select('key_value_expire', 'k')
      ->fields('k', ['expire'])
      ->condition('name', $jti)
      ->execute()->fetchField();
    self::assertNotFalse($row, 'The kill mark is stored.');
    $now = $this->container->get('datetime.time')->getRequestTime();
    self::assertGreaterThanOrEqual($now + $lifetime, (int) $row);
  }

  /**
   * A media UUID on a site without Media is simply not found.
   */
  public function testLookupByMediaUuidNeedsNoMediaModule(): void {
    $tool = $this->tool('file_gate_file_gate');
    $tool->setInputValue('media', '00000000-0000-4000-8000-000000000001');
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    self::assertSame(['found' => FALSE], $tool->getResult()->getContextValues());
  }

  /**
   * Creates a fresh tool instance.
   */
  private function tool(string $id): object {
    return $this->container->get('plugin.manager.tool')->createInstance($id);
  }

  /**
   * Builds a revoke tool with both inputs set.
   */
  private function revokeTool(string $field, string $jti): object {
    $tool = $this->tool('file_gate_grant_revoke');
    $tool->setInputValue('field', $field);
    $tool->setInputValue('grant_id', $jti);
    return $tool;
  }

  /**
   * Records one live usage-limited grant.
   */
  private function recordGrant(string $jti, string $field, int $lifetime = 3600): void {
    $this->container->get('file_gate.grant_inventory')->record(
      $jti,
      '11111111-1111-4111-8111-111111111111',
      $field,
      $this->container->get('datetime.time')->getRequestTime() + $lifetime,
      self::SECRET_ID,
      2,
      self::SUBJECT_HASH,
    );
  }

  /**
   * Creates a file field on entity_test.
   */
  private function createField(string $field_name, string $scheme, bool $gated): void {
    $storage = FieldStorageConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => $field_name,
      'type' => 'file',
      'settings' => ['uri_scheme' => $scheme],
    ]);
    $gate = [
      'gated' => TRUE,
      'method' => 'signed_url',
      'method_settings' => ['max_uses' => 2],
    ];
    if ($gated && $scheme === 'private') {
      foreach ($gate as $key => $value) {
        $storage->setThirdPartySetting('file_gate', $key, $value);
      }
    }
    $storage->save();
    if ($gated && $scheme !== 'private') {
      // A save that gates a non-private scheme is refused. A site that was
      // already in that state is reproduced by writing the active storage
      // directly, which runs no entity hook and no config event.
      $name = 'field.storage.entity_test.' . $field_name;
      $active = $this->container->get('config.storage');
      $data = $active->read($name);
      $data['third_party_settings']['file_gate'] = $gate;
      $data['dependencies']['module'][] = 'file_gate';
      sort($data['dependencies']['module']);
      $active->write($name, $data);
      $this->container->get('config.factory')->reset($name);
      $this->container->get('entity_type.manager')->getStorage('field_storage_config')->resetCache();
    }
    FieldConfig::create([
      'entity_type' => 'entity_test',
      'field_name' => $field_name,
      'bundle' => 'entity_test',
    ])->save();
  }

  /**
   * Creates a private file referenced from the given field.
   */
  private function createFile(string $field_name, string $filename): FileInterface {
    $directory = 'private://docs';
    $this->container->get('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);
    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();
    $entity = EntityTest::create(['name' => 'host', $field_name => ['target_id' => $file->id()]]);
    $entity->save();
    $this->container->get('file.usage')->add($file, 'file', 'entity_test', (string) $entity->id());
    return $file;
  }

}
