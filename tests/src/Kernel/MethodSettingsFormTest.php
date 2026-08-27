<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\file_gate\GateMethodInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests each gate method's per-field settings form (build + submit mapping).
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class MethodSettingsFormTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'field', 'file', 'file_gate'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['file_gate']);
  }

  /**
   * A method instance.
   *
   * @param string $id
   *   The gate method plugin id.
   *
   * @return \Drupal\file_gate\GateMethodInterface
   *   The instance.
   */
  private function method(string $id): GateMethodInterface {
    return $this->container->get('plugin.manager.file_gate.gate_method')->createInstance($id, []);
  }

  /**
   * Signed URL exposes and round-trips ttl / available_until / max_uses.
   */
  public function testSignedUrlSettings(): void {
    $method = $this->method('signed_url');
    $form = $method->fieldSettingsForm(['ttl' => 300, 'max_uses' => 1]);
    $this->assertArrayHasKey('ttl', $form);
    $this->assertSame(300, $form['ttl']['#default_value']);

    $settings = $method->fieldSettingsSubmit(['ttl' => '300', 'available_until' => '0', 'max_uses' => '1']);
    $this->assertSame(
      [
        'ttl' => 300,
        'available_until' => 0,
        'max_uses' => 1,
        'require_identity_mint' => FALSE,
      ],
      $settings,
    );
  }

  /**
   * Every mintable method exposes and round-trips require_identity_mint.
   *
   * Regression test for drupal.org issue 3619534: the setting is enforced by
   * the mint controller for every method, but the non-assurance submit
   * handlers rebuilt their settings from their own form values alone — so a
   * config-imported TRUE was silently stripped by any form save, downgrading
   * identity-bound grants to unbound ones without a trace.
   */
  public function testIdentityMintSettingSurvivesFormRoundTrip(): void {
    foreach (['signed_url', 'token', 'referrer_lock'] as $id) {
      $method = $this->method($id);

      $form = $method->fieldSettingsForm(['require_identity_mint' => TRUE]);
      $this->assertArrayHasKey('require_identity_mint', $form, $id);
      $this->assertSame('checkbox', $form['require_identity_mint']['#type'], $id);
      $this->assertTrue($form['require_identity_mint']['#default_value'], $id);

      // The form-shaped save of an enabled flag keeps it enabled…
      $settings = $method->fieldSettingsSubmit([
        'ttl' => '120',
        'available_until' => '0',
        'max_uses' => '1',
        'require_identity_mint' => 1,
      ]);
      $this->assertTrue($settings['require_identity_mint'], $id);

      // …and clearing the checkbox genuinely clears it (no sticky TRUE).
      $settings = $method->fieldSettingsSubmit([
        'ttl' => '120',
        'available_until' => '0',
        'max_uses' => '1',
      ]);
      $this->assertFalse($settings['require_identity_mint'], $id);
    }
  }

  /**
   * Token parses the pre-shared hash textarea into a clean list.
   */
  public function testTokenSettingsParsesHashes(): void {
    $settings = $this->method('token')->fieldSettingsSubmit([
      'ttl' => '0',
      'available_until' => '0',
      'max_uses' => '0',
      'tokens' => "aaa\n  bbb  \n\nccc",
    ]);
    $this->assertSame(['aaa', 'bbb', 'ccc'], $settings['tokens']);
  }

  /**
   * Referrer lock inherits signed_url's fields and adds the origin allowlist.
   */
  public function testReferrerLockSettings(): void {
    $method = $this->method('referrer_lock');
    $form = $method->fieldSettingsForm([]);
    $this->assertArrayHasKey('ttl', $form);
    $this->assertArrayHasKey('allowed_origins', $form);

    $settings = $method->fieldSettingsSubmit([
      'ttl' => '0',
      'available_until' => '0',
      'max_uses' => '0',
      'allowed_origins' => "https://a.example\nhttps://b.example",
      'on_missing_referrer' => 'allow',
    ]);
    $this->assertSame(['https://a.example', 'https://b.example'], $settings['allowed_origins']);
    $this->assertSame('allow', $settings['on_missing_referrer']);
  }

  /**
   * Authenticated exposes an optional role allowlist.
   */
  public function testAuthenticatedRoleAllowlistSettings(): void {
    $form = $this->method('authenticated')->fieldSettingsForm([]);
    $this->assertArrayHasKey('roles', $form);
    $this->assertSame('textarea', $form['roles']['#type']);
    $this->assertSame('', $form['roles']['#default_value']);

    $settings = $this->method('authenticated')->fieldSettingsSubmit([
      'roles' => "member\npremium",
    ]);
    $this->assertSame(['member', 'premium'], $settings['roles']);
  }

}
