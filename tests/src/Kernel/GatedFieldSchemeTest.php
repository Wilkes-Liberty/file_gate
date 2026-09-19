<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\Extension\Requirement\RequirementSeverity;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * A field cannot claim to be gated while storing files publicly.
 *
 * This is the module's worst state, and the one that looks least wrong: the
 * configuration says the files are gated, the field UI shows them as gated, and
 * they are readable by anyone with the URL. Nothing errors, because nothing is
 * broken — gating only applies to the private file system, so the gate simply
 * never engages.
 *
 * The field edit form prevents it by forcing the private scheme, but that is a
 * form alter and a config-import-authoritative deploy never runs it.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class GatedFieldSchemeTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'field', 'file', 'file_gate'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
  }

  /**
   * Creates a file field storage.
   *
   * @param string $name
   *   The field name.
   * @param string $scheme
   *   The uri_scheme storage setting.
   * @param bool $gated
   *   Whether to mark it gated.
   *
   * @return \Drupal\field\Entity\FieldStorageConfig
   *   The saved storage.
   */
  private function makeStorage(string $name, string $scheme, bool $gated): FieldStorageConfig {
    $storage = FieldStorageConfig::create([
      'field_name' => $name,
      'entity_type' => 'user',
      'type' => 'file',
      'settings' => ['uri_scheme' => $scheme],
    ]);
    if ($gated) {
      $storage->setThirdPartySetting('file_gate', 'gated', TRUE);
      $storage->setThirdPartySetting('file_gate', 'method', 'signed_url');
    }
    $storage->save();
    return $storage;
  }

  /**
   * The runtime requirements, asked for the way the status report asks.
   *
   * Through the module handler, not by calling an implementation: a direct
   * call passes whether or not core still invokes the hook, which is how a
   * security finding could leave the status report with every test green.
   * Only this module's implementation is asked for; the System module's needs
   * install-time functions a kernel test does not load.
   *
   * @return array<string, array<string, mixed>>
   *   Requirements keyed by id.
   */
  private function runtimeRequirements(): array {
    return $this->container->get('module_handler')->invoke('file_gate', 'runtime_requirements') ?? [];
  }

  /**
   * A healthy site reports nothing.
   */
  public function testNoFindingWhenGatedFieldsArePrivate(): void {
    $this->makeStorage('field_ok_private', 'private', TRUE);
    $this->makeStorage('field_ok_public', 'public', FALSE);

    $this->assertArrayNotHasKey('file_gate_public_gated_fields', $this->runtimeRequirements());
  }

  /**
   * A gated public field is reported as an error, naming the field.
   *
   * At ERROR rather than WARNING: the module's single promise is that these
   * files are not publicly readable, and while this holds they are.
   */
  public function testGatedPublicFieldIsReportedAsAnError(): void {
    $this->makeStorage('field_leaky', 'public', TRUE);

    $requirements = $this->runtimeRequirements();

    $this->assertArrayHasKey('file_gate_public_gated_fields', $requirements);
    $this->assertSame(
      RequirementSeverity::Error,
      $requirements['file_gate_public_gated_fields']['severity'],
    );
    $this->assertStringContainsString(
      'field_leaky',
      (string) $requirements['file_gate_public_gated_fields']['value'],
      'The finding must name the field so an operator can act on it.',
    );
  }

  /**
   * The procedural hook is gone, so nothing depends on core still calling it.
   */
  public function testTheLegacyProceduralHookIsRemoved(): void {
    $this->container->get('module_handler')->loadInclude('file_gate', 'install');

    $this->assertFalse(function_exists('file_gate_requirements'));
  }

  /**
   * An ungated public field is normal and must not be reported.
   *
   * Most file fields on most sites are exactly this, so a false positive here
   * would make the check noise and get it ignored.
   */
  public function testUngatedPublicFieldIsNotReported(): void {
    $this->makeStorage('field_plain', 'public', FALSE);

    $this->assertArrayNotHasKey('file_gate_public_gated_fields', $this->runtimeRequirements());
  }

  /**
   * The resolver declines to gate a public file, which is what makes it unsafe.
   *
   * Pins the behaviour the two guards exist to compensate for: a gated field on
   * the public scheme produces no gate at all, silently. If this ever started
   * returning a gate, the guards would be redundant rather than load-bearing —
   * and a future reader should be able to tell which.
   */
  public function testResolverReturnsNoGateForPublicFiles(): void {
    $this->makeStorage('field_leaky', 'public', TRUE);

    $file = $this->container->get('entity_type.manager')->getStorage('file')->create([
      'uri' => 'public://leaky.pdf',
      'filename' => 'leaky.pdf',
    ]);
    $file->save();

    $this->assertNull(
      $this->container->get('file_gate.resolver')->getGateForFile($file),
      'A public file is never gated, however the field is configured.',
    );
  }

}
