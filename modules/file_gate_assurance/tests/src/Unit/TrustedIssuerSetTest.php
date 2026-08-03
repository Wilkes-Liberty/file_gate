<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate_assurance\Unit;

use Drupal\Tests\UnitTestCase;
use Drupal\file_gate_assurance\TrustedIssuerSet;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests trusted-issuer settings normalization and fail-closed validity.
 *
 * @coversDefaultClass \Drupal\file_gate_assurance\TrustedIssuerSet
 */
#[Group('file_gate')]
final class TrustedIssuerSetTest extends UnitTestCase {

  /**
   * Legacy single keys map to a one-entry list, trimmed and normalized.
   */
  public function testLegacySingleKeysMapToOneEntry(): void {
    $set = TrustedIssuerSet::fromSettings([
      'issuer' => ' https://idp.example ',
      'audience' => ' file-gate ',
      'required_acr' => ['aal3', ' aal2 ', ''],
    ]);
    $this->assertTrue($set->isValid());
    $entries = $set->entries();
    $this->assertCount(1, $entries);
    $this->assertSame('https://idp.example', $entries[0]->issuer);
    $this->assertSame('file-gate', $entries[0]->audience);
    $this->assertSame(['aal3', 'aal2'], $entries[0]->requiredAcr);
  }

  /**
   * Legacy shape without an issuer parses to an empty, invalid set.
   */
  public function testLegacyWithoutIssuerIsInvalid(): void {
    $set = TrustedIssuerSet::fromSettings([
      'audience' => 'file-gate',
      'required_acr' => ['aal3'],
    ]);
    $this->assertFalse($set->isValid());
    $this->assertSame([], $set->entries());
    $this->assertNull($set->match('https://idp.example'));
  }

  /**
   * A non-empty trusted_issuers list wins over the legacy keys.
   */
  public function testTrustedIssuersWinsOverLegacyKeys(): void {
    $set = TrustedIssuerSet::fromSettings([
      'issuer' => 'https://legacy.example',
      'audience' => 'legacy-aud',
      'required_acr' => ['legacy-acr'],
      'trusted_issuers' => [
        [
          'issuer' => 'https://idp.example',
          'audience' => 'file-gate',
          'required_acr' => ['aal3'],
        ],
      ],
    ]);
    $this->assertTrue($set->isValid());
    $this->assertCount(1, $set->entries());
    $this->assertNull($set->match('https://legacy.example'));
    $this->assertNotNull($set->match('https://idp.example'));
  }

  /**
   * Newline-separated acr strings normalize like the settings form submit.
   */
  public function testNewlineStringAcrParsing(): void {
    $set = TrustedIssuerSet::fromSettings([
      'trusted_issuers' => [
        [
          'issuer' => 'https://idp.example',
          'audience' => 'file-gate',
          'required_acr' => "aal3\r\n aal2 \n\naal1",
        ],
      ],
    ]);
    $this->assertSame(['aal3', 'aal2', 'aal1'], $set->entries()[0]->requiredAcr);
  }

  /**
   * Duplicate issuers invalidate the whole set — never "first wins".
   */
  public function testDuplicateIssuersInvalidateTheSet(): void {
    $set = TrustedIssuerSet::fromSettings([
      'trusted_issuers' => [
        [
          'issuer' => 'https://idp.example',
          'audience' => 'file-gate',
          'required_acr' => ['aal3'],
        ],
        [
          'issuer' => 'https://idp.example',
          'audience' => 'other-audience',
          'required_acr' => ['aal2'],
        ],
      ],
    ]);
    $this->assertFalse($set->isValid());
    // No match while invalid, even for the issuer both entries name.
    $this->assertNull($set->match('https://idp.example'));
  }

  /**
   * An entry missing its issuer or audience invalidates the whole set.
   */
  public function testIncompleteEntryInvalidatesTheSet(): void {
    $missing_audience = TrustedIssuerSet::fromSettings([
      'trusted_issuers' => [
        ['issuer' => 'https://idp.example', 'audience' => '', 'required_acr' => ['aal3']],
      ],
    ]);
    $this->assertFalse($missing_audience->isValid());

    $missing_issuer = TrustedIssuerSet::fromSettings([
      'trusted_issuers' => [
        ['issuer' => '', 'audience' => 'file-gate', 'required_acr' => ['aal3']],
      ],
    ]);
    $this->assertFalse($missing_issuer->isValid());

    // A malformed (non-array) entry keeps its slot and fails the set closed
    // instead of silently shrinking it to the well-formed rows.
    $malformed = TrustedIssuerSet::fromSettings([
      'trusted_issuers' => [
        ['issuer' => 'https://idp.example', 'audience' => 'file-gate', 'required_acr' => ['aal3']],
        'garbage',
      ],
    ]);
    $this->assertFalse($malformed->isValid());
    $this->assertNull($malformed->match('https://idp.example'));
  }

  /**
   * Matching is byte-exact on the issuer with no normalization.
   */
  public function testMatchIsByteExact(): void {
    $set = TrustedIssuerSet::fromSettings([
      'trusted_issuers' => [
        ['issuer' => 'https://idp.example', 'audience' => 'a', 'required_acr' => ['aal3']],
        ['issuer' => 'https://idp-b.example', 'audience' => 'b', 'required_acr' => ['aal2']],
      ],
    ]);
    $this->assertSame('a', $set->match('https://idp.example')?->audience);
    $this->assertSame('b', $set->match('https://idp-b.example')?->audience);
    // No trailing-slash, case, or prefix leniency.
    $this->assertNull($set->match('https://idp.example/'));
    $this->assertNull($set->match('https://IDP.example'));
    $this->assertNull($set->match('https://idp.exampleX'));
  }

  /**
   * The acr union deduplicates across entries and keeps strings intact.
   */
  public function testAcrUnionDeduplicates(): void {
    $set = TrustedIssuerSet::fromSettings([
      'trusted_issuers' => [
        ['issuer' => 'https://idp.example', 'audience' => 'a', 'required_acr' => ['aal3', '3']],
        ['issuer' => 'https://idp-b.example', 'audience' => 'b', 'required_acr' => ['aal3', 'aal2']],
      ],
    ]);
    // Deduplicated across entries, and numeric-looking acr values stay
    // strings (strict comparisons downstream).
    $this->assertSame(['aal3', '3', 'aal2'], $set->acrUnion());
  }

  /**
   * An empty settings array parses to an empty, invalid set.
   */
  public function testEmptySettingsAreInvalid(): void {
    $set = TrustedIssuerSet::fromSettings([]);
    $this->assertFalse($set->isValid());
    $this->assertSame([], $set->entries());
    $this->assertSame([], $set->acrUnion());
  }

}
