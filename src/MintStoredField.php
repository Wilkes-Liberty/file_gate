<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\file_gate\Plugin\GateMethod\Token;
use Drupal\file_gate\Service\GrantInventory;
use Symfony\Component\HttpFoundation\Request;

/**
 * Reads the field storage key persisted at mint from a redeem request.
 *
 * Unpinned getGateForFile() picks the lexicographic winner among equal-
 * strictness methods. Redeem must pin to the field stored on the grant row
 * (inventory jti or token hash) or the HMAC-bound `fld` claim so
 * allowsField() matches the minted scope. Unlimited signed_url grants have
 * no inventory row and carry `fld` instead.
 */
final class MintStoredField {

  /**
   * Constructs the reader.
   *
   * @param \Drupal\file_gate\Service\GrantInventory $grantInventory
   *   Signed-url jti inventory (field stored at mint).
   * @param \Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface $keyValueExpirableFactory
   *   The expirable key/value factory (token store).
   */
  public function __construct(
    private readonly GrantInventory $grantInventory,
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
  ) {}

  /**
   * Field storage id from the grant row or an authenticated request body.
   *
   * Prefers inventory / token store (the mint-persisted row) over a JSON
   * body "field" used by OTP issue and session establish.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The redeem, bridge, OTP, or WebAuthn request.
   *
   * @return string|null
   *   entity_type.field_name, or NULL when no mint-stored field is present.
   */
  public function fromRequest(Request $request): ?string {
    $jti = trim((string) $request->query->get('jti', ''));
    if ($jti !== '') {
      $field = $this->fieldFromRow($this->grantInventory->meta($jti));
      if ($field !== NULL) {
        return $field;
      }
    }

    $token = (string) $request->query->get('token', '');
    if ($token !== '') {
      $record = $this->keyValueExpirableFactory->get(Token::TOKEN_COLLECTION)
        ->get(hash('sha256', $token));
      $field = $this->fieldFromRow(is_array($record) ? $record : NULL);
      if ($field !== NULL) {
        return $field;
      }
    }

    $content = $request->getContent();
    if ($content !== '') {
      $data = json_decode($content, TRUE);
      if (is_array($data) && !empty($data['field']) && is_string($data['field'])) {
        $field = trim($data['field']);
        if ($field !== '') {
          return $field;
        }
      }
    }

    return NULL;
  }

  /**
   * Field storage id from the signed `fld` query claim.
   *
   * Resolver hint only. Authorizing callers must HMAC-validate the claim
   * (SignedUrl::signatureValid) so a forged `fld` fails closed. Do not treat
   * an unsigned `field` query parameter as a pin.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The redeem request.
   *
   * @return string|null
   *   entity_type.field_name, or NULL when `fld` is absent.
   */
  public function fromSignedClaim(Request $request): ?string {
    $fld = trim((string) $request->query->get('fld', ''));
    return $fld !== '' ? $fld : NULL;
  }

  /**
   * Prefer the grant-row pin; fall back to the signed `fld` claim.
   *
   * Limited jti/token/OTP paths keep using fromRequest(). Unlimited
   * signed_url grants have no inventory row and carry `fld` instead.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The redeem, bridge, or WebAuthn request.
   *
   * @return string|null
   *   entity_type.field_name, or NULL when neither pin is present.
   */
  public function pin(Request $request): ?string {
    return $this->fromRequest($request) ?? $this->fromSignedClaim($request);
  }

  /**
   * Extracts a non-empty field key from a store row.
   *
   * @param array<string, mixed>|null $row
   *   Inventory meta or token record.
   *
   * @return string|null
   *   The field storage id, or NULL.
   */
  private function fieldFromRow(?array $row): ?string {
    if ($row === NULL) {
      return NULL;
    }
    $field = $row['field'] ?? NULL;
    return is_string($field) && $field !== '' ? $field : NULL;
  }

}
