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
 * strictness methods. Redeem must pin to the HMAC-bound `fld` claim, or to
 * the field stored on the grant row when `fld` is absent, so allowsField()
 * matches the minted scope. Unlimited signed_url grants have no inventory
 * row and carry `fld` instead. An unsigned JSON body field is not a pin.
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
   * body "field" used by OTP issue and session establish. Redeem must call
   * pin(): this method's body field is unsigned and must not override fld.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The redeem, bridge, OTP, or WebAuthn request.
   *
   * @return string|null
   *   entity_type.field_name, or NULL when no mint-stored field is present.
   */
  public function fromRequest(Request $request): ?string {
    $persisted = $this->fieldFromPersistedGrant($request);
    if ($persisted !== NULL) {
      return $persisted;
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
   * Field pin for redeem: signed fld, else a persisted grant row.
   *
   * The signed fld claim wins when it is present. Referrer lock and
   * assurance read gate settings from the instance chosen here, before
   * the HMAC is checked. A JSON body "field", or a token query (not a
   * signed_url claim), must not select another field's settings while
   * fld still verifies. Grants minted before fld existed fall back to
   * the jti inventory row or token store. OTP issue and session
   * establish keep calling fromRequest().
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The redeem, bridge, or WebAuthn request.
   *
   * @return string|null
   *   entity_type.field_name, or NULL when neither pin is present.
   */
  public function pin(Request $request): ?string {
    return $this->fromSignedClaim($request)
      ?? $this->fieldFromPersistedGrant($request);
  }

  /**
   * Field storage id from a jti inventory row or a token-store row.
   *
   * Does not read the JSON body. Callers that need the OTP body field use
   * fromRequest().
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return string|null
   *   entity_type.field_name, or NULL when no persisted row matches.
   */
  private function fieldFromPersistedGrant(Request $request): ?string {
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

    return NULL;
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
