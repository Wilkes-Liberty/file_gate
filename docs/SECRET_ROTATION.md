# Secret rotation runbook

File Gate signing secrets are capability credentials. Rotating without a grace
period **invalidates every live grant** signed with the old material.

## Dual-key grace (1.4+)

Mint/sign always uses the **current** secret. Validate/redeem also tries
**previous** materials so outstanding links keep working during cutover.

### Named secrets

```php
// settings.php
$settings['file_gate.secrets'] = [
  's_public' => getenv('FILE_GATE_SECRET_PUBLIC'), // NEW value
];
// While old links may still be live:
$settings['file_gate.previous_secrets'] = [
  's_public' => getenv('FILE_GATE_SECRET_PUBLIC_PREV'), // OLD value
  // or multiple: 's_public' => [getenv('…PREV1'), getenv('…PREV2')],
];
```

### Legacy `download_secret`

```php
$config['file_gate.settings']['download_secret'] = getenv('FILE_GATE_SECRET'); // NEW
$settings['file_gate.previous_download_secrets'] = [
  getenv('FILE_GATE_SECRET_PREV'),
];
```

OTP codes store the secret id (`k`) at issue and hash with that material;
redeem tries `validationMaterials()` (current + previous).

Session bridge cookies and HMAC grants follow the same dual-key path.

## Order of operations

1. Generate a new secret offline; store it in the secret manager.
2. Deploy with **new** as current and **old** as previous.
3. Confirm mint + download still work for existing and new links.
4. Wait for max TTL of outstanding grants (and OTP TTLs, bridge TTLs).
5. Remove the previous entry from settings; redeploy.
6. If the secret was **compromised**: skip grace — rotate immediately, accept
   mass invalidation, and revoke known tokens/jtis via `POST /api/file-gate/revoke`.

## Compromised mint secret

1. Rotate immediately (no previous key).
2. Restrict network access to mint/revoke/OTP.
3. `POST /api/file-gate/revoke` with known token plaintexts; for signed_url
   one-time links, revoke by `{"jti": "…"}` if you still have jtis.
4. Query `file_gate` logs / audit_chain for mints after compromise time.
5. Re-issue credentials only to trusted BFFs with scoped secrets.

## Scoped secrets

Narrowing `secret_scopes` for a named id **revokes** outstanding grants for
fields dropped from the allowlist (checked at redeem). Prefer dual-key rotation
when only the value changes; use scope narrowing when authority must shrink.
