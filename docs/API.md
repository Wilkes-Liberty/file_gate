# File Gate API reference

## HTTP endpoints

### `POST /api/file-gate/mint`

Mints a short-lived signed download URL. **Server-to-server only** — the caller
must present the shared secret; never call this from a browser.

**Authentication.** Constant-time comparison of:

- **Legacy:** Basic password or `X-File-Gate-Secret` matching
  `download_secret` (username ignored if it is not a configured named id).
- **Named:** Basic **username = secret id**, password = value; or
  `X-File-Gate-Secret-Id` + `X-File-Gate-Secret`. Scope is the field storage
  allowlist for that id (`secret_scopes`).

**Request body** (JSON) — exactly one of:

| Field | Type | Notes |
|---|---|---|
| `media` | string | A media entity UUID (requires the Media module). Its source file is used; the media must be published. |
| `file` | string | A managed file UUID (media-agnostic). |
| `subject` | string | Optional. Caller-asserted subject (assurance binds `sh=`). With A2, may be filled from the verified token `sub`. |
| `account` | string | Optional (required when global `require_acting_account` or field `require_identity_mint`). Acting user UUID. Mint fails closed unless that user may download the file (and view host entities). Prefer over `uid`. |
| `uid` | int | Optional. Acting user id (same check as `account`). |
| `field` | string | Field storage id (`entity_type.field_name`). **Required** when the file is gated by more than one field; selects which gate method/settings apply. |

For **assurance A2** (`verify_oidc_at_mint`): also send `Authorization: Bearer|DPoP` with a token whose `aud` is the field audience (token exchange / IdP mapper).

**Responses:**

| Status | Meaning |
|---|---|
| `200` | `{ "path": "/api/file-gate/download?…", "expires": <unix-ts|null>, "ttl": <int>, "field", "method" }`. `path` is root-relative — prepend your public origin. Named secrets add `k=<id>` to the query. |
| `400` | Invalid JSON, multi-field without `field`, neither `file` nor `media`, or method does not support minted URLs. |
| `401` | Missing or wrong secret (or missing A2 token when required). |
| `403` | Credential scope, identity, or A2 acr/token check failed. |
| `404` | Unknown file/media. |
| `409` | The host media is unpublished. |
| `422` | The file is not gated, or the media has no file. |
| `429` | Rate limited (per client IP). |
| `503` | No signing secret is configured — the module is failing closed. |

### `GET /api/file-gate/download`

Redeemed by the visitor's browser. Query parameters:

| Param | Notes |
|---|---|
| `f` | The file UUID (required). |
| `exp` | Grant expiry, Unix time (from the mint response). |
| `sig` | HMAC signature. |
| `k` | Opaque secret id for named credentials (key selection only; not an HMAC claim). Absent = legacy site secret. |
| `token` | Present for the `token` method: the plaintext token. A minted link also carries `exp`/`sig`; a pre-shared campaign link carries only `token`. |
| `jti`, `max` | Present only for usage-limited grants (one-time / N-use links). |
| `nbf` | Present only when a not-before window was set. |

**Responses:** `200` streams the file (`Cache-Control: private, no-store`; a
`Content-Disposition` of attachment or inline per the field/global setting);
`403` when the grant is missing, expired, tampered, not yet valid, or spent;
`404` when the file is unknown or not gated.

The `referrer_lock` method carries the same `exp`/`sig` as `signed_url` and adds
no query parameter — it reads the request's `Origin` header (falling back to the
origin of `Referer`) and denies (`403`) when it is not in the field allowlist.

The `assurance` method (File Gate Assurance submodule): **primary path is plain
link** — open the signed URL, complete step-up (OIDC or WebAuthn), receive
HttpOnly bridge cookie `FG_AB`, re-GET the same URL. See
`docs/assurance-redeem.md`. API clients may still use `Authorization: Bearer|DPoP`
on the bridge POST. Do not put `login_url` in the step-up query; configure
**Step-up login URL** on the field only.

The `otp` method reads `email` and `otp` query parameters (no `exp`/`sig`) and
verifies the passcode against the one issued for that (file, email) — single use,
within its TTL, under the attempt cap. OTP HMAC uses the **authenticated mint
secret** (named or legacy), not only legacy `download_secret`.

### `POST /api/file-gate/revoke`

Server-to-server. Body:

| Body | Effect |
|------|--------|
| `{"token":"<plaintext>"}` | Deletes a minted `token`-method row (field-scoped when field known). |
| `{"jti":"<jti>","ttl":86400}` | Marks a signed_url usage jti fully spent (optional ttl seconds). |

### `POST /api/file-gate/otp`

Issues a one-time passcode for an `otp`-gated file. **Server-to-server only** —
same shared-secret authentication as mint. Generates a code bound to (file,
email), stores its hash (TTL-limited, attempt-capped), and e-mails it via the
site mail transport. Rate-limited per IP and per (file, email).

**Request body** (JSON):

| Field | Type | Notes |
|---|---|---|
| `file` / `media` | string | The file or media UUID (exactly one). |
| `email` | string | The recipient address the code is bound to. |

**Responses:** `204` (a code was sent), `400` (bad JSON / invalid email / no
file), `401` (bad/absent secret), `404` (unknown file/media), `409` (media
unpublished), `422` (file is not OTP-gated), `429` (rate limited), `503` (no
secret configured).

### `POST /api/file-gate/revoke`

Revokes a **minted** `token`-method grant. **Server-to-server only** — same
shared-secret authentication as mint (Basic-auth password or `X-File-Gate-Secret`
header, constant-time). Deletes the token's stored hash so later redemptions
fail, without rotating the site secret (which would break every other live link).

Pre-shared campaign tokens are revoked by removing their hash from the field's
`tokens` configuration, not through this endpoint.

**Request body** (JSON):

| Field | Type | Notes |
|---|---|---|
| `token` | string | The plaintext token to revoke. |

**Responses:**

| Status | Meaning |
|---|---|
| `204` | Revoked (the token's stored hash was deleted). |
| `400` | No `token` supplied, or invalid JSON. |
| `401` | Missing or wrong secret. |
| `404` | Unknown token, or already expired/revoked. |
| `429` | Rate limited (per client IP). |
| `503` | No signing secret is configured — the module is failing closed. |

## The grant signature

```
sig = HMAC-SHA256(normalized_file_uri . "|" . canonical(claims), secret)
canonical(claims) = claims sorted by key, rendered "key=value" and joined by "&"
```

`claims` always contains `exp`; optionally `nbf`, and (`jti`, `max`) for usage
limits. Because every claim is part of the signed payload, a client cannot alter
the file, the expiry, or the usage cap without invalidating the signature.

## Field configuration (third-party settings)

Stored on the **field storage** config under
`third_party_settings.file_gate`:

```yaml
third_party_settings:
  file_gate:
    gated: true
    method: signed_url
    method_settings:
      ttl: 300            # optional; seconds; overrides the global default
      available_until: 0  # optional; absolute Unix timestamp cap
      max_uses: 1         # optional; 1 = one-time link
```

Edit these on the field's settings page — enable *Gate access to these files*,
pick a method, and the selected method's own settings form appears inline (each
method implements `fieldSettingsForm()`); or set `method_settings` directly in
exported YAML. The `token` method also accepts a `tokens` list under
`method_settings` — an array of **SHA-256 hashes** (never plaintext) of
pre-shared campaign tokens:

```yaml
third_party_settings:
  file_gate:
    gated: true
    method: token
    method_settings:
      max_uses: 0         # optional; minted tokens (0 = unlimited)
      tokens:             # optional; SHA-256 hashes of pre-shared tokens
        - '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
```

The `referrer_lock` method extends `signed_url` (so it takes the same `ttl` /
`available_until` / `max_uses`) and adds an origin allowlist. It is hardening,
not authorization — the `Origin` / `Referer` header is spoofable:

```yaml
third_party_settings:
  file_gate:
    gated: true
    method: referrer_lock
    method_settings:
      allowed_origins:              # required; empty ⇒ deny all (fail closed)
        - 'https://app.example.com'
      on_missing_referrer: 'deny'   # optional; 'deny' (default) or 'allow' when no parseable Origin/Referer is available
```

The `otp` method (core) e-mails a one-time passcode; its `method_settings`:

```yaml
third_party_settings:
  file_gate:
    gated: true
    method: otp
    method_settings:
      ttl: 600            # optional; code lifetime in seconds (default 600)
      max_attempts: 5     # optional; wrong tries before lockout (default 5)
      code_length: 6      # optional; number of digits (default 6; 4–10)
```

The `form`, `commerce`, and `assurance` methods ship in optional submodules;
their `method_settings` keys are documented in each submodule's README
([`file_gate_form`](../modules/file_gate_form/README.md),
[`file_gate_commerce`](../modules/file_gate_commerce/README.md),
[`file_gate_assurance`](../modules/file_gate_assurance/README.md)).

## Plugin API — `GateMethod`

Implement `\Drupal\file_gate\GateMethodInterface` (extend `GateMethodBase`) and
tag the class with the `#[GateMethod(id, label, description)]` attribute in
`src/Plugin/GateMethod`.

| Method | Contract |
|---|---|
| `grants(FileInterface $file, Request $request): bool` | Decide, at delivery time, whether the request may receive the file. **Must fail closed.** |
| `mint(FileInterface $file): ?array` | Pre-issue a grant: return query params to append to the download URL (e.g. `['exp' => …, 'sig' => …]`), or `NULL` if the method decides access live (no minted URL). |
| `fieldSettingsForm(array $settings): array` | Return a Form API array of the method's per-field options (rendered inline on the field edit form), or `[]` for a method with no settings. |
| `fieldSettingsSubmit(array $values): array` | Normalise the submitted values into the `method_settings` to persist (cast types, split textareas, drop empties). |

The plugin's per-field `method_settings` are available as `$this->configuration`.

**Optional: `ContextualMintInterface`.** A method that needs the mint *request*
itself — e.g. to bind a caller-asserted subject — implements
`\Drupal\file_gate\ContextualMintInterface::mintWithContext(FileInterface $file, Request $request): ?array`.
The mint controller feature-detects it and calls `mintWithContext()` in place of
`mint()`, so `mint()` stays backward compatible. (This is how the `assurance`
method reads the `subject` from the mint body for per-user binding.)

## Services

| Service | Purpose |
|---|---|
| `file_gate.grant_signer` | `GrantSignerInterface` — sign/validate HMAC grants (target-agnostic). |
| `file_gate.resolver` | `FileGateResolver` — map a file to its gate config (method + settings) via the referencing field. |
| `plugin.manager.file_gate.gate_method` | The gate-method plugin manager. |
| `logger.channel.file_gate` | The module's logger channel. |
