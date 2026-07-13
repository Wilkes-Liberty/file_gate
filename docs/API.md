# File Gate API reference

## HTTP endpoints

### `POST /api/file-gate/mint`

Mints a short-lived signed download URL. **Server-to-server only** — the caller
must present the shared secret; never call this from a browser.

**Authentication.** The secret is sent as the HTTP Basic password (username is
ignored) or in an `X-File-Gate-Secret` header. The comparison is constant-time.

**Request body** (JSON) — exactly one of:

| Field | Type | Notes |
|---|---|---|
| `media` | string | A media entity UUID (requires the Media module). Its source file is used; the media must be published. |
| `file` | string | A managed file UUID (media-agnostic). |

**Responses:**

| Status | Meaning |
|---|---|
| `200` | `{ "path": "/api/file-gate/download?…", "expires": <unix-ts|null>, "ttl": <int> }`. `path` is root-relative — prepend your public origin. |
| `400` | Invalid JSON, or neither `file` nor `media` supplied, or the gate method does not support minted URLs. |
| `401` | Missing or wrong secret. |
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

Edit these on the field's settings page (enable *Gate access to these files* and
pick a method); the plugin's per-field `method_settings` are configured in YAML.
The `token` method also accepts a `tokens` list under `method_settings` — an
array of **SHA-256 hashes** (never plaintext) of pre-shared campaign tokens:

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
      on_missing_referrer: 'deny'   # optional; 'deny' (default) or 'allow'
```

## Plugin API — `GateMethod`

Implement `\Drupal\file_gate\GateMethodInterface` (extend `GateMethodBase`) and
tag the class with the `#[GateMethod(id, label, description)]` attribute in
`src/Plugin/GateMethod`.

| Method | Contract |
|---|---|
| `grants(FileInterface $file, Request $request): bool` | Decide, at delivery time, whether the request may receive the file. **Must fail closed.** |
| `mint(FileInterface $file): ?array` | Pre-issue a grant: return query params to append to the download URL (e.g. `['exp' => …, 'sig' => …]`), or `NULL` if the method decides access live (no minted URL). |

The plugin's per-field `method_settings` are available as `$this->configuration`.

## Services

| Service | Purpose |
|---|---|
| `file_gate.grant_signer` | `GrantSignerInterface` — sign/validate HMAC grants (target-agnostic). |
| `file_gate.resolver` | `FileGateResolver` — map a file to its gate config (method + settings) via the referencing field. |
| `plugin.manager.file_gate.gate_method` | The gate-method plugin manager. |
| `logger.channel.file_gate` | The module's logger channel. |
