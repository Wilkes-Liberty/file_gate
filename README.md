# File Gate

Gate access to private files with pluggable methods (short-lived signed URLs,
authenticated access, …) and deliver them to any decoupled front end.

## The problem it solves

Out of the box, Drupal grants a private-file download to anyone who can *view*
the entity that references it. Because anonymous users can view **published**
content, a private file attached to published media is effectively public to
anyone who has the link — `private://` only means "not guessable", not "gated".

File Gate closes that gap. It **denies** the normal `/system/files` path for any
private file a *gated* field references, and delivers those files instead through
its own endpoint, only after a pluggable **gate method** approves the request.

## How it works

```
                    (1) editor uploads a file to a gated, private:// field
                         │
 visitor ──(2)──▶ your front end ──(3, server-to-server)──▶  POST /api/file-gate/mint
   ▲   passes the front end's gate         (file/media UUID + shared secret)
   │   (lead form, login, purchase…)                        │
   │                                                        ▼
   └─────(5) browser redeems ◀──(4)── { path, expires, ttl } (short-lived signed URL)
             GET /api/file-gate/download?f=…&exp=…&sig=…
                         │
                         ▼
             File Gate verifies the grant and streams the bytes.
             Meanwhile GET /system/files/… stays denied for the public.
```

1. A private file/image field is marked **gated** (see *Configuration*).
2. A visitor passes **your** gate — a lead form, a login, a purchase — entirely
   in your front end. File Gate does not care how you gate; it only mints and
   verifies.
3. Your back end calls the **mint** endpoint (server-to-server) with the file or
   media UUID and the shared secret.
4. File Gate returns a **relative, short-lived, signed path**.
5. The visitor's browser redeems it at the **download** endpoint. File Gate
   verifies the signature (and any usage limit) and streams the file. The raw
   `/system/files` path is denied to the public throughout.

## Features

- **Pluggable gate methods.** A clean plugin type (`GateMethod`) decides *how* a
  request proves it passed the gate. Ships with **Signed URL** (HMAC),
  **Authenticated access**, **Token** (revocable per-grant links and pre-shared
  campaign tokens), **Referrer lock** (a signed URL restricted to an allowed
  origin), and **One-time passcode** (email-verified); optional submodules add
  **File Gate Form** (a coupled email / lead-capture form Drupal renders),
  **File Gate Commerce** (gate behind a Drupal Commerce purchase or a pluggable
  entitlement), and **File Gate Assurance** (hardware-backed, phishing-resistant
  **PIV/CAC + FIDO2/WebAuthn** gating over any OIDC IdP, with opt-in DPoP). Add
  your own in a few lines.
- **Front-end agnostic / headless-first.** Mint over a server-to-server API;
  redeem in the browser. Nothing about React, Next.js, Vue, or a coupled Twig
  theme is assumed. Works for decoupled, coupled, and hybrid sites.
- **Per-field configuration.** Mark any file/image field gated where you choose
  its storage; enabling gating **forces and locks the private file system** so a
  gated field can never silently store public, world-readable files.
- **Media-optional.** Gate a Media source field, a plain file field, or any other
  private file field. The only hard dependency is core *File*.
- **Expiry & usage controls.** Per-field TTL, an absolute availability window
  (`available_until`), and **usage limits** (`max_uses`, including one-time
  links). All are bound into the signature and cannot be altered by the client.
- **Fails closed.** With no signing secret configured, minting returns `503` and
  every gated file is denied.
- **Constant-time verification.** HMAC-SHA256 grants compared with
  `hash_equals()`; the secret lives in the environment, never in configuration.
- **Editors keep working.** A *Bypass file gate* permission lets trusted staff
  download gated files normally through the admin UI.
- **Auditing & analytics.** A dedicated logger channel records security events
  (denied downloads, failed mint auth, fail-closed refusals) and usage events
  (mints and deliveries).
- **Admin dashboard.** Reports the secret status, sets global defaults, lists
  gate methods, and links every gated field to its settings.

## Requirements

- **Drupal 11.4+** — the module builds on core's `FileReferenceResolver`
  (introduced in 11.4).
- A configured **private file system** (`file_private_path`).
- A **signing secret**, injected from the environment (below).

## Installation

```bash
composer require drupal/file_gate
drush en file_gate
```

## Configuration

### 1. Provide the signing secret (required)

The secret is **never** stored in configuration. Inject it from the environment
in `settings.php`:

```php
$config['file_gate.settings']['download_secret'] = getenv('DRUPAL_FILE_GATE_SECRET');
```

Generate a strong random value (e.g. `openssl rand -hex 32`) and set
`DRUPAL_FILE_GATE_SECRET` in your environment. While it is empty the module fails
closed. This secret doubles as the mint endpoint's credential; keep it off the
public network and never expose it to the browser (only the derived signature is
ever public).

### 2. Gate a field

Edit any private file or image field. In its settings you will find **"Gate
access to these files"**. Enabling it:

- forces the field's storage to the **private** file system and locks that
  control; and
- lets you pick a **gate method** (default: *Signed URL*).

Gating is stored as third-party settings on the field storage, so it travels
with your exported configuration.

Per-method options (for *Signed URL*, under the field's `method_settings`):

| Setting | Meaning |
|---|---|
| `ttl` | Signed-URL lifetime in seconds (defaults to the global TTL). |
| `available_until` | Absolute Unix timestamp; caps every grant's expiry (a "download available until X" window). |
| `max_uses` | Maximum redemptions per minted URL (`1` = one-time link). |

#### Token method

The **Token** method (`token`) adds the one thing a bare signature cannot do:
**revoke a single live link without rotating the site secret** (which would break
every other link). It offers two shapes, chosen at redemption by whether the URL
carries a signature:

- **Minted, revocable (per grant).** `mint` self-issues a random token, records
  its SHA-256 hash, and binds that hash into the signed URL. Revoke a link by
  deleting its stored hash — via the [revoke endpoint](#revoke--post-apifile-gaterevoke)
  or by removing the key from the `file_gate_tokens` expirable key/value store.
  Because `mint` receives no caller input, a token is per-grant / independently
  revocable — attach recipient meaning (token → person) in your own back end.
- **Pre-shared campaign.** Configure an allowlist of token **hashes** and hand
  out static `?token=<plaintext>` links (no `mint`). Revoke by removing the hash
  from configuration. These links are static — no per-request expiry.

Per-field `method_settings`:

| Setting | Meaning |
|---|---|
| `ttl`, `available_until`, `max_uses` | Same as *Signed URL*, applied to minted tokens. |
| `tokens` | Array of **SHA-256 hashes** of pre-shared tokens (e.g. `hash('sha256', $token)`). Store hashes only — never the plaintext token, which travels only in the recipient's link. Leave empty to disable pre-shared mode. |

Tokens are stored and configured only as hashes, so a store or config dump yields
no usable credentials. Like *Signed URL*'s usage counter, the revocation store is
a fast key/value store, not a lock: a redemption whose use-increment races a
manual revocation could admit one extra request. Adequate for lead-gen and
distribution; not a hard licensing lock.

#### Referrer lock method

The **Referrer lock** method (`referrer_lock`) is a *Signed URL* that is
additionally only redeemable from an allowed origin. It mints and validates the
same signed grant (and inherits `ttl`, `available_until`, and `max_uses`), and at
redemption also checks the request's `Origin` header — falling back to the origin
of the `Referer` — against a per-field allowlist. The origin is checked first, so
a request from a disallowed origin is denied before a usage-limited grant would
spend one of its uses.

> **Hardening, not authorization.** The `Origin` / `Referer` header is trivially
> spoofable by any non-browser client and is often stripped by privacy setups, so
> this is **not** an access boundary — the signature is. Use it to discourage a
> leaked link from working when embedded on another site, not to protect anything
> the signature alone should not already protect.

Per-field `method_settings` (in addition to all of *Signed URL*'s):

| Setting | Meaning |
|---|---|
| `allowed_origins` | List of allowed origins, e.g. `https://app.example.com`. Matched as scheme + host + (non-default) port. An empty list denies every request (fail closed) — configure at least one. |
| `on_missing_referrer` | What to do when no parseable `Origin`/`Referer` is available: `deny` (default) or `allow` (tolerate privacy setups that strip the header, leaning on the signature alone). |

#### Assurance method (PIV/CAC + FIDO2/WebAuthn)

The optional **File Gate Assurance** submodule (`file_gate_assurance`) adds the
`assurance` method: a signed URL whose delivery also requires a hardware-backed,
phishing-resistant NIST SP 800-63 assurance level proven at any OIDC IdP —
PIV/CAC (HSPD-12 / FIPS 201) or FIDO2/WebAuthn — with opt-in DPoP (RFC 9449)
sender-constraining. It is **federation** (an *asserted* level), not File Gate
acting as an AAL3 verifier. See
[`modules/file_gate_assurance/README.md`](modules/file_gate_assurance/README.md)
and the design note in
[`docs/design/piv-cac-webauthn.md`](docs/design/piv-cac-webauthn.md).

#### One-time passcode method

The **One-time passcode** method (`otp`) proves control of an email address: a
trusted back end requests a code bound to (file, email) at `POST
/api/file-gate/otp` (shared-secret auth, like mint), File Gate e-mails it, and the
visitor redeems the download with `?f=…&email=…&otp=…`. The code is single-use,
TTL-limited, attempt-locked, and stored only as a hash. A step up from a bare
token — verified in the moment — without an account.

| Setting | Meaning |
|---|---|
| `ttl` | Code lifetime in seconds (default 600). |
| `max_attempts` | Wrong-code tries before the code is locked out (default 5). |
| `code_length` | Number of digits in the passcode (default 6). |

> **Email is not a confidential channel.** The passcode proves *control* of the
> address, not that the message is secret — anyone who can read the recipient's
> mail (or intercept it without transport encryption) can use the code within its
> window. Use `otp` to gate lead-gen / self-service documents, not to protect
> content a real secret should protect; keep the TTL short.

### 3. Global defaults

Visit **Administration → Configuration → Media → File Gate**
(`/admin/config/media/file-gate`) to set the default TTL, content disposition
(attachment/inline), and mint rate limiting, to check the secret status, and to
see every gated field.

## API contract (for front ends)

### Mint — `POST /api/file-gate/mint`

Server-to-server only. Authenticate with the shared secret as the HTTP Basic
password (or the `X-File-Gate-Secret` header).

Request body (JSON):

```json
{ "media": "<media-uuid>" }
```

or

```json
{ "file": "<file-uuid>" }
```

Response `200`:

```json
{
  "path": "/api/file-gate/download?f=<file-uuid>&exp=1720800000&sig=<hmac>",
  "expires": 1720800000,
  "ttl": 120
}
```

`path` is **root-relative and host-agnostic** — prepend your public Drupal file
origin. Errors: `503` (no secret configured), `401` (bad/absent secret), `404`
(unknown file/media), `409` (host media unpublished), `422` (file not gated /
empty), `429` (rate limited), `400` (bad request).

### Download — `GET /api/file-gate/download?f=…&exp=…&sig=…`

Redeemed by the visitor's browser. Returns the file stream (`200`) or `403` when
the grant is missing, expired, tampered, or spent; `404` when the file is unknown
or not gated.

For the *Token* method the browser also sends `token` (the plaintext token); a
pre-shared campaign link sends only `token` (no `exp`/`sig`).

### Revoke — `POST /api/file-gate/revoke`

Server-to-server, same shared-secret authentication as mint. Invalidates a
**minted** `token`-method grant before its natural expiry by deleting its stored
hash — without rotating the site secret. Pre-shared campaign tokens are revoked
by removing their hash from the field's `tokens` configuration, not here.

Request body (JSON):

```json
{ "token": "<plaintext-token>" }
```

Responses: `204` (revoked), `400` (no token), `401` (bad/absent secret), `404`
(unknown or already-gone token), `429` (rate limited), `503` (no secret
configured).

### Front-end integration sketch (any framework)

```js
// Server-side (never expose the secret to the browser):
const res = await fetch(`${DRUPAL_INTERNAL_ORIGIN}/api/file-gate/mint`, {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + Buffer.from(':' + process.env.DRUPAL_FILE_GATE_SECRET).toString('base64'),
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ media: mediaUuid }),
});
const { path } = await res.json();
// Hand the browser the public URL to redeem:
const downloadUrl = `${DRUPAL_PUBLIC_FILE_ORIGIN}${path}`;
```

The metadata the front end needs (that a gated document exists, its name, type,
size) should be exposed via your API (JSON:API/GraphQL) **without** a directly
resolvable file URL — the bytes are delivered only through the gated endpoint.

## Security model

- **Deny by default.** The `hook_file_download()` implementation returns `-1`
  (a hard veto that overrides core's permissive private-file access) for any
  gated file requested at `/system/files`, unless the account holds *Bypass file
  gate*. It never grants there — delivery happens only on the module's route.
- **Signed grants.** `sig = HMAC-SHA256(normalized_uri . "|" . canonical(claims),
  secret)`. Every claim (expiry, not-before, usage token/cap) is bound, so a
  client cannot change the file, the expiry, or the usage limit without
  invalidating the grant. Comparison is constant-time.
- **Fail closed.** No secret ⇒ nothing validates and minting refuses (`503`).
- **No path disclosure.** The signed URL carries the file UUID, not the
  `private://` path; delivery streams `BinaryFileResponse` with
  `Cache-Control: private, no-store`.
- **Trust boundary.** The mint endpoint trusts the secret-holding caller; it does
  **not** re-verify the front end's own gate. Keep the endpoint on a trusted
  network (and rate-limited) and keep the secret secret.
- **Usage limits are approximate.** The redemption counter is a fast key/value
  store, not a lock; a tight race could allow one extra redemption. Adequate for
  lead-gen and casual limits, not for hard licensing.

## Extending: writing a gate method

A gate method answers "has this request passed the gate for this file?"

```php
namespace Drupal\my_module\Plugin\GateMethod;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\GateMethodBase;
use Symfony\Component\HttpFoundation\Request;

#[GateMethod(
  id: 'my_method',
  label: new TranslatableMarkup('My method'),
  description: new TranslatableMarkup('…'),
)]
final class MyMethod extends GateMethodBase {

  public function grants(FileInterface $file, Request $request): bool {
    // Return TRUE only if the request positively proves it passed the gate.
  }

  public function mint(FileInterface $file): ?array {
    // Return query params to append to the download URL, or NULL if this
    // method decides access live (no pre-issued grant).
  }

}
```

### Built-in methods and roadmap

| Method | Status | Notes |
|---|---|---|
| `signed_url` | shipped | HMAC signed URL; TTL, availability window, usage limits. |
| `authenticated` | shipped | Delivers to any logged-in Drupal user. |
| `token` | shipped | Revocable per-grant token and/or a pre-shared campaign allowlist. |
| `form` | shipped | Coupled email / lead-capture form (Drupal renders the gate). Ships in the **File Gate Form** submodule. |
| `otp` | shipped | One-time passcode e-mailed to a self-identified address; single-use, TTL-limited, attempt-locked. |
| `referrer_lock` | shipped | Signed URL that is only redeemable from an allowed origin/referrer (hardening, not authz). |
| `assurance` | shipped | Signed URL gated on a hardware-backed OIDC assurance (PIV/CAC + FIDO2/WebAuthn), with opt-in DPoP. Ships in the **File Gate Assurance** submodule. |
| `commerce` | shipped | Gate behind a purchase / entitlement (Drupal Commerce by default, or a pluggable external checker). Ships in the **File Gate Commerce** submodule. |

## Permissions

- **Administer File Gate** — configure the module and view gated fields.
- **Bypass file gate** — download gated files directly via `/system/files`
  (editors/operators). The administrator role holds it implicitly.

## Logging

File Gate logs to its own `file_gate` channel: `warning` for security events
(denied downloads, failed mint auth, fail-closed refusals) and `info` for usage
events (mints, deliveries). Watch it via *Reports → Recent log messages* or your
log aggregator.

## Maintainers

- Jeremy Michael Cerda (jmcerda) — <https://www.drupal.org/u/jmcerda>
- Sponsored by **Wilkes & Liberty, LLC** — <https://wilkesliberty.com>

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
