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
  (mints and deliveries). Optional soft integration with **audit_chain** for a
  hash-chained durable trail (`docs/AUDIT.md`).
- **Admin dashboard.** Secret status, defaults, gate methods, gated fields, plus
  mint/delivery/denial tables from the `file_gate` dblog channel when Database
  Logging is enabled.
- **Secret rotation with dual keys**, multi-field mint pin, forced identity mint,
  mint-time OIDC (A2), WebAuthn enrollment UI — see `CHANGELOG.md` and
  `docs/SECRET_ROTATION.md`, `docs/E2E-ASSURANCE.md`.
- **IdP-first (Keycloak) architecture:**
  [`docs/KEYCLOAK-UNIFIED-AUTH.md`](docs/KEYCLOAK-UNIFIED-AUTH.md). Roadmap and
  scheduling are tracked internally rather than in this repository.
- **Optional identity-aware mint.** Pass `account` (user UUID) or `uid` on mint
  so a grant cannot exceed that user's download and host-entity view rights.

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

Secrets are **never** stored in exported configuration. While none are set the
module fails closed.

**Legacy (single secret, whole gated corpus)** — fine for one trusted mint
backend:

```php
$config['file_gate.settings']['download_secret'] = getenv('DRUPAL_FILE_GATE_SECRET');
```

**Named secrets (field-scoped)** — use when different front ends must not mint
each other's files. Values in `$settings` (not `$config`); scopes in config
(admin form or export):

```php
// settings.php — values never export.
$settings['file_gate.secrets'] = [
  's_public' => getenv('FILE_GATE_SECRET_PUBLIC'),
  's_nda' => getenv('FILE_GATE_SECRET_NDA'),
];
// Scopes (exportable) — or set under Admin → File Gate "Named secret scopes":
//   s_public: node.field_whitepaper
//   s_nda: node.field_nda_pdf
$config['file_gate.settings']['secret_scopes'] = [
  's_public' => ['node.field_whitepaper'],
  's_nda' => ['node.field_nda_pdf'],
];
```

Mint with Basic auth **username = secret id**, **password = value**. Minted URLs
include `k=<id>` so redemption uses the same key. Scope is checked at mint and
again at download (narrowing a secret revokes outstanding grants). A named
secret with a value but no scope can mint nothing and is reported on the status
report. Keep secrets off the public network; only signatures reach the browser.

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
sender-constraining. A field trusts a **list of issuers** (`trusted_issuers`),
each with its own audience and accepted `acr` values; a token is matched to
exactly one entry by `iss`, with no cross-matching and no fallback, and the
legacy single-issuer settings behave as a one-entry list. It is **federation**
(an *asserted* level), not File Gate acting as an AAL3 verifier. See
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

#### Form (email / lead capture) method

The optional **File Gate Form** submodule (`file_gate_form`) adds the `form`
method: Drupal renders a lightweight email / lead-capture form at
`/file-gate/form/{file}` and grants the download on submission (a per-session
grant in the private tempstore, TTL-limited). Spam is bounded by a honeypot and a
per-IP rate limit, and a `LeadCapturedEvent` lets the site persist submissions
without File Gate storing PII. See
[`modules/file_gate_form/README.md`](modules/file_gate_form/README.md).

#### Commerce (purchase / entitlement) method

The optional **File Gate Commerce** submodule (`file_gate_commerce`) adds the
`commerce` method: deliver only to a buyer / licensee, re-checked live on every
download. The bundled checker grants on a completed Drupal Commerce order matching
a configured SKU; override the `file_gate_commerce.entitlement_checker` service
for licences or an external entitlement API. Access gating, not DRM. See
[`modules/file_gate_commerce/README.md`](modules/file_gate_commerce/README.md).

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
pre-shared campaign link sends only `token` (no `exp`/`sig`). For the *OTP*
method the browser sends `email` and `otp` (the emailed code) in place of a
signature (`?f=…&email=…&otp=…`).

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

### OTP — `POST /api/file-gate/otp`

Server-to-server, same shared-secret authentication as mint. Issues a single-use
passcode bound to a `(file, email)` pair and e-mails it to that address (File Gate
sends the mail and stores only a hash of the code). The visitor then redeems the
download with `?f=…&email=…&otp=…`.

Request body (JSON):

```json
{ "file": "<file-uuid>", "email": "person@example.com" }
```

(or `"media": "<media-uuid>"` in place of `"file"`.)

Responses: `204` (code issued and e-mailed), `400` (invalid body or email),
`401` (bad/absent secret), `404` (unknown file/media), `409` (host media
unpublished), `422` (file not gated with the `otp` method), `429` (rate limited —
per IP and per `(file, email)`), `503` (no secret configured).

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
- **Usage limits are approximate.** The redemption counter is a fast key/value
  store, not a lock; a tight race could allow one extra redemption. Adequate for
  lead-gen and casual limits, not for hard licensing.

### The trust boundary — read this before deploying

**Mint authorizes nothing.** It authenticates the *caller* with the shared
secret and then mints whatever was asked for. It performs **no entity access
check and no field access check**. The only content test anywhere in the path is
that a *media* host must be published; minting by file UUID does not check even
that.

So the secret's blast radius is **the entire gated corpus**. Anyone holding it
can mint a working download URL for any gated file whose UUID they can guess or
obtain, regardless of who they are or whether they could view the referencing
entity.

That is a deliberate design — File Gate delegates the gate decision to a trusted
back end that has already run its own (a lead form, a login, an entitlement
check) — but it has two consequences worth stating plainly:

- **Never provision the secret into a public web tier.** If a front-end
  container that serves anonymous traffic holds it, that tier holds a skeleton
  key to every gated file. Mint from a server-side route or a back-end service,
  not from code that ships to the browser or from an environment an attacker
  reaching the front end can read.
- **The secret is worth rotating like a credential**, because it is one. It also
  doubles as the HMAC signing key, so rotating it invalidates outstanding
  grants — which is the point when you suspect exposure.

If you need mint to enforce per-user rights rather than delegate them, that is
not built yet. Scoping a secret to particular fields or media bundles, so a
front end that only serves whitepapers cannot mint an NDA, is also not built.
Both are tracked in the issue queue.

### Gating requires the private file system

Gating only applies to files on the private file system. Public files are served
straight off disk by the web server or a CDN and never reach Drupal, so there is
no request to gate.

The field edit form enforces this by forcing the private scheme when you enable
gating. A configuration import does **not** run that form, so an exported
`field.storage.*.yml` carrying `file_gate.gated: true` alongside
`uri_scheme: public` would install a field that claims to be gated and is not.
The module rejects that import and reports any site already in that state on the
status report — but if you hand-edit exported configuration, this is the pairing
to keep intact.

Changing an existing field to the private scheme does not move files that are
already stored publicly. They stay where they are, and stay readable, until they
are re-uploaded or migrated.

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

### Built-in methods

Five methods ship in the core module; three more ship in optional submodules (each
noted below). All are complete — new methods are added by third parties or future
submodules, not tracked as a roadmap here.

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
