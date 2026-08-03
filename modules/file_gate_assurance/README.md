# File Gate Assurance

Gate file delivery behind a **hardware-backed, phishing-resistant** assurance
level — PIV/CAC smart cards (HSPD-12 / FIPS 201) or FIDO2/WebAuthn (e.g. a
YubiKey) — proven at any standards-compliant **OIDC** Identity Provider. This
submodule adds one File Gate gate method, `assurance`, and a provider-agnostic
OIDC token verifier with opt-in **DPoP** (RFC 9449) sender-constraining.

See the full design rationale in
[`../../docs/design/piv-cac-webauthn.md`](../../docs/design/piv-cac-webauthn.md).

## Honest scope (read first)

File Gate is an OIDC **Relying Party**. It verifies the IdP's signature and
claims on a token the IdP issued *after* the hardware authentication — it never
validates PIV certificate chains or WebAuthn attestations itself. That makes this
**federation (NIST SP 800-63C): an *asserted* assurance level**, not File Gate
acting as an AAL3 **verifier** under 800-63B.

A signed download URL is a **bearer capability**, so the delivery step is not
itself AAL3-bound — *unless* you enable DPoP, which sender-constrains the token to
a key the client proves possession of on each request. Do not describe a plain
(non-DPoP) delivery as AAL3. FIPS-validated crypto, reauthentication, and session
limits live at the IdP and the authenticator, not here.

## Requirements

- The `file_gate` module.
- The [`firebase/php-jwt`](https://packagist.org/packages/firebase/php-jwt)
  library (`^6.10 || ^7.0`): `composer require firebase/php-jwt`. The parent
  module does not require it, keeping File Gate's core dependency-light.

## How it works

The `assurance` method extends `signed_url`: it mints and validates the same
short-lived HMAC grant (inheriting `ttl`, `available_until`, `max_uses`) and
binds the asserted level (`aal`) into the signature. The assurance check runs
*before* the signature/usage check, so a failed check never spends a
usage-limited grant. Two modes, chosen by `verify_at`:

- **`redeem` (default — Model B, plain-link primary):** open the signed download
  URL normally. Without a live proof, File Gate challenges (302 step-up page or
  401 JSON). After `POST /api/file-gate/assurance/bridge` with a valid OIDC
  token (optional DPoP), a short-lived HttpOnly cookie lets the **same plain
  URL** stream the file. Direct `Authorization` on download still works. See
  [`docs/assurance-redeem.md`](../../docs/assurance-redeem.md).
- **`mint` (Model A):** the trusted mint caller has already stepped the user up;
  File Gate binds the level as an audit claim and trusts the caller (consistent
  with the mint trust model). Works with plain direct-navigation downloads, but
  the URL is a bearer capability — not itself AAL3-bound.
- **`webauthn` (native RP):** File Gate runs the WebAuthn assertion ceremony for
  a registered authenticator (`web-auth/webauthn-lib`), then sets the same
  session bridge cookie. Register keys via
  `/api/file-gate/webauthn/register/*` (permission *Register File Gate WebAuthn
  credentials*). Configure RP ID + allowed origins on the field.

## Configuration

Gate a field with the `assurance` method and set its `method_settings` (field
storage third-party settings):

Configure it on the field's settings page (a per-method settings form is provided
in the UI), or in exported YAML:

```yaml
third_party_settings:
  file_gate:
    gated: true
    method: assurance
    method_settings:
      verify_at: redeem                 # 'redeem' (default), 'mint', or 'client_cert'
      aal: 3                            # bound into the grant (audit + tamper)
      trusted_issuers:                  # trusted OIDC issuers (required for redeem)
        - issuer: 'https://idp.example.gov'
          audience: 'file-gate-api'     # this issuer's expected token aud
          required_acr:                 # acceptable acr values — as THIS IdP emits
            - 'http://idmanagement.gov/ns/assurance/aal/3'
        - issuer: 'https://sso.partner.example'
          audience: 'file-gate-partner'
          required_acr:
            - 'urn:partner:acr:phrh'
      required_amr: []                  # optional, advisory; enforced only if set
      dpop: false                       # true = require an RFC 9449 DPoP proof
      introspect: false                 # true = RFC 7662 live revocation check
      introspection_endpoint: ''        # required when introspect is true
      introspection_client_id: ''       # optional; secret is env-injected (below)
      leeway: 60                        # clock-skew tolerance (seconds)
      # edge-mTLS mode (verify_at: client_cert):
      trusted_proxy_header: ''          # header your proxy sets to the cert subject
      allowed_subjects: []              # optional DN allowlist; empty = any valid cert
      # inherited from signed_url:
      ttl: 120
      max_uses: 1
```

A presented token is matched to **exactly one** entry by its `iss` claim: only
that entry's audience and acr values apply — there is no cross-matching between
entries and no laxer fallback when no entry matches. The legacy single-issuer
keys (`issuer`, `audience`, `required_acr` directly under `method_settings`)
keep working forever and behave as a one-entry list; saving the field's
settings form migrates them to `trusted_issuers`.

| Setting | Meaning |
|---|---|
| `verify_at` | `redeem` (verify a live token at delivery), `mint` (trust the caller; audit binding only), or `client_cert` (edge mTLS — below). |
| `aal` | The assurance level bound into the signed grant (audit + downgrade protection). |
| `trusted_issuers` | The trusted OIDC issuers. Each entry has its own `issuer` URL (JWKS via OIDC discovery), `audience`, and `required_acr` list. Matched exactly-one by the token's `iss`; duplicate issuers invalidate the whole set (every token denied). Required for `redeem`. |
| `trusted_issuers[].issuer` | That entry's OIDC issuer URL, compared byte-exactly against the token's `iss`. |
| `trusted_issuers[].audience` | The token audience to require for that issuer. |
| `trusted_issuers[].required_acr` | Acceptable `acr` values for that issuer, **exactly as it emits them**. Empty denies. The decision is driven by `acr` (IdP policy). |
| `required_amr` | Optional advisory `amr` values to also require. Off unless set; `amr` is advisory (RFC 8176). |
| `dpop` | `true` to require a DPoP proof (RFC 9449) sender-constraining the token. |
| `introspect` | `true` for a live RFC 7662 revocation check (adds a round-trip). Needs `introspection_endpoint`; the client secret is injected globally (below), never stored here. |
| `trusted_proxy_header` / `allowed_subjects` | Edge-mTLS mode — see below. |

### Per-user binding (optional)

By default a valid token from *any* sufficiently-assured user redeems the URL. To
tie a grant to one person, the trusted back end passes the user's subject in the
**mint** request body (`{ "file": "…", "subject": "<sub>" }`). File Gate binds
only `hash(subject)` into the signed URL, and at redemption the presented token's
`sub` must match. (Binding a caller-asserted subject is safe: redemption still
requires a valid IdP token for that subject.)

### Edge mTLS (PIV via a reverse proxy)

`verify_at: client_cert` enforces PIV/CAC at the download **without** File Gate
doing any PKI. Terminate the client-certificate TLS at your reverse proxy / load
balancer (validating against the Federal PKI trust store), and have it pass the
validated certificate subject in a header. **The proxy plus its trust store is
the verifier; File Gate consumes the result.**

- `trusted_proxy_header` — the header the proxy sets (e.g. `X-Client-Cert-Dn`).
- `allowed_subjects` — optional exact-match DN allowlist; empty accepts any
  subject the proxy validated.

> **SECURITY:** this trusts a request header, so it is only safe when File Gate is
> reachable **exclusively** through that proxy and the proxy strips any
> client-supplied copy of the header.

### Introspection secret

When `introspection_client_id` is set, the matching client **secret** is injected
from the environment into global config — never stored in field settings:

```php
// settings.php
$config['file_gate.settings']['introspection_client_secret'] = getenv('FILE_GATE_INTROSPECTION_SECRET');
```
| `leeway` | Clock-skew tolerance in seconds (default 60). |

`acr` values are **entirely IdP-configured** — pin to whatever your IdP emits.
Common federal example: login.gov / ICAM emit
`http://idmanagement.gov/ns/assurance/aal/3` (and `…/aal/3?hspd12=true` for PIV).
A commercial IdP (Okta, Entra ID, Ping, …) emits its own step-up ACR — use that.

## Front-end integration (Model B)

Because the download endpoint must receive the token, redeem with `fetch` rather
than a plain link:

```js
const res = await fetch(downloadUrl, {
  headers: { Authorization: `Bearer ${accessToken}` },      // or `DPoP ${token}`
});
const blob = await res.blob();
// …hand the blob to the user (object URL / download).
```

With DPoP enabled, send `Authorization: DPoP <token>` plus a `DPoP: <proof>`
header (a per-request proof JWT bound to the method + URL); your OIDC client
library generates it.

## IdP setup (non-normative examples)

The module is provider-agnostic; configure your IdP to authenticate with the
hardware authenticator and emit the `acr` you list in `required_acr`:

- **PIV/CAC:** an x509 / smart-card authentication flow; the IdP performs
  certificate path validation (CRL/OCSP, FIPS 201 policies).
- **FIDO2/WebAuthn:** a passwordless WebAuthn authenticator with user
  verification and a resident key.

Keycloak, Okta, Ping, Entra ID, ForgeRock, login.gov, Authentik, and Zitadel can
all do this; the specifics are the IdP's, not File Gate's.

## Security notes

- Algorithm is pinned to the IdP's published JWKS keys, never the token header
  (`none`/HMAC rejected). The File Gate HMAC `download_secret` is never used as a
  JWT key.
- The issuer and its JWKS come from configuration, never the token (no SSRF).
  The token's unverified `iss` only *selects* among the admin-configured
  trusted issuers; an issuer no entry matches is denied without any discovery
  or JWKS network traffic, and the verified claims' `iss` is re-checked after
  signature verification.
- DPoP proofs are checked for `htm`/`htu` binding, freshness, single use (replay
  protection), and that the token's `cnf.jkt` matches the proving key.
- Mid-grant IdP session revocation is not reflected until the token expires;
  token introspection (RFC 7662) is a possible future addition.
