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

- **`redeem` (default — Model B):** the browser presents a live OIDC token at the
  download endpoint (via a JavaScript `fetch`, not a plain navigation) and the
  method verifies its signature (JWKS, algorithm pinned to the published keys),
  `iss`, `aud`, `exp`/`nbf`, and `acr` — optionally requiring a DPoP proof. Real,
  live, per-request enforcement.
- **`mint` (Model A):** the trusted mint caller has already stepped the user up;
  File Gate binds the level as an audit claim and trusts the caller (consistent
  with the mint trust model). Works with plain direct-navigation downloads, but
  the URL is a bearer capability — not itself AAL3-bound.

## Configuration

Gate a field with the `assurance` method and set its `method_settings` (field
storage third-party settings):

```yaml
third_party_settings:
  file_gate:
    gated: true
    method: assurance
    method_settings:
      verify_at: redeem                 # 'redeem' (default) or 'mint'
      aal: 3                            # bound into the grant (audit + tamper)
      issuer: 'https://idp.example.gov' # your OIDC issuer (required for redeem)
      audience: 'file-gate-api'         # expected token aud (required for redeem)
      required_acr:                     # acceptable acr values — as YOUR IdP emits
        - 'http://idmanagement.gov/ns/assurance/aal/3'
      required_amr: []                  # optional, advisory; enforced only if set
      dpop: false                       # true = require an RFC 9449 DPoP proof
      leeway: 60                        # clock-skew tolerance (seconds)
      # inherited from signed_url:
      ttl: 120
      max_uses: 1
```

| Setting | Meaning |
|---|---|
| `verify_at` | `redeem` (verify a live token at delivery) or `mint` (trust the caller; audit binding only). |
| `aal` | The assurance level bound into the signed grant (audit + downgrade protection). |
| `issuer` | The OIDC issuer URL. JWKS is found via OIDC discovery. Required for `redeem`. |
| `audience` | The token audience to require. Required for `redeem`. |
| `required_acr` | Acceptable `acr` values, **exactly as your IdP emits them**. Empty denies. The decision is driven by `acr` (IdP policy). |
| `required_amr` | Optional advisory `amr` values to also require. Off unless set; `amr` is advisory (RFC 8176). |
| `dpop` | `true` to require a DPoP proof (RFC 9449) sender-constraining the token. |
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
- DPoP proofs are checked for `htm`/`htu` binding, freshness, single use (replay
  protection), and that the token's `cnf.jkt` matches the proving key.
- Mid-grant IdP session revocation is not reflected until the token expires;
  token introspection (RFC 7662) is a possible future addition.
