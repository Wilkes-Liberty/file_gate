# Design note: PIV/CAC + FIDO2/WebAuthn assurance (`file_gate_assurance`)

Status: **implemented / accepted** — shipped in the `file_gate_assurance`
submodule (see
[issue #6](https://github.com/Wilkes-Liberty/file_gate/issues/6)). This note is
retained as the design record; the decisions table at the end records how each
question was resolved as built. Two hardenings were added beyond the original
two-model framing — see "As shipped" below.

This note designs a gate method that delivers a gated file only after
phishing-resistant, hardware-backed authentication — PIV/CAC smart cards
(HSPD-12 / FIPS 201) or FIDO2/WebAuthn (e.g. YubiKey) — proven through a standard
OIDC Identity Provider. It answers three questions: **where** the assertion is
verified, **how** the assurance level is conveyed to File Gate, and **how** it is
bound into the grant.

## Provider-agnostic by design

File Gate integrates with **any** standards-compliant OIDC Identity Provider —
Keycloak, Okta, Ping, Entra ID, ForgeRock, login.gov, Authentik, Zitadel, … — via
OIDC discovery + JWKS. It hard-codes **no** assumptions about, and takes **no**
hard dependency on, a specific IdP. Vendor names in this note are non-normative
examples only. The contract is the standard OIDC token: an `acr` claim mapped, at
the IdP, to an assurance level the site configures.

## Honest scope (read first)

- The AAL3 authentication **event** happens at the IdP + the PIV card / FIDO2
  authenticator. File Gate is an OIDC **Relying Party** consuming an assertion.
  This is **federation — NIST SP 800-63C — an *asserted* assurance level**, not
  File Gate acting as an AAL3 **verifier** under 800-63B.
- File Gate does **not** validate PIV x509 chains (CRL/OCSP, FIPS 201 policies),
  verify WebAuthn attestation/challenge, or assert any FIPS 140 boundary — those
  belong to the authenticator and the IdP.
- **Holder-of-key caveat:** a signed download URL is a **bearer capability**, so
  the *delivery step* is not itself AAL3-bound even when the login was — unless the
  delivery token is proof-of-possession bound (DPoP; opt-in, below).
- Honest phrasing for docs: *"AAL3 (asserted at the IdP) gates the authorization
  decision; file delivery is a short-lived bearer capability unless DPoP-bound."*
  Do not claim the module "provides AAL3" or that a plain download is AAL3.

## Where the assertion is verified — two models

### Model A — verify at mint, bind the asserted level (decoupled default)

The front end authenticates the user to AAL3 via its IdP; its back end calls the
mint endpoint.

- **A1 (recommended default):** trust the secret-holding caller's asserted level —
  consistent with the existing mint trust model (the mint endpoint already trusts
  the secret-holder). File Gate records the level for audit; it does not
  independently verify a token. Honestly labeled "RP-asserted."
- **A2 (stronger, shipped as opt-in):** File Gate verifies the user's OIDC token
  at mint when field setting `verify_oidc_at_mint` is enabled. The token's `aud`
  must be File Gate's audience — use **RFC 8693 token exchange** or an IdP
  audience mapper; SPA-only tokens fail audience pin by design. Fail closed on
  missing/invalid token, wrong acr (empty allowlist denies), or failed
  introspection when enabled.
- Redemption is a normal direct-navigation signed-URL GET; the signature vouches
  the level was checked at mint. Mitigate the bearer window with a very short TTL,
  `max_uses=1`, `referrer_lock`, and TLS.
- **Subject binding is not enforceable in Model A:** direct navigation presents no
  identity to compare, so the bound level/subject are self-attestations under File
  Gate's own HMAC — they gate what mint *issues*, not what redemption *verifies*.

### Model B — verify at redemption (opt-in; same-origin or JS-driven)

- The download carries the OIDC token; the method's `grants()` validates it live
  (JWKS signature, `iss`/`aud`/`exp`, `acr`) and compares the token subject to a
  `sub_hash` bound at mint — **real per-user enforcement lives here.**
- Fits the plugin interface (`grants()` sees the request) but **not** headless
  direct navigation (you can't set `Authorization` on an `<a href>`). It requires
  a JS `fetch` + Bearer → Blob download (loses Range/resumable/native UX; whole
  file in memory) or a same-origin cookie/session (hard cross-origin).
- As a resource server, File Gate can issue an **RFC 9470** step-up challenge
  (`401 WWW-Authenticate: Bearer error="insufficient_user_authentication",
  acr_values="…"`) when the presented `acr` is too low.
- **Revocation:** a JWT stays valid until its own `exp` regardless of IdP session
  termination; true mid-grant revocation needs introspection (RFC 7662, opt-in).

### Opt-in hardening: DPoP proof-of-possession (RFC 9449)

The only way the **delivery** step approaches AAL3's holder-of-key requirement. In
**Model B**, accept a **DPoP-bound** access token: the client proves possession of
a private key on each request via a `DPoP` header JWT, and File Gate checks the
token's `cnf.jkt` thumbprint matches — so a stolen bearer token is useless without
the key. Trade-off: DPoP requires the client to send the header, so it applies to
the JS-`fetch` flow only, **not** plain `<a href>` navigation. (mTLS-bound tokens,
RFC 8705, are an alternative PoP mechanism with the same constraint.) DPoP ships
**opt-in**, off by default; sites needing PoP at delivery choose Model B + DPoP.

**Recommendation:** Model A (A1) as the decoupled default (honestly labeled);
Model B opt-in for same-origin / JS flows; DPoP (RFC 9449) opt-in hardening on
Model B; A2 later.

### As shipped (additions beyond this note)

Two hardenings landed in `file_gate_assurance` beyond the two models above:

- **Live revocation (RFC 7662 introspection), opt-in.** In Model B, the method can
  additionally introspect the presented token at redemption so an IdP-revoked
  session is denied before its `exp`. The introspection client secret is injected
  from the environment (`file_gate.settings:introspection_client_secret`), never
  stored in field config.
- **A third `verify_at` mode, `client_cert` (edge mTLS).** File Gate trusts a
  PIV/CAC certificate subject that an mTLS-terminating reverse proxy validated
  against the Federal PKI and passed in a configured header, checked against a
  **required** subject allowlist. The header is only trustworthy when File Gate is
  reachable *solely* through that proxy; the mode fails closed without an
  allowlist. This is the closest File Gate gets to a verifier-adjacent posture,
  and it is still the proxy + PKI — not File Gate — doing the certificate
  validation. A2 (verify the OIDC token at mint) was **not** built; it still needs
  the file-gate-audienced-token story (decision #4).

## How assurance is conveyed

- Drive the decision off OIDC **`acr`**, mapped **at the IdP** to the required
  level (e.g. an ICAM URI like `http://idmanagement.gov/ns/assurance/aal/3`, or any
  value the IdP emits). `acr` values are IdP-configured; the field pins to exactly
  what *your* IdP emits — none is canonical across providers.
- **`amr` is advisory (RFC 8176) — informational only, never the access decision.**
  RFC 8176 registers `sc` (smart card → PIV/CAC x509), `hwk`, `user`, `mfa`; it
  does **not** register `pki`/`pop`. Many IdPs do not emit `amr` without a mapper —
  another reason to rely on `acr`.
- The field declares the required `acr` value(s) as opaque strings the admin copies
  from their IdP. No provider names or values are baked into the module. IdP setup
  (x509 / WebAuthn flows, acr-to-LoA mapping, CRL/OCSP/FIPS-201 path validation) is
  the IdP's responsibility; the note ships only non-normative examples.

## How it is bound into the grant

- Bind a single normalized scalar `aal` (e.g. `3`) and, for Model B, a
  `sub_hash = hash('sha256', subject)` into the signed claims.
- **Mandate hashing the subject and a scalar `aal`:** the grant signer renders
  claims as unescaped `key=value` joined by `&` with no value escaping, so a raw
  `sub` containing `&`/`=` could collide. Never bind a raw `sub`; never bind an
  `amr` array (the signer is scalar-only) — bind one normalized level.
- **Prerequisite refactor:** `SignedUrl::grants()` reconstructs the signed claim
  set from a hard-coded allowlist (`exp`, `nbf`, `jti`, `max`). A claim-binding
  subclass cannot reuse it (the parent won't reconstruct `aal`/`sub_hash`, so the
  HMAC fails closed). `SignedUrl` must first expose an overridable claim-key seam,
  with tests proving `signed_url` / `token` / `referrer_lock` are unaffected.

## Architecture

- A new **submodule `file_gate_assurance`** keeps the core module dependency-light
  (core File only). It provides the assurance method(s), a provider-agnostic
  OIDC/JWT verification service (OIDC discovery + JWKS), typed config schema, and a
  settings form.
- **No interface break:** verify the token in the mint controller / a service (it
  already holds the request), passing verified claims to the method via
  configuration or a narrow optional `AssuranceAwareGateMethodInterface` the
  controller feature-detects. The `mint(FileInterface): ?array` signature does not
  change (third-party plugins implement it).
- **Extends `signed_url`?** Model A: yes, after the claim-seam refactor. Model B:
  only if it also mints a signed URL binding `sub_hash`/`aal` plus a live check; a
  purely live method (mint returns `NULL`, like `authenticated`) should not extend
  `signed_url`.
- **JWT verification (normative):** configure the IdP by **issuer URL**; use OIDC
  discovery to find the JWKS. Select the verification key by trusted JWKS `kid`,
  and allowlist acceptable `alg` values for that key type (e.g. RS256/PS256 for
  RSA, ES256 for P-256); reject `none` and symmetric algorithms such as HS256.
  **Never reuse the File Gate HMAC `download_secret` as a JWT key** — keep the key domains
  separate. Take `iss`/JWKS from admin config, never the token's own `iss` (SSRF);
  cache JWKS by `kid` with a TTL and rate-limited refetch on unknown `kid`. Pin
  `aud` + `iss`; check `exp`/`nbf`/`iat` with bounded clock skew; reject the wrong
  `typ`. File Gate cannot verify the front end's `nonce`. With DPoP, validate the
  proof JWT and match `cnf.jkt`.
- **Config surface (as shipped):** per-method options are configured through a
  settings form on the field edit form (issuer, audience, `required_acr`, optional
  advisory `required_amr`, DPoP toggle, plus the introspection and edge-mTLS
  options). The `method_settings` bag itself stays `type: ignore` in config schema
  — it is polymorphic across gate methods — while the shared, env-injected
  `introspection_client_secret` is declared in the parent `file_gate.settings`
  schema.

## Security & compliance caveats (ship in the docs)

- Federation (800-63C), *asserted* AAL — not File-Gate-verified AAL3. Delivery is a
  bearer capability (Model A) unless DPoP-bound (Model B + RFC 9449).
- No FIPS 140 boundary in File Gate. Reauthentication / session limits are the
  IdP's. Mid-grant revocation requires introspection (Model B, RFC 7662).
- Provider-agnostic: no IdP is assumed; the admin supplies the issuer and `acr`
  values.
- Audit: log the asserted level, `sub_hash`, method, and decision.

## Decisions (resolved as shipped)

| # | Decision | Resolved as shipped |
|---|---|---|
| 1 | A1 (trust asserted level) vs A2 (verify token at mint) | A1 shipped as `verify_at: mint`; A2 **not** built (still needs the audience solution, #4) |
| 2 | Model A only / B only / both | Both — `verify_at: mint` (A) and `verify_at: redeem` (B), plus `client_cert` (edge mTLS) — with the honest caveat in docs |
| 3 | Refactor `SignedUrl` claim-reconstruction seam | Shipped — `signedClaimKeys()` / `extraMintClaims()`, with regression tests |
| 4 | File-Gate-audienced token for A2/B | Deferred — token exchange (RFC 8693) or an IdP mapper, when A2 is built |
| 5 | Interface: verify-in-controller + optional interface vs `mint()` change | Shipped as `ContextualMintInterface` (feature-detected by the mint controller); `mint()` unchanged |
| 6 | PoP at delivery: none / DPoP (9449) / mTLS (8705) | DPoP shipped opt-in on Model B (off by default); mTLS documented as the alternative |
| 7 | Revocation: valid-until-exp vs introspection | Introspection shipped optional (Model B); Model A limit documented |
| 8 | Assurance signal: `acr` policy vs `amr` | `acr` drives the decision; `amr` advisory only |
| 9 | Typed schema + settings form for the submodule | Settings form shipped; `method_settings` kept `type: ignore` (polymorphic), not per-method typed schema; `introspection_client_secret` declared in the parent schema |
| 10 | Claims contract: `sub_hash` + scalar `aal`; forbid `download_secret` reuse as JWT key | Shipped — scalar `aal` + `sh` (sha-256 subject hash) bound; JWT key domain kept separate; the signer canonicalisation was later hardened to be injective so a bound claim cannot be dropped |
| 11 | JWT/OIDC dependency (provider-agnostic) | `firebase/php-jwt` + OIDC discovery (a suggested dependency of the parent module) |

## Phased implementation (after the decisions are settled)

1. Refactor the `SignedUrl` claim-reconstruction seam (+ regression tests).
2. `file_gate_assurance`: config schema + settings form; provider-agnostic OIDC
   verification service; Model A (A1) method binding `aal`; kernel tests; docs.
3. Model B (live token verify + `sub_hash`) opt-in; RFC 9470 challenge; optional
   introspection.
4. DPoP (RFC 9449) opt-in hardening on Model B; then A2 once the audience story is
   settled.
