# Unified hardware authentication (IdP-first)

**Audience:** operators and integrators who run File Gate behind a real IdP
(Keycloak, login.gov-style ICAM, Okta, Entra, …).  
**W&L status:** delivered for staging (2026-08-01). Keycloak emits the frozen ACR
string **`phrh`** (phishing-resistant hardware-protected, OpenID EAP vocabulary)
when a WebAuthn step-up completes; plain password+TOTP logins emit `"1"`. Copy
`phrh` byte-exact into `required_acr`. The site-specific contract (issuer,
step-up URL, flow design, rollback) lives in the infra repo's
`docs/runbooks/KEYCLOAK_WEBAUTHN_STEPUP.md`; program state is `PLAN.md`
workstream C.

---

## Goal

A user enrolls a **YubiKey or PIV once at the Identity Provider**. That credential
is used for:

1. **Site login** (Drupal via OIDC SSO),
2. **High-assurance File Gate downloads** (assurance method),
3. **Future** auth-required product features,

without a second hardware enrollment in Drupal or File Gate.

---

## Decision record

| # | Decision |
|---|----------|
| D1 | The **IdP is the sole hardware Relying Party** for operators. |
| D2 | Drupal is an OIDC client; session cookie authorizes normal HTML after SSO. |
| D3 | File Gate **assurance** verifies IdP assertions (`acr` / optional DPoP), not the hardware crypto itself (NIST SP 800-63C federation). |
| D4 | File Gate **native WebAuthn** remains available for sites without IdP WebAuthn; it is **not** the primary path when an IdP is in use. |
| D5 | Plain-link download + session bridge (`FG_AB`) is the primary redeem UX. |
| D6 | Mint secrets stay server-to-server; prefer identity binding (`account`/`uid`/`subject`) for authenticated products. |

---

## Trust boundaries

```
[YubiKey/PIV] ──► [Keycloak / IdP] ──OIDC──► [Drupal SSO]
                         │                        │
                         │ acr + sub              │ PHP session
                         │                        │
                         └──── OIDC token ──► [File Gate assurance]
                                              HMAC grant still required
```

- **IdP** proves hardware auth and emits `acr` (and `sub`).
- **File Gate** checks the grant (HMAC) **and** live (or recently bridged)
  assurance. The bridge cookie is not a substitute for a valid grant.
- **Drupal session alone** is not enough for high-assurance files unless the
  **session bridge SSO path** (GH #41) re-checks a live access token from
  `openid_connect` (issuer/aud/acr) and sets `FG_AB`. Stale tokens still fail
  closed — refresh remains a site OIDC concern.

---

## Recommended field configuration (IdP path)

| Setting | Recommendation |
|---------|----------------|
| Method | `assurance` |
| `verify_at` | `redeem` |
| `issuer` | IdP issuer URL (e.g. Keycloak realm) |
| `audience` | Resource audience for File Gate (may need mapper or token exchange) |
| `required_acr` | Exact string(s) IdP emits for WebAuthn/PIV |
| Bridge | Enabled |
| `step_up_login_url` | IdP **authorize** URL (absolute https); module may append `acr_values` (GH #42) |
| `step_up_append_acr` | On (default) — append field `required_acr` as `acr_values` |
| `session_bridge_sso` | On (default) — use openid_connect session token same-origin (GH #41) |
| `verify_oidc_at_mint` | On only if mint BFF can present File-Gate-audienced tokens (A2) |
| Native `verify_at: webauthn` | Off for IdP-first deployments |

See `assurance-redeem.md` and `API.md`.

---

## Token audience

SPA/Drupal browser clients often have `aud` = that client. File Gate pins
**its** audience. Choose one:

1. **Audience mapper** — access token includes File Gate client id in `aud`.
2. **RFC 8693 token exchange** — BFF exchanges user token for File Gate audience
   (fits A2 mint-time verify).
3. **Multi-audience access tokens** — IdP lists both clients in `aud`.

Without one of these, correct audience pinning rejects the SPA token at File Gate
(by design).

---

## User journeys

### A. First login of the day (operator)

1. Hit Drupal → SSO redirect → IdP.
2. Authenticate with YubiKey/PIV (after IdP WebAuthn/PIV is enabled).
3. Drupal session established; authmap links OIDC `sub` to Drupal user.

### B. Gated download (plain link)

1. Trusted backend mints signed URL (shared secret; optional `subject` = `sub`).
2. Browser opens download URL.
3. No bridge yet → step-up page → IdP (or silent if IdP session still high ACR).
4. Bearer presented to `/api/file-gate/assurance/bridge` → `FG_AB` cookie.
5. Same URL streams the file; `max_uses` / TTL still apply.

### C. Same-origin already logged in (planned)

When a Drupal session exists with a recent high-ACR OIDC login, a future
integration may establish `FG_AB` without a separate JS token handoff — only if
`sub` matches grant `sh=` and ACR policy is satisfied. Until then, journey B
applies.

---

## What not to do

- Do not enroll the same YubiKey only in File Gate for W&L operators.
- Do not treat long-lived Drupal sessions as perpetual AAL3 without re-auth policy.
- Do not mint high-assurance grants with a shared secret and no subject/identity
  when the product is “named user only.”
- Do not put secrets or full tokens in audit_chain metadata.

---

## W&L inventory (current)

| Component | Today | Target |
|-----------|--------|--------|
| Keycloak MFA | TOTP | WebAuthn (YubiKey); PIV later |
| Drupal login | openid_connect + wl_sso_redirect | unchanged pattern; higher ACR |
| OIDC tokens in session | Stored at login; not auto-refreshed | refresh or re-auth for live File Gate token |
| File Gate on site | Module product; assurance configurable | issuer/aud/acr + step-up to Keycloak |
| Native WebAuthn UI | Available in module | Fallback only |

Platform tickets: see `PLAN.md` workstream C.

---

## Related module docs

- `PLAN.md` — goal, workstreams, ticket index  
- `assurance-redeem.md` — redeem protocol  
- `E2E-ASSURANCE.md` — lab checklist (extend with Keycloak WebAuthn)  
- `design/piv-cac-webauthn.md` — original design decisions  
