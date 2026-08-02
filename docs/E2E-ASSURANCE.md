# Manual E2E checklist: assurance + WebAuthn

Kernel tests cover contracts. Hardware + real IdP ceremonies are **manual**
(and optional browser automation later). Record the last successful run on
GitHub [#37](https://github.com/Wilkes-Liberty/file_gate/issues/37) /
d.o [#3614250](https://www.drupal.org/project/file_gate/issues/3614250).

## Prerequisites

- HTTPS origin (WebAuthn and secure cookies).
- **Preferred:** IdP with WebAuthn or PIV (Keycloak, login.gov-style, etc.) —
  same key as site login. See `KEYCLOAK-UNIFIED-AUTH.md`.
- **Fallback:** YubiKey registered only in File Gate native WebAuthn.
- File Gate secret configured; assurance field with issuer, audience, acr.
- For native WebAuthn only: `web-auth/webauthn-lib`, field `verify_at: webauthn`,
  `rp_id` + origins; user registered at `/user/{uid}/file-gate-webauthn`.

## 0. IdP enrollment (once per operator)

The IdP path assumes the hardware key is enrolled **at the IdP**, not in File
Gate. Two routes exist when the IdP offers optional WebAuthn (the recommended
posture — nothing forces enrollment and password login keeps working):

- **Self-service, ahead of time:** the IdP's account console. Keycloak:
  Account Console → **Signing in** → **Two-factor authentication** →
  **Security key** → register, then name the key so multiple keys are
  distinguishable.
- **Inline, at first step-up:** with the register action enabled at the IdP, a
  user who hits the step-up flow (`acr_values` requested) without an enrolled
  credential is prompted to register in-line after their password factor, then
  continues. Verified behavior on Keycloak 26.

Checklist:

1. Enroll the key by either route.
2. Verify at the IdP that the credential exists (Keycloak admin:
   Users → *user* → Credentials → a `webauthn` entry) and carries the label
   you set.
3. Enroll a **second key or spare before relying on the first** — required
   before any enforcement phase.
4. Lost-key drill: confirm password(+OTP) login still works, remove the
   credential in the account console, re-enroll the replacement.

**Pass criteria:** credential visible at the IdP with the chosen label; login
without the key still works (enrollment is optional); the same key satisfies
the step-up in §1.

## 1. OIDC redeem + plain-link bridge (primary / IdP-first)

1. (W&L) Log into Drupal via Keycloak with the same YubiKey enrolled in §0.
2. Mint a grant for an assurance field (`verify_at: redeem`, bridge on);
   include `subject` = OIDC `sub` when testing per-user binding.
3. Open the signed download URL in a browser **without** Authorization.
4. Expect redirect or step-up page.
5. Complete IdP step-up (WebAuthn or PIV via IdP); set access token in
   `sessionStorage.file_gate_access_token` (or use configured step-up login URL
   from **field settings only** — not a query override). Token `aud` must
   satisfy File Gate audience (mapper or exchange).
6. Step-up establishes `FG_AB` bridge cookie; same URL streams the file.
7. Confirm `max_uses` / TTL: spent one-time link fails; expired grant fails.

**Pass criteria:** file bytes download; second use fails if max_uses=1;
**same physical key** works for site login and this path.

## 1b. Same-origin session bridge (when implemented)

When the Drupal session → File Gate bridge ships: while logged in via SSO with
sufficient ACR, open the download URL and expect bridge without a separate
token paste. Until then, mark this section N/A.

## 2. Native WebAuthn

1. Enroll a key at **Account → File Gate keys** (or JSON register APIs).
2. Mint with `subject` equal to the user handle (Drupal uid string by default).
3. Open plain download URL → step-up `mode=webauthn` → touch authenticator.
4. Bridge cookie set; file streams.

**Pass criteria:** assertion fails with no credentials; succeeds after enroll.

## 3. Failure modes

| Case | Expected |
|------|----------|
| Wrong `acr` | 401/403; no bridge |
| Spent one-time link | 403 |
| Expired grant | 403 |
| Missing credentials (WebAuthn) | clear error on assert options |
| Wrong `wh` / `sh` | assertion or redeem fail |
| Crafted `?login_url=https://evil` | **ignored**; only field step_up_login_url used |

## 4. DPoP (if enabled)

- Bearer without DPoP proof fails when `dpop` is on.
- Valid DPoP + token succeeds at bridge or redeem.

## 5. Edge mTLS (lab only)

- Proxy sets trusted subject header; allowlist match → pass.
- Direct hit with forged header → fail (network isolation required).

## Lab notes

| Date | Operator | Paths | Result |
|------|----------|-------|--------|
| 2026-08-02 | jmcerda | §0 IdP enrollment (2 keys) + OIDC step-up login (acr phrh, aud file-gate, 300 s lifespan; silent SSO re-auth inside 300 s recency window) | PASS |
| 2026-08-02 | jmcerda | §1 OIDC redeem: step-up page + fail-closed on acr "1" session OK; Bearer redeem blocked — simple_oauth intercepts the token before the bridge controller ([#3614535](https://www.drupal.org/project/file_gate/issues/3614535)) | FAIL |
| 2026-08-02 | jmcerda | §1 re-run on 1.5.1 (webcms staging): no-header POST reaches the bridge controller, any Bearer 401s pre-routing (route-independent) — the `_auth` route pin proven inert against global providers; root cause + fix constraints in [#56](https://github.com/Wilkes-Liberty/file_gate/issues/56), fixed by the 1.5.2 AuthorizationShield middleware. Full §1 re-run pending a site bump to 1.5.2 | FAIL (superseded by 1.5.2) |

Do not require CI runners to hold hardware keys.
