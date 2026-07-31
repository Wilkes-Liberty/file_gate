# File Gate — program plan & tracking

**Status:** living document (updated 2026-07-31)  
**Gap-closure release:** merged to `1.x` as **1.4.0** (2026-07-31)

---

## Stated goal

**Operators and authorized users authenticate once with a hardware-backed
credential (YubiKey / PIV) at the site Identity Provider. That same assurance
level gates Drupal session access and File Gate high-assurance downloads, and
can be reused by future auth-required features — without registering the key a
second time in Drupal or File Gate.**

Supporting goals for the **module** (contrib product):

1. Ship a security-literate, enterprise-usable gated-file stack on Drupal 11+.
2. Keep the grant core (HMAC, scopes, locks) stable; extend via plugins and docs.
3. Dual-venue tracking (GitHub + drupal.org); no AI authorship credit.

---

## Architecture decision (enterprise default)

| Decision | Choice |
|----------|--------|
| Sole hardware Relying Party | **Identity Provider (Keycloak at W&L)** |
| Site login | OIDC SSO into Drupal (`openid_connect`) |
| High-assurance downloads | File Gate **`assurance`** method as **OIDC RP** (`verify_at: redeem` + bridge) |
| Native File Gate WebAuthn | **Optional / contrib fallback** when no IdP WebAuthn; **not** the W&L primary path |
| Mint secrets | Capability credentials; prefer scoped named secrets + identity-aware mint |
| Durable audit | Soft optional **`audit_chain`** (`docs/AUDIT.md`) |

Full W&L-specific narrative: `docs/KEYCLOAK-UNIFIED-AUTH.md`.  
Design history: `docs/design/piv-cac-webauthn.md`.

---

## Workstreams

```
A  Ship gap-closure on 1.x          (code on feature/file-gate-gap-closure)
B  File Gate product backlog        (remaining OSS gaps, dual-venue)
C  Unified hardware auth (W&L)      (Keycloak + Drupal + File Gate glue)
D  Ops / dogfood                    (E2E, rotation, audit_chain on site)
```

---

## A — Gap-closure release (branch `feature/file-gate-gap-closure`)

Implements recommended order from the 2026-07-31 full-module review.

| Item | Status | Trackers |
|------|--------|----------|
| #40 Step-up open redirect | **Shipped 1.4.0** | GH #40 / d.o #3614254 |
| #39 OTP named secrets | **Shipped 1.4.0** | GH #39 / d.o #3614253 |
| #38 WebAuthn enrollment UI | **Shipped 1.4.0** | GH #38 / d.o #3614251 |
| #37 Manual E2E checklist | **Shipped 1.4.0** | GH #37 / d.o #3614250 |
| #36 Mint-time OIDC A2 | **Shipped 1.4.0** | GH #36 / d.o #3614249 |
| Dual-key secret rotation | **Shipped 1.4.0** | `docs/SECRET_ROTATION.md` |
| Forced identity mint | **Shipped 1.4.0** | config + field setting |
| Multi-field determinism | **Shipped 1.4.0** | mint `field` + strictest-wins |
| Soft audit_chain | **Shipped 1.4.0** | `docs/AUDIT.md` |
| Download flood, revoke scope/jti | **Shipped 1.4.0** | — |
| Authenticated role allowlist | **Shipped 1.4.0** | — |
| Kernel tests (subset) | **Shipped 1.4.0** | open-redirect, named OTP, dual-key |
| Merge + tag release | **Shipped** | PR #47 → 1.x → tag **1.4.0** |

**Exit criteria for A:** PR merged to `1.x`, release notes in CHANGELOG, tags cut,
dual-venue issues Fixed/closed when shipped, d.o project page notes if needed.

---

## B — File Gate product backlog (after A)

| Priority | Topic | Why | Ticket |
|----------|--------|-----|--------|
| P0 | Drupal session → assurance bridge (same-origin) | Seamless downloads when already SSO’d with high acr | **new** |
| P0 | Step-up → IdP authorize helper (ACR in authorize URL) | Standard redeem path without hand-built JS | **new** |
| P1 | File Gate resource audience / token-exchange notes | Correct `aud` for A2 and redeem | **new** (docs + optional helper) |
| P1 | OTP redeem without query string | Leak reduction (POST / cookie exchange) | **new** |
| P1 | Signed-url grant inventory API | List outstanding jtis for an account/field | **new** |
| P2 | Commerce order-scan performance | Large B2B accounts | **new** |
| P2 | Pre-shared token TTL / max uses | Campaign token hygiene | **new** |
| P2 | Charts / Prometheus metrics | Ops beyond dblog | backlog |
| — | Keep native WebAuthn docs as secondary path | Contrib sites without IdP | existing #38/#37 |

---

## C — Unified hardware auth (W&L platform)

**Not all of this lives in the file_gate repo.** Jira DEV is authority; GitHub
issues on `infra` / `webcms` are implementation records.

| Phase | Work | Repo | Ticket |
|-------|------|------|--------|
| C1 | Keycloak WebAuthn (YubiKey) for operator login | infra | **new** |
| C2 | Stable `acr` mapping for WebAuthn (document exact string) | infra | **new** (with C1) |
| C3 | Optional PIV/X.509 authenticator or edge mTLS → KC | infra | **new** (later) |
| C4 | Drupal OIDC: refresh / retain usable tokens; record acr at login | webcms | **new** |
| C5 | File Gate field config on W&L site (issuer, aud, acr, step-up URL) | webcms | **new** |
| C6 | File Gate step-up + session bridge integration (depends B P0) | file_gate + webcms | **new** |
| C7 | Operator browser access policy on KC clients (related infra#477) | infra | link existing |
| C8 | Future features: “require hardware ACR” pattern doc | internal | **new** |

**Exit criteria for C:** One YubiKey enrolls only in Keycloak; Drupal login and
assurance-gated downloads both require that ACR; no second enrollment UI required
for operators.

---

## D — Ops / dogfood

| Work | Ticket |
|------|--------|
| Run `docs/E2E-ASSURANCE.md` against Keycloak WebAuthn (not only native RP) | extend #37 |
| Enable `audit_chain` on W&L Drupal; configure signing key; `drush audit-chain:verify` | **new** (webcms) |
| Secret rotation drill using `docs/SECRET_ROTATION.md` | ops note |
| Compromised-secret tabletop | ops note |

---

## Document map

| Doc | Purpose |
|-----|---------|
| **This file (`PLAN.md`)** | Goal, decisions, workstreams, ticket index |
| `KEYCLOAK-UNIFIED-AUTH.md` | W&L + enterprise IdP-first design |
| `assurance-redeem.md` | Redeem / bridge / A2 / enrollment |
| `AUDIT.md` | audit_chain soft integration |
| `SECRET_ROTATION.md` | Dual-key runbook |
| `E2E-ASSURANCE.md` | Manual hardware checklist |
| `API.md` | HTTP contracts |
| `design/piv-cac-webauthn.md` | Original design record |
| `SECURITY.md` | Operator security policy |

---

## Ticket index (filled when issues are filed)

Update this table when creating or closing issues. Do not invent keys.

### File Gate (GitHub Wilkes-Liberty/file_gate + d.o)

| Topic | GH | d.o | State |
|-------|----|-----|--------|
| Open redirect | [#40](https://github.com/Wilkes-Liberty/file_gate/issues/40) | [#3614254](https://www.drupal.org/project/file_gate/issues/3614254) | **Closed / Fixed in 1.4.0** (mark d.o Fixed if not yet) |
| OTP named secrets | [#39](https://github.com/Wilkes-Liberty/file_gate/issues/39) | [#3614253](https://www.drupal.org/project/file_gate/issues/3614253) | **Closed / Fixed in 1.4.0** (mark d.o Fixed if not yet) |
| Enrollment UI | [#38](https://github.com/Wilkes-Liberty/file_gate/issues/38) | [#3614251](https://www.drupal.org/project/file_gate/issues/3614251) | **Closed / Fixed in 1.4.0** (mark d.o Fixed if not yet) |
| Manual E2E | [#37](https://github.com/Wilkes-Liberty/file_gate/issues/37) | [#3614250](https://www.drupal.org/project/file_gate/issues/3614250) | **Closed / Fixed in 1.4.0** (mark d.o Fixed if not yet) |
| A2 mint OIDC | [#36](https://github.com/Wilkes-Liberty/file_gate/issues/36) | [#3614249](https://www.drupal.org/project/file_gate/issues/3614249) | **Closed / Fixed in 1.4.0** (mark d.o Fixed if not yet) |
| Session bridge from Drupal SSO | [#41](https://github.com/Wilkes-Liberty/file_gate/issues/41) | [#3614264](https://www.drupal.org/project/file_gate/issues/3614264) | Open |
| IdP step-up authorize helper | [#42](https://github.com/Wilkes-Liberty/file_gate/issues/42) | [#3614265](https://www.drupal.org/project/file_gate/issues/3614265) | Open |
| OTP without query string | [#43](https://github.com/Wilkes-Liberty/file_gate/issues/43) | [#3614266](https://www.drupal.org/project/file_gate/issues/3614266) | Open |
| Grant inventory API | [#44](https://github.com/Wilkes-Liberty/file_gate/issues/44) | [#3614267](https://www.drupal.org/project/file_gate/issues/3614267) | Open |
| Commerce scale | [#45](https://github.com/Wilkes-Liberty/file_gate/issues/45) | [#3614268](https://www.drupal.org/project/file_gate/issues/3614268) | Open |
| Pre-shared token TTL | [#46](https://github.com/Wilkes-Liberty/file_gate/issues/46) | [#3614269](https://www.drupal.org/project/file_gate/issues/3614269) | Open |

### Platform (Jira DEV + GH)

| Topic | Jira | GH | State |
|-------|------|-----|--------|
| Epic: unified hardware auth | **[DEV-221](https://wilkesliberty.atlassian.net/browse/DEV-221)** | — | Open |
| Keycloak WebAuthn + ACR | [DEV-222](https://wilkesliberty.atlassian.net/browse/DEV-222) | [infra#503](https://github.com/Wilkes-Liberty/infra/issues/503) | Open |
| Keycloak PIV/X.509 follow-on | [DEV-223](https://wilkesliberty.atlassian.net/browse/DEV-223) | [infra#504](https://github.com/Wilkes-Liberty/infra/issues/504) | Open |
| Drupal OIDC token refresh / acr | [DEV-224](https://wilkesliberty.atlassian.net/browse/DEV-224) | [webcms#479](https://github.com/Wilkes-Liberty/webcms/issues/479) | Open |
| Site File Gate assurance config | [DEV-225](https://wilkesliberty.atlassian.net/browse/DEV-225) | [webcms#480](https://github.com/Wilkes-Liberty/webcms/issues/480) | Open |
| audit_chain on W&L site | [DEV-226](https://wilkesliberty.atlassian.net/browse/DEV-226) | [webcms#481](https://github.com/Wilkes-Liberty/webcms/issues/481) | Open |

**Branch key for all platform work under this epic:** `DEV-221` (e.g. `feature/DEV-221-keycloak-webauthn`).

---

## Method of work

1. **One goal, many trackers** — this PLAN is the map; tickets are the units.
2. **Ship A before building C6** — gap-closure must be on `1.x` first.
3. **IdP before native RP** — do not dogfood W&L on File Gate native WebAuthn as primary.
4. **Dual-venue for OSS** — every new File Gate issue gets d.o the same day.
5. **DEV key on platform branches** — `feature/DEV-N-slug` for infra/webcms work.
6. **Close tickets only when reality matches** — merged+deployed for platform; release tag for module.

---

## Immediate next actions (operator)

1. Review/merge `feature/file-gate-gap-closure` → tag when ready.
2. Close GH/d.o #36–#40 when the release ships (Fixed → Closed).
3. Execute workstream **C1** (Keycloak WebAuthn) in parallel with remaining **B** items.
4. Keep this PLAN ticket index updated as each issue is created or closed.
