# File Gate — program plan & tracking

**Status:** living document (updated 2026-07-31)  
**Module releases:** **1.4.0** (gap-closure) tagged; backlog **#41–#46** merged to `1.x` (PR #48) — next minor tag when ready.

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
| Durable audit | Soft optional **`audit_chain`** (`docs/AUDIT.md`) — module integration shipped; site enable is platform work |

Full W&L-specific narrative: `docs/KEYCLOAK-UNIFIED-AUTH.md`.  
Design history: `docs/design/piv-cac-webauthn.md`.

---

## Workstreams

```
A  Gap-closure on 1.x               DONE — 1.4.0
B  File Gate product backlog        DONE on 1.x — tagged **1.5.0**
C  Unified hardware auth (W&L)      OPEN — Keycloak + Drupal + site config (all phases ticketed)
D  Ops / dogfood                    OPEN — E2E/rotation/tabletop ticketed; audit_chain **Done** on site
```

---

## A — Gap-closure (1.4.0)

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
| Merge + tag release | **Shipped** | PR #47 → tag **1.4.0** |

---

## B — File Gate product backlog

| Priority | Topic | Status | Ticket |
|----------|--------|--------|--------|
| P0 | Drupal session → assurance bridge | **Merged 1.x** (PR #48) | GH #41 / d.o #3614264 |
| P0 | IdP step-up ACR authorize helper | **Merged 1.x** | GH #42 / d.o #3614265 |
| P1 | OTP redeem without query string | **Merged 1.x** | GH #43 / d.o #3614266 |
| P1 | Signed-url grant inventory API | **Merged 1.x** | GH #44 / d.o #3614267 |
| P2 | Commerce order-scan performance | **Merged 1.x** | GH #45 / d.o #3614268 |
| P2 | Pre-shared token TTL / max uses | **Merged 1.x** | GH #46 / d.o #3614269 |
| P1 | File Gate resource audience / token-exchange notes | **Partial** (KEYCLOAK + assurance-redeem docs) | docs only unless new ticket |
| P2 | Charts / Prometheus metrics | **Backlog** | not filed |
| — | Native WebAuthn as secondary path | **Docs + 1.3/1.4** | — |

**Exit for B product code:** merged to `1.x`. Tag as **1.5.0** when cutting a release.

---

## C — Unified hardware auth (W&L platform)

**Not all of this lives in the file_gate repo.** Jira DEV is authority; GitHub
issues on `infra` / `webcms` are implementation records.

| Phase | Work | Repo | Ticket | State |
|-------|------|------|--------|--------|
| C1 | Keycloak WebAuthn (YubiKey) for operator login | infra | DEV-222 / [infra#503](https://github.com/Wilkes-Liberty/infra/issues/503) | **Merged** ([infra PR #514](https://github.com/Wilkes-Liberty/infra/pull/514)); staging live + verified; physical-key pass pending, prod binding = Phase C |
| C2 | Stable `acr` mapping for WebAuthn | infra | with C1 | **Done** — ACR frozen: `phrh` (contract in [infra#503](https://github.com/Wilkes-Liberty/infra/issues/503) comment; runbook `infra/docs/runbooks/KEYCLOAK_WEBAUTHN_STEPUP.md`) |
| C3 | Optional PIV/X.509 / edge mTLS → KC | infra | DEV-223 / [infra#504](https://github.com/Wilkes-Liberty/infra/issues/504) | **Open** |
| C4 | Drupal OIDC: refresh / retain tokens; record acr | webcms | DEV-224 / [webcms#479](https://github.com/Wilkes-Liberty/webcms/issues/479) | **Merged** ([webcms PR #488](https://github.com/Wilkes-Liberty/webcms/pull/488): wl_oidc_session); live on next webcms deploy, then the 300s staging token lifespan applies |
| C5 | File Gate field config on W&L site | webcms | DEV-225 / [webcms#480](https://github.com/Wilkes-Liberty/webcms/issues/480) | **In progress** — audience `file-gate` live on staging ([infra PR #517](https://github.com/Wilkes-Liberty/infra/pull/517) merged); site field config pending |
| C6 | Site step-up + session bridge dogfood | webcms | [webcms#484](https://github.com/Wilkes-Liberty/webcms/issues/484) (depends C1/C4/C5 + module #41) | **Open** |
| C7 | Operator browser access policy on KC clients | infra | [infra#477](https://github.com/Wilkes-Liberty/infra/issues/477) | **Open** |
| C8 | “Require hardware ACR” pattern doc | internal | [internal#82](https://github.com/Wilkes-Liberty/internal/issues/82) | **Open** |

Epic: [DEV-221](https://wilkesliberty.atlassian.net/browse/DEV-221).  
Branch key: `DEV-221` (e.g. `feature/DEV-221-keycloak-webauthn`).

---

## D — Ops / dogfood

| Work | Ticket | State |
|------|--------|--------|
| Run `docs/E2E-ASSURANCE.md` against Keycloak WebAuthn | [webcms#485](https://github.com/Wilkes-Liberty/webcms/issues/485) (after C1) | **Open** |
| Enable `audit_chain` on W&L Drupal; signing key; verify | DEV-226 / [webcms#481](https://github.com/Wilkes-Liberty/webcms/issues/481) | **Done** (v1.35.0 prod 2026-08-01) |
| Secret rotation drill | [infra#508](https://github.com/Wilkes-Liberty/infra/issues/508) | **Open** |
| Compromised-secret tabletop | [infra#509](https://github.com/Wilkes-Liberty/infra/issues/509) | **Open** |
| wl-onprem runner: Docker Desktop `credsStore` hang | [infra#510](https://github.com/Wilkes-Liberty/infra/issues/510) | **Open** (ops hygiene from 2026-08-01 staging deploy) |

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

## Ticket index

### File Gate (GitHub + d.o) — module product

| Topic | GH | d.o | State |
|-------|----|-----|--------|
| Open redirect | [#40](https://github.com/Wilkes-Liberty/file_gate/issues/40) | [#3614254](https://www.drupal.org/project/file_gate/issues/3614254) | **Done 1.4.0** |
| OTP named secrets | [#39](https://github.com/Wilkes-Liberty/file_gate/issues/39) | [#3614253](https://www.drupal.org/project/file_gate/issues/3614253) | **Done 1.4.0** |
| Enrollment UI | [#38](https://github.com/Wilkes-Liberty/file_gate/issues/38) | [#3614251](https://www.drupal.org/project/file_gate/issues/3614251) | **Done 1.4.0** |
| Manual E2E docs | [#37](https://github.com/Wilkes-Liberty/file_gate/issues/37) | [#3614250](https://www.drupal.org/project/file_gate/issues/3614250) | **Done 1.4.0** |
| A2 mint OIDC | [#36](https://github.com/Wilkes-Liberty/file_gate/issues/36) | [#3614249](https://www.drupal.org/project/file_gate/issues/3614249) | **Done 1.4.0** |
| Session bridge SSO | [#41](https://github.com/Wilkes-Liberty/file_gate/issues/41) | [#3614264](https://www.drupal.org/project/file_gate/issues/3614264) | **Done on 1.x** (PR #48) |
| IdP step-up ACR | [#42](https://github.com/Wilkes-Liberty/file_gate/issues/42) | [#3614265](https://www.drupal.org/project/file_gate/issues/3614265) | **Done on 1.x** |
| OTP no query secrets | [#43](https://github.com/Wilkes-Liberty/file_gate/issues/43) | [#3614266](https://www.drupal.org/project/file_gate/issues/3614266) | **Done on 1.x** |
| Grant inventory | [#44](https://github.com/Wilkes-Liberty/file_gate/issues/44) | [#3614267](https://www.drupal.org/project/file_gate/issues/3614267) | **Done on 1.x** |
| Commerce scale | [#45](https://github.com/Wilkes-Liberty/file_gate/issues/45) | [#3614268](https://www.drupal.org/project/file_gate/issues/3614268) | **Done on 1.x** |
| Campaign token TTL | [#46](https://github.com/Wilkes-Liberty/file_gate/issues/46) | [#3614269](https://www.drupal.org/project/file_gate/issues/3614269) | **Done on 1.x** |

GitHub: **no open issues** on Wilkes-Liberty/file_gate (2026-07-31 sweep).  
drupal.org: shipped work at **Fixed** (auto-closes after the usual Fixed window).

### Platform (still open)

| Topic | Jira | GH | State |
|-------|------|-----|--------|
| Epic: unified hardware auth | [DEV-221](https://wilkesliberty.atlassian.net/browse/DEV-221) | — | Open |
| Keycloak WebAuthn + ACR | [DEV-222](https://wilkesliberty.atlassian.net/browse/DEV-222) | [infra#503](https://github.com/Wilkes-Liberty/infra/issues/503) | Open |
| Keycloak PIV follow-on | [DEV-223](https://wilkesliberty.atlassian.net/browse/DEV-223) | [infra#504](https://github.com/Wilkes-Liberty/infra/issues/504) | Open |
| Drupal OIDC refresh / acr | [DEV-224](https://wilkesliberty.atlassian.net/browse/DEV-224) | [webcms#479](https://github.com/Wilkes-Liberty/webcms/issues/479) | Open |
| Site File Gate config | [DEV-225](https://wilkesliberty.atlassian.net/browse/DEV-225) | [webcms#480](https://github.com/Wilkes-Liberty/webcms/issues/480) | Open |
| audit_chain on W&L site | [DEV-226](https://wilkesliberty.atlassian.net/browse/DEV-226) | [webcms#481](https://github.com/Wilkes-Liberty/webcms/issues/481) | **Done** (v1.35.0) |
| C6 site dogfood (step-up + bridge) | under DEV-221 | [webcms#484](https://github.com/Wilkes-Liberty/webcms/issues/484) | Open |
| E2E-ASSURANCE vs Keycloak WebAuthn | under DEV-221 | [webcms#485](https://github.com/Wilkes-Liberty/webcms/issues/485) | Open |
| C8 “require hardware ACR” pattern | under DEV-221 | [internal#82](https://github.com/Wilkes-Liberty/internal/issues/82) | Open |
| Secret rotation drill | under DEV-221 | [infra#508](https://github.com/Wilkes-Liberty/infra/issues/508) | Open |
| Compromised-secret tabletop | under DEV-221 | [infra#509](https://github.com/Wilkes-Liberty/infra/issues/509) | Open |
| Runner Docker credsStore hang | — (ops) | [infra#510](https://github.com/Wilkes-Liberty/infra/issues/510) | Open |

Related open (not closed here — not confirmed done): [infra#500](https://github.com/Wilkes-Liberty/infra/issues/500) mint secret blast radius (depends on scoped secrets in use + ui mint plan).

---

## Method of work

1. **One goal, many trackers** — this PLAN is the map; tickets are the units.
2. **Module product vs platform** — close GH/d.o when code is on `1.x` (tag for releases); platform needs deploy.
3. **IdP before native RP** — do not dogfood W&L on File Gate native WebAuthn as primary.
4. **Dual-venue for OSS** — every new File Gate issue gets d.o the same day.
5. **DEV key on platform branches** — `feature/DEV-N-slug` for infra/webcms work.
6. **audit_chain** — soft-enable on sites that need a durable trail; no hard module dependency.

---

## Immediate next actions (operator)

1. Module **1.5.0** shipped (GH + d.o); Fixed issues closed on d.o.
2. Platform: **C1** Keycloak WebAuthn (DEV-222 / [infra#503](https://github.com/Wilkes-Liberty/infra/issues/503)), then C4–C5, then **C6** [webcms#484](https://github.com/Wilkes-Liberty/webcms/issues/484) + E2E [webcms#485](https://github.com/Wilkes-Liberty/webcms/issues/485).
3. Ops: rotation drill [infra#508](https://github.com/Wilkes-Liberty/infra/issues/508), tabletop [infra#509](https://github.com/Wilkes-Liberty/infra/issues/509); runner [infra#510](https://github.com/Wilkes-Liberty/infra/issues/510).
4. **webcms#481** audit_chain enable is **Done** (site v1.35.0). Keep this PLAN index updated when platform tickets move.
