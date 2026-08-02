# Changelog

All notable changes to **File Gate** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- **Assurance token endpoints beside simple_oauth, correctly this time (#56 /
  d.o #3614535).** The 1.5.1 `_auth: ['cookie']` route pin turned out to be
  inert for this failure: global authentication providers (simple_oauth
  registers `global: TRUE`) authenticate at request priority 300 — before
  routing — so they 401 a foreign Bearer token before any route option is
  consulted. Verified by probing a live 1.5.1 site. A new `AuthorizationShield`
  http middleware now stashes the Bearer/DPoP `Authorization` value into a
  request attribute and removes the header on File Gate's own token endpoints
  (`/api/file-gate/download`, `/api/file-gate/assurance/bridge`) before any
  provider runs; handlers read the stash transparently. Clients keep standard
  `Authorization: Bearer`/`DPoP` wire semantics — no client changes. Basic
  (service-secret) credentials and all other routes, including the
  permission-gated WebAuthn registration endpoints, are untouched. Regression
  coverage is behavioral: shield unit tests in both directions plus a
  stashed-attribute redeem through the bridge and the direct download.

## [1.5.1] - 2026-08-02

### Fixed
- **Assurance bridge unreachable beside simple_oauth (#54 / d.o #3614535).** The
  bridge and WebAuthn assertion routes now pin `_auth: ['cookie']` so a global
  authentication provider that consumes `Authorization` (simple_oauth being the
  common case) can no longer reject the external IdP Bearer/DPoP token before
  the controller validates it. Without the pin, redemption on such sites always
  failed with simple_oauth's `access_denied` — and no File Gate log entry.

### Removed
- **`docs/PLAN.md`.** The programme plan was an internal working document — workstreams,
  scheduling and an index of internal ticket keys — that had ended up in the published
  tree. Roadmap and scheduling are tracked internally; the module's own documentation
  (`API.md`, `ADR.md`, `KEYCLOAK-UNIFIED-AUTH.md`, `assurance-redeem.md`) is unaffected.

## [1.5.0] - 2026-07-31

### Security
- **OTP redeem without query secrets (#43 / d.o #3614266).** Prefer
  `POST /api/file-gate/otp/session` then download with HttpOnly `FG_OTP` cookie.
  Query `email`/`otp` remains for backward compatibility.
- **Drupal SSO session bridge (#41 / d.o #3614264).** Same-origin step-up uses
  `openid_connect` session access token when present (still verifies acr/aud).
- **IdP step-up ACR helper (#42 / d.o #3614265).** Field-configured authorize URL
  can append `acr_values` (Keycloak) without open redirects.

### Added
- **Signed-URL grant inventory API (#44 / d.o #3614267).**
  `GET /api/file-gate/grants`, `POST /api/file-gate/grants/revoke-bulk`.
- **Commerce SKU-scoped entitlement (#45 / d.o #3614268).** Avoids loading every
  completed order for large accounts.
- **Pre-shared campaign token optional TTL / max uses (#46 / d.o #3614269).**

## [1.4.0] - 2026-07-31

### Security
- **Step-up open redirect closed (#40 / d.o #3614254).** Step-up HTML no longer
  honors query `login_url`. Only field `step_up_login_url` (absolute http(s)) is
  used; crafted query values are stripped from bridge/download hops.
- **OTP HMAC uses authenticated secrets (#39 / d.o #3614253).** Issue/redeem use
  the mint credential material (named or legacy) and store secret id `k`; dual-key
  previous materials accepted at redeem. Named-only deploys no longer hash with an
  empty legacy secret.
- **Download denial flood** (`download_flood_limit` / `window`) bounds abuse on
  `GET /api/file-gate/download`.
- **Token revoke field scope:** minted token rows store field + secret id; revoke
  fails closed when the revoking credential is not allowed for that field.
- **Dual-key secret rotation:** `$settings['file_gate.previous_secrets']` and
  `previous_download_secrets` keep outstanding grants valid during cutover. See
  `docs/SECRET_ROTATION.md`.

### Added
- **Optional audit_chain integration** (`file_gate.audit`, soft). Durable
  hash-chained events for mint/download/deny/revoke/otp. See `docs/AUDIT.md`.
- **Mint-time OIDC (A2)** — field `verify_oidc_at_mint` + `MintTimeOidcInterface`
  (#36 / d.o #3614249).
- **Forced identity mint** — global `require_acting_account` and per-field
  `require_identity_mint`.
- **Multi-field mint** — body `field` required when a file has multiple gated
  fields; redeem prefers strictest method when no pin.
- **Signed_url jti revoke** — `POST /api/file-gate/revoke` with `{"jti":"…"}`.
- **WebAuthn enrollment UI** — `/user/{user}/file-gate-webauthn` (#38 / d.o
  #3614251).
- **Authenticated method role allowlist** — optional `roles` on the method.
- **Manual E2E checklist** — `docs/E2E-ASSURANCE.md` (#37 / d.o #3614250).
- **Program plan** — `docs/PLAN.md` (goal, workstreams, ticket index).
- **IdP-first auth architecture** — `docs/KEYCLOAK-UNIFIED-AUTH.md` (Keycloak /
  enterprise: one hardware credential for SSO and assurance downloads).

## [1.3.0] - 2026-07-31

### Security
- **Assurance plain-link primary path (#33 / d.o #3612909).** For
  `verify_at: redeem`, a browser that opens the signed download URL without a
  live OIDC token is redirected (or given a 401 JSON challenge) to step-up.
  After POST `/api/file-gate/assurance/bridge` with a valid Bearer/DPoP token,
  a short-lived HttpOnly cookie (`FG_AB`) satisfies the assurance layer so the
  **same plain URL** streams the file. HMAC grant and `max_uses` still apply;
  bridge establish never burns a use. RFC 9470-style `WWW-Authenticate` for API
  clients. See `docs/assurance-redeem.md`.
- **Native WebAuthn RP mode (`verify_at: webauthn`) (#33 / d.o #3612909).** File
  Gate can verify a FIDO2 assertion for a registered authenticator (using
  `web-auth/webauthn-lib`), then set the same session bridge cookie for
  plain-link download. Registration endpoints for permitted users; assertion
  endpoints bound to the signed grant. Honest scope: resource-level RP, not a
  full-site AAL3 verifier.

## [1.2.0] - 2026-07-31

### Security
- **Scoped signing secrets (#30 / d.o #3614157).** Named mint credentials map to
  field storage allowlists so a front end that may mint whitepapers cannot mint
  an NDA. Config holds `secret_scopes` (id → field keys); values stay in
  `$settings['file_gate.secrets']`. Basic-auth username (or
  `X-File-Gate-Secret-Id`) selects the secret; minted URLs carry `k=<id>`.
  Scope is enforced at mint and redemption (narrowing revokes outstanding
  grants). Deleted secrets fail closed at redeem. Named secrets with a value
  but empty/missing scope grant nothing and ERROR on the status report. The
  legacy `download_secret` without `k=` remains whole-corpus for existing
  installs.
- **Optional identity-aware mint (#31 / d.o #3614158).** Mint body may include
  `account` (user UUID) or `uid`. When present, File Gate fails closed unless
  that account may download the file and view referencing host entities.
  Omitted for anonymous lead-capture flows.

### Added
- **Admin dashboard (#28 / d.o #3612910).** Settings page shows mints, deliveries,
  denials, auth failures, per-method and top-file tables from the `file_gate`
  dblog channel when Database Logging is enabled (table fallback; Charts not
  required).

## [1.1.0] - 2026-07-30

### Upgrading

**`drush config:import` will now fail on a site whose configuration marks a field as gated
while storing its files publicly.** That combination was previously accepted and silently
produced no gate at all, so an import that used to succeed may now stop — correctly. Fix it
by setting `settings.uri_scheme` to `private` in the exported field storage, or by removing
the `file_gate.gated` third-party setting from a field that is not meant to be gated.

Sites already in that state are reported on the status report after upgrading. Note that
changing a field to the private scheme does **not** move files already stored publicly:
they stay where they are, and stay readable, until they are re-uploaded or migrated.

### Added
- **A gated field can no longer claim protection it does not provide.** Gating only
  applies to the private file system — public files are served straight off disk and
  never reach Drupal, so `FileGateResolver::getGateForFile()` returns NULL and no gate
  runs.

  The field edit form already forced the private scheme when gating was enabled, but that
  is a *form* alter and a config-import-authoritative deploy never runs it. So
  `drush config:import` could install a field storage carrying `file_gate.gated: true`
  alongside `uri_scheme: public` — the configuration asserting the files are gated, the
  admin UI showing them as gated, and the files readable by anyone with the URL. Nothing
  errored, because nothing was broken: the gate simply never engaged.

  Two guards, because they cover different sites:

  - a config-import validator rejects the combination and names the field to fix. It
    rejects rather than silently rewriting `uri_scheme`, which would make the site
    disagree with its own exported configuration and oscillate on the next export;
  - `hook_requirements()` reports any site already in that state at ERROR, which the
    validator cannot reach.

  Note that changing an existing field to the private scheme does not move files already
  stored publicly — they stay readable until re-uploaded or migrated.

### Changed
- **The README states the mint trust boundary plainly.** It described the cryptography
  accurately but left an integrator to infer the most important property: **mint
  authorizes nothing.** It authenticates the caller with the shared secret and then mints
  whatever was asked for, with no entity or field access check, so the secret's blast
  radius is the entire gated corpus. That is a deliberate design — the gate decision is
  delegated to a trusted back end — but it means the secret must never be provisioned into
  a public web tier, which is now said in those words.

## [1.0.2] - 2026-07-30

### Changed
- **`composer.json` now declares `"php": ">=8.3"`.** It previously specified no PHP
  constraint at all, so the effective floor came only from whatever core happened to
  require — the supported surface was implied rather than stated, and a reader had
  to trace Drupal's own requirements to find it.

  8.3 is the real floor, and unlike the sibling modules it is set by this module's own
  code rather than by core: `GrantSignerInterface` declares typed class constants,
  which are PHP 8.3 syntax and a parse error below it, and `SharedSecretAuthTrait`
  declares constants in a trait, which needs 8.2. Drupal 11.4 requires `>=8.3.0`
  independently, so the two agree.

  This does not change which sites can install today: `^11.4 || ^12` already implies
  the same floor. What it changes is that the claim is stated where Composer and a
  human both read it, and it stops moving silently if core's floor moves or this
  module adopts newer syntax.

## [1.0.1] — 2026-07-30

### Added
- **A `phpstan.neon.dist`, and a PHPStan job in GitHub CI.** The module shipped neither, and
  the absence was not neutral: the drupalcode pipeline analysed it with the shared
  `gitlab_templates` default rather than the level and rule set every sibling module pins,
  and GitHub ran no static analysis at all. That is how ten `readonly` injected services
  stayed green through a stable release while being a fatal on PHP 8.3 (fixed below).

  The config matches the sibling modules — level 6, `bleedingEdge` — and the job runs on
  **PHP 8.3 rather than the newest available**, deliberately: the rule that caught the
  `readonly` defect only reports below 8.4, so analysing solely on the newest PHP would
  leave the supported floor the version least checked.

  Two scoped ignores, each with its reason and the condition for removing it. The mint and
  OTP controllers reach Media through `method_exists()` so the module never hard-depends on
  the Media module; PHPStan resolves the entity to the concrete class and calls the check
  redundant, but deleting it would remove a real guard. And `firebase/php-jwt` is optional
  (`suggest`, plus a `hook_requirements` check), so a consumer analysing without it
  installed should not be told their code is broken.

### Fixed
- **Thirteen type errors the new analysis surfaced**, none behavioural but several papering
  over a wrong assumption: `file_gate_file_download()` was untyped; two form handlers called
  `getEntity()` on `FormInterface`, which does not declare it, and then called
  `FieldConfig`/`FieldStorageConfig` methods on the `EntityInterface` that came back;
  `_file_gate_apply_field_gating()` demanded the concrete `FieldStorageConfig` while its
  only caller passes what `loadByName()` returns. The form handlers now narrow explicitly
  and return early if the object is not what they expect, which is a no-op on the form they
  are attached to and honest everywhere else.

- **`readonly` injected services made both settings forms fatal on PHP 8.3.** `SettingsForm`
  and `file_gate_form`'s `FileGateForm` declared their injected services `readonly`. Both
  extend `ConfigFormBase`/`FormBase`, which bring in `DependencySerializationTrait`, and on
  PHP below 8.4 that trait's `__wakeup()` cannot reinitialize a readonly property declared
  in a child class — it is out of the declaring scope. Drupal caches form objects and
  unserializes them when a form rebuilds, so the grant signer, gate-method manager and
  entity type manager came back unusable.

  PHP 8.3 is inside the supported range: this module declares `^11.4 || ^12`, and Drupal
  11.4's minimum PHP is 8.3. Ten properties across the two forms were affected.

  Nothing caught it because the module shipped no `phpstan.neon.dist`, so the drupalcode
  pipeline analysed it with the shared default config rather than the level and rule set
  the sibling modules use. That gap is closed in this same release (see Added).
  Confirmed by running PHPStan against the module with
  `phpVersion: 80300`: ten `dependencySerializationTraitProperty.unsupportedReadOnlyProperty`
  before, zero after. `menu_autopilot` 1.0.1 and `mcp_sentinel` fixed the same defect.

## [1.0.0] — 2026-07-23

### Security
- Delivery responses now always send `X-Content-Type-Options: nosniff`, and
  `inline` disposition is honoured only for a safe MIME allowlist (PDF, common
  images, plain text, common audio/video). A user-uploaded SVG or HTML file is
  always sent as an attachment, closing a stored-XSS vector when a site enabled
  inline delivery.
- Minted-token redemption and revocation are now serialized with a lock keyed on
  the token hash. A redemption can no longer resurrect a token that was revoked
  during the same instant, and a one-time (`max_uses = 1`) link can no longer be
  redeemed more than once by a concurrent burst.
- Assurance (DPoP): the proof is now bound to the specific access token via the
  RFC 9449 `ath` claim, so a proof captured for one token cannot be paired with
  another token bound to the same key.

### Fixed
- Signed grants are now bound to the file's entity UUID as well as its URI, so
  two managed files that reference the same `private://` path no longer share a
  signature. (Outstanding short-lived grants minted before this change are
  invalidated; the front end simply re-mints.)
- Minting a link whose absolute availability window has already closed now
  returns `410 Gone` instead of a `200` carrying an already-expired link.
- A download whose bytes are missing on disk now returns `404` without consuming
  a one-time link's single use.
- OTP: a failed e-mail delivery no longer spends the caller's per-(file, email)
  send-throttle slot.
- Assurance: rotate-tolerant JWKS handling — a token signed by a freshly rotated
  key triggers a single JWKS refetch instead of failing until the cache expires.
- Assurance: token verification now requires an `exp` claim (a token without one
  no longer verifies), refuses a non-HTTPS introspection endpoint (except an
  explicit loopback), and can pin the DPoP `htu` origin behind a TLS-terminating
  proxy via a new **DPoP htu origin override** field setting.

### Changed
- Documentation: the "fails closed" note now states precisely that the empty
  signing secret fails the `signed_url`/`token` methods closed; `authenticated`,
  `commerce`, and `form` enforce their own gate and do not use the secret.

### Added
- Continuous integration: drupal.org GitLab CI (`.gitlab-ci.yml`) plus a
  self-contained GitHub Actions workflow running PHPCS and the PHPUnit suite on
  Drupal 11.4 and 12, so the `^11.4 || ^12` support claim is verified, not just
  asserted.
- Test coverage for Media-entity gating, the `authenticated` method, the
  `nosniff`/inline hardening, the closed-availability `410`, the DPoP `ath`
  binding, and the missing-bytes one-time-use behaviour.

## [1.0.0-rc1] - 2026-07-14

### Added
- Initial 1.0 release line: the full set of gate methods, submodules, and
  endpoints below.
- `hook_file_download()` deny for `private://` files referenced by a **gated**
  field — a hard veto that overrides core's permissive private-file access
  (which grants anonymous download whenever the referencing published entity is
  viewable).
- Self-hosted signed delivery route (`GET /api/file-gate/download`) that streams
  the file after a gate method approves the request — never `/system/files`, so
  the private path is never disclosed and delivery does not depend on anonymous
  media-view access.
- Server-to-server mint endpoint (`POST /api/file-gate/mint`) with shared-secret
  (constant-time) authentication, flood limiting, and published-host enforcement.
- Server-to-server revoke endpoint (`POST /api/file-gate/revoke`, same
  shared-secret authentication as mint) that invalidates a minted `token` grant
  by deleting its stored hash — without rotating the site secret.
- Pluggable `GateMethod` plugin type (attribute-based) with five built-in
  methods: `signed_url` (HMAC), `authenticated`, `token` — a revocable per-grant
  token (a random token whose SHA-256 hash is stored and bound into the
  signature, revocable by deleting the hash) and/or a pre-shared campaign-token
  allowlist (static `?token=` links) — `referrer_lock`, a signed URL that is
  additionally only redeemable from an allowed origin/referrer (defense in depth,
  not authorization — the Referer/Origin header is spoofable), and `otp`, a
  single-use one-time passcode e-mailed to a self-identified address (issued at
  `POST /api/file-gate/otp`; TTL-limited, attempt-locked, stored only as a hash).
  Minted tokens support TTL, an availability window, and usage limits.
- **File Gate Assurance** submodule (`file_gate_assurance`) adding an `assurance`
  gate method: a signed URL whose delivery also requires a hardware-backed,
  phishing-resistant OIDC assurance level (PIV/CAC — HSPD-12 / FIPS 201 — or
  FIDO2/WebAuthn) proven at any standards-compliant IdP. Provider-agnostic (OIDC
  discovery + JWKS, algorithm pinned to the published keys), with opt-in DPoP
  (RFC 9449) sender-constraining and replay protection. Verifies live at
  redemption (Model B) or trusts a stepped-up mint caller (Model A); binds the
  asserted level (`aal`) into the signature. This is federation (NIST SP 800-63C,
  an *asserted* level), not an AAL3 verifier — a plain signed URL is a bearer
  capability unless DPoP-bound. Requires `firebase/php-jwt` (a suggested
  dependency of the parent module).
- **File Gate Form** submodule (`file_gate_form`) adding a coupled `form` gate
  method: Drupal renders a lightweight email / lead-capture form at
  `/file-gate/form/{file}` and grants the download on submission (a per-session
  grant in the private tempstore, TTL-limited). Spam-guarded (honeypot + per-IP
  rate limit); a `LeadCapturedEvent` lets sites persist submissions into Contact,
  Webform, or a CRM without File Gate storing PII. The coupling is isolated in
  this optional submodule so the headless path pulls in no form assumptions.
- **File Gate Commerce** submodule (`file_gate_commerce`) adding a `commerce`
  gate method: deliver only to a buyer / licensee. A live-decision method that
  re-checks entitlement on every download (so expiry/revocation take effect
  immediately), delegating to a swappable `EntitlementCheckerInterface`. The
  bundled checker grants on a completed Drupal Commerce order matching a
  configured SKU; override the `file_gate_commerce.entitlement_checker` service
  for licences or an external entitlement API. Access gating, not DRM.
- A `SignedUrl` claim-binding seam (`signedClaimKeys()` / `extraMintClaims()`)
  so gate methods can extend it and bind additional signed claims.
- Per-method settings forms: gate methods expose `fieldSettingsForm()` /
  `fieldSettingsSubmit()` and the field edit form renders the selected method's
  own options inline — every built-in method (signed_url, token, referrer_lock,
  otp, form, commerce, assurance) is now configurable in the UI, not only in
  exported YAML.
- `ContextualMintInterface` — an optional interface letting a gate method receive
  the mint request (e.g. to bind a caller-asserted subject); the mint controller
  feature-detects it, so `mint()` stays backward compatible.
- Assurance enhancements: **per-user binding** (the mint request may assert a
  `subject`; its hash is bound and the redeemed token's `sub` must match), an
  opt-in **RFC 7662 introspection** live-revocation check (client secret injected
  from the environment, never stored in field config), and an **edge-mTLS
  (`client_cert`) mode** that trusts a validated PIV client-certificate subject
  passed by an mTLS-terminating reverse proxy (the proxy + Federal PKI is the
  verifier).
- Target-agnostic `GrantSigner` (HMAC-SHA256 over the resource id plus canonical
  claims; constant-time comparison; fails closed with no secret).
- Per-field gating via field-storage third-party settings, plus a field edit
  form control (a "Gate access to these files" toggle and a gate-method picker)
  that forces and locks the private file system when gating is enabled, and an
  admin menu link under Configuration → Media.
- Expiry and usage controls for `signed_url`: per-field TTL, an absolute
  availability window (`available_until`), and usage limits (`max_uses`, where
  `1` yields a one-time link), all bound into the signature.
- Dedicated `file_gate` logger channel for security events (denied downloads,
  failed mint authentication, fail-closed refusals) and usage events (mints,
  deliveries).
- Admin settings page (`/admin/config/media/file-gate`) reporting the secret
  status, global defaults, available gate methods, and a gated-fields overview
  linking to each field's settings.
- `administer file gate` and `bypass file gate` permissions.
- Kernel test coverage of the deny hook, signed delivery, mint endpoint, the
  signer, and usage-limited (one-time) links; the `token` method (minted,
  revoked, expired, tampered, one-time, unlimited, and pre-shared paths); the
  revoke endpoint; the field-gating persistence helper; the `referrer_lock`
  method (allowed/disallowed origin, Origin vs Referer, default-port
  normalization, missing-header policy, empty-allowlist fail-closed, signature
  still enforced, and origin-checked-before-usage-consumed); and the `assurance`
  method (valid/insufficient-acr/wrong-audience/wrong-issuer/expired/forged-key
  tokens, aal-tamper, advisory amr, asserted mode, and DPoP grant / missing
  proof / thumbprint mismatch / wrong-htu / replay); the `otp` method
  (request-then-redeem via the mail collector, single use, wrong code, attempt
  lockout, endpoint guards, send throttle, and mint-not-supported); and the
  `form` method (submit-grants-download, no-submission-denied, expired grant,
  honeypot rejection, live-decision mint, and the settings form); and the
  `commerce` method (entitled-grants / not-entitled-denied via a fake checker,
  no-SKU fail-closed, the bundled checker's fail-closed paths without Commerce
  and for anonymous, live-decision mint, and the settings form); and the signer's
  canonicalisation injectivity (a folded claim cannot be dropped) and the
  `client_cert` fail-closed-without-allowlist path.

### Fixed
- The mint response `ttl` now reflects the grant's real remaining lifetime
  (derived from the minted expiry), not the global default — accurate when a
  field configures its own TTL or availability window.
- `config/schema/file_gate.schema.yml` now declares `introspection_client_secret`
  (env-injected, like `download_secret`) so config validation covers it.
- The lead-capture form's honeypot field is no longer named `url` (which browser
  and password-manager autofill could populate and falsely trip); it uses a
  non-autofill name.

### Security
- The grant signer's claim canonicalisation is now injective — each key and value
  is `rawurlencode()`d before signing — closing a claim-folding bypass. A holder
  of one legitimately minted URL could previously fold a signed claim into an
  adjacent value and drop it (dropping `max` to defeat a one-time / usage-capped
  link, or the assurance subject hash `sh` to defeat per-user binding) while
  keeping a valid HMAC. **Signed URLs minted before this change must be re-minted**
  (the signature format changed). Regression-tested.
- The assurance `client_cert` (edge-mTLS) mode now fails closed without an
  explicit certificate-subject allowlist. The trusted proxy header is spoofable
  off-proxy, so "accept any validated subject" is no longer permitted; a subject
  allowlist is required.
