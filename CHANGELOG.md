# Changelog

All notable changes to **File Gate** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial release.
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
- Pluggable `GateMethod` plugin type (attribute-based) with four built-in
  methods: `signed_url` (HMAC), `authenticated`, `token` — a revocable per-grant
  token (a random token whose SHA-256 hash is stored and bound into the
  signature, revocable by deleting the hash) and/or a pre-shared campaign-token
  allowlist (static `?token=` links) — and `referrer_lock`, a signed URL that is
  additionally only redeemable from an allowed origin/referrer (defense in depth,
  not authorization — the Referer/Origin header is spoofable). Minted tokens
  support TTL, an availability window, and usage limits.
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
- A `SignedUrl` claim-binding seam (`signedClaimKeys()` / `extraMintClaims()`)
  so gate methods can extend it and bind additional signed claims.
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
  proof / thumbprint mismatch / wrong-htu / replay).
