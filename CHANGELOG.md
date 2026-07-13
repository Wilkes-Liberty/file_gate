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
- Pluggable `GateMethod` plugin type (attribute-based) with two built-in methods:
  `signed_url` (HMAC) and `authenticated`.
- Target-agnostic `GrantSigner` (HMAC-SHA256 over the resource id plus canonical
  claims; constant-time comparison; fails closed with no secret).
- Per-field gating via field-storage third-party settings, plus a field form
  control that forces and locks the private file system when gating is enabled.
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
  signer, and usage-limited (one-time) links.
