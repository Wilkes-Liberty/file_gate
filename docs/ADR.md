# ADR: architecture of File Gate

Status: accepted. This records the design decisions behind File Gate so future
contributors understand *why* it is built this way.

## Context

Drupal's private-file access (`FileAccessControlHandler`) grants a download to
anyone who can *view* an entity that references the file. Anonymous users can
view **published** content, so a `private://` file attached to published media is
effectively public to anyone with the link. `private://` therefore means "not
URL-guessable", not "gated". Sites — especially **decoupled** ones — need a way
to withhold a private file and release it only after a gate (a lead form, a
login, a purchase) that the front end owns.

## Decision

1. **Deny at the file level, allow on our own route.**
   `hook_file_download()` returns `-1` (a hard veto over core's permissive
   access) for any private file a *gated* field references, except for accounts
   holding *Bypass file gate*. It never grants there. Authorised delivery happens
   on a **module-owned** route (`/api/file-gate/download`) that validates a grant
   and streams `BinaryFileResponse` directly.

2. **Short-lived signed URLs, minted server-to-server.** A trusted back end calls
   `POST /api/file-gate/mint` (authenticated with a shared secret) and receives a
   relative, HMAC-signed, TTL-limited path the browser redeems. The gate itself
   lives entirely in the front end; Drupal only mints and verifies.

3. **Pluggable gate methods.** A `GateMethod` plugin type decides *how* a request
   proves it passed the gate (`signed_url`, `authenticated`, and third-party
   methods). This keeps the mechanism open-ended.

4. **Target-agnostic core.** The `GrantSigner` and the mint mechanism operate on
   an opaque *resource id* plus a bag of claims — they never assume the resource
   is a file. Only `hook_file_download()`, the download route, and the
   private-scheme field control are file-specific. This makes it cheap to reuse
   the signing/mint core for other gated resources later.

5. **Per-field configuration that forces private storage.** Gating is a
   third-party setting on the field storage, configured where the stream wrapper
   is chosen; enabling it forces and locks `private://`, because a public file
   cannot be gated.

## Alternatives considered

- **`drupal/protected_download`** — rejected. It renders the gate UI *inside*
  Drupal and assumes a coupled site. There is a genuine gap for a *100%
  decoupled* private-file gate (deny + server-minted signed URLs for any
  front end), which is what this module fills.

- **Redeem at `/system/files` via `hook_file_download()` granting** — rejected.
  Making core allow the redemption there requires anonymous `view` access to the
  referencing media, which (a) discloses the `private://` path via JSON:API /
  GraphQL and (b) couples the allow-path to core's permissive behaviour. A
  module-owned route removes both problems and is framework-agnostic.

- **Front-end streaming proxy** (the front end fetches with an authenticated
  consumer and re-streams) — rejected as the default. It doubles bandwidth
  through the front end and needs a broad file-download consumer credential.

## Consequences

- Delivery is fully decoupled and leaks no path; the raw `/system/files` route is
  always denied to the public for gated files.
- The allow-path does not depend on core's private-file access rules.
- Editors need *Bypass file gate* to download via the admin UI.
- Usage limits require a small amount of server-side state (an expirable
  redemption counter) and are therefore approximate under races.
- The signing/mint core can graduate into a shared base module (for content or
  entity gating) without a rewrite.
