# Security policy

File Gate is a security module — it controls access to private files — so please
report vulnerabilities responsibly rather than in a public issue.

## Reporting a vulnerability

- **Released versions covered by the Drupal Security Team:** follow the official
  process at <https://www.drupal.org/security-team/report-issue>. Do **not** open
  a public issue for an exploitable vulnerability.
- **Pre-release / development code:** email the maintainer privately
  (see the project page) with steps to reproduce. We will acknowledge, assess,
  and coordinate a fix and disclosure.

Please include the affected version, a clear description, and a proof of concept
if you have one.

## Security model and operator responsibilities

File Gate is only as strong as its deployment. Operators must:

- **Keep the signing secret in the environment**, never in exported
  configuration, and rotate it if it may have leaked. Rotating the secret
  immediately invalidates every outstanding signed URL.
- **Keep the mint endpoint on a trusted network.** It authenticates the caller
  with the shared secret but does not re-verify the front end's own gate — the
  secret-holder is trusted to have gated the request. Restrict the endpoint to
  server-to-server traffic and keep flood limiting enabled.
- **Store gated files in `private://`.** Public files are served by the web
  server/CDN and cannot be gated; enabling gating on a field forces and locks the
  private scheme to prevent this mistake.
- **Understand that usage limits are approximate.** The redemption counter is a
  fast key/value store, not a lock; a tight race could permit one extra
  redemption. Do not rely on it for hard licensing.

## What the module guarantees

- Deny-by-default for gated private files at `/system/files` (a `-1` veto that
  overrides core's permissive access).
- Signed grants that bind the exact file and every claim (expiry, not-before,
  usage token/cap); constant-time (`hash_equals`) verification.
- Fail-closed behaviour when no secret is configured (minting returns `503`;
  every gated file is denied).
- No `private://` path disclosure in signed URLs; delivery sets
  `Cache-Control: private, no-store`.
