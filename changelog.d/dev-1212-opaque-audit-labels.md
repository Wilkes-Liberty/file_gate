---
section: Security
---
Audit Chain rows no longer store original filenames in `label` (they use an
opaque `file:<id>` instead). Optional `audit_require_keyed` (default off)
refuses mint and download with HTTP 503 when a signed audit append fails.
