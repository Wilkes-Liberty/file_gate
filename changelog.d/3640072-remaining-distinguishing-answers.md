---
section: Security
---
Five more answers no longer tell a caller whether a file or grant exists or is
in scope. Revoke answers a grant outside the secret's scope like an unknown one
(404, was 403). An unpublished media host is reported only to a secret that
could mint its file. The OTP session endpoint, which takes no secret, gives the
same 403 for an unknown file, a file that is not OTP-gated and a wrong passcode
(was 404, 422 and 403). The multi-field answer lists only the fields the secret
may mint, and a secret that may mint exactly one needs no `field`. Scope
refusals on passcode requests and revokes are now audited as `otp_denied` and
`revoke_denied`. A client that branches on the old statuses needs updating.
