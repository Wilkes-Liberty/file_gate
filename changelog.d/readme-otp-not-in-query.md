---
section: Security
---
OTP redeem no longer accepts `email` or `otp` query parameters. Present the
passcode in the JSON body of `POST /api/file-gate/otp/session`, then download
with the `FG_OTP` cookie. A query-string passcode is denied so it cannot
land in access logs or browser history.
