---
section: Security
---
The mint and OTP request endpoints answer a field-scope refusal with the same
404 as an unknown file, instead of 403. A named secret can no longer tell an
existing out-of-scope file from a missing one. The refusal is still logged and
audited as `mint_denied`. A client that treats 403 from these endpoints as the
refusal must treat 404 the same way.
