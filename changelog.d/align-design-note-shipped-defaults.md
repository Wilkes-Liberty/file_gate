---
section: Changed
---
Assurance design note `docs/design/piv-cac-webauthn.md` now matches shipped
defaults: `verify_at: redeem` (Model B, plain-link + `FG_AB` session bridge).
A1 remains trust-the-secret-holder (`verify_oidc_at_mint` off); A2 stays
opt-in.
