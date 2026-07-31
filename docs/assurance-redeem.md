# High-assurance redeem (plain-link primary path)

This is the **recommended** delivery path for the `assurance` gate method
(`verify_at: redeem`). It is designed so a user can open a **normal signed URL**
(email, `<a href>`, Save as…) after a single hardware-backed step-up.

## Security model (honest)

1. **HMAC grant** (minted server-to-server) still binds file, expiry, `aal`, and
   optional subject hash. Without a valid signature the request is 403.
2. **OIDC assertion** (PIV/CAC or FIDO2 via your IdP) proves phishing-resistant
   authentication. File Gate is a Relying Party (NIST SP 800-63C).
3. **Session bridge cookie** (`FG_AB`) is a short-lived HttpOnly cookie set only
   after a successful live OIDC check. It allows the **same** signed URL to
   stream without `Authorization` on every GET. It does **not** replace the
   grant signature.
4. Optional **DPoP** on the step-up POST binds the access token to a client key.

Do not describe a plain download without step-up as AAL3. With bridge + short
TTL + `max_uses`, delivery is a constrained capability after asserted hardware
auth.

## Flow

```
Mint (BFF + shared secret)
  → signed path: /api/file-gate/download?f=…&exp=…&sig=…&aal=3&sh=…

Browser GET download (plain link)
  → no bridge cookie, no Bearer
  → 302 → /api/file-gate/assurance/step-up?…

Step-up page (or your SPA)
  → obtain access token from IdP (acr meets required_acr)
  → POST /api/file-gate/assurance/bridge  Authorization: Bearer …
  → Set-Cookie: FG_AB=… (HttpOnly, Path=/api/file-gate, short TTL)

Browser GET same download URL
  → bridge cookie satisfies assurance layer
  → signature + max_uses enforced; file streams
```

API clients that send `Accept: application/json` receive **401** with:

```http
WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="…"
```

and a JSON body listing `step_up` and `bridge` URLs (RFC 9470-style).

## Integrator checklist

1. Field method: `assurance`, `verify_at: redeem`, non-empty `required_acr`,
   `issuer`, `audience`. Prefer `dpop: true` and `max_uses: 1` for sensitive
   files. Keep **plain-link session bridge** enabled (default).
2. Mint with `subject` when the grant is per-user (binds `sh=`).
3. After IdP login, set either:
   - `sessionStorage.setItem('file_gate_access_token', accessToken)`, or
   - `window.fileGateAccessToken = accessToken`
   and optionally `window.fileGateDpopProof` when DPoP is required.
4. Optional field setting **Step-up login URL**: the step-up page redirects
   there with `return_to=` when no token is present.
5. Open the minted path as a normal link.

## Minimal SPA redeem (JSON clients)

```js
async function redeem(downloadUrl, getAccessToken) {
  let res = await fetch(downloadUrl, { credentials: 'same-origin' });
  if (res.status === 401) {
    const body = await res.json();
    const token = await getAccessToken(body.acr_values || []);
    const bridge = body.bridge;
    const b = await fetch(bridge, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' },
    });
    if (!b.ok) throw new Error('bridge failed');
    const { path } = await b.json();
    res = await fetch(path, { credentials: 'same-origin' });
  }
  if (!res.ok) throw new Error('download failed');
  return res.blob();
}
```

## Federal vs commercial

| Stack | Notes |
|-------|--------|
| **login.gov / agency ICAM** | Map `required_acr` to the ICAM AAL3 URI your IdP emits; PIV often via IdP or edge `client_cert`. |
| **Keycloak / Okta / Entra** | Configure step-up ACR for WebAuthn or smart card; copy exact `acr` strings into the field. |
| **Edge CAC only** | Use `verify_at: client_cert` instead of redeem; plain link works without bridge. |

## Native WebAuthn mode (`verify_at: webauthn`)

When the field uses native WebAuthn, File Gate is the **Relying Party** for the
download step (not the site login IdP):

1. Register credentials: `POST /api/file-gate/webauthn/register/options` then
   `POST /api/file-gate/webauthn/register` (permission
   *Register File Gate WebAuthn credentials*).
2. Mint a grant; pass `subject` (or set a fixed `webauthn_user_handle` on the
   field) so the grant’s `sh=` matches the credential handle.
3. Open the signed URL → step-up page runs `navigator.credentials.get()` →
   `POST /api/file-gate/webauthn/assert` sets the same `FG_AB` bridge cookie →
   plain download.

Configure **RP ID**, **allowed origins**, and optional fixed user handle on the
field. Origins may also be set in `settings.php` as
`$settings['file_gate.webauthn']`.

Requires `composer require web-auth/webauthn-lib`.

## Related

- Design: `docs/design/piv-cac-webauthn.md`
- Module: `modules/file_gate_assurance/README.md`
- Issues: GitHub #33, d.o #3612909
