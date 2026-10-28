---
section: Changed
---
The File Gate keys page (`/user/{user}/file-gate-webauthn`) is self-only.
Administrators are denied (403) on another account's page; the form lists
the current user's credentials. JSON APIs were already current-user-only.
