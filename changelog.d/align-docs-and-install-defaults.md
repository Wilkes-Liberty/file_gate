---
section: Changed
---
Install config now ships an empty `introspection_client_secret` to match
schema. ADR usage-limit wording matches `GrantLockTrait` / SECURITY.md
(locked, fail closed). CONTRIBUTING phpcs uses `phpcs.xml.dist`; phpunit
covers unit tests and submodule suites.
