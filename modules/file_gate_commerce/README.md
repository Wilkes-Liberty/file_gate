# File Gate Commerce

Gate file delivery behind a **completed purchase or entitlement** — release the
file only to a buyer or licensee. Adds one File Gate gate method, `commerce`, and
a **swappable entitlement checker**.

## How it works

The `commerce` method is a live-decision gate (`mint()` returns `NULL`): on every
download it asks an entitlement checker "is the current account entitled to this
file?" and streams only if so. Because the check is live, an expired or revoked
entitlement stops delivery immediately — the gate never trusts a long-lived
signed URL.

Gate a field with the `commerce` method and set the entitlement:

| Setting | Meaning |
|---|---|
| `sku` | The product variation SKU whose purchase (or, with a custom checker, whose entitlement) grants this file. Empty denies. |

Because orders are tied to an account, the visitor must be **authenticated to
Drupal** at download time (or a custom checker must resolve entitlement another
way).

## The entitlement checker is swappable

The decision is delegated to the `file_gate_commerce.entitlement_checker` service
(`\Drupal\file_gate_commerce\EntitlementCheckerInterface`). File Gate hardcodes no
single store:

- **Bundled default** — `CommerceEntitlementChecker` grants when the account has a
  completed Drupal Commerce order containing the configured SKU. Needs the
  [Commerce](https://www.drupal.org/project/commerce) module; without it (or with
  no matching order) it fails closed. `hook_runtime_requirements` flags a missing
  Commerce install.
- **Your own** — override the service to check `commerce_license`, custom order
  states, guest-by-email orders, or an **external entitlement API** (a SaaS, a
  licence server):

  ```yaml
  # my_module.services.yml
  services:
    file_gate_commerce.entitlement_checker:
      class: Drupal\my_module\MyEntitlementChecker
  ```

  ```php
  final class MyEntitlementChecker implements EntitlementCheckerInterface {
    public function isEntitled(AccountInterface $account, string $entitlement, FileInterface $file): bool {
      // Return TRUE only if $account is currently entitled. Fail closed.
    }
  }
  ```

## Access gating, not DRM

This controls *who may download*, not what happens after. Once the bytes are
delivered they are out of File Gate's control — combine with a short-lived flow
if you need to limit re-download, and do not rely on it for hard licence
enforcement. The check is re-run every request, so revocation/expiry take effect
on the next download attempt.
