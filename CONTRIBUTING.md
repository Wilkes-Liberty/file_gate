# Contributing to File Gate

Thanks for helping improve File Gate. This project is developed on GitHub and
mirrored to drupal.org.

## Where to file things

- **Bugs and feature requests:** the
  [drupal.org issue queue](https://www.drupal.org/project/issues/file_gate).
- **Security vulnerabilities:** see [SECURITY.md](SECURITY.md) — never in a
  public issue.

## Coding standards

- Follow the [Drupal coding standards](https://www.drupal.org/docs/develop/standards).
  Code must pass `phpcs` with the `Drupal` and `DrupalPractice` standards:

  ```bash
  vendor/bin/phpcs --standard=Drupal,DrupalPractice web/modules/contrib/file_gate
  ```

- Target **PHP 8.4** and **Drupal 11.4+**.
- Keep the signing/mint core (`GrantSigner`, the `GateMethod` plugin type, the
  mint endpoint) **target-agnostic** — it must not assume it is protecting a
  file, so the core can be reused for other gated resources in future.

## Tests

Kernel tests live in `tests/src/Kernel`. Run them with a database configured:

```bash
vendor/bin/phpunit -c web/core web/modules/contrib/file_gate/tests/src/Kernel
```

Any change to the deny hook, the signer, delivery, minting, or a gate method must
keep the suite green and add coverage for new behaviour. Security-relevant
changes should include a test that fails without the fix.

## Adding a gate method

Implement `\Drupal\file_gate\GateMethodInterface` (extend `GateMethodBase`) with
the `#[GateMethod]` attribute in `src/Plugin/GateMethod`. `grants()` must fail
closed. See the README "Extending" section.

## Documentation

Update `README.md`, `CHANGELOG.md` (under `[Unreleased]`), and the docs in
`docs/` for any user-facing change.
