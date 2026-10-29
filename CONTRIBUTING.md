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
  Code must pass `phpcs` with this repository's `phpcs.xml.dist` (Drupal and
  DrupalPractice on `php,module,inc,install,test,profile,theme,yml` — not JS).
  From the module root, same as the GitHub phpcs job:

  ```bash
  phpcs -p .
  ```

- Target **PHP 8.2 / Drupal 10.6** for the base module and **PHP 8.3 / Drupal 11.3+** on Drupal 11. Optional submodules retain their declared floor.
- Keep the signing/mint core (`GrantSigner`, the `GateMethod` plugin type, the
  mint endpoint) **target-agnostic** — it must not assume it is protecting a
  file, so the core can be reused for other gated resources in future.

## Tests

Kernel tests live in `tests/src/Kernel`. Unit tests live in `tests/src/Unit`.
Submodule suites live under `modules/*/tests`. Run the same paths GitHub CI
uses, with a database configured:

```bash
vendor/bin/phpunit -c web/core/phpunit.xml.dist \
  web/modules/contrib/file_gate/tests \
  web/modules/contrib/file_gate/modules
```

Any change to the deny hook, the signer, delivery, minting, or a gate method must
keep the suite green and add coverage for new behaviour. Security-relevant
changes should include a test that fails without the fix.

## Adding a gate method

Implement `\Drupal\file_gate\GateMethodInterface` (extend `GateMethodBase`) with
the `#[GateMethod]` attribute in `src/Plugin/GateMethod`. `grants()` must fail
closed. See the README "Extending" section.

## Documentation

Update `README.md`, a unique `changelog.d/` fragment, and the docs in
`docs/` for any user-facing change.

## Changelog fragments

Follow [the changelog workflow](.github/CHANGELOG.md) for independent PR notes
and lossless release compilation. Existing opt-in entry policy is unchanged.
