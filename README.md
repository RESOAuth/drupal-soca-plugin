# SOCA for Drupal

Installable CIMD OpenID Connect sign-in for Drupal, with ES256 client assertions, PKCE S256, deny-by-default admission and explicit account links. **Version 0.1.0 is an evaluation preview**, with [remaining requirements](docs/requirements.md) documented per ID.

Drupal browser user login through `/user/login` and `/soca/login`. UID 1 and accounts with user/permission administration are excluded.

Run `composer install --no-dev`, then place this directory at `web/modules/custom/soca` or install it as a Composer path/package repository. Enable **SOCA CIMD sign-in** in Extend. Configure **Configuration, People, SOCA sign-in** (`/admin/config/people/soca`). No `openid_connect` module is required. This preview owns its hardened callback; an `openid_connect` provider adapter is a remaining gap.

Mount a persistent P-256 signing key using `SOCA_PRIVATE_KEY_FILE` and set the canonical HTTPS origin plus admission rules. Keep the candidate disabled until public document checks and an operator test login pass for that exact revision. See [configuration](docs/configuration.md), [operations and recovery](docs/operations.md), and [verification](docs/verification.md).

```sh
composer install
composer test
CONTAINER_ENGINE=podman bash demo/run.sh test
CONTAINER_ENGINE=podman bash demo/run.sh serve
```

The disposable local demo installs the actual host in PHP containers. Local HTTP never bypasses production HTTPS or public-network checks; live SSO activation requires publicly reachable HTTPS metadata or a checked proxy profile. Tests include signed synthetic-provider flows and native host account/session checks. No live-provider login has been completed.

Runtime: Drupal 10.3/11 on PHP 8.3+; native smoke tested with Drupal 11.4.10 and SQLite. Only the native authenticated user baseline is created, with no extra Drupal roles.

CI tests protocol/bridge cases on PHP 8.3/8.4, installs the native host, audits Composer dependencies and builds packages/SBOMs. Dependabot tracks Composer, actions and the demo image. CodeQL checks Python packaging and workflow code; [CodeQL does not analyse PHP](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/). See [security reporting](SECURITY.md).
