# Verification record

Version 0.1.0, assessed 2026-10-21 against `RESOAuth/soca-plugins` requirements commit `60ea4db827457b4a4a7b11d79e86b654612a75e1`.

| Layer | Reproducible command | Result |
| --- | --- | --- |
| Protocol | `composer install && php tests/core.php` | 129 assertions pass on PHP 8.3; ES256, ES384, RS256 in hosted and proxy modes; signed synthetic provider |
| Host bridge | `php tests/bridge.php` | 18 assertions pass; revision gates, side-effect-free tests, changed operator/policy, replay, deployment overrides and emergency disable |
| Native host | `CONTAINER_ENGINE=podman bash demo/run.sh test` | 12 assertions pass using Drupal 11.4.10 on PHP 8.3 in a disposable container; native account, database replay and session APIs |
| Public HTTP routes | `python3 tests/http_smoke.py`, run automatically by the demo | 8 assertions pass for native login link, exact CIMD/callback URLs and public JWKS |
| PHP syntax | CI recursive `php -l` | Local syntax checks pass |
| Packaging | `python3 bin/package.py`; `cd build && sha256sum -c SHA256SUMS` | Installable package and CycloneDX inventory generated from Composer lock |

The native demo uses a pinned PHP runtime image whose preinstalled extensions support the target host; its WordPress application/entrypoint is not used. Moodle/Joomla use a disposable pinned MariaDB 11.4 container. Upstream source archives and image references are pinned. The Joomla 5.4.0 fixture is an initial-branch compatibility test, not a production patch-level recommendation. Keep deployed hosts patched.

Hosted and proxy modes have synthetic signed-provider evidence only. Protected surface: Drupal browser user login through `/user/login` and `/soca/login`. UID 1 and accounts with user/permission administration are excluded. No dated live RESOAuth login, real browser cookie/fixation matrix, OIDC conformance suite, multi-worker race/failure test, production rotation, restore drill, independent review or WCAG certification has been completed. Moodle native CLI tests establish native login user state; browser-cookie rotation is a separate pending acceptance test.

Run a real acceptance pass with publicly reachable HTTPS documents or the checked metadata proxy. Verify discovery and document contents separately, then initiate the native operator test. Record issuer, algorithms by purpose, exact metadata mode, application version/commit and date. Exercise cancellation, wrong issuer/audience/nonce/signature, response issuer absence, UserInfo identity conflict, denied domain, disabled account, copied callback, parallel tabs, replay, configuration changes, local recovery, emergency disable during a test and logout during provider outage. Confirm no test-mode account/link/profile/permission/session replacement writes. Record provider cache bounds before any rotation design. Redact tokens and identity data from saved evidence.

The local HTTP demo binds loopback only and uses disposable credentials. It cannot activate production SSO because the protocol retains strict HTTPS/public-network rules. Remove demo containers and `demo/.runtime` when finished; they contain disposable accounts and database configuration. Avoid running these tests against a real site.

Upstream integration references: [Drupal native login](https://api.drupal.org/api/drupal/core%21modules%21user%21user.module/function/user_login_finalize/11.x), [Moodle authentication plugins](https://docs.moodle.org/dev/Authentication_plugins), [Joomla authentication and user events](https://manual.joomla.org/docs/5.4/building-extensions/plugins/plugin-events/user-auth/). Standards: [CIMD draft 02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html), [PKCE](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html).
