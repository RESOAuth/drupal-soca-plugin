# Configuration

The native Drupal configuration form provides document checks, a side-effect-free operator test, pending-login invalidation and administrator-approved identity linking/unlinking. Local login is `/user/login`.

Use Drupal deployment configuration, for example `$config['soca.settings']['profile'] = [...]` in `settings.php`, or set `SOCA_CONFIG_FILE`. Use the host bootstrap example in `tests/host.php` to instantiate `Drupal\soca\DrupalFlow`; `status()`, `checkDocuments()` and `invalidate()` have no UI requirement. Administrator-approved linking requires a local administrator account context.

Configuration precedence is built-in defaults, native host settings, then `SOCA_CONFIG_FILE`. The deployment file contains a JSON object and is limited to 65,536 bytes. Deployment values always win. The Drupal/Moodle GUI locks profile edits while deployment configuration is present; Joomla marks its JSON field read-only. Secrets are never read from UI/database JSON. Effective status reports sources/locked fields, metadata URL, revision and document/login results without private material.

Use `demo/profile.example.json`. `origin` is the canonical HTTPS scheme and authority, without a trailing slash, credentials, query or fragment. Installation path prefixes are derived from host configuration. Do not use untrusted Host/Forwarded values to set origin; configure trusted proxies in the host.

| Setting | Default / accepted values |
| --- | --- |
| `enabled` | `false`; ordinary sign-in also requires matching document and operator-login evidence |
| `provisioning` | `false`; true opts into native account creation after authentication/admission |
| `issuer` | `https://auth.resoauth.cloud`; exact explicitly trusted HTTPS issuer |
| `origin` | Required canonical application HTTPS origin |
| `metadata_mode` | `hosted` or `proxy` |
| `proxy_template` | `https://dynamic-cimd.resoauth.cloud/cimd/%s`; exactly one placeholder in HTTPS path, no query |
| `metadata_jwks_mode` | Hosted defaults to `uri`, proxy to `inline`; either explicitly configurable |
| `client_name`, `client_uri` | Host site name and canonical home URL; explicit overrides allowed |
| `logo_uri`, `policy_uri`, `tos_uri` | Omitted when unavailable; explicit public HTTPS application URLs |
| `allowed_emails`, `allowed_domains` | Empty arrays deny all; verified boolean `email_verified: true` required |
| `denied_emails`, `denied_domains` | Empty arrays; deny overrides allow |
| `assertion_alg`, `id_token_alg` | Independently pinned `ES256` by default; `ES384` or `RS256` only on explicit approval |
| `key_id` | Stable derivation from public key unless an explicit bounded identifier is supplied |
| `assertion_audience` | `token_endpoint` by default; explicit `issuer` only with provider agreement |
| `userinfo` | `optional`, `required`, `disabled`; returned identity conflicts always fail |
| `scopes` | `openid email profile`; minimum configured combination begins with `openid`; offline access prohibited |
| `max_age` | `null`, or integer 0..86,400 seconds; zero requests fresh authentication |
| `required_acr`, `required_amr` | Empty arrays, or up to 20 bounded identifiers; semantics require provider agreement |

Domain syntax accepts `example.com` and `*.example.com`. Wildcards match one or more complete subdomain labels, never the apex or `badexample.com`. Single-label rules, URLs, emails, repeated/embedded wildcards and empty labels are rejected. Both startup and protocol construction validate rules.

Public documents: `/soca/client.json` and `/soca/jwks.json`. They return JSON with explicit 300-second cache lifetime. Status exposes the exact client ID for preview. To reset the proxy, remove `proxy_template` or restore its documented default. Proxy serialisation sorts object keys recursively, uses UTF-8 JSON without escaped slashes/Unicode, then unpadded base64url. `client_id` is excluded from the encoded input and added as the exact resulting URL. Hard limits are 6,144 payload bytes and 8,192 URL bytes. The entire URL/metadata/public keys are public and visible to the proxy. Provider authentication uses issuer endpoints directly.

Generate a persistent key outside the web root, for example `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /secure/soca.pem`, set restrictive owner-only permissions and mount it read-only. `SOCA_PRIVATE_KEY_FILE` is an absolute readable path, limited to 32,768 bytes. Do not generate a new key at each worker startup. `SOCA_EMERGENCY_DISABLE=1` overrides all ordinary/test sign-in. Change `SOCA_SECURITY_EPOCH` after security revocation or restore; it is part of transaction/evidence binding.

Save a candidate with `enabled: false`. Publish documents, run the document check, then start a test as a local administrator. Normal admission and protocol checks apply. Test callbacks are bound to the initiating operator and never create/link/update accounts, write profiles/permissions or replace that session. Activate by changing only `enabled` to true. Covered configuration/key changes invalidate evidence and in-flight logins; there is no overlapping-snapshot migration yet. The enabled flag itself is excluded from the revision so candidate evidence can activate the profile. Ordinary sign-ins fail closed without both proofs, including headless deployments. Evidence is a configuration-revision proof, not a periodic availability probe.
