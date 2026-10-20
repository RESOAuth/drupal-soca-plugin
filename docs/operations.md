# Operations, threats and recovery

Local recovery is preserved: The native Drupal configuration form provides document checks, a side-effect-free operator test, pending-login invalidation and administrator-approved identity linking/unlinking. Local login is `/user/login`.

Set `SOCA_EMERGENCY_DISABLE=1`, increment `SOCA_SECURITY_EPOCH`, restart/reload all workers and run `invalidate()` through the native maintenance/CLI context. Emergency access to any sign-in path also clears pending shared replay rows and rejects ordinary/test callbacks. An epoch change covers disable/re-enable cycles with no intervening requests and prevents restored sessions from reusing old transactions. Retain independent strong local administrator authentication and test recovery before rollout. No automatic redirects or forced global SSO are installed.

Only one profile is supported. Identity links store a unique SHA-256 digest of the exact issuer/subject tuple plus a unique local account ID. Mutable email/profile data never select an account. Administrator linking requires independent ownership verification, never verified email alone. Unlinking stops future SSO for that link, but existing native sessions require host administrator revocation. Email reuse, subject/issuer changes and proxy-client-ID changes require explicit reviewed unlink/link operations. Preserve local credentials, profiles and permissions on return. Only the native authenticated user baseline is created, with no extra Drupal roles.

Transactions retain verifier/nonce/issuer/callback/revision only in the host server-side session. A minimal state hash/expiry in the host database is consumed once before token exchange. The callback must have both the originating session entry and the unused shared replay row. No new plugin cookies, localStorage, sessionStorage or IndexedDB are used. Configure shared confidential session storage for every worker; Moodle's native lock backend must coordinate all workers. Parallel tabs are bounded to five pending transactions per session. Old replay rows are cleared opportunistically at new login starts; scheduled host cleanup and storage/rate metrics are future work.

| Bound | Implemented value and implication |
| --- | --- |
| Transaction lifetime | 300 seconds; no stale/configuration-changed snapshots accepted |
| Client assertion lifetime | 60 seconds; independent random jti per exchange |
| Clock skew | 60 seconds for ID-token times; transaction start cannot be in the future |
| Public metadata/JWKS HTTP cache | 300 seconds; provider/CDN effective cache bounds remain unconfirmed |
| Provider JWKS | Fresh bounded fetch per completion; no stale cache fallback |
| Key set | One active signing key; no overlap, rotation or cache-derived retention guarantee |
| Proxy metadata/URL | 6,144 / 8,192 bytes, measured before activation |
| HTTP | HTTPS only, no redirects, public-IP checks, pinned DNS, 3-second connect and 12-second total deadline, 262,144-byte body and 32,768-byte header bounds |
| ID token/access token | Maximum 32,768 / 16,384 bytes; no persistent token retention |
| Diagnostics | No raw claim/token capture or retained diagnostics |
| Existing session revocation | Host expiry/manual revocation; no bounded plugin propagation guarantee |

Threats addressed include CSRF/login replay, copied callbacks, issuer mix-up, algorithm substitution, UserInfo conflicts, email account takeover and metadata SSRF. Shared protocol tests use actual asymmetric signatures and validate outgoing PKCE/client assertions. They simulate the provider and do not prove a live integration. Platform administrators, deployment secret readers and compromised host code remain trusted boundaries. Account creation and link insertion use native database transactions/unique constraints; arbitrary third-party host hooks may have external side effects and are outside database rollback.

Keep keys outside application data/backups with separate access controls. Back up persistent keys and identity links together with approved configuration, protect backup access and bump the security epoch before restore. No restore/failover drill or unattended rotation has been completed. A lost key requires a reviewed candidate, publication/check/test and explicit identity migration when its proxy client ID changes. Do not promise seamless rollover in this preview.

No telemetry is enabled. Issuer discovery/JWKS/token/UserInfo calls go to trusted issuer endpoints; proxy metadata is public and may be logged by its operator. Codes/access/ID tokens are request-local and discarded. Host session payloads expire according to host storage; replay records expire logically after 300 seconds. Audit uses host-restricted logs/tables and never includes tokens/claims; tamper-evident retention is a gap. Configure a 30-day audit retention policy and purge through approved host/database operations. Redact callback query strings from reverse-proxy/access/error logs, for example log `$uri` instead of `$request_uri` in nginx. The plugin cannot rewrite infrastructure logs.

Disable stops new SSO; invalidate pending replay state and bump epoch at deployment. Existing host sessions remain until host logout/administrator revocation. Re-enable only the reviewed candidate. Uninstall preserves local accounts/credentials/roles and externally managed signing keys. Drupal/Moodle remove plugin tables/configuration through native uninstall; Joomla retains its association/audit tables intentionally until an explicit, audited operator purge of `#__soca_*`. Permanent deletion removes linking recovery evidence, so review backup retention first. No account deletion is performed by plugin removal.

Availability/recovery objectives are not established. Provider/network failures fail closed while local login remains available. Apply per-IP/session ingress limits at the reverse proxy, for example 10 sign-in starts/minute with a small burst, and tune only after load tests. No load, independent penetration, assistive-technology or conformance certification is claimed.
