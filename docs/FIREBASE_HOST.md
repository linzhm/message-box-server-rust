# Firebase host and ADC

The provider is implemented; real external delivery remains unverified.
This guide describes configuration and synthetic tests shipped with the source.
It does not implement payments or change send/commit/notification ordering.

## Entry contract

The executable now calls `firebase_host::assemble_host_firebase(app, environment)`
before sharing the MessageBox and before opening its listener. It uses the existing
immutable process environment snapshot, the host's current working directory,
and a 30-second OAuth/FCM caller timeout. It does not load an additional `.env`.

- Only the exact value `ENABLE_FIREBASE=true` enables Firebase. Every other value
  removes any preinstalled provider and skips backend construction and credential
  discovery. This retains the existing disabled-provider regression fix.
- Enabled startup requires a nonempty `FIREBASE_PROJECT_ID`. The existing HTTP v1
  provider additionally requires the documented restricted ASCII project ID.
- Credential priority is nonempty `FIREBASE_SERVICE_ACCOUNT_JSON`, then nonempty
  `FIREBASE_SERVICE_ACCOUNT_PATH` resolved relative to the startup working
  directory, then ADC. An invalid higher-priority source is an error, not fallback.
- Standard ADC discovery uses `GOOGLE_APPLICATION_CREDENTIALS` (also the Google
  Node lowercase spelling), then the gcloud well-known ADC file, then metadata.
  The well-known file is under `CLOUDSDK_CONFIG` when supplied, otherwise
  `$HOME/.config/gcloud` on Unix or `%APPDATA%/gcloud` on Windows. This executable
  remains Unix-only. A missing well-known file permits metadata fallback, but
  a missing explicit file, an unreadable file, malformed JSON or unknown type
  fails initialization. No credential file or token is created or saved.
- Service-account files use the retained RS256 assertion/OAuth JWT-bearer exchange
  to `https://oauth2.googleapis.com/token`, requesting the
  `https://www.googleapis.com/auth/firebase.messaging` scope. Their in-memory
  cache refreshes 60 seconds before expiry. Standard downloaded Google RSA
  PKCS#8 PEM keys are supported; encrypted keys are not supported.
- `authorized_user`, `impersonated_service_account`, and `external_account`
  configurations use the official `google-cloud-auth` credential builders.
  Metadata uses that library's metadata credential builder. The official library
  owns their token cache, expiry and background refresh/retry lifecycle. Token
  acquisition may start when these credentials are built. Metadata honors
  `GCE_METADATA_HOST` as the official library does, including its process-level
  environment precedence. Do not mutate host environment during startup.
- Other credential types and the sovereign/GDCH feature are not implemented by
  this adapter. The external-account source variants are the official library's
  capabilities, not separately reimplemented or all independently tested here.
  Credential JSON and any file/URL/executable references are trusted operator
  configuration; never populate them from a request or untrusted tenant.
- OAuth/FCM errors are redacted. Initialization/configuration errors stop startup;
  a later token or send failure is a notification failure and never rolls back
  an already committed message. The generic notification payload never includes
  the private message body. Existing device invalidation and resource limits are
  unchanged. A ready listener does not prove that credentials are accepted.

`FirebaseHostBackend::with_transports` supports synthetic service-account OAuth
and FCM transports. Its environment and cwd must be supplied explicitly. It does
not disable the official ADC network operations; tests using ADC must isolate
those configurations/endpoints too. Backend app cache is per initializer/host,
not a Firebase Admin SDK process-global registry.

## Why service accounts retain the OAuth exchange

The official FCM HTTP v1 authentication contract requires a short-lived OAuth
access token and the Firebase messaging scope:
<https://firebase.google.com/docs/cloud-messaging/send/v1-api#authorize-http-v1-send-requests>.

The pinned `google-cloud-auth` 1.18.0 public service-account builder offers
`AccessSpecifier::Audience` or `AccessSpecifier::Scopes`, not an OAuth-exchange
switch. In its `src/credentials/service_account.rs`,
`ServiceAccountTokenProvider::token` directly returns `generate()`'s signed JWT;
`build_access_token_credentials` uses the same path. Its JWT-bearer exchange in
`credentials/idtoken/service_account.rs` produces an ID token, not an FCM access
token. Therefore routing discovered service accounts into the already implemented
OAuth exchange is necessary. No second service-account exchange was created.

The fixed TS initialization source is blob
`e5871dab0061bd7970925249fd6839bf5de409fb` in
`bsv-blockchain/ts-stack@52d36a5ab1ae7cb9e3243ff4147558bcccde3c07`.
Its 19 fake initialization observations remain covered by existing tests.

## Dependencies and licenses

- `google-cloud-auth = 1.18.0`, official Google package, Apache-2.0, MSRV 1.91.
  Crate SHA-256:
  `d563c7b987f40249c274a4e6a671661df6be2d084f08476dda2f0f931576cfcf`.
  License copied from its declared VCS revision
  `googleapis/google-cloud-rust@38e533f01d980911303336743cfdfdf828d713b3` into
  `LICENSES/google-cloud-auth-1.18.0-APACHE.txt`.
- `ring = 0.17.14`, Apache-2.0 AND ISC. Package notices,
  including the once_cell notices, are retained under `LICENSES/ring-0.17.14/`.
- `rustls = 0.23.45`, Apache-2.0 OR ISC OR MIT, explicitly selects the ring crypto
  provider. This is the existing lockfile version, not a version downgrade.
  The Apache license is retained in `LICENSES/rustls-0.23.45-APACHE.txt`.
- Google default features are disabled, avoiding AWS-LC and unused ID-token
  support. Existing versions remain locked; 61 additional crate versions are
  resolved, including reqwest 0.13.5 alongside existing 0.12.28. All are from
  crates.io. Cargo.lock records their checksums. New dependency license labels
  include Apache/MIT/ISC, Unlicense and CDLA-Permissive-2.0 (root certificate data).
  See the complete source-release [dependency inventory](DEPENDENCY_LICENSES.md).
  A binary/container distribution would need its own full notice bundle. The repository's Open BSV and scoped historical ISC obligations
  are unchanged.

## Synthetic tests and external limits

The Rust tests exercise service-account signing/OAuth, cache behavior, ADC
selection, startup failures, post-commit notification failures and fake TLS/FCM
transports. Executable startup tests isolate their environment and use temporary
files. The committed RSA key is a public synthetic fixture, not a credential for
any live account. See [TESTING.md](TESTING.md) for the full commands.

Real Firebase provider acceptance, device receipt and notification display are
three separate unverified layers. They require an operator-owned test project,
credentials and device; a ready listener or synthetic OAuth response proves none
of them. Enabling Firebase may make external network requests as described above.
