# message-box-server-rust

Independent, self-hosted Rust implementation of the MessageBox storage and
forwarding component, intended as a foundation for PayMessage. This is **not an
official BSV Blockchain project** and is not the complete PayMessage protocol.
Its compatibility reference is
[bsv-blockchain/ts-stack 52d36a5a](https://github.com/bsv-blockchain/ts-stack/tree/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server)
(package 1.1.59).

The implemented milestone includes authenticated HTTP, persistent SQLite storage,
and the bounded Socket.IO polling/upgrade/WebSocket implementation. Earlier development acceptance covered a fixed client and test corpus; it does
**not** establish drop-in or
production compatibility. The Cargo description deliberately retains
“Experimental ... not a production-compatible server”. The executable binds
only to loopback, has no TLS listener, and does not accept payments. Real FCM
and device delivery remain unverified. See [release scope](docs/RELEASE_SCOPE.md)
for evidence boundaries, two known TS reference deviations, and deployment limits;
[compatibility contract](docs/COMPATIBILITY.md) contains detailed boundaries.

## Install and build

Use a Unix host (Linux is tested), Git, Rust 1.94.1 with Cargo, a C compiler/linker,
`pkg-config`, and SQLite development headers/library. On Debian/Ubuntu the native
build prerequisites are `build-essential pkg-config libsqlite3-dev`. Cargo needs
registry access on the first build; Cargo.lock pins dependency versions.

```sh
git clone https://github.com/linzhm/message-box-server-rust.git
cd message-box-server-rust
rustup toolchain install 1.94.1 --profile minimal --component rustfmt --component clippy
cargo +1.94.1 build --locked --release --bin message-box-server
```

Copy [config.example.json](config.example.json) to a private location, replace
the absolute placeholder paths, and provision your own private identity key as
described below. The example enables Socket.IO and disables browser CORS;
configure an explicit allowlist if a browser client needs access. It contains no
working identity or credentials. Start the built executable with:

```sh
./target/release/message-box-server /absolute/path/config.json
curl --fail http://127.0.0.1:8080/health
```

A `/health` response reports listener liveness. `/ready` checks availability of
the message SQLite connection. Neither proves client authentication or message
delivery. Application requests require the supported signed SDK
handshake and authentication; an identity header alone is insufficient.

## Implemented

- Method/path dispatch for the supported post-middleware route subset using
  already-parsed JSON fields. This is an integration seam, not a listener.
- Route-shaped JSON input/output for `sendMessage`, `listMessages`,
  `acknowledgeMessage`, and recipient-owned permission set/get/list and quote, plus device registration/listing, callable from a
  trusted embedding application.
- Real SQLite persistence, atomic recipient fanout, globally unique message IDs,
  and recipient-scoped listing and acknowledgments.
- SEC1/secp256k1 key canonicalization; exact UTF-8 name/ID byte limits; bounded
  bodies, recipient lists, pagination and acknowledgments.
- Owner-scoped device registration and redacted listing. The executable can
  configure a post-commit FCM provider; real provider and device delivery have
  not been verified.
- Wallet-injected nonce encoding/checking and low-level BRC-42 child-key
  derivation, ECDSA signing/verification and HMAC; these are not a complete
  wallet or network-ready authentication. A separate preimage encoder and
  no-certificate responder require externally supplied canonicalization and wallet.
  A separate SQLite session/replay store accepts a caller-chosen path.
- A narrow authenticated HTTP adapter supports the no-certificate handshake
  bodyless `GET /devices`, 1–100-recipient `GET /permissions/quote`, `GET /permissions/get`, `GET /permissions/list`, and
  supported JSON `POST /listMessages`,
  `/sendMessage` (including free batches), `/acknowledgeMessage`, and
  `/registerDevice` and `/permissions/set`. The fixed SDK and MessageBoxClient were exercised during development;
  [release scope](docs/RELEASE_SCOPE.md) distinguishes those historical observations
  from this source release's reproducible tests.
- Stored body envelope, deterministic ordering, list response budget, retention
  filtering, explicit expired-message maintenance, sender/inbox quotas.
- Persistent recipient permissions: sender-specific settings override box-wide
  defaults; notifications default to 10 sats, other boxes to free. Positive fees
  fail explicitly until payments are implemented.
- Required additional server-policy adapter: free, blocked, payment required or
  policy unavailable. Neither policy can bypass the other. **No permissive
  default adapter.**
- An isolated BRC-105 payment-header parser and offline signed-frame vector;
  parsing does not validate or accept payment, and authenticated business routes still refuse it.
- Explicit refusal of unsupported payments and routes.

## Run the restricted local service

The binary is Unix-only and binds only to an explicit loopback IP. It does not
provide TLS, full WebSocket/AuthSocket, the upstream MySQL schema, or general
TypeScript-server compatibility. The FCM provider is implemented, but delivery
through a real provider to a device remains unverified. The caller must protect the key,
trusted parent paths and any ACLs; POSIX mode-bit checks alone do not validate
ACLs. Do not use the public test keys for a real identity.

Provide an absolute configuration file path as the only argument. Example config
(paths are placeholders; the key file must already contain a valid, private
32-byte secp256k1 secret encoded as 64 hex characters):

```json
{
  "bind": "127.0.0.1:8080",
  "dataDir": "/absolute/private/messagebox-data",
  "identityKeyFile": "/absolute/private/identity.key",
  "freeBoxes": ["inbox"]
}
```

The key must be a regular file with no group/other mode bits. The data directory
must likewise be private; new directories and database files are created with
0700 and 0600 modes, while insecure existing paths are rejected and not changed.
Only the listed boxes have a configured zero server fee; unknown boxes fail
closed for sending and quote. Recipient permissions still apply independently.
This explicit free-box policy is narrower than the TS server's fee database.

Alternatively, explicitly set `"pricingMode": "ts-table"` and omit `freeBoxes`.
This opts into a private SQLite server-fee table initialized once with the fixed
TS defaults: notifications 10 satoshis, inbox and payment_inbox 0, and missing
boxes 0. It replaces the host policy's server-fee source for quotes and sends;
separate host admission rules and recipient permissions still apply. Changes
to existing rows persist across restarts. This is not an upstream MySQL migration
or a fee-management API. Positive fees still return 501 on send because payment
is not implemented. Keep the database private; selecting this mode allows an
otherwise unconfigured box to be delivered free when no fee row exists.

HTTP requests with an Origin use the fixed TS default public CORS profile: any
origin is allowed without cookie credentials, and the BSV auth response headers
are exposed. This includes local pages and other websites that can reach the
loopback listener. CORS is not authentication or an access-control boundary.
To restrict HTTP browser origins, set `"corsMode": "allowlist"` and
`"corsAllowedOrigins": ["https://app.example"]` in the JSON configuration,
or set `"corsMode": "disabled"`. Without either explicit JSON CORS key, the
runtime reads the pinned TS `MESSAGE_BOX_CORS_MODE` / `CORS_MODE` and
`MESSAGE_BOX_CORS_ALLOWED_ORIGINS` / `CORS_ALLOWED_ORIGINS` settings at startup.
`MESSAGE_BOX_CORS_ALLOWED_HEADERS` and `MESSAGE_BOX_CORS_EXPOSED_HEADERS`
control the respective lists; an explicit allow list disables header reflection.
JSON CORS mode/origins override environment mode/origins as a pair. These local
settings are not a production deployment configuration.
Socket.IO requests pass through the same configured Origin decision, including
preflight; development acceptance covered fixed default-client and browser Origin scenarios.
The private acceptance harness/results are not included in this initial release.

```sh
cargo run --locked --bin message-box-server -- /absolute/path/config.json
```

After successful initialization it prints a JSON ready line with its loopback
address and public identity key for client pinning, never the private key.
Public GET/HEAD `/health`, `/healthz` and `/ready` are available; readiness
checks only the message SQLite connection. An optional `routingPrefix`, such as
`/tenant/v1`, prefixes those health and application routes while authentication
handshake remains at `/.well-known/auth`. Prefix segments are restricted to
ASCII letters, digits and `-._~`, excluding empty, `.` and `..` segments; this is
not full `ROUTING_PREFIX` parity. An optional `enableWebSockets: true`
configuration enables bounded Engine.IO polling, polling-to-WebSocket upgrade
and direct WebSocket, authenticated room control, free sends and best-effort
process-local push. The default-client transport has codec tests and historical fixed-client live
observations, including polling and upgrade; see [release scope](docs/RELEASE_SCOPE.md). Consumers must use listMessages to recover missed notifications.

The server reads the MessageBox resource profile once at startup. It applies
message, list, quota, device, permission, notification, retention and selected
WebSocket limits in this port; network frame limits remain separate.
The fixed TypeScript send handler snapshots message fields with a maximum of
101 array elements before applying the configured recipient limit, so a higher
recipient setting does not permit larger batches through that handler.
Firebase is disabled unless `ENABLE_FIREBASE` is exactly `true`. When enabled,
the host assembles the HTTP v1 provider using the configured project and
service-account credentials or supported application default credentials;
invalid configuration fails startup. Details and credential precedence are in
[Firebase host](docs/FIREBASE_HOST.md). A ready listener does not prove that
Google accepts the credentials or that a device receives a notification. No
real provider or device delivery has been verified for this release.
WebSocket send events are processed serially per connection, so
`WEBSOCKET_MAX_CONCURRENT_SENDS` does not reproduce the TypeScript server's
concurrent-send rejection behavior. This remains a compatibility gap.
Finite `RETENTION_DAYS` follows the fixed TypeScript safe-integer parser; a
resulting date outside the JavaScript Date range causes a send error before
insertion rather than becoming unlimited retention.
The local SQLite schema is migrated on open to allow unlimited message retention;
this migration is for this port's schema, not an upstream MySQL database.
The health network field is a label
from `BSV_NETWORK` (default `mainnet`), not evidence of a blockchain connection.
It runs bounded expiration cleanup at startup and periodically; interval and
batch size are configurable, including a disabled periodic timer. Ctrl-C stops acceptance and
attempts to drain in-flight connections for five seconds before aborting them;
an interrupted request can have an uncertain result. The host is responsible
for protecting paths and providing any deployment-specific controls.

## Verify locally

Rust 1.94.1 was used. No external network access, database daemon, Node.js, wallet
or real assets are needed to run the Rust tests once Cargo dependencies are cached.
Some tests open loopback listeners and therefore require local socket access.

```sh
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

Use `--offline` on test/clippy commands in a dependency-cached environment.
The [testing guide](docs/TESTING.md) distinguishes reproducible Rust tests, optional
SDK fixture scripts, historical observations and unverified external behavior.

## Integration boundary

`MessageBox::open(path, policy, limits)` opens **this port's own SQLite schema**.
Call `handle(path, Some(&identity), &json_request)` only after a real SDK or
transport has verified request authentication. `Identity::from_verified_key`
checks/canonicalizes a public key; **it does not authenticate the caller**.
Supported paths are `/sendMessage`, `/listMessages`, `/acknowledgeMessage`,
`/permissions/set`, `/permissions/get`, `/permissions/list`, and
`/permissions/quote`, `/registerDevice`, and `/devices`. For permission
get/list/quote and device listing, pass parsed query fields; other paths take
parsed body fields. `dispatch_http` matches the nine
supported GET/POST method and path pairs and selects parsed query or body fields.
It returns `None` for unmatched pairs, leaving the outer framework to respond.
The caller still owns routing-prefix handling, parsing, other framework semantics
(including HEAD), authentication and middleware; it must never derive an identity
from an unverified request field or header.

Implement `DeliveryPolicy` from authoritative server fee/admission state.
`Decision::Free` must mean the adapter's requirements are satisfied without
payment. Stored recipient permissions apply independently. `PaymentRequired`
from either policy refuses the request with 501.
For quotes and send admission, `DeliveryPolicy::delivery_fee` must provide an
authoritative per-box server fee; its default implementation fails closed. A
positive fee prevents delivery until payment support exists. Existing policy
adapters must implement this method even for free delivery. This does not process
or accept a payment. BRC-105 middleware is not implemented.
For the narrow `http_auth` adapter, the caller must cap request streams before
buffering, provide a trusted wallet, enforce edge controls and TLS, and manage
maintenance. Other HTTP routes and general request forms are not implemented.
The embedding application owns rate limiting and scheduled maintenance.
Call `purge_expired` periodically to reclaim expired records. No scheduler is
silently installed.

The [pinned HTTP/authentication contract](docs/HTTP_AUTH_CONTRACT.md) records
verified middleware ordering, exact dependency versions and remaining evidence
gaps. Authentication is not inferred from an older locally cached SDK.

MOSAIC SDK identity/transport and MCAP authorization remain external boundaries.
No Kernel dependency, settlement protocol, on-chain transaction or multi-hop
contract is introduced. An MCAP adapter may enforce application authorization,
but must not substitute for proof of the sender's identity.

## License

[Open BSV License Version 6](LICENSE.txt), with preserved, scoped historical
ISC notice. The current upstream license restricts use to BSV. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); this is not an unrestricted
cross-chain release.
