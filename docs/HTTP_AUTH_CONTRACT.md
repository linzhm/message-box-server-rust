# Pinned HTTP and authentication boundary

Inspected on 2026-11-10 from the existing, clean upstream checkout at commit
`52d36a5ab1ae7cb9e3243ff4147558bcccde3c07`. This is a source review, not a
running-server observation. The reproducible test scope and historical evidence limits are described
separately in TESTING.md; neither is a production server claim.

## Exact dependency baseline

The standalone server's `infra/message-box-server/package-lock.json` pins:

| Component | Version |
| --- | --- |
| MessageBox server | 1.1.59 |
| `@bsv/sdk` | 4.0.1 |
| `@bsv/auth-express-middleware` | 2.3.0 |
| `@bsv/message-box-client` | 2.7.0 |
| `@bsv/payment-express-middleware` | 2.1.11 |
| `@bsv/authsocket` | 2.1.11 |
| `@bsv/wallet-toolbox` | 2.15.3 |

The monorepo pnpm lock instead links workspace packages. A test report must say
whether it used the pinned monorepo sources or the standalone npm lock; package
version labels alone do not prove that their bytes match.

An available local SDK 2.1.2 is **not** this baseline and does not even satisfy
the pinned auth middleware's peer range (`^2.8.5 || ^3.0.0 || ^4.0.1`). Tests
against that old SDK must not be presented as pinned authentication conformance.
No old-SDK fixture has been used to implement authentication in this port.

## Verified server pipeline

`src/app.ts:177-255` installs, in order:

1. Normalize only a run of leading URL slashes, then security headers and CORS.
2. Concurrent-request limit (standard profile: 24), pre-authentication rate
   limit (300/minute), JSON parser (standard profile: 4 MiB), stable parser
   errors, response-size limit, and Swagger routes.
3. Pre-authentication health routes.
4. `createAuthMiddleware({ wallet, sessionManager, logger })`.
5. Response-size limiting again, after response-signing interception.
6. Post-authentication composition.

`src/compose.ts:244-285` adds request-local runtime dependencies, canonicalizes
**already-authenticated** identity, applies another response bound and the
identity-keyed authenticated rate limit (1000/minute), then payment middleware,
then application handlers. Invalid authenticated identity is
`401 ERR_INVALID_AUTHENTICATED_IDENTITY`. Missing auth is left to the subsequent
middleware/route; do not invent its complete wire response from this function.

`KnexSessionManager` receives a finite 24-hour default TTL. The server migration
`2026-09-24-001-auth-message-nonces.ts` provisions durable replay claims keyed
by `(sessionNonce, messageNonce)` and indexed by expiry. This is evidence that
real auth includes session/replay state, not permission to claim that this
Rust core already provides it.

The body-parser errors are `413 ERR_BODY_TOO_LARGE` and
`400 ERR_INVALID_BODY` (`src/security/edgePolicy.ts:612-651`). These differ from
application-field errors after a body has been decoded.

## Verified route registration

All application paths receive the configured `ROUTING_PREFIX`:

| Authentication position | Method | Paths |
| --- | --- | --- |
| Before auth | GET | `/health`, `/healthz`, `/ready` |
| After auth/payment middleware | POST | `/sendMessage`, `/listMessages`, `/acknowledgeMessage`, `/registerDevice`, `/permissions/set` |
| After auth/payment middleware | GET | `/devices`, `/permissions/get`, `/permissions/list`, `/permissions/quote` |

`GET /permissions/get`, `/permissions/list`, and `/permissions/quote` consume query fields;
`POST /permissions/set` consumes
body fields. The Rust in-process `handle` method accepts their already-parsed fields only.
`dispatch_http` matches the nine implemented GET/POST pairs and selects query or
body, but does not parse HTTP, start a listener, verify credentials or implement
the surrounding middleware. It returns `None` for unmatched pairs and does not
claim Express HEAD behavior.

At the early source-review checkpoint, no Rust health listener had been added.
The current loopback runtime serves `/health` and `/healthz` as static listener
liveness responses with configured network/WebSocket labels; `/ready` checks
the message SQLite connection. See the current [runtime boundary](COMPATIBILITY.md#restricted-loopback-runtime)
and [testing guide](TESTING.md); these probes do not prove authentication or delivery.

## Historical authentication source-review checkpoint

The pinned `auth-express-middleware/src/index.ts` and
`authMiddlewareHelpers.ts` were subsequently obtained in the fixed TS evidence
bundle and independently matched to their Git blob IDs
`327d0b8f305f75e1b7130f524187ba83f9f3b618` and
`223b41e28d21fd20486775137cce15b67653a42f`. This is source review, not an
executed handshake or interoperability test.

The middleware dispatches the public `/.well-known/auth` handshake separately
from signed general requests. General requests require an authentication request
ID, version `0.1`, a compressed public identity key, nonces and a hex signature;
partial authentication headers are rejected. Responses can carry the matching
authentication headers. The middleware hands protocol processing to the SDK
`Peer`, and only continues an authenticated request after that path verifies the
sender and binds it to the request. The server's caller-supplied `Identity` seam
is not an implementation of this process.

At that early checkpoint, a separately obtained and hash-verified source bundle
contained the complete SDK
4.0.1 production source tree, including `Peer`, `AuthFetch`, nonce and signature
code, and its authentication tests. It is Git source at the pinned commit; its
identity with the npm release tarball had not been established. A narrow nonce
fixture was executed from that source with a fake HMAC wallet, but no SDK build,
complete handshake or client/server interoperability test had run at that point.
The response queue and full runnable server dependency closure had not yet been
established. The locally cached SDK 3.2.1 was not the pinned 4.0.1.

The checkpoint therefore called for real fixture exchanges and request/response
signature, identity-binding, nonce and replay tests before completing the adapter.
This is a historical gap record, not a statement that the current adapter is absent.
See the [implemented adapter](COMPATIBILITY.md#authenticated-http-application-adapter),
[public testing scope](TESTING.md), and [historical acceptance limits](RELEASE_SCOPE.md).
Missing/invalid proof and unsupported features must still fail explicitly; MCAP
application authorization must not replace BRC identity authentication.

## Reproducible source evidence

Paths below are relative to `infra/message-box-server` at the pinned commit:

| Path | SHA-256 |
| --- | --- |
| `package-lock.json` | `9a8b47c0539b82e87f6b08a464c6bc55ab92b4c52ab842b90a0174a744704a6e` |
| `src/app.ts` | `2a10eb48096a428c97d0a60b2c379529dc9e7b611d7ed0bcf33f0ac47a264c8c` |
| `src/compose.ts` | `fd35760ced6aa340fc6f5c17c5316086e3950ca2b16986670cf5d56a065941c9` |
| `src/routes/index.ts` | `f6d85906586ecad37edcf43b68fa46bcab208af8834874bdc970e475bac073a8` |
| `src/routes/permissions/setPermission.ts` | `ce3223d82b8e13c78330c51b27ee898be97a86d5b9835734be5f0b1e868cd3a5` |
| `src/routes/permissions/getPermission.ts` | `e1739f3ccdad2e31fb79634d376b4907aa0a07085468fee1cab1d0388e466d6a` |
| `src/routes/permissions/listPermissions.ts` | `12c6a891fff28dd9ad8248b8d83ed2bfe6133ae05fc16b2588160a14e825bc5e` |
| `src/utils/messagePermissions.ts` | `421c09500da6e4a0df9db93b58966790877f939501edff53c042217981318d40` |

[Immutable upstream source](https://github.com/bsv-blockchain/ts-stack/tree/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server).

## Rust HTTP application adapter

The current adapter handles all nine listed application route pairs and the
no-certificate handshake. Ordinary UTF-8 JSON is parsed before auth, then
normalized with ECMAScript binary64 numbers and property enumeration for the
fixed middleware's stringifyBRC100 signing material. Simple query parsing follows
the pinned Express 5 default; authorization and custom x-bsv-* headers are bound
to the request. Body/query/header effects remain after authentication. Payment
headers remain explicitly deferred after verification, with zero business writes.

See the current [HTTP contract](COMPATIBILITY.md#authenticated-http-application-adapter)
for exact behavior and remaining representation/transport limits. In particular,
an AuthFetch caller signing a noncanonical raw string is not equivalent to a
request signed over parsed/stringified JSON; the new frame corpus tests that
incompatible signatures fail. No independent real-client or full running-TS
acceptance is implied by author-side frame regressions.
