# Compatibility contract, application core and permission slice

## Authority and claim

Baseline: `bsv-blockchain/ts-stack` commit
`52d36a5ab1ae7cb9e3243ff4147558bcccde3c07`, `infra/message-box-server`, package
version **1.1.59**. All upstream links below use that immutable commit.

The claim is **a source-derived application-contract subset**, verified by Rust
integration tests and selected fixed Git-source SDK/MessageBoxClient loopback
tests. It is not a complete TypeScript port, upstream database migration,
production replacement, or proof of all wire/BRC behavior. The full upstream
TypeScript server has not been run differentially against this implementation.

## Boundaries

| Boundary | Milestone behavior |
| --- | --- |
| Authentication | HTTP adapter verifies a no-certificate BRC handshake and the nine documented application routes using a wallet and session store. Other application-core calls still require caller-verified `Identity`. Key parsing and nonce checks alone are not proof. |
| Transport | `http_auth` handles the documented GET/POST routes with fixed-TS JSON/query/header preparation; `http_stream` bounds body data. A separately configured loopback binary has HTTP CORS and restricted Socket.IO polling/upgrade. An optional restricted route prefix is supported. Non-UTF-8/compressed bodies, TLS and full rate-limit parity remain incomplete. |
| Admission | Persistent recipient permissions plus required trusted `DeliveryPolicy` for admission. Server fee comes from that policy by default, or explicitly from a private SQLite table. Admission and recipient permissions still apply in either mode. |
| Payments | After message validation, any `payment` field (even null) returns `501 ERR_PAYMENT_NOT_IMPLEMENTED`. Without that field, policy blocks take precedence over `PaymentRequired`; a positive authoritative server fee or a payment requirement returns 501; an unavailable or out-of-range server fee returns 503 in host-policy mode or 500 in explicit SQLite fee-table mode. All these failures perform zero writes. No fake wallet or BEEF acceptance. |
| Persistence | SQLite schema private to this port, not upstream MySQL-compatible. No migration claim. One pooled connection; transactional fanout/quota checks. |
| SDK/MCAP | External application integration seams only; neither is implemented or implicitly trusted. |
| Notification | Device registration/listing and optional restricted loopback free-send push from WS and HTTP. The executable can assemble an FCM HTTP v1 provider from service-account or supported application default credentials; only `ENABLE_FIREBASE=true` enables it. No real Firebase delivery or durable notification queue has been verified. |

## Supported route subset

### `/sendMessage`

Input: `{ "message": { "recipient": keyOrArray, "recipients": optionalAlias,
"messageBox": string, "messageId": stringOrArray, "body": string } }`.

- `recipients` has precedence unless null/missing; fallback to `recipient`.
- 1–100 recipients by default, trimmed with ECMAScript whitespace, curve-checked
  SEC1 keys canonicalized to compressed lowercase hex; duplicates rejected.
- Message boxes: 1–128 UTF-8 bytes, no surrounding ECMAScript whitespace or C0/C1
  controls. IDs: 1–256 bytes under the same exact-text rules.
- Nonblank string body, maximum 1 MiB by default. Body is stored as the JSON
  string envelope `{"message":"..."}`, not as raw body text.
- IDs correspond to recipients in order and must be globally unique across
  stored records. All recipient inserts commit or roll back together.
- Response: `status`, human-readable `message`, and `results` containing
  `{recipient, messageId}`. No invented top-level message ID.
- Blocks return 403 with `ERR_DELIVERY_BLOCKED` and `blockedRecipients`.
- Default sender/inbox limits: 10,000 active messages and 1 GiB each. Stored
  envelope bytes count, not only plaintext body bytes. Expired rows do not count.

Authority: [sendMessage.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/routes/sendMessage.ts),
[messageFields.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/security/messageFields.ts).

### `/listMessages`

- Scope is authenticated recipient plus exact message-box name. Unknown box
  returns an empty successful page without creating database state.
- `limit` default/max 1000, `offset` default 0/max 100000, `skip` alias. If both
  offset and skip are nonnull they must agree. Integral JSON floats are accepted
  as JavaScript safe integers within the configured bounds. Strings are not.
- Optional `messageId` filter; explicit null is invalid for this field.
- `created_at ASC, message_id ASC`; timestamps returned as UTC RFC3339 milliseconds.
- Returns string `body`, `sender`, `messageId`, `createdAt`, `updatedAt`, plus
  `limit`, `offset`, `nextOffset`, `hasMore`.
- Default 8 MiB response budget uses the upstream 256-byte allowance plus each
  encoded item and comma. A first item exceeding the budget returns 413; it is
  not silently skipped. Rows are streamed rather than loading an entire page
  before applying the byte budget.
- Expired rows are excluded at query time. Retention defaults to 30 days.

Authority: [listMessages.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/routes/listMessages.ts),
[resources.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/config/resources.ts).

### `/acknowledgeMessage`

- Requires 1–1000 exact bounded IDs by default; validates the entire batch before
  deletion and deduplicates it.
- Deletes only records belonging to the authenticated recipient. If at least
  one owned ID was deleted, succeeds even if other supplied IDs were unknown.
- No owned match returns `400 ERR_INVALID_ACKNOWLEDGMENT`. Repeating an already
  completed acknowledgment is therefore not falsely reported as successful.

Authority: [acknowledgeMessage.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/routes/acknowledgeMessage.ts).

### `/permissions/set` and `/permissions/get`

- Set accepts parsed POST body fields: `messageBox`, numeric `recipientFee`, and
  optional `sender`. Get accepts parsed GET query fields: `messageBox` and
  optional `sender`. The core accepts parsed fields; the HTTP adapter supports
  the UTF-8 JSON and simple-query shapes documented below.
- The owner is exclusively the verified caller, never a `recipient` field.
  Set and get require authentication even when their fields are invalid.
- Omitted/null sender selects box-wide scope; otherwise its SEC1 public key is
  canonicalized without trimming. Box names are exact control-free strings of
  1–128 UTF-8 bytes. Fees are integral JSON numbers from -1 through 2147483647,
  accepting integral floats just as upstream JavaScript does.
- -1 blocks, 0 allows without recipient payment, positive values require
  payment. Storing a positive fee succeeds; delivery still returns 501 because
  payment processing is unimplemented.
- Set upserts one owner/box/sender scope, preserves creation time and changes
  update time. Success is returned only after SQLite persistence.
- Get returns the exact stored setting and timestamps, or `permission: null`.
  It does not resolve defaults or create rows.
- Sending resolves sender-specific, then box-wide, then notifications=10 sats
  or other boxes=0. The mandatory server-policy adapter also applies. A block
  from either takes precedence over payment requirements across fanout.
- Bad stored fees or unavailable permission storage fail closed. Send-time
  permission lookup failure returns `503 ERR_POLICY_UNAVAILABLE`, set persistence
  failure `500 ERR_DATABASE_ERROR`, and get failure `500 ERR_INTERNAL`. Policy is
  checked during admission; there is no claim of atomic revocation across
  concurrent permission updates and already-admitted sends.
- The port adds its own SQLite permission table when opening an existing core
  database, preserving messages. This is not an upstream MySQL migration.
- Permission deletion, administrative server-fee storage, MCAP
  delegation and permission-entry quotas are not implemented. No implicit
  permission-management authority is granted to a delegate.

Authority: [setPermission.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/routes/permissions/setPermission.ts),
[getPermission.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/routes/permissions/getPermission.ts),
[messagePermissions.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/utils/messagePermissions.ts).

### `/permissions/list`

- Accepts parsed GET query fields. Without runtime resources, or with the
  standard profile and no overrides, default/max `limit` is 100 and maximum
  `offset` is 100000; default `offset` remains 0. The small profile uses
  default/max limit 50/100 and maximum offset 10000; high-throughput uses
  500/1000 and 1000000. `resource_config` allows the respective
  `MESSAGE_BOX_PERMISSION_LIST_DEFAULT_LIMIT`, `MESSAGE_BOX_PERMISSION_LIST_MAX_LIMIT`
  and `MESSAGE_BOX_PERMISSION_LIST_MAX_OFFSET` overrides, including supported
  unlimited sentinels; these numbers are not universal hard caps.
- Pagination accepts scalar numeric strings and JSON numbers. String conversion
  supports whitespace, decimal/exponent, and unsigned hexadecimal/octal/binary
  forms used by JavaScript `Number`; then integer/range checks apply. Unlike
  implicit JavaScript coercion on constructed non-HTTP objects, arrays, objects
  and booleans are rejected. Empty offset string means zero; empty limit fails.
- `createdAtOrder` is exactly `asc` or `desc` (default). Validation order is
  limit, offset, sort order, then optional exact message-box filter.
- Owner identity is always the verified caller. An optional `recipient` field
  cannot select another owner. Sorting is box ASC, sender scope ASC (box-wide
  first), then creation time in the chosen direction. It is not globally sorted
  by creation time; owner/box/sender uniqueness makes that third key a tie-break.
- Response is `{status, permissions, totalCount}`. Each permission has `sender`
  (null for box-wide), `messageBox`, `recipientFee`, `createdAt`, `updatedAt`.
  There is no per-row status, next offset, or limit echo. The total counts the
  filtered owner set before paging, not the page length.
- Missing auth returns `401 ERR_UNAUTHORIZED`; storage/invalid stored fee
  failures return `500 ERR_LIST_PERMISSIONS_FAILED` without partial success.
- At most 100 permission records are materialized under the default/standard
  settings above. Other profiles/overrides change the accepted limit; an unlimited
  setting does not retain a 100-record cap. HTTP response-byte limits remain the
  embedding adapter's responsibility. Count and page are not advertised as an
  atomic snapshot across concurrent setting changes.

Authority: [listPermissions.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/routes/permissions/listPermissions.ts).

### `/permissions/quote`

- Accepts parsed GET query fields with a single recipient or an array of 1–100.
  The authenticated sender and recipient keys are canonicalized; duplicate keys
  are rejected after normalization. Box validation precedes recipient-array
  validation. The input parser and authentication remain external.
- Recipient fees use sender-specific, then box-wide, then notifications=10 sats
  or other boxes=0. By default `DeliveryPolicy::delivery_fee` supplies the server
  fee; its default returns an error. An explicitly enabled SQLite table can
  instead be the sole fee source for quote and send, with missing or null rows
  treated as zero. The fee is validated against 0–2,147,483,647. Storage and adapter failures produce `500 ERR_INTERNAL`. There is no claim that quoted
  payments can be accepted by this port.
- A single recipient, including an array of length one, uses the legacy `quote`
  shape. Multi-recipient results retain input order and list blocked recipients.
  Per upstream, delivery fees include blocked recipients in the totals even though
  the total is named `totalForPayableRecipients`. Status reflects the recipient
  fee only: an additional delivery policy can still reject the subsequent send.
- Unlike upstream's ten-at-a-time fetch, this SQLite implementation reads fees
  sequentially. It does not claim a snapshot across concurrent permission edits.
  SEC1 key acceptance is only the tested subset, not exhaustive SDK parity.

Authority: [getQuote.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/routes/permissions/getQuote.ts).

### Device registration and listing

- `/registerDevice` accepts an exact control-free token of at most 500 UTF-8
  bytes, optional exact device ID of at most 255 bytes, and optional platform
  `ios`, `android` or `web`. The owner is the verified caller. The same owner
  can refresh a token; another owner receives `409 ERR_DEVICE_TOKEN_ALREADY_REGISTERED`.
- `/devices` is owner-scoped, with standard default/max limit 100 and maximum
  offset 100000. It returns the last 10 UTF-16 code units of each token with
  an ellipsis prefix, never the full token unless it is at most 10 code units.
  A split surrogate at the boundary is replaced by U+FFFD because Rust strings
  cannot represent the lone surrogate that JavaScript can; exact parity for
  such tokens is not claimed. Scalar query-number parsing is the same bounded
  subset as permission-list parsing.
- SQLite persists this port's own device schema; token uniqueness and sorting
  can differ from an upstream MySQL collation. Ordering ties are unspecified,
  and timestamps and DB errors have not been compared against a live TS server.
  The SQLite database stores full delivery tokens; embedding operators must
  protect access to the database. The executable's configured Firebase host has
  not been tested against a real Firebase provider and does not prove delivery.

Authority: [registerDevice.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/routes/registerDevice.ts),
[listDevices.ts](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/src/routes/listDevices.ts).

### Authentication nonce helper

The isolated `auth_nonce` module implements the fixed SDK helper's 16-byte OS
random challenge, 32-byte wallet HMAC and canonical base64 framing. It passes
the `[2, "server hmac"]` protocol, TextDecoder-compatible key ID, counterparty
and originator to an injected wallet. Invalid MACs return false; other wallet
errors propagate. The injected wallet is not implemented here. Validating a
nonce alone does not prove identity, bind a request, establish freshness or
prevent replay. This helper is not connected to the route dispatcher.

### Standalone BRC-105 replay claims

`payment_replay::SqlitePaymentReplayStore` uses a caller-selected Rust-owned
SQLite file and a separate `brc105_replay_claims` table, not the TS migration
schema. Empty, `:memory:` and `file:` URI targets are rejected; the host must
still supply a genuinely persistent filesystem with correct SQLite locking. Its atomic insert returns false for an existing transaction ID. Default
retention is 365 days; a positive `u32` day count or forever can be selected.
Elapsed records continue to block until explicit pruning, and permanent records
are not pruned. The store accepts opaque IDs; the caller must obtain valid IDs
from verified transactions in one canonical encoding (such as lowercase hex),
and follow the payment mode’s validation requirements. BRC-105 header claims
require a trusted wallet to newly accept the payment; legacy recipient-only
payments have different upstream checks. No scheduled/batched maintenance is supplied. This is not wired
to HTTP or a wallet. A separate method inserts a permanent claim in a supplied
SQLite transaction. The caller must initialize the same replay table in that
database used by ordinary claims; the method cannot enforce that condition. The
caller must explicitly roll back the transaction if a duplicate or error makes
its other writes invalid. The message route does not call this method.
Wallet receipt, replay claim and delivery are not one atomic transaction.

### Offline payment candidate inspection

`payment_candidate::inspect_payment_candidate` combines the narrower no-BUMP or regular-BUMP,
unique-ID normalizer, requiring an acyclic traversed subject graph, with the
subject's first-output amount check for a positive JavaScript-safe price. Matching BUMPs and txid-only placeholders stop
the dependency walk without proving ancestry. `None` can mean unsupported, not necessarily
invalid under the fixed middleware. `Some` is only an unverified structural
observation: it does not check the payment prefix, request authentication,
scripts, chain, wallet internalization, replay or authorize delivery. Input
size must be bounded by the caller. The HTTP adapter does not call it.

### Offline regular BUMP root calculation

`regular_bump::parse_regular_bump` accepts a narrow standalone form: one
flagged offset-zero leaf, or a flagged leaf with one explicit unflagged sibling
at level zero and exactly one explicit unflagged sibling at each higher level.
It computes a Merkle root, but does not verify that the root belongs to a real
block, verify a transaction, or prove payment. Compound paths, duplicate
markers, extra flags and other valid BUMP forms are unsupported. The standalone
parser rejects trailing bytes and requires the caller to bound input size. It is
not connected to BEEF or online payment processing.

### Offline Atomic BEEF with regular BUMPs

`beef_bump::parse_atomic_beef_with_regular_bumps` structurally reads Atomic
BEEF V1/V2 with the restricted regular BUMP forms above, raw transactions and
V2 txid-only entries. It preserves BUMP indexes without proving they are in
range or match a transaction. It does not validate Atomic membership or
closure, trust a block root, execute scripts, normalize BEEF, accept payment or
contact a wallet. Unsupported BUMPs and other valid forms return `None`. Input
size must be bounded by the caller. Unlike the SDK's lazy BEEF scan, this
subset rejects raw output amounts above JavaScript's safe-integer maximum
during structural parsing. `normalize_regular_bump_atomic_beef` additionally
normalizes a unique-ID, acyclic subject graph with supported regular BUMPs,
remapping used proof indexes. A selected proof must be in range, match a
level-zero hash and already use canonical leaf order. It rejects unsupported
forms that the SDK can normalize. A matching local Merkle path or txid-only
placeholder terminates traversal but does not prove a real block, complete
ancestry, script validity or payment. Neither function is connected to HTTP
payment.

### Offline Atomic BEEF framing subset

`beef_subset::parse_atomic_beef_subset` reads only Atomic BEEF V1/V2 with no
BUMPs: V1 raw transactions without BUMP indices and V2 raw or txid-only entries.
It rejects unsupported forms as well as malformed data and requires no trailing
bytes. Unlike the SDK's structural BEEF scan, it also rejects transactions
whose output amounts exceed JavaScript's safe-integer range. Successful parsing
can include an absent subject, unrelated or duplicate entries, or no entries.
It does not validate the Atomic dependency closure, BUMP, chain roots, scripts,
wallet internalization, replay or payment. The caller must bound input size.
It is not connected to online payment processing. `normalize_linear_atomic_beef`
separately normalizes only unique-ID, no-BUMP, single-parent paths ending at a
zero-input transaction or txid-only placeholder. It rejects missing referenced
entries and branch graphs, even when the SDK accepts them. A txid-only end does
not prove its ancestry. This is not proof of dependency closure or payment.
`normalize_acyclic_atomic_beef` also handles unique-ID, no-BUMP acyclic
graphs when all subject-reachable referenced entries are present. It rejects
cycles in that selected graph and duplicate IDs anywhere, but drops unrelated
entries without checking their dependencies. It retains the same txid-only
placeholder limitation and rejects other forms the SDK may accept.
`inspect_subject_output` selects the last matching subject entry and observes its first output only;
it does not normalize dependencies or approve a payment.

### Offline raw transaction framing

`transaction_frame::parse_transaction_frame` structurally reads one standalone
raw transaction, extracts input transaction IDs, output amounts and opaque script
bytes, and computes its display-order txid. It requires canonical CompactSize
fields, JavaScript-safe output amounts and no trailing bytes. The caller must
bound input size. It does not parse BEEF, execute or validate scripts, verify
transaction economics, check a chain proof, or authorize a payment.

### Offline unsigned CompactSize decoder

`compact_size::decode_unsigned_compact_size` reads one canonical unsigned
CompactSize value bounded by the pinned SDK's JavaScript safe-integer limit,
returning its byte count. It leaves trailing bytes to the enclosing parser and
is not a BEEF, transaction, Merkle proof or payment validator.

### Offline payment-header parser

`payment_header::parse_payment_header` parses only the pinned BRC-105 JSON
object and its three nonempty canonical Base64 fields; extra fields are ignored
as in the fixed middleware. `verify_payment_prefix` separately uses the SDK
nonce/HMAC path with `self` and maps wallet errors to rejection. It does not
prove freshness or authenticate the whole header, validate a transaction,
check payment amount, internalize funds, prevent replay,
or authorize delivery. Authenticated business routes still reject `x-bsv-payment`. The
caller must bound the incoming header size. Rust JSON parsing may reject deeply
nested, lone-surrogate, or extreme-number JSON accepted by JavaScript. BRC-105 and legacy body
payments remain unimplemented.

### Authenticated HTTP application adapter

`HttpAuthAdapter` handles the no-certificate `POST /.well-known/auth` handshake,
five application POSTs (`/listMessages`, `/sendMessage`, `/acknowledgeMessage`,
`/registerDevice`, `/permissions/set`) and four GETs (`/devices`,
`/permissions/quote`, `/permissions/get`, `/permissions/list`). These application
requests are prepared according to the fixed TS middleware, not by requiring
wire bytes to already equal JSON.stringify output.

- UTF-8 JSON parsing precedes authentication. Strict-mode object/array JSON,
  whitespace, alternate escapes, duplicate keys (last value wins), numeric key
  enumeration, finite binary64 values across all magnitudes, and integer
  rounding follow JSON.parse/JSON.stringify semantics. The same normalized
  values are signed and consumed by business handlers. The existing `ryu-js`
  formatter handles numbers, without magnitude-specific special cases.
- A dense root array of bytes uses the middleware's raw-byte signing branch;
  other arrays use JSON serialization. All root arrays still fail the
  application's object requirement after authentication. Root primitives and
  malformed JSON return 400 `ERR_INVALID_BODY` before authentication.
- An absent/unframed empty body uses the absent-body sentinel. A framed JSON
  body is signed as parsed data. Content types not parsed by the TS JSON parser
  do not contribute application fields. Non-UTF-8 charsets and compressed
  content encoding have not been implemented or validated; this is a UTF-8,
  identity-encoding contract, not complete body-parser coverage.
- Raw negative zero, structural depth over 64, and over 100000 data nodes fail
  the pinned middleware's authentication-data checks before business work.
  Ordinary SDK JSON.stringify(-0) emits zero and remains valid. Valid lone
  UTF-16 surrogates and overflowing numeric lexemes outside serde Value's
  representation remain explicit 501 boundaries after auth-header validation;
  the latter is not TS parity (the TS middleware rejects nonfinite data).
  No new Unicode/number representation model is claimed.
- Express 5.2.1 defaults to Node's simple query parser. Decoded values remain
  strings, repeated keys become arrays, unknown fields remain ordinary fields,
  bracket-looking keys are literal keys, and at most 1000 pairs are consumed.
  Business validators, not a pre-auth allowlist, decide which fields matter.
  `%20`, `+`, percent-escape case, extra fields and scalar duplicates do not
  cause an unsupported-route error.
- Signature pathname/search come from WHATWG URL applied to Host plus the
  original request target. A bare `?` is absent. Nonempty search order and
  percent spellings are not rebuilt from parsed business fields. POST query
  data never substitutes for body data. Routing prefixes and initial slash
  normalization affect routing only, not the authenticated URL.
- Signed headers include Content-Type (media-type case retained, parameters
  removed), authorization, and x-bsv-* except x-bsv-auth*. Their lower-case
  ASCII names use the fixed Node localeCompare order, checked against actual
  middleware/SDK frames including all legal HTTP token characters. Duplicate
  bound headers remain rejected. Header addition/removal/value changes are
  signature changes, not merely ignored transport metadata.
- `x-bsv-payment` is authenticated but still returns a signed 501
  `ERR_PAYMENT_NOT_IMPLEMENTED` before any business writes. Supporting its
  signature does not enable payment acceptance, wallet access or delivery.

**SDK strings and parsed JSON are different signing inputs.** AuthFetch signs
an explicitly supplied string as its original UTF-8 bytes. The server signs
parsed/stringified JSON. A noncanonical string signed by AuthFetch can therefore
fail real TS authentication. This adapter reconstructs the TS frame and rejects
that incompatible proof; it does not accept both frames. A proof made over the
middleware frame permits equivalent JSON whitespace/escape/number spellings,
while any change in the consumed value still fails verification.

The adapter verifies the request before constructing the caller Identity,
dispatches owner-scoped business handlers and signs actual response bytes.
Missing/partial/duplicated/invalid auth never authorizes business writes. Its
handshake/error response shapes remain a subset; full auth failure parity,
certificate exchange, arbitrary route prefixes and non-application routes are
not claimed. It is buffered; the host supplies streaming limits, wallet/session
lifecycles, TLS and edge controls. The configured loopback runtime supplies
CORS and bounded Socket.IO separately. No production deployment is implied.

`tests/fixtures/http-compat-sdk4-lock.json` is generated using the fixed server's
SRI-verified npm SDK 4.0.1 and middleware 2.3.0. Source-map contents for the
middleware helper, SDK AuthFetch, BRC100ByteEncoding and Writer were each matched
to their fixed Git blobs. This establishes equivalence for those files, not the
whole packages. These new frame tests use a fake wallet/session store; they
are Rust regressions rather than live TS acceptance. Earlier live-client
observations are historical; this initial source release does not include their
private platform reports. See TESTING.md for reproducible checks.

### BRC-103 responder subset

`auth_responder` handles no-certificate initial requests and signed general
messages with an injected wallet and session store. Initial requests create
unauthenticated sessions. General messages require the server's valid nonce,
matching stored identity, valid signature, an atomic nonce claim and a successful
session update before returning an identity. Certificate-bearing requests are
explicitly unsupported. The caller must supply a trusted, expiring, replay-safe
store and bind the `actual_frame` argument to the actual request. The store must
reject duplicate session nonces, retain immutable identity bindings, and reject
a final authentication update if the session has disappeared or expired. It
must retain each claimed general-message nonce until that session is invalid
and fail closed on capacity exhaustion; initial-request claims need the
configured bounded replay window. The responder can build and sign a
prepared response using the request ID from an accepted frame and the stored
peer nonce, but the HTTP transport must canonicalize the actual response and
transmit matching authentication headers. `SqliteAuthSessionStore` provides an independent SQLite implementation of
that subset, using a caller-chosen path, 24-hour default TTL, bounded initial
claim eviction and signed-message claim retention until session expiration.
Expiry decisions use SQLite's statement-time `unixepoch('subsec')`; the store
requires a SQLite build that supports it and refuses to open if unavailable.
Instances sharing an authentication database must use consistent TTL and
capacity settings. A later out-of-range clock prevents session lookup and claim
from succeeding, although that abnormal-clock path has not been dynamically tested.
The host must schedule `prune_expired` and protect the database. Its SQLite
schema is private to this port, not an upstream MySQL migration. A fixed SDK
Peer-to-responder exchange and replay after process restart passed only over
a test stdio bridge on local macOS SQLite. The narrow HTTP adapter connects this responder to the limited routes stated above and
emits signed HTTP responses; no production wallet or general route integration is provided. Hosted VFS, crash
recovery and full BRC/HTTP interoperability remain unverified.

### BRC-104 preimage encoding

`auth_frame` encodes already-canonicalized request and response components
using the pinned SDK's CompactSize conventions, including the -1 absent-body
sentinel. It validates the source server's method character set, but does not
parse an HTTP request, canonicalize the URL or body, select/sort/validate signed
headers, enforce transport limits, bind components to the actual request, sign
responses or verify a signature. The caller must distinguish absent bodies from
zero-length binary bodies: the former uses -1, the latter encodes length zero;
empty text/form bodies use -1 in the source helper. A caller must perform those steps using the
verified request and must not treat this encoder as authentication. It is not
connected to the route dispatcher.

### BRC-42 child-key primitive

`brc42` derives a private child or corresponding peer public child using the
secp256k1 ECDH point, compressed-point HMAC-SHA256 and exact invoice string, as
in the fixed SDK source. The caller constructs and validates the invoice; this
low-level API does not implement SDK wallet validation, a complete wallet,
authentication, forward secrecy or replay protection. It signs SHA-256 message
hashes and verifies standard DER signatures with the derived keys, accepting both
low-S and high-S signatures as the SDK verifier does. Rust's strict DER parser
and the SDK's low-level DER parser differ on some noncanonical encodings;
`ProtoWallet` also applies its own canonical-DER validation. Exhaustive DER
acceptance parity is not claimed. `verify_message` returns `Ok(false)` for invalid signatures or
malformed DER, whereas SDK `ProtoWallet.verifySignature` rejects or throws.
This API accepts message bytes only; SDK direct-hash and `forSelf` modes are
not provided. BRC-derived HMAC uses the SDK's minimal big-endian symmetric key
encoding; it is a primitive, not a wallet adapter. Its `verify_hmac` returns
`Ok(false)` for a mismatch, while SDK `ProtoWallet.verifyHmac` throws
`ERR_INVALID_HMAC`. The tag comparison uses a constant-time library check; no
constant-time claim is made for the entire derivation. It rejects zero private children or an
infinite public child; no SDK parity is claimed for those exceptional values.
Fixtures use publicly disclosed test keys and must never protect assets.

## Deliberate differences and remaining compatibility gates

1. No complete HTTP/BRC-103/104, BRC-105, BRC-29, Atomic BEEF verification, wallet
   internalization or replay recovery. Bounded Socket.IO and the FCM provider are
   implemented; full transport parity and real Firebase delivery are not verified.
   The transport-neutral core does not dispatch health routes; unknown core paths return 501.
2. All payment fields fail explicitly on otherwise valid messages. Message
   validation runs first, so `{ "payment": null }` without a message returns the
   400 message-required error. With no payment field, a blocked recipient yields
   403 even if another recipient requires payment. Current upstream distinguishes malformed
   payment data from valid payments; this milestone does not emulate that parser.
3. Policy-unavailable uses explicit `503 ERR_POLICY_UNAVAILABLE`; upstream DB or
   policy errors may instead produce its internal error. The upstream recipient
   fallback is now implemented: notifications require 10 sats and other boxes
   default to free. Server fees still require the explicit trusted adapter.
4. The startup resource profile supports selected TS environment settings and
   unlimited sentinels where defined by `resource_config`; it is not complete TS
   configuration parity. Port config bounds are validated at startup.
5. Native JSON cannot represent JS accessors, prototypes, sparse arrays or
   undefined. Rust rejects invalid Unicode at the parser boundary; lone-surrogate
   compatibility is untested. Nonobject requests are explicitly rejected.
6. Common compressed/uncompressed SEC1 hex keys are tested. Exhaustive equality
   with `@bsv/sdk PublicKey.fromString` acceptance rules has not been established.
7. SQLite binary text ordering/uniqueness, UTC timestamps and errors must be
   compared to the actual upstream DB/collation before claiming all-ID parity.
   Offset pagination is not a snapshot across separate client calls.
8. No multiserver/load/OS-crash claim. SQLite transaction rollback is tested;
   MySQL/PXC locks, database retry policy and payment failure recovery are not.
9. Embedders call expiry maintenance explicitly; the executable also runs bounded
   startup/periodic maintenance. Acknowledgment/maintenance removes IDs, so this
   is not an eternal replay tombstone service.

The library is an embedding boundary; the executable binds only to loopback.
Public deployment requires a separately reviewed TLS/edge configuration and
operational controls. Existing authentication and resource controls do not
constitute production deployment acceptance. Multi-hop contracts remain outside scope.

The [HTTP/authentication boundary](HTTP_AUTH_CONTRACT.md) pins verified
standalone dependencies and preserves the early source-review checkpoint. The
[current adapter](#authenticated-http-application-adapter) is implemented;
[TESTING.md](TESTING.md) and [RELEASE_SCOPE.md](RELEASE_SCOPE.md) distinguish its
reproducible checks from historical observations and remaining evidence limits.

### Offline supplied-payment stage

`payment_stage` is an offline composition of the positive-price supplied-header
steps: parse, nonce check, restricted candidate inspection, injected wallet
internalization, then replay claim. Its status and code mapping covers only
those steps. It is not connected to HTTP and implements neither the 402 challenge
nor the zero-price branch. Unsupported BEEF shapes can be rejected even when the
pinned SDK accepts them. Its JSON wallet-result check represents data-only values;
a real adapter must safely decode results and cannot infer JavaScript accessor or
prototype behavior from this representation.

The host must bind the header, price and sender to an authenticated request and
provide a trusted wallet and durable replay implementation. A successful result
only records what those injected components reported, not independent proof of a
valid payment or message delivery. Wallet errors or timeouts can occur after a
wallet side effect, as can replay failure. No cross-system atomicity or recovery
is provided. No actual wallet or payment was exercised.

### Offline legacy payment intent state

`payment_intents` is a Rust-owned SQLite state store for the pinned send route's
transaction-ID/request-digest/attempt-token binding and prepared,
wallet-accepted and completed states. Its table and timestamps are not the
upstream migration schema. It does not compute the digest, authenticate the
sender, internalize funds, write messages, or connect to HTTP. A caller must
derive the canonical lowercase transaction ID from the verified transaction, and
compute the digest from a validated authenticated request using the pinned
serialization, not accept a client-provided hash. Every new attempt needs a
fresh cryptographically random token; only that same owned attempt may reuse it.
The store cannot distinguish concurrent callers that supply an identical token.
The caller must ensure a prepared record is released only before any wallet attempt, and completion is
marked only after message and replay transaction commit. This store cannot
validate these preconditions or automatically recover wallet side effects; a
process interruption can leave a prepared record requiring careful handling.

### Offline payment intent digest subset

`payment_intent_digest` produces the fixed source's SHA-256 preimage and digest
for a strict JSON-data subset: string sender, validated message fields and
original BEEF byte array; optional missing, null or string description; optional
string-array labels and missing, boolean or null seekPermission; and one or more ordinary wallet
payment outputs with safe nonnegative integer indexes and three string
remittance fields. Output-level and remittance-level customInstructions may be omitted, null or a
string. It rejects unsupported fields and types, including object/array/numeric
customInstructions, insertion outputs, numeric or string seekPermission, and
other remittance metadata. Rejection can also mean that an upstream-valid request is outside this
subset. Input is a decoded JSON value and Rust strings cannot contain lone
surrogates; duplicate JSON keys and original wire parsing are outside its scope.

The caller must supply the authenticated and validated source snapshot, a
canonical transaction ID derived from that same transaction and **original**,
not normalized, BEEF bytes. The snapshot must already be size bounded. The
helper does not validate ownership, transaction/payment validity, fee policy,
source normalization, or sender identity, and does not invoke a wallet or
connect to a route. Its result is not proof of payment.

### Offline legacy delivery remittance metadata

`delivery_remittance` checks the first delivery output's wallet-payment
protocol, a nonnegative safe integer index represented as a JSON integer,
canonical bounded Base64 derivation tokens, and canonical sender equality against an identity already authenticated
by the caller. It does not authenticate that identity, parse or validate a
transaction, check amount or script, verify chain proofs, call a wallet, claim a
replay or deliver a message. Floating-point index representations return unsupported (`None`) because Rust
default serde_json and JavaScript parsers can round the same decimal differently,
and an externally supplied Value may already have lost precision. The route
does not use this helper.

### Offline legacy delivery amount subset

`legacy_delivery_amount` observes whether a specified wallet-payment output in
an Atomic BEEF subject meets a positive safe-integer fee. It parses the original
packet, checks that the supported subject graph retains every original
transaction entry, and reads the original subject output. The internal
normalization is only used to establish the supported graph subset; its bytes
are not passed to a wallet. `None` includes invalid as well as valid but
unsupported inputs, and must not be treated as the upstream server's false
result. Floating-point output-index representations are unsupported. Unrelated
transactions are not silently trimmed into accepted packets.

A `Some(true)` result does not authenticate a sender, check remittance metadata,
execute scripts, verify a chain, internalize a payment, claim replay, or
authorize delivery. The caller must bound input size. The route does not invoke
this helper, and the SDK accepts additional BEEF/BUMP forms.

### Offline BRC-29 recipient script derivation

`brc29_recipient_script` derives the fixed SDK anyone-wallet BRC-29 child
public key and expected P2PKH locking script from a canonical recipient key and
canonical bounded derivation tokens. The anyone wallet's scalar 1 is public and
must never protect assets. The helper does not compare an actual transaction
output, verify its amount, validate a chain or transaction, check that the remittance sender is the anyone identity, call a wallet, claim replay or authorize payment or message delivery.
The caller must perform the remaining checks on an authenticated, validated,
size-bounded request. The route does not invoke this helper.

### Offline recipient-output checks

`recipient_output_check` compares supplied transaction output frames to an
already allocated recipient/fee mapping. It checks the anyone sender, canonical
derivation tokens, BRC-29 P2PKH script, output index uniqueness and safe amount
sum. The caller must authenticate the request, obtain authoritative fees,
perform allocation, supply every positive-fee recipient, and use frames from the
same original transaction subject. An empty group list does not establish that
no recipient payment was required.
When server delivery fees are positive, the caller must pass the validated
server output index; omitting it could count one output for both fee categories.
Floating-point index representations return an unsupported error with no source
error code; they are not classified as invalid upstream. This module does not
parse or validate BEEF, verify a transaction or chain, call a wallet, claim replay, or authorize payment. A successful check is not proof of
payment; the route does not invoke it.

### Offline recipient-output allocation subset

`recipient_allocation` maps already validated positive-fee recipients to output
positions using the fixed source's positional, tagged and mixed allocation rules.
It retains the source's nullish instruction precedence and reservation of tagged
output indexes, including tags for unknown recipients. The supported subset
requires each output index to have a nonnegative safe JSON integer
representation and recipients to be unique. Floating-point representations are
unsupported because default serde_json and JavaScript can round the same decimal
differently, and an external Value may already be rounded. Instruction strings that Rust cannot parse as JSON are returned as
unsupported, even though the source ignores some malformed strings. Other
unsupported inputs must not be interpreted as source rejection.

The caller must snapshot and bound the input, supply the authenticated request's
complete recipients and authoritative fees in source order, exclude the server
output when appropriate, and validate the allocated outputs and transaction.
Allocation is not payment verification and is not connected to the route.

### JSON number parsing precision

The project enables serde_json's `float_roundtrip` feature. Two reproduced raw
JSON cases that were incorrectly rounded to integer 1 now remain non-integers,
and 18 finite JavaScript JSON.parse binary64 observations match. This is not an
exhaustive proof of JavaScript JSON equivalence: unsupported non-finite overflow,
Unicode and serialization differences remain. An embedding that supplies a
Value already parsed elsewhere is responsible for its parsing fidelity. Payment
output indexes still conservatively reject floating-point representations.

### Bounded streaming HTTP adapter

`http_stream::handle_http_stream` limits the incoming body to the existing
4 MiB maximum before passing buffered bytes and the original request parts to
`HttpAuthAdapter`. Exceeding the limit returns 413; another body-stream failure
returns 400. Trailers are discarded as they arrive and are not used as authentication or application
fields. The host must manage its listener, request headers, connection and body
timeouts, concurrency, TLS, shutdown and trustworthy wallet/session-store
lifetimes. This adapter does not supply those controls or make the application
production-ready. It opens no socket itself.

### Shared payment schema initialization

MessageBox now initializes the existing Rust-owned replay and payment-intent
schemas using its message database pool. This adds empty tables/index to the
chosen database even when payment is disabled, including the in-memory test
configuration. It does not migrate or fully validate a preexisting incompatible
same-name table, and is not the upstream SQL migration schema. A paid route,
wallet coordination and intent/replay use from the MessageBox transaction remain
unimplemented. The host must choose the correct persistent application database.

### Local authentication wallet adapter

`local_auth_wallet::LocalAuthWallet` implements the existing no-certificate
BRC authentication wallet traits using a secp256k1 secret supplied by the host.
It supports self-only server HMAC and BRC-42 authentication signatures; it does
not create, persist, rotate or log a key and is not a payment wallet. The host
must supply a stable private identity key from an appropriate secure source.
Public fixture keys must never be used for an actual identity. This adapter does
not provide TLS, certificate-bearing auth, complete wallet behavior, or a
listener.

### Restricted loopback runtime

The `message-box-server` binary accepts an explicit configuration file for a
loopback bind, private data directory, private identity-key file and free-box
allowlist. Unknown boxes fail closed for sending/quote; recipient permissions
still apply. This policy is not the TS fee database and does not implement the
full TS environment/profile configuration. The binary is Unix-only and checks
POSIX mode bits for private directory/key/database files, creating new directories
and databases at 0700/0600; it does not validate ACLs, ownership or protect
against untrusted parent paths. No existing permissions are changed.

It uses the existing bounded stream adapter, local authentication wallet and
SQLite stores. Header reads are limited to 15 seconds and body reads to 60
seconds; the latter timeout ends before application dispatch. It caps concurrent
connections at 1,000, periodically purges expired data, and on Ctrl-C asks HTTP
connections to drain for up to five seconds before aborting the remainder.
These measures do not make it a production-hardened service, provide TLS, or
eliminate uncertain outcomes when shutdown interrupts an in-flight request.
The runtime exposes public GET/HEAD `/health`, `/healthz` and `/ready`. It
implements optional bounded Socket.IO polling, WebSocket upgrade and direct
WebSocket authentication, room control, and free-send push for WS and HTTP.
Socket.IO requests use the configured CORS Origin decision. Historical development acceptance covered the fixed default client and browser
Origin scenarios; it is not new-tree CI or universal client compatibility. This
release has not verified real FCM delivery or implemented upstream MySQL migration,
certificate authentication, non-UTF-8/compressed HTTP bodies
or paid delivery.

### Public health routes

The loopback runtime serves public GET/HEAD `/health`, `/healthz` and `/ready`
with `Cache-Control: no-store`. Health uses the `BSV_NETWORK` environment value
or the fixed server's `mainnet` default as a label only; it does not connect to a
chain. It reports `websockets:true` only when the restricted WS boundary is enabled;
this does not imply complete live delivery. Ready probes only `SELECT 1` on the message SQLite pool, matching the
scope of the pinned source's database probe; it does not check the auth store,
wallet, chain or notification systems. The response generator's failure shape is
tested with a synthetic failure; an actual SQLite fault has not been injected.

### Offline AuthSocket event payload subset

`authsocket_payload` encodes and parses a restricted JSON-tree subset of the
fixed server's AuthSocket event envelope. It distinguishes absent data from
explicit null, preserves supported object order, enforces event-name, depth,
node and byte limits, and rejects unsafe property names. Floats, integers
outside JavaScript's safe range, numeric-index object keys and values Rust JSON
cannot represent return unsupported; these may be valid in upstream. A parse
error can likewise mean unsupported rather than source-invalid.

The codec alone is not Socket.IO, BRC authentication, replay protection, room
membership or message delivery. The optional restricted runtime now uses it
after authenticating the exact received payload bytes; it does not re-encode
those bytes for signature verification. Live push is implemented for WS and
HTTP free sends, subject to the bounded best-effort queue.


### Optional SQLite server fees

The runtime's default explicit free-box policy remains fail-closed for unlisted
boxes. Explicit `pricingMode: ts-table` instead selects the SQLite fee table as
the sole server-fee source; it does not override host admission or recipient
permissions. The fixed TS migration seeds notifications=10, inbox=0 and
payment_inbox=0 once, preserving later modifications or deletions; missing or
null fees read as zero. Invalid and unavailable fees fail closed. This mode
permits delivery to an unconfigured box at zero fee and must be selected
intentionally. The table is this port's private SQLite schema, not an upstream
MySQL migration or a fee-management API. Positive-fee sends remain 501; BRC-105
and legacy payment acceptance are not implemented.
