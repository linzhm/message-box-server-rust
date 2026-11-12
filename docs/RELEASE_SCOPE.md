# Release scope

This is an independent, self-hosted Rust MessageBox storage and forwarding
implementation intended as a component for PayMessage. It is not an official
BSV Blockchain project or the complete PayMessage protocol. Socket.IO supplies
bounded live transport, not settlement, application authorization or a Kernel driver.

## Implemented boundary

Authenticated HTTP supports message send/list/acknowledge, recipient permissions
and device registration/listing. SQLite persists the application's messages and
authentication/replay state. Optional Socket.IO supports polling, upgrade and
direct WebSocket, authenticated room control, free sends and process-local push.

The compatibility reference is TS stack commit
`52d36a5ab1ae7cb9e3243ff4147558bcccde3c07` (server 1.1.59). Earlier development
acceptance exercised a fixed SDK, HTTP corpus, Socket.IO, restart and composed
TS/MySQL routes. Its private platform history/raw reports are not distributed
with this initial source release. These historical observations are not new-tree
CI or an independently reproducible full-production compatibility claim. The
public reproducible tests and their limits are described in [TESTING.md](TESTING.md).
The Cargo description deliberately retains experimental/non-production status.

Two known reference differences remain explicit:

| Scenario | This implementation | Fixed TS reference observation |
| --- | --- | --- |
| Registered device `active` | Boolean, following the upstream interface/OpenAPI/client | Numeric MySQL value; the unchanged client rejects it |
| Exact unsigned invalid device request | 401 error with `description` | 401 error with `message` |

These do not authorize generic coercion or error-key renaming. Historical registered
scenarios checked exactly true/1; they did not establish inactive-device behavior.
The OpenAPI/client contracts must be checked separately from raw server equality.

## Operational limits

- The Unix binary binds to an explicit loopback IP and has no TLS listener.
  Public deployment needs a separately reviewed edge and operational configuration.
- Use one process and local SQLite files on one host. Message and authentication
  pools each have one connection. This is not an upstream MySQL migration.
  Clean restart observations do not establish crash durability, shared filesystem
  correctness, replication, multi-process throughput or disaster recovery.
- Notifications are best-effort and process-local. Clients recover missed events
  with authenticated `listMessages` and explicitly acknowledge messages. Sharing a
  database does not distribute notifications. HA, cross-process notification
  delivery, coordinated maintenance and failover remain future work.
- Retention, quotas and bounded maintenance apply to this schema. Backup/restore
  automation is not included; operators need a SQLite-consistent private backup
  procedure for database and identity material.
- The FCM provider and credential assembly are implemented; real provider acceptance,
  device receipt and notification display remain unverified. Tests use synthetic
  credentials/loopback services. Firebase is disabled unless explicitly configured.
- Payment compatibility is deferred. Parsing/verification helpers do not accept
  delivery payments; positive fees and explicit payments are refused by supported
  business routes. No paid delivery, wallet settlement or chain acceptance is claimed.
- Hyper's 1000-total-header parser cap has separate byte/time limits. Historical
  fixed-SDK attempts at 999+ headers failed before sending because of a client
  encoding limit. They are not evidence of successful signed requests at that size.
- No sustained 100-concurrent SLA or complete five-round performance result is
  claimed. Private diagnostic harnesses/results are excluded from this source release.

## Related official-organization projects

Pinned public source was inspected for positioning, not imported into this tree:

| Project and inspected commit | Scope and license observed |
| --- | --- |
| [rs-sdk `99d2313f`](https://github.com/bsv-blockchain/rs-sdk/tree/99d2313f2ede48a465aa8be1907d26d098aac8fd) | Rust SDK (`bsv-sdk` 0.8.1); LICENSE contains Open BSV License v5 and a scoped historical MIT notice. It is not a dependency in this Cargo.toml/Cargo.lock. |
| [go-stack `e36d173f`](https://github.com/bsv-blockchain/go-stack/tree/e36d173f997ba6dd5e39fe9da2db7bd0f83811db) | Monorepo README includes `infra/go-message-box-server`; no Go code is imported here and no root-wide license assumption is made. |
| [bsv-messagebox-cloudflare `bbbdcf86`](https://github.com/bsv-blockchain/bsv-messagebox-cloudflare/tree/bbbdcf86a634c29bc105eadd765c8882164be63c) | Official-organization fork with Rust/Wasm Workers entrypoint and D1/KV storage; README specifies HTTP REST without WebSocket. Root LICENSE is MIT, copyright Calhooon Contributors. It depends on its own BSV middleware/`bsv-rs`; its tests/compatibility claims were not independently rerun for this release. |

These projects are possible future comparison/reuse inputs, subject to their
actual component licenses and compatibility review. This repository remains the
independent native Rust/SQLite implementation described above. The adaptation
from pinned TS source retains Open BSV License v6 and the scoped historical ISC
notice in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md); another project's
MIT notice does not relicense this implementation.
