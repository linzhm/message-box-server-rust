# Testing the initial source release

Use Rust 1.94.1 on Linux with a C compiler/linker, pkg-config and SQLite development
headers. Fetch Cargo.lock dependencies once; the Rust tests then require no
external network/service, wallet or real assets. Some tests bind loopback sockets.
Do not configure real Firebase credentials when running fixtures.

```sh
cargo +1.94.1 fmt --check
cargo +1.94.1 test --locked --all-targets
cargo +1.94.1 clippy --locked --all-targets -- -D warnings
cargo +1.94.1 build --locked --release --bin message-box-server
cargo +1.94.1 doc --locked --no-deps
```

Add `--offline` to Cargo test/clippy/build/doc when dependencies are cached.
The checked-in routine GitHub Actions workflow uses these checks; its presence
is not a claim that CI has run on a future remote repository.

## What is checked

The full Rust suite covers storage fanout/list/acknowledge, quotas and retention,
permissions, auth frames/nonce/replay, HTTP parsing and signatures, runtime health
and readiness, CORS, bounded Socket.IO codecs/runtime behavior, payment refusal
and offline payment helpers, and synthetic Firebase/ADC/TLS behavior. Tests and
examples use fixed public test identities or ephemeral keys. In particular,
`tests/fixtures/fcm-synthetic-rsa.pk8` is a deliberately public synthetic RSA fixture.
Never use any fixture as a real service identity or credential.

JSON/frame fixtures compare selected fixed SDK/middleware encodings. The
serializer uses the locked serde_json and ryu-js packages; Rust-only expected
results are not golden responses from a running TS server. Fixture regeneration
scripts under `scripts/` and `tests/fixtures/sdk4/` are optional development tools;
read their required SDK/source paths before running them. They are not run by the
Rust-only CI and do not vendor the external JavaScript packages.

Earlier development used a fixed SDK/MessageBoxClient, composed TS/MySQL and
Socket.IO/restart scenarios. The private platform history and complete live
harness are not part of this initial release. Reproducing a complete live
comparison requires separately preparing the pinned upstream code, dependencies,
databases and a reviewed harness. Do not describe these historical observations
as new CI on this root commit. See [release scope](RELEASE_SCOPE.md) for two known
TS reference deviations and the remaining compatibility boundaries.

No real Google/device delivery, paid delivery, production deployment, crash/HA
recovery, or sustained-load SLA is certified by the local suite. No private raw
logs or benchmark archives are included.

## Manual local smoke

Use `config.example.json` with private absolute paths and a newly generated
identity (never a checked-in fixture). Start the release binary, then check:

```sh
curl --fail http://127.0.0.1:8080/health
curl --fail http://127.0.0.1:8080/ready
```

Health is static listener liveness; readiness probes only the message SQLite
connection. An unsigned application request must not be accepted as an
authenticated sender. Ctrl-C requests graceful shutdown; interruption can leave
an in-flight request outcome uncertain. A health/ready smoke is not a signed
send/list/acknowledge integration test.
