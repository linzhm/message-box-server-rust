# Provenance and notices

© BSV Association

This experimental Rust implementation adapts the application behavior of
`infra/message-box-server` in [bsv-blockchain/ts-stack at
52d36a5ab1ae7cb9e3243ff4147558bcccde3c07](https://github.com/bsv-blockchain/ts-stack/tree/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server).
The inspected package version is 1.1.59. The older standalone repository is
not the compatibility authority for this milestone.

The current upstream first-party code is under **Open BSV License Version 6**.
Its text is retained in [LICENSE.txt](LICENSE.txt), including the BSV-only use
condition. This repository is not represented as MIT/Apache/ISC-only software.
Rust is a language change, not a removal of upstream license conditions. Use
on other networks must not be assumed permitted by this license.

The upstream notices separately identify historical `messagebox-server`
material under ISC, from [p2ppsr/messagebox-server at
2ca683e28e1eb0fddfbecc0e7f5b9943e6625075](https://github.com/p2ppsr/messagebox-server/tree/2ca683e28e1eb0fddfbecc0e7f5b9943e6625075),
incorporated in `infra/message-box-server/src`. We retain the scoped notice in
[LICENSES/messagebox-server-ISC.txt](LICENSES/messagebox-server-ISC.txt).
Copyright (c) 2025-2026 messagebox-server contributors. That historical grant
continues for its identified material; it does not relicense later upstream
contributions. The current upstream [THIRD_PARTY_NOTICES.md](https://github.com/bsv-blockchain/ts-stack/blob/52d36a5ab1ae7cb9e3243ff4147558bcccde3c07/infra/message-box-server/THIRD_PARTY_NOTICES.md)
is the source of this distinction.

Cargo dependencies retain their own respective licenses. Cargo.lock pins the
resolved dependency graph. The source release includes a reproducible
[complete locked dependency inventory](docs/DEPENDENCY_LICENSES.md). It lists
registry provenance and declared license expressions for every resolved external
package, including development and target-specific dependencies. Dependencies
are fetched by Cargo, not vendored here. This source-only inventory is not a
binary/container redistribution notice bundle.

The combined HTTP compatibility update enables the existing serde_json 1.0.150
`raw_value` feature (MIT OR Apache-2.0) to distinguish syntax errors from values
outside Rust's representation. It adds no package/version to Cargo.lock. The
fixture generator consumes, but does not redistribute, the fixed npm SDK and
middleware packages; its compared source files retain the upstream license scope
described above.

The ECMAScript number formatter uses `ryu-js` 1.0.3 from crates.io, declared
under Apache-2.0 OR BSL-1.0. The package's license texts are retained in
[LICENSES/ryu-js-1.0.3-APACHE.txt](LICENSES/ryu-js-1.0.3-APACHE.txt) and
[LICENSES/ryu-js-1.0.3-BOOST.txt](LICENSES/ryu-js-1.0.3-BOOST.txt). This
dependency notice complements the locked inventory.

The Firebase host adds `google-cloud-auth` 1.18.0 (Apache-2.0), `ring` 0.17.14
(Apache-2.0 AND ISC), and an explicit `rustls` 0.23.45 (Apache-2.0 OR ISC OR
MIT) dependency. Their retained license notices and the scope and limitations of
the added transitive dependency review are listed in
[docs/FIREBASE_HOST.md](docs/FIREBASE_HOST.md). The locked inventory also covers the transitive packages; a binary distribution
would still require a complete notice bundle and native/data component review.
