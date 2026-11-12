#!/usr/bin/env python3
"""Generate source-release dependency provenance from locked Cargo metadata.

Usage: cargo metadata --locked --format-version 1 | python3 scripts/dependency-license-inventory.py
No registry sources or credentials are copied into the output.
"""
import hashlib
import json
from pathlib import Path
import sys

metadata = json.load(sys.stdin)
packages = sorted((p for p in metadata['packages'] if p['source']), key=lambda p: (p['name'], p['version']))
if any(not p['license'] for p in packages):
    raise SystemExit('Dependency without declared license requires manual review')
lines = [
    '# Locked dependency license inventory', '',
    'Generated from `cargo metadata --locked --format-version 1`; includes resolved',
    'target-specific and development dependencies, not just the Linux runtime.',
    'These are package-declared license expressions, not a claim that metadata',
    'proves every bundled file\'s provenance. Registry sources are not vendored in',
    'this source release. Binary/container redistribution needs its own complete',
    'component notices (including bundled native code and data), chosen license',
    'alternatives and corresponding obligations. Existing scoped notices remain.', '',
    f'Cargo.lock SHA-256: `{hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest()}`.',
    f'External packages: {len(packages)}. All sources below are the crates.io registry;',
    'Cargo.lock records each downloaded archive checksum. No Git SDK dependency is present.', '',
    '| Package | Version | Declared license |', '| --- | --- | --- |',
]
for p in packages:
    if p['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
        raise SystemExit('Non-registry source requires provenance review')
    lines.append(f'| [{p["name"]}](https://crates.io/crates/{p["name"]}/{p["version"]}) | {p["version"]} | {p["license"]} |')
Path('docs/DEPENDENCY_LICENSES.md').write_text('\n'.join(lines) + '\n')
