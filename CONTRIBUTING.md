# Contributing

Read [AGENTS.md](AGENTS.md), the architecture and the
[implementation checklist](docs/implementation-checklist.md) first. Update stable
task IDs and evidence in the same change; keep all P-* mode gates synchronized
with the mode catalog.
Documentation and comments use English. Keep simulator evidence unchanged unless
an experiment change is explicitly part of the task; save new runs separately.

Commit each coherent module checkpoint locally with its scoped validation and
remaining limitations. The integrator stages verified source bytes and preserves
concurrent working-tree edits; generated evidence/build outputs and private
credentials stay excluded. Do not defer all commits until the whole product is
finished, or describe a checkpoint commit as a fully qualified release.

## Rust conventions

The pinned toolchain includes `rust-analyzer` and `rust-src` so VS Code can use
the matching language server instead of an incompatible extension-bundled server.
After opening the repository, run `rustup show` to install declared components
and restart the rust-analyzer server if the editor was already running. Check
`rustup which rust-analyzer` from this directory when diagnosing server selection.

- Rust 2024, pinned toolchain in `rust-toolchain.toml`; public errors are explicit.
- `cargo fmt` is authoritative. Clippy warnings are errors in checks/CI. Public
  items require docs. Runtime code may not use unwrap, expect, panic or unsafe.
- No implicit network/device side effects in library constructors; inject time,
  I/O and bounded buffers. Use newtypes for unrelated sequence spaces.
- Validate external lengths before indexing/allocation. Bound retained bytes,
  packet counts, decoding work, timers and contexts. Use checked arithmetic.
- Never log private keys, exporter secrets or raw authentication tokens. Use
  maintained crypto implementations; no homegrown primitives or accept-all TLS.
- Keep wire parsing, transport delivery and native device ownership separate.
  A new native FFI crate needs an isolated documented unsafe policy/review.
- Avoid ABI/semver promises while the wire and embedding contracts remain draft.
  An unused enum or trait cannot satisfy a mode-completion requirement.

## Required checks

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e './simulator[dev,quic,plots]'
.venv/bin/python tools/check.py
# With that environment already activated:
python3 tools/check.py
```

This runs formatting, Clippy, Rust tests including the raw-native example and
the codec's no-default-features branch, rustdoc, catalog validation, CLI
status/failure checks, Linux-only unprivileged lab tests and, on Linux, the complete
simulator test suite including its native KCP C adapter. The full Linux check requires the simulator's dev and QUIC
dependencies; it fails explicitly if these are missing. Ordinary simulator
users may still run non-QUIC tests without the optional QUIC dependency.
It does not run
privileged networking, install drivers, rerun the simulator sweeps or certify
cross-platform execution. `.github/workflows/checks.yml` additionally defines
Windows host checks and an Android compile-only job.

Use focused behavioral tests for parsing, recovery, cryptographic failures and
state transitions. Golden codec vectors must include arbitrary nonzero payloads,
unsupported frames, length boundaries and loss/reorder/context-reset cases.
Fuzz unauthenticated entry points and replay/epoch handling before release.

New Python tooling uses Python 3.11+, standard-library-only where practical,
4-space indentation and explicit argument vectors rather than shell execution.
`tools/check.py` checks compilation and the focused tooling tests; it does not
apply a new formatter/linter policy to the existing simulator history.

Report actual commands and scope. A dry run is not an integration test, a Linux
compile is not a Windows/Android device test, and a finite simulation result is
not a deployment performance guarantee.
