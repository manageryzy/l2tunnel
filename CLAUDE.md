# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Read AGENTS.md first

@AGENTS.md

`AGENTS.md` (imported above) is the authoritative engineering rule set for this
repository, which was created with Codex. Its rules on evidence and scope, the
progress ledger, Rust boundaries and verification apply to every change here.
This file only adds commands and orientation; if the two ever disagree,
`AGENTS.md` and `CONTRIBUTING.md` win. Do not duplicate their rules here.

## Commands

Rust 1.92.0 is pinned by `rust-toolchain.toml`; Python 3.11+ is required.

```sh
# One-time environment for the full gate (simulator dev + QUIC + plot extras)
python3 -m venv .venv
.venv/bin/python -m pip install -e './simulator[dev,quic,plots]'

# Required gate before reporting a change complete
.venv/bin/python tools/check.py

# Same gate, preserving source hashes, output and scope as a receipt
python3 tools/record_check.py --output work/<fresh-name>
```

`tools/check.py` runs, in order: mode-catalog/parity validation, checklist ID
checks, vendored smoltcp source verification, golden-vector `--check` runs,
`cargo fmt --all --check`, Clippy with `-D warnings`, the workspace tests, the
codec's `--no-default-features` tests, warning-denied rustdoc, CLI
status/failure checks, the unprivileged Linux harness tests and the complete
simulator suite. On Linux it fails if the simulator's optional dependencies are
missing or if any simulator test is skipped. It never runs privileged
networking.

Individual steps while iterating:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test -p l2tunnel-fec --locked                    # one crate
cargo test -p l2tunnel-fec --locked rolling::          # filter by test path
cargo test -p l2tunnel-fec --locked --test rolling_stream   # one integration test file
cargo test -p l2tunnel-codec --no-default-features --locked  # non-LZ4 branch
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked

python3 -m unittest tools.test_native_smoke -v         # one harness test module
python -m pytest simulator/tests/test_mux_tcp.py -k <name>   # one simulator test (venv)
python3 tools/generate_packed_goldens.py --check       # Python/Rust golden parity
```

Running and lab tooling:

```sh
cargo run -p l2tunneld -- --help
cargo run -p l2tunnelctl -- status --control-socket /private/owned-directory/service.sock
python3 tools/selftest.py             # unprivileged TAP/tc self-test of the swift profile (release build)
python3 tools/netns_lab.py            # prints a plan only; changes no network state
python3 tools/native_smoke.py ...     # dry run unless --apply (needs sudo, owned namespaces)
```

`README.md` lists the `native_smoke.py --apply` invocations per carrier/profile.
Privileged runs need a new `--output` directory and a unique `--lab-id`. Do not
run them without the owner asking; a dry run is not an integration test.

Build notes: dev builds use `debug = 1` and `incremental = false`. Use the one
shared `target/` directory and a single active source tree; do not create
per-copy target directories. `work/` (ignored by Git) holds validation receipts
and frozen builds. Treat existing entries as historical evidence: add new
directories, never rewrite old ones.

## Architecture

Three bodies of code share the repository:

- `simulator/` is the Python Monte Carlo model (`l2tunnel-sim`) that the Rust
  protocol is grounded in. It is the parity oracle: `tools/generate_*_goldens.py`
  derive byte-exact vectors from `simulator/src` into
  `crates/l2tunnel-codec/tests/data/*.tsv`, and `tools/check.py` verifies they
  are current. Simulated throughput is not native performance.
- `crates/` and `apps/` are the Rust workspace (edition 2024, `publish = false`).
- `tools/` is the validation and Linux namespace lab harness, each with a
  `test_*.py` unittest module.

`third_party/smoltcp` is a vendored, patched smoltcp 0.14 wired in through
`[patch.crates-io]` and excluded from the workspace. Its file manifest and
provenance are checked by `tools/check_smoltcp_source.py`, so edits there must
update the recorded patches/manifest.

### Rust layering

The conceptual stack in `docs/architecture.md` runs device adapter → flow
control/QoS → frame validation and codec → shared MUX admission → record
packing and recovery (ARQ/FEC) → authenticated session and epoch control →
carrier (TCP/TLS, authenticated UDP, QUIC, experimental raw TCP). Crates fall
into four tiers:

1. **Pure protocol libraries** with no Tokio, OS handles or clocks: `core`,
   `wire`, `codec`, `mux`, `recovery`, `fec`, `reliable`, `flow-control`, `qos`,
   `packet`, `pipeline`, `active`, `aligned`, `datagram`, `management`,
   `udp-control`, `vxlan`, `raw-tcp`, `tcp-proxy`, `session`, `transport`,
   `device`, `swift` (all prefixed `l2tunnel-`). The `l2tunnel` crate is a facade that
   re-exports them; `crates/l2tunnel/tests/pipeline.rs` holds cross-module
   tests.
2. **I/O adapters**: `l2tunnel-auth` (rustls TLS 1.3 plus Ed25519 member
   authentication), `-udp`, `-quic`, `-https`, `-openvpn`, `-raw-io`,
   `-platform-linux` (TAP/TUN) and `-platform-vxlan`.
3. **`l2tunnel-runtime`**: Tokio runtimes that compose tiers 1 and 2, one
   module per profile (`managed`, `udp`, `quic`, `active`, `aligned`, `packed`,
   `rolling`, `proxy`, `openvpn`, `raw_packet`, `drained`, `swift`).
4. **`l2tunnel-client-core`**: the shared client lifecycle, with a matching
   module per profile, the versioned private local control API (`local`), the
   shared service (`service`) and the CLI adapter (`cli`).

The app binaries are deliberately thin. `l2tunneld`, `l2tunnel-linux` and
`l2tunnelctl` all call `l2tunnel_client_core::cli::main_entry`, so behavior
belongs in `client-core`, never in an app `main.rs`. `l2tunnel-windows` and
`l2tunnel-android` are scaffolds with no network runtime.

Three counts are independent and must stay separate in fields and metrics: a
carrier lane (an authenticated physical connection), a MUX channel (an
ordering/admission domain) and an inner flow (a classified user connection).

### Documentation as the source of status

Feature status lives in documents that `tools/check.py` validates, not in the
code's shape:

- `docs/implementation-checklist.md` is the entry point. Its unchecked `FIX-*`
  items are blocking behavior corrections that take priority over new features.
  Stable task IDs are never reused; a box is ticked only with an `Evidence:`
  link once its stated deliverable passed.
- `config/mode-catalog.toml` lists every Python mode with a `status`; each ID
  must also appear in `docs/mode-parity.md`.
- `docs/modules/<module>.md` is a per-module design document written before the
  code, holding the module's API, bounds, task IDs and acceptance matrix.
- `docs/implementation-status.md` records current evidence;
  `docs/development-workflow.md` describes the design → implement → review →
  integrate → receipt → checkpoint-commit cycle.

Update the relevant ledger entries in the same change as the code.

### Known stale statement

`README.md` still says the tree has no Git metadata. A local repository was
initialized on 2026-11-12 (`docs/checkpoints/2026-11-12.md`); there is still no
remote and no chosen license.
