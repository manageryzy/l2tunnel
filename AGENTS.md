# Engineering rules

This repository contains a Python simulator and a Rust protocol workspace. The
Rust workspace includes the runnable Common record runtime (UDP, raw-packet,
TCP/TLS, QUIC carriers), desktop GUI, local control API v5, Windows service/
Wintun host, and independently tested protocol modules. Read
`docs/implementation-status.md` before treating any broader planned carrier,
platform or simulator mode as implemented or natively qualified.

## Evidence and scope

- Read `docs/architecture.md`, `docs/implementation-plan.md`, and the relevant
  entries in `docs/mode-parity.md` before implementing a protocol feature.
- Preserve `simulator/` and saved experiment receipts. Do not overwrite historical
  observations or treat simulated throughput as real kernel performance.
- Mark features as planned, contract-tested, implemented, or integration-tested.
  An enum, empty adapter, or successful compile is not an implemented mode.
- Keep documentation and source comments in English. Do not publish packages or
  choose a project license without the owner's decision.

## Progress ledger

- Start implementation work from `docs/implementation-checklist.md` and its linked
  FC/MG/VX/UDP/CL task lists. Preserve stable task IDs and update status/evidence in
  the same change. Checkboxes mean their stated deliverable passed, not just that
  the design was written. All Python mode IDs require a P-* checklist entry.
- TAP retains endpoint/system TCP algorithms. Transparent TUN active credit does
  not control endpoint cwnd; actual TCP-window ownership requires the explicitly
  selected TCP-proxy profile. Keep the three window domains separate.
- Internal L2 management is authenticated session control, never a privilege
  granted by a user Ethernet EtherType/MAC or a VXLAN payload. Keep control framing
  and bounded service alive across user-data mode switches.
- CLI and GUI share one client/service API. Keep requested versus effective
  carrier, UDP cover, traffic policy and capability status observable.

## Rust boundaries

- Keep public protocol libraries independent of Tokio, OS handles, privileges,
  clocks, and TAP/TUN setup. Inject time and I/O at the runtime boundary.
- Use typed identifiers, checked lengths/arithmetic, bounded queues, and explicit
  errors. Never panic on packets or configuration supplied by a peer.
- Do not write custom cryptographic primitives. Use a maintained TLS/crypto
  implementation and domain-separated keys. Integrity and replay protection are
  required even when optional payload confidentiality is disabled.
- `unsafe` is forbidden in workspace protocol, runtime, client-core, and UI
  crates. Platform FFI/driver adapters (`l2tunnel-platform-linux`,
  `l2tunnel-platform-windows`) require narrow, documented exceptions and safety
  review; never weaken library defaults.
- All user traffic, including latency probes and TCP control frames, uses the same
  MUX admission policy and configured channel budget.
- Hot switching requires negotiated epochs, matching configuration digests,
  authenticated messages, explicit drain barriers, and idempotent retries.
  A local configuration-file change alone is never an atomic peer switch.

## Verification and formatting

- Run `python3 tools/check.py` before reporting a change complete.
- Follow `.editorconfig`, `rustfmt.toml`, workspace Rust/Clippy lints, and
  `CONTRIBUTING.md`. Use `cargo fmt`, not manual formatting conventions.
- Add focused tests for parser limits, state-machine failure paths, replay,
  deadline handling, and byte-exact Python/Rust parity when implementing them.
- Record commands actually run and distinguish local Linux checks from CI,
  Windows/Android builds, privileged labs, and real-device tests.
- `tools/netns_lab.py` is dry-run by default. Privileged tests must stay in their
  owned namespaces; never modify the host's existing routes, bridges, or qdiscs.
