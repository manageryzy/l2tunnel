# l2tunnel

A Rust protocol-library workspace for a configurable TAP/TUN tunnel, grounded in
[the Python experiments](simulator/README.md). Platform entry points own
sockets, devices, privileges and process lifecycle; public libraries own
session state, records, MUX, recovery and codecs.

**Current status:** the Common record runtime (`--record-profile common`) is
runnable on Linux over authenticated UDP (`quic-like`, `media-like`, `tls-like`,
`openvpn-like`), raw-packet TCP (`raw-packet`, with optional `--udp-cover tls-like`),
TCP/TLS (`tcp`), and genuine QUIC (`quic`), carrying TAP, TUN, and VXLAN traffic
with Swift, Aligned, Packed, Compact, Rolling, Striped, Research, and TCP-proxy
record profiles. A shared local control API v5 backs `l2tunnelctl`, the
`l2tunneld` / `l2tunnel-linux` daemon, and the `egui` desktop GUI
(`l2tunnel-linux-gui` / `l2tunnel-windows-gui`), including live protocol and
FEC/MTU tuning, live speed-budget tuning (`1 Mbit/s..=10 Gbit/s`), local and
remote CSR meters, and in-process tunnel speed/ping tests. Windows service/Wintun
and Android FD-broker binaries cross-compile and pass unit/Wine checks, while
native Windows/Android device qualification, GUI SOCKS5, live carrier switching,
and full 49-mode parity acceptance remain open. This is not a complete
production VPN. See [current implementation status](docs/implementation-status.md).

## Start here

Start with the [persistent implementation checklist](docs/implementation-checklist.md).
It tracks the 49 mode-catalog entries and the TUN flow control, QoS, internal
L2 management, VXLAN, UDP covers and GUI/CLI work with stable task IDs and evidence.

- [Architecture and protocol decisions](docs/architecture.md)
- [Implementation order, source projects and acceptance gates](docs/implementation-plan.md)
- [Current implementation status](docs/implementation-status.md)
- [TUN active flow control and QoS](docs/flow-control.md)
- [Internal management, VXLAN and UDP covers](docs/overlay-and-carriers.md)
- [CLI/GUI client architecture](docs/client-design.md)
- [Complete Python-to-Rust mode parity](docs/mode-parity.md)
- [Machine-readable mode checklist](config/mode-catalog.toml)
- [Bridge and tc/netem validation plan](docs/testing.md)
- [Coding and verification conventions](CONTRIBUTING.md)

## Build and check

Rust 1.92.0 (pinned in `rust-toolchain.toml`) and Python 3.11+ are required.
Dependencies are pinned in `Cargo.lock` for reproducibility.

```sh
# Full verification gate (requires simulator venv with dev, quic, plots extras)
python3 tools/check.py

# Release binaries (daemon, CLI, Linux client + desktop GUI)
cargo build --release --locked -p l2tunneld -p l2tunnelctl -p l2tunnel-linux --features l2tunnel-linux/gui

# CLI help
cargo run -p l2tunneld -- --help
cargo run -p l2tunnelctl -- --help
```

## Local GUI / real-pair demo

`tools/local_real_pair.py` prepares and runs a real loopback `l2tunneld`
server/client pair (authenticated Common UDP session) for desktop GUI and CLI
testing:

```sh
python3 tools/local_real_pair.py prepare --row demo-multi-udp
python3 tools/local_real_pair.py run --side server --replace
python3 tools/local_real_pair.py run --side client --replace
./target/release/l2tunnel-linux-gui
```

## Local control CLI (`l2tunnelctl`, API v5)

Start a daemon or endpoint with `--control-socket /private/owned-directory/service.sock`
(parent directory owned by the effective user, mode `0700`). The grouped CLI
uses the same local API v5 as the desktop GUI:

```sh
l2tunnelctl --socket /private/owned-directory/service.sock status
l2tunnelctl --socket /private/owned-directory/service.sock tune show
l2tunnelctl --socket /private/owned-directory/service.sock tune set --repair 1/4
l2tunnelctl --socket /private/owned-directory/service.sock meters read --side remote
l2tunnelctl --socket /private/owned-directory/service.sock test speed --direction upload --streams 4 --seconds 10
l2tunnelctl --socket /private/owned-directory/service.sock test ping --probes 10
```

Only the authenticated initiator coordinates peer configuration switches. A
local configuration-file edit alone is never an atomic peer switch.

## Isolated Linux namespace harnesses

`tools/netns_lab.py` prints a namespace/bridge/`tc` plan by default and changes
no host network state. Native benchmark plans and isolated campaign runners live
under `tools/` (see [tools/common_native_matrix.md](tools/common_native_matrix.md)
and [docs/testing.md](docs/testing.md)):

```sh
# Export Common benchmark plans (default 100/10, or custom high-BDP budgets)
cargo run --locked -p l2tunnel-client-core --example common_benchmark_plan -- \
  --output-dir /tmp/l2tunnel-plans --budget-mbps 1000/100

# Dry-run topology plan (changes no host state)
python3 tools/netns_lab.py

# Unprivileged Linux TAP self-test (uses user namespaces)
python3 tools/selftest.py
```

Privileged `--apply` namespace runs require root, a fresh `--output` directory,
and a unique `--lab-id`; all link, route, bridge, and qdisc changes remain
inside owned namespaces.

Crates are `publish = false` until the owner chooses licensing and release
policy. No package has been published.
