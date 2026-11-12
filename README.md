# l2tunnel

A Rust protocol-library workspace for a configurable TAP/TUN tunnel, grounded in
[the Python experiments](simulator/README.md). Platform entry points will own
sockets, devices, privileges and process lifecycle; public libraries will own
session state, records, MUX, recovery and codecs.

**Current status: an authenticated Linux TAP/TUN vertical slice is runnable.**
TCP/TLS 1.3 verifies the server and an allowlisted Ed25519 member, with SNI disabled.
The same TLS connections carry packets after authentication. Half duplex uses two
paired carriers by default; full duplex uses one. Native Linux bridge/TAP and TUN
smoke tests passed, including IPv6, checksum-verified TCP payloads and a
70 ms RTT / 15% loss `tc/netem` profile. Point-to-point Linux VXLAN also passed
with checksum/segmentation offloads explicitly completed before its byte-only boundary.

Compression can switch Off/LZ4 through the private local API after both peers
drain and agree on the new epoch. Nine native TAP/TUN/VXLAN cases passed two
switches during checksum-verified TCP transfer, including impaired links.
Protected UDP data with retained TLS authentication/control is also runnable.
Both custom OpenVPN-like/QUIC-like headers and AEAD/integrity-only suites passed
36 native cases, including path-MTU fragmentation and deliberate UDP path failure.
Optional Cauchy repair plus ARQ fallback passed another 36 native cases. TUN over
TCP can explicitly select active flow credits, weighted DRR and CRC MUX; six
native None/LZ4 cases passed with fixed bootstrap targets. Optional measured
adaptation and authenticated idle retirement also passed six native None/LZ4 cases,
including twelve distinct TCP connections through two flow slots. Broad mode
integration remains tracked separately. Genuine standalone QUIC has also passed
36 native TAP/TUN/VXLAN cases with underlay TCP explicitly blocked before auth,
None/LZ4 and ARQ/Cauchy, and independently audited physical MTU 1228 captures.
Raw native TCP, complete
hot switching, all Python recovery/header modes, TCP proxy, Windows/Android native
execution and GUI remain unfinished. This is not a complete production VPN.
See [current implementation evidence](docs/implementation-status.md).

## Start here

Start with the [persistent implementation checklist](docs/implementation-checklist.md).
It tracks the original mode inventory and the added TUN flow control, QoS, internal
L2 management, VXLAN, UDP covers and GUI/CLI work with stable task IDs and evidence.

- [Architecture and protocol decisions](docs/architecture.md)
- [Implementation order, source projects and acceptance gates](docs/implementation-plan.md)
- [TUN active flow control and QoS](docs/flow-control.md)
- [Internal management, VXLAN and UDP covers](docs/overlay-and-carriers.md)
- [CLI/GUI client architecture](docs/client-design.md)
- [Complete Python-to-Rust mode parity](docs/mode-parity.md)
- [Machine-readable mode checklist](config/mode-catalog.toml)
- [Bridge and tc/netem self-test plan](docs/testing.md)
- [Coding and verification conventions](CONTRIBUTING.md)

## Self-test on Linux TAP

`tools/selftest.py` builds five private network namespaces inside an
unprivileged user namespace, shapes the path with HTB and netem, runs real
`serve` and `connect` endpoints on TAP devices and measures verified TCP flows.
It needs no sudo and changes nothing on the host.

```sh
cargo build --release -p l2tunneld
python3 tools/selftest.py                      # 16 flows, 100/10 Mbit/s, 70 ms, 15% loss
python3 tools/selftest.py --path clean --flows 4 --duration 10
python3 tools/selftest.py --require-reference  # fail unless within 2.5% of the simulator
l2tunneld status --control-socket /private/dir/swift.sock   # live counters, with --control-socket on the endpoint
```

The default `swift` profile is selected on the CLI with:

```sh
l2tunneld serve --listen IP:PORT --device tap0 --layer tap --duplex full \
  --cert server.der --key server.pkcs8 --allow-key member.pub \
  --carrier udp --record-profile swift --udp-bind IP:PORT --udp-peer IP:PORT \
  --swift-forward-kbit 99000 --swift-reverse-kbit 9900
```

`connect` takes the same swift options. Budgets are IP kilobits per second,
client-to-server then server-to-client, and both peers must state both. See
[the swift module](docs/modules/swift.md) for the design, bounds and results.

## Build and check

Rust 1.92.0 and Python 3.11+ are required. Crypto/runtime/codec dependencies are
pinned in Cargo.lock for reproducibility.

```sh
python3 tools/check.py
cargo run -p l2tunneld -- --help
cargo build -p l2tunneld -p l2tunnel-linux
python3 tools/netns_lab.py --help
python3 tools/netns_lab.py
```

The last command only prints a network plan; it changes no network state.
The topology command prepares isolated namespaces, TAPs and bridges. The separate
native harness launches real endpoints and records finite device smoke tests:

```sh
python3 tools/native_smoke.py --include-netem --compression lz4
# Explicitly create owned namespaces, run endpoints, then clean up:
sudo python3 tools/native_smoke.py --apply --include-netem --compression lz4 \
  --lab-id my-native-test --output /tmp/l2tunnel-my-native-test
# Exercise both compression changes during an active TCP transfer on all adapters:
sudo python3 tools/native_smoke.py --apply --hot-switch --include-netem \
  --layers tap tun vxlan --lab-id reload-test --output /tmp/l2tunnel-reload-test
# Exercise protected UDP data with retained authenticated TCP/TLS control:
sudo python3 tools/native_smoke.py --apply --carrier udp --udp-cover quic-like \
  --udp-protection aead --path-mtu 1200 --include-netem --layers tap tun vxlan \
  --lab-id udp-test --output /tmp/l2tunnel-udp-test
# Select real systematic repair plus selective-repeat fallback:
sudo python3 tools/native_smoke.py --apply --carrier udp --fec cauchy \
  --path-mtu 1200 --include-netem --layers tap tun vxlan \
  --lab-id fec-test --output /tmp/l2tunnel-fec-test
# Select transparent active credit/QoS on TUN over retained TLS:
sudo python3 tools/native_smoke.py --apply --traffic active --layers tun \
  --include-netem --lab-id active-test --output /tmp/l2tunnel-active-test
# Exercise actual measured feedback and authenticated two-slot flow reuse:
sudo python3 tools/native_smoke.py --apply --traffic active --layers tun \
  --adaptive --flow-churn --include-netem \
  --lab-id measured-test --output /tmp/l2tunnel-measured-test
# Genuine standalone QUIC, with outer TCP blocked before handshake by the lab:
sudo python3 tools/native_smoke.py --apply --carrier quic --path-mtu 1228 \
  --include-netem --layers tap tun vxlan \
  --lab-id quic-test --output /tmp/l2tunnel-quic-test
```

The output directory must be new. This verifies connectivity and authentication;
it is not a throughput, fairness or production-readiness certificate.

Start an endpoint with `--control-socket /private/owned-directory/service.sock`.
The parent directory must already be owned by the effective user and have no
group/other permission bits. The shared CLI then queries or requests a change:

```sh
cargo run -p l2tunnelctl -- status --control-socket /private/owned-directory/service.sock
cargo run -p l2tunnelctl -- set-compression --control-socket /private/owned-directory/service.sock --compression lz4
```

Only the authenticated initiator coordinates a change. A timeout has unknown
outcome; query both endpoints before retrying. The API never treats editing a
local configuration file as proof of a completed peer switch.

UDP requires explicit `--udp-bind`, `--udp-peer` and `--udp-cover` options in
addition to the TLS credentials and listener/remote. Half duplex also requires
`--udp-reverse-bind` and `--udp-reverse-peer`. `--udp-protection integrity`
disables data confidentiality while retaining authentication/replay protection.
These custom headers do not interoperate with OpenVPN or QUIC. UDP compression
is fixed per session; its CLI currently rejects `--control-socket`.
See [UDP client configuration and evidence](docs/modules/udp-client.md).

`--traffic active` requires TUN over TCP.
`--mux-channels`, `--max-flows` and `--qos-dscp D:W[,D:W...]` configure its finite
policy. It preserves endpoint TCP windows and starts with a static per-flow
bootstrap grant; `--adaptive on` enables measured credit growth.
See [active client scope](docs/modules/active-client.md).

Both active endpoints can opt into a finite authenticated policy catalog using
`--active-policies config/active-policies.example.json`. Its initial policy must
match the session's channel count and all 64 DSCP weights. The example starts at
four equally weighted channels and also allows two channels with DSCP 46 weight
four. With a private `--control-socket`, the initiator can request that entry:

```sh
cargo run -p l2tunnelctl -- set-active-policy --control-socket /private/owned-directory/service.sock --mux-channels 2 --qos-dscp 46:4
```

The runtime drains old flows and completes the authenticated epoch transaction
before returning success. Compression and other immutable session settings remain
fixed in this profile. Native switch qualification is tracked in the
[managed active client checklist](docs/modules/active-managed-client.md).

The source tree currently has no Git metadata or configured remote. CI definitions
are ready to run after it is placed in a repository. Crates are `publish = false`
until the owner chooses licensing and release policy. No package was published.
