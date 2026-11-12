# Implementation plan and source projects

Status: parallel implementation and native Linux qualification in progress.
This plan turns the simulator into a public embeddable Rust library and separate
applications. The [current evidence](implementation-status.md) distinguishes
runnable slices from pending work; no milestone heading implies all its gates passed.
All requirements remain tracked until their acceptance gates are met.

Use the [implementation checklist](implementation-checklist.md) as the durable
progress ledger. Detailed FC, MG, VX, UDP and CL checklists cover the new TUN active
flow control, QoS, internal L2 management, VXLAN, carrier covers and GUI/CLI work.
Update checkbox evidence and capability status with every implementation change.

## Source projects

| Project | Responsibility | Current state |
| --- | --- | --- |
| `crates/l2tunnel` | Public embedding facade | Exports tested pure protocol engines; OS/runtime adapters remain separate |
| `crates/l2tunnel-core` | Typed IDs, capabilities, policy and config validation | Initial mode types and structural validation |
| `crates/l2tunnel-wire`, `crates/l2tunnel-session` | Versioned records, parsers, session contracts | Bounded wire/framing and local reload guard; distributed transactions live in management |
| `crates/l2tunnel-auth` | Verified TLS and member authentication | Retained TCP/TLS and generic I/O TLS, exporter/member/config binding and negative tests |
| `crates/l2tunnel-transport` | Carrier selection semantics | Capability-aware explicit fallback contract; actual adapters below |
| `crates/l2tunnel-mux`, `crates/l2tunnel-packet`, `crates/l2tunnel-pipeline` | Classification, connection affinity, common admission | Real parsed frames, bounded affinity/channel scheduling and DRR composition |
| `crates/l2tunnel-codec` | L2/L3 fragmentation and compression | None/LZ4 frame bytes, bounded reassembly, Python timestamp/delta and aligned body primitives; complete mode integration pending |
| `crates/l2tunnel-recovery`, `crates/l2tunnel-fec`, `crates/l2tunnel-reliable` | Feedback, ARQ, actual FEC and shared budgets | Selective repeat plus actual Cauchy payload repair and finite compositions; all catalog families pending |
| `crates/l2tunnel-flow-control`, `crates/l2tunnel-qos`, `crates/l2tunnel-active` | Tunnel credit, QoS, demand and measured adaptation | Bounded credits/DRR, authenticated retirement and optional measured target control; no endpoint TCP-window ownership |
| `crates/l2tunnel-management` | Fixed authenticated control framing and mode transactions | Prepare/drain/commit/retire state machine; runtime compression switching qualified |
| `crates/l2tunnel-datagram`, `crates/l2tunnel-udp` | Protected custom UDP envelopes and lanes | AEAD/integrity profiles with retained TCP/TLS bootstrap/control; native tests passed |
| `crates/l2tunnel-quic` | Genuine standalone QUIC carrier | UDP-only maintained QUIC/member auth and 36 native TAP/TUN/VXLAN cases with physical MTU captures |
| `crates/l2tunnel-udp-control`, `crates/l2tunnel-openvpn` | Standalone OpenVPN-like UDP control and retained TLS/member authentication | Real UDP-only bootstrap, full/paired-half data and bounded clean drain; four clean TAP/TUN native drain cases passed, outage recovery and broader qualification remain open |
| `crates/l2tunnel-raw-tcp`, `crates/l2tunnel-raw-io` | Single-owner userspace TCP and native adapter | Retained TLS-to-protected-packet transition, runtime and explicit shared client are implemented; original native packet captures and startup sampling are under separate qualification; congestion control, clean drain and broader path behavior remain open |
| `crates/l2tunnel-tcp-proxy` | Explicit TCP ownership and reliable relay | Maintained-TCP legs and ACK-based fixed credit; clean Linux TUN full/half native split, exact-byte/FIN and lane-close tests passed; adaptive proxy windows pending |
| `crates/l2tunnel-device` | Packet-device abstraction and adapter capability rules | Native packet-layer validation and trait |
| `crates/l2tunnel-runtime` | Tokio/clock/I/O orchestration | Retained TCP/TLS, managed compression, active TUN, protected UDP and standalone QUIC with optional real FEC |
| `crates/l2tunnel-platform-linux`, `crates/l2tunnel-platform-vxlan`, `crates/l2tunnel-vxlan` | Native device/VTEP boundaries and portable VXLAN codec | Linux TAP/TUN and fixed-peer VXLAN qualified; broad VTEP switching/offloads pending |
| `crates/l2tunnel-client-core` | Shared CLI/GUI lifecycle and local API | Strict shared CLI, private Unix API, explicit runnable profiles; GUI remains planned |
| `apps/l2tunneld`, `apps/l2tunnel-linux` | Linux server/client entry points | Real authenticated packet forwarding and supported local administrative actions |
| `apps/l2tunnel-windows` | Windows service/client, Wintun or TAP | Status/help CLI; runtime returns nonzero |
| `apps/l2tunnel-android` | Rust Android embedding library; later narrow JNI | rlib/cdylib staging crate, no JNI |
| `apps/l2tunnelctl` | Local status and reload control | Private Unix status/compression requests; full versioned deployable config parser pending |
| `simulator/` | Existing reference algorithms, experiments and golden oracle generation | Preserved existing Python project |
| `tools/` | Local checks, isolated topology and native qualification | Source-hashed checks, immutable binary snapshots, TAP/TUN/VXLAN/netem, payload/path/cleanup receipts |
| `config/` | Mode requirement catalog; later versioned deployable profiles | Catalog is an inventory, not a daemon config |

Additional planned source boundaries (create at the first actual implementation):

| Planned project | Responsibility |
| --- | --- |
| Native Windows/Android adapter crates | Reviewed driver/FD/JNI boundaries and native device lifecycle |
| `clients/desktop`, `clients/android` | Future desktop GUI and Kotlin Android GUI/VpnService shell |

[Client design](client-design.md) assigns service/runtime/platform responsibilities;
[flow control](flow-control.md) and [overlays](overlay-and-carriers.md) define protocol
contracts. The second table contains remaining projects, not empty built packages.

Split actual OS implementations into dedicated adapter crates when native FFI
appears, keeping `unsafe` exceptions outside protocol crates. The runtime crate
owns Tokio orchestration and telemetry. Avoid exposing Tokio
or platform handles in public pure APIs. Add `testkit/` golden fixtures and a Rust
in-memory integration driver at M2; add `bench/` baseline adapters at M5. These
additional projects are planned, not empty claims of functionality.

## Ordered milestones and exit gates

### M0: contracts, inventory and tooling

The initial foundation supplied the workspace, library boundaries, CLI
scaffolds, first parser/MUX/reload primitives, a 47-family parity inventory, code
conventions, CI definitions and dry-run network topology. Complete M0 before M1
by reviewing the architecture, freezing canonical config encoding and adding a
strict versioned TOML loader/schema. The current catalog is checked as TOML but is
not the runtime schema; unsupported options must not be silently accepted.

Local exit evidence: fmt, Clippy with warnings denied, unit/doc tests, rustdoc,
mode-catalog consistency, CLI status/non-running behavior and lab-plan safety
checks. Remote CI is a separate receipt; no remote is configured here.

### M1: authenticated connection and transport

1. Build persistent TCP + TLS first. Complete TLS, pinned/CA server verification,
   Ed25519 member authentication bound to exporter/nonces/capabilities, session
   creation, authenticated lane joins and bounded control messages.
2. Keep socket and TLS object through auth and data; capture no reconnect/new SYN
   at the boundary. Test no-SNI mode plus independently configured cover name.
   Implement valid HTTPS profile, including ALPN and unauthenticated handling.
3. Add both `openvpn_like` and `quic_like` UDP cover profiles, AEAD/MAC packet
   protection and staged TLS-authenticated lane bootstrap. Standalone authenticated
   UDP bootstrap is separately required; explicit UDP must eventually work without
   TCP reachability. Prove
   replay windows, role/lane separation, packet-number exhaustion, rekey,
   downgrade rejection and resource limits. Confidentiality-off retains integrity.
4. Prototype raw TCP with a single packet owner and a specified bootstrap-to-data
   transition. Qualify sequence/window/options/RST/conntrack/NAT behavior. Preserve
   preference raw > TCP > UDP where available; capability mismatch cannot silently
   activate different semantics. Publish concrete failure reasons and backend state.
5. Implement the requested L2TP cover adapter with a real protocol contract and
   interoperability tests; do not call TCP prefix bytes L2TP.

TCP compatibility may ship before raw qualification; mark its per-connection HOL
and kernel ACK behavior explicitly. Native recovery comparisons require datagram
semantics. Failed raw permission probing must not abort an otherwise compatible
TCP configuration. All carrier profiles keep the same upper session API.

Exit: loopback multi-lane auth integration, hostile/invalid/replayed inputs, failure
timeouts, real TLS packet capture, no plaintext tunnel banners, bounded memory,
TCP fallback without raw privileges, and independent raw/L2TP qualification status.
No throughput target is accepted using only simulation or encryption-byte counters.

### M2: frame bytes, shared MUX and basic codecs

Implement TAP/TUN packet records, arbitrary Ethernet fallback, IPv4/IPv6/VLAN/ARP
classification, symmetric hashing and connection-RR with deterministic simultaneous
open arbitration. Separate physical lanes from MUX channels. Carry business frames
and test SYNs through the same common arbiter, window and channel pool.

Introduce fixed internal L2 management framing independent of data modes, with
user-origin isolation and bounded reliable service in both TUN/TAP sessions. Add
VXLAN pass-through plus an explicit VTEP adapter with VNI/domain isolation, FDB/BUM
limits, loop controls and MTU accounting. MG-* and VX-* define the acceptance gates.

Port full-frame, timestamp/delta header, cross-frame, shared and aligned codecs.
Specify fragmentation, valid-byte/padding semantics, wraparound and context
recovery. Freeze byte-exact Python/Rust vectors for supported reference formats;
version/auth additions use a documented enclosing envelope. Account for changed
MTU overhead. Add bounded queues by bytes and record counts, decoder work limits
and injected-time integration tests before high-load tests.

Exit: random opaque payload round trips, unsupported-header fallback, all truncation
and malformed-length tests, no cross-channel context leakage, no probe privilege,
reorder/dedup/fragment/timeout cases, stable callback ownership and backpressure.

### M3: every production recovery family

Port selective ARQ, first-flight, bounded-gap, systematic block, sliding, hybrid,
elastic RLNC, rank-feedback block and local/global-window recovery; preserve the
catalog's legacy modes as selectable comparison profiles. Implement actual GF(256)
payload arithmetic with byte-exact recoveries, not only rank accounting. Port
feedback batching, cumulative/bitmap/rank acknowledgments, timed partial flushes,
interleaved repairs, reverse FEC, retransmission guards and pacing/path scheduling.

Use finite per-peer budgets and causal feedback only. Define congestion behavior
for UDP/raw under competing traffic; the simulator's known link capacity is not a
production measurement. Reliable TCP normally uses `carrier_only`; an explicitly
selected overlay mode may run for parity experiments but cannot remove outer HOL.

Exit: all M3 catalog entries have golden vectors plus trace-based decisions and
real-payload reconstruction tests. Measure CPU cost and retention bounds; compare
loss/reorder/burst traces with fixed input budgets and honest terminal confirmation.

Implement TUN active tunnel credit and per-flow QoS with few-flow probing,
receiver reservations and active backpressure (FC-*). TAP continues endpoint/system
TCP behavior and system-backed QoS. Keep TCP windows, tunnel credit and carrier
congestion control independent and observable. Real TCP-window acceleration is
implemented through the explicitly selected TCP proxy in M4, not header rewriting.

### M4: small packets, compression and coordinated hot switching

Port independent-short release, generic short-source copies, context-only selective
copies, packed sources, exact reverse ACK records and aggregate ACK encodings.
Keep simulator-only ACK-generation/congestion-controller knobs in workloads;
production ACK coalescing needs a safe parsed-frame rule with unchanged fallback.
Add optional bounded payload compression as new work, with expansion fallback and
explicit compression-context epochs.

Implement `tun_tcp_proxy`, owned TCP leg lifecycle and buffer-backed window
advertisement; document ACK responsibility, source addressing, recovery/failure and
unsupported-flow semantics. Do not migrate existing transparent TCP flows into a
proxy on reload. Complete all FC-* active-flow and QoS gates.

Implement the full PREPARE/READY/DRAIN/COMMIT/RETIRE protocol from architecture.md
over the stable internal L2 management channel.
Allow compatible MUX, codec and recovery changes without breaking outer sockets.
Handle duplicate/lost control messages, old frames, commit uncertainty, shrink
limits, staged state expiry, simultaneous proposals and peer restart. Packet/key
counters cannot reset during a switch. Device-layer/trust/endpoint changes use a
controlled reconnect and must be reported as such.

Exit: two-endpoint fault-injection tests at every transition, exactly-once frame
release, no old/new context mixing, all M4 inventory modes exercised, saturated
small-packet tests with measured CPU and bounded memory. Enabling an enum or a
local ReloadGuard is not this milestone.

### M5: platform clients and real local validation

Build the shared client-core/local control API and full CLI, then desktop GUI
and Android GUI using the same operations, schema and capability reporting. Follow
CL-01..CL-36, including asynchronous reload progress, privilege separation and
CLI/GUI parity. Select a desktop toolkit at its explicit design gate.

Complete Linux TAP/TUN wrappers, Windows Wintun/TAP driver/service handling, and
Android Kotlin VpnService plus JNI/FD ownership/socket protection. Keep control and
library APIs reusable by another application. Validate actual Windows and Android
devices; CI target checks alone are insufficient.

Use [the isolated bridge/route/netem plan](testing.md), then add daemon launch,
traffic generation and receipts. Baseline fixed 100/10 Mbps, 70 ms RTT, 15% IID loss,
MTU 1500; extend 0/10/20% loss, burst, reorder, duplication, jitter and PMTU changes.
Test payloads 64/256/512/1024/1228/1448, 1/2/4/16/64 demanding flows, half/full duplex, idle tails,
competing TCP and hot switches. Include actual OS TCP, QUIC and pinned upstream
KCP comparisons. KCP's no-congestion-control reference is labeled, not a safe
internet default. Keep inner TCP over QUIC/KCP on the same ordered stream/queue as
its probes when matching that campaign.

Exit: recorded configuration/source hashes, kernel/tool versions, captures,
qdisc stats, CPU/RSS, same-window goodput/byte cost/SYN P99, complete delivery and
outer confirmation, CI/native-device receipts, fuzz/parser robustness, and a
reviewed public API/license/release process. Optimize only after baseline validity.

### M6: causal research algorithms

Port the 15 causal research families listed in the catalog as explicit experimental
strategies, with their own real-payload and protocol-integration gates. Preserve
negative results and analytic diagnostics. Oracle/converse/counterfactual results
remain test/research tools and are never runtime modes or performance guarantees.
M6 is required for complete research parity, but does not block an honestly scoped
M1–M5 release that identifies its supported modes.

## Release and progress rules

Every catalog item progresses from `planned` to `implemented` only with an actual
algorithm and focused tests, then to `integration-tested` with a receipt naming
carrier/platform/configuration. Record unsupported combinations explicitly. Keep
API semver, wire version, configuration schema and algorithm IDs independent.

The eventual public library needs a chosen license, minimal dependency/features
policy, supported toolchain/platform matrix, security contact and changelog. No
license was chosen on behalf of the owner; crates currently prohibit publishing.
Runtime dependencies will be locked and audited at introduction. Add cargo-deny,
fuzz targets and dependency advisory checks when those dependencies exist; the
current pinned dependencies do not imply a completed advisory/security audit.
