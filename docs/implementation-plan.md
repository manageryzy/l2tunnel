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

## Target architecture and migration scope

The approved target is a fixed point-to-point tunnel between an owner's client
and server. A reusable common inner secure session must provide peer authentication,
key exchange, record protection, replay defense, rekeying and authenticated
management across every selected carrier, including TCP/HTTPS. This is a
WireGuard-like separation of responsibilities, not a decision to use WireGuard's
wire protocol, a particular library, provisioning scheme, packet format or cipher
negotiation. Those contracts remain open in the
[secure-session design and SEC-01..SEC-12 ledger](modules/secure-session.md).
Account systems, multi-device enrollment and multi-peer product workflows are
not assumed by this point-to-point design.

The operator selects the outer carrier/cover independently of the data algorithm:
OpenVPN-like UDP, QUIC header cover, minimal RTP audio/video-like UDP, or the
original HTTPS TCP/TLS-to-raw path. Swift provides packing, ordering and recovery
inside the selected carrier; it is not an independent default carrier. Its
existing AEAD behavior must survive moving security into the common session.
All other recovery, codec, packed, rolling, proxy and 47 Python-parity requirements
remain in scope, including SW-11 switching between Swift and other record profiles.
QUIC header cover does not require the native QUIC congestion controller. Existing
genuine QUIC remains a separate implemented transport/reference capability. The
RTP cover is a minimal media-like encapsulation, not full WebRTC.

Carrier handshake, common inner authentication, data and management continue on
the same carrier connection or UDP socket and five-tuple. Separate TCP/TLS
bootstrap followed by another UDP data flow is historical implementation evidence,
not the target. The HTTPS requirement remains a real TCP/TLS handshake followed
by raw TCP-shaped packets on the same ports and sequence space without ordinary
TCP ACK-driven transport. Valid HTTPS/H2 streaming is an optional distinct
compatibility profile; it does not satisfy that raw requirement. Each cover needs
its own explicit wire/handshake contract and parser validation. Parseability,
endpoint interoperability and measured ISP classification remain separate claims.

Default automatic recovery is required with bounded timers, retained state and
retry work. A temporary outage retains bounded logical session, delivery and
recovery state for authenticated reconciliation. Peer restart requires fresh
authentication and a new cryptographic session; never blindly replay old-session
packets or reuse their nonces. State retention, expiry, terminal failure and any
fresh carrier connection must be observable. This does not promise preservation
of the old five-tuple when recovery must create a new carrier connection.

These are planned migration requirements. Current certificate-root/name and
exporter-bound member APIs, finite Linux receipts, and existing custom UDP/raw
formats do not implement the common target. Configurable cover SNI independent of
server trust and pin-based verification remain unfinished. Preserve simulator
outputs, source-bound receipts and independently useful existing transports.

## Source projects

| Project | Responsibility | Current state |
| --- | --- | --- |
| `crates/l2tunnel` | Public embedding facade | Exports tested pure protocol engines; OS/runtime adapters remain separate |
| `crates/l2tunnel-core` | Typed IDs, capabilities, policy and config validation | Initial mode types and structural validation |
| `crates/l2tunnel-wire`, `crates/l2tunnel-session` | Versioned records, parsers, session contracts | Bounded wire/framing and local reload guard; distributed transactions live in management |
| `crates/l2tunnel-auth` | Verified TLS and member authentication | Retained TCP/TLS and generic I/O TLS, exporter/member/config binding and negative tests |
| `crates/l2tunnel-identity` | Reusable existing-member keys and possession proofs | Pure Ed25519 extraction and explicit Noise-bound member gate; same-carrier runtime integration has its own ledger |
| `crates/l2tunnel-security` | Shared opaque protection and explicit Swift v2 compatibility | Pure AEAD/HMAC, domains, metadata, replay and adjacent ratchets; existing Swift runtime consumes byte-compatible owners |
| `crates/l2tunnel-handshake` | Maintained fixed-pattern Noise adapter | Protocol-tested pinned-peer proof, caller entropy/time, public secret handoff and final-confirmation custody; no production credential migration or full lifecycle |
| `crates/l2tunnel-cover` | Explicit QUIC-header/RTP-like appearance | Bounded pure codecs, without standard transport validity, identification or ISP classification claims |
| `crates/l2tunnel-swift` | Reusable packing/recovery, numbered records and policy negotiation | Pure full-record and directional policy engines; legacy TLS and new common-UDP adapters share the coordinator |
| `crates/l2tunnel-transport` | Carrier selection semantics | Capability-aware explicit fallback contract; actual adapters below |
| `crates/l2tunnel-mux`, `crates/l2tunnel-packet`, `crates/l2tunnel-pipeline` | Classification, connection affinity, common admission | Real parsed frames, bounded affinity/channel scheduling and DRR composition |
| `crates/l2tunnel-codec` | L2/L3 fragmentation and compression | None/LZ4 frame bytes, bounded reassembly, Python timestamp/delta and aligned body primitives; complete mode integration pending |
| `crates/l2tunnel-recovery`, `crates/l2tunnel-fec`, `crates/l2tunnel-reliable` | Feedback, ARQ, actual FEC and shared budgets | Selective repeat plus actual Cauchy payload repair and finite compositions; all catalog families pending |
| `crates/l2tunnel-flow-control`, `crates/l2tunnel-qos`, `crates/l2tunnel-active` | Tunnel credit, QoS, demand and measured adaptation | Bounded credits/DRR, authenticated retirement and optional measured target control; no endpoint TCP-window ownership |
| `crates/l2tunnel-management` | Fixed authenticated control framing and mode transactions | Prepare/drain/commit/retire state machine; runtime compression switching qualified; pure whole-message custody, stream gates and leased final-reply authority have protocol/original-UDP fixtures; explicit Swift runtime integration is tracked separately from generic dispatch |
| `crates/l2tunnel-datagram`, `crates/l2tunnel-udp` | Protected custom UDP envelopes and lanes | AEAD/integrity profiles with retained TCP/TLS bootstrap/control; native tests passed |
| `crates/l2tunnel-quic` | Genuine standalone QUIC carrier | UDP-only maintained QUIC/member auth and 36 native TAP/TUN/VXLAN cases with physical MTU captures |
| `crates/l2tunnel-udp-control`, `crates/l2tunnel-openvpn` | Standalone OpenVPN-like UDP control and retained TLS/member authentication | Real UDP-only bootstrap, full/paired-half data and bounded clean drain; four clean TAP/TUN native drain cases passed, outage recovery and broader qualification remain open |
| `crates/l2tunnel-raw-tcp`, `crates/l2tunnel-raw-io` | Single-owner userspace TCP and native adapter | Retained TLS-to-protected-packet transition, runtime and explicit shared client are implemented; original native packet captures and startup sampling are under separate qualification; congestion control, clean drain and broader path behavior remain open |
| `crates/l2tunnel-tcp-proxy` | Explicit TCP ownership and reliable relay | Maintained-TCP legs and ACK-based fixed credit; clean Linux TUN full/half native split, exact-byte/FIN and lane-close tests passed; adaptive proxy windows pending |
| `crates/l2tunnel-device` | Packet-device abstraction and adapter capability rules | Native packet-layer validation and trait |
| `crates/l2tunnel-runtime` | Tokio/clock/I/O orchestration | Retained TCP/TLS, managed compression, active TUN, protected UDP and standalone QUIC; new same-socket secure-UDP Swift/control driver has finite Unix socket/device tests |
| `crates/l2tunnel-platform-linux`, `crates/l2tunnel-platform-vxlan`, `crates/l2tunnel-vxlan` | Native device/VTEP boundaries and portable VXLAN codec | Linux TAP/TUN and fixed-peer VXLAN qualified; broad VTEP switching/offloads pending |
| `crates/l2tunnel-client-core` | Shared CLI/GUI lifecycle and local API | Managed TCP, base UDP and Swift paths use the shared service; QUIC-header/media-like Swift has version2 status/control, and explicit generic Prepared selection adds complete-C APIv3 with paired-service fixtures; explicit complete-plan CLI/inspection/APIv3 commands have finite external-process evidence; production CLI attachment and complete failure/resource matrices, native qualification, other profile lifecycles, default state-retaining recovery and GUI remain open |
| `apps/l2tunneld`, `apps/l2tunnel-linux` | Linux server/client entry points | Real authenticated packet forwarding and supported local administrative actions |
| `apps/l2tunnel-windows` | Windows service/client, Wintun or TAP | Status/help CLI; runtime returns nonzero |
| `apps/l2tunnel-android` | Rust Android embedding library; later narrow JNI | rlib/cdylib staging crate, no JNI |
| `apps/l2tunnelctl` | Local status and reload control | Private Unix status/compression requests; full versioned deployable config parser pending |
| `simulator/` | Existing reference algorithms, experiments and golden oracle generation | Preserved existing Python project |
| `tools/` | Local checks, isolated topology and native qualification | Source-hashed checks, immutable binary snapshots, TAP/TUN/VXLAN/netem, payload/path/cleanup receipts |
| `config/` | Mode requirement catalog; later versioned deployable profiles | Catalog is an inventory, not a daemon config |

The [shared UDP client factory](modules/client-secure-udp.md) passed the
[frozen-source local aggregate](../work/shared-session-client-20261113/validation.json),
including actual same-socket cookie/Noise establishment, existing-member proof
and protected Swift/control over both appearances. The
[Swift record extraction](modules/swift-record-engine.md) removes duplicated
packing/channel/header processing from the legacy runtime. Their ledgers record
the actual checks. Neither source presence nor factory authentication completes
the selected shared-service/native data path or remaining carrier/lifecycle
requirements.

The [new common-UDP runtime/service focused checks](../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json)
passed with unchanged compiled-source inputs, including actual original-socket
transport, native readiness/backpressure fixtures, authenticated Swift policy
changes, explicit credential/CLI validation, versioned local API and manual fresh
reconnect. This follows the factory checkpoint; it does not qualify actual
CLI/TAP throughput. The [separate native lab](modules/secure-udp-native.md) retains
clean, delay, 1%/15% loss, sixteen-flow ACK-return, reverse-bulk stress, payload,
policy/lifecycle and capture acceptance without reducing parent gates.
The [preceding deadline-correction aggregate](../work/secure-udp-native-progress-20261113/attempt-1/validation.json)
passed with stable source inputs. The subsequent [immutable CLI/TAP baselines](modules/secure-udp-native.md#initial-immutable-native-baseline)
exercise exact bytes, real policy commits and manual reconnect for both appearances.
Clean/delay QUIC-like cases passed; both impaired cases failed the unchanged
80 Mbit/s target. Source-backed deadline/wakeup corrections and the remaining
matched matrix require new recorded qualification; these finite observations do
not close FIX-04, FIX-13 or full SW-11.

The [counter-guided correction](modules/secure-udp-native.md#counter-guided-performance-correction)
now has [source-stable focused evidence](../work/secure-udp-performance-focused-20261113/attempt-4/validation.json)
for production class/credit/native observations, shared bounded reports/logging,
original control-loss bounds and output-drain scheduling. The initial-rate burst
and write pre-drain improve finite impaired QUIC-like goodput to70.6236Mbit/s,
with reported native-pressure rejection removed;80Mbit/s remains unqualified.
The later [expanded focus](../work/secure-udp-performance-focused-20261113/attempt-5/validation.json)
and actual immutable CLI proofs validate the IPC-only helper scheduler correction;
build8 reaches77.3464Mbit/s impaired and still fails80. Kernel perf and simultaneous
process I/O observations do not establish disk I/O as the primary cause.
SUR-11 now reproduces and corrects the independent saturated native-read fairness
defect, with a [passing focus](../work/secure-udp-performance-focused-20261113/attempt-8/validation.json)
and both-cover forward/reverse native observations. Build9 forward16 measures
78.6206/78.2435Mbit/s, still failing80; the separate reverse-stress receipts pass
their functional gates. Simulator
overhead sensitivity, sampled CPU/credit and historical-binary replay remain
separate evidence, not a reduction of any mode, lifecycle or performance gate.
The [preceding source-stable aggregate](../work/secure-udp-performance-progress-20261113/attempt-3/validation.json)
passed the complete ordinary workspace checks. Both earlier failed aggregate
attempts remain preserved; actual native80Mbit/s acceptance remains open.
The scheduler checkpoint's [required aggregate](../work/secure-udp-fairness-progress-20261113/attempt-2/validation.json) also passes
1528 Rust cases including doctests, 295 Python tooling cases and 1658 simulator cases, without changing assertions or deadlines. The
conditional wire-capacity estimate in the native ledger preserves the target
and requires separate validation of any future framing/rate proposal.


The additive [generic Swift runtime](modules/generic-secure-udp.md#current-explicit-runtime-checkpoint)
now has explicit runtime-library and shared Prepared/service/APIv3 selection in
that same sole I/O loop. Finite Unix tests use actual original UDP sockets,
maintained authentication, canonical H0/D0 scopes, reserved engines and physical
native writes through two nonzero asymmetric switches. The actual shared service
also passes both-cover traffic, complete-C/key operations, IPC v3 status/switch,
liveness and fresh-session reconnect with periodic reporting disabled. Actual
observations precede successful completion; requested/current/physical values
and incomplete resources remain distinct. All three generic control streams
now use actual reserved ARQ backing; sole-loop inputs are charged and moved once.
The additive [complete-plan CLI](modules/generic-transaction-cli.md) now exposes
explicit generic selection, complete-C APIv3 commands and bounded full-catalog
inspection. Its [source-stable batch](../work/generic-transaction-cli-20261114/aggregate-attempt-2/validation.json)
passes1960 Rust cases including doctests,376 tooling cases and1658 simulator
cases. The external probe executes34 real CLI processes per cover against
actual authenticated shared-service owners and UnixDatagram PacketDevices,
including2 switches and fresh reconnect. It does not qualify successful
production CLI TAP/TUN startup. Existing defaults and fixed v1/v2 bytes remain
preserved. The complete generic IPC/negative-service/fault matrix, full
reservation, cross-profile SW-11 and broader carrier/lifecycle/platform/performance
acceptance remain open. No new native or performance run is inferred.

Additional unfinished source and integration boundaries:

| Unfinished boundary | Responsibility |
| --- | --- |
| Native Windows/Android adapter crates | Reviewed driver/FD/JNI boundaries and native device lifecycle |
| `clients/desktop`, `clients/android` | Future desktop GUI and Kotlin Android GUI/VpnService shell |
| Cross-carrier secure-session lifecycle | Complete the existing pure security/Noise/control implementation draft across every carrier, including fresh-DH exchange and default retained-state recovery; parent SEC-* gates remain open |
| Additional carrier and appearance composition | Preserve implemented QUIC-header/RTP codecs and the selected UDP driver while qualifying native use and other carriers; no native QUIC controller or full WebRTC is implied |

[Client design](client-design.md) assigns service/runtime/platform responsibilities;
[flow control](flow-control.md) and [overlays](overlay-and-carriers.md) define protocol
contracts. The second table identifies unfinished boundaries; it does not imply
that another empty package or duplicated secure protocol is needed.

Split actual OS implementations into dedicated adapter crates when native FFI
appears, keeping `unsafe` exceptions outside protocol crates. The runtime crate
owns Tokio orchestration and telemetry. Avoid exposing Tokio
or platform handles in public pure APIs. Add `testkit/` golden fixtures and a Rust
in-memory integration driver at M2; add `bench/` baseline adapters at M5. These
additional projects are planned, not empty claims of functionality.

## Approved parallel execution order

On 2026-11-15 (Asia/Tokyo), the owner approved the following execution order.
Run three implementation lanes with one integrator; independent work may overlap
batches after its shared interfaces are frozen. Preserve the existing milestones,
stable task IDs and complete acceptance definitions below.

1. Finish the current GCN/GSF/CMS/KCA functionality batch: actual production CLI,
   service failures/lifecycle, complete control-message storage and known
   construction admission. Integrate before combined checks and the four
   quic-like/media-like TAP/TUN functional cases.
2. Extend the common session foundation and lifecycle in parallel: reusable
   record-profile interfaces/configuration, authenticated fresh-DH exchange and
   bounded retained-state recovery, and remaining control/resource/fault work.
3. Integrate existing reliable/aligned/packed/rolling/RLNC/parity components and
   the generic engine lifecycle. Complete actual Swift-to-other-profile switching
   under the full SW-11 definition, including typed feedback and native fences.
4. Complete production recovery/record families alongside TUN active credit,
   QoS, explicitly selected TCP proxy and VXLAN isolation/attachment.
5. Compose the common session through the remaining carriers. Preserve the
   original OpenVPN wire-handshake and HTTPS TCP/TLS-to-ACK-independent packet
   requirements, with feasibility, ownership and failure gates before exposure.
6. Deliver shared CLI/GUI and Linux/Windows/Android integration after schema/API
   stability. Retain the existing toolkit decision and actual-device evidence
   gates; public protocol libraries remain independent of runtimes and OS handles.
7. Complete all47 P-* parity gates, including the15 causal research families.
   Their independent work may start once interfaces stabilize rather than waiting
   for platform work. Existing primitives are reused after source/evidence audit.
8. After functionality, concentrate native performance, kernel profiling, original
   80Mbit/s acceptance and controlled real-path carrier/QoS comparisons in matched,
   immutable campaigns. Preserve negative results and historical receipts.

Each coherent source batch receives cross-review and affected regression checks.
Combine the full frozen-source aggregate and required native acceptance at stage
boundaries. Repair failures with focused dependency-aware checks; do not repeat
unaffected suites after each leaf. Run independent functional tests with bounded
parallelism, retaining shared-resource isolation and explicit reused evidence.
Performance campaigns remain deferred and controlled. This scheduling approval does not change
any mode requirement or select unresolved wire formats, timeout values, a desktop
toolkit, package publication or a project license. Engineering interface choices
remain distinct from owner decisions.

The [current scoped foundation](../work/common-foundation-20261114/scoped-checkpoint-validation.json)
provides the [directional record owners](modules/directional-record-endpoints.md),
[Swift adapter](modules/swift-record-adapter.md) and actual
[control wrapper backing](modules/control-wrapper-storage.md). It retains full
stage acceptance and common cross-profile composition as open work. Complete
directional Aligned/Packed encoding exceeds the current512-byte transaction
configuration bound; the next composition must version the full configuration
and all dependent bounds, preserving every field and independent direction.
The [fresh-DH proposal](modules/session-refresh.md) remains design-only, including
the unresolved managed Joining handoff and required runtime/lifecycle follow-ons.

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

1. Freeze the common secure-session contract under SEC-01..SEC-12 before choosing
   a maintained implementation. Specify peer trust/provisioning, authenticated
   capability/digest binding, authenticated lane joins, key domains, record
   protection and common management
   without changing the existing Swift AEAD guarantee. Keep optional inner
   confidentiality versus mandatory integrity/replay protection explicit; no final
   packet format or cipher negotiation is selected by this plan.
2. Compose that same inner session through every selected carrier, including
   TCP/HTTPS. Preserve the original connection/socket and five-tuple through its
   handshake-to-data boundary; UDP must work without a second TCP bootstrap flow.
   Keep existing TCP/TLS and staged UDP receipts as historical scoped evidence.
3. Specify and validate the OpenVPN-like, QUIC-header and minimal RTP audio/video
   cover contracts independently. Header-only QUIC does not require native QUIC
   congestion control; genuine QUIC stays a separate capability/reference. RTP
   does not imply WebRTC signaling, ICE or a full WebRTC stack. Prove bounded
   pre-authentication work, replay, role/lane separation, packet-number exhaustion,
   rekeying, downgrade rejection and exact protected MTU/wire budgets.
4. Qualify the original HTTPS TCP/TLS-to-raw transition with one packet owner,
   retained ports and sequence space, configurable SNI independent of our server
   trust, sequence/window/options behavior, kernel ACK/RST fencing, privileges,
   firewall/conntrack/NAT behavior and
   bounded failure recovery. Keep required peer management alive on that same
   carrier after leaving TLS record transport. Do not substitute H2 streaming or
   ordinary TCP ACK-driven delivery for the raw requirement.
5. Preserve retained TCP/TLS and optional valid HTTPS/H2 compatibility paths with
   their kernel ACK/retransmission/HOL limitations. HTTPS/H2 must honor selected
   ALPN and bounded unauthenticated HTTP handling. Any fallback needs explicit
   operator configuration and an observable effective profile; raw unavailability
   cannot silently select incompatible semantics. Existing genuine QUIC and other
   requested carrier acceptance gates remain independently tracked.
6. Implement the requested L2TP cover adapter with a real protocol contract and
   interoperability tests; do not call TCP prefix bytes L2TP.
7. Implement bounded default automatic recovery, authenticated state reconciliation
   after temporary outage, and fresh authentication after peer restart. Exercise
   retained-state expiry, retry exhaustion, duplicate/late packets and uncertain
   management commits without nonce reuse or blind old-session replay.

Exit: actual selected-carrier handshake/data/control integration, exact bytes and
identity/config binding, hostile/replayed input, original deadlines and bounded
memory/work, captures of connection continuity, and independent cover/raw/platform
qualification. Cover parser acceptance does not prove endpoint interoperability
or improved ISP QoS; the latter needs controlled path measurements. No throughput
target is accepted using only simulation or encryption-byte counters.

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
over the stable internal L2 management channel of the common secure session.
Allow compatible MUX, codec and recovery changes without breaking outer sockets.
Handle duplicate/lost control messages, old frames, commit uncertainty, shrink
limits, staged state expiry, simultaneous proposals and peer restart. Packet/key
counters cannot reset during a switch. Device-layer/trust/endpoint changes use a
controlled reconnect and must be reported as such.
SW-11 explicitly includes negotiated epoch switching between Swift and other
record profiles. An in-Swift policy change does not close that requirement or
reduce any RLNC, parity, rolling, packed or proxy acceptance gate.

Exit: two-endpoint fault-injection tests at every transition, exactly-once frame
release, no old/new context mixing, all M4 inventory modes exercised, saturated
small-packet tests with measured CPU and bounded memory. Enabling an enum or a
local ReloadGuard is not this milestone.

### M5: platform clients and real local validation

Build the shared client-core/local control API and full CLI, then desktop GUI
and Android GUI using the same operations, schema and capability reporting. Follow
CL-01..CL-39, including common secure-session selection, bounded outage recovery,
asynchronous reload progress, privilege separation and
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
