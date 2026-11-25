# Implementation plan and source projects

The owner requested implementation and testing of an explicit KCP-like mode for
raw or compressed Ethernet. The [KCP-like L2 design](modules/kcp-like-l2.md)
tracks the recovery policy, native delivery, shared API selection, local runtime
checks and separately qualified upstream comparisons. `P-kcp-like-l2` is additive;
existing FEC modes, the pinned `P-kcp-baseline`, management, platforms and the
single-flow throughput target retain their original requirements.

Status: compact Common cutover is active and operational on Linux with
cross-compiled Windows/Android service components; full native/platform
qualification and remaining parity gates stay tracked in
[docs/implementation-checklist.md](implementation-checklist.md) and
[docs/implementation-status.md](implementation-status.md). Removing an obsolete
entry never counts as implementing its replacement.

The owner-authorized [compact cutover](modules/compact-wire-cleanup.md) removed
obsolete standalone entry points and legacy wire encoders (Git retains their
history). **Common per-flow transparent TUN active credit** remains pending
(session-level receiver credit `L2CR` is implemented and active across Common
profiles), alongside **fresh-DH integration with the Compact owner** and
**native Windows/Android device qualification**.

Current Common Records use a five-byte kind/reader and packet-number prefix.
Data protection adds a 16-byte ChaCha20-Poly1305 tag by default (21 bytes total),
a 32-byte HMAC-SHA256 tag (37 bytes), or an explicitly selected four-byte CCM tag
or unkeyed CRC32C check (9 bytes). Management and recovery feedback use their
independent full-tag domain (21 bytes). Raw IPv4/TCP adds 40 bytes (plus 5 bytes
with `--udp-cover tls-like`). Selected Block FEC systematic records transmit
only their exact original length-prefixed source extent, and Rolling/Research/
sliding repairs serialize the maximum encoded source extent in their support.

Use the [implementation checklist](implementation-checklist.md) as the durable
progress ledger. Detailed FC, MG, VX, UDP and CL checklists cover TUN active
flow control, QoS, internal L2 management, VXLAN, carrier covers and GUI/CLI
work. Update checkbox evidence and capability status with every implementation
change. All 49 entries in `config/mode-catalog.toml` (`48 planned`, `1 implemented`:
`kcp-like-l2`), full SW-11, native/platform, raw-kernel, resource,
protocol-identification and measured QoS/performance gates remain in scope. See
[implementation status](implementation-status.md) and
[compact-wire-cleanup.md](modules/compact-wire-cleanup.md#evidence-and-remaining-work).

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
All other recovery, codec, packed, rolling, proxy and 49 catalog-parity requirements
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
formats do not implement the common target. Configurable cover SNI now has finite maintained-TLS and supported CLI evidence;
complete effective IPC naming and pin-based verification remain unfinished. Preserve simulator
outputs, source-bound receipts and independently useful existing transports.

## Current execution priority: named Python behavior and L3 TCP

Follow [PBA-01..06](modules/python-behavior-alignment.md) and FIX-14 before
accepting any claim that the Common migration matches the simulator. Bind each
profile to exact Python source/configuration, recovery ownership, ACK path and
measurement units. The per-connection CompactARQ sensitivity and shared Packed
C46/C47/C48 candidates are separate required comparisons, not interchangeable
performance baselines. This changes no default selection.

The additive C48 near8 comparison under TEST-12 uses a separately negotiated
forward descriptor. Measure both socket admission settings against the original
C48 on the same release. Record the measurement window's row count, IP cost,
application latency and final confirmation separately. The original C48 target
and the independent platform and carrier gates retain their existing criteria.

The L3 TCP throughput target also applies to one inner TCP connection using the
selected tunnel. Measure application goodput on that connection with enough
offered traffic to exercise the 80 Mbit/s target. Keep the sixteen-connection
aggregate comparison for the existing FIX-04 workload. Report the socket-level
outstanding payload cap, send and receive buffers, congestion window and peer
advertised window alongside the tunnel's recovery settings.

For the physical-path bundle, compare one inner TCP connection over multiple
connected UDP tuples sharing one directional service budget. Use identical
N/K, byte limits, path holds, lossy feedback, gap timers and endpoint workload
in the Python model and Linux lab. Distinguish an accepted socket send,
observed arrival, successful TUN write and cumulative inner TCP ACK. Report
single-flow goodput, application P99, native TCP retransmissions, per-direction
IP bytes and final debt. Production integration needs authenticated association
of each path with a parent session, slot, epoch and negotiated geometry,
bounded rejoin/drain, and service-visible effective settings under CONN-04.
[Experiment and readiness](modules/frame-channel-experiment.md#independent-physical-paths-for-one-inner-flow).

The [native order and pacing comparison](modules/frame-channel-experiment.md#native-delivery-order-and-sender-pacing-in-the-linux-path-bundle)
records the established-path Linux results for PBL-01 through PBL-03. PBL-04
compares actual original payment progress across physical paths at 12/8 and
6/5. Retain the one-frame control, source custody, old-gap probes and original
deadlines, and report payment spread separately from receiver rank delay.

Compare physical-ACK-driven retries against named requests at identical
geometry and credit, with loss on both feedback and DATA. Collect the
sender's paid packet number, reported ACK window and ranges, timeout,
replacement handoff and native cumulative ACK. Evaluate how N/K changes
first-flight rank, redundancy bytes and the fraction of paid retransmission
bytes. Keep first-flight group failures, retransmitted datagrams and
retransmitted member bytes as separate measurements when datagrams mix
several records.

For the optional shared-member scheduler, measure first-flight service age,
repair entries paid before their natural first flights, pending intent merges
and physical bytes alongside throughput. Compare at fixed geometry and credit.
Do not equate fewer inner retransmissions or shorter first-flight queues with
improved goodput. Keep an independent physical retry obligation when another
path holds an unpaid copy, and check recovery through a healthy path when the
original path remains blocked. Same-turn assembly may combine overdue entries
without postponing their original send deadline.

The first Linux shared-member arm removes delayed duplicate first flights but
increases timeout-driven physical repairs and inner TCP retransmissions.
Audit physical ACK repetition after a lost ACK page, logical delivery arriving
below an active pagination cursor, and actual socket-to-wire queue time before
selecting an RTO or an adaptive coding geometry. A timeout count is not an
independent estimate of link erasure probability. Preserve bounded path-local
recovery, original packet delivery and logical cancellation in any correction.

Compare the optional paced-recovery policy with a same-binary control on an
explicit shaper-then-loss topology. Preserve the historical topology receipts.
Use the same N/K, source credit, endpoint workload, lossy feedback and directional
rates. Reconcile sender payment, source-side post-shaper capture and peer-side
post-loss capture so erased bytes are charged before loss in both implementations.
Report actual byte-pacing waits and physical RTT, and distinguish shorter kernel
queues from debt merely moved into the native admission or batch queues.

The completed 05b/06 pair reduces measurable socket-to-wire queueing but fails
the throughput and application-latency criteria. Before another runtime change,
join the early warmup congestion-window divergence to original native sequences,
distinct shard arrivals and returning ACK/SACK packets. Extend the offline
geometry model with measured loss, retry-byte goals and the probability of a
hole across a consecutive TCP window. Preserve the distinction between a small
repair-byte fraction and infrequent endpoint loss recovery; do not select a
default geometry from one seed or hide an infeasible bandwidth/latency target.

The single-flow study identified a dependency on earlier TCP-header deltas
after all of a record's fragments had arrived. A research candidate encodes
each delta relative to its channel's latest full context. Evaluate the
complete cost of identifying that context, repacking fragments, recovering a
missing context and retiring it safely across an epoch change. Compare
throughput, application P99 and inner retransmissions with the current
chained-delta profile. The implemented fixed-anchor policy uses an explicit
record distance and a separately reserved receiver history. The matched UDP
experiment selects it only in the forward direction. Record same-release TUN
and application measurements separately from receiver replay.
[Header dependency experiment](modules/frame-channel-experiment.md#fixed-anchor-ip-header-compression).

Keep two independent near8 comparisons. The bounded-reordering comparison
changes the receiver's TCP delivery timing and keeps the repair grammar and
sender recovery schedule fixed. The confirmed-prefix comparison keeps immediate
TCP delivery and negotiates a distinct repair grammar. It excludes sources
already cumulatively confirmed at the sender when a global equation is frozen.
Keep the 8192-source maximum, 128-source local repairs, global cadence and named
recovery for old holes. Check equation residuals against captured original
bytes, then measure single-flow goodput, delivery P99 and inner retransmissions
on the same native workload.

Run independent implementation lanes in parallel: actual CompactARQ serial/RTT/
receiver-delay/guarded-retry behavior; flow ownership, learned reverse affinity
and ACK custody; L3 codec and actual rolling/copy execution. The integrator owns
authenticated configuration/wire revisions and selected runtime composition.
Finish the pending TCP carrier/shared-proxy service batch while those bodies are
implemented. Its completion cannot close Python parity gates.

Then integrate the complete global8192/local128/every16 candidate with actual
short copies and ACK coalescing, prioritizing real L3 TCP and preserving L2.
Replace the legacy reliable algorithm-feedback side path for the lossy named
profiles while retaining independent authenticated management on the same
carrier. Explicit lossy ACK bypass needs truthful retirement/drain semantics;
shared Packed ACK recovery remains a separate composition.

Run changed-behavior differential/runtime cases together, reusing unchanged
source-bound results. Run the required full suite at batch acceptance; native
performance follows installed behavior with matched configurations and counters.
Do not substitute component checks, a compile, an enum, RawIp packing or an API
migration for end-to-end delivery. All existing full acceptance gates remain.

## Source projects

| Project | Responsibility | Current state |
| --- | --- | --- |
| `crates/l2tunnel` | Public embedding facade | Exports pure reserved Engine/mixed Bank, live tuning (`live_tuning`), shared native pool/counts, and record profiles |
| `crates/l2tunnel-core` | Typed IDs, capabilities, policy and config validation | Mode types and structural validation |
| `crates/l2tunnel-wire`, `crates/l2tunnel-session` | Versioned records, parsers, session contracts | Bounded wire/framing and local reload guard; distributed transactions live in management |
| `crates/l2tunnel-auth` | Verified TLS and member authentication | Retained TCP/TLS and generic I/O TLS, configurable named SNI (`ClientSni::Named`), exporter/member/config binding |
| `crates/l2tunnel-identity` | Reusable member keys and possession proofs | Pure Ed25519 keys and Noise-bound member authentication |
| `crates/l2tunnel-security` | Compact record protection and key ratchets | 5-byte compact prefix, ChaCha20-Poly1305 / HMAC-SHA256 / AES-CCM-4 / ChaCha20+CRC32C, replay and key generations |
| `crates/l2tunnel-handshake` | Maintained Noise IK/IKpsk2 adapter (`snow`) | Pinned-peer proof, M1/M2 live-tuning proposal/verdict payloads, confirmation context binding; timed fresh-DH runtime integration remains open |
| `crates/l2tunnel-cover` | Explicit UDP/raw cover appearance | Pure codecs for `quic-like`, `media-like`, and `tls-like` (no transport-interoperability or ISP classification claim) |
| `crates/l2tunnel-swift` | Systematic sliding-window packing/recovery & policy | Pure multi-channel Swift codec with SIMD GF(2^8), base-first rotating gap requests, tighter RTT retries, and bounded HoL retry copy protection |
| `crates/l2tunnel-aligned` | Aligned/packed frame codec & compact endpoint owners | Aligned/Packed ARQ, Cauchy FEC, and Compact/KCP-like L2 endpoints |
| `crates/l2tunnel-transport` | Carrier selection semantics | Capability-aware explicit fallback contract |
| `crates/l2tunnel-mux`, `crates/l2tunnel-packet`, `crates/l2tunnel-pipeline` | Classification, connection affinity, common admission | Parsed frames, bounded affinity/channel scheduling and DRR composition |
| `crates/l2tunnel-codec` | L2/L3 fragmentation and compression | None/LZ4 frames, bounded reassembly, Python timestamp/delta and aligned body primitives |
| `crates/l2tunnel-recovery`, `crates/l2tunnel-fec`, `crates/l2tunnel-reliable` | Feedback, ARQ, Cauchy/Rolling/Striped/Research FEC | Selective repeat, CompactARQ/KCP-like, Cauchy, Rolling, Striped, Research, and Legacy Sliding recovery |
| `crates/l2tunnel-flow-control`, `crates/l2tunnel-qos`, `crates/l2tunnel-active` | Receiver credit, tunnel credit, QoS, demand | Live `session_credit` (`L2CR`, quiescent backoff, high-BDP bursts/ceilings), `delivery_window`, bounded credits/DRR; per-flow transparent TUN active credit pending |
| `crates/l2tunnel-management` | Fixed authenticated control framing and mode transactions | `L2SC` PREPARE/READY/DRAIN/COMMIT/RETIRE, control streams, and `ProfileTag` 1..=6 (`SwiftPolicyV1`, `SessionRefreshV1`, `SlotReuseV1`, `TunnelTestV1`, `MetersV1`, `RateBudgetV1`) |
| `crates/l2tunnel-meters` | Control/status register (CSR) catalog, snapshots & wire paging | Typed local and in-band remote CSR meters |
| `crates/l2tunnel-tunnel-test` | In-process authenticated TCP speed & ICMP ping tester/responder | Embedded `smoltcp` stack with 4 MiB buffers and adaptive upload/download send-queue caps |
| `crates/l2tunnel-datagram`, `crates/l2tunnel-udp` | Protected UDP envelopes and lanes | UDP framing and socket helpers |
| `crates/l2tunnel-quic`, `crates/l2tunnel-https` | Genuine Quinn QUIC and TLS/HTTP2 carriers | Maintained QUIC Common carrier (`--carrier quic`); `l2tunnel-https` HTTP/2 streaming crate (runtime exposure `MOD-HTTPS-07` open) |
| `crates/l2tunnel-udp-control`, `crates/l2tunnel-openvpn-wire`, `crates/l2tunnel-openvpn` | OpenVPN outer handshake/control and carrier | Standard outer OpenVPN handshake composed with Common inner session on one UDP socket (dissector audit open) |
| `crates/l2tunnel-raw-tcp`, `crates/l2tunnel-raw-io` | Userspace TCP and raw-packet carrier | Real TCP/TLS handshake to synchronous fast-path raw packet phase, optional `--udp-cover tls-like`; broader NAT/firewall qualification open |
| `crates/l2tunnel-tcp-proxy` | Explicit TCP ownership and reliable relay | Maintained-TCP legs and fixed-buffer relay; adaptive TCP receive-window ownership pending |
| `crates/l2tunnel-device` | Packet-device abstraction and adapter capability rules | Native packet-layer validation and trait |
| `crates/l2tunnel-runtime` | Tokio/clock/I/O orchestration | Sole Common `secure_udp` driver (`L2CR` credit, live tuning + MTU gate, live speed budget, CSR meters, tunnel tests), `retained_tls`, `proxy`, `buffer_metrics` |
| `crates/l2tunnel-platform-linux`, `crates/l2tunnel-platform-vxlan`, `crates/l2tunnel-vxlan` | Linux TAP/TUN/rtnetlink and VXLAN boundaries | Linux TAP/TUN + rtnetlink `netconf.rs` and fixed-peer VXLAN qualified |
| `crates/l2tunnel-platform-windows` | Windows Wintun L3 and named-pipe ACL/owner FFI | Narrow documented `unsafe` FFI boundary; cross-compiled and Wine-tested, native Windows run open |
| `crates/l2tunnel-client-core` | Shared CLI/GUI lifecycle, `daemon`, and local API v1/v4/v5 | Profile store, host device/route mgmt, `pkexec` systemd installer, live tuning, live speed budget, CSR meters, tunnel tests, 15 grouped CLI commands on Unix & Windows |
| `crates/l2tunnel-desktop-ui` | Shared `egui`/`eframe` desktop GUI | 8-page GUI (`l2tunnel-linux-gui`, `l2tunnel-windows-gui`), version-mismatch service installer; SOCKS5 & live carrier switch remain open |
| `apps/l2tunneld`, `apps/l2tunnel-linux`, `apps/l2tunnelctl` | Linux server/client/GUI and cross-platform grouped CLI | Thin frontends delegating to `l2tunnel-client-core` and `l2tunnel-desktop-ui` |
| `apps/l2tunnel-windows` | Windows Common UDP service, foreground host, and GUI | `service install|start|install-start|uninstall|run`, `foreground`, `l2tunnel-windows-gui`; cross-compiled/Wine-tested, native Windows run open |
| `apps/l2tunnel-android` | Android embedding library and FD-broker service binary | `rlib`/`cdylib` plus `l2tunnel-android-service` (`ScmRights` TUN + `protect`); Kotlin app & JNI shell remain open |
| `simulator/` | Reference Python algorithms, experiments and golden oracle | Preserved Python simulator |
| `tools/` | Local checks, isolated namespace labs and native campaign runners | Source-hashed checks, `common_native_campaign.py`, `local_real_pair.py`, `fake_local_service.py`, golden generators |
| `config/` | Mode requirement catalog (49 entries) | Inventory validated by `tools/check.py` |

Remaining unfinished source and qualification boundaries:

| Unfinished boundary | Responsibility |
| --- | --- |
| Native Windows & Android device qualification | Real-host Windows driver/service/ACL/L2 TAP tests and Android Kotlin/JNI `VpnService` app |
| Desktop GUI remaining gaps | SOCKS5 (`DGUI-08`) and live carrier switching |
| Cross-carrier secure-session lifecycle | Timed fresh-DH rekey integration on Compact owner and default state-retaining automatic outage recovery (`CL-38`, `SEC-*`) |
| Native high-BDP & parity qualification | Real Linux kernel/netns high-BDP sweeps (`200/20`..`1000/100`), per-flow transparent TUN active credit, adaptive TCP-proxy receive windows, and remaining 48 `planned` catalog modes |

[Client design](client-design.md) assigns service/runtime/platform responsibilities;
[flow control](flow-control.md) and [overlays](overlay-and-carriers.md) define protocol
contracts. Golden codec vectors are generated and verified via
`tools/generate_*_goldens.py` into crate test data directories, and public
protocol crates remain free of Tokio, OS handles, and `unsafe`.

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
7. Complete all 49 P-* parity gates, including the 15 causal research families.
   Their independent work may start once interfaces stabilize rather than waiting
   for platform work. Existing primitives are reused after source/evidence audit.
8. After functionality, concentrate native performance, kernel profiling, original
   80 Mbit/s acceptance, high-BDP sweeps, and controlled real-path carrier/QoS
   comparisons in matched, immutable campaigns. Preserve negative results and
   historical receipts.

Each coherent source batch receives cross-review and affected regression checks.
Combine the full frozen-source aggregate and required native acceptance at stage
boundaries. Repair failures with focused dependency-aware checks; do not repeat
unaffected suites after each leaf. Run independent functional tests with bounded
parallelism, retaining shared-resource isolation and explicit reused evidence.
Owner selected `egui`/`eframe` for the desktop GUI (`crates/l2tunnel-desktop-ui`);
package publication and project license remain explicit owner decisions.

## Ordered milestones and exit gates

### M0: contracts, inventory and tooling

The initial foundation supplied the workspace, library boundaries, CLI
scaffolds, first parser/MUX/reload primitives, the initial 47-family parity
inventory (now 49 entries in `config/mode-catalog.toml`), code conventions, CI
definitions and dry-run network topology. Complete M0 before M1 by reviewing
the architecture, freezing canonical config encoding and adding a strict
versioned TOML loader/schema. The current catalog is checked as TOML but is
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

For FIX-04 and TEST-12 qualify the reverse `TargetedExactAckLz4` experiment
against the same fixed-anchor Linux UDP control, on one TCP flow with 4 MiB
of application credit. Verify the physical reverse sizes of all copies, the
original bytes recovered after loss, the ACK return time, application goodput,
write-to-read P99, inner retransmissions and terminal recovery. Report the
corresponding FIFO and early-release model results with their TCP semantics.
The original Packed parity and platform gates remain separate.

For the same single-flow comparison, preserve both the historical one-write
TCP segment and stream segmentation up to the observed Linux MSS. Price each
physical copy after Packed fragmentation. Compare MUX admission to physical
send, receiver admission to first solvability, native delivery, and the first
covering TCP ACK for each steady retransmission. Treat authenticated inputs
refused by the recovery FIFO as local losses in the same-event replay.
Keep the original throughput target and validate out-of-order delivery and
old-hole recovery under the same capacity bounds.

For FIX-04 and TEST-12 distinguish a missing source at B from the wait
between FEC input, record admission and native preparation. Compare
application credit with actual TCP unsent bytes, congestion window, SRTT
and flight on the same samples. Trace the first named gap request from B
selection to physical acceptance, A authenticated input and application,
and the first corresponding named data send. Keep request losses and
ambiguous request-to-retry matches visible.

For the same Linux flow, compare the old receiver schedule with the candidate
under identical observation. Trace the first sustained TCP recovery episode
from its original outer sources to the first covering cumulative ACK at both
endpoints. Include startup congestion-window changes and duplicate SACK reports
when interpreting steady goodput. Keep receiver service time paired with its
offered load.

For the independently selected near8 headroom profile, compare the existing
forward selector 6 and selector 10 with the same reverse ACK compression.
Account for additional equations at physical IP acceptance, preserve the
ordinary source, repair and named-retry schedules, and inspect the effective
selector and its counters before attributing a throughput difference to FEC.

For FIX-04 and TEST-12, qualify the optional simulated TCP endpoint against
captured DATA arrivals and ACKs at both TUNs. Validate the cumulative edge,
ordinary SACK blocks, duplicate SACK blocks, their order and their actual
option bytes with timestamps enabled. For the closed-loop comparison, carry
those bytes through the selected reverse MUX and Packed codec. Count feedback
only after receiver-side reconstruction. The sender study must bound how many
holes it retransmits by its congestion window and estimated outstanding data.
Record data still missing when PAWS rejects an older copy, real and redundant
retransmissions, paid reverse bytes and final confirmation. Keep the historical
FIFO reference, immediate TUN delivery and old-gap recovery as distinct checks.

Compare record splitting and actual Packed source counts separately at MSS
1,448. In the frozen Linux input all full-sized data segments still required
two aligned units at the largest symbol that fits the current advertised
worst-case union in one datagram. Use the Rust 500 µs tail-packing rule in
the matched Python control. For repetitions whose full byte prefix appeared
at the receiver TUN, correlate the first uncovered byte with the kernel's
receive cursor, individual packet verdict and first returning cumulative ACK.
Count repeated ranges separately from distinct blocking gaps.

At fixed application credit, compare socket-accepted forward IP bytes
with inner TCP acknowledged bytes at the same steady snapshot boundaries.
Price regular FEC, named retries and copies separately. Before changing
the default request policy, compare repeated gap masks with identical
directional physical copies and per-source deduplication in both model
arms. Include serialization, actual retries, control service and final
drain in the experiment.

For the mixed-packet profile, compare every admissible erasure subset at
representative group sizes against actual-byte Rust and Python codecs.
Exercise loss above the threshold followed by a late member, early direct
delivery, the oldest input's deadline and shortened groups under the physical
MTU. Report useful, parity, metadata and repeated bytes independently for
both directions. In the single-flow workload measure time to seal, kth distinct
arrival, first decodability, actual native delivery and cumulative TCP ACK.
Keep authentication, named recovery, application credit and independent
delivery in the normal carrier integration gate.

The authenticated UDP fixture exercises full-width named feedback and
inclusive confirmation through the last possible source. Tag 10 binds both
directional policies and the functional Common Engine uses the mixed owners,
physical completions, timers and actual native codec. The Bank now supports
the mixed owner's complete reserved storage. UDP, raw TCP, TLS and QUIC
pass normal service resource preflight. Two impaired Linux UDP/TUN single-flow
runs transferred every application record. The second arm also drained all
directional source custody. The single-flow goal above 70 Mbit/s remains
open. Compare paid bytes at matched native input times as well as the
closed-loop response of the inner TCP sender.
Use the sender's cwnd, effective flight and ACK progress across the entire
measurement. Join late retries to their direct or recovered data, required
header context and both native TCP timestamp histories. The 12/10 run
shows separate failures at each of these boundaries.
[Linux window and retry evidence](modules/frame-channel-experiment.md#single-flow-congestion-window-and-header-dependency).
Qualify shortened groups by physical membership as well as negotiated
geometry. Check a double loss from the same source, submit time, seal
eligibility and MTU against the six original sends. Compare any cross-source
alternative at the same offered application load, with serialized repair
bytes and a second loss seed, before selecting a Rust wire profile.
[Short-group measurements](modules/frame-channel-experiment.md#erasure-protection-at-the-short-group-deadline).
For TCP parity, report whether the sending endpoint consumes SACK ranges,
how it reenters recovery after a partial ACK, and how the connection starts.
Use the exact native record codec and a common event trace when attributing
a difference to receiver scheduling.

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
