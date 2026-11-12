# Native packets over genuine standalone QUIC

Status: the new mandatory native-byte delivery profile passes focused memory-device
carrier tests and the [source28 aggregate](../../work/implementation-wave28/validation.json); new-profile native qualification remains pending.
The 36 native Linux TAP/TUN/VXLAN scenarios below are historical receipts for the
earlier fixed-count profile. See [current delivery contract](packet-delivery.md). This runtime
uses genuine UDP-only QUIC authentication, a retained reliable control stream and
QUIC DATAGRAM data. It is separate from custom `QuicLike` UDP and never changes
existing custom UDP selections. No TCP socket is required. Hot switching remains
unsupported and requires a fresh authenticated connection for profile changes.

## API and composition

`quic::Config::new(duplex, application_id, path_mtu, ipv6)` constructs finite
ARQ defaults. `with_recovery(udp::RecoveryMode)` selects existing selective repeat
or Cauchy recovery. Config binds ARQ limits/timers, common `udp::WireBudget`, control
heartbeat/deadline, fragment expiry, datagram queue allowance and control window.
The opaque ALPN identifier is explicitly configured and observable. QUIC is always
AEAD. Complete IP MTU must accommodate QUIC's 1200-byte minimum UDP payload.

`carrier_profile(config, udp::Lane)` produces the genuine carrier Profile;
`base_session_config(runtime, config, delivery)` binds native layer, codec, device packet/queue
bounds and the exact recovery/runtime policy before carrier profile binding.
The QUIC endpoint's `connect`/`accept` receives this base, applying the profile once.
`session_config(runtime, config, lane, delivery)` computes the final expected authentication
binding for link validation. `Link::full` and asynchronous `client_pair` /
`server_pair` also require the final `DeliveryConfig` argument.
`run(device, link, runtime, config, delivery)` follows the UDP embedding pattern.
Full uses one connection; Half uses two genuine independently authenticated QUIC
connections, First C2S and Second S2C. Both retain bidirectional reliable control.

Pairing uses a fresh random challenge on First echoed on Second, with a distinct
QUIC-runtime pairing domain, matching member/server/config and role, different
session IDs, and a bounded mutual completion. Constructors inspect the actually
authenticated session metadata and reject lane/role/profile swaps before any
native device read. No hand-constructed binding authorizes a link.

The implementation extracts a narrow private generic datagram adapter from the
existing UDP runtime: `DatagramPolicy`, typed owned parts, bounded async sender and
receiver adapters, and one `run_datagrams` pump. That historical extraction kept
legacy UDP unchanged; the current base migration requires mandatory delivery
policy in both runtimes. Genuine QUIC uses the new distinct `L2Q2` base control
prefix and `l2tunnel/quic-runtime/v2/delivery-window-v1` digest domain, sharing the
same FrameCodec, Fragmenter/Reassembler, SelectiveRepeat/Reliable, common budget,
native delivery credit and failure handling. No second recovery algorithm or
separate native admission bypass is introduced.

## Bounds and failure semantics

All data, repairs, retransmissions, feedback, heartbeat and credit consume one
finite shared admission ledger across both lanes. A bounded control reservation
inside that total prevents queued data from exhausting internal control service.
Control ACK/credit are coalesced; readers and writers persist across pump polls.
Control stream timeout/EOF/error closes the entire link. A blocked native device
retains bounded decoded packets and withholds delivery credit until actual device
transmit succeeds; the authenticated control reader continues to run. Admission
uses `READ_BUFFER_BYTES` sentinel and rejects packets beyond configured size.

QUIC's maintained congestion/loss machinery controls outer transport, while
application recovery handles unreliable DATAGRAM payloads. The finite runtime
budget is admission pacing, not a substitute congestion controller. Byte charges
include explicit IP/UDP and conservative QUIC/header allowances for data and
control. QUIC ACKs, stream retransmissions, handshake/Retry and packet coalescing
are maintained-transport behavior, not exact application-ledger wire events;
actual IP-wire totals require captures and cannot be inferred from this ledger.

Recovery payload budgets subtract the native-fragment header, ARQ header,
optional Reliable/FEC envelope and complete carrier envelope/MTU headroom. FEC
uses the existing maintained-by-project bounded Cauchy implementation with
selective-repeat fallback. FrameCodec is fixed None or Lz4IfSmaller; channels=1,
epoch=1. Reassembly count/bytes/age are bounded; malformed authenticated content,
credit violations, incomplete expiry and retry exhaustion terminate explicitly.
The same user admission path carries every native protocol and probe.

## Acceptance ledger

- [x] [MOD-QUIC-RUNTIME-01] Freeze embedding API, exact authenticated profile and separate genuine-carrier selection. Evidence: [QUIC runtime](../../crates/l2tunnel-runtime/src/quic.rs), [shared pump](../../crates/l2tunnel-runtime/src/udp.rs), [QUIC tests](../../crates/l2tunnel-runtime/src/quic_tests.rs), [unchanged UDP tests](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-QUIC-RUNTIME-02] Extract one internal pump with unchanged UDP public API/wire/defaults; all 18 existing UDP runtime tests pass unchanged. Evidence: [QUIC runtime](../../crates/l2tunnel-runtime/src/quic.rs), [shared pump](../../crates/l2tunnel-runtime/src/udp.rs), [QUIC tests](../../crates/l2tunnel-runtime/src/quic_tests.rs), [unchanged UDP tests](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-QUIC-RUNTIME-03] Real UDP-only authenticated TAP/TUN memory-device forwarding works for Full/Half, None/LZ4 and ARQ/Cauchy. Evidence: [QUIC runtime](../../crates/l2tunnel-runtime/src/quic.rs), [shared pump](../../crates/l2tunnel-runtime/src/udp.rs), [QUIC tests](../../crates/l2tunnel-runtime/src/quic_tests.rs), [unchanged UDP tests](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-QUIC-RUNTIME-04] Verify pair/lane/role/config rejection before reads, malformed data/control and bounded cancellation/closure/liveness. Evidence: [QUIC runtime](../../crates/l2tunnel-runtime/src/quic.rs), [shared pump](../../crates/l2tunnel-runtime/src/udp.rs), [QUIC tests](../../crates/l2tunnel-runtime/src/quic_tests.rs), [unchanged UDP tests](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-QUIC-RUNTIME-05] Validate MTU fragmentation, native backpressure, shared budget/control service and actual loss recovery via owned injected UDP relay. Evidence: [QUIC runtime](../../crates/l2tunnel-runtime/src/quic.rs), [shared pump](../../crates/l2tunnel-runtime/src/udp.rs), [QUIC tests](../../crates/l2tunnel-runtime/src/quic_tests.rs), [unchanged UDP tests](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-QUIC-RUNTIME-06] Run targeted tests/Clippy/rustdoc and required aggregate checker at shared workspace freeze; record finite local scope. Evidence: [stable wave4](../../work/implementation-wave4/validation.json), targeted carrier/auth/runtime tests plus complete Linux workspace checks; no non-Linux native execution implied.
- [x] [MOD-QUIC-RUNTIME-07] Integrate client configuration and qualify native TAP/TUN/VXLAN with UDP-only reachability, captures and owned namespace cleanup. Evidence: [36-case independent audit](../../work/native-quic-matrix-audit.json), both duplex modes, None/LZ4 and ARQ/Cauchy; physical path MTU 1228 with segmentation/receive offloads disabled.


## Executed local evidence

`cargo test --offline -p l2tunnel-runtime udp::tests` passed all 18 pre-existing
UDP tests unchanged after extraction. `cargo test --offline -p l2tunnel-runtime
quic::tests` passed five tests, including a 16-case Full/Half × TAP/TUN ×
None/LZ4 × ARQ/Cauchy matrix over real UDP sockets. The relay injected actual
packet drops/reordering and recorded maximum UDP packet length; each pair used
independent native queues, verified exact bytes/order, and blocked device delivery
before releasing credit. Tests also cover low shared allowance with continued
control, complete UDP blackhole termination, malformed control/data, maximum-plus-
one native read sentinel and constructor binding/role/lane rejection.

Strict targeted Clippy passed for runtime, auth and genuine QUIC. The shared
workspace aggregate check passed at [stable wave4](../../work/implementation-wave4/validation.json).
The separate [native audit](../../work/native-quic-matrix-audit.json) covers 36
TAP/TUN/VXLAN cases. These are finite local Linux checks, not cross-platform or
production congestion/fairness qualification.

`DatagramPolicy` and its traits are private runtime adapters. Recovery mathematics
and parsers remain in their existing protocol crates. For custom UDP, canonical
profile/digests, `L2UC` controls and charge values are unchanged. Genuine QUIC uses
`L2QF`, a distinct pairing prefix and distinct runtime/carrier authentication
domains; it cannot be selected by changing custom UDP header appearance.


## Mandatory byte-delivery profile migration

- [ ] [MOD-QUIC-RUNTIME-08] Qualify the new mandatory delivery-policy profile through separately scoped native runs; its [source28 aggregate](../../work/implementation-wave28/validation.json) passed. Focused [shared ownership tests](../../crates/l2tunnel-runtime/src/packet_delivery_tests.rs), [same actual-carrier contract](../../crates/l2tunnel-runtime/src/packet_delivery_actor_tests.rs), and [current scoped evidence](../../work/base-delivery28/) cover local integration only; the historical 36-case audit does not qualify the changed profile. The existing64-source recovery bank and QUIC congestion/queue limits remain independent and do not establish80Mbit/s or close [FIX-01](../implementation-checklist.md).

Successful `DatagramSender::send` is the maintained QUIC
`send_datagram_wait` handoff, not captured UDP kernel transmission. The native
service observation spans that successful adapter boundary to authenticated
remote device delivery and includes downstream QUIC scheduling. See
[packet delivery and copy/memory accounting](packet-delivery.md).
