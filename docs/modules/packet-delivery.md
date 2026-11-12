# Shared native packet delivery ownership

Status: base UDP/genuine-QUIC integration has focused passing tests. Stable
combined aggregate, new native profile qualification, recovery-window expansion
and 80 Mbit/s acceptance remain open. Raw uses the shared helper through its own
original-owner completion adapter; that integration has separate evidence.

- [x] [MOD-PACKET-DELIVERY-01] Track exact original bytes and all original fragment send completions using sender-owned identities and the existing pure controller, with bounded metadata and original deadlines. Evidence: [shared helper](../../crates/l2tunnel-runtime/src/packet_delivery.rs), [nine focused ownership tests](../../crates/l2tunnel-runtime/src/packet_delivery_tests.rs), [scoped work](../../work/base-delivery28/).
- [x] [MOD-PACKET-DELIVERY-02] Locally test native flight larger than 64 packets with queue two over actual authenticated UDP and genuine QUIC, both duplex modes, TAP/TUN contracts, None/LZ4 and ARQ/Cauchy. Evidence: [single actual-carrier contract instantiated twice](../../crates/l2tunnel-runtime/src/packet_delivery_actor_tests.rs), [UDP fixture](../../crates/l2tunnel-runtime/src/udp_tests.rs), [QUIC fixture](../../crates/l2tunnel-runtime/src/quic_tests.rs), [scoped results](../../work/base-delivery28/scoped-results.json).
- [ ] [MOD-PACKET-DELIVERY-03] Complete the coordinated stable aggregate and separately qualified native/capacity gates before closing the base portion of [FIX-01](../implementation-checklist.md). Native debt larger than 64 does not imply recovery debt larger than 64 or80Mbit/s.

## Distinct domains and authentication

`DeliveryConfig` is a mandatory final argument on base authentication, link and
runner entry points. Canonical forward/reverse policies match on both roles and
bind all twelve fields per direction. Old transport digest helpers preserve the
exact bytes used by independently bound aligned/packed/rolling profiles. The
new base control identities are UDP `L2U2` and genuine QUIC `L2Q2`.

Local device queue packets, recovery source bytes/records/span and original
native delivery bytes/records are independent. Current recovery remains at most 64
sources with a 48-byte cumulative/bitmap ACK. Its byte banks remain explicitly
bounded by maximum source size times 64. It can constrain throughput even while
native outstanding credit is larger. There is no recovery-window widening,
endpoint cwnd/rwnd control, per-flow QoS or common MUX16 parity claim here.

Base recovery and native reassembly deliver FIFO. Therefore the native receipt
ordinal genuinely identifies an original admission prefix; sender-owned
`credit_at_record` resolves the exact bytes. A peer cannot declare byte credit.
Independent-channel aligned/packed actors instead use their selective native
identities and must not adopt this cumulative mapping.

## Original send and feedback ownership

Original fragments from one native packet are submitted before the next packet.
Successful source IDs define a contiguous sender-owned range per original native
identity. Maintained ARQ/reliable output parsers resolve source IDs; there is no
second fragment/header parser. First successful sends set individual bitmap bits.
Repair equations and repeated original sends cannot invent completion. All bits
must complete before the shared controller confirms that native record's first
flight. The latest genuine original fragment completion supplies its time.

The callback queue reserves capacity before I/O. Successful adapter sends capture
an original `Instant` before any queue wait or buffer return. Authentication/parser
receipt time is captured before event queueing. The actor applies genuine actual
times and distinct observation times; delayed callbacks cannot revive original
admission deadlines, and early feedback never acquires retroactive RTT samples.
A QUIC send is the maintained datagram handoff, not proof of kernel emission.
All traffic remains charged to existing common wire accounting.

Metadata retains the complete bounded ordinal span until send and delivery
ownership can retire. Lookup binary-searches active source ranges, not all 8192
configured slots. Retirement visits only a newly retired prefix. Wrapped-ring,
range-boundary and 8192-capacity/single-active operation-count tests cover those
bounds. Constructor policy/fragment/metadata checks precede allocation.

## Storage, copying and status

Receiver pending native bytes and records across bank/local queue stay within
the authenticated incoming hard limits. The local queue remains its configured
size; the separate delivery bank backs larger advertised native capacity.
`FrameCodec::decoded_len` uses the existing strict parser to preflight original
size before decode allocation; compression content is checked by actual decode.
WouldBlock keeps original bytes and sends no device-delivery credit.

Exactly two preallocated outgoing buffers per sending lane move through the
one-slot output queue and writer. A bounded return queue wakes the actor, and
buffers return only after successful sends. The focused 100-send test retains one
buffer pointer while validating exact prefixes. This removes the base writer's
per-datagram output clone, not receive allocation, frame/fragment copying, small
feedback snapshots, maintained QUIC framing, kernel copies or all allocations.

At 8192 records and at most 64 fragments per native, the measured backing layout
is 458752 controller bytes + 589824 original-entry bytes + 65536 bitmap bytes
= 1114112 bytes per `Flight`, excluding owner structs and allocator bookkeeping.
The current half-mode peer allocates two such flights, including the unused
receive-only sender ledger: 2228224 bytes before payload/recovery storage. The
2 MiB policy metadata ceiling applies per flight, not to the complete process.
The outgoing payload pool adds exactly two configured maximum datagram buffers
per sending lane. Receiver payload has its separate authenticated hard cap;
recovery/FEC has separate configured storage caps. These bounds are not a claim
of pooling or allocation-free behavior for all packet stages.

`udp::observations` returns a latest-snapshot watch owner without a task/history
queue. Both base runtimes expose `run_observed(..., observer, delivery)` and keep
`run(..., delivery)` as the no-observer wrapper. Status separates native target,
actual debt/send/delivery, local queue use, native bank bytes/count, staged bytes,
recovery configured limits/current retention and observed blocking causes. Reading
status neither refreshes timestamps nor creates a capacity/performance claim.

## Focused acceptance boundary

Each carrier's generated contract covers full/half × TAP/TUN × None/LZ4 ×
ARQ/Cauchy,32 cases across both carriers. It retains128 mixed1500/40-byte packets
and 98560 original bytes per direction. Before unblocking, both peers must show
more than 64 actual completed native first sends and outstanding records, zero
native delivery, and a real device WouldBlock. After release all 128/98560 must
be admitted, delivered and fully sent with exact FIFO bytes, both cumulative
prefixes/totals and zero outstanding/retained send metadata. The unchanged
recovery windows are explicitly asserted as 64. This is a causal storage/flight
integration test using real local carriers and injected devices, not a native
throughput benchmark.
