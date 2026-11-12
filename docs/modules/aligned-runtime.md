# Native aligned-symbol runtime composition

Status: required v2 native identity/byte-budget integration is implemented and
locally integration-tested with [the source27e aggregate](../../work/implementation-wave27e/validation.json). Native v2 qualification and throughput remain open. The historical
v1 [client selection](aligned-client.md) and
[capture audit](../../work/native-aligned-matrix-audit.json) cover18 owned Linux
UDP/QUIC, TAP/TUN/VXLAN and duplex/impairment cases; those receipts are preserved
and do not qualify the changed authenticated v2 policy. The
[pure aligned pipeline](aligned-envelope.md) has separate finite tests. Existing
frame/fragment runtime formats stay unchanged.

## Scope and explicit exclusions

The first native slice uses fixed aligned timestamp/delta/predictive body policy,
finite per-channel contexts and existing real Cauchy recovery with ARQ fallback.
It supports TAP Ethernet and TUN IP, full duplex and the existing two separately
authenticated directional lanes for half duplex. TAP uses common FIFO/RR;
transparent TUN uses the existing per-flow DRR pipeline. This does not yet compose
adaptive TUN credit growth or a TCP proxy. Generic short frames share exactly the
same channel pool and admission budget as every native frame and probe.

Initial mapping is deterministic CRC32. Connection-round-robin simultaneous-open
arbitration needs its own negotiated binding protocol and is rejected in this
slice. Timed multi-source packing, early-short delivery across lost recovery
sources, raw TCP carrier selection, fixed-frame LZ4, hot reload and full Python
catalog completion are not implied. The global source-ordered recovery limitation
remains explicit. Unsupported combinations fail before device reads.

## Public API

New `runtime::aligned` owns the native pump. Existing carrier modules get only
private helpers for accepting an explicitly supplied canonical base binding,
validated pair construction and consuming the resulting link parts. Their public
constructors and old digest/wire paths continue to call the original base helper.
No authenticated connection is silently reinterpreted as an aligned session.

```text
Config { delivery: managed::DeliveryConfig, protocol: l2tunnel_aligned::Config, pipeline: PipelineConfig }
Config::for_udp(runtime, udp::Config, channels, delivery) -> Result<Config>
Config::for_quic(runtime, quic::Config, channels, delivery) -> Result<Config>
udp_base_session_config(runtime, transport, config) -> Result<SessionConfig>
udp_session_config(runtime, transport, config, lane) -> Result<SessionConfig>
udp_carrier_config(runtime, transport, config, lane, peer) -> Result<udp::Config>
quic_base_session_config(runtime, transport, config) -> Result<SessionConfig>
quic_session_config(runtime, transport, config, lane) -> Result<SessionConfig>
UdpLink::full(carrier, runtime, transport, config) -> Result<UdpLink>
udp_client_pair(first, second, runtime, transport, config) -> Result<UdpLink>
udp_server_pair(first, second, runtime, transport, config) -> Result<UdpLink>
QuicLink::full(connection, runtime, transport, config) -> Result<QuicLink>
quic_client_pair(first, second, runtime, transport, config) -> Result<QuicLink>
quic_server_pair(first, second, runtime, transport, config) -> Result<QuicLink>
run_udp(device, link, runtime, transport, config) -> Result<()>
run_quic(device, link, runtime, transport, config) -> Result<()>
```

The transport parameters are the existing runtime transport Config types. Profile
construction reuses their exact carrier limits and full/half role mapping, while
using a new aligned base digest. Constructors verify actual authenticated info,
expected lane profile, role/member/server identity, distinct paired sessions and
existing random pair proof before native admission. Pairing keeps the same
retained control connections. A link's private bound config is rechecked by run.

## Authentication and complete configuration

Domain `l2tunnel/aligned-runtime/v2/common-mux-crc32/native-identity-credit-v2` binds the existing complete transport-base
digest, the pure aligned config digest, all common PipelineConfig fields and native
layer/max-packet/queue/poll policy. A separate domain-separated canonical binding
includes all12 fields of each required `managed::DeliveryConfig` direction:
forward means originator to acceptor, reverse means acceptor to originator.
There is no omitted-policy or legacy64-record fallback. Complete profile application is performed once
by the carrier helper, as in the existing runtime. The exact body format, native
layer, symbol size, channels, first IDs, memory/timing/work caps, mapping/QoS,
finite common budget and carrier/duplex/ALPN/protection policy therefore cannot
change after authentication. Wrong initial profile fails before reading devices.

The runtime requires Cauchy recovery and sets symbol size to existing maximum
source payload minus the new 48-byte aligned envelope. Body maximum equals the
validated native maximum. This produces exactly the maximum recovery packet
allowed by the carrier and accounts for the full new envelope, ARQ, length field,
FEC header/coefficient row, reliable wrapper and carrier protection/underlay.
QUIC accounting remains application admission plus a conservative transport
allowance; Quinn's independent ACKs/handshake/retransmissions are not a physical
wire cap. Native path-MTU receipts remain separate from the accounting contract.

TUN uses explicit raw-body staging (kind2), including large fragmented IP packets,
without accidentally interpreting IP bytes as an Ethernet timestamp header. The
additive `encode_raw`/`stage_raw`/`enqueue_admitted_raw` helpers preserve contexts
and existing wire bytes. TAP uses normal eligible-header compression and exact
raw fallback. No endpoint TCP ACK/window/header values are rewritten.

## One common scheduling and ownership pipeline

All native packets first enter the existing bounded `Pipeline`. Its configured
packet/byte ceilings, flow cap, FIFO channel order and TAP/TUN policy are retained.
Device input always supplies the shared 65536-byte receive sentinel and rejects
packets beyond negotiated max_packet. A retained one-packet device-to-pipeline
handoff handles pressure without dropping a packet already read. It is charged
separately in the memory budget and prevents further reads until admitted.

Only a scheduler-selected complete native packet enters the aligned frame stage.
A one-packet selected handoff retains ownership across unexpected staging pressure;
normal admission preflights the empty single-frame stage and peer native delivery
credit. No repair/retry/context record re-enters native MUX or receives fresh flow
credit. Recovery owns copied complete source envelopes and their original IDs.
Frame admission and source receipt are distinct from successful native delivery.

For receive, protected data and retained-control feedback are authenticated by the
carrier before dispatch. The endpoint validates all recovered envelope identity,
body/fragment geometry and native preparation. Common channel scheduling chooses
receiver prepare order. Before device transmission the original packet is validated
for the negotiated native layer and its authenticated channel is checked against
the deterministic flow map. An immutable pending frame survives WouldBlock; only
complete device acceptance calls commit_delivery and publishes its exact native
body identity. Recovery ACKs alone never release native admission credit.

Local Pipeline queues retain `runtime.queue_packets`; admission uses the shared
actual-byte `delivery_window::Controller` and its independent hard byte/record
caps, bandwidth and causal service RTT. A staged original packet is retained once
when the byte target is full. Small TCP ACKs and probes charge their actual bytes
and one record through the same MUX. The sender-owned `(channel, absolute body
RecordId)` ledger excludes context records and resolves every authenticated
receipt to its original admission ordinal. Independent channel delivery is kept:
a later40-byte delivery releases40 bytes, never an earlier1500-byte charge.

Receiver decoded native pending storage is one immutable frame, checked against
negotiated maximum packet and incoming hard bytes; encoded native record counts
are capped by the incoming record policy. Encoded record/context/fragment banks
have separately checked finite pure-codec limits, derived independently of the
local queue. A smaller encoded/recovery bank retains original ownership and can
backpressure; a flight cap is not a promise of unbounded payload storage. The
maximum pure lookahead remains4096 records/128MiB/1048576 fragment slots. Runtime
identity slots and original-fragment bitmaps plus the pure controller bank fit the
explicit metadata budget before device I/O. The entire retained ordinal span is
bounded even when selective delivery releases bytes around a missing callback.
Counters never reset within a link or alias source, record, flow, cryptographic
packet or carrier sequence spaces.

## Shared carrier tasks, budgets and liveness

Reuse the existing cancellation-safe long-lived control/datagram read/write tasks.
Control magic `L2A2` rejects the historical scalar-credit profile. The shared
strict parser retains56-byte recovery ACKs and heartbeat; v2 native receipts have
exact9-byte bodies (channel u8, absolute body RecordId u64). Receipt ownership is
reserved in a bounded channel before native transmit. These exact identities are
never dropped by watch coalescing; only cumulative recovery feedback uses watch.
Each receipt retains its original authenticated parse time before queue waiting.
One immutable datagram
handoff is retained while its writer blocks. Control EOF, deadline, malformed
record, expired receiver stage or retry exhaustion closes the whole link and
aborts and joins all owned tasks on an ordinary error return. External future
cancellation drops the owning JoinSet, which aborts its tasks. No user EtherType can dispatch control.

Reuse the existing one interval ledger shared across both physical lanes, all
sources/repairs/retries, feedback, credit and heartbeat. A narrow callback-based
poll helper lets that ledger call the pure Endpoint, verifying its exact returned
packet/byte debit. The pure engine's external overhead is zero in this adapter;
the common runtime ledger adds the selected data or control path's bound exactly
once. Both zero-overhead engine config and actual external charges are included
in the authenticated combined digest. Feedback reservation is a portion of this
same total, never an extra uncharged lane.

A source/systematic packet is inspected using the maintained recovery/envelope
parsers. Its original unit witnesses do not confirm a send. The writer reserves
bounded completion-event capacity before carrier I/O and timestamps only after
`DatagramSend::send` succeeds. The sender records each original fragment bit and
confirms the native record only after all parts have genuinely sent. A packed
source may witness multiple records; a later completion never confirms an earlier
record implicitly. Retries cannot restamp a previously sent part. Failed sends
publish no completion. ACK-before-callback retains the original send deadline
and never creates a retrospective RTT sample. This is application carrier-send
acceptance, not proof of physical wire transmission.

Time is injected from one runtime Instant. Receiver and immutable recovered-source
handoff have separate stage deadlines; they are not one wire-arrival clock.
Runtime ticks service endpoint deadlines and the existing recovery poll even with
no native input. Backpressure remains finite in memory; no delivery guarantee is
made when device/carrier service stalls past configured expiry.

## Acceptance ledger

Checked v1 items below retain their stated historical scope. FIX-01 v2 integration
requires the new separate gate and does not inherit old native/performance results.


- [x] [MOD-ALIGNEDRT-01] Freeze public constructors, exact authentication/profile binding and shared-helper ownership before code. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-02] Add explicit TUN raw staging and test byte/context/fragment preservation without changing existing APIs. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-03] Integrate actual bounded common MUX/DRR, selected packet retention, per-channel codec and native delivery credits. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-04] Reuse control/data tasks and one shared finite budget with cancellation-safe backpressure in full and paired-half modes. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-05] Test real authenticated UDP/genuine-QUIC loopback TAP/TUN traffic, body compression evidence, loss/reorder/repair, malformed profile, EOF/expiry and queued native WouldBlock. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-06] Run strict focused checks plus every prior UDP/QUIC regression and a coordinated stable aggregate. Evidence: [wave6 receipt](../../work/implementation-wave6/validation.json), 492 Rust cases including doctests and 36 Python cases with identical before/after source hashes; CLI/native OS qualification is separate.
- [x] [MOD-ALIGNEDRT-07] Add explicit client configuration and owned native namespace/bridge/qdisc/packet-capture qualification before declaring native integration complete. Evidence: [client design and checks](aligned-client.md), [18-case native audit](../../work/native-aligned-matrix-audit.json), [UDP receipt](../../work/native-aligned-udp-matrix/receipt.json), [QUIC receipt](../../work/native-aligned-quic-matrix/receipt.json).
- [ ] [MOD-ALIGNEDRT-08] Integrate negotiated mode switching, connection-round-robin arbitration, actual timed packing and unordered early-short recovery before enabling their catalog gates.
- [ ] [MOD-ALIGNEDRT-09] Complete [FIX-01](../implementation-checklist.md) required authenticated v2 actual-byte/selective-native integration, strict combined aggregate and separately scoped native qualification. Evidence: focused work in progress under [aligned/packed delivery evidence](../../work/aligned-delivery27/); pure selective stage is [frozen](../../work/aligned-delivery27/pure-validation.json), but it does not close this actor/native gate. Native throughput remains unqualified.

## Finite verification and remaining gates

Six focused runtime tests pass. The actual protected UDP matrix covers 16 cases:
TAP/TUN, full/paired-half, both custom covers and both AEAD/integrity suites. The
actual genuine QUIC matrix covers four TAP/TUN/full/paired-half cases without a
TCP bootstrap. Each has independent native-memory devices, actual authenticated
carrier objects, a lossy/reordering UDP relay and held native delivery. Tests
check complete original bytes, bounded native reads/credit, MTU-limited protected
UDP output and cleartext aligned context/predictive records in integrity-mode
captures. They also check wrong configuration before any device read, retained
control EOF, authenticated raw-policy/native-credit violations and exact receiver
expiry under WouldBlock. The relay observations are finite local test evidence,
not a privileged native-device packet-capture qualification.

All 18 pre-existing UDP and five genuine QUIC runtime tests passed after private
bound-constructor/shared-budget refactoring, without changes to those test files.
Strict focused Clippy passed. The [wave6 stable aggregate](../../work/implementation-wave6/validation.json)
includes this runtime and the explicit RawIp extension: 492 Rust cases including
doctests and 36 Python cases, with identical before/after source hashes. That
aggregate is separate from the later native receipts below. Hot reload,
connection-round-robin arbitration, timed source packing, adaptive TUN flow control
and cross-source early-short gates remain open.

The subsequent [native audit](../../work/native-aligned-matrix-audit.json) verifies
18 fixed-profile UDP/QUIC cases across TAP/TUN/VXLAN, clean full/half and impaired
half with 70 ms delay and 15% configured loss. Each completes the exact 65,536-byte
TCP payload and native IPv4/IPv6 probes. Captures use the expected physical lane
ports, have whole-IP maxima of 1,500 bytes, and contain no captured truncation or
fragmentation. These finite functional/path proofs do not establish throughput,
graceful session shutdown or complete capture of every wire packet.

An independent read-only review found no material blocker in configuration and
authentication binding, shared budget debit, RawIp dispatch, common channel
validation, retained ingress/native credit or task shutdown. That review did not
rerun the tests. Strict rustdoc and the 2,588-symbol Python sender fixture check
also pass locally.


## Required v2 delivery evidence (FIX-01)

The focused current actor run passes17 aligned cases (including six shared ledger,
control parser and writer ownership cases), and the packed selection passes11.
The shared pure codec/aligned packages pass75 and19 tests respectively. The
actual authenticated larger-flight test covers UDP and genuine QUIC, full/paired
half modes, TAP/TUN, both directions and real `PacketDevice::transmit` WouldBlock.
With local queues of two and the unchanged 128-record/98560-byte workload, the
pressure phase requires more than 64 actually completed native first sends and
more than 64 outstanding records in both directions, with no native delivery.
After release it requires all 128 records/98560 bytes admitted, delivered and
fully sent, exact device bytes/per-flow FIFO, and zero debt/send metadata. The
original phase and protocol deadlines remain unchanged. The earlier
[wave27b failure](../../work/implementation-wave27b/local-check.log) reached
healthy larger flight but failed an unrelated all 128 first sends within 3 seconds condition;
[the correction evidence](../../work/aligned-pressure27c/) retains that distinction.
These are actual loopback carriers with injected packet devices, not
kernel TAP/TUN throughput or advertised-window qualification.

The old scalar mapping's exact1500/40-byte counterexample and original first-send
prefix counterexample are preserved in
[the pure-stage receipt](../../work/aligned-delivery27/pure-validation.json).
The current runtime identity ledger also covers missing earlier fragments, early
ACK, duplicate/context/future/wrong-channel identities, real send failures and
bounded event-queue ownership before send. The complete actor receipt is under
[delivery work](../../work/aligned-delivery27/); the combined frozen
`tools/check.py` gate passed in source27e. The v2 native parent remains unchecked.
