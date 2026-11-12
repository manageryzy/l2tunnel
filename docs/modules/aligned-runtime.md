# Native aligned-symbol runtime composition

Status: runtime composition implemented, tested over real authenticated loopback
carriers, and qualified in a finite owned Linux native matrix. The explicit
[client selection](aligned-client.md) and [capture audit](../../work/native-aligned-matrix-audit.json)
cover 18 UDP/QUIC, TAP/TUN/VXLAN and duplex/impairment cases. The
[pure aligned pipeline](aligned-envelope.md) has separate finite tests.
This slice carries its actual Python-compatible symbols over existing
TLS-bootstrapped protected UDP and genuine UDP-only QUIC. These remain distinct
carrier selections. Existing frame/fragment runtime formats stay unchanged.

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
Config { protocol: l2tunnel_aligned::Config, pipeline: PipelineConfig }
Config::for_udp(runtime, udp::Config, channels) -> Result<Config>
Config::for_quic(runtime, quic::Config, channels) -> Result<Config>
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

New domain `l2tunnel/aligned-runtime/v1` binds the existing complete transport-base
digest, the pure aligned config digest, all common PipelineConfig fields and native
layer/max-packet/queue/poll policy. Complete profile application is performed once
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
complete device acceptance calls commit_delivery and publishes cumulative native
credit. Receipt ACKs alone never release that native admission credit.

The total sender native admission window is runtime.queue_packets per directional
lane. Receiver reserved channel heads and lookahead memory are sufficient for that
window's worst-case context/body records and fragments. More peer work than this
admission permits fails closed. Counters never reset within a link or alias source,
record, flow, cryptographic packet or carrier sequence spaces.

## Shared carrier tasks, budgets and liveness

Reuse the existing cancellation-safe long-lived control/datagram read/write tasks.
New control magic distinguishes the aligned runtime while keeping bounded ACK,
cumulative native-credit and heartbeat classes. Reliable ACK length is 56 bytes.
Control messages use bounded channels/watch coalescing, and one immutable datagram
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

Time is injected from one runtime Instant. Receiver and immutable recovered-source
handoff have separate stage deadlines; they are not one wire-arrival clock.
Runtime ticks service endpoint deadlines and the existing recovery poll even with
no native input. Backpressure remains finite in memory; no delivery guarantee is
made when device/carrier service stalls past configured expiry.

## Acceptance ledger

- [x] [MOD-ALIGNEDRT-01] Freeze public constructors, exact authentication/profile binding and shared-helper ownership before code. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-02] Add explicit TUN raw staging and test byte/context/fragment preservation without changing existing APIs. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-03] Integrate actual bounded common MUX/DRR, selected packet retention, per-channel codec and native delivery credits. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-04] Reuse control/data tasks and one shared finite budget with cancellation-safe backpressure in full and paired-half modes. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-05] Test real authenticated UDP/genuine-QUIC loopback TAP/TUN traffic, body compression evidence, loss/reorder/repair, malformed profile, EOF/expiry and queued native WouldBlock. Evidence: [runtime](../../crates/l2tunnel-runtime/src/aligned.rs), [actual-carrier tests](../../crates/l2tunnel-runtime/src/aligned_tests.rs), [pure composition](../../crates/l2tunnel-aligned/src/lib.rs).
- [x] [MOD-ALIGNEDRT-06] Run strict focused checks plus every prior UDP/QUIC regression and a coordinated stable aggregate. Evidence: [wave6 receipt](../../work/implementation-wave6/validation.json), 492 Rust cases including doctests and 36 Python cases with identical before/after source hashes; CLI/native OS qualification is separate.
- [x] [MOD-ALIGNEDRT-07] Add explicit client configuration and owned native namespace/bridge/qdisc/packet-capture qualification before declaring native integration complete. Evidence: [client design and checks](aligned-client.md), [18-case native audit](../../work/native-aligned-matrix-audit.json), [UDP receipt](../../work/native-aligned-udp-matrix/receipt.json), [QUIC receipt](../../work/native-aligned-quic-matrix/receipt.json).
- [ ] [MOD-ALIGNEDRT-08] Integrate negotiated mode switching, connection-round-robin arbitration, actual timed packing and unordered early-short recovery before enabling their catalog gates.

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
