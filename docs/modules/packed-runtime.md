# Authenticated packed runtime composition

Status: required v2 native identity/byte-budget integration is implemented and
locally integration-tested with [the source27e aggregate](../../work/implementation-wave27e/validation.json). The historical v1 [wave11](../../work/implementation-wave11/validation.json)
remains valid for its stated nine packed tests and ordinary aligned regressions;
it does not qualify changed v2 authentication/control or native performance.
The [pure composition](packed-recovery.md) and one shared aligned actor retain
actual codec, recovery, common MUX/QoS and carrier owners. Native v2 qualification,
clean distributed drain and full Python composition remain open.

## Public configuration and authenticated capabilities

`l2tunnel_runtime::packed` provides the following checked public surface:

```rust
pub struct Options {
    pub hold_micros: u64, // 1..=1000, original first-unit deadline
    pub max_units: u8,   // 1..=255, further limited by physical MTU
    pub work_limit: usize, // 1..=255
}
pub struct Config {
    pub delivery: managed::DeliveryConfig, // required canonical forward/reverse policies
    pub protocol: l2tunnel_aligned::packed::Config,
    pub pipeline: l2tunnel_pipeline::PipelineConfig,
}
impl Config {
    pub fn for_udp(runtime: RuntimeConfig, transport: udp::Config,
        channels: u16, options: Options, delivery: managed::DeliveryConfig) -> io::Result<Self>;
    pub fn for_quic(runtime: RuntimeConfig, transport: quic::Config,
        channels: u16, options: Options, delivery: managed::DeliveryConfig) -> io::Result<Self>;
}
// Mirror existing aligned helpers with the new Config and distinct link types:
// udp_base_session_config, udp_session_config, udp_carrier_config,
// quic_base_session_config, quic_session_config,
// UdpLink::full, udp_client_pair, udp_server_pair,
// QuicLink::full, quic_client_pair, quic_server_pair,
// run_udp, run_quic.
```

The new runtime digest uses its own fixed version/domain and the complete packed
protocol digest, complete pipeline policy and existing carrier/native base. Every
lane authenticates that digest before native reads. Actual full/paired links
retain the genuine carrier objects and pair proofs; ordinary aligned links cannot
be relabeled as packed. Both peers must select identical packing geometry/time.
The required v2 delivery policy binds every canonical forward/reverse field under
`l2tunnel/packed-runtime/v2/common-mux-crc32/native-identity-credit-v2`, with the
shared delivery subdomain. Ordinary aligned and packed remain distinct; both
explicit v2 profiles reject historical scalar-credit authentication. Existing
base frame/fragment mode digests stay unchanged.

The fixed packed control magic is `L2P2`; it reuses the same strict control parser
and actual TLS/QUIC owner. Recovery ACK and heartbeat retain their bounded forms;
exact native receipts use9 bytes (channel u8 and absolute native body RecordId u64). It is
not a second management protocol, reader or retry layer. The first slice requires
explicit Cauchy recovery, compression off, CRC MUX, TAP system policy or transparent
TUN DRR, just like the qualified aligned profile. Early-short gap bypass, active
TCP proxy, hot mode switching and standalone OpenVPN-like UDP remain separate.

## One shared runtime actor

Refactor only private aligned runtime wiring to select ordinary or packed endpoint
ownership. Use one private enum with bounded boxed concrete endpoint owners and
shared method forwarding. Share native validation, carrier tasks, retained output,
credit counters, native confirmation, channel service, task cancellation and
shared budget accounting. Do not fork the 700-line actor or copy recovery logic.

Ordinary configuration helpers remain wrappers around their original selection;
packed helpers pass the explicit new selection. Common validation must invoke the
selected protocol validator before allocating tasks or reading a device. A packed
base has different source geometry and must never accidentally pass through the
ordinary envelope validator or silently fall back after an error.

Native admission remains after common pipeline classification and MUX/QoS. A frame
increments native admission once only after the selected endpoint retains it.
Busy preserves the exact selected frame. Neither packed unit count nor recovery
source count is native credit. A native identity is acknowledged only after successful whole
`PacketDevice::transmit`; WouldBlock retains the same frame and byte charge.
Exact receipt ownership is reserved in a bounded queue before device I/O, and no
watch coalescing discards identities. Native receipts resolve only the original
sender-owned body ledger; neither contexts nor peer-supplied byte counts create
credit. Selective per-record completion preserves independent channel delivery.
All sources, repairs, retries and TLS feedback use the existing shared allowance,
including actual carrier overhead. No extra probe lane or new sender bypass exists.

## Geometry and bounded progress

Let `S` be the existing carrier's maximum original recovery source bytes and `N`
the negotiated maximum packed units. Derive `symbol_bytes = S - 56 - 8*N` with
checked arithmetic and validate the resulting body/envelope geometry. This keeps
the existing ARQ/FEC/physical packet ceilings exact instead of increasing MTU to
fit metadata. Reject options that leave insufficient symbol space before I/O.

Derive fragment count from the actual maximum encoded native body and symbol
fragment capacity. Preserve the ordinary native queue bounds and additionally
reserve at least `N` lookahead record slots, `N * maximum_declared_record_bytes`
lookahead bytes and `N * max_fragments_per_record` fragment slots. Source/unit
window is at least `N`; existing carrier source windows retain their separate
limits. Record window must also admit a complete legal batch. The pure packed
validator proves this cross-module geometry and bounds preflight storage.

For the packed selection only, service bounded native/pipeline ingress and
admission bursts. Each burst is limited by negotiated `work_limit`, native queue,
the authenticated byte/record flight target and codec staging. A burst must use the same arbiter
as every other user packet. This allows already queued small frames to actually
share a source; merely polling one frame per millisecond would defeat submillisecond
packing. Keep an immutable retained ingress/selected frame on admission pressure.
Ordinary profile scheduling remains unchanged.

Each bounded iteration can perform ingress and common-arbiter admission together;
otherwise one frame per outer ticker would remain an accidental throughput limit.
Sample fresh elapsed monotonic time before each enqueue/service operation. A long
burst must not keep admitting units against one stale time sampled before the
original packing deadline. Crossing that deadline seals the old source normally.

## Native first-flight ownership independent of local queues

The shared aligned actor uses the existing pure delivery controller, including
selective exact-record delivery/send APIs. Local Pipeline queues stay unchanged;
encoded receive storage and source/recovery windows remain separate bounded
owners. Receiver native counts and its one prepared frame are checked against the
incoming hard policy, with separate finite encoded lookahead limits. Sender
identity entries, per-native fragment bitmaps and the controller's retained span
fit the explicit metadata allocation budget; an ACK cannot reclaim metadata still
waiting for an original send callback.

The pure sender returns the native body identity before packed polling can
consume its units. Maintained recovery/envelope parsers expose typed original-unit
witnesses, including every native sharing one physical source. The datagram writer
reserves bounded callback capacity before actual send and records its original
successful-send Instant. Only all original fragment bits confirm a native first
flight; one later/final unit cannot imply earlier parts were sent. Retries preserve
first successful times, failed sends publish no confirmation, and an early ACK
never creates a later retrospective sample. Original admission-to-send deadlines
remain terminal, alongside unchanged packing/recovery/reassembly deadlines. No
native FIFO reorder is imposed to fit cumulative-prefix accounting.

## Original microsecond deadline and timer service

Use elapsed `Duration` from the actor's existing monotonic start. The pure codec
alone owns the checked first-unit microsecond deadline; later frames, timer polls,
native pressure and output stalls cannot renew it. Add a timer wake for an
unsealed packed source's original deadline alongside the existing native polling,
carrier/task/control/data events. Once sealed, a past packing deadline is retained
as ownership evidence but must not create a CPU busy loop while recovery is full.
No newly selected timer may replace an earlier codec/receiver failure deadline.
Derive this additional unsealed-packing wake from the packing status separately.
Do not clamp or skip the entire pure `Endpoint::deadline()` when its minimum is a
sealed past packing deadline: doing so can hide an earlier independent receiver,
handoff or recovery obligation. Preserve existing service of those obligations,
or add a separately reviewed actionable-deadline helper that excludes only sealed
packing while retaining every other original deadline.

Runtime timers can wake late because of executor/OS scheduling. Record this as
service latency; do not claim hard real-time microsecond transmission. Pure tests
prove exact deadline semantics. Async tests prove an idle partial source is
eventually serviced without a later user packet, full output pressure does not
discard it, and repeated service cannot reset the original deadline.

The actor still has no successful distributed native-drain API. Cancellation or
carrier failure retains the existing explicit error/cancellation outcome and
aborts/joins owned tasks. A packed `flush` is a local source seal, not a peer native
delivery barrier or a clean TLS shutdown receipt.

## Checklist and acceptance

The checked original items describe historical v1 deliverables. Their saved
receipts do not close the new FIX-01 v2 actor/native gate below.


- [x] [MOD-PACKRUN-01] Independently review configuration, geometry, shared actor ownership, bounded burst admission and original-deadline wake before implementation. Evidence: [shared actor contract](#one-shared-runtime-actor), [fresh per-operation time and geometry](#geometry-and-bounded-progress), [separate packing wake and unchanged failure deadlines](#original-microsecond-deadline-and-timer-service).
- [x] [MOD-PACKRUN-02] Implement distinct typed UDP/QUIC packed bindings and exact policy digest, preserving a pinned ordinary aligned runtime digest and failure-before-native-read behavior. Evidence: [typed factories and digest (retired in Common cutover)](compact-wire-cleanup.md), [configuration and actual-link rejection tests (retired in Common cutover)](compact-wire-cleanup.md), [pinned ordinary digest (retired in Common cutover)](compact-wire-cleanup.md).
- [x] [MOD-PACKRUN-03] Integrate the existing packed endpoint into the shared actor, with bounded common MUX bursts, exact native credits, retained output and non-spinning timer service. Evidence: [shared actor (retired in Common cutover)](compact-wire-cleanup.md), [private endpoint selection (retired in Common cutover)](compact-wire-cleanup.md), [deterministic timer/pressure tests (retired in Common cutover)](compact-wire-cleanup.md).
- [x] [MOD-PACKRUN-04] Test actual authenticated full/paired UDP and genuine QUIC with injected TAP/TUN endpoints, both directions, small/context/fragment/zero-tail bytes, and inspect actual packed envelopes. Evidence: [real carrier matrix and envelope observations (retired in Common cutover)](compact-wire-cleanup.md); 16 protected UDP combinations and four genuine QUIC combinations passed within the nine-test focused run.
- [x] [MOD-PACKRUN-05] Test mismatched bound runtime policies, attempted ordinary-link reuse, loss/reorder/repair, blocked native/output, idle partial flush, a burst crossing its original deadline, sealed-pressure/no-spin with earlier receiver expiry, finite failure and cancellation; no false clean result or renewed deadline. Evidence: [seven geometry/real-carrier/failure tests (retired in Common cutover)](compact-wire-cleanup.md), [two injected-carrier timer tests (retired in Common cutover)](compact-wire-cleanup.md); all nine passed, with unchanged six ordinary runtime regressions passing.
- [x] [MOD-PACKRUN-06] Independently review ownership and run all ordinary runtime regressions, focused strict lint/docs and a stable workspace aggregate. Evidence: independent shared-owner and original-deadline review, [ordinary runtime regressions (retired in Common cutover)](compact-wire-cleanup.md), [wave11](../../work/implementation-wave11/validation.json) with all nine packed runtime tests and unchanged source hashes.
- [ ] [MOD-PACKRUN-07] Add [shared client/CLI configuration](packed-client.md) and separately scoped native qualification before claiming packed mode deployment or Python catalog parity.
- [ ] [MOD-PACKRUN-08] Complete [FIX-01](../implementation-checklist.md) required authenticated v2 byte/record flight budgets, native identities and all-part original-send accounting through the one actor; pass strict aggregate and separately qualify native v2 behavior. Evidence: focused work in progress under [delivery evidence](../../work/aligned-delivery27/), with [pure selective receipt](../../work/aligned-delivery27/pure-validation.json). Native throughput is unqualified.

The integrator owns this shared aligned actor change, new packed runtime module,
tests and public module registration. Workers must wait for the reviewed API
checkpoint before implementing client selection. No root dependency change is
needed; all underlying codec/recovery/carrier owners already exist.

## Focused evidence and remaining limits

The real-carrier matrices perform actual authentication and preserve bidirectional
native bytes with injected loss, reorder and native WouldBlock. Cleartext integrity
mode additionally permits inspection of actual multi-unit packed sources and
context/predictive envelopes. Genuine QUIC uses its real UDP connections; these
local fixtures do not prove a privileged TCP-blocked network or native TAP/TUN
drivers. An ordinary authenticated UDP carrier is rejected by packed construction.

The two paused-clock tests inject carrier traits without authentication and are
only timer/ownership evidence. A one-source FEC block isolates the packing wake
from the independent FEC partial-block flush timer. The pressure fixture binds its
injected peer to the single common MUX channel, retains blocked physical output,
observes actual native transmission attempts, and checks that a sealed past
packing deadline cannot spin or hide the original receiver expiry. Earlier fixture
failures came from combining the separate FEC flush deadline, invalid recovery
lifetime geometry and a mismatched injected channel; no production validator,
deadline or policy was relaxed to make the test pass.

The added wake services only an unsealed packing deadline. Independent recovery,
handoff and receiver deadlines retain the ordinary ticker/I/O service contract;
this change does not introduce a universal earliest-deadline timer. The test-only
Tokio `test-util` feature provides paused time. Production timing still has OS and
executor latency, and successful cancellation is never a clean native-drain proof.


## Required v2 delivery evidence (FIX-01)

The current focused packed actor passes11 tests and shares the six ledger/parser/
writer regressions in aligned. New real authenticated UDP/QUIC full/half TAP/TUN
cases keep local queues at two while reserving exactly80 native records/61600
bytes in each direction. Each blocked-device phase witnesses actual WouldBlock
and more than64 complete original native sends. After device release, all80
frames and their exact identities are delivered, per-flow FIFO is checked, and
all send/delivery metadata must be released. The source256 pure fixture separately
packs two actual80/40-byte bodies into one source and delivers the later channel
first without confusing their sender-owned identities. The1500/40 exact byte
release case remains in the shared controller/runtime ledger regressions.

Failure lineage is retained. The new initial128-record fixture demanded every
record's first send before a newly chosen3s observation bound; the healthy packed
actor had116 admitted and95–96 fully sent records at that cutoff. An80-record
variant also reached exact debt with76/80 complete sends on one QUIC side. The
final condition requires the stated >64 complete sends while blocked and all
original records fully confirmed after release. Original3s observation,5s native
lifetime,10s first-send policy, transport budgets and576-byte UDP MTU are unchanged;
no production deadline or geometry was raised. These receipts qualify bounded
flight separation, not throughput. The failed large-symbol pure fixtures were
corrected to ordinary geometry; no protocol maximum was relaxed. Exact logs are
preserved under [delivery work](../../work/aligned-delivery27/). The combined
frozen aggregate and separate native v2 gate remain open.
