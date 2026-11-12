# Standalone native distributed quiescence

Status: carrier and additive device adapter locally integration-tested. Existing
`openvpn::run` still returns
explicit incomplete/error outcomes on cancellation or carrier termination. The
[wave9 aggregate](../../work/implementation-wave9/validation.json) includes this
new protocol and the focused checkpoint below. The separately bounded native
outage
[observations](openvpn-native.md#finite-outcome-checkpoint) do not prove clean
native shutdown. No new native run is authorized by this checkpoint. The additive [client/CLI selection](openvpn-drain-client.md) now has local
integration evidence, including an unresolved historical timing observation.
Privileged native clean-drain qualification remains a separate unimplemented gate.

## Existing ownership and the missing seam

The [device adapter](../../crates/l2tunnel-runtime/src/openvpn.rs) owns one native
fragment batch, one pending source handoff, one source reader, one reassembly and
a bounded native queue. Carrier `send` completion means recovery admission;
carrier `receive` releases its application permit before the native device write.
Its sampled observer fields are not authoritative shutdown inventory.

The retained [TLS actor](../../crates/l2tunnel-openvpn/src/heartbeat.rs) already
owns authenticated session/role/sequence framing, heartbeat, Close/Drained/Ack
and TLS shutdown. The [UDP driver](../../crates/l2tunnel-openvpn/src/driver.rs)
already owns both recovery engines, the only socket reader, common allowance and
actual output drain. Existing [Control::close](../../crates/l2tunnel-openvpn/src/runtime.rs)
and [PairControl::close](../../crates/l2tunnel-openvpn/src/pair.rs) preserve task
ownership and their original carrier deadlines. They must remain those owners.

What is missing is a separately negotiated, typed upper-layer fence capability
on that same TLS actor, plus authoritative source admission/receive seals. Calling
the existing carrier close early freezes source admission before retained native
fragments finish. Calling it after an empty sampled queue cannot prove remote
native delivery. A second TLS reader, socket receiver, ARQ instance, arbitrary
exporter assertion or sleep-based empty-queue guess is not the solution.

## Additive capability and exact binding

Keep the ordinary public factories, `Config`, OVC1 bytes and legacy digest vectors
unchanged. The additive wrappers have private fields and checked constructors:

```rust
pub struct NativeDrainConfig { /* checked Config + drain duration/profile */ }
impl NativeDrainConfig {
    pub fn new(carrier: Config, drain_timeout: Duration) -> Result<Self, Error>;
    pub fn session_config(&self) -> Result<SessionConfig, Error>;
}
pub struct NativeCarrier { /* actual verified full capability */ }
pub struct NativePairedCarrier { /* actual verified joined capability */ }
pub async fn client_connect_native(/* socket, NativeDrainConfig, credentials */)
    -> Result<NativeCarrier, Error>;
pub async fn server_accept_native(/* same typed policy, server credentials */)
    -> Result<NativeCarrier, Error>;
pub async fn client_pair_native(/* two sockets/configs, existing pair credentials */)
    -> Result<NativePairedCarrier, Error>;
pub async fn server_pair_native(/* matching two-lane inputs */)
    -> Result<NativePairedCarrier, Error>;
```

The new domain binds the original complete carrier policy, new control version,
fixed frame/slot/work bounds and positive drain duration (1 ms through 120 s).
The device layer additionally binds every existing `DeviceConfig` field and this
drain duration. The wrappers cannot be made from caller-provided session IDs or
exporters. Their internal factories retain the genuine verified TLS objects and
existing admission, lease, counter, key, recovery and pairing state. A legacy
capability cannot be converted into a native-drain capability after authentication.

Full mode derives its logical control scope with maintained SHA-256 over a new
domain and actual accepted session/config/member/server identifiers. Paired mode
uses the actual joined `PairInfo.digest`, which already binds both actual sessions,
directions/configs and identities. Only the canonical first TLS lane transports
native control; it remains full duplex regardless of that lane's bulk direction.
Both lanes use the new negotiated fixed framing. Native kinds on the inactive
management lane fail closed. Private pair preparation installs the common domain
and correct send/receive lane references before either heartbeat actor is enabled.

## Typed control seam and fixed wire

Carrier APIs transfer the original owners, not an unbounded message bus:

```rust
NativeCarrier::split(self) -> (NativeControl, PacketSender, PacketReceiver);
NativePairedCarrier::split(self)
    -> (NativePairControl, PacketSender, PacketReceiver);

pub struct SourceFence { /* private scope + source count/byte prefix */ }
pub struct NativeFence {
    pub packets: u64,
    pub native_bytes: u64,
    pub sources: u64,
    pub source_bytes: u64,
}
pub struct PeerFence { /* private authenticated scope + NativeFence */ }

NativeControl::request_stop(&self) -> Result<(), Error>;
NativeControl::state(&self) -> Result<NativeControlState, Error>;
NativeControl::changed(&mut self) -> Result<NativeControlState, Error>;
NativeControl::seal_send(&self) -> Result<SourceFence, Error>;
NativeControl::publish_fence(&self, native_packets: u64, native_bytes: u64,
    sources: &SourceFence) -> Result<(), Error>;
NativeControl::ack_peer_native(&self, peer: &PeerFence) -> Result<(), Error>;
NativeControl::close(self) -> Result<CloseReceipt, Error>;
// NativePairControl exposes the same logical operations and two close receipts.
```

`state` is bounded scalar/watch state: first request arrival, local/peer phases,
one exact local and peer fence, acknowledgments and actual TLS flush watermarks.
It is not a queue that can discard an early stop behind native pressure. Repeating
the same local operation is idempotent; changing a published fence is an error.
`SourceFence` and `PeerFence` have no public constructors. The carrier authenticates
the latter and verifies its source-related constraints. It does not pretend to
inspect a TAP/TUN write: the native counters remain the adapter's responsibility.

OVC2 is exactly 112 bytes: magic/version at 0..4, kind at 4, sender role at
5, zero reserved 6..8, actual physical session 8..24, nonwrapping sequence 24..32,
heartbeat nonce 32..40, logical full/pair scope 40..72, four big-endian fence fields
72..104 and zero reserved 104..112. Existing heartbeat/carrier-close kinds keep
zero fence fields. New Request has zero nonce/fence; Fence and NativeAck carry
one exact `NativeFence` and zero nonce. Roles, scope, lengths, zero fields, sequence
and phase are validated before mutation. Request precedes Fence on the same TLS
stream. No extra retry protocol is added above reliable TLS-over-UDP control.

Use at most eight combined queued/current TLS frames in this new profile (896
plaintext bytes), one fixed receive frame and bounded phase snapshots. Existing
OVC1 stays at its current four frames. Mandatory native/close phases are serviced
before optional new pings; already owned output keeps its exact position until
flushed. Every resulting TLS datagram/retry still uses the existing control
reserve and common byte/packet allowance. Exact duplicate logical phases do not
create fresh slots or renew any deadline or inactivity timer. Altered duplicates,
wrong roles/scopes and counter overflow terminate explicitly.

## Authoritative source and native fences

All counters are checked cumulative prefixes from zero, not queue lengths:

| Counter | Exact transition |
| --- | --- |
| Native accepted packet/byte prefix | A valid native original has been read, encoded and its complete bounded fragment batch retained by the actor. |
| Source admitted packet/byte prefix | The existing carrier driver successfully submits a unique complete source to data recovery. Retries add nothing. |
| Source consumed packet/byte prefix | The original `PacketReceiver` actually copies that ordered source into adapter ownership. |
| Native completed packet/byte prefix | A whole ordered original is reassembled and validated. |
| Native confirmed packet/byte prefix | `PacketDevice::transmit` succeeds for that exact original; WouldBlock advances nothing. |

The actor's next native message ID equals its native accepted count. On stop it
freezes further native reads when it handles the local or authenticated remote
request. One already returned original remains accepted and must drain. Kernel
packets never read by this actor are outside the accepted prefix; this protocol
does not claim that endpoint applications stop generating traffic.

Finish the retained original's fragments and every outstanding send result.
`seal_send` then atomically rejects future submissions and mints the actual
source count/byte prefix only when every send reservation, queue and held
submission is accounted for. A concurrent reserved `PacketSender` cannot enqueue
after the seal: the same serialization used by ordinary close checks the seal.
The actor compares the minted source prefix with its own successful handoffs,
then publishes its native count/bytes and that exact source fence. No rollback or
reopening is possible after sealing.

Authenticated peer Fence installs a receive source ceiling on the actual bulk
receive lane. A bounded scalar highest accepted source identity detects a fence
below an already accepted source. Future authenticated source IDs at or beyond
the exclusive ceiling fail; duplicates below it remain the existing recovery's
responsibility. The current standalone profile uses selective-repeat only. The driver checks
the ceiling while recording successful source admission and again at ordered
delivery; a future FEC adapter must use the same acceptance gate for restored IDs
before it can claim this profile. No standalone FEC mode is implemented. Thus
a TLS fence cannot race a source between preflight and recovery mutation. No
second payload ledger or unbounded source-ID set is introduced. The source-byte
prefix is checked again at exact ordered consumption. Pending data below the
ceiling continues normally when a TLS fence arrives before that data.

The adapter may acknowledge `PeerFence` only when its consumed source count and
bytes equal the fence, its completed and successfully transmitted native count
and bytes equal the fence, and no reader handoff, incomplete reassembly or native
original remains owned. Equality is exact, never `>=`; overshoot/mismatched bytes
are terminal protocol errors. The carrier independently verifies source equality
when accepting this trusted adapter acknowledgment. It does not label carrier
application receive as native delivery.

Before clean carrier close, both sides must have sealed/published their own
fence, received an exact peer native acknowledgment, confirmed/acknowledged the
peer fence, and flushed their own typed controls through the retained TLS writer.
A management-lane Close received before these native proofs is invalid. The
secondary paired lane is independent and can overtake the peer's management-lane
NativeAck. It retains at most one pending Close under the already-started native
deadline, without activating carrier close, sending Drained, or claiming native
proof. Once the ordered management proof arrives, it activates that retained
Close. Exact repeats add no deadline or state; absence of proof still expires.
The existing carrier's Close/Drained/Ack, real recovery/socket drain, TLS EOF and
quiet interval still run afterward. Local ACK flush notification may lag peer
receipt; state ordering must tolerate that benign race while keeping TLS output
owned until actual flush. No close success is derived from an observer snapshot.

## Runtime API, deadline and cancellation

The additive `openvpn::drain` device API leaves legacy `run` behavior unchanged:

```rust
pub struct DrainConfig { pub device: DeviceConfig, pub drain_timeout: Duration }
pub struct DrainingLink { /* NativeControl or NativePairControl + original handles */ }
pub struct ShutdownRequest { /* one-shot producer, timestamp generated internally */ }
pub struct ShutdownSignal { /* one-shot consumer */ }
pub fn shutdown_request() -> (ShutdownRequest, ShutdownSignal);
impl ShutdownRequest { pub fn request(self) -> std::io::Result<()>; }
pub async fn run_draining<D: PacketDevice<Error = io::Error>>(
    device: D, link: DrainingLink, config: DrainConfig, stop: ShutdownSignal,
) -> Result<NativeDrainReceipt, NativeDrainError>;
```

The request records `Instant::now()` before signaling. The TLS control owner
records a first authenticated remote Request immediately, independently of a
blocked native queue. The actor's deadline is the earliest local request timestamp
or remote receipt timestamp plus the negotiated duration. Later observations can
only shorten that deadline; duplicate requests, progress, packet retries and
switching to carrier close never extend it. Checked overflow is an error. Earlier
carrier inactivity, lease/key-use exhaustion or an already initiated carrier close
can still fail the operation sooner.

The new adapter uses one actor owning the original `PacketReceiver` directly
and one pinned, retained source-send future. There are no spawned adapter reader
or writer tasks and no adapter joins to infer. Cancellation of a receive wait
retains the receiver's pending packet; a selected source send remains owned until
its actual admission result. Once both native proofs are complete, the future
has finished and both original handles remain owned while existing carrier
close runs. This is necessary because dropping the receiver prematurely
currently closes the driver's application handoff. The source ceiling prevents
an unseen post-fence source from being accepted during this transition. A queued
reader value prevents this step and must first be accounted for, never discarded.

The existing consuming `close()` futures can be wrapped with `timeout_at` using
the original native deadline; they already retain every carrier task handle.
Both native carrier close wrappers also explicitly check time before and after
the inner close: timeout_at alone can poll an already-ready inner future after
its deadline. An already-clean inner carrier cannot produce a late native success.
No new public arbitrary-deadline or exporter API is required. Full/paired carrier
close and all existing carrier task joins share the remaining original native allowance;
the legacy fresh `task_shutdown_timeout` must not add time to this path. On expiry
or cancellation, abort/drop every owned task and original control owner and return
an explicit incomplete/error outcome. No post-deadline join or cancellation is
reported as a clean close. Dropping an unsent ShutdownRequest is cancellation,
not an implicit successful drain request.

`NativeDrainReceipt` is produced only after exact local/peer fences, actual native
confirmation, the completed pinned send, retained original receiver and original full/paired carrier clean
receipts. Include both four-field fences, confirmed counts/bytes, typed-control
flush completion, carrier receipts and lane count. This proves the accepted
native prefixes reached the devices and the maintained carrier closed within
its finite model; it does not prove arbitrary-loss peer shutdown or consumption
by applications above those devices.

## Implementation order and test matrix

Ownership proposal: new `l2tunnel-openvpn` native-control module plus narrow
runtime/heartbeat/driver/pair/config integration; new device drain module beside
`openvpn.rs`; owned module documents. Shared client/CLI selection and native
signals remain later coordinated gates. No root codec/proxy or shared Cargo
changes are needed for this design checkpoint.

- [x] [MOD-OVPNDRAIN-01] Inspect existing ownership and specify additive capability, exact source/native fences and one original deadline before implementation. Evidence: [missing seam](#existing-ownership-and-the-missing-seam), [source and native fences](#authoritative-source-and-native-fences), [deadline contract](#runtime-api-deadline-and-cancellation).
- [x] [MOD-OVPNDRAIN-02] Review and freeze exact wrapper/API/frame geometry, legacy-byte compatibility and paired logical-scope wiring. Evidence: [approved additive contract](#additive-capability-and-exact-binding), [exact framing](#typed-control-seam-and-fixed-wire).
- [ ] [MOD-OVPNDRAIN-03] Implement fixed control parsing/state with wrong length/role/scope/sequence/reserved fields, altered duplicates, counter overflow, bounded output and canceled-owner tests.
- [ ] [MOD-OVPNDRAIN-04] Implement authoritative send seal, count/byte prefixes and receive ceiling; test reserved-send races, barrier-before-data, preaccepted beyond-fence sources, duplicates and extra post-fence data.
- [x] [MOD-OVPNDRAIN-05] Integrate genuine full and paired control capabilities with existing TLS/recovery/budget/quiet owners and preserve legacy factory bytes/domains. Evidence: [actual full/paired native tests](../../crates/l2tunnel-openvpn/src/native/tests.rs), [OVC1 byte regression](../../crates/l2tunnel-openvpn/src/heartbeat.rs), [unchanged legacy configuration domain](../../crates/l2tunnel-openvpn/src/config.rs).
- [x] [MOD-OVPNDRAIN-06] Implement native accepted/complete/confirmed counters, exact empty-owner proof and retained-handle transition using one actor; test WouldBlock and a stopped, still-draining multi-fragment original. Evidence: [direct actor](../../crates/l2tunnel-runtime/src/openvpn/drain.rs), [blocked native and 32 KB drain tests](../../crates/l2tunnel-runtime/src/openvpn/drain/tests.rs).
- [x] [MOD-OVPNDRAIN-07] Test zero-packet, one-sided and simultaneous stop in both duplex modes, TAP/TUN and None/LZ4 with byte-exact mock-device native receipts over actual TLS/UDP. Evidence: [seven focused device tests](../../crates/l2tunnel-runtime/src/openvpn/drain/tests.rs).
- [ ] [MOD-OVPNDRAIN-08] Test peer-only stop while local native output is blocked, missing/mismatched fences/acks, early carrier EOF, ACK-flush ordering, timeout/cancellation during every phase and no deadline restart during joins.
- [x] [MOD-OVPNDRAIN-09] Run strict focused checks and coordinated workspace aggregate, retaining all failures and finite evidence limits. Evidence: [focused commands](#focused-implementation-checkpoint), [stable wave9 aggregate](../../work/implementation-wave9/validation.json); no CLI or privileged native-drain qualification is implied.
- [ ] [MOD-OVPNDRAIN-10] Separately review client typed shutdown selection and owned native clean-close evidence; keep outage tests and broader carrier matrix independent.


## Focused implementation checkpoint

The carrier exposes `NativeDrainConfig`, `NativeCarrier`, `NativePairedCarrier`,
`NativeControl`, `NativePairControl`, `NativeControlState`, `SourceFence`,
`PeerFence` and four native-profile authentication factories. `Error::Busy`
explicitly means retained send reservations or exact native proofs are not ready.
No legacy capability conversion exists. Existing Config/domain code is unchanged;
OVC1's exact 80-byte writer is covered alongside strict 112-byte OVC2 parsing.

`openvpn::drain::{DrainConfig, DrainingLink, shutdown_request, run_draining}` is
additive. The device actor owns both original packet handles, one pinned send
future, one native fragment batch, one reassembly and the configured native
queue. It subscribes to actual control changes independently of native pressure.
After the peer source ceiling is consumed, it stops source reads but keeps the
receiver alive through carrier close. Local request time is generated by the
one-shot producer; an explicit timer and the outer close timeout use the earliest
original deadline. There are no spawned adapter tasks or fresh post-error join
allowances. `NativeDrainError.progress` records exact actor event counters and
retained ownership; an in-flight source admission is explicitly marked unknown
until its result is observed. It is not called a final carrier ledger.

Commands executed for this checkpoint:

- `cargo test -p l2tunnel-openvpn --offline`: 46 tests passed, including all legacy
  tests and new real-TLS full/paired native-control paths.
- `cargo test -p l2tunnel-runtime --offline openvpn::drain`: seven tests passed;
  this includes eight layer/duplex/codec combinations, zero/peer-only/simultaneous
  stop, retained 32 KB fragmented input, actual native WouldBlock with reverse
  progress, original-deadline expiry, canceled producer, stale local timestamp and
  ready-timer starvation (1 us poll with at least 10 us bounded device service).
- `cargo clippy -p l2tunnel-openvpn -p l2tunnel-runtime --all-targets --offline -- -D warnings`: passed.
- `RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-openvpn -p l2tunnel-runtime --no-deps --offline`: passed.
- `python3 tools/check_checklists.py`: passed. The coordinated
  [wave9 aggregate](../../work/implementation-wave9/validation.json) passed with
  identical before/after source hashes; no native-device or CLI clean-close claim is made.

- [x] [MOD-OVPNDRAIN-03A] Test strict frame geometry, roles/scopes/reserved fields, zero-field policy, bounded output and writer sequence exhaustion, plus phase duplicate/alteration and failed-owner notifications. Evidence: [frame tests](../../crates/l2tunnel-openvpn/src/heartbeat.rs), [phase/terminal tests](../../crates/l2tunnel-openvpn/src/native/tests.rs).
- [x] [MOD-OVPNDRAIN-04A] Test reserved-capacity seal rejection, no enqueue after seal, barrier-before-data, preaccepted tail rejection and exact source-byte acknowledgment; reject consumption without changing caller output or retained bytes. Evidence: [source tests](../../crates/l2tunnel-openvpn/src/runtime.rs), [fence tests](../../crates/l2tunnel-openvpn/src/native/tests.rs).

The broader MOD-OVPNDRAIN-03/04/08 failure matrix remains open: exhaustive ingress
sequence/phase injection, deterministic every-boundary races, malicious extra
post-fence authenticated sources and cancellation at every close/join phase are
not inferred from these finite tests. The current profile has no FEC decoder.

- [x] [MOD-OVPNDRAIN-09A] Run focused carrier/device tests, strict Clippy and rustdoc, and checklist validation for this local checkpoint. Evidence: [executed commands and finite scope](#focused-implementation-checkpoint).


The paired ordering regression starts close only on the currently-ready server,
then physically drops its management-lane TLS datagrams while allowing secondary
lane traffic. It observes `secondary_close_pending` on the still-unready client
and verifies its secondary carrier has not begun closing. Releasing the primary
path completes both carriers; leaving it blocked produces an incomplete result
within the original native deadline. This is a real two-lane TLS/UDP test using a
bounded test-only packet drop gate, not synchronized readiness or synthetic peer
state. Additional regressions cover a clean lane with a pending logical phase
(no repeated ready wake), failed terminals present before or arriving during a wait, and
calling native close after its inner carrier is already clean but the original
native deadline has expired.

- [x] [MOD-OVPNDRAIN-08A] Test secondary Close overtaking a delayed primary native ACK with only one ready peer, retained-close expiry, already-Clean lane waiting, and expired native close after an inner clean carrier. Evidence: [genuine paired skew and deadline tests](../../crates/l2tunnel-openvpn/src/native/tests.rs), [bounded deferred-close owner](../../crates/l2tunnel-openvpn/src/heartbeat.rs).
