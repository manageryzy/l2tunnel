# Raw Seal prerequisites: typed pairing and exporter ownership

Status: implemented production prerequisite with focused real TLS/owner tests;
coordinated aggregate evidence remains a separate gate. The wave 13/build 13
release authorized typed, from-birth raw lane pairing and retained exporter
ownership. Actual Seal remains blocked on authenticated all-lane Armed
and installed ingress classification/quarantine. There is no `FrozenTls`, Seal
factory, `request_handoff` call, packet-phase selector or native experiment in
this checkpoint. Retained TCP/TLS remains the default.

This narrows the next step after [the exclusive TLS owner](raw-tls-owner.md).
The larger [transition contract](raw-tls-transition.md) requires both peers to
prove all-lane Armed **before either sends a terminal Seal**. A caller-supplied
transcript, empty-state boolean or private fixture constructor cannot substitute
for that authority. A private production Seal type with no legitimate constructor
would not be an implemented protocol. Existing real TLS feasibility and owner
regressions already preserve the relevant terminal counterexamples; another
fixture-only terminal prototype is not the next production prerequisite.

## Existing interfaces and missing ownership

The current `runtime::client_pair/server_pair` check member/server/configuration
compatibility, exchange a fresh TLS-protected token and return a type-erased Link.
That path consumes AuthenticatedIo, splits the TLS stream, and cannot preserve
this checkpoint's whole TLS object or original switch handle/driver relationship.
Its existing compatibility check also does not establish the new profile/local
role/ordered-lane authority. Reuse the ordering concept, not its Link constructor,
wire format or fresh ten-second timeout. Half mode orders lane 0 as client-to-server
bulk and lane 1 as server-to-client bulk; full mode has one bidirectional lane.

`auth::AuthenticatedIo::export_key` already uses maintained TLS exporters and
purpose/direction/lane separation. Its context includes the actual session ID,
member/server identities, native layer and configuration digest. Export the fixed
required roots immediately before the authenticated object is consumed into the
same concrete tokio-rustls stream. Public Copy SessionInfo is diagnostic metadata
and cannot create an exporter or ownership capability. The current ordinary
message setup consumes AuthenticatedIo immediately; a narrow private completion
path must retain the finite roots alongside the resulting original TLS owner.
No new public TLS accessor or arbitrary exporter label/context API is needed.

## Implemented runnable public boundary

Place the runtime adapter in `l2tunnel-raw-io::handoff::pairing`; no dependency on
`l2tunnel-runtime` is introduced. Keep existing ordinary bridges/message factories
and their authenticated digest unchanged. Reuse `l2tunnel_core::Duplex` rather
than create another mode enum. The following implemented APIs retain the reviewed ownership boundary.

```rust,ignore
pub struct RawInput<I: PacketIo> {
    pub config: l2tunnel_raw_tcp::Config,
    pub io: I,
}
pub enum RawInputs<I: PacketIo> {
    Full(RawInput<I>),
    Half { forward: RawInput<I>, reverse: RawInput<I> },
}
pub struct PairConfig {
    pub session: SessionConfig,
    pub messages: MessageLimits,
    pub driver: SwitchLimits,
    pub timeout: Duration,
}
pub enum PairLane { First, Second }
pub struct PairSetup<'a, I: PacketIo + Send + 'static>;
pub struct PairedRaw<I: PacketIo + Send + 'static>;
pub struct PairStartFailure<I: PacketIo> {
    pub inputs: Box<RawInputs<I>>,
    pub error: PairError,
}
pub struct PairInfo;   // actual ordered identities, roles, profile/transcript hashes
pub struct PairStatus; // bounded progress, original deadline, terminal cause

pub fn begin_pair_client<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>, tls: &'a ClientTls, verification_name: &'a str,
    member: &'a MemberKey, config: PairConfig,
) -> Result<PairSetup<'a, I>, PairStartFailure<I>>;
pub fn begin_pair_server<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>, tls: &'a ServerTls, allowed: &'a MemberAllowlist,
    config: PairConfig,
) -> Result<PairSetup<'a, I>, PairStartFailure<I>>;
// PairSetup implements Future<Output = Result<PairedRaw<I>, PairError>>.
impl<I: PacketIo + Send + 'static> PairedRaw<I> {
    pub fn info(&self) -> &PairInfo;
    pub fn status(&self) -> PairStatus;
    pub fn stage_message(&mut self, lane: PairLane, payload: &[u8])
        -> Result<(), PairError>;
    pub fn poll_progress(&mut self, cx: &mut Context<'_>)
        -> Poll<Result<(), PairError>>;
    pub fn message(&self, lane: PairLane) -> Option<&[u8]>;
    pub fn consume_message(&mut self, lane: PairLane) -> Result<(), PairError>;
    pub fn abort(self) -> PairAbortReport;
}
```

PairStartFailure boxes the exact unchanged original inputs to bound the error's
inline size. PairSetup also exposes `status() -> Option<PairStatus>` while it owns
the group; it returns None after successful ownership transfer. PairStatus retains
the original absolute deadline, actual message/record and bridge counters,
ResourceCharge, local paired flag and first fault. None of these copied fields
is transferable authority.

The post-pair methods service bounded ordinary bootstrap messages on the original
TLS lanes; they do not recognize or authorize protocol Seal. This is a usable
control owner for the later Prepare/Armed manager, not a native data runtime.
`poll_progress` fairly polls both retained drivers and at most one outgoing and
one incoming exact-message operation per present lane; a completed inbound slot
blocks further reads on that lane. It returns Ready after semantic counter/state
progress (elapsed-time-only changes are ignored), Pending with registered I/O/timer
wakes when stalled, and a sticky error on any terminal condition. Local invalid
lane, Busy, Payload and NoMessage rejection does not terminate the group or
refund lifetime reservations. Copied status never yields a stream, handle, key or physical
transfer capability. There is no AsyncRead/AsyncWrite implementation, arbitrary
lane adoption, re-pairing, stream split, reset or mutable inner accessor.

Factories receive the original owned PacketIo objects, not already-authenticated
lanes or independently supplied handles. They construct one or two fresh counted
bridges and their TLS owners as a single group. The client factory fixes raw/TLS
client role on both lanes; the server fixes raw/TLS server role. Bulk direction is
separate from handshake initiator role. The initial checkpoint supports the
current IPv4 switchable bridge; IPv6 expansion is a separate gate, not inferred
from the raw engine's broader IpConfig type.

## Construction, cancellation and original deadline

Capture one absolute deadline at factory entry, before constructing either lane.
The factory initially retains RawInputs untouched. Validate name, current runtime,
1 ms..=30 s timeout, exact duration units, input shape, both raw configurations,
equal shared geometry, symmetric message limits, checked resource charges below,
and driver bounds. Then construct **both** fallible prepared engines/bridge
allocations without attaching either original I/O object. A private PreparedBridge
contains the validated engine and allocated finite buffers but no PacketIo, TLS
future or polled task. Failure or elapsed deadline during this phase drops only
prepared state and returns PairStartFailure with the exact unchanged RawInputs.
The existing bridge constructor can delegate to the same private preparation;
its public behavior need not change.

The irreversible boundary is the single infallible ownership move attaching the
original inputs to all prepared bridges, after a final pre-attachment deadline
check. From that point onward, expiry, setup failure or cancellation drops the
whole group; it does **not** return reusable RawInputs, even if the first outer
poll has not yet occurred. The resulting PairSetup may therefore be returned
already expired if synchronous construction crossed the deadline; its first poll
reports terminal expiry before I/O. Fallible authentication setup after attachment
also belongs to this terminal path. There is no promise that every constructor
error after validation can recover original inputs. Allocation failure follows
the workspace/allocator behavior, not a fabricated recoverable out-of-memory API.

Timer-enabled Tokio remains the existing documented local runtime precondition;
there is no fabricated timer-enablement query or catch_unwind-based validation.
No socket syscall, driver poll or TLS poll occurs before group attachment.

PairSetup owns both authentication futures, whole completed lane owners, original
driver futures, exact message offsets, roots, phase and one nonce. Driver futures
are boxed and polled in place; no per-lane task is spawned or detached. A completed
first lane stays owned while the second is Pending. Borrow-cancelling a poll
preserves every future/offset/phase; it never restarts authentication or regenerates
the nonce. Dropping the one setup/paired owner synchronously drops every driver
future, original I/O owner, TLS object, handle and secret. No asynchronous cleanup
worker is abandoned. Tests that spawn the whole owner must still cancel and join
that enclosing task explicitly.

After irreversible attachment, any lane authentication/I/O/protocol failure terminates the
whole group; no successful sibling or unrelated owner is returned for adoption.
Any driver exit before explicit abort is terminal, including an unexpected Clean
or Handoff result; this owner never requests handoff. Failure retains diagnostic
actual progress and the first cause, then releases all group resources without
holding a bridge mutex across generic I/O destruction. Terminal release captures
message status, drops the original owners/drivers, then reads the retained private
bridge observers before removing them. The private paired driver publishes any
completed-but-not-yet-published I/O in Drop. Abort uses that same ordering, so a
bridge read completed immediately before YieldOnce or expiry is not lost from the
report. Generic I/O destruction never runs under the bridge mutex. Abort/drop does
not poll TLS shutdown, send a synthetic reset, or claim clean TCP close.

Use the same absolute deadline for authentication, pair messages and later
bootstrap messages. New lane factories receive the captured deadline internally,
not newly sampled independent timeouts. Check expiry before and after every ready
or pending operation and immediately before publishing paired success. Timer
Ready returns expiry immediately. Retained successful lanes and exporter work
cannot extend the deadline. The owner must continue receiving poll service while
in use; status alone cannot keep its drivers running.

## Actual identity and canonical pairing exchange

Before pairing, verify each lane's actual profile is TcpTls, negotiated TLS is
1.3 with the existing approved pinned ring suites, and its original observer and
switch handle identities match. Verify `peer_member == None` for a client owner
and `peer_member == Some(member)` for a server owner, consistently with the actual
TLS variant. Derive roles from the factory/actual object, never caller SessionInfo.
Half lanes require distinct original bridge identities and distinct actual
session IDs, with equal authenticated member/server identities.

### Exact canonical configuration encoding

All integers are unsigned big-endian with the widths below; no usize/native enum
representation, text rendering, padding or optional-field omission enters a hash.
A duration is accepted only when `subsec_nanos() % 1000 == 0`; checked conversion
to u64 microseconds must succeed. Sub-microsecond values are rejected, never
rounded. Existing integer raw millisecond fields are converted with checked
multiplication by 1000. Original timeout remains 1,000..=30,000,000 microseconds;
max_handoff_duration remains 1,000,000..=30,000,000 microseconds, subject to the
existing driver validation. Each actual stage uses the original absolute deadline,
not this encoded duration as a fresh interval.

The common profile digest is SHA-256 over these fields in this exact order:

| Order | Field | Encoding |
| --- | --- | --- |
| 1 | Domain | literal bytes `l2tunnel/raw-owned-pair/v1\0`, including final NUL |
| 2 | Version, layer, duplex, lane count, reserved | u16=1; u8 Ethernet=1/IP=2; u8 Full=1/Half=2; u8=1/2; three zero bytes |
| 3 | Base session configuration digest | exact 32 bytes |
| 4 | Raw mtu, send_bytes, receive_bytes, packet_slots | u32, u32, u32, u16 |
| 5 | Raw ack_delay, keepalive, idle_timeout | three u64 microsecond values, in that order |
| 6 | Driver work_limit, max_handoff_duration | u16, u64 microseconds |
| 7 | Original total timeout | u64 microseconds |
| 8 | Message max_payload, messages_per_direction, bytes_per_direction | u16, u16, u64 |
| 9 | Incoming wire_bytes/records, outgoing wire_bytes/records, record max_payload | u64, u64, u64, u64, u16; symmetric direction limits required |
| 10 | Envelope identity and header size | exact six bytes `L2RM\x01\0`, u16=8 |
| 11 | Pair magic/version and fixed sizes | four literal bytes `L2RP`, u8=1, u16=8 pair header, u16=244 payload, u16=236 transcript |
| 12 | Phase order | three u8 values Offer=1, Confirm=2, Accepted=3 |
| 13 | Two ordered lane slots | each: u8 lane ID, u8 bulk direction, u8 present, u8 reserved=0 |
| 14 | Resource policy version and retained/peak payload, fixed metadata ceilings | u16=1, u64=16,777,216, u64=20,971,520, u64=1,048,576 |
| 15 | Cooperative driver-turn policy version | u16=1 |

Slot 0 is `[0, 0, 1, 0]` for Full and `[0, 1, 1, 0]` for Half. Slot 1 is
`[0, 0, 0, 0]` for Full and `[1, 2, 1, 0]` for Half. Bulk codes are Full=0,
ClientToServer=1 and ServerToClient=2. The input variant determines count/duplex;
no contradictory independent caller count is accepted. Before hashing, both
half inputs must have identical values for **all** raw fields listed in rows 4
and 5. Both endpoints must agree on the complete common encoding. This first
profile does not negotiate asymmetric send/receive geometry. Each raw tuple and
seed is separately validated; local tuples, seeds, numeric socket marks and OS
handles are deliberately excluded from the shared bytes. Bind an outer adapter
policy kind in the supplied base session when applicable; this owner does not
verify unexposed OS mark policy.

For lane i, the private base digest passed to the existing message setup is
`SHA256("l2tunnel/raw-owned-pair-lane/v1\0" || common_digest || u8(i) ||
u8(bulk_direction))`; its layer is the validated base layer. The actual lane
SessionInfo.config is then exactly the existing `message_session_config` result
for that base and MessageLimits. This explicit nesting preserves the ordinary
message digest and binds every limit. The two half-lane authenticated digests
intentionally differ; compare each against its own factory result. Tests pin the
whole canonical preimage/digests and independently change every listed field,
including exact microsecond durations and rejected fractional durations.

Use one canonical 236-byte group transcript: version/duplex/count/reserved (4),
common pair profile digest (32), fresh server nonce (32), actual member (32),
actual server (32), then two ordered 52-byte lane slots. Each slot contains lane
ID/bulk direction/two reserved bytes (4), actual session ID (16) and actual lane
config digest (32). Full mode requires the absent second slot to be exactly zero.
Never sort sessions or substitute a peer-provided identity for an actual local
lane observation. Server generates the nonce once with ring SystemRandom after
all authentication succeeds; resuming the phase never regenerates it.

Pair records have an eight-byte fixed magic/version/kind/lane/reserved header plus
that exact transcript: 244 bytes of payload within the existing exact-message
envelope. Require payload capacity at least 244, at least three message slots and
at least 756 framed plaintext bytes per direction/lane before starting. All
traffic uses the existing nonresetting lifetime counters; actual reservations
and progress remain authoritative. Unknown kind/role/lane, wrong length/reserved,
wrong phase or transcript mismatch fails the group; no retry creates a new nonce.

1. Server sends and flushes Offer on **every** actual lane. Each includes the
   complete ordered group binding. Client checks every copy against its own
   actual lane owners and requires one identical canonical transcript.
2. Client sends and flushes Confirm with that exact binding on every lane. Server
   accepts only the expected phase on the matching physical lane and compares
   the complete transcript with its own immutable proposal.
3. Server sends and flushes Accepted on every lane. Client publishes paired success
   only after checking every Accepted; server publishes after every actual flush.
   Final ready checks preserve the original deadline and every driver owner.

This proves an ordered authenticated channel group, not simultaneous peer
knowledge. A lost final Accepted may leave the server paired while the client
expires. It is still not Armed, no Seal is legal, and no rollback/reuse of a failed
same-session group is implied. The future manager's independent Prepare/Armed
exchange must establish its own all-lane authority. Because Ready transfers each
live driver into PairedRaw, a caller coordinating two local peers must service an
already-ready PairedRaw while the other PairSetup is still Pending. Waiting on a
join that parks the completed peer cannot drive the remaining Accepted bytes; no
hidden background task makes that usage live. The independent asymmetric-Accepted
regression preserves this distinction explicitly.

The common preimage is exactly 227 bytes. Checked-in
[Python-generated vectors](../../crates/l2tunnel-raw-io/src/handoff/pairing/profile_vectors.json)
pin both full/half preimages and hashes, lane-base hashes, the 236-byte transcript,
transcript digest, and 244-byte Offer. The independent standard-library generator
is retained in [the focused receipt](../../work/raw-pairing-checkpoint/profile_oracle.py).
The production transcript digest uses streaming maintained SHA-256 with domain
`l2tunnel/raw-owned-pair-transcript/v1\0` followed by the exact transcript.

## Finite exporter ownership

Capture a fixed six existing exporter roots per lane: LaneJoin, Management and
Data, each in ClientToServer and ServerToClient direction, using the actual lane
ID. Call the existing AuthenticatedIo method before into_parts; do not duplicate
its context construction or reconstruct AuthenticatedIo afterward. Maximum root
storage is twelve 32-byte secrets for two lanes. Preserve the same TLS object,
wrapper state, record observer and original counters through that operation.

After the full canonical transcript is accepted, use maintained ring HKDF-SHA256
to bind roots to the complete ordered group. For each purpose/direction, the
HKDF input is the ordered concatenation of the actual present-lane roots (32 or
64 bytes); the salt is the transcript SHA-256 digest. Expansion info has a new
fixed raw-pair domain, version, purpose, direction, destination lane ID and that
transcript digest. Produce exactly one 32-byte result per purpose/direction/lane;
no unbounded caller label, output length, derivation counter or public secret
injection is accepted. Including all ordered roots prevents transplanting one
lane's key into another group even if that lane alone was the same owner.

Retain exactly six final 32-byte keys for full mode or twelve for half mode in a
private zeroizing boxed slice inside PairedRaw. This matches the per-present-lane
payload charge; the full profile does not allocate a hidden twelve-key array. Roots, concatenation
scratch and final keys use existing pinned zeroizing storage, have no Debug or
status-byte output, and are destroyed on group failure/drop. The root has approved
the direct existing pinned `zeroize = "=1.9.0"` dependency and narrow private
setup/bridge factoring; Cargo generated only the local raw-io dependency edge.
No cipher/provider/version or vendor change was made. Derive the complete fixed set before
publishing success; failure exposes no partial key set. There is no public key
export in this checkpoint. A subsequent reviewed manager/carrier seam may consume
these owners exactly once. Tests can compare complementary private outputs and
domain separation without logging secret bytes. The fixed expansion info is
`l2tunnel/raw-owned-pair-key/v1\0`, u16 version 1, u8 purpose
(LaneJoin=1/Management=2/Data=3), u8 direction (ClientToServer=1/ServerToClient=2),
u32 destination lane and the 32-byte transcript digest, concatenated in that order.

Tests inject an entropy error and a finite exporter-collector error through
private helpers, and remove a required root before final derivation to prove that
no partial key set is exposed. These are controlled failure-path tests, not an
observation of an actual operating-system entropy failure. Production helpers
always call ring SystemRandom and the actual retained AuthenticatedIo exporter.
Partial roots and HKDF output use maintained zeroizing storage.

## Seal and freeze remain blocked

The new pairing owner enables a later manager to retain its original objects; it
does not install ingress classification/quarantine or send Prepare/Armed/Seal.
The next Seal constructor must consume actual private all-lane Armed authority
from that manager. There will be no public arbitrary SealContext or armed boolean.
Actual native/recovery drain is also not supplied by this bootstrap-message API.

The retained [feasibility report](../../work/raw-tls-freeze-feasibility-20261112/REPORT.md)
requires exact remaining-length reads from birth, same-record plaintext rejection,
public backend error/close/output checks, and a one-shot backend empty-write
materialize-and-reject check. `wants_write == false` and zero public IoState are
insufficient: incomplete handshake fragments and deferred KeyUpdate exist.
Successful future proof must retain the whole maintained TLS object and stop
polling it before requesting its exact original gate. Driver physical send/ACK
proof and the bounded old-prefix responder are still separate prerequisites.

A newly inspected failure path further narrows the claim: pinned tokio-rustls
0.26.5 `src/common/mod.rs::Stream::read_io` calls `write_io` as a last-gasp fatal
alert when `process_new_packets` fails (lines 110–120 in the cached source).
Consequently a TLS read poll can write ciphertext. Such malformed-peer failure
may be explicitly terminal: preserve actual output counts, the original whole
TLS object and owned cleanup, and produce no FrozenTls/handoff/rollback result.
Do not claim reads never write, suppress this maintained alert solely to improve
a capture predicate, or misreport the failed path as successful quiescence.
Any later success predicate must separately prove no unexpected output occurred.

## Checked resource policy

The following is an enforceable policy for **pair-controlled payload storage**,
not an assertion about allocator overhead, total RSS or arbitrary external
PacketIo/TLS configuration allocations. Resource-policy version 1 fixes retained
payload charge at most 16 MiB, peak payload charge at most 20 MiB, and separately
checked fixed metadata at most 1 MiB per group. All sums/products/conversions use
checked u64 arithmetic before allocation; overflow or exceeding either ceiling
returns the original inputs during preflight. Limits are fixed authenticated
constants, not local knobs silently omitted from the profile.

Let L be 1 or 2, M the shared MTU, S/R the shared TCP send/receive ring capacities,
and P the shared packet_slots. Charge retained payload bytes as:

```text
R_payload = L * (S + R + 2*P*M + 5*M + 65_536 + 2*4_104 + 6*32)
            + 236 + 2*244
P_payload = R_payload + L*(2*M + 6*32) + 64 + 244
```

`2*P*M` reserves both raw packet queues at their configured maximum; `5*M`
reserves two driver stream buffers, the two bounded duplex directions and one
WouldBlock-retained raw send packet. The sentinel is 65,536 bytes. Both actual
Exact frame arrays are 4,104 bytes even with a smaller configured payload limit.
Six 32-byte secrets per lane cover either retained roots or final keys. The fixed
transcript and two fixed record scratch copies are charged at group level. Peak
adds two transient packet buffers per lane while tokens/stack output are being
processed, coexistence of old roots and the entire new final key set, 64-byte
ordered root concatenation, and one temporary pair record. Conversion to PairedRaw
must move owners/buffers, not clone complete rings or create a second group. The
private preparation phase allocates only these same final per-lane objects.

A separate conservative metadata preflight counts actual `size_of` values for
PairSetup/Group/PairedRaw, prepared bridges, Gate, driver future captures, message
owners, fixed timer storage and bounded queue descriptors. Counting coexisting
representations/inline frame arrays twice is intentional conservatism. The new
read-only `TrackedEngine::fixed_metadata_bytes()` adds checked inline TrackedEngine,
boxed TcpEngine and its one SocketStorage element; no stack state is exposed.
The preflight reserves 128 KiB per lane for Setup plus its concrete authentication
future. Its actual concrete future size is measured before trait-object boxing
and checked against that reservation after the irreversible attachment; excess
is terminal Capacity, never a reusable-input error. No future is polled before
these checks. Queue descriptors reserve eight times max(P,4) Vec descriptors per
lane, covering both deques and old allocation coexistence during growth. One
checked `ResourceCharge.metadata` conservatively bounds both retained and peak
known metadata and must fit 1 MiB. No unsafe or private-layout inspection is used.

TLS/ring internal heap allocations, allocator rounding/control blocks, shared
trust/certificate/member configs, runtime task infrastructure and caller-supplied
PacketIo internal heap allocations are separate
existing resource domains; the payload formulas must not be presented as their
hard heap bound. Keep their maintained parser/configuration and original record
lifetime limits; report this scope explicitly in status/docs. No per-record TLS
buffer can bypass the 4 MiB directional lifetime observer ceilings, but cumulative
wire bytes are not a measurement of TLS heap usage. Tests verify exact formula
boundaries/overflow, no config-dependent allocation before rejection, fixed frame
array charge with tiny message limits, and configured queue occupancy maxima.

## Explicit yielding driver turn

Polling boxed `SwitchDriver::run` once is **not** a bounded turn: its async loop
can complete wait_for_work immediately and run another pass indefinitely when
I/O is hot or a slow pass always outruns the one-millisecond tick. Do not use the
existing run future directly for the pairing owner or rely on incidental Tokio
cooperative budgeting.

Factor a private `SwitchDriver::run_owned_pair(original_deadline)` runner that
reuses the existing receive/poll/send/move/publish logic and exact counters. The
public legacy run path remains unchanged. The private runner completes at most
one synchronous bounded pass and at most one wait_for_work completion, then
**unconditionally awaits a private YieldOnce future outside every select/loop**.
YieldOnce's first poll records its state, wakes the task and returns Pending; only
a later poll returns Ready. Its Pending must propagate out of the boxed driver
future. Thus one outer poll cannot execute a second packet pass, even when every
adapter call, bridge operation and timer is immediately ready. A Pending wait
may produce a zero-pass resume before that same explicit yield; it is not a
license to start another turn inside the old poll.

Each pass still composes work_limit with the maintained engine's own bound. Check
the original pair deadline before/after packet-adapter calls, before/after the
bounded engine pass, around completed bridge operations and before terminal
publication. Slow synchronous work can cross the deadline; record its actual
progress and fail before subsequent I/O. This is a checked operation boundary,
not preemption of arbitrary user PacketIo code or an atomic wall-clock snapshot.
No caller callback, sleep or await is added after a physical handoff commit in
the unrelated existing path.

PairSetup/PairedRaw visits each live driver once in rotating lane order, then each
lane's bounded auth/message state once, with deadline checks between visits. It
does not repoll a self-woken driver in a local drain loop. A terminal lane cancels
the group before further lane work. Existing maintained TLS/auth polling retains
its own bounded record/lifetime work; this design does not mislabel a complete
TLS handshake future poll as one syscall.

Required regressions use an always-ready PacketIo and ready bridge/tick sources
with counting wakers/adapter calls. One outer poll must do no more than one raw
pass per lane, lane 1 must run while lane 0 stays hot, and a second poll may run
only the next turn. A deliberately slow but finite test adapter call that crosses the
original deadline must prevent later-lane I/O and paired success. Also cover a
pass slower than one millisecond, all-ready waits, Pending wait resumption,
self-wakes, cancellation while yielded, and no counter/pending-send loss. These
checks demonstrate explicit structural fairness; wall-clock scheduling fairness
of a caller that never polls the owner is not promised.

## Focused gates

- [x] [MOD-RAWSEAL-01] Review this production prerequisite, exact public ownership API, canonical field widths/order, resource charges, irreversible attachment, explicit yielding turns, key derivation and remaining Seal blockers before implementation. Evidence: root reviewed the actual auth/exporter, whole-TLS and driver APIs plus this [canonical contract](#exact-canonical-configuration-encoding); an independent source review confirmed from-birth pairing requirements, and the root's driver-fairness finding is resolved by the [explicit yielding turn](#explicit-yielding-driver-turn). Narrow private setup/prepared-bridge factoring and pinned zeroize 1.9.0 were approved; the wave 13/build 13 release authorized this implementation.
- [x] [MOD-RAWSEAL-02] Implement one/full and ordered two/half from-birth factories with complete prepared-engine validation, exact original-input rejection/irreversible attachment, the single original deadline and retained original drivers/TLS owners; preserve ordinary APIs/digests. Evidence: [from-birth factories and retained group](../../crates/l2tunnel-raw-io/src/handoff/pairing.rs), [prepared bridge/private driver](../../crates/l2tunnel-raw-io/src/handoff/driver.rs), and [configuration/deadline tests](../../crates/l2tunnel-raw-io/src/handoff/pairing_tests.rs); prior ordinary owner/driver tests pass in the [focused package receipt](../../work/raw-pairing-checkpoint/validation.json).
- [x] [MOD-RAWSEAL-03] Implement actual role/profile/member/server/session/bridge validation and fixed Offer/Confirm/Accepted exchange on every lane; test swapped/cross-paired lanes, wrong identities/configuration, malformed/duplicate/wrong-phase records and asymmetric final acceptance. Evidence: [fixed profile/transcript encoding](../../crates/l2tunnel-raw-io/src/handoff/pairing/profile.rs), [real authentication/protocol fault tests](../../crates/l2tunnel-raw-io/src/handoff/pairing_fault_tests.rs), and [independent cross-wiring/asymmetric-Accepted tests](../../crates/l2tunnel-raw-io/src/handoff/pairing_review_tests.rs).
- [x] [MOD-RAWSEAL-04] Retain finite existing exporter roots before into_parts and derive the transcript-bound fixed key set with maintained HKDF/zeroization; test complementary agreement and every purpose/direction/lane/group separation. Evidence: [actual exporter completion](../../crates/l2tunnel-raw-io/src/handoff/tls_owner.rs), [maintained HKDF and zeroizing six/twelve-key owner](../../crates/l2tunnel-raw-io/src/handoff/pairing/keys.rs), and [real complementary/group separation plus injected provider failures](../../crates/l2tunnel-raw-io/src/handoff/pairing_fault_tests.rs); injected failures are explicitly distinguished from observed OS failures above.
- [x] [MOD-RAWSEAL-05] Test partial/Pending writes/flush/read, completed first lane plus stuck second, borrowed cancellation/resume, whole-owner drop/abort, Ready after expiry, timer Ready, randomness/export failure and every original I/O destructor exactly once; distinguish cleanup from clean TCP close. Evidence: [independent retained-packet/phase/drop/expiry tests](../../crates/l2tunnel-raw-io/src/handoff/pairing_review_tests.rs), [post-yield actual-counter abort/expiry regressions](../../crates/l2tunnel-raw-io/src/handoff/pairing_tests.rs), [controlled entropy/export collector/missing-root failure tests](../../crates/l2tunnel-raw-io/src/handoff/pairing_fault_tests.rs), and retained [exact TLS owner deadline/partial-I/O tests](../../crates/l2tunnel-raw-io/src/handoff/tls_owner_tests.rs).
- [x] [MOD-RAWSEAL-06] Test usable bounded post-pair ordinary messages while both drivers are serviced, retained delivery backpressure, unchanged byte/message/record counters and checked retained/peak resource charges; prove always-ready driver turn fairness/deadline service without Tokio budget assumptions; no Seal or packet/native activation. Evidence: [real ordinary message/fairness/deadline regressions](../../crates/l2tunnel-raw-io/src/handoff/pairing_tests.rs) and [canonical Python vectors/exact charge/minimum-budget tests](../../crates/l2tunnel-raw-io/src/handoff/pairing_profile_tests.rs), with actual commands in the [focused receipt](../../work/raw-pairing-checkpoint/validation.json).
- [ ] [MOD-RAWSEAL-07] Pass focused package tests/strict lint/docs, independent source review and a coordinated stable aggregate before separately reviewing actual Prepare/Armed, classifier/quarantine, Seal/freeze, old-prefix responder or native activation.

The focused checkpoint passed 22 pairing tests (five independently authored), all
107 runnable raw-io tests, and 19 raw-tcp tests. One privileged adapter test remains
explicitly ignored; no native run was authorized or performed. Both packages pass
warning-denied all-target Clippy and rustdoc. Root source review found two actual
issues—post-yield progress capture before driver destruction and elapsed-only
progress reporting—and accepted their fixes after the corresponding real tests.
The exact commands, logs and owned source hashes are retained in
[validation.json](../../work/raw-pairing-checkpoint/validation.json). This is Linux
unprivileged maintained TLS/packet-I/O evidence. The coordinated full
`python3 tools/check.py` gate is still pending for this checkpoint; wave 13
predates these source changes and is not represented as their aggregate result.
