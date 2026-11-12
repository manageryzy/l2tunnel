# Coordinated active-TUN policy switching

Status: design and proposed interfaces reviewed by the coordinating owner;
implementation is authorized in staged library-first slices. Generic transactions,
canonical policy/catalog binding, explicit drained retirement and atomic pure epoch
rotation are implemented and locally tested. The separate managed active runtime
now exposes the reviewed local transaction endpoint and passes actual authenticated
loopback tests. The original [active runtime](active-runtime.md) retains its
unmanaged API. Privileged native policy switching, CLI integration and the full
adversarial management matrix remain separate unchecked gates.

## Minimal compatible change

The first switch changes exactly two fields: CRC MUX channel count, in 1..=256,
and the complete 64-entry DSCP weight table, with each multiplier in 1..=1024.
These values change together as one policy. Every old flow finishes its original
channel and first-packet weight before the new epoch opens any flow. IP bytes,
including DSCP, remain unchanged. The first packet admitted in a new epoch fixes
that epoch's new flow weight.

TUN layer, TCP/TLS carrier, original full/paired-half arrangement, authentication,
physical lanes, compression, MTU, queue/flow capacities, base DRR quantum, adaptive
selection and observation bounds, retirement policy and control-service limits
remain immutable. Compression, carrier, recovery, TAP/TUN, adaptive/static,
congestion-controller and physical-lane changes require separate designs.
Both endpoints of this point-to-point session participate; this is not a mesh or
multi-node consensus protocol.

The runtime authenticates a finite policy catalog before starting: 1..=16 unique
policies including the initial policy. Both peers must authenticate the same
canonically sorted catalog and transaction settings. A local request selects an
already negotiated policy. Arbitrary new weights require a new authenticated
session in this first implementation. This restriction reuses the existing
transaction engine's explicit supported-mode admission instead of inventing a
post-authentication capability expansion.

## Existing mechanisms and required extension

[transaction::Peer](../../crates/l2tunnel-management/src/transaction/mod.rs)
already provides coordinator-only prepare, explicit staging/fences, independent
directional barriers, commit acknowledgment, retirement, immutable retries,
request retirement floors and uncertain-commit reconciliation. Its
[24-byte ModeConfig codec](../../crates/l2tunnel-management/src/transaction/config.rs)
cannot encode active DSCP policy. Encoding weights in unrelated ModeConfig fields
or appending unauthenticated side data is not acceptable.

The proposed extension parameterizes the existing state machine; it does not copy
it into a second active-only implementation. Existing ModeConfig users retain the
default type and byte-exact version-one encoding/digest. Proposed pure APIs are:

```rust,ignore
pub trait Configuration: Clone + Eq {
    const ENCODED_LEN: usize;               // validated in 1..=512
    const DIGEST_DOMAIN: &'static [u8];     // validated in 1..=128
    fn validate(&self) -> Result<(), transaction::Error>;
    fn encode_into(&self, output: &mut [u8]) -> Result<(), transaction::Error>;
    fn decode(input: &[u8]) -> Result<Self, transaction::Error>;
    fn channels(&self) -> u16;
    fn duplex(&self) -> Duplex;
}

pub struct Peer<C: Configuration = ModeConfig> { /* same state machine */ }
pub struct Effects<C: Configuration = ModeConfig> { /* existing fields */ }
pub enum Event<C: Configuration = ModeConfig> { /* existing variants */ }
pub struct Reader<'a, C: Configuration = ModeConfig> { /* existing fields */ }
pub fn configuration_digest<C: Configuration>(config: &C)
    -> Result<ConfigDigest, transaction::Error>;
```

The implementation centrally hashes the exact validated canonical bytes with the
configuration type's domain using maintained SHA-256. Configuration implementers
do not supply arbitrary digest results. Encoding must use exactly ENCODED_LEN,
and decoding must reject noncanonical bytes; Prepare parsing uses this checked
length before decoding its exact old-channel fence. Peer continues to reject a
different duplex and any digest outside the finite supported catalog. Current
mode_digest/encode_mode/decode_mode wrappers and existing transaction vectors
remain compatible. All existing state-machine failure tests must run unchanged.

The runtime's private ActivePolicy configuration consists of an immutable-session
digest, duplex, channel count and all 64 weights. Its proposed canonical body is
296 bytes: `LATM` magic(4), version one(1), duplex(1), channels(2), immutable
settings digest(32), then 64 big-endian u32 weights(256). No implicit enum values,
platform-sized integers, optional suffixes or hidden defaults are allowed. The
digest domain is `l2tunnel/active-management/policy/v1\0`. Every proposed policy
must reproduce the negotiated immutable digest.

The initial managed authentication binding uses a distinct versioned domain and
contains the immutable runtime/settings digest, initial ActivePolicy digest,
sorted supported-policy digests, transaction timing and resource/service limits.
The immutable digest excludes only channels and DSCP weights. It includes the
actual derived TargetConfig and observation Config values. It does not include
the catalog recursively. Unmanaged active v3 and managed active profiles cannot
authenticate as one another.

## Runtime surface

The new adapter belongs in `l2tunnel_runtime::active_management`. Existing
`active::run` and its public Settings remain unchanged. Public types are:

```rust,ignore
pub struct Mode {
    pub channels: u16,
    pub dscp_weights: [u32; 64],
}
pub struct Config {
    pub initial: active::Settings,
    pub supported: Vec<Mode>,             // validated unique count 1..=16
    pub transaction: transaction::Settings,
}
pub struct SwitchOutcome {
    pub epoch: Epoch,
    pub digest: ConfigDigest,
    pub mode: Mode,
}
pub fn session_config(runtime: RuntimeConfig, config: &Config)
    -> io::Result<SessionConfig>;
pub fn channel() -> (ControlHandle, ControlReceiver);
impl ControlHandle {
    pub async fn switch_policy(&self, mode: Mode)
        -> Result<SwitchOutcome, ControlError>;
    pub fn status(&self) -> Option<Status>;
    pub fn subscribe(&self) -> watch::Receiver<Option<Status>>;
}
pub async fn run<D: PacketDevice<Error = io::Error>>(
    device: D, link: Link, runtime: RuntimeConfig,
    config: Config, control: ControlReceiver,
) -> io::Result<()>;
```

ControlHandle has one queued proposal and one in-progress transaction, returning
Busy on further requests. Client is the sole coordinator, derived from retained
authenticated Link metadata; a caller cannot supply a different role. Status
includes active epoch/digest/mode, transaction phase, admission-gate state,
per-channel fences/progress, actual data/control/observation flush counts,
retirement progress and the existing active measurements. A local phase or
canceled waiter never implies successful peer application. SwitchOutcome is
returned only after transaction retirement and the required reply flush gate.

## Admission, fences and old-flow retirement

1. On Stage, stop native reads and all new calls to enqueue_ip. Retain the existing
   at-most-one native packet outside the old engine; it was not admitted and is
   deliberately excluded from the old fence. It is admitted exactly once after
   safe abort or final new-epoch activation. No already admitted packet is moved
   or re-enqueued into the new engine.
2. Stage a validated empty next-epoch engine and reader state before calling
   Peer::staged. Allocation failure is a precommit failure. At most one current
   and one staged engine exist. Validated per-engine capacities and the fixed
   two-engine bound account for this additional retention; one engine's cap is
   not claimed to cover both.
3. Capture one final old-epoch original-admission count per old MUX channel.
   Increment these counts on successful enqueue_ip using its returned
   PacketMetadata.binding.channel. This includes originals still queued before
   logical credit admission; it avoids pretending the current wire-output count
   is already the final fence. No later old admission is allowed.
4. Continue normal old poll_data, credit/Final service, native delivery and exact
   confirmations. Track actual data outputs per old channel,
   and increment received-delivered counts only after native transmit success,
   using the delivery's channel. An aggregate counter cannot prove every channel
   reached its own boundary. At the complete drain, the global produced-equals-
   actual-flushed watermark proves every handed record completed; combined with
   the exact per-channel handed vectors, this proves each channel's flush fence.
   Any count above its declared fence fails before another native write.
5. Stop optional publication and target growth during Stage/drain. Drain existing
   optional outputs and finite pending observations; incoming already emitted
   observations may be validated, but cannot create new demand publications or
   growth. Required Ping replies remain bounded and included in the output drain.
6. After source queues are empty and all admitted source records are released,
   explicitly retire every old outgoing flow, one Final at a time. The peer does
   the same independently for its own direction. Retire even empty registrations
   and unused issued grants. Keep exact key/weight until each matching FinalAck.
7. Call confirm_drained only when the complete proof below holds. A Stage or Drain
   event is a work request, never evidence that the operation finished.

After that local proof, retain `Active::drained_reader(ExternalDrain)` and keep
admission frozen. The reader validates old controls without generating another
Grant/FinalAck. Before this point normal bounded Pong/Final service continues;
afterward strict old observation scope/flow validation discards late optional
retries without creating a new Pong. Previously required acknowledgments have
already completed actual TLS flush. This makes the published barrier stable.
The same immutable snapshot becomes the old reader after commit. Abort clears
the snapshot and permits fresh increasing IDs only after reconciliation and any
remaining Final barrier. Commit rechecks the actor's actual external snapshot.

The required proof consists of: final per-channel admitted == handed == actual
TLS-flushed; peer fence == actual local native-delivered vector; empty original
queues; zero sender retention and receiver payload; zero incoming and outgoing
flow registrations and issued receiver reservations; no pending Final; no pending
active controls; no observer pending frames; actual produced == flushed for all
old active-control/data/observation outputs and empty corresponding external
queues. An unadmitted deferred native packet is explicitly accounted separately.
There are no application ARQ/FEC/retry records in this TCP profile; this observed
zero does not assert empty kernel TCP buffers. Any future recovery adapter must
supply its own non-fabricated drain proof before it can use this transaction.

The existing idle-only API cannot retire a just-active flow under a short
management deadline: its default inactivity requirement is 60 seconds. Proposed
narrow pure additions are implemented as `Active::drained_candidate()` and
`Active::request_drained_retirement(key, now, policy, ExternalDrain)`. They keep
all empty-queue, logical-release, scope, retry and FinalAck checks, but make no idle
age claim. The existing request_idle_retirement preserves its idle requirement.
Pipeline has an explicit empty/drained removal path over FlowTable; do not advance a fake clock
or temporarily edit the negotiated idle timeout to bypass checks. The runtime
owns the global admission freeze. The candidate stays individually frozen inside
Active until acknowledgment, as it does for idle retirement.

## Epoch installation and sequence continuity

The logical active session, authenticated physical sockets, TLS objects, original
bulk directions and outer L2AC stream sequence numbers remain unchanged. The
transaction's request, attempt and replay packet counters also never reset.
New active tokens use the same session and the next checked epoch. Per-flow record
offsets and credits are scoped by that new epoch and fresh flow identity; they are
never interpreted under the previous ledger or used as cryptographic nonces.

Preserve monotonic outgoing flow IDs and the incoming flow-ID retirement high-water
across epoch installation. Replacing Active with an ordinary Active::new would
silently reset those counters, so it is not an acceptable implementation shortcut.
The implemented pure rotation surface is:

```rust,ignore
pub struct PreparedEpoch { /* opaque, owns the staged empty engine allocation */ }
pub struct RetiredEpoch { /* immutable old scope, high-waters and exact final cache */ }
impl RetiredEpoch {
    pub fn epoch(&self) -> u64;
    pub fn check_control(&self, authenticated_token: &[u8])
        -> Result<(), l2tunnel_active::Error>; // success means discard, no output
}
pub struct EpochCommitError {
    pub error: l2tunnel_active::Error,
    pub prepared: PreparedEpoch,
}
impl Active {
    pub fn drained_reader(&self, external: ExternalDrain)
        -> Result<RetiredEpoch, l2tunnel_active::Error>;
    pub fn prepare_epoch(&self, next: ActiveConfig, now: Micros)
        -> Result<PreparedEpoch, l2tunnel_active::Error>;
    pub fn commit_epoch(&mut self, prepared: PreparedEpoch, now: Micros,
        external: ExternalDrain) -> Result<RetiredEpoch, EpochCommitError>;
}
```

PreparedEpoch holds its engine and staging metadata through one owned Box so failure preserves
the staged allocation without a large error value or another allocation. The
commit validates the complete empty/retired state, same session, exact next epoch
and no renewal failure. It carries the final authoritative flow high-waters into
the new empty pipeline, resets only epoch-scoped ledgers and measurements, and
returns an immutable old-scope reader/tombstone. Failed commit preserves the current engine and returns the
same prepared allocation for explicit abort/retry. Pipeline/FlowTable ID
inheritance requires an empty old table and a fresh empty destination, carries
the old monotonic clock floor and preserves ID exhaustion. Active separately
checks the retained incoming high-water before opening a new epoch ledger.
The prepared configuration may change only epoch and channel count; DSCP weights
remain the runtime policy which selects each new flow's initial weight.

The immutable tombstone uses the authoritative 72-byte token decoder. It rejects
records, unknown future IDs, wrong scopes, unsupported retirement modes and a
conflicting latest Final/FinalAck. Valid older controls are discarded with no
ledger or output capability. It retains two high-waters and one exact final cache
per direction, not a collection proportional to historical flows. Dropping the
tombstone is controlled by the existing transaction's final retirement. Actual
process allocation failure is not made recoverable by Box staging; no live state
is changed before construction succeeds, but allocator OOM policy remains the
Rust process policy.

On follower Commit, install the staged epoch but keep native admission closed.
On coordinator CommitAck, install it locally and send Retire. Both retain the old
reader/tombstone as DrainOnly until transaction retirement. Old data arriving
after its verified fence is an error, never re-delivered. Stale scoped controls
use the retained authoritative old context only; they cannot replenish the new
ledger, recreate a flow, or change a new measurement.

Follower admission resumes only after its Retire reply has actually flushed on
the ordered management/control path, not merely after Peer becomes Idle. This
ensures the coordinator's Retire acknowledgment is ordered before any new Open.
Coordinator admission resumes only after processing that acknowledgment. New
data cannot overtake its new Open/Grant because credit admission remains required.
Outer parsing must validate channels against the authenticated transport ceiling
256; actor-side epoch/config validation enforces that epoch's exact channel count.
Retaining the initial channel bound in a long-lived reader would incorrectly
reject a later increase. No new payload bypass or permissive epoch fallback is
introduced.

## Management framing, bounded service and failure

Use a distinct authenticated L2AC kind five, on the same ordered control path as
active controls, with maximum body length 4096. It carries the existing strict
L2MC management envelope; native IP bytes never enter this dispatch. The largest
Prepare body is bounded by 112-byte management header + 8-byte request reference
+ 296-byte ActivePolicy + 2-byte count + 256*8-byte old fence = 2466 bytes.
AdmissionGate binds the logical session, authenticated role/endpoints and fixed
control lane. Both half-duplex physical lanes belong to that same authenticated
logical session; user data remains on their original bulk directions.

Use separate finite active-control and management queues with fair service
between these mandatory classes, and an optional observation queue. Every class
and heartbeat consumes the existing total control allowance. Observations retain
their at-most-half share; they cannot consume the mandatory reserve. Coalesce
transaction retries by immutable logical header identity (excluding replay packet
number) and exact body, retaining ownership until actual TLS flush, as the current
[managed ControlSender](../../crates/l2tunnel-runtime/src/managed.rs) does. A retry
with a fresh replay number must not fill an unbounded queue behind a blocked
writer. Management input also has a finite negotiated rate; invalid or excessive
authenticated management fails explicitly. TCP head-of-line blocking remains.

Management messages are not old user-flow payload copies and do not prevent their
own Barrier by being counted as pending active-flow outputs. Their independent
queue/flush state remains bounded and supplies the reply-resumption gate. Data,
credit, Final and observations do participate in the old-flow drain. Keep these
ownership classes explicit instead of reporting a convenient aggregate zero.

Before Commit can have been sent, existing Peer abort/reject reconciliation may
restore the old policy. Any flow already successfully retired remains retired;
a later packet opens a fresh increasing ID under the unchanged old policy.
If a Final is still pending, retain the runtime admission gate until its exact
acknowledgment; do not treat Peer::can_admit_data alone as permission to resume.
Final exhaustion or renewal-required status fails the session without rollback.
Once Commit may have reached the peer, use only the existing immutable uncertain
reconciliation; failure tears down the session. EOF, cancellation and process
restart do not report success or resume the same session. The current finite
phase/reconciliation deadlines may expire under large flow count or a slow peer;
report that outcome rather than assuming retirement completes in one RTT.

## Acceptance checklist

- [x] [MOD-ACT-MGMT-01] Review and freeze compatible knobs, negotiated catalog, canonical ActivePolicy, generic transaction trait and runtime APIs before implementation. Evidence: [reviewed design and stage boundaries](#existing-mechanisms-and-required-extension), [runtime surface](#runtime-surface).
- [x] [MOD-ACT-MGMT-02] Generalize the existing transaction state machine without changing ModeConfig wire vectors or legacy retry/replay/abort/uncertainty behavior. Evidence: [generic state machine](../../crates/l2tunnel-management/src/transaction/mod.rs), [18 original/generic management tests](../../crates/l2tunnel-management/src/transaction/tests.rs), [stable wave4 aggregate receipt](../../work/implementation-wave4/validation.json).
- [x] [MOD-ACT-MGMT-03] Implement bounded canonical active policy/catalog authentication with channel/weight limits, duplicate rejection and no unsupported fallback. Evidence: [canonical policy/catalog and two focused tests](../../crates/l2tunnel-runtime/src/active_management.rs), [stable wave4 aggregate receipt](../../work/implementation-wave4/validation.json).
- [x] [MOD-ACT-MGMT-04] Add explicit drained-flow retirement and staged atomic epoch rotation preserving session flow high-waters and old-scope tombstones. Evidence: [explicit retirement](../../crates/l2tunnel-active/src/retirement.rs), [atomic epoch implementation](../../crates/l2tunnel-active/src/epoch.rs), [six adversarial and bidirectional tests](../../crates/l2tunnel-active/src/epoch/tests.rs).
- [x] [MOD-ACT-MGMT-05] Integrate Stage admission freeze, returned-metadata per-channel fences, exact native delivery, all old-flow Finals and actual external flush proof. Evidence: [managed actor and stable barrier](../../crates/l2tunnel-runtime/src/active_management/runtime.rs), [actual blocked-native and sequential switch tests](../../crates/l2tunnel-runtime/src/active_management/runtime/tests.rs).
- [x] [MOD-ACT-MGMT-06] Integrate kind-five authenticated management, bounded fair control service, retry coalescing and Retire-reply actual-flush resumption. Evidence: [shared negotiated framing and writer](../../crates/l2tunnel-runtime/src/active.rs), [bounded management output and completion gate](../../crates/l2tunnel-runtime/src/active_management/runtime.rs), [retry-until-flush test](../../crates/l2tunnel-runtime/src/active_management/runtime/tests.rs).
- [x] [MOD-ACT-MGMT-07] Test 1-to-many and many-to-1 channels, changed weights, preserved packet order/bytes and new flow identity in full/paired-half links. Evidence: [actual TLS 1-to-256-to-2 static/adaptive tests](../../crates/l2tunnel-runtime/src/active_management/runtime/tests.rs), [pure global flow-ID and channel/weight continuity](../../crates/l2tunnel-active/src/epoch/tests.rs).
- [x] [MOD-ACT-MGMT-08] Test queued originals, retained native input, native WouldBlock, outstanding credit, blocked output, asymmetric fences and missing FinalAck without false drain. Evidence: [queued originals and retry ownership](../../crates/l2tunnel-runtime/src/active_management/runtime/tests.rs), [retained native packet, asymmetric proof and withheld FinalAck](../../crates/l2tunnel-runtime/src/active_management/runtime/tests/failure.rs), [actual stalled writer and flush tests](../../crates/l2tunnel-runtime/src/active_tests.rs).
- [x] [MOD-ACT-MGMT-09] Test repeated/conflicting/replayed management, unsupported catalogs, old/future epoch frames, lost CommitAck/RetireAck, bounded abort and terminal uncertainty. Evidence: [management replay/conflict tests](../../crates/l2tunnel-management/src/transaction/tests.rs), [catalog, cancellation and retry identity tests](../../crates/l2tunnel-runtime/src/active_management/runtime/tests.rs), [authenticated withheld replies, abort and uncertainty](../../crates/l2tunnel-runtime/src/active_management/runtime/tests/failure.rs), [strict old-scope validation](../../crates/l2tunnel-active/src/epoch/tests.rs).
- [ ] [MOD-ACT-MGMT-10] Test adaptive observation pause/drain/reset, stale old measurements, monotonic physical/management/flow counters and precommit allocation failure.
- [ ] [MOD-ACT-MGMT-11] Run focused tests, warning-denied lints/docs and repository checks, then qualify owned native namespace switching with exact payload/epoch receipts.
- [ ] [MOD-ACT-MGMT-12] Extend CLI/local-control integration only after the concrete runtime transaction is reviewed and qualified; keep broader active-mode switching unchecked.

This design was checked against the current management transaction, managed TCP
runtime, active runtime, idle-retirement implementation and pipeline metadata APIs.
Local commands executed for the first library checkpoint: `cargo test -p
l2tunnel-management --offline` passed all 18 tests (the 15 original tests remain
unchanged), `cargo test -p l2tunnel-runtime active_management --offline` passed two
catalog/codec tests, and warning-denied management Clippy passed. That historical
checkpoint did not include the runtime switching endpoint.
The coordinating owner subsequently produced the source-stable
[wave4 receipt](../../work/implementation-wave4/validation.json), with 352 Rust
and 18 Python tests; that receipt includes the generic transaction/catalog slice
and predates the later pure epoch implementation. The latter passed focused
Active tests, including explicit no-idle retirement, zero-data reservations,
failed commit allocation ownership, bidirectional channel/weight changes across
12 sequential flows, terminal/exhausted state, and old control tombstones.
The current managed runtime checkpoint adds nine management-focused tests,
including seven actual runtime/output cases and the two policy/catalog cases;
shared active framing/service tests additionally cover negotiated kind-five
bounds, actual writer flush and common finite credit/management service.
Actual authenticated loopback cases cover full and paired-half TCP, static and
measured targets, 1-to-256-to-2 channels, changed DSCP policy, retained native
backpressure, cancellation and precommit deadline safety. A follower phase may
expire before an abort reaches it under the preserved transaction timing rules:
that terminates the session and reports Closed, never a successful rollback.
Seven additional failure tests cover a single native packet retained outside the
old fence under a one-flow capacity limit, asymmetric fences and each unflushed
output class, a pure queued Ping blocking drain, stale observations and controls
before and after epoch replacement, and abort acknowledgment plus actual reply
flush before resumption. Actual authenticated faulty peers suppress selected
logical FinalAck, CommitAck or Retire replies before TLS encoding; this tests
bounded semantic reply withholding, not TCP packet loss. Both full and paired-half
links reconcile withheld commit/retirement replies only after the exact retry
response. Permanent withholding terminates without reporting local success.

The stale-measurement test establishes that the retained old reader cannot queue
a Pong, recreate a flow or change feedback in the new observer. Independent pure
epoch tests preserve the same staged allocation after rejected commits. Actual
allocator exhaustion remains the Rust process policy, with no recoverable
allocation-failure injection; item 10 remains unchecked for that broader gate.
Unprivileged runtime tests do not qualify a native namespace switch. The pending
coordinated repository check will record a source-stable aggregate separately.
At this failure-coverage checkpoint, `cargo test -p l2tunnel-runtime --offline`
passed all 69 runtime tests. Warning-denied runtime Clippy and rustdoc were also
run; the coordinating owner is responsible for the subsequent stable whole-tree
`python3 tools/check.py` receipt.
The subsequent [wave5 aggregate](../../work/implementation-wave5/validation.json)
passed 420 Rust tests including doctests and 28 Python tests, all required checks,
with matching before/after source hashes. This qualifies the local failure-test
checkpoint; native policy-switching remains a separate acceptance step.

## Native acceptance profiles and retained failures

The harness selects managed switching explicitly with `--active-policy-switch`
on active TUN/TCP. It authenticates four channels with all weights one and two
channels with DSCP 46 weight four, rejects a follower proposal, then switches to
epochs two and three during a paced 512 KiB native TCP transfer. Both peers must
report the exact complete policy, matching 64-hex digest, Idle, running and
admitting. Each case also checks both-direction IPv4 and IPv6 probes.

Native tests use immutable binary/harness/probe copies and owned namespaces.
The first static/adaptive attempts stopped on an incorrect harness readiness
banner, before requested traffic; both failed receipts remain retained. After
correcting that readiness string, the [adaptive uncompressed default profile](../../work/native-active-switch-adaptive-none-v2/receipt.json)
passed clean half/full and impaired half cases. The [static default 60-second
transfer attempt](../../work/native-active-switch-static-none-v2/receipt.json)
exhausted its finite completion bound after both switches. The [adaptive LZ4
default attempt](../../work/native-active-switch-adaptive-lz4/receipt.json)
failed its five-second transaction phase deadline while old payload was draining.
These remain default-profile limitations, not successful qualifications.

The explicit slow profile fixes retry/phase/reconciliation at 250/30000/60000 ms
and overall sender completion at 180 seconds from sender start, including switch
requests. Default application probing waits for one final checksum; the retained
static 180-second and slow-profile attempts exhausted that checksum read's
45-second timeout even while remote payload delivery advanced. Adaptive slow
attempts passed with the original final-checksum protocol. No old failure is
relabelled by a later profile.

The optional `--active-progress` qualification protocol is separately named
`progress32k-v1`: each actual remote 32 KiB receipt emits a strictly advancing
bounded count, and a final SHA-256 follows only exact complete receipt. At the
1 MiB probe maximum there are at most 32 progress notices. Unknown, duplicate,
non-advancing, excessive or premature final records fail. Only valid progress
renews the 45-second no-progress deadline, and the overall 180-second bound never
extends. Raw progress counts/times, first/last target samples and both-peer
policy states are retained in each receipt. This application protocol differs
from the original single-checksum test and is not a claim of static throughput.

The [independently re-read receipt audit](../../work/native-active-switch-audit.json)
verifies binary/harness hashes, exact payload digest, both-peer policies and live
gates, all 16 progress records, declared deadlines, IPv4/IPv6 probe counts and
cleanup. The fixed slow-profile results are:

| Target profile | Payload codec | Clean half/full | Impaired half | Receipt |
| --- | --- | --- | --- | --- |
| Static | None | Passed | Passed, 147.40 s payload completion | [static None](../../work/native-active-switch-progress-static-none/receipt.json) |
| Adaptive | None | Passed | Passed | [adaptive None](../../work/native-active-switch-progress-adaptive-none/receipt.json) |
| Static | LZ4-if-smaller | Passed | Failed progress receive deadline; epoch three remained live | [static LZ4](../../work/native-active-switch-progress-static-lz4/receipt.json) |
| Adaptive | LZ4-if-smaller | Passed | Passed, 27.42 s payload completion | [adaptive LZ4](../../work/native-active-switch-progress-adaptive-lz4-v2/receipt.json) |

Thus 11 of 12 requested cases qualified; item 11 and the complete native matrix
remain open. The static LZ4 failure was not rerun or given a larger deadline.
Its final independently sampled epoch-three observations were Idle/admitting on
both peers: the client had admitted 358 records and handed 332 (26 still not
handed); the server had admitted 332 and handed 327 (five still not handed).
Both handed counters advanced in their final two samples. The error log appeared
about 145.32 seconds after the first-send marker, before the overall 180-second
bound. These are sampled ownership counters, not an exact simultaneous queue
snapshot or evidence that LZ4 caused the timeout in one stochastic-loss trace.
The earlier adaptive LZ4 progress attempt completed its clean payload but the
harness read a partially written trailing statistics line; its failed receipt
remains retained. A regression now ignores only an unfinished trailing record,
and the corrected run above uses the same binary, timing and protocol bounds.

The source now optionally journals each validated progress record into a bounded
sidecar, so future failed runs retain partial progress alongside their failure.
The qualifying snapshots predate this logging-only addition; a real local TCP
legacy/progress test with a 65537-byte nonuniform final block verified the journal
matches the sender output. Ten Python harness tests passed, including malformed
progress, strict policy acceptance, absolute deadlines and incomplete log records.
Nineteen client tests and warning-denied Clippy passed after adding explicit
catalog timing. These later changes require the next coordinated aggregate;
the historical source-stable wave5 receipt is not relabelled.
