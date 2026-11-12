# Proxy measurement records and bounded ownership

Status: checkpoints A codec and B bounded owner are implemented and focused-tested.
Checkpoint B's bounded owner API is separately approved below; C's
observation/runtime work remains planned and subject to source/API review. This refines
[ADAPT04/05](proxy-adaptive.md#acceptance-checklist) after the pure allocator. Its
feedback inputs remain caller assertions until an actual observation owner and
reviewed runtime adapter supply evidence.

Three checkpoints are separate: A, canonical codec without state authority; B,
bounded pure record/output owner; C, actual table-derived rate, demand and echo
observations feeding the existing planner. No raw/vendor, runtime or client change
belongs to A/B. No new external dependency is needed.

## A: canonical codec

Implemented module: [`l2tunnel_tcp_proxy::measurement::wire`](../../crates/l2tunnel-tcp-proxy/src/measurement/wire.rs). All integers are big
endian. `HEADER_BYTES = 48`, `DEMAND_BYTES = 104`, `ECHO_BYTES = 56`, and
`MAX_RECORD_BYTES = 104`; lengths are exact, with no extension or trailing padding.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | `LTPM` |
| 4 | 1 | Version 1 |
| 5 | 1 | Demand(1), EchoRequest(2), EchoReply(3) |
| 6 | 1 | Original stream: OriginatorToAcceptor(1) or AcceptorToOriginator(2) |
| 7 | 1 | Zero |
| 8 | 16 | Nonzero authenticated logical session |
| 24 | 8 | Nonzero fixed epoch |
| 32 | 8 | Nonzero lifetime flow ID |
| 40 | 8 | Nonzero serial, monotonic within this flow/direction/kind |

Demand contains produced original bytes/records at 48..64; the producer's observed
peer-grant bytes/records at 64..80; unread native-ring bytes at 80..88; original
payload bytes in its retained Data record at 88..96; and byte-credit-blocked(bit 0)
and record-credit-blocked(bit 1) flags at byte 96. Other flags and bytes 97..104
are zero. Produced is componentwise no larger than observed grant. A blocked flag
requires native unread bytes and equality of produced and observed grant in that
dimension. Zero counters are valid. Echo bodies contain one nonzero u64 nonce at
48..56; a reply echoes request nonce/flow/direction but has its own reply serial.
There are no peer timestamps, ACK claims, TCP windows or target updates on wire.

```rust,ignore
pub enum Direction { OriginatorToAcceptor, AcceptorToOriginator }
pub struct Header { pub scope: Scope, pub direction: Direction, pub serial: u64 }
pub struct Demand {
    pub produced: Window, pub observed_grant: Window,
    pub native_unread_bytes: u64, pub pending_data_bytes: u64,
    pub byte_blocked: bool, pub record_blocked: bool,
}
pub enum Body { Demand(Demand), EchoRequest { nonce: u64 }, EchoReply { nonce: u64 } }
pub struct Record { pub header: Header, pub body: Body }
pub fn decode(bytes: &[u8]) -> Result<Record, DecodeError>;
pub fn encode(record: Record, output: &mut [u8]) -> Result<usize, EncodeError>;
```

Parsing is allocation-free and has no side effects. It validates syntax and the
intrinsic relationships above, not authentication, table existence or freshness.
Encoding prevalidates before writing; rejected input/capacity leaves output
unchanged. Test every truncation, excess length, reserved bit/byte, enum value,
zero identity and counter boundary.

## B: actual-table record owner

Checkpoint B is implemented in [the pure owner](../../crates/l2tunnel-tcp-proxy/src/measurement/owner.rs). Its public
surface is limited to actual-table record staging, replay admission and bounded
output handoff. Rate/RTT snapshots, automatic observations, a measured Planner
wrapper and a Controller remain unavailable until checkpoint C.

The owner retains the actual table's private identity and validated policy. It
derives directions from negotiated origination role, never native addresses or
asserted TLS names. These roles coincide with current client/server policy, but
the pure names describe table authority rather than an assumed connection role.

```rust,ignore
pub struct OwnerConfig {
    pub pending_ttl_micros: u64,
    pub probe_interval_micros: u64,
    pub probe_timeout_micros: u64,
    pub handoff_timeout_micros: u64,
    pub max_records_per_interval: u16,
    pub emission_interval_micros: u64,
}
pub struct Owner;
pub struct OutputId; // Private owner identity, slot and immutable generation.
pub struct Pending<'a> { pub id: OutputId, pub flow: u64, pub bytes: &'a [u8] }
pub enum Ingress { Accepted, Duplicate, Stale }
pub struct MemoryBound; // Separate fixed buffers, slot counts and metadata.
pub struct OwnerStatus; // Ownership/counts only; no rate/RTT/sample evidence.
impl OwnerConfig {
    pub fn validate(self, table: &session::Table) -> Result<MemoryBound, Error>;
}
impl Owner {
    pub fn new(config: OwnerConfig, table: &session::Table, now: Micros)
        -> Result<Self, Error>;
    pub fn stage_demand(&mut self, table: &session::Table, flow: u64, now: Micros)
        -> Result<(), Error>;
    pub fn stage_probe(&mut self, table: &session::Table, flow: u64, now: Micros)
        -> Result<(), Error>;
    pub fn receive_authenticated(&mut self, table: &session::Table,
        record: &[u8], now: Micros) -> Result<Ingress, Error>;
    pub fn pending(&mut self, table: &session::Table, now: Micros)
        -> Result<Option<Pending<'_>>, Error>;
    pub fn confirm_admission(&mut self, id: OutputId, now: Micros)
        -> Result<(), Error>;
    pub fn confirm_written(&mut self, id: OutputId, now: Micros)
        -> Result<(), Error>;
    pub fn tick(&mut self, table: &session::Table, now: Micros) -> Result<(), Error>;
    pub fn next_deadline(&self) -> Option<Micros>;
    pub fn status(&self) -> OwnerStatus;
    pub fn quiesce(&mut self, now: Micros) -> Result<(), Error>;
    pub fn drained(&self) -> bool;
}
```

`stage_demand` reads the actual active relay counters, native unread bytes and
retained Data using the existing authoritative LTPR decoder. It accepts no supplied
Demand or measured facts. `stage_probe` explicitly reserves a bounded probe; it
does not assert demand or expose an RTT sample. Tests use actual admitted tables
and a finite fake common-MUX/writer handoff; that is pure ownership evidence only.
Durations are 1,000..=120,000,000 microseconds; emission count is 1..=256.
Validate absolute-deadline arithmetic and authoritative table
time range. Backward time, wrong actual table or exhausted counters fail explicitly.
Recoverable validation errors leave all owner state unchanged. Observing an
expired admitted handoff instead latches only terminal failure and retains every
immutable proof. All subsequent valid operations reject, including callbacks
using an earlier previously valid timestamp; the runtime must stop the session.
Successful tick/peek drops expired or terminal-flow
unadmitted work, while admitted immutable proofs survive until actual full write
or terminal timeout. Clock maintenance never renews a record/probe deadline.

`receive_authenticated` requires a trusted caller that has verified the retained
session identity/configuration, authenticated outer record type and ordered
complete record. This pure crate verifies neither TLS nor an invented evidence
token. TUN/TAP payload bytes beginning with `LTPM` cannot invoke it. The future
runtime calls it only from the verified adaptive-profile user-record dispatcher.
Pure tests exercise the state machine under that precondition, not cryptography.

The owner checks actual table identity, session, epoch, allocated active flow and
direction. Inbound Demand and EchoReply describe the local incoming stream;
inbound EchoRequest describes the local outgoing stream. Observed peer grants
must not exceed local authoritative grants. Native unread is bounded by the
receive ring and pending Data by the record maximum. New produced/grant offsets
cannot regress. A peer hint never acknowledges or releases retained memory.

### Serials and terminal owners

Keep the last serial and exact bytes for each allowed incoming flow/kind, at most
three per lifetime flow. Parse/scope checks precede lookup. Same serial and bytes
is Duplicate; same serial with different bytes is a conflict. Older serials are
Stale without changing response slots, rates, deadlines or sample freshness.
Serial gaps are valid because unscheduled generations coalesce. Novel messages
for unknown/Opening flows fail. A known terminal flow returns Stale for a novel
otherwise canonical/scoped record, with no sample or response; an exact retained
duplicate still returns Duplicate. This accommodates measurement bytes already
in the shared reliable path when a flow retires. A conflicting retained serial
still fails. Terminal traffic cannot recreate an owner or refresh proof storage.

Outgoing records use one checked nonzero owner counter, which also gives their
generation; this guarantees monotonic serials within every flow/kind. Coalescing
consumes a fresh serial. Nonces use a separate checked nonzero counter across all
flows and never repeat after idle/timeout. Neither counter is cryptographic
randomness. Exhaustion requires a new session. Wrong-owner, stale-generation and
wrong-transition output tokens fail without releasing the current slot.

### Common-MUX handoff

For N lifetime slots reserve N Demand slots, N EchoReply slots and one shared
EchoRequest slot. Each has one coalescible unadmitted record and at most one
admitted immutable generation. There is only one live probe token, including
after its request bytes finish. Demand/reply slots may hold a new dirty generation
while the older generation is admitted; requests cannot overlap live probes.

`pending` round-robins eligible slots and only borrows bytes. Failed common-MUX
admission changes no ownership, emission credit or probe timestamp. Copy the exact
bytes into the existing flow's shared DRR/channel queue and call
`confirm_admission` in the same synchronous single-owner section, with no await
or owner update between them. This debits one emission token and freezes that
generation. `confirm_written` accepts that exact generation only after the
retained writer completes the entire framed write and flush. Queue selection or
a TUN write cannot confirm it. No cancel-admitted operation exists initially:
accepted bytes complete or the session fails. Table Data/FIN ownership is separate.

Every copy uses the original flow's weight/channel and ordinary shared byte/count
budget, including the existing 48-byte outer-user charge. No Ready/Barrier/control
reservation, reverse-half shortcut, extra scheduler or per-flow capacity is added.
Saturation coalesces or blocks; it does not allocate another queue.

The local emission bucket permits the configured count per local interval and
does not accumulate catch-up credit. Inbound work is fixed per record; the future
runtime bounds calls per actor turn using existing reader/work limits. A valid
reliable-stream burst is not rejected by a differently phased receiver bucket:
network/writer queues can bunch compliant emissions. Incoming reports coalesce
bounded state; replies still obey local emission and shared-MUX budgets.

### Memory and work bounds

With fixed 104-byte storage buffers, including unused space for shorter echoes:

| Owner | Buffer count | Buffer bytes |
| --- | --- | --- |
| Unadmitted local slots | 2N+1 | 104(2N+1) |
| Admitted immutable proofs | 2N+1 | 104(2N+1) |
| Latest incoming duplicate proofs | 3N | 312N |
| Measurement-owner total | 7N+2 | 104(7N+2), at most 46,800 for N=64 |

The common arbiter/writer has at most one additional copy per admitted slot:
encoded bytes at most `160N+56`, or `256N+104` including the existing 48-byte
user-frame charge (16,488 at N=64). These copies must fit existing common queue
caps; the formula grants no additional capacity. No native payload is copied.

`MemoryBound` exposes buffer bytes, slot counts and metadata bytes separately.
Metadata uses checked `size_of` accounting for timestamps/tokens, incoming
serials, one probe/candidate and identities. B has no rate bins or sample history.
Capacities are fixed at construction. Allocator/Arc control-block overhead,
bounded temporary record copies, caller-retained tokens and runtime/TLS buffers
are separate. No map grows with serials, samples, duplicates or elapsed time.
One tick scans at most N flows and 2N+1 slots; parsing examines at most 104 bytes.

## C: observations and authority

The next [measured controller checkpoint](proxy-observation.md) proposes the exact
API, rate-bin mathematics and private echo completion seam. It remains design
only until its independent review gate passes.

### Original deadlines and asynchronous echo completion

A probe's deadline is fixed at creation plus probe timeout. Queueing, duplicates
and callbacks never renew it. Successful common-MUX admission stores its local
echo origin once. The resulting service latency includes local MUX/writer and
peer scheduling; it is neither native TCP RTT nor propagation alone.

The reader can deliver a reply before the actor observes local writer completion.
Retain one matching candidate `(nonce, received_at)`. Publish a sample only after
both the valid reply and complete write are observed, and both precede the
original probe deadline. Compute `received_at - admitted_at`, never subtract the
later flush callback. Zero/negative intervals do not qualify. Freshness starts at
reply receipt, not delayed publication; late callbacks cannot revive evidence.

Every admitted output separately gets one handoff deadline at admission plus
handoff timeout. Still-unwritten output at that deadline is terminal
HandoffExpired and latches terminal failure; deleting its proof or continuing
after an unknown partial write is forbidden. No earlier callback can recover the
owner after that observation. Probe expiry invalidates its sample but does not discard admitted
bytes. Unadmitted Demand/reply generations expire at creation plus pending TTL;
replacement requires a new observation/request. A never-admitted probe also
expires at the earlier pending TTL; its original creation-spacing reservation
still prevents an immediate replacement burst. Repeated peeks preserve timestamps.

`next_deadline` returns the earliest pending report/probe/rate/expiry/handoff work,
without catch-up loops or a serviced past deadline. `tick` processes expiry before
new work. Quiesce stops new reports/probes/replies, invalidates sample eligibility,
drops only unadmitted generations and waits for admitted copies. Novel post-quiesce
messages create no reply. The runtime's earliest original shutdown deadline always
wins and is never reset; its Barrier waits for admitted user work.

### Actual observations and planner composition

`observe_table` reads at most N actual entries without polling TCP. `relay_status`
supplies produced/peer-grant offsets, native unread and current immutable Data;
`credit_status` supplies ACK progress including terminal snapshots. A narrow
internal helper may reuse the authoritative LTPR parser to distinguish pending
Data from Credit/FIN; no second parser or header-size guess. Copies already handed
to the carrier are in flight, not newly unread native demand. Measurements and
pure native ACKs cannot create payload demand.

Rate is positive delta of authoritative acknowledged original bytes over local
sampling intervals. A completed bin retains both actual byte delta and actual
elapsed microseconds; divide summed bytes by summed time, not nominal interval
count. Complete a bin once elapsed time reaches the configured interval, provided
it is at most twice that interval. Include zero-delivery bins. A larger observation
gap clears the history and establishes a new baseline; discard its ambiguous
delta instead of placing it in a short fresh bin. No catch-up samples are created.
First observation also establishes a baseline. Terminal snapshots contribute at most
once; attaching after termination establishes a baseline rather than inventing
historic delivery. Reset-cleared queues and TUN/TLS writes cannot create ACKs.
Zero/stale rate is unavailable, with actual blockage reported separately. Echo
SRTT starts at its first eligible sample, then uses checked `(7 * old + sample)/8`;
its freshness remains the latest reply's original receipt time. Probe interval
spacing is measured from the prior request's creation, never from a duplicate.

Demand uses novel authenticated reports and local receipt freshness. A fresh
empty report starts idle timing; both emptiness and elapsed idle time are needed
to remove demand. TTL expiry makes evidence unknown and forbids growth, not
reservation release. Queueing can delay a new report, so receipt freshness does
not claim producer-observation age. Fresh actual ACK rate and echo service latency
remain necessary for growth. Credit-exhausted growth also requires reported grant
equal to the current relevant local grant; a new serial carrying an old grant
cannot keep obsolete exhaustion qualified.

Checkpoint C will separately define report/sample/demand-idle and rate-history
configuration: sample TTL at least report interval and probe timeout, demand idle
at least report interval, 1..=16 rate bins and checked
`2 * rate_interval * bin_count <= 120 seconds`. Those fields are not accepted by B.
The planned wrapper is `MeasuredConfig { allocation: adaptive::Config,
measurement: ObservationConfig }` and `Controller { planner, measurements }`.
`prepare` accepts only local shared-queue/native/writer pressure, derives feedback
and demand, and binds a plan to both measurement revision and the existing
table/planner snapshot. `apply` checks both revisions before the atomic planner
commit. Observation facts do not roll back on failed target apply; candidate
policy history must. There is no public setter for measured rate, native RTT or
synthetic ACK. Runtime pressure observations still require actual adapter evidence.

Only existing maintained ACK accounting releases grant debt. Measurement does
not release payload/native credit, retire flows, shrink issued right edges or
authorize an epoch. Demand, echo and rate can qualify bounded future growth;
staleness/pressure can suppress growth or reduce future targets. Native TCP RTT
remains unavailable. The future adaptive authentication digest binds every policy
limit and measurement version; the fixed proxy profile remains unchanged.

## Review and implementation gates

- [x] [MOD-PROXY-MEAS-01] Review checkpoint A's exact wire layout, intrinsic validation and failure-atomic API before code; B/C ownership and observation review remains separate. Evidence: [accepted A contract](#a-canonical-codec), [implemented codec boundary](../../crates/l2tunnel-tcp-proxy/src/measurement/wire.rs).
- [x] [MOD-PROXY-MEAS-02] Implement canonical codec with exact roundtrip fixtures, truncation/bounds/reserved-field tests and failed-encode atomicity; do not promote owner or observations. Evidence: [seven codec tests](../../crates/l2tunnel-tcp-proxy/src/measurement/wire/tests.rs), [literal canonical fixtures](../../crates/l2tunnel-tcp-proxy/src/measurement/wire/fixtures/demand.hex), [A validation scope](#checkpoint-a-validation).
- [x] [MOD-PROXY-MEAS-03] Implement actual-table identity, scope/role/phase checks, duplicate/conflict/stale rules and generation-bound pending/admitted/written transitions. Evidence: [bounded owner](../../crates/l2tunnel-tcp-proxy/src/measurement/owner.rs), [actual-table regressions](../../crates/l2tunnel-tcp-proxy/src/measurement/owner/tests.rs).
- [x] [MOD-PROXY-MEAS-04] Prove bounded coalescing/emission/buffers, no receiver-clock burst rejection, exhaustion and recoverable failed-admission nonmutation. Evidence: [finite storage and handoff tests](../../crates/l2tunnel-tcp-proxy/src/measurement/owner/tests.rs), [B validation scope](#checkpoint-b-validation).
- [x] [MOD-PROXY-MEAS-05] Prove original deadlines, reply-before-write callback, expiry while admitted, stale callbacks, quiesce/admitted-work drain prerequisites and cross-owner rejection. Evidence: [sticky-expiry and retained-proof regressions](../../crates/l2tunnel-tcp-proxy/src/measurement/owner/tests.rs), [bounded owner](../../crates/l2tunnel-tcp-proxy/src/measurement/owner.rs); actual runtime Barrier integration remains separate.
- [ ] [MOD-PROXY-MEAS-06] Implement native ACK rate, actual pending-payload reports, local-clock echo and demand hysteresis; test idle/gaps/zero/reset/terminal baselines and stale-grant exhaustion.
- [ ] [MOD-PROXY-MEAS-07] Compose observation revision with atomic target planning; stale/failed apply changes no policy history and releases no debt.
- [x] [MOD-PROXY-MEAS-08] Run A/B focused tests, strict lint/docs and independent review; retain separate C/runtime/native/window and B aggregate evidence gates. Evidence: [B validation](#checkpoint-b-validation), [owner regressions](../../crates/l2tunnel-tcp-proxy/src/measurement/owner/tests.rs), [A source-stable receipt](../../work/implementation-wave11/validation.json) predating B.
- [x] [MOD-PROXY-MEAS-09] Review the B-only owner API, actual-table role scope, MUX handoff ownership and exact memory/deadline geometry before implementation; C remains separate. Evidence: [approved bounded API](#b-actual-table-record-owner), [C-only observation boundary](#c-observations-and-authority).

## Checkpoint A validation

The implemented codec uses fixed fields and caller buffers, with no allocation,
retained state, clock or I/O. Three independently written literal hex fixtures
cover Demand, EchoRequest and EchoReply; tests also apply both directions to each.
These are vectors for the new contract, not Python parity or interoperability
evidence. Seven focused tests cover each truncation, bounded excess lengths,
every unknown discriminator value, reserved bytes/bits, zero identities/nonces,
late counter/flag rejection, u64 extremes, each insufficient output capacity,
and unchanged surrounding/trailing output on success or failure.
All 38 proxy package tests pass, including the seven codec cases and the 31
existing tests. Package formatting, strict all-target Clippy, warning-denied
rustdoc and checklist validation also pass locally.

Local commands for this checkpoint:

```text
cargo test -p l2tunnel-tcp-proxy --offline measurement::wire
cargo test -p l2tunnel-tcp-proxy --offline
cargo fmt -p l2tunnel-tcp-proxy --check
cargo clippy -p l2tunnel-tcp-proxy --all-targets --offline -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-tcp-proxy --no-deps --offline
python3 tools/check_checklists.py
```

The source-stable [wave 11 receipt](../../work/implementation-wave11/validation.json)
includes A and the earlier pure allocator: 702 Rust cases including doctests and
85 Python cases, with unchanged source hashes. It predates B's owner source.
No table Owner, serial admission, measurement freshness, authentication dispatch,
runtime capability, native window behavior or performance gate is implied by
that codec checkpoint alone.

## Checkpoint B validation

Fourteen owner cases exercise actual admitted Tables and maintained native legs.
Demand staging reuses the authoritative retained LTPR Data parser and leaves
table counters/output unchanged. Both roles are exercised. Fixed capacities,
per-flow/kind replay proofs, coalescing behind immutable admitted bytes, emission
counts, original TTLs, global nonce/serial exhaustion, input burst coalescing,
terminal flows, quiesce, early and late echo callbacks, and copied-scope actual
owner rejection have focused coverage. The bounded fake MUX/writer handoff uses
the exact record plus 48-byte cost; it is not actual runtime integration evidence.

Review found and fixed a terminal-expiry recovery gap: merely returning an error
allowed a later callback with an earlier valid timestamp to release proof. Expiry
now latches only terminal failure, and tests retain every admitted byte across
older callbacks and later tick/quiesce calls. Recoverable rejections compare the
entire mutable owner state before/after; no validation error partially consumes
serials, emission credit or proof slots.

An independent read-only owner/contract review found no material blocker after
the sticky-expiry fix; it did not rerun tests or qualify runtime behavior.
The package's 52 tests pass, including the unchanged 38 preceding cases. Package
formatting, strict all-target Clippy and warning-denied rustdoc pass locally.
Commands run for B:

```text
cargo test -p l2tunnel-tcp-proxy --offline measurement::owner
cargo test -p l2tunnel-tcp-proxy --offline
cargo fmt -p l2tunnel-tcp-proxy --check
cargo clippy -p l2tunnel-tcp-proxy --all-targets --offline -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-tcp-proxy --no-deps --offline
python3 tools/check_checklists.py
```

B does not expose delivery rate, RTT/SRTT, demand hysteresis, measured Planner or
Controller APIs. It has no socket/device/TLS adapter and cannot grant credit,
release ACK debt, change native windows or authorize hot switching. Full
ADAPT04/05 remain open. The subsequent source-stable
[wave12 aggregate](../../work/implementation-wave12/validation.json) includes B:
787 Rust cases and 105 Python cases passed, including strict lint/docs and the
unchanged prior tests. C/runtime/native authority remains separately gated.
