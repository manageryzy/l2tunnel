# Reusable Swift policy coordinator

Status: **implemented and focused-tested; common integration partially tested**,
2026-11-13. The integrator reviewed
the design/API before implementation. This scoped extraction refines FIX-11,
FIX-13 and SW-15. It preserves the retained Swift
runtime's policy protocol; it does not complete full SW-11, select a new default,
or complete the common-policy fault matrix or native qualification. The [Swift contract](swift.md),
[numbered records](swift-record-engine.md), [fixed control delivery](control-delivery.md)
and [shared secure-session contract](secure-session.md) remain authoritative.
No existing `SPC-*` task namespace was present when this design was written.

## Ownership and exact public API

One `l2tunnel_swift::policy::Coordinator` owns the proposal, digest agreement,
directional drain/barrier phases, original deadline, bounded outstanding output,
committed policy and request outcome. Both the retained TLS adapter and the new
common-control adapter consume this owner. Neither adapter implements another
transaction state machine. Authentication, reliable ordering/deduplication,
crypto, pacing, packet counters, actual I/O and frontend reporting remain outside.

```rust,ignore
Time(pub u64);                   // injected monotonic microseconds
Epoch(pub u64);                  // logical Swift policy epoch; startup may be 0
Digest(pub [u8; 32]);
OutboundId(pub u64);             // local custody identity, never a wire counter
Authority::{Coordinator, Participant}
Settings { transaction_micros: u64, max_outbound: usize }
Direction { records: records::Config, bytes_per_second: u64 }
Resolved { send: Direction, receive: Direction, digest: Digest }
Committed { epoch: Epoch, policy: Option<control::Policy> }
Outbound { id: OutboundId, message: control::Message }
Status { send_drained: bool, receive_deliverable: bool,
         receive_drained: bool, next_number: records::RecordNumber }

trait Hooks {
    type Error;
    fn status(&self) -> Status;
    fn replace_send(&mut self, now: Time, policy: Direction,
                    feedback_from: records::RecordNumber) -> Result<(), Self::Error>;
    fn replace_receive(&mut self, policy: Direction,
                       source_from: records::RecordNumber) -> Result<(), Self::Error>;
}

Coordinator::new(authority: Authority, initial: Committed,
                 settings: Settings, now: Time) -> Result<Coordinator, Fault>
Coordinator::request(now: Time, policy: control::Policy,
                     resolved: Option<Resolved>) -> Result<(), RequestError>
Coordinator::receive<H: Hooks>(now: Time, message: control::Message,
    resolve: impl FnMut(&control::Policy) -> Option<Resolved>, hooks: &mut H)
    -> Result<(), Error<H::Error>>
Coordinator::progress<H: Hooks>(now: Time, hooks: &mut H)
    -> Result<(), Error<H::Error>>
Coordinator::outbound() -> Option<Outbound>
Coordinator::complete_outbound(now: Time, id: OutboundId) -> Result<(), Fault>
Coordinator::{check, deadline, admission_allowed, committed, pending, take_outcome}(...)
```

`check(&mut self, now: Time) -> Result<(), Fault>` observes successful monotonic
progress and checks the pending original deadline. `pending() -> Option<Pending>`
returns public nonsecret `epoch`, `deadline`, `policy`, `digest`, `send` and
`receive` observations. `admission_allowed()` permits idle, Proposed and local
send-Done admission; it denies Draining/Barrier admission independently of the
receiving phase. `outstanding()` iterates bounded owed output without releasing
custody. These observations do not fabricate actual data-path or I/O completion.

`Fault` distinguishes invalid configuration, nonmonotonic time, original deadline,
out-of-state input, digest disagreement, capacity and counter/ownership errors.
`Error<E>` preserves a hook's actual application error. Request refusals remain
separate from a session-ending fault. `Outcome` is local `Applied(Epoch)` or
`Rejected`; transport teardown remains the runtime's `Closed`/`OutcomeUnknown`.
The coordinator does not promise rollback after either direction changed.

The timeout is required and positive, with checked absolute addition. There is
no library timeout default. The legacy adapter explicitly supplies its existing
ten-second value; this does not select a common-session timer. Outstanding output
is limited to a configured 1..=64 messages, preallocated before peer traffic.
Identical messages already owed can share custody, and repeated pending proposals
retain the same Accept/digest. Capacity and counter checks precede effects.

## Directional barriers and output custody

Before agreement, admission and old-policy forwarding continue. Agreement stops
new native admission. `send_drained` means every queued source was emitted and
every retained source confirmed; queue emptiness alone is insufficient. The
Barrier captures the next full authenticated User record number, never the cover
number, management number, ARQ source identity or a truncated seed.

An authenticated peer Barrier enters receive flushing. Deliverable native records
must finish before replacement. If nothing is deliverable but pending old receive
state remains, the barrier is invalid. Successful receive replacement installs the
new decoder/header contexts and source floor before the BarrierAck is owed.
Successful send replacement installs the new encoder/header contexts and feedback
floor before admission resumes. Hooks apply synchronously; an error ends the
session, rather than advancing a successful phase or fabricating completion.

The caller borrows the same outstanding token until transport completion. Merely
reading or encoding a message does not remove custody. Legacy TLS completes only
after its actual write and flush succeed. A common adapter must define and verify
its bounded reliable completion evidence, retain the exact submitted source and
map its source identity to the token; repeated polling must not submit a new
logical source. A receipt-backed common adapter may provide stronger evidence
than TLS flush, which does not establish peer observation. Repeated completion of
an already completed token is idempotent; an unknown or out-of-order token fails.

Both directions must be Done and all owed output completed before `progress`
publishes a committed epoch/outcome. Every receive, progress and output-completion
turn checks the same original deadline first. Proposal waiting, drains, flushing,
barrier waiting, blocked terminal writes and receipt waiting cannot renew it.
The runtime includes that deadline in its wake and performs a fresh time check
after awaited writes. Terminal reports and requester closure remain runtime work.

The exact existing `control::Message` framing/bytes remain unchanged. Existing
strict unexpected-message rejection is preserved; the reliable transport supplies
ordered, once-only logical delivery despite physical retries. An explicit repeated
pending Propose gets the same answer without re-resolution or deadline renewal.

## Adapter and common-control limits

The legacy public Config/Resolved/Resolver/Switcher APIs stay intact. A bounded
one-transaction cache retains the exact runtime Resolved configuration, including
custom resolver network charging and local reporting fields. The pure Direction
contains only records and rate. Hooks apply the cached exact configuration and
rebuild the legacy pacer; this cache holds configuration, not transaction phases.
Crypto counters, replay, key generations, record statistics and private wire bytes
are retained across the extraction.

The existing common L2SC Management body requires an L2MC frame; raw Swift bytes
cannot be relabeled as that body. The integrator owns an explicit typed/versioned
ProfileControl dispatch and its session/epoch/digest admission. The existing
management `transaction::Peer<C>` has a different commit/retire/reconciliation
protocol; mapping Swift kinds onto it would change semantics. The session owner
must serialize transactions across profile-specific coordinators.

Crossing Swift directional barriers can combine sources from the old send policy
with feedback from a newly replaced receive policy. Common wrapping must preserve
the actual feedback provenance through typed/scoped dispatch or an equally explicit
mixed-direction format. One global User scope activation alone does not solve it.
The parent owns the outgoing-scope and fixed-envelope integration. This extraction
does not remove any barrier, profile, RLNC/parity/rolling/packed/proxy requirement,
or turn within-Swift policy change into SW-11 cross-profile switching.

## Acceptance and evidence

- [x] [SPC-01] Record and review the pure API, original deadline, directional hooks, bounded output custody and exact legacy adapter/cache contract before implementation. Evidence: this pre-implementation contract, integrator API review and the [public pure API](../../crates/l2tunnel-swift/src/policy.rs).
- [x] [SPC-02] Implement one pure coordinator with typed bounds/errors, unchanged Message bytes, explicit refusal/violation behavior, duplicate proposal handling and no runtime/clock/I/O dependency. Evidence: [coordinator](../../crates/l2tunnel-swift/src/policy.rs), unchanged [Message codec](../../crates/l2tunnel-swift/src/control.rs) and [seven passing pure tests](../../work/directional-control-focused-20261113/attempt-2/06.log).
- [x] [SPC-03] Verify proposal, drain, flushing, barrier and terminal-output deadlines, failed hooks, no false Applied/rollback, bounded custody, idempotent completion and checked time/epoch/token limits. Evidence: [actual record-engine, deadline, failed-hook and ownership regressions](../../crates/l2tunnel-swift/src/policy/tests.rs) and [passing focused receipt](../../work/directional-control-focused-20261113/attempt-2/validation.json).
- [x] [SPC-04] Refactor the retained runtime to consume that owner; preserve public APIs, exact custom resolved fields, pacing, floors, counters, cumulative snapshots and terminal report/requester semantics. Evidence: [single coordinator consumer and exact-config adapter](../../crates/l2tunnel-runtime/src/swift.rs), including the custom-Resolved regression, retained lossy directional transition and paused-runtime terminal-write/report tests; [17 tests passed](../../work/directional-control-focused-20261113/attempt-2/07.log).
- [x] [SPC-05] Pass meaningful pure tests with actual numbered record engines and all retained runtime policy/deadline tests; record exact focused source/command evidence and preserve failed attempts. Evidence: [source-stable focused result](../../work/directional-control-focused-20261113/attempt-2/validation.json), [pure test log](../../work/directional-control-focused-20261113/attempt-2/06.log), [legacy test log](../../work/directional-control-focused-20261113/attempt-2/07.log) and [strict five-package Clippy log](../../work/directional-control-focused-20261113/attempt-2/08.log). The [first failed attempt](../../work/directional-control-focused-20261113/attempt-1/validation.json) remains preserved.
- [ ] [SPC-06] Integrate typed authenticated fixed common control with actual same-socket policy changes, original deadlines, loss/retries, crossing directional feedback, delayed old records and control progress under saturated data. Partial evidence: the [same-socket driver](../../crates/l2tunnel-runtime/src/secure_udp/transport.rs) and paired-service policy tests passed the [focused integration batch](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json). Complete fault/old-record/saturated-data qualification remains open; a clean successful transaction does not prove all retry and terminal-custody paths.
- [x] [SPC-07] Pass the source-stable aggregate and retain native/platform/performance limitations; full SW-11 and SEC lifecycle gates remain open at their stated scope. Evidence: the [required source-stable aggregate](../../work/secure-udp-runtime-service-20261113/attempt-1/validation.json) passed all local workspace checks with 1487 Rust cases including doctests, 271 Python tooling cases and 1658 simulator cases; formatting, strict workspace Clippy and rustdoc passed, and before/after input hashes match. The actual common adapter and retained legacy runtime are checked; SPC-06, full SW-11 and the SEC lifecycle gates remain open.

The pure/legacy [focused receipt](../../work/directional-control-focused-20261113/attempt-2/validation.json)
records exact offline/locked commands, stable input hashes and logs: seven pure
coordinator tests,17 retained runtime tests, adjacent scoped-record/control/receipt
checks and warning-denied five-package Clippy on local Linux. The subsequent
[combined common-runtime focus](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json)
also exercises actual same-socket transport and paired-service policy transactions.
That partial integration evidence does not finish the complete loss/retry,
old-record, saturated-data and terminal-custody matrix named by SPC-06. The required
source-stable `python3 tools/check.py` aggregate passed under SPC-07. Native
devices/performance, other platforms, ISP/QoS behavior and full SW-11 remain outside
these focused receipts.
