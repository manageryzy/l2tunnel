# Actual record admission handoff

Status: **frozen engineering contract, implementation and focused tests authored,
not yet executed** from clean checkpoint `d988ab4`. No execution result is claimed. This
is the actual queue handoff prerequisite beneath
[CRE-03](common-record-engine.md), not the common record Engine or a new owner
scope decision. Full CRE, SW-11, GSU-05, SRS-07, every requested algorithm,
mode-parity, native, resource and platform requirement remains unchanged.

The integrator owns public facade/manifest registration, common Engine consumers,
master ledgers, validation and Git. This lane owns MUX/QoS/Pipeline source plus
dedicated handoff tests and this document. Preserve the shared scalar validators.
All libraries remain independent of OS handles, Tokio, privileges and real clocks.
The [source proposal](../../work/record-composition-20261114/common-record-engine/next-transactional-handoff-v0.md)
retains its historical scope; the pre-production binding for this slice lives
in [the pre-production binding](../../work/common-record-engine-20261114/record-admission-handoff-pre-production-v0.json).

## Actual gap and frozen public interfaces

At the bound checkpoint, MUX popped bytes and advanced RR before a codec saw
them. TAP Pipeline then read separate metadata and subtracted accounting. TUN
already supported a selected-head eligibility/commit transaction, but its commit
saw Candidate metadata only; actual bytes remained inside the existing DRR
owner. Scheduler service subtracted checked counters after popping, and Pipeline
performed additional checked bookkeeping after downstream commit. The authored
handoff moves those checks before real codec admission.

```rust
// In l2tunnel_mux.
pub enum OfferError<E> {
    Channel, Budget, Busy, Invariant, Downstream(E),
}
Mux::offer_front<T, E>(
    &mut self,
    offer: impl FnOnce(u16, &[u8]) -> Result<Option<T>, E>,
) -> Result<Option<(u16, Vec<u8>, T)>, OfferError<E>>;
Mux::offer_selected<T, E>(
    &mut self, channel: u16, bytes: &[u8],
    offer: impl FnOnce(u16, &[u8]) -> Result<Option<T>, E>,
) -> Result<Option<T>, OfferError<E>>;

// In l2tunnel_qos.
pub enum OfferError<E> { Schedule(ScheduleError), Downstream(E) }
Scheduler::offer_selected<T, E>(
    &mut self,
    offer: impl FnOnce(PacketHead, &[u8]) -> Result<Option<T>, E>,
) -> Result<Option<(ScheduledPacket, T)>, OfferError<E>>;

// In l2tunnel_pipeline, retaining existing public result/error types.
Pipeline::offer_front<T, E>(
    &mut self,
    offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>,
) -> Result<Option<Admitted<T>>, DequeueError<E>>;
Pipeline::offer_with<T, E>(
    &mut self,
    eligible: impl FnMut(Candidate) -> bool,
    offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>,
) -> Result<Option<Admitted<T>>, DequeueError<E>>;
```

`offer_front` chooses actual TAP RR or all-eligible TUN service.
`offer_with` remains explicitly TUN-only: TAP returns TunOnly without executing
eligibility or admission callbacks. TUN eligibility retains the existing once
per active head policy. Callback receives exact ingress PacketMetadata,
including its original classification and selected binding.channel, plus the
actual retained bytes. Original Vec ownership transfers on Some; no empty
replacement Packet, payload clone, pop/requeue, extra queue or classifier exists.

None means empty/all-ineligible or actual downstream Full/Busy. An actual codec
success returns Some(original identity/token). Downstream E becomes the existing
DequeueError::Commit. Queue arithmetic/invariant failures occur before callback
entry and retain their typed Pipeline/Schedule category. MUX invalid channel,
budget and busy refusals are typed for its borrowed selected API; Pipeline
treats those as internal inconsistencies because its real admission already
established the same channel and budget bounds.

## Selection, preflight and commit

Queued MUX selection scans with a local index. Until Some, its actual RR cursor,
FIFO payloads, counts and bytes are unchanged. On Some, return the original
allocation and move the cursor exactly as old pop did. Empty scans preserve the
existing cursor behavior. Each scan is bounded by installed channel count.

DRR `peek_eligible` already changes eligibility, resets blocked deficits and may
traverse/credit the ring to select a head. Retain those existing semantics rather
than claim whole-call rollback. The new Scheduler operation consumes only the
actual already selected head; no second eligibility scan or additional round
credit occurs. None/error preserves the selected state and payload and spends
no successful service debit. Existing APIs retain their selection behavior.

Preflight before the callback includes exact selected/front identity and length,
nonempty bytes, representable charge, sufficient deficit, per-flow/global
bytes/counts, metadata/classification length and channel, correct flow/by-id
binding, and last-packet ring/cell cleanup. Compute every subtraction and next
cursor before admission. A private checked plan is local scratch, never another
payload owner, retained transaction FSM or public authority token.

After Some, commit with only infallible ownership moves and precomputed values.
Take the payload from its already borrowed Box cell, discard the now empty FIFO
cell, and apply planned counters/metadata/ring changes. No fallible map lookup,
checked arithmetic, downstream retry or packet allocation follows actual codec
acceptance. No unsafe code, packet-triggered panic or rollback snapshot is needed.
Share the checked preflight/application with the old service paths where needed;
do not fork a different scheduler or acceptance policy.

The queue cannot undo arbitrary callback side effects. Actual codec Full/Busy
may return None only under its maintained no-admission contract. A terminal
codec error after partial mutation is terminal: retain queue custody until
session cleanup and never retry those bytes into the damaged engine.

## Borrowed TUN MUX transition

The previous TUN path pushed a selected Scheduler payload into an otherwise
empty MUX and immediately popped it. The authored borrowed MUX `offer_selected`
performs that same configured admission and RR transition while Scheduler keeps
the original allocation until codec acceptance. Check channel, nonempty length,
shared byte/count ceiling and actual empty state before its callback. None/error
changes no MUX state. Some advances only the same RR cursor that immediate
push/pop would leave; queued byte/count state remains empty. This avoids a
second payload owner and post-admission Vec-to-Box allocation.

The surrounding Pipeline still owns all originals and enforces its existing
aggregate/per-flow budget across DRR and MUX stages. This is an actual shared MUX
policy call, not a claim that empty MUX counters account for originals retained
inside DRR. Preserve real admission metadata and channel selection; no bypass
for probes, TCP controls or user packet kinds is permitted.

Credit eligibility remains pure. Any external credit spent with actual codec
admission requires reversible reservation before the callback and commitment
only on Some; release on None/error. This seam does not install an unavailable
credit/proxy policy or make two irreversible operations atomic.

PacketMetadata currently has no per-packet admission timestamp/deadline. Do not
derive original age from FlowSnapshot.last_activity or call dequeue physical
first-send. Existing externally owned operation/recovery caps remain unchanged;
complete per-packet age forwarding needs its own explicit metadata contract.

## Tests, resource boundary and stable tasks

Dedicated child tests own actual queue instances and allocations. Cover two
channels with leading empty channels and multiple FIFO heads; repeated None/error
then Some must preserve exact bytes/pointers/metadata/counters and old RR order.
For DRR, select a real weighted head, refuse repeatedly, then accept; verify no
additional debit/round credit, blocked-head skip and unchanged successful order.
Private inconsistent accounting must refuse before callback entry. Pipeline
TAP/TUN checks exact original classification/channel/bytes and once-only
metadata/accounting removal, including TUN-only rejection on TAP. Preserve old
tests and compare legacy versus new successful selection on the same inputs.

The authored production entry points live in the actual
[MUX](../../crates/l2tunnel-mux/src/lib.rs),
[Scheduler](../../crates/l2tunnel-qos/src/lib.rs) and
[Pipeline](../../crates/l2tunnel-pipeline/src/lib.rs). Existing pop/dequeue APIs
share those checked paths. Focused child modules contain three MUX, three QoS and
four Pipeline tests. Their assertions cover retained pointers across repeated
refusal, successful FIFO/RR/weighted order versus existing public APIs, actual
blocked heads, exact ingress classification/channel, once-only accounting,
TAP-only policy boundaries and private corrupted-state refusals before callback
entry. The [source-stable affected batch](../../work/common-record-engine-20261114/handoff-scoped-validation.json)
passes49 actual queue tests across the three packages, including these10 new
cases. The three independent binaries use four threads each; the slowest test
binary takes0.157 seconds after a1.563-second shared build. An initial strict
Clippy type-complexity failure remains recorded; a documented equivalent tuple
alias passes the repair check without repeating unchanged behavioral tests.
This is local protocol evidence, not full-stage or physical-device acceptance.

The actual facade common Engine consumer owns real Swift/Aligned/Packed callback
integration checks: selected channel different from legacy hash, actual Full/Busy,
original profile identity and exact retry. Queue-only callback tests qualify
the seam, not record-profile integration or physical delivery.

New callbacks/ownership moves allocate no backing. Existing legacy construction
and enqueue storage remain unreserved. Complete fallible MUX/Pipeline/FlowTable/
QoS and nested profile resource admission remain required; this slice does not
qualify CRE-06, complete GSU-05/SRS-07 or literal CRS-06. Existing native/control
owners and their caps remain unchanged. Protocol tests do not prove runtime,
platform or performance acceptance.

- [x] [RAH-01] Freeze exact signatures, typed errors, actual ownership, DRR selection semantics, complete preflight and source binding before implementation; no owner scope decision is inferred. Evidence: the engineering interface freeze and original source hashes are retained in the [pre-production binding](../../work/common-record-engine-20261114/record-admission-handoff-pre-production-v0.json).
- [x] [RAH-02] Implement actual queued and borrowed selected MUX admission with original allocation/RR behavior and no destructive refusal or hidden queue. Evidence: [actual MUX code](../../crates/l2tunnel-mux/src/lib.rs) and [five passing package tests](../../work/common-record-engine-20261114/handoff-scoped-validation.json), including three new handoff cases.
- [x] [RAH-03] Implement actual selected DRR byte admission with all service checks before callback and unchanged eligibility/weighted order across old and new APIs. Evidence: [actual Scheduler code](../../crates/l2tunnel-qos/src/lib.rs) and [24 passing package tests](../../work/common-record-engine-20261114/handoff-scoped-validation.json), including three new handoff cases.
- [x] [RAH-04] Forward exact original Pipeline bytes/channel/metadata through TAP/TUN with preflighted accounting, original ownership and no extra classifier/queue. Evidence: [actual Pipeline code](../../crates/l2tunnel-pipeline/src/lib.rs) and [20 passing package tests](../../work/common-record-engine-20261114/handoff-scoped-validation.json), including four new handoff cases.
- [x] [RAH-05] Pass focused actual-queue refusal, invariant, ordering, ownership and legacy differential tests in the source-frozen affected batch; distinguish queue contracts from actual record Engine integration. Evidence: [49-case scoped receipt](../../work/common-record-engine-20261114/handoff-scoped-validation.json) preserves the initial failed aggregate, exact alias-only repair and unchanged-input reuse; real-profile consumer/native gates remain open.
- [ ] [RAH-06] Integrate the actual common record Engine consumer and reconcile full CRE/resource/native/platform/stage acceptance without reducing any parent definition.
