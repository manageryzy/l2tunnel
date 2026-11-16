# Reserved common record engine storage

Selected compact v3 now uses this module through the existing runtime owners.
See [runtime algorithm migration](compact-wire-cleanup.md#runtime-algorithm-migration)
for the selected wire representation, exact-cost boundaries and validation scope.
Legacy constructors and historical receipts below retain their original meaning.

Status: **actual single Swift owner and complete reserved common Engine
implemented and protocol-tested; full mixed Bank/runtime/resource/stage gates
remain open**. The source-stable affected checkpoint passes142 distinct cases,
including32 new focused cases, with exact failed-test repairs and reuse.
Start from `dd16d1b`, the actual [functional Engine](common-record-engine.md),
[Swift backing](swift-storage.md), [record recovery backing](record-recovery-storage.md)
and [Aligned/Packed backing](aligned-record-storage.md). Read the architecture,
implementation plan/checklist and mode parity first. This is an engineering
composition contract, not an owner decision, default change or scope reduction.

## Actual single Swift owner

The common owner cannot embed a second two-slot Swift Set in every common slot.
Add `swift::storage::Owned` using the same actual Plan, Allocation and reserved
records constructor. It is move-only and contains exactly one actual duplex
record Engine. It exposes no mutable Engine, backing, replacement, into-inner or
clone escape. Existing Set/Entry APIs and wire/default behavior stay compatible.

```rust
pub struct Owned { /* one actual inline engine and immutable usage */ }
pub struct OwnedUsage {
    pub limit_bytes: usize,
    pub fixed_bytes: usize,
    pub heap_bytes: usize,
    pub allocations: usize,
}
impl Owned {
    pub fn new(plan: Plan, limits: Limits) -> Result<Self, Error>;
    pub fn engine(&self) -> &records::Engine;
    pub fn entry(&mut self) -> Entry<'_>;
    pub fn usage(&self) -> OwnedUsage;
}
```

The unchanged Plan counts heap only. Owned admission checks
`size_of::<Owned>() + plan.capacity_bytes() <= limits.capacity_bytes` before the
first allocation. Actual successful requested layouts must equal that Plan.
Partial owners drop on failure before publication. No existing engine or its
identity, clock, contexts and pending data changes. Allocation count observes
explicit successful nonzero constructor reservations, not process allocations.
The common Engine counts this inline Owned only inside its actual outer enum,
then adds only Owned's heap; it never sums the nested fixed header twice.

The functional Engine's private Swift representation will use this same one
owner instead of its one-occupied-slot legacy Set. This does not change its
qualification or select a carrier. Actual comparisons must prove original full64
numbered bytes, selected channels, admission identities, receive bytes, feedback
and drain against the existing Set, including unequal directions and loss.

## Actual reserved Engine composition

The packet/MUX, QoS and Pipeline additive interfaces are now engineering-frozen
in [common queue storage](common-queue-storage.md), [QoS storage](qos-storage.md)
and [Pipeline storage](pipeline-storage.md). Their actual implementations precede
execution; an approved interface alone is not passed resource evidence.

The common Engine continues to own one actual Pipeline and one actual Swift,
Aligned or Packed duplex owner. Preserve the current functional constructor as
explicit functional selection. Add a distinct reserved constructor after actual
queue storage interfaces freeze; never fall back to unreserved construction.

The engineering target surface is:

```rust
record_engine::storage::{Limits, Plan, Usage, Error}
Plan::for_engine(configuration, context, geometry, native_limits) -> Result<Plan, Error>
Plan::{configuration(), context(), geometry(), native_limits(), capacity_bytes(), heap_bytes()}
Engine::new_reserved(plan, limits) -> Result<Engine, storage::Error>
Engine::storage_usage() -> Option<storage::Usage>
Engine::enqueue_borrowed(now, bytes) -> Result<PacketMetadata, record_engine::Error>
Engine::admit_borrowed(now) -> Result<Option<pipeline::Admission<ProfileIdentity>>, record_engine::Error>
```

The reserved Engine storage surface is now frozen with the exact types below:
Limits contains `capacity_bytes:usize`. Usage contains `limit_bytes`,
`fixed_bytes`, `pipeline_bytes`, `record_bytes`, `capacity_bytes` and
`allocations`, all usize. Construction Error variants are `Engine(super::Error)`,
`Pipeline(pipeline::storage::Error)`, `Swift(swift::storage::Error)`,
`Aligned(aligned::storage::Error)`, `Layout`, `Limit{required:usize,limit:usize}`
and `Invariant`. Plan owns private immutable full configuration/context/geometry/
native limits, validated scalar parameters and actual Pipeline/profile plans.
Its configuration getter borrows the exact full value; other input getters
return their Copy values. `capacity_bytes` is fixed+heap, `heap_bytes` excludes
the Engine header for future inline generation-bank accounting.

`Qualification::Reserved` reports complete actual backing of this one Engine,
not complete runtime/external/mixed-generation qualification. Old owned-output
`admit_one` on that constructor returns additive `record_engine::Error::OwnedOutput`
before selecting or admitting a codec head. Actual borrowed input and admission
remain available. Existing functional entry points retain their original results.

Plan's complete Engine capacity is actual `size_of::<Engine>()` plus complete
actual Pipeline heap plus complete selected-record heap. Nested plans count heap
only and actual successful usage must agree. Configuration/context/geometry and
native limits are immutable and field-preserving. Share the authoritative scalar
capability/geometry validation with the functional constructor; do not allocate
dummy owners to validate. Keep existing explicit unsupported Active/credits,
TCP-proxy and native-window requests, with their full requirements open.

Pipeline owns actual FlowTable/affinity/registration/by-ID/channel/flow metadata,
and only the selected queue owns actual packet storage: MUX for TAP, Scheduler
for TUN. A TUN borrowed-transit MUX still exists and has its actual channel
metadata counted, without unused packet slabs. Physical `packet_count * max_len`
slabs are charged even when larger than logical byte capacity. Enforce original
logical global/per-flow bytes and packet counts separately, without new clamps.

Actual reserved input/output methods borrow original bytes and return actual
metadata plus the maintained codec's identity, with no allocated payload result.
All user packets, probes and TCP controls still enter the same Pipeline policy.
Only callback Some releases the original selected slab slot and charges service;
None/error retains exact bytes, metadata, counters and original queue position.
Keep the same existing classifier/MUX/DRR state machines, not a second algorithm.
Legacy owned-output methods remain explicitly allocating conveniences outside the
reserved packet-path contract. A reserved Engine refuses an owned-output entry
point before codec mutation if that operation would allocate an output Vec.

`Usage` separates the complete inline header, actual Pipeline heap, actual record
heap and successful explicit reservations. It is retained requested-layout
accounting, excluding allocator rounding/bookkeeping/RSS, stacks, physical pages,
OS buffers and caller input/output/witness buffers. Those real external owners
must be counted once by the later mixed-generation/runtime envelope; a numeric
external byte label cannot establish their actual bounded behavior.

## Unchanged full integration and evidence requirements

This work is a prerequisite for an actual two-slot mixed-profile Set/Bank. That
owner must precharge current + building/prepared/draining + actual external
capacity before construction and retain attempted peaks. Construction failure
drops the partial owner before releasing its charge, preserves the old owner and
consumes no generation token. Commit installs the exact virgin prepared owner;
retirement requires actual protocol drain and separately authenticated physical
native/control/feedback custody. This contract does not claim those behaviors
are running merely because Engine allocation succeeds.

Keep SW-11, CRE-02..CRE-08, GSU-05, SRS-07, full allocator/drop/inventory gates,
retained recovery, fresh-DH runtime, RLNC/parity/rolling/packed/proxy, all47 modes,
original carrier/platform/native and80 Mbit/s requirements unchanged. Public
libraries remain independent of Tokio, OS handles, privileges, real clocks and
device setup. No source/documentation/memory interpretation is an owner decision.

Root owns Swift storage additive owner and facade composition, root manifests,
ledgers and every Cargo/fmt/check/test/Git/native execution. Independent workers
own packet/MUX, QoS and Pipeline modules with their linked storage contracts.
Freeze each dependency API before consumer production. Tests use actual owners,
independent exact bytes/identities, failure/refusal/deadline paths, complete
capacities and stable buffer reuse. Run affected groups with bounded parallelism
from one source-frozen build; preserve failed receipts and unchanged-input reuse.

- [x] [CSE-01] Freeze actual movable Swift owner, exact fixed/heap accounting and restricted API before production; preserve old Set/Entry behavior and record no owner scope decision. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [CSE-02] Implement and test the actual single movable Swift reserved owner, exact/one-short limits, every local constructor refusal, full64 bytes/identities/feedback and unequal-direction differential behavior against the existing Set. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [CSE-03] Freeze and implement the actual complete common Engine Plan/Usage/new_reserved using real reserved Pipeline and selected Swift/Aligned/Packed owners; no double-counted headers, dummy owners or compatibility fallback. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [CSE-04] Integrate actual borrowed common queue admission and selected codec identity without packet-time payload allocation or a second classifier/MUX/DRR; prove exact Full/error retry and original widths, budgets and metadata. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [ ] [CSE-05] Exercise actual reserved common Engine paired protocol/native-custody operations across supported families and unequal policies, original deadlines/identity/witnesses, exact capacities, pressure, repairs and malformed inputs while preserving functional compatibility.
- [ ] [CSE-06] Qualify complete nested construction failure/drop, actual full backing inventory reuse and old-owner isolation before publication; local failpoints or numeric equality alone do not qualify literal dependency allocator events.
- [ ] [CSE-07] Integrate actual reserved mixed-profile current/prepared/draining Set/Bank, complete shared external ownership and authenticated switching/physical retirement, without reconstruction or security-state reset; preserve full SW-11 and CRE definitions.
- [ ] [CSE-08] Pass affected source-stable checks and required full-stage acceptance with exact commands/selection/time and honest evidence reuse; retain native/platform/performance/ISP boundaries.

## Affected checkpoint boundary

The [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) records exact commands, bounded parallel execution, source
hashes and evidence reuse. Initial failures remain failed receipts. Local
Linux pure-protocol and selected existing caller tests do not establish selected
reserved runtime integration, full nested allocator behavior, physical native
acceptance, Windows/Android devices, performance or ISP classification. The
required full-stage `tools/check.py` gate remains open.
