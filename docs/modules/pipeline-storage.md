# Fallible packet Pipeline storage

Status: **implemented and protocol-tested:28 Pipeline cases, including eight
new storage cases, plus actual reserved common Engine consumers**. Full nested
allocator/drop, mixed-generation, selected runtime and stage gates remain open.
The baseline supplied by the integrator is `dd16d1b`. The
[pre-edit source binding](../../work/common-queue-storage-20261115/pipeline/preedit-v0.json)
records the inputs read before production changes. This contract precedes code;
it records an engineering interface proposal, not an owner decision or a reduced
mode requirement.

Read the [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[implementation checklist](../implementation-checklist.md), [mode parity](../mode-parity.md),
[existing Pipeline](pipeline.md), [transactional handoff](record-admission-handoff.md)
and [common record Engine](common-record-engine.md). Complete CRE-06, GSU-05,
SRS-07, full SW-11, Active/tunnel-credit, proxy, rolling/RLNC/parity, all47 modes,
selected runtime/native/platform qualification and the80 Mbit/s requirement
remain unchanged and open.

## Existing owners and actual allocation gap

`l2tunnel-pipeline::Pipeline` already owns the actual classifier, FlowTable,
TAP MUX or TUN Scheduler, per-flow observations, reverse ID lookup and packet
classification sidecars. Preserve those algorithms and their actual transitions;
do not introduce another classifier, queue, DRR implementation or channel mapper.

| Existing storage | Current allocation point | Reserved replacement |
| --- | --- | --- |
| FlowTable | Flow assignment/learned registration map nodes | Dependency's actual fixed reserved FlowTable |
| Pipeline states | Per-flow BTreeMap nodes | Sorted capacity-F registration vector |
| Reverse IDs | BTreeMap nodes on registration | Sorted capacity-F `(FlowId, FlowKey)` vector |
| TUN sidecars | One growing VecDeque per flow | One shared capacity-P metadata pool with per-flow FIFO heads |
| TAP sidecars | Growing VecDeque per channel | The same capacity-P pool with C channel FIFO heads |
| TAP packet bytes | MUX per-packet Box plus channel queues | Dependency's actual P-slot reusable MUX payload slab |
| TUN packet bytes | Scheduler per-packet Box, per-flow queues and active ring | Dependency's actual reserved Scheduler slab and DRR metadata |
| TUN MUX admission | Empty MUX retains channel policy/cursor only | Fallible handoff-only MUX; no unused second packet slab |

F is flow capacity, C is channel count, P is shared packet count and M is maximum
original packet length. TUN instantiates one class with the existing class0
weight1. TAP instantiates no Scheduler. Actual byte capacity is distinct from
the existing logical shared byte/count allowance. A P*M slab is charged fully
even when it exceeds the logical queue byte limit. No metadata/payload capacity
is represented by a fabricated Usage observation.

## Additive public boundary

Constructor errors remain separate from packet/policy errors. Plans contain
private checked complete configs/layouts; planning performs no allocation.

```rust,ignore
pub mod storage {
    pub struct Limits { pub capacity_bytes: usize }
    pub struct Plan { /* complete config and nested plans */ }
    impl Plan {
        pub fn for_pipeline(config: PipelineConfig) -> Result<Self, Error>;
        pub fn config(&self) -> PipelineConfig;
        pub fn capacity_bytes(&self) -> usize;
    }
    pub struct Usage {
        pub limit_bytes: usize,
        pub capacity_bytes: usize,
        pub allocations: usize,
    }
    pub enum Error {
        Pipeline(PipelineError),
        Flow(l2tunnel_packet::storage::Error),
        Mux(l2tunnel_mux::storage::Error),
        Qos(l2tunnel_qos::storage::Error),
        Layout,
        Limit { required: usize, limit: usize },
        Allocation,
        Invariant,
    }
}
pub struct Admission<T> {
    pub metadata: PacketMetadata,
    pub permit: T,
}
impl Pipeline {
    pub fn new_reserved(config: PipelineConfig, limits: storage::Limits)
        -> Result<Self, storage::Error>;
    pub fn storage_usage(&self) -> Option<storage::Usage>;
    pub fn enqueue_borrowed(&mut self, bytes: &[u8], now: Duration)
        -> Result<PacketMetadata, PipelineError>;
    pub fn enqueue_borrowed_weighted(&mut self, bytes: &[u8], weight: u32,
        now: Duration) -> Result<PacketMetadata, PipelineError>;
    pub fn offer_front_borrowed<T, E>(&mut self,
        offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>)
        -> Result<Option<Admission<T>>, DequeueError<E>>;
    pub fn offer_with_borrowed<T, E>(&mut self,
        eligible: impl FnMut(Candidate) -> bool,
        offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>)
        -> Result<Option<Admission<T>>, DequeueError<E>>;
}
```

The integrator explicitly froze the names and physical ownership contract before
production edits. No library gains
Tokio, clocks, OS handles, privileges,
native setup, global allocator hooks, unsafe code or a backing escape.

`enqueue_borrowed` copies accepted original bytes once into the actual selected
queue slab. It retains no caller reference. It uses the same classification,
preflight, prepared FlowTable assignment, scheduler registration and commit as
the owned API. It does not allocate a temporary Vec. Borrowed ingress on a legacy
Pipeline may allocate as an explicit convenience; only successfully constructed
reserved backing qualifies the allocation-free packet path.

`offer_front_borrowed` follows TAP channel FIFO/RR or all-eligible TUN DRR;
`offer_with_borrowed` retains TUN-only eligibility semantics. They invoke the
actual selected codec callback with exact metadata/channel and a borrow of the
retained original bytes. Only `Some(actual_permit)` commits once, releases the
slab slot, pops its metadata and reduces logical usage. `None` or callback error
retains the actual packet, metadata, counters and service debit. Existing DRR
eligibility/traversal changes remain exactly as before; refusal does not undo
earned selection or invent a second eligibility scan. The callback is exclusive,
performs no I/O and returns None/error only when it admitted nothing. An arbitrary
downstream partial mutation cannot be rolled back by this queue.

The returned Admission contains no payload Vec. It is metadata plus the actual
codec permit/identity; it does not prove transport delivery or physical native
completion. The callback borrow ends before the actual slab is recycled.

Existing `new`, enqueue(Vec), dequeue/offer returning Packet/Admitted and all
learning/observation/retirement APIs remain available. Legacy owned ingress keeps
its original rejected Vec, including spare capacity. On reserved backing the
owned-result APIs may copy into a newly allocated Vec as an explicit allocating
compatibility convenience. The selected reserved common Engine must call only
the borrowed ingress/handoff APIs; an owned convenience cannot qualify its
packet-time allocation gate. Both forms share the actual admission/commit
transitions and backing, without a second classifier or scheduler.
Owned compatibility output reserves its fallible copy before entering the actual
codec callback. Additive `PipelineError::Allocation` preserves a MUX copy failure;
the Scheduler's typed allocation failure remains inside `PipelineError::Schedule`.
Neither refusal is reported as an empty queue or successful callback admission.

## Complete physical inventory and construction

Use checked `Layout::array::<T>(n).size()` for every actual vector/slot/slab,
including isize limits, multiplication and sums. The selected nested plans are
FlowTable plus full MUX for TAP, or FlowTable plus Scheduler and handoff-only MUX
for TUN. Add each nested heap once. The Pipeline inline header embeds those
owner headers and is charged by its enclosing Engine exactly once; this Plan
does not add its own inline Self again.

Pipeline wrapper capacity is:

1. F sorted `(FlowKey, FlowState)` elements, including each fixed FIFO head/tail.
2. F sorted `(FlowId, FlowKey)` elements; IDs remain nonreusable across retirement.
3. P actual metadata slots containing PacketMetadata and bounded next/free links.
4. C fixed TAP channel FIFO heads; TUN may retain empty channel heads as explicitly
   counted wrapper metadata, but never an unused MUX payload slab.

The global metadata pool is shared by the profile-selected actual queue. It is
not F*P or C*P. A slot is either free or belongs to exactly one live metadata FIFO;
packet admission and metadata consume/release one slot together. Per-flow queued
counts include every retained packet; the pool does not create independent
logical queue allowance. Pool/state/ID capacity is preflighted before nested
queue mutation. Empty queues recycle slots without discarding vector capacity.
Sorted fixed vectors preserve canonical-key iteration and monotonic-ID lookup;
checked insertion/removal can shift metadata but never copy packet bytes.

Construction performs authoritative complete scalar Pipeline validation first,
then all checked layouts and exact nested plans, then the complete limit check
before the first selected allocation. Invalid configuration keeps legacy error
precedence; valid overflowing layouts return Layout, then insufficient complete
budget returns Limit. Provision real nested owners and every wrapper vector by
fallible exact reservation. A failed reservation returns Allocation; unexpected
actual capacity/layout is Invariant, never an infallible or legacy fallback.
Partial owners drop before the external constructor/build charge can release.

Usage is an observation of actual retained Rust allocation-layout capacities,
including idle slots and nested owners, with each allocation counted once.
It excludes allocator bookkeeping, RSS, stack, physical page commitment, kernel
buffers and OOM/overcommit guarantees. Actual measured capacities must equal the
checked plan. `storage_usage()` is None for a legacy owner, not a fake zero-byte
reserved success.

## Preserved semantics and meaningful acceptance

Keep exact TAP Ethernet/ARP/VLAN/opaque handling, TUN IPv4/IPv6 parsing, common
admission for TCP controls/probes, trusted immutable weights, CRC32/RR mapping,
learned-channel conflicts, parser bounds, global/per-flow budgets and all error
ordering. Full queue/parse/weight/time/flow rejection must preserve ID allocation,
channel cursor, timers, registrations, actual bytes and logical usage. No packet
content grants a scheduling or authenticated management privilege.

Keep nonmutating flow heads and idle scans, canonical-key cursor order including
removed cursors, bounded examined-work, pinned exclusions, idle ties, retrograde
time, explicit downstream-drain requirement, busy retirement, empty registration
learning, and continuation of exhausted/nonreusable IDs. No automatic eviction,
new wrapping, implicit channel modulo, changed DRR shares or retained state reset.

Acceptance compares real legacy and reserved owners under identical literal
nonzero native bytes, TAP/TUN profiles, mappings, weights and operations. It must
exercise actual selected callbacks and exact returned metadata/permits, refusal
then retry, budgets, invalid packets/policies, learned conflicts, original time,
queue pressure, idle/retirement/churn/ID continuation, all-blocked credit, mixed
small/bulk service and TCP controls/probes. Borrowed successful paths must reuse
actual slab/metadata capacities and slot inventory over repeated cycles. Plan
arithmetic or a callback-only enum is not proof of actual reserved ownership.

Local constructor failure injection checks each explicit wrapper reservation and
preserves an already-live old owner. Nested allocator failure and complete actual
partial-drop observation are separate required qualification; local budget
refusal, planned counts or a successful compile do not establish those claims.

## Stable acceptance gates

- [x] [PQS-01] Freeze the exact complete storage/borrowed API and pre-production binding; no production change before interface review. Evidence: [pre-edit binding](../../work/common-queue-storage-20261115/pipeline/preedit-v0.json) and [integrator engineering freeze](../../work/common-queue-storage-20261115/pipeline/interface-freeze-v0.md).
- [x] [PQS-02] Provision actual reserved FlowTable/MUX/Scheduler plus all Pipeline state/ID/sidecar storage through one checked fallible complete plan, preserving legacy behavior and refusing before allocation on incomplete budget. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [PQS-03] Use one actual admission/handoff state machine with borrowed ingress and exact retained-byte callback/permit; None/error retains original head, metadata, counters and service debit, with no packet-time allocation on reserved paths. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [PQS-04] Preserve full TAP/TUN classification/mapping/DRR/budgets/error/time/learn/observation/retirement/ID-continuation semantics through meaningful actual legacy/reserved differential tests and repeated slot reuse. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [ ] [PQS-05] Qualify exact/one-short/overflow plans, actual nested capacity once, every explicit wrapper/nested allocation failure, complete partial-drop ownership, old-owner preservation and unchanged reserved inventory under pressure; distinguish partial local injection from the full gate.
- [x] [PQS-06] Integrate actual reserved Pipeline into the common Engine without owned-payload compatibility handoffs, count full inline/nested/wrapper capacity once and reject unsupported capability before construction. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [ ] [PQS-07] Integrate actual mixed prepared/current/draining owners and selected carrier/runtime/service with original security/control/native custody, complete admission and full SW-11/CRE/resource requirements; library tests alone do not pass this gate.
- [x] [PQS-08] Record source-stable affected checks and exact reused evidence with bounded parallelism; preserve full stage/native/platform/performance gates and distinguish proposed, authored, protocol-tested and integration-tested scope. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.

## Ownership and evidence

This lane exclusively owns `crates/l2tunnel-pipeline/` and this new module document.
The packet/MUX lane owns those actual dependency backings; the QoS lane owns the
actual Scheduler. The integrator owns facade Engine/Bank, exports/manifests,
master ledgers, formatting, Cargo/check execution and Git. No project tests,
builds, native commands or formatting have been run by this lane for this slice.

The authored source is `pipeline/src/{lib,backing,storage}.rs`, with eight focused
tests in `storage_tests.rs`. Existing handoff corruption tests retain their
assertions through the actual shared metadata backing. The authored tests cover
actual nested/wrapper inventories, exact/one-short/overflow plans, each of four
explicit wrapper reservation failures with a live old owner, TAP/TUN and CRC/RR
borrowed refusal/retry/reuse, channels1/256, parser/weight/budget/time/learn/flow
errors, idle cursors/retirement/churn/cross-backing IDs, real weighted/blocked
service, owned-result compatibility, and literal ARP/VLAN/opaque/IPv4/IPv6 bytes.
Root subsequently passed these eight cases and all20 existing Pipeline cases;
the exact invalid overflow-fixture failure and its single-test repair remain
preserved in the linked checkpoint. Local constructor injection does not prove every
nested allocator failure or complete actual partial-drop traces; PQS-05 retains
that full definition. The integrator owns execution and evidence reconciliation.

## Affected checkpoint boundary

The [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) records exact commands, bounded parallel execution, source
hashes and evidence reuse. Initial failures remain failed receipts. Local
Linux pure-protocol and selected existing caller tests do not establish selected
reserved runtime integration, full nested allocator behavior, physical native
acceptance, Windows/Android devices, performance or ISP classification. The
required full-stage `tools/check.py` gate remains open.
