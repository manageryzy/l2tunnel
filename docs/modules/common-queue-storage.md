# Actual common queue storage

Status: **implemented and protocol-tested in the source-stable affected batch**.
The [checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json)
records25 packet and11 MUX cases, including ten new storage cases. Full combined
Bank/runtime/resource gates remain open. The engineering contract was frozen
from clean `dd16d1b` before production. This is the actual FlowTable/MUX storage prerequisite beneath
[CRE-06](common-record-engine.md), composed by
[the reserved Pipeline](pipeline-storage.md). It does not replace full CRE,
GSU-05, SRS-07, literal CRS-06, SW-11, all47 modes, selected runtime/native,
platform or performance acceptance. Historical sources and receipts remain intact.

The lane owns `l2tunnel-packet`, `l2tunnel-mux`, focused local tests and this
document. The Pipeline lane owns its actual consumer, metadata and scheduler
composition. The integrator owns exports/master ledgers, actual common Engine/
Bank/runtime integration, formatting, builds, affected tests and Git. These pure
libraries inject time and contain no OS handles, Tokio, privileges or real clock.

## Frozen additive public contract

Both crates expose a public `storage` module. Limits and usage count retained
managed heap capacity only, following the existing Reliable/Aligned convention.
Embedding Pipeline/Engine plans must count their actual inline headers once;
these nested heap plans do not charge those headers again. Logical occupancy,
requested layout capacity, allocator overhead/RSS, stack and kernel memory remain
different quantities.

```rust
// In packet::storage and mux::storage, with crate-specific Error::Flow/Configuration.
pub struct Limits { pub capacity_bytes: usize }
pub struct Usage {
    pub limit_bytes: usize,
    pub capacity_bytes: usize,
    pub allocations: usize,
}
// packet::storage::Error:
// Flow(FlowError), Layout, Limit{required:usize,limit:usize}, Allocation, Invariant
// mux::storage::Error:
// Configuration, Layout, Limit{required:usize,limit:usize}, Allocation, Invariant

// packet::storage::Plan has private validated fields and is Copy.
Plan::for_config(config: FlowTableConfig) -> Result<Plan, Error>;
Plan::capacity_bytes(&self) -> usize;
Plan::config(&self) -> FlowTableConfig;
FlowTable::new_reserved(config: FlowTableConfig, limits: storage::Limits)
    -> Result<FlowTable, storage::Error>;
FlowTable::with_plan(plan: storage::Plan, limits: storage::Limits)
    -> Result<FlowTable, storage::Error>;
FlowTable::storage_usage(&self) -> Option<storage::Usage>;

// mux::storage::Plan has private validated fields and is Copy.
Plan::for_queue(channels:u16, byte_limit:usize, frame_limit:usize,
                max_frame_bytes:usize) -> Result<Plan, Error>;
Plan::for_handoff(channels:u16, byte_limit:usize, frame_limit:usize)
    -> Result<Plan, Error>;
Plan::capacity_bytes(&self) -> usize;
Plan::channels(&self) -> u16;
Plan::byte_limit(&self) -> usize;
Plan::frame_limit(&self) -> usize;
Plan::max_frame_bytes(&self) -> Option<usize>;
Plan::is_handoff(&self) -> bool;
Mux::with_plan(plan: storage::Plan, limits: storage::Limits)
    -> Result<Mux, storage::Error>;
Mux::new_reserved(channels:u16, byte_limit:usize, frame_limit:usize,
                  max_frame_bytes:usize, limits:storage::Limits)
    -> Result<Mux, storage::Error>;
Mux::new_handoff_reserved(channels:u16, byte_limit:usize, frame_limit:usize,
                          limits:storage::Limits) -> Result<Mux, storage::Error>;
Mux::storage_usage(&self) -> Option<storage::Usage>;

// OfferError gains Allocation for an owned reserved-slab copy before callback.
pub enum BorrowedAdmissionError { Channel, Budget, Unavailable, Invariant, Allocation }
Mux::push_borrowed(&mut self, channel:u16, bytes:&[u8])
    -> Result<(), BorrowedAdmissionError>;
Mux::offer_front_borrowed<T,E>(&mut self,
    offer: impl FnOnce(u16,&[u8])->Result<Option<T>,E>)
    -> Result<Option<(u16,T)>, OfferError<E>>;
```

Existing constructors and public protocol methods retain their valid-input
behavior. `storage_usage` returns None for explicitly legacy allocating owners;
Some reports measured actual retained capacities of a reserved owner, including
idle backing. No reserved constructor substitutes a legacy owner after refusal.
The complete plan is checked against Limits before the first reservation.
Every `Layout::array`, product, sum and actual-capacity comparison is checked.
Use fallible reservation and publish only after the entire owner matches its
plan. A failed partial constructor drops its real earlier buffers. Local
constructor injection remains distinct from literal dependency allocator failure.

## FlowTable: same transactional state over fixed backing

The actual legacy BTreeMap and reserved sorted vector are private storage
variants behind the same FlowTable state machine. The reserved vector holds
`(FlowKey, Entry)` cells and has one fallible nonzero reservation for the complete
configured capacity. Lookup uses binary search. Insertion/removal shifts bounded
in-place Copy cells; no BTree node or vector growth occurs on a reserved event.
Its maintained key order preserves the existing canonical-key idle tie breaker.
Lookup is logarithmic; insertion/removal is linear in configured capacity. This
storage slice makes no performance qualification of that bounded work.

Retain complete capacity1..65536 and channels1..256, nonzero idle timeout,
nonreusable IDs including u64::MAX, time regression checks, CRC versus learned
connection-RR mapping, binding conflict precedence and sequence inheritance.
`preview_assign` checks time before existing lookup, then capacity before ID
exhaustion for a new key. `preview_learn` checks time, invalid channel, existing/
CRC conflict, then new insertion capacity/ID. Dropped PreparedAssignment changes
nothing. Commit has the exclusive table borrow and a previously proved
`len < configured capacity` for insertion into its already reserved vector;
replacement never needs capacity. Commit advances IDs/RR/time exactly once and
cannot introduce an allocator or a second fallible check after downstream admit.

The storage Plan calls the existing scalar validator first and preserves its
FlowError. Layout precedes Limit, which precedes attempted Allocation. Actual
allocation capacity exceeding the admitted plan is an Invariant refusal before
publication, rather than an uncharged success. Plan/Usage exclude the table's
inline header, which the embedding actual owner must include.

## MUX: actual fixed slots, global free list and reusable slabs

The reserved queue has four fallible nonzero reservations:

| Backing | Complete extent |
| --- | --- |
| Channel lane metadata | `channels * size_of::<Lane{head,tail}>()` |
| Frame slot metadata | `frame_limit * size_of::<Slot{length,next}>()` |
| Global free slot indices | `frame_limit * size_of::<usize>()` |
| Reusable native payload slab | checked `frame_limit * max_frame_bytes` bytes |

The global slab and slots permit every frame slot to belong to any channel;
there is no per-channel artificial frame quota. The original shared logical
byte/count limits remain authoritative. Physical slab capacity can exceed the
logical byte limit and is charged in full, even when mostly idle. The explicit
physical maximum is not silently clamped to the logical byte limit. Pipeline
binds it to the exact configured parser/native maximum before use. There is no
new arbitrary slot-count/channel/packet-size cap beyond checked layouts and the
existing channels1..256, positive logical limits and positive physical maximum.

The actual MUX retains one channel cursor and shared logical counters. Legacy
queues and fixed slots use shared selection, preflight and commit transitions;
do not fork RR or create pop/requeue adapters. Invalid channel precedes budget
failure. Empty bytes, full count, exhausted shared logical bytes or an input
above the explicit physical slot size return Budget without changing custody.
Private slot/free-list/accounting inconsistencies return Invariant before an
admission callback. Checked slot ranges, successor/tail state, free-list room,
counter subtraction and next cursor are established before the callback.

Reserved `push_borrowed` copies bytes into one already reserved slot and commits
links/counts only after preflight. It allocates nothing and leaves the caller's
input borrowed. `offer_front_borrowed` offers exact retained bytes to the actual
downstream owner. None/error leaves FIFO/cursor/slot/bytes/accounting unchanged.
Some consumes that actual head once, updates precomputed counters/RR, and recycles
the same slot with no allocation or post-admission failure. Its return contains
only channel and downstream token; the downstream already copied or retained
what its actual algorithm requires. Arbitrary callback side effects cannot be
rolled back; partial authoritative failure remains terminal at the consumer.

The old owned methods remain explicit convenience APIs. On legacy queues they
preserve original allocation transfer. On a reserved slab an owned Vec result
fallibly reserves and copies before callback acceptance, returning the additive
OfferError::Allocation on refusal; that API is not a nonallocating reserved
handoff. Legacy `push_borrowed` may allocate explicitly and returns its typed
Allocation before admission if the fallible reservation fails.
The actual reserved Pipeline/Engine uses borrowed ingress and borrowed egress;
an owned return must never be used as evidence of no packet-time allocation.

## Empty MUX handoff for TUN

TUN originals remain in the one actual reserved Scheduler. Its MUX needs no
second payload queue. `Plan::for_handoff` and `new_handoff_reserved` explicitly
select an actual inline scalar owner with the full configured channel width,
logical byte/count limits, empty counters and the shared RR cursor. It has zero
managed heap capacity and zero reservations; no hidden lane vectors are created.

The existing actual `offer_selected` performs its original channel/nonempty/
logical byte/count/empty checks and commits the same eventual RR cursor only on
Some. It stores no bytes. Queued borrowed egress on this empty owner returns None.
Borrowed queue ingress returns Unavailable; old owned push returns Budget with
the unchanged input Vec. This observable purpose is not an allocating fallback.
TUN Pipeline still accounts every original through its actual Scheduler and
common logical admission. Empty MUX counters do not pretend to own those bytes.

## Stable acceptance tasks

- [x] [CQS-01] Freeze exact Plan/Limits/Usage/errors, borrowed interoperability, complete heap inventory, old-state semantics and pre-production binding before production edits; no owner scope reduction is inferred. Evidence: the [original source binding](../../work/common-queue-storage-20261115/pre-production-v0.json) and engineering interface freeze on 2026-11-15 precede production edits.
- [x] [CQS-02] Implement the actual fallible FlowTable sorted backing with unchanged preview/commit, ID/time/mapping/retirement and no reserved event allocation. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [CQS-03] Implement actual globally shared reserved MUX slots/slabs/free-list, full logical versus physical accounting and the same FIFO/RR transitions. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [CQS-04] Implement nonallocating actual borrowed ingress/egress and the explicit zero-heap TUN handoff owner; preserve existing owned convenience behavior honestly. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [CQS-05] Pass focused exact/one-short/+1 capacity, checked geometry/maxima, local reservation failure/drop, repeated refusal, reuse and legacy-differential tests in the source-frozen affected batch; distinguish local allocator gates from full CRS-06. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [ ] [CQS-06] Integrate the actual reserved Pipeline/Engine/Bank consumer and reconcile complete resources, full SW-11, all47 modes and required runtime/native/platform/performance gates without reducing any parent definition.

The focused tests must inspect actual vector/slab capacities and stable backing
addresses across repeated admissions/removals, not fabricate Usage or assert only
logical occupancy. Exercise global capacity concentrated in one lane, both RR
wrap endpoints, shared-byte refusal with free slots, physical-frame refusal,
Some/None/error custody, released-slot reuse and handoff width256. Flow tests
cover capacity65536 planning, final ID exhaustion, canonical idle ties, dropped
transactions, full-table error precedence and retirement/reassignment across
legacy/reserved instances. Every checkbox remains open until its deliverable
has the required evidence; this design alone implements no runtime capability.

## Focused affected evidence

`packet/src/flow/storage_tests.rs` contains four focused cases:

- `complete_plan_admission_measures_actual_capacity_before_publication`: exact/
  one-short/+1 allowance, a local first-reservation gate, actual vector capacity
  and reserved versus legacy Usage.
- `scalar_maxima_and_layout_validation_preserve_full_original_domain`: full
  capacity65536/channels256 planning and original scalar precedence over limits.
- `real_reserved_and_legacy_tables_preserve_mapping_retirement_and_reuse`:
  actual CRC/RR tables, canonical idle ties and repeated in-place reuse.
- `dropped_transactions_and_last_identity_keep_error_order_and_epoch_continuation`:
  unchanged abandonment, final u64 ID, failure precedence and drained inheritance.

`mux/src/storage_tests.rs` contains six focused cases:

- `exact_capacity_and_local_partial_reservation_failure_drop_actual_buffers`:
  complete actual capacity, one-short before any reservation, all four local
  reservation boundaries, cleanup of real earlier buffers and successful transfer.
- `checked_layouts_retain_full_width_and_distinct_logical_and_physical_limits`:
  channel256, physical capacity above logical bytes and checked overflow.
- `globally_shared_slots_refuse_without_changing_custody_and_recycle_in_place`:
  all slots in one lane, exact borrowed slab pointers, Some/None/error, explicit
  owned-copy local refusal before callback, shared-byte/physical-size refusal,
  repeated actual slot reuse and stable complete backing.
- `mixed_owned_and_borrowed_paths_match_real_legacy_fifo_and_round_robin`:
  actual FIFO/RR differential at both wrap endpoints and distinct owned copy.
- `inline_handoff_has_zero_heap_full_logical_domain_and_original_cursor_semantics`:
  actual no-payload owner, zero reservations, full scalar logical bounds,
  observable queue refusal and selected-channel RR commit only on Some.
- `reserved_link_and_accounting_refusals_precede_downstream_callback`:
  defensive real backing/accounting refusal without downstream side effects.

The private per-construction observer drops the very same guard-owned Vecs in
production and tests; only the post-drop trace is test-only. On success the guard
has transferred its buffers into the actual MUX and observes no retained buffers.
Local refusal gates stand immediately before the selected `try_reserve_exact`;
they neither induce a real dependency allocator failure nor complete literal
CRS-06. The owned-copy refusal uses the same private operation-local reservation
gate before its real copy; actual borrowed reserved handoff does not use a copy.
Existing legacy handoff tests keep their assertions, with only private backing
access adjusted for the actual storage enum. No runtime, native, platform,
allocator-overhead or performance qualification follows from these authored tests.

## Affected checkpoint boundary

The [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) records exact commands, bounded parallel execution, source
hashes and evidence reuse. Initial failures remain failed receipts. Local
Linux pure-protocol and selected existing caller tests do not establish selected
reserved runtime integration, full nested allocator behavior, physical native
acceptance, Windows/Android devices, performance or ISP classification. The
required full-stage `tools/check.py` gate remains open.
