# Fallible weighted-DRR Scheduler storage

Status: **implemented and protocol-tested:31 Scheduler cases, including seven
new actual-storage cases; full combined resource/stage gates remain open**.
This contract starts from the integrator-supplied checkpoint `dd16d1b` and the
actual [Scheduler](../../crates/l2tunnel-qos/src/lib.rs). The integrator froze
this interface and representation before production edits. It is a complete
backing prerequisite, not a new scheduling policy or an owner decision.

Read the [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[checklist](../implementation-checklist.md), [mode parity](../mode-parity.md),
[existing QoS contract](qos.md), [actual queue handoff](record-admission-handoff.md),
[Pipeline](pipeline.md) and [common record Engine](common-record-engine.md).
Existing flat weighted DRR, flow FIFO, error ordering and full configured bounds
remain authoritative. Hierarchical class guarantees, AQM, pacing, authenticated
credit, endpoint TCP windows, full resources, all47 modes, SW-11, native/platform
and performance gates retain their original definitions.

## Actual owners and allocation gap

The current Scheduler owns immutable classes in a BTreeMap, registered Flow
objects in another BTreeMap, an active-flow VecDeque and one VecDeque of boxed
payloads per flow. Registration, activation and admission can allocate. The
selected head is already an inline `Option<PacketHead>`; selection does not own
a second packet. The current selected callback validates service accounting
before entering downstream, then transfers the original boxed payload on Some.

The selected reserved consumer needs actual retained slabs and metadata before
first admission. Preallocating an unused pool beside the existing maps/queues,
warming those containers or reporting a scalar bound is insufficient. This
slice must put the real Scheduler transitions over the selected backing and
provide output that does not require constructing an owned Vec. Pipeline keeps
its own classification/flow metadata separately; it must not duplicate Scheduler
payloads in a second retained queue.

## Frozen additive public interface

```rust
pub mod storage {
    pub struct Limits { pub capacity_bytes: usize }
    pub struct Plan { /* checked private policy and physical inventory */ }
    pub struct Usage {
        pub limit_bytes: usize,
        pub capacity_bytes: usize,
        pub allocations: usize,
    }
    pub enum Error {
        Configuration(super::ConfigError),
        Layout,
        Limit { required: usize, limit: usize },
        Allocation,
        Invariant,
    }
    impl Plan {
        pub fn for_scheduler(config: SchedulerConfig, classes: &[ClassConfig])
            -> Result<Self, Error>;
        pub fn config(&self) -> SchedulerConfig;
        pub fn class_count(&self) -> usize;
        pub fn capacity_bytes(&self) -> usize;
    }
}
impl Scheduler {
    pub fn new_reserved(config: SchedulerConfig, classes: &[ClassConfig],
        limits: storage::Limits) -> Result<Self, storage::Error>;
    pub fn storage_usage(&self) -> Option<storage::Usage>;
    pub fn enqueue_borrowed(&mut self, flow: FlowId, payload: &[u8])
        -> Result<(), AdmissionErrorKind>;
    pub fn offer_selected_borrowed<T, E>(&mut self,
        offer: impl FnOnce(PacketHead, &[u8]) -> Result<Option<T>, E>)
        -> Result<Option<(PacketHead, T)>, OfferError<E>>;
}
```

`AdmissionErrorKind::Invariant` is an additive defensive refusal for
internally inconsistent fixed-pool/index/ring state. It is checked before copying
or mutation, never used instead of an existing valid-input policy refusal. All
original admission reasons retain their precedence. Existing public constructors,
registration, selected-head and owned-return methods preserve their signatures.
`storage_usage()` returns None for the allocating constructor and actual complete
retained heap capacity for the reserved constructor. Usage is observational,
never accepted as construction authority.

`AdmissionErrorKind::Allocation` is an additive failure only for fallible copying
by legacy `enqueue_borrowed`, before any queue mutation. The actual reserved
borrowed path uses its provisioned slab and cannot reach that allocation branch.

`Plan::for_scheduler` runs the same existing scalar validator first, preserving
zero/inconsistent/no-class/count/weight/duplicate/arithmetic error precedence.
It then checks every actual layout/product/aggregate without allocation. The
constructor recomputes that Plan from the supplied policy, checks the complete
explicit budget before its first reservation and never falls back to allocating
backing. No new absolute class/flow/packet/byte maximum is invented. Rust layout
or capacity failure is explicit; a smaller budget never reduces dimensions.

Class weights cannot change or gain new classes through the current API.
Therefore the reserved class table owns exactly the supplied validated class
count A; `max_classes` remains the unchanged acceptance bound, not a promise of
later class insertion. Registration still provisions all F advertised flow
slots, including initially idle/unregistered flows. Packets can use all P global
slots without a hidden smaller per-flow physical quota.

## Exact selected physical inventory

Let A = supplied class count, F = `max_flows`, P = `max_queued_packets`, and
M = `max_packet_bytes`. The selected reserved backing owns these real vectors:

| Allocation | Requested elements and retained purpose |
| --- | --- |
| Immutable classes | A ClassConfig entries, sorted by class ID for bounded lookup |
| Registered-flow slots | F optional actual flow owners, with FlowId, class, quantum, deficit, byte/count, eligibility and FIFO metadata |
| Flow index | F sorted `(FlowId, slot)` entries; binary search without scanning idle flow state during selection |
| Free-flow stack | F usize indices; removal/re-registration returns exactly one actual slot |
| Active ring | F FlowId entries with inline head/length; only nonempty flows are visited |
| Packet slots | P actual packet metadata entries, including next index and payload length |
| Free-packet stack | P usize indices |
| Payload slab | checked P times M bytes, one distinct maximum-sized slice for each packet slot |

Each flow's selected FIFO consists only of inline head/tail/count indices into
the one global packet pool. There is no F times P per-flow metadata or payload
reservation. The implementation retains empty legacy BTreeMap/VecDeque headers
in the inline Scheduler and empty legacy FIFO headers in fixed Flow slots.
They own no heap on the reserved branch; actual Flow-slot layouts include those
headers, and outer owners separately charge the real inline Scheduler layout.
Selected operations never populate or allocate those compatibility containers.
Unused indices/metadata and idle payload slices remain fully charged. Selected
head, visit state, ring positions, counts, Usage and vector headers live inline
in the Scheduler/backing owner and are excluded from the heap total. An outer
owner must separately charge its actual inline/heap-cell layout once.

The exact Plan equals the sum of Layout::array for those seven metadata vectors
and the checked payload array. Total retained managed heap excludes allocator
overhead, RSS, caller output, kernel buffers and downstream owners. Every array
and multiplication must fit Rust layout/isize constraints; aggregate addition is
checked. Actual fallible exact reservations verify capacity before publication,
and Usage equals the actual retained capacity sum and successful nonzero
reservation count. Per-slot P times M physical overreservation can exceed logical
`max_queued_bytes`; it is explicit and fully charged rather than silently raising
the logical byte budget. Global/per-flow byte/count bounds remain independent.

## One authoritative scheduling and commit path

Private backing operations provide class lookup, registered-flow lookup/mutation,
active-ring traversal/rotation, FIFO head access and exact insertion/removal.
The current DRR algorithm remains one implementation: `peek_eligible`,
`scan_round`, `peek_visit`, `skip_empty_rounds`, visit retention and deficit
arithmetic execute the same transitions for both backings. No alternate reserved
selector, reference scheduler or post-hoc reconciliation may drive production.

Flow lookup is binary search in the sorted reserved index. Selection traverses
only the active ring, not all registered idle flows. Registration/removal may
shift the bounded sorted index, but neither allocates or changes active-ring
order. A successful empty-flow removal returns its actual slot; reuse of numeric
IDs retains the existing local-only semantics, with session generation external.

Registration retains duplicate then capacity then weight/class/arithmetic error
ordering. Weight changes retain unknown then busy before quantum validation.
Admission retains unknown flow, empty, too large, global bytes, global packets,
per-flow bytes, per-flow packets ordering. It preflights all selected physical
indices/lengths/free slots and active-ring capacity before copying or mutating.
`enqueue_borrowed` copies accepted bytes once into the actual free slab slice,
links that slot into the owning FIFO, invalidates selection and updates the same
checked logical accounting. Refusal changes no bytes, index, ring turn, deficit
or selected head. No source-content priority or management bypass is added.

Both selected offer APIs share the existing checked service preflight and one
commit path. It checks actual selection, FIFO head/length, class, deficit debit,
flow/global byte/count subtraction, last-packet consistency and real backing
links before calling downstream. None/error retains the same slot, bytes,
selection, visit and deficit. Some commits once, updates the same DRR accounting
and returns the actual slot to the free pool only after the callback returns.
Emptying a flow resets deficit and removes its active-ring entry exactly as now.
The borrowed result is only PacketHead plus the downstream token; it grants no
native completion or downstream lifetime authority and retains no borrowed peer
or callback memory after return.

The existing owned enqueue/offer/dequeue APIs remain compatibility conveniences.
On legacy backing, accepted ownership still normalizes spare capacity and the
original selected allocation transfers unchanged. On reserved backing, producing
a caller-owned Vec may explicitly allocate/copy outside the retained Scheduler
budget. Those convenience methods must not appear in the selected reserved
Pipeline/Engine path. Borrowed enqueue on legacy backing may allocate its owned
payload; allocation-free packet handling is conditional on actual reserved
construction, not a misleading property of the method name alone.

The reserved owned-output convenience pre-reserves and copies its caller-owned
Vec after checked service preflight but before callback entry. A fallible output
reservation returns additive `ScheduleError::Allocation` without entering the
callback or committing queue state. There is no allocation or fallible service
check after a downstream Some. Legacy owned output keeps its original allocation
transfer, and borrowed selected output requires no such temporary Vec.

## Construction, cleanup and validation

Use a temporary construction guard with real fields for every partially acquired
vector/slab. Its actual drop statements run in production and tests. Only local
test metadata around those statements is cfg(test); no hook is retained by a
published Scheduler or invoked on packet paths. A deterministic local fail-at
allocator may refuse each actual reservation after earlier fields were acquired.
Before/after actual drop and successful transfer observations prove the local
guard path; they do not qualify a global allocator or downstream dependency
failure. All successfully acquired buffers are either transferred once into the
published backing or dropped once on error.

Focused tests must compare actual reserved and allocating Scheduler traces with
the existing textbook DRR cases: weighted unequal sizes, skipped rounds, idle
flows, blocked eligibility, repeated selected None/errors and exactly one Some.
Callbacks receive identical actual bytes and Head metadata, once per selected
service; eligibility remains once per active head. Exercise every original
admission refusal independently, exact maximum packet, full F/P registrations and
queues, shared byte pressure, removal/re-registration and repeated wrapped ring/
FIFO reuse. Original owned allocation-pointer guarantees remain tested on legacy
backing. Reserved full inventories/pointers and Usage stay unchanged across
success, refusal and reuse; they are not RSS or universal allocator observations.

## Stable acceptance leaves and ownership

Every checkbox remains open until its stated deliverable passes with actual
evidence. The pre-edit binding records this proposal and current source before
implementation under `work/common-record-engine-20261115/qos-storage/`.

- [x] [QSR-01] Freeze exact Plan/Limits/Usage/errors, selected backing, shared DRR/admission/commit ownership, borrowed consumer interface and source binding before production edits; distinguish engineering choices from owner decisions. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [QSR-02] Implement complete fallible actual class/flow/index/ring/packet/slab backing with checked exact capacities, no uncharged pool or allocating fallback and no reduced original policy dimensions; report allocating versus reserved Usage honestly. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [QSR-03] Use one authoritative DRR and checked admission/service implementation for both backings; selected borrowed enqueue and callback commit allocate no packet-path backing and preserve exact FIFO/order/weights/eligibility/accounting/refusal semantics. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [QSR-04] Exercise all local construction reservations, insufficient full budget/layouts, actual partial-owner cleanup and success transfer through the same production guard; distinguish constructor-local failpoints from dependency/global allocator qualification. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [QSR-05] Differentially compare actual Scheduler success/refusal/weight/registration/blocked/selected traces against allocating behavior and the existing reference, including actual bytes and unchanged legacy allocation ownership. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [x] [QSR-06] Exercise repeated full flow/packet/ring/FIFO reuse, independent byte/count bounds, exact packet geometry, original accepted dimensions and selected invariant refusal; verify actual complete inventory and retained Usage without hidden growth. Evidence: [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) with retained initial failures, exact repair bindings and source-stable commands.
- [ ] [QSR-07] Consume the actual reserved Scheduler in the reserved Pipeline/common Engine and charge its real heap plus outer metadata/cells/current/prepared/draining/shared owners exactly once; isolated constructor success does not close combined resource admission.
- [ ] [QSR-08] Pass affected source-stable package/stage checks with recorded commands and retained failures. Full hierarchical QoS, flow-control, resource, mode, SW-11, native/platform and performance gates remain independent.

This lane owns `crates/l2tunnel-qos/` and this document. The Pipeline worker owns
its actual reserved consumer. The integrator owns master links, facade/Bank/
runtime selection, manifests, all builds/tests/format/check/Git and acceptance.
The worker authored production backing and seven focused tests without
executing checks. Root subsequently passed the affected library tests, strict
Clippy and rustdoc recorded in the linked checkpoint. The tests include all eight local
construction failure positions with actual guard drop/transfer observations,
complete retained capacity observations, 130 full flow/packet/ring reuse cycles,
blocked-head refusal, 1/2/4/16/64-flow legacy DRR differentials, independent byte/
count errors, legacy allocation transfer, corrupted local metadata preflight and
large unchanged scalar dimensions. Construction-local failpoints do not prove
literal global/dependency allocator failures; unchanged pointers/capacities do
not establish RSS or complete cross-owner admission. The checked leaves above have affected evidence; combined resource and full
stage leaves remain open.

## Affected checkpoint boundary

The [affected checkpoint](../../work/common-reserved-records-20261115/scoped-checkpoint-validation.json) records exact commands, bounded parallel execution, source
hashes and evidence reuse. Initial failures remain failed receipts. Local
Linux pure-protocol and selected existing caller tests do not establish selected
reserved runtime integration, full nested allocator behavior, physical native
acceptance, Windows/Android devices, performance or ISP classification. The
required full-stage `tools/check.py` gate remains open.
