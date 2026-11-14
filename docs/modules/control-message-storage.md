# Fallible whole-message control storage

Status: **implemented and protocol-tested, with finite selected runtime integration**.
The initial engineering contract preceded production edits; the pre-edit source
binding caveat below remains explicit. It extends the actual
[whole-message owner](control-messages.md) beyond its existing
[reserved ARQ backing](control-recovery-storage.md), while preserving that
narrower API and every existing constructor. It is a resource prerequisite for
GSU-05/SRS-07, not completion of either parent, full SW-11, any record profile,
native/platform qualification or the80 Mbit/s requirement. It records an
engineering contract, not an owner decision about scope, wire or defaults.

## Owner and compatibility boundary

Keep the existing Fragmenter, Reassembler, management delivery Service and
whole-message Owner as the actual algorithm owners. Add a private legacy/reserved
backing selection beneath their current transitions. There is no second fragment
FSM, sequence allocator, ARQ engine, receipt algorithm, authentication owner or
runtime I/O loop. Existing allocating constructors and `new_reserved_arq` remain
available with their existing bytes, validation and error meanings.

Preserve all current maxima and independently configured bounds: complete
messages through65536 bytes; 1..64 outbound and incomplete messages; up to65535
fragments in the existing `u16` field; the current16 MiB logical outbound and
reassembly limits; configured work1..4096; and the full65536-ID replay window
selected by management. The standalone Reassembler retains every currently
accepted `ReassemblyConfig` and replay width1..65536. A failed storage limit is an
explicit construction failure, never catalog pruning, a changed negotiated
setting, a legacy allocating fallback or an implicit loss of a stream.

LXv1 remains40 bytes per fragment. Recovery data/ACK, L2CF/L2SC, complete message
identity/digest, source ordering and the45-byte Accepted source remain unchanged.
Full authenticated session/lane/role binding precedes codec input. LX64 is still
only a redundant discriminator. Source ACK, semantic Accepted, whole Confirmed,
physical native delivery and transaction Applied remain different claims.

Public libraries keep caller-injected `Duration`/ticks and borrowed I/O buffers.
They gain no Tokio, real clock, OS handle, privilege, allocator replacement,
global/thread-local fail hook or cryptographic primitive.

## Additive pure codec interface

The codec facade exports `fragment_storage`, implemented beside the existing
fragment algorithm. Constructor-only errors are separate from `FragmentError`:

```rust
pub struct Limits { pub capacity_bytes: usize }
pub struct Plan { /* checked private ReassemblyConfig and layouts */ }
impl Plan {
    pub fn for_reassembly(config: ReassemblyConfig) -> Result<Self, Error>;
    pub fn config(&self) -> ReassemblyConfig;
    pub fn capacity_bytes(&self) -> usize;
}
pub struct Usage {
    pub limit_bytes: usize,
    pub capacity_bytes: usize,
    pub allocations: usize,
}
pub enum Error {
    Fragment(FragmentError),
    Layout,
    Limit { required: usize, limit: usize },
    Allocation,
    Invariant,
}
impl Reassembler {
    pub fn new_reserved(
        context: FragmentContext, config: ReassemblyConfig, limits: Limits,
    ) -> Result<Self, fragment_storage::Error>;
    pub fn storage_usage(&self) -> Option<fragment_storage::Usage>;
    pub fn expire_count(&mut self, now_ticks: u64) -> Result<usize, FragmentError>;
    pub fn expire_into(
        &mut self, now_ticks: u64, expired: &mut [MessageId],
    ) -> Result<usize, FragmentError>;
}
```

Plan performs the same configuration validation before layout calculations and
allocates nothing. `Usage` observes actual retained backing, including idle
buffers; it is never accepted as backing authority. `Allocation` means failed
`try_reserve_exact`; `Invariant` means the actual capacity differs from its exact
validated request. There is no new packet error meaning. A violated internal
reserved-storage invariant returns existing `FragmentError::Arithmetic`; valid
logical admission after successful construction must not reach it or allocate a
fallback. Errors contain no message bytes or secret context.

Add an opaque Copy `FragmentLayout`, containing the checked message ID, record
length, chunk size, count and complete encoded-batch length. Its public interface
is `message() -> MessageId`, `fragments() -> usize`, `encoded_bytes() -> usize`
and `fragment_range(index: usize) -> Option<Range<usize>>`. It is codec geometry,
not authentication or delivery authority. It owns no payload and has no public
field constructor. The caller retains the exact encoded buffer.

`FragmentBatchView<'out>` borrows the exact initialized batch prefix. Its methods
are `message() -> MessageId`, `len() -> usize`, `is_empty() -> bool`,
`encoded() -> &'out [u8]`, `fragment(index: usize) -> Option<&'out [u8]>` and
`layout() -> FragmentLayout`. There is no mutable-buffer escape or payload
allocation. A real encoded batch is nonempty; out-of-range fragment lookup is
None. Both the view and the layout are exported by the codec facade. The layout
lets the actual persistent Owner retain checked geometry after ending a temporary
buffer borrow, avoiding a self-referential owner or a second fragment parser.

```rust
impl Fragmenter {
    pub fn fragment_into<'out>(
        &mut self, record: &[u8], encoded: &'out mut [u8],
    ) -> Result<FragmentBatchView<'out>, FragmentError>;
}
```

`fragment_into` writes the complete canonical index-ordered batch into one flat
caller buffer, with every original40-byte header preserved. It checks record
emptiness, record bound, count/wire bound, ID exhaustion, checked geometry and
complete output size before any write or ID change. Short output is
`OutputTooSmall`, consumes no ID and changes no caller bytes. Success consumes
exactly one message ID, including the final representable `u64` ID, exactly as
the current allocating API. Both APIs share the same validated geometry and
header encoder; the old `fragment` still returns its existing `FragmentBatch`.

`expire_into` checks monotonic time, the complete expired-ID count and caller
output capacity before release/time mutation. It emits IDs in ascending full-ID
order, matching current `expire`. `expire_count` uses the same cleanup without
an owned result allocation. The existing owned `expire -> Vec<MessageId>` stays
available; that explicitly owned caller result is outside reserved backing and
is not used by the reserved management packet path. Reassembler `accept` uses
the no-allocation cleanup internally. Preserve its existing ordering: validate
the fragment first, then perform deadline cleanup before the subsequent replay,
geometry/budget and output admission decisions.

## Exact reassembly heap inventory

Let `A(T,n)=Layout::array::<T>(n).size()`, checked for layout/isize and sum/product
overflow. Let `R=config.max_messages`, `L=config.max_message_bytes`,
`P=min(usize(config.max_fragments_per_message), L)` and
`W=config.replay_window`. Canonical positive chunks imply actual count<=L; P
therefore supports every accepted geometry without lowering the configured cap.

| Retained backing | Requested layout | Reservations |
| --- | --- | --- |
| Persistent reassembly slots, including metadata and both Vec headers | `A(PendingSlot,R)` | 1 |
| Every slot's complete payload buffer | `R*A(u8,L)` | R |
| Every slot's fragment presence buffer, byte flags0/1 | `R*A(u8,P)` | R |
| Exact full-ID replay tags, including empty slots | `A(Option<MessageId>,W)` | 1 |
| Reusable expired-ID scratch | `A(MessageId,R)` | 1 |
| Total reassembly heap | sum above | `3+2R` |

Metadata contains the exact full message ID, declared length/chunk/count,
received count and original deadline. Slot payload/presence capacity survives
completion, expiry and reuse. Empty metadata alone marks a free slot. No source
or payload buffer moves into a dropped temporary on an error path.

The replay table indexes by `message_id % W` and stores the **complete** optional
ID. Membership compares the complete ID, never only a modulo slot or low bits.
Two distinct IDs in the admitted width-W interval cannot collide. Existing full
`highest`, window floor, stale-message and pending-window checks retain authority.
Window advance removes only tags below the actual floor; old/new IDs cannot
alias after more thanW uses or near `u64::MAX`. `retired_messages` retains its
logical meaning. This is a backing substitution for the existing tombstone set,
not a new replay contract or smaller history.

Expired scratch retains at mostR full IDs and sorts only its occupied slice
without allocation. The same IDs are released and tombstoned in existing order.
Logical reserved bytes/fragments remain actual declared pending-message sums;
they do not replace R*L/P in the persistent capacity ledger. Single-fragment
completion must retain its original budget/error precedence even though it does
not occupy a pending slot. Completion preflights caller output and accounting,
copies exact bytes and recycles the same persistent buffers.

## Additive complete management storage interface

```rust
// In management::messages:
pub mod storage {
    pub struct Limits { pub capacity_bytes: usize }
    pub struct Plan { /* private settings and layouts checked against all inputs */ }
    impl Plan {
        pub fn for_owner(
            settings: messages::Settings, binding: delivery::Binding,
            now: Duration, expires: Duration,
        ) -> Result<Self, Error>;
        pub fn capacity_bytes(&self) -> usize;
        pub fn arq_plan(&self) -> recovery::storage::Plan;
        pub fn reassembly_plan(&self) -> codec::fragment_storage::Plan;
    }
    pub struct Usage {
        pub limit_bytes: usize,
        pub capacity_bytes: usize,
        pub allocations: usize,
        pub arq: recovery::storage::Usage,
        pub reassembly: codec::fragment_storage::Usage,
    }
    pub enum Error {
        Message(messages::Error),
        Recovery(recovery::storage::Error),
        Fragment(codec::fragment_storage::Error),
        Layout,
        Limit { required: usize, limit: usize },
        Allocation,
        Invariant,
    }
}
impl messages::Owner {
    pub fn new_reserved(
        settings: messages::Settings, binding: delivery::Binding,
        now: Duration, expires: Duration, limits: messages::storage::Limits,
    ) -> Result<Self, messages::storage::Error>;
    pub fn storage_usage(&self) -> Option<messages::storage::Usage>;
}
```

These signatures use crate aliases for readability; implementations expose their
actual crate types. Plan calls the same complete existing validation with the
same injected inputs and precedence before planning any layout. Existing service
validation remains nested in the existing messages Error through `Message`;
actual recovery/reassembly provisioning failures use their respective arms.
Do not first construct a legacy Owner and replace its backing.

`storage_usage` is Some only for complete reserved construction; legacy and
ARQ-only construction return None. Existing `arq_storage_usage` remains Some for
both ARQ-only and complete reserved construction and reports the same real nested
subpool. The top-level capacity/allocations sum includes each nested owner once;
the nested Usage fields are breakdowns, not additional charges.

## Exact whole-message heap inventory

Use `O=settings.max_outbound_messages`, `R=settings.max_incomplete_messages`,
`M=settings.max_message_bytes`, `S=settings.delivery.recovery.max_source_bytes`
and the actual validated Fragmenter chunk `C=S-1-40` for this source geometry.
Set `L=min(M,C*usize(settings.max_fragments))`, `F=ceil(L/C)` and `B=L+40F`, with
checked arithmetic. L is the largest geometry-valid record under the existing
configured limits, not a changed field or a new admission cap. Preserve all
logical outbound byte checks over the actual original plus encoded batch sizes.

| Retained backing | Requested layout | Reservations |
| --- | --- | --- |
| Persistent outbound slots, including metadata and all three buffer headers | `A(OutboundSlot,O)` | 1 |
| Existing insertion/confirmation order, as slot indices | `A(usize,O)` | 1 |
| Every slot's original exact-message buffer | `O*A(u8,L)` | O |
| Every slot's flat canonical encoded batch | `O*A(u8,B)` | O |
| Every slot's submitted source-ID FIFO Vec | `O*A(u64,F)` | O |
| First-arrival/deadline slots | `A(ArrivalSlot,R)` | 1 |
| Source scratch | `A(u8,S)` | 1 |
| Complete/held-message buffer | `A(u8,M)` | 1 |
| Actual reserved recovery subowner | existing recovery Plan H | existing K |
| Actual reserved reassembly subowner | reassembly inventory above | `3+2R` |
| Total whole-message heap | sum above | `K+8+2R+3O` |

The source-ID capacity is F, **not the current ARQ send_records limit**. Confirmed
source IDs can still await the existing round-robin confirmation scan while new
fragments submit; a source-ID backlog can exceed the live ARQ count. Each fragment
submits one source ID at most once, so F is the safe existing-algorithm bound.
Retries remain the existing ARQ owner's responsibility.

The slot table is permanent and a bounded search finds free slots; its order
Vec stores indices in the exact existing outbound insertion order. Removing an
ordinal shifts at most64 indices. Each reserved source FIFO uses a Vec plus a
consumed-prefix cursor: confirmation advances the cursor, submission appends at
mostF total IDs for that message, and confirmation/retirement clears it for
reuse. Heap capacities/counts are unchanged. This representation makes each
actual backing pointer observable through safe Vec APIs; movable VecDeque slice
addresses are not mistaken for allocator relocation. Legacy keeps VecDeque. A live
entry retains its ticket, immutable deadline, FragmentLayout, next fragment,
acceptance/confirmation state and source FIFO. Original and flat batch buffers
are actual retained copies; there is no zero-copy or synthetic Retained claim.
Fragment ranges borrow the encoded batch. No per-fragment Vec or heap node is
needed. On confirmation, clear original/batch/source lengths while retaining
their capacities and retry metadata. On retire, release only that logical slot;
the same buffers remain owned and charged. No `shrink_to_fit` is permitted in
the reserved path. Legacy may retain its existing allocation/drop behavior.

Fixed per-slot provisioning intentionally reserves more than instantaneous
logical byte occupancy. It avoids a second arena allocator, compaction algorithm
or fragmentation-based refusal. The existing16 MiB logical budgets remain
unchanged; the explicit physical storage limit must admit the full validated
inventory. Large valid configurations can require a large explicit limit, or
fail construction visibly. Do not reduce capacities, prune a catalog, silently
increase a negotiated budget or fall back to allocation to conceal that cost.

The inline Owner, Reassembler, Service and backing-enum headers are excluded
from heap H and charged once by their enclosing runtime owner. Vec headers
inside slot arrays are included in those arrays exactly once. Requested Rust
layout capacity excludes allocator rounding/bookkeeping, caches, RSS, physical
pages, stacks and kernel queues. The exact-capacity claim remains pinned to the
reviewed Rust1.92.0 behavior; actual differing capacities are refused rather
than reported as the requested size. Re-audit on toolchain changes.

## Construction, packet operations and failure ordering

Construct and validate the full Plan, compare the complete limit and checked
component sums, then provision actual ARQ, codec and own backing. Publish no
Owner until every actual capacity witness exists and matches Plan. Each partial
owner immediately owns its real buffers; the same safe drop statements run in
production and tests. Local per-construction failpoints/observations remain
outside retained slot layouts. No fake Usage or numeric permit can substitute
for provisioned buffers.

Preserve existing protocol validation and time behavior, including:

- `submit` observes original time/expiry, then empty/maximum input, exact live
  idempotent retry, new submission ordering, deadline/overflow, fragment count
  and complete logical byte/count budgets. Physical slot/buffer checks precede
  copying or consuming fragment/submission IDs. A valid exact live retry does
  not copy again or renew a cap. Confirmed retries still compare their retained
  fingerprint even though payload lengths have been cleared.
- The work rotation and `work_per_call` remain unchanged. Fragment source
  reservation still leaves a real source slot/bytes for the45-byte receipt.
  Reserved backing cannot multiply the shared stream wire quota.
- Ordered delivery uses the persistent scratch; held completion stops the same
  semantic progression while other independent streams remain serviceable.
  First-arrival entries retain the existing receive clock and are removed only
  at the same completion point. Reordered source arrival is not a new physical
  UDP-arrival deadline claim.
- Accepted is issued only after the real receipt enters ARQ; Backpressure keeps
  the same held ticket/bytes/deadline. Confirmed requires that exact receipt and
  all actual submitted source confirmations. Neither grants Peer/native effects.
- Parser, context/profile, replay, conflict, stale/window, caller-output,
  byte/count/fragment pressure, overflow and exact original-expiry behavior keep
  their existing order. Terminal failures retain their bounded inventory until
  owner drop; no reset/recreate escape renews an ordered context.

All reserved message/reassembly packet paths use existing storage and bounded
caller buffers. They cannot reserve, insert allocating map/set nodes, grow a Vec
or deque, shrink, allocate a fresh fragment batch, clone a retained payload pool
or create an owned expiry result. If a locally corrupted physical pool violates
a preflighted invariant, return an explicit existing protocol/invariant error
without an allocating fallback; meaningful tests must show valid admission
cannot encounter it. Caller-owned allocating convenience results are outside the
backing promise and absent from the actual selected consumer.

## Actual selected runtime consumer and remaining parents

Root owns the private runtime seam and combined admission. The intended additive
constructor is `control::Owner::new_leased_reserved_messages`, with the same
context/settings/time inputs as the current leased reserved-ARQ constructor and
`[messages::storage::Limits;3]`; `message_storage_usage()` returns Some of all
three actual whole-message Usages or None. Preflight every Plan before the first
stream, preserve fixed Transaction/Liveness/DataFeedback construction order and
drop prior unpublished streams on later failure. This seam must call the actual
complete reserved constructor, not an unused parallel pool.

The explicit generic constructor selects this path. Charge actual whole-message
heaps once in place of the previous ARQ-only subtotal; do not add both totals.
Retain the same single common crypto owner, sole reader/driver, full authenticated
H0/D0, immutable envelope IDs, original operation caps and borrowed proof bridge.
Legacy/SwiftPolicyV1 defaults and bytes remain unchanged. All three Owners are
constructed and charged; unsupported DataFeedback semantics are not invented by
a storage change.

Actual complete message storage still does not reserve Peer/Fence/Effects,
bridge envelope copies, catalog copies, bootstrap tails, reports/frontend owners
or the entire construction peak. Keep the qualification flag false and full
CRS-06/GSU-05/SRS-07 definitions open until their remaining actual-owner and
physical/recovery/performance requirements pass. Constructor-boundary injection
is distinct from an injected dependency reservation refusal; a new test-support
contract is required before exposing any cross-crate local failpoint.

## Executed validation boundary

The combined checks pass all8 codec and11 management storage tests, plus actual
selected runtime/service, constructor collector and leased control pressure
regressions. Their temporary constructor guards use
the same actual `drop` statements in production and tests; only local before/after
metadata observation and deterministic reservation refusal are test-only. No
observer or failpoint field survives into a published Reassembler or Owner.
Local failure tests observe all successful preceding local allocations and
already constructed nested owners being released, and successful guards transfer
their backing without release. This is not an injected failure inside another
crate's allocator or a measurement of allocator/RSS bookkeeping.

Executed coverage includes byte-exact owned/flat batches; actual reassembly of
65536 bytes and the 65535-fragment boundary; full 65536-ID replay replacement and
near-maximum IDs; independent parser/context/conflict/output, byte/count/fragment,
window, clock/overflow and original-expiry cases compared with legacy; 130 full
outbound reuse rounds; 130 actual interleaved full receive windows; and genuine
source ACK backlog reaching the whole message's F while the live ARQ has only
three slots. The source-cursor test then obtains real semantic Accepted and whole
Confirmed before clearing/retiring the same metadata. Lost first/middle/final
fragments, source ACK and whole receipt, reordering and duplication compare
actual emitted bytes and retention with legacy. Caller-owned fixture vectors
are separate from retained library backing.

Full nested ARQ/reassembly Usage remains constant in those message-owner tests;
their internal pointer inventories are tested in the owning crates rather than
exposed as public authority. The new management tests observe every additional
message-owned slot/order/source/arrival/scratch/completion pointer and capacity.
CMS-01 remains open because the retained source-binding reconciliation was
created after authoring, even though the initial contract hash predates edits.
CMS-05 remains open: local failpoints and dependency-owner drops do not inject
reservation failures inside the dependency constructors or jointly observe their
full pointer inventories. See the [honest provenance reconciliation](../../work/generic-functionality-20261114-batch2/cms-binding-reconciliation-v0.json).
No full-resource, platform, performance or recovery parent is qualified.

## Acceptance ledger

- [ ] [CMS-01] Freeze the complete pure APIs, exact owned layouts, physical/logical distinction, same-algorithm backing selection, errors, full unchanged limits, actual consumer and pre-edit source binding before production edits.
- [x] [CMS-02] Implement caller-buffer fragment batches through the same LX encoder, preserving allocating API bytes/ID validation, canonical ranges, full geometry, final IDs and atomic short-output/error behavior. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [CMS-03] Implement actual fallible reserved reassembly slots, full-ID65536-window tombstones, presence/payload/expiry reuse and no-allocation bounded expiry; preserve all existing parser/context/replay/budget/conflict/output/time semantics and caller-owned convenience APIs. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [CMS-04] Implement actual complete reserved message Owners, including original/batch/source/order/arrival/scratch/completion and actual reserved codec/ARQ backing; prove complete exact/one-short layouts and unchanged storage/proof/retention semantics with every configured limit intact. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [ ] [CMS-05] Test every new constructor reservation/failure/drop/transfer path and more than64 full outbound and receive reuse cycles with constant actual pointer/capacity inventory. Differentially cover malformed/context/replay/conflict input, all independent pressures, lost/reordered/duplicate fragments and receipts, held/confirmation backlog, nonwrapping IDs, clock/overflow/exact original expiry and recoverable output errors against legacy.
- [x] [CMS-06] Select and charge the actual three complete reserved message Owners in the generic Driver, replacing the ARQ-only subtotal once; validate both covers/roles, real complete PREPARE/READY, shared quotas, independent liveness under held/saturated Transaction, actual Accepted/Confirmed and later-stream cleanup without legacy fallback, catalog pruning or parent qualification claims. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [CMS-07] Run focused codec/management/runtime tests, all legacy/CarrierOnly compatibility, required format/strict Clippy/rustdoc and frozen-source workspace checks; preserve failures, exact sources, commands actually executed and a coherent scoped checkpoint before reporting completion. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.

Tests must include message65536 with a geometry that can actually carry it,
max-fragment boundary geometry, the full replay wrap/replacement history and
high nonwrapping IDs. Private seeding is allowed only for otherwise unreachable
counter/invariant boundaries; actual byte/fragment/pool pressure comes from
public operations. Proof and crypto claims require the real owning APIs, not
fabricated receipts or accepted flags. Component tests do not stand in for
privileged native, GUI, Windows/Android, ISP or80Mbit/s qualification.

## Checkpoint evidence

The [full baseline](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json) passed with unchanged recorded inputs:2011 Rust cases including
doctests,406 tooling and1658 simulator cases. The subsequent [affected completion repair](../../work/generic-functionality-20261114-batch2/completion-projection-focused-attempt-1/validation.json)
passes77 affected service/local cases with4 test threads and strict client-core
Clippy after the narrow APIv3 completion repair. Only owner.rs and its existing
generic failure test changed outside documentation. Unchanged protocol, tooling
and simulator evidence is reused explicitly; the full baseline is not relabeled
as a new post-repair full run. Native acceptance remains separate and unqualified.
