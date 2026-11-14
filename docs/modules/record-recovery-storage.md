# Fallible FEC and Reliable storage

Status: **actual reserved FEC/Reliable owners implemented and protocol-tested;
complete nested failure/resource/runtime qualification remains open**. The baseline is
`d988ab4`. The [pre-edit source binding](../../work/common-record-engine-20261114/record-recovery-storage-preedit-v0.json)
records the inspected production inputs. This prerequisite supports
[common record Engine storage](common-record-engine.md),
[directional endpoints](directional-record-endpoints.md), and the existing
[recovery backing](control-recovery-storage.md). It does not complete CRE-06,
GSU-05, SRS-07, full SW-11, native qualification or the80 Mbit/s requirement.

Read the [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[implementation checklist](../implementation-checklist.md) and
[mode parity](../mode-parity.md). Every retained record profile, RLNC, parity,
rolling, packed, proxy and all47 mode entries remain required. This slice changes
the actual existing block-FEC/Reliable owners, not rolling algorithms, another
transport, cryptography, management, native custody or runtime defaults.

## Actual allocation gap

`Reliable` owns one duplex SelectiveRepeat, one outgoing block pipeline and one
incoming block Decoder. Existing complete directional validation and maximum
packet selection are reused. The ARQ has actual reserved backing already;
Reliable still selects its legacy constructor and independently allocates:

| Source owner | Current allocation or retained operation |
| --- | --- |
| Reliable construction | ARQ legacy backing; scratch Vec; building Vec headers; outgoing VecDeque |
| Partial block | A new Vec copy of every polled complete ARQ source |
| Block sealing | Collected source references; padded BlockEncoder; coefficient vectors; FEC packets; wrapped outgoing packets and a replacement VecDeque |
| Direct retry/feedback | A newly allocated reliable wrapper for every copy |
| Restored receive | Copied direct/systematic sources; BTreeMap nodes; complete decoded Vec<Vec<u8>> |
| Receive deadlines | BTreeMap nodes and allocated expiry result Vec |
| FEC decoder | Generation/terminal/history map nodes; basis and Row vectors; every original received equation; complete basis clone in Generation::prepare; owned decoded/expiry outputs |

`DecoderConfig::max_reserved_bytes` is an existing logical reservation bound,
excluding metadata. `Decoder::reserved_bytes()` and `Reliable::storage()` retain
that meaning. They are not evidence of provisioned heap capacity. New actual
Usage is separate and counts idle capacity too.

## Proposed additive public APIs

All Plan fields are private, validated and allocation-free. Limits/Usage follow
the existing recovery storage conventions. No constructor accepts Usage as
authority; no mutable backing, replacement or raw-owner escape is added.

```rust,ignore
// l2tunnel_fec::storage
pub struct Limits { pub capacity_bytes: usize }
pub struct EncoderPlan { /* checked BlockConfig and actual heap layout */ }
impl EncoderPlan {
    pub fn for_encoder(config: BlockConfig) -> Result<Self, Error>;
    pub fn config(&self) -> BlockConfig;
    pub fn capacity_bytes(&self) -> usize;
}
pub struct DecoderPlan { /* checked DecoderConfig and actual heap layout */ }
impl DecoderPlan {
    pub fn for_decoder(config: DecoderConfig) -> Result<Self, Error>;
    pub fn config(&self) -> DecoderConfig;
    pub fn capacity_bytes(&self) -> usize;
}
pub struct Usage {
    pub limit_bytes: usize,
    pub capacity_bytes: usize,
    pub allocations: usize,
}
pub enum Error {
    Fec(crate::Error), Layout,
    Limit { required: usize, limit: usize }, Allocation, Invariant,
}

impl BlockEncoder {
    // Empty reusable backing, not a fabricated sealed generation.
    pub fn new_reserved(context: FecContext, config: BlockConfig,
        limits: storage::Limits) -> Result<Self, storage::Error>;
    pub fn seal_sources<'a, I>(&mut self, generation: GenerationId, sources: I)
        -> Result<(), crate::Error>
        where I: ExactSizeIterator<Item = &'a [u8]> + Clone;
    pub fn systematic_into(&mut self, source: SourceId, output: &mut [u8])
        -> Result<usize, crate::Error>;
    pub fn repair_into(&mut self, coefficients: &[u8], output: &mut [u8])
        -> Result<usize, crate::Error>;
    pub fn cauchy_repair_into(&mut self, repair_index: u16, output: &mut [u8])
        -> Result<usize, crate::Error>;
    pub fn storage_usage(&self) -> Option<storage::Usage>;
}
impl Decoder {
    pub fn new_reserved(context: FecContext, config: DecoderConfig,
        limits: storage::Limits) -> Result<Self, storage::Error>;
    pub fn decoded_sources(&self, generation: GenerationId)
        -> Result<DecodedSources<'_>, crate::Error>;
    pub fn commit_decoded(&mut self, generation: GenerationId)
        -> Result<(), crate::Error>;
    pub fn expire_into(&mut self, now_ticks: u64,
        output: &mut [ExpiredGeneration]) -> Result<usize, crate::Error>;
    pub fn storage_usage(&self) -> Option<storage::Usage>;
}
pub struct DecodedSources<'a> { /* private validated generation borrow */ }
// ExactSizeIterator<Item=&'a [u8]>, original source-index order.
// No raw mutable row or decoder ownership is returned.
```

The integrator froze the exact APIs/layout/error order before production edits.
The additional typed packet errors are `Error::Unsealed`, `Error::OutputTooSmall { required: usize }`
and existing `StaleGeneration` for a reusable encoder generation not above its
retained high-water mark. A successful replacement consumes no repair ID until
an actual repair output is emitted. Equal/current generation cannot reset repair
numbering. New maximum source count is a capacity, not an initialized block.
All source lengths, dimensions, work, generation and output capacities are
checked before copying or replacing the sealed block/repair allocator.

Existing `BlockEncoder::new/systematic/repair`, `Decoder::new/accept/take_decoded/expire`
and their existing valid behavior remain available. Owned standalone output
methods retain their explicit owned-result API. The selected reserved Reliable
path calls only borrowed/caller-output operations; it must never call those
allocating owned-output conveniences. Shared wire writing, elimination,
canonical source checks and coefficient arithmetic remain authoritative for
legacy and reserved backing. There is one block algorithm, not an alternative
reserved codec.

```rust,ignore
// l2tunnel_reliable::storage
pub struct Limits { pub capacity_bytes: usize }
pub struct Plan { /* complete directional configs and checked nested plans */ }
impl Plan {
    pub fn for_duplex(send: ReliableConfig, receive: ReliableConfig)
        -> Result<Self, Error>;
    pub fn send_config(&self) -> ReliableConfig;
    pub fn receive_config(&self) -> ReliableConfig;
    pub fn capacity_bytes(&self) -> usize;
}
pub struct Usage {
    pub limit_bytes: usize,
    pub capacity_bytes: usize,
    pub allocations: usize,
}
pub enum Error {
    Reliable(crate::Error), Recovery(l2tunnel_recovery::storage::Error),
    Fec(l2tunnel_fec::storage::Error), Layout,
    Limit { required: usize, limit: usize }, Allocation, Invariant,
}
impl Reliable {
    pub fn new_duplex_reserved(send: ReliableConfig, receive: ReliableConfig,
        context: RecoveryContext, limits: storage::Limits)
        -> Result<Self, storage::Error>;
    pub fn storage_usage(&self) -> Option<storage::Usage>;
}
impl ReliableConfig {
    pub fn maximum_packet_bytes(self) -> Result<usize, crate::Error>;
}
```

`ReliableConfig::maximum_packet_bytes` is the allocation-free authoritative
maximum of actual inner emissions after complete validation, excluding outer
overhead. It forwards the existing scalar geometry. A larger optional Aligned
`max_recovery_packet_bytes` ceiling must not be substituted for this exact value
when checking actual carrier MTU/burst geometry. The integrator approved this
additive scalar accessor during source review; existing validation and bytes do
not change.

The returned value is the actual Reliable owner used by existing Aligned/Packed.
Its existing submit/poll/receive/delivery/deadline/drained/inspection/statistics
interfaces remain authoritative. Legacy `new/new_duplex` stay selected by old
callers. Legacy Usage is None, never a fictitious zero-capacity reserved owner.
The Aligned consumer counts the Reliable inline header in its enclosing fixed
layout and adds this Plan's heap once, not another ARQ/FEC charge.

## Exact persistent layout and nested ownership

Use `A(T,n)=Layout::array::<T>(n).size()`; every product, sum, count conversion
and layout is checked, including isize limits. Plans include actual Vec/slot
headers and every retained payload buffer; plans exclude their inline Self
headers. Those headers belong to the enclosing owner once. Report requested
Rust allocation-layout capacity, excluding allocator bookkeeping, RSS, stacks,
physical pages, OS buffers and overcommit/OOM guarantees. Exact capacity must
match successful `try_reserve_exact`, as in existing pinned-toolchain storage.

The following defines the proposed concrete capacity inventory. Private type
sizes are source/target-bound; metadata counts are not serialized constants.

For Encoder let N=`block.max_sources`, W=`block.max_source_bytes+2`:

| Actual retained object | Exact heap charge |
| --- | --- |
| Original padded source slot headers | `A(Vec<u8>,N)` |
| Original padded source buffers | `N*A(u8,W)` |
| Coefficient workspace | `A(u8,N)` |
| Repair payload workspace | `A(u8,W)` |

The source-reference iterator borrows existing Reliable buffers; it creates no
reference Vec. `seal_sources` captures at most256 stable source borrows in a fixed
stack array before mutation rather than assuming a custom Clone iterator repeats
its contents. Count/length inconsistencies are rejected before source replacement.
This bounded stack inventory is excluded from the heap metric as stated above. Systematic and repair write directly into the caller's retained
outgoing slot with unchanged FE bytes. Sources are stored once as actual padded
encoder data; Reliable's complete ARQ originals are a separate real building
owner and are counted separately. A BlockEncoder is reused across successive
nonrepeating generations; clearing a block retains all backing.

For Decoder let N=`block.max_sources`, W=`block.max_source_bytes+2`,
G=`max_generations`, H=`max_symbols_per_generation`, T=`generation_window`.
Reserve fixed generation metadata G, terminal metadata T, basis row metadata
G*N, exact accepted-history row metadata G*H, and shared transaction row metadata
N+1. A basis/history/transaction row includes its real coefficient/payload Vec
headers in its metadata element. Each row has capacity N coefficients and W
payload bytes, charged once. Occupancy/identity is explicit metadata; an empty
payload cannot identify a free slot. The proposed total is:

```text
A(GenerationSlot,G) + A(TerminalSlot,T)
+ A(BasisSlot,G*N) + A(HistorySlot,G*H) + A(TransactionRow,N+1)
+ (G*N + G*H + N+1) * (A(u8,N) + A(u8,W))
```

The shared transaction rows represent one in-progress equation and only changed
basis rows plus one exact received-history candidate. Copy-on-write rows are
prepared into preallocated row versions, canonical checks see the combined
prospective basis, and one infallible checked commit swaps changed rows and
publishes history/rank/clock. Unchanged rows remain borrowed. Do not clone the
whole generation basis, decoder bank, map or payload pool. Retain the existing
GF work predicate and operation count; a second elimination pass to avoid
transaction storage must not silently exceed it. A conflict or noncanonical
recovered original leaves committed rows/history/rank/reservation/time unchanged.
Scratch dirt is unpublished and reused. No peer length chooses a reservation.

The physical plan may exceed `DecoderConfig::max_reserved_bytes`: that existing
value limits logical active equations/scratch reservation, while the new Plan
provisions worst-case slots under all accepted dimensions. Preserve the logical
predicate exactly. Refuse insufficient physical budget explicitly; do not shrink
G/H/N/W, clamp the original config or claim the logical reservation as actual
backing. A future more compact shared pool requires its own revised inventory.

`decoded_sources` borrows only a fully validated live complete generation and
retains original expiry semantics. Reliable validates the complete source list,
contiguous IDs, duplicate bytes and restored headroom before copying into its
preallocated restored slots; only then `commit_decoded` publishes the existing
Delivered tombstone and recycles the generation. No borrowed source survives
another mutable decoder operation. `expire_into` preflights the complete due
count against output before any removal, preserves ascending generation order,
and recycles metadata/rows while retaining capacity. Legacy allocating outputs
delegate to the same validation/retirement semantics.

For Reliable let Ns=`send.fec.block.max_sources`,
Os=`Ns+send.repair_symbols`, Bs=`DATA_HEADER_BYTES+send.arq.max_source_bytes`,
Br=`DATA_HEADER_BYTES+receive.arq.max_source_bytes`,
R=`receive.max_restored_packets`, G=`receive.fec.max_generations`, and
P=`send.maximum_packet()` from the existing scalar validator. Its exact total
is the sum below:

```text
recovery::storage::DuplexPlan(send.arq,receive.arq).capacity_bytes()
+ fec::storage::EncoderPlan(send.fec.block).capacity_bytes()
+ fec::storage::DecoderPlan(receive.fec).capacity_bytes()
+ A(BuildSlot,Ns) + Ns*A(u8,Bs)
+ A(OutgoingSlot,Os) + Os*A(u8,P)
+ A(RestoredSlot,R) + R*A(u8,Br)
+ A(DeadlineSlot,G) + A(ExpiredGeneration,G)
+ A(u8,actual_arq_send_maximum)
```

Build/Outgoing/Restored slot elements contain their payload Vec headers exactly
once. Deadline slots preserve the current nonrenewing receive deadline owner;
the expiry output array is retained actual scratch, not a temporary packet Vec.
Fixed queues use the existing order/selection semantics: building source order,
outgoing FIFO and ascending restored SourceId. Slot removal clears identity and
length, preserving its payload capacity. No free-list allocation is hidden.
Retry/feedback write the Reliable header and existing ARQ scratch directly to
caller output; they do not need another owned wrapper. A shared allowance still
charges actual local outer overhead once.

## Construction, error order and cleanup

Validate complete send then complete receive using the existing authoritative
Reliable validators; preserve context validation after both. Calculate the full
nested plan and refuse the total Limit before the first selected allocation.
Construct the actual reserved duplex ARQ, actual FEC encoder/decoder and wrapper
buffers with the exact subplan limits. Each nested Usage must equal its plan;
the outer Usage sums actual nested capacities/allocations and wrapper capacities
once. Never call a legacy constructor after reserved failure. Partial failure
drops every completed real owner/buffer before returning; no old engine, source
allocator, native identity, timer, budget or caller output changes.

Storage errors are constructor-only, preserving existing packet errors and old
constructor error order. Packet admission/output/deadline/generation/repair-ID
arithmetic is checked before authoritative mutation. Logical pressure retains
the existing ARQ Capacity/RestoredCapacity/FEC skip behavior. No hidden new
maximum, reserved-only success stub, unsafe allocator, global fail hook,
environment hook, Box fallback or grow-on-packet path is permitted.

Use per-construction private test allocation observers/failpoints. Local exact
budget refusal, local reservation failure and a literal nested allocator failure
are distinct acceptance. Observe actual partial ownership/drop and eventual
capacity reuse; arithmetic equality alone proves none of these. Production APIs
expose observations only, not fake allocation permits or failure controls.

## Exclusive ownership and stable acceptance

This lane owns `crates/l2tunnel-fec/` and `crates/l2tunnel-reliable/`, this module
and its pre-edit binding. Proposed new files are `src/storage.rs`, bounded
`decoder/{backing,transaction}.rs` and focused child storage tests in FEC, plus
Reliable `src/{storage,backing}.rs` and focused storage tests. Existing algorithm
entry points receive only required storage/borrow/output factoring. Rolling
source is outside this slice. The Aligned worker owns its consumers; root owns
facade/manifest/master/runtime integration, validation and Git. No project
execution is authorized for this worker lane; the integrator's execution receipts
below establish the actual tested scope.

- [x] [RRS-01] Freeze the complete pre-edit source inventory, exact additive public APIs, nested heap/inline ownership, error order, transaction/cleanup and acceptance contracts before production changes; record engineering approval without an owner scope decision. Evidence: [pre-edit source binding](../../work/common-record-engine-20261114/record-recovery-storage-preedit-v0.json) and [engineering interface freeze](../../work/common-record-engine-20261114/record-recovery-storage-interface-freeze-v0.md).
- [x] [RRS-02] Implement actual fallible reusable block encoder backing and caller-output wire/coefficient operations; preserve all existing bytes, dimensions/work/repair identity/exhaustion and owned convenience APIs; verify exact actual capacity and no allocation on the selected reserved emission path. Evidence: [actual encoder/storage](../../crates/l2tunnel-fec/src/lib.rs), fixed-vector/identity/failpoint tests and [76 passing FEC cases](../../work/common-record-engine-20261114/records-attempt-1/validation.json); selected caller-output paths use provisioned buffers, while historical owned convenience outputs remain allocating.
- [x] [RRS-03] Implement actual reserved decoder generation/history/terminal/transaction/output backing under the same block elimination/state machine; prove atomic rejection, exact duplicates/conflicts, real recovery, expiry/window/tombstone ordering, no bank/basis snapshots or packet allocation, and complete pool reuse. Evidence: [shared changed-row transaction](../../crates/l2tunnel-fec/src/decoder/transaction.rs), exact N+1 occupancy/invalid-output/pointer-reuse tests and [76 passing FEC cases](../../work/common-record-engine-20261114/records-attempt-1/validation.json); literal allocator failure remains RRS-05.
- [x] [RRS-04] Compose one actual reserved duplex ARQ/FEC/Reliable owner with complete asymmetric configs, all queue/slab/deadline/scratch metadata counted once, actual nested Usage, original time/error/backpressure/feedback/wire-budget behavior and no fallback. Evidence: [actual reserved constructor](../../crates/l2tunnel-reliable/src/lib.rs), complete Plan/Usage, asymmetric legacy/reserved loss/repair/ACK differentials and [26 passing Reliable plus28 Aligned consumer cases](../../work/common-record-engine-20261114/records-attempt-1/validation.json).
- [ ] [RRS-05] Qualify exact/one-short/overflow plans, every local and literal nested reservation failure, partial drop before publication, old-owner isolation, full pool use/reuse, legacy/reserved differential event traces and independent fixed wire goldens. Constructor-boundary failure or numeric budget equality alone does not close this leaf.
- [x] [RRS-06] Pass source-stable affected validation in the integrator's bounded parallel batch and report authored/executed/local-platform scope exactly. Full Aligned/Packed/common-Engine/Driver storage, SW-11 switches, original resource gates, native matrices and performance remain separate open acceptance. Evidence: [255-case five-package source-stable batch](../../work/common-record-engine-20261114/records-attempt-1/validation.json) passes tests, strict Clippy/rustdoc/format; [11 exact downstream callers](../../work/common-record-engine-20261114/downstream-attempt-1/validation.json) also pass. No full-stage/native/platform/performance pass is inferred.


## Implemented behavior and remaining evidence

The selected reserved constructors now provision the actual single duplex ARQ,
reusable block encoder, block decoder and Reliable wrapper slots. Legacy and
reserved decoder backings call the same changed-row transaction; prospective
canonical checks precede row/history publication. The complete Reliable reserved
path uses caller-output FE/envelope writing, borrowed decoded originals and a
retained expiry array. Historical owned convenience outputs remain explicitly
allocating APIs outside that selected path. Constructor existence alone is not
the test evidence; the linked source-stable receipts record that separately.

The Aligned consumer identified an existing Packed scalar memory predicate that
includes old inline Endpoint/Reliable headers. The additive const
`Reliable::legacy_inline_bytes()` mirrors only the pre-RRS header/error layout
for that historical acceptance calculation. It creates no owner and reports no
actual current memory. Actual storage plans must charge the current real inline
owner and all current backing, never this compatibility number. The integrator
approved this engineering correction; it records no owner scope decision.

Seven FEC and four Reliable tests are authored for exact/one-short plans, current
nested capacity, every explicit local constructor reservation failure, existing
independent Python FE vectors, repeated real Cauchy recovery under asymmetric
loss/reorder, exact original bytes/source IDs, output refusals, original partial
flush/retry, atomic invalid reconstructed length/padding, expiry/window ordering
and actual decoder pointer/capacity reuse. A dense final equation exercises the
maximum incoming + changed + exact-history transaction occupancy of N+1 rows.
The integrator's [affected validation](../../work/common-record-engine-20261114/records-attempt-1/validation.json)
now passes those assertions plus existing regressions. Literal nested
allocator failure and complete partial-drop observer traces are not established
by these authored local failpoints; RRS-05 retains its full definition and stays
open. Full wrapper/native/Engine/runtime resource qualification remains open.
