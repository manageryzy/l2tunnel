# Fallible Swift engine storage

Status: **implemented with protocol and local record-integration tests;
selected generic driver integration pending**. This is a resource
prerequisite beneath GSU-05 and FIX-09, not generic driver integration or full
SW-11. The source-reviewed [preparation investigation](../../work/generic-secure-udp-20261114/swift-storage-design-v0.md)
records the existing allocation sites and pinned standard-library evidence.
This engineering interface does not record a new owner decision or reduce any
carrier, record-profile,47-mode, lifecycle, platform or80 Mbit/s requirement.

## Boundary and ownership

Add `l2tunnel_swift::storage` without dependencies, I/O, keys, OS handles, real
clocks, privileges or unsafe code. Reuse the existing Sender, Receiver, header
and records algorithms. Legacy public construction/replacement remains
available with its existing wire bytes and valid behavior. The reserved path
constructs an asymmetric duplex engine directly; it cannot destructively replace
an old half and then attempt allocation.

```rust
pub struct Limits { pub capacity_bytes: usize }
pub struct Plan { /* private validated send/receive and heap capacity */ }
impl Plan {
    pub fn for_engine(send: records::Config, receive: records::Config)
        -> Result<Self, Error>;
    pub fn capacity_bytes(&self) -> usize;
    pub fn send_config(&self) -> records::Config;
    pub fn receive_config(&self) -> records::Config;
}
pub struct EngineId { /* private slot and nonwrapping generation */ }
pub struct Usage {
    pub limit_bytes: usize,
    pub fixed_bytes: usize,
    pub external_bytes: usize,
    pub engine_bytes: usize,
    pub building_bytes: usize,
    pub peak_bytes: usize,
}
pub struct Set { /* private exactly-two slots */ }
impl Set {
    pub fn new(limits: Limits, external_capacity_bytes: usize) -> Result<Self, Error>;
    pub fn prepare(&mut self, plan: Plan) -> Result<EngineId, Error>;
    pub fn engine(&self, id: EngineId) -> Result<&records::Engine, Error>;
    pub fn entry(&mut self, id: EngineId) -> Result<Entry<'_>, Error>;
    pub fn retire(&mut self, id: EngineId) -> Result<(), Error>;
    pub fn usage(&self) -> Usage;
}
pub struct Entry<'a> { /* private mutable borrow, no Deref/DerefMut */ }
```

Entry forwards only existing `offer`, `offer_identified`, `poll`, `accept`,
`pop` and `pop_identified` with their existing arguments and borrowed results.
Read-only observations use `Set::engine`. No mutable Engine reference,
`into_inner`, replacement or extraction is exposed. IDs are local to one Set,
not cross-Set identity or authenticated epoch authority. Two slots cover current
plus prepared, then current plus draining; a third preparation is refused.
Retirement requires both pure drain queries. The runtime must additionally prove
physical completion, peer fences and control proof custody before calling it.

## Capacity and failure contract

The quantity is requested owned allocation-layout capacity, including metadata,
payload pools, header scratch and workspaces, plus `size_of::<Set>()` and the
explicit caller-accounted external charge. Per-engine plans count heap layouts
only: the two inline Engine headers are already in the fixed Set charge.
Checked admission is `fixed + external + published heaps + building heap <= limit`.
Reserve the complete target before its first allocation, retain the attempted
peak on failure, drop partially built storage before releasing its reservation,
and publish no slot or generation until construction succeeds. Failed preparation
does not change the old engine, its counters, contexts or native identities.

This excludes allocator rounding/bookkeeping/caches, process RSS, stack peaks,
physical page reservation, OS socket/device buffers and unrelated runtime owners.
It does not promise survival of OS overcommit/OOM. The external charge is a
trusted local accounting input, not proof that arbitrary external code is bounded.
Complete GSU-05 requires actual shared runtime/control/native owners to reserve
and keep those capacities too.

Use safe empty Vec/VecDeque plus `try_reserve_exact`, checking element layouts,
isize limits, total arithmetic and reported exact capacities. The construction
peak claim is bound to the inspected Rust1.92.0 allocation sources recorded in
the investigation; public reserve documentation alone permits extra capacity.
Re-audit on toolchain changes. No grow, new payload allocation, equation clone or
whole-bank snapshot is permitted on a reserved engine's packet path. Caller-owned
standalone Sender/Receiver/header output vectors remain the caller's obligation;
the reserved Engine provisions its actual outputs before use.

Private shared API: `storage::array_bytes<T>(usize) -> Result<usize, crate::Error>`;
`Allocation::{new,vec<T>,deque<T>,used}` with fallible exact layouts; the
allocation-attempt observer and failure hook are test-only.
Sender/Receiver each implement `reserved_bytes(Config)` and
`new_reserved(Config, &mut Allocation)`, excluding their inline Self layout.
`records::Engine::{reserved_heap_bytes,new_reserved}` compose the same inventory
and constructor. New codec errors `Storage` and `Allocation` distinguish checked
capacity/invariant refusal from allocator failure. Storage owner errors distinguish
budget, full slots, stale IDs, generation exhaustion, not-drained retirement and
wrapped record-engine errors. Failure injection is local and test-only.

For each directional codec let F=flow_sources,W=window,S=symbol_bytes,Q=queue_bytes,
P=max_packet,N=F+W,R=2W,T=R+1,B=F*S+P+FRAME_PREFIX. All operations are checked.

- Sender reserves Q bytes, F Source metadata, F retransmit u64 entries, F spare
  Vec headers and F payload buffers of capacity S. Every ACKed payload returns
  to the pool; legacy64-spare retention remains the legacy allocation choice.
- Receiver reserves N slots, N source-spare headers and N buffers of S+2 bytes;
  R active-row, T free-row and R repivot metadata entries; T total Row objects,
  each with F terms and S+2 data; F scratch terms; and B stream bytes. Row/source
  data exchanges preserve all capacities. All dependent/evicted/solved/error rows
  and pending repivot rows are recycled. Preflight the complete contiguous append
  before changing stream/base/floor so malformed ingress never grows beyond B.
- Engine reserves channel owner/header arrays, max directional datagram body,
  feedback block, max record, native output, per-send native compressor scratch,
  and persistent94-byte probes per receive decompressor. Inline header contexts
  are included in array element sizes.

No wire revision is introduced. Checked source-window arithmetic, saturated RTT
clamping and feedback preflight may fix panic/partial-mutation failure paths;
valid ordering, feedback bytes, deadlines, coefficients and counters must match.
Malformed authenticated record errors remain terminal, without a rollback claim.

This owner retains the current record engine's feedback packing behavior.
Standalone codec validation permitting64-byte datagrams does not establish
selected runtime support: the existing record packer requires room for a full
maximum feedback block. The selected runtime's existing minimum-body validation
remains in force. This resource change does not silently widen or shrink that
separate protocol/capability boundary.

## Local verification

The [third focused attempt](../../work/swift-storage-20261114/focused-attempt-3/validation.json)
passes122 Swift cases including the ownership-escape doctest, strict Swift
Clippy and rustdoc,20 existing runtime Swift cases and127 existing secure-UDP
runtime cases, with unchanged recorded sources. Those runtime consumer tests
exercise existing selections; they do not select the new reserved storage owner.
The first attempt's test-counter type error remains preserved separately.
The [exact old-source reproduction](../../work/swift-storage-20261114/malformed-row-regression-attempt-1/validation.json)
fails the strengthened empty-row cleanup assertion on the pre-fix receiver and
restores the fixed bytes exactly afterward. The new receiver recycles that
contradictory row as well as all detached pending rows before returning failure.

The [required checkpoint aggregate](../../work/swift-storage-20261114/checkpoint-aggregate-attempt-1/validation.json)
passes1787 Rust cases including doctests,376 tooling cases and1658 simulator
cases with unchanged recorded inputs. It also passes formatting, full strict
Clippy, rustdoc, the codec's no-default-features branch and existing CLI checks.
The [isolation receipt](../../work/swift-storage-20261114/checkpoint-isolation-attempt-1/validation.json)
records exclusion of the three frozen unintegrated Control bridge files in the
same worktree and exact restoration afterward. The preceding
[live working-tree check](../../work/swift-storage-20261114/live-aggregate-attempt-1/validation.json)
fails on those unused production helpers and remains preserved. No warning is
suppressed and this pass does not qualify the restored working tree as fully
integrated. Selected-driver, native and platform qualification remain separate.

## Verification and integration gates

- [x] [SRS-01] Record the complete pre-edit interface, source inventory, allocation-layout scope, failure rules and ownership/test contract before implementation. Evidence: [pre-edit source binding](../../work/swift-storage-20261114/pre-edit-binding.json) and [source-reviewed investigation](../../work/generic-secure-udp-20261114/swift-storage-design-v0.md). The private attempt observer was subsequently clarified as test-only; no public, wire or runtime selection changed.
- [x] [SRS-02] Implement exact fallible allocation and two-slot custody, precharged construction, stale/generation/drain checks and failure-atomic publication; fail every real allocation point in tests. Evidence: [actual owner](../../crates/l2tunnel-swift/src/storage.rs), [every-allocation and ownership tests](../../crates/l2tunnel-swift/src/storage/tests.rs), [focused pass](../../work/swift-storage-20261114/focused-attempt-3/validation.json).
- [x] [SRS-03] Fully provision the actual Sender queues/payload pool and pre-mutation capacity checks; prove >64-buffer recycling, retransmit bounds and legacy/reserved wire/timer/stat parity under loss and wrap. Evidence: [sender](../../crates/l2tunnel-swift/src/sender.rs), [13 resource/failure/differential tests](../../crates/l2tunnel-swift/src/sender_storage_tests.rs), [focused pass](../../work/swift-storage-20261114/focused-attempt-3/validation.json).
- [x] [SRS-04] Fully provision actual Receiver history/rows/scratch/stream; remove packet-time row cloning/allocation and recycle all failure paths; prove fill-in beyond W, wrap, partial records and legacy/reserved byte/feedback/stat parity. Evidence: [receiver](../../crates/l2tunnel-swift/src/receiver.rs), [10 actual algebra/resource tests](../../crates/l2tunnel-swift/src/receiver_storage_tests.rs), [old failure reproduction](../../work/swift-storage-20261114/malformed-row-regression-attempt-1/validation.json), [focused pass](../../work/swift-storage-20261114/focused-attempt-3/validation.json).
- [x] [SRS-05] Compose actual asymmetric record engines and persistent header scratch, account every owned layout, test exact-budget/one-short/failed construction and multi-epoch native identity/borrowed output behavior without mutable-owner escape. Evidence: [record constructor](../../crates/l2tunnel-swift/src/records.rs), [actual two-owner/differential integration](../../crates/l2tunnel-swift/src/records/storage_tests.rs), [header buffer/failure tests](../../crates/l2tunnel-swift/src/header.rs), [focused pass](../../work/swift-storage-20261114/focused-attempt-3/validation.json). These are local engine generations; authenticated epochs and physical completion remain SRS-07.
- [x] [SRS-06] Run focused tests, strict Clippy/rustdoc/formatting and required frozen-source workspace checks; save a coherent scoped checkpoint with evidence and explicit unresolved integration gates. Evidence: [focused pass](../../work/swift-storage-20261114/focused-attempt-3/validation.json), [required aggregate](../../work/swift-storage-20261114/checkpoint-aggregate-attempt-1/validation.json), [evidence-only postcheck](../../work/swift-storage-20261114/checkpoint-postcheck-attempt-1/validation.json) and [local checkpoint](../../work/swift-storage-20261114/checkpoint-attempt-1/validation.json). The independently tested but unintegrated Control bridge and SRS-07/GSU-05/full SW-11 remain open.
- [ ] [SRS-07] Integrate actual storage reservations into the selected generic driver and leased management transaction before PREPARE/staging; qualify physical custody, shared external owners and original resource/native/performance requirements. Pure storage tests cannot close this gate or GSU-05.

Focused regressions must compare actual legacy and reserved algorithms, preserve
every pool allocation/capacity through long reuse and malformed failure, test
checked arithmetic/sequence exhaustion and verify Set is Send. No global allocator
hook, unsafe test instrumentation, fake physical receipt, default switch or
benchmark result substitution is permitted. Windows/Android and native throughput
remain separate runtime evidence.
