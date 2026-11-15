# Shared native packet custody storage

Status: **implemented; fourteen pure storage and five runtime-adapter regressions
passed, with a separately repaired actual Bank-token/Lease custody case and
passed named pure checkpoint checks**.
Selected Common runtime custody cases also passed; complete shared external
ownership, configured-P behavior and native/resource parents remain open.
The supplied baseline is `33f60c0`. The
[pre-edit source binding](../../work/common-mixed-bank-20261115/external/source-binding-v0.json)
and [engineering proposal](../../work/common-mixed-bank-20261115/external/proposal-v0.md)
precede production edits. This prerequisite extracts the existing actual
[runtime native pool](runtime-native-storage.md), without another queue, native
delivery algorithm or device loop. Its interface freeze is engineering approval,
not a new owner decision, capability/default selection or scope reduction.

Read the [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[implementation checklist](../implementation-checklist.md), [mode parity](../mode-parity.md),
[common Engine](common-record-engine.md), [reserved Engine](common-engine-storage.md)
and [known runtime construction](runtime-construction-admission.md). Full
SW-11/CRE/CSE/GSU-05/SRS-07, complete resources, retained recovery, every requested
record/recovery family, all47 modes, native/platform and 80 Mbit/s gates remain.

## Exact reusable owner and interface

`l2tunnel::native_storage` owns exactly the old ready FIFO, free-buffer stack and
P actual native payload Vecs. Public APIs inject integer age and borrowed bytes;
they introduce no Tokio, I/O, real clock, handles, privileges or device setup.
Keep T unconstrained and preserve real non-Copy metadata destruction. Queue Usage
counts its own actual header/payload allocations. Any additional heap owned by an
arbitrary T is the caller's separate obligation; selected production metadata is
fixed inline origin/identity/token data without additional owned heaps.

```rust,ignore
pub struct Config { pub packets: usize, pub bytes: usize, pub max_native: usize }
pub struct Limits { pub capacity_bytes: usize }
pub struct Plan<T> { /* checked Config, layouts and metadata type */ }
impl<T> Plan<T> {
    pub fn for_queue(config: Config) -> Result<Self, Error>;
    pub fn config(&self) -> Config;
    pub fn capacity_bytes(&self) -> usize;
}
pub struct Usage {
    pub limit_bytes: usize,
    pub capacity_bytes: usize,
    pub allocations: usize,
}
pub enum Error {
    Configuration, Layout, Limit { required: usize, limit: usize },
    Allocation, Invariant,
}
impl<T> Queue<T> {
    pub fn new_reserved(plan: Plan<T>, limits: Limits) -> Result<Self, Error>;
    pub fn storage_usage(&self) -> Usage;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn bytes(&self) -> usize;
    pub fn can_acquire(&self) -> bool;
    pub fn acquire(&mut self) -> Option<Lease<'_, T>>;
    pub fn front(&self) -> Option<&Packet<T>>;
    pub fn iter(&self) -> impl Iterator<Item = &Packet<T>>;
    pub fn complete_front(&mut self) -> Result<(), Error>;
}
impl<T> Packet<T> {
    pub fn metadata(&self) -> &T;
    pub fn since(&self) -> u64;
    pub fn bytes(&self) -> &[u8];
}
impl<T> Lease<'_, T> {
    pub fn copy(self, metadata: T, since: u64, input: &[u8]) -> Result<(), Error>;
    pub fn output(&mut self) -> Result<&mut [u8], Error>;
    pub fn publish(self, metadata: T, since: u64, length: usize) -> Result<(), Error>;
}
```

Plan validates original packets>0, M>0 and logical bytes>=M, then every checked
layout, product and sum without allocation. Complete capacity is
`A(Packet<T>, P) + A(Vec<u8>, P) + P*A(u8, M)`, excluding the inline Queue header.
Charge all P*M storage even when it exceeds the logical byte limit. Preserve
exactly P+2 fallible reservations: ready deque, free-buffer Vec, then P payload
Vecs. The complete limit check precedes their allocation. Successful actual
capacities must match; failure drops all partial real owners. No Box fallback,
resize-on-packet, count clamp, flat replacement slab, unsafe or allocator hook.

Usage reports actual retained requested layouts, including empty buffers and
immutable construction allowance. It excludes allocator metadata/RSS/stack,
kernel buffers and OOM/overcommit guarantees. Its allocation count observes these
explicit retained reservations, not process-wide allocations. The outer owner
counts Queue's inline header once; no forged Usage is accepted as backing.

## Atomic publication and physical completion

Keep original conservative admission: a free buffer, fewer than P ready entries
and `occupied_bytes + M <= logical_bytes`. A smaller packet does not bypass that
rule. Acquisition takes one actual existing buffer and borrows the Queue
exclusively. Drop returns that same buffer on empty, error or declined work.

`output` checks exact reserved capacity and initializes its existing Vec to M,
returning only `&mut [u8]`. This zero initialization is a write, not an allocation
or an end-to-end zero-copy claim. `publish` requires a positive length within M
and the initialized output, validates every byte/count/header bound before
mutation, then truncates and moves that same buffer into ready custody. `copy`
uses the same publication transition for existing runtime extraction. No mutable
Vec or replacement/backing escape exists.

The front and bounded read-only iterator retain exact metadata, original age
and bytes through WouldBlock. Neither permits mutable metadata/backing escape.
`complete_front` is an external physical-completion acknowledgment, not an I/O
operation or proof minted by the Queue. It checks all accounting before mutation,
then recycles exactly one complete packet. Actual partial writes cannot qualify.
Non-Copy metadata drops at the original completion/failure/owner-drop boundary.

The current common Engine retains one pending PreparedNative/token until physical
commit. A queue lease can supply the actual caller output directly and retain
that token as metadata; it cannot call `commit_native` at extraction/enqueue to
manufacture room. Keep full configured P backing, explicitly retaining this
one-pending-per-Engine limitation. Full multi-packet profile custody remains a
required separate composition gate, not a silent cap reduction.

Generation-bound Bank metadata must route completion to the issuing real Engine.
The runtime must observe a whole native write before later fallible clock/expiry
work can hide it, preserving saved original deadline/age after queue removal.
The Queue does not reinterpret Swift64 native counts, Aligned256/Packed255 record
identities, independent-short receipts or context records as interchangeable
fence proofs. The actual common Engine exposes separate per-channel event totals;
the selected Common Driver combines those with complete-generation drain and
original physical/control custody. Totals alone never authorize retirement.

## Runtime compatibility and incomplete shared envelope

`secure_udp/transport_native.rs` is a private thin adapter over this same
owner, preserving existing Queue/Plan/Lease call signatures, fixed FIFO/batch
behavior and counters. Context-specific conversion preserves constructor
InvalidInput, allocator OutOfMemory and completion-accounting InvalidData errors.
The existing Driver, extraction scope/order checks and physical NativeWritten
commit ordering stay unchanged by this extraction. Core pool regression assertions
move beside the actual pure owner; runtime adapter tests preserve the observable
io categories, bytes, age, FIFO, drop and lease behavior.

The selected Common `OutputQueue` chooses one real Swift-metadata or
Common-metadata native pool. Common metadata retains the exact origin,
Bank-generation token, original profile identity and deadline. The actual lease
provides Engine output storage directly; publication does not commit the Engine.
Whole device acceptance commits the issuing original token once before later
clock/expiry sampling, then recycles the queued buffer. Ready output keeps its
first age and exact bytes through WouldBlock. This is actual selected composition,
with the finite runtime checks below; the one-pending-per-Engine/full-P limitation
is not removed.

Selected Common construction includes actual native, buffer/input, witness and
Control-message/wrapper reservations in its admitted known subtotal. Remaining
State/Peer/catalog, setup/security tails, bridge/reporting/frontend ownership and
complete construction peaks/failure/drop coverage still need their own actual
accounting. Passing external_bytes to a Bank alone reserves none of them. The
runtime keeps `resource_preallocation_complete` false. Complete SNS-06/07 and
resource parents remain open.

The historical Swift UDP EAGAIN-as-loss path remains separate. The new selected
Common path retains one actual sealed output with unchanged bytes/security
number/scope and a single wire debit across WouldBlock in a passing focused case.
That finite correction does not qualify retained output/control behavior across
all carriers, lifecycles or profile/resource fault matrices.

## Executed acceptance and exact remaining evidence

The pure owner has fourteen passing tests: all ten original native-pool layout,
allocation-refusal, conservative-admission, FIFO/age, reuse, non-Copy drop and
private-accounting-corruption regressions moved beside the actual owner; four
additional cases exercise complete-limit-before-allocation, exact same-buffer
output/publication, uninitialized/invalid publication and atomic refusal with
non-Copy metadata. Five passing private runtime tests cover observable plan/layout,
original invalid-input/error categories, byte/count admission, immutable FIFO
age/bytes and non-Copy lifetime compatibility. Allocator-category conversion tests
are labeled conversion tests; actual failpoints remain beside the real owner.

The Bank lane additionally passed actual prepared-token to Lease output,
publication, held original bytes/age, foreign/recycled-token refusal, expiry and
simulated whole-write/commit/recycle composition. It does not assert an OS write,
full P common batching, authenticated runtime switching or device qualification.
The single-pending Engine limitation and complete SNS-05 fault matrix remain
explicit. Parent runtime custody fixtures retain immutable real queue metadata.
Trusted negative fixtures recycle and republish genuine queued bytes and original age
with deliberately inconsistent local metadata through the same actual Lease
API. All eight pre-I/O refusal variants remain; no public mutable queue escape
is introduced.

The implementation author performed source reads, edits and source hashes only;
root executed the source-bound affected checks described below. Authorship or
compilation alone advances no acceptance gate. The authored
[source freeze](../../work/common-mixed-bank-20261115/external/authored-source-freeze-v0.json)
binds the exact inputs before integrator formatting and validation.

## Stable acceptance gates

- [x] [SNS-01] Freeze actual extracted owner, exact typed API/layout/metadata/error boundaries and pre-edit binding before production; record no owner scope decision. Evidence: [bound proposal](../../work/common-mixed-bank-20261115/external/proposal-v0.md), [source binding](../../work/common-mixed-bank-20261115/external/source-binding-v0.json) and [integrator freeze](../../work/common-mixed-bank-20261115/external/interface-freeze-v0.md).
- [x] [SNS-02] Implement the actual existing Queue once in the pure reusable module with exact P+2 fallible allocations, full original bounds/FIFO/conservative admission/age/drop behavior and truthful observed capacities. Evidence: [split fourteen pure storage passes; failed aggregate](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json).
- [x] [SNS-03] Implement borrowed lease output and atomic publication over actual preallocated storage, preserving decline/error recycling, exact initialized bytes and the real pending-token/physical-completion boundary. Evidence: [split same-buffer/publication/refusal passes; failed aggregate](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json).
- [x] [SNS-04] Preserve existing runtime adapter error categories, actual original extraction/physical-write/batching semantics and every existing core regression, including non-Copy metadata destruction and retained pointer/capacity reuse. Evidence: [split five adapter and affected native-custody passes; failed aggregate](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json), [named pure checkpoint and exact reuse](../../work/parallel-features-20261115/pure-scoped-checkpoint-validation.json).
- [ ] [SNS-05] Exercise actual Engine/Bank prepared-token-to-queue custody, refusal/pressure/expiry/generation/stale-token paths and exact physical-receipt simulation without early commit; qualify actual devices separately.
- [ ] [SNS-06] Qualify complete shared external owners, all nested constructor failure/drop and attempted peak accounting once with the real mixed Bank/State/control/runtime; numeric labels or local failpoints alone do not pass this full gate.
- [ ] [SNS-07] Preserve and complete full configured-P/multi-packet custody, typed per-profile physical fences, retained sealed output/control progress, SW-11 and all native/resource/lifecycle/platform/performance parent requirements.
- [ ] [SNS-08] Run source-stable affected checks with bounded parallelism and exact reused evidence, preserving initial failures and full-stage/native/platform/performance boundaries.

This worker owns the new pure module/tests, old private native adapter/tests and
this new document only. Root owns facade exports, parent wiring, master ledgers,
Cargo/format/check/test/native execution and Git. No project execution has been
performed by this author for this slice.

## Saved execution scope

The [initial affected receipt](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json)
remains **failed: 119 passed, eight failed**. All 14 pure `native_storage::tests`
cases passed there, including every local reservation refusal position, complete
limit before allocation, FIFO/first age, same-buffer publication/recycling,
invalid initialized-prefix publication, accounting preflight and non-Copy drops.
The five exact `secure_udp::transport::native_storage::tests` adapter cases also
passed. Their conversion-category tests do not claim a real process OOM, and
local reservation gates do not qualify unrelated nested owners.

The Bank pending-native case failed its drain assertion in that first receipt.
Its exact case passed in the [facade repair receipt](../../work/common-mixed-bank-20261115/facade-repair-attempt-1/validation.json)
after servicing real receiver readiness before claiming drain. That receipt's
other early-short case failed, so the aggregate stays failed. Existing passing
pool cases are reused with explicit input hashes; current pure pool source and
tests still match those recorded bytes. Later changed consumers have separate
focused evidence rather than an assumed blanket old-binary pass.

The [later runtime receipt](../../work/parallel-features-20261115/runtime-cases-attempt-1/validation.json)
records 19 passes and two failures of 21 exact cases against unchanged immutable
binaries. Relevant passing Common cases are
`held_common_physical_token_blocks_real_switch_and_preserves_original_native_age`,
`common_original_operation_cap_guards_physical_write_and_preserves_late_success_facts`,
`common_sealed_user_wouldblock_retains_exact_bytes_number_scope_and_single_debit`
and `original_udp_nonempty_swift_aligned_packed_switches_preserve_physical_native_bytes`.
It also passes all six listed existing `native_custody` cases: directional
witness retention, mismatched physical generation/count, metadata refusal before
I/O, noncanonical boundary refusal, whole-write success despite later completion
failure, and original FIFO bytes/origin/age through WouldBlock. These actual
original-UDP/Unix packet-device fixtures preserve directly affected behavior;
they are not Linux TAP/TUN, privileged namespace, other-platform, performance or
ISP-QoS measurements.

That earlier runtime receipt fails the State multi-switch coexistence budget
case and the Common shared-service case (stack overflow). The later
[integrated attempt1](../../work/parallel-features-20261115/integrated-cases-attempt-1/validation.json)
and [attempt2](../../work/parallel-features-20261115/integrated-cases-attempt-2/validation.json)
select and pass the corrected State fixture and further selected Common custody
consumers. Their aggregates remain failed at 23/26 and 16/17, with the Common
service stack overflow still failing. Only exact positive cases are reusable;
neither State/runtime positives nor legacy service success prove Common service
readiness/release or complete SNS-05/06/07/08.

The [named pure checkpoint](../../work/parallel-features-20261115/pure-scoped-checkpoint-validation.json)
consolidates 49 distinct saved pure passes, including all fourteen unchanged
native-storage cases and the repaired real Bank-token/Lease case. The five
runtime-adapter cases remain separate consumer evidence, outside that pure-case
count. Both pure pool files still match their original executed hashes; all
30 named pure inputs match the current stable strict-check snapshots. The
[five-package strict checks](../../work/parallel-features-20261115/pure-checkpoint-checks-attempt-1/validation.json)
pass format checking, strict all-target/all-feature Clippy and rustdoc in
25.255 seconds. No functional tests were added or repeated for this checkpoint.
The owner retains all P payload buffers; reuse does not relax the one-pending
Engine limitation, prove full configured-P composition or qualify nested owners.

Unpacked Aligned with an explicitly enabled independent-short policy now has a
separate passing [four-case early-short test](../../work/common-mixed-bank-20261115/early-short-implementation-attempt-3/validation.json).
That path uses real retained recovery sources and selective receiver tombstones;
Packed receive and rolling remain outside that bypass. Their complete native,
copy/ACK, gap-bypass and parity gates are preserved. SNS-05 retains its full
Engine/Bank/pool fault matrix, and SNS-06..08 retain complete external resources,
configured-P custody, full-stage `python3 tools/check.py`, lifecycle, carrier,
native/platform, full SW-11/all47 and 80 Mbit/s acceptance. This reconciliation
ran no tests, builds, formatting, simulator, native or performance workloads.
