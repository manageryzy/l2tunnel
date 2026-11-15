# Reserved mixed-profile record Bank

Status: **implemented; seven focused pure Bank cases passed across the initial
source-bound batch and its narrow repair; named pure checkpoint checks passed**. Selected Common runtime regressions
also passed; complete State/service/native/resource qualification remains open.
The [source-audited proposal](../../work/common-mixed-bank-20261115/bank/proposal-v0.md),
[pre-production binding](../../work/common-mixed-bank-20261115/bank/pre-production-v0.json)
and [root engineering freeze](../../work/common-mixed-bank-20261115/bank/engineering-freeze-v0.json)
precede production edits. This is the pure two-slot storage/publication prerequisite
for [CSE-07](common-engine-storage.md) and full [CRE-06/07](common-record-engine.md),
not their completion or a new owner decision/default.

## Actual ownership and public surface

`l2tunnel::record_bank` owns two inline slots containing actual reserved
`record_engine::Engine` values. Each occupied slot selects exactly one real Swift,
Aligned or Packed duplex owner. No unused Swift Set, mutable Engine escape,
replacement, into-inner, clone, allocating fallback or third slot is exposed.
The runtime alone retains current/staged/draining roles and the existing leased
Peer/transaction FSM. This pure owner uses no OS handle, Tokio, I/O, real clock,
privilege or TAP/TUN setup.

The frozen public surface is Bank/GenerationId/Prepared/Entry and public storage
Plan/Limits/Usage/Error. Plan::for_bank takes the actual initial Engine Plan and
the caller-accounted external subtotal; Bank::new constructs the actual initial
owner. Bank::initial denotes its original historical ID, not a runtime current
epoch. prepare constructs a virgin owner; prepared_engine is immutable, publish
returns its exact GenerationId and cancel releases it after actual drain.
Published owners have immutable engine observations, restricted entry packet
operations and actual-drain-checked retire. Guard drop alone leaves the separately
owned slot retained/charged; only explicit cancel or owner teardown releases it.

GenerationId binds a private nonwrapping slot generation to a checked process-local
AtomicU64 Bank discriminator. It is a local ownership label, never wire/crypto/
nonce authority. Prepared is move-only and consumed once. Failed construction
does not consume a generation. A foreign, stale or consumed ID/guard refuses
before accessing an Engine. Virgin entries cannot mutate packet state.

Entry forwards the actual borrowed enqueue/admission, typed poll/authenticated
receive, tick and native prepare/pending/commit APIs. Bank PreparedNative and
NativeToken add the exact GenerationId to the original Engine metadata/token.
Ready/AlreadyPending preserves original bytes, identity and deadline. A token
from another Bank or reused slot refuses before Engine/time mutation. Only a
whole physical write permits trusted commit; native enqueue is not completion.
No additional payload queue or copy is introduced by this wrapper.

## Complete retained accounting and failure

Plan and Usage count `size_of::<Bank>()` once, including both actual inline Engine
slot extents even when vacant. Only each occupied Engine Plan's heap_bytes is
added. Actual nested Pipeline/record heap and reservation totals must match the
planned Engine before publication; nested Engine headers are not charged twice.
Shared external storage is counted once, independently of occupied slot count.

Usage retains limit_bytes, fixed_bytes, external_bytes, engine_bytes,
building_bytes, capacity_bytes, peak_bytes and allocations. Engine/building
bytes are heap-only; capacity is the complete current charge. Before construction,
precharge fixed + external + all retained heaps + complete target heap, then
retain the admitted attempted peak. Over-limit requests never enter a constructor.
On construction/refusal/invariant failure, actual partial/full target ownership
drops before building charge release; the old owner and next generation remain
unchanged. Retirement checks real Engine drain and all release arithmetic before
drop, then releases its charge. Failed/undrained whole-owner teardown is cleanup,
never a claim of clean delivery or negotiated retirement.

These are retained Rust layout capacities, not allocator bookkeeping/rounding,
RSS, stack, physical pages, kernel memory or an OOM guarantee. Private local
constructor gates are distinct from literal nested dependency allocator failure.
The external subtotal remains an explicitly caller-accounted scalar in this
pure prerequisite. Full resource qualification requires the real single external
native/buffer/witness/control/Peer/catalog/report/bootstrap/bridge owner bundle,
verified actual capacities and complete failure cleanup.

## Runtime and unchanged parent requirements

The actual `transport_common_engines::Bank` adapter owns the immutable
`tx::Preparation` and pure Bank guard. The same generic leased TransactionState
uses this backend, revalidates identity/full ticket/origin/expiry/configuration
after allocation, publishes that same virgin instance at stage and switches
retained IDs at commit. This is one actual backend of the existing transaction
FSM. The selected Common Driver consumes it with original security/member/replay/
key owners and fixed Control; stopped admission, old feedback/receiver/tombstone/
native deadlines and final Control custody remain required through retirement.
Actual protocol drain is necessary, while authenticated full-width fence equality,
empty sealed/native/feedback/proof ownership and whole-message confirmation remain
separate runtime retirement obligations. Local counts, RecordId+1 and publication
do not manufacture those proofs.

One actual Engine currently permits one pending native packet. The original
runtime's configured P-slot batching remains required integration work; do not
reduce P or commit at queue publication. Full CSE-07, CRE-06/07, GSU-05, SRS-07,
literal CRS-06, SW-11, retained recovery/fresh-DH, RLNC/parity/rolling/packed/proxy,
all47, carrier/native/platform and 80 Mbit/s requirements remain unchanged.

## Stable acceptance tasks

- [x] [MBS-01] Freeze exact pure Bank API, actual backing, complete layout and failure order, ownership/native binding and pre-production source evidence before production edits. Evidence: [root engineering freeze](../../work/common-mixed-bank-20261115/bank/engineering-freeze-v0.json).
- [x] [MBS-02] Implement actual two-slot mixed-profile reserved construction/publication, exact fixed/heap/external/peak accounting, real partial cleanup and original-owner isolation without fallback or generation burn. Evidence: [split six pure Bank passes; failed aggregate](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json).
- [x] [MBS-03] Implement restricted actual packet/native operations with foreign/stale/consumed guard/ID/token refusal, original native deadlines and real-drain retirement. Evidence: [split identity/retirement passes; failed aggregate](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json), [exact repaired token/Lease pass](../../work/common-mixed-bank-20261115/facade-repair-attempt-1/record_bank_tests_actual_pending_native_lease_keeps_custody_and_rejects_foreign_and_recycled_tokens.log).
- [x] [MBS-04] Pass focused actual-family transition, exact/one-short/+1 capacity, current-held queue/native custody, local build failure/drop and foreign/recycled identity regressions in a source-frozen affected batch; distinguish local gates from nested allocator proof. Evidence: [split six Bank passes; failed aggregate](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json), [split repaired Bank pass; failed two-case aggregate](../../work/common-mixed-bank-20261115/facade-repair-attempt-1/validation.json), [named pure checkpoint and exact reuse](../../work/parallel-features-20261115/pure-scoped-checkpoint-validation.json).
- [ ] [MBS-05] Integrate the same real prepared instance into the actual generic leased State/selected runtime, complete real external owners, authenticated physical/native/control/fence retirement and full parent acceptance without shrinking any definition.

This lane owns only the new facade Bank/children and this module document. Root
owns exports/master ledgers and all formatting/build/check/test/Git/native
execution. Source/test authorship alone cannot check implementation/evidence
gates; the executed scope below supports the checked pure leaves, not MBS-05 or its parents.

## Focused pure cases with executed evidence

Seven passing focused cases use actual reserved Engine owners:

- `every_real_family_transition_publishes_the_exact_virgin_and_preserves_current_queue`
  covers all six ordered transitions among the three actual families, exact
  prepared/published Engine address, complete configuration and continued old
  queue admission after retirement refusal.
- `foreign_consumed_and_recycled_guards_refuse_without_accessing_an_engine`
  covers actual foreign Banks, consumed guards, slot reuse and retained charge
  after abandoned guard drop.
- `actual_pending_native_lease_keeps_custody_and_rejects_foreign_and_recycled_tokens`
  carries a real Swift packet into the actual preallocated native Lease, publishes
  the same buffer without another copy, holds original metadata/age, verifies
  identical actual Engine tokens cannot cross Banks, observes unchanged pending
  bytes, refuses expiry retirement, then commits a simulated whole sink once and
  rejects stale/recycled ownership. Trusted plaintext and an in-process sink do
  not establish outer authentication, real device execution or full P batching.
- `actual_two_slot_layout_counts_inline_headers_once_and_measures_nested_heaps`
  measures actual reserved Usage for every family at exact/one-short/+1 initial
  allowances, with both inline Engine extents and external subtotal counted once.
- `one_short_second_slot_never_enters_constructor_and_exact_plus_one_admits`
  checks the complete live-plus-target charge, actual nested reservation totals
  and retained peak after cancelling a genuine virgin Packed owner.
- `actual_target_drop_keeps_attempted_peak_and_preserves_live_old_owner_and_generation`
  observes real precharge, constructs/drops a real target under a local injected
  post-construction refusal, then verifies old queue/address/stats and generation
  survive and both old/new actual owners remain usable.
- `nonwrapping_instance_and_final_generation_exhaustion_preserve_retained_owners`
  uses a local Atomic helper and the final real slot generation without modifying
  shared global identity, wrapping, constructing after exhaustion or losing the
  retained initial owner.

The local post-construction refusal is neither nested allocator exhaustion nor
full CSE-06/CRS-06 qualification. The numeric external test subtotal is not the
complete real external owner inventory. Full runtime transaction/physical proof,
native/platform/performance and all unchanged parent gates remain open.

## Executed receipts and remaining integration

The [initial integration build](../../work/common-mixed-bank-20261115/integration-build-attempt-1/validation.json)
passed compilation only. The subsequent
[initial affected execution](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json)
records 119 passes and eight failures. Six Bank cases above passed there; the
pending-native Lease case failed its test drain assertion. The
[narrow facade repair](../../work/common-mixed-bank-20261115/facade-repair-attempt-1/validation.json)
then selected and passed that Bank case after servicing actual pending receiver
readiness before asserting drain. Its complete two-case receipt remains failed
because the separate early-short case still failed. This split evidence supports
MBS-02..04's actual pure owners and checked custody/capacity transitions; it does
not turn either aggregate into a full-stage pass or prove nested allocator/OOM
qualification. Each recorded version, exact command and binary hash is retained.

The later [runtime execution](../../work/parallel-features-20261115/runtime-cases-attempt-1/validation.json)
records 19 passes and two failures across 21 exact cases on immutable build-receipt
binaries. Its three `common_engines::tests` cases pass actual same-instance
preparation/publication, complete-envelope refusal before reservation and genuine
one-short target refusal preserving the current queue and readonly Peer intent.
The selected Common Driver passes nonempty original-UDP Swift→Aligned→Packed
and back with exact packet bytes, retained physical-token switching refusal,
original operation expiry/late-write facts, context progress and unchanged sealed
output/number/scope/debit across WouldBlock. These are real user-space runtime
fixtures with Unix packet-device observations, not a privileged TAP/TUN lab,
standard-dissector capture, Windows/Android or throughput qualification.

That earlier receipt fails the State multi-switch case with
`Limit { required:2696673, limit:1440608 }` and the Common shared-service case
with stack overflow. The multi-switch fixture initially budgeted an initial
Swift heap plus one maximum target heap, while later Aligned/Packed coexistence
correctly requires both retained real heaps. The later
[integrated attempt1](../../work/parallel-features-20261115/integrated-cases-attempt-1/validation.json)
and [attempt2](../../work/parallel-features-20261115/integrated-cases-attempt-2/validation.json)
select and pass the corrected State case while preserving all original
production admission limits. Those aggregates remain failed at 23/26 and 16/17;
the Common service still aborts with stack overflow. These consumer passes do
not close MBS-05, and legacy Swift service success is not Common service evidence.

For any successive mixed switch, retain the original complete allowance and
precharge `Bank inline + external once + current/draining heaps + target heap`.
Do not recalculate capacity as initial Swift plus a target, silently grow an
operator limit, remove a catalog entry or retire an undrained owner to fit. A
per-test coexistence allowance is a fixture requirement, not permission to relax
production admission.

The [named pure checkpoint](../../work/parallel-features-20261115/pure-scoped-checkpoint-validation.json)
consolidates seven distinct Bank cases within 49 saved pure passes. Its audit
binds all 30 named pure inputs, including the five Bank files, to the stable
strict-check snapshots and their recorded functional evidence. The actual pure
Bank storage, generation and publication transitions are unchanged. The repaired
foreign-guard test also passed after its lexical-scope-only Clippy correction.
Moving this same Bank into the runtime's fallible StateCell changes the runtime
wrapper, not the pure API, two actual slots or pure Plan's fixed/heap accounting.
The [five-package strict checks](../../work/parallel-features-20261115/pure-checkpoint-checks-attempt-1/validation.json)
pass format checking, strict all-target/all-feature Clippy and rustdoc in
25.255 seconds. No functional tests were added or repeated for this checkpoint;
none of these checks proves a Common service or complete resource envelope.

The selected Common construction now reserves real native/buffer/input/witness
and Control-message/wrapper owners in its known subtotal. Pure Bank's external
scalar still grants no ownership by itself, and remaining Peer/catalog/security/
bootstrap/reporting allocations and complete construction/failure/drop peaks
retain their own gates. `resource_preallocation_complete` remains false. Full
configured-P behavior and MBS-05/CSE-07/CRE/CRS-06/SW-11/native/platform/performance
acceptance remain open. Explicit unpacked Aligned early-short evidence does not
qualify Packed/rolling gap bypass or their full parity requirements. The required
full `python3 tools/check.py` stage is not supplied by these focused receipts.
This documentation reconciliation ran no tests, builds, formatting or workloads.
