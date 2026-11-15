# Actual rolling scheduler heap admission

Status: **implemented; three focused cases and strict affected checks passed**.
The [source-stable receipt](../../work/rolling-storage-20261115/affected-attempt-1/validation.json)
records formatting, the exact three-case selection, strict Clippy and rustdoc in
13.519 seconds. No unchanged recovery, simulator, runtime or native suite ran.
This is an additive
pure backing prerequisite for the complete rolling record Engine/Bank, not
installation of a selected runtime or completion of its full resource gate.

`l2tunnel_fec::rolling::storage::Plan` inventories the existing scheduler Sender's
three real allocations and Receiver's thirteen, including both decoder equation
banks, version metadata, transaction decisions/free slots, history and scratch.
Plan/Usage exclude inline owner headers, which the embedding owner counts once.
Observed Usage uses actual retained vector capacities, including idle buffers;
it is not the compatibility `memory_bound`, allocator rounding/bookkeeping, RSS,
stack, kernel memory or a guarantee against allocation failure.

`Sender::new_reserved` and `Receiver::new_reserved` validate the original complete
policy, both existing conservative caps, every relevant constructor-time deadline
addition and the complete requested heap allowance before the first allocation.
They construct the same existing owners and algorithms through their original
fallible constructors. Actual capacities must match the plan and fit the allowance
before publication; otherwise the real constructed owner drops and construction
refuses. There is no alternate GF implementation, packet queue or fallback.
Existing constructors, wire bytes and defaults remain unchanged. Observations are
available for both original and reserved constructors.

- [x] [RLS-01] Implement actual nested requested and observed scheduler capacities, complete pre-admission and existing-constructor reuse; prove exact/one-short/+1 allowances, both original conservative guards and overflow-before-allocation checks in the focused affected batch. Evidence: [three focused source-bound passes and strict checks](../../work/rolling-storage-20261115/affected-attempt-1/validation.json), [actual backing tests](../../crates/l2tunnel-fec/src/rolling/storage/tests.rs). Literal allocator entry/failure instrumentation remains RLS-03.
- [x] [RLS-02] Confirm actual source/feedback/upper-handoff and ring recycling retain the same observed capacities and arbitrary payload bytes; record source-bound focused strict formatting, Clippy and rustdoc results. Evidence: [real twelve-source/feedback/handoff ring reuse](../../crates/l2tunnel-fec/src/rolling/storage/tests.rs), [affected receipt](../../work/rolling-storage-20261115/affected-attempt-1/validation.json).
- [ ] [RLS-03] Exercise literal failure at every nested allocation position, observe complete partial cleanup and integrate the same real backing into complete record Engine/Bank/native/control admission; local admission refusal does not prove this matrix.

Complete reference local128/global8192/every16 recovery, old-source loss, configured
native P batching, compact rolling selection, authenticated switching/rekey,
retained recovery, native/platform/performance and every original parity gate
remain required. See [rolling records](rolling-records.md),
[local/global recovery](local-global-rlnc.md) and
[implementation checklist](../implementation-checklist.md).

## Committed feedback snapshot prerequisite

Implemented and protocol-tested: derive feedback only from the committed
decoder header. Compute checked historical sources as prefix minus
actual evicted-before, future known as known-count minus that history, and
missing extent as end minus prefix minus future-known. The deficit subtracts
committed rank with saturation. Handoff can advance prefix before eviction;
shadow, candidate and aborted transaction state cannot enter this snapshot.

Freeze one concrete Feedback while serializing its unchanged 64 bytes under the
existing copy/metadata budgets. Permit ingress and handoff subject to the real
decoder Busy/Capacity constraints. Reset feedback events/due at snapshot start
only; subsequent events retain their first due time through older output
confirmation. Add no allocation, wire field, identity, deadline or budget.
Higher-level feedback-building handoff guards remain unchanged.

- [x] [RFB-01] Verify the checked snapshot against actual committed-column scans across lagging eviction, in-flight GF shadow and Capacity/abort; preserve the 64-byte format and identity exhaustion. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [x] [RFB-02] Verify tiny-budget immutable serialization with concurrent ingress/handoff, retained later feedback debt/first trigger, unchanged work caps and original output expiry. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [x] [RFB-03] Exercise actual global8192/local128/every16 recovery of an old hole using a real global repair, all exact originals, retained sender debt, ring reuse and stable storage; separate finite component evidence from full FIX-03. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).

Six new focused cases and the existing feedback identity-exhaustion case pass,
alongside affected strict checks. The actual8192 experiment uses payload8 and
rows4, with one old hole and two subsequent full ring reuses; it is finite
component evidence, not full-width GF or kernel throughput qualification.

The legacy support128 guard and window-times-lanes ingress queue remain unchanged.
Full FIX-03 still requires decoupled ingress, full/half local2 pressure,
Busy/Capacity loss/deadline coverage and global-GF/native/performance evidence.
