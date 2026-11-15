# Bounded packed sender ownership

Status: implemented pure composition with six focused tests and an independent
review that identified and fixed the clock-exhaustion ownership boundary. This module joins
the exact aligned-unit sender, Python-compatible timed packer and absolute
identity envelope. Actual ARQ/FEC remains the separate recovery owner. Runtime,
native credit and complete packed-mode qualification remain unfinished.

## Frozen interface

`l2tunnel_codec::packed_sender::Config { sender, packing, max_units, first_unit,
work_limit }` requires matching symbol geometry, at most255 ordinary channels,
1..255 units per source and1..255 unit attempts per poll. All source metadata and
memory products are validated before allocation. `first_unit` is a separate
negotiated absolute sequence, never the recovery source ID.

`Sender::new(scope, config)`, `stage(channel, frame, now_micros)`, `stage_raw`,
`poll(now_micros)`, `flush(now_micros)`, `write_pending(recovery_source, output)`,
`commit_source`, `status`, `is_idle` and `deadline_micros` form the lifecycle.
The authenticated profile must select Ethernet/header or exact raw-IP staging;
this pure primitive grants no permission to mix those policies.

One bounded aligned frame and one bounded packed source may coexist. Successful
stage owns the frame even if the packed source is already sealed. A second frame
is Busy until the first is copied into the packer. Each copied unit has its exact
absolute record ID retained in a preallocated vector. Unit IDs advance only when
the packer copied that complete unit. Reaching max_units explicitly seals the
source; capacity/timer/large-unit behavior remains the original packer. Existing
constructors keep exactly one physical copy per source. The additive explicit
[copy policy](source-copy-policy.md) supplies `new_with_copies` and
`new_reserved_with_copies`, retaining an immutable policy and classifying actual
units before the same Packer admission. A different selected count seals a
copy-policy boundary without consuming the new unit. `pending_copies` reports
the actual homogeneous sealed-source count. This source implementation has
focused tests authored but validation pending; returning the count does not
perform or charge physical copies in recovery/runtime.

`write_pending` binds the caller's actual next recovery source ID and writes the
canonical complete envelope without consuming anything. The same source and
bytes remain retained under output/recovery backpressure. Call `commit_source`
only after the actual recovery engine copied the complete envelope and returned
that same ID. It releases the packer and its metadata, not peer/native credit.
Recovery IDs are never allocated locally. No source-prefix feedback is invented.
Multiple-copy selection does not change envelope bytes, unit/record IDs or this
single recovery-ownership commit. Actual repeated physical sends must retain the
same recovery source and independently satisfy their enclosing write budgets.

## Failure, time and resource boundary

Unit-ID exhaustion never wraps. Failure halfway through a multi-unit staged frame
is terminal and retains ownership; it is not a clean drain or fallback. Ordinary
bad input, Busy, short output and clock regression preserve their existing
retry/error contracts. NoPending cannot discard a staged unsealed source.
An unrepresentable initial hold deadline rejects a fresh frame before time,
ownership or context changes. If time exhausts after a frame was already owned
and needs another source, the failure is sticky and retains that frame. No future
monotonic timestamp could make that remaining work succeed.

One sender allocation, one packing buffer, at most max_units record IDs and fixed
metadata are charged by `Config::memory_bound_bytes`, capped at64 MiB excluding
caller output and allocator bookkeeping. Each poll attempts at most work_limit
units; all copies are bounded by symbol capacity. No ambient clock or I/O exists.
The packer's original first-unit deadline is exposed and never renewed by later
units or recovery pressure. An explicit flush can seal a partial frame's already
copied units; remaining fragments stay in the original single-frame stage.

## Checklist

- [x] [MOD-PACKSEND-01] Implement exact timed unit/record/source ownership and bounded metadata with externally assigned recovery identities. Evidence: [bounded sender](../../crates/l2tunnel-codec/src/packed_sender.rs).
- [x] [MOD-PACKSEND-02] Test multi-channel packing, fragments/context records, fixed timer, negotiated count/capacity flush, retained immutable output and source/unit/record exhaustion. Evidence: [six focused tests including fresh versus owned clock exhaustion](../../crates/l2tunnel-codec/src/packed_sender_tests.rs).
- [x] [MOD-PACKSEND-03] Test actual envelope/receiver byte round trips and strict checks, independent review and source-stable aggregate validation. Evidence: [focused ownership and byte tests](../../crates/l2tunnel-codec/src/packed_sender_tests.rs), [stable wave8 receipt](../../work/implementation-wave8/validation.json).
- [ ] [MOD-PACKSEND-04] Integrate the actual reliable recovery engine and transactional context-aware receiver before exposing runtime/native packed mode or source-copy claims.

The integrator owns `packed_sender.rs`, its tests and the additive codec export.
