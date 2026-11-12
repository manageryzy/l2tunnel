# Transactional admission for a packed source

Status: implemented pure additive receiver primitive with five focused tests.
Strict Clippy/rustdoc, independent read-only review and the source-stable wave7
aggregate passed. The packed
container and authenticated identity envelope already have focused tests.
This slice reserves all aligned units atomically; it does not yet provide a
complete packed sender/recovery/runtime or atomic multi-context native delivery.

## Interface and ownership

Add `AuthenticatedSymbol<'a> { identity: SymbolIdentity, bytes: &'a [u8] }`
and `Receiver::admit_batch_authenticated(&[AuthenticatedSymbol], Tick)` to the
existing aligned receiver. The result is a bounded `Vec<Admission>` in input
order. There must be 1..=255 units. Each input retains the existing exact padded
symbol geometry. The packed composition will zero-extend its validated
meaningful units before invoking this API; this primitive never guesses a
meaningful length from padding.

Every unit still requires existing carrier integrity and replay verification.
Packed composition must verify the outer recovery source, full scope and
contiguous absolute unit identity space before admission. Neither this API nor
the envelope creates that trust. Duplicate/stale outcomes retain the existing
single-symbol semantics, and the composition must decide which are legal for
its current source. No recovery feedback or native-delivery credit is emitted.

## Transaction boundary and bounds

Validate count and a checked `Limits::batch_memory_bound_bytes()` before any
copy. The conservative ceiling is twice the existing receiver reservation plus
255 result entries, at most 256 MiB excluding allocator bookkeeping and caller
input storage. Configurations accepted by the ordinary receiver may therefore
reject the optional batch API. No existing constructor or ordinary admission
behavior changes.

Check current monotonic time and existing expiry before the transaction. Existing
expiry stays terminal. Snapshot only the finite record and source-proof ledgers,
source floor and last accepted time. Existing decoder contexts, prepared native
bytes and pending delivery are untouched by admission. Apply the authoritative
single-symbol admission in input order. A later parse, identity, capacity,
record-window, arithmetic or conflict error restores the complete snapshot;
earlier units consume no source IDs or record storage. The same timestamp is
used throughout. This requires no OS operation, clock, task or callback.

Work is bounded by copying one configured ledger and at most 255 existing
single-symbol admissions, each bounded by the configured record/source tables.
The temporary copy is explicit rather than an uncharged hidden clone of decoder
contexts. Source-frontier advancement may clear multiple proofs, so rollback
must preserve those proofs as well as newly written slots.

Admission validates structural records and completed fragments. Context-dependent
body decoding remains the existing later `prepare` operation. This slice must
not claim that every compressed body has decoded, that multiple native writes
are atomic, or that context-dependent failure after earlier delivery is rolled
back. Those are separate packed receiver composition requirements.

## Checklist

- [x] [MOD-PACKADMIT-01] Implement bounded additive batch admission and complete ledger rollback while preserving the existing single-symbol API and pending native ownership. Evidence: [receiver API and transaction](../../crates/l2tunnel-codec/src/aligned_receiver.rs), [focused tests](../../crates/l2tunnel-codec/src/aligned_batch_tests.rs).
- [x] [MOD-PACKADMIT-02] Test late malformed/conflicting units, source-frontier rollback, capacity/record-window failure, fragment completion, time/expiry and retained native delivery; successful batches preserve exact existing admission outcomes. Evidence: [five focused tests](../../crates/l2tunnel-codec/src/aligned_batch_tests.rs).
- [x] [MOD-PACKADMIT-03] Run focused strict checks, independent review and stable aggregate validation. Evidence: [stable wave7 receipt](../../work/implementation-wave7/validation.json), [focused tests](../../crates/l2tunnel-codec/src/aligned_batch_tests.rs).
- [ ] [MOD-PACKADMIT-04] Compose validated packed envelopes and exact unit/source identities with recovery, then separately implement complete context-dependent validation and native delivery ownership before claiming packed-wire parity.

The integrator owns `aligned_receiver.rs`, its additive batch tests and this
document. No runtime or client worker should depend on this interface until the
focused implementation checkpoint is reported.
