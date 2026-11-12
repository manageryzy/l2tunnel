# Context-aware packed source admission

Status: implemented additive preflight with four focused tests and independent
read-only review, strict codec checks and stable wave8 validation. Existing batch admission
validates structure and reserves every unit atomically. This optional stronger
entry point validates complete decoded records before committing any admission.
It does not make native device writes atomic and does not acknowledge recovery.

## Interface and transaction

Add `Receiver::admit_validated_batch_authenticated(symbols, now)` with the same
1..255 exact padded authenticated inputs and returned `Vec<Admission>` as ordinary
batch admission. Validate the existing optional batch memory ceiling and check
preexisting expiry/time first. Existing terminal state stays terminal.

Create one private bounded shadow receiver: copy the authoritative finite
record/proof ledgers, channel decoder contexts, staged decoder context, native
scratch and pending ownership. Admit each input in the shadow through the
existing single-symbol API. In the shadow only, simulate accepting its existing
pending output, then prepare/commit complete records in each ordinary channel.
This uses the existing decoder; no second header/parser implementation exists.
All decoder/context/native changes in this step remain private to the shadow.

If any complete record cannot be validated because an earlier context/record is
missing, return `UnresolvedContext`. An incomplete fragment tail may remain
reserved: its body is validated when the last fragment arrives, before exposing
any newly complete output from that later source. Already validated early raw
tombstones may remain. This stronger API can therefore reject inputs accepted by
ordinary out-of-order admission. The packed endpoint will use global ordered
recovery and must preserve the exact current source under retryable storage
pressure. It must treat an unexplained complete context gap as a protocol error.

On any structural, capacity, semantic or unresolved-context failure, discard the
shadow. Original channel contexts, admission ledgers, source floor, accepted time,
pending bytes and terminal semantic state are unchanged. Preexisting expiry is
the sole earlier terminal mutation. On success, drop the shadow and call the
existing transactional batch admission with the same immutable inputs/time.
The final admission repeats no body decoding and changes no live decoder/native
state. Only later actual whole-frame device acceptance permits `commit_delivery`.

## Explicit bounds

Peak storage is the existing `Limits::batch_memory_bound_bytes`: at most two
full bounded receivers plus255 admission outcomes, capped at256 MiB excluding
allocator bookkeeping/caller inputs. The shadow is dropped before the existing
batch API takes its ledger backup, so the two temporary owners never coexist.
No source ID, native credit or lifetime is created during preflight. Every
deadline uses the same caller-injected timestamp; duplicates never renew it.

At most one preexisting pending commit and `record_slots + channels` preparation
calls occur. Each call uses max_records=1 and either retires/prepares one record
or ends that channel's scan. Existing fixed table scans and bounded body decoding
still apply. Shadow construction/context copying is bounded by validated limits.
No OS, clock, callback or async work appears in this library.

## Checklist

- [x] [MOD-PACKVALID-01] Implement bounded shadow preflight and preserve live contexts, source/record ledgers and pending native ownership on late semantic failure. Evidence: [additive receiver API](../../crates/l2tunnel-codec/src/aligned_receiver.rs).
- [x] [MOD-PACKVALID-02] Test late context-dependent failure, valid multi-channel/context/fragment batches, complete gaps, retry under pending native ownership, deadlines/exhaustion and original API compatibility. Evidence: [four semantic batch tests alongside the unchanged five ordinary batch tests](../../crates/l2tunnel-codec/src/aligned_batch_tests.rs).
- [x] [MOD-PACKVALID-03] Complete independent review, strict focused checks and a source-stable aggregate run. Evidence: [stable wave8 receipt](../../work/implementation-wave8/validation.json), [semantic failure and ownership tests](../../crates/l2tunnel-codec/src/aligned_batch_tests.rs).
- [ ] [MOD-PACKVALID-04] Integrate actual packed recovery ownership and test hostile mixed sources before exposing the runtime profile.

The integrator owns the additive receiver method, its private shadow helper,
focused tests and this document. Existing single/batch admission semantics remain
unchanged.
