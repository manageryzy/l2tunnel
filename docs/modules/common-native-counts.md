# Common native event observations

Status: **implemented and protocol-tested; named pure checkpoint checks passed;
finite selected Common runtime regressions passed separately**. The engineering baseline was `33f60c0`; executed receipt
versions and remaining failures are distinguished below. This is an actual-event
prerequisite for mixed-profile transactions, not a new management FSM or authenticated delivery proof. Full
CRE-05/06/07, CSE-05/06/07, SW-11, native batching, resource and runtime gates
retain their complete definitions.

## Exact observation and ownership contract

The implementation exposes `record_engine::NativeCounts<'a>` and
`Engine::native_counts(&self) -> Result<NativeCounts<'_>, record_engine::Error>`.
The view contains public immutable `context:Context`, `digest:ConfigDigest`,
`admitted:&'a[u64]`, `prepared:&'a[u64]` and `committed:&'a[u64]`.
Admitted uses the actual local send width; prepared and committed use the actual
local receive width. Views do not allocate or copy a maximum-width snapshot.
They remain observable after a terminal error, retaining physical-write facts.

The actual Engine owns three inline `[u64;256]` arrays, counted by its existing
`size_of::<Engine>()` storage Plan and by the real mixed Bank's inline slots.
There is no separate heap, shared global counter, hidden packet queue or native
identity conversion. Swift64, Aligned256 and Packed255 limits stay independent.
Its actual full configuration determines each directional slice width.

Increment admitted for the exact selected channel only when the maintained
codec accepts original native bytes. Preflight that channel's next count before
calling the codec. None, Full, Busy, parser/policy refusal or downstream error
admits no native record and increments no channel count. Both owned functional
and borrowed reserved admission use the same counted callback helper. The
original Pipeline/MUX/DRR remains the only classification/admission algorithm.

Increment prepared only when an actual original native body is exposed as Ready,
using its real profile identity's channel. Context/tombstone Progress, Idle,
AlreadyPending and retry do not increment. Preflight representable per-channel
preparation and completion counts before extraction, as with existing global
statistics. Retain original profile identity and the immutable pending token;
these counters never replace either.

Increment committed once for the pending channel only after the trusted caller
reports a whole physical write using the exact original token. Preserve that
fact, clear pending once and keep it observable even if subsequent time/expiry/
receiver cleanup is fatal. A stale token, buffer enqueue, source ACK, fragment,
repair or context is not physical completion. Never renew the original deadline.

## Counts are not a contiguous delivery prefix

The transaction Fence is explicitly an exclusive admitted-native count per
channel. Aligned/Packed codec record IDs also include contexts and may start at
nonzero values. Do not use RecordId+1 or a last/max body ID to create that count.
Independent-short native delivery can occur before an older gap; prepared and
committed are event totals, never evidence that a prefix completed. Maintain
actual receiver selective receipts/tombstones and original profile identity.

The selected Common controller freezes a local admitted count only after
stopping new native ingress and draining the existing common admission queue
into its original codec generation. An authenticated peer fence limits native
body totals in the exact old session/epoch/digest/global-sender width. A clean
switch additionally requires the actual entire generation's send/receive drain,
exact per-channel counts, empty pending/native/sealed-output custody, original
receiver tombstone retirement and genuine whole-message control confirmations.
A numeric equality or an event view alone grants none of those authorities.
The actual existing leased Peer remains the only switch FSM.

## Implementation and meaningful checks

Actual production code is in `record_engine.rs`, `record_engine/native.rs` and
private `record_engine/native_counts.rs` plus focused tests. Bank/native-pool/transaction
owners consume the same maintained Engine; no second counting algorithm is added.
No clock, OS handle, Tokio, device setup, unsafe code, custom crypto, wire/default change or owner decision is introduced.

Passing cases drive actual accepted/refused codec admissions, paired Swift/Aligned/
Packed native bodies with unequal widths/nonzero codec IDs, pending retries,
context-only Progress, trusted whole-write completion and stale tokens. Original
bytes and profile identity are checked separately from counts. The late-receipt
case preserves the physical fact after a terminal deadline error; selected-channel
exhaustion refuses before codec mutation with unchanged queue/Usage. These pure
callbacks acknowledge an in-process sink, not a real TAP/TUN write.

The actual unpacked Aligned path now uses `Reliable::received_sources()` to
observe authenticated retained out-of-order sources in the same receiver before
ordered recovery closes the gap. It is explicitly gated by nonzero
`independent_short_frame_bytes` and disabled when receive packing is selected.
The passing strengthened case covers Ethernet/raw-IP and both roles: a later
independent short body is committed before the withheld older long body, duplicate
sources do not duplicate delivery, the old gap later recovers and the actual
generation drains with stable Usage. This supplies direct evidence that counts
are event totals rather than a record prefix. Packed and rolling do not inherit
this bypass; their complete independent-short, parity and native/fence gates stay
open.

The Common Driver's `Boundary::capture` reads the exact generation's admitted or
committed slice with session/epoch/digest/origin checks. Its barriers additionally
require stopped admission, actual full-generation drain and empty retained native/
sealed-wire custody; incoming peer counts are not treated as prefix receipts.
The selected runtime cases below exercise this implementation. They do not
complete every CNF-04 fault/native/lifecycle condition or its parent gates.

- [x] [CNF-01] Freeze actual-event semantics, exact directional views and complete inline accounting before production; preserve original profile identity and distinguish totals from prefix/authentication proof. Evidence: [pre-production engineering freeze](../../work/common-mixed-bank-20261115/native-counts/pre-production-v0.json).
- [x] [CNF-02] Implement actual per-channel admitted/prepared/committed observations with checked preflight and the same production admission/native transitions; None/error/retry/context does not fabricate a native event. Evidence: [split count/roundtrip/late-receipt passes; failed aggregate](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json).
- [x] [CNF-03] Test real families, unequal widths, nonzero codec identities, pending and stale-token behavior, exhaustion and late physical receipts, with exact bytes and stable complete storage accounting. Evidence: [split family/count passes; failed aggregate](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json), [exact four-case unpacked Aligned pass](../../work/common-mixed-bank-20261115/early-short-implementation-attempt-3/validation.json), [named pure checkpoint and exact reuse](../../work/parallel-features-20261115/pure-scoped-checkpoint-validation.json).
- [ ] [CNF-04] Consume actual observations in selected mixed-profile native/control barriers with genuine stopped admission, full-generation drain, selective receipts and physical custody; no equality-only or synthetic fence qualifies SW-11.
- [ ] [CNF-05] Pass affected source-stable checks with bounded parallelism and required full-stage acceptance, preserving original native/platform/performance gates and exact evidence reuse.

## Recorded checks and limits

The [initial affected receipt](../../work/common-mixed-bank-20261115/affected-tests-attempt-1/validation.json)
records **119 passed and eight failed**, not an aggregate pass. Within its
59 passing facade cases, all three actual-family TAP/TUN/asymmetric roundtrips,
`exhausted_selected_channel_refuses_before_actual_codec_admission`,
`local_counter_preflight_and_monotonic_failure_do_not_fabricate_native_custody`
and `late_actual_physical_receipt_counts_once_but_never_completes_expired_owner`
passed. The early-short case initially reported `Profile`; the
[facade repair receipt](../../work/common-mixed-bank-20261115/facade-repair-attempt-1/validation.json)
still failed that case with `RetryExhausted`, while its separate Bank custody
case passed. Neither failed aggregate is relabeled as successful.

The original narrow [early-short attempt1](../../work/common-mixed-bank-20261115/early-short-implementation-attempt-1/validation.json)
passed. [Attempt2](../../work/common-mixed-bank-20261115/early-short-implementation-attempt-2/validation.json)
failed before test execution because `--locked` rejected a changed lockfile.
[Attempt3](../../work/common-mixed-bank-20261115/early-short-implementation-attempt-3/validation.json)
then selected and passed the strengthened exact test with four real reserved
Aligned role/layer cases. Its command, input hashes and log bind that result; it
is not Packed/rolling, a full allocator matrix or native-device qualification.

The [later runtime receipt](../../work/parallel-features-20261115/runtime-cases-attempt-1/validation.json)
records **19 passed and two failed out of 21** against stable immutable binaries.
Relevant passes include `original_udp_nonempty_swift_aligned_packed_switches_preserve_physical_native_bytes`,
`held_common_physical_token_blocks_real_switch_and_preserves_original_native_age`
and `common_original_operation_cap_guards_physical_write_and_preserves_late_success_facts`
under `secure_udp::transport::tests::common_selected`, plus the six exact
`native_custody` regressions listed there. They provide finite authenticated
original-UDP/Unix packet-device evidence, not privileged TAP/TUN execution.
The pure `one_real_state_switches_empty_reserved_swift_aligned_packed_and_back`
case failed its coexistence budget; the new Common shared-service case aborted
with stack overflow. Those failures remain in that receipt. The later
[integrated attempt1](../../work/parallel-features-20261115/integrated-cases-attempt-1/validation.json)
and [attempt2](../../work/parallel-features-20261115/integrated-cases-attempt-2/validation.json)
record the corrected State case passing, but remain failed aggregates with
23/26 and 16/17 positive cases respectively. Common shared-service stack overflow
still fails in both. These individually selected runtime/State positives are
auxiliary consumer evidence; neither they nor legacy service success complete
a pure mode, full transaction gate or Common service qualification.

The [named pure checkpoint](../../work/parallel-features-20261115/pure-scoped-checkpoint-validation.json)
consolidates 49 distinct saved pure passes across native storage, Bank, native
counts, rolling, Reliable/Aligned and bounded Swift feedback. All 30 named pure
source/test inputs match the recorded strict-check snapshots and audited reuse
inputs. The [five-package strict receipt](../../work/parallel-features-20261115/pure-checkpoint-checks-attempt-1/validation.json)
passes format checking, strict all-target/all-feature Clippy and rustdoc in
25.255 seconds with stable sources. No functional test was added or rerun for
this checkpoint. Historical failures and exact positive log lines remain bound
to their original receipts; this does not claim an entire integrated revision
passed. CNF-04/05 remain open, including required
`python3 tools/check.py`, complete resources, configured-P custody, retained
recovery, full SW-11, all record/parity modes, native/platform and 80 Mbit/s gates.
This reconciliation executed no tests, builds, formatting or workloads.
