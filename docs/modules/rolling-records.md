# Compact records over actual rolling recovery

Status: **implemented pure composition; four focused protocol tests and named
pure checkpoint checks passed**.
The saved Linux checks establish actual byte/identity/custody behavior below, not
a selected runtime or a physical native-device path.
This additive lane addresses the missing compact-record-to-rolling composition in
[FIX-02](../implementation-checklist.md). It does not complete that item, any
P-* family, full SW-11, full resources, selected runtime/service/CLI integration,
native qualification or the 80 Mbit/s target. The original definitions remain.

Read the [architecture](../architecture.md), [plan](../implementation-plan.md),
[checklist](../implementation-checklist.md), [complete parity matrix](../mode-parity.md),
[actual rolling scheduler](local-global-rlnc.md), [legacy rolling runtime](rolling-runtime.md),
[common Engine](common-record-engine.md), [record configuration](record-configuration.md)
and [common Engine backing](common-engine-storage.md) with this module.

## Actual owners and delivered source scope

The new pure `l2tunnel::rolling_records::Endpoint` owns one actual reserved
`codec::packed_sender::Sender`, one actual reserved
`codec::aligned_receiver::Receiver`, one actual
`fec::rolling::scheduler::Sender` and one actual
`fec::rolling::scheduler::Receiver`. It connects meaningful actual L2PK units to
the causal local/global rolling encoder/decoder. It does not embed two unused
bidirectional endpoints, duplicate GF arithmetic, reimplement packing, add a
classifier/scheduler, select a carrier or construct authentication/control state.

`Config` retains independent complete forward/reverse DirectionConfig values,
exact forward/reverse outer overhead and an explicit native stall cap. Each
DirectionConfig includes the complete existing packed sender policy, record
receiver limits, native interpretation, independent positive codec_stage_micros
and actual rolling scheduler policy.
All injected ticks are microseconds, including the rolling scheduler's timers;
legacy rolling runtime millisecond interpretation and identity remain unchanged.
No timer is silently converted or defaulted. Construction validates both
policies/cross-owner geometry before actual allocation and uses real fallible
codec reservations plus the existing fallible rolling constructors. Scratch is
fallibly reserved once. No whole history/equation snapshot or per-record output
Vec is added by this composition. Rolling conservative memory bounds are not
reported as exact complete common Engine/Bank Usage or full allocator proof.

`Config::digest` hashes the complete validated policies under the additive
`l2tunnel/packed-records/local-global-rolling/v1/microsecond-ticks` domain.
`binding_digest(stream)` additionally binds the exact coding stream under its own
version-one domain. The selected carrier/session must authenticate that actual
binding and its session/epoch/role before installing the endpoint. These helpers
confer no authentication authority. Existing Swift/Mode/CompleteV2 encodings and
legacy rolling-session digests remain unchanged; CompleteV2 currently has no
installed rolling variant. Full common configuration/catalog/Bank negotiation is
an explicit integration prerequisite, not inferred from this standalone API.

## Exact functional adapter

The constructor is `Endpoint::new(config, record_engine::Context, stream,
record_engine::Tick)`. Context projects actual global send/receive scopes by role.
Nonzero session/epoch, per-direction geometry and initial clock arithmetic are
checked before selected allocations. Packed channels remain1..255; unpacked256
and Swift64 remain supported by their existing owners and are not removed.
The distinct rolling u32 source, u64 repair, feedback ID, aligned unit ID,
per-channel record ID, full-width external security PN and native count spaces
are never substituted for one another.

`enqueue_admitted_identified(now, channel, bytes)` returns an actual body identity
or None for unchanged Busy admission. The separate
`admit_from_pipeline(now, &mut Pipeline)` calls the existing real
`offer_front_borrowed` once: only actual codec admission consumes its head; None
retains its original bytes, metadata, affinity and DRR debit. Invalid channels
are rejected without modulo before context/identity changes. Direct enqueue is
for already-admitted traffic only. The embedding common runtime still binds the
correct TAP/TUN Pipeline, learns reverse affinity from decoded originals and owns
delivery-window/Active/proxy admission. This endpoint does not install those
capabilities simply by accepting bytes.

`step(now, WorkBudget)` services the two actual independent scheduler owners,
each under that explicit cap; fixed packing work remains its existing
work_limit. At most one decoded packed source enters the record ledger per call.
A single preexisting received source stays retained on record Capacity/RecordWindow
pressure; there is no hidden wire-input queue. Real atomic reserved batch admission
preserves source/record/context state on refusal. Generated per-unit padding is
reconstructed only into preallocated scratch; meaningful zero tails remain exact.
Feedback/decode receipt is separate from record handoff and physical native
completion. Full RLNC equations still use the original authenticated rolling wire
v1 or explicitly selected exact-source v2; repairs remain full width.

`flush` seals real packed work without an empty source. The original first native
admission starts its explicitly configured codec_stage_micros cap; that cap
is independent of the recovery scheduler job timer. Later native admissions, Busy,
WouldBlock and observation do not renew it. Actual scheduler debt/job/handoff,
record first-arrival and prepared-native deadlines remain authoritative. Packing,
feedback and tail wake times are service triggers, not replacement expiry bounds.

`prepare_output(now, security_number, allow_data, output, budget, witnesses)`
services ready actual feedback before new data, including when data is disabled.
It checks actual output/witness space and exact available complete wire debit
before reserving one output. It reuses the common EmissionKind/SourceForm,
OutboundBudget, full-width security number and actual UnitWitness types. The
SystematicFec source branch here is the real rolling systematic source, never a
claim of block interoperability. The original source owns actual compact units;
repairs contain no original unit witness. This adapter does not add cryptography.

A PreparedOutput retains its exact private endpoint instance and nonwrapping
serial, authoritative typed output identity, full security number, bytes/wire
length and witness count. Repeated
preparation while pending returns that same token without rewriting caller
storage, selecting a new PN, charging again or canceling an already-owned output
when allow_data changes. The caller retains actual output/witness storage through
WouldBlock. `confirm_output` acknowledges complete carrier ownership, never mere
encoding/enqueue. Only that acknowledgment earns source repair credit/releases
actual scheduler output. Stale tokens cannot advance time or mutate ownership.
A complete observed handoff is counted once before propagating a subsequent
terminal clock/expiry failure. The caller must separately retain sealed encrypted
output and perform actual pacing/write/failure recovery; this API alone supplies
neither that runtime owner nor a cryptographic replay window.

`accept_authenticated` accepts only caller-authenticated/replay-checked complete
plaintext and verifies the declared actual source/repair/feedback kind through
the maintained wire codec. Scope mismatches and malformed bytes fail before
record/native delivery. Rolling Busy/Capacity returns unchanged caller-owned
input for explicit retry. Data and feedback are separate authoritative parsers.

`prepare_native(now, work, original_deadline, output)` reconstructs a real native
body into caller storage and retains one exact endpoint-instance/context/digest/
stream/serial/body NativeToken. AlreadyPending rewrites nothing and renews no
deadline. The retained expiry is the minimum of actual record first-arrival lifetime, first prepare
stall cap and supplied original cap. `commit_native` is a trusted complete
physical-write acknowledgment; encoding, receipt, extraction and enqueue cannot
invoke it. It counts that observed write exactly once even if later timing
validation fails. Stale tokens cannot alter time/custody. Common Bank integration
must add its own actual Bank/slot/generation wrapper. A checked nonwrapping
local atomic identifier distinguishes endpoint instances without entering the wire,
digest or nonce. Foreign endpoint output tokens are refused before time/custody
mutation in a passing regression. This local custody identity is not an
authenticated peer identity or a physical fence.

## Source-bound common-session integration gaps

These are remaining engineering dependencies, not new owner decisions.
`record_configuration::Profile` and its CompleteV2 canonical encoding currently
install Swift, Aligned and Packed, with no rolling descriptor. A rolling addition
must retain every `DirectionConfig` field, the independent outer overheads,
`native_stall_micros` and explicit stream binding, and preserve existing canonical
bytes/digests. Representation alone cannot install rolling in the catalog, Engine
or two-generation Bank; the encoding/version and migration contract still need
an explicit integration contract.

`Endpoint` already supplies actual borrowed Pipeline admission, output identity,
unit witnesses, authenticated-input parsing and retained native tokens. It does
not yet supply the common Engine's authoritative per-channel sent/prepared/
committed native-count and fence interface. Its aggregate `Statistics` cannot be
substituted for those per-channel proofs, and rolling source/repair IDs cannot
serve as native counts. Complete real backing Plan/Usage and retirement/error
accounting also remain prerequisites for a reserved mixed-Bank selection.

The current common Noise/member path hands `member::Parts` to
`transport::run_common`, whose contract/catalog and Bank select the existing three
record families. It must explicitly authenticate the complete rolling binding,
service its actual feedback/debt/retained output through the same selected carrier,
and route native completion to the issuing generation. No new authentication,
transport or transaction state machine is supplied by this pure endpoint. Shared
service/CLI/GUI selection and requested/effective capabilities remain part of
CRL-04; no automatic mode or default change is implied.

## Required scope that remains open

The legacy runtime remains FrameCodec/LX over rolling and keeps its actual
support128 guard. This module is a new real pure composition, not a selected
same-UDP carrier, local service API profile, GUI, native device or successful
switch. Full8192 deployment, local128/global8192/every16 geometry/retained debt,
complete authenticated control/rekey/recovery and original80 Mbit/s workload
still require their original gates. The separate Aligned early-short path does
not change this ordered rolling scheduler.
This first composition hands rolling sources upward in source order, so it does
not bypass an earlier missing rolling source for independent short records.
That remains a required explicit follow-on, with its deduplication/native fences.

Existing packed_sender emits one physical copy per packed source. Selected
context/independent-short three-copy scope, repair-padding trimming, compact
Python source/repair identity overhead, ACK coalescing/policy, cross-frame variants,
independent global/per-channel release and the full reference high-performance
profile are not silently defaulted or marked complete. Required fixed-total and
per-flow windows, actual Active/native delivery/proxy owners, every legacy FEC,
sliding/hybrid/elastic/rank-feedback family and all15 causal research parity
families remain in their existing scope. No new parity enum substitutes for
those algorithms. Header compression fallback remains the maintained codec's
actual behavior. Kernel/ISP classification and performance require controlled
runtime evidence, not these finite pure exchanges.

## Stable acceptance

- [x] [CRL-01] Implement actual independent compact-record and causal rolling owners with complete directional fields, exact stream binding, borrowed common admission and authoritative wire/identity checks; compile and source-review the actual path. Evidence: [affected build/Clippy pass](../../work/parallel-features-20261115/carrier-pure-attempt-1/validation.json), [split four rolling passes; failed aggregate](../../work/parallel-features-20261115/pure-attempt-1/validation.json), [named pure checkpoint and exact reuse](../../work/parallel-features-20261115/pure-scoped-checkpoint-validation.json).
- [ ] [CRL-02] Exercise independent paired actual-byte recovery with both source wire versions, TAP/TUN interpretations, unequal directional policies, real systematic/repair/feedback loss, arbitrary meaningful zero tails and complete native reconstruction; no sender payload ledger oracle.
- [ ] [CRL-03] Verify exact wire debit/full-width security PN, retained caller output/WouldBlock, insufficient space/budget/Busy retry, actual reserved Pipeline custody and original native expiry/physical-observation ordering with stale-token refusal.
- [ ] [CRL-04] Integrate complete common configuration/catalog/Bank ownership and same-carrier runtime/control/service selection with real per-profile native/send fences, retained sealed output and authenticated negotiated switching; preserve full SW-11 and API/CLI gates.
- [ ] [CRL-05] Complete independent-short gap bypass, configured copy scope/ACK policy/repair trimming/reference packing and complete P-local-global-rlnc/P-compact-wire/P-packed-wire/P-independent-short-records/P-unified-duplex-mux definitions; preserve all other P-* families.
- [ ] [CRL-06] Qualify complete real resource admission/failure/drop/retirement, full reference8192 geometry, original native/platform/carrier matrices and actual80 Mbit/s performance with controlled evidence. No local pure test, compile or scalar bound completes this gate.

Recorded verification on 2026-11-15 is finite and source-bound:

| Exact `rolling_records::tests` case | Passed scope |
| --- | --- |
| `actual_compact_rolling_recovers_both_directions_with_loss_and_original_zero_tails` | Paired real-byte recovery for padded/exact source wire and Ethernet/raw-IP interpretations, unequal directions, dropped systematic and feedback packets, actual repair use and exact original zero tails. Repairs are not deliberately dropped in this case. |
| `exact_output_budget_retry_retains_real_owner_and_full_security_number` | One-short wire budget and exact retry, full u64 security number, unchanged pending output across data-disable/retry, foreign/stale/repeated-token refusal and one actual carrier-handoff observation. |
| `complete_policy_and_stream_binding_preserve_independent_fields_and_width_limits` | Actual digest changes for selected independent policy fields/stream and refusal of invalid packing/channel geometry. This is not an exhaustive field-mutation matrix. |
| `actual_reserved_pipeline_handoff_retains_busy_head_and_original_native_expiry` | Actual reserved Pipeline admission with unchanged Busy head/capacity, feedback while reverse data is disabled, exact recovered original and retained native expiry with one physical-write acknowledgment supplied by the pure test. No device write is performed. |

The [first affected receipt](../../work/parallel-features-20261115/pure-attempt-1/validation.json)
records each of these four exact filters selecting and passing one test. Its
whole-batch status remains **failed**: strict Clippy rejected an unrelated Bank
test's explicit non-Drop guard drop, and two old Aligned filter paths selected
zero tests. Those are preserved failures, not rolling test failures or zero-test
passes. The
[later affected receipt](../../work/parallel-features-20261115/carrier-pure-attempt-1/validation.json)
records the repaired Bank test and corrected Aligned filters passing, alongside
affected library builds, strict Clippy and format checks. The rolling source and
its tests match both receipts' recorded input hashes; their four passing results
are reused rather than rerun. The first receipt also records successful affected
rustdoc generation. Commands, exact filters, binary/input hashes and logs remain
in those receipts; no receipt is rewritten or promoted to a full workspace check.

The [named pure checkpoint](../../work/parallel-features-20261115/pure-scoped-checkpoint-validation.json)
consolidates these four cases within 49 distinct saved pure passes. All five
rolling files and the actual packed/record-receiver/rolling-FEC dependency inputs
remain unchanged from their passing source-bound execution. New Swift feedback
and read-only Reliable/Aligned feedback-deadline APIs do not alter this path.
All 30 named pure inputs match the strict-check snapshots. The
[five-package strict receipt](../../work/parallel-features-20261115/pure-checkpoint-checks-attempt-1/validation.json)
passes format checking, strict all-target/all-feature Clippy and rustdoc in
25.255 seconds. No functional tests were added or rerun for this checkpoint.
Common State/runtime/service results and the separately committed OpenVPN carrier
checkpoint supply no selected rolling-mode or native completion claim here.

CRL-01 is complete for this pure implemented scope. CRL-02 retains its complete
repair-loss acceptance requirement; the passing case above does not exercise
lost repairs. CRL-03 retains all its output/witness-space, budget, Busy, native
custody and retry definitions; four passing finite cases do not supply every
promised refusal path. Those leaves and CRL-04..06 remain open. In particular,
there is no selected rolling common-Noise/runtime/service/native-device,
Windows/Android, reference8192, performance or ISP-QoS evidence from these checks,
and no simulator workload was rerun.

The [original authored source binding](../../work/parallel-rolling-20261115/authored-source-v0.json)
records the pre-validation authored bytes, before root's reviewed local-instance
custody and digest-field corrections; it is not the final validation receipt.
The source-hashed executed receipts above are authoritative for their checked
versions. This documentation reconciliation ran no tests, builds, formatting,
native or performance workloads. Master checklist/status integration remains
root-owned; the full `python3 tools/check.py` requirement and all parent gates
retain their original definitions.
