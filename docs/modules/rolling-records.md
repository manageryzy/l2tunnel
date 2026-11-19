# Compact records over actual rolling recovery

Selected compact v3 now uses this module through the existing runtime owners.
See [runtime algorithm migration](compact-wire-cleanup.md#runtime-algorithm-migration)
for the selected wire representation, exact-cost boundaries and validation scope.
Legacy constructors and historical receipts below retain their original meaning.

Status: **implemented pure composition; four focused protocol tests and named
pure checkpoint checks passed on their recorded inputs**. The subsequent
[actual common-family configuration/Engine/storage slice](rolling-common-records.md)
has two real Engine cases, a real Bank carrier-token case, tag4 negatives and
legacy vectors passing in the [failed26/27 combined receipt](../../work/parallel-features-20261115/parallel-wave2-cases-attempt-1/validation.json).
Its repaired tag4 literal fixture and six-package strict checks subsequently
[passed in their named scopes](../../work/parallel-features-20261115/parallel-wave2-rolling-scoped-validation.json);
these are not selected-runtime evidence.
The saved Linux checks establish actual byte/identity/custody behavior below, not
a selected runtime or a physical native-device path.
This additive lane addresses the missing compact-record-to-rolling composition in
[FIX-02](../implementation-checklist.md). It does not complete that item, any
P-* family, full SW-11, full resources, selected runtime/service/CLI integration,
native qualification or the 80 Mbit/s target. The original definitions remain.

The Wave7 additive committed-source view and bounded independent-short preview
are implemented and protocol-tested within CRL-07's finite scope below. The
[committed-source case](../../work/parallel-features-20261115/parallel-wave7-final-build-cases-attempt-1/validation.json),
[three final Endpoint cases](../../work/parallel-features-20261115/parallel-wave7-report-correction-attempt-1/validation.json)
and [affected strict checks](../../work/parallel-features-20261115/parallel-wave7-strict-attempt-2/validation.json)
passed. This does not qualify the full Rolling/native/resource or Python-family
gates.

Read the [architecture](../architecture.md), [plan](../implementation-plan.md),
[checklist](../implementation-checklist.md), [complete parity matrix](../mode-parity.md),
[actual rolling scheduler](local-global-rlnc.md), [legacy rolling runtime](rolling-runtime.md),
[common Engine](common-record-engine.md), [record configuration](record-configuration.md)
and [common Engine backing](common-engine-storage.md) with this module.

A subsequent silent-tail correction reports `Step.native_progress` only when
bounded short preview has actually admitted native records. The existing Common
loop rearms native scanning on that event even when no further UDP packet arrives;
GF work alone does not advertise native output. The component event case passes
[Cases22](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-22/validation.json) and the real protected UDP/Unix silent-tail case passes
[Cases21](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-21/validation.json) with work1, a lost older source and exact-once native delivery.
This finite symbol256 case does not close full8192/native acceptance.

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
confer no authentication authority. Existing Swift/Mode, CompleteV2 tags1..3 and legacy rolling-session encodings
and digests remain unchanged. The subsequent common-family slice adds explicit
tag4 inside the existing CompleteV2 slot, binding all rolling fields and stream.
Full selected common-session/runtime installation remains separate from this
standalone API and the new pure configuration/Engine/Bank integration.

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

## Bounded independent-short preview (Wave7)

The actual decoder now exposes
`decoded_source(SourceId) -> Result<Option<&[u8]>, Error>`, forwarded by its
existing scheduler Receiver. It borrows exact bytes only when the live committed
identity bank contains that source at or beyond the upper handoff prefix.
Checked original length is required. A candidate or shadow GF recovery remains
invisible until the existing atomic publication; retired handoffs are not exposed.
The view changes no receipt, handoff, timer, native count or authentication state.

When `independent_short_frame_bytes` is nonzero, Endpoint scans committed future
sources through that view and the maintained packed-envelope parser. It rebuilds
units in the same preallocated symbol slab, applies the existing generic-size
`Receiver::is_independent_short` classifier and admits the selected symbols in
one existing atomic receiver batch. Context-dependent records remain owned by
the recovery path. No second payload queue, recovery algorithm or parser grammar
is introduced. Zero disables the preview scan and retains ordinary ordered
source handoff.

Preview source lookups and unit actions consume the receive step's remaining
metadata allowance; slab zeroing and copying consume its remaining copy
allowance. At most `packing.work_limit` preview state actions occur per call.
Partial unit preparation retains exact slice coordinates and the same slab,
so a work budget of one can progress without restarting its byte copy. The
reported `Step.receive.work` includes those new operations and the existing
decode/feedback work, within the supplied receive cap. Complete synchronous
packed parsing, bounded unit indexing and atomic record admission retain their
existing fixed packing-unit work domain; these counters do not measure every
parser instruction, CPU time or a physical service rate.

An inline deferred-rescan flag coalesces actual successful source/repair ingress,
new decoder publication and native progress. A new earlier committed source
therefore cannot be missed merely because the scan already passed it while a
later source's preview was being copied. The flag restarts the bounded scan only
at a preview boundary, preserving the partial slab. Completion does not create
another rescan event; no new ingress or progress means the scan can quiesce.

The ordered packed-unit cursor is separate from the receiver's admission floor.
Only successful ordinary source admission advances that cursor and confirms the
actual recovery handoff. A later ordered source may encounter already-previewed
units without replaying their native frames. Early physical completion retains
the existing tombstone; committing an older native frame advances its channel
once, and a subsequent bounded channel preparation retires the now-head
tombstone. Recovery handoff completion alone is not that native cursor service.
Pending native bytes/tokens remain immutable, and their original record,
first-prepare and external caps are not renewed by preview, duplicates or rescan.

Four focused protocol cases passed: decoder committed/shadow visibility using a real GF repair;
actual missing-source bypass, later deduplication and tombstone retirement with
work1 under both source formats/backing modes; retained native original expiry;
and source2 partial preview followed by newly available source1, requiring both
exact originals to release without further ingress. The getter case passed in the
[final build/case receipt](../../work/parallel-features-20261115/parallel-wave7-final-build-cases-attempt-1/validation.json)
and its FEC implementation was unchanged afterward. All three Endpoint cases
were rerun and passed after the equivalent Clippy boolean simplification in the
[report-correction receipt](../../work/parallel-features-20261115/parallel-wave7-report-correction-attempt-1/validation.json).
[Strict checks](../../work/parallel-features-20261115/parallel-wave7-strict-attempt-2/validation.json)
passed Clippy for all targets/features, formatting and rustdoc for FEC, facade
and client-core. These finite results supply no native-device, full8192,
platform, complete resource or full mode-parity evidence. Earlier failed
attempts remain historical failures; these receipts do not promote the pending
Common native runner or a wider aggregate to a pass.

## Source-bound common-session integration gaps

These are engineering dependencies, not new owner decisions. The subsequent
[common-family slice](rolling-common-records.md) implements CompleteV2 tag4 with
all directional fields, outer overheads, native stall and explicit stream, plus
actual Engine construction, complete heap-only Plan/Usage, per-channel event
observations and retained carrier/native tokens. Two actual Engine cases, one
Bank case, strict tag4 negatives and legacy byte/digest vectors passed in the
[failed26/27 aggregate](../../work/parallel-features-20261115/parallel-wave2-cases-attempt-1/validation.json).
The one literal failure was an omitted expected reverse packing-symbol word17
override192→224; that fixture-only correction passed its exact rerun, and
six-package strict checks passed in the
[named receipt](../../work/parallel-features-20261115/parallel-wave2-rolling-scoped-validation.json).
The original standalone aggregate Statistics never substitutes for
those per-channel observations or authenticated physical fences. Root's Bank
adds issuing-generation custody; this is not selected runtime installation.

The later [Common rolling runtime](common-rolling-runtime.md) installs the fourth
family through the existing Noise/member handoff and sole runtime loop. The
[Common original-carrier native leaf](common-carrier-cli-native.md) now adds four
finite production TAP/TUN cases with actual four-family switches. The pure
Engine/Bank receipts alone do not establish that integration. Complete acceptance
must still authenticate the rolling binding, service feedback/debt/retained
output through the selected carrier and route native completion to the issuing
generation across the full fault/resource matrix. No new authentication,
transport or transaction state machine is supplied by this pure endpoint. Shared
service/CLI/GUI selection and requested/effective capabilities remain part of
CRL-04; no automatic mode or default change is implied.

## Required scope that remains open

The legacy runtime remains FrameCodec/LX over rolling and keeps its actual
support128 guard. This module owns the pure composition; selected carrier/service and finite
native switching evidence is recorded in the later integration leaves above.
GUI, full8192 deployment, local128/global8192/every16 geometry/retained debt,
complete authenticated control/rekey/recovery and original80 Mbit/s workload
still require their original gates. Actual rolling source handoff remains ordered.
The Wave7 preview above adds independent-short record admission across a source
gap without fabricating ordered recovery or native completion. Its finite pure
acceptance does not complete the full independent-short/native-fence matrix.

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
- [x] [CRL-07] Validate the additive committed-source view and bounded independent-short preview with real GF shadow isolation, work1/zero-budget limits, both source formats/backing modes, actual gap bypass and ordered deduplication, bounded native tombstone retirement, original pending-native expiry and newly available earlier-source rescan while a later preview is retained; pass the affected strict checks. Evidence: [committed-source exact case](../../work/parallel-features-20261115/parallel-wave7-final-build-cases-attempt-1/validation.json), [three final Endpoint exact cases](../../work/parallel-features-20261115/parallel-wave7-report-correction-attempt-1/validation.json), [three-package strict Clippy/format/rustdoc](../../work/parallel-features-20261115/parallel-wave7-strict-attempt-2/validation.json). This finite pure leaf does not close CRL-05/06 or any complete parent gate.

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
consolidated these four cases within49 distinct saved pure passes at its recorded
freeze. The five rolling files and actual packed/record-receiver/rolling-FEC
inputs then matched their source-bound executions, as did all30 named pure
inputs and strict-check snapshots. The subsequent common-family changes are
new inputs and are not qualified by that historical hash comparison. The
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

## Early native TCP delivery on targeted TUN

The targeted native IP header sender periodically emits an ordinary full IP
context at a channel record serial divisible by eight. A context has its own
serial and consumes real packing, transmission and recovery credit. Subsequent
frames keep the existing header-delta grammar. A raw fallback at the boundary
leaves the previous context intact. The receiver can also read streams from
senders that refresh only when a header requires it.

For established TCP on TUN, the receiver can prepare a fully reassembled raw
or stateless LZ4 packet across a hole. For a header delta it needs a complete
explicit IP context and every intervening record through that delta. Preview
uses a separate bounded header checkpoint per channel. The canonical decoder
advances when the ordered record frontier catches up. A successful device write
commits that packet once. An incomplete write or a pending device operation
retains the original packet. TCP setup, close, uncertain flow identity and
ACKs covering a local FIN retain their ordering rules. The receiver continues
to request and recover missing outer sources while Linux processes out-of-order
TCP data and generates its own SACKs.

After a successful early write, targeted TUN can move the record into bounded
replay storage. It retains the exact encoded bytes, fragment map and deadline.
The ordinary lookahead record slot becomes available immediately. Both stores
still count against the existing byte and fragment limits. If the replay
store is full or the encoding exceeds its narrow slot width, the ordinary
slot retains custody. Ordinary Aligned and Packed owners keep their original
allocation policy. The runtime exports `receiver_compacted_replay_records`
alongside the ordinary lookahead occupancy.

The [single-flow experiment](frame-channel-experiment.md#early-ip-tcp-delivery-across-a-compression-gap)
records code coverage, observed native behavior and performance separately.
