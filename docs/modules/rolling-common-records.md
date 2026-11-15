# Rolling as an actual common record family

Status: **implemented and finitely protocol-tested: two real Engine cases, one
real Bank carrier-token case, tag4 negatives and legacy vectors passed**. The
tag4 literal fixture was corrected and its exact rerun passed. Six-package strict
formatting, Clippy and rustdoc passed. The
[named rolling receipt](../../work/parallel-features-20261115/parallel-wave2-rolling-scoped-validation.json)
consolidates seven positive cases without relabeling the failed enclosing batch.
Earlier standalone rolling tests and the pure checkpoint remain historical
evidence for their recorded inputs, not these new changes. The
[pre-edit binding](../../work/rolling-common-records-20261115/pre-edit-binding-v0.json)
records engineering baseline `62d195f` and the frozen interface, not an owner
scope decision. All [CRL deliverables](rolling-records.md), full SW-11, every
P-* definition and native/resource/platform/performance parents remain required.

## Complete canonical configuration

`Profile::Rolling { config, stream }` selects the actual rolling-record owner;
it is not Packed with a new label. Tag4 explicitly extends the existing L2RC v2
grammar. Descriptor1272/Configuration1304 bytes, old tags1..3, their bytes and
padding, v2 config/catalog domains and legacy Swift v1 vectors remain unchanged.
Earlier readers reject tag4; no fallback, default or automatic upgrade exists.

Each356-byte profile slot contains44 big-endian u64 words and four zero bytes.
Words0..40 preserve all directional fields: native policy; body geometry/options/
short threshold; receiver channel/IDs/window/lookahead/fragment/lifetime bounds;
packing geometry/hold/units/first-unit/work; codec stage age; all eleven rolling
recovery fields; and all seven scheduler fields including source wire version.
Sender body/channels/first-record are validated exact aliases of receiver fields,
never defaults copied across directions. Words41..43 bind directional overhead,
shared native stall microseconds and stream (checked to fit u32). Both slots must
agree on stall/stream. Exact length, bool words, enum tags, integer conversions,
inactive padding and canonical re-encoding are checked before publication.

The existing complete digest/catalog binds those exact bytes when the actual
session/management owner authenticates it. `DirectionProfile::Rolling` exposes
the actual borrowed DirectionConfig and overhead/stall/stream. Channel widths
remain1..255; Swift64 and Aligned256 remain independent. Engine construction
requires external geometry/native stall to equal these bound fields. Policy
representation installs no Active/native-window/proxy capability.

## Actual work, output and native custody

One shared Pipeline feeds one actual rolling Endpoint through maintained
classification/DRR/MUX and borrowed admission. `ProfileIdentity::Rolling` retains
the real body identity. Existing checked per-channel native event observations
include this family; source/repair/feedback/security/native spaces stay distinct.
`Engine::step(now, rolling::WorkBudget)` explicitly services actual computation.
Tick/poll introduce zero GF budget; `wake_at()` exposes packing/tail/feedback
triggers as well as original hard expiry. Full output bounds include actual data
and feedback sizes, overhead once, MTU and burst admission.

`pending_carrier_output()` returns a move-only `CarrierOutputToken` with the
actual private Endpoint prepared token and Engine context/digest. Getters borrow
`&self`; it is not Clone/Copy, authentication or physical proof. Poll never
confirms it. Repeated pending poll retains original PN, bytes/witness ownership,
charge and emission count without rewriting caller storage. The caller retains
that storage through WouldBlock. `confirm_carrier_output` requires observed whole
carrier ownership, checks the exact issuing token before time mutation and records
it once even if later timing validation fails. The other three families expose
no new pending token or emission behavior.

Native preparation retains the actual rolling NativeToken beneath the Engine
token and writes into caller storage. Enqueue/publication cannot commit it;
trusted whole native write routes to that issuing owner. Original record/stall/
external minimum caps never renew. Late physical facts are counted once without
claiming clean delivery/drain after expiry. Root's Bank wrapper adds its exact
GenerationId to native and carrier tokens. Neither publication nor local counts
manufacture authenticated retirement/fence authority.

## Complete actual backing

`rolling_records::storage::{Plan, Limits, Usage}` is heap-only; Engine/Bank layout
counts Endpoint inline headers once. `Plan::for_endpoint` validates both policies,
all constructor-time deadline additions, real reserved codec plans, actual rolling
scheduler plans and source/symbol scratch layouts before allocation. Complete
limit admission precedes construction. `Endpoint::new_reserved` constructs those
same actual owners fallibly and verifies actual codec/scheduler/scratch capacities
against the admitted plan. Usage sums actual retained layouts/reservations once.
Functional construction stays explicit and reports no complete reserved Usage.

The [nested FEC receipt](../../work/rolling-storage-20261115/affected-attempt-1/validation.json)
qualifies its exact scheduler scope only, not this parent Endpoint/Engine.
Conservative memory caps remain scalar guards, never substituted for observed
Usage. Allocator metadata, RSS, kernel memory, literal nested failure/drop peaks
and complete external ownership retain their separate acceptance requirements.

## Stable acceptance

- [x] [RCE-01] Pass literal complete tag4 directional vectors and strict parser/alias/shared-binding limits while retaining all existing Swift/Aligned/Packed v2 and Swift v1 byte/digest tests. Evidence: [exact repaired literal](../../work/parallel-features-20261115/parallel-wave2-literal-repair-attempt-1/validation.json), [named positive cases and strict checks](../../work/parallel-features-20261115/parallel-wave2-rolling-scoped-validation.json).
- [ ] [RCE-02] Pass paired actual functional/reserved rolling Engines with complete bytes in both asymmetric directions, TAP/TUN interpretation, both source wire versions, real recovery/feedback loss, original zero tails, explicit work, retained output, foreign/stale tokens and physical native acknowledgment.
- [ ] [RCE-03] Pass actual Endpoint/Engine Plan-versus-Usage and exact/one-short limits with real nested owners; preserve complete allocator/failure/drop/retirement and shared-resource parent acceptance rather than inferring it from one observation.
- [ ] [RCE-04] Install the fourth actual family in selected Common runtime/control/service/CLI through the same authenticated carrier/FSM, with explicit rolling work, post-carrier ownership acknowledgment, generation-specific native custody and genuine full drain/fences. Pure config/Engine/Bank availability is not this installation.
- [ ] [RCE-05] Complete original CRL-02..06 and relevant P-* definitions, configured-P custody, ordered-rolling independent-short bypass, repair-loss/copy/ACK/trim/reference8192 matrices and native/platform/80 Mbit/s qualification without shrinking any definition.

## Recorded finite execution

The [combined exact-case receipt](../../work/parallel-features-20261115/parallel-wave2-cases-attempt-1/validation.json)
remains **failed:26 passed of27**. Only its individually selected positive cases
are reused here:

- `record_engine::rolling_tests::actual_fourth_family_uses_reserved_owners_recovers_bytes_and_routes_typed_custody` passed actual reserved paired Engines in both directions, TAP/TUN interpretation and padded/exact source wire, with dropped systematic/feedback records, real repair use, exact zero tails, original native custody and stable Usage.
- `record_engine::rolling_tests::actual_rolling_plan_limits_aliases_foreign_tokens_and_functional_emissions_are_exact` passed actual one-short admission, functional/reserved emission-byte/identity/budget equality, foreign carrier-token refusal before time mutation and exact geometry refusal.
- `record_bank::carrier_tests::actual_rolling_carrier_tokens_bind_bank_before_time_and_never_ack_on_poll` passed real fourth-family Bank ownership and generation-bound carrier tokens; poll did not acknowledge output.
- `record_configuration::rolling_tests::tag4_padding_shared_bindings_narrow_fields_and_aliases_refuse_without_output_mutation` passed strict padding/shared-binding/narrow-field/alias negatives. Existing Swift v1 and Swift/Aligned/Packed v2 literal bytes/digests also passed their two exact legacy cases.

`tag4_preserves_fixed_v2_shape_and_literal_complete_directional_words` failed:
the expected reverse word17 retained forward192 while the real fixture and
encoder correctly used reverse packing symbol224. Only its explicit reverse
literal override was repaired to224; no production value or assertion weakened.
Its [exact rerun](../../work/parallel-features-20261115/parallel-wave2-literal-repair-attempt-1/validation.json)
then passed, including a 5.62-second incremental build; no other functional case
was repeated. [Strict six-package checks](../../work/parallel-features-20261115/parallel-wave2-strict-attempt-1/validation.json)
passed in 137.324 seconds. RCE-02..05 and their full definitions remain open;
the existing finite results are partial evidence for those complete matrices.
No receipt is relabeled as an aggregate pass. These pure exchanges simulate
trusted whole carrier/native acknowledgments; they perform no physical device
write or selected rolling runtime installation.

The subsequent [selected Common rolling runtime](common-rolling-runtime.md)
implements explicit bounded work and post-carrier confirmation, with finite
original-UDP/Unix packet-device cases and strict affected checks passed. A catalog without explicit admitted work still refuses
rolling. This authoring checkpoint does not close RCE-04. Kernel TAP/TUN, namespace/device,
standard dissector, Windows/Android, performance and ISP/QoS are outside this pure
slice. This author executed no Cargo/tests/format/check or workloads and changed
no historical receipt.
