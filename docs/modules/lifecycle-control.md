# Explicit four-stream Lifecycle control

Status: **implemented and focused protocol-tested**, 2026-11-15. All six new
cases and the selected directly affected v1 cases pass; [strict affected checks](../../work/parallel-features-20261115/parallel-wave3-strict-attempt-2/validation.json) passed. This is a
control-custody prerequisite for [session refresh](session-refresh.md), not an
enabled runtime fresh-DH path or retained-state recovery. All SREF-01..SREF-08
definitions and parent gates remain open and unchanged.

## Explicit version and grammar

[L2CF v1](../../crates/l2tunnel-management/src/control_streams.rs) retains its
version1 bytes, three-entry `Stream::ALL`, `3 * base + stream` mapping and legacy
selection. Its encoder, decoder, context derivation and admission gates reject
the shared enum's v2-only `Lifecycle` value before indexing a selected owner.
There is no input-driven upgrade or conversion of a live session.

The new [v2 codec](../../crates/l2tunnel-management/src/control_streams/v2.rs)
requires an explicitly authenticated version2 selection, complete stream set,
context map and resource settings. Its eight-byte header is
`L2CF | version2 | stream | reserved00`, followed by one unchanged reliable
control packet. IDs are Transaction1, Liveness2, DataFeedback3 and Lifecycle4.
The checked map is `4 * base + stream`, refusing zero/overflow. The authenticated
version is part of the namespace contract; the derived scalar is not claimed to
be globally disjoint from every possible v1 scalar. Recreating active contexts
with reset source IDs remains forbidden.

Lifecycle uses the existing L2SC binding parser with the distinct
`ProfileTag::SessionRefreshV1` value2. Its typed payload prefix is
`L2RL | version1 | kind | reserved00`, followed by nonempty original bytes.
Kinds are Request1, NoiseFlight2 and Activation3. Unknown kinds, versions,
reserved bytes, empty bodies and oversized output fail explicitly. This parser
does not verify a Noise flight, authenticate a nested request or mint admission.

SwiftPolicyV1 tag1 retains its exact43-byte maximum. Lifecycle has a separate
maximum65452-byte typed payload, including its eight-byte prefix, so the complete
`L2SC80 + profile-tag4 + typed-prefix8 + original-material` envelope remains at
most65536 bytes. Existing message/fragment/replay bounds are not reduced.
The selected [stream gate](../../crates/l2tunnel-management/src/control_streams/gate.rs)
admits Lifecycle only under the exact fixed Control scope, full authenticated
session/role/physical lane and its own nonwrapping consecutive sequence. Data
scope changes confer no Lifecycle authority. Legacy/v1 gates reject this tag,
and substitution into Transaction, Liveness or DataFeedback fails without an
admitted sequence.

## Actual shared owner and storage

[SettingsV2](../../crates/l2tunnel-runtime/src/secure_udp/control_v2.rs) carries
four complete message settings. Its checked message plans and the
[wrapper plan](../../crates/l2tunnel-runtime/src/secure_udp/control_wrapper_storage.rs)
are distinct: full message capacities include each actual ARQ/reassembly pool
once; wrapper capacity includes the retained Streamed cell, actual owner headers,
outgoing metadata and envelope/raw scratch. V1 retains three actual inline
owners. Only v2 reserves a four-header Vec and constructs all four complete
reserved message owners. The enum's physical inline padding is also included
in the actual Streamed cell. No dummy owner, fallback or engine-only resource
claim substitutes for these charges.

The new constructor and `message_storage_usage_v2` report the real selected
four-owner inventory. The old three-owner observation does not silently truncate
v2. All constructor limits are checked; a too-small fourth message limit refuses
before wrapper provisioning. Dependency-internal allocator-failure coverage is
not inferred from that preflight or from local failpoints.

The existing [Control Owner](../../crates/l2tunnel-runtime/src/secure_udp/control.rs)
and [leased bridge](../../crates/l2tunnel-runtime/src/secure_udp/control_leased.rs)
remain the only message/transaction machinery. All selected streams share the
original global packet/byte/refill quota, round-robin service and caller wire
allowance. Stream delivery overhead includes the same eight-byte wrapper once;
the stream count does not multiply the global budget or create another crypto
owner. The Transaction binding follows the selected map into the actual leased
Peer and its existing final-reply custody.

`submit_lifecycle` retains one immutable typed envelope with the original cap,
session expiry and message lifetime minimum. Ordinary semantic `accepted` marks
dispatch once and retains receipt admission under pressure; source ACK alone is
not whole-message acceptance/confirmation. Lifecycle has no automatic retirement
and cannot be presented through the leased Peer acceptance callback. The real
Records owner remains responsible for any refresh admission and key effects.

## Finite protocol evidence

The [source-stable case receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json)
records all six cases below individually `passed`, with valid exact selection
and unchanged test binaries. It also records passes for the selected existing v1
codec/gate/profile-wire, wrapper refusal/drop/transfer/reuse, leased preview and
held/saturated-Transaction Liveness cases.

The enclosing receipt remains **FAILED: 51/55 passed**, with four failures in
other feature lanes. Individual C passes do not relabel that result. The
[first build failure](../../work/parallel-features-20261115/parallel-wave3-build-attempt-1/validation.json)
is also retained; its selected-owner iteration fix precedes the passing case
binaries. No full workspace, native or platform pass is inferred. The [strict affected checks](../../work/parallel-features-20261115/parallel-wave3-strict-attempt-2/validation.json) passed; no full-stage acceptance is inferred.

| Source | Exact cases and intended distinction |
| --- | --- |
| [Pure v2 tests](../../crates/l2tunnel-management/src/control_streams/v2/tests.rs) | `explicit_versions_keep_v1_bytes_and_reject_cross_version_or_unselected_lifecycle`: exact headers, retained v1 bytes, strict version/context bounds and no unselected Lifecycle. |
| Same source | `lifecycle_full_bound_is_distinct_from_unchanged_swift43_and_parser_grants_no_authority`: exact65536 envelope, independent Swift43 limit and atomic malformed/output refusal. |
| Same source | `lifecycle_gate_is_v2_fixed_control_bound_and_independent_of_transaction_scopes`: full ingress checks, cross-stream/scope refusal, independent Liveness and continued Lifecycle sequence through a data-scope retirement. |
| [Runtime owner tests](../../crates/l2tunnel-runtime/src/secure_udp/control_v2_tests.rs) | `four_actual_reserved_owners_charge_exact_plans_and_v1_rejects_without_upgrade`: real four-owner usage, wrapper accounting and fourth-limit preflight. |
| Same source | `fragmented_lifecycle_and_sixteen_confirmed_pings_progress_while_real_transaction_is_held`: actual leased Peers and complete message owners, fragmented Lifecycle held independently of a real held PREPARE,16 accepted/confirmed/retired Ping/Pong pairs, shared wire quota, then real Lifecycle acceptance/confirmation and retained Transaction custody completion. |
| Same source | `lifecycle_original_message_cap_is_not_renewed_by_independent_liveness`: original sender cap, separately retained receiver deadline, independent Ping/Pong and expiry refusal without envelope-ID reuse. |

The Owner fixture supplies authenticated ingress at the same trusted boundary as
the existing leased tests. It is protocol composition evidence, not a new socket,
crypto, native-device or runtime fresh-DH qualification. Directly affected old
v1 wire, gate, wrapper drop/transfer/reuse and leased preview/pressure assertions
pass in that finite selection; private four-slot fixture shape changes do not waive
their original checks or replace broader qualification.

## Acceptance ledger

- [x] [LFC-01] Validate exact explicit v2 framing/context bounds and v1 no-upgrade/byte compatibility with the authored strict codec cases. Evidence: the new explicit-version case and selected old codec cases in the linked receipt. [Exact case receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).
- [x] [LFC-02] Validate typed Lifecycle limits, unchanged Swift43, fixed Control scope, full ingress binding, cross-stream refusal and independent sequence state. Evidence: the two new pure Lifecycle cases and selected old gate/profile-wire cases in the linked receipt. [Exact case receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).
- [x] [LFC-03] Validate actual four-owner reserved construction and observed full-message/wrapper capacity, with no allocating fallback or truncated v1 observation. Evidence: the new four-owner case in the linked receipt. [Exact case receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).
- [x] [LFC-04] Validate independent fragmented Lifecycle and whole-confirmed Liveness while a real leased transaction is held, under the original shared quota and custody rules. Evidence: the new fragmented-Lifecycle/16-pair case in the linked receipt. [Exact case receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).
- [x] [LFC-05] Validate immutable original caps, separate receive expiry, semantic acceptance/confirmation, once-only presentation and directly affected v1 failure/drop/reuse paths. Evidence: the new cap and fragmented-Lifecycle cases plus selected old wrapper/leased-pressure cases in the linked receipt. [Exact case receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).
- [x] [LFC-06] Record source-stable combined execution and strict checks, retaining failures and exact scope before checkpoint qualification. Evidence: [scoped final validation and strict checks](../../work/parallel-features-20261115/parallel-wave3-scoped-validation.json).
- [ ] [LFC-07] Consume the authenticated v2 contract in the actual sole runtime owner and integrate actual Records/Noise refresh authority, original key/operation caps, overlap, native/data/control/transaction-debt retention and fault cases before claiming runtime Lifecycle/fresh-DH support. This prerequisite does not replace or narrow SREF-05..SREF-08 or retained recovery.
