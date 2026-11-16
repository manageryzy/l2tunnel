# Fixed-cohort independent Compact owners

Status: **implemented collection, tag8 Engine/Bank, Common runtime and shared
Prepared/service path with finite protocol/protected-I/O evidence**. No default
or named profile selection changes. Full PBA-03, drained/fenced flow reuse and
the complete raw-ACK pressure/retirement gate remain open.

The named `quic-overhead-1/2/3` reference constructs sixteen independent CompactTCP
objects, each with directional recovery and codec contexts, and shares physical
Links/events. The existing Rust Compact tags6/7 retain one shared duplex body
owner. A channel count alone does not change that topology.

## Selected-owner integration and finite evidence

The collection supplies explicit bounded source-free ACK send/receive/native
custody and immutable flow claims.
An optional per-direction policy provisions actual fixed slabs; the old omitted
policy continues to refuse raw admission. A complete277-byte directional codec
is used by the explicit CompleteV2 tag8 Engine/runtime selection.
Actual common Pipeline metadata now retains original received/admitted time and
an optional original cap; old APIs select equal times and no new cap. Engine
admission preserves this metadata and the earliest held ACK age.
These new bodies pass source-stable Build39 and six actual collection cases plus
five Pipeline handoff cases in [Cases25](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-25/validation.json).
The new raw ACK cases cover immutable flow claims, complete directional policy,
original caps, exact wire debit, Busy retention and physical retirement without
recovery debt. Those component passes alone do not prove the later installed
Engine/runtime/service composition. PCO-05/06 and full PBA-03 remain open.

The newly integrated explicit tag8 consumer selects that same collection behind
one actual Pipeline, preserves its original received/cap metadata, and dispatches
real physical/native custody tokens. Recovered and source-free native identities
remain distinct; source-free ACKs create no reliable native-prefix debt. Its
fixed-cohort capability explicitly reports `flow_reuse=false`, and passive
retirement cannot discard live claims. The actual Engine roundtrip passes in
[Cases29](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-29/validation.json),
including strict canonical tag8 decoding, independent-owner loss progress, raw
ACK physical/native custody and distinct reliable fences. The genuine shared
Prepared/service case passes in
[Cases30](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-30/validation.json):
real catalog-bound Noise/member setup, sixteen reserved owners, exact forward TCP
and learned reverse raw ACK bytes, actual status/Pong/original tuples and owned
disconnect/release. It does not exercise sixteen active service flows or switches.

The separate sixteen-flow protected UDP pressure case passes in
[Cases31](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-31/validation.json)
after the fixture services at most the actual receive width at the same timestamp.
It retains the actual owner1 native token and its original cap without performing
a native write. It preserves queue-full/replay/expiry and separate reliable
retirement assertions. The source fix for sealed runtime output uses the existing
hard expiry deadline, rather than a different owner's soft retry/feedback wake.
PCO-05/06 remain open for their full reuse/drain compositions; finite pressure and
service passes do not establish the entire named profile. Earlier failed
aggregates remain preserved with their original status.

## First deliverable and ownership

New pure facade module `connection_records` owns a bounded fixed cohort of actual
reserved `aligned::Endpoint` Compact owners. It supplies no classifier, Pipeline,
cryptography, socket, clock, task or congestion controller. The Engine selects it
through one actual shared Pipeline and the existing single authenticated
User/carrier path. Existing constructors, old tags and defaults remain unchanged.
The finite tag8 runtime/service evidence above does not qualify the complete
named Python profile.

`Config { owners, incarnation, send, receive, send_carrier_overhead_bytes,
receive_carrier_overhead_bytes, send_unreliable, receive_unreliable }` requires owners1..=256, a positive
incarnation, actual single-channel directional Compact configs and copy count1.
The same directional config is instantiated independently for every owner; source,
feedback, retry, RTT, codec and native state are not shared between them. A fixed
cohort has no eviction, rebinding or reuse method. Engine integration binds actual
flow claims and learned reverse affinity to authenticated decoded native channels
and refuses conflicts before publication. Complete authenticated drained/fenced
reuse remains required; an owner index alone grants no such authority.

## Exact route v1

The route header is24 bytes: magic `L2PC` (4), version1 (1), class (1), owner u16
(2), incarnation u64 (8), unreliable-native serial u64 (8), in network byte order.
Classes are recovered source1, recovered feedback2 and unreliable native3.
Recovered records require serial0; unreliable native requires a positive serial.
The complete route and payload must be authenticated/replay-checked by the caller
before admission. A structural parser grants no authentication or management
authority. Unreliable native is a distinct typed grammar branch with actual
bounded ACK custody only when explicitly selected; None refuses admission. It
cannot silently enter recovery or be counted as reliable peer confirmation.

Each Compact direction's explicit external overhead must equal its separately
declared carrier overhead plus24 checked route bytes; the collection validates
that equality and adds no hidden rebase. Actual endpoint
wire budgets therefore charge route bytes exactly once. Parser/output capacity,
index/incarnation, actual source/feedback kind and caller output geometry are
checked before downstream emission/admission. Repeated polling of a held output
does not rewrite bytes, allocate, reseal or debit again.

## Public implementation surface

`storage::Plan::for_collection(Config)` validates pure geometry and every actual
nested CompactPlan. `Collection::new_reserved(plan, RecoveryContext, Limits)`
fallibly reserves the fixed Slot vector and constructs every actual endpoint.
The plan counts `size_of::<Collection>()` once, actual Slot capacity (including
each inline Endpoint/native witness) once, and each endpoint's managed heap once.
Actual capacities/allocation counts must match before publication. Caller buffers,
Pipeline/security/carrier owners and their heaps are external to this subtotal.
When embedding the collection inline in a larger owner, its parent must count only
this Plan's heap subtotal in addition to that larger owner's actual fixed layout.

`owner(index)` yields a checked `OwnerId`. `enqueue(owner, now, bytes)` accepts
only already-admitted common-Pipeline bytes and returns owner/incarnation plus the
real local-channel0 `RecordIdentity`. `poll_data` and `poll_feedback` use the
maintained independent lanes and return move-only `PreparedOutput` witnesses that
contain the actual nested token. They write route plus actual maintained recovery
bytes into caller storage. `pending_*_output` only observes custody.
`confirm_output_at(observed, accepted, token)` forwards the physical receipt once,
preserving actual acceptance and observation times and actual late failure facts.

`accept_authenticated_at(received, observed, bytes)` checks strict route and actual
maintained inner classification before forwarding to the same endpoint, preserving
retryable pressure and the original arrival time. `prepare_native` performs caller
bounded work for one selected owner; `pending_native` borrows its actual immutable
bytes and a collection/owner/incarnation-bound token. `commit_native` consumes that
token only after the caller's whole native write. Existing endpoint deadlines and
errors remain authoritative; no additional timer renews them. Aggregate deadline,
hard expiry, drained and actual storage observations inspect the finite cohort.
There is no second scheduling or recovery state machine.

The first collection installs only ordinary Compact Aligned endpoints. Complete
Packed/other-family connection-owner installation remains required where selected;
there is no unused Packed engine or fabricated legacy/FEC configuration. The
facade exports the actual module. No Cargo dependency changes are needed.
The executed component tests assume the caller
authenticated complete route/body bytes and inject physical receipts; they do not
provide a real TLS/Noise/member/carrier/native-device integration receipt.

A matching native completion failure is retained per owner: once the caller has
reported the physical native write, a backward-time or downstream completion
error cannot expose the same body for another write or report false drain.
Foreign/mismatched witnesses leave the real pending output intact.

Four cases in [Cases21](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-21/validation.json) pass strict routing, actual16-owner construction,
independent progress under source/feedback loss, exact storage/wire debit,
physical acceptance before observation, foreign/duplicate token refusal, final
drain and the native-completion failure latch. These are injected-I/O protocol
checks, not sixteen-flow client/native or performance qualification.

## Staged original-operation reuse prerequisite

A private, uninstalled extension stages bounded retirement of an actual claimed
owner. It preserves that same reserved Compact endpoint and all codec/recovery,
source, native and raw-event counters. Only the per-slot route incarnation advances
by a checked increment. This is a monotonic reuse extension beyond the fixed16
experiment, not a fresh-state Python parity claim. Canonical tag8/default bytes
and the installed public capability remain unchanged; flow_reuse stays false.

The scope constructor accepts a real retained transaction Operation and checks
session, role, origin epoch/configuration digest, operation attempt/target and
logical endpoints/lane. It retains the original local expiry. Opposite endpoints
do not compare unrelated local absolute clocks. A private scope or parsed data
route does not authenticate the peer: actual selected reliable-control ingress,
replay checks and final confirmation remain required before exposing this path.

Beginning retirement closes new local offers while existing old-incarnation
source, feedback, raw and native custody remains serviceable. A local fence is
available only after actual owner drain. It carries actual native-body admissions
and whole-native writes, with crossed peer totals; source IDs and source-free ACKs
are never substituted for reliable native counts. Installation requires a matching
peer fence and another drain check, clears the old claim and advances incarnation,
but keeps admission closed until matching peer installation confirmation. Old
route packets and stale/foreign native or carrier witnesses then refuse. Expired
or conflicting operations stay closed and cannot reset/reopen the endpoint.

The private Engine hook preflights the actual Pipeline registration and internal
queue/native/carrier custody, retires that same binding and passive ACK history,
then installs the already-preflighted collection transition. Runtime still must
stop new admission, prove external held/deferred/carrier/native custody absent,
and transport the exact scoped fences/installation confirmations under the sole
selected authenticated management owner. No public installed/runtime authority
or reuse capability is supplied by this prerequisite.

The existing size_of-based Plans charge the original RecoveryContext once and
all additional inline Slot state/counts through the actual Slot vector. No queue,
map, replacement endpoint, heap reservation, clock, crypto or timer is added.
Two focused real-owner regressions pass in the
[Batch14 receipt](../../work/parallel-features-20261115/parallel-batch14-scoped-validation.json).
The original [source binding](../../work/parallel-features-20261115/per-connection-reuse-v0/handoff.json)
and failed drain-fixture attempt remain preserved. The fixture now services all
three original feedback repetitions before fencing; no deadline was enlarged.
They cover actual old native/recovery/feedback drain and independent other-owner
progress before new bytes on the same monotonic owner, plus held/lost raw ACK
custody, original caps, conflicts, foreign/stale tokens and fail-closed activation.

- [x] [PCOR-01] Pass actual same-owner drain/crossed native fences, independent other-owner progress and monotonic new-flow bytes under a checked next incarnation; no endpoint/counter reset or additional allocation. Evidence: [Batch14](../../work/parallel-features-20261115/parallel-batch14-scoped-validation.json).
- [x] [PCOR-02] Pass held raw/native/carrier custody, foreign/conflicting/stale operation/token refusal, original expiry, closed-until-peer-confirmed activation and exact actual Plan/Usage accounting. Evidence: [Batch14](../../work/parallel-features-20261115/parallel-batch14-scoped-validation.json).
- [ ] [PCOR-03] Install canonical authenticated retirement/installation control and actual runtime external-custody/Pipeline/history coordination through the selected shared service, including idempotent retries, conflicts, requested/effective capability and negotiated switching. PCO-05/06 and PBA-03 remain open until their complete acceptance passes.

## Acceptance boundaries

- [x] [PCO-01] Strict route v1 roundtrip/malformed/index/incarnation/class refusal and typed unreliable branch, without authority claims. Evidence: [Cases21](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-21/validation.json).
- [x] [PCO-02] Actual fallible fixed-cohort construction and complete fixed/vector/nested-heap accounting; one-short refusal and exact allowance, including sixteen actual owners. Evidence: [Cases21](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-21/validation.json).
- [x] [PCO-03] Actual owner1 byte/native/feedback progress while owner0 source is lost or physically held; recovery/custody isolation and original bytes/debits/caps. Evidence: [Cases21](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-21/validation.json).
- [x] [PCO-04] Owner-aware foreign/duplicate physical and native token refusal, actual original-time acceptance and real aggregate drain. Evidence: [Cases21](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-21/validation.json).
- [ ] [PCO-05] Complete authenticated topology/config/route and common Pipeline/Engine/Bank/runtime/service installation, including learned reverse affinity and conflict/drained-fenced reuse.
- [ ] [PCO-06] Actual lossy complete-native ACK bypass through the same admission/security/carrier budget, bounded custody and separate local retirement versus peer/native delivery; loss cannot strand epoch drain.

PCO-05/06 and full PBA-03/all47 remain required and open regardless of the finite
component tests. Native8192/P, full resource totals, platform and performance gates
are unchanged. This module does not implement endpoint CUBIC/window ownership in
transparent TUN or claim exact serialized Python wire parity.


## Selected SlotReuseV1 composition

The additive implementation is source-bound in
[the ignored source binding](../../work/parallel-features-20261115/tcp-staging/connection-reuse/handoff-v0.json).
Finite protocol/runtime/shared-service checks pass in [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json);
PCOR-03 and PCO-05/06 remain open.
`Profile::new_with_connection_reuse` explicitly commits grammar/version, bounded
history and immutable retry/operation policy into H0; legacy constructors/canonical
tag8 bytes remain unchanged. The same authenticated reliable Transaction stream
carries opaque STOP totals, actual crossed native fences, closed installation,
peer installation and activation/done messages. Reuse creates no data epoch,
replacement Engine, recovery owner, device queue or key exchange. A live reuse
and ordinary epoch switch are explicitly serialized; SW-11 remains required.

The initiator keeps its original accepted local cap; the responder freezes its
first authenticated arrival plus the immutable duration in its own clock domain.
No absolute peer time is compared locally and no retry renews a cap. Existing
old source, feedback, raw, deferred input and native writes remain serviceable
while fresh native admission conservatively pauses. Installation retires exactly
the old Pipeline/passive-ACK binding, preinstalls the explicit next key while
closed, and advances only that slot's incarnation. Source/native/raw counters and
the actual reserved endpoint survive. Physical acceptance alone is not reliable
peer delivery. Late old routes and retired native keys cannot silently reclaim
that owner. Partial post-retirement installation errors fail closed.

Exactly32 completed tombstones retain full operation identity, old key and
the actual confirmed semantic reply. Exhaustion rejects before STOP. Current
exact duplicate phase replies use the same Control owner before the original cap;
expired or older completed operations cannot reopen admission or gain a new cap.
Actual runtime status exposes the local original operation/phase/result, and
`flow_reuse` is availability of the authenticated installed controller with an
actual per-connection Engine. Pure Engine/collection observation alone remains
false; availability is not delayed until first exercise. Completed provenance is
retained honestly across later ordinary mode epochs.

The supported first path is Full/TUN over original authenticated UDP with both
actual peers already claiming the old native flow. Two focused pure composition
cases and the actual shared-service consumer pass root validation. Full carrier/layer/platform/resource/native/performance and all
original PCOR-03/PCO-05/06/PBA acceptance remain open.

The runtime installs one fallible `StateCell<Installed>` only when explicitly
selected, after checked total memory admission. Its actual payload contains the
controller and all32 tombstones; that payload is charged once in external bytes.
The Driver already charges the cell header. Unselected profiles allocate none of
this payload. Actual status distinguishes selected reserved bytes/allocation from
incomplete whole-service resource qualification.

The [shared-service API4](connection-reuse-service.md) uses the same runtime owner
and original accepted cap. Root [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json) preserves the failed attempts
and passing continuations; these finite cases do not qualify native behavior.
