# Fixed-cohort independent Compact owners

Status: implemented pure component with four executed protocol cases. No default
or named profile selection changes. This is a prerequisite for full PBA-03;
Common Engine/Bank/runtime/service installation remains required and open.

The named `quic-overhead-1/2/3` reference constructs sixteen independent CompactTCP
objects, each with directional recovery and codec contexts, and shares physical
Links/events. The existing Rust Compact tags6/7 retain one shared duplex body
owner. A channel count alone does not change that topology.

## First deliverable and ownership

New pure facade module `connection_records` owns a bounded fixed cohort of actual
reserved `aligned::Endpoint` Compact owners. It supplies no classifier, Pipeline,
cryptography, socket, clock, task or congestion controller. Future Engine wiring
must select it through one actual shared Pipeline and the existing single
authenticated User/carrier path. Existing constructors, tags and defaults remain
unchanged. Tag8 remains a proposed explicit CompleteV2 integration, not a claimed
installed profile.

`Config { owners, incarnation, send, receive, send_carrier_overhead_bytes,
receive_carrier_overhead_bytes }` requires owners1..=256, a positive
incarnation, actual single-channel directional Compact configs and copy count1.
The same directional config is instantiated independently for every owner; source,
feedback, retry, RTT, codec and native state are not shared between them. A fixed
cohort has no eviction, rebinding or reuse method. Full authenticated flow claims,
reverse affinity, conflict handling and drained/fenced reuse remain required
follow-on work; the caller cannot obtain those guarantees from an owner index.

## Exact route v1

The route header is24 bytes: magic `L2PC` (4), version1 (1), class (1), owner u16
(2), incarnation u64 (8), unreliable-native serial u64 (8), in network byte order.
Classes are recovered source1, recovered feedback2 and unreliable native3.
Recovered records require serial0; unreliable native requires a positive serial.
The complete route and payload must be authenticated/replay-checked by the caller
before admission. A structural parser grants no authentication or management
authority. Unreliable native is a distinct typed grammar branch but is explicitly
refused by this first collection until actual bounded ACK custody is installed.
It cannot silently enter recovery or be counted as reliable peer confirmation.

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
