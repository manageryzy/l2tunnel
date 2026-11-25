# Explicit authenticated control streams

Status: additive pure implementation with protocol and both-cover original-socket
tests. An explicitly selected [Swift runtime backend](streamed-swift-control.md)
now composes these owners; focused qualification is in progress and CLI defaults
remain legacy. This refines FIX-11 and SEC-07 without changing legacy L2SC/L2MC bytes,
default carrier, common security owners or full SW-11 scope. It is not an owner
decision about the final public wire protocol.

One reliable sequence cannot guarantee liveness behind a missing management
fragment. Queue priority does not solve that head-of-line dependency. Define
explicit Transaction, Liveness and DataFeedback streams under one physical
carrier lane and one Control security sender/receiver owner. Each stream has a
distinct fixed reliable context and its own nonwrapping logical envelope sequence.
All emitted IP bytes still consume one shared session allowance; independent
contexts do not authorize multiplying control reservations or bandwidth.

## Additive framing and admission

The negotiated draft wrapper is 8 bytes: `L2CF`, version 1, stream 1..3, and two
zero reserved bytes. Its payload is one unchanged reliable control packet.
Authenticate the entire wrapper and payload inside the existing Control record.
Parsing a matching discriminator never grants management authority. Selection,
stream map, bounds and accounting must be in the authenticated configuration;
no fallback guessing or automatic legacy upgrade is permitted.

The fixed control base epoch maps to recovery epochs `3*base + stream`, using
checked arithmetic and rejecting zero/overflow. This is a reliable-context
namespace, not a new data epoch, key generation, cryptographic counter or owner.
The common Control counter/replay state remains shared and never resets.

The unchanged L2SC packet field is stream-local only under this explicitly
selected contract. Leave the existing global-order Gate and writer unchanged for
the legacy contract. Removing its sequence check would not suffice: frequent
Pings could age an incomplete transaction out of its 128-entry replay window.

The new gate must check verified full session, remote role and physical lane
before parsing or mutation, and reserve external delivery custody before sequence
commitment. Liveness permits only Ping/Pong and the tunnel-test address
exchange (`ProfileControl` tag `TunnelTestV1`, docs/modules/tunnel-tests.md) in
immutable control scope.
Transaction permits nested Management or an explicitly supported ProfileControl
grammar from the registered originating data scope. Target configuration digest
is not origin digest. DataFeedback permits only the actual registered recovery
grammar/target lane/native receipt policy; Swift must not masquerade as another
feedback grammar. Active and one draining data scope remain explicit and bounded.
The gate checks envelope syntax and registered tag/length/lane/policy. The actual
selected algorithm adapter must still validate opaque feedback/profile bytes and
authorize semantic effects before complete-message acceptance.

Retirement requires a further bounded cached-retry permit tied to the actual
logical command/reply and `transaction::Peer<C>` custody. It must not admit retired
user data or feedback, or renew on duplicate input. This remains a separate open
deliverable; initial active/draining gate work cannot claim complete switching.

## Bounded transaction composition

The additive implementation selects a leased transaction contract explicitly;
legacy `Peer::new`, legacy envelopes and existing carrier defaults retain their
behavior. `new_leased` receives a session expiry, maximum operation duration and
expected fixed Transaction recovery context. Custody proofs must match that full
context, including session, local role and physical lane; a liveness-stream proof
cannot complete a management operation.
`propose_until` and the first accepted `receive_until` receive an already owned
absolute local deadline. The immutable lease stores the original data epoch and
canonical configuration digest, full session identity and target ticket. Later
phase changes, duplicate commands, uncertain-commit retries and terminal cached
replies cannot renew it. Local injected `Tick` values are milliseconds, not shared
cross-peer wall time; an adapter must never round an earlier deadline forward.

Every leased effectful entry point checks original expiry, including late input
without a preceding poll and cached replies in Idle. Expiry is a terminal explicit
result that preserves bounded diagnostic/reconciliation custody; it does not
authorize rollback of a possibly committed peer or reinterpret old readers.
Invalid new caps and conflicting retry deadlines reject before counters or
logical request admission change. Per-phase retry rules still apply inside the
original operation cap. The missing-PREPARE/first-REJECT path remains supported.

A transaction-bound Gate rejects Management through ordinary `admit`. Its joint
entry point computes sequence admission prospectively, checks the actual leased
Peer and dispatches that same Peer before committing the outer sequence. A retired
origin exception requires the exact currently retained incoming request and its
matching cached reply, borrowed from that Peer. Session, role, physical lane,
endpoints, kind, request, original scope, target ticket and every body byte must
match; only transmission packet numbers may change. This does not restore any
retired data policy or authorize ProfileControl, feedback or user data.
An already dispatched terminal incoming reply may also retry only while its exact
retained logical request still awaits local acceptance custody. It grants no new
effects, and its exception disappears at actual completion. This prevents receipt
backpressure from turning a valid late final reply into a broad old-scope grant.

The current generic transaction FSM originates every command/reply from the old
source scope. A staged target reader alone grants no Management authority.
Actual staged algorithm feedback, if needed by a selected profile, still requires
its real adapter and reader custody; this proposal does not fabricate that grant.

Idle and `Event::Retired` are insufficient to release the final lease. New borrowed
message proofs distinguish a locally queued complete-message acceptance receipt
from an outbound complete message confirmed by its peer. Completion must match
the exact authenticated envelope and actual final logical command/reply, original
scope and unexpired lease. Borrowing the owner prevents a proof from surviving
mutation or loss of that custody. A dispatched incoming ticket remains owned
through receipt backpressure, and an outgoing submission retains identical bytes,
ID and deadline through admission backpressure. These are integration deliverables,
not permission to reduce the unchecked SCS-05/SCS-07 definitions.

An adapter must retain exactly one immutable whole-message envelope, submission
ID and original deadline for each logical output. Repeated Peer emissions of the
same logical reply reuse that retained submission; recovery retransmits its
original source IDs under fresh common Control protection. Final proof completion
retires the logical request and its special origin authority. A duplicate in a
new envelope after that point is rejected and can block ordered Transaction
delivery; the adapter must never create it. Supporting such new envelopes would
require separately bounded retired discard custody and its own tests. Ordinary
delayed copies of the original ARQ sources remain below semantic dispatch.

## Acceptance ledger

- [x] [SCS-01] Specify explicit negotiated framing, independent sequencing, legacy compatibility and exact shared accounting without enabling a runtime default. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCS-02] Implement strict bounded wrapper vectors, atomic output rejection, context separation and malformed/unknown/reserved-field failures. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCS-03] Implement pure per-stream sequencing and body/scope-specific authenticated admission; reject cross-stream substitution without state mutation. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCS-04] Compose independently bounded existing fragmentation/ARQ owners with one shared allowance; prove liveness progress while a transaction remains incomplete beyond 128 liveness envelopes. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [ ] [SCS-05] Integrate exact cached-retry permits, staged/retired origin authority, absolute expiry and final-reply custody with the existing generic transaction owner. Progress: [leased generic core and actual message custody](#leased-transaction-checkpoint) are protocol-tested; selected-profile staged authority and complete adapter lifecycle remain unqualified.
- [x] [SCS-06] Fault-test loss, duplication, reorder, binding/replay/exhaustion, capacity and stale-scope failures without modifying legacy vectors. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [ ] [SCS-07] Integrate and qualify actual selected-carrier scheduling, both covers, saturated user/native traffic, complete mode switches, liveness and shared API reporting. Progress: [explicit streamed Swift runtime custody](streamed-swift-control.md) passes finite original-socket tests; generic/cross-profile dispatch, shared frontend status and saturated native qualification remain open.
- [x] [SCS-08] Pass focused and required aggregate checks with frozen sources and preserved failures; distinguish protocol fixtures from native/platform/ISP qualification. Evidence: [required pass](../../work/leased-control-20261113/aggregate-attempt-1/validation.json).

The [whole-message ledger](control-messages.md) tracks payload custody. These
children do not complete MG-*, FIX-11, full SW-11, retained recovery, other carriers,
platforms or any of the 47 complete Python mode gates.

## Finite checkpoint evidence

The [source-stable focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json)
includes three strict wrapper/context tests, seven pure gate tests, fourteen
whole-message tests and both-cover original-socket integration. Gate tests admit
257 liveness envelopes before Transaction packet 1, reject cross-stream/body/scope
substitution atomically, check full 128-bit session, physical lane and remote role
before parsing, and preserve sequences across active/draining retirement. Missing
numbers, replay, zero, exhaustion, unknown origins, optional feedback grammar and
native receipt bounds have explicit failure cases. The legacy Gate and vectors
are unchanged.

The UDP fixture completes 130 fully confirmed Ping/Pong rounds while withholding
Transaction emissions, then accepts one genuine delayed PREPARE under its original
origin. It uses one common cryptographic counter/replay owner and an allowance
debited across all streams, including dropped emissions. That finite allowance
is not saturated, so this proves accounting and independent progress, not native
saturation fairness. Selection is explicit in the fixture; production negotiation
of the stream contract and complete runtime switching remain open under
SCS-05/SCS-07. The later leased checkpoint adds generic cached-retry authority
below. Whole-message receipt is never transaction Applied.

The [source-stable required aggregate](../../work/common-control-messages-20261113/aggregate-attempt-3/validation.json)
passes 1555 Rust cases including doctests, 295 Python tooling cases and 1658
simulator cases. Earlier checklist-format failures remain preserved; see the
[message ledger](control-messages.md#finite-checkpoint-evidence) for exact scope
and environment. No native, remote CI, Windows/Android device or ISP experiment
was run for this additive protocol checkpoint.

## Leased transaction checkpoint

The [source-stable focused pass](../../work/leased-control-20261113/focused-attempt-4/validation.json)
runs 84 management cases, codec fragment cases, all three original-socket UDP
fixtures, strict three-package Clippy and rustdoc. Thirteen new leased-peer cases
and ten joint Gate/Peer cases preserve original caps across genuine phases,
uncertain commit, the missing-PREPARE/first-REJECT path and locally Idle final
custody. Boundary checks cover exact expiry without an earlier poll, changed
deadlines, backwards/overflow time, immutable original digest, full binding,
counter/exact-request retirement and repeated events. Legacy tests remain intact.

The new both-cover fixture drives real PREPARE/READY/BARRIER/COMMIT/RETIRE through
the existing fragmentation/ARQ owners and common protected Control records. Drain
facts are independently injected asymmetric vectors; no native data drain is
claimed. The follower removes its old Gate origin while its final reply is lost.
The same original UDP pair completes 130 fully confirmed Ping/Pong rounds, then
admits three exact fresh-number RETIRE retries under the retained request/cache
exception. All Stage/Committed/Retired events occur exactly once. Duplicate logical
replies reuse the first retained whole-message envelope instead of creating more
complete messages. Common cryptographic counters and key generations continue.
The three new-envelope RETIRE retries are deliberately injected while final
custody is retained to exercise that exact authority; they do not relax the
adapter's one-envelope-per-logical-output requirement.

Final output admission is deliberately refused by retaining three confirmed
metadata entries; releasing them admits the identical pending bytes, ID and cap.
The fault injector permits source ACKs but withholds follower Transaction DATA.
Three exact retries then fill its bounded source queue and force whole-message
acceptance backpressure. The held incoming bytes/ticket survive, and retrying
acceptance does not dispatch the transaction a second time. After delivery resumes,
actual borrowed Accepted and Confirmed proofs settle both roles and every retained
whole-message/source entry under the original cap. Idle alone remains insufficient.

After those proofs and message retirement, bounded copies of the original follower
Transaction source packets, including the exact final reply, are delayed and
resealed on the original UDP pair with fresh common Control nonces. They produce
an actual ACK whose contiguous prefix covers every replayed source ID, with no
new pending message, Gate sequence, lifecycle event or proof completion. Normal
dispatch and final queue-drain assertions still pass on both covers. This tests
retransmission of the original sources; it does not add post-retirement authority
for a new whole-message envelope.

Actual proof checks reject altered bytes, wrong session/lane/recovery context,
wrong completion direction, changed observation time and reuse after completion.
Pure transcript-rebound negative peers are not additional authenticated UDP
sessions. These are protocol tests; the allowance is accounted but not saturated,
no Records User-scope/data-profile switch occurs, and no service/native/ISP result
is inferred. The generic FSM rejects staged target Management origins even when
a staged reader exists. Real profile-specific staged feedback/lifecycle authority
still requires the selected adapter, so the full SCS-05/SCS-07 definitions remain
unchanged and open.

Focused attempt 1 passed behavior tests but failed strict Clippy on a collapsible
conditional. That raw failed receipt is preserved; attempts 2 and 3 also pass.
Attempt 4 includes the stronger proof/backpressure and delayed-source ACK
assertions and passes without relaxed assertions or deadlines.

The [required source-stable aggregate](../../work/leased-control-20261113/aggregate-attempt-1/validation.json)
passes `tools/check.py`: 1579 Rust cases including doctests, 295 Python tooling
cases and 1658 simulator cases, plus formatting, strict workspace Clippy, rustdoc
and ordinary CLI/loopback checks. The [environment record](../../work/leased-control-20261113/aggregate-environment.json)
retains `RUST_TEST_THREADS=1`; no existing test, assertion or runtime deadline was
weakened. After this aggregate, only evidence documentation is reconciled. No
privileged native, remote CI, Windows/Android device or ISP experiment ran for
this checkpoint, and full SCS-05/SCS-07 and SW-11 remain open.
