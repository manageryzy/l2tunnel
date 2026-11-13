# Explicit authenticated control streams

Status: additive pure implementation with protocol and both-cover original-socket
tests; no current runtime selects it. This refines FIX-11 and SEC-07 without changing legacy L2SC/L2MC bytes,
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
commitment. Liveness permits only Ping/Pong in immutable control scope.
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

## Acceptance ledger

- [x] [SCS-01] Specify explicit negotiated framing, independent sequencing, legacy compatibility and exact shared accounting without enabling a runtime default. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCS-02] Implement strict bounded wrapper vectors, atomic output rejection, context separation and malformed/unknown/reserved-field failures. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCS-03] Implement pure per-stream sequencing and body/scope-specific authenticated admission; reject cross-stream substitution without state mutation. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCS-04] Compose independently bounded existing fragmentation/ARQ owners with one shared allowance; prove liveness progress while a transaction remains incomplete beyond 128 liveness envelopes. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [ ] [SCS-05] Integrate exact cached-retry permits, staged/retired origin authority, absolute expiry and final-reply custody with the existing generic transaction owner.
- [x] [SCS-06] Fault-test loss, duplication, reorder, binding/replay/exhaustion, capacity and stale-scope failures without modifying legacy vectors. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [ ] [SCS-07] Integrate and qualify actual selected-carrier scheduling, both covers, saturated user/native traffic, complete mode switches, liveness and shared API reporting.
- [x] [SCS-08] Pass focused and required aggregate checks with frozen sources and preserved failures; distinguish protocol fixtures from native/platform/ISP qualification. Evidence: [required pass](../../work/common-control-messages-20261113/aggregate-attempt-3/validation.json).

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
of the stream contract, cached-retry permits and complete runtime switching remain
open under SCS-05/SCS-07. Whole-message receipt is never transaction Applied.

The [source-stable required aggregate](../../work/common-control-messages-20261113/aggregate-attempt-3/validation.json)
passes 1555 Rust cases including doctests, 295 Python tooling cases and 1658
simulator cases. Earlier checklist-format failures remain preserved; see the
[message ledger](control-messages.md#finite-checkpoint-evidence) for exact scope
and environment. No native, remote CI, Windows/Android device or ISP experiment
was run for this additive protocol checkpoint.
