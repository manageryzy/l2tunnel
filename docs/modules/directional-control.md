# Directional record scopes and fixed profile control

Status: **implemented and locally protocol-tested**, 2026-11-13. The design/API
preceded code; the required frozen-source aggregate passed. Complete common-runtime
fault qualification remains open. This integration
supports the actual shared UDP runtime under FIX-11/FIX-13 and SW-15. It preserves
full SW-11, the existing common control formats, all data profiles and all parent
lifecycle/platform/performance gates. These are implementation interfaces, not
new owner decisions or a new default carrier.

## Crossing directional policies

Swift replaces its sender and receiver behind separate authenticated barriers.
During a crossing, source packets can use the old sending policy while feedback
already describes the new receiving policy. Each numbered Swift body contains
either data or concatenated feedback; its actual direction determines its scope.
A single local outgoing-scope activation cannot describe both correctly.

The existing compact User/Control routes, packet bytes and four security owners
remain unchanged. Add this facade API:

```rust,ignore
Records::seal_user_in(&mut self, scope: Scope, outer: cover::PacketMeta,
                     plaintext: &[u8], workspace: &mut [u8], output: &mut [u8])
    -> Result<Sealed, Error>
```

The scope must equal the exact active or additional registered data scope,
including its full configuration digest. A matching epoch with a substituted
digest fails. Ordinary `seal(Class::User, ...)` still uses the active source
scope; Control still uses only its immutable control scope. Explicit scoped
sealing shares the existing User sender, full counter, key generations and replay
owner. It creates no new key/domain, resets no counter and registers no scope.
Capacity/phase/scope failures occur before nonce use or output mutation.
The facade also forwards the actual `Sealed.generation` observation from its
existing maintained sender for runtime status; it exposes no secret material.

The authenticated runtime stages the new reader after agreement, uses its source
scope for data and its receiver scope for feedback, and checks the corresponding
local direction after opening. It retains at most the existing two scopes and
retires the old one only after both directional barriers and owed control
completion. This API alone neither authorizes a peer change nor implements SW-11.

## Typed fixed-control dispatch

L2SC's existing Management body requires an exact L2MC frame. Swift messages must
not be mislabeled as that body or mapped onto a different transaction protocol.
Extend the draft L2SC v1 body discriminator with kind 6:

```text
[unchanged 80-byte L2SC header, kind=6]
[profile tag u16 big endian = 1, SwiftPolicyV1]
[reserved u16 = 0]
[exact existing framed Swift Message, 1..=43 bytes]
```

The public borrowed API is `Body::ProfileControl { tag: ProfileTag, bytes }` and
`ProfileTag::SwiftPolicyV1`. The generic envelope checks the known tag, reserved
bytes and fixed body bound; the selected adapter strictly parses the existing
Swift grammar and requires exactly one complete message. No dependency from the
management crate to a data algorithm is introduced. Existing kinds 1..5 and all
legacy L2MC bytes remain byte-for-byte unchanged. Unknown tags/kinds, empty,
oversize or trailing profile data fail explicitly before output or replay credit.
A tag establishes syntax, never peer authority or feature availability.

Only verified Control ingress, exact session/lane/remote role and the admitted
active or retained origin data scope can supply ProfileControl. Ping/Pong use
the immutable control scope in the same envelope instead. The runtime's typed
dispatcher validates these body-specific scopes and one nonwrapping ordered
logical envelope sequence before effects. The existing generic L2SC Gate keeps
its separately qualified active/draining-data semantics; this profile does not
claim Swift uses another algorithm's RecoveryTag to fit that gate. Fixed
security/control scope and the ordered owner survive data-policy changes.
The complete negotiated application digest binds this dispatch version/tag;
older adapters reject the new kind rather than silently downgrade. The runtime
serializes policy coordinators and retains one logical source per outbound token.
Swift recovery feedback remains User traffic with its actual directional scope;
it is not relabeled as another algorithm's recovery tag or management authority.

## Reliable output completion

The common runtime must distinguish retained submission, encryption, native socket
acceptance, reliable receipt and logical peer transaction completion. For common
policy output, use reliable source receipt as the custody-completion condition;
the existing TLS adapter retains its original actual write/flush condition.

```rust,ignore
SelectiveRepeat::source_confirmed(&self, source: SourceId)
    -> Result<bool, RecoveryError>
delivery::Service::source_confirmed(&self, source: u64, now: Duration)
    -> Result<bool, Error>
```

An unallocated source or retained source returns false. For SelectiveRepeat,
only a validated acknowledgement removes an allocated source, so absence then
proves its reliable receipt. Polling or socket acceptance does not remove it.
Sticky recovery failure is an error; the wrapper also checks monotonic time and
its unchanged finite expiry. CarrierOnly gets no such receipt API because its
poll transfers custody without proving receipt. This query allocates nothing,
changes no counters/queues/timers and cannot refresh a deadline.

The runtime retains bounded OutboundId-to-source ownership until receipt and a
fresh policy-deadline check. A missing acknowledgement leaves the transaction
pending even after both local directions reset. Retries keep the same logical
source and exact framed command; physical packet-security numbers remain unique.
Source receipt proves recovered bytes at the peer, not application consumption,
full distributed commit, outage reconciliation or a clean native-device drain.
The adapter processes and validates delivered control before emitting its ACK
turn. Uncertain session termination never implies rollback.

## Ownership and acceptance

The integrator owns facade record changes/tests, management envelope changes,
selective-repeat receipt observation and the delivery wrapper. The policy worker
owns the one pure Swift coordinator and retained runtime adapter; the carrier
worker owns actual same-socket scheduling and policy integration. All use one
serialized Cargo build slot and frozen inputs for source-bound evidence.

- [x] [DSC-01] Record/review exact directional scope, additive profile wire, authenticated admission and reliable output-completion APIs before implementation. Evidence: this API/wire design preceded the [record](../../crates/l2tunnel/src/secure_record.rs), [envelope](../../crates/l2tunnel-management/src/session_control.rs) and receipt implementations; dependent runtime/policy workers reviewed the boundaries.
- [x] [DSC-02] Implement exact registered-scope User sealing without changing existing route bytes, Control scope, nonce/counter/ratchet/replay ownership or atomic preflight behavior. Evidence: the [scoped seal implementation](../../crates/l2tunnel/src/secure_record.rs) uses only an exact registered scope and the existing User owner. All 19 [record tests](../../crates/l2tunnel/tests/secure_record.rs) passed, including nonce/output preflight, both covers and AEAD/HMAC without changing the separate Swift-AEAD requirement. See the [source-bound focused receipt](../../work/directional-control-focused-20261113/attempt-2/validation.json).
- [x] [DSC-03] Test crossing old/new source/feedback scopes, full-digest substitution, canceled/retired scope refusal, fixed control, shared counters/generations and replay rejection across activation. Evidence: the [record regressions](../../crates/l2tunnel/tests/secure_record.rs) alternate opaque User bytes in staged/draining scopes through three key generations, verify fixed Control, replay rejection across activation and exact-digest/cancel/retire refusal. Actual algorithm feedback provenance remains DSC-06 runtime work. See the [source-bound focused receipt](../../work/directional-control-focused-20261113/attempt-2/validation.json).
- [x] [DSC-04] Implement strict borrowed ProfileControl codec/admission with unchanged old vectors, unknown/reserved/truncated/oversize rejection and no replay/output mutation on refusal. Evidence: ten [session-control regressions](../../crates/l2tunnel-management/src/session_control/tests.rs) passed, including the frozen new-kind vector, borrowed bytes, strict tag/reserved/length refusal, atomic output and trusted-origin/scope/replay checks; old vectors still pass. Full Swift grammar/capability validation remains the runtime adapter responsibility. See the [source-bound focused receipt](../../work/directional-control-focused-20261113/attempt-2/validation.json).
- [x] [DSC-05] Implement and test exact SelectiveRepeat source receipt observation plus timed delivery wrapper; prove submit/poll/loss/unsent or invalid ACK cannot manufacture completion and sticky failure/expiry remain errors. Evidence: the [ARQ confirmation regressions](../../crates/l2tunnel-recovery/src/arq/tests.rs) and nine [delivery tests](../../crates/l2tunnel-management/src/delivery/tests.rs) passed. They distinguish submitted/emitted/received sources from actual selective acknowledgement, reject unsent/forged-origin receipts, preserve sticky failure and enforce original expiry/nonmonotonic time. See the [source-bound focused receipt](../../work/directional-control-focused-20261113/attempt-2/validation.json).
- [ ] [DSC-06] Integrate actual same-socket common policy transactions with exact outbound-to-source mapping, original deadlines, loss/reorder/duplicates and crossing directional feedback; keep full SW-11 and recovery requirements open. Partial evidence: the [actual driver](../../crates/l2tunnel-runtime/src/secure_udp/transport.rs) and [paired-service checks](../../crates/l2tunnel-client-core/src/service/tests/secure_udp.rs) passed the [focused integration batch](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json), including authenticated policy changes and control progress during native pressure. The complete loss/reorder/duplicate and dropped-terminal-receipt matrix remains open.
- [x] [DSC-07] Run focused parser/security/state tests and strict checks with exact source/command evidence; preserve failed observations. Evidence: the [focused receipt](../../work/directional-control-focused-20261113/attempt-2/validation.json) passed exact commands and strict selected-package Clippy with stable explicitly compiled inputs; uncompiled concurrent runtime/client modules, docs and simulator are excluded. The earlier failed test-import attempt is preserved. This is not the required full aggregate or native qualification.
- [x] [DSC-08] Pass the required frozen-source aggregate and reconcile evidence without promoting library/loopback tests into native/platform/ISP performance claims. Evidence: the [required source-stable aggregate](../../work/secure-udp-runtime-service-20261113/attempt-1/validation.json) passed all local workspace checks with 1487 Rust cases including doctests, 271 Python tooling cases and 1658 simulator cases; formatting, strict workspace Clippy and rustdoc passed, and before/after input hashes match. The complete common-policy fault matrix remains DSC-06; no native/platform/ISP claim follows.
