# Management module contract

Status: local codec and admission primitives **implemented and contract-tested**,
2026-11-12 (Asia/Tokyo). The design was recorded before implementation. The codec, bounded admission and distributed transaction state machine are implemented.
Authenticated network dispatch and actual device drain barriers belong to the runtime integration.
This module refines MG-01, MG-03 and the local replay portion of MG-04, without
completing any whole management acceptance gate.

The [shared point-to-point session target](secure-session.md) requires this fixed
authenticated control service through every selected carrier, independently of
Swift or another data profile. Swift's private TLS policy messages are current
implementation scope, not the completed common control protocol. SEC-07/SEC-08
and full SW-11 retain reliable bounded service, duplicate/epoch/digest/deadline
checks and recovery/reconciliation under loss; a WireGuard-like handshake or
encrypted packet alone does not implement those operations.

## Public API and dependency boundary

`l2tunnel-management` depends on the local `l2tunnel-core`,
`l2tunnel-session`, `l2tunnel-recovery` and compression-disabled `l2tunnel-codec`
crates, Rust's standard library, and maintained ring for canonical configuration
and exact-message SHA-256. The [fixed reliable control service](control-delivery.md)
reuses selective repeat with independent retention, expiry and charged service
bounds; it is separate from transaction semantics and physical carrier I/O.
The additive [whole-message](control-messages.md) and
[control-stream](control-streams.md) work composes existing bounded fragmentation
and reliable delivery for complete generic transactions and independent liveness.
Their implementation and integration gates remain separate from full SW-11.
The explicit [leased transaction contract](control-streams.md#bounded-transaction-composition)
now binds the original operation cap and originating digest through terminal
request/reply custody. Joint stream admission borrows exact retained authority
from that Peer, while actual message-owner proofs settle final delivery. Legacy
constructors, wire bytes and selected runtime paths retain their prior contracts.
The crate has no socket, clock, runtime or random source; it does
not authenticate records or implement cryptographic primitives. It reuses `Epoch`,
`ConfigDigest` and `Ticket`; a ticket's target epoch, attempt and digest do not
prove that the reload state machine accepts it.

The exact initial public API is:

- Typed `SessionId`, `LaneId`, `EndpointId`, `PacketNumber` and `RequestId` prevent
  accidental interchange. `Role` distinguishes client and server control senders.
- `Header` carries source/target identities, a `MessageKind`, source epoch and
  target `Ticket`. `Frame<'a>` borrows opaque message bytes.
- `Frame::encode(output, limits)` and `Frame::decode(input, limits)` operate on
  caller buffers and return typed `Error` values. Neither authenticates input nor
  changes a reload state machine. Unknown versions/kinds and trailing bytes fail.
- `SessionBinding` identifies one authenticated peer direction in one session.
  `Ingress` explicitly distinguishes caller-verified management records from
  unauthenticated and user traffic. The verified variant is a trust assertion by
  the embedding runtime, not a cryptographic proof constructed by this crate.
- `AdmissionGate::new(binding, limits)` creates a bounded request ledger and a
  fixed 128-packet replay window. `admit(ingress, input)` returns `Admission` plus
  the borrowed parsed frame. It rejects user origin before any parsing or state
  mutation. All accepted peer input requires verified-origin metadata matching
  the session, lane and sender encoded in the protected frame.
- `Admission::NewRequest` permits later semantic processing;
  `Admission::RepeatedRequest` permits a cached/idempotent reply only. The same
  packet number is a replay error even when its request is an exact duplicate.
  Neither result establishes legal reload phase transitions or an applied action.

## Draft wire layout

All integers use network byte order. Exactly one complete internal control frame
is passed to the codec; carrier stream assembly is outside it. The header is 112
bytes, followed by opaque message bytes, with a configured total-length limit of
at most 65,536 bytes. No field is a globally assigned Ethernet EtherType.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | Internal `L2MC` discriminator |
| 4 | 1 | Draft version 1 |
| 5 | 1 | Kind: PREPARE=1, READY=2, BARRIER=3, COMMIT=4, COMMIT_ACK=5, RETIRE=6, REJECT=7, STATUS=8, RECONCILE=9 |
| 6 | 1 | Sender role: client=1, server=2 |
| 7 | 1 | Reserved, must be zero |
| 8 | 4 | Exact total frame length |
| 12 | 4 | Authenticated physical lane ID |
| 16 | 16 | Session ID |
| 32 | 8 | Peer-direction control packet number |
| 40 | 8 | Logical message request ID |
| 48 | 8 | Source data epoch |
| 56 | 8 | Target data epoch |
| 64 | 8 | Proposal attempt |
| 72 | 32 | Canonical target configuration digest |
| 104 | 4 | Logical source L2 endpoint ID |
| 108 | 4 | Logical destination L2 endpoint ID |
| 112 | variable | Opaque message body |

The internal endpoint addresses are not learned device MAC addresses. The
authenticated outer record class is required for dispatch; discriminator,
endpoint address and Ethernet-like bytes never grant control authority. Both TAP
and TUN user payload paths remain separate. This format deliberately has no MAC,
AEAD tag, key ID or certificate; a future crypto adapter must authenticate the
exact frame and outer record class before constructing verified ingress evidence.
It is not a standalone safe network format or a final interoperable wire version.

## Replay and duplicate invariants

Use one gate for the whole peer direction of a session, including authenticated
lane migration. Its packet number space does not reset on a data epoch or lane
change. A fresh number within 128 positions of the largest accepted number may
arrive out of order once; older numbers are rejected. Advance the replay bitmap
only after all syntax, binding, request consistency and capacity checks succeed.
Invalid input must not evict valid replay evidence or consume ledger capacity.

A request ID identifies one immutable logical message in a peer direction. Every
new logical phase message uses a new request ID; the ticket attempt correlates the
larger transaction. An exact retransmission uses the same request ID and message
content with a fresh packet number, and may use another authenticated lane. Compare
kind, roles/endpoints, session, epochs, attempt, digest and every payload byte;
exclude only packet number and physical lane from request equality. Same request
ID with different content is a conflict, not an authorized amendment.

Ledger count and retained encoded-byte budget are configured up front and bounded
by hard limits. `retire_through` advances a permanent monotonic request watermark
only when the caller has authenticated progress or abort evidence. Retired IDs,
including previously unseen lower IDs, are rejected forever in that session.
The transaction module supplies the proof of progress and retains one responder
reply plus one outstanding coordinator command; no time-only eviction occurs.
Logical byte
accounting covers the encoded header and body; Vec metadata/allocator overhead
is separately bounded by the entry count, not claimed equal to wire byte usage.

The gate is not transactional with the later reload state machine. A new admitted
message may still be semantically rejected; the runtime must preserve a bounded
reply outcome for repeated requests and coordinate resource admission before
performing effects. The codec alone does not send replies or mark anything applied; `transaction::Peer`
coordinates semantic admission and returns bounded outbound effects.

## Focused verification plan

- [x] [MGT-01] Exact draft byte vector, arbitrary/nonzero body round-trip, unchanged output beyond the encoded slice. Evidence: [golden and round-trip test](../../crates/l2tunnel-management/src/tests.rs).
- [x] [MGT-02] Truncated headers, discriminator/version/kind/role, reserved bits, length mismatch, trailing bytes and configured size bounds. Evidence: [malformed and bounded codec test](../../crates/l2tunnel-management/src/tests.rs).
- [x] [MGT-03] User/unauthenticated spoof rejection and session/sender/lane/endpoint binding failures without mutation. Evidence: [origin and binding test](../../crates/l2tunnel-management/src/tests.rs).
- [x] [MGT-04] Logical retries versus packet replay, immutable-content conflict, reorder/window edges, jumps and exhaustion. Evidence: [request and replay tests](../../crates/l2tunnel-management/src/tests.rs).
- [x] [MGT-05] Retention count/byte bounds, retries at capacity and nonmutation on failure. Evidence: [ledger capacity test](../../crates/l2tunnel-management/src/tests.rs).

Executed locally: `cargo fmt -p l2tunnel-management`,
`cargo test -p l2tunnel-management --offline` (15 unit tests and doc-test harness), and
`cargo clippy -p l2tunnel-management --all-targets -- -D warnings`; all passed.
These are local Linux codec and deterministic two-peer transaction tests. They do not include cryptographic,
network/peer, Windows/Android, privileged lab or complete workspace validation.

## Remaining management work

- [ ] [MGT-06] Implement and review the real authenticated evidence adapter,
  key domains, replay persistence/session renewal and record-class protection.
- [x] [MGT-07] Implement canonical bodies, supported-profile capabilities, bounded request outcomes/reply caching, authenticated retirement and deadline policy. Evidence: [transaction implementation](../../crates/l2tunnel-management/src/transaction/mod.rs).
- [x] [MGT-08] Integrate PREPARE/READY/barriers/COMMIT with ReloadGuard, staged readers, deterministic coordinator ownership and uncertain-commit recovery. Evidence: [two-peer tests](../../crates/l2tunnel-management/src/transaction/tests.rs).
- [ ] [MGT-09] Implement fixed control framing/reliable delivery and charged queue
  reservation across every carrier, duplex policy and hot data-mode switch.
- [ ] [MGT-10] Run peer/network fault injection, saturation, restart and crypto
  rejection tests before describing the control plane as implemented.

## Distributed transaction design (recorded before implementation)

The `transaction` module implements one bounded stop-and-wait control
transaction over an existing authenticated session. Client is the sole
coordinator; Server cannot race a proposal. A local server UI must route a request
to the coordinator outside this initial API. Frames still require the explicit
verified `Ingress` assertion; user-origin records remain unauthorized.

The initial exact API is `Peer::new(Identity, initial_epoch, ModeConfig,
supported_modes, Settings, Tick)`, `propose(config, now)`,
`staged(Fence, now)`, `confirm_drained(sent_confirmed, received_delivered, now)`,
`receive(Ingress, bytes, now)` and `poll(now)`. Methods return bounded `Effects`
with at most one outbound complete management frame and one runtime `Event`.
`active_config`, `active_epoch`, `phase` and `reader(epoch)` expose state. Time is
monotonic caller-injected milliseconds. No socket, task, system clock or native
device is accessed. The embedding layer must reserve control service and preserve
authenticated record origin independently of user MUX routing.

Canonical `ModeConfig` encoding is fixed-length, versioned and platform-size
independent; SHA-256 through maintained ring computes its domain-separated digest.
Unknown enum values, nonzero reserved bytes, invalid configurations and unsupported
target profiles fail before state mutation. The supported-mode list is bounded
and supplied by the embedding runtime; an enum does not establish runtime support.
Changing the duplex policy is excluded from this in-place transaction and requires
the separate lane-lifecycle contract.

`Fence` is a bounded vector of exclusive final admitted-record counts, one per
old-epoch channel. `staged` means the runtime has allocated target readers and
stopped new old-epoch admissions before capturing its local fence. Exact local
send-confirmation and remote receive-delivery vectors must subsequently match the
local/peer fences. Queue emptiness is not accepted as drain evidence.

1. Coordinator proposes and receives `Stage` locally. After its `staged` call it
   sends PREPARE with canonical target config and local fence.
2. Follower validates, stages and emits `Stage` once. After its `staged` call it
   responds READY with its fence. Both runtimes receive `Drain` events containing
   local and peer fences.
3. Once coordinator drain evidence is complete it sends BARRIER. Follower replies
   only once its own independent drain evidence is also complete. The two fence
   directions cannot be substituted for one another.
4. Coordinator sends COMMIT only after BARRIER response. Follower applies the
   target and replies COMMIT_ACK. Coordinator applies it only on that exact ACK.
   During uncertainty the coordinator can interpret the target with a staged
   reader but cannot release its staged user records or send new data prematurely.
5. Coordinator sends RETIRE after ACK; follower removes the old reader and replies
   RETIRE. Coordinator then removes its old reader. Future old-epoch records have
   no reader; a retained old reader before retirement is drain/duplicate handling,
   never permission to deliver an old record again.

Each logical command and response has a monotonically increasing request ID;
responses bind the exact command ID. Retries preserve all logical contents and
use a fresh packet number. Keep one outstanding command and one cached response.
The follower's next valid command proves receipt of its prior response, allowing
retirement of prior request bodies. Coordinator retires a consumed response
immediately. Permanent per-direction request watermarks reject forgotten IDs,
including a replay wrapped in a fresh packet. Reply memory is constant in the
number of completed transactions; there is no automatic time-only eviction.

Coordinator timeout before COMMIT sends an authenticated abort and waits for its
ACK before resuming old admission or allowing a new proposal. A follower cannot
know that COMMIT is not in flight merely from timeout; it preserves staged state.
After COMMIT is emitted, timeout enters uncertainty and retransmits that exact
COMMIT. An idempotent COMMIT_ACK reconciles the state within the same session.
Post-commit timeouts never authorize rollback. Expired reconciliation bounds fail
the session while retaining the last epoch decision until teardown. A restarted
peer must establish a fresh session; persisted same-session resume is unsupported.

This is a reliable-session transaction foundation. Deterministic tests drop,
duplicate, delay and reorder logical attempts to verify retry safety, but that is
not qualification of UDP/raw carrier recovery, lane migration, a running device
pipeline or crash recovery. The runtime still supplies real staging/drain evidence
and bounded frame delivery; the module does not fabricate those facts.

- [x] [MOD-MGMT-01] Implement canonical configuration encode/decode/digest and supported-mode validation with strict bounds. Evidence: [transaction tests](../../crates/l2tunnel-management/src/transaction/tests.rs).
- [x] [MOD-MGMT-02] Implement two-peer staging, independent drain fences, commit/ack and explicit old-reader retirement using ReloadGuard. Evidence: [transaction tests](../../crates/l2tunnel-management/src/transaction/tests.rs).
- [x] [MOD-MGMT-03] Implement bounded idempotent responses, permanent retired-request watermarks and retry delivery with injected time. Evidence: [transaction tests](../../crates/l2tunnel-management/src/transaction/tests.rs).
- [x] [MOD-MGMT-04] Test loss/duplicate/reorder, asymmetric drain, timeout/uncertain commit, stale attempts/session restart, capacity and repeated transitions. Evidence: [transaction tests](../../crates/l2tunnel-management/src/transaction/tests.rs).
- [x] [MOD-MGMT-05] Integrate authenticated TCP/TLS runtime dispatch, native delivery barriers and bounded control service for None/LZ4 switching. Evidence: [managed runtime integration tests (retired in Common cutover)](compact-wire-cleanup.md). The additional buffered-arrival defect and correction are tracked by FIX-05 and [its before/after regression](../../work/managed-control-audit26/validation.json); finite original tests did not cover it. Native-device and other-carrier qualification remain separate.

Evidence for MOD-MGMT-01..04: [canonical codec](../../crates/l2tunnel-management/src/transaction/config.rs), [transaction state machine](../../crates/l2tunnel-management/src/transaction/mod.rs), and [focused tests](../../crates/l2tunnel-management/src/transaction/tests.rs). The tests include 100 consecutive transitions with constant reply/request retention, independent barriers, loss/reordering/retries, timeout abort and uncertainty, stale-session rejection and packet-counter exhaustion.

The [managed runtime](managed-runtime.md) now supplies the actual TLS origin adapter and injected-device delivery barriers for the supported one-channel None/LZ4 family in both duplex modes. That integration does not implement persistent crash resume or qualify UDP/raw control delivery.

## Mode-independent control codec and admission (pure checkpoint29)

`session_control` adds a separately versioned80-byte `L2SC` envelope without
changing the existing `L2MC` codec, request ledger or transaction engine. Its
borrowed parser bounds lengths before owned allocation and distinguishes
management, actual feedback grammar, native receipt and liveness bodies.
Physical primary-control lane and target data lane are separate. One ordered
primary stream per session/direction supplies packet identities; scope changes
retain its counter/gate. Exactly one active and one draining scope can be
registered, with matching epoch/digest, feedback tag and native receipt policy.
No primary migration, runtime I/O, authentication adapter, original-time service,
mode switch or OpenVPN recovery composition is implemented by this pure module.
Those FIX-10/FIX-11 gates remain open.

- [x] [MOD-MGMT-06] Implement and test the pure versioned session-control codec/admission contract: borrowed payloads, byte-exact golden vectors, atomic output rejection, trusted-origin/session/primary/target binding, fixed active/draining scope ownership, no-state-change errors and nonwrapping ordered counters. Evidence: [source and eight new focused tests](../../crates/l2tunnel-management/src/session_control.rs), [exact contract/wire specification](../../work/control29/wire-and-admission.md), and [26-case scoped receipt](../../work/control29/RECEIPT.md). This leaf does not complete runtime integration or stable switching.
