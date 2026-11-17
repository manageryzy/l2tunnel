# Pure current record protection

Status: **old Records implementations removed; scoped validation recorded; full gate open**.
The sole `Records` owner uses the current five-byte prefix. The old fixed-owner
and refreshable record wrappers, their framing implementation and their public
constructors are removed. There is no legacy format detection or fallback.
Current runtime qualification is tracked in the
[cutover ledger](compact-wire-cleanup.md).

## Ownership and framing

`Records` consumes the authenticated initial root into purpose-separated Data,
Feedback and Control send/receive owners. Public protocol code remains independent
of Tokio, OS handles, privileges, real clocks and native interfaces. Packet
processing uses checked lengths, caller buffers and bounded owner storage.

```text
[kind/reader: 1 byte][low packet number: 4 bytes][algorithm body][selected check]
```

| Selection | Prefix and check bytes |
| --- | ---: |
| ChaCha20-Poly1305 | 21 |
| HMAC-SHA256 with clear data | 37 |
| Explicit AES-CCM4 | 9 |
| Explicit ChaCha20/CRC32C | 9 |
| Management, recovery feedback and strong authenticated-data arm | 21 |

CRC32C is an error check, not authentication. Reliable-retiring feedback and
management retain their full-tag domains. Opaque proxy records containing credit
or lifecycle controls use the strong authenticated-data arm when ordinary data
selects a short check. That arm shares the feedback counter/replay owner with a
distinct authenticated route, and still grants only user-data authority.
Algorithm union fields, packing, fragmentation and physical carrier bytes are
additional; Rust enum size never determines serialized padding.

The original-UDP and maintained-carrier route namespaces are explicit current
layouts. Carrier routes exclude supported bootstrap prefixes. They are not
compatibility paths for the removed record format. Initial appearance stays
with the selected carrier; it is not repeated as an inner data cover.

## Scope and failure contract

The immutable control scope, active data scope and one bounded staged/draining
reader bind full epoch and configuration locally. Session, direction, lane,
record kind and the exact route remain protection context. Reader changes do
not create new counter/replay owners. Stage, cancel, activate and retire are
local operations; authenticated peer negotiation and drain barriers are still
required before switching or retiring a reader.

Constructors require explicit current selection and layout. Capacity queries
include the selected check before admission. Output-capacity failure does not
consume a packet number; authenticated open commits replay state only after
successful verification. Unregistered scopes, malformed routes, tampering and
replay do not trigger another format, purpose or protection attempt.

Fresh-DH integration with the removed refreshable Records wrapper is no longer
implemented here. The lower handshake/security primitives and their requirements
are separate from this removal. Reconnecting with new authenticated initial
material remains distinct from in-session refresh; no periodic exchange default
is introduced. The complete SEC/SW-11 requirements remain open where the current
owner lacks an integrated replacement.

## Validation

The current facade passed 24 secure-record and three same-UDP-session cases.
The affected runtime/client checks and unresolved carrier failures are recorded
in the [removal ledger](compact-wire-cleanup.md#old-records-removal-2026-11-17).
These finite checks do not establish a pristine full-suite or native-platform
pass. Tests and benchmarks whose only deliverable was the removed wire format
are removed with that implementation. Saved experiment receipts remain untouched
and must not be presented as current-format or native-platform evidence.
See `work/old-record-removal-20261117/` for this deletion batch and
`work/compact-cutover-20261117/` for the preceding source-bound tests.

## Stable retired checkpoint IDs

The following completed IDs identify the earlier implementation and its receipts.
They do not require restoring the deleted framing and do not qualify the current
owner. Current acceptance remains CWC-01 through CWC-18; no mode definition is
reduced by retiring these implementation paths.

- [x] [SREC-01] Record and review the pure API, nine-byte authenticated route, four fixed domain owners, two-reader scope bounds and pre-crypto capacity contract before implementation. Evidence: retained [historical checkpoint](../../work/shared-session-primitives-20261113/focused-validation.json); implementation retired by the current cutover.
- [x] [SREC-02] Implement actual bounded seal/open and typed authenticated User/Control results with no packet allocation, I/O, time, unsafe or secret getters. Evidence: retained [historical checkpoint](../../work/shared-session-primitives-20261113/focused-validation.json); implementation retired by the current cutover.
- [x] [SREC-03] Verify both covers and both common protection selections, opaque/empty/zero-tailed bytes, exact overhead, both directions, truncation/tamper/replay and user-to-control forgery rejection. Evidence: retained [historical checkpoint](../../work/shared-session-primitives-20261113/focused-validation.json); implementation retired by the current cutover.
- [x] [SREC-04] Verify staged/active/draining transitions, control availability during data changes, old/new scope exactness, no counter/replay resets, fixed reader bounds and preflight failures that do not burn nonces or receive replay credit. Evidence: retained [historical checkpoint](../../work/shared-session-primitives-20261113/focused-validation.json); implementation retired by the current cutover.
- [x] [SREC-05] Pass focused tests, formatting, warning-denied Clippy/rustdoc and the required source-stable aggregate checker; record exact commands and separate parent composition evidence. Evidence: retained [historical checkpoint](../../work/shared-session-primitives-20261113/focused-validation.json); implementation retired by the current cutover.
- [x] [SREC-06] Exercise real protected User/Control records on the same two real UDP sockets for both appearances, while keeping this finite loopback fixture distinct from client/service/native, full handshake/liveness/recovery, platform, standard-protocol and ISP/QoS qualification. Evidence: retained [historical checkpoint](../../work/shared-session-primitives-20261113/focused-validation.json); implementation retired by the current cutover.
- [x] [SREC-07] Validate the compact nine-byte route with implicit full-digest authentication, unambiguous current/staged/draining lookup, canceled-epoch re-registration under a changed digest/attempt without replay reset, and explicit rejection of the former unpublished 41-byte draft. Evidence: retained [historical checkpoint](../../work/shared-session-primitives-20261113/focused-validation.json); implementation retired by the current cutover.
