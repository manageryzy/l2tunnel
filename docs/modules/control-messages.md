# Whole-message control custody

Status: implemented and protocol-tested pure composition, with both-cover
original-socket fixtures. Required aggregate checks are recorded below separately.
This is an integrator proposal for SEC-07, FIX-11 and full SW-11, not an
additional owner decision or completion of those gates. The explicit
[Swift runtime integration](streamed-swift-control.md) now owns semantic custody
for SwiftPolicyV1 and independent Ping/Pong; generic Management dispatch and
complete shared API/native qualification remain open under SCM-07.

The existing reliable control service accepts one bounded source. A complete
generic PREPARE can require 2762 bytes including L2SC, while the selected Swift
composition currently allows 256 source bytes. The complete 256-channel and
512-byte canonical
configuration contracts remain required. Compose the existing codec fragmenter,
reassembler and management delivery service instead of another recovery engine.

## Ownership and wire contract

`management::messages` owns bounded outgoing messages, fragment submission,
reassembly, a held complete incoming message and complete-message receipts. It
uses injected monotonic `Duration`; it owns no clocks, sockets, device, privileges
or cryptographic session. The codec dependency disables optional compression.
The enclosing runtime must first authenticate the exact Control bytes and full
session, lane and role. The fragment codec's 64-bit context is not authentication
and never replaces the full 128-bit management binding.

The existing SelectiveRepeat source and receipt formats remain unchanged.
Within a source, kind 1 carries one unchanged LXv1 fragment; kind 2 carries a
complete-message receipt: 64-bit message ID, 32-bit exact message length and SHA-256 of the
exact message bytes. That receipt occupies 45 source bytes including its kind.
Maintained ring supplies SHA-256; this is a message fingerprint inside already
authenticated control, not a new authentication or cryptographic primitive.
The additive stream wrapper is specified in [control streams](control-streams.md).

Fragment recovery ACKs prove only source custody. They can acknowledge a source
that has not yet reached ordered delivery or reassembly. A message remains owned
until a matching complete-message receipt and its submitted source receipts are
observed. Neither event means a configuration is Applied. Only the existing
`transaction::Peer<C>` and its native drain evidence decide transaction effects.

Reserve a full fragment scratch buffer, reassembly capacity and held completion
storage before consuming ordered delivery. The reassembler tombstones completion;
its bytes must transfer into held custody until the embedding parser and
authoritative dispatcher accept them. Caller output or receipt backpressure must
preserve exact bytes and ticket. Queue the complete-message receipt only after
that explicit acceptance. If receipt admission is backpressured after dispatch,
retain the semantic ticket and retry acceptance without dispatching its effects
again. Reserve source slots/bytes so fragmented user commands
cannot consume every receipt opportunity. Existing ARQ retries that receipt;
there is no separate receipt retry algorithm or ACK-of-ACK protocol.

The additive `Accepted` and `Confirmed` proofs borrow their actual Owner. Only a
successful `accept_with_receipt` can issue the first after retaining the exact
complete-message receipt. Only actual whole-message confirmation can issue the
second; source ACKs alone remain insufficient. Neither proof has a public
constructor or Clone/Copy escape. The [leased transaction integration](control-streams.md#leased-transaction-checkpoint)
checks exact complete-envelope SHA-256/length, full session/lane/local role,
expected Transaction recovery context, originating policy, final logical
request/reply and injected observation before releasing operation custody. Bad
proof/context checks leave peer time unchanged and preserve the borrowed proof
for a correct retry. These tokens do not authenticate a record or imply Applied.
The embedding adapter must reuse one immutable envelope/submission per logical
output, including repeated cached replies; it must not create a fresh envelope
after final operation custody is released. The [stream contract](control-streams.md#bounded-transaction-composition)
states the retirement boundary and its ordered-delivery consequence explicitly.

## Bounds and deadlines

Admit message bytes, fragment count, outgoing retention and IDs atomically.
Retrying a local submission with changed bytes or deadline is an explicit error.
Count whole-message storage, fragment batches, fixed source scratch and recovery copies separately;
there is no zero-copy claim. Complete path-MTU validation includes common
protection, appearance, stream wrapper, recovery header and fragment metadata.
Configured control reservations remain inside the selected session's budget.

Each local message has its accepted absolute deadline, including transport waits.
Incoming assembly and held delivery retain the bound from first ordered fragment
delivery into the reassembler. Fragments still buffered in ARQ behind a preceding
held message have not started that receive-side clock; this API does not claim a
physical UDP-arrival deadline. Monotonicity, overflow
and exact-expiry failures are explicit; duplicates and interval refill cannot
renew them. An expired transfer cannot cancel/recreate an ordered ARQ context:
its source IDs, replay state and original service expiry persist. Expiry is an
explicit terminal/reconciliation result. The runtime must separately preserve
liveness through its independent control stream and report recovery status.

## Acceptance ledger

- [x] [SCM-01] Implement bounded reusable whole-message custody from existing fragmentation and reliable delivery, with exact retained-copy observations and no runtime/crypto owner. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCM-02] Deliver genuine 354-byte and 2762-byte generic PREPARE envelopes byte-exactly through smaller recovery windows, preserving all configuration/fence limits. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCM-03] Enforce complete-message acceptance separately from fragment ACKs and transaction Applied; retain completion through output/receipt backpressure. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCM-04] Fault-test lost first/middle/final fragments, reordering, duplicates and lost complete-message/source receipts using the existing ARQ. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCM-05] Test independent queue/byte/fragment/work limits, atomic refusal, original deadlines, backwards/overflow time and sticky terminal failure without owner reset. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [x] [SCM-06] Compose authenticated Control and the explicit stream wrapper on both original UDP cover pairs, including transaction blockage with independent liveness. Evidence: [focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json).
- [ ] [SCM-07] Integrate actual selected-carrier runtime dispatch, semantic receipt custody, original operation caps and shared service/API status during complete profile switches. Progress: [explicit streamed Swift runtime custody](streamed-swift-control.md) passes finite original-socket tests; generic/cross-profile dispatch, shared frontend status and saturated native qualification remain open.
- [x] [SCM-08] Pass focused and required aggregate checks with exact source identities and preserve all failed attempts and legacy receipts. Evidence: [required pass](../../work/leased-control-20261113/aggregate-attempt-1/validation.json).

These child gates preserve CDL-07, MG-01/04..08, SEC-07/08/10, SW-11/SW-15 and
every other requested record profile, carrier, platform and Python parity gate.

## Finite checkpoint evidence

The [source-stable focused pass](../../work/common-control-messages-20261113/focused-attempt-2/validation.json)
runs all 61 management cases, codec fragment cases, both original-socket UDP tests,
strict three-package Clippy and rustdoc. Fourteen new message tests construct real
generic transaction peers and PREPARE envelopes. The 2762-byte case uses 13 LX
fragments over a three-source recovery window, with only two slots available to
fragments because one is reserved for complete-message receipts. First, middle
and final source loss, source ACK loss, whole receipt loss, reordered duplicates
and immutable retry bytes are explicit assertions. Zero remaining fragment
sources still cannot confirm a held, unaccepted complete message.

The both-cover fixture uses the actual Noise handshake on connected UDP sockets,
one common Control security owner per endpoint, fresh protection on every ARQ
attempt and one debited IP-byte allowance across streams. It withholds Transaction
emissions while completing 130 accepted/confirmed Ping/Pong rounds, then delivers
the genuine delayed PREPARE. Both roles cross key generations and retain the
original socket pair. The follower remains in Staging with its original active
epoch even after whole-message confirmation. This is not an actual service,
native saturation, completed mode switch or ISP classification test.

The preceding focused attempt is also preserved. No legacy receipt, simulator
output, runtime default, configuration limit or full acceptance gate was changed.

The [required source-stable aggregate](../../work/common-control-messages-20261113/aggregate-attempt-3/validation.json)
passes `tools/check.py`: 1555 Rust cases including doctests, 295 Python tooling
cases and 1658 simulator cases, with formatting, strict workspace Clippy, rustdoc
and ordinary CLI/loopback checks. The [environment record](../../work/common-control-messages-20261113/aggregate-environment.json)
retains `RUST_TEST_THREADS=1`; no existing test, assertion or runtime deadline was
weakened. Aggregate attempts 1 and 2 remain failed because the new checked ledger
items first lacked per-item links and then their required `Evidence:` marker.
Neither reached Rust execution; both raw receipts remain unchanged. After the
successful aggregate, only evidence prose and checkbox reconciliation change.

The later [leased-custody aggregate](../../work/leased-control-20261113/aggregate-attempt-1/validation.json)
also passes with frozen sources: 1579 Rust cases including doctests, 295 Python
tooling cases and 1658 simulator cases. The [leased checkpoint](control-streams.md#leased-transaction-checkpoint)
records actual borrowed final-custody proofs, both forms of backpressure and
post-proof delayed-original-source ACKs on both covers. Its [environment record](../../work/leased-control-20261113/aggregate-environment.json)
preserves the serial Rust test setting. SCM-07 and the complete parent runtime,
platform, native and mode-switch requirements remain open.
