# ARQ timers after physical carrier acceptance

Status: implemented and protocol-tested, with finite selected-runtime and Linux
native integration evidence. This addresses FIX-01 and preserves the full compact-arq/first-flight parity gates.
No wire byte, cryptographic domain, default carrier or handshake is added.

The existing selective-repeat owner starts its retry timer when `poll_source`
produces bytes. Reliable may still hold those bytes in a partial FEC block, and
the runtime may retain a sealed packet under carrier backpressure. Those waits
must not count as an already transmitted flight in the selected Common path.

The existing ARQ owner gains explicit physical confirmation before use. Legacy
constructors and callers retain their previous handoff timing. The selected
Common Aligned/Packed owners activate confirmation at construction. They retain
one actual recovery engine and the same source allocator, payload slots, receipt
window, retry limit and exponential backoff. Preparation reserves an attempt and
a checked nonwrapping local transmission identity, but leaves its retry timer
unarmed. Exact physical confirmation arms the original retry interval
from caller-injected whole-send time. Asynchronous completion carries separate
acceptance and observation times: acceptance lies between preparation and the
monotonic observation, and scheduler delay cannot postpone the retry deadline.
An already due interval remains due at observation. The existing single-time
API delegates with equal times. Rolling retains its previous observation-time
contract; this change does not claim to fix its asynchronous timer semantics.
Already accepted peer receipts may confirm
a prior flight while its retry packet remains physically owned. Retain that
existing payload slot until the local confirmation is consumed once; do not
resurrect the confirmed source or arm another retry. Independent prepared sources
may complete in actual carrier order, which can differ from FEC collection order.

Prepared identities are local custody tokens, not peer authentication. Their
outstanding count is bounded by the existing send-record count. Initial-flight
feedback received before physical acceptance is rejected. Feedback for an older
physical attempt can retire a pending retry. Wrong or repeated
confirmations cannot arm or move another flight's deadline. Physical completion
with invalid/overflowing time consumes its custody and fails explicitly rather
than inventing a later deadline. No RTT estimate is inferred from enqueue time.

Reliable holds one inline pending-output witness for direct/systematic source,
repair or feedback output. It keeps existing caller-owned bytes and one shared
wire debit; it does not allocate another packet queue. Systematic source tokens
come from the actual ARQ owner. Aligned/Packed expose that witness through the
existing Common Engine/Bank carrier-output contract. The runtime's existing
whole-carrier completion calls it for the exact issuing epoch. Native, liveness,
operation and session deadlines remain independent and unchanged while output
is held. Actual heap plans include changed slot layouts; historical scalar
layout mirrors and old wire/configuration identities remain unchanged.

The legacy Aligned/Packed datagram runtime also needs this explicit contract.
Its endpoint selects physical confirmation before admitting traffic. The existing
data writer carries the exact prepared-output token, including repairs with no
native record witness, and reports the original whole-send acceptance time.
The existing authenticated control writer similarly confirms feedback only after
the complete frame is written and flushed. Queue admission is not confirmation.
Incoming recovery feedback may race the local completion callback; the actor
must settle the corresponding actual send before applying that feedback, retaining
its original receipt time and bounded event ownership. The same actor, carrier,
native accounting, queue/work limits and deadlines remain in force. This runtime
extension is under implementation; its acceptance gate is separate below.

Root owns recovery ARQ/backing/storage, Reliable, aligned wrappers, pure Common
Engine carrier/constructor integration, focused tests and this ledger. Parallel
workers own codec copy policy, rolling feedback and runtime same-flow recovery.

- [x] [APC-01] Implement bounded physical attempt custody in the existing ARQ owner; verify actual blocked first/retry timing, receipt races, exact/foreign/repeated confirmation, overflow and unchanged legacy bytes. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [x] [APC-02] Compose actual direct/FEC Reliable and Aligned/Packed with one caller-held output and the Common Engine/Bank issuing-generation confirmation; verify same bytes/debit, partial FEC delay, real peer recovery and native delivery. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [x] [APC-03] Qualify the selected runtime's original carrier completion with blocked physical output and mixed-family transitions, and pass affected strict checks. Preserve full fault/resource/native/platform/compact-arq acceptance separately. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [ ] [APC-04] Integrate the same physical-output custody into the existing Aligned/Packed UDP and maintained-QUIC actors, including actual control-feedback flush, zero-native-unit repair and completion/input races. Preserve the existing bounded native-pressure, delivery and deadline tests; do not infer success from enqueue or relax their limits.
