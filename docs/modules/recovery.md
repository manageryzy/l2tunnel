# Recovery library design

Status: implemented and locally tested selective-repeat real-payload baseline,
not completion of `compact-arq`, `legacy-arq`, FEC or the
47-mode parity catalog. It preserves the public `RecoveryEngine` event boundary.

## APIs and ownership

`SelectiveRepeat::new(ArqConfig, RecoveryContext)` and the separate
`CarrierOnly::new(ArqConfig, RecoveryContext)` implement `RecoveryEngine`:

| Operation | Contract |
| --- | --- |
| `submit(source, now)` | Copy actual source bytes into bounded owned storage and assign a nonwrapping source ID; report backpressure before mutation. |
| `receive(packet, now)` | Parse an already-authenticated complete packet, check role/session/epoch/profile, then process bounded source or ACK state. |
| `poll(now, output)` | Emit one packet into caller storage; insufficient space does not consume a packet or attempt. Caller must retain the returned bytes until its carrier accepts them and charge all wire/QoS budgets. |
| `poll_delivered(output)` | Copy the next complete ordered source from received bytes only; insufficient storage leaves it queued. |
| `deadline()` | Earliest pending ACK, unsent source or retry deadline using injected monotonic time. |
| `drained()` | ARQ: no unconfirmed source, retained receive payload or pending feedback. Carrier-only: local handoff/receive queues drained, not independently proven peer receipt. |
| `statistics()/failure()/retained()` | Observable attempts, retries, duplicates, byte/count retention and terminal retry exhaustion. |

The runtime owns authentication, anti-amplification, carrier congestion/pacing,
MUX admission, clocks and actual I/O. A context label does not authenticate bytes.
Each direction has its own source ID space. `EndpointRole` prevents accepting a
locally emitted packet as peer input. One engine instance can send and receive.

`SelectiveRepeat::poll_feedback` and `poll_source` expose the same emission state
separately for bounded FEC composition. Feedback-only polling never advances a
source attempt, and source-only polling leaves due ACKs pending. The embedding
composition must provide bounded fair service and charge both to its common wire
budget; these methods do not grant a control bypass. The original `poll` retains
its alternating policy. `inspect_packet` returns a borrowed `PacketView` through
the same authoritative parser, checking encoding/context/size without mutating
state; ACK claims still require the actual engine's send ledger in `receive`.

## Selective-repeat behavior

- Retain immutable source payloads until cumulative/selective receipt confirms
  them. Retries serialize those retained bytes; receivers have no sender ledger.
- Bound send/receive payload bytes, source counts, source size and source-ID span.
  The source window is at most 64 so feedback remains fixed size. Empty payloads
  still consume one source/count slot. The receiver's window is relative to its
  next application delivery, so a slow application cannot grow retained memory.
- ACKs contain the next missing contiguous received source ID plus a 64-bit
  selective receipt bitmap. Duplicate/reordered feedback may confirm additional
  sent sources but never acknowledge an unsent source or schedule a fast retry.
- ACKs are coalesced behind a configured finite delay. Duplicate data requests a
  fresh ACK, recovering a lost final ACK through the sender's timeout. Due ACKs
  and data alternate when both are ready, preventing a perpetual feedback stream
  from starving the data queue. Outer admission still accounts every packet.
- Timeout retries use injected monotonic time, exponential backoff and configured
  maximum RTO. Retry counts are finite. Exhaustion reports a sticky terminal
  `RetryExhausted` error; no silent drop or false drain is allowed.
- Receiving identical retained data is idempotent. Conflicting duplicate payloads
  fail. IDs below the delivered/received prefix are never redelivered; fixed
  watermarks avoid an unbounded replay-ID set. Different session/epoch/role/profile
  packets fail before data-state mutation.
- Application backpressure rejects newly arriving sources when byte/count/window
  limits are full without ACKing them. A sender may eventually exhaust retries if
  the application never drains; this is a reported failure, not unlimited memory.

`CarrierOnly` has no recovery ACK or retransmission timer. It relies on an
authenticated reliable ordered outer carrier, rejects new out-of-order sources,
and drops its send copy only after `poll` hands the packet to the caller. It cannot
repair a dropped datagram and must not be selected for an unreliable carrier.

## Draft packet encoding

All integers are big-endian. This is a versioned draft inner encoding, not Python
wire parity, encryption or a public standalone network protocol.

| Offset | Field |
| --- | --- |
| 0..4 | ASCII `L2AR` magic |
| 4 | Version 1 |
| 5 | Profile: selective repeat 1, carrier-only 2 |
| 6 | Kind: source 1, ACK 2 |
| 7 | Sender endpoint role: initiator 0, responder 1 |
| 8..24 | Session ID, 128 bits |
| 24..32 | Epoch, 64 bits |
| 32..40 source | Source ID, 64 bits |
| 40..44 source | Payload length, 32 bits; exactly that many bytes follow |
| 32..40 ACK | Cumulative next-missing source ID |
| 40..48 ACK | 64-bit bitmap; bit `i` acknowledges `prefix + i` |

ACK bit zero must be clear because the prefix is the first missing source. Reject
truncation, trailing bytes, unsupported versions/profiles/kinds, out-of-range IDs,
future/unsent acknowledgments and inconsistent payload lengths. Source IDs and
time additions use checked arithmetic. Stats counters saturate and never alter
protocol decisions.

## TODO and verification matrix

- [x] [MOD-REC-01] Specify APIs, bounded real-payload ownership and authenticated-input premise. Evidence: [this design](#apis-and-ownership).
- [x] [MOD-REC-02] Implement bounded packet codec and role/session/epoch/profile checks. Evidence: [codec and engine](../../crates/l2tunnel-recovery/src/arq.rs).
- [x] [MOD-REC-03] Implement selective-repeat source retention and exact payload retransmission. Evidence: [SelectiveRepeat](../../crates/l2tunnel-recovery/src/arq.rs).
- [x] [MOD-REC-04] Implement cumulative/bitmap receipt, delayed/coalesced feedback and duplicate protection. Evidence: [receipt and emission state](../../crates/l2tunnel-recovery/src/arq.rs).
- [x] [MOD-REC-05] Implement monotonic timers, capped exponential retry and explicit exhaustion. Evidence: [backoff/exhaustion tests](../../crates/l2tunnel-recovery/src/arq/tests.rs).
- [x] [MOD-REC-06] Implement ordered bounded delivery and unchanged state on small caller buffers. Evidence: [source/ACK/delivery buffer tests](../../crates/l2tunnel-recovery/src/arq/tests.rs).
- [x] [MOD-REC-07] Implement explicit carrier-only path with no ACK/retry behavior. Evidence: [CarrierOnly](../../crates/l2tunnel-recovery/src/arq.rs).
- [x] [MOD-REC-08] Test truncation, oversize, replay scopes, conflicting duplicates and unsent/future ACK rejection. Evidence: [adversarial tests](../../crates/l2tunnel-recovery/src/arq/tests.rs).
- [x] [MOD-REC-09] Test timer boundaries/backoff, time regression, lost final ACK and finite exhaustion. Evidence: [timer and tail-loss tests](../../crates/l2tunnel-recovery/src/arq/tests.rs).
- [x] [MOD-REC-10] Run deterministic bidirectional actual-byte transfers through dropped/reordered/duplicated packet queues. Evidence: [independent-engine lossy test](../../crates/l2tunnel-recovery/src/arq/tests.rs).
- [x] [MOD-REC-11] Verify send/receive count/byte/span bounds, output retry ownership and carrier-only failure on reorder. Evidence: [capacity, bitmap-boundary and carrier-only tests](../../crates/l2tunnel-recovery/src/arq/tests.rs).
- [x] [MOD-REC-12] Run crate tests, formatter and warning-denied Clippy; keep full workspace checks with root. Evidence: [local validation](#verification-scope).
- [ ] [MOD-REC-13] Add RTT estimation, transmission serial/ACK echo, delay subtraction, feedback repeats and byte-exact Python parity before completing compact/legacy ARQ gates.
- [ ] [MOD-REC-14] Implement first-flight/bounded-gap fast recovery and independent-record release under separate parity gates.
- [ ] [MOD-REC-15] Implement real GF(256) FEC and all remaining block/sliding/hybrid/research families.
- [ ] [MOD-REC-16] Integrate authenticated datagram carriers, negotiated peer source/window budgets, shared QoS/credit budgets and real namespace/netem receipts.
- [x] [MOD-REC-17] Expose separately pollable source/feedback and authoritative borrowed packet inspection for bounded FEC composition. Evidence: [engine APIs](../../crates/l2tunnel-recovery/src/arq.rs), [split-poll ownership and inspection regression](../../crates/l2tunnel-recovery/src/arq/tests.rs).

## Verification scope

Deterministic tests construct two independent engines and deliver only copied
wire packets through a lossy queue. Expected payloads belong to the test harness;
the receiving engine never receives a sender-side source object. These tests do
not establish production congestion fairness, native-device integration, crypto
correctness, or simulator throughput parity.

Local commands: `cargo fmt -p l2tunnel-recovery`,
`cargo test -p l2tunnel-recovery`, and
`cargo clippy -p l2tunnel-recovery --all-targets -- -D warnings`.
Final results: 14 unit tests and one public lifecycle doctest passed; formatting
and warning-denied Clippy passed. No privileged, native-platform or remote CI
execution is claimed by this module receipt.
