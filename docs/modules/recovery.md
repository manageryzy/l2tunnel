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
  A window of at most 64 keeps the original fixed-size feedback; larger windows,
  up to 8192, use the [wide ACK](#wide-ack-for-large-windows). Empty payloads
  still consume one source/count slot. The receiver's window is relative to its
  next application delivery, so a slow application cannot grow retained memory.
- ACKs contain the next missing contiguous received source ID plus a 64-bit
  selective receipt bitmap. Duplicate/reordered feedback may confirm additional
  sent sources but never acknowledge an unsent source or schedule a fast retry.
- ACKs are coalesced behind a configured finite delay. Duplicate data requests a
  fresh ACK, recovering a lost final ACK through the sender's timeout. Due ACKs
  and data alternate when both are ready, preventing a perpetual feedback stream
  from starving the data queue. Outer admission still accounts every packet.
- Eligible first sends and retries alternate after successful source emission.
  Each class retains its own lowest source or earliest due deadline. Failed
  output preflight does not consume the turn, and fresh service does not move
  an old source's retry deadline. This prevents continuous due retries from
  starving originals already admitted to the finite send window. Compact uses
  its separate selected algorithm. This finite fairness correction is not proof
  that the legacy Packed runtime pressure timeout is resolved.
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

## Wide ACK for large windows

Decided 2026-11-23 (owner, option 1): the 64-bit bitmap limited every base-ARQ
profile to 64 records in flight. Aligned and Packed rows then measured about
4.5 Mbit/s on the 100/10 Mbit/s, 70 ms RTT lab with no loss, against 44 Mbit/s
for the same Aligned code over Compact ARQ. Classic ARQ behaviour and the
optional Cauchy FEC above it stay unchanged; only the window and its feedback grow.

- `send_records` and `receive_records` accept 1..=8192. A direction whose
  configuration has both values at most 64 keeps the original ACK bytes, packet
  kind 2 and the 20-byte body maximum, so existing configurations, digests and
  control channels are byte-identical.
- A direction with either value above 64 uses the wide ACK. Both peers derive
  the format from the same authenticated direction configuration: the ACK
  emitter reads its receive configuration, the ACK parser its send configuration.
  Nothing is negotiated on the wire, and a legacy ACK in a wide direction (or
  the reverse) is malformed.
- Wide ACK: the cumulative next-missing prefix, then a bitmap of `n` bytes in
  which bit `i % 8` of byte `i / 8` acknowledges `prefix + i`. The bitmap is
  canonical: bit zero is clear, the last byte is nonzero (or `n` is zero), and
  `n <= ceil(receive_records / 8)`. The packet form is kind 3: the 32-byte common
  header, the 64-bit prefix, then the bitmap, `40 + n` bytes in total. The
  context-free body is the varint prefix followed by the bitmap bytes.
- Per-configuration maxima replace the fixed constants for budgets:
  `ArqConfig::ack_packet_bytes()` (48 or `40 + ceil(receive_records / 8)`) and
  `ArqConfig::feedback_body_max_bytes()` (20 or `10 + ceil(receive_records / 8)`).
  Callers charge feedback with these, never the legacy 48/20 constants alone.
- Large windows store sources by `source % window`. The existing span limits
  (send: oldest unconfirmed to next source; receive: next delivery plus window)
  keep every live source in a distinct slot, so lookups stay O(1). Windows of at
  most 64 keep the original storage.
- Management, OpenVPN-like and UDP control channels keep windows of at most 64;
  their fixed feedback charges are unchanged and their configuration validation
  refuses a wide window.
- Direction-aware parsing: `inspect_packet_for` and `inspect_body_for` take the
  acknowledged direction's configuration; `SelectiveRepeat::inspect_peer_body`
  applies an owner's own pair. `inspect_packet` and `inspect_body` keep parsing
  only the legacy form.
- Reliable charges each direction with its own maximum: local output ceilings,
  scratch and storage plans include the receive direction's ACK, peer ceilings
  the send direction's ACK, so asymmetric legacy/wide pairs fit. Restored-source
  staging is capped at `MAX_ARQ_WINDOW + 256` packets and 16 MiB. Staged
  diagnostics keep the first 64 offsets in `bitmap` and the wide length in
  `bitmap_bytes`.
- The Aligned and Packed benchmark rows size the window from the lab's
  bandwidth-delay product (12.5 MB/s × 70 ms in full sources, tripled for loss
  and RTO recovery, rounded up to a power of two). That is 2048 for the UDP and
  raw carriers. The aligned receiver's source window grows to hold the ARQ window
  plus restored sources.

## Adaptive resend and O(1) scheduling for wide windows

Decided 2026-11-23 (owner): a fixed 200 ms first resend, doubling per retry,
left wide-window Aligned at 0.9–1.4 Mbit/s at 15% loss on the 70 ms lab. Base
ARQ gets an adaptive timer and fast resend, **only in directions above 64
records** (the same boundary as the wide ACK). Windows of at most 64, including
every control channel, keep the classic timer exactly.

- RTT samples come from authenticated ACKs. A flight released by an ACK after
  exactly one attempt yields `now - sent_at`, where `sent_at` is when its retry
  timer was armed (poll time, or the physical acceptance time under physical
  confirmation). Retried flights give no sample (Karn).
- Smoothing follows RFC 6298: the first sample sets `srtt = R` and
  `rttvar = R / 2`; later samples set `rttvar = 3/4 rttvar + 1/4 |srtt - R|`
  and `srtt = 7/8 srtt + 1/8 R`.
- `RTO = srtt + 4 rttvar + ack_delay`, at least `min(20 ms, initial_rto)` and
  at most `maximum_rto`. Before the first sample the RTO is `initial_rto`.
  A timeout resend doubles that flight's timer, capped at `maximum_rto`.
- Fast resend is ordered by transmission, not by wall time. Every transmitted
  copy gets the next transmission serial. An ACK raises the highest
  acknowledged serial using only sources released after exactly one copy
  (Karn: a re-sent source does not say which copy arrived). A confirmed,
  unacknowledged copy with serial `t` becomes due now once that highest serial
  reaches `t + 3`. Its next timer uses the current RTO without doubling, and
  `max_retries` applies to every resend. The first version waited one
  smoothed RTT instead; when queueing pushed the real RTT above srtt it
  re-sent copies still queued, counted each as an attempt and exhausted
  retries within about two seconds (native Packed `RetryExhausted`,
  reproduced by `packed_wide_window_survives_queue_inflated_rtt_with_drops`).
- Copies wait for that evidence in a transmission-order queue (lazy deletion,
  reserved at twice `send_records`, compacted to current copies when full), so
  each copy is examined once.
- A wide ACK without diagnostic observation visits only what it covers: the
  retained sources below its prefix (from the oldest-retained pointer) and its
  set bitmap bits. It validates all of them before changing state. The
  observed path keeps the original whole-window passes, and a randomized test
  checks that both give identical results, state and output.
- Scheduling is O(1) amortized per operation in wide directions: a deadline
  queue (binary heap with lazy deletion, reserved at twice `send_records` and
  rebuilt from live flights when full), pointers to the oldest retained and the
  first unsent source, and the highest received source for exact ACK sizing.
- Reliable's restored-source staging keeps occupancy, live and free lists, so
  its operations cost O(live entries) rather than O(capacity).
- A wide receive direction keeps a receipt journal: each newly stored source
  with an arrival serial, in a ring reserved at `receive_records`. Early
  consumers (Aligned/Packed preview of independent short frames) read
  receipts after their own cursor in O(1) instead of rescanning every receive
  slot on each pump; a pressure stop leaves the cursor before the refused
  receipt. A cursor that fell out of the ring, or a Compact owner, falls back
  to the original full scan. Native profiling had shown that scan at 14–52%
  of daemon CPU with a 2048-record window.

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
- [ ] [MOD-REC-WIDE-01] Widen base-ARQ windows to 8192 with the canonical wide ACK, per-configuration feedback maxima and indexed storage, keeping windows of at most 64 byte-identical; test encode/parse limits, canonical rejection, cross-format refusal, acknowledgement past offset 64 and lossy transfers with large windows.
- [ ] [MOD-REC-WIDE-02] Charge wide feedback in every base-ARQ consumer (Reliable envelopes and geometry, selected Common wire, runtime contracts), keep control channels at windows of at most 64, size Aligned/Packed benchmark windows from bandwidth and RTT, and qualify the result natively.
- [ ] [MOD-REC-WIDE-03] Make wide-window scheduling and Reliable restored staging O(1) amortized per operation (deadline queue, oldest/unsent pointers, highest received, restored live/free lists), with storage plans charging the new reservations; measure the per-source cost at window 64 and 2048.
- [ ] [MOD-REC-WIDE-04] Add the adaptive RTO (RFC 6298 smoothing, Karn, 20 ms floor) and transmission-order fast resend to wide directions only, keeping windows of at most 64 on the classic timer; test sampling, backoff, fast resend under queue-inflated RTT and the unchanged classic path, then qualify Aligned/Packed natively at 0% and 15% loss.
- [ ] [MOD-REC-WIDE-05] Make wide ACK processing and early preview independent of the window (covered-source ACK path with an equivalence test against the observed path; reserved receipt journal with cursor-based preview), with storage plans charging the journal and send-order queue; profile natively.
- [ ] [MOD-REC-16] Integrate authenticated datagram carriers, negotiated peer source/window budgets, shared QoS/credit budgets and real namespace/netem receipts.
- [x] [MOD-REC-17] Expose separately pollable source/feedback and authoritative borrowed packet inspection for bounded FEC composition. Evidence: [engine APIs](../../crates/l2tunnel-recovery/src/arq.rs), [split-poll ownership and inspection regression](../../crates/l2tunnel-recovery/src/arq/tests.rs).

- [x] [MOD-REC-18] Bound first-send service when retries stay continuously due, preserving original retry deadlines and transactional output preflight. Evidence: [Cases16](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-16/validation.json) passes all nine physical-custody cases, including real allocated/reserved owners and genuine peer ACK release. The enclosing build failed in unrelated fixture borrow checks; only its completed immutable recovery artifact was executed.

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
