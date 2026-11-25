# Session receiver credit

Status: implemented and contract-tested in the Common runtime
(MOD-RCREDIT-01..06) and integration-tested natively on a few cells; full
native qualification is open (MOD-RCREDIT-07). Design recorded before code
(2026-11-23); the sections below include the changes made while testing.

## Problem and owner decisions

Native Packed ARQ with 16 inner flows at 0% loss failed with `PeerTimeout`
([receipts](../../work/wide-ack-20261123d/prof/RESULTS.md)). The receiving
daemon's single owner thread could not keep up: its UDP socket dropped 31% of
datagrams (`RcvbufErrors` 24,696 of 56,060), and a liveness ping was lost on
every control retry. The ARQ window bounds records in flight, not how fast the
receiver processes them, and ARQ acknowledges a record when it reaches the ARQ
buffer, before the costly profile decode. Nothing told the sender to slow down.

The owner decided, one question at a time (2026-11-23):

1. The receiver grants a **processed window plus its measured drain rate**. The
   window bounds sustained overrun; the rate bounds bursts.
2. **Session level, every Common data profile** (Aligned, Packed, Rolling,
   Swift and later ones). Profiles do not implement credit themselves.
3. Credit travels as an **unreliable authenticated Credit message** inside the
   Control record. It is never retransmitted; the newest value wins.
4. The window counts **data datagrams and data wire bytes**. Control and data
   feedback (ACK) datagrams are never gated or charged, so credit cannot block
   its own return path or the liveness service.
5. **The receiver computes the window** from its machine and path, within a
   floor and ceiling from the authenticated session configuration.

Credit is a required part of the Common contract (no legacy fallback; the owner
stated that no old binaries are in use). Its configuration is bound into the
session configuration digest.

## Terms

- *Data datagram*: an authenticated Common datagram of class User that is not
  data feedback. Its packet number comes from the sender's data counter
  (`Records::next_number(Class::User)`; in proxy short-tag mode the shared
  feedback counter, `secure_record_compact.rs`).
- *Processed*: the receiver's owner has finished handling an authenticated data
  datagram, meaning the engine accept returned, whatever the outcome (accepted,
  duplicate, stale, discarded or refused for native backpressure)
  (`receive_common_user_observed`, `transport_common_io.rs`). A datagram that
  fails authentication is not counted.

## Wire message

`Credit` is a fixed 64-byte body inside the existing Control record, sealed
with `Class::Control` and therefore authenticated, replay-protected and charged
to the shared session allowance like every control datagram. It is carried
beside, not inside, the reliable L2CF streams: a distinct canonical tag that the
control receive path checks before `streams::Frame::decode`, so it never enters
a stream's SelectiveRepeat and never waits behind a gap.

| Bytes | Field |
|---|---|
| 0..4 | `L2CR` |
| 4 | version 1 |
| 5..8 | zero |
| 8..16 | `serial`: strictly increasing per sender of Credit, starting at 1 |
| 16..24 | `processed`: highest processed data packet number, plus one (0 = none yet) |
| 24..32 | `limit`: the peer may send data packet numbers below this value |
| 32..40 | `bytes_above`: maximum data wire bytes the peer may have sent above `processed` |
| 40..48 | `drain_bytes`: measured processed data wire bytes per second |
| 48..56 | `drain_datagrams`: measured processed data datagrams per second |
| 56..64 | zero |

Big-endian integers. Rejected: other versions, nonzero reserved bytes, wrong
length, `limit < processed`, or a `limit`/`processed` that moves backwards with
a higher serial. A Credit with a serial at or below the newest accepted one is
counted as stale and ignored. A Credit never grants anything by itself beyond
the data window; it is not management authority.

## Receiver

Per receive direction the owner keeps, in reserved storage with no per-packet
allocation:

- `processed`: highest processed data packet number + 1. Lost packets never
  hold it back, because it follows the highest number, so loss cannot leak
  credit.
- A drain estimate in 8 bins of 25 ms: processed data bytes, processed data
  datagrams and the advance of `processed`. The rate uses the maximum of the
  completed-bin average since the first processed datagram (at most 175 ms) and
  the best contiguous two-bin (50 ms) burst rate, while still returning zero
  once all completed bins are empty. Holding the best two-bin rate prevents a
  brief 1-RTT ARQ recovery pause from slashing the grant and pacing rate, while
  steady slow receivers still report their true drain rate. The datagram rate
  follows the advance of `processed`, which counts lost packets too, and the
  byte rate is scaled by the same ratio. The grant is in the sender's packet
  numbers, so it must cover what the sender has in flight, lost packets
  included; counting only arrivals shrank the window by the loss rate every
  round trip.
- `allowance`: half of the data socket's actual `SO_RCVBUF`, read back once from
  the kernel at runtime entry (`socket2::SockRef::recv_buffer_size`), capped
  at 106,496 bytes. Linux reports twice the set value, and small datagrams cost
  more than their length, so half is the payload it can hold without drops.
  The raw and carrier paths have no UDP socket to read and use 106,496 bytes,
  half of Linux's default receive buffer; status reports which one is in use.
- Receive and send buffers: before that read-back, `credit_observe_udp` requests
  a receive buffer of `ceiling_bytes` (using `SO_RCVBUFFORCE` on Linux when
  `net.core.rmem_max` would cap it; the daemon holds `CAP_NET_ADMIN` for TUN)
  and also requests `SO_SNDBUF` up to 4 MiB so high-BDP bursts do not hit small
  default kernel send buffers. Credit can let up to `ceiling_bytes` be in flight,
  so a receive buffer that holds it keeps a receiver stall from overflowing the
  socket; the kernel charges only queued bytes. Without the request, every UDP
  cell ran on the 212,992-byte default and the Packed receivers dropped up to
  8.9% of datagrams (`work/full-matrix-20261123`). The allowance stays capped:
  it is the grant's headroom over the measured drain, and an uncapped 16 MiB
  allowance removed credit's limit and flooded the bottleneck queue
  (`work/credit-20261124b/RESULTS.md`). Status and buffer metrics report the
  requested size and the raw read-back.

The grant is

```text
avg_datagram_bytes = clamp(completed_bytes / completed_datagrams, 256, 1024)   (1024 when none)
window_bytes       = clamp(drain_bytes     * (min_rtt + period) + allowance,                          floor_bytes,     ceiling_bytes)
window_datagrams   = clamp(drain_datagrams * (min_rtt + period) + allowance / avg_datagram_bytes + 1, floor_datagrams, ceiling_datagrams)
limit              = processed + window_datagrams
bytes_above        = window_bytes
```

`drain * min_rtt` covers what is legitimately still in the network, and one
`period` covers the sender seeing `processed` up to one Credit late. The
allowance is what may queue at the receiver, and it also lets the grant grow:
a window-bound sender achieves `window / rtt`, which exceeds the measured drain
whenever the receiver has headroom. `min_rtt` is the minimum of this endpoint's
RTT samples (see [Sender](#sender)) over the last 10 s. Before any sample it is
zero, so the grant is `allowance`, clamped by floor and ceiling.

(At decision 5 the owner was offered `min(socket buffer, drain × SRTT × 2)`.
Packets in flight do not occupy the receive buffer, so capping the window at the
socket buffer would cap throughput at about `buffer / RTT`. The formula above
uses the same inputs: the receiver's socket buffer, its drain rate and the RTT.)

While the native pending queue (`NativeBudget`) is full, the receiver freezes
`limit` and `bytes_above` at their last sent values instead of growing them,
because accepting more data would only turn into native backpressure drops.

Sending: nothing is due before the first processed data datagram (the sender
starts with the floor, so an idle session sends no credit). Afterwards a new
Credit is due when `limit` grew by at least a quarter of `window_datagrams`
since the last one sent, or `period` has passed since the last one sent and a
data datagram was processed during that period. When traffic stops, the
receiver transitions immediately to idle and sends a heartbeat Credit starting
at `idle_period` with exponential backoff up to 10 s (`MAX_QUIET_IDLE_PERIOD`)
so an idle session emits minimal traffic. Credit takes the
control slot before the reliable streams: at the top of `prepare_control`
(UDP and carrier send loops) and in the single raw management slot
(`prepare_raw_management`), so every path sends it. On receipt it is
recognized by its tag before `streams::Frame::decode`.

## Sender

Per send direction, in reserved storage:

- The newest accepted Credit (`serial`, `processed`, `limit`, `bytes_above`,
  drain rates), initialized from the configuration: `limit = first data packet
  number + floor_datagrams`, `bytes_above = floor_bytes`.
- An in-flight ring of `(packet number, wire bytes, sent_at)` for data datagrams
  sent above the peer's newest `processed`, reserved at `ceiling_datagrams`.
  Entries at or below `processed` are retired when a newer Credit arrives.
  `inflight_bytes` is the sum over the ring.

Data may be prepared only when

```text
in-flight datagrams < window       (window = limit - processed of the newest Credit)
inflight_bytes + maximum data datagram wire bytes <= bytes_above
the data pacing bucket holds at least one maximum data datagram
```

The first version compared the next packet number with `limit`. When an
outage lost the whole in-flight tail, nothing arrived, `processed` and the
limit never moved, and the sender's data (ARQ retransmissions included)
stayed blocked until the receiver expired (native Packed, 16 flows). Now a
Credit that shows the receiver idle (zero drain) with no progress declares
lost every in-flight datagram sent more than one minimum RTT plus one period
earlier (the idle period before any RTT sample). An idle receiver has nothing
queued, so those datagrams cannot still be waiting; the idle heartbeat bounds
recovery to about one `idle_period`. Counting in-flight datagrams instead of
packet numbers lets those declared losses free the window.

This is folded into `allow_data` at `prepare_common_wire_for`
(`transport_common_io.rs`), which every engine already treats as
"feedback only". Blocked data stays in the profile's existing bounded queues and
admission refuses new input, so native backpressure reaches the TUN/TAP reader
as before. The shared session `bucket` and its control `reserve` are unchanged.
Feedback still uses the whole allowance.

The pacing bucket is separate from the session bucket and charges data
datagrams only. Its rate spreads the byte window over one round trip:
`max(drain_bytes × 5/4, bytes_above / (min_rtt + period))`, capped by the
configured send rate. Before any RTT sample it is `drain_bytes × 2`, and before
any drain it is the configured rate. Pacing at a fixed gain over the drain let
each Credit release its window as a burst (the modeled socket queue swung by
the drain over one Credit interval), and a gain of 5/4 alone took seconds to
reach the receiver's real rate. The allowance term keeps the rate above the
drain while the receiver has headroom. Its pacing burst (`pacing_burst`) scales
to 5 ms of the configured send rate (capped at 2 MiB, with a floor of
`16 * max_datagram`) so high-BDP sessions (200–1000 Mbit/s) do not stall
between loop turns. Live speed-budget updates (`ProfileTag::RateBudgetV1`)
adjust the active pacing rate and credit ceiling in place via
`set_configured_rate`, `raise_ceiling`, and `raise_ceiling_for_rates`. When
data is credit- or
pacing-blocked, the send loop's wake (`wake_common_with_custody`) includes the
pacing bucket's ready time; a newly accepted Credit wakes the loop.

RTT samples: when a Credit advances `processed` past a ring entry, that entry's
`now - sent_at` is one sample (the newest such entry only). It includes the
receiver's queueing, which is intended. The minimum over 10 s feeds this
endpoint's own grant as a receiver (the same path in the other direction).

Liveness and recovery: a lost Credit is replaced by the next one. If the peer
stops sending Credit, the sender keeps its last `limit` and stops at it, and
liveness (`pong_timeout`) decides whether the session is dead. Credit never
causes a terminal error by itself.

An idle session sends no Credit: the receiver issues the first one after its
first processed data datagram, and the sender starts from the floor.

## Key-generation range (owner decisions 2026-11-23)

Root cause of a data blackhole after burst loss: the compact record receiver
(`l2tunnel-security/src/compact/receive.rs`, `open`) holds keys only for the
current and next generation and rejects with `Error::Generation` any packet
number more than `range = min(packets_per_key, max_forward_packets)` above the
highest number it accepted. A sender keeps numbering through an outage; once
more than `range` consecutive datagrams of one counter are lost, every later
one is rejected (`rejected_packets`), `highest` never moves and that direction
carries no data again, while control and liveness, which use their own
counter, stay up. Found with runtime fixtures that rotated keys every 8
packets; production plans use 2^28.

Owner decisions: the sender stays inside the range, and configuration makes the
range large enough that the bound never throttles normal traffic.

- Sender bound: with `ahead = number - peer_processed`, where `peer_processed`
  is the newest Credit's processed number (the first data number before any
  Credit), data is gated (`Gate::Credit`, counted as `range_blocked`) at
  `ahead >= range / 2`. The upper half is a probe reserve: after each accepted
  Credit one data datagram may enter it (`range_probes`), and nothing is sent
  at `ahead >= range - 1`, the last number the receiver can open if everything
  since `processed` was lost. Without probes, a lost tail at the bound left
  nothing to advance `processed` and the gate never reopened (seen in the first
  runtime test). In a two-way outage no Credit arrives, so no numbers are
  spent; in a one-way outage each heartbeat spends one, so the reserve lasts
  `range / 2` idle periods, beyond the liveness timeout once the floor holds
  for production ranges. Compact data uses its own counter (feedback and
  control have separate ones), so ungated feedback never spends this range.
- Floor, clamped (owner decision 2026-11-24, replacing the 2026-11-23
  refusal): when `range < 4 * ceiling_datagrams`, the runtime runs with
  `ceiling_datagrams = range / 4` (and a floor above it lowered to match,
  `Config::fit_range`), warns once on stderr naming both values and the fix,
  and reports requested and effective datagrams in status and in
  `inspect-common-transaction-plan` (`credit` block, with the warning text).
  Half the range is then still at least twice the effective window, so the
  bound binds only when the peer stops processing. Contract validation
  (`new_compact_wire`, `new_on_carrier_paired_compact`) refuses only a range
  below 64, where no valid window (floor at least 16) fits. Both peers derive
  the same effective ceiling from the same authenticated limits. Defaults:
  2^28 against 4 * 8,192, unchanged.
  Runtime test fixtures move from `packets_per_key: 8` to 8,192 with a credit
  ceiling of 2,048; shorter key-rotation intervals stay covered by the security
  crate's own tests.

## Configuration

`credit` in the Common runtime configuration (required, `deny_unknown_fields`,
bound into `common_resource_digest` under its own domain tag):

| Field | Meaning | Bounds |
|---|---|---|
| `floor_datagrams` | initial and minimum window | 16..=ceiling |
| `ceiling_datagrams` | maximum window and in-flight ring size | ..=65,536 |
| `floor_bytes` | initial and minimum byte window | ≥ 16 × maximum datagram |
| `ceiling_bytes` | maximum byte window | ..=64 MiB |
| `period_micros` | Credit repeat period while data flows | 1,000..=100,000 |
| `idle_period_micros` | heartbeat period without data | period..=1,000,000 |

The benchmark plans size the ceiling from bandwidth × RTT like the ARQ window
(`bdp_window`) with the same 3× margin, the floor at 64 datagrams and 64 maximum
datagrams of bytes, `period` 10 ms and `idle_period` 250 ms.

## Observability

Both send and receive directions report in Common status and buffer metrics:
the effective `limit`, `bytes_above`, `inflight_bytes`, the peer's drain rates,
the pacing rate, time spent credit-blocked and pacing-blocked, Credits sent,
accepted and stale, the frozen-grant time and the current `min_rtt`. Requested
(configured) and effective values stay separate, as for carrier and cover.

## Tasks and acceptance

- [x] [MOD-RCREDIT-01] Implement the Credit codec in a pure library crate: canonical encode/decode, every rejection above, golden bytes and truncation tests. Evidence: [codec](../../crates/l2tunnel-flow-control/src/session_credit.rs), [tests](../../crates/l2tunnel-flow-control/src/session_credit/tests.rs).
- [x] [MOD-RCREDIT-02] Implement the receiver state (processed, drain bins, grant formula, freeze, due rule) and the sender state (newest Credit, in-flight ring, gate, pacing rate, RTT samples) as pure, clock-injected types with bounded reserved storage; test loss not leaking credit, reordering, stale and backwards Credits, window growth with headroom, the floor at startup and freeze under native backpressure. Evidence: [state and tests](../../crates/l2tunnel-flow-control/src/session_credit/tests.rs); a modeled 70 ms path with 20% loss of data and Credit and a receiver draining at a third of the sender's rate has no socket drops and reaches at least 95% of the drain rate in steady state.
- [x] [MOD-RCREDIT-03] Add `credit` to the Common configuration with validation, digest binding and CLI/plan parsing; reject a missing or out-of-bounds block. Evidence: [validation and digest](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_contract.rs), [CLI DTO](../../crates/l2tunnel-client-core/src/secure_udp/common_runtime_cli.rs), [benchmark plans](../../crates/l2tunnel-client-core/examples/common_benchmark_plan.rs); runtime, client-core and flow-control suites pass (674 tests).
- [x] [MOD-RCREDIT-04] Integrate into the Common runtime: count processed data, read back `SO_RCVBUF`, send Credit in the control slot, accept it before the L2CF streams, gate `allow_data`, add the pacing bucket and wake; feedback and control stay ungated. Evidence: [runtime credit](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_credit.rs), [raw slot](../../crates/l2tunnel-runtime/src/secure_udp/transport_raw_send.rs).
- [x] [MOD-RCREDIT-05] Expose requested and effective credit state in status and buffer metrics. Evidence: [`CreditStatus`](../../crates/l2tunnel-client-core/src/secure_udp/common_status.rs) (carried in native `status_samples`); the buffer report's `credit` section and `CreditWindow` gauge (in-flight datagrams and bytes against the granted window), [observer](../../crates/l2tunnel-runtime/src/buffer_metrics/observer.rs), tested by `buffer_metrics_report_requested_and_effective_credit` in [runtime tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_credit_tests.rs).
- [x] [MOD-RCREDIT-06] Runtime tests in the two-driver harness, on Aligned and Packed: a receiver reading two datagrams per millisecond from its real socket gets every frame with no kernel drops and a queue bounded by the credit window, not the ARQ window (the test fails with the gate disabled); 10% seeded loss of every datagram in both directions, Credits included, delivers every frame with liveness checked each turn. Evidence: [runtime tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_credit_tests.rs). 35% loss exhausted the fixture's ARQ retry budget (4 retries) and is left to the native loss cells.
- [x] [MOD-RCREDIT-08] Sender range bound: `Sender::new` takes the authenticated range; the gate refuses data at `number - peer_processed >= range / 2` except one probe per accepted Credit below `range - 1`, and counts `range_blocked` and `range_probes`; status and buffer metrics expose them. Unit tests: the bound holds with no Credit, moves with a Credit's processed advance, admits exactly one probe per Credit, never reaches `range - 1`, and never binds inside a credit window when the floor holds. Evidence: [sender](../../crates/l2tunnel-flow-control/src/session_credit.rs), `sender_stays_within_half_the_receive_range` in [unit tests](../../crates/l2tunnel-flow-control/src/session_credit/tests.rs).
- [x] [MOD-RCREDIT-09] Floor: both compact contract constructors reject `min(packets_per_key, max_forward_packets) < 4 * ceiling_datagrams`, with focused rejection tests; fixtures move to 8,192 packets per key with a 2,048 credit ceiling, and key rotation through the whole Common UDP path stays covered at the floor interval (64 packets, `common_data_crosses_key_generations_at_the_floor_interval`). Evidence: `require_credit_range` in the [compact contract](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_wire_contract.rs), `compact_contract_enforces_the_credit_range_floor` (63 refused, 64 accepted with a 16-datagram ceiling) and the crossing test in [runtime tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_credit_tests.rs); client-core test selections moved from a forward limit of 8,192 to 32,768 and its test plan's ceiling to 2,048. The raw fairness test no longer crosses key generations (its raw carrier window allows about 20 packets without driver progress).
- [x] [MOD-RCREDIT-10] Outage regression: in the widened Aligned and Packed fixture at the floor interval (64 packets per key, credit ceiling 16, idle period 20 ms), a 400 ms one-way outage (side 0 to side 1 lost, heartbeats returning) delivers every frame with no `rejected_packets`, using range blocks and probes; with the range bound disabled the same run blackholes the data scope and ends in ARQ `RetryExhausted`. (A one-way outage over about 0.5 s expires liveness, as intended.) Evidence: `one_way_outage_keeps_data_within_the_receive_range` in [runtime tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_credit_tests.rs).
- [x] [MOD-RCREDIT-11] Clamp instead of refuse: `Config::fit_range` lowers the ceiling to a quarter of a small record-receive range; the runtime warns and runs with it, status reports `configured_datagrams` and `effective_datagrams`, and `inspect-common-transaction-plan` emits a `credit` block with the range, both values and the warning; ranges below 64 are refused. Evidence: `fit_range_clamps_the_ceiling_to_a_quarter_of_the_range` in [unit tests](../../crates/l2tunnel-flow-control/src/session_credit/tests.rs), `small_record_receive_range_clamps_the_credit_ceiling` (63 refused; 64 runs with ceiling 16 and delivers) in [runtime tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_credit_tests.rs), and the forward-limit 4,096 case in [CLI tests](../../crates/l2tunnel-client-core/src/secure_udp/common_cli_compact_tests.rs).
- [x] [MOD-RCREDIT-12] UDP receive buffer: the data socket requests `ceiling_bytes` (forced past `rmem_max` when permitted) before the allowance read-back; the allowance stays capped at 106,496 bytes; status and buffer metrics report the request and the raw read-back. Evidence: native cells in [work/credit-20261124b/RESULTS.md](../../work/credit-20261124b/RESULTS.md) (B read-back 32 MiB, 0 RcvbufErrors in all eight cells; packed-arq f4 64.8 to 85.6, f16 71.2 to 89.3, Packed compact f1 17-19 to 24-26) and the same runtime test's buffer assertions.
- [ ] [MOD-RCREDIT-07] Native qualification in owned namespaces: Packed ARQ 16 flows at 0% loss passes with no `RcvbufErrors` growth during the phase, and the Aligned, Cauchy and Packed cells from the 2026-11-23 reruns do not regress. Progress ([results](../../work/credit-20261123b/RESULTS.md)): Packed f16 0% passed twice (89.0 and 71.7 Mbit/s; failed before credit), with 0 and 1.3% receive-buffer drops (31% before); Packed f1 78.3 (46.4); Aligned f16 0% 85.5 (74.3); the 15% loss cells and Cauchy within their usual spread. Not ticked: one run still had 1.3% kernel drops, and each cell ran once or twice.
