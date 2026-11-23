# Rolling delivery policy: per-flow native release and return-traffic guard

Status: contract-tested (DP-01..DP-07). This document preceded the code.
Nothing here is native qualification; DP-08 is the owner's privileged
measurement and remains open.

## Problem and evidence

One inner Linux CUBIC flow over a targeted rolling TUN direction at 15% loss,
70 ms RTT and 100/10 Mbit/s produced 4.5–70 Mbit/s with the same seed and binary
([repeat receipts](../../work/raw-udp-near8-repeat-20261122/reports/mechanism.md)).
The decoded sender `tcp_info` in those receipts shows:

- The receiver delivered complete TCP data across sequence gaps. Receiver
  `tcpi_rcv_ooopack` reached thousands, and 80–100% of sender retransmissions
  were later DSACKed, so they were spurious.
- Slow runs took a cwnd cut below the path BDP (about 490 segments) within the
  first second that DSACK did not undo (ssthresh 12–207), then regrew at
  3.5–6.7 segments/s.
- The reverse sender's socket-accepted IP bytes were 9–25% of delivered forward
  payload on a 10 Mbit/s return link. Extra physical copies of reverse sources
  were the largest share, then regular repairs, then feedback records.

The release decision is in `rolling_records/native.rs`: targeted IP directions
call `prepare_with_independent_packets` with
`fin_order::Guard::independent_ip_decision`, whose `Edge::permits` skips the
contiguity check. The Python oracle releases a channel in record order and lets
only short self-contained records go early (`aligned_records.py`).

## Owner selections (2026-11-22)

The owner selected each of these in a separate question:

1. Release unit: per-flow TCP order, reusing the existing TAP decision for TUN.
2. Selection: a separate authenticated per-direction field in the canonical
   configuration encoding and digest, independent of `SourceWire`.
3. Wait bound: no new timer. A held segment waits until its gap is repaired or
   the record expires under the existing authenticated lifetime.
4. Return guard: adaptive shedding. Extra copies are shed first, then
   proactive (regular) repairs. First copies, feedback, requested retries and
   control are never shed. Local sender policy with no packet-format change.
5. Defaults: both are the default for targeted TUN directions. Independent
   release remains explicitly selectable and the guard can be turned off.

## Configuration

`DirectionConfig` gains two fields.

`native_release: NativeRelease`

| Value | Wire word | Meaning |
|---|---|---|
| `Default` | 0 | `FlowOrdered` on a targeted IP direction without the Hold35 selector; otherwise the existing behaviour |
| `Independent` | 1 | Existing release of complete TCP data across gaps |
| `FlowOrdered` | 2 | Per-flow TCP order (below) |

Explicit `Independent` and `FlowOrdered` require a targeted IP direction and
reject the Hold35 selector, which keeps its own bounded hold.

`return_guard: ReturnGuard { mode, per_mille }`

| Mode | Wire | Meaning |
|---|---|---|
| `Default` | 0 | On at 100‰ for a targeted IP direction; otherwise off |
| `Off` | 1 | Measure only; never shed |
| `On` | 2 | Shed above `per_mille` (1..=1000) |

`per_mille` is 0 unless the mode is `On`.

Encoding. The CompleteV2 descriptor size is unchanged. Tags 4 and 5 carry only
all-default values and keep their exact bytes. Tags 11 (Rolling) and 12
(RollingCopies) are the same layouts, except that the upper 32 bits of each
direction's `stream` word (a `u32` today, so those bits were always zero) carry
`release (8) | guard mode (8) | per_mille (16)`. The encoder selects 11/12 only when
some field is non-default; the decoder rejects all-default values under 11/12,
so the canonical re-encoding stays unique. Research (tag 9) and other profiles
accept only default values.

Digest. `Config::digest` is unchanged when both directions are default. Otherwise
it appends a domain-separated block with each direction's three values,
following the `CopyPolicies::ONE` legacy-binding pattern. Both behaviours are
local to one endpoint (receiver release order and sender redundancy), so peers
running different binaries remain wire-compatible.

## DP release: per-flow TCP order

`fin_order::Guard` gains a third decision mode beside the TAP decision and the
independent decision:

- SYN, FIN and RST: `Ordered`, as in the independent mode.
- TCP with payload: `Allow` only when the flow's edge is proven, live and the
  segment does not start after the edge (`!after(seq, next)`). Otherwise
  `Wait(token)`, re-evaluated when that flow's edge version changes.
- Unclassified: `Ordered`. Other short packets: `Allow`. Other packets: `Ordered`.

`native.rs` uses `prepare_with_independent_packets` with this decision when the
effective release is `FlowOrdered`. The codec consults the decision only for
records ahead of the channel head, and the head is always delivered in order.
So an expired or unrepaired record lets the channel advance, and its successors
then leave in channel order. An inner retransmission that fills the gap advances
the edge and wakes waiting records. No timer, queue or allocation is added.

The divergence from the oracle's channel FIFO is that another flow on the same
channel is not blocked by this flow's gap. With one flow per channel the two are
the same.

## DP guard: return-traffic guard

A bounded `return_guard::Guard` per endpoint uses only injected ticks. Eight
125 ms buckets form a 1 s window holding:

- `D`: native bytes the local receiver committed to the device (traffic from the peer);
- `U`: accepted wire bytes of first copies of local sources;
- `R`: accepted wire bytes that are never shed (feedback, requested retries,
  quiet probes, tail repairs);
- `E`: accepted wire bytes of sheddable extras (source copies after the first,
  regular repairs).

With budget `B = per_mille × D / 1000`, the guard is engaged only while `U ≤ B`,
i.e. while this direction acts as a return path. A bulk sender is never engaged,
so its repairs are untouched. While engaged, an extra of estimated `w` bytes is
allowed only if `U + R + E + w ≤ B`.

- Copies: at source admission the endpoint lowers the requested copy count to
  one when the extra copies would not fit.
- Regular repairs: the existing `send_step_filtered` and `confirm_priced_copy`
  closures displace a regular repair the guard refuses, before the retry-credit
  budget is consulted.

Startup floor. The guard stays disengaged while `B` is below 16 KiB
(`MIN_BUDGET_BYTES`). Without it, a direction that has delivered nothing yet has
`B = 0 ≥ U = 0` and would shed every copy and repair of its first packets; the
floor keeps that startup redundancy until about 160 KB/s of peer traffic has been
delivered at the default ratio. This was found by the existing ACK LZ4 copy tests
while implementing DP-05.

Status: requested and effective mode, ratio, engaged, window `D/U/R/E`, and shed
counts and bytes for copies and repairs. `Endpoint::delivery_status`,
`Engine::rolling_delivery`, the runtime snapshot's `rolling_delivery` and the
client-core Common status field `rolling_delivery` carry the requested and
effective release with the guard status.

## Acceptance

- [x] [DP-01] Implement `NativeRelease` and `ReturnGuard` with default resolution and validation, tags 11/12 using the stream word's upper bits, and the digest extension; test round trips, legacy tag 4/5 byte identity, and rejection of all-default values under 11/12, overrides on unsupported directions, and invalid ratios. Evidence: [tag 11/12 round trips, rejections and digest](../../crates/l2tunnel/src/record_configuration/rolling_tests.rs) (`delivery_policy_selects_tags_11_and_12_and_round_trips_canonically`); the unchanged literal tag 4 words test keeps default byte identity.
- [x] [DP-02] Add the per-flow TCP order decision to `fin_order`; test gap-crossing data waiting, contiguous data, other flows, short ACKs, SYN/FIN/RST, unproven flows and wake on edge advance. Evidence: [decision comparison](../../crates/l2tunnel/src/rolling_records/fin_order_tests.rs) (`flow_ordered_decision_differs_from_independent_only_across_gaps_and_keeps_close_ordered`).
- [x] [DP-03] Dispatch the effective `FlowOrdered` release in `native.rs`; endpoint test that a gap holds later data of that flow, short ACKs pass, and expiry or an inner retransmission resumes in-order delivery. Evidence: [endpoint flow-ordered release](../../crates/l2tunnel/src/rolling_records/fin_order_tests.rs) (`flow_ordered_tun_holds_gap_crossing_data_but_releases_other_flows_and_short_acks`); the independent test now pins `NativeRelease::Independent`.
- [x] [DP-04] Implement the bounded return guard; unit tests for window expiry, the engagement rule, shedding order, never-shed classes and counter saturation. Evidence: [guard unit tests](../../crates/l2tunnel/src/rolling_records/return_guard.rs).
- [x] [DP-05] Integrate the guard in the endpoint at native commit, output acceptance, copy admission and both regular-repair displacement closures; endpoint tests that copies and regular repairs are shed only while engaged. Evidence: [endpoint shedding and delivered accounting](../../crates/l2tunnel/src/rolling_records/ack_lz4_tests.rs) (`return_guard_sheds_ack_copies_and_regular_repairs_only_while_engaged`, `return_guard_counts_committed_native_bytes_from_the_peer`).
- [x] [DP-06] Expose requested and effective release and guard status through the endpoint and the client-core Common status. Evidence: [client-core status](../../crates/l2tunnel-client-core/src/secure_udp/common_status.rs) `RollingDelivery`, fed by the runtime snapshot.
- [x] [DP-07] Record the per-flow divergence in `docs/mode-parity.md` and update the checklist and implementation status with the commands actually run. Evidence: [mode parity note](../mode-parity.md), [checklist entry](../implementation-checklist.md), [status entry](../implementation-status.md); local Linux gate run in the integration tree with simulator steps skipped (no simulator environment).
- [ ] [DP-08] Owner native qualification: single flow, raw and UDP, at least five seeds with repeats, recording ssthresh at 0.5 s and 1 s, HyStart counters, receiver out-of-order packets and the return/forward byte ratio.
