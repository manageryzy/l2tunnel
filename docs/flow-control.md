# TUN active flow control and cross-flow QoS

Status: design and policy contracts only. The active controller, TCP proxy and QoS
scheduler are not implemented. This document adds requirements beyond the Python
experiments; their throughput numbers do not validate these mechanisms.

## Profiles and ownership

| Profile | Packet service | Window/controller ownership |
| --- | --- | --- |
| `tap_system` | Transparent Ethernet, including VXLAN payloads | Preserve endpoint TCP and system queueing algorithms. Use normal bounded tunnel queues and carrier pacing; do not rewrite inner ACK/window fields or enable the custom active TCP controller. |
| `tun_active` | Routed IPv4/IPv6 | Active tunnel credit, pacing and per-flow QoS; endpoint TCP sequence/ACK/window values stay unchanged. |
| `tun_tcp_proxy` | Routed IP with explicitly selected TCP termination | Own TCP legs through an embedded TCP stack/proxy, so the library can control real TCP receive-window admission as well as tunnel credit. UDP and unsupported protocols retain native IP forwarding. |

A new TUN profile selects active credit/QoS; actual TCP acceleration is a separate
explicit profile and a required implementation deliverable. Existing imported
transparent configurations never silently become proxies. TAP always retains
system TCP algorithms. TAP QoS integration uses the platform scheduler, with the
same measurable class goals; it does not adopt the custom TUN credit controller.

TUN supplies IP packets; it does not own the application's TCP congestion window.
TCP's `cwnd`, peer-advertised `rwnd`, our tunnel byte credit and the carrier's own
congestion window are separate. Raising a receive window cannot force a remote
sender to exceed its congestion window. No transparent packet-header edit is
advertised as controlling all these windows.
[Linux TUN/TAP](https://docs.kernel.org/networking/tuntap.html),
[TCP congestion control](https://www.rfc-editor.org/rfc/rfc5681.html)

## Active-credit algorithm to prototype

The goal is to let a few demanding flows consume idle capacity rapidly, then
actively slow admission when receiver or queue pressure appears. It is not to
fill unlimited buffers or bypass congestion control.

Track each direction separately: demand-bearing flow count, delivered bytes,
unique admitted bytes, received/released offsets, repair/retry wire bytes, queue
bytes and packet counts, queue sojourn percentiles, receiver reserved memory,
delivery-rate estimate, minimum and smoothed RTT, ECN/loss and carrier stalls.
A connected but idle socket does not count as a demanding flow. Apply activity
hysteresis so many short connections cannot oscillate the controller.

Negotiate connection and per-flow byte and record-count limits. Authenticated
credit updates carry cumulative maximum offsets, session/epoch/flow identity,
update serial and a bound on newly admitted records. Reserve receiver memory for
all outstanding grants, including granted bytes that have not arrived. Duplicate
or reordered updates cannot recreate credit; retiring a flow has an authenticated
final offset and generation. Never reuse a retired flow ID within the same epoch.
The monotonic credit model is inspired by QUIC flow control, not a claim that our
carrier is QUIC. [RFC 9000 flow control](https://www.rfc-editor.org/rfc/rfc9000.html#section-4)

Admission of a fresh logical record requires every applicable constraint:

```text
new_unique_bytes <= min(flow_remaining_credit,
                        connection_remaining_credit,
                        local_free_payload_budget,
                        current_scheduler_allowance)
new_record_count <= min(flow_remaining_record_credit, connection_record_credit)
wire emission     <= min(path_congestion_allowance, pacing_tokens, class_ceiling)
```

A retransmitted logical byte consumes credit once, but every transmitted copy
consumes wire capacity. Repair symbols consume decoder memory/work and wire
budgets. Abandonment must reliably retire its final offset; a lost record cannot
permanently leak credit. For TCP proxy streams, silently abandoning accepted
stream data is forbidden: recover it or fail/reset the affected TCP connection.

Proposed prototype controller (all constants are experimental configuration):

1. **Bootstrap** with a small bounded grant and pacing rate. Estimate path delivery
   and RTT from authenticated acknowledgments; do not assume the simulator's
   configured capacity is available on the live path.
2. **Probe** when demand exists, outstanding flight uses the current target, and
   delay/receiver/ECN/loss thresholds are clear. An initial experiment uses
   `few_flow_threshold = 4` and at most 2x target-credit growth once per measured
   RTT for few flows. For many flows, use conservative additive growth and
   redistribute idle shares through QoS. Both gains and thresholds are tunable.
3. Cap target credit by negotiated memory, per-flow/peer policy and an estimated
   bandwidth-delay product plus a finite queue allowance. A faster target never
   bypasses the carrier's actual `cwnd`, peer window or pacing constraints.
4. **Backpressure/drain** immediately on persistent queue-delay pressure, receiver
   high-watermark, actual receiver reservation pressure, ECN/loss or carrier congestion.
   Stop grant growth, reduce the target and future pacing allowance. Already granted
   credit is a promise: it cannot be revoked just because the target shrank.
   Ordinary sender credit exhaustion only pauses fresh admission. When the receiver
   releases reserved capacity, issue or retry authenticated cumulative credit
   updates even if the sender is stalled; an update timer/control path cannot
   depend on new data arrival. Do not confuse reaching a healthy credit limit
   with congestion or suppress the replenishment needed to make progress.
5. **Steady/recovery** resumes with hysteresis after pressure clears. Probe again
   after capacity increases or flows finish. Reset stale path estimates after
   rebinding/idle according to an explicit restart rule, without forgetting
   outstanding reservations or retransmission obligations.

No actual endpoint TCP `cwnd` doubling is implied by target-credit doubling.
Standard TCP carriers retain kernel congestion control. Raw/UDP carriers require
an independently tested aggregate path congestion controller; adding lanes or
opening flows cannot multiply the destination/path's permitted load.
[UDP congestion guidance](https://www.rfc-editor.org/rfc/rfc8085.html)

## Actual TCP-window acceleration

The `tun_tcp_proxy` module owns two TCP legs and the reliable intermediate stream.
A [bounded maintained-TCP relay primitive](modules/tcp-proxy.md) is now implemented
and tested independently; remote-open admission and the native proxy profile are
still planned.
A caller must select it explicitly; do not splice it into established transparent
flows during hot reload. Application TLS remains opaque end-to-end unless the
application itself terminates it; this module terminates TCP, not application TLS.

The ingress leg advertises only buffer-backed receive credit. Window scaling is
negotiated at SYN time, not invented later; enforce zero-window/persist behavior.
Use endpoint-owned congestion algorithms for each TCP leg. The short local leg
can ramp under its own feedback; the controlled tunnel segment uses the active
credit/pacing scheme. The remote egress socket still obeys the real remote peer's
receive window and path congestion control. Endpoint cooperation is an alternative
backend when available, not an assumption about arbitrary remote applications.

Once the proxy ACKs bytes locally, it owns their retransmission responsibility.
Retain them within explicit per-flow/session bounds until transferred to the next
reliable leg. Define resets, timeout and crash behavior; an in-memory ACK is not
proof of remote application consumption or durable receipt. Document source-IP
and original-destination preservation and any privileges required by a transparent
proxy adapter. Preserve half-close, FIN/RST, SACK, timestamps, ECN negotiation,
MSS/PMTU, IPv6 and option fallback; TCP-AO/MD5-protected flows are not silently
intercepted. The safe fallback is transparent forwarding from connection start or
explicit refusal, never switching ownership halfway through a stream.
[Performance-enhancing proxy considerations](https://www.rfc-editor.org/rfc/rfc3135.html),
[TCP specification](https://www.rfc-editor.org/rfc/rfc9293.html)

## QoS hierarchy and scheduling

```text
peer/path aggregate wire cap and congestion budget
  -> class minimum shares, weights and ceilings
    -> per-flow deficit round robin and bounded queue/AQM
      -> existing MUX admission and channel affinity
        -> carrier lane pacing
```

Classification happens before irreversible channel FIFO admission. Derive classes
from configured tenant/VNI/interface/flow rules, with DSCP trusted only by policy.
Define interactive, bulk and background presets, borrowing idle shares without
violating ceilings. Bound bursts, active-flow table size and idle eviction. Account
in bytes, not only packet count; charge FEC/copies/retries to the originating class
(or a documented weighted shared-source attribution when packing classes).

Mixed-class packing/coding windows can recreate head-of-line blocking. Initially
pack within a class and preserve per-flow order; a shared-source optimization
requires measured latency/attribution tests. Weighted QoS and MUX assignment remain
separate configuration fields. Bulk, SYN/SYN-ACK, ACK and latency probes all enter
the same classified admission system and channel budget; there is no probe-only
priority or extra user lane. A configured class applies equally to ordinary user
traffic matching that rule. Reserved management service is authenticated and
strictly rate/byte bounded, as defined by the management protocol.

Use a tested fair-queue/AQM design as a reference, but do not call the custom
weighted scheduler FQ-CoDel unless that algorithm is actually implemented. TAP can
use OS qdisc/QoS bindings where available; report unsupported Windows/Android
controls rather than assuming Linux configuration is portable.
[FQ-CoDel](https://www.rfc-editor.org/rfc/rfc8290.html)

ECN behavior needs a separate exact specification: mark eligible IP traffic or
apply a drop/backpressure rule as appropriate, never fabricate TCP ECE/CWR at an
intermediate bridge. Define outer/inner ECN propagation for fragments, packed
records and L2 shims before enabling it. Preserve unsupported encrypted traffic
as opaque data; QoS may classify by allowed outer fields without decrypting it.
[AQM guidance](https://www.rfc-editor.org/rfc/rfc7567.html),
[ECN for shim and L2 tunnels](https://www.rfc-editor.org/rfc/rfc9601.html)

## Implementation and acceptance checklist

- [ ] [FC-01] Freeze the three traffic profiles and report endpoint, tunnel and carrier windows separately.
- [ ] [FC-02] Implement cumulative byte/count credit with memory reserved for all granted offsets, including packets not received yet.
- [ ] [FC-03] Add generation-qualified flow IDs, replay-safe updates, final-offset retirement and wrap/exhaustion behavior.
- [ ] [FC-04] Implement bounded connection/flow queues, decoder-work accounting and exact retry/FEC credit accounting.
- [ ] [FC-05] Implement active-demand counting, path-rate/RTT estimation and stale-estimate restart rules.
- [ ] [FC-06] Implement few-flow aggressive target growth, multi-flow growth and BDP/memory/policy caps.
- [ ] [FC-07] Implement pressure detection, hysteresis and target shrink without revoking advertised grants.
- [ ] [FC-08] Add aggregate raw/UDP congestion control and prevent allowance multiplication through extra lanes.
- [ ] [FC-09] Implement weighted classes, per-flow deficit scheduling, ceilings, borrowing and starvation protection.
- [ ] [FC-10] Define DSCP/VNI trust rules, flow eviction, unsupported-protocol handling and fragmented-IP affinity.
- [ ] [FC-11] Implement class-aware packing/coding attribution and preserve flow ordering through MUX.
- [ ] [FC-12] Implement safe ECN/AQM/drop semantics, including non-ECT packets and packed/shim traffic.
- [ ] [FC-13] Implement `tun_tcp_proxy` with an embedded stack or explicit endpoint-cooperation backend; actual TCP window control is a required deliverable.
- [ ] [FC-14] Complete proxy buffer ownership, ACK responsibility, SACK/scaling/timestamps/persist and FIN/RST behavior.
- [ ] [FC-15] Define original source/destination handling, protected-TCP fallback, crash/reset semantics and per-flow opt-in.
- [ ] [FC-16] Bind TAP QoS to supported system facilities; prove inner TCP ACK/window behavior remains unchanged.
- [ ] [FC-17] Test 1/2/4/16/64 demanding flows, simultaneous joins/exits, many idle flows and receiver stalls.
- [ ] [FC-18] Fault-test lost/reordered credit, duplicated updates, stale epochs, retirement loss and count exhaustion.
- [ ] [FC-19] Test shrink with outstanding grants, zero sender credit while receiver capacity is free, lost replenishment updates, bounded recovery and no transient memory oversubscription.
- [ ] [FC-20] Test saturated bulk plus interactive/background traffic and report minimum shares, tail delay and starvation.
- [ ] [FC-21] Test external competing TCP, asymmetric links, extra lanes and FEC-heavy loss without unfair aggregate growth.
- [ ] [FC-22] Test TCP proxy reconnect/half-close/reset and contrast its failure semantics with transparent TUN.
- [ ] [FC-23] Verify user probes share ordinary traffic rules and management traffic stays within its reservation.
- [ ] [FC-24] Record controller transitions, all window types, queue P95/P99, goodput, wire cost, CPU/RSS and fairness in real-device receipts.
- [ ] [FC-25] Permit QoS/credit target reload through epochs; keep advertised grants and existing TCP ownership until drained/closed.
