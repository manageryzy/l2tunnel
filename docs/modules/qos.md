# QoS scheduler module

Status: first DRR primitive implemented and locally unit-tested, 2026-11-12
(Asia/Tokyo). The design was written before its implementation. It is now composed
by the pure [packet pipeline](pipeline.md); real-device QoS remains unqualified.
Parent requirements: [FC-09, FC-10, FC-11, FC-17, FC-20 and FC-23](../flow-control.md)
and [the protocol architecture](../architecture.md). This first increment is a
portable scheduling primitive, not the complete QoS hierarchy or a wire congestion
controller. It introduces no platform dependencies, clocks, sockets or threads.

## First implementation contract

`crates/l2tunnel-qos` provides a byte-accounted weighted deficit round-robin
(DRR) scheduler for opaque user packets. Classification happens before admission.
The caller supplies typed `FlowId` and `ClassId`; packets contain no scheduling
override and all user traffic uses the same `enqueue` path. There is no special
case for latency probes, ACKs, SYNs or payload contents.

The first version is **flat weighted per-flow DRR**. Effective flow quantum equals
`base_quantum_bytes * class_weight * flow_weight`, with checked arithmetic. Two
continuously backlogged flows receive byte shares approaching their effective
quantum ratio. A class with more active flows receives the sum of those flows'
shares. Class weights therefore are not an aggregate class minimum/ceiling or a
hierarchical fairness guarantee. The complete class-first hierarchy remains TODO.
No API or status should call this FQ-CoDel, active flow control or TCP acceleration.

Implemented public API (methods shown without the implicit `&self`/`&mut self`):

```rust
Scheduler::new(config: SchedulerConfig, classes: &[ClassConfig])
    -> Result<Scheduler, ConfigError>;
Scheduler::register_flow(config: FlowConfig) -> Result<(), FlowError>;
Scheduler::set_flow_weight(flow: FlowId, weight: u32) -> Result<(), FlowError>;
Scheduler::remove_flow(flow: FlowId) -> Result<(), FlowError>;
Scheduler::enqueue(flow: FlowId, payload: Vec<u8>)
    -> Result<(), AdmissionError>;
Scheduler::dequeue() -> Result<Option<ScheduledPacket>, ScheduleError>;
Scheduler::queued_bytes() -> usize;
Scheduler::queued_packets() -> usize;
Scheduler::registered_flows() -> usize;
Scheduler::active_flows() -> usize;
```

`SchedulerConfig` carries base quantum, maximum classes/flows, maximum packet
length, global byte/packet limits and per-flow byte/packet limits. `ClassConfig`
contains a class ID and nonzero weight. `FlowConfig` contains a flow ID, class ID
and nonzero weight. `ScheduledPacket` returns flow/class identity and the unchanged
payload. `AdmissionError` returns the original rejected payload with a typed reason.
Every public type and field has Rust documentation.

Reject zero limits/weights, inconsistent bounds, duplicate classes/flows, unknown
classes/flows and quantum/deficit overflow explicitly. Normalize accepted payload
storage to a boxed byte slice so spare caller `Vec` capacity does not bypass the
payload-byte bound. Queue metadata is separately bounded by configured flow/packet
limits; exact allocator overhead and whole-pipeline RSS are not asserted here.

## Scheduling and progress

Only nonempty flows appear in the active ring, exactly once. Starting a visit
adds one effective quantum. Send FIFO packets while their lengths fit the deficit;
retain the same visit across successive `dequeue` calls. Once the next packet
does not fit, rotate to the next active flow. When a flow empties, discard its
remaining deficit and release its queue storage; later activation starts at zero.
Idle flows never accumulate a burst entitlement.

Large packets may require more than one quantum. If a complete active-ring pass
cannot emit a packet, compute the minimum additional rounds until any head packet
can fit. Add the credit for only the empty intervening rounds, then perform the
next real pass. This is equivalent to ordinary DRR empty rounds but avoids a loop
proportional to packet length divided by quantum. Checked arithmetic and the
invariant `deficit < next_packet_length` between visits bound stored deficit by
`effective_quantum + max_packet_bytes - 1`. Configuration/registration validates
that this bound fits in `u64`.

`dequeue` returns a packet whenever any queue is nonempty; it does not require the
caller to manufacture repeated polling calls to accumulate deficit. Per-call work
is bounded by a constant number of scans of the active flows, plus bounded map
lookups; registered idle flows are never scanned. This means work-conserving
**scheduler selection**, not permission to send on a congested path.

Call `dequeue` only when downstream can accept one bounded packet. Returned bytes
are the scheduler's choice; connection/flow credit, receiver memory reservation,
MUX admission, path congestion allowance, pacing and wire overhead must still be
enforced by integration. Repairs/retries will require class attribution at that
later integration boundary. This primitive has no clock or wire-rate budget.

## Dynamic state and lifecycle

Flow registration is bounded and does not enter the active ring until enqueue.
Removal and weight changes require an empty flow and leave all state unchanged
on rejection. No API silently discards queued data. Class weights are immutable;
replace the scheduler only after the coordinated epoch/drain integration permits
it. Re-registering a removed numeric flow ID is locally allowed, but peer-visible
generation/retirement/replay rules belong to session/flow-control and must be
checked before calling this local scheduler.

Global and per-flow accounting is released exactly once on dequeue. Unknown-flow,
oversized, empty, byte-exhausted and packet-exhausted enqueues return ownership to
the caller without changing accounting, ring order or deficits. Payload contents
do not affect selection.

## Work and evidence checklist

- [x] [QOS-01] Implemented validated configuration, typed IDs/errors and checked class/flow quantum arithmetic. Evidence: [implementation and focused tests](../../crates/l2tunnel-qos/src/lib.rs).
- [x] [QOS-02] Implemented global/per-flow byte and count bounds, FIFO payload ownership, idle reset and non-destructive dynamic operations. Evidence: [implementation and focused tests](../../crates/l2tunnel-qos/src/lib.rs).
- [x] [QOS-03] Implemented weighted DRR, active-only traversal and empty-round skipping for a one-byte quantum and large packets. Evidence: [implementation and focused tests](../../crates/l2tunnel-qos/src/lib.rs).
- [x] [QOS-04] Contract-tested invalid/overflow configuration, IDs, rejection ownership, byte/count limits, FIFO and accounting. Evidence: [focused tests](../../crates/l2tunnel-qos/src/lib.rs).
- [x] [QOS-05] Contract-tested weighted byte shares, unequal packet sizes, idle populations, reactivation, busy mutations and maximum-size packet progress. Evidence: [focused tests](../../crates/l2tunnel-qos/src/lib.rs).
- [ ] [QOS-06] Implement aggregate class shares/minima/ceilings, idle borrowing,
  per-class burst bounds and hierarchical fairness independent of flow count.
- [ ] [QOS-07] Integrate classification, trusted DSCP/VNI rules, fragmented-flow
  affinity, MUX channels and class-aware repair/packing attribution.
- [ ] [QOS-08] Integrate separate receiver credit, path congestion control and
  pacing; quantify reservations across scheduler and downstream queues.
- [ ] [QOS-09] Specify and implement AQM/ECN behavior with exact marking/drop
  semantics; this scheduler does not implement an AQM algorithm.
- [ ] [QOS-10] Coordinate epoch changes, flow retirement and budget shrink with
  session barriers; current local empty-flow updates are not peer hot switching.
- [ ] [QOS-11] Add reference/differential scheduler traces and adversarial
  sustained-load tests with 1/2/4/16/64 active flows plus idle populations.
- [ ] [QOS-12] Record real-device class delay/fairness/CPU/RSS and wire-cost tests,
  including FEC-heavy loss and competing external traffic; bind TAP to system QoS.

Focused tests validate the implemented primitive only. Passing them does not
complete FC-09's hierarchy, FC-20's real traffic guarantees or native-device gates.

## Local verification receipt

### Eligibility extension design

The packet-pipeline wave adds `PacketHead`, `peek_eligible`, `dequeue_peeked` and
`dequeue_eligible`. A pure eligibility callback checks each active flow's FIFO
head once per selection. Blocked flows retain original payload/accounting, reset
their deficit to zero and earn no skipped-round credits. Eligible flows retain
the original DRR behavior, and repeated all-blocked polls cannot bank a burst.
Selection uses a constant number of active-flow passes and no additional queue.

`peek_eligible` selects and retains a head without consuming its deficit or packet.
`dequeue_peeked` commits that selection once; successful queue/flow mutations
invalidate a pending selection. This supports a serialized caller checking credit,
then committing credit, then removing the exact selected packet without I/O or
interleaved queue mutations. Eligibility callbacks must never consume credit.
The scheduler itself has no peer-credit or network-feedback implementation.

- [x] [QOS-13] Implement bounded eligibility snapshots, blocked deficit reset and eligibility-aware empty-round skipping. Evidence: [eligible scheduler](../../crates/l2tunnel-qos/src/lib.rs).
- [x] [QOS-14] Add non-consuming selected-head peek and explicit single-use dequeue commit. Evidence: [selected-head implementation and tests](../../crates/l2tunnel-qos/src/lib.rs).
- [x] [QOS-15] Test all-blocked retention, eligible-flow progress, callback bounds, unblock burst bounds and selection invalidation. Evidence: [focused tests](../../crates/l2tunnel-qos/src/lib.rs), [pipeline-wave receipt](pipeline.md#local-verification-receipt).

The eligibility wave passes 17 scheduler tests, including the unchanged textbook
DRR comparison, plus the pipeline's actual packet/credit tests. Formatting and
warning-denied Clippy passed using the offline commands in the linked receipt.

### Initial primitive receipt

Implementation and tests are in
[`crates/l2tunnel-qos/src/lib.rs`](../../crates/l2tunnel-qos/src/lib.rs).
The following commands passed on the local Linux host:

```sh
cargo fmt --package l2tunnel-qos
cargo test --package l2tunnel-qos
cargo clippy --package l2tunnel-qos --all-targets -- -D warnings
cargo doc --package l2tunnel-qos --no-deps
```

All 15 unit tests passed. Cases include 1:3 byte shares under sustained backlog,
100-byte versus 1500-byte fairness, class/flow weight multiplication, 10,000 idle
registered flows, 8 MB packets with a one-byte quantum, queue limits, checked
overflow and unchanged packet contents. A deliberately slow textbook DRR reference
matches complete scheduler traces for 1/2/4/16/64 active flows with varied packet
sizes and weights. This is partial QOS-11 evidence; sustained adversarial lifecycle
campaigns and real-device QoS integration remain outstanding. Workspace-wide checks
are recorded by the integrating change, separately from this crate-only receipt.
