# Packet scheduler pipeline

Status: implemented and locally tested pure pipeline; design preceded code.
This module composes existing packet,
flow-table, weighted-DRR and common-MUX primitives. It is not authenticated network
flow-control integration, a TCP proxy, hierarchical QoS, pacing or AQM.
Parent requirements: [architecture](../architecture.md), [M2 parity](../mode-parity.md),
[flow control](../flow-control.md), [packet](packet.md) and [QoS](qos.md).

## Public boundary

```rust
Pipeline::new(PipelineConfig) -> Result<Pipeline, PipelineError>;
Pipeline::classify(&[u8]) -> Result<Classification, ParseError>;
Pipeline::enqueue(Vec<u8>, Duration) -> Result<PacketMetadata, EnqueueError>;
Pipeline::enqueue_weighted(Vec<u8>, u32, Duration)
    -> Result<PacketMetadata, EnqueueError>;
Pipeline::learn(FlowKey, u16, u32, Duration) -> Result<Binding, PipelineError>;
Pipeline::dequeue() -> Result<Option<Packet>, PipelineError>;
Pipeline::dequeue_with(eligible, commit)
    -> Result<Option<Admitted<Permit>>, DequeueError<CommitError>>;
Pipeline::retire_idle_drained(&FlowKey, Duration) -> Result<Binding, PipelineError>;
Pipeline::flow(&FlowKey) -> Option<FlowSnapshot>;
Pipeline::tun_flow_heads() -> Result<impl Iterator<Item = FlowHead>, PipelineError>;
Pipeline::usage() -> QueueUsage;
Pipeline::idle_candidate(Duration) -> Result<Option<(FlowKey, Binding)>, PipelineError>;
```

`PipelineConfig` fixes `Profile::TapSystem` or `Profile::TunDrr(TunQosConfig)`,
`FlowTableConfig`, `ParseLimits` and aggregate `QueueLimits`. TUN config supplies
base byte quantum, maximum trusted flow weight and per-flow byte/count bounds.
One pipeline covers one direction/tenant/session/epoch. Configuration changes
require external negotiated drain; this API cannot perform a peer hot switch.

`PacketMetadata` includes classification and local flow/channel binding. Dequeue
returns original bytes with that metadata. `EnqueueError` returns ownership of
the rejected input, including spare caller allocation. Successful queues normalize
payload capacity. No clock, socket, runtime, driver or packet mutation is involved.

## Profiles and common admission

TAP parses Ethernet/VLAN/ARP/IP/opaque frames and queues directly into the common
FIFO-per-channel round-robin MUX. It never instantiates a custom flow DRR scheduler,
rewrites TCP headers or trusts DSCP as a scheduling override. A custom weight or
per-flow credit-gated dequeue is rejected for TAP. The adapter may still wait for
aggregate carrier capacity before ordinary TAP dequeue.

TUN parses native IPv4/IPv6, uses configured trusted per-flow weights in the
existing flat byte DRR, and passes every selected packet through common MUX
admission. The TUN MUX handoff holds at most one selected packet at a time, so
deep per-channel packet round-robin staging cannot undo byte-weighted DRR shares.
All user packets, TCP control packets and probes follow these exact same paths.
There is no management bypass selected by EtherType, ports or payload. Reserved
authenticated internal management belongs outside this user-packet pipeline.

Weights are explicit local policy, not inferred from untrusted packet fields.
An existing flow must keep its registered weight until it is fully retired.
Fragment/opaque keys deliberately share coarser identities as the packet module
documents. This remains flat DRR rather than aggregate class guarantees.

## Atomic resources and lifecycle

Classification, weight checks, total/per-flow byte and packet budgets and
`FlowTable::preview_assign/preview_learn` precede state mutation. Preview predicts
the exact next binding without consuming an ID, channel turn or timer. On a new
TUN flow, register its validated scheduler policy and admit its first packet;
if queue admission fails, remove the still-empty registration. Commit the table
assignment only after successful queue admission, under the same exclusive actor.
The actual transaction uses `prepare_assign/prepare_learn`: an exclusive borrow
retains the preview, dropping the token changes nothing, and its `commit` is
infallible. Preflight and commit cannot race. Unsupported peer inputs never leave partial
flow registrations or advance ID/RR counters on rejection.

Aggregate usage includes every retained packet through handoff; byte/count limits
do not multiply across QoS, MUX and selection. Fixed flow metadata and scheduler
entries are separately count bounded. Queue movement never creates new capacity.
Errors preserve the original rejected input, and there is no packet-content
exception for control-shaped or short traffic.
Original payload storage is normalized by the component queues. Classification
sidecars are bounded by the same packet count and contain no payload copies.
Allocator capacities and component B-tree/channel-ring overhead remain finite
under configured flow/channel/packet limits, but are not claimed as byte-exact RSS.

An idle timer is only a retirement candidate. `retire_idle_drained` requires no
locally queued packet and the caller's explicit knowledge that downstream credit,
recovery and codec state are drained. IDs never wrap or reuse. There are no
unbounded retirement tombstones and no automatic capacity eviction. Learned RR
conflicts remain explicit until distributed arbitration is implemented.

## Eligibility and credit handoff

`dequeue_with` is TUN-only. Its eligibility callback receives a fixed-size
`Candidate { binding, key, packet_bytes }` for each active flow's FIFO head,
at most once per call. It must only check the current allowance and never consume
credit or perform I/O. It skips blocked flows so one exhausted peer allowance
cannot stall eligible flows. All-blocked returns `None` while usage stays nonzero.

Blocked flows reset their DRR deficit to zero. They earn no deficit during blocked
rounds and restart from one ordinary quantum after becoming eligible; repeated
polls cannot bank a future burst. Eligible flow ratios retain ordinary DRR bounds.
Selection scans a constant number of active-flow passes, never all idle entries
or a number of rounds proportional to packet size. Selected payload and accounting
remain in the QoS queue until commit succeeds.

After a head is selected, `commit` runs once and may consume the actual sender
credit and return a record/token. A rejected commit leaves payload and byte/count
accounting retained. No callback runs when no flow is eligible. The callbacks and
queue handoff execute under one serialized actor without intervening mutation.
This is an adapter point for `SenderCredits::admit`; the target controller and
receiver grants remain separately driven by authenticated runtime feedback.
The eligibility closure can use the actor's immutable authenticated allowance
snapshot while the commit closure mutates its sender ledger. There is no speculative
`admit` call for every candidate; only the selected candidate spends credit.
The pipeline does not claim to exchange credit messages, estimate RTT/demand,
account recovery wire copies or integrate network active flow control.

`tun_flow_heads` provides exact retained FIFO head length and queue byte/count
observations without allocation, selection, deficit accrual or idle-age refresh.
One traversal is bounded by registered flow capacity; empty heads remain explicit.
TAP rejects this per-flow observation API. The Active observer uses these heads
with authoritative sender-ledger preflight; snapshots consume no credit.

## Checklist

- [x] [MOD-PIPE-01] Specify profile separation, atomic admission, eligible selection and exact APIs before coding. Evidence: [public boundary](#public-boundary), [API](../../crates/l2tunnel-pipeline/src/lib.rs).
- [x] [MOD-PIPE-02] Compose TAP classification with common FIFO/RR MUX and explicit custom-weight rejection. Evidence: [profile implementation](../../crates/l2tunnel-pipeline/src/lib.rs), [TAP tests](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-PIPE-03] Compose TUN native-IP classification, trusted weighted DRR and common MUX handoff. Evidence: [pipeline implementation](../../crates/l2tunnel-pipeline/src/lib.rs).
- [x] [MOD-PIPE-04] Enforce aggregate/per-flow bytes/counts and max-flow limits across every stage. Evidence: [budget and capacity tests](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-PIPE-05] Make rejected parsing, flow registration and queue admission resource-atomic. Evidence: [prepared flow transaction](../../crates/l2tunnel-packet/src/flow.rs), [failure tests](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-PIPE-06] Skip credit-blocked TUN flows with bounded eligibility checks and no blocked deficit accumulation. Evidence: [eligible DRR and tests](../../crates/l2tunnel-qos/src/lib.rs), [pipeline tests](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-PIPE-07] Preserve bytes/accounting on commit failure and consume credit only for selected handoff. Evidence: [commit and ledger tests](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-PIPE-08] Implement explicit idle/drain retirement and authenticated learned-channel conflict handling. Evidence: [lifecycle tests](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-PIPE-09] Test mixed small/bulk weighted byte fairness, reverse CRC identity and common admission of TCP control/probes. Evidence: [fairness and affinity tests](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-PIPE-10] Test TAP ARP/VLAN/opaque preservation and atomic full-queue/max-flow/weight/parser failures. Evidence: [TAP and admission tests](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-PIPE-11] Test blocked-flow progress, idle lifecycle and actual cumulative-credit adapter release/regrant progress. Evidence: [credit and lifecycle tests](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-PIPE-12] Run focused format/test/Clippy and record their exact local scope. Evidence: [local verification receipt](#local-verification-receipt).
- [ ] [MOD-PIPE-13] Integrate managed native runtime, authenticated credit feedback, congestion/pacing and distributed RR arbitration.
- [ ] [MOD-PIPE-14] Qualify hierarchy/AQM, real device fairness and epoch-switch/drain accounting; no whole-mode parity claim.
- [x] [MOD-PIPE-15] Expose exact nonmutating TUN heads without changing scheduler service or TAP policy. Evidence: [head API](../../crates/l2tunnel-pipeline/src/lib.rs), [FIFO/deficit regression](../../crates/l2tunnel-pipeline/src/tests.rs).

## Local verification receipt

Executed on local Linux, 2026-11-11 UTC:

```text
cargo fmt -p l2tunnel-pipeline -p l2tunnel-packet -p l2tunnel-qos
cargo test --offline -p l2tunnel-pipeline -p l2tunnel-packet -p l2tunnel-qos
  pipeline: 10 unit tests and 1 doctest passed
  packet: 18 unit tests and 1 doctest passed
  qos: 17 unit tests passed
cargo clippy --offline -p l2tunnel-pipeline -p l2tunnel-packet -p l2tunnel-qos --all-targets -- -D warnings
  passed
```

The 100/1500-byte weighted test uses actual original IP/TCP bytes; the credit test
uses real sender/receiver ledgers and releases/regrants after exhaustion. These
are finite local composition tests, not authenticated runtime/native traffic
qualification. Root integration owns `python3 tools/check.py`, native bridge/netem
and Windows/Android receipts.

The subsequent observation extension ran `cargo test --offline -p l2tunnel-active
-p l2tunnel-pipeline`: pipeline 11 unit tests and 1 doctest, Active 31 unit tests
passed. Targeted formatting and warning-denied Clippy also passed; the earlier
packet/QoS counts above are the retained original module receipt.
