# Transparent-TUN active credit engine

Status: implemented and locally unit-tested. This pure two-peer composition joins the
[packet pipeline](pipeline.md), cumulative ledgers, [target controller](flow-control.md)
and [72-byte credit tokens](credit-wire.md). It does not authenticate a carrier,
recover dropped packets, perform native I/O, own endpoint TCP windows or select TAP.

## API and direction boundaries

```rust
Active::new(ActiveConfig, Direction, Micros) -> Result<Active, Error>;
Active::enqueue_ip(&[u8], weight: u32, Micros) -> Result<PacketMetadata, Error>;
Active::receive_control(&[u8], Micros) -> Result<(), Error>;
Active::receive_data(&[u8], channel: u16, payload: &[u8], Micros)
    -> Result<ReceiveOutcome, Error>;
Active::update_targets(Micros, Feedback, &[FlowId]) -> Result<TargetPlan, Error>;
Active::poll_output() -> Result<Option<Output>, Error>;
Active::poll_control() -> Result<Option<[u8; 72]>, Error>;
Active::poll_data() -> Result<Option<Data>, Error>;
Active::delivery() -> Option<Delivery<'_>>;
Active::confirm_delivery(Record) -> Result<ConfirmOutcome, Error>;
Active::confirm_delivery_at(Record, Micros) -> Result<ConfirmOutcome, Error>;
Active::demand_snapshots() -> Result<Vec<LocalDemand>, Error>;
Active::native_sample() -> Option<NativeSample>;
Active::status() -> Status;
```

Configuration fixes session/epoch, a `TunDrr` + `Crc32` pipeline, sender/receiver
capacities and target policy. Sender scope uses the supplied local direction;
receiver scope uses its opposite. Each owns a separate monotonically increasing
flow-ID space. `Open`/`Record`/`Final` match receiver scope; `Grant`/`Release`/`FinalAck` match sender
scope. Every token and exact data length is validated before ledger mutation.

`Output::Control` carries an encoded fixed token. `Output::Data` carries the encoded
record token, actual native IP bytes, typed record and channel. The caller must
retain each output until its authenticated reliable carrier/recovery accepts it.
Recovery owns payload copies/retries; this engine owns the cumulative logical
reservation until an actual downstream `Release`, rather than until network ACK.
Wire/FEC/retry bytes still need the caller's separate congestion and wire budgets.

The first scope requires CRC affinity, so reverse tuples independently select the
same channel and received channels can be checked deterministically. Channel
numbers never grant authority. Distributed RR binding and TAP selection are
explicitly unsupported rather than silently enabled. Drained retirement uses the
serialized final barrier below.

## Flow admission and bounded bootstrap

Successful local enqueue registers its new pipeline flow in the sender ledger
and queues `Open`; no payload can leave without an authoritative sender grant.
`SenderCredits::preview_admit` performs the same checks as `admit` without mutation.
Pipeline eligibility consults that preflight once per active head. Only the
selected head calls `admit`, so blocked flows cannot stall other eligible flows
or spend speculative credit.

Each receiver flow retains a fixed one-packet bootstrap floor: maximum configured
IP packet bytes and one record. Protect an additional such floor for every still
unopened receiver slot. The adaptive target minimum, policy/memory caps and queue
allowance must accommodate the complete configured floor pool. Before assigning
adaptive surplus, subtract protected unopened floors from the target's aggregate
allowance. An aggressive early flow therefore cannot consume a later flow's first
packet entitlement. This trades some small-flow peak window for bounded admission
progress; choose maximum flows and MTU deliberately.

Every confirmed delivery restores that flow's fixed floor before allocating
adaptive surplus. The floor is independently protected even while old irrevocable
surplus grants exceed a reduced target. Idle flows retain their floor until a
negotiated retirement barrier; they do not count as demanding flows for
controller growth. Runtime-supplied demanding IDs govern adaptive surplus only.
The engine does not fabricate RTT, delivery rate, congestion or demand estimates.
The optional [observation module](active-observation.md) supplies authoritative
queued-head snapshots, authenticated demand framing, timed actual native samples
and one-outstanding measured RTT probes. Its caller explicitly opts into target
updates; existing static confirmation/regrant behavior remains available.
Actual sender exhaustion can qualify measured controller growth: protected unopened
slots otherwise prevent a demanding flow from reaching the full aggregate target.
The caller must set this flag only when retained queued demand actually exhausts
its effective grant. RTT/rate measurements, one-step-per-RTT, hard caps and pressure
precedence still apply; no synthetic in-flight bytes are added.

Incoming `Open` is idempotent for a live flow and re-advertises its latest grant.
New opens must arrive in monotonic order through caller-owned reliable ordered
control delivery; out-of-order new opens fail explicitly. Grants/releases/data
may be duplicated or reordered within their bounded ledger windows. No Open retry
timer, data ARQ or FEC algorithm is duplicated inside this engine. The separate
finite final-barrier timer does not provide generic control delivery reliability.

## Actual downstream release

Received data must have the opposite scope, a known peer flow, a canonical record
token, exact payload length, a complete supported/opaque native IP classification
and the deterministic CRC channel. Bind each remote flow to its first actual
canonical packet key; reject later key changes or duplicate remote IDs for the
same key. Metadata and payload bytes are retained only after ledger admission.
Conflicting retained duplicate bytes fail; ordinary retries never redeliver data.

`delivery` borrows the next contiguous record in a peer flow. Reordered records
remain pending behind that flow's missing prefix; other flows can progress.
The caller writes those bytes to its real destination, then explicitly invokes
`confirm_delivery` with the exact record. A failed write must not confirm.
Borrowed delivery remains unchanged until confirmation, and cumulative release
advances only after this explicit actual-consumption event. Repeated confirmation
does not recreate credit. Taking bytes from the network is not release.

The receiver ledger reserves granted-but-not-received bytes and counts. Actual
retained payload and metadata fit inside those promises. The status separately
reports queued source packets, sent logical retention, received payload, issued
receiver reservations, protected unopened floors and coalesced controls. Control
storage has at most one pending Open per outgoing flow and one Grant plus one
Release per incoming flow, plus one Final and one FinalAck. Control/data output
alternates when both are ready. Separate `poll_control`/`poll_data` paths let a
runtime reserve its independently bounded output queue before taking ownership.
Control polling never dequeues a user packet or spends its credit. Split-poll
callers own finite control rate/burst and data fairness, preserving credit-message
service when a bulk carrier queue is full.

Sender and receiver ownership are separately bounded: source queue + sender
in-flight capacity + receiver capacity + flow/control metadata. Caller recovery
and native output copies must respect their own compatible bounds. No exact RSS,
kernel throughput or authenticated native flow-control claim follows from tests.

## Lifecycle limitations

Only explicitly requested idle, drained, serialized `Final`/`FinalAck` retirement
is implemented. Abandonment remains unsupported. The engine does not evict flows
or inspect external recovery state. At maximum live flow count, new flows receive
backpressure until an exact barrier completes or the session is drained/recreated.
UDP requires independent authenticated reliable ordered control and data recovery
before selecting this engine. The finite final retry policy is not a data ARQ.
Counter exhaustion and configuration epoch changes require session renewal;
issued grants never wrap or retract.

Confirmation always commits an already-consumed valid buffer even if its next
regrant would overflow. In that case status sets `renewal_required`, queues the
Release, stops new grants and permits existing native delivery to drain. Local
new admission and target updates then reject until a new session is created.

## Checklist

- [x] [MOD-ACT-01] Define scopes, pure APIs, caller authentication/recovery ownership and unsupported profiles before code. Evidence: [public API](../../crates/l2tunnel-active/src/lib.rs).
- [x] [MOD-ACT-02] Add authoritative nonmutating sender admission preview and regression tests. Evidence: [ledger regression](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-ACT-03] Compose local IP pipeline/Open/Grant/data with credit-eligible flow skipping. Evidence: [Active::poll_output](../../crates/l2tunnel-active/src/lib.rs).
- [x] [MOD-ACT-04] Bind incoming record scopes, exact lengths, keys and CRC channels before storing actual payloads. Evidence: [hostile-input tests](../../crates/l2tunnel-active/src/tests.rs).
- [x] [MOD-ACT-05] Implement bounded per-flow receive reorder and explicit native confirmation/release. Evidence: [receive and native prefix test](../../crates/l2tunnel-active/src/tests.rs).
- [x] [MOD-ACT-06] Coalesce finite control queues, duplicate Opens/grants/releases and alternate control/data service. Evidence: [control and output service tests](../../crates/l2tunnel-active/src/tests.rs).
- [x] [MOD-ACT-07] Integrate injected target updates and protected MTU bootstrap floors without revoking grants. Evidence: [Active::update_targets and replenish](../../crates/l2tunnel-active/src/lib.rs).
- [x] [MOD-ACT-08] Transfer actual bidirectional payloads between two independent engines and recover zero-credit progress after downstream release/regrant. Evidence: [two-endpoint transfer test](../../crates/l2tunnel-active/src/tests.rs).
- [x] [MOD-ACT-09] Test scope/length/channel/key rejection, duplicate conflicts, reorder, slow native consumer and all resource bounds. Evidence: [adversarial test suite](../../crates/l2tunnel-active/src/tests.rs).
- [x] [MOD-ACT-10] Test aggressive first-flow growth plus later small-flow admission, pressure and blocked-flow skipping. Evidence: [protected bootstrap and retention tests](../../crates/l2tunnel-active/src/tests.rs).
- [x] [MOD-ACT-11] Run local targeted tests, formatting and warning-denied Clippy with honest receipts. Evidence: [local validation receipt](#local-validation-receipt).
- [x] [MOD-ACT-12] Implement scoped serialized drained final barriers under caller authentication, bounded final retries and safe idle retirement. Evidence: [retirement state machine](../../crates/l2tunnel-active/src/retirement.rs).
- [ ] [MOD-ACT-13] Integrate managed native runtime, real authentication/recovery, feedback estimation and privileged traffic receipts.

## Serialized distributed retirement

The implemented API preserves constructor configuration:

```rust
RetirementPolicy { retry_micros: u64, max_attempts: u32 }
ExternalDrain { pending_outputs: usize, pending_recovery_records: usize }
Active::request_idle_retirement(&FlowKey, Micros, RetirementPolicy, ExternalDrain)
    -> Result<FinalOffset, Error>;
Active::poll_retirement(Micros) -> Result<(), Error>;
Active::idle_candidate(Micros) -> Result<Option<FlowKey>, Error>;
```

Permit one outgoing retirement per direction. Both external pending counts must
be zero, original queued packets must be empty, configured idle age must have
elapsed, and the sender ledger must prove every admitted record was released.
The caller supplies truthful external counts after its serialized output/recovery
barrier. Freeze the canonical key and retain its pipeline registration until an
exact scoped `FinalAck` arrives. Never roll back the freeze after a retry timeout.

The receiving peer accepts only drained `Final` with the exact consumed prefix
and no pending native payload. It removes the remote key/ledger, reclaims unused
promises, and caches the exact ACK. Duplicate cached Finals requeue that ACK;
conflicting offsets never receive success. Each peer has only one outgoing Final
in flight, so receiving its next legitimate Final proves it already completed the
previous barrier. One cached incoming ACK is sufficient for this protocol. Older
uncached final messages are ignored as stale without fabricating acknowledgments.
Caller-owned reliable ordered control remains required; arbitrary simultaneous
retirement negotiation is deliberately not provided.

Retry interval/count are explicit and time-injected. Coalescing an already queued
Final does not count another transmission attempt. Exhaustion remains frozen and
sets session-renewal status; all state/control metadata stays bounded. A new flow
using a completed key receives a strictly greater ID. No ever-growing retired-key
or per-flow tombstone map is introduced. Delayed stale grants/releases cannot
recreate a retired ledger; data retries must already be drained externally.

- [x] [MOD-ACT-14] Define serialized retirement APIs, external drain proof and bounded exact ACK cache before implementation. Evidence: [retirement contract](#serialized-distributed-retirement).
- [x] [MOD-ACT-15] Freeze only fully released idle source flows and reclaim pipeline registrations after matching scoped final ACK. Evidence: [request and final-ACK handling](../../crates/l2tunnel-active/src/retirement.rs).
- [x] [MOD-ACT-16] Validate actual native drain, reclaim unused receiver promises and make cached duplicate finals idempotent. Evidence: [receiver final handling](../../crates/l2tunnel-active/src/retirement.rs).
- [x] [MOD-ACT-17] Implement bounded time-injected retries and explicit exhausted-session behavior without rollback or eviction. Evidence: [retry and exhausted-state tests](../../crates/l2tunnel-active/src/tests.rs).
- [x] [MOD-ACT-18] Test repeated flow churn beyond configured capacity, retransmitted/mismatched finals, live queues and externally pending recovery rejection. Evidence: [200-flow churn and adversarial retirement tests](../../crates/l2tunnel-active/src/tests.rs).
- [x] [MOD-ACT-19] Re-run targeted formatting/tests/Clippy and update retirement receipts without claiming native barriers. Evidence: [local validation receipt](#local-validation-receipt).
- [x] [MOD-ACT-20] Keep bounded credit control independently serviceable while a runtime holds blocked bulk output. Evidence: [split output liveness test](../../crates/l2tunnel-active/src/tests.rs).
- [ ] [MOD-ACT-21] Carry authenticated bounded actual sender demand/exhaustion observations and derive real RTT/delivery-rate feedback at the runtime boundary.

## Local validation receipt

`cargo fmt -p l2tunnel-active -p l2tunnel-flow-control`, `cargo test --offline -p
l2tunnel-active -p l2tunnel-flow-control`, and `cargo clippy --offline -p
l2tunnel-active -p l2tunnel-flow-control --all-targets -- -D warnings` passed locally:
Initial composition: 12 active unit tests, 31 ledger/controller/wire tests and one
ledger doctest. Retirement/split-output followup: `cargo fmt -p l2tunnel-active`,
`cargo test --offline -p l2tunnel-active`, and `cargo clippy --offline -p
l2tunnel-active --all-targets -- -D warnings` passed all 18 active tests.
These are deterministic independent-engine payload/ownership tests. They do not
claim actual authentication, network loss recovery, native device/kernel behavior,
Windows/Android support, runtime external-drain proof or whole-simulator mode parity.
