# Flow-control library design

Status: implemented and locally unit-tested credit primitive and adaptive target
controller. This module does not implement a TCP stack, QoS scheduler or carrier.
It does not alter TAP or endpoint TCP behavior. Parent requirements are FC-02,
parts of FC-03/FC-04 and the zero-credit/retirement cases of FC-18/FC-19.

## Public contract

`l2tunnel-flow-control` uses only Rust `std`; no clock, OS, async runtime or crypto
dependency is introduced. A `Scope` identifies session, epoch and direction.
`FlowId` and `RecordId` are separate types. `Credit { bytes, records }` represents
either an absolute cumulative limit or a capacity, as named by each API.

| API | Responsibility |
| --- | --- |
| `ReceiverCredits::new(scope, capacity)` | Bound total granted-but-unreleased bytes/count and active flow metadata. |
| `ReceiverCredits::open_flow(flow)` | Open strictly increasing flow IDs; retired IDs cannot return. |
| `ReceiverCredits::grant(flow, limit)` | Reserve the increase before returning absolute flow/session `Grant` limits. Stale/lower requests retain the existing grant. |
| `ReceiverCredits::receive(record)` | Check limits and bounded record ranges; report new/duplicate/already-released without allocating payload. |
| `ReceiverCredits::release_next(flow)` | Release exactly the next received record after the caller has handed off/discarded its payload safely; return a cumulative `Release`. |
| `ReceiverCredits::retire(final_offset, mode)` | Reclaim unused grants after a final authenticated barrier; drained mode requires the exact released prefix, abandon mode explicitly discards the flow. |
| `SenderCredits::new/open_flow/apply_grant` | Maintain monotonic flow/session admission limits for one scope. |
| `SenderCredits::preview_admit(flow, bytes)` | Run the authoritative next-record checks without reserving or consuming anything; commit on the same serialized actor. |
| `SenderCredits::admit(flow, bytes)` | Charge unique logical bytes/count once and return an immutable logical `Record`. |
| `SenderCredits::retry(flow, record_id)` | Return the same retained record token without consuming new credit. |
| `SenderCredits::apply_release(release)` | Validate cumulative record boundaries; release local metadata once despite duplicate/reordered updates. |
| `SenderCredits::retire(flow, mode)` | Produce an exact final offset, normally only after release; explicit abandonment is separate. |
| `ReceiverCredits::grant_to_target(flow, flow_target, session_target)` | Replenish cumulative grants toward independent byte/count targets without revoking prior promises. |

The caller authenticates messages and validates peer identity before invoking
wire-facing methods. Scope matching is an additional guard, not authentication.
Tokens contain no payload; payload identity/integrity belongs to the authenticated
record layer. Equal metadata alone is not proof that two payloads are identical.
The caller must release only after actual downstream consumption or permitted
discard, never merely after network receipt.

## Invariants and boundaries

- Receiver reservation is the sum of each live flow's granted minus released
  bytes/count. It includes unreceived, reordered and lost data. It never exceeds
  configured capacity; payload storage itself remains the caller's responsibility.
- Absolute limits never decrease. Checked arithmetic rejects exhaustion before
  mutation. Independent stale flow/session updates merge componentwise maxima.
- Every new record consumes one record credit even when its payload is empty.
  Retry does not consume fresh logical credit; all copies still need external
  wire/congestion/QoS accounting.
- The receiver's session grant counter is the cumulative sum of per-flow grants.
  Retirement can reclaim an unused grant's memory but never retract its already
  advertised session limit. Per-flow caps and non-reusable IDs retain the bound.
- Receiver metadata is bounded by outstanding record reservations and active-flow
  count. Sender retained metadata has a separate local bytes/count/flow cap.
- Records may arrive out of order. Neighbor ranges may not overlap or contradict
  contiguous record boundaries; release advances only over the next record.
  Independent-short delivery is future work and must not be inferred here.
- Reaching sender credit is ordinary admission blocking (`SenderExhausted`). It
  does not signal receiver pressure. After receiver release, a new bounded grant
  can immediately restore progress. `ReceiverPressure` and `LocalRetention` are
  separate failures.
- A flow's IDs start at record zero and never wrap. Flow IDs strictly increase
  within a scope. A fixed high-water mark rejects old IDs without unbounded
  tombstones. Old final-message retransmission receives `UnknownFlow` after
  retirement; the reliable authenticated management layer must retain its own
  bounded final-ACK/retry state. This module does not falsely acknowledge a
  conflicting final offset it no longer remembers.
- `RetirementMode::Abandon` is an explicit trusted cancellation action after a
  peer final barrier. It is forbidden for proxy-ACKed TCP bytes unless the caller
  has first failed/reset that TCP connection. Normal retirement requires all
  admitted records to have been released; lost unrecovered records cannot pretend
  to be delivered.
- Creating a new epoch ledger does not authorize dropping the old ledger. The
  session must drain or explicitly retire its old reservations first.

## TODO and verification matrix

- [x] [MOD-FC-01] Specify public APIs, accounting invariants, caller trust and bounded state. Evidence: [public Rust API](../../crates/l2tunnel-flow-control/src/lib.rs).
- [x] [MOD-FC-02] Implement checked absolute flow/session grants and resource reservations. Evidence: [ReceiverCredits and SenderCredits](../../crates/l2tunnel-flow-control/src/lib.rs).
- [x] [MOD-FC-03] Implement sender admission, retry, exact cumulative release and retirement. Evidence: [focused tests](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-FC-04] Implement bounded reordered receiver records and safe contiguous release. Evidence: [all-six-orderings test](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-FC-05] Test flow/session exhaustion independently; zero-length/count exhaustion. Evidence: [limit and empty-record tests](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-FC-06] Test grant reservation before any packet arrives; aggregate pressure across flows. Evidence: [aggregate reservation test](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-FC-07] Test duplicate/reordered grants/releases/records without credit recreation. Evidence: [retry and stale-grant tests](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-FC-08] Test malformed overlapping/gapped ranges, incorrect scopes and byte/count overflow. Evidence: [adversarial ledger tests](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-FC-09] Test healthy progress after sender exhaustion and receiver release/regrant. Evidence: [zero-credit recovery test](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-FC-10] Test retirement with unused credit, lost data, conflicting finals and stale flow IDs. Evidence: [retirement tests](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-FC-11] Run primitive unit/doc tests, formatting and warning-denied Clippy. Evidence: [local receipt](#local-validation-receipt); repository-wide checks belong to the integrating root task.
- [ ] [MOD-FC-12] Add authenticated wire serialization, feedback retries and distributed final barriers.
- [ ] [MOD-FC-13] Add independent-short release and recovery/FEC/codec retention accounting.
- [ ] [MOD-FC-14] Add delivery/RTT/demand estimation, pacing, AQM and wire QoS around the target controller.
- [ ] [MOD-FC-15] Integrate optional TCP proxy ownership and real namespace/device receipts.

## Adaptive target controller design

This is transparent-TUN tunnel credit policy, never endpoint TCP `cwnd`/`rwnd`.
The runtime supplies authenticated feedback estimates and monotonic microsecond
timestamps; this module does not read a clock or estimate a network path from
simulator configuration. TAP does not select this controller.

| API | Responsibility |
| --- | --- |
| `TargetController::new(config, now)` | Validate byte/count caps and initialize an unissued target window. |
| `TargetController::update(now, feedback, demanding_flows)` | Return a bounded aggregate target and equal-share per-flow targets; accept at most one growth step per measured RTT. |
| `TargetController::restart(now)` | Reset the unissued target after path/idle changes without touching ledger grants. |
| `ReceiverCredits::grant_to_target(flow, flow_target, session_target)` | Replenish only after release, respecting both target and actual free reservations; existing grants never decrease. |

`TargetConfig` specifies initial/minimum targets, session memory cap, uniform
per-flow memory cap, policy cap, queue allowance, queue-delay threshold, many-flow
additive step, maximum demanding-flow count, the few-flow threshold (1..4), a
bootstrap RTT and recovery RTT count. Demand is an explicit bounded unique flow
list. Its classification/hysteresis is runtime-owned; idle sockets are excluded.

`Feedback` supplies positive optional RTT/rate estimates, logical in-flight
bytes/count, queue delay and explicit receiver/ECN/loss/carrier pressure flags.
Ordinary sender credit exhaustion is an observable flag, never pressure. Growth
requires target utilization or actual queued demand exhausting its effective
grant, plus a measured RTT/rate and no pressure:
few flows grow at most 2x; more flows add a configured fixed step. Long gaps do not
cause multiple catch-up growth steps. Aggregate target is capped by all configured
caps, per-flow cap times demand count, and measured BDP plus queue allowance.
The byte/count minimum is subordinate to hard caps. Zero demand issues no target.

The exhaustion flag matters when an engine protects unused flow slots: a single
sender can reach its effective grant before in-flight data reaches the aggregate
target. The runtime may assert it only after actual retained demand hits that
grant. It does not fabricate in-flight bytes, bypass the RTT/rate or timing gates,
or override pressure. [The active engine](active.md) exercises this reservation
case with an aggressive early flow and a later small flow.

ECN/loss/carrier/receiver pressure reduces the target immediately, then no more
often than one RTT while persistent. Excess queue delay must persist for one RTT
before it triggers pressure. Growth resumes only after a configured quiet period.
Pressure and cap shrink affect future grants: existing ledger reservations remain
unchanged. Replenishment can run independently of growth and data arrival, so a
sender with exhausted credit can resume after release without an RTT-growth event.
Byte/count dimensions replenish independently: an already-issued count allowance
above a reduced count target does not prevent replenishing freed byte capacity.
Otherwise a sender could be unable to consume its remaining count promises
because it cannot send the payload bytes needed to drain them. Neither dimension
issues additional credit beyond its own target or actual free memory capacity.

Per-flow targets divide the aggregate equally; remainder units rotate at most
once per RTT. This provides equal credit shares and bounded remainder preference,
not wire-rate fairness, weighted QoS or instantaneous revocation of old grants.
The existing QoS/MUX scheduler still controls actual admission and wire service.
An old flow's unspent grant must drain/retire before its reservation is reusable.

- [x] [MOD-FC-16] Specify target-controller API, time/feedback ownership and grant separation. Evidence: [controller design](#adaptive-target-controller-design).
- [x] [MOD-FC-17] Implement checked monotonic-time RTT-gated few/many-flow target updates and all hard caps. Evidence: [TargetController](../../crates/l2tunnel-flow-control/src/target.rs).
- [x] [MOD-FC-18] Implement pressure reduction, queue-delay persistence, recovery hysteresis and explicit path restart. Evidence: [controller and state transitions](../../crates/l2tunnel-flow-control/src/target.rs).
- [x] [MOD-FC-19] Implement bounded equal flow shares with rotating remainders; validate duplicate/oversized demand sets. Evidence: [allocation and validation tests](../../crates/l2tunnel-flow-control/src/target/tests.rs).
- [x] [MOD-FC-20] Integrate target-only replenishment with irrevocable receiver reservations. Evidence: [ReceiverCredits::grant_to_target](../../crates/l2tunnel-flow-control/src/lib.rs).
- [x] [MOD-FC-21] Test time regression, repeated feedback, long gaps, BDP/policy/memory limits and small/large demand sets. Evidence: [controller adversarial tests](../../crates/l2tunnel-flow-control/src/target/tests.rs).
- [x] [MOD-FC-22] Test pressure without grant revocation, sender exhaustion recovery and progress after release. Evidence: [controller/ledger integration tests](../../crates/l2tunnel-flow-control/src/target/tests.rs).
- [x] [MOD-FC-23] Run final targeted unit/doc tests, formatter and warning-denied Clippy for the controller wave. Evidence: [local validation receipt](#local-validation-receipt).
- [x] [MOD-FC-24] Share authoritative sender admission validation between nonmutating preview and commit. Evidence: [preview and atomic rejection tests](../../crates/l2tunnel-flow-control/src/tests.rs).
- [x] [MOD-FC-25] Let actual effective-grant exhaustion qualify demand without bypassing measured growth, pressure, no-demand or RTT gates. Evidence: [focused controller regression](../../crates/l2tunnel-flow-control/src/target/tests.rs).

No Python byte-parity claim applies: cumulative credit is a new real-protocol
requirement, not a port of the simulator's fixed window or workload TCP controls.

## Local validation receipt

Commands run in the Linux workspace: `cargo fmt -p l2tunnel-flow-control`,
`cargo test -p l2tunnel-flow-control`, and
`cargo clippy -p l2tunnel-flow-control --all-targets -- -D warnings`.
Primitive wave: 15 unit tests and one public lifecycle doctest passed. Controller
wave: 25 unit tests and the same doctest passed; formatting and warning-denied
Clippy passed. These checks do not exercise network
authentication, kernels, devices or native clients. No full-repository or
cross-platform verification is claimed by this module receipt.

Active-composition followup: `cargo test --offline -p l2tunnel-active -p
l2tunnel-flow-control` passed 12 active tests, 31 ledger/controller/wire tests and
one flow-control doctest. `cargo fmt -p l2tunnel-active -p l2tunnel-flow-control`
and warning-denied `cargo clippy --offline -p l2tunnel-active -p
l2tunnel-flow-control --all-targets -- -D warnings` also passed. The wire tests are
the separate [credit-wire](credit-wire.md) module's work, not an authentication
implementation in these ledgers.
