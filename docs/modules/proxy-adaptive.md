# Measured TCP proxy credit and native receive-window response

Status: reviewed design with a focused-tested pure allocation checkpoint. The
planner, atomic table targets and terminal grant-debt snapshots are implemented;
the canonical measurement codec and bounded record owner are also focused-tested.
Measured observations, adaptive runtime/client selection and native qualification
remain planned. Caller-supplied feedback in pure tests is not measured evidence. The
existing [fixed-credit runtime](proxy-runtime.md) and [clean native receipts](proxy-native.md)
remain separate evidence. The [wave 11 receipt](../../work/implementation-wave11/validation.json)
includes the pure allocator and codec, but predates the bounded record owner.

This is an explicit extension of `tun_tcp_proxy`. It keeps the maintained TCP
owners, Open/Ready/Commit, reliable records, native confirmation, common MUX and
full/paired TLS ownership. It does not reuse the transparent TUN active ledger as
though transparent packet delivery were a native TCP acknowledgment. The planned
runtime slice changes future relay grants in response to measured demand and delivery;
the resulting native receive-window response requires its own packet evidence.

## Current source establishes a limited actuator

The following are current interfaces, not proposed implementations:

| Existing surface | What it actually supplies |
| --- | --- |
| [`Leg::set_target`, `Leg::advance`](../../crates/l2tunnel-tcp-proxy/src/lib.rs) | A byte/record target for future cumulative relay grants. Grant creation is `max(previous_grant, acknowledged + target)` per dimension. Lower targets cannot recall an existing grant. |
| [`Table::set_target`, `relay_status`, `flow_status`](../../crates/l2tunnel-tcp-proxy/src/session.rs) | Per-active-flow target updates and real maintained/relay ownership counters. Opening and terminal owners do not accept target changes. |
| [`TcpEngine::new_ip`, `read`, `write`, `status`](../../crates/l2tunnel-raw-tcp/src/lib.rs) | Fixed receive/send rings allocated before TCP establishment, bounded native packets, ordered receive consumption and actual send-queue occupancy. No live ring resize, exact advertised-window setter, cwnd setter or RTT getter is exposed. |
| [Pinned maintained TCP socket](../../third_party/smoltcp/src/socket/tcp.rs) | `scaled_window()` derives the window from receive-ring space; `recv_impl()` advances receive consumption; `window_to_update()` determines when to advertise a significant reopening. SYN window fields are unscaled. These are stack decisions, not a controller callback. |
| [`TargetController`](../../crates/l2tunnel-flow-control/src/target.rs) | Bounded future-credit policy: measured few-flow doubling, many-flow additive growth, pressure reduction and recovery hysteresis. It neither reserves issued proxy grants nor measures traffic. |
| [Proxy arbiter](../../crates/l2tunnel-runtime/src/proxy/arbiter.rs) | Shared weighted byte DRR and channel FIFO for transparent frames and every proxy record. Native output has the corresponding shared native arbiter. |

For a stream A → B, B's relay controller grants A future relay capacity. A may
then consume its maintained native receive ring into immutable relay records.
Consumption frees ring space, and the maintained stack may advertise a larger
native receive window to A's application-side sender. When the grant is exhausted,
A stops consuming that ring; the remaining already-advertised space can fill and
the stack eventually advertises pressure/zero window. Both directions follow the
same rule independently, even though the TLS client remains the sole connection
originator in the current proxy profile.

The receive ring starts with its configured capacity available. This design
cannot advertise a smaller initial TCP window and then enlarge that ring online.
It cannot promise an exact rwnd after a target update or a one-update/one-packet
relationship. Larger initial ring capacity is an immutable, preallocated
per-connection policy; its memory is charged even when relay targets are small.
Arbitrary live rwnd sizing would need a separately reviewed maintained backend
capability. No smoltcp mutation, forged ACK, buffer replacement, private-field
access or native packet rewrite belongs in this slice.

## Three window domains and confirmation boundaries

| Domain | Authority and units | Planned control and required observation |
| --- | --- | --- |
| Native TCP legs | Maintained native stacks and real peers own byte sequence/ACK spaces, rwnd, scaling, cwnd, retransmission and persist. | Indirect receive consumption through peer relay grants, within the fixed ring. Record actual emitted/delivered TCP window fields and native ACK progress. cwnd remains unknown unless a separate authoritative observer supplies it. |
| Reliable relay | Each receiving relay owns cumulative original-byte/record grants and the reservation for all granted offsets. | Adaptive future targets, exact grant debt, measured native-ACK delivery rate, peer demand and bounded shared scheduling. A target is neither a TCP window field nor total process memory. |
| Outer carrier | The retained kernel TCP/TLS connections own outer cwnd/rwnd, retransmission and stream ordering. | Observe bounded writer delay/queue pressure. Preserve kernel congestion control and all physical lanes. No multiplication of allowances by adding flows or lanes; a finite application budget is not a physical wire congestion controller. |

TCP transmission is constrained independently by congestion and receive windows;
increasing receiver space cannot override cwnd. [RFC 5681 section 2](https://www.rfc-editor.org/rfc/rfc5681.html#section-2)

At B, `acknowledged.bytes = injected_bytes - maintained_send_queue_bytes`, only
after the existing abnormal-close checks. Fully acknowledged record boundaries
advance `acknowledged.records`. Writing a relay record into the send ring, writing
an IP packet to TUN, flushing TLS and receiving a native TCP ACK are different
events. Only the last releases relay grant debt. A peer TCP ACK still does not
prove application consumption or durable storage; split TCP retains the existing
failure semantics. [RFC 3135 sections 3.1.2 and 4.1.3](https://www.rfc-editor.org/rfc/rfc3135.html)

Native packet ownership remains immutable until the actual complete
`PacketDevice::transmit` succeeds. Its credit/queue budget is additional to relay
grant reservations. WouldBlock cannot confirm native delivery or advance an
observation from "generated" to "delivered".

## Implemented pure allocation checkpoint

[`adaptive`](../../crates/l2tunnel-tcp-proxy/src/adaptive.rs) depends only on the
existing pure target policy and the actual proxy table. It accepts explicit
`Feedback` and a bounded distinct active-flow demand set as caller assertions.
It does not authenticate these inputs, collect observations or drive TCP. The
future measured controller below must derive them from authoritative observations.

```rust,ignore
pub struct Config {
    pub target: TargetConfig,
    pub minimum_per_flow: Window,
}
pub struct FlowWeight { pub flow: u64, pub weight: u16 }
pub struct Planner;
pub struct Plan; // Opaque; owns a bounded proposal and exact table snapshot.

impl Planner {
    pub fn new(config: Config, table: &session::Table,
               now: Micros) -> Result<Self, Error>;
    pub fn bind_flow(&mut self, weight: FlowWeight) -> Result<(), Error>;
    pub fn status(&self) -> PlannerStatus;
    pub fn prepare(&self, table: &session::Table, feedback: Feedback,
                   demanding: &[u64], now: Micros) -> Result<Plan, Error>;
    pub fn apply(&mut self, table: &mut session::Table,
                 plan: Plan, now: Micros) -> Result<Applied, Error>;
}
impl Plan {
    pub fn allocation(&self) -> &Applied;
}
```

`Applied` separates the policy candidate from actual active targets and reserved
debt, including unallocated/Opening and terminal reservations. It reports the
candidate policy state and revision; it is not permission to send. `PlannerStatus`
reports only committed logical time, revision and integer-remainder cursor.
Immutable weights in 1..=16 may be bound to lifetime slots before activation;
every active slot must have a weight before preparing a complete plan.

[`Table::policy`, `credit_status`, `set_targets`](../../crates/l2tunnel-tcp-proxy/src/session.rs)
expose the validated immutable geometry, active/final credit accounting and an
all-or-nothing target batch. Single-target calls reuse the same preflight. Target
updates do not poll the table, generate grants, consume a receive ring or change
any existing relay bytes or fixed-profile default.

Each table and planner has a private local owner identity. Copied session IDs do
not make two instances interchangeable. A prepared plan binds its planner
revision, exact table snapshot and preparation time. Apply requires that same
logical time, rechecks every owner phase, credit offset, target and table time,
then validates the entire batch before its infallible commit. Only after the
table batch succeeds does candidate-policy history advance. The caller must
reprepare after time or relevant table state changes. Opaque plans are bounded
per value; callers own any additional copies prepared without applying them.

Terminal accounting adds one `Option<CreditSnapshot>` per lifetime entry:
acknowledged, received, granted and target, each a two-u64 `Window` (64 bytes of
field data plus the option discriminant/padding). Stop captures these counters
before aborting the maintained leg; clean retirement captures them before dropping
it. This fixed metadata has no payload. Owner identities, bounded snapshot/target
vectors and the existing target-controller state are additional metadata; none is
included in the table's existing payload-capacity bound. A planner attached after
termination still charges the frozen reservation instead of treating an emptied
send queue as proof of acknowledgment.

The planner uses weighted, checked byte/count water filling under a common hard
reservation cap. Existing debt costs no additional space when a desired target
remains below it. Floors remain positive even with zero demand. Capped flows leave
their excess for other demanding flows; integer remainders rotate no more than
once per supplied RTT. This is an allocator over explicit inputs, not a measured
fairness or native-window claim.

## Planned measurement interface and ownership

The next [measurement codec/owner contract](proxy-measurement.md) refines this
proposal into separate codec, retained-output and observation checkpoints. It
specifies the common-MUX admission timestamp needed when a reply arrives before
the writer-completion callback. Its allocation-free codec and pure bounded
record owner are implemented; observation and runtime interfaces remain proposed.

These names are a proposed contract, not available Rust APIs. Implementation
will compose the existing pure planner instead of creating another grant owner.
Time is injected as `target::Micros`; table polling
continues using checked conversion to its existing `Millis`. No Tokio, sockets,
device handles or process-global clock enters the pure module.

```rust,ignore
pub struct MeasuredConfig {
    pub allocation: Config,
    pub measurement: MeasurementConfig,
}

pub struct MeasurementConfig {
    pub report_interval_micros: u64,
    pub probe_interval_micros: u64,
    pub probe_timeout_micros: u64,
    pub sample_ttl_micros: u64,
    pub demand_idle_micros: u64,
    pub rate_interval_micros: u64,
    pub rate_window_intervals: u8,
    pub max_measurements_per_interval: u16,
    pub measurement_rate_interval_micros: u64,
}

pub struct FlowPolicy { pub id: u64, pub weight: u16 }
pub struct Pressure {
    pub shared_wire_sojourn_micros: u64,
    pub native_sojourn_micros: u64,
    pub receiver_blocked: bool,
    pub carrier_blocked: bool,
}

pub struct Controller;       // Owns bounded measurements/reservation policy.
pub struct ObservationId;    // Private fields: scope, kind, generation.
pub struct TargetPlan;       // Opaque complete plan; no caller-edited grant rows.
pub struct Applied;          // Immutable status/counters, not authority to send.
pub struct Error;            // Explicit bounds/scope/order/time/accounting errors.

impl Controller {
    pub fn new(config: MeasuredConfig, table: &session::Table,
               direction: Direction, now: Micros) -> Result<Self, Error>;
    pub fn bind_flow(&mut self, policy: FlowPolicy) -> Result<(), Error>;
    pub fn observe_table(&mut self, table: &session::Table,
                         now: Micros) -> Result<(), Error>;
    pub fn receive_authenticated(&mut self, table: &session::Table,
        record: &[u8], now: Micros) -> Result<(), Error>;
    pub fn pending(&self) -> Option<(ObservationId, &[u8])>;
    pub fn confirm_handoff(&mut self, id: ObservationId,
                           now: Micros) -> Result<(), Error>;
    pub fn prepare(&self, table: &session::Table, pressure: Pressure,
                   now: Micros) -> Result<TargetPlan, Error>;
    pub fn apply(&mut self, table: &mut session::Table,
                 plan: TargetPlan, now: Micros) -> Result<Applied, Error>;
    pub fn quiesce(&mut self, now: Micros) -> Result<(), Error>;
}
```

`Direction` is a closed client→server/server→client enum bound to the actual
authenticated roles. Each endpoint has one controller for its incoming relay
direction. The same bounded owner reports its table's outgoing demand and answers
incoming echo requests for the opposite direction; these do not create a second
target authority. `Table` continues to hold both native stream directions.

`Controller::new` will reuse the actual validated table policy; it must not accept
an independently asserted maximum that could disagree with that table.
`observe_table` reads each of at most 64 lifetime entries once. The implemented
batch-target operation validates every active ID and target before changing any
target; it neither polls nor grants credit. The planned controller must preserve
the pure planner's atomic commit and stale-plan rules.

`prepare` is read-only and produces a plan tied to the controller revision and
the exact relevant table snapshot: owner phases, cumulative acknowledged/granted
offsets and current targets. `apply` rechecks that snapshot, scope, monotonic time
and all constraints before its atomic target batch. A stale plan changes neither
targets nor controller history. No table poll, authenticated receive, native
ingress or handoff may interleave with this short single-owner commit. A single
bounded pass updates all active targets before the next table poll. Flow weights
are fixed from the authenticated session's existing DSCP policy and lifetime
binding; peer reports cannot select a weight.

Maximum flow count remains 64; record maxima remain 1024 per flow and byte maxima
4 MiB per flow. The measurement window has 1..16 slots. Timings are positive,
checked integral microseconds, individually at most 120 seconds; report/probe/rate
intervals are at least 1 millisecond. Sample TTL is at least a report interval and
a probe timeout; demand idle time is at least a report interval. Counter/time
overflow, backward local time and unrepresentable table time fail explicitly.
Configuration validation uses the actual table/ring/scheduler geometry, rather
than copying these limits into an unrelated permissive parser.

## Outstanding grants constrain every allocation

For each receiving active relay i, use authoritative original-byte/record pairs:

```text
A_i = native acknowledged cumulative offset
R_i = relay received cumulative offset
G_i = cumulative grant already created, including an unsent retained Credit
T_i = proposed future outstanding target
D_i = G_i - A_i                         # Irrevocable grant debt
Q_i = componentwise_max(D_i, T_i)       # Reservation required after applying T_i
0 <= A_i <= R_i <= G_i
sum(Q_i) + opening/unallocated + terminal reservations <= session reservation cap
T_i <= per-flow maximum, in both bytes and record count
```

`G_i - R_i` is capacity promised to bytes/records that may not have arrived;
`R_i - A_i` is accepted unacknowledged ownership. Both count. Do not substitute
occupied queues, produced records, target sums or TLS delivery for grant debt.
Records count separately: a large byte allowance cannot permit unbounded one-byte
records. `max` and `sum` above are componentwise checked operations.

To avoid an opening creating an unreserved initial grant, reserve `table.initial`
for every not-yet-allocated lifetime owner slot from session construction. Require
`max_flows * initial <= session_cap` in both dimensions. Opening entries retain
that reservation until activation. Active entries retain at least
`minimum_per_flow`, which is positive, no larger than `initial` and able to admit
one `max_record_bytes` record. Each remaining initial reservation is included in
the allocation calculation, so few-flow borrowing cannot consume the next Open's
guarantee. This is an explicit conservative capacity cost, not an elastic memory
allocation claim.

Active targets may decrease immediately; debt decreases only through actual ACK
progress. Allocate growth only from unused reservation after charging every
remaining old grant. A pressure reduction can therefore yield
`reserved > desired_target`; report both without shrinking an issued right edge.
Never recycle another flow's unused grant because that flow looks idle. Terminal
entries conservatively retain their last reservation until session close in this
first slice; clean flow retirement still releases maintained resources according
to the table, but does not create a new flow ID or justify forgetting old control
messages. A later terminal-reservation reclamation protocol is a separate gate.

The hard logical reservation cap is immutable and independent from the dynamic
policy target. A candidate reduction below outstanding debt stops new excess
growth rather than making existing traffic invalid. Preallocated receive/send
rings, native packet queues, held outputs, scheduler copies, measurement metadata,
TLS buffers and allocator overhead have separately counted bounds. Preserve the
table's configured 256 MiB payload-capacity ceiling; the sum of logical targets
alone is never described as the process memory bound.

## Measurement protocol on the common user path

The adaptive profile proposes one canonical `LTPM` measurement family. Existing
`LTPA`, `LTPR` and `LTPX` bytes remain unchanged. `LTPM` is parsed only after actual
authenticated outer framing, role, flow binding and epoch validation; a user TUN
packet cannot invoke it. The adaptive runtime intercepts it before ordinary table
record dispatch. Fixed-credit sessions reject it.

All integers are big endian; exact lengths and zero reserved fields are mandatory.
The proposed fixed header is 48 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | `LTPM` |
| 4 | 1 | Version 1 |
| 5 | 1 | Demand(1), EchoRequest(2), EchoReply(3) |
| 6 | 1 | Measured stream direction: authenticated client→server(1) or reverse(2) |
| 7 | 1 | Zero |
| 8 | 16 | Common logical session ID |
| 24 | 8 | Epoch |
| 32 | 8 | Lifetime flow ID |
| 40 | 8 | Monotonic message serial per flow/direction/kind |

Demand is exactly 104 bytes: the header plus produced bytes/records(16), observed
peer grant bytes/records(16), actual unread native-ring bytes(8), pending original
Data bytes(8), credit-blocked flags(1: byte/count bits) and seven zero bytes. The
producer supplies this report; its reported grants cannot exceed grants actually
created by the receiver. Produced offsets cannot regress or exceed those grants.
Native unread and pending Data bytes cannot exceed the configured ring/record
bounds. A Credit/Fin/measurement record alone is not native payload demand.
Reports are hints for bounded policy, never evidence releasing memory.

EchoRequest/EchoReply are exactly 56 bytes, with one u64 nonce after the header.
For A→B, B requests an echo from A on that flow; only A may reply and only B may
use the matching outstanding nonce. There is no peer clock or peer-selected
timestamp in the record. Each receiver controller permits at most one in-flight
probe across its direction's flows, rotating fairly over demanding flows. A
timeout retires the nonce permanently and suppresses growth until fresh evidence;
it does not declare native loss or grant extra capacity.

All measurement kinds use the existing flow's class/weight, MUX channel pool,
FIFO ordering, record count, framed-byte admission and writer capacity. This is
the same path used by Data, Credit, Open, ACK-bearing native packets and ordinary
transparent traffic. Measurement does not take the session Ready/Barrier/control
service reservation or a separate priority lane. In paired-half mode, each
measurement travels on its actual bulk direction's ordinary user path, not a
privileged reverse control writer. A saturated path may delay/stale measurement;
that freezes growth and is not an excuse to bypass admission.

Before scheduling there is at most one replaceable Demand and one EchoReply slot
per flow, plus the direction's single pending EchoRequest. Once copied into the
arbiter, a record is immutable until full writer completion or session failure;
one subsequent dirty report is coalesced in its slot. Bound all slot metadata and
copied payload separately, at most `2 * max_flows + 1` pending slots and one
scheduled copy per slot. The single probe token and accepted serials have fixed
storage. Flow/kind round-robin service and a shared rate bucket bound output to
`max_measurements_per_interval` records per configured interval, without a
catch-up burst after pauses. The bucket is an additional ceiling inside existing
user capacity. EchoRequests obey the negotiated emission rate at the sender.
The receiver uses bounded slots and runtime read work; queue-induced bursts are
not rejected by comparing differently phased intervals. Replies remain bounded
by the local emission bucket and common MUX.

Retain the latest accepted serial and exact fixed-size record for each allowed
kind/scope. An identical duplicate is a no-op: it cannot refresh demand, sample
TTL, probe deadline or rate. A conflicting same-serial message is an error; older
serials cannot revive state. Coalesced reports may skip serials, so serials need
not be contiguous. A novel message for a retired or wrong-epoch flow cannot
recreate an owner. Sequence/nonce exhaustion requires a new session.

## Provenance of rates, delays and demand

The growth inputs deliberately have different meanings:

* **Egress delivered rate:** a bounded rolling average of positive deltas of the
  local relay's actual `acknowledged.bytes`, sampled on local monotonic time over
  complete `rate_interval_micros` intervals. Rates combine only flows in the
  controller's own direction. Queue insertion/TUN write/TLS flush is not a sample.
  Reset/timeout is terminal before a shrinking send queue could fabricate ACKs.
  Empty/stalled intervals remain part of the window; zero rate is represented as
  unavailable to `TargetController`, with actual stall pressure separate.
* **Authenticated tunnel service RTT:** local successful common-MUX admission
  time for an EchoRequest until its matching authenticated reply, eligible only
  after complete write confirmation. It includes local writer, TLS, both common
  schedulers and peer actor delay. Start once, never on repeated polling/failed
  admission, and never replace it with a peer timestamp. A reply may precede the
  writer callback; retain one candidate without renewing its original deadline
  or receipt freshness. First sample initializes SRTT; subsequent
  samples use checked integer `(7 * SRTT + sample) / 8`, with at most one live
  sample. Track local freshness independently. This is not a native TCP RTT or a
  kernel TCP_INFO measurement.
* **Native TCP RTT:** currently unavailable from `TcpEngine::status`. Report
  `None`, not echo RTT. A future authoritative stack accessor or bounded passive
  estimator requires its own review; retransmitted sequence ranges cannot yield
  an unambiguous native RTT without the appropriate timestamp evidence.
  [RFC 6298 section 3](https://www.rfc-editor.org/rfc/rfc6298.html#section-3)
* **Demand:** a fresh scoped producer report with unread native bytes or a pending
  Data record. Keep it demanding until both empty reports and the configured
  idle interval have elapsed; report TTL expiry makes demand unknown and forbids
  growth. Connected sockets, lifetime tombstones, pure ACKs, probes and an unused
  grant do not count as demanding flows. Reappearance starts with a fresh report;
  stale samples are not inherited across idle, new flow, session or epoch.

Record sojourn from the first local queue admission until actual next-owner
handoff; failed retries preserve that timestamp. Track native WouldBlock and
writer capacity blocking independently. Fresh producer offsets can estimate
admitted relay flight as `max(reported_produced, received) - acknowledged`, capped
by the authoritative grant debt. A stale report cannot establish utilization.
Credit-exhausted demand qualifies growth only when the report's observed grant is
the current relevant grant; a stale report from before replenishment does not.

The policy's rate × service-RTT term is a measured pipeline heuristic plus finite
queue allowance. It is not a measured path capacity or proof of available native
cwnd. Configured lab rate is never supplied as delivered rate. The first slice
has no authoritative ECN/loss input from kernel TLS or a native congestion
observer: those inputs remain absent/false, never inferred from a zero window or
missing echo. Failure and timeout paths keep their existing meanings.

## Growth, pressure and QoS allocation

Reuse the existing `TargetController` as the aggregate candidate policy. Its
equal-share output is not used as an issued grant ledger. After charging opening,
idle and terminal reservations, the proxy planner distributes the usable
candidate across demanding flows with their fixed QoS weights and per-flow caps.
Use checked weighted water filling: cap fulfilled flows, redistribute remaining
units among the rest, and rotate integer remainders at most once per measured
RTT. Work is bounded by at most 64 flows and at most 64 cap-removal rounds. Bytes
and records are allocated independently, with every active flow retaining its
positive minimum. Reserved debt always wins over a desired weighted share.

At most one policy step occurs per fresh measured RTT; a long pause never causes
multiple catch-up increases. With 1..`few_flow_threshold` demanding flows (maximum
threshold 4), the aggregate candidate can double. With more flows it grows by the
configured additive step. Require fresh positive rate, fresh service RTT, actual
utilized/credit-exhausted demand, quiet recovery and hard reservation room.
No measured estimate means bounded bootstrap, not speculative growth. Candidate
caps include session/per-flow memory, operator policy and measured rate × RTT
plus bounded queue allowance. Fixed opening reserves can make the usable target
smaller than the candidate; expose the limiting reason.

Persistent shared/native sojourn, actual blocked receiver capacity or retained
writer pressure suppresses growth and enters the existing pressure/recovery
policy. Immediate future-target reduction never revokes grant debt. Merely
reaching a healthy sender credit ceiling is demand, not congestion. A blocked
native receiver cannot cause synthetic successful ACKs or target renewal that
exceeds reserved capacity. After pressure clears, require the existing quiet-RTT
hysteresis and a fresh sample before increasing again.

The two existing directional arbiters remain authoritative. Every queued item,
including all measurement, handshake, ACK/FIN and user-probe work, consumes the
same configured channel budget and byte DRR service. Channel FIFO can constrain
ideal weighted fairness; test and report that constraint rather than claiming
strict per-flow isolation. The first slice retains the existing fixed DSCP weight
mapping and single scheduler class. Multi-class guarantees, class ceilings and
arbitrary live weight changes are separate work, not implied by weighted target
allocation. A flow's extra credit does not grant extra wire turns.

## Runtime composition, binding and lifecycle

Proposed additive runtime API:

```rust,ignore
pub struct Config { pub fixed: proxy::Config, pub adaptive: adaptive::MeasuredConfig }
pub struct Link; // Wraps the actual verified retained full/paired Link privately.
pub struct Status { pub session: proxy::Status, pub adaptive: AdaptiveSnapshot }
pub struct Handle;  // Wraps the existing command producer plus bounded snapshots.
pub struct Control; // Retains the existing single command receiver, not a second one.
pub struct AdaptiveSnapshot; // At most 64 rows plus fixed aggregate counters.
pub fn session_config(config: &Config) -> io::Result<auth::SessionConfig>;
pub fn control_channel() -> (Handle, Control);
impl Handle {
    pub fn status(&self) -> Option<Status>;
    pub fn request_drain(&self) -> io::Result<proxy::DrainWaiter>;
}
impl Link {
    pub fn full(connection: auth::AuthenticatedConnection,
                config: &Config) -> io::Result<Self>;
}
pub async fn client_pair(first: auth::AuthenticatedConnection,
    second: auth::AuthenticatedConnection, config: &Config) -> io::Result<Link>;
pub async fn server_pair(first: auth::AuthenticatedConnection,
    second: auth::AuthenticatedConnection, config: &Config) -> io::Result<Link>;
pub async fn run<D: PacketDevice<Error = io::Error>>(
    device: D, link: Link, config: Config, control: Control,
) -> io::Result<proxy::CloseReport>;
```

The wrapper preserves the current one-slot command queue, prompt drain submission
and actual terminal-result ownership; measurement snapshots cannot complete a
`DrainWaiter`. The ownership contract is one
actual existing proxy actor/table/native arbiter/wire arbiter/reader per lane,
with an additive fixed/adaptive policy owner. No second data pump, TCP stack,
reader or independent reservation manager owns the same bytes. New runtime files
and any narrow shared actor/manifest declarations need explicit coordination.
No current client or fixed-credit profile changes as part of this design.

Bind the exact existing proxy digest and ordered role mapping plus all adaptive
fields, maximum wire lengths, observation direction/serial rules, allocation
algorithm version and measurement-slot/work budgets under a distinct domain:
`l2tunnel/tun-tcp-proxy-adaptive/v1/fixed-rings/measured-relay`.
Use fixed-width canonical integer encodings, not Debug/serde field order. Bind
the unchanged TimeWait policy as part of the embedded fixed configuration;
`Maintained` remains the default. Negotiation rejects adaptive/fixed, unknown
version, routes, limits, clock-unit or role mismatches before native reads.
Full and paired factories verify actual authenticated lane information and retain
both physical owners; direction does not come from a caller's assertion.

Idle excludes a flow from aggressive growth but does not retire its TCP owner,
mapping, old grants, ACK state or tuple tombstone. Keepalive/idle timeout remains
the maintained connection policy. Only existing explicit clean/abnormal terminal
paths may end ownership; a timeout is never relabeled clean. No new flow ID is
allocated by telemetry and no live tuple is evicted to make controller space.

The first adaptive profile has a fixed epoch and no hot reload. Ordinary target
adjustments within authenticated caps do not change record interpretation and do
not require an epoch. Changing caps, rings, weights, algorithms or measurement
wire policy does require a future negotiated transition. Do not reset grant,
record, probe, packet or TLS counters. Old/native-owned flows cannot become
transparent midway through the stream. A proposed later transition must retain
all issued grants and old readers, matching digest/epoch, explicit drain barriers
and acknowledged retirement; a local config-file update is insufficient.

On either local or authenticated peer quiescence, stop new proxy owners and new
periodic probes, stop speculative growth, preserve existing admission deadlines
and finish retained ownership. Once measurement bytes enter the common MUX,
their exact OutputId and immutable copy remain owned through complete framed TLS
write and flush, including after terminal flow transitions or quiesce. There is
no admitted cancellation API or stale-copy discard. Only unadmitted B work may
coalesce, expire or be dropped. The [measured runtime contract](proxy-measured-runtime.md)
requires an empty token ledger and Controller::drained before the local Barrier.
Late echoes/pings during quiescence cannot demand a new response after the local
user Barrier; they have no role in clean completion. Do not wait for measurement
freshness to drain bytes.
Debt and safe minimum future replenishment remain valid so existing streams can
finish. The earliest original drain deadline governs every queue, native TCP and
TLS join; no controller update, echo, secondary lane or local waiter renews it.

## Required native advertised-window evidence

Pure target changes alone cannot pass this gate. First use four independent
maintained owners and then an owned Linux TUN lab with two real kernel endpoints.
Use exact opaque bidirectional bytes, SYN options and FINs; retain the default
TIME-WAIT policy and fixed deadlines. Existing clean receipts are the fixed-credit
comparison, not proof of this algorithm. New privileged cases require a separate
approved harness contract and immutable build provenance.

Capture both native TCP legs from SYN through closure. Parse negotiated scaling
for each direction; SYN/SYN-ACK fields remain unscaled. Observe actual ACK and
window values after native transmission, separately from queued generated
packets. Reconstruct sequence/ACK progress with checked wrap-aware arithmetic;
reject ambiguous captures, truncation, unsupported options or missing handshake
evidence. Window scale is negotiated during establishment, not changed by later
credit updates. [RFC 7323 sections 2.2–2.3](https://www.rfc-editor.org/rfc/rfc7323.html#section-2.2)

The required pressure/recovery trace correlates: authenticated target decision →
actual grant handoff → peer receive-ring consumption/stall → emitted and delivered
native window → remote sender ACK/byte progress. Under a blocked egress application,
first observe real egress ACK plateau, retained debt and eventual producer-side
native window pressure. After unblocking, observe actual native ACK release,
safe credit replenishment and a larger advertised available window with renewed
exact-byte progress. A larger target with no native window change is explicitly
"relay target changed; native effect unobserved", not a passed window gate.

The controller never shrinks a granted relay right edge. Native TCP window
right-edge validation belongs to the maintained protocol's semantics, including
scaling quantization; track ACK advance separately from the field value. Do not
mistake a falling window field with an advancing ACK for revoked capacity. Any
rounding retraction must be identified and bounded using the negotiated scale,
not silently exempted or corrected by rewriting packets. Excess/unexplained
retraction fails the gate. [RFC 9293 window management](https://datatracker.ietf.org/doc/html/rfc9293#section-3.8.6),
[RFC 7323 section 2.4](https://www.rfc-editor.org/rfc/rfc7323.html#section-2.4)

Receipts report per direction: targets, grants, ACK-confirmed original bytes,
reserved debt, native rings/queues, RTT provenance/freshness, demand count and
weight, policy transitions, limiting cap, P95/P99 queue delay, exact goodput,
native/outer wire bytes, CPU/RSS, and finite-window weighted fairness. Include
1/2/4/16/64 demanding flows, many idle connected flows, simultaneous joins/exits,
small requests mixed with bulk, blocked native/TLS outputs and restored capacity.
Assess measured throughput against the fixed-credit baseline without claiming
that raising rwnd forces cwnd growth or establishes general Internet fairness.

## Acceptance checklist

- [x] [MOD-PROXY-ADAPT-01] Review and freeze the limited actuator, three window domains, pure ownership/API and planned measured-wire gate before implementation. Evidence: [reviewed boundary and staged interfaces](#implemented-pure-allocation-checkpoint); parent approval and independent measurement/reservation design review, with runtime binding still a later gate.
- [x] [MOD-PROXY-ADAPT-02] Add bounded pure configuration/snapshot/batch-target surfaces without changing fixed relay bytes, TCP rings, default TIME-WAIT or fixed-profile behavior. Evidence: [planner/configuration](../../crates/l2tunnel-tcp-proxy/src/adaptive.rs), [actual table policy and atomic batch](../../crates/l2tunnel-tcp-proxy/src/session.rs), [focused regressions](../../crates/l2tunnel-tcp-proxy/src/adaptive_tests.rs).
- [x] [MOD-PROXY-ADAPT-03] Implement atomic grant-debt reservations, unallocated/Opening minima and weighted byte/count allocation; test old grants after reduction, 64 concurrent activations, one-byte records, overflow and stale plans with no partial mutation. Evidence: [thirteen pure regression cases](../../crates/l2tunnel-tcp-proxy/src/adaptive_tests.rs), [focused validation boundary](#pure-checkpoint-validation).
- [ ] [MOD-PROXY-ADAPT-04] Implement exact authenticated LTPM decoding, role/direction/flow/epoch checks, bounded coalescing, rate/work caps, serial/nonce exhaustion and duplicate freshness invariants.
- [ ] [MOD-PROXY-ADAPT-05] Implement actual native-ACK delivery-rate sampling, local-clock echo provenance, demand hysteresis and missing/stale evidence behavior; prove TUN/TLS writes and resets cannot fabricate delivery or RTT.
- [ ] [MOD-PROXY-ADAPT-06] Reuse measured sparse/many-flow target policy with weighted reservation caps; test one step per RTT, pressure/recovery, 1/2/4/16/64 demand sets, idle shares, joins/exits and debt-limited regrowth.
- [ ] [MOD-PROXY-ADAPT-07] Compose one existing runtime actor and shared DRR/MUX for all data/control/measurement classes in full and paired-half modes; test saturation, FIFO head blocking, no privileged probes and independent native/outer pressure.
- [ ] [MOD-PROXY-ADAPT-08] Preserve Open/Ready/Commit, actual native output confirmation, reset/FIN handling, fixed epoch, earliest drain deadline and no post-Barrier measurements; test blocked native output and asymmetric paired shutdown.
- [ ] [MOD-PROXY-ADAPT-09] Prove four-owner actual advertised-window contraction/reopening, scaled/unscaled handshake interpretation, ACK release and exact bytes with no lost/revoked grant under growth and pressure.
- [ ] [MOD-PROXY-ADAPT-10] Add explicit shared client configuration/status only after runtime review; reject unsupported reload/carriers and distinguish requested target, reservation, observed native window and unavailable cwnd/native RTT.
- [ ] [MOD-PROXY-ADAPT-11] Freeze an owned native harness and run clean TUN IPv4/IPv6 full/half packet-evidence gates with immutable builds, exact bytes/FIN, pressure/recovery and cleanup before any performance claim.
- [ ] [MOD-PROXY-ADAPT-12] Qualify finite delay/loss, demand-count/fairness/idle and queue/RSS matrices against fixed-credit baselines without changing native options, TIME-WAIT or deadlines to hide failures.
- [ ] [MOD-PROXY-ADAPT-13] Run focused adversarial tests, strict lint/docs, independent review and source-stable `python3 tools/check.py`; attach actual receipts without promoting broad proxy/catalog gates prematurely.
- [ ] [MOD-PROXY-ADAPT-14] Separately design negotiated live policy/epoch transitions and terminal reservation reclamation; keep them unsupported until old grants, ownership and retirement are proven.

## Pure checkpoint validation

Local commands run after the narrow table/planner implementation:

```text
cargo fmt -p l2tunnel-tcp-proxy --check
cargo test -p l2tunnel-tcp-proxy --offline
cargo clippy -p l2tunnel-tcp-proxy --all-targets --offline -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-tcp-proxy --no-deps --offline
python3 tools/check_checklists.py
```

The package has 31 passing tests: 13 adaptive regressions and all 18 pre-existing
proxy tests. The new cases cover actual one-byte/count exhaustion, old grant debt
above pressure-reduced targets, 64 active owners, zero demand, capped/rotating
integer remainders, arithmetic/clock limits, copied-scope cross-owner plans,
changed table time/targets/weights, late batch failure without history mutation,
and terminal snapshots captured before abort or clean retirement. A test fixture
initially closed the application hosts when only relay grants were ready; the
corrected fixture first waits for both actual host TCP connections to establish.
The default maintained TIME-WAIT behavior and production deadlines are unchanged.

Parent read-only review of the planner and narrow table changes found no material
blocker. This finite pure checkpoint does not implement measurement collection,
authentication of feedback, runtime selection or an adaptive advertised-window
result. No simulator, raw/vendor source, runtime, client or native lab changed in
this slice. The existing workspace flow-control path dependency is reused.
The source-stable [wave 11 receipt](../../work/implementation-wave11/validation.json)
includes this allocator and the canonical codec. The later bounded measurement
owner and future observation/runtime work retain separate gates, so the complete
MOD-PROXY-ADAPT-13 remains unchecked.
