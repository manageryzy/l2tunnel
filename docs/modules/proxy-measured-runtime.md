# Measured TCP proxy runtime integration

Status: the additive configuration, retained-link factories, version-2 framing,
private handoff ledger and actual common-actor composition are implemented.
Focused tests cover maintained native TCP endpoints over real authenticated TLS
in full/paired-half mode, plus bounded writer, expiry and admission failures.
Explicit measured client selection and bounded aggregate local status are now
implemented and focused-tested through the [shared client](proxy-measured-client.md).
Kernel advertised-window qualification, native activation evidence and per-flow
pagination remain separate gates.
The pure C checkpoint is recorded in
[its focused receipt](../../work/proxy-observation-c/validation.json). Its runtime
authority and native advertised-window gates remain separate.

## Scope and existing implementation constraints

The first profile is explicit TUN, compression None, ordinary retained TCP/TLS,
epoch 1, one full or two authenticated paired-half lanes. It composes the actual
existing proxy actor, Table, wire arbiter, native arbiter and persistent TLS tasks.
It does not add a data pump, change the maintained stack, resize rings, supply
native RTT/cwnd, change TIME-WAIT defaults, or expose hot reload. Existing fixed
proxy API, authentication digest, bytes and scheduling remain unchanged.

Authoritative source read for this proposal:

- [Fixed runtime factories](../../crates/l2tunnel-runtime/src/proxy.rs),
  [configuration](../../crates/l2tunnel-runtime/src/proxy/config.rs),
  [actor](../../crates/l2tunnel-runtime/src/proxy/actor.rs),
  [arbiter](../../crates/l2tunnel-runtime/src/proxy/arbiter.rs),
  [TLS tasks](../../crates/l2tunnel-runtime/src/proxy/io.rs), and
  [user framing](../../crates/l2tunnel-runtime/src/proxy/wire.rs).
- [Client policy/factories](../../crates/l2tunnel-client-core/src/proxy.rs),
  [local API](../../crates/l2tunnel-client-core/src/local.rs), and fixed proxy CLI.
- [C Controller](../../crates/l2tunnel-tcp-proxy/src/measurement/controller.rs),
  [B Owner](../../crates/l2tunnel-tcp-proxy/src/measurement/owner.rs), canonical
  LTPM codec, actual Table snapshots and pure adaptive Planner.
- [Adaptive boundary](proxy-adaptive.md),
  [B ownership](proxy-measurement.md),
  [C observation contract](proxy-observation.md), architecture,
  implementation plan and the explicit-proxy boundary in mode-parity.

Important actual API constraints, not missing functionality to assume:

1. `Controller` requires the actual Table identity, owns its Owner and Planner,
   and exposes no mutable inner owner or synthetic measurement input. Only its
   actual `observe_table` operation creates ACK-rate bins.
2. `OutputId` is opaque, cloneable and owner/generation-bound. It is not a Copy
   integer suitable for the current `arbiter::Owner` enum. The runtime needs a
   separately bounded token ledger; it must not reinterpret its private fields.
3. B/C admission is the successful common-MUX copy, **not** the later writer
   channel send. Admitted records have no cancellation API and survive terminal
   flows/quiesce until exact full-write confirmation or terminal failure.
4. `Progress.users` is already a continuous cumulative count published only after
   the complete outer length-prefix/header/body write and flush. It can prove a
   particular user ordinal was written, even when the watch coalesces updates.
   It provides no native ACK, application-consumption or physical wire timestamp.
5. The original fixed `Arbiter` did not expose admission age, and its source admission order
   can repeatedly fill capacity with table records before measurements get a
   turn. Shared dequeue DRR alone does not solve this producer-admission issue.
6. Fixed user framing admits version 1 classes 0/1 only. A measurement class
   requires a distinctly authenticated parser profile before any dispatch.
7. The client local response cap is 8192 bytes. A worst-case 64-flow diagnostic
   snapshot cannot simply be appended to every existing response.
8. Existing public `proxy::Link` factories insist on the fixed digest.
   The measured wrapper needs narrowly reviewed crate-private bound helpers;
   calling the fixed constructor and relabeling the result is invalid.

## Proposed public runtime and client surfaces

Place the public runtime wrapper at `l2tunnel_runtime::proxy::measured`, with
implementation in `proxy/measured.rs` plus bounded helper/test submodules. This
keeps the shared actor private to its existing module and avoids a second pump.
The proposed client module is `l2tunnel_client_core::proxy_measured`.

```rust,ignore
pub struct ServicePolicy {
    pub report_work_per_turn: u16,
    pub admission_work_per_turn: u16,
    pub callback_work_per_turn: u16,
    pub plan_interval_micros: u64,
    pub status_interval_micros: u64,
}
pub struct Config {
    pub fixed: proxy::Config,
    pub measured: measurement::MeasuredConfig,
    pub service: ServicePolicy,
}
pub struct MemoryBound { /* base, controller, fixed ledgers/scratch, shared-copy cap */ }
impl Config { pub fn validate(&self) -> io::Result<MemoryBound>; }
pub fn session_config(config: &Config) -> io::Result<auth::SessionConfig>;
pub struct Link; // Private actual retained lanes + exact measured binding.
impl Link {
    pub fn full(connection: AuthenticatedConnection, config: &Config) -> io::Result<Self>;
}
pub async fn client_pair(first: AuthenticatedConnection, second: AuthenticatedConnection,
    config: &Config) -> io::Result<Link>;
pub async fn server_pair(first: AuthenticatedConnection, second: AuthenticatedConnection,
    config: &Config) -> io::Result<Link>;
pub struct Status {
    pub runtime: proxy::Status,
    pub measurement: Snapshot, // Concrete copied observations and last actual apply.
}
pub struct Handle;
pub struct Control;
pub fn control_channel() -> (Handle, Control);
impl Handle {
    pub fn status(&self) -> Option<Status>;
    pub fn request_drain(&self) -> io::Result<proxy::DrainWaiter>;
}
pub async fn run<D: PacketDevice<Error = io::Error>>(device: D, link: Link,
    config: Config, control: Control) -> io::Result<proxy::CloseReport>;
```

The measured control constructor owns exactly one existing-shaped one-slot drain
command queue and one coalesced combined status watch. It does not wrap a second
command receiver. Drain acceptance, dropped waiters and actual terminal result
remain distinct. The existing five-second **local API only** post-result grace
is retained; it cannot extend a network or native deadline.

The client mirrors the existing typed `Session { link, config }`, read-only
`config()`, consuming `run`, `connect` and `accept` signatures with its own
`Settings`. One original setup deadline covers first accept/connect, both
TLS/member exchanges and pair proof. Only ordinary TcpStream factories are
supported; actual authenticated role/profile/layer and both members are checked
before device input. Reverse half directions stay polled for session liveness.

Suggested explicit selection, subject to client-owner review:
`--traffic proxy-measured --proxy-policy PATH --carrier tcp --layer tun
--record-profile frame --compression off`. Existing `--traffic proxy` continues
to mean fixed credit. Reject active/adaptive-transparent, aligned/packed, FEC,
UDP/QUIC/raw, VXLAN/TAP and reload options before files or device I/O. Do not infer
measured selection merely because a JSON object has extra keys.

## Exact settings schema, validation and canonical binding

New JSON top level, at most 65536 bytes, all fields required:

```text
version: 1
profile: "measured-relay-v1"
fixed: existing strict v1 object {version, channels, time_wait_reset, routes}
allocation: {target: TargetConfig fields below, minimum_per_flow: Window}
ownership: all six OwnerConfig fields
observation: all five ObservationConfig fields
service: all five ServicePolicy fields
```

`Window`/Credit objects are exactly `{bytes: u64, records: u64}`. Reject duplicate
and unknown fields at every nesting level, negative/fractional/out-of-range
integers, unsupported versions and noncanonical routes using existing bounded
parsers. Do not deserialize through an intermediate `serde_json::Value` that
would lose duplicate-field rejection. Reuse a narrow private strict route DTO if
approved; preserve the existing fixed parser's accepted bytes and behavior.
There is no new measured default selection. The initial explicit policy retains
`time_wait_reset = "maintained"`; optional IgnoreInTimeWait remains an explicit
bound operator choice, not a test repair.

All of `fixed` is validated as today. Validate `MeasuredConfig` against both
role policies before authentication. The existing API requires a Table: a
bounded empty validation Table with fixed nonzero placeholder session/seed can
check geometry without opening a socket/leg, but it conveys no authority.
Construct and validate the real Controller again against the actual authenticated
Table. No fake validation Table/identity may enter the running actor.

Additional service rules:

- Each work count is 1..=64. Plan/status intervals are 1000..=120000000 microseconds.
- Measured mode requires the native poll interval to be an exact positive number
  of microseconds; reject fractional conversion. Its interval is no greater than
  report, rate, probe, plan and status intervals.
- `ceil(N/report_work) * poll_micros <= report_interval`, checked, bounds a full
  configured report scan under timely servicing. Scheduling delays can still
  make reports stale; they never authorize growth or deadline renewal.
- `ceil((2*N+1)/callback_work) * poll_micros < handoff_timeout`, checked. This is
  a service-capacity condition, not a guarantee against a stopped executor.
- All original B/C timer relationships remain authoritative. No zero interval,
  silent clamp or artificial RTT/rate is accepted.
- Validate total fixed rings/queues plus Controller live/shadow banks and runtime
  metadata against the same 256 MiB configured payload/storage ceiling with
  checked arithmetic. Report metadata and separately bounded maintained TLS/
  allocator allowance explicitly; a target sum is not total process memory.

Use SHA-256 through the existing maintained ring API, with this exact new domain:

```text
l2tunnel/tun-tcp-proxy-adaptive/v1/fixed-rings/measured-relay\0
```

Canonical input after the domain is:

1. 32 bytes of `proxy::session_config(&fixed).digest` (all existing fields,
   canonical routes, duplex, TIME-WAIT, ring capacities and role rule included).
2. Four u8 values: measured profile version 1, user-envelope version 2, LTPM
   version 1, ordered role-rule version 1 (TLS client originator/server acceptor).
3. All values below as **u64 big-endian** in this order, including checked
   conversion of usize/u16/u8 values. A Window/Credit is bytes then records:
   target.initial, target.minimum, target.session_cap, target.per_flow_cap,
   target.policy_cap, target.queue_allowance_bytes,
   target.queue_delay_target_micros, target.many_flow_step,
   target.few_flow_threshold, target.max_flows, target.bootstrap_rtt_micros,
   target.recovery_rtts, allocation.minimum_per_flow;
   ownership.pending_ttl_micros, probe_interval_micros, probe_timeout_micros,
   handoff_timeout_micros, emission_interval_micros, max_records_per_interval;
   observation.report_interval_micros, sample_ttl_micros, demand_idle_micros,
   rate_interval_micros, rate_bins;
   service.report_work_per_turn, admission_work_per_turn,
   callback_work_per_turn, plan_interval_micros, status_interval_micros.
4. u64 constants: outer header 44, length prefix 4, user header 24, LTPM header
   48, Demand 104, Echo 56, ownership-slot multiplier 2, slot extra 1,
   source-admission algorithm version 1, current-queue pressure algorithm version 1,
   immutable token-proof bytes per slot 104.

Return `SessionConfig { layer: Ip, digest }`. Both peers use the same canonical
configuration; local role is never independently hashed into a different digest.
The pair retains the existing first-lane logical session and actual per-lane
outer sessions/sequences. Start/Ready carries this exact new digest on every
physical direction. Unknown/mismatched profile, wire version, settings, role or
lane fails before native read. No fixed Link is silently relabeled measured.

## Authenticated user records and bounded ingress

Measured profile uses the same 24-byte `LTPW` envelope with version **2**:
class 0 transparent, class 1 existing proxy records, class 2 LTPM. Existing
reserved, channel, flow and exact body-length fields retain their offsets.
Class 0 requires flow zero; classes 1/2 require an existing nonzero bounded flow.
Fixed profile remains version 1 and rejects class 2. Inner LTPA/LTPR/LTPX/LTPM
bytes are unchanged.

Only actual retained TLS readers may dispatch class 2 after physical session,
epoch 1, lane, sequence, complete length, Start/Ready and pre-Barrier checks.
Require bulk direction. The actor validates logical session/epoch/flow against
the actual table and the saved original tuple's channel/weight. Then the existing
canonical LTPM parser and `Controller::receive_authenticated` determine original
stream direction, phase, counters, replay/duplicates and response ownership.
Do not infer LTPM from class 0 native payload magic or a device EtherType.

Class 2 uses the same bounded user receive channel and retained `incoming` slot,
never the eight-slot session-control queue or reverse-half liveness direction.
An application packet containing LTPM remains ordinary native traffic. Do not
add an independent receive measurement rate bucket; peer bursts remain bounded
by existing user framing/channel capacity, finite B proofs and finite actor work.
Malformed/scoped/conflicting records fail closed; Duplicate/Stale still count as
received user records for the outer fence but refresh no measurement.

LTPM's direction is the original stream being described, not a guessed network
socket direction. Each endpoint's one Controller manages its incoming relay
targets while staging its actual outgoing producer demand. Requests/replies use
the same allocated flow's common tuple/channel and DSCP weight in each direction.

## Shared admission, exact owner tokens and full-write callbacks

One new private `arbiter::Owner::Measurement(runtime_id: u64)` value references a
fixed runtime ledger with at most S=`2*N+1` entries. Its checked monotonically
increasing runtime_id is only a local index; B OutputId remains the authority.
Each occupied entry stores OutputId, flow, canonical serial/kind/length, original
admission Micros, an immutable 104-byte body-proof array and state `Queued` or
`Writer { user_ordinal }`. Slot reuse
requires a new runtime_id; no counter wrap or lossy mapping is allowed.

Admission steps are one synchronous single-owner section:

1. Reserve an empty runtime ledger slot and preflight ID/count/length arithmetic.
2. At fresh actor time call `Controller::pending(&table, now)`. Clone only its
   exact OutputId and copy at most 104 canonical bytes into the new envelope.
3. Resolve the already-owned flow binding and perform the **existing** common
   Arbiter push, with its global/per-flow byte and record caps, CRC32 channel,
   FIFO and DRR weight. A rejected push leaves B unadmitted; no deadline/nonce
   reset, slot leak or second queue allowance is permitted.
4. After successful push call `confirm_admission(id, same_now)` immediately,
   with no await or table/controller mutation between copy and confirmation.
   Install the matching ledger entry in the same section. A callback error after
   the copy is terminal; retain ownership evidence and abort the session rather
   than dropping the copy and retrying as new work.

Demand costs 4+44+24+104 = **176** framed bytes; Echo costs **128**. Charge the
whole amount and one common record. B's reported `common_copy_bytes` currently
accounts the 48-byte outer framing but not the 24-byte proxy envelope: the
maximum all-slots copy bound here is `304*N+128`, not `256*N+104`. This is a
bound on copies admitted inside existing shared caps, **not** extra reservation
that increases those caps. The maximum source user payload continues to include
all existing larger Open/Data/transparent records.

The measured-only source-admission order must prevent pre-queue starvation.
Use a persistent bounded round-robin cursor over N table-record sources, one
retained transparent-ready source, and one B pending source. Each attempt consumes
the configured admission work, including a per-flow/global capacity rejection;
advance the cursor, retain the original source on rejection, and never spin
unboundedly for a free queue slot. B already round-robins its output slots. This
is producer admission order, not a replacement DRR algorithm. It supplies no
reserved probe channel, priority credit or free bytes. Existing fixed scheduling
keeps its current ordering. Native-generated SYN/ACK/FIN packets remain in the
existing native common arbiter with the same weights.

After arbiter selection, a measurement entry cannot use the existing ordinary
proxy stale-pending drop rule. Validate its ledger identity, scope/channel and
canonical metadata, reserve the one-slot bulk writer channel, preflight the next
continuous `sent_records` ordinal, then transfer the exact bytes and associate
that ordinal with the retained OutputId. Preserve queued measurement records
through terminal flow transitions and quiesce. They remain ordinary counted
user work until actually flushed.

Keep `Progress.users` as the authoritative cumulative full-write count. Validate
it is monotonic and no greater than locally handed `sent_records`. In bounded
ordinal order, for each retained measurement with ordinal <= progress.users,
call `Controller::confirm_written(&actual_table, id, fresh_actor_now)`, then free
its ledger entry only on success. Do not substitute partial write, channel send,
writer dequeue, Barrier enqueue or TUN transmission. A coalesced watch cannot
lose callbacks because all outstanding ordinals remain retained. The two writer
branches, including draining queued users ahead of Quiesce, already publish only
after full flush and must retain that invariant.

Receipt/flush callbacks use current actor time, never a backdated captured writer
timestamp that bypasses C's watermark. A physically completed write observed too
late can fail its original deadline; this is an explicit abnormal result, not
permission to renew ownership. Service latency is admission-to-first-accepted
actor reply, including shared queue/TLS/peer/actor delay. C preserves that reply
time if the flush callback arrives later. It is not native TCP or propagation RTT.

## Actual observations, pressure, timers and bounded passes

Use one Tokio Instant origin for both checked Micros and Table Millis=floor(Micros
/1000). Obtain fresh time at each bounded phase; no sampled time crosses an await.
Only prepare/apply and successful MUX-copy/admission pairs deliberately share one
logical timestamp, with no intervening owner mutation.

Construct C once from the actual Table before readiness. Bind each lifetime flow
weight exactly once from the same retained SYN DSCP mapping used by both arbiters;
an active flow lacking a binding is a terminal invariant violation. No silent
weight migration or flow-ID reuse is introduced.

A measured turn, before any new work, processes the earliest observed drain
watermark and original deadlines. Then it services a finite amount of writer
progress and authenticated events, advances existing maintained/Table work,
processes bounded retained native/user input, and calls `observe_table` from the
actual owner. This must occur before clean retirement discards live leg state;
the retained final-credit snapshot also guarantees terminal ACK accounting once.
Plan/apply follows a successful fresh observation and weight registration, in one
atomic section. No peer rate, synthetic lab bandwidth or elapsed-idle catch-up is
ever supplied.

Periodic report staging scans at most report_work entries per turn with a retained
cursor and per-flow next-due time. Stage actual `Controller::stage_demand` only
for active flows; due reports coalesce only before admission. A successful stage
sets next due from actual staging time, never catches up missed periods. It does
not count as emitted or delivered. Unknown/stale peers conservatively disable
growth through C. Probe creation scans at most N bindings and attempts at most
one eligible active flow, rotating its flow choice; B's original spacing, one
live probe and emission limit remain authoritative. ProbeBusy is scheduled for a
future service turn, never an immediate retry loop.

LocalPressure derives only from current owned work:

| Input | Exact runtime source |
| --- | --- |
| queue_delay_micros | Oldest current outbound common-arbiter enqueue age or retained bulk-writer handoff age, whichever is larger; zero when neither exists. Failed retries preserve first admission time. |
| receiver_pressure | A retained selected native output whose latest transmit returned WouldBlock, or an actual native-arbiter capacity rejection in the current turn. Clear on the corresponding successful progress; do not retain a historical pressure event forever. |
| carrier_pressure | Current common wire admission capacity rejection, or retained bulk-writer work whose current age is at least target.queue_delay_target_micros. This is local pipeline pressure, not an inferred kernel cwnd/loss signal. |

Add bounded arbiter enqueue-time metadata and a read-only oldest-age query using
current retained queue heads. Track the at-most-one queued plus one in-flight
bulk writer user with a fixed two-entry ordinal/first-time ledger, releasing only
against flushed progress. A stale progress observation may conservatively defer
a send; it cannot allocate an unbounded third entry. Reject impossible time or
age above C's 120-second bound; do not silently clamp it into evidence. Native
queue sojourn can be separately reported but does not become service RTT or ACK
rate. ECN, loss and native RTT/cwnd remain absent. TUN write confirmation only
releases native-output ownership; ACK-rate and grant release still require actual
maintained native ACKs through Table.

Timer wakes combine the existing native poll tick, Controller.next_deadline,
pending report/probe/plan/status service times and earliest startup/drain deadline.
Use skipped rather than accumulated periodic ticks. An overdue B deadline must
be serviced by C tick (or fail terminally); never hide it by adding a new period.
Observation-only deadlines processed by C's watermark cannot cause repeated
immediate wakes. When a bounded scan runs out of work, resume at the next native
poll turn instead of spinning on the unchanged past due item. All actor metadata
Controller/owner scans remain explicitly bounded by N<=64/S<=129. The common
arbiter oldest-age query additionally scans at most mux.max_flow_bindings<=4096
retained queue heads; flow_poll_work is not a total whole-turn scan bound.

MemoryBound separately includes Controller live/shadow allocations, N due-time
and binding rows, S token entries including S*104 immutable body-proof bytes,
two writer-age rows, bounded copied Status and
one transient <=104-byte measurement encoding buffer. Existing common queues,
one incoming/user source slot and native buffers keep their current caps. Any
transparent-ready refactor remains the existing single retained native input
slot, not an additional unlimited producer queue. One optional retained last
Applied contains at most N rows; plans are immediately applied or dropped.
The service storage calculation conservatively reserves two N-row FlowSnapshot
arrays and four N-row FlowTarget arrays, plus both copied Snapshot values. This
covers old/new watch replacement and the current/next apply plan simultaneously.
Caller-created status clones and allocator/TLS internals are outside this explicit
component bound; they are not hidden runtime queues.

The measured actor checks the original startup deadline before processing late
Ready events, and wakes at the earliest native/C/startup/drain deadline. Exact
full-write callbacks and successful final joins also check the original drain
deadline. A ready or empty JoinSet cannot turn an expired deadline into success.
The original fixed profile's scheduling/deadline interpretation remains unchanged.

## Quiesce, terminal flows, fences and epochs

At first local drain or reader-observed authenticated peer Quiesce, preserve the
earliest original shutdown deadline and immediately quiesce C at fresh actor time.
Do not wait for an earlier user record blocked on native output to enter quiesce.
Stop new measurement staging/probes/plans and new native proxy ownership. Keep
existing Open/Ready/Commit reservations, their original deadlines, positive
already-applied targets and all issued grant debt so existing streams can finish.
Continue required native/reliable progress and actual ACK observation. Do not
call C prepare after quiesce or restore a new Controller to get fresh history.

Unadmitted B pending records may expire/coalesce/be dropped by quiesce. Every
already admitted measurement must instead drain through its common queue, exact
writer ordinal and full-write callback, even if the named flow becomes terminal.
Future fresh peer measurements during quiesce are handled as B Stale without
generating new replies; exact outer user counters still advance. After a peer
Barrier, the existing reader rejects all new user classes including LTPM.

Local Barrier additionally requires `Controller::drained()`, empty runtime token
ledger, no remaining user arbiter/retained input, and exact flushed user count.
All measurement copies are included in Fence.records; transparent native credit
counts remain unchanged. Reverse-half liveness cannot carry measurements or
renew shutdown. Final peer fences, native confirmed outputs and every retained
TLS close/join still use the earliest original absolute deadline. Callback after
that deadline or B handoff expiry is abnormal even when a later write succeeds.

This explicitly supersedes the older adaptive design paragraph allowing an
admitted measurement copy to be discarded before writer ownership. Upon approval,
replace that paragraph in the published adaptive document with the above
admission-is-irrevocable rule; no B cancellation API is requested.

Ordinary target updates within negotiated bounds do not change wire interpretation
or epoch. Caps, rings, work policy, weights, measurement version and algorithm
changes require a new authenticated session in this profile. A future negotiated
hot switch needs a separate transaction retaining old grants/readers; no local
JSON reload or reset of source/TLS/probe counters is implemented here.

## Status and later client/native evidence

MeasuredSnapshot reports actual C ObservationStatus, last applied revision/time,
candidate/reserved/opening/terminal totals, bounded current pressure with local
provenance, S-ledger queued/writer/callback counts, original deadline state,
common queued bytes/records, measurement admitted/framed bytes/counts per kind,
actual flushed count, and at most N per-flow rows. Rows retain current actual
target/grant/received/ACK, phase, weight and native unread/pending sizes; unavailable
native RTT/cwnd/advertised-window observations are explicit None. Do not label a
future target as rwnd or expose keys/nonces as diagnostics. A time-indexed status
read cannot advance C authority or complete drain.

The local API should emit only the bounded aggregate in ordinary status. Proposed
separate read-only action `proxy_measured_flows { after_flow: u64, limit: u8 }`
uses limit 1..=4 and an explicit continuation cursor, with strict nested DTOs and
worst-case numeric/string serialization below the unchanged 8192-byte response
cap. Wrong profile returns Unsupported. This paging design needs client-owner
review; simply increasing the shared response limit is not part of the proposal.
Repeated drain requests remain prompt and cannot renew network deadlines.

Native evidence must distinguish three domains: the fixed preallocated native
receive ring and stack-owned advertised window; relay targets/grants/ACK debt;
outer kernel TCP/TLS flow/congestion behavior. Target changes control receive-ring
consumption only indirectly. The initial SYN window/ring capacity is already
available, is not progressively enlarged, and must be captured as such.

## Implementation order and acceptance gates

The design gate records source review only. Every implementation gate stays open
until its complete behavior has focused evidence. No native action is authorized
by a completed pure/runtime gate alone.

- [x] [MOD-PROXY-MEASURED-01] Review exact profile/API, canonical field order, version-2 user class, immutable token ledger, actual-pressure definitions and admitted-quiesce correction; publish the reviewed contract before code. Evidence: root independently reviewed the [work draft](../../work/proxy-measured-runtime-design/proposal.md) against current C/B ownership, actual actor/arbiter and writer full-flush progress; accepted with the explicit checkpoint, lifetime-slot and canonical-fixture clarifications recorded here. This is design review only.
- [x] [MOD-PROXY-MEASURED-02] Implement additive typed configuration/link factories and bound private helpers; reject every fixed/measured, role, lane, settings, timing, geometry and unsupported carrier/layer mismatch before device read; pin unchanged fixed digest/wire fixtures. Evidence: the [38-case focused receipt](../../work/proxy-measured-runtime/validation.json), [independent canonical fixtures](../../crates/l2tunnel-runtime/src/proxy/measured/config_tests.rs) and actual full/paired authenticated factory/binding tests in [proxy_tests.rs](../../crates/l2tunnel-runtime/src/proxy_tests.rs); structural framing is not authentication evidence.
- [ ] [MOD-PROXY-MEASURED-03] Compose C inside the one existing actor and common source admission/DRR path; test exact 176/128-byte costs, all global/per-flow/count caps, channel FIFO, source-admission fairness, saturation/coalescing and no reverse-half/control-lane shortcut.
- [x] [MOD-PROXY-MEASURED-03A] Implement actual common-actor composition and its first finite cost/rotation/saturation checkpoint without claiming the entire per-limit runtime matrix. Evidence: [focused checks](../../work/proxy-measured-runtime/validation.json), actual-table cost/rotation/saturation tests in [measured_actor_tests.rs](../../crates/l2tunnel-runtime/src/proxy/measured_actor_tests.rs), unchanged common-arbiter tests, and the authenticated full/paired matrix. These finite tests do not establish multi-flow performance or kernel QoS.
- [x] [MOD-PROXY-MEASURED-04] Implement the fixed token/ordinal and queue-age ledgers; verify writer prefix/body partial progress, pending flush, coalesced Progress.users, both writer branches, immutable generation retention, callback-after-expiry and counter exhaustion without false confirmation. Evidence: [focused checks](../../work/proxy-measured-runtime/validation.json), the actual bounded AsyncWrite partial-body/flush fixture and terminal/callback cases in [measured_actor_tests.rs](../../crates/l2tunnel-runtime/src/proxy/measured_actor_tests.rs), plus [ordinal exhaustion tests](../../crates/l2tunnel-runtime/src/proxy/measured/ledger.rs). The standalone writer fixture uses an explicit already-flushed setup ordinal offset; production never resets its writer counter.
- [ ] [MOD-PROXY-MEASURED-05] Drive actual Table ACK observation, due reports/probes, fresh local-pressure and atomic measured apply; test historical/terminal ACK baselines, stale/missing demand, original reply time, weighted sparse/many-flow growth, no synthetic rate/RTT and bounded overdue-timer service.
- [ ] [MOD-PROXY-MEASURED-06] Preserve startup and original quiesce/drain barriers; test prequeued native input, pre-start drain, admitted measurement on a terminal flow, local/peer quiesce with blocked native/writer, no post-Barrier user work, asymmetric paired shutdown, and callback after original session deadline.
- [x] [MOD-PROXY-MEASURED-06A] Implement actual measured original-deadline/drain composition and finite terminal/writer/native-pressure regressions; retain the full profile-specific startup/barrier matrix above as a separate acceptance task. Evidence: [38 focused tests](../../work/proxy-measured-runtime/validation.json) include all 17 fixed regressions, measured Ready-at/after-expiry, 10ms startup versus 100ms native poll, terminal admitted records, original-deadline callback/empty-join rejection, both writer branches and full/half blocked-native peer-only drain. No production deadline or maintained TIME-WAIT timer was widened.
- [ ] [MOD-PROXY-MEASURED-07] Run actual authenticated TCP/TLS full/paired loopback with independent maintained native endpoints, exact bidirectional opaque bytes/FIN, transparent ICMP bypass and denied-route behavior; pressure/recovery must advance real native ACKs and preserve grant right edges. Keep this separate from kernel/device proof.
- [x] [MOD-PROXY-MEASURED-08] Pass focused runtime/old fixed regressions, strict lint/docs and independent review, followed by root-coordinated stable aggregate; no source-stability or native claim from a targeted compile alone. Evidence: [source-stable wave14b](../../work/implementation-wave14b/validation.json), 858 Rust/107 Python cases with strict workspace lint/docs; this runtime checkpoint precedes later client edits.
- [ ] [MOD-PROXY-MEASURED-09] Add separately reviewed strict client JSON/explicit CLI selection and bounded aggregate/paged status; keep fixed defaults, unsupported-action errors, prompt drain acceptance, actual terminal result and five-second local-only grace unchanged.
- [x] [MOD-PROXY-MEASURED-09A] Implement explicit strict measured client/CLI selection and bounded aggregate status through the shared service, keeping paged per-flow status separate. Evidence: [client checklist](proxy-measured-client.md), [95 library/19 example focused checks and independent review](../../work/proxy-measured-client/validation.json).
- [ ] [MOD-PROXY-MEASURED-10] Freeze a dedicated owned-native acceptance plan and immutable build before one clean TUN case: prearm native/underlay capture, actual split proof, original SYN options/scaling, maintained TIME-WAIT, IPv4/IPv6 exact bytes/FIN, transparency/routes, final fences and complete cleanup.
- [ ] [MOD-PROXY-MEASURED-11] Independently prove actual advertised-window pressure/reopening in each direction: retained application backpressure must exhaust real buffers, constrain native receive consumption and emit/deliver scaled window changes; unblocking must yield real ACK release, nonrevoked relay grants, reopened native window and renewed exact-byte progress. A target-only change is explicitly unobserved native effect.
- [ ] [MOD-PROXY-MEASURED-12] Only after clean full/half gates, qualify bounded 1/2/4/16/64 demand, idle/joins/exits, weighted fairness and finite loss/delay against unchanged fixed-credit baselines with queue/RSS/native and outer byte accounting; preserve timeout/reset/unsupported outcomes and do not infer a performance claim from pure tests.

The first compiling checkpoint covers gate02 configuration/digest, actual bound
Link factories, version-2 envelope and bounded token/ordinal primitives. It must pin a
literal canonical byte/digest fixture, mutate every bound field, reject fractional
duration conversions and preserve existing fixed digest bytes. Gate03 remains
open until real common-actor admission composition; gate04 remains open until
actual TLS writer callback composition, even when its bookkeeping primitives are
tested. No public run/Handle/status placeholders are added at this checkpoint.
The ledger remains private; source-review approval extends implementation through
real common-actor use (gates03..06) before the strict-ready checkpoint, rather than
exporting unused bookkeeping or suppressing its warnings. Those public activation
surfaces appear only together with their actual behavior. C remains the sole
handoff-expiry authority and ledger release requires successful C full-write
confirmation; no independent cancellation or expiry state machine is introduced.
Lifetime report/admission/binding slots cover every allocated ID, including
tombstones. Retired admitted tokens remain in scans, and neither flow IDs nor
checked generation IDs are reused. Actual actor observation/drain composition and
authenticated loopback now have the focused evidence above. Gate05 remains open
for its full weighted sparse/many-flow runtime matrix: pure C already tests those
allocation and provenance rules, but the new real runtime matrix currently uses
one actual proxied flow per direction. Gate07 remains open for dedicated measured
ICMP and route-denied fixtures, despite the corresponding fixed-profile regressions
passing. Captured advertised-window qualification remains a later gate.

## Focused checkpoint and limits

[The focused receipt](../../work/proxy-measured-runtime/validation.json) records
38 passing proxy tests, unchanged hashes for the owned proxy Rust sources,
rustfmt, strict all-target runtime Clippy, warning-denied runtime rustdoc and the
checklist validator. Its source-stability scope is those Rust files; the whole
workspace aggregate and immutable build are root-coordinated separate receipts.
The actual measured stream test runs four IPv4/IPv6 by full/paired-half cases
with independent maintained native TCP endpoints, exact opaque bytes and FIN,
actual Table ACK-rate bins and authenticated echo samples. Pressure/drain tests
also use both duplex modes. This is loopback runtime evidence, not a kernel
TUN capture, native advertised-window measurement, or performance result.

The first 5-second fixture drain waiter expired after exact bytes/EOF while one
native leg remained in maintained TIME-WAIT with empty queues. Its observed
failure is [preserved separately](../../work/proxy-measured-runtime/initial-close-observation.json).
Only that test observer was changed to the existing fixed fixture's 15-second
bound; the later matrix completed in about 10.3 seconds. No production timeout,
reset policy, TIME-WAIT timer or clean-close predicate was relaxed.

Root and an independent agent read the actual actor/state/ledger and writer
ownership. Their startup/ready-join deadline findings and simultaneous status-copy
memory finding were fixed and read back before this checkpoint. Client JSON/CLI,
local API paging, hot reload, other carriers and privileged native tests remain
unimplemented for this explicit measured profile.
