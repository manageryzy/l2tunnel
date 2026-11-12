# Measured proxy controller checkpoint

Status: implemented and focused-tested as a pure controller; runtime and native
activation remain unimplemented. The canonical interface lives in
[`measurement::Controller`](../../crates/l2tunnel-tcp-proxy/src/measurement/controller.rs).
This is checkpoint C of [proxy measurement](proxy-measurement.md), following the
tested canonical codec and bounded record owner. The existing
[adaptive allocator](proxy-adaptive.md) still accepts caller-supplied feedback;
this checkpoint supplies observations from the actual table and authenticated
record path. Runtime wiring, authentication profile selection and native window
qualification remain subsequent work.
The next [measured runtime contract](proxy-measured-runtime.md) separates its
configuration/framing checkpoint from actual shared-actor and native activation.

## Ownership and public boundary

`measurement/controller.rs` lives inside the pure TCP proxy crate, with no new
dependency, socket, task, system clock or native packet polling. A Controller
constructs and exclusively owns one existing measurement Owner, one Planner and
fixed observation storage from the same actual Table. It cannot adopt an existing
Owner or Planner after unobserved operations. It exposes no mutable inner owner,
planner, fabricated measurement setter, caller-provided demanding set or public
constructor for an observation proof. The standalone B APIs remain available for
their original nonmeasurement purpose.

```rust,ignore
pub struct ObservationConfig {
    pub report_interval_micros: u64,
    pub sample_ttl_micros: u64,
    pub demand_idle_micros: u64,
    pub rate_interval_micros: u64,
    pub rate_bins: u8,
}
pub struct MeasuredConfig {
    pub allocation: adaptive::Config,
    pub ownership: measurement::OwnerConfig,
    pub observation: ObservationConfig,
}
pub struct LocalPressure {
    pub queue_delay_micros: u64,
    pub receiver_pressure: bool,
    pub carrier_pressure: bool,
}
pub struct Controller;
pub struct MeasuredPlan; // Actual controller identity + observation revision + Plan.
pub struct ObservationStatus; // Copied facts, origins, freshness and bounds.
impl Controller {
    pub fn new(config: MeasuredConfig, table: &Table, now: Micros)
        -> Result<Self, ControllerError>;
    pub fn bind_flow(&mut self, flow: adaptive::FlowWeight) -> Result<(), ControllerError>;
    pub fn observe_table(&mut self, table: &Table, now: Micros) -> Result<(), ControllerError>;
    // Same bounded B signatures for stage_demand, stage_probe, pending,
    // receive_authenticated, confirm_admission, tick, quiesce.
    pub fn confirm_written(&mut self, table: &Table, id: OutputId, now: Micros)
        -> Result<(), ControllerError>;
    pub fn prepare(&mut self, table: &Table, pressure: LocalPressure, now: Micros)
        -> Result<MeasuredPlan, ControllerError>;
    pub fn apply(&mut self, table: &mut Table, plan: MeasuredPlan, now: Micros)
        -> Result<adaptive::Applied, ControllerError>;
    pub fn observations(&self, table: &Table, now: Micros)
        -> Result<ObservationStatus, ControllerError>;
    pub fn next_deadline(&self) -> Option<Micros>;
    pub fn drained(&self) -> bool;
}
```

`LocalPressure` is explicitly caller-supplied local information, not a measured
capability. The later runtime must derive it from actual shared-queue sojourn,
reservation and retained writer/native pressure. This checkpoint accepts no ECN
or loss assertions; those Feedback fields remain false until separately reviewed
observations exist. Queue delay uses a bounded, validated duration. Native TCP RTT
is unavailable; the echo value is named **service latency** in status.

Every duration is 1,000..=120,000,000 microseconds. Rate bins are 1..=16;
checked `2 * rate_interval * rate_bins <= 120 seconds`. Sample TTL is at least
the report interval, probe timeout and twice the rate interval. Demand idle is
at least the report interval. Validate actual table/planner policies, original
deadline arithmetic and bounded memory before allocation. No runtime-configurable
array grows after construction. Report interval is a scheduling requirement for
the later adapter, not an assertion that a report was actually sent.
The lower duration bound applies to configured timers. Local queue delay accepts
zero through 120,000,000 microseconds; zero represents no observed queuing.

## Actual ACK rate

Retain one baseline per lifetime flow and one session-level ring of completed
rate bins. `observe_table` scans at most the configured N entries using
`credit_status`, including its final terminal snapshot; it does not poll a TCP
socket, release credit or read a reset-cleared transmit queue. For each known
baseline, accumulate only a checked positive increase in acknowledged original
bytes. A decrease or impossible acknowledged/received/granted relationship is an
accounting error. First observation of any flow establishes its current baseline
and contributes no historical bytes, including when attaching after termination.
Final terminal progress contributes at most once and the baseline remains retained
until session destruction. Lifetime flow IDs are never reused.

All flows contribute to one observation clock and aggregate interval. Multiple
flows do not multiply elapsed time. Accumulate deltas until actual elapsed time
from the bin start reaches the interval. Complete exactly one bin when elapsed
is between one and two intervals, inclusive; record actual elapsed microseconds
and actual bytes, including zero bytes. Set the new bin start to the current
observation time. A larger gap discards the ambiguous accumulated delta, clears
the history, updates all actual baselines and starts a new interval. It creates
no catch-up bins or fabricated delivery rate. Reading the same table at the same
time cannot create another delta or completed bin.

At query/prepare time exclude bins whose completion time is at least sample TTL
old. Sum valid bin bytes and elapsed microseconds using checked wide arithmetic;
compute `floor(total_bytes * 1_000_000 / total_micros)`. A result of zero or no
eligible completed bin is unavailable for growth, with the observed zero-delivery
condition reported separately. Retain the actual latest completed-bin time and
denominator in status. Native/TLS writes, MUX admission, peer reports, FIN, repair
copies and credit messages contribute no acknowledged bytes.

## Authenticated demand and echo observations

Controller ingress delegates to the existing B admission path. Only a novel
Accepted Demand updates its fixed flow observation and local receipt timestamp.
Duplicate, Stale, conflict and terminal-flow traffic create no sample or freshness.
Reuse the existing authoritative wire parser; do not infer demand from magic
inside a TUN packet. Authentication remains the documented runtime precondition.
Stage outgoing Demand from the actual B table reader, never from caller counters.

A fresh report qualifies nonempty demand when its actual reported unread/pending
payload is positive, or its produced prefix remains beyond the local authoritative
ACK prefix. It does not acknowledge bytes or release memory. A fresh empty report
and subsequent elapsed demand-idle interval are both required to mark the flow
idle. Consecutive novel fresh empty reports preserve the original idle-start
time; only positive demand evidence resets it. A stale report is Unknown, not
Empty; preserve the preceding demand allocation classification and invalidate
growth qualification. A newly active unknown flow is conservatively included in
allocation until fresh evidence can establish idle. Any unknown active demand
disables aggregate growth; explicit pressure may still reduce future targets.
Already issued grants remain irrevocable under the existing allocator.
If a zero-backlog report still had produced bytes beyond ACK at receipt, and
actual ACK later catches up, its empty-idle interval starts at the first successful
authoritative observation or prepare that sees this change. It is never backdated
to report receipt or advanced by a diagnostic query. Prepare commits this staged
classification only after all recoverable checks succeed.

Reported credit exhaustion qualifies growth only with fresh positive native
unread demand, the appropriate byte/record blocked flag, and the corresponding
reported grant exactly equal to the current local authoritative grant. Recheck
that equality at prepare time, because a locally issued grant can change after
report reception. A new serial with an obsolete grant cannot renew exhaustion.
Neither a pure ACK nor an idle probe creates payload demand.

The existing owner retains a probe's original creation deadline, single admission
timestamp, exact nonce and early reply candidate. Add only a private completion
seam: when both the original request's complete write/flush callback and matching
reply exist before expiry, emit one fixed event containing flow, generation,
admission time and original reply time. The Controller consumes this synchronously
within the successful owner operation; no public event injection or unbounded
event queue exists. The standalone Owner discards observation events. An event
cannot be reconstructed later from a copied status boolean.

Unlike B's callback, the measured `confirm_written` also takes the actual Table.
Its private owner seam validates token, time and original table identity before
mutation, and processes actual terminal-flow eligibility before completing the
echo. Do not first call a mutating tick and then discover an invalid token. Keep
B's existing public signature and behavior unchanged; only Controller's private
composition can produce a measured event from a complete table-checked operation.

Service latency is `reply_at - admitted_at`, strictly positive. Late write
confirmation uses that original interval and receipt time, not its callback time.
Quiesce, terminal flow, probe expiry, handoff failure or a now-stale candidate
invalidates eligibility. A first eligible sample initializes SRTT; subsequent
samples use checked `(7 * old + sample) / 8`. Store the latest original reply time
as freshness. If the preceding estimate is already stale, a new eligible sample
starts a fresh estimator instead of blending with stale history. A previously
eligible completed sample remains a session service observation until its TTL;
later flow retirement cannot rewrite its original completion evidence. Terminal
flow invalidation applies to unfinished candidates. One probe at a time and
original creation spacing remain unchanged.
The echo includes local common-MUX/writer and peer scheduling, and therefore is
not a propagation or native TCP RTT measurement.

## Observation revision and atomic planning

Controller owns a checked nonwrapping observation revision, an authoritative
monotonic time watermark and private identity. The watermark begins at
construction time. Every mutating/planning operation with an injected timestamp
must first reject time older than that watermark, in addition to the actual
Table/B/Planner time checks. Successful operations advance it even if no rate bin
or sample completes. Read-only diagnostic views never advance it.
Every accepted fact or lifecycle change that could affect planning advances the
observation revision;
exact duplicates do not refresh facts. Prepare captures that identity/revision,
the query time, the existing Planner revision and its actual Table snapshot.
Compute incoming original in-flight bytes/records from authoritative
`received - acknowledged` over current active entries, with checked sums. Issued
but not yet received grants are debt reserved by the Planner, not measured
in-flight delivery. Do not substitute queue size or peer-supplied counters.

Prepare derives the complete Feedback and demanding set internally. Growth needs
fresh positive actual ACK rate, fresh eligible service latency and known demand;
credit exhaustion is qualified as above. It cannot bypass existing floors, caps,
future-slot reservations, terminal debt, weights or RTT pacing. Multiple plans
may be inspected but only the current one can commit. Wrong owner, changed
observation revision, changed table/planner snapshot or different apply time
rejects before mutating targets/policy history. The existing Planner remains the
single atomic target commit. An apply rejection does not roll back real observed
ACKs, authenticated reports or completed echoes.

Observer operations preflight all recoverable validation/arithmetic before
committing their bounded observation state. In particular, check the next
Controller revision and all fallible derived-observation arithmetic before any
mutating B call. After B commits, observation derivation must be infallible under
those preflight bounds; it cannot return a recoverable error after consuming an
owner serial, token, probe or admission fact. B's sticky handoff expiry is the
explicit terminal exception: retain all admitted proof bytes, invalidate sample
eligibility, stop planning, and require the outer session to terminate. Subsequent
callbacks cannot revive it with an earlier timestamp. Revision exhaustion is
terminal and cannot reset identity/history within the current session.

Prepare uses a private B validation seam to check actual table/time and latch an
expired admitted handoff before publishing a plan. After all recoverable pressure,
arithmetic and Planner preflight succeeds, it commits the authoritative watermark
and next checked observation revision, then binds the result to those committed
values. It changes no target or Planner policy history and does not run a mutating
tick followed by fallible validation. Another successful prepare invalidates the
older observation revision even when its measured values are identical. Apply
performs the same terminal/time preflight before its normal revision checks.
Diagnostic observations are read-only time-indexed views; they can show
ineligibility but cannot authorize a plan or mutate expiry/history.

This watermark is necessary even when no admitted handoff has expired. For
example, prepare after a probe deadline but before the request's later handoff
deadline may legitimately produce a nongrowing plan. A subsequent write callback
using a pre-expiry timestamp must fail monotonic time validation, rather than
reviving the expired probe's early reply. Test this independently of the sticky
terminal-handoff case. Recoverable failed prepare leaves the watermark/revision
unchanged; terminal expiry remains the explicit exception.

Keep explicit staging calls in C. Do not hide an N-message staging transaction
inside `observe_table`, whose failure would otherwise partially consume B serials
or emission state. The later runtime services report/probe timers with its fixed
work budget and shared MUX; C tests can exercise those explicit calls. A future
automatic scheduler needs its own bounded preflight/partial-progress contract.
Observation-only deadlines already processed at or below the Controller watermark
are omitted from `next_deadline`, avoiding repeated stale-sample wakes. Every live
B handoff/probe deadline is preserved; explicit report/probe scheduling remains
the adapter's responsibility.

## Storage, runtime seam and acceptance

In addition to B's separately recorded buffers, retain N flow baselines/demand
rows, at most16 aggregate bins, one service-latency estimator and fixed counters.
Report concrete checked `size_of` storage and bounded scratch separately; no
payload copy belongs to the observation model. A pass scans at most N flows and
16 bins. Caller-held plans retain their already documented bounded snapshots and
are outside the Controller's storage count.

The implementation allocates two equal fixed observation banks at construction.
Recoverable operations copy only fixed-size rows/bins into the shadow bank, then
swap after validation; neither bank grows or allocates on observation. The
`ObservationMemory` result reports live retained bytes (including B's fixed
record buffers and existing Planner weights), separately preallocated shadow
bytes, and `size_of` the derived view with its fixed 64-entry temporary demanding
set. It excludes allocator/Arc control blocks, caller-held plans, the Table's
existing native buffers and a whole native thread-stack estimate. `AckRate`
retains the actual byte sum, elapsed denominator, bin count and completion time;
`ServiceLatency` retains original flow/generation/admission/reply times and explicit
freshness. `ObservationStatus` also reports actual in-flight prefixes, unknown
demand, record ownership and any latched terminal Controller failure.

Every successful timestamped owner wrapper advances the authority watermark and
conservatively invalidates older plans, even when B classifies an incoming record
as Duplicate or Stale. Those dispositions never install a report or refresh any
measurement timestamp. Identical immutable weight binding is an unchanged retry.
Observation and staging calls remain explicit; neither diagnostics nor planning
fabricates ACK bins, and parsing never establishes authenticated ingress authority.

The future runtime must call observation from the actual table owner, route only
authenticated measurement user records, retain every writer token and quiesce
before its original drain barrier. Admission must preflight pending lifetime and
common queue capacity at one logical actor timestamp, then copy and confirm in
one synchronous section. A callback failure after the copy is terminal; it must
not silently discard admitted bytes. No extra control lane, queue budget or
reverse-half bypass is allowed. Runtime profile digests must bind all measurement
settings/version while preserving the existing fixed proxy profile bytes.

- [x] [MOD-PROXY-OBS-01] Independently review ownership, sample mathematics, freshness, demand fallback, private echo completion seam and revision semantics before code. Evidence: two independent reviews of this contract against the actual Owner, Planner and Table accepted the accounting and bounded ownership; the review finding that successful prepare must advance the Controller time watermark is resolved in the [atomic planning contract](#observation-revision-and-atomic-planning), with explicit older-callback regressions, preserved empty-demand idle timing and preflight before B mutation.
- [x] [MOD-PROXY-OBS-02] Implement fixed actual-table ACK baselines and aggregate elapsed-time bins; test zero, first/terminal observation, duplicate time, gaps, expiry and checked arithmetic. Evidence: [focused validation](../../work/proxy-observation-c/validation.json) runs all 70 proxy tests, including actual multi-flow ACK aggregation, first/terminal baselines, inclusive interval boundaries, stale gaps and overflow nonmutation in the [controller tests](../../crates/l2tunnel-tcp-proxy/src/measurement/controller/tests.rs).
- [x] [MOD-PROXY-OBS-03] Implement novel authenticated demand, idle hysteresis and original-time echo/SRTT without changing B replay, handoff or memory ownership. Evidence: [focused validation](../../work/proxy-observation-c/validation.json) covers duplicate/stale freshness, renewed empty versus positive demand, original reply time, stale-estimator reset, retained handoff expiry and quiesce; all existing B owner tests also pass unchanged.
- [x] [MOD-PROXY-OBS-04] Compose measured prepare/apply with actual in-flight accounting and both revisions; test wrong owners, stale plans, obsolete grants, failed apply and irrevocable debt. Evidence: [focused validation](../../work/proxy-observation-c/validation.json) covers authority-time and identity/revision rejection, recoverable preflight atomicity, debt-preserving pressure and current-grant checks; the [growth regressions](../../crates/l2tunnel-tcp-proxy/src/measurement/controller/tests/growth.rs) prove unknown/stale demand cannot grow targets despite fresh actual rate/echo.
- [x] [MOD-PROXY-OBS-05] Exercise real maintained ACK progress through admitted paired Tables, early/late echo callbacks and quiesce/terminal failure; retain finite pure evidence separate from runtime authority. Evidence: [focused validation](../../work/proxy-observation-c/validation.json) records 18 C tests within 70 passing proxy tests, package formatting, warning-denied all-target Clippy and rustdoc, with unchanged package source hashes. Two independent source reviews found no material blocker. The common-MUX handoff is a bounded synchronous test contract, not a runtime, captured advertised-window or native qualification claim.
- [x] [MOD-PROXY-OBS-06] Pass focused tests, strict lint/docs, independent source review and a stable aggregate before separately reviewing runtime/configuration/native activation. Evidence: [focused validation](../../work/proxy-observation-c/validation.json), two independent source reviews, and [source-stable wave13](../../work/implementation-wave13/validation.json) with 805 Rust and 105 Python cases plus strict workspace lint/docs. The [exact build13](../../work/packed-native-build13/receipt.json) preserves that source map. Runtime/configuration/native activation remains a separate unimplemented checkpoint.
