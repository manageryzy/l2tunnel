# Measured transparent-TUN observations

Status: implemented and locally tested; design preceded code. This optional pure module supplies bounded
observations for [Active](active.md); it does not authenticate transport, estimate
kernel congestion from configuration, own TCP windows or change TAP policy. The
existing 72-byte credit tokens remain unchanged. A runtime negotiates a separate
observation frame kind before selecting measured growth.

## APIs and truthful measurements

```rust
Active::demand_snapshots() -> Result<Vec<LocalDemand>, ActiveError>;
Active::confirm_delivery_at(Record, Micros) -> Result<ConfirmOutcome, ActiveError>;
Active::native_sample() -> Option<NativeSample>;
observation::Observer::new(Config, &Active, Micros) -> Result<Observer, Error>;
Observer::tick(&Active, Micros) -> Result<(), Error>;
Observer::receive(&Active, &[u8], Micros) -> Result<(), Error>;
Observer::poll_output(Micros) -> Result<Option<[u8; 96]>, Error>;
Observer::feedback(&Active, Micros) -> Result<ObservationFeedback, Error>;
```

Read-only pipeline heads expose actual retained queue byte/count and exact first
packet length without changing DRR deficit, queue order or credit. The local
snapshot uses `SenderCredits::preview_admit` on that head. Flow/session credit
exhaustion is distinct from local sender-retention pressure; an empty queue never
advertises exhaustion. Each snapshot carries the actual aggregate sender-retained
credit, which the receiver must not sum across flow rows.

`confirm_delivery_at` releases exactly the same native buffer as the existing
static API, while recording an actual local timestamp and elapsed time since its
first receipt. Duplicate records/confirmations never reset age or create samples.
Cumulative actual consumed bytes/count include both static and timed confirmations;
only timed confirmation publishes a timestamped sample. The first timed sample is
an anchor, not an invented rate. A later sample measures actual consumed byte
delta over local elapsed time, including intervening static confirmations. The
existing static API supplies no fabricated timestamp or RTT.

Runtime Open delivery must precede a new flow's Demand, through its negotiated
reliable ordered control service. Before a Final barrier, drain already handed-off
observation copies along with ordinary control/data copies. A late Demand for a
retired ID is harmless and cannot recreate flow state. The optional observer is
not a replacement for reliable Open delivery or recovery.

The observer returns fresh demanding IDs and `target::Feedback`; it does not call
`update_targets` implicitly. Empty/stale measurements leave RTT/rate absent, so the
existing static floor/regrant remains the fallback. Runtime congestion, ECN and
native-pressure observations stay explicit; grant exhaustion is never pressure.

## Fixed observation framing

Every message is exactly 96 bytes, with `LA`, version 1, a kind, direction and
reserved-zero fields. Big-endian fields bind session (u128), epoch (u64), sequence
or probe nonce (u64), then bounded kind-specific words. Decode rejects unsupported
tags, nonzero reserved/unused words, contradictory count/byte/head fields and zero
sequence IDs before state mutation. Authenticate the enclosing carrier first.

`Demand` contains flow ID, actual queued bytes/count, head bytes, aggregate actual
sender retention, and Ready/FlowCredit/SessionCredit/LocalRetention. Demands bind the
sender's data direction. The receiving engine must already know that flow and the
operator-negotiated remote queue/retention caps. One latest row per live incoming
flow is retained. Per-flow sequence high-water marks survive freshness expiry;
duplicate or reordered rows cannot refresh expiry. A separate aggregate sequence
chooses the newest actual retained-credit snapshot without summing flow rows.
Retired flow rows are pruned, and old unknown IDs never recreate state.

`Ping` requests an echo for the observer's incoming data direction; `Pong` echoes
the exact nonce/scope. Only one local probe may be queued/outstanding. Start its
clock when the frame leaves the observer, so measured RTT includes subsequent
runtime queueing, transport and peer processing/response queueing. It is not a
claim of propagation-only RTT. Exact nonce, direction and finite timeout are
required; duplicate/old replies cannot recreate or refresh a measurement. A zero
elapsed interval provides no RTT sample. Peer pings use a fixed high-water mark
and one coalesced reply, avoiding unbounded response state or amplification.
Fresh RTT samples use a 7/8 previous plus 1/8 new smoothing rule; an expired old
sample is discarded before smoothing. The measured interval starts at actual
observer handoff, not when a probe was first queued internally.

## Bounds, clocks and output service

Config fixes publish interval, demand TTL, probe interval/timeout, measurement
TTL, native-rate window, control refill interval/burst, and negotiated peer
queue/retention ceilings. All times are injected nondecreasing microseconds.
Deadline/counter/rate arithmetic is checked; exhaustion requires session renewal.
Local rate uses wide intermediate arithmetic and fails rather than wrapping.
The public fields are `publication_micros`, `demand_ttl_micros`,
`probe_interval_micros`, `probe_timeout_micros`, `measurement_ttl_micros`,
`rate_window_micros`, `output_interval_micros`, `output_burst`, `peer_queue` and
`peer_retained`. `Config::new(peer_queue, peer_retained)` provides finite defaults;
runtime negotiation must bind the selected values and ceilings. TTL must cover
the publication/rate interval respectively, and burst must be in 1..=4096.

At most one coalesced Demand per local live flow plus one Ping and one Pong wait
for output. Remote metadata is bounded by active receive flow capacity. A finite
interval/burst gate covers every emitted observation; unused allowance never
accumulates beyond its configured burst. Caller output queues and the common
wire/control budget remain separately bounded. A blocked observer output queue
must not block mandatory credit/final messages. Choose publication/TTL/output
allowances so the negotiated live-flow set can be refreshed in time.

Freshness uses local receipt time for remote demand, the actual completed probe
time for RTT, and the actual timed native sample for rate/sojourn. Re-reading a
snapshot does not refresh it. Current sampled native sojourn is an observation,
not proof that all flows have low delay; runtime native-pressure signals remain
necessary. No packet/network ACK is treated as actual native consumption.

## Checklist

- [x] [MOD-OBS-01] Specify optional pure APIs, fixed framing, trust and measurement ownership before code. Evidence: [API design](#apis-and-truthful-measurements).
- [x] [MOD-OBS-02] Add nonmutating exact TUN queue-head and authoritative Active demand snapshots. Evidence: [Active APIs](../../crates/l2tunnel-active/src/lib.rs), [pipeline nonmutation test](../../crates/l2tunnel-pipeline/src/tests.rs).
- [x] [MOD-OBS-03] Record timed actual native consumption and first-receipt sojourn without duplicate resets. Evidence: [confirmation APIs](../../crates/l2tunnel-active/src/lib.rs), [actual native tests](../../crates/l2tunnel-active/src/observation/tests.rs).
- [x] [MOD-OBS-04] Implement strict fixed 96-byte versioned Demand/Ping/Pong codec and literal golden framing tests. Evidence: [codec](../../crates/l2tunnel-active/src/observation.rs), [golden test](../../crates/l2tunnel-active/src/observation/tests.rs).
- [x] [MOD-OBS-05] Coalesce bounded local observations and retain reorder-safe per-flow demand freshness/high-water state. Evidence: [observer](../../crates/l2tunnel-active/src/observation.rs), [expiry and 100-retirement-cycle tests](../../crates/l2tunnel-active/src/observation/tests.rs).
- [x] [MOD-OBS-06] Implement one-outstanding bounded nonce RTT probes with correct scope and expiry behavior. Evidence: [probe state machine](../../crates/l2tunnel-active/src/observation.rs), [probe tests](../../crates/l2tunnel-active/src/observation/tests.rs).
- [x] [MOD-OBS-07] Derive local actual native rate/sojourn and fresh remote demand/in-flight feedback without synthetic inputs. Evidence: [feedback](../../crates/l2tunnel-active/src/observation.rs), [static/timed and duplicate confirmation tests](../../crates/l2tunnel-active/src/observation/tests.rs).
- [x] [MOD-OBS-08] Gate all observation emission by finite interval/burst and preserve mandatory credit service separation. Evidence: [output gate](../../crates/l2tunnel-active/src/observation.rs), [finite burst tests](../../crates/l2tunnel-active/src/observation/tests.rs).
- [x] [MOD-OBS-09] Test malformed/oversized/stale/duplicate/wrong-scope/unknown-flow inputs and arithmetic/time boundaries. Evidence: [adversarial tests](../../crates/l2tunnel-active/src/observation/tests.rs).
- [x] [MOD-OBS-10] Test real two-engine measured growth from actual queued demand, explicit pressure and no-measurement fallback. Evidence: [two-engine actual-payload test](../../crates/l2tunnel-active/src/observation/tests.rs).
- [x] [MOD-OBS-11] Run focused tests, formatting, warning-denied Clippy and checklist validation with precise receipts. Evidence: [local verification receipt](#local-verification-receipt).
- [x] [MOD-OBS-12] Negotiate and integrate observation frames, real timer/native samples and bounded common control admission in the native runtime. Evidence: [runtime integration (retired in Common cutover)](compact-wire-cleanup.md), [native measured receipt](../../work/native-active-measured/receipt.json), [finite native scope](#native-integration-evidence).

## Local verification receipt

Executed on local Linux, 2026-11-11 UTC:

```text
cargo fmt -p l2tunnel-active -p l2tunnel-pipeline
cargo test --offline -p l2tunnel-active -p l2tunnel-pipeline
  active: 31 unit tests passed, including 13 observation tests
  pipeline: 11 unit tests and 1 doctest passed
cargo clippy --offline -p l2tunnel-active -p l2tunnel-pipeline --all-targets -- -D warnings
python3 tools/check_checklists.py
```

The two-engine test transfers actual IP payloads and exchanges actual probe/echo
frames with injected finite delay. Native confirmations establish the measured
rate; 512-byte initial target grows only to the measured BDP/policy cap of 768
bytes, below the unconstrained 1024-byte doubling limit. Explicit pressure then
reduces future target without revoking issued grants. Another test churns 100
retired flows through fixed-capacity metadata while replaying old observations.
These finite pure checks do not qualify native throughput, congestion inference,
UDP delivery reliability or platform behavior. Native integration has its separate
[runtime checklist](active-runtime.md).

## Native integration evidence

Independently read back the root-run Linux namespace receipt
`work/native-active-measured/receipt.json`: all three full/half clean and impaired
half cases passed, with two live flow slots, 12 distinct TCP source ports, exact
payload hashes, IPv4/IPv6 probes and successful cleanup. Both endpoints retained
a measured-growth snapshot with positive actual RTT/rate, demanding flows and a
target above the 3200-byte protected floor. The impaired case used 70 ms configured
base RTT and 15% netem loss. Repeated log copies of a retained maximum snapshot
are not counted as independent growth events. This supports finite native wiring
and lifecycle integration, not a throughput, fairness, congestion-control or
Windows/Android qualification claim.
