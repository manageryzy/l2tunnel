# Transparent active TUN over authenticated TCP

Status: implemented and genuine authenticated TCP/TLS loopback integration-tested
with independent memory packet devices. The design was written before implementation.
This adapter connects the actual
[active credit engine](active.md) and its unchanged-IP weighted DRR/MUX pipeline
to the existing authenticated full or paired-half TCP/TLS `Link`. It implements
fixed per-flow bootstrap credit, actual-native-release/regrant and authenticated
idle-flow retirement. An explicit optional profile integrates authenticated real
demand, RTT and native-delivery measurements with bounded target growth. TCP
proxy/window ownership, external fairness and managed hot switching remain separate gates. TAP continues to use system policy.

## Public interface and negotiated policy

`Settings::new(runtime: RuntimeConfig, duplex: Duplex)` constructs finite static
defaults. Settings contain duplex, finite flow slots, MUX channel count, base DRR
quantum, a 64-entry operator-controlled DSCP-to-flow-weight table, control packet
rate, heartbeat spacing, I/O deadline, finite idle/final-retry policy and an
explicit `adaptive` boolean that defaults to false. All weights default to one; no user
probe or TCP-control special case exists. A flow's first packet fixes its weight;
changing DSCP within that flow does not silently change its registration.

`session_config(runtime, settings)` hashes every behavioral setting, the fixed
wire/profile version and static derived ActiveConfig before TLS authentication.
Every physical lane must authenticate the same digest. `run(device, link, runtime,
settings, optional_reporter)` validates retained authenticated metadata and native
IP layer before any device read. `observations()` returns a read-only observer and
unique reporter; status includes separate engine queue, logical retention,
receiver reservation/native payload and actual delivery observations.

The logical active session ID is a domain-separated SHA-256 truncation over the
authenticated digest, duplex and global client-to-server then server-to-client
lane session IDs. Full duplex uses the same physical session twice. Complementary
authenticated client/server roles select Forward/Reverse; epoch is fixed to one.
This is identity binding, not a new key derivation or proof of lane authentication.
Existing authenticated Link constructors and half-lane pairing remain authoritative.

The adapter derives a transparent-TUN CRC-affinity pipeline with configured
weighted DRR, bounded total/per-flow original bytes and packet counts, and no
automatic idle eviction. Receive credit reserves one maximum native packet and
one record per configured flow slot. Every flow gets that fixed floor and is
replenished only after actual native delivery. The optional measured profile may
increase unissued targets within the same negotiated memory and count ceilings. No RTT, bandwidth, demand or
pressure observations are fabricated. A full flow table retains native admission
while safe idle retirement makes space. Cumulative counter exhaustion requires an
explicit new authenticated session; IDs are never reused within this session.
Static one-record floors constrain per-flow flight independently of scheduler
weights: these checks prove common weighted scheduling is used, not a particular
native throughput ratio or measured adaptive TCP acceleration.

## Framing, control service and ownership

Each authenticated direction carries a strict 40-byte `L2AC` version-one header:
magic(4), version(1), kind(1), reserved(2), monotonically increasing stream record
sequence(8), logical session(16), body length(4), MUX channel(2), reserved(2).
Kinds are control(1), user data(2), heartbeat(3), and explicitly negotiated
observation(4). The optional observation body is exactly 96 bytes. The fixed 72-byte active token
is a control body; a user-data body is that token followed by the negotiated
stateless FrameCodec IP record. Heartbeats have no body. Context, sequence,
reserved bits, exact length, channel and kind are validated before bounded body
allocation. Stream sequence never resets; repeated or skipped sequence values
fail closed even though TLS already supplies integrity and replay ordering.

Full duplex multiplexes bounded control/data queues into the same original TLS
writer. Paired half duplex keeps user data on each original bulk direction and
sends control on the reverse direction of the opposite bulk lane. Open tokens
have one reliable ordered control path; the returned Grant causally precedes the
first admitted user packet even when control/data use different physical lanes.
User data on a control-only lane, or control on a bulk-only lane, is rejected.

Dedicated reader/writer tasks own partial framing across main-loop ticks. Native
WouldBlock retains the exact borrowed Active delivery and does not confirm it.
Only a successful device write calls `confirm_delivery(record)` (or timed
`confirm_delivery_at(record, now)` in the optional measured profile). Native input uses
the 65536-byte maximum-plus-one buffer contract and retains one pending original
packet when admission is full. No packet is re-submitted after logical admission.

The runtime reserves a bounded destination queue before calling split
`Active::poll_control` or `poll_data`. Both APIs transfer ownership exactly once.
Writers retain the selected record through complete TLS write/flush; failure
terminates the session. Control has a fixed-size queue and configured rate/burst;
data remains bounded by queue slots and the unique logical-credit ledger. The
full-duplex writer alternates ready control/data records while a shared TCP byte
stream still has ordinary head-of-line blocking. Heartbeats are timer state, not
an accumulating queue, and consume control service. No extra user lane is added.

All work loops are bounded. Input queues and external record copies are accounted
separately from engine-owned payload/reservations. A dropped run future aborts and
drops all child tasks and unique stream owners. EOF, I/O timeout, invalid peer
input or counter exhaustion is explicit failure, with the latest observation
marked stopped; no graceful-drain success or reconnect/resume is claimed.

## Authenticated idle retirement

The design preceded implementation. Settings include `idle_flow_timeout` (default 60 seconds),
`retirement_retry` (default one second), and `retirement_max_attempts` (default
eight). All are finite positive policy fields included in authenticated profile
digest version three (retirement was introduced in version two). Existing frame/token formats stay fixed. Idle age is bounded
to one millisecond through one day; retry spacing to one millisecond through
30 seconds, with at most 32 attempts and 120 seconds of configured retry intervals.

The runtime uses `Active::idle_candidate` and permits exactly one outgoing
logical Final barrier. Before requesting retirement, it establishes a conservative
global external drain: cumulative data outputs handed to the writer equal actual
completed TLS data flushes, cumulative control and optional-observation outputs
equal their actual completed flushes, every bounded output queue has all slots
available, and the optional observer retains no pending outputs. Merely
dequeueing a record is not a flush. A pending native packet with the candidate key
prevents retirement. The engine independently verifies idle age, empty original
queues and complete logical release for the candidate.
This global barrier is conservative: continuously active unrelated output can
postpone retirement. When a new native flow is retained because the table is full,
existing data/control continue draining until the barrier can be established.

There is no caller-owned ARQ/FEC/retry layer in this TCP profile, so the observed
external recovery-record count is zero. This does not claim kernel TCP queues are
empty: authenticated actual-native release proves the candidate's original bytes
were consumed, while any kernel retransmission remains the same ordered stream
bytes. No application record copy may remain outside the engine at the barrier.

The source key/weight remains registered and frozen until the engine accepts an
exact FinalAck. Runtime cleanup occurs only after that authoritative transition.
Flow-capacity and frozen-key admission failures retain the one pending native
packet; existing control, delivery and drain continue. New frames for a just-retired
key receive a fresh increasing flow ID and establish a new initial weight. No
silent eviction, local ID reset or timeout rollback is permitted.

Retry polling waits for previous external controls to flush, so a blocked writer
cannot accumulate copies of the same Final. Engine coalescing and finite attempts
remain authoritative. A lost/stuck peer eventually hits the finite Final/I/O
deadline; the session fails with the key still frozen. Other existing flows can
continue before that deadline. Native observed status exposes pending retirement,
completed retirements and actual produced/flush observations separately.

Retirement does not enable managed hot reload. Optional observation publication
pauses while Final is pending. Absent fresh qualified observations cannot grow
unissued credit, and an empty demanding set restores per-flow floor allocation.

## Optional measured profile (design preceded implementation)

`Settings.adaptive` defaults to false. The explicit adaptive profile authenticates
a distinct version-three digest including every derived observation timing, rate,
queue and retention bound. Kind four carries exactly 96 bytes from the optional
[observation engine](active-observation.md), only on the existing ordered control
path. Open and Demand retain causal ordering. Input shares the bounded ordered
control queue; output observations have their own eight-slot queue. They consume
the same total per-writer control allowance, with at most half that allowance
available to observations, reserving the remainder for mandatory credit/Final
and heartbeat service. No extra user lane or admission bypass is introduced.

Observation handoff waits until prior mandatory controls have entered their
writer queue. Mandatory records have selection priority over optional records on
the same writer, and an already selected Open completes before any following
record starts. This preserves Open-before-Demand without waiting for every later
Release to flush. Sustained mandatory traffic can postpone optional measurements;
expired or absent measurements cannot qualify growth. Demand
publication and probe freshness scale with the negotiated flow count and optional
service allowance. The output budget refills once per second with half the
negotiated control burst. A full publication cycle is the ceiling of
`(max_flows + 2) / optional_burst` seconds; demand and measurement freshness are
three cycles, probe timeout two cycles and probe interval one cycle. Demand
coalesces at 100 ms and native-rate anchors require at least 10 ms of actual time.
RTT starts at observer handoff and includes subsequent writer
queue and peer-processing delay. Native rate and queue sojourn use only successful
`confirm_delivery_at` calls; a real native `WouldBlock` supplies receiver pressure.
No configured bandwidth, invented RTT, ECN, loss or carrier-congestion signal is
substituted. The runtime explicitly calls `update_targets` only in this profile.

Every optional output has produced/flushed watermarks and joins the conservative
Final drain alongside the observer's finite pending outputs. Publication pauses
while a Final is outstanding; peer observations and mandatory control continue.
Status distinguishes negotiated adaptive mode, fresh RTT/rate/demand, actual
native pressure and logical target from native throughput qualification.

## Acceptance checklist

- [x] [MOD-ACT-RUNTIME-15] Implement explicitly authenticated adaptive configuration, strict optional framing and reserved bounded observation service. Evidence: [Settings/binding and writer](../../crates/l2tunnel-runtime/src/active.rs), [negotiation/budget tests](../../crates/l2tunnel-runtime/src/active_tests.rs).
- [x] [MOD-ACT-RUNTIME-16] Integrate real demand/RTT/native rate/sojourn, actual pressure and explicit target updates while preserving static behavior and retirement drain. Evidence: [runtime ownership loop](../../crates/l2tunnel-runtime/src/active.rs), [independent measurement engine](../../crates/l2tunnel-active/src/observation.rs).
- [x] [MOD-ACT-RUNTIME-17] Test measured growth, native-pressure handling, stale/absent measurement fallback, framing and mandatory-control reservation in both duplex modes. Evidence: [16 focused runtime tests](../../crates/l2tunnel-runtime/src/active_tests.rs).
- [ ] [MOD-ACT-RUNTIME-18] Qualify the optional measured profile with native evidence separately from local loopback tests and external fairness claims.

- [x] [MOD-ACT-RUNTIME-01] Freeze bounded settings, exact canonical binding and shared logical session identity before implementation. Evidence: [Settings/session binding](../../crates/l2tunnel-runtime/src/active.rs), [binding tests](../../crates/l2tunnel-runtime/src/active_tests.rs).
- [x] [MOD-ACT-RUNTIME-02] Implement strict session/sequence/length framing and cancellation-safe full/paired-half reader/writer ownership. Evidence: [lane reader/writer](../../crates/l2tunnel-runtime/src/active.rs), [parser/partial/EOF tests](../../crates/l2tunnel-runtime/src/active_tests.rs).
- [x] [MOD-ACT-RUNTIME-03] Integrate unchanged TUN admission, real per-flow weighted DRR/MUX, static floor grants and actual native-release/regrant. Evidence: [native ownership loop](../../crates/l2tunnel-runtime/src/active.rs), [independent bidirectional memory-device tests](../../crates/l2tunnel-runtime/src/active_tests.rs).
- [x] [MOD-ACT-RUNTIME-04] Retain backpressured native/output bytes, reserve bounded control service and expose truthful lifecycle/resource observations. Evidence: [bounded writer/observer](../../crates/l2tunnel-runtime/src/active.rs), [WouldBlock/control-refill tests](../../crates/l2tunnel-runtime/src/active_tests.rs).
- [x] [MOD-ACT-RUNTIME-05] Test genuine authenticated TCP/TLS loopback, both duplex modes, multiple IP flows, native WouldBlock, mismatch/malformed/replay/EOF and cancellation bounds. Evidence: [nine focused tests](../../crates/l2tunnel-runtime/src/active_tests.rs), [validation receipt](#local-validation).
- [x] [MOD-ACT-RUNTIME-06] Run local formatting, strict Clippy, focused tests, rustdoc and repository checks with an evidence receipt. Evidence: [local validation](#local-validation), [repository check runner](../../tools/check.py).
- [x] [MOD-ACT-RUNTIME-07] Integrate CLI/native namespace qualification and explicit transparent-active selection; preserve TAP/system defaults. Evidence: [active client](active-client.md), [native None](../../work/native-active-plain/receipt.json), [native LZ4](../../work/native-active-lz4/receipt.json).
- [ ] [MOD-ACT-RUNTIME-08] Add authenticated measured demand/RTT feedback, qualified adaptive target growth and external TCP fairness evidence.
- [ ] [MOD-ACT-RUNTIME-09] Add explicit serialized output/recovery drain proof for safe idle-flow retirement and coordinated mode-switch barriers.
- [x] [MOD-ACT-RUNTIME-10] Authenticate finite idle/retry policy and prove external drain with actual data/control flush watermarks before freezing a flow. Evidence: [settings/binding and ExternalOutputs barrier](../../crates/l2tunnel-runtime/src/active.rs), [actual writer flush tests](../../crates/l2tunnel-runtime/src/active_tests.rs).
- [x] [MOD-ACT-RUNTIME-11] Integrate one serialized Final, finite retry service, retained capacity/frozen-key backpressure and exact FinalAck key/weight cleanup. Evidence: [retirement service and native ownership loop](../../crates/l2tunnel-runtime/src/active.rs), [pure authoritative final protocol](../../crates/l2tunnel-active/src/retirement.rs).
- [x] [MOD-ACT-RUNTIME-12] Test sequential churn beyond flow capacity, same-key revival, delayed old controls, unflushed output rejection and stuck-peer failure without rollback in both duplex modes. Evidence: [full/half TLS churn and withheld-ACK tests](../../crates/l2tunnel-runtime/src/active_tests.rs).
- [x] [MOD-ACT-RUNTIME-13] Revalidate local tests/lints/docs/aggregate checks and separately qualify native churn before asserting native retirement coverage. Evidence: [stable wave4](../../work/implementation-wave4/validation.json), [static native churn](../../work/native-active-churn-qualified/receipt.json), [measured native churn](../../work/native-active-measured/receipt.json).
- [x] [MOD-ACT-RUNTIME-14] Add a separately negotiated measured-observation profile while preserving the static fallback and original user bulk lanes. Evidence: [explicit adaptive binding and lane implementation](../../crates/l2tunnel-runtime/src/active.rs), [full/half TLS measurement tests](../../crates/l2tunnel-runtime/src/active_tests.rs).

## Local validation

Executed on local Linux: `cargo fmt -p l2tunnel-runtime`,
`cargo test -p l2tunnel-runtime active:: --offline` (16 focused tests after retirement and optional measurements),
`cargo clippy -p l2tunnel-runtime --all-targets --offline -- -D warnings`, and
`RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-runtime --no-deps --offline`
passed. The original static `python3 tools/check.py` receipt is
`/tmp/l2tunnel-active-runtime-check.log`; the retirement/adaptive aggregate rerun
is tracked separately in `/tmp/l2tunnel-active-adaptive-check.log`. Loopback cases
use fresh real TLS/member-authenticated connections and
independent engine/device state; both full/paired-half and None/LZ4 are exercised.
The adapter used the shared native receive sentinel buffer and retained exact
original bytes across within-flow DSCP changes. Separate native receipts above
passed all six TUN half/full clean and impaired-half cases with None/LZ4, exact
IPv4/IPv6 probes, TCP SHA-256 and cleanup. The root-run
[native retirement receipt](../../work/native-active-churn-qualified/receipt.json)
was independently read back: all three full/half clean/impaired cases passed with
12 distinct source ports, per-flow 4096-byte SHA-256 checks, a 100 ms idle policy,
and namespace cleanup. This receipt predates native adaptive qualification.
Measured native growth, external fairness, remote CI and Windows/Android device
results remain unqualified.
