# Managed TCP/TLS profiling and performance acceptance

Status: opt-in runtime instrumentation implemented; native profiling and the
80 Mbit/s forward performance gate remain open. This is separate from exact
payload, authentication and cleanup acceptance.

The ordinary client currently sets a local queue of 64 packets. The managed
runtime also uses that value as the entire unconfirmed native-packet window.
Credits return only after remote device delivery and authenticated feedback.
At 70 ms RTT, even 64 full 1500-byte packets permit only about 11 Mbit/s before
overhead. The intended correction separates local queues from a bounded,
negotiated bandwidth-times-service-RTT outstanding-byte allowance; see the
[delivery-window contract](delivery-window.md). No fixed 64-packet window can
qualify the required 80 Mbit/s forward target in that delayed profile.

`--profile-ms 100..60000` explicitly enables ordinary system TCP/TLS frame
instrumentation; zero/default disables it. Unsupported paths are rejected
before connection setup. Public runtime observers and the CLI share one
replaceable watch snapshot. There is no extra packet queue or background
protocol task. The fixed metric labels contain no peer payloads or secrets.

Snapshots contain cumulative device/codec/data/control/feedback counters,
configured limits and queue high-water marks, driver/writer wake reasons,
admission-credit and queue blocking, and count/sum/max stage timings.
Transport read/write/flush and select durations include async suspension;
concurrent stage durations overlap and must not be summed as CPU utilization.
Codec/device synchronous call timings are elapsed call durations, not a
thread CPU clock. Disabled profiling does not read clocks at each stage.

The harness's `--profile-ms` selects the same diagnostics and saves them in
bounded daemon logs. Common application-window goodput and exact byte/hash/EOF
checks remain unchanged. `performance_acceptance` explicitly requires at least
80 Mbit/s A-to-B; B-to-A has a separately configured 10 Mbit/s ceiling. A
successful integrity result with a failed performance gate is not qualified.

The source23c matched half-duplex baseline has six successful system transfers:
TAP/TUN with 2 ms nominal RTT, 70 ms RTT, and 70 ms/1% per-direction random loss.
Every forward rate is below 80 Mbit/s. Both 15%-loss system cases exhausted the
original probe deadline and yield no accepted application rates. The measured
proxy's new 2-second probe lifetime yields fresh actual service observations at
70 ms RTT, but its three completed cases also fail performance acceptance.
All twelve owned case cleanups passed. See the
[system audit](../../work/throughput23-analysis/23c-system-half-final8/report.md),
[proxy audit](../../work/throughput23-analysis/23c-proxy-half-final4/report.md), and
[simulator reference comparison](../../work/throughput23-analysis/simulator80-comparison.md).
The saved 80 Mbit/s simulator uses a different raw/CRC/RLNC protocol and a
16-flow forward workload; that distinction does not waive the native target.

- [ ] [MOD-PROFILE-01] Check bounded opt-in instrumentation and CLI/harness selection together, including unchanged full/half exact traffic and disabled behavior.
- [ ] [MOD-PROFILE-02] Run matched immutable profiled native cases and quantify actual blocking, queue occupancy and stage timing without conflating asynchronous wait with CPU.
- [ ] [MOD-PROFILE-03] Verify the causal outstanding-budget and record-emission corrections against the original slow baseline; require actual forward goodput at least 80 Mbit/s and preserve data/deadline/cleanup checks.
