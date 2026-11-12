# Managed TCP/TLS profiling and performance acceptance

Status: opt-in runtime instrumentation and explicitly selected BDP delivery
integration-tested on finite native cases; the 80 Mbit/s forward performance gate remains open. This is separate from exact
payload, authentication and cleanup acceptance.

The ordinary client sets a local queue of 64 packets. The legacy/default managed
policy also uses that value as the entire unconfirmed native-packet window.
Credits return only after remote device delivery and authenticated feedback.
At 70 ms RTT, even 64 full 1500-byte packets permit only about 11 Mbit/s before
overhead. The explicitly selected BDP policy now separates local queues from a
bounded, authenticated bandwidth-times-service-RTT outstanding-byte allowance; see the
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

- [x] [MOD-PROFILE-01] Check bounded opt-in instrumentation and CLI/harness selection together, including unchanged full/half exact traffic and disabled behavior. Evidence: [source24 aggregate](../../work/implementation-wave24/validation.json), [focused runtime proof](../../work/managed-profiling24/validation.json).
- [x] [MOD-PROFILE-02] Run matched immutable profiled native cases and quantify actual blocking, queue occupancy and stage timing without conflating asynchronous wait with CPU. Evidence: [four-case independent audit](../../work/throughput24-analysis/24p-final4/report.md), [exact release build](../../work/native-build24/receipt.json).
- [ ] [MOD-PROFILE-03] Verify the causal outstanding-budget and record-emission corrections against the original slow baseline; require actual forward goodput at least 80 Mbit/s and preserve data/deadline/cleanup checks.

The source24 profile-enabled baseline reports 54.6%..89.2% completed credit-blocked
elapsed time over each process's observed 16.5..18.0-second profile lifetime.
All eight endpoints reach 64 unconfirmed packets, while local queue-full events
remain zero and outgoing queue maxima are 10..30. Mean actual native frame sizes
are 1004..1184 bytes, so 64 records are not necessarily 96 KB of application data.
Prefix/body/flush elapsed totals are short relative to the observed lifetime;
sampled process CPU is 12.4%..17.8% of one core. These observations identify the
credit limit as the leading constraint, but only a matched budget intervention
can establish the resulting throughput gain. Feedback/data record ratios of
0.733..1.078 also leave reverse-path overhead to investigate. All four measured
forward goodputs remain below 80 Mbit/s. The original diagnostic clock is relative
to profile start, so these ratios are not asserted to cover the exact shared
ten-second application measurement window.


## Source25 BDP intervention

The [source25 aggregate](../../work/implementation-wave25/validation.json) passes
1159 Rust, 202 Python tool and 1654 simulator test executions with all 799 copied
inputs stable. Its [exact release build](../../work/native-build25/receipt.json)
completed four serial TAP/TUN clean/delay half-duplex cases. Independent
[profile/policy auditing](../../work/throughput24-analysis/25bdp-final4/report.md)
and [byte/window/WAN auditing](../../work/throughput24-analysis/25bdp-bandwidth-final4/report.md)
pass payload integrity, source identity and owned cleanup; actual schema2 gauges
confirm BDP execution on both peers with the local queue still 64 packets and
separate byte/metadata bounds. All four **fail the 80 Mbit/s forward target**.

| Case | Source24 A-to-B Mbit/s | Source25 A-to-B Mbit/s | Source25 B-to-A Mbit/s |
|---|---:|---:|---:|
| TAP half clean | 6.465 | 17.571 | 6.748 |
| TUN half clean | 6.860 | 9.066 | 7.692 |
| TAP half delay | 4.714 | 11.191 | 6.642 |
| TUN half delay | 5.237 | 10.473 | 6.821 |

Profiling intervals and benchmark plans match, but these remain finite separate
observations. Source25 A has zero completed delivery-credit-blocked time in all
four profile lifetimes; B has 0..3.58%, versus source24's 54.6..89.2% across peers.
The prior 64-record admission stall is removed. Local queue-full counts are 0..33
and record high waters remain below the 8192 metadata cap. These measurements do
not establish an80 Mbit/s performance pass.

Reverse WAN aggregate traffic reaches 9.99..10.00 Mbit/s in every case, while
forward WAN traffic is only 11.32..21.80 Mbit/s over independently covered
8.57..8.95-second intervals. Those counters include reverse bulk, ACKs, framing
and control. In clean cases the delivery-service RTT EWMA reaches roughly 1.1 s;
inner and outer TCP observations also show substantial RTT growth. This
supports reverse-path competition and reliable-carrier queueing as the next
investigation, without proving a unique TLS cause or packet-overhead breakdown.
Schema2 reserved bytes are not physical-wire in-flight bytes, and no timing is
recast as CPU. The80 Mbit/s gate and matched high-performance raw/RLNC comparison
remain open; the saved simulator result is not reproduced by this TCP/TLS mode.
