# Native TCP window and throughput qualification

Status: priority investigation; full native adaptation and performance acceptance
remain open under FC-06/07/13/14/17/20/21/24. A relay credit target, a TCP receive
window and a carrier congestion window are separate observations and authorities.

## Current verified boundaries

TAP and transparent TUN preserve endpoint TCP sequence, ACK and receive-window
behavior. The explicit TUN TCP proxy owns maintained TCP legs, but its current
native policy preallocates 65536-byte send and receive rings. The measured profile
changes internal relay byte/record targets, not an exact native receive-window
setting; its public capability reports `exact_tcp_rwnd_control: false` and no
native cwnd/RTT authority. Finite zero-window/reopen behavior is implemented, but
that alone does not implement adaptive enlargement of the native receive ring.

The source19 pressure tests use real same-host Linux namespaces and kernel TCP:
proxy A's wan0 crosses a veth and router namespace to proxy B's wan0. HTB retains
100 Mbit/s A-to-B and 10 Mbit/s B-to-A, shared by all physical lanes and ACKs.
The pressure case overrides only child netem delay/loss to 0 ms/0%; it is not an
unshaped direct connection. The separate baseline TAP/TUN tests include actual
35 ms one-way/15% random loss on each direction and saved nonzero drop counters.

The [read-only native audit](../../work/window-investigation22/audit.json) records
exact pressure receipt identity, topology, observed native receive windows and
sparse measured status. Both full/half candidate targets peak at 32768 bytes.
All eight maintained native legs have accepted zero/reopen/new-ACK evidence.
Established receive-window maxima are 49920 bytes for IPv4 and 49280 for IPv6;
these are advertised windows, not the 65536-byte ring capacity or cwnd. Sparse
status sampling cannot prove every internal controller decision.

The [system-window capture readback](../../work/window-investigation22/system-native-windows.json)
checks original source18 capture hashes against the accepted raw integrity matrix.
Those finite system-traffic TAP/TUN cases preserve the application's TCP windows;
they do not qualify a different carrier or current sustained throughput.
Earlier 64 KiB LZ4 transfer timings include short-flow startup and are not speed
benchmarks. The 100/10 Mbit/s configured ceilings are not measured goodput.

## Required matched network experiment

The owner explicitly requires delay/loss and measured bandwidth, not inference
from clean same-host windows. Keep the 100/10 Mbit/s shared HTB limits and use
four explicit child-netem profiles: 1 ms per direction with zero random loss;
35 ms per direction with zero random loss; 35 ms with 1% random loss per
direction; and 35 ms with 15% random loss per direction. Their nominal added RTTs
are 2/70/70/70 ms; queueing and retransmission can increase actual RTT. Per-direction
loss configuration must not be mislabeled as an aggregate round-trip loss rate.

Use the same carrier, duplex, compression-off load and measurement interval for
each TAP/system, transparent TUN and explicit TUN proxy comparison. Report
receiver unique-application-byte goodput and WAN interface byte deltas separately
in each direction, with warmup and post-window drain excluded from timed goodput.
Interface bytes include protocol/retransmission costs and need their accounting
boundary stated; they are not application bandwidth. Capture time series for
endpoint and outer TCP cwnd (segments times MSS), RTT/retransmissions, actual
scaled advertised rwnd, and internal relay credit where observable. Label absent
observations rather than estimating them from configuration. Loss alone need not
reduce rwnd; a controlled downstream read pause separately tests receive pressure.

## Required design and evidence

- [x] [MOD-NATIVEWIN-01] Audit actual native topology, qdisc overrides, target/native-window domains and saved pressure evidence. Evidence: [read-only audit](../../work/window-investigation22/audit.json), [fixed native policy](../../crates/l2tunnel-runtime/src/proxy/config.rs), [measured capability validator](../../tools/proxy_measured_native_smoke.py).
- [ ] [MOD-NATIVEWIN-02] Establish why real few-flow native runs do not grow: distinguish sparse snapshots from exact controller updates, sender exhaustion from downstream pressure, initial grant use, stale samples, quiet recovery and queue-delay caps. Preserve the original failed receipts and workload.
- [ ] [MOD-NATIVEWIN-03] Define and implement bounded maintained-stack native receive-window admission where required, with SYN-time scaling, irrevocable advertised space, accepted-byte ownership, zero-window/persist and safe growth/shrink. Do not substitute relay-target growth for native-window authority.
- [ ] [MOD-NATIVEWIN-04] Add a causal three-phase native workload: sustained demand consumes the initial allowance and grows; downstream read pause produces pressure and reduces future admission without revoking promises; release permits exact completion and recovery. Both original duplex profiles, original protocol deadlines and complete cleanup remain required.
- [ ] [MOD-NATIVEWIN-05] Measure sustained TAP/system, TUN/transparent-active and TUN/proxy paths with explicit carrier, duplex, compression, traffic and topology. Record separate directions, one/two/many flows, warmup and measurement intervals, unique application bytes, wire cost, TCP info, actual qdisc stats, CPU/RSS and concurrent-host load.
- [ ] [MOD-NATIVEWIN-06] Compare clean and fixed impaired profiles with repeated runs and matched settings. Qualify weighted QoS, mixed bulk/interactive delay and fairness separately; short payload completion and configured bandwidth ceilings are not speed results.
- [ ] [MOD-NATIVEWIN-07] Run required source-stable checks, exact builds and independent native evidence audits before closing parent FC gates or advertising native window acceleration.

Any benchmark or controller experiment must use newly owned namespaces, bounded
traffic/process/capture resources and exact source/binary/helper provenance. A
longer measurement interval does not renew handshake, retention or drain deadlines.
Keep diagnostic modifications separate from passing product/native receipts.
