# L2 tunnel simulator

Run reproducible Monte Carlo comparisons of tunnel recovery, outer-IP byte cost, and
TCP payload goodput over a virtual link. The model runs locally in simulated time.
[Design discussion](https://chatgpt.com/share/6af2f026-75d4-8322-9056-f73a901bed92).

## Run

Run these commands from the repository root with Python 3.11 or newer.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e './simulator[dev,quic,plots]'
l2tunnel-sim --config simulator/example.toml --out work/example
l2tunnel-sim --out work/baseline
l2tunnel-sim --config simulator/tcp.toml --out work/tcp-long
python -m pytest simulator
```

The output directory must be new. The built-in sweep crosses 20, 70, and 150 ms
RTT with 10%, 15%, and 20% independent datagram loss. It uses a 1500-byte outer
MTU, 100 Mbps forward and 10 Mbps reverse IP budgets, and a 1 MiB inner TCP
flight window. Its six strategies are selective ARQ, systematic 20+10 block
FEC, 33% sliding repair, 50% short/long-window repair, direct CUBIC TCP, and
direct NewReno TCP. The example adds burst
loss, two paths, both MTUs, and a strategy with source and repair packing,
four ordered lanes, and reverse FEC. It includes separate direct TCP routes on
each path. The longer direct-TCP configuration in `tcp.toml` uses 20
replications with 30 seconds of traffic and 5 seconds of drain per run.

## Model and configuration

The top-level TOML arrays `rtt_ms`, `loss_rates`, `loss_models`, and `mtus`
define a Cartesian sweep. `replications` and `seed` control repeatability.
A scenario applies the same loss parameters to both directions on every path,
with independent draws. The `burst` option uses a stationary two-state
per-datagram Markov chain with mean loss-run length `mean_burst`. Each path
has separate forward and reverse rates, half the scenario RTT multiplied by
`rtt_factor` in each direction, and optional uniform propagation jitter.
The sender assigns datagrams to the path with the earliest estimated arrival
given its current FIFO reservation, serialization, and nominal propagation.

A source frame is split into approximately equal symbols that fit the outer
MTU. `fragments` sets the minimum for forward frames, up to one fragment per
byte. Each datagram costs 88 bytes of modeled outer overhead, with 4 bytes
for each additional packed symbol. `source_batch`, `repair_batch`,
`reverse_batch`, and `reverse_repair_batch` set the maximum symbols per
datagram. The MTU, `pack_wait_ms`, and FEC source flushes can make a batch
smaller. A packed datagram has one shared loss event. Forward frames release
in order within each of `streams` round-robin lanes. `reverse_ordered`
sets strict release order for the reverse TCP ACK stream.

All tunnel modes retain unconfirmed source symbols and selectively retransmit at
timeout. Tunnel feedback batches exact received symbol IDs and consumes
capacity in the opposite direction. It is separate from the inner TCP ACK
frames, which are themselves sent through the tunnel.

`cumulative_feedback = true` includes a four-byte contiguous receive prefix
alongside selective IDs above that prefix. A newer prefix also confirms data
covered by a lost earlier feedback packet. The default remains per-batch feedback
for reproducibility of prior experiments.

For sliding and hybrid codes, `repairs_per_group / repair_every` controls the
scheduled repair ratio. A timed partial group rounds its repair count upward.
Feedback-triggered repairs add to that ratio. Strategy names describe scheduled
redundancy, and measured byte counters include all actual repairs and retries.

| Mode | Proactive recovery |
| --- | --- |
| `tcp` | Direct IPv4 TCP with configurable CUBIC or Reno congestion avoidance and NewReno cumulative-ACK recovery. |
| `quic` | Actual aioquic CUBIC or Reno recovery and pacing over the simulated IP links. |
| `arq` | No scheduled repair |
| `block` | Systematic GF(256) Cauchy parity. A partial group uses the configured repair ratio rounded up. |
| `sliding` | One random linear repair over the last `long_window` symbols per `repair_every` sources. |
| `hybrid` | Uses `short_window` for most periodic repairs and `long_window` every `long_every` repairs. |

`fec_wait_ms` flushes a partial block or repair period after a pause.
`repair_spacing_ms` spreads scheduled repairs in time. With
`feedback_repair`, feedback can trigger additional coded repairs for older
unconfirmed symbols once previously scheduled repairs have had time to
return feedback. Selective ARQ covers remaining gaps. `reverse_fec` applies
the configured coding policy to reverse ACK frames. Decoding tracks GF(256)
coefficients and rank, with optional serial decode cost set by
`decode_us_per_symbol`.

The inner TCP model for tunnel strategies sends 1514-byte frames with 1448 bytes of application
payload. It uses a fixed flight window, in-order application delivery, and
cumulative ACKs after `ack_every` frames or `ack_delay_ms`. The
`frame_interval_ms` setting caps the source rate when positive. The
throughput results depend on the simulated release and ACK timing. Kernel
congestion control, TCP loss detection and retransmission, actual codec
CPU cost, bounded router buffers, and real TAP devices are outside the model.

## Direct TCP baseline

Set a strategy's `mode` to `tcp` and choose `tcp_cc = "cubic"` or `"reno"`.
The model sends data and ACKs directly through one configured `tcp_path`, a
zero-based path index. It uses the same link queues, erasure models, IP budgets,
and per-path random streams as the tunnel strategies. Each direct TCP segment
carries at most `min(traffic.payload_bytes, mtu - 52)` payload bytes. Forward
packets cost payload plus 52 IPv4/TCP/timestamp bytes, and ACKs cost 52 IP bytes.
L2 delivered bytes additionally include a 14-byte Ethernet header.

Direct TCP starts on an established connection with `tcp_initial_cwnd = 10`
segments. It models slow start, congestion avoidance, three-duplicate-ACK fast
retransmit, NewReno partial-ACK recovery, receive reordering, delayed ACKs,
timestamp-echo RTT sampling, and exponential RTO backoff. ACKs supplied
without a timestamp use Karn sampling. CUBIC uses beta 0.7 and C 0.4,
with its Reno-friendly estimate and bounded next-RTT target. Single-flow fast
convergence is disabled. Reno uses beta 0.5 and per-ACK additive increase.
The timer starts at `tcp_rto_initial_ms = 1000`, with a selected minimum of
`tcp_rto_min_ms = 200` and a 60-second maximum. The 200 ms floor is an experiment
parameter that differs from RFC 6298's conservative one-second recommendation.

The direct baseline is a packet-level reference implementation. Linux-specific
SACK/RACK-TLP recovery, PRR, HyStart++, connection establishment, and BBR remain
future implementation work. Tunnel strategies continue to use their specified
fixed inner flight window. Comparisons therefore include differences in
congestion control, startup, encapsulation and loss recovery. Use the recorded
controller and path fields when interpreting the results.

The congestion and recovery definitions follow
[RFC 9438](https://www.rfc-editor.org/rfc/rfc9438.html),
[RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html),
[RFC 6582](https://www.rfc-editor.org/rfc/rfc6582.html),
[RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html), and
[RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html).
The initial window setting follows
[RFC 6928](https://www.rfc-editor.org/rfc/rfc6928.html).

## Read the results

- `report.html` is self-contained and has a scenario selector. It plots
  goodput, forward latency percentiles, forward payload efficiency, and TCP
  delivery at the observation cutoff.
- `replications.csv` contains one row per strategy, scenario, and seed. It
  includes wire bytes and losses by direction and packet type, delivery,
  unconfirmed symbols, and peak retained and reordered bytes. Direct-TCP rows
  also record the controller, route, segment payload, retransmissions,
  timeouts, fast-retransmit events and final congestion window.
- `summary.csv` gives 95% Student-t intervals over independent replications.
  `paired.csv` gives matched differences against the first listed strategy.
  Matched strategies use the same random streams per path and direction.
  Different strategies may consume those draws at different times.
- `latency_cdf.csv` contains pooled percentiles for delivered forward frames.
  `experiment.json` records the expanded configuration and runtime versions. The CLI writes it last.

Goodput counts application bytes released in order during `duration_s`.
The simulation stops submitting new frames at that cutoff and continues
transmitting through `drain_s`. Efficiency divides delivered L2 bytes or
in-order TCP payload by all completed forward outer-IP bytes through the
drain, including control packets. Duplex efficiency includes both directions.
Latency measures frame submission to virtual-link release and is conditional
on release by the end of the drain. Delivery fractions show how many submitted
frames the tunnel and inner TCP actually released by that cutoff. ACK RTT
samples measure submission of the newest cumulatively acknowledged frame to
the sender's receipt of its ACK. Missing estimates appear as blank CSV fields.

For direct TCP, forward latency ends at ordered application delivery. Its
retained-byte counter measures unacknowledged payload. The L2/IP efficiency
ratio can exceed one on a lossless direct route because its numerator includes
the Ethernet header. TCP-payload/IP efficiency uses application bytes only.

## QUIC carrying complete Ethernet frames

Install the `quic` extra to use `mode = "quic"`. The optional dependency pins
`aioquic==1.3.0`. `tcp_cc` selects its `cubic` or `reno` controller and `tcp_path`
selects a route. `quic_l2 = true`, the default, sends fixed-size records containing
complete `traffic.frame_bytes` Ethernet frames on one reliable QUIC stream.
The adapter passes actual encrypted datagrams and timer events through the
simulated links. Actual UDP payload length plus 28 IPv4/UDP bytes is charged.
The IP MTU must be at least 1228 bytes. Receive credit is expressed in complete
records with the same application-window budget as the tunnel modes.

Both endpoints complete a lossless warmup before measurement. Warmup bytes and
handshake delay are excluded. Simulation time excludes CPU and encryption time.
QUIC retains its own congestion control and pacing. The tunnel model retains its
configured fixed inner flight window. Frame latency includes sender queue time,
so low-throughput QUIC runs can retain a substantial unfinished application queue
at cutoff. Completion fractions expose that queue.

`quic_retransmitted_stream_bytes` counts repeated stream bytes in completed
forward datagrams. A datagram containing any repeated stream bytes is categorized
as a retry, including datagrams that also carry new stream bytes. Qlog records
supply ACK ranges and stream offsets without accessing private connection state.

```sh
l2tunnel-sim --config simulator/quic.toml --out work/quic
```

## Complete-frame Pareto study

The study preserves 1514-byte Ethernet frames and a 1500-byte outer IP MTU.
`l2_goodput_mbps` counts complete Ethernet bytes delivered during measurement.
Extra forward byte cost is `100 * (forward_wire_bytes / forward_l2_bytes - 1)`.
At 100% extra cost the sender transmits two IP bytes for every delivered L2 byte.
Duplex cost also includes reverse traffic. Both byte-cost metrics include drain.
Packet multiplier is exported separately because fragmentation changes packet
count independently of byte cost.

The study compares feedback, FEC rates, coding windows, packing, and pacing.
`interleave_repairs = true` spreads a fractional repair ratio through the source
sequence using integer credit. Timed partial groups still flush a repair.
Paced candidates use known configured capacity and a 4 MiB application window.
Their source interval budgets 92% of link capacity for source and scheduled
repair packets. Other candidates retain the 1 MiB window. These settings are
recorded in every experiment manifest.

Run from the repository root after the editable installation. Each study saves
completed replications atomically and resumes a matching configuration.

```sh
python3 simulator/studies/l2_pareto.py --out work/l2-pareto/main
python3 simulator/studies/l2_pareto.py --out work/l2-pareto/long-check --long-check --duration 20 --drain 10
python3 simulator/studies/l2_pareto.py --out work/l2-pareto/refinement --refinement --duration 20 --drain 10
python3 simulator/studies/l2_pareto.py --out work/l2-pareto/interleaved --refinement --interleaved --duration 20 --drain 10
python3 simulator/studies/l2_pareto.py --out work/l2-pareto/feedback-batching --feedback-tuning
python3 simulator/studies/l2_pareto.py --out work/l2-pareto/feedback-long --feedback-tuning --long-check --duration 20 --drain 10
python3 simulator/studies/l2_pareto_report.py --root work/l2-pareto
```

Frontiers are empirical comparisons among tested candidates. Eligibility requires
at least 99.9% frame completion in every replication. Additional curves constrain
each replication's P99 to nominal one-way delay plus 5, 10, or 20 ms. An empty
curve means the tested candidates did not meet the constraint. Reported intervals
are Student-t intervals across replications. The report distinguishes research
sources from implemented candidates, and includes all selected configuration,
measurement, and incomplete-delivery records.

## Flow counts, coding levels, and the 80/20 target

The additional studies distinguish three packet denominators. Scheduled FEC is
the configured repair/source ratio. Measured recovery overhead includes every
repair, retransmission, and forward control datagram. The strict target uses
`100 * (all_forward_datagrams / unique_delivered_TCP_segments - 1)`, which also
charges fragmentation and packetization. TCP application goodput divided by the
configured forward IP capacity supplies the 80% throughput metric. Ethernet
preamble, inter-frame gap, and physical-layer byte costs are outside that capacity.

`studies/flow_count.py` creates independent sessions sharing the same duplex
queues, event clock, and loss process. Its fixed-total-window policy divides the
application flight budget across sessions. `Strategy.streams` continues to
represent ordering lanes within a session. `studies/ecc_levels.py` compares
GF(256) blocks including 5+1 through 200+40 and exports exact independent-erasure
binomial probabilities separately from executed recovery results.

`CompactTransport` packs records across frame boundaries and uses an elastic
GF(256) coding window. `CompactARQTransport` uses cumulative confirmations,
selective receipt bitmaps, RTT estimates, and retransmission guards. Their
feedback packets traverse the same lossy links and consume actual IP budgets.
The compact header codec implements reversible profiles for Ethernet/IPv4/TCP
with timestamp options. Delta records carry changed header fields, complete
opaque payload bytes, and a charged reliable context. Unsupported frame formats
use complete-frame records in the byte codec. The simulated bulk profile uses
supported timestamp TCP frames and measures their actual encoded record lengths.

`CompactTCP` connects these transports to the existing CUBIC/Reno TCP engine.
Data and ACKs experience the modeled links, including slow start, cumulative ACK
recovery, timestamp RTT samples, and TCP timeouts. An explicit native-ACK variant
sends complete 66-byte Ethernet ACK records over the lossy reverse path. Later
cumulative ACKs acknowledge earlier data. The reliable-ACK variant encodes the
reverse record stream as well. Minimum TCP RTO, known-capacity source pacing,
and optional authentication-byte budgets are recorded experiment parameters.

Paced TCP tracks congestion-window utilization across a sequence window so
an ACK burst followed by a pacing wait preserves the prior full-flight signal.
Its slow-start utilization rule follows the Linux window-validation design.
[Linux v6.12 TCP output](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_output.c)

`studies/compact_tcp_goal.py` exports both the full traffic interval and a
post-warmup interval. The latter uses packet counts and delivered payload from
the same interval. A successful target observation requires complete application
delivery, all TCP ACKs, and confirmation of every outer source. It also requires
at most 20% extra forward packets and at least 80% application goodput. Reports
retain individual replication results and 95% intervals. A finite passing run
does not guarantee a hard redundancy bound for every random loss realization.

Compact simulations execute coefficient/rank recovery and header byte codecs.
Their payload transport uses record callbacks. Codec CPU throughput, an AEAD
implementation, competing traffic, and real kernel/TAP behavior require separate
implementation and validation. A configured authentication cost charges bytes
without executing an authentication algorithm. The compression and coding
designs draw on the following research and standards.
[RFC 6846](https://www.rfc-editor.org/rfc/rfc6846.html),
[RFC 8681](https://www.rfc-editor.org/rfc/rfc8681.html),
[RFC 9407](https://www.rfc-editor.org/rfc/rfc9407.html).

### Reproducing the compact multi-flow candidate

The following run uses 16 independent established CUBIC connections, a shared
100/10 Mbps IP bottleneck, 70 ms propagation RTT, and independent 15% packet
erasures in both directions. The aggregate application window is 4 MiB. Compact
selective-repeat ARQ uses the reversible delta header profile. Full ACK records
traverse the reverse link. Each TCP connection has a 1-second minimum RTO.
The measurement includes initial congestion-window growth from 10 segments per
connection and leaves 20 seconds to confirm delivery after traffic stops.

```sh
python3 simulator/studies/compact_multiflow.py \
  --out work/compact-multiflow-validation --flows 16 --rto 1000 \
  --pacing unpaced --replications 5 --duration 60 --warmup 5 --drain 20
```

Use `--pacing paced` in a new output directory to compare an 81.5 Mbps aggregate
application source cap, divided equally among the 16 connections. This cap uses
the configured capacity as an input. The study records the resulting throughput,
packet cost, and delivery delay for both variants.

`CompactBlockTransport` also supports bounded GF(256) generations, initial
repair ratios, and rank-deficit feedback. The feedback echoes transmission
serials, allowing the sender to subtract repairs still in flight. Its assumed
loss rate and safety margin are explicit configuration parameters.

### Payload-size and RTT measurements

`studies/payload_sizes.py` compares 64, 256, 512, 1024, and 1448 application bytes
per TCP segment or QUIC-carried L2 record. Each L2 frame includes another
66 bytes of Ethernet, IPv4, TCP, and timestamp headers. The study exports
application throughput and RTT P50/P95/P99, together with replication intervals,
completion checks, packet costs, and source hashes.

TCP timestamp-estimator samples, smoothed RTT estimates, and ACK completion
latency have separate columns. ACK completion latency includes waiting for
recovery from the original segment submission. TCP timers use the continuous
simulation clock. The header codec's millisecond timestamp quantization is
outside that RTT calculation. QUIC RTT comes from aioquic's ACK-delay-adjusted
qlog recovery samples after connection establishment.

Profiles can select independent connection counts while sharing the same fixed
total window. A profile matching the compact candidate is

```json
[
  {
    "name": "Compact ARQ 16 flows RTO1s",
    "compact": {"header_profile": "tcp_delta", "repair_ratio": 0},
    "recovery": "arq",
    "reliable_acks": false,
    "controller": "cubic",
    "rto_min_ms": 1000,
    "flow_count": 16
  }
]
```

Save this profile as a JSON file and provide its path to `--profiles`. The
default RTT grid is 20, 70, and 150 ms at 100/10 Mbps. `--bandwidths` instead
selects 10/10 and 1000/10 Mbps at 70 ms. Each directory contains a self-contained
interactive report, a standalone figure, raw CSV, and summary CSV.

```sh
python3 simulator/studies/payload_sizes.py --out work/payload-baselines \
  --baselines-only --replications 3
python3 simulator/studies/payload_sizes.py --out work/payload-compact \
  --profiles compact-profile.json --replications 5
python3 simulator/studies/payload_report.py --root work \
  --studies payload-baselines payload-compact --output payload-comparison
```

The comparison report keeps each protocol's RTT definition separate, displays
terminal delivery and confirmation for every point, and exports directional IP
utilization. It combines matching traffic, warmup, and drain durations and rejects
duplicate replications. `reliable_acks = true` in a compact profile enables a
separate reverse ARQ record stream, whose confirmations also consume forward
packet and byte budgets.

### Latency mechanisms and complete experiment coverage

The optional `FirstFlightARQTransport` expedites the first retransmission after
fresh selective feedback confirms at least three later sources. Retries retain
the existing RTT guard. `BoundedGapARQTransport` also sends rate-limited feedback
when a qualified receive gap appears. Both use the charged, lossy feedback path.
The loss-evidence design draws on the delivery-order principles in RACK.
[RFC 8985](https://www.rfc-editor.org/rfc/rfc8985.html)

`CoalescedACKTCP` can supersede unsent advancing cumulative ACKs over a short
timer. It preserves distinct duplicate ACKs and the selected timestamp echo.
Optional redundant copies each cost a full ACK datagram and use a charged tunnel
record identifier for deduplication. Its separately selected acknowledged-segment
slow-start option changes congestion-window growth after stretch ACKs. Matched
experiments apply that option to both control and coalesced variants.
[RFC 3449](https://www.rfc-editor.org/rfc/rfc3449.html),
[Linux v6.12 TCP congestion control](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_cong.c)

The latency studies keep every pilot, negative outcome, incomplete run, and
validation replication. Queue observations distinguish serialization wait from
the complete TCP RTT sample. Small GF(256) groups also record achieved group
sizes because an idle timer can close a group before its configured size.

```sh
python3 simulator/studies/latency_window.py --out work/tcp-latency/window \
  --windows 4 --rates 81.5 --flows 16 64 --duration 60 --drain 20 \
  --warmup 5 --replications 3
python3 simulator/studies/latency_crossframe.py --out work/tcp-latency/crossframe
python3 simulator/studies/latency_ack.py --out work/tcp-latency/ack
python3 simulator/studies/all_experiments.py --root work/results-20261110
python3 simulator/studies/latency_report.py --root work/results-20261110
```

The all-experiments report inventories original saved observations and verifies
derived exports against their source runs. Each observation has an individual
scatter point wherever the required measurements exist. Configuration means
and empirical frontiers are separate overlays. Payload, duplex bandwidth, RTT,
loss process, measurement duration, drain, and model provenance define matching
conditions. Missing historical RTT samples remain explicitly unavailable.
Historical diagnostics and incomplete confirmations stay visible and have no
eligibility for fully confirmed frontiers. Packet-count overhead uses delivered
application records as its denominator, so packing several short records into
one datagram can produce a negative value. The byte-cost view separately charges
all forward IP bytes against delivered application payload.
