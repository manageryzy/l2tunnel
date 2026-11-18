# Frame-channel recovery experiments

The simulator can place each Ethernet frame in an independently ordered channel,
or split one frame across two channels and reassemble its actual bytes at the
receiver. All channels share one forward IP serializer and one reverse serializer.
This is a diagnostic workload for TEST-12 and PBA-03/06. It has no Rust wire
profile, production default or carrier capability assignment.

## What the experiment measures

Each admitted frame has a channel sequence and one or more source fragments.
A size-bounded sender window retains data until selective or cumulative
confirmation. Only a cumulative frontier opens more sequence space. A later
fragment or sequence can reveal a gap. An incomplete record also has a local
stall timer. The receiver requests individual missing fragments over the lossy
reverse link. A completely erased final frame leaves no receiver observation.
The sender's timeout covers that case. Optional one-parity-per-record XOR
recovers one erased fragment using received bytes and the original length.

The load runs offer 1,400-byte Ethernet frames with 16 flow identities at a
fixed aggregate rate. Each flow can queue 32 original frames before input
drop. Each directional receiver has 256 service slots including the active job.
Default per-packet receiver service is an assumed 20 microseconds plus 2 ns
per XOR input byte when reconstruction executes. The slow and zero controls
change the service assumptions. Sender XOR bytes are counted. Sender CPU time,
crypto execution, inner TCP congestion control and NIC scheduling are outside
this particular workload.

The base case uses 16 channels and 32 outstanding records per channel. Each
frame produces 720- and 680-byte fragments. A packet reserves 28 IP/UDP bytes,
a 16-byte authentication allowance and a type-specific descriptor.
First request delay is 2 ms, repeat interval 80 ms, sender timeout 180 ms and
ACK delay 1 ms. These values are experimental choices. The shared-order control
uses a single 512-record window. The two-stripe control puts an 8-byte descriptor
on each half, uses adjacent channels and doubles the record slots to preserve the
aggregate original-frame byte budget. The receiver releases only complete frames.

Link service is 100/10 Mbit/s with 35 ms propagation each way and 15% IID loss
in both directions, including recovery feedback. Each original fragment/attempt
identity has a seeded loss decision. Reordering the same transmissions preserves
their decisions. Different packetizations and admission drops change the
population of transmitted records.

## Controlled loss and bulk results

In the deterministic witness, A arrives at the sender at 0 ms and B at 1 ms.
The first piece of A is erased. With independent lanes B is delivered at
36.141 ms. The first request leaves receiver logic at 37.141 ms, and A is
delivered at 107.288 ms. Shared ordered release holds B until 107.288 ms.
Erasing the first request as well leads to a second request at 117.141 ms and
delivery of A at 187.288 ms. With the sender timeout alone A arrives at
215.204 ms. With one parity packet A is reconstructed locally at 35.206 ms.
[Forced event traces](../../work/frame-channel-study-20261118/lanes-final/forced-loss.json)

The following rows average three seeds (17, 29 and 43). Frame goodput counts
the full original Ethernet bytes delivered in seconds 1 through 5. Each latency
P99 is the nearest rank among delivered frames offered after warmup, including
their input wait and up to five seconds of drain. The table averages those three
P99s. Input losses cover the entire offered period. Every admitted frame in this
matrix drained and matched its original bytes. Input drops remain failures for
the offered workload.

| Configuration | At 8 Mbit/s, frame P99 ms | At 60 Mbit/s, frame goodput Mbit/s | At 60 Mbit/s, frame P99 ms | At 60 Mbit/s, input dropped |
| --- | ---: | ---: | ---: | ---: |
| One ordered window, 512 slots | 422 | 15.42 | 990 | 71.86% |
| 16 lanes, 32 slots, timeout only | 561 | 16.85 | 1,090 | 69.52% |
| 16 lanes, 32 slots, early request | 352 | 25.05 | 690 | 55.80% |
| Same with 180 ms request repeats | 460 | 20.10 | 1,031 | 63.87% |
| Same early request with one XOR per frame | 231 | 38.04 | 491 | 34.10% |
| Same early request with 64 slots per lane | 352 | 43.40 | 603 | 25.93% |
| Two stripes per frame across adjacent lanes | 354 | 24.44 | 778 | 57.19% |

At the 8 Mbit/s offered rate all rows delivered about 8 Mbit/s with zero input
drops. At 60 Mbit/s the early-request base used 34.25 Mbit/s forward and
1.46 Mbit/s reverse. Its forward decoder queue P99 was zero and mean application
input wait was 196 ms for the reported delivered cohort. Doubling the window
raised throughput with the same decoder and link. Changing the service assumption
to 180 microseconds per packet gave 23.81 Mbit/s, a 42.37 ms forward decoder
queue P99 and 337 post-link decoder drops across three runs. The measurement
distinguishes waiting for admission from waiting for receiver CPU.
[Low-load runs](../../work/frame-channel-study-20261118/lanes-low-final/manifest.json)
and [high-load runs](../../work/frame-channel-study-20261118/lanes-final/manifest.json)

A read-only sample every millisecond reproduced every field in the three lossy
base runs. Without loss the same base delivered 60.001 Mbit/s with zero input
drops. Under loss, 191,757 of 192,000 per-channel observations found an input
waiting and the window full. In 57.19% of those blocked observations the oldest
unconfirmed frame was incomplete at the receiver while a later frame was
complete on its channel. In 38.63% the receiver had already delivered the
oldest frame and the sender still awaited cumulative confirmation. The
remaining 4.18% included partially received and in-flight frames. These are
fractions of sampled channel time. A delayed cumulative ACK can reflect normal
propagation, feedback timing or loss.
[Clean/loss control and frontier sampling](../../work/frame-channel-study-20261118/frontier-diagnostic/summary.json)

Reproduce with separate fresh output directories.

```sh
PYTHONPATH=simulator/src python3 simulator/studies/frame_channel_recovery.py work/frame-lanes-60
PYTHONPATH=simulator/src python3 simulator/studies/frame_channel_recovery.py work/frame-lanes-8 --load-mbps 8
```

## Several Ethernet frames per record

A separate paired study uses 256-byte originals, up to four originals per
record, a count byte and one two-byte length per frame. The sender retains at
most 128 original frames per channel in both arms. An unsent batch has a
2.5 ms flush timer and can still wait for recovery credit. One lost packet
removes all frames in that batch. Receivers check each delivered frame's bytes.

| Offered Mbit/s | Frames per record cap | Frame goodput Mbit/s | Offer-to-delivery P99 ms | Reverse IP Mbit/s |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 1 | 2.00 | 298.0 | 0.52 |
| 2 | 4 | 2.00 | 300.5 | 0.52 |
| 48 | 1 | 17.06 | 508.1 | 4.64 |
| 48 | 4 | 21.22 | 424.9 | 1.42 |

These rows report the median of three seeds for each metric. The quiet input
filled only singleton batches. Four originals together occupy 1,091 IP bytes.
Four singleton records require 1,268 IP bytes. The loaded four-frame arm still
dropped about 56% of arrivals before custody. Its latency includes only
delivered originals, including their admission and packing waits.
[Batch manifest and reproduction command](../../work/frame-channel-study-20261118/batching-final/manifest.json).
The sender responds to an arrived request using only its retained sequence
and fragment. Removing use of an experiment-only attempt identifier reproduced
all 68 load and forced-trace JSON results byte for byte.
[Final frame-model replay](../../work/frame-channel-study-20261118/frame-core-replay-comparison.json)

## PackedWire receiver service

The existing named PackedWire experiment can now attach a serial receive server
to each directional transport. It bounds waiting datagrams, meters known
source folds and payload row mixes implied by the actual receiver rank state,
and delays the original receive/feedback action until service completes. The
experiment reports queue overflow, occupancy, service demand, terminal work
and both directions' wait distributions. The baseline still executes the
original rank algorithm and recovers solved payload from its source ledger.
The service model estimates compute time for the missing byte work.

An isolated Rust release run measured the public rolling decoder with dense
1,460-byte coded symbols, all but source zero already present. It verified the
reconstructed bytes and cumulative prefix for every sample. Median service
time over nine post-warmup samples was 0.191 ms for 128-source support and
7.486 ms for 8,192-source support. The source width, number of missing pieces,
retained equations and available CPU all matter when using this measurement.
The benchmark excludes queuing and the carrier.
[Full calibration, raw samples and commands](../../work/frame-channel-study-20261118/calibration/rolling-service-summary.json)

The whole-decoder estimate uses piecewise linear service versus logical GF
payload bytes, anchored at the local systematic service time and the two
repair medians. Its predictions at held-out widths of 1,024 and 2,048 were
1.000 and 1.927 ms. The measured medians were 0.791 and 1.546 ms. The curve
overestimated these intermediate single-hole cases by 26% and 25%. Retained
equation populations, scheduling overhead, source density and sender CPU
remain important when comparing against a full tunnel.

In the shortened C48 control (512-byte TCP payloads, 76 Mbit/s offered),
charging the measured GF kernel alone gave forward queue P99 near 4.8 ms with
no overflow in either seed. The two whole-decoder runs delivered 13.39 and
14.87 Mbit/s in the two-second measurement interval. Forward queue P99 was
1.91 and 1.93 seconds with 1,659 and 6,049 FIFO drops respectively over the
runs including drain. TCP eventually acknowledged all data in both. The second
run retained 233 waiting jobs and one active job at cutoff with unconfirmed
MUX state. At four times the dense kernel cost, both seeds delivered zero new
application bytes in the measurement interval and ended with unconfirmed work.

Short C46 and C47 kernel-only controls also demonstrated finite receiver queues.
C46 measured 64.44 / 64.53 Mbit/s with zero / dense-kernel service, and
C47 measured 71.76 / 71.92 Mbit/s. Both confirmed, with respective dense
forward queue P99 of 4.63 and 4.75 ms. A fixed-window arrival rate can exceed
the offered rate briefly because earlier frames arrive within the measurement
window. These controls use the corresponding original workload and seed with
3 seconds of traffic, 1 second of warmup and 3 seconds of drain.
[C46/C47 controls](../../work/frame-channel-study-20261118/other-packed-short/summary.json),
[C48 kernel controls](../../work/frame-channel-study-20261118/packed-reference-final/summary.json)
and [C48 whole-decoder controls](../../work/frame-channel-study-20261118/packed-decoder-anchors/manifest.json)

Applying the same frozen whole-decoder curve to the C46 and C47 short runs
gave 64.61 and 71.95 Mbit/s with full confirmation. Forward decoder queue
P99 rose to 7.10 and 7.39 ms. TCP application delivery P99 rose from 151.97 to
202.35 ms for C46 and from 183.56 to 187.50 ms for C47. Neither had an
overflow. The throughput collapse in the C48 short experiment depends on the
workload and recovery dynamics. For example, C48 seed one produced four tail
repairs in the zero-cost arm and 2,171 in the whole-decoder arm, even as its
source count fell from 23,888 to 11,705.
[C46/C47 whole-decoder controls](../../work/frame-channel-study-20261118/other-packed-curve/summary.json)

A C48 short-run intervention tested whether feedback-driven tail bursts account
for the queue. It allowed one full-support tail repair per timer expiry and
preserved regular local/global repairs. Tail counts fell from 2,171 and 7,176
to 29 in each seed. Forward queue P99 fell from 1.91/1.93 seconds to
47.7/45.4 ms. Throughput rose from 13.39 to 20.23 Mbit/s in seed one and
stayed at 14.87 Mbit/s in seed two. At cutoff the senders still held 7,381
and 7,694 unconfirmed sources, respectively. Both TCP and MUX confirmation
failed in both capped cases. The all-cohort lower bound on P99 delivery
worsened in both cases. This intervention identifies a cause of the queue
and a simultaneous loss of recovery progress. Its receipt records a concurrent
change to an unused observer argument during the post-run source audit.
[Tail intervention and terminal state](../../work/frame-channel-study-20261118/tail-control/summary.json)

On the full original C48 first seed (90 seconds of traffic, 5 seconds of
warmup and 30 seconds of drain), the unchanged-cost rerun reproduced all 423
shared observation/configuration fields other than wall-clock runtime. Both
the original and dense-kernel arms confirmed. Their steady application rates
were 75.9963 and 75.9936 Mbit/s, and their TCP application delivery P99s were
141.49 and 145.27 ms. The dense-kernel arm's forward decoder queue P99 was
5.52 ms without queue overflow.
[Historical field comparison](../../work/frame-channel-study-20261118/packed-full-pair/historical-comparison.json)
and [full kernel control](../../work/frame-channel-study-20261118/packed-full-pair/summary.json)

The same complete C48 workload with the whole-decoder service curve delivered
**0.884832 Mbit/s** in seconds 5 to 90. TCP application delivery P99 through
drain was **19.677 seconds**. The forward decoder dropped 400,072 of 424,674
arrivals at its full input queue. The 24,602 serviced jobs had queue P99 of
2.248 seconds. The reverse decoder had zero queue wait and overflow.
All 45,051 application frames actually offered under TCP backpressure were
acknowledged by the end of the 30-second drain, and both MUX directions
confirmed. The steady-state gate produced no active SYN probe samples.

Over the entire run the sender produced 472,041 tail repairs for 22,626
source symbols. In the throughput window, 504,543,422 forward IP bytes
carried repair packets and 9,048,376 carried sources. Repair took 98.24% of
the forward wire bytes. A receiver that stays behind delays feedback, the
sender spends more service on old gaps and inner TCP submits much less new
data. Fitting a service curve to isolated repairs exposes this feedback loop.
The quantitative result is conditional on the cost curve and one long seed.
[Full calibrated C48 observation](../../work/frame-channel-study-20261118/packed-rank-dense-full/result.json)

The optional dense rank backend executes the same GF operations using translated
byte rows and integer XOR in the simulator process. It charges the same model
work before committing each job. The historical sparse solver remains available.
The two short seeds reproduced the sparse receiver and application metrics.
The long workload also records simultaneous checkpoints of both receive
directions, equation/known-state hashes, all flow counters, losses, wire bytes
and the hash of the whole sequence of realized FIFO waits. All seven checkpoints
at 1, 3, 5, 8, 10, 12 and 15 simulated seconds matched the sparse reference
byte for byte. The dense backend completed the 90-second workload and 30-second
drain. The independent sparse reference was checked through 15 seconds.
[Rank replay manifest](../../work/frame-channel-study-20261118/packed-rank-dense-full/manifest.json)

The regular study entry accepts either a kernel-work price
(`packed_receiver_cost`) or an empirically fitted whole-decoder price
(`packed_decoder_curve`). Leaving both out reproduces the original behavior.
The normal whole-decoder entry reproduced all 170 comparable fields per seed
from the short calibration run.
[Normal-entry replay verification](../../work/frame-channel-study-20261118/packed-anchored-entry/verification.json)

To repeat the full pair and fit using the same archived costs, use the original
C48 task plan and the measured calibration files below. Fresh native
recalibration additionally requires the Rust source revision and dirty-source
hashes recorded in the native calibration manifest. The frame-channel runner
above requires only the checked-in model and the Python standard library.

```sh
study=work/frame-channel-study-20261118
PYTHONPATH=simulator/src python3 simulator/studies/packed_service_sensitivity.py \
  --full-pair --gf-manifest "$study/packed-full-pair/manifest.json" --out work/c48-full-replay
PYTHONPATH=simulator/src python3 simulator/studies/packed_decoder_sensitivity.py \
  --anchors "$study/calibration/rolling-service-summary.json" \
  --paired-manifest work/c48-full-replay/manifest.json --rank-backend dense \
  --out work/c48-full-decoder-replay
```

## Targeted recovery in the original PackedWire workload

The opt-in `packed_targeted_recovery` experiment runs through the ordinary
duplex PackedWire MUX. It keeps C48's packing, compressed channel records,
local 128-source and periodic global 8,192-source FEC, decoder cost curve and
16 inner TCP flows. The existing receiver already releases a solvable record
when its own channel's dependencies are satisfied. Cumulative confirmation
continues to control sender custody.

A later source or repair header tells the receiver which source IDs could
already have arrived. It waits 2 ms for a missing ID, then shares a budget
of eight IDs per 2 ms between newly observed holes and older requests due
for a repeat. Each packet names IDs within a 32-source span. The span start
and the cumulative confirmation are separate fields so a request far ahead
of the oldest hole never acknowledges that hole. A missing ID becomes
eligible again after 80 ms. Both the request and the original-byte retry
use their respective lossy link serializers. If the sender has gone quiet
for 140 ms with outstanding data, it retries its earliest unconfirmed
original. A wholly erased tail needs no receiver-side guess.

In a forced-loss test, source 0 remained unavailable while source 150 on a
different channel was explicitly requested, recovered and delivered. The
receiver delivered 200 later frames before source 0, kept the cumulative
frontier at zero and eventually confirmed all 201 sources. Tests also cover
the loss of a request, a retry and a final confirmation, ID wrap, malformed
requests, duplicate fragments and channel-local codec order.
[Targeted repair tests](../../simulator/tests/test_packed_targeted.py) and
[independent channel delivery tests](../../simulator/tests/test_packed_channel_release.py)

Run the original calibrated C48 seed and write new evidence with
`PYTHONPATH=simulator/src python3 simulator/studies/packed_targeted_study.py --out work/targeted-full-replay`.
The runner verifies the archived control before starting. Goodput and wire
byte shares use seconds 5 through 90. The delivery P99 includes delivery
during the 30-second drain. The recovery byte share counts FEC repair and
retransmitted original IP bytes divided by all departed IP bytes in the same
direction and interval. The receipt also breaks out feedback and short-source
copies.

| Full C48 run, first archived seed | TCP goodput Mbit/s | Application delivery P99 ms | Forward recovery share | Reverse recovery share | Unconfirmed sources at 90 s, forward / reverse | Unconfirmed sources after drain |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Archived calibrated deficit-driven tail | 0.885 | 19,677.27 | 98.24% | 1.66% | 1,694 / 0 | 0 / 0 |
| Targeted originals with fair fresh/old requests | 67.863 | 577.73 | 29.21% | 10.92% | 1,322 / 0 | 0 / 0 |

The targeted run delivered and confirmed all 1,496,400 original TCP segments.
At traffic end 7,471 segments awaited acknowledgement and after drain none
remained. Forward IP service ran at 100.00 Mbit/s over the measured interval.
Of those bytes, 14.72% went to coded repairs and 14.48% to retried originals.
On the reverse link, the recovery share including the configured short-source
copies was 61.33%. Forward receiver queue P99 fell to 35.67 ms, with 50,286
input overflows across the run. The short runs with two original seeds delivered
71.22 and 71.09 Mbit/s, with delivery P99 of 271.92 and 255.65 ms and full
confirmation. The long result is one finite simulation with the same receiver
cost calibration as the baseline. The altered packet sequence consumes the
seeded erasure stream differently.
[Full targeted run](../../work/packed-targeted-20261118/fresh-full-r1/summary.json),
[matched historical control](../../work/packed-targeted-20261118/fresh-full-r1/archived-full-summary.json),
[short seed one](../../work/packed-targeted-20261118/fresh-pilot-r1/summary.json)
and [short seed two](../../work/packed-targeted-20261118/fresh-pilot-r2/summary.json)
