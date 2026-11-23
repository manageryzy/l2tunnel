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

## Original-frame latency in the calibrated C48 run

The [frame observer](../../simulator/src/l2tunnel_sim/packed_frame_path.py)
follows each original forward TCP segment from the inner sender's first
submission to contiguous application delivery. It joins the TCP flow and
segment number to the MUX attempt that reached TCP first, the last required
packed source to become available, and the physical packet that unlocked
that source. A retry of a *different* source can unlock an existing equation.
Time spent waiting for that transmission includes any intervening failed
attempts. Time after all of the frame's own sources are known is measured
separately at channel release and at ordered TCP delivery. The measured
origin excludes demand waiting to enter the inner TCP sender.

Sort the completed originals by their total lifetime and take the slowest
one percent, rounded up to a whole frame. Phase means below refer to those
same frames and add up to their mean total lifetime. The decoder FIFO's P99
uses a different population, individual physical packets that entered service.
Input overflow, erasure, and an earlier missing record can delay application
delivery beyond any single accepted packet's decoder wait.

The [byte-budget policy](../../simulator/src/l2tunnel_sim/packed_latency_policy.py)
lets a requested retransmission displace future proactive FEC on its own
direction. It charges the actual IP bytes of each retry and the encoded size
of each prospective repair. The selected variant credits half the retry
bytes, with a cap of 32 MTUs for this workload. A regular repair is skipped
only once its entire cost is covered. Residual credit expires at full
confirmation. All transmitted equations keep their local 128 / every 16th
global schedule. The source custody bound remains 8,192 and the sender can
retry an old missing original while another channel delivers newer frames.

In two short pilots, crediting every retry byte reduced mean MUX wait below
0.4 ms, but increased application P99 to 301 and 334 ms. Half credit retained
more proactive FEC and yielded 135 and 132 ms. Both pilots use one second of
warmup, three seconds of offered traffic and three seconds of drain.
[Two-seed budget comparison](../../work/packed-latency-20261118/budget-pilots/comparison.json)

The full original-seed replay reproduced 418 stored result fields and all
three cutoff snapshots. The baseline delivered 1,496,400 original segments.
Its slowest 14,964 spent 325.86 ms on average waiting for MUX admission,
151.94 ms waiting for earlier channel records after their own data was
known, and 75.98 ms waiting for the transmission that unlocked their own
last required source. Forward propagation added 35.00 ms and waiting for
decoder service added 27.28 ms. Packing, physical FIFO wait, serialization
and decoder execution together added 0.34 ms. The mean lifetime of these
frames was 616.39 ms. Inner TCP reordering added zero time in this cohort.
The baseline's slowest original, flow 8 segment 21618, waited 361.79 ms for
MUX admission and a further 312.93 ms until the sender issued the successful
retry of source 175043. It reached the application 731.14 ms after submission.
[Baseline phase evidence](../../work/packed-latency-20261118/baseline-full-1/frame-path.json)
and [baseline replay check](../../work/packed-latency-20261118/baseline-full-1/parity.json)

The original sender schedules proactive FEC in addition to each named
retransmission. Both occupy the physical FIFO. The MUX admits the next user
frame only when that serializer is free. In the 85-second measurement window,
the baseline used 29.21 Mbit/s for forward repairs and retries on the
saturated 100 Mbit/s link, leaving 70.74 Mbit/s for forward source IP
packets including all headers. The inner sender requested 76 Mbit/s of
application payload. Under sustained load, original frames accumulated
*before* MUX admission. This explains why the physical FIFO residence of
the final solving packet itself could be very short.

At full duration the fixed half-credit policy increased TCP goodput from
67.86 to 75.41 Mbit/s and reduced delivery P99 from 577.73 to 399.55 ms.
Forward decoder overflows fell from 50,286 to zero. The forward MUX still
accumulated 3.00 MB and the slowest one percent spent 276.31 ms on average
waiting for admission. Both arms confirmed every offered original by the
end of drain. [Fixed half-credit comparison](../../work/packed-latency-20261118/comparison.json)

The [ranked per-original export](../../work/packed-latency-20261118/full-tail-segments-1/slowest-originals.jsonl.gz)
contains a row for each of the 14,964 baseline originals. Of these, 12,553
waited for channel order. A named retry unlocked the last required source
for 5,617 originals, including 2,270 whose solution depended on another
source's retry. For each of those 5,617 rows the observer matched the gap
evidence, the request that reached the sender and the resulting transmission.
The remaining 9,347 got their own last required source from a systematic
packet. The cause counts overlap the channel-wait count.
[Export validation](../../work/packed-latency-20261118/full-tail-segments-1/readback.json)

Flow 14 segment 16249 sat exactly at the baseline P99. It spent 301.12 ms
at MUX admission and 185.11 ms from source sealing to the successful retry
of source 131567. Forward propagation took 35.00 ms, decoder FIFO wait took
9.81 ms, and the solved record waited 46.17 ms for channel 12. Source 131559
then advanced the expected channel serial from 16249 to 16252. The physical
FIFO, transmission and decode execution accounted for the remaining 0.52 ms.
[Original-frame timelines](../../work/packed-latency-20261118/full-tail-segments-1/examples.json)

The [queue-aware policy](../../simulator/src/l2tunnel_sim/packed_backlog_policy.py)
samples the oldest locally queued MUX frame in the retry's direction when
the sender handles a request. At 15 ms or more the sender credits the full
retry size against future regular repairs. At 5 ms or less it returns to
half credit. Between the thresholds it keeps the previous weight. It
preserves MUX admission order, source retention, the silence probe and the
request retry deadlines. These thresholds control the sender's budgeting
decision at a request event and do not impose a maximum per-frame delay.

The forced-loss test holds source zero while its sender switches to full
credit and back to half credit. It also erases sources 129
through 142 and every coded repair. The receiver verifies the exact bytes
of the other 399 frames before the oldest frame arrives, then confirms all
400. [Old-source recovery test](../../simulator/tests/test_packed_latency_policy.py)

| Full C48 first seed, forward bulk application | Original targeted | Fixed half credit | Queue-aware credit |
| --- | ---: | ---: | ---: |
| Goodput in seconds 5–90 (Mbit/s) | 67.86 | 75.41 | 75.99 |
| Application delivery P99 including drain (ms) | 577.73 | 399.55 | 197.19 |
| Mean MUX admission time in slowest 1% (ms) | 325.86 | 276.31 | 9.09 |
| Mean channel-order wait in slowest 1% (ms) | 151.94 | 62.99 | 136.98 |
| Forward wire bytes spent on FEC and retries | 29.21% | 21.45% | 20.79% |
| Forward decoder FIFO drops | 50,286 | 0 | 0 |
| Original segments delivered and acknowledged by 120 s | 1,496,400 | 1,656,671 | 1,664,546 |

With queue-aware credit all 1,664,546 original frames waited at most 16.99 ms
for MUX admission. Median wait was 9.17 ms and P99 was 14.82 ms. Peak forward
MUX occupancy fell from 3,178,422 to 171,088 bytes. At 90 seconds the candidate
still had 1,372 forward and 13 reverse unconfirmed sources and 3,014 inner
unacknowledged TCP segments. All were confirmed by the drain cutoff. Reverse
repair and retry share increased from 10.92% to 12.76%, before counting
short-source copies. Each arm uses the same link seed, but the changed packet
schedule changes which original packets encounter a given erasure.

The candidate's slowest 16,646 originals averaged 210.30 ms. Channel order
accounted for 136.98 ms, propagation for 35.00 ms, time until the solving
transmission for 28.10 ms, MUX admission for 9.09 ms and the decoder FIFO
for 0.94 ms. In the whole cohort, 90,907 segments waited at least 100 ms for
channel order. This remaining wait is visible even after standing MUX queues
clear. These figures describe a calibrated Python simulation with one full
seed. [Full comparison](../../work/packed-latency-20261118/queue-aware-comparison.json)
and [all-original stage distributions](../../work/packed-latency-20261118/queue-aware-full-1/completed-stage-distributions.json)

To repeat the full comparison and export the reference originals, choose
fresh output directories and run

```sh
export PYTHONPATH=simulator/src
python3 simulator/studies/packed_latency_study.py --out work/c48-original-baseline
python3 simulator/studies/packed_latency_study.py --policy queue-aware-repair-budget \
  --stage-distributions --out work/c48-queue-aware
python3 simulator/studies/packed_tail_export.py \
  --archive work/packed-targeted-20261118/fresh-full-r1 --out work/c48-original-tail
```

## Rust implementation of the C48 candidate

The authenticated Packed/Rolling descriptor selects `TargetedExact` (version
5) independently in each direction. Version 4 selects the existing exact
source control. Both use actual source bytes, local GF repairs over 128
sources and every sixteenth regular equation over up to 8192. The candidate
adds an authenticated, lossy request naming specific missing IDs. Each
request round can name up to eight previously observed gaps, including
old gaps beyond the first 32-source bitmap. A 140 ms quiet timer can probe
the oldest unconfirmed original even when the receiver has no evidence of
a later source. Sender custody ends at cumulative confirmation. Solved
packed units may be admitted to their own channel before the cumulative
source prefix advances. That channel still owns record order and compression
context.

The Common sender samples the age of its oldest locally queued MUX frame
when handling authenticated feedback. A requested retry earns half its
accepted wire cost at or below 5 ms, or the full cost at or above 15 ms.
Between those thresholds it keeps the previous tier. The request retains
that tier through output backpressure. Credit is capped at 32 MTUs and can
displace only a complete prospective regular repair. The calculation includes
the selected framing and all fragments. Quiet probes and repeat copies are
accounted separately. The age and work budgets use caller-supplied time.

The paired exporter option `--packed-c48-pair` produces matched control and
candidate descriptors for the four Common carriers. The Linux experiment
selects the authenticated UDP carrier and TUN, with 16 kernel CUBIC flows,
512-byte timed application writes and 76 Mbit/s aggregate offered load.
Kernel TCP segmentation, ACK generation, socket buffering, runtime CPU and
the actual carrier MTU affect the result. The Python 75.99 Mbit/s and
197.19 ms figures above describe the calibrated single-seed simulation.

The protocol regression injects losses of sources 0 and 150 and drops recovery
traffic before confirming all 201 sources. A two-driver UDP test combines an
old gap with a second ordinary channel, reordered authenticated feedback,
output backpressure and a duplicate retry. These tests exercise exact native
delivery and original custody. Standalone Rolling and Research components
retain their existing cohort deadlines. The sliding Rolling scheduler uses
the deadline of the actual oldest retained source on each side, so confirming
one source cannot renew another or expire a younger source prematurely.

### Matched Linux TUN/UDP observation

One release binary ran both arms in owned namespaces on a 100/10 Mbit/s
link with 35 ms delay and 15% netem loss in each direction. Only the two
directional recovery-version bytes differed between descriptors. The test
offered 76 Mbit/s forward over 16 CUBIC flows for 12 seconds, including
2 seconds of warmup. Goodput uses receiver TCP payload bytes in the next
10 seconds. Latency includes all complete 512-byte application records through
drain. Each arm used an independent kernel loss draw.

| Native metric | Exact control | Queue-aware candidate |
| --- | ---: | ---: |
| Case outcome | Expired at source 3916 | Passed |
| Receiver sample goodput | Unqualified, 1,481,176 bytes observed | 27.07 Mbit/s |
| Scheduled / completely written / completely read | Incomplete | 222,657 / 80,503 / 80,503 |
| First attempted write to complete read P99 | Unqualified | 1,048.75 ms |
| Scheduled release to complete read P99 | Unqualified | 8,406.42 ms |
| Unconfirmed immediately after application EOF, forward / reverse | Unqualified | 74 / 7 |
| Unconfirmed at terminal snapshot, forward / reverse | Unqualified | 0 / 0 |

In the candidate, requested retries, silent probes and regular equations
accounted for 23,753,233 / 70,870,762 accepted Common record IP bytes forward
(33.52%) and 632,982 / 4,863,648 reverse (13.01%) over the full session.
These fractions exclude short copies from the numerator and management from
the denominator. The schedule left 142,154 records unsubmitted at the offer
cutoff. Both P99s describe the 80,503 delivered records. The failed control
cannot establish a passing speed ratio. The candidate preserved old-source
recovery in this trial, with a substantial native performance gap against the
calibrated Python workload. This comparison keeps the existing exact version
available. [Build, manifest, commands and per-file source hashes](../../work/packed-native-c48-20261118/matched-3/run.json)
and [native results for both arms](../../work/packed-native-c48-20261118/matched-3/summary.json)

The candidate receiver measured at most 95.74 ms from authenticated input to
decoder admission across 61,847 forward inputs. The sending daemon measured
30,324 per-flow admission stalls with a maximum of 40.37 ms. During 9.69
seconds inside the sample, the receiving daemon used 0.87 logical CPUs in
user space and 0.23 in the kernel. These intervals cover separate operations.
The trial did not correlate individual application records with TCP, MUX,
recovery and channel-order waits, so their contributions to the 1.05 s
end-to-end P99 remain unresolved. [CPU samples and queue measurements](../../work/packed-native-c48-20261118/matched-3/bottlenecks.json)

A separate build isolated the C48 protocol and original-deadline fixes from
the concurrent Rolling decoder and runtime optimizations. Both arms failed.
The candidate read 754 of 5,326 written records and had 1,176 forward sources
unconfirmed at expiry. The receiver observed source 1074 at tick 11,531,456
and admitted it at tick 14,926,679, a 3.395 s wait. The decoder was copying
a retained row while the unresolved prefix was 468. The 27.07 Mbit/s result
above belongs to the integrated worktree. [Isolated build](../../work/packed-native-c48-20261118/checkpoint-pair/run.json)
and [failed case results](../../work/packed-native-c48-20261118/checkpoint-pair/summary.json)

### Reproducing the candidate from the Rust checkpoints

The next checkpoint includes the Rolling receiver and sender work used by
the Packed path: bounded GF operations, copying and scanning only necessary
row contents, cached record lookups, timestamps of original pack admissions,
and immediate service of runnable recovery work. Authenticated inputs enter
an idle decoder directly when the FIFO is empty. A busy FIFO head resumes
when the active decode finishes. These changes also export the actual time
between authenticated arrival and admission. The reproduction uses a fresh
source tree with these changes and the C48 implementation.

| Final scoped binary, same 100/10, 70 ms RTT, 15% loss each way | Exact control | Queue-aware candidate |
| --- | ---: | ---: |
| Outcome | Encoder and decoder custody expired | Passed, hash and EOF on all 16 flows |
| Sample goodput | Unqualified, 1,250,448 bytes observed | 26.53 Mbit/s |
| Application records fully written / fully read | 7,653 / 4,249 | 78,904 / 78,904 |
| First attempted write to complete ordered read P99 | Unqualified | 1,319.39 ms |
| Scheduled release to complete ordered read P99 | Unqualified | 9,062.87 ms |
| Forward / reverse repair, requested retry and quiet probe share | Unqualified | 33.76% / 12.85% |
| Unconfirmed after application EOF, then at shutdown (forward / reverse) | Unqualified | 37 / 2, then 0 / 0 |
| Maximum forward authenticated input residence | 4,343 ms | 93.545 ms |

The candidate recorded no forward decoder admission at or above 100 ms
across 62,576 inputs. It submitted 78,904 of 222,657 scheduled application
records before cutoff. Its longer application P99 includes TCP, recovery and
channel order. Measurements here do not allocate those waits to individual
records. Forward named retries consumed 19,372,673 bytes, regular equations
4,400,410 bytes and one quiet probe 1,311 bytes. Across 320 samples of the
inner TCP sockets, smoothed RTT had median 310.62 ms and P99 473.13 ms.
The old arm expired in both comparisons even with the same lifetime
and decoder changes. The control remains available; the native UDP result
does not qualify the other carriers or establish equivalence with Python.
[Exact build and workload](../../work/packed-native-c48-20261118/hotpath-pair/run.json),
[directional results](../../work/packed-native-c48-20261118/hotpath-pair/summary.json)
and [CPU and queue measurements](../../work/packed-native-c48-20261118/hotpath-pair/bottlenecks.json)

### Scheduling fresh sources during C48 recovery

The selected Rust `TargetedExact` sender can admit up to eight sealed Packed
sources while a carrier output or FEC job is in progress. These slots count
toward the negotiated recovery window. The encoder starts them in order.
A peer can acknowledge only a physically handed-off original. Equations use
the existing encoder window and retain its original bytes until confirmation.
The fresh queue holds the source creation time and copy policy. Its live
depth, high-water mark and capacity are visible in the Common repair budget.

When fresh and recovery work are both ready, the scheduler aims to send two
fresh bytes per recovery byte. It charges full accepted physical outputs,
including fragment overhead and each physical copy. When only one class has
work it can use the whole sender. Regular repair debt can accumulate to two
opportunities. Named retries and regular equations take turns when both are
waiting. If cumulative confirmation stalls for 140 ms, the sender can probe
the oldest retained source even as other channels send. The Python candidate
instead waits for a quiet interval after the latest fresh source.

The Linux comparison used the original MTU, source fragmentation, channel
bindings and authenticated feedback. A separate experiment let a physical
send batch select another output using the remainder of the same epoch's
sender work grant. Its socket regression covered repeated `WouldBlock`,
packet identity, and exhaustion of that grant. Two native runs delivered
26.91 and 25.92 Mbit/s, with first-write-to-read P99 of 1.095 and 1.694 s.
A third run ended before EOF when both peers reached the liveness message
acceptance deadline. Both had submitted the fragment and still awaited
semantic acceptance. This observation does not establish why those
acknowledgments were missing. The selected sender keeps normal per-turn
carrier service. [Experimental patch](../../work/packed-schedule-20261118/batch-final/reproduce.patch)

All runs below used 16 Linux CUBIC flows on the same 100/10 Mbit/s link,
70 ms round-trip delay and 15% independent loss in each direction. The
installed netem did not expose a reproducible loss seed. Goodput covers ten
seconds after warm-up. P99 runs from a record's first attempted write until
its complete application read, including the period after the offer stops.
Repair shares include regular equations, named retries and quiet probes as a
fraction of accepted physical record bytes for that direction.

| Scheduler and run | Forward goodput (Mbit/s) | Application P99 (ms) | Repair share forward / reverse | Unconfirmed forward / reverse at EOF, then teardown |
| --- | ---: | ---: | --- | --- |
| Previous sender, first control | 28.11 | 1,160 | 33.66% / 12.09% | 4/1, then 0/0 |
| Previous sender, second control | 25.53 | 1,218 | 33.96% / 13.01% | 25/14, then 0/1 |
| Selected sender, first run | 30.79 | 906 | 25.66% / 13.77% | 21/1, then 0/1 |
| Selected sender, repeat | Failed before EOF | Incomplete | 25.18% / 11.46% through failure | No EOF, 2,218/22 at last observation |
| Selected sender, separate EOF observation | 24.14 | 9,606 | 25.37% / 12.55% | 2/0, then 0/0 |

The ordinary harness disconnects after EOF. A separate observer polled both
peers after the capture ended and saw two consecutive 0/0 samples. The
failed selected-sender repeat read 23,508 of 27,175 fully written records
before the server's 5 s authenticated liveness challenge expired. Its
source remained unconfirmed. Successful runs validated stream hashes on
all 16 connections. These trials establish cross-channel service and a
lower observed forward repair fraction. A repeatable goodput or tail
latency improvement is still open.
[All nine runs and failure evidence](../../work/packed-schedule-20261118/comparison.json)

In the 9.606 s P99 trial, four receiver TCP sockets account for 483 of the
735 tail records. Their bytes were visible in sequence at the receiver TUN
after a median 3.755 s. Socket samples still placed their stream offsets
beyond the received byte count a median of at least 6.994 s later. The
first covering receiver ACK followed the TUN observation by a median of
7.039 s. The TUN captures passed IPv4 and TCP checksum verification.
The four flows advertised nonzero receive windows. For every one of the
483 records, the first intersecting segment fit within the last observed
advertised right edge. The captures do not identify a kernel drop reason.
Per-record application read timestamps were unavailable to subdivide the
remaining time. [Tail records and socket evidence](../../work/packed-schedule-20261118/fifo-post-eof/receiver-tail.json)
and [receiver-window evidence](../../work/packed-schedule-20261118/fifo-post-eof/tcp-window-trace.json)

### Receiver TCP half-close and the 483-record tail

At the end of the historical forward offer, the receive-only application at B
closed its write half about 4 ms after cutoff while A still had application
data in flight. B's FIN consumed one sequence number. The pure ACK confirming
that FIN reached B ahead of 226 older forward data packets that matched
byte-for-byte at both TUNs. Of these, 223 were first transmissions at A.
The four TCP streams had nonzero receive windows and valid checksums. The
table follows the segment starting at the first blocked application byte.
All times are milliseconds relative to offer cutoff, and offsets exclude
the SYN and the four identity bytes.

| Flow | First blocked stream byte | Old-ACK data at B | Retry with current ACK at B | First covering cumulative ACK from B |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 2,395,120 | 1,549.619 | 9,375.345 | 9,375.373 |
| 8 | 2,438,024 | 1,664.074 | 8,957.738 | 8,957.799 |
| 12 | 2,344,496 | 1,573.833 | 7,746.741 | 7,746.801 |
| 15 | 2,319,360 | 1,637.405 | 7,936.480 | 7,936.557 |

After accepting the FIN acknowledgment, B entered `FIN_WAIT2`. The older
data still acknowledged one byte less than B's new `SND.UNA`. On this
Linux 6.8 path `tcp_ack` returns zero for that old ACK and
`tcp_rcv_state_process` discards the segment before queuing its payload.
Its sequence and payload can therefore look contiguous in tcpdump even
while the receiving socket is missing the bytes. Reconstructing receipt
with this check explains all 483 historical application records. At the
four first holes the cumulative ACK followed the acceptable retry by
28–77 microseconds. The archived trial has no per-packet kernel trace.
[Original four-flow reconstruction](../../work/receiver-gap-20261118/topology/analysis.md),
[full packet match](../../work/receiver-gap-20261118/seq/overtake.json),
[Linux old-ACK handling](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_input.c#L3762-L3775)
and [half-closed state handling](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_input.c#L6280-L6290).

A separate reproduction traced B's inner TCP tuples inside its network
namespace. All 564 first-seen old-ACK data packets observed after the FIN
acknowledgment returned zero from `tcp_ack`. Fourteen started exactly at
`RCV.NXT`. On each flow the receive cursor stayed put until a retry
covering the same starting sequence carried the current ACK. All fourteen
retries were accepted. The four captures passed and the kernel observer
reported zero lost events.
[Kernel and capture evidence](../../work/receiver-gap-20261118/lab/original-r1-cross.json).

The one-way benchmark receiver now waits for the producer's EOF before
calling `shutdown(SHUT_WR)`. An actual application is still free to close
its write half while reading. With independent-short delivery enabled, the
targeted Packed/Rolling receiver remembers a locally admitted TCP FIN and
holds a short returning packet that acknowledges it until the ordinary
record turn on its channel. Unrelated short frames, including ones sharing
that channel, stay eligible for early delivery. Ordered native acceptance
releases the matching FIN entry. The rule covers parsed, unfragmented native
TCP, including TUN IP and supported TAP/VLAN headers. A bounded table falls
back to ordered early ACKs for the affected hash bucket on overflow. Direct
switches between targeted record generations carry the pending entries
through authenticated commit. The change adds no wire bytes.
[Two-peer gap regression](../../crates/l2tunnel/src/rolling_records/fin_order_tests.rs)
and [native TCP tracking](../../crates/l2tunnel/src/rolling_records/fin_order.rs).

#### Independent probe and tunnel changes

The four qualified forward runs used 16 native CUBIC flows, 100/10 Mbit/s,
70 ms RTT, 15% independent loss each way, MTU 1500, a 76 Mbit/s offer of
512-byte records, 2 s warmup and a 10 s sample. All used the same capture
and kernel observers. Each cell has one independent loss realization.
Receiver TUN time is the first capture time at which all stream bytes
through a record are present in sequence. Application time is the first
attempted write through the complete read. The final column counts newly
seen data packets discarded with the old ACK in `FIN_WAIT2`.

| Rust | Receive-only probe | Forward Mbit/s | Application P99 (ms) | In-order TUN to read P99 (ms) | In-order TUN to covering ACK P99 (ms) | Old-ACK drops |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Original | Closes at cutoff | 29.38 | 1,181.47 | 323.960 | 323.88 | 564 |
| Original | Closes after peer EOF | 29.31 | 1,069.40 | 0.150 | 40.52 | 0 |
| Fixed | Closes at cutoff | 30.15 | 1,064.58 | 0.135 | 40.69 | 0 |
| Fixed | Closes after peer EOF | 28.50 | 1,148.46 | 0.155 | 40.40 | 0 |

With the fixed Rust and the original early half-close, 1,095 first-seen
data segments (1,369,568 bytes) were already between the TUNs when B sent
FIN. All arrived before the FIN acknowledgment could overtake them. With
both changes, 84,246 complete records were read. Forward/reverse recovery
used 29.31%/12.92% of accepted physical record bytes. There were 1,538/26
unconfirmed sources at application EOF, then two consecutive bilateral
0/0 observations. All four qualified runs reached bilateral 0/0, validated
the stream hashes, passed all four captures and lost zero BPF events.
In the combined run, first write to in-order receiver TUN alone had P99
1,148.39 ms. The residual end-to-end latency therefore needs investigation
upstream of that observation. These runs establish the effect on TCP
delivery during half-close. They do not establish a throughput improvement.
[Four-arm comparison](../../work/receiver-gap-20261118/lab/comparison.json)
and [combined timing distribution](../../work/receiver-gap-20261118/lab/combined.json).

The focused two-peer regressions also exercise a sequence wrap, data-bearing
FIN, an unrelated short ACK on the blocked channel and bounded table overflow.
In the workspace check, strict Clippy passed. One OpenVPN impairment test
delivered its full payload in both directions and timed out in its own close
handshake. Rerunning that exact test from the same workspace test binary
passed. Its close implementation and the Packed/Rolling receive path are
separate. In the remaining checks the standalone loopback pressure-probe
client exited nonzero once. The same IPv4/IPv6 test passed on a focused
retry. The first run did not expose the client's error details. Both
first-attempt failures remain visible in the logs.
[Aggregate attempt](../../work/receiver-gap-20261118/verification/check.log),
[exact retry](../../work/receiver-gap-20261118/verification/openvpn-workspace-binary-retry.log)
and [remaining checks](../../work/receiver-gap-20261118/verification/check-remaining.log).
[Pressure-probe retry](../../work/receiver-gap-20261118/verification/pressure-retry.log)
and [simulator suite](../../work/receiver-gap-20261118/verification/simulator.log).

### Sender MUX residence and the C48 throughput gap

The matched Python run offers 512-byte records across 16 streams at 76 Mbit/s.
Both implementations use the same two-second warmup, ten-second measurement,
100/10 Mbit/s link, 35 ms one-way delay, and independent 15% loss in each
direction. The selected regular repair rate is 41/200 in both frozen plans.
Python issues one TCP segment per record. Linux CUBIC can combine writes into
MSS-sized segments, which can require two protected source fragments. Linux
also executes both codecs, real authentication, packet I/O and TCP ACKs.
The model's segment-issue clock starts after TCP has a congestion-window slot.
The native first-write clock starts at the application's first attempted write.
The scheduled clock additionally includes backlog at the producer in both tests.
[Matched Python manifests and definitions](../../work/c48-parity-20261119/python/comparison.json).

| Forward experiment | Application Mbit/s | Issue or first-write P99 (ms) | Scheduled P99 (ms) | Unsubmitted records |
| --- | ---: | ---: | ---: | ---: |
| Python seed 1 | 75.94 | 179.44 | 470.52 | 5,375 |
| Python seed 2 | 75.78 | 193.74 | 554.67 | 6,599 |
| Linux after TCP half-close fix | 28.50 | 1,148.46 | 8,602.5 | 138,411 |
| Linux R4 | 40.97 | 561.44 | 5,922.31 | 102,957 |
| Linux R5 | 38.14 | 784.85 | 7,035.74 | 109,381 |
| Linux R6, independent repeat | 48.27 | 543.27 | 5,121.91 | 81,915 |
| Linux R6, profiler enabled at cutoff | 48.81 | 468.82 | 5,855.54 | 81,134 |

R4 and R5 each passed stream hashes, the four captures, and two successive
observations of zero unconfirmed sources at both peers. Other qualified draws
recorded 35.28, 37.25 and 28.65 Mbit/s. The last included a 2.82-second
receiver traffic pause. Its cause remains undetermined. R4 with the same
workload and lighter observation delivered 44.25 Mbit/s. A separate R4
zero-loss control delivered 36.33 Mbit/s. Each control has one draw.
[R4](../../work/c48-parity-20261119/native/candidate-r4/summary.json),
[R5](../../work/c48-parity-20261119/native/candidate-r5/summary.json),
[pause](../../work/c48-parity-20261119/native/candidate-r3/pause.json)
and [zero-loss control](../../work/c48-parity-20261119/native/diagnostic-r4-loss0/summary.json).

R4 removed repeated negotiated-configuration hashing, reduced finite-field
work and empty channel scans, serviced due held ACKs during I/O batches,
and shared the original receive work grant across queued inputs. Under full
lookahead, the receiver now admits units needed by a channel head from a
mixed packed source while retaining the source until all units are accepted.
With MSS explicitly constrained in a diagnostic, the former receiver rejected
the same already-decoded source 70,949 times and exhausted the original debt
deadline. The same 15%-loss diagnostic with R4 delivered 36.91 Mbit/s and
drained both peers. An isolated fragment-packing candidate still encountered
the receiver's original held-ACK deadline in another run.
[Old-gap evidence](../../work/c48-parity-20261119/native/diagnostic-r2-mss512/old-gap-status.json),
[MSS repeat](../../work/c48-parity-20261119/native/diagnostic-r4-mss512/summary.json)
and [ACK failure](../../work/c48-parity-20261119/native/candidate-r4-fragment/diagnostic-failure.json).

Process-scoped markers on channels 0, 4, 8 and 12 distinguish a kernel TUN
capture from a successful device read, MUX enqueue, first codec offer, admission,
and receiver handoff. In the R5 marker run all 47,385 sender TUN packets matched
device reads. The device read P99 was 1.455 ms. On 9,584 measured data packets,
MUX enqueue to first codec offer averaged 131.48 ms with P99 388.10 ms.
The first offer to acceptance averaged 0.294 ms with P99 1.880 ms.
For the 309 traced records in the application tail, MUX residence averaged
148.72 ms. For the 225 records in the tunnel-only tail it averaged 394.61 ms.
No marker events were lost. The markers add overhead, so these values apply
to their own run. R4's lighter application trace measured 0.052 ms average
in-order receiver TUN to read for its slowest one percent.
[Packet and record join](../../work/c48-parity-20261119/native/trace-run-r5-sender/cohort.json),
[queue depth](../../work/c48-parity-20261119/native/trace-run-r5-sender/depth.json),
[per-flow service](../../work/c48-parity-20261119/native/trace-run-r5-sender/mux-service.json)
and [R4 stages](../../work/c48-parity-20261119/native/candidate-r4/stages.json).

R6 groups compatible short fragment tails while full first fragments continue
in their existing scratch space. Replaying 48,043 actual native packets through
the two Rust packers changed the protected source count from 75,400 to 52,283.
Both retained all 82,392 units, consecutive wire unit IDs and the same 1,824
additional physical copies. R6 also reduces flow lookup and unfiltered
weighted-DRR selection work. Both completed Linux runs passed hashes, four
captures and bilateral drain. For the independent repeat, the physical
recovery shares were 21.39% forward and 11.54% reverse. Lifetime sender IP
bytes per application byte were 1.401, versus 1.318 in the two Python runs.
The sender accepted 66.15 Mbit/s in the synchronized 8.06-second status
interval inside the measurement window. The complete trial still left
81,915 of 222,657 scheduled producer opportunities unsubmitted.
[Packing replay](../../work/c48-parity-20261119/recovery/packing-comparison.json),
[R6 repeat](../../work/c48-parity-20261119/native/candidate-r6-repeat/summary.json),
[synchronized wire counters](../../work/c48-parity-20261119/native/candidate-r6-repeat/sample-counters.json)
and [late-profiled repeat](../../work/c48-parity-20261119/native/candidate-r6-late-perf/summary.json).

The first R6 trial failed authenticated liveness during drain. All 139,878
submitted records reached the server, but nine returning TCP FINs had yet to
reach the client TUN. The sender WAN was silent for 5.049 s. An independent
probe's half-second timer also stalled, and 15 server-side Linux FIN timers
then fired within 0.2 ms of one another. Guest scheduling counters showed a
concurrent tick deficit across 28 vCPUs. The guest evidence cannot isolate a
hypervisor cause. Both original five-second challenge caps remained active.
This run does not qualify as a successful performance sample.
[Failed-run timeline](../../work/c48-parity-20261119/native/candidate-r6/terminal-timeline.json).

The sequence-number join on the qualified R6 repeat covers all 140,742
records. For the slowest 1% of observed round trips, forward TUN transit
averaged 427.89 ms, server data to covering ACK 0.15 ms, and reverse ACK
transit 42.64 ms. Median reverse transit was 40.78 ms. The join uses the
first covering cumulative ACK at each capture point and permits the returned
ACK to cover more bytes. These are packet timings rather than Linux RTO
estimates. [Cumulative ACK reconstruction](../../work/c48-parity-20261119/native/candidate-r6-repeat/cumulative-ack.json).

An experimental extra encoder handoff on admission plus inline scheduler
turns (R7) delivered 45.72 and 46.57 Mbit/s. The main path retains the R6
scheduling behavior. R8 isolates runtime-dispatched GF(256) multiply-add
over the existing polynomial and exact per-direction work bounds. The public
encoder's dense 128-source equation fell from 43.53 to 9.27 microseconds in
a same-CPU replay, and its dense 8192-source equation fell from 2.94 to
1.10 ms. R9 also constructs only populated packed receive witnesses and
records separate wall time for ACK service, native collection, management
progress and Rolling computation. R8 and R9 delivered 44.11 and 47.47 Mbit/s
in their completed trials. Each had a separate incomplete attempt at the
receiver's held-ACK deadline. These observations establish an arithmetic
speedup in the isolated encoder and leave whole-tunnel performance
and deadline reliability open.
[R7 experiment](../../work/c48-parity-20261119/native/r7-split/hashes.json),
[encoder reference](../../work/c48-parity-20261119/recovery/encoder-reference-same-cpu.csv),
[encoder with runtime dispatch](../../work/c48-parity-20261119/recovery/encoder-dispatch-repeat.csv),
[R8](../../work/c48-parity-20261119/native/candidate-r8/summary.json)
and [R9](../../work/c48-parity-20261119/native/candidate-r9/summary.json).

Limiting the real Linux TCP payload to 1200 bytes on a separate R8 diagnostic
kept both MTUs at 1500. The 96,255 captured native frames required 96,271
aligned units, compared with 95,258 units for 53,166 frames in the ordinary
R8 run. That diagnostic delivered 49.50 Mbit/s with first-write P99 434.60 ms
and a complete bilateral drain. These trials have different record totals.
The original Linux MTU and unconstrained TCP segment size remain the
acceptance workload. [Diagnostic summary](../../work/c48-parity-20261119/native/diagnostic-r8-mss1200/summary.json).

R9's terminal trace locates one missed ACK service inside a 23.01 ms native
write batch. The original 5 ms service time and 20 ms hard expiry both fell
inside that batch. R10 services the opposite-direction ACK at the existing
clock checks around each native write. A successful write settles its
original physical token first. Two complete four-capture runs delivered
46.83 and 47.06 Mbit/s. First application write to read P99 was 729.30 and
494.14 ms; scheduled issue to read P99 was 6512.44 and 5769.55 ms.
Both reached zero unconfirmed sources in both directions after drain. Each
accepted about 66 Mbit/s at the sender UDP socket during the observed steady
interval, with zero socket drops. The two measurements leave a substantial
gap to the Python 75.78–75.94 Mbit/s application results.
[R10](../../work/c48-parity-20261119/native/candidate-r10/summary.json),
[R10 repeat](../../work/c48-parity-20261119/native/candidate-r10-repeat/summary.json).

The next decoder change records which of 64 physical coefficient blocks
can contain a nonzero value in each working or committed row. All-zero
blocks can be skipped during elimination, normalization and copying. Old
and wrapped rows retain every previously occupied block. For the 2048-row
configuration the two banks reserve an additional 32 KiB in total.
In a matched single-CPU experiment restoring 19 known missing sources, the
local case took 393.35 microseconds (previously 731.81) and needed 53
bounded service calls (previously 125). The global case took 37.39 ms
(previously 40.59) and needed 2223 calls (previously 2273). The benchmark
checks every recovered byte and uses the same work grants in both versions.
[Paired decoder benchmark](../../work/c48-parity-20261119/recovery/rank-block-comparison.json).

With this change, the qualified R11 repeat delivered 50.44 Mbit/s with
475.23 ms first-write P99 and 5119.56 ms scheduled P99. Of 222,657 scheduled
records, 148,922 reached the receiver and 73,735 remained unsubmitted. At
application EOF, 1137 forward and 35 reverse sources still awaited confirmation.
Both peers drained to zero. Physical recovery traffic represented 21.79% of
forward bytes and 12.08% of reverse bytes. A profiled repeat delivered 50.04
Mbit/s. The first trial hit the original held-ACK deadline at the receiver
and is excluded from throughput. A separate trace timed 52,373 receiver TUN
writes and found a maximum of 5.29 ms. It did not reproduce that failed trial.
[Regular repeat](../../work/c48-parity-20261119/native/candidate-r11-repeat/summary.json),
[profile](../../work/c48-parity-20261119/native/candidate-r11-steady-perf/profile.json)
and [failed trial](../../work/c48-parity-20261119/native/candidate-r11/diagnostic-failure.json).

Two sender-only R12 measurements allowed the next data selection to spend the
remaining grant after a complete physical handoff. The active sender used
about 0.86–0.89 CPU cores versus 1.00 for the R11 repeat and accepted
1.29–1.33 packets per turn versus 0.63. The resulting 48.55 and 50.93 Mbit/s
did not establish a throughput increase. The runtime also fences the remaining
grant at the next turn and terminal settlement. The delayed-completion tests
cover the original physical receipt, immutable token, and terminal and
late-error handling. [Sender results and receipt tests](../../work/c48-parity-20261119/native/r12-guarded-overlay/evidence.json).

In a separate R11 receive measurement, 70,600 ordered source handoffs on the
server involved 5,576,638 full parses in ordered and preview handling.
Of 1,540,255 completed previews, 1,470,484 selected no new units. The
targeted receiver now remembers absolute source blocks once a complete
preview proves that every unit already has a receipt. It can skip consecutive
proven bits with one bounded metadata visit. An absent proof, a hole, or a
reused slot with another absolute block number still requires normal processing.
The W8192 cache uses 2048 bytes. The ordered owner retains its original check
of unit sequence, framing and policy. The codec also retains validated
container framing for repeated iteration, and the sender preserves an
immutable serialized source over admission refusals.
[Original parse counts](../../work/c48-parity-20261119/native/candidate-r11-preview-counts/preview-counts.json)
and [sender replay](../../work/c48-parity-20261119/recovery/sealed-source-comparison.json).

The R13 preview experiment includes these codec changes and uses R11 sender
scheduling. Its two regular runs delivered 50.95 and 52.26 Mbit/s, with
first-write P99 of 443.96 and 470.70 ms and scheduled P99 of 4354.28 and
5740.85 ms. All four captures and stream hashes passed in both runs. Both
directions drained every remaining source. The original 75.78–75.94 Mbit/s
Python target remains open.
[First R13 run](../../work/c48-parity-20261119/native/candidate-r13-preview/summary.json)
and [second R13 run](../../work/c48-parity-20261119/native/candidate-r13-preview-repeat/summary.json).

The instrumented repeat counted 643,398 full parses for 72,351 ordered source
handoffs at the receiver, down from 79.0 to 8.9 parses per handoff. Its counter
also recorded 11,997,524 source IDs skipped with an existing proof.
[Receiver counters](../../work/c48-parity-20261119/native/diagnostic-r13-preview-counts/preview-counts.json).

The targeted sender can now offer one fresh source or a requested retry
while an unexposed full-window regular equation is being computed. The
encoder keeps the selected support, original deadline and every unread ring
slot. Physical acceptance of the intervening source restores the pending
equation. The FIFO-to-encoder transfer charges its copy work once, including
when selected using the remainder after a previous physical acceptance.
On a 24,000-source replay, 604 fresh sources became available before their
global equation finished. All 69 global equations matched the independent
scalar oracle byte for byte. A separate run mixed zero, insufficient and
exact copy grants and preserved that result.
[Work grants and repair bytes](../../work/c48-parity-20261119/recovery/global-copy-replay-summary.json).

With a clean release build of this version, two standard four-capture runs
delivered 52.14 and 53.03 Mbit/s. First-write P99 measured 536.00 and
589.32 ms. Scheduled P99 measured 5111.48 and 5566.09 ms. The two runs
left 70,798 and 67,932 scheduled records unsubmitted. Both peers drained to
zero. At EOF the forward/reverse unconfirmed counts were 1468/46 and
1134/81. The receiver's in-order TUN to application read P99 stayed below
0.2 ms in both. Two earlier cached-build runs of the same sources delivered
47.64 and 47.20 Mbit/s. Their binary hash differed. These trials do not
establish a throughput effect for the copy-accounting correction alone.
[Clean run](../../work/c48-parity-20261119/native/candidate-r13-accounting-clean/summary.json)
and [clean repeat](../../work/c48-parity-20261119/native/candidate-r13-accounting-clean-repeat/summary.json).

In a separate Python sensitivity run, both original seeds used the projected
UDP/IPv4, record-number and 16-byte authentication costs on each modeled send.
The new price was applied before loss and to repair scheduling. Forward
regular repairs plus named retries fell from 20.83–20.86% to 18.71–18.76%
of physical bytes. The runs delivered 75.73 and 76.06 Mbit/s, with scheduled
P99 of 634.25 and 609.10 ms. Kernel work, byte-wise coding, actual TCP
segmentation and authenticated management remain outside this sensitivity
model. The original 75.78–75.94 Mbit/s reference remains the acceptance
target. [Both seeds and cost assumptions](../../work/c48-parity-20261119/python/authenticated-udp-sensitivity/comparison.json).

A separate encoder experiment avoided clearing bytes that the new source
immediately overwrites. On the same 23,999 queued source transfers, actual
ring writes fell from 49,201,220 to 20,390,827 bytes and all 69 global
repairs matched the scalar oracle. In the two ordinary native runs this
version delivered 48.64 and 47.23 Mbit/s, and 82,157 and 83,051 scheduled
records remained unsubmitted. A third run of the original clean binary after
the experiment delivered 52.45 Mbit/s and left 68,469 unsubmitted.
The experiment is retained separately. The qualified implementation still
clears the full slot and charges the actual clear plus the length and payload.
[Ring-slot replay](../../work/c48-parity-20261119/recovery/source-surplus-summary.json),
[experiment and tests](../../work/c48-parity-20261119/recovery/source-surplus-with-tests.patch)
and [bracketing run](../../work/c48-parity-20261119/native/bracket-r13-after-r14/summary.json).

The three clean runs had 180.5–193.2 ms median sender TCP RTT across periodic
samples of the 16 application sockets. Over the intervals bounded by those
samples, Linux reported zero peer-receive-window-limited time and
0.019–0.053% of aggregate busy-sending time limited by the local send
buffer. These are TCP socket counters. They do not measure the tunnel's
separate MUX admission delay. [Socket TCP_INFO observations](../../work/c48-parity-20261119/native/tcp-window-limited.json).

One diagnostic followed forward source IDs congruent to 11 modulo 16 from
gap selection through physical output, authentication and decoder publication.
Of 345 repeated IDs in receiver-issued requests, 149 had already arrived
at the receiver with the preceding named retry. For 100, the eventual
successful decoder input matched that exact arrival. Another 33 retries
arrived after the repeat. The observation could not match an arrival for
84 retries and could not match sender receipt of 79 prior requests.
These counts use receiver-issued requests as the denominator. In the same
interval the sender saw 239 repeated IDs among 850 eligible IDs.
Neither auth success nor a possibly dropped wire packet proves that the
receiver retained a complete source. [Native per-source timeline](../../work/c48-parity-20261119/native/diagnostic-r13-named-trace/named-timeline.json).

### Global repair scheduling and small TCP segments

In a 7.75-second interval, the UDP sender spent 1.66 seconds in turns with
queued fresh data, enough tokens for a full MTU, and no UDP handoff. Each such
turn started and ended with the same unfinished global repair and at least two
earned regular repairs. Socket activity cannot show whether the qdisc was
still draining earlier packets. Separately, pre-loss socket bytes divided by
application bytes over matching status intervals were 1.34–1.40 in three
ordinary R13 runs. Filling a 100 Mbit/s link at those exact byte ratios would
yield 71.22–74.57 Mbit/s. The ratios can change with delivery and scheduling.
[Per-turn measurement](../../work/c48-parity-20261119/native/diagnostic-r13-global-turn-v2/global-turn-analysis.json)
and [matched byte costs](../../work/c48-parity-20261119/native/native-byte-efficiency.json).

Suppressing repeated requests for sources in authenticated local input custody
reduced the sender's repeated share of named IDs to 8.25% and 10.61% in two
ordinary R15 runs. Goodput was 49.32 and 49.87 Mbit/s. R16 additionally allowed
up to 64 extra physical copies of fresh data while making field progress on a
global equation, up to one cadence of earned regular debt. Neither an outstanding
named retry nor an oldest-due probe yields to this extra service. The pair
delivered 54.71 and 51.56 Mbit/s with scheduled-to-read P99 of 4.42 and 4.11 s.
Both drained every source. In replay all 69 full global equations matched the
scalar reference. Deferring local work grouped up to five distinct serials on
the same 128-source support. The Python implementation chooses support when an
opportunity is earned. Local support timing and performance parity remain open.
[Native runs](../../work/c48-parity-20261119/native/candidate-r16-lane/summary.json),
[repeat](../../work/c48-parity-20261119/native/candidate-r16-lane-repeat/summary.json)
and [support distribution](../../work/c48-parity-20261119/recovery/r16-bounded-lane/public-replay.json).

One discarded approach prepared 128-source partial sums for a predicted global
repair during otherwise idle turns. Across 292 native global intervals, spare
time before genuine timer wakes could cover only 19 blocks in total after
preserving ready traffic and 100 microseconds of deadline slack. The median
interval had no usable blocks. [Native spare-time measurement](../../work/c48-parity-20261119/native/diagnostic-r13-spare-grants/spare-grant-analysis.json).

The 512-byte application record statistic concealed much smaller TCP data
segments delivered ahead of their own stream. In two R13 measurement windows,
800 and 928 segments of at most 64 payload bytes appeared in order at the sender
TUN and ahead of the contiguous byte frontier at the receiver TUN. Matching
both endpoints by flow, sequence range and payload hash tied 16,156 of 16,278
and 17,575 of 17,694 SACK-bearing ACKs to these segments: the first reported
SACK block exactly equalled one outstanding segment. The P99 time to fill the
earlier bytes was 189 and 211 ms. Both R16 runs reproduced this effect. The
matrix's offline capture summary counts SACK-bearing ACKs and short first
blocks per direction in the original measurement window. The per-flow join
attributes specific blocks to packet reordering between the two TUN devices.
[Two-ended reconstruction](../../work/c48-parity-20261119/native/short-sack-order.json).

A receiver experiment tracked the next contiguous TCP byte per directional
flow at native handoff. Both R18 runs eliminated every observed short-segment
overtake. Across the two 10-second measurement windows, the receiver generated
one SACK-bearing ACK (a DSACK) and zero, respectively. The sender's sampled
TCP retransmission counters advanced by one segment and zero. In R16 the
corresponding deltas were 156 and 259 segments. Median sampled congestion
windows grew from 68/97 segments to 131/129. In the first R18 measurement the
sender TUN carried 98,325 data segments and 9,462 full MSS segments; the first
R16 measurement carried 54,739 and 43,517. The smaller average native payload
raised the packet-processing load. R18 delivered 47.15 and 48.36 Mbit/s,
below both R16 runs. Both completed the stream hash, four-capture and bilateral
drain checks. An additional invocation missed the shared probe start before
the transfer. It provides no goodput measurement.
[First R18 run](../../work/c48-parity-20261119/native/candidate-r18-short-order/summary.json),
[repeat](../../work/c48-parity-20261119/native/candidate-r18-short-order-repeat2/summary.json)
and [kernel TCP counter comparison](../../work/c48-parity-20261119/native/inner-tcp-recovery.json).

### Repair selection and TCP socket admission

Python chooses the support and displacement of a regular repair when the
last copy of a new source earns the opportunity. Deferring that choice to
the Rust encoder's next service turn changed both the support and the named
retry credit available for displacing a regular repair. R19 fixes the support
end, serial and byte price at the final physical source-copy handoff. Field
work remains bounded and interruptible. An independent byte oracle verified
all 1,673 selected equations for 24,000 inputs, including 69 mature globals,
under both full and partial grants. Losing all four copies of an old source
and its first named retry still allowed 148/148 sources to be confirmed.
These are component and owner tests. The two real Linux runs gave 42.49 and
43.00 Mbit/s. Caching early-delivery eligibility in receiver slot metadata
(R20) reduced the 512-entry scan from 5.47 to 1.13 microseconds in replay.
Its two Linux runs gave 44.95 and 40.92 Mbit/s. All four runs drained both
endpoints. Neither change establishes a throughput gain over R13.
[Repair oracle and old-hole tests](../../work/c48-parity-20261119/recovery/regular-earn-overlay/replay-summary.json),
[receiver replay](../../work/c48-parity-20261119/recovery/r20-receiver-slot/public-replay.json)
and [matched native bytes](../../work/c48-parity-20261119/native/matched-byte-cost-r18-r20.json).

Both R19 traces carried 512-byte TCP data segments during the measurement.
For 103,569 complete ranges in the first run, the mean time from sender TUN
to receiver TUN was 152.18 ms. The receiver emitted a cumulative ACK
covering the range after another 0.044 ms on average. The first covering
ACK reached the sender TUN 40.03 ms later. The repeat gave 149.86, 0.045
and 40.34 ms respectively. Sequence numbers, payload hashes and cumulative
ACKs match across both endpoints. A separate socket observation measured
125 unacknowledged segments per stream at the median. Holding 125 segments
per stream for 191 ms would sustain about 42.9 Mbit/s across 16 streams.
[First cumulative ACK trace](../../work/c48-parity-20261119/native/candidate-r19-earn/cumulative-ack.json)
and [repeat](../../work/c48-parity-20261119/native/candidate-r19-earn-repeat/cumulative-ack.json).

The native probe requested 128 KiB of Linux send and receive buffer space
per socket and read back 256 KiB. The measured Linux sender accounted 1,408
bytes per 512-byte segment in the original geometry. Across 160 flow-seconds,
the original socket diagnostic found 147.97 flow-seconds with an overdue
offer and no write readiness. In 97.1% of that time, queued socket memory
exceeded the Linux stream writeability threshold. The median was 176,000
socket-memory bytes, 64,000 queued payload bytes and zero unsent bytes.
The kernel TCP transmission counter for send-buffer-limited time measures a
different event from application write readiness. The Python producer counts
512 outstanding *payload records* per flow at this setting, or 262,144 bytes.
[Socket and readiness evidence](../../work/c48-parity-20261119/native/diagnostic-r19-socket-memory/send-readiness.json).

| Forward experiment | Goodput (Mbit/s) | Issue or first write to read P99 (ms) | Scheduled to read P99 (ms) | Unsubmitted |
| --- | ---: | ---: | ---: | ---: |
| Python original, two seeds | 75.94 / 75.78 | 179 / 194 | 471 / 555 | 5,375 / 6,599 |
| Python authenticated UDP prices, same seeds | 75.73 / 76.06 | 265 / 269 | 634 / 609 | 6,767 / 6,232 |
| Python same prices, observed 125-record admission cap | 50.01 / 49.31 | 179 / 183 | 4,241 / 4,304 | 77,954 / 78,584 |
| Linux R13, strict payload credit and timed recheck | 51.93 / 56.37 | 1,114 / 997 | 6,219 / 6,147 | 69,176 / 57,090 |
| Linux R19, original sockets | 42.49 / 43.00 | 273 / 264 | 5,302 / 5,197 | 95,930 / 94,053 |
| Linux R19, strict payload credit and timed recheck | 64.09 / 66.96 | 898 / 757 | 3,477 / 2,860 | 34,236 / 25,458 |

Increasing only the native sender socket budget raised goodput to 62.18
Mbit/s in a single diagnostic but let outstanding payload exceed 262,144
bytes per stream for 149.18 out of 160 flow-seconds. For the strict-credit
pair, the producer instead checked actual queued payload including unsent
bytes before every write, enforced the 262,144-byte limit, and rechecked
only the affected flow on a timer. The unchanged ten-second goodput window,
completed-record latency cohort, stream hashes and final bilateral drain
apply to both runs. The original C48 acceptance comparison remains open.
[Python admission sensitivity](../../work/c48-parity-20261119/python/native-admission-sensitivity/comparison.json),
[native socket-only control](../../work/c48-parity-20261119/native/diagnostic-r19-socket-544k/send-readiness.json),
[strict-credit measurement](../../work/c48-parity-20261119/native/diagnostic-r19-credit-wait/summary.json)
and [repeat](../../work/c48-parity-20261119/native/diagnostic-r19-credit-wait-repeat/summary.json).

The R13 strict-credit pair used its original clean release binary and the
same socket probe, observer and manifest hashes as the R19 strict-credit pair.
R13 left 1,370/10 and 747/52 forward/reverse sources outstanding at EOF.
Both runs passed all four captures and drained to 0/0. In these four draws,
R19 delivered more with matched payload credit even though R13 had delivered
more with the original socket settings.
[Strict-credit R13 run](../../work/c48-parity-20261119/native/diagnostic-r13-credit-wait/summary.json)
and [repeat](../../work/c48-parity-20261119/native/diagnostic-r13-credit-wait-repeat/summary.json).

The strict-credit experiments also distinguished TCP receive-window pressure
from tunnel efficiency. Increasing only the receiving TCP sockets' buffer
made the advertised window cover 262,144 bytes throughout both samples.
Throughput fell to 61.55 and 58.91 Mbit/s. CUBIC reached its congestion
window for 77.5% and 76.4% of flow-time, and first-write P99 was 775 and
890 ms. Receivers refused more authenticated inputs at their bounded decoder
queue. In the original strict-credit pair, the pre-loss forward IP cost was
1.387 and 1.372 bytes per delivered payload byte over matching eight-second
intervals. At those byte ratios, fully using 100 Mbit/s would yield 72.1
and 72.9 Mbit/s. Reaching 75.78 Mbit/s requires lowering that ratio to
about 1.320 as well as keeping the forward link busy.
[Window and kernel evidence](../../work/c48-parity-20261119/native/peer-window-semantics-r19.json)
and [pre-loss byte counters](../../work/c48-parity-20261119/native/peer-window-wire-matched-r19.json).

An isolated single-thread encoder reused GF products across consecutive global
repairs. All 1,673 tested equations remained byte-exact. The median time per
pair fell from 1,272 to 1,066 microseconds, but the first equation required
90 service grants instead of 85 and its median rose from 631 to 958 microseconds.
The original encoder remains in the runtime while the cost of delaying that
first repair is unresolved. [Paired encoder replay](../../work/c48-parity-20261119/recovery/r21-paired/summary.json).

### Which TCP byte holds up the next read

One original-socket R19 run with sparse markers delivered 42.47 Mbit/s.
The two TUN captures and both applications matched TCP payloads by flow,
sequence range and hash. The 2,008 matched application records covered
all 16 flows. Their last required native segment took a mean of 151.21 ms
between TUN devices. Its sender MUX residence averaged 8.59 ms and the
sealed source waited 0.75 ms for physical UDP acceptance. At the receiver,
the datagram that made the source solvable spent 14.10 ms awaiting decoder
admission, the transaction took 0.12 ms and exposing the solved unit to
the record receiver took 10.74 ms. The complete record then waited 65.88 ms
for native preparation. Of that last interval, 65.73 ms overlapped a missing
preceding TCP byte on the same flow. Once the preceding byte reached the
receiver TUN, preparation followed in 0.16 ms on average (P99 0.61 ms).
The marker run's first-write P99 was 398.63 ms. The two uninstrumented
runs had 272.52 and 264.26 ms.

Among the 2,002 records whose preceding records could all be indexed,
1,826 depended on a named retry for their latest preceding source. In
457 cases the retry carried that exact source. In 1,369 cases receiving
a different requested original completed an existing equation and recovered
the blocking source. These samples share dependencies and represent 1,532
distinct blocking sources. The time from the blocking source's first
send to the successful retransmission's send averaged 101.64 ms in the
1,826 retry-dependent cases. In the remaining 176 cases, 84 depended on
a repair datagram and 92 on the first original.

An optimistic replay retained the observed loss dependencies and original
source transmissions. It assumed an immediate request upon the first evidence
of a gap, a successful first retransmission, exactly 35 ms for each trip
and zero receiver CPU or delivery time. Even under those assumptions the
mean forward delay was at least 97.60 ms for this cohort. Adding the observed
40 ms return ACK path gives about 138 ms. With 16 streams each holding
125 segments of 512 bytes, 75.78 Mbit/s would require a mean ACK cycle
of about 108 ms. These figures bound this specific replay. Earlier proactive
recovery or a change in the effective TCP flight would change its assumptions.
[Native run](../../work/c48-parity-20261119/native/diagnostic-r19-source-stages/summary.json),
[matched stage and dependency results](../../work/c48-parity-20261119/recovery/r19-stage/result.json)
and [sampled source and frame identities](../../work/c48-parity-20261119/recovery/r19-stage/samples.json).

With the same marker binary and the strict 262,144-byte per-flow credit,
Linux delivered 65.00 Mbit/s. All four captures passed. At EOF 2,523/23
sources were outstanding; both peers drained to zero. For 3,019 sampled
application completions across all 16 flows, mean sender MUX residence rose
to 89.06 ms (P99 200.96 ms). Mean receiver decoder admission fell to 4.90 ms
and the decoder transaction averaged 0.08 ms. Once the enclosing record
was complete, an earlier byte in the same stream held it for another
86.06 ms on average. In 2,936 of 2,984 completions with a complete
predecessor index, a named retry supplied the last missing information.
This observed cohort has different segmentation and admission pressure
from the 125-segment socket sample.
[Strict-credit marker run](../../work/c48-parity-20261119/native/diagnostic-r19-strict-credit-stages/summary.json)
and [matched source and frame stages](../../work/c48-parity-20261119/recovery/r19-strict-stage/result.json).

In the two strict-credit runs without these markers, the P99 from the last
required sender TUN byte to application read was 459.29 and 413.96 ms.
Ranking the completed application records by first write to read selected
1,885 and 1,972 records in the slowest percent. They spent an average of
879.03 and 569.04 ms from first write until the last required byte appeared
on the sender TUN, then 167.36 and 253.74 ms between TUN devices. After the
contiguous receiver bytes arrived, the read took 0.05 and 0.06 ms on average.
[Completed-record reconstruction](../../work/c48-parity-20261119/native/diagnostic-r19-credit-wait/stages.json)
and [repeat](../../work/c48-parity-20261119/native/diagnostic-r19-credit-wait-repeat/stages.json).

In the original-socket marker run, four missing sources (58820, 58825,
58827 and 58840) were already due for a request before repair 7024 entered
a 19.17 ms receiver job. A separate receiver candidate spent a bounded part
of the original work grant on an already discovered gap before servicing a
wide repair. It retained the existing timers, authentication, repeat limits
and decoder budget. A replay used the captured identifiers and 8,019
measured source lengths, assigning the observed median length to the other
173 sources. The authenticated request was available in grant one instead
of grant 130, 15.85 ms earlier on the replay clock. Both variants completed
the same equation in grant 130. The historical capture did not record
each service grant or the exact contents of the encrypted response.
[Reproduction and reviewed patch](../../work/c48-parity-20261119/recovery/r22-gap/receipt.json).

The native evidence does not qualify this candidate. Its first build twice
entered the original-socket lab. One trial stopped at the held TCP ACK
deadline. The other completed at 36.08 Mbit/s with a first-write P99 of
2,498 ms and a final bilateral 0/0. The slowest 990 records in that run
all originated between 2.072 and 2.540 seconds after workload start, during
a period of major page faults and reduced CPU service at both endpoints.
In a subsequent adjacent pair the original R19 passed at 44.84 Mbit/s.
The reviewed build missed the same 20 ms hard ACK deadline while the
server was servicing Rolling work. Its four captures passed; the workload
did not reach completion. The original deadline remains in force.
[Initial trials and fault evidence](../../work/c48-parity-20261119/native/r22-offline/outcomes.json),
[adjacent control](../../work/c48-parity-20261119/native/control-r19-before-reviewed/summary.json)
and [reviewed trial](../../work/c48-parity-20261119/native/candidate-r22-reviewed/summary.json).

The native C48 planner also reserves 200 bytes of the MTU for worst-case
framing. Replaying the two strict-credit captures with the actual Rust
codec at the current planner's 1,313-byte safe symbol limit instead of
1,251 bytes saved 0.223 and 0.248 Mbit/s of source and prescribed-copy
wire bytes. Most 1,448-byte Linux TCP payloads still needed two fragments.
On the original all-512-byte R19 trace the ten-second saving was 201 bytes.
This replay fixes the input sequence and measures encoding costs. It does
not reproduce feedback, CPU scheduling or new loss draws.
[Offline geometry and per-direction byte costs](../../work/c48-parity-20261119/native/compact-geometry/summary.json).

The first two strict-credit captures also separate framing cost from a
changing volume in flight. Within the matched roughly eight-second status
windows, data already seen at the sender TUN but still unread at the receiver
grew by 883,888 and 633,592 bytes. This accounts for 0.01390 and 0.00941
bytes per application byte in the interval. Fixed IPv4/UDP and authentication
headers on fresh packets cost about 0.0475 bytes per application byte in
Linux and 0.0483 in the priced Python runs. Inner compressed headers,
fragment and unit framing, packed identities and length tables together
cost about 0.030 in Linux and 0.016 in Python. An optimistic packing bound
retaining the current symbol size, unit cap, flush deadline and copy classes
could save at most 0.46 and 0.49 Mbit/s of fresh wire traffic in those
windows. Keeping source order and allowing the existing 500-microsecond
flush allowance merged just three adjacent pairs in each replay and saved
156 bytes each. The real inner TCP/IP headers averaged 52 bytes. After
the current body codec their incremental cost averaged 11.94 and 12.11
bytes. [Capture byte accounting and packing bound](../../work/c48-parity-20261119/native/fresh-attribution/breakdown.json)
and [source-order replay](../../work/c48-parity-20261119/native/fresh-attribution/adjacent.json).

### Sending originals during a mature global repair

The strict-credit trace established a lower bound of 0.713 s in the ten-second
sample with queued MUX traffic and unused sender service at the configured
100 Mbit/s rate while the same global equation was running. This calculation
charges the MTU for unidentified data lengths and subtracts all feedback and
management bytes for the entire process. For at least 0.462 s fresh sources
were continuously available. For at least 0.112 s the existing allowance of
64 extra physical copies had also been exhausted. The calculation uses the
sender's actual UDP handoffs. It cannot timestamp physical NIC departures.

The R23 sender let progress on the active global earn an extra physical copy
per 65,536 actual GF byte operations. It preserved earned repair identities,
support, byte credit, the cap of 16 owed equations and the original deadlines.
In a 24,000-source replay, 1,673 equations matched a separate scalar oracle
and both senders consumed 33,836,413 simulated IP bytes. The longest period
with no output fell from 5.28 to 0.48 ms. The first mature global was emitted
in grant 7,318 for both, and completion moved from 3.464 to 3.331 seconds.
A separate real sender/receiver test lost all four original copies and the
first named retry of one source. The oldest-source probe recovered it, and
all 9,000 sources were delivered and confirmed. [Replay, bounds and byte
accounting](../../work/c48-parity-20261119/recovery/r19-strict-sender/r23-receipt.json)
and [focused Rust regression](../../work/c48-parity-20261119/recovery/r19-strict-sender/r23-focus.log).

The frozen R23 release differed from R19 only in the sender scheduler.
All four native runs verified the 16 payload hashes, both endpoint and WAN
captures, and two consecutive bilateral zero confirmations. Goodput uses
the ten-second measurement. Latency uses all completed application records.
Recovery counts named retries, regular equations and oldest-source probes
as a share of lifetime pre-loss IP bytes, excluding extra short copies.

| R23 socket setting | Forward Mbit/s | First write to read P99 (ms) | Scheduled to read P99 (ms) | Unsubmitted | Forward / reverse recovery (%) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original, first draw | 42.85 | 332 | 5,328 | 94,784 | 22.31 / 12.24 |
| Original, repeat | 47.96 | 478 | 4,538 | 81,632 | 21.75 / 12.61 |
| Strict payload credit, first draw | 63.86 | 798 | 3,543 | 31,816 | 19.39 / 12.47 |
| Strict payload credit, repeat | 65.44 | 782 | 3,126 | 32,370 | 19.46 / 12.58 |

With strict credit, R19 delivered 64.09 and 66.96 Mbit/s. The offline
reduction in sender silence did not produce a repeatable throughput or
latency improvement in the four native draws. The two strict-credit runs
also recorded wall/monotonic clock calibration brackets of 0.601 and
0.676 ms. Matching packet and probe timestamps produced 366 and 3,000
negative first-write-to-TUN intervals below the 20-microsecond join
tolerance. The most negative intervals (0.297 and 0.333 ms in magnitude)
were within half the respective bracket. The latency figures in the table
use only the common monotonic application clock. [Four-cell native evidence
and timing precision](../../work/c48-parity-20261119/native/r23-four-cell.json).

### An eight-source repair at two TCP flight limits

A Python sensitivity run sent one additional forward equation for each group
of eight new sources when the sender had earned enough bytes. It kept C48's
ordinary local and global repairs, named retries and oldest-source recovery.
Each new equation occupied the same serializer and lossy link and consumed
receiver work. All rows below use 100/10 Mbit/s, 70 ms RTT and 15% loss per
direction, with the projected authenticated UDP prices. The first two arms
at each flight limit use both archived seeds. The local-credit arm uses seed
one. Every arm drained all submitted data and both source frontiers.

| Maximum in flight per TCP flow | Repair policy | Forward goodput (Mbit/s) | Issue to read P99 (ms) | Scheduled to read P99 (ms) |
| ---: | --- | ---: | ---: | ---: |
| 125 | C48 | 50.01 / 49.31 | 179 / 183 | 4,241 / 4,304 |
| 125 | Additional eight-source repair | 69.82 / 70.31 | 87 / 83 | 1,170 / 1,082 |
| 512 | C48 | 75.73 / 76.06 | 265 / 269 | 634 / 609 |
| 512 | Additional eight-source repair | 70.40 / 70.33 | 442 / 443 | 1,112 / 1,105 |

With 125 records per flow the baseline used about 68 Mbit/s on the forward
link. The additional equation brought forward recovery from about 21.5%
to 24.8% of IP bytes while increasing application throughput. At 512 the
link was already full. Forward recovery rose from about 18.7% to 24.8%.
The sender's instantaneous 1 ms queue check skipped at most one of about
ten thousand opportunities in each run, including the saturated runs.
The new rows used a rank model and a source payload ledger. The price of
an additional row in the two-seed tests omitted its two coded length bytes.
[Small flight results](../../work/c48-parity-20261119/python/near8/comparison-125.json)
and [original flight results](../../work/c48-parity-20261119/python/near8/comparison-512.json).

Charging those two bytes and letting the new equations displace up to half
of the otherwise eligible 128-source local repairs produced 58.31 Mbit/s
at 125 and 73.44 Mbit/s at 512. All periodic global slots were preserved.
Named retry traffic rebounded from 2.10 to 6.75 MB and from 1.90 to
9.50 MB respectively in the two ten-second comparisons with the additional
repair arm. These research configurations leave the original C48 acceptance
comparison open. [Local-credit rules and byte totals](../../work/c48-parity-20261119/python/near8-shared/comparison.json)
and [independent length oracle](../../work/c48-parity-20261119/python/near8-shared/canonical-oracle.json).


## Negotiated eight-source forward repair

The forward descriptor selects `TargetedNear8` (wire version 6) and the reverse
descriptor selects `TargetedExact` (version 5). The C48 experiment keeps
8192 global and 128 local sources, every sixteenth regular equation global,
named retransmission, silent-oldest probing and short-record copies. Both
directions retain their original authentication and management paths. A peer
with only the old descriptor rejects the new selection. The plan generator
accepts `--packed-c48-near8` separately from `--packed-c48-pair`. Raw TCP,
maintained TLS/QUIC and the separate OpenVPN carrier lack the all-traffic
socket receipt used here and cannot select the new option.

A group covers eight consecutive first transmissions. Each complete authenticated
IP first-copy receipt earns one eighth of its actual bytes, up to one MTU of
credit. One row costs the outer IP/UDP and Records bytes (49 in the IPv4
ChaCha20-Poly1305 test), one tag byte, a canonical unsigned LEB128 exclusive
group end, and two coded original-length bytes plus the longest original's
payload extent. End 8 and end 128 use one and two index bytes respectively.
The receiver uses its own retained equations, lengths and source bytes. Separate
duplicate history keeps a coincident regular serial and group number distinct.

The sender starts with forward repair disabled. Four consecutive complete,
nonempty 100 ms intervals at or below 75% of the configured local IP rate
with ordinary backlog within eight MTUs enable repair. An empty or skipped
interval, utilization at or above 90%, or excess ordinary backlog at the
boundary closes the gate. The same eight-MTU threshold applies at group selection. Its ordinary backlog
combines native MUX custody, unconsumed packing bytes, untransmitted originals
and whole ordinary IP packets awaiting the end of local virtual serialization.
The local model charges every accepted IP packet at the configured rate. It does not observe the kernel or ISP queue.
Fresh data, named retransmission and ordinary earned repair retain priority.
The optional sender has a bounded work grant, original expiry and physical
handoff. It records gate skips, insufficient credit, oversize and abandoned
opportunities separately from accepted rows and IP bytes.

In the frozen Python study, the 125-segment window went from 50.01 to 52.68
and 49.31 to 50.74 Mbit/s on seeds 1 and 2. First-write P99 changed from
178.6 to 168.9 and 183.0 to 168.3 ms. The sample sent 392 and 110 additional
rows. At 512 segments the two sample windows emitted zero additional rows.
Warmup did emit rows, changing the simulated loss draws. Throughput changed
from 75.73 to 76.05 and 76.06 to 75.82 Mbit/s. All runs drained both directions
and inner TCP. The model uses sender-source and rank bookkeeping for receiver
recovery and a calibrated service curve. Rust reconstructs the application bytes
from received data and equations. [Python results and byte accounting](../../work/c48-parity-20261119/python/near8-spare-mux/comparison.json).


The initial Linux integration sampled ordinary and serializer backlog separately.
Two counterbalanced original-socket pairs delivered 47.78/44.62 Mbit/s on v5
and 46.94/44.28 on v6. The strict admission pairs delivered 61.75/66.08 on
v5 and 65.27/63.40 on v6. Both strict v6 measurement windows sent zero extra
rows. Regular repair, retry and extra-copy bytes were counted independently.
The four captures for each run reported no capture drops, all TCP stream hashes
matched, and each run recorded two consecutive zero-unconfirmed observations
in both directions. These measurements characterize the first implementation;
the matched gate uses the combined ordinary queue at both decision points.
[Initial eight cells](../../work/c48-parity-20261119/native/near8-v6-20261119/eight-cells.json).

### Combined backlog gate on Linux UDP

The matched gate was tested with 16 Linux TCP connections, 512-byte writes,
76 Mbit/s aggregate offered load, 100/10 Mbit/s link rates, 70 ms RTT and 15%
independent loss in each direction. Each cell used the same release executable.
The strict socket setting capped unacknowledged payload at 512 writes per flow.
The ordinary socket used Linux's effective flight. Delivered goodput covers
ten seconds after two seconds of warmup. Both latency percentiles include
records completed during drain. Their clocks start at the first successful
application write or at the scheduled offer, respectively.

| Initial attempt | Delivered Mbit/s | First-write P99, ms | Scheduled P99, ms | Forward / reverse recovery IP bytes, % | Unsubmitted at cutoff |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ordinary v5 | 40.52 | 490.91 | 5,720.46 | 23.20 / 12.74 | 100,824 |
| Ordinary v6 | 44.97 | 322.16 | 5,064.10 | 21.63 / 13.22 | 87,406 |
| Strict 512 v5 | 63.38 | 781.52 | 3,170.88 | 19.66 / 12.57 | 33,521 |
| Strict 512 v6 | Failed during warmup | — | — | — | — |

Recovery includes ordinary repair, named retransmission, oldest-source probes
and eight-source rows, measured between status snapshots inside the sample.
All three completed cells verified the 16 stream hashes and twice observed
zero unconfirmed sources in both directions. Ordinary v6 emitted 11 rows
costing 12,144 IP bytes. These were 0.020% of forward IP bytes in the inner
8.12-second observation interval. This one pair does not establish a repeatable
throughput gain. The strict v6 server held one original 52-byte ACK. Its 5 ms
flush point and 20 ms hard deadline both passed within a 16.716 ms rolling
service interval. The coalescer reported zero refusals. The two extra rows
(376 IP bytes) preceded the measurement window. That attempt ended before any
qualifying throughput, latency or drain measurement. The service timestamps do
not separate CPU execution from time spent descheduled.
[Four-cell results and captures](../../work/c48-parity-20261119/native/near8-mux-gate-20261119/four-cells.json).

One independent repeat of the failed strict v6 cell with the same binary
delivered 66.27 Mbit/s, with 733.54 ms first-write P99 and 2,513.44 ms
scheduled P99. At cutoff 28,618 writes were unsubmitted. Forward and reverse
recovery shares were 19.01% and 12.65%. Unconfirmed sources fell from 1,385/0
at EOF to 0/0 at two consecutive observations. The ten-second window emitted
zero eight-source rows. All 80 complete status buckets had ordinary backlog,
and all 8,022 group opportunities in that interval were gated. The original
failed attempt is counted alongside this repeat. The 512-write Python result
remains outstanding on Linux.
[Independent strict v6 repeat](../../work/c48-parity-20261119/native/near8-mux-gate-strict-repeat-20261119/strict-repeat.json).

On the first strict v5 control, all 16 flows were simultaneously held at their
sender payload credit for 4.515 seconds of the ten-second sample. Summing across
flows gives 139.856 out of 160 flow-seconds. In approximately 5 ms TCP samples,
77.3% of flow-time had a due write and was within one MSS of the advertised
window. These intervals can overlap. The local forward UDP socket accepted IP
at 86.17 Mbit/s between seconds 1.634 and 9.629 of the sample. Both Python
seeds spent about 100 Mbit/s over their full ten seconds. The native forward
recovery share was 19.66%, compared with 18.71–18.76% in the model. The traces
establish underutilization and simultaneous credit stalls. They do not isolate
how much of either is attributable to each queue or ACK delay.
[Per-flow intervals, accounting and source hashes](../../work/c48-parity-20261119/native/near8-mux-gate-20261119/strict-credit-accounting.json).

### Servicing a held ACK during a rolling decode

During the failed strict v6 warmup, the server entered rolling service 1.682 ms
before the ACK's 5 ms flush point and stopped 35 µs after its hard deadline.
The unfinished regular equation numbered 592 covered sources `[0, 3176)`.
Its own deadline was almost five seconds away. The driver now gives an active
targeted decoder up to eight slices of its existing receive allowance while a
local ACK is held. Between slices it reads the injected runtime clock and
services due ACKs through normal MUX admission. An existing feedback record
awaiting physical transmission keeps its original receipt identity. Newly
prepared feedback can yield the remainder of the turn. The sender still gets
one turn per epoch, and both directional work limits remain in force.

The deterministic regression exercises the previous unsliced turn, a checkpoint
before the soft deadline with pending feedback, admission at the soft deadline
and rejection at the hard deadline. A thread that receives no CPU service for
the full hold interval can still miss its deadline.

The checkpoint release delivered 60.45 Mbit/s on strict v5, with first-write
P99 of 901.69 ms and scheduled P99 of 4,007.19 ms. At cutoff 44,308 writes
remained unsubmitted. Recovery IP shares were 20.00% forward and 12.31%
reverse. The 16 streams matched and the endpoints drained from 1,491/1 at EOF
to 0/0 twice. Strict v6 stopped in warmup. Three reverse ACKs (156 bytes) were
held. Server buffer sampling ran from 8.470586 to 8.496010 seconds and
finished 24.440 ms after the earliest soft deadline and 9.440 ms after its hard deadline.
The driver stopped at 8.496013 seconds. The terminal sample had no active
decoder job. Six other attempts had peak server buffer sampling intervals of
0.372–1.244 ms. The 25.424 ms outlier is measured wall time for the aggregate
sampling stage. The recorded timer cannot apportion it among sampler calls.
The focused decoder regression passes. Strict v6 stability and application
performance parity remain open.
[Pair results](../../work/c48-parity-20261119/native/near8-ack-feedback-edge-20261119/checkpoint-pair.json),
[server clocks](../../work/c48-parity-20261119/native/near8-ack-feedback-edge-20261119/failed-held-ack.json)
and [stage maxima for all seven attempts](../../work/c48-parity-20261119/native/near8-ack-feedback-edge-20261119/stage-maxima-by-attempt.json).

The Aligned and Packed receiver now uses its retention ledger to count proofs,
actual proof bytes, records and fragments. It classifies head records using one
indexed lookup per channel. Compact proofs can have different lengths. Their
exact byte totals follow insertion, release and transaction rollback. The older
capacity scan is retained as a test oracle. On one pinned EPYC 7B12 core, an
optimized build with 1,198 occupied proof slots out of 16,384 and 650 records
out of 1,040 reduced median time per snapshot from 15.166 to 0.402 µs across
eight alternating batches of 4,096 calls. The timer covers the receiver query.
The Linux driver times a broader sampling stage. The microbenchmark does not
attribute the earlier 25.424 ms wall interval to this query.
[Oracle and microbenchmark measurements](../../work/c48-parity-20261119/native/near8-ack-feedback-edge-20261119/buffer-snapshot-indexed-micro.json).

One strict v6 run on the indexed-snapshot release delivered 63.41 Mbit/s.
First-write P99 was 767.45 ms, scheduled P99 was 2,832.47 ms, and 38,159
scheduled writes remained unsubmitted at cutoff. Forward and reverse recovery
IP shares were 20.15% and 12.26%. All 16 streams verified, four captures had
zero capture drops, and both endpoints had zero unconfirmed sources at EOF
and in both final observations. The gate declined all 7,618 opportunities in
the inner status interval. No eight-source repair was sent in the ten-second
sample. The maximum server buffer-sampling interval was 167 µs across 265,721
observations in this run. Stable deadline service across runs and throughput
parity with either 512-write Python seed remain open. The corresponding two
v6 model runs delivered 76.05 and 75.82 Mbit/s. Their first-write P99s were
272.2 and 248.0 ms, their scheduled P99s were 612.9 and 580.8 ms, and their
unsubmitted write counts were 6,249 and 6,147.
[Indexed-snapshot Linux run](../../work/c48-parity-20261119/native/near8-snapshot-ledger-20261119/strict-v6.json)
and [per-endpoint sampling times](../../work/c48-parity-20261119/native/near8-snapshot-ledger-20261119/buffer-sampling.json).

In that final ten-second run all 16 writers were simultaneously held at the
configured outstanding-payload cap for 5.569 seconds. The sum was 147.827
out of 160 flow-seconds. In the inner 8.053-second status span, the forward
UDP socket accepted 87.02 Mbit/s, with 20.15% in recovery. The two v6 Python
seeds spent approximately 100 Mbit/s over their full ten seconds, with 18.75%
and 18.77% in recovery. The data establish delayed credit release and lower
use of the configured forward link. The individual contributions of forward
recovery and reverse cumulative ACK transit remain unresolved.
[Final v6 credit intervals and byte totals](../../work/c48-parity-20261119/native/near8-snapshot-ledger-20261119/v6-credit-accounting.json).

A PID-scoped user CPU profile on the pre-indexed release recorded 4,287 server
samples. Four hit `Receiver::buffer_snapshot` under `sample_protocol_buffers`.
Their owner ticks were outside that run's 1.838 ms peak sampling interval.
The 25.424 ms stall did not recur in the profiled run. These samples verify
that the scan executed and leave the cause of the historical outlier open.
The profiled transfer delivered 63.47 Mbit/s with 870.31 ms first-write P99
and 3,618.47 ms scheduled P99. It verified bilateral drain. This diagnostic
uses the earlier executable with profiling active.
[Sampled call sites and owner ticks](../../work/c48-parity-20261119/native/near8-buffer-sample-perf-20261119/receiver-scan-ticks.json)
and [profiled run](../../work/c48-parity-20261119/native/near8-buffer-sample-perf-20261119/profile-summary.json).

### Single TCP connection and outstanding payload credit

The forward target is 80 Mbit/s of unique application payload on one inner TCP
connection. The sixteen-flow comparison above measures aggregate service. The
single-flow credit experiment used one identified TCP connection, one producer,
one receiver, the existing C48 v6/v5 Linux TUN/UDP binary, 512-byte application
writes, a two-second warmup and a ten-second measurement. The link was 100/10
Mbit/s with 70 ms propagation RTT and independent 15% loss in both directions.
The probe set its socket buffers before the handshake so TCP could negotiate
window scaling. The same socket buffer sizes were used for every credit setting.

The probe's outstanding-payload cap counts bytes written to the socket that
have yet to receive a cumulative TCP ACK, including unsent bytes. The TCP
congestion window and peer advertised window independently limit transmission.
At the propagation RTT alone, 256 KiB permits about 29.96 Mbit/s of sustained
single-flow throughput. An application rate of 80 Mbit/s requires at least
700,000 bytes in flight at 70 ms and 2,000,000 bytes at a 200 ms ACK cycle.
The 76 Mbit/s offered-load experiments compare credit sensitivity. The
90 Mbit/s offered-load experiments exercise the 80 Mbit/s acceptance target.

| Offered Mbit/s | Per-flow credit | Linux delivered Mbit/s | Python seed 1 delivered Mbit/s | Linux first-write P99, ms | Linux scheduled P99, ms |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 76 | 256 KiB | 15.36 | 24.92 | 252.8 | 9,617.4 |
| 76 | 1 MiB | 44.10 | 46.02 | 416.7 | 5,391.4 |
| 76 | 4 MiB | 56.57 | 75.99 | 1,260.0 | 4,071.9 |
| 90 | 4 MiB | 54.34 | 77.46 | 1,341.3 | 5,656.8 |
| 90 | 160 MiB, never reached | 14.39 | — | 10,514.5 | 11,431.3 |

Each reported rate is one completed workload on its named implementation. All
five measured Linux transfers verified the stream contents. The 1 MiB data phase completed, then the client
reported an expired authenticated liveness challenge. The case failed to verify
bilateral drain and disconnect. The other four measured Linux cases passed.
An earlier 160 MiB attempt ended during Noise admission before the TCP workload
started. Both ends read back 32 MiB send and receive socket buffers. Python used one
TCP model with cumulative ACKs and congestion control, the same initial cwnd
of ten records and a fixed controller ceiling of 8,192 records across arms.
In the 90 Mbit/s Python arm the forward IP rate was 99.78 Mbit/s and recovery
used 17.22% of those bytes. All four model cases drained. Application delivery
P99 includes completions after the ten-second goodput window.
[Python receipts](../../work/c48-parity-20261119/python/single-flow-near8-seed1/comparison.json)
and [single-flow TUN sequence and ACK analysis](../../work/c48-parity-20261119/native/near8-single-tcp-credit-20261119/ack-timeline.json).

At 4 MiB and 76 Mbit/s offered, the first forward transmission to its covering
cumulative ACK at the sender TUN took 253 ms at the median and 419 ms at P95.
The reverse leg of the covering ACK took 41 ms at the median. For one missing
1,448-byte segment, 77 ACKs repeated the same cumulative edge. Later bytes
waited 348 ms at the receiving TUN until a packet matching the inner TCP
retransmission filled the gap. At 90 Mbit/s offered a second example held later
bytes for 442 ms. The 4 MiB runs were within one segment of the sampled Linux
congestion window in 89% and 88% of snapshots. The original inner TCP segment
has no join to its particular outer FEC source in this capture.

The 160 MiB probe never denied a write on credit. Its sampled median socket
send queue was 21.94 MB, including 21.52 MB still unsent. The median sent but
unacknowledged payload was 0.417 MB, and the median peer advertised window
was 14.01 MB. The sender TUN saw a 3.570-second interval with no new data
during the measurement. At 1.656 seconds the covering ACK visible there had
already acknowledged every forward byte seen at that TUN. The sender probe's
periodic socket observations also have a gap, from 1.507 to 5.082 seconds.
The traces cannot establish the kernel's socket state throughout that gap.
This run demonstrates that removing the probe cap alone does not guarantee
80 Mbit/s. The samples do not establish an optimal credit setting.
[Socket observations, checksums and per-attempt lifecycle results](../../work/c48-parity-20261119/native/near8-single-tcp-credit-20261119/single-flow-summary.json)
and [sender gap with its adjacent socket observations](../../work/c48-parity-20261119/native/near8-single-tcp-credit-20261119/nonbinding-sender-gap.json).

### Sender TUN loss before Packed source assignment

The two original single-flow gaps can be identified by TCP sequence number,
IPv4 ID, TCP timestamp and payload hash. Times are milliseconds from the
start of the ten-second measurement on the common capture clock. The
out-of-order hold starts when B first saw later bytes.

| Offer (Mbit/s) | TCP sequence | IPv4 ID | Original at A | TCP retry at A | Matching retry at B | Covering ACK at A | Out-of-order hold at B |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 76 | 22,847,427 | 60,000 | 6,932.121 | 7,356.007 | 7,664.582 | 7,707.428 | 347.550 |
| 90 | 4,172,841,251 | 31,246 | 6,171.802 | 6,547.690 | 6,855.734 | 6,893.417 | 441.506 |

A full comparison finds 59 and 119 original 1,448-byte TCP transmissions
missing at B. Every missing payload arrived on a later TCP transmission.
All other forward data transmissions match in order. A's count of accepted
native packets, B's count of written native packets and the complete
forward B capture including control are equal at 56,244 and 53,082.
A's native captures have 59 and 119 more packets than those counts.
A reported zero oversize, refused or outstanding native input at shutdown.
These totals and packet identities locate the loss before A's recovery layer.
A missing native input has no Packed source ID, equation membership or named
retry timer. Higher TCP sequence numbers can still traverse the tunnel under
consecutive outer source numbers. The surviving inner TCP retry takes a new
trip through the sender. The original encrypted captures cannot identify
which outer copy carried that retry. [Original packet, payload and admission
reconciliation](../../work/c48-parity-20261119/native/near8-single-tcp-credit-20261119/original-custody.json).

On the Ubuntu 6.8.0-60.63 kernel the packet tap sees a transmitted packet
before the TUN driver enqueues it for the userspace reader. A full reader
ring increments the device TX drop counter and frees the packet with reason
`FULL_RING`. The two original runs did not record this kernel reason. In a
separate reproduction with a deliberately small 64-slot ring, the sender
namespace trace recorded 257 such drops, with zero lost trace events. Each
sequence and length matched an A-only packet fingerprint. All 257 payloads
subsequently arrived at B on an inner retransmission. The device counted
257 drops and its qdisc counted zero. A separate reader-paused fixture sent
619 numbered datagrams in a private namespace. A 500-slot ring lost the last
119 and a 640-slot ring delivered all 619. [Kernel TUN enqueue and drop
path](https://github.com/torvalds/linux/blob/v6.8/drivers/net/tun.c#L1133-L1155),
[per-segment kernel trace](../../work/c48-parity-20261119/native/single-gap-custody-20261119/trace76/sender-drop-join.json)
and [controlled reader fixture](../../work/c48-parity-20261119/native/single-gap-custody-20261119/ring-fixture.json).

An independent bottleneck was visible in two same-release controls with the
system's 500-slot ring. Device drops and inner TCP retransmissions were zero
in both. Linux CUBIC recorded one delay-triggered HyStart exit per connection,
at 73 and 75 MSS, within the first half-second. The corresponding effective
congestion windows after two seconds were 208,512 and 230,232 bytes. The
Python seed-one controller reached 4 MiB in both arms. Forward TUN-to-TUN
median latency during the first half-second was 109.6 and 111.9 ms.
At B, the median delay from delivery to the covering TCP ACK was 0.028 and
0.021 ms. That ACK then took 36.7 and 36.6 ms to return. A change in the
4 MiB application credit would not remove this measured forward delay.
[76 Mbit/s control](../../work/c48-parity-20261119/native/single-gap-custody-20261119/base76/measured.json)
and [90 Mbit/s control](../../work/c48-parity-20261119/native/single-gap-custody-20261119/base90/measured.json).

In the uninstrumented 768-slot control at 90 Mbit/s offered, 96 original
1,448-byte payloads each matched a sender `FULL_RING` event. All 96 matched
a retransmission at B, with no unmatched B payload and zero qdisc drops.
A bounded larger ring moves the overflow threshold. For one 640-slot trial,
the 50 ms before the first drop already contained 414 packets at 99.36 Mbit/s.
The thread ran for 87.2 ms of the enclosing 100.2 ms. These samples cannot
attribute a particular drop to a scheduler stall.
[768-slot per-segment join](../../work/c48-parity-20261119/native/single-gap-custody-20261119/owned90/sender-drop-join.json)
and [640-slot burst and admission accounting](../../work/c48-parity-20261119/native/single-gap-custody-20261119/paced90/burst-accounting.json).

A separate instrumented 76 Mbit/s transfer joined all 395 forward startup
segments in the first 500 ms. The P99 from A TUN to the physical handoff of
all sources of a segment was 2.669 ms. A TUN to B TUN P99 was 117.839 ms.
Two examples distinguish paid forward repair from actual possession of
enough independent equations at B.

| TCP sequence / IPv4 ID | Packed sources | Earliest event that made the last source recoverable at B |
| --- | --- | --- |
| 2,456,959,740 / 14,807 | 181, 183 | Source 181 arrived on its first handoff. Source 183's first handoff was absent at both WAN taps. B named it at +340.801 ms. A received the request at +375.947 ms and handed off packet 382 at +375.994 ms. B could solve at +411.076 ms and committed 46 µs later. |
| 2,456,914,852 / 14,776 | 143, 144 | Source 144 arrived first. Source 143's first two handoffs were absent at both WAN taps. Sixteen ordinary rows covering 143 arrived. An exact GF(256) replay first uniquely determined 143 when the named retry of source 190 arrived at +411.318 ms. The decoder committed 143 41 µs later. |

Times in these two examples are relative to the new workload's start.
Neither eight-source group emitted an optional near8 row. Each lacked
only its named source on first transmission. A timely received group row
would have supplied the missing degree of freedom. A different group lost
four first transmissions. The first near8 handoff in this run was for group
38 at +411.923 ms. The current gate requires four qualifying 100 ms intervals.
Of the 395 startup segments, 179 spent at least 50 ms waiting for native
preparation after all of their own Aligned units had arrived. During the
ten-second measurement, the corresponding wait was 246.944 ms at P99 and
the time to hand off all original sources was 157.732 ms at P99. These
percentiles describe different distributions and cannot be added.
[Source identities, physical packet numbers, named requests, replay and clock checks](../../work/c48-parity-20261119/native/single-gap-custody-20261119/diag76/source-custody.json).

### Bounded sender handoff and native ingress pacing

The Rust sender now retries an already encoded source when its full fresh
FIFO gains a slot during the same sender step and the remaining work grant
can pay for the copy. The same rule applies after a physical receipt. The
original source deadline, byte contents, retry priority and FIFO order are
retained. A focused regression reproduces the old one-slot delay and checks
both call sites at the exact byte and metadata boundaries.
[Sender implementation](../../crates/l2tunnel/src/rolling_records/endpoint.rs)
and [grant and ordering regression](../../crates/l2tunnel/src/rolling_records/targeted_scheduling_tests.rs).

The following Linux results used one CUBIC connection, 4 MiB of outstanding
application credit, 512-byte writes, two seconds of warmup and ten seconds of
measurement at 100/10 Mbit/s, 70 ms propagation RTT and 15% loss per
direction. Each cell is one draw. The two P99 columns include the drain and
start at first attempted application write and at scheduled offer, respectively.
The 82 Mbit/s setting paced the TCP flow at the sender's native TUN, upstream
of the separate 100 Mbit/s WAN qdisc. This is an explicit local intervention.

| Binary and native TUN settings | Offer Mbit/s | Goodput Mbit/s | First-write P99 ms | Scheduled P99 ms | A TUN TX drops |
| --- | ---: | ---: | ---: | ---: | ---: |
| Prior release, system ring (500) | 76 | 43.09 | 2,215.95 | 6,297.36 | 0 |
| Prior release, system ring (500) | 90 | 44.29 | 2,256.47 | 6,996.22 | 0 |
| Prior release, 768 slots | 76 | 54.00 | 1,373.28 | 4,432.85 | 0 |
| Prior release, 768 slots | 90 | 58.19 | 1,192.03 | 5,093.68 | 96 |
| Same-step handoff, 768 slots | 76 | 62.40 | 870.74 | 3,134.33 | 541 |
| Same-step handoff, 768 slots | 90 | 34.07 | 3,646.17 | 8,299.00 | 0 |
| Prior release, 768 slots and 82 Mbit/s native pacing | 76 | 54.10 | 1,416.04 | 4,439.21 | 0 |
| Prior release, 768 slots and 82 Mbit/s native pacing | 90 | 65.64 | 716.29 | 3,917.16 | 0 |
| Same-step handoff, 768 slots and 82 Mbit/s native pacing | 76 | 62.93 | 850.85 | 2,936.67 | 0 |
| Same-step handoff, 768 slots and 82 Mbit/s native pacing | 90 | 59.43 | 1,005.23 | 4,837.46 | 0 |
| Python v6/v5 seed one | 76 | 75.99 | 285.82 | 877.72 | N/A |
| Python v6/v5 seed one | 90 | 77.46 | 482.82 | 2,435.79 | N/A |

All ten Linux workload cells above verified the stream hashes and drained to
two consecutive 0/0 source counts. The 541 dropped transmission attempts in
the 76 Mbit/s unpaced candidate all correspond to kernel full-ring events.
B received 539 payloads with identical segment boundaries. Linux combined
the other two adjacent 512-byte payloads into a single 1,024-byte retry.
The two scheduling entry points pass their functional regression. These
measurements do not establish a repeatable gain in single-flow goodput.
All four 82 Mbit/s paced cells had zero device drops and zero sampled inner
TCP retransmitted bytes. Single-flow throughput and latency parity remain
open. [Byte-exact resegmentation check](../../work/c48-parity-20261119/native/single-gap-custody-20261119/edge76/resegmentation.json).

A repeat used the same single-flow probe and flow-count adapter, with the
matrix's shipped `--native-tun-txqueuelen 768` and
`--native-forward-tun-maxrate-mbit 82` options. It verified the effective
sender rate of 10,250,000 bytes/s in the kernel. It delivered 67.26 and 55.82 Mbit/s
at the 76 and 90 Mbit/s offers, with first-write P99s of 843.38 and
1,213.80 ms and scheduled P99s of 2,320.41 and 5,449.69 ms. Both native TUN
captures matched the opposite endpoint's data with zero missing packets and
zero kernel full-ring events. Two earlier observation attempts failed before
measurement because the installed iproute2 emits two unrelated FQ statistics
under the name `throttled`. The matrix now obtains the generic counters and
the effective root FQ parameters separately and rejects duplicated drop
counts. [All attempts, release hashes, effective settings and drain](../../work/c48-parity-20261119/native/single-gap-custody-20261119/comparison.json).

A research-only sender also allowed short forward repair for the first
400 ms after the first complete group of eight original physical handoffs.
Starting at the session's very first physical source would have ended the
window 264.830 ms before bulk traffic in the diagnostic transfer. Group one
completed 1.252 ms into bulk traffic. The temporary rule retained the
instantaneous eight-MTU backlog check, paid repair budget, physical confirmation
and old-gap priorities. Both Linux arms below used the same owned FQ and ring
settings as the repeat above. Python used its existing single-flow controller
and seed one. Each startup-only byte total counts accepted IP bytes.

| Research sender | Offer Mbit/s | Goodput Mbit/s | First-write P99 ms | Scheduled P99 ms | Startup-only rows / IP bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Linux, isolated release | 76 | 51.49 | 1,589.92 | 4,823.15 | 11 / 14,397 |
| Linux, isolated release | 90 | 63.49 | 827.85 | 4,603.62 | 11 / 14,397 |
| Python | 76 | 75.86 | 271.13 | 746.53 | 35 / 38,242 |
| Python | 90 | 77.79 | 460.20 | 2,362.43 | 24 / 26,219 |

Both Linux trials had zero device drops, zero sampled inner retransmitted bytes,
matched stream hashes and bilateral drain. Early repair improved native latency
and throughput in the 90 Mbit/s draw and worsened both in the 76 Mbit/s draw.
This does not qualify a new default or negotiated production profile. The
build, tests and measurements remain an isolated research result.
[Research source and release](../../work/c48-parity-20261119/native/single-gap-custody-20261119/startup-rust/build.json),
[Linux startup charges at 76](../../work/c48-parity-20261119/native/single-gap-custody-20261119/grp76/startup-paid.json)
and [90 Mbit/s](../../work/c48-parity-20261119/native/single-gap-custody-20261119/grp90/startup-paid.json),
and [matched Python experiment](../../work/c48-parity-20261119/python/single-flow-near8-first-group-400ms-seed1/gate-comparison.json).

With a 1,448-byte TCP payload in a 1,500-byte native IP packet, the
optimistic payload ceiling at the 82 Mbit/s local FQ setting is 79.16 Mbit/s.
An additional pair used 85 Mbit/s at the sender TUN to leave room for the
80 Mbit/s application target. Both runs used the normal matrix provisioning
options, the single-flow probe and the same FIFO-fix release. At 76 Mbit/s
offered, goodput was 58.33 Mbit/s with first-write/scheduled P99 of
1,110.56/3,669.27 ms. At 90 Mbit/s offered the values were 56.36 Mbit/s
and 1,084.63/5,196.28 ms. Both cases recorded an effective 85 Mbit/s,
zero full-ring events, zero device and qdisc drops on both native interfaces,
zero sampled retransmitted TCP bytes, exact application payloads and 0/0
unconfirmed after drain. The higher native rate did not close the throughput
or latency gap in these samples.
[76 Mbit/s offer](../../work/c48-parity-20261119/native/single-gap-custody-20261119/rate8576/measured.json)
and [90 Mbit/s offer](../../work/c48-parity-20261119/native/single-gap-custody-20261119/rate8590/measured.json).

## Early IP TCP delivery across a compression gap

The earlier 246.944 ms P99 measured the time from admission of a TCP record's
last aligned unit to preparation for native delivery. The original sender
capture replayed byte-exactly through the ordered Rust codec for 47,846
packets. All 99 followers of record 126 were header deltas. Decoding each from
the last good context at record 125 produced 99 incorrect TCP sequences and
IPv4 IDs. For record 127 that would have placed the payload at sequence
2456914852 instead of 2456916300. The source 143 hole therefore blocked real
header state even after both of a follower's own fragments were present.
[Capture and per-record byte comparison](../../work/early-tun-20261119/diagnostic/historical-body-replay.json).

The normal Linux TUN and CUBIC trials used one connection, a 4 MiB outstanding
application payload cap, 512-byte application writes, a 768-slot sender TUN and
85 Mbit/s local FQ. The emulated underlay supplied 100/10 Mbit/s, 70 ms RTT
and 15% independent loss in each direction. Goodput is receiver application
payload over seconds 2 through 12. First-write latency includes sender socket
queuing. Scheduled latency also includes waiting to issue a write. Each run
draws live packet losses independently, including runs with identical link
parameters. Outer source recovery, Linux retransmissions and application
payload verification are separate measurements.

With an ordinary full IP context every eight channel record serials, the first
production pair exposed 16,809 and 23,285 out-of-order segments carrying new
bytes to the receiver. In the 76 Mbit/s arm all 1,547,912 retransmitted bytes
were already present when the retransmissions arrived. In the 90 Mbit/s arm
2,479,488 of 2,533,064 retransmitted bytes were already present. Both streams
had correct hashes and bilateral drain. The heavy diagnostic for the 76 Mbit/s
arm matched 40,984 segments. The P99 from all dependencies admitted to native
preparation was 0.860 ms. Its P99 from the record's own units to preparation
was 611.624 ms. Its receiver exhausted all 1,024 lookahead slots, including
482 already delivered records at one observed saturation point. The two
uninstrumented production runs with this configuration had zero record-capacity handoff
refusals. Run-specific wait times and saturation observations belong to their
individual traces.
[Native measurements](../../work/c48-parity-20261119/native/tun-early-sack-20261119/comparison.json),
[stage join](../../work/early-tun-20261119/diagnostic/candidate-stage-join.json)
and [lookahead reconstruction](../../work/early-tun-20261119/diagnostic/candidate-lookahead-witness.json).

The frozen Python FIFO reference reached 75.99 and 77.46 Mbit/s at 76 and
90 Mbit/s offered. In the same seeded model, adding periodic Ethernet header
contexts with FIFO delivery produced 67.15 and 67.21 Mbit/s and zero inner
retransmissions. Allowing immediate delivery of complete anchored chains in
that model produced 0.372 and 0.413 Mbit/s, 33 and 36 inner retransmissions
and a median congestion window below ten 512-byte segments. The model uses
cumulative ACK and duplicate-ACK fast retransmit. Linux uses real MSS-sized
segments and SACK. These are separate comparisons of ordering and TCP
feedback. [Three-way Python control](../../work/c48-parity-20261119/python/tun-early-anchor-seed1/comparison.json).

A five-site observer then used one writer across the historical sender, the
new anchored sender/receiver, and the receiver with a bounded replay store
for delivered records. For the 76 Mbit/s offer, P50/P99 from the record's own
units to native preparation were 90.133/459.748, 0.175/175.785 and
0.191/116.861 ms respectively. These are separate draws. In the last arm all
41,527 timed TCP payloads matched between native captures and 19,898 were
delivered early. Complete compression chain to native preparation P99 was
0.745 ms. Of its slowest 416 records, 411 waited for a preceding body and
five for the full context. The independent RawIp control matched all 28,851
segments. Every one needed two fragments. Last fragment to completed device
write P99 was 0.667 ms, with 21,258 early writes and a maximum of 1.704 ms.
The RawIp control selected its own authenticated header policy.
[Matched observer cohorts](../../work/early-tun-20261119/diagnostic/light-comparison.json)
and [RawIp case](../../work/c48-parity-20261119/native/tun-early-sack-20261119/rawip76/run.json).

The final scoped implementation allocates the additional replay store only
for targeted TUN, including configurations with a zero short-packet threshold.
In a fresh 76 Mbit/s trace of that release all 16,307 native segments matched,
and Linux received 3,974 early. Own aligned units to native preparation P99
was 61.762 ms, and own units to completed TUN write P99 was 61.784 ms. From
the last aligned unit of the full dependency chain to the completed write P99
was 1.035 ms, computed from per-record intervals. All 164 records in the
slowest one percent waited for a prior body in their compression group.
[Exact release stage join](../../work/early-tun-20261119/diagnostic/light-deployed-stages.json).

The following Linux runs used the normal release without stage tracing. Each
repetition has its own live loss draw. Retransmissions are the sender namespace
TCPFastRetrans delta across the phase, cross-checked against repeated payload
bytes in the TUN captures.

| Linux case | Offered Mbit/s | Received Mbit/s | First-write P99 ms | Scheduled P99 ms | TCP retransmitted segments |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original FIFO | 76 | 65.56 | 851 | 2,719 | 0 |
| Final, first draw | 76 | 35.39 | 1,047 | 7,004 | 389 |
| Final, repeat | 76 | 24.41 | 1,651 | 8,931 | 192 |
| Original FIFO | 90 | 59.21 | 1,061 | 4,959 | 0 |
| Final, first draw | 90 | 35.06 | 1,212 | 7,709 | 1,364 |
| Final, repeat | 90 | 40.72 | 957 | 7,121 | 999 |

All four final runs completed with matched payload, bilateral drain and zero
remaining TCP holes. All four had zero TCP timeouts. The 76 Mbit/s repeats
sent 561,912 and 278,016 retransmitted payload bytes respectively. In both
runs all those bytes were already present by the time the repeat arrived.
Sender median cwnd fell from 1,842 MSS in the 76 Mbit/s FIFO run to 325 and
204 MSS. Median socket bytes waiting to be sent increased from 2.08 MB to
3.68 and 3.90 MB. In the two 90 Mbit/s runs retransmissions delivered
34,752 and 5,792 bytes ahead of the corresponding originals. Earlier trials
of the anchor-only build include authenticated liveness and ingress deadline
failures. FIX-04 and TEST-12 single-flow performance qualification remain open.
[Uninstrumented trials and controls](../../work/c48-parity-20261119/native/tun-early-sack-20261119/comparison.json),
[final 76 Mbit/s TCP sequence evidence](../../work/c48-parity-20261119/native/tun-early-sack-20261119/final76/tcp-custody.json)
and [90 Mbit/s repeat](../../work/c48-parity-20261119/native/tun-early-sack-20261119/finalrepeat90/tcp-custody.json).

The first inner retransmission appeared 148–377 ms after data start in the
four final trials. Reverse post-qdisc IP averaged 3.22–5.49 Mbit/s over the
measurement interval. The 90 Mbit/s repeat exceeded 9 Mbit/s in two of its
100 consecutive 100 ms intervals. SACKs and short-packet copies added reverse
traffic while the sender remained congestion-window-limited. These measurements
do not establish persistent saturation of the 10 Mbit/s return path.
[Socket progression and capture timing](../../work/c48-parity-20261119/native/tun-early-sack-20261119/socket-progress.json)
and [reverse path byte accounting](../../work/c48-parity-20261119/native/tun-early-sack-20261119/reverse-path.json).

A documentation build overlapped some of the earlier production measurements
and later reached about 54 GiB resident memory. After stopping that build, a
fresh series alternated FIFO and final releases at each offer. Each workload
had 19–21 one-second host samples, zero observed rustdoc processes and a
maximum reported 10-second memory pressure average of 0.00%. This controls
for the observed build pressure. The four runs still draw independent losses.

| Offered Mbit/s | Release | Received Mbit/s | First-write P99 ms | Scheduled P99 ms | Inner fast retransmissions | Median cwnd, MSS |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 76 | FIFO | 43.35 | 2,583 | 6,132 | 0 | 697 |
| 76 | Final | 11.97 | 4,231 | 11,333 | 24 | 87 |
| 90 | FIFO | 53.43 | 1,495 | 5,711 | 0 | 1,201 |
| 90 | Final | 44.16 | 1,061 | 6,643 | 3,518 | 574 |

The final 76/90 runs exposed 2,868/21,931 segments carrying new out-of-order
bytes. Every run verified the application hash, closed all TCP sequence holes,
and observed two consecutive 0/0 recovery-debt pairs. All had zero TCP
timeouts. The original interrupted attempt is retained separately. These
samples confirm that the throughput regression can occur under low observed
memory pressure. They do not estimate its typical size.
[Interleaved low-pressure comparison](../../work/c48-parity-20261119/native/tun-early-sack-20261119/clean-interleaved-0910.json).

## Receiver admission and a lost gap request on a single TCP stream

The Linux run used one inner TCP flow, a 4 MiB application outstanding limit,
a 90 Mbit/s offer, 100/10 Mbit/s outer links, 35 ms propagation per direction
and 15% independent loss in each direction. The selected profile was C48
with optional Near8 on the forward original UDP path. The sender TUN used
85 Mbit/s pacing and 768 slots. Four instrumented runs used the same release
and independent loss draws. Only the fourth produced steady original TCP
segments taking at least 300 ms from the sender TUN to the receiver TUN.
The following times are milliseconds since the start of its measured interval.

| Event | Earliest long original | Longest long original |
| --- | ---: | ---: |
| TCP sequence, payload bytes | 3759853259, 1448 | 3779923987, 1448 |
| Original at sender TUN | 624.124 | 3235.486 |
| Missing recovery source | 16033, own record 12457 | 36200, predecessor record 28402 |
| Source's first physical packet | PN22932, absent at both WAN taps | PN51607, authenticated then refused at FIFO depth 256 |
| First missing-source request at B | 723.711 | 3402.293 |
| First successful decode at B | 958.325 | 3798.308 |
| Original at receiver TUN | 958.384 | 3799.131 |
| First cumulative ACK covering the segment at B / A | 958.427 / 995.643 | 3744.128 / 3790.469 |

For the earliest segment, B's first request was lost on its way to A. The next
two requests reached A. Neither of the two physical copies of source 16033
appeared at the post-qdisc WAN taps. A named retry of source 16037 arrived,
and the retained equations then recovered both sources. Linux issued 171
higher SACK reports at the missing segment's cumulative edge. The edge held
for 179.840 ms. This segment had a single inner transmission. Replaying every
authenticated arrival from session start in the frozen Python rank decoder
made 16033 solvable at 958.203 ms, at the same arrival as Rust. The remaining
0.122 ms covered receiver admission and transaction commit. Two local and
ten global rows with a nonzero coefficient for source 16033 were physically
sent by that time, and two local and five global rows reached B before
recovery. No Near8 row covering this source was sent. The pivotal local row
PN22987 arrived at 725.830 ms with 16 unknowns. Immediately before PN25593
it had reduced to `46 * S16033 + 88 * S16037` over GF(256). Python verified
the bytes of all twelve repair right-hand sides against the source ledger.
Removing either PN22987 or PN25593 postponed recovery of 16033 to 972.354 ms.
[Repair and feedback packet evidence](../../work/c48-parity-20261119/native/long-gap-fix-20261119/baseline90-04/earliest/repair-feedback-decision.json).
[Earliest TCP and ACK](../../work/c48-parity-20261119/native/long-gap-fix-20261119/baseline90-04/earliest/ack-cohort.json),
[outer admissions and physical sends](../../work/c48-parity-20261119/native/long-gap-fix-20261119/baseline90-04/earliest/outer-witness.json)
and [Python arrival replay](../../work/c48-parity-20261119/native/long-gap-fix-20261119/baseline90-04/earliest/python-rank-counterfactual.json).

For the longest original, the receiver discarded a usable authenticated
systematic source. Three later physical retries of that source disappeared
before the capture points. Two global equations arrived and committed while
it was missing. Each added zero known sources. The fourth named retry reached
B and released the predecessor. An inner retransmission with another IP ID
and compression context had already delivered the TCP bytes at 3716.227 ms.
Keeping the observed Rust commit times for every other input and inserting
just PN51607 at its observed receiver time advances mathematical availability
of the complete dependency chain by 311.687 ms. This is an open-loop
intervention. Fresh closed-loop measurements draw independent losses.

Of 38,902 matched steady originals, 1,140 exceeded 300 ms. For 315 of them,
a last required dependency had its first systematic copy refused locally.
The other 825 had no authenticated arrival of the initial systematic copy
for their last dependency. Multiple segments can share a compressed
predecessor. The longest successful receiver FIFO residence was 50.333 ms.
At PN51607, 33 of the occupied slots held extra byte-identical systematics.
Replaying arrivals against fixed dequeue opportunities also admits other
previously refused originals into those slots. Duplicate coalescing alone
still refuses this particular packet in that replay.
[Original and retransmission](../../work/c48-parity-20261119/native/long-gap-fix-20261119/baseline90-04/outer-witness.json),
[Python single-input intervention](../../work/c48-parity-20261119/native/long-gap-fix-20261119/baseline90-04/python-rank-counterfactual.json)
and [cohort](../../work/c48-parity-20261119/native/long-gap-fix-20261119/baseline90-04/first-systematic-population.json).

The v6 receiver can send one additional physical copy of a named gap request.
It retains one optional request after successful carrier handoff. A newer
logical receipt has priority. Both copies carry the same named-request serial
under distinct physical records, individual byte/packet reservations and
separate completion tokens. A peer which processes both suppresses the second
named retry by serial. An unreserved copy expires at the original output
deadline. Regular old-gap requests continue on their existing timer.
A separate instrumented final run recorded 1,185 two-copy request groups.
At A, 853 arrived twice, 146 arrived only on their first physical send,
161 arrived only on their second send and 25 had neither copy arrive.
These assignments match the actual strong-domain packet numbers, both
post-qdisc captures and the authenticated receiver payloads. Six steady
sources had a successful named retransmission with only the second physical
copy of a relevant request observed at the sender. For source 1286, the
original PN1934 went missing and request 754 reached A only on its second
physical copy PN896. A issued the named source PN2019 at 904.628 ms and B
committed it at 939.743 ms, 124.505 ms after the original send. This particular
trace delivered 6.35 Mbit/s and had no 300 ms original transfer. Its zero
full-queue refusals occurred at a lighter receive load than the clean final
run. [Reverse physical receipts](../../work/c48-parity-20261119/native/long-gap-fix-20261119/final-trace90-01/reverse-physical-ordinal.json).

The targeted input queue combines identical originals already held in the FIFO,
preserves the original custody age and compares bytes before treating a copy
as redundant. At three-quarters occupancy, receive service can spend the
unused part of the current grant on additional decoder jobs after the first
native handoff. The existing per-turn bound and feedback yield still apply.
A late systematic source outside the support of every active equation can
also use the direct validation and storage path after a bounded column check.

Five clean Linux namespace runs used the same manifest, two-second warmup and
ten-second measurement. The interleaved order was baseline, candidate,
candidate, baseline. The fifth run used the final build including the
earlier-deadline guard and the shared service counter. Each run verified the
stream hash, kept independent out-of-order native delivery, and drained both
outer directions with zero outstanding holes. Goodput counts unique
application bytes during measurement. P99 covers all issued 512-byte
application records through drain. The post-TUN column starts once all bytes
of the individual record first appeared at the sender TUN. Fast retransmits
are Linux counters over the workload including drain. All five had zero TCP
timeouts.

| Release and order | Received Mbit/s | First write to read P99 ms | Sender TUN to read P99 ms | Fast retransmits | Longest receiver TCP prefix hole ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline 1 | 37.90 | 993.39 | 368.07 | 2,128 | 97.86 |
| Candidate 1 | 48.72 | 866.55 | 381.86 | 2,065 | 155.09 |
| Candidate 2 | 11.89 | 5,648.18 | 108.69 | 24 | 76.16 |
| Baseline 2 | 8.42 | 6,212.81 | 110.72 | 25 | 79.92 |
| Final | 47.28 | 1,161.59 | 933.23 | 4,277 | 439.00 |

Both the slow baseline and slow candidate had a median smoothed RTT near
76 ms. Their median congestion windows were 63 and 99 MSS and their median
socket bytes written but unsent exceeded 4 MB. In these two runs, about 99%
of the mean first-write-to-read time of the slowest 1% of records elapsed
before those records reached the sender TUN. The socket's outstanding
application limit was 4 MiB in all runs.

The final run coalesced 10,573 authenticated source copies. It still refused
744 systematics and 17 repair packets at a full receiver FIFO. Its 439.001 ms
continuous prefix hole at sequence 2103321971 closed with an inner retransmission.
Among the slowest post-TUN 1% of records in this run, the mean time was
392.93 ms until the individual record reached the receiver TUN, 560.80 ms
waiting for the complete TCP prefix there, and 64.13 ms until application
read. The sender kernel trace locates the missing original before Rust
ingress. A captured it at 3218.360 ms and freed the matching skb 65.276
microseconds later with reason FULL_RING in the sender TUN namespace.
All 81 sender-only native packet identities matched all 81 kernel ring
drops. The BPF reader lost zero events, the sender device counted 81 drops
and the sender qdisc counted zero. Across the target byte interval, B
saw only the matching inner retransmission. That retransmission took
315.797 ms from A TUN to B TUN. The clean build omits its per-input FEC trace.
B sent a covering ACK 31 microseconds after the retransmission arrived.
[Sender ring and capture reconciliation](../../work/c48-parity-20261119/native/long-gap-fix-20261119/final1/sender-ring.json)
and [TCP, SACK and retransmission timestamps](../../work/c48-parity-20261119/native/long-gap-fix-20261119/final1/longest-gap.json).

The frozen FIFO Python comparison at the same 90 Mbit/s offer achieved
77.46 Mbit/s with an issue-to-delivery P99 of 482.82 ms. It uses a modeled
TCP controller and different admission and delivery semantics. Arrival-tape
replay establishes equation and receive-order behavior for the traced
gap. Single-flow 80 Mbit/s qualification and reduction of native P99
remain open.
[Clean release measurements](../../work/c48-parity-20261119/native/long-gap-fix-20261119/comparison.json),
[final clean arm](../../work/c48-parity-20261119/native/long-gap-fix-20261119/final1/summary.json)
and [Python control variants](../../work/c48-parity-20261119/python/tun-early-anchor-seed1/comparison.json).

### Sender TUN ring pressure on one Linux TCP flow

The earlier clean run lost 81 packets at the sender TUN. All 81 A-only
TCP identities matched kernel `FULL_RING` events. The sender qdisc reported
zero drops. On this Linux 6.8.0-60 x86-64 host, the 768-slot pointer ring
returns consumed slots to the producer in batches of 16. Between the first
and last drops of each burst, 128 and zero new packets respectively entered
the ring. Those observations bound actual dequeues to 113–143 over 25.931 ms
and 0–15 over 2.425 ms. At the start of the bursts, the oldest unread packet
was already at least 120.549 and 125.358 ms old. The sender main thread ran
for 98.86 and 96.78 ms of the respective roughly 100 ms sampling windows.
Each surrounding one-second interval contained thousands of native
admission refusals as well as successful sends. All three bracketing
snapshots had eight of eight fresh-source slots occupied. Terminal counters
showed zero recovery-window capacity refusals and zero user-socket write
refusals. The clean run did not trace the reader's exact gate at each loss.
[Kernel, FIFO and sender observations](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/old/historical.json).

For TCP sequence 2103321971, the original IPv4 packet 49220 was dropped
before Rust could read it. The retransmission, IPv4 packet 51949, spent
315.797 ms from A TUN capture to B TUN capture. B sent the covering ACK
31 µs later. The release captured encrypted outer packets without their
source or repair mapping. A reconstruction using the entire native FIFO
order and the configured minimum 35 ms transit bounds the retransmission's
A-side TUN residence to 0–280.797 ms. The exact split across the sender,
forward repair and named retries is unobservable for this instance.
Replaying the 53,261 data arrivals at B with their TCP timestamps through
the frozen Python receiver advanced the same 1,448-byte interval on the same
event. Its covering ACK submission followed the captured Linux ACK by
0.091 ms.
[FIFO bounds and kernel receive](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/old/replay/fifo-and-kernel.json)
and [Python TCP replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/old/replay/python-rx-counterfactual.json).

The Common event loop can encounter backpressure at the start of a turn
and release MUX capacity during that same turn's sends. It now retries the
retained native packet once before selecting the next I/O event when the
issuing generation has actually admitted another MUX head. The retry
uses the original slab, generation and deadline and samples the clock
after sending. A runtime regression drives a real UDP send with refused
ingress and checks that the read gate reopens in that turn and the pending
input is accounted for exactly once.

Three interleaved clean namespace runs kept one TCP flow, 4 MiB outstanding,
100/10 Mbit/s, 70 ms RTT, 15% independent loss in each direction, a 90 Mbit/s
application offer and a 768-slot sender TUN. Each run used its own loss draw.
Goodput uses the ten-second measurement window. Both latency quantiles use all
issued application records through drain. The retransmission column counts
sender-TUN segments carrying previously seen TCP bytes in the measurement
window.

| Build in run order | Received Mbit/s | Write to read P99 ms | A TUN to read P99 ms | Inner TCP retransmitted segments | A TUN ring drops |
| --- | ---: | ---: | ---: | ---: | ---: |
| Retry after MUX progress, first draw | 34.75 | 1039.80 | 147.25 | 562 | 0 |
| Earlier release | 41.21 | 1000.62 | 882.61 | 2774 | 65 |
| Retry after MUX progress, second draw | 49.86 | 769.92 | 250.63 | 1578 | 0 |

The earlier release recorded 4,432 A-side native admission refusals across
772.888 ms of blocked time. Neither modified clean run encountered native
admission refusal. A separate instrumented 50.02 Mbit/s draw also counted
zero opportunities to use the new retry. These draws verified byte identity,
out-of-order delivery support and eventual recovery. All three clean runs
had zero TCP timeouts and drained to zero outstanding sources and old holes.
They cannot establish a throughput or latency improvement from the retry.
[Closed-loop measurements](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/gate-comparison.json)
and [branch and load counters](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/gate-probe-load.json).

A separate prototype let an unfinished local repair serve a fresh source
when the eight-slot sender FIFO was full. One closed-loop draw lost 1,182
sender packets to the kernel ring and reached 1,498.52 ms write-to-read P99.
That prototype was removed. A full eight-slot FIFO alone does not imply
a closed TUN read gate. In a 50.29 Mbit/s baseline trace the packer repeatedly
encountered this FIFO full, yet all 44,675 steady-state native data attempts
were read and A capture-to-read P99 was 1.168–1.171 ms.
[Prototype comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/comparison.json)
and [native read and downstream pressure](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/prior-ring90-01/ring-pressure-time.json).

A traced inner retransmission took 242.917 ms from A TUN to B TUN. For its
remaining dependency, source 72229, the first source and first named retry
were handed to the socket but appeared at neither post-qdisc WAN tap. B
issued another named request at 9663.114 ms. A handed its retry to the
socket at 9710.036 ms, B captured it at 9745.052 ms, admitted it to the
decoder at 9764.069 ms and committed it at 9764.376 ms. B TUN captured the
segment at 9764.836 ms. Earlier TCP copies had already advanced the receiver
ACK for this particular retransmission. In a separate 130.832 ms transfer,
Python replay of the actual authenticated inputs made all ten required
sources decodable at 125.429 ms. Rust committed the last at 134.065 ms
and B TUN captured the segment at 134.742 ms. The replay checked the bytes
of twelve relevant repair equations. Each timestamp belongs to its own run.
[Source and named-retry trace](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/prior-ring90-01/ring-outer-trace.json)
and [same-arrival FEC replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/prior-ring90-02/frozen-rank/python-rank-counterfactual.json).

An open-loop namespace replay injected the same 29,908 forward and 16,677
reverse historical TCP/IP packets into each build's real TUN. Both captures
preserved the complete byte sequence in both directions. With native fq
enabled, the baseline sender's read gate was closed for 124 ms. The modified
sender retried 1,107 times after MUX progress, reopened 1,106 times, and
recorded 1,106 subsequent reads, on average 60 µs after reopening. Both
builds had zero ring drops. Reapplying fq to a tape captured after fq reduced
the peak forward arrival burst from 31 packets per 100 µs to five. This
experiment verifies the gate transition under live backpressure.
[Input, timing fidelity and branch measurements](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/open-loop/comparison.json).

A second replay injected at the recorded post-qdisc time boundary to avoid
applying the native rate limit twice. It preserved packet order and bytes
with forward timing error P99 of 0.198 ms on the baseline and 0.189 ms on
the modified build. For the 1,182 specific packets previously dropped, these
errors were 0.121 and 0.069 ms. The modified sender reopened on all 434
eligible retries and performed its next successful read on average 80.85 µs
later. Neither build dropped a packet from the ring. Forward peak arrivals
per 100 µs were 19 in each replay and 31 in the historical capture. The WAN
also used independent loss draws. Replaying the same native byte sequence
alone does not reproduce the original queue state.
[Post-qdisc input replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/open-loop/post-qdisc/comparison.json).

A diagnostic then compressed just the offered native packet intervals to
65% to reproduce actual ring overflow. Both namespace runs captured all
29,908 forward packets at the TUN transmit tap, upstream of ring admission.
Arrival-time error P99 against the requested tape was 0.224 and 0.239 ms.
The baseline lost 3,883 packets in the ring. At 2,906 drops its last
selection had disabled read interest, and at 2,564 drops it had a retained
packet refused by admission. These observations overlap. At 274 drops read
interest was enabled with no retained packet. Of those, 40 occurred during
a measured management/send interval and 234 fell outside stage intervals
lasting at least 200 µs. On the modified build 9,999 retries reopened the
gate, followed by 9,998 reads averaging 59.67 µs from reopening. It still
lost 3,851 packets. This positive control verifies the competing conditions
at the instant of actual loss. The pair uses different WAN loss draws and
cannot establish a change in drop rate. A preceding timing-distorted pair
is excluded.
[Real ring overflow and timing fidelity](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/open-loop/post-qdisc-pressure-pinned/comparison.json)
and [per-drop read interest, pending input and stage](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/open-loop/post-qdisc-pressure-pinned/baseline-drop-stages.json).

A separate fixed-input comparison used the real Rust record engine, a
modeled 768-slot ring with batched slot returns, and one driver turn every
50 µs. For seed 421 the gate change reduced modeled drops from 3,712 to
3,683 across 30,694 offered packets. Ring wait P99 was 213.720 and 213.684 ms.
The fixed-turn model does not reproduce the Linux event loop's readiness
order or elapsed compute time. In another diagnostic using the old loop,
quadrupling the sender's field and metadata budgets still left 3,196 drops
and 191.915 ms ring wait P99. The deployed work and queue limits stay at
their original values. The local repository gate passed on a frozen copy
of the modified runtime and its regression.
[Fixed-input replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/offline-wave/sweep.json),
[grant sensitivity](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/offline-wave/pressure.json)
and [repository verification](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/full-check.json).

In the reference engine replay, all 3,712 simulated ring drops had an
unadmitted native head and eight occupied fresh slots. Across 2.273 seconds
at high water, arrivals averaged 5,593 packets/s and reads averaged 3,928.
The serializer was transmitting for 62.08% of that interval. For another
25.17%, a complete packet was waiting on the model's next 50 µs poll of an
already idle serializer. Only 4.59% of the high-water interval comprised
entire idle transmit turns without a prepared output. These figures describe
the fixed-turn experiment. They do not measure Linux socket or wire
utilization during the historical losses.
[State and service by replay turn](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/offline-wave/labels/cohorts.json).

## Inner TCP retransmissions in the single-flow near8 run

The steady interval covers seconds 2–12 on one Linux TCP connection, with a
4 MiB application outstanding limit, 90 Mbit/s offered, 85 Mbit/s sender TUN
pacing and the 100/10 Mbit/s, 70 ms RTT, 15% loss-per-direction link.
The capture join uses TCP byte ranges to detect repeated bytes and exact
packet identity to determine which attempt arrived first. Both TUN captures
passed their saved SHA-256 checks and recorded zero capture drops.

| Steady A TUN transmit cohort | gate1 | gate2 |
| --- | ---: | ---: |
| TCP segments repeating earlier bytes | 562 | 1,578 |
| Earlier copy already at B TUN when A transmitted again | 549 | 1,119 |
| Earlier copy still in transit, reached B before this retry | 13 | 432 |
| This retry first at B for the bytes | 0 | 27 |
| Latest ACK at A carried a forward SACK beyond the retried range and its cumulative ACK was behind | 549 | 1,506 |
| B had cumulatively acknowledged the range and A had yet to observe a covering ACK | 536 | 775 |

For the last row, the median time from B's first covering cumulative ACK to
A's first covering cumulative ACK was 36.568 and 37.163 ms. The respective
P99 values were 39.718 and 43.732 ms. These can be different ACK packets
covering the same bytes. The forward gap exposed to Linux and the return
propagation time explain how A can retransmit while B has already closed a
gap. B TUN visibility alone does not prove kernel acceptance. An emitted
cumulative ACK does prove receipt through that byte. All numbers in the table
use the A transmit interval, including copies that arrived after its end.
[gate1 byte and ACK races](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/gate1-races.json)
and [gate2 byte and ACK races](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/gate2-races.json).

The same ACK can trigger different decisions in the Python and Linux senders.
At steady time +26.846 ms in gate1, A received a cumulative ACK for relative
byte 6,690,540 with a SACK covering bytes 6,697,780–6,702,124 (exclusive end).
The NewReno sender replay requested the first missing byte again. The Linux
sender left its congestion window at 352 MSS in both adjacent samples and
never retransmitted that byte. A covering ACK arrived 1.513 ms later. The
two steady captures contained 52 and 39 such model retries with a forward
SACK where Linux received confirmation before retransmitting the byte. The
replay fixes the original sends and inbound ACKs. It measures individual
decisions and does not predict the throughput of a different closed loop.
[gate1 sender replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/perf-sender-replay-gate1.json)
and [gate2 sender replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/perf-sender-replay-gate2.json).

The optional forward near8 TUN policy initially held reconstructed TCP data
beyond a gap for up to 35 ms, released it on timeout or at a 256 KiB span,
and kept the original source eligible for recovery. The policy is a distinct
authenticated descriptor and accepts the same near8 packet grammar. Both
arms below used tree `986cf74a6191` and independent live loss draws.

| Forward delivery | Received Mbit/s | First-write to read P99 ms | Steady inner retries | Retries first to reach B | A TUN ring drops |
| --- | ---: | ---: | ---: | ---: | ---: |
| Immediate | 45.45 | 831.17 | 1,243 | 4 | 0 |
| Bounded hold, initial implementation | 46.61 | 963.50 | 2,476 | 125 | 104 |

The 104 kernel ring drops matched 104 A-only data attempts. Both arms drained
their source confirmations and delivered the application stream with a matching
hash. This pair did not establish a performance gain.
[Immediate arm](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate1-986cf74/measured.json),
[bounded arm](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/hold351-986cf74/measured.json)
and [kernel ring join](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/hold351-986cf74/sender-ring.json).

The next pair used tree `ec87281c2420`. It retained up to 32 disjoint
delivered ranges and counted only completed TUN writes. Both runs delivered
the expected stream, drained their source confirmations and recorded zero
sender TUN drops. Each run used an independent loss draw.

| Forward delivery | Received Mbit/s | First-write to read P99 ms | Steady inner retries | CUBIC HyStart delay exit (MSS) |
| --- | ---: | ---: | ---: | ---: |
| Immediate | 34.83 | 1,038.27 | 455 | 353 |
| Bounded hold, 32 ranges | 11.18 | 4,770.96 | 9 | 48 |

The bounded run started 370 holds through application EOF. The missing prefix
closed 317 of them before the deadline. The other 53 expired. The sender
entered the steady interval with a congestion window of 54 MSS in the bounded
run and 354 MSS in the immediate run. Its median steady window was 81 and
365 MSS respectively. The bounded sender had 4.08 MB written to its socket
and still unsent at the median sample. Neither steady interval recorded a
TCP timeout. These measurements locate a sustained throughput limit in the
endpoint congestion window. Independent startup loss draws limit attribution
of either HyStart exit to the hold policy alone.
[Immediate arm](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate1-ec87281/arm-evidence.json)
and [bounded arm](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/hold351-ec87281/arm-evidence.json).

The two native captures show where the bounded run first lost ACK progress.
For TCP byte 42,772, A sent the original at 182.434 ms after the offer began.
B received that original at its TUN at 342.336 ms, produced a covering ACK
at 342.376 ms and A received it at 378.456 ms. A had already retransmitted
the segment at 343.676 ms. The reverse trip took 36.080 ms. Replaying the
immediate run's first 750 ms of B arrivals through the bounded delivery
policy delayed 206 of 1,183 segments by over 1 ms. All 855 advances of the
contiguous TCP prefix occurred at their original times. Of 150 positive
SACKs emitted before 500 ms, 94 had reported blocks that became visible over
1 ms later under replay, with a maximum delay of 14.342 ms. The replay fixes
the input and omits endpoint feedback. The 500 ms socket sampling interval
during warmup cannot identify the single ACK that triggered HyStart.
[Bounded startup timeline](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kernel-startup-hold351-ec87281.json)
and [immediate timeline and fixed-input replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kernel-startup-immediate1-ec87281.json).

### Confirmed source bytes in global equations

At each global opportunity a sender can freeze the greater of the original
window start and its authenticated cumulative receipt. Sources below that
bound are already known at the peer. Removing their contributions changes
the transmitted equation payload, but leaves precisely the same equation
over missing sources once the receiver subtracts its known contributions.
The start cannot move beyond the oldest unconfirmed source. A lost receipt
leaves a wider equation. The local window and the original global cadence
remain available.

Two captured sender traces contain 540 and 525 global regular repairs. Using
only confirmed prefixes witnessed before the source acceptance that earned an
equation, the excluded columns account for at least 85.33% and 92.97% of the
original global GF input bytes respectively. In the first trace 79 support
ends were bounded using adjacent emissions. The percentages cover global
encoding work and do not estimate total daemon CPU time.

In the second trace, repair 3968 covered sources [17867, 26059) with prefix
25459 confirmed. Sources 26055 and 26058 were both still missing. Independent
re-encoding matched all 1,261 captured bytes. After subtracting known sources,
the two-source residuals matched byte for byte for the full and shortened
equations. A second equation recovered source 26463 and matched all 1,259
original bytes. These traces contain no standalone tail repair for this
profile. Native performance requires a closed-loop trial of the negotiated
new grammar. On both examples the compact repair record grew from 1,267 to
1,269 bytes. The two-byte prefix offset reduced the number of source columns
processed while leaving the repair's field payload available to the decoder.
[First trace work bounds](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/perf-prefix-gf-prior-ring90-01.json)
and [second trace and byte proofs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/perf-prefix-gf-prior-ring90-02.json).

Both forward configurations were then selected through the authenticated
Common service on original UDP, using tree `7e02a546c6a0`, immediate native
delivery and the same single-flow workload described above. Both streams
passed payload verification and drained without outstanding sources.

| Forward repair | Received Mbit/s | First-write to read P99 ms | Steady repeated segments | Median cwnd in MSS | Sender TUN drops |
| --- | ---: | ---: | ---: | ---: | ---: |
| Confirmed prefix | 13.19 | 3,759.44 | 8 | 99 | 0 |
| Original near8 control | 18.41 | 2,146.10 | 10 | 149 | 0 |

All 18 repeated segments across the two draws had already been cumulatively
acknowledged at B when A repeated them. The median volumes written to the
application socket and still unsent were 4.05 MB in the prefix run and
3.98 MB in the control. The two independent loss draws qualify functional
interoperation of the two controlled peers and leave the throughput target open.
[Confirmed-prefix arm](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/prefix1-7e02a54/arm-evidence.json)
and [original control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate1-7e02a54/arm-evidence.json).

Tree `e40a794f40f7` also counted columns when a real carrier send completed.
In the prefix arm 105 of 105 global rows used a shortened span during the
sampled status interval (11,021 processed columns out of 680,656 nominal).
The control sent all 2,678,784 nominal columns in its 327 rows. The prefix
arm delivered 8.23 Mbit/s at 5,706.99 ms P99 with nine steady inner retries;
the control delivered 38.86 Mbit/s at 993.87 ms P99 with 564. Median cwnd
was 67 and 499 MSS respectively. Each run had its own loss draw. Both sender
TUNs recorded zero drops. B refused 167 original and ten repair inputs in
the busier control. The confirmed prefix eliminated field operations in real
sends. Those savings alone did not resolve the TCP throughput limit.
[Physical prefix counts and application results](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/prefix1-e40a794/arm-evidence.json)
and [same-build control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate1-e40a794/arm-evidence.json).

An independent diagnostic draw of the same prefix binary delivered 39.25
Mbit/s with a first-write-to-read P99 of 1,133.04 ms. A read-only probe
filtered to the sending network namespace and application TCP tuple recorded
472 calls to the CUBIC HyStart update with zero lost events. At workload
+637.334 ms, the measured round minimum was 115.552 ms against a delay
threshold of 81.190 ms. CUBIC set the slow-start threshold to 499 MSS on
cumulative ACK 720436 (relative). The corresponding B-side fill advanced
the stream by 1,448 bytes. The data took 77.567 ms from A TUN to B TUN,
B emitted its ACK in 0.014 ms, and that exact ACK reached A in 38.205 ms.
The kernel update followed the A capture by 4.582 microseconds. The trace
records a congestion decision for this round; its RTT estimator can select a
different transmitted segment from the one that last advanced B's edge.
[Kernel samples joined to both packet captures](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/prefix2-cubic-e40a794/cubic-ack-join.json)
and [Linux CUBIC delay test](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_cubic.c#L399-L416).

A separate Python experiment applies one additional XOR row per eight original
sources during the first 64 KiB, while charging its serialized bytes and
preserving the existing repair schedule. Across eight paired synthetic loss
draws, the median time saved at the 64 KiB cumulative application milestone
was 69.95 ms. At 128 KiB the median saving was 0.004 ms. The full single-flow
FIFO run improved from 77.46 to 77.71 Mbit/s in seed one while P99 increased
from 482.82 to 492.85 ms. In seed two goodput increased from 75.64 to
77.75 Mbit/s and P99 decreased from 520.51 to 499.36 ms. All four runs
recorded zero inner retransmissions and drained. These results describe
the synthetic FIFO workload. The Rust runtime retains its original startup
behavior.
[Startup milestones](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/outer-closed-loop-summary.json)
and [full runs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/outer-closed-full-summary.json).

### Crossing buffered repairs with independent sources

The receiver now tracks the furthest source covered by the earlier repair
rows it passed while scanning the existing FIFO. It passes a row only after
earlier committed sources have proved its complete observation range. An
original beyond the active equation, existing basis and previously passed
rows may commit immediately. A row that would first establish a further
gap keeps its original FIFO position and deadline. Replaying the full queue
that refused source 36123 identified 240 eligible source entries among 256.
[Capture replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kernel-decoder-fences.json)
and [runtime regression](../../crates/l2tunnel/src/rolling_records/ingress_tests.rs).

The native measurements below used one Linux TCP flow, a 4 MiB outstanding
cap, 90 Mbit/s of offered 512-byte writes, the 768-slot TUN at 85 Mbit/s,
100/10 Mbit/s WAN, 70 ms propagation RTT and 15% IID loss in both directions.
Each private netem leaf started from the same read-back seed for its direction.
This reproduces the random sequence by packet ordinal. Timing and control
traffic can still change which source sees a particular loss. Recovery in
both directions drained after the application stream passed its hash check.

| UDP forward near8 | Goodput Mbit/s | First-write to read P99 ms | Warmup / steady / after steady repeated segments | Sender TUN drops | B FIFO refused sources / repairs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Before the receiver change | 46.97 | 823.02 | 154 / 714 / 24 | 0 | 757 / 75 |
| After the receiver change | 58.11 | 1,027.33 | 1,777 / 109 / 8 | 117 | 0 / 0 |

In the first run, only two of the 714 steady retries reached B before the
previous attempt. In the second run all 117 full-ring events matched
original packets lost before Rust read them. All 109 steady retransmissions
and all eight later retransmissions delivered their missing bytes first.
No warmup retransmission was the first copy at B. Sender admission recorded
70,463 capacity refusals across 20,456 completed blocking intervals in the
second run. The longest interval lasted 13.353 ms. The 6.246 seconds summed
over those intervals cover the entire process. They do not specify the
reader's instruction at an individual kernel drop.
The 117 drops were concentrated in 57.230 ms, about 9.39 s into the steady
interval. The A daemon's main thread ran for 99.995 ms during the enclosing
100.220 ms observation. FIFO accounting bounds its actual reads to 161–191
packets between the first and last drops. At the first drop the oldest unread
native packet had already spent at least 118.617 ms waiting. The sealed
Packed source was repeatedly refused by the recovery sender and the upstream
codec could no longer admit new work. Snapshot counters cover multiple turns.
[Sender thread, ring and admission evidence](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/outer-fence-ring.json).
[Same-seed release comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/fence-seed31248.json),
[before byte join](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kernel-control-immediate3-cubic-seed31248-e40a794.json)
and [after byte join](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kernel-control-immediate3-cubic-seed31248-e679a6c.json).

On the changed receiver paired with the optional confirmed-prefix sender,
the same seed settings yielded 41.19 Mbit/s, 988.05 ms P99, zero TUN drops
and zero receiver FIFO refusals. Four of 48 steady retransmissions delivered
their bytes first. All 445 sampled global equations were trimmed, retaining
200,208 of 3,645,440 nominal input columns. This third configuration changed
the sender as well. Single-flow throughput and P99 qualification remain open.
[Changed receiver and confirmed-prefix sender](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/prefix3-cubic-seed31248-e679a6c/arm-evidence.json).

The targeted sender remembers when a sealed source was refused because
the fresh-source FIFO was full. Further work turns can service feedback,
repairs and output while that source waits. Selecting an original frees a
slot and reopens admission in the same turn when enough work budget remains.
The source keeps its original deadline throughout. A regression case with
three zero-progress turns measured four admission attempts before this
change and one after it. This count measures calls on an unchanged FIFO.
Native performance needs a separate measurement.

The Common service status also exposes counters for native admission
refusals at the ACK accumulator, flow table, shared byte and packet
budgets, and per-flow byte and packet budgets. Each counts actual
admission attempts. A refused packet can be retried several times.
The timed NativeIngress summary measures the blocked intervals.
[Sender scheduling regression](../../crates/l2tunnel/src/rolling_records/targeted_scheduling_tests.rs)
and [client observation fields](../../crates/l2tunnel-client-core/src/secure_udp/common_observations.rs).

With the same directional netem seeds and the same one-flow workload,
the first run of this sender delivered 16.27 Mbit/s and 2,570.87 ms
first-write-to-read P99. The previous sender delivered 58.11 Mbit/s
and 1,027.33 ms P99. Sender TUN drops fell from 117 to zero, and the
new sender reported zero refusals in all six native admission counters.
All 22 steady inner retransmissions repeated bytes the receiver had
already cumulatively acknowledged. The covering ACK reached the sender
a median 3.056 ms after it retransmitted. There were no TCP RTOs and the
final recovery observations drained in both directions. The median
congestion window in the new run was 139 MSS with an 81.792 ms SRTT.
The two runs saw different TCP window trajectories and consequently
different traffic at the TUN. This comparison does not establish a
higher sustainable TUN read rate or a single-flow performance improvement.
[New native measurement](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-seed31248-3fd6740/arm-evidence.json)
and [all 22 retransmissions](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-seed31248-3fd6740/retrans-races.json).

At 680.959 ms the new run's CUBIC HyStart trace recorded an exit at
113 MSS. The kernel's minimum RTT for that round was 88.859 ms, above
its 81.923 ms threshold. The last matching cumulative ACK took
46.974 ms from B TUN to A TUN. The data segment that completed that
byte range took 41.787 ms from A TUN to B TUN, and B generated the
ACK 0.055 ms later. The sender still had a 113 MSS slow-start threshold
at two seconds. Across the slowest 1% by first-write-to-read latency,
mean time from the first write to A TUN was 2,569.20 ms, A TUN to B TUN
was 47.19 ms, and waiting for preceding bytes at B took 2.92 ms.
[Kernel and both TUN captures](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-seed31248-3fd6740/cubic-ack-join.json)
and [record-level latency breakdown](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-seed31248-3fd6740/record-byte-delay.json).

The nine ACKs in the exit round span 10.751 ms at B TUN and 1.359 ms
at A TUN. As an offline sensitivity check, keeping each current forward
path and substituting the previous run's first return ACK covering the
same byte gives 71.6–80.5 ms. Every reconstructed path falls below the
observed threshold. The previous run's covering ACKs advanced 936 bytes
farther, and changing a live return path would also change later sends.
This check isolates the timing contribution within the recorded round.
[Startup byte ranges and ACK return times](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/sender-startup-pair.json).

A diagnostic run of the previous binary attached `perf` to the A daemon's
main thread with the same workload. Of 703 steady CPU-clock samples, 430
were in user mode and 273 in kernel mode. The rolling encoder took 31.58%
including its callees. The AVX2 field-multiplication function alone took
21.62%. This run delivered 18.99 Mbit/s with zero TUN drops. The profile
therefore covers an active sender, and the earlier 57.230 ms TUN drop
interval still has no instruction-level profile.
[Sender thread sampling and loss counters](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate7-cubic-perf-seed31248-e679a6c/sender-thread-profile.json)
and [sampled stacks](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate7-cubic-perf-seed31248-e679a6c/steady-perf-chains.txt).

### Waking the sender for the next short physical copy

All nine ACKs in the new sender's measured HyStart exit round were 52-byte
IPv4 packets without SACK blocks. The previous sender's exit round had nine
72-byte packets with SACK blocks. Both fit the configured 128-byte independent
short-frame threshold. The encoder emits a self-contained raw record and the
selected copy policy requests three physical copies. The packing timer is
500 µs from the first unit. During the extra time beyond 35 ms of propagation,
the new run's WAN taps saw 39–45 reverse UDP datagrams per ACK interval.
Those data contain ciphertext. The captures cannot identify which copy
delivered the corresponding native ACK.
[Reverse ACK and WAN witnesses](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/short-ack-wan.json).

Separately, the Common selector could return to its idle timer when the
second copy of a short source was already affordable. The protected UDP
fixture reproduced a 100 µs delay after the first physical handoff. Rolling
now exposes the actual ready output's debit, including fragment costs.
The selector schedules runnable work when that debit and the management
reserve are available. With one byte of credit missing, it waits until the
exact refill instant. The fixture also checks delivery after dropping the
first copy and a subsequent mode switch on both tested UDP appearances.
The effect on the measured HyStart round and single-flow throughput remains
unverified.
[Original wake](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/short-copy-wake-red.log)
and [exact-credit regression](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/short-copy-wake-credit.log).

### Following an inner ACK through the reverse carrier

The single-flow run keeps a 4 MiB application outstanding limit, Linux CUBIC,
100/10 Mbit/s, 35 ms per direction and independent 15% directional netem loss.
In the 64 KiB reverse-burst control on tree 3fd6740, all 309 steady duplicate
TCP transmissions reached B after the corresponding original. At retransmit
time B had sent a cumulative ACK for 211 of those ranges that was still in
transit, 49 waited for an earlier hole, 10 already had a covering ACK at the
A TUN tap, and 39 originals were still in transit. All 309 eventually drew
D-SACKs. Once B had the contiguous prefix its ACK generation P99 was 0.136 ms.
The TUN tap precedes Linux TCP processing and cannot date its loss decision.
[Sequence-by-sequence reconstruction](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/revq-steady-retrans-attribution.json).

The optional startup observer records rolling source/copy/equation labels,
actual socket acceptance, Records opening, decoded native IP hashes and whole
TUN writes. Matching the per-record witnesses to native IP hashes and outer
packet numbers covers 4,093 early ACKs in each arm on tree 84fcf45. For the
nine ACKs sampled at the 64 KiB arm's CUBIC slow-start exit, the completing
forward segment took 92.216–108.013 ms and the reverse ACK took
35.882–36.902 ms. Later in startup, ACK IPID 33911 took 195.107 ms end to end.
159.863 ms had already elapsed when B selected a copy that reached A.
The receiver's opening-to-native-ready P99 was 0.884 ms for the direct
candidates in the traced startup sample.
[64 KiB per-record join](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-revq-records-seed31248-84fcf45/reverse-record-join.json).

Reducing only B's burst from 65,536 to 4,096 bytes with identical rate limits
reduced B qdisc P99 from 48.705 to 36.223 ms on 3fd6740. The corresponding
steady cumulative ACK coverage P99 increased from 88.078 to 348.162 ms.
On 84fcf45 the smaller burst decreased early native ACK P99 from 196.598 to
73.216 ms. Steady throughput was 57.98/53.21 Mbit/s for the larger/smaller
burst respectively, application first-write-to-read P99 was 917.23/950.40 ms
and steady duplicate transmissions numbered 2,077/37. Both arms drained all
observed TCP byte gaps. The selected burst remains an experimental setting.
The same netem seed preserves the loss sequence by packet ordinal. Different
packet ordering changes the TCP trajectory and the set of sources lost.
[Cumulative coverage](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/rp3-reverse-native-cumulative.json),
[larger burst](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-revq-records-seed31248-84fcf45/arm-evidence.json)
and [smaller burst](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/rp3-cubic-revq-records-seed31248-84fcf45/arm-evidence.json).

The 64 KiB run on 84fcf45 refused native input 53,895 times at the
1 MiB per-flow MUX byte limit during 15,690 blocked periods. In 4.73 seconds
of aggregate blocked time, the driver retained its single input and stopped
reading the TUN until that flow made space. The 4 MiB application outstanding
limit and the observed Linux CUBIC window are separate limits. Common now
skips retrying the same data packet while its issuing flow's queued bytes
alone prove that admission will fail. Releasing enough bytes reopens the
original read gate in the same send turn. Direct Pipeline admission also
reuses the initial packet classification. Six interleaved local microbenchmark
rounds on captured packets reduced a successful data admission from 599.30
to 481.75 ns and a successful ACK admission from 722.29 to 607.74 ns.
[Per-packet CPU comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/pipeline-direct-forward-cost.json).

The next frozen Linux run on b78b47d added bounded startup observations at
the reverse TUN read, MUX admission and actual packing admission. The 64 KiB
and 4 KiB reverse bursts measured 44.02 and 39.79 Mbit/s, with application
first-write-to-read P99 of 1,077.38 and 956.26 ms. All 437 and 113 steady
duplicate transmissions respectively had a covering cumulative ACK at B
before the retransmit was observed at A. Both arms recorded zero FULL_RING,
zero MUX flow-byte refusals and complete terminal gap recovery. The blocked
retry guard therefore had no occasions to affect these two measurements.
For the slowest 1% of application records, mean time from write to A TUN was
870.50 and 882.05 ms. Across the 4,093 early reverse ACKs with full
stage coverage in each run, B TUN to first socket acceptance P99 was
44.294 and 33.133 ms. In each arm's slowest 41 records most elapsed time
was between MUX entry and packer admission, or between packer admission and
first physical selection. These observations support further work on service
cadence and tunnel recovery. The Python and native performance gates remain open.
[64 KiB application stages](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-revq-records-seed31248-b78b47d/record-byte-delay.json),
[4 KiB application stages](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/rp3-cubic-revq-records-seed31248-b78b47d/record-byte-delay.json),
[64 KiB ACK stages](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-revq-records-seed31248-b78b47d/reverse-ingress-stages.json)
and [4 KiB ACK stages](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/rp3-cubic-revq-records-seed31248-b78b47d/reverse-ingress-stages.json).

During the wait to first socket acceptance for those slowest 41 early ACKs,
median B pre-qdisc throughput on the DATA route alone was 9.50 and
9.56 Mbit/s respectively, against a 10 Mbit/s reverse link. During the
48.348 ms wait for record 2681 in the larger-burst arm, B issued 56,809
DATA-route IP bytes, including 35,010 bytes in 45 additional original
copies, 17,894 in 23 first or unmarked sources and 3,905 in five repairs.
These intervals overlap across records. Times and bytes are measured
individually per interval. The figures identify competition for reverse link
service while an ACK is waiting for its first transmission.
[64 KiB interval composition](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-revq-records-seed31248-b78b47d/reverse-preselection-load.json)
and [4 KiB interval composition](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/rp3-cubic-revq-records-seed31248-b78b47d/reverse-preselection-load.json).

### Receive service and inner TCP timestamp validation

The 64 KiB reverse-burst run on tree `b78b47d` had 3,475 authenticated
DATA datagrams matched from the A WAN capture to the A runtime. Median
receive time was 0.084 ms. Packet 595 took 29.828 ms, including 29.039 ms
of an active Common send call. Ninety UDP packets arrived at A during that
call. The plain UDP runtime now checks for an actual waiting datagram
between accepted sends once its receive-service interval expires. The
selector carries that observation through to the existing budgeted receive
path. Common also seals its retained outgoing plaintext directly into the
final send buffer. Incoming deferred connection ACKs have separate scratch
space. The per-datagram work inside a send still runs to completion.
[Packet 595 and thread scheduling](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-revq-records-seed31248-b78b47d/a-udp-receive-stall.json).

In the same run, all 46,487 forward data packets matched byte-for-byte at
both TUNs, including the TCP timestamps. At B, an inner retransmission for
byte offset 2,681,028 advanced the observed TCP timestamp baseline. Three
subsequent original packets had timestamps 166, 78 and 15 ticks behind that
baseline. Across the run, 404 incoming data packets were more than one tick
behind B's observed baseline. B's namespace recorded 404 established PAWS
events. The historical trace captured TCP entry state and lacks an individual
drop verdict. In the 4 KiB reverse-burst run only three packets exceeded the
same threshold. The original that closed its 81.499 ms gap had a current
timestamp and B emitted its covering ACK 0.083 ms later. The two gaps
therefore have different receiver-side explanations.
[64 KiB timestamp and sequence audit](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate3-cubic-revq-records-seed31248-b78b47d/receiver-paws-threshold.json)
and [4 KiB timestamp and sequence audit](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/rp3-cubic-revq-records-seed31248-b78b47d/receiver-paws-threshold.json).

The following runs used the same Linux CUBIC workload, 4 MiB application
outstanding cap, 90 Mbit/s offer, 100/10 Mbit/s links, 70 ms base RTT and
15% independent loss in each direction. A scoped receiver probe matched an
individual TCP call and the kernel drop of its skb. One earlier probe setup
failed before sending application data. The completed runs used the same
observer and netem seeds. Thread timing can change which logical packets
occupy the seeded physical slots.

| Single TCP flow | Steady goodput, Mbit/s | First application write to complete read P99, ms | Steady repeated TCP segments | B PAWS drops, whole run | A TUN drops | Unfilled final TCP gaps |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 KiB reverse burst, earlier tree `b78b47d` | 56.80 | 690.82 | 200 | 26 | 0 | 0 |
| 64 KiB reverse burst, receive-service candidate `5aee69b` | 8.34 | 6961.44 | 4 | 18 | 0 | 0 |
| 4 KiB reverse burst, same candidate | 27.43 | 1562.11 | 25 | 0 | 0 | 0 |

The first repeat in both 64 KiB runs covered byte 24,460. Comparing the
next originals locates a consequential divergence. On the earlier build,
the original covering byte 30,252 reached B at 215.53 ms, ahead of its
inner retransmission at 298.12 ms. On the candidate the retransmission
arrived first at 265.39 ms and advanced the TCP timestamp baseline. Its
original followed at 276.44 ms. Linux subsequently dropped the original at
byte 33,148 while that byte was exactly next to receive. Its timestamp was
119 ticks behind the baseline. Of the 18 PAWS drops, 16 still carried
needed bytes. On the earlier build all 26 PAWS drops covered bytes already
cumulatively acknowledged. At 500 ms the sender's cwnd was 263 MSS on
the earlier build and 15 MSS on the candidate. Median steady cwnd on the
candidate was 68 MSS with 4,102,608 bytes queued unsent. Its four steady
repeats exclude the 35 repeats already present in the first half-second.
These traces locate when the receiver and sender diverged. They do not
isolate the scheduling change from the physical loss and timing of each draw.
[Earlier 64 KiB receiver verdicts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-records-verdict-seed31248-b78b47d/receiver-verdict-startup64k.json),
[candidate 64 KiB receiver verdicts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-records-verdict-seed31248-5aee69b/receiver-verdict-startup64k.json),
[4 KiB receiver verdicts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/rp4-cubic-revq-records-verdict-seed31248-5aee69b/receiver-verdict-gaps.json)
and [64 KiB candidate socket samples](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kernel-control-immediate4-cubic-revq-records-verdict-seed31248-5aee69b.json).

A further 64 KiB run traced the forward record stream and every successful
UDP send-batch yield. It delivered 55.79 Mbit/s with 800.11 ms write-to-read
P99, 99 steady repeated TCP segments, zero sender TUN drops and zero final
byte gaps. The first inner repeat covered offset 3,588 at 148.772 ms. A's
first send yield was at 718.494 ms and B's at 2820.369 ms. The receive-service
yield did not precede that first repeat. Tracing a different direction changes
the work done by the observers. These are separate closed-loop outcomes.
[Forward-traced run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-235044b/arm-evidence.json)
and [yield times and first repeated byte](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-235044b/udp-yield-at-first-repeat.json).

The first repeat combined two original 512-byte TCP payloads starting at
offset 3,588. Both original records were in source 10. A's socket accepted
the original outer packet 24 at 2.434 ms. Neither WAN capture saw it.
A sent the named retry in packet 33 at 77.416 ms. B authenticated it at
112.913 ms, delivered both original TCP segments and emitted a cumulative
ACK for the full 1,024 bytes at 113.144 ms. Linux A retransmitted the range
at 148.772 ms. Its covering ACK arrived at A at 150.054 ms, 1.282 ms later.
For byte 8,020 the record spanned sources 16 and 18. Source 16 opened at B
at 112.923 ms. Source 18's original packet 36 was absent from both WAN taps.
A sent its named retry at 159.138 ms, B opened it at 194.328 ms and the
restored TCP segment reached B TUN at 194.673 ms, closing a 67.565 ms gap.
The four ordinary repair packets opened in this interval lack exact
coefficient and rank witnesses in this trace. The last uncovered TCP byte
and the final outer outstanding counts both drained.
[Full TCP ranges, fragment identities and physical packet attempts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-235044b/forward-record-custody-final.json).

The Python established-DATA PAWS option rejected zero segments on the
frozen FIFO single-flow path and reproduced its 77.464 Mbit/s, 482.818 ms
issue-to-application P99 and zero inner retransmissions. Its one forward
TCP flow mapped to channel 0. That receiver held 512-byte data records
behind their channel predecessor. The early-delivery study, at the same
4 MiB window and 90 Mbit/s offer, actually delivered independently decodable
TCP data across gaps. Enabling PAWS there rejected 23 segments. With PAWS
off/on, throughput was 0.331/0.431 Mbit/s, inner retransmissions were
28/39 and all submitted data drained. In each run more than 262,000 scheduled
records were never submitted. The Python sender uses cumulative NewReno
feedback. These two simulator paths give very different TCP inputs and
neither reproduces the Linux SACK and loss-recovery decisions in these runs.
[Frozen FIFO model and packet-tape replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/paws-comparison.json)
and [early-delivery model](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/paws-early-comparison.json).

### Separating insufficient repair rank from Linux retransmission timing

The single-flow C48 run on tree `62af965` used the same 4 MiB outstanding
application limit, 90 Mbit/s offer, 100/10 Mbit/s links, 70 ms base RTT and
15% iid loss per direction. Forward tracing now records the actual ordinary
repair's inclusive start, exclusive end, seed and tail flag alongside its
packet number. Of the first 4096 numbered outputs at A, 3487 opened at B.
The replay uses those opened rows and source copies in B event order. Its
first-solvable times assume zero computation and sufficient row retention.
Native readiness, TUN delivery and the Linux cumulative ACK have separate
witnesses. The first untraced WAN packet reached B at 866.228 ms.
[Rank replay and measured delivery times](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/forward-rank-joined.json).

TCP payload at offset 25,396 required sources 36 and 37. B opened source 36
at 142.029 ms. Neither WAN tap saw the original source 37. Five received
ordinary repair equations included 37, with seven to nine unknowns at their
respective arrivals. Together with all earlier arrivals they left source 37
undetermined. The named retry in packet 116 made it solvable at 218.546 ms.
The TCP segment appeared at B TUN at 218.601 ms. B emitted the covering ACK
at 218.640 ms. The same ACK reached A at 255.046 ms, 13.401 ms after A
emitted its inner retransmission. Another 73.190 ms native gap closed when
source 2042 arrived in a named retry. That arrival unlocked four sources at
once. A later 109.223 ms gap occurred outside the bounded row trace.

An offline counterfactual substituted an eight-source equation in every
fourth local repair slot, retaining the original sender seed, packet loss,
global and tail rows and named retransmissions. Each replacement fit the
original slot. Selecting the latest complete group advanced S2042 by
94.911 ms, because the replacement excluded the other unknown S2048.
The one replacement covering S37 was lost. Across 2826 prefix endpoints,
105 advanced and 859 were delayed. The first source still missing at the
trace cutoff moved from 2144 to 2140. The cutoff precedes the measured
end-to-end drain. This gives no basis for replacing the existing policy.
[Fixed-slot equations](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/forward-shifted-eight.json)
and [cumulative-prefix comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/forward-shifted-eight-prefix.json).

Across the 1603 native records with complete fragment mappings, the P99
from all of a record's own source fragments becoming solvable to native
readiness was 95.595 ms. Re-encoding 3584 original A TUN packets on their
actual channels reproduced the record identities and 512 header contexts.
All 17 tail records were two-fragment TCP header deltas. Both fragments
were available from original systematic packets. The receiver still
needed earlier records to reconstruct the header from its latest reset.
Waiting for those dependencies accounted for 94.935 to 103.069 ms.
Once the chain was solvable, native readiness followed in 0.476 to
4.122 ms. During each wait, 161 to 177 later records on that channel
reached native readiness. The observed dependency is specific to this
cohort of the bounded trace.
[Original fragment arrivals, reconstructed header dependencies and actual readiness](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/forward-rank-tail.json).

On the same tape, a counterfactual encoded each delta against its existing
eight-record reset context. A fresh decoder reproduced each original IP
packet byte for byte. Readiness would still require the anchor and all of
the record's own fragments. Of 1603 records, 371 would meet that condition
sooner. Five would still wait for their anchor, with a maximum of 71.420 ms.
All 17 tail records already had the anchor when their own fragments became
solvable. The 1603 codec bodies grew by a net 562 bytes over 2,317,902 bytes.
This excludes an anchor reference, negotiation and changes to packetization,
loss, recovery and TCP. The current receiver also has a measured P99 of
22.608 ms between mathematical availability of its complete context chain
and native readiness across the full cohort. The 4.122 ms upper bound above
applies only to the original 17 tail records.
[Fixed-anchor comparison and byte checks](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/forward-rank-anchor.json).

The existing wire grammar also permits more frequent full-context records.
Re-encoding all 3584 native packets at serial intervals of 8, 4 and 2
produced 512, 1194 and 3580 contexts. Since the context has its own record
serial, these intervals average about seven, three and one native packet
per context in this stream. At intervals 4 and 2 the sum of contexts, bodies
and fragment headers rose by 36,767 and 165,679 bytes respectively over
the 5,288,135-byte control. The body fragment counts stayed identical. Of
the original tail cohort, 11 and 17 records respectively no longer depended
on the particular earlier delta that had held them up. A new context still
has to arrive before its referencing record can be delivered.
[Re-encoding cost and dependency changes](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/refresh-cadence-codec.json).

An isolated release build then changed the sender refresh interval from 8
to 4. The Common plan bytes and observation settings matched the control.
Both real Linux runs used seed 31248 on the same single-flow workload.

| Context refresh interval in record serials | Steady goodput, Mbit/s | Write-to-read P99, ms | Steady TCP repeats | A TUN ring drops | Final unfilled TCP gaps |
| --- | ---: | ---: | ---: | ---: | ---: |
| 8, current runtime | 51.568 | 864.720 | 369 | 0 | 0 |
| 4, experimental build | 49.642 | 768.998 | 91 | 0 | 0 |

All 91 steady repeats in the four-record run were visible on A TUN after
B had sent a covering cumulative ACK. For 90 repeats the ACK was still
on its way. The median remaining time was 5.368 ms. Across the 1405
fully mapped startup records before 806.803 ms, the P99 from own fragments
being solvable to actual native readiness was 15.370 ms. The eight-record
trace covered 1603 records before 866.228 ms. All 17 records in the
eight-record trace's slowest 1% reached readiness after the four-record
trace had ended. These unequal trace horizons prevent attributing the
full difference in this startup P99 to the refresh interval. Restricting
both captures to the first 806.800 ms gives 1460 and 1401 complete records.
On this common horizon the own-fragment-to-native-ready P99 was 49.515
and 15.370 ms, the median was 1.740 and 3.479 ms and the maximum was
72.935 and 71.852 ms. The median sender cwnd fell from 623 to 557 MSS.
The median smoothed RTT fell from
144.731 to 130.872 ms.
Median cwnd divided by RTT implied 49.80 and 49.28 Mbit/s respectively.
The four-record run ended with zero outer debt. In this one pair the
throughput target remained open.
[Four-record run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-4c3c597/arm-evidence.json),
[common startup horizon](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-4c3c597/shared-cadence-rank-prefix.json),
[replayed header dependencies](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-4c3c597/forward-rank-tail-cadence4.json)
and [Linux socket samples](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kernel-control-immediate4-cubic-revq-forward-records-verdict-seed31248-4c3c597.json).

The run delivered 51.568 Mbit/s with 864.720 ms first-write-to-read P99,
369 steady repeated segments, zero sender TUN drops and no final TCP gaps
or outer debt. For 313 repeats, B had already emitted a covering cumulative
ACK when the repeat was captured at A, but A had yet to see a covering ACK.
The median time between those two ACK observations was 36.475 ms and the
maximum was 39.311 ms. In 13 cases the repeated data beat all prior attempts
to B. Linux sampled a median smoothed RTT of 144.731 ms, cwnd of 623 MSS
and 3,161,632 unsent bytes. For the slowest 1% by write-to-read time, the
paired mean was 781.29 ms from application write to A TUN and 879.47 ms from
write to completed read. The adjacent traced run delivered 55.786 Mbit/s
and 800.109 ms P99. The common seed fixes the loss generator, while
scheduling changes which logical packet occupies a given slot.
[Steady retransmission races](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/retrans-races.json),
[paired application delays](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/record-byte-delay.json)
and [sender socket samples](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kernel-control-immediate4-cubic-revq-forward-records-verdict-seed31248-62af965.json).

Two real Linux endpoints also drove the Python Packed transport in a
controlled, single-loss experiment. With ordered delivery the stream
completed without an inner repeat. With independent delivery B saw 13 data
segments above the hole and issued SACKs. A received a SACK at 143.679 ms,
dispatched the outer named retry at 144.607 ms and exposed the inner retry
on TUN at 144.616 ms. B recovered the original at 180.058 ms. Both
endpoints verified the same 256 KiB payload. This finite arm used zero
ordinary FEC to isolate the two feedback loops.
[Endpoint configuration, custody and commands](../../work/c48-parity-20261119/kernel-python-closed-loop/README.md).

An optional Python startup study issued one partial XOR after 1 ms idle,
using the first 64 KiB of original forward IP bytes and the existing near8
credit. A two-seed, 16-arm comparison kept the ordered and early-delivery
paths separate. One seed sent zero partial rows. In the other, removing one
received equation from the same arrival tape delayed S20 by 72.113 ms
on the ordered path and S14 by 142.265 ms on the early path. On the early
startup-open arm, enabling partial rows reduced P99 and repeats but reduced
goodput from 0.447 to 0.345 Mbit/s. All arms drained their submitted data.
This study establishes no throughput qualification for a Rust mode.
[Paired study](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/idle-prefix-v1/comparison.json)
and [recipient-byte-only S20 recovery](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/idle-prefix-byte-check-frozen2/summary.json).

Rust native preparation now reserves global receipt-counter capacity before
extraction and checks the selected channel when producing a physical-write
token. Receiver deadline recomputation visits occupied record slots and
stops after counting the retained source proofs. In a release measurement
with a single remaining record and zero proofs, median recomputation fell
from 8.96 to 0.08 microseconds. A lone proof at physical slot 8191 still
required scanning the preceding slots. These are costs of individual owner
operations.
[Isolated CPU measurements](../../work/c48-parity-20261119/deadline-owner-cost/README.md).

### Fixed-anchor IP header compression

The authenticated forward native policy selects a full TCP-header context
(tag 8), an exact raw IP packet (tag 2), or a fixed-anchor delta (tag 11).
The delta contains one byte of backward record distance and the full encoded
inner delta. The receiver checks the exact record number on the same channel
and within the same receive epoch. Either a complete live context or one of
eight retained context slots per channel can satisfy the reference. An
incomplete context delays its dependent records until recovery. Other
decodable groups can cross that hole. Physical delivery is committed once.

The fixed-anchor sender and receiver tests check fragment reordering, raw IP
fallback, byte-exact decoding, stale references, reserved backing, and replay
after an old hole closes. The matched Linux workload keeps the reverse header
policy, 8192/128 recovery windows, short source copies, named retries and
authenticated management in both arms. The extra two bytes count before
fragmentation and packing and can change how many physical sources are sent.

The archived forward input contains 3,584 original IP packets. Both encodings
reconstructed every packet from received bytes. The first-send IP byte count
increased by 8,889 (0.158%) with a fixed anchor. The baseline reproduced all
5,430 Packed sources and their copy counts byte for byte. With a calibrated
decoder on a 384-packet prefix, dependency wait P99 fell from 71.762 ms to
zero and admission-to-ready P99 changed from 108.307 to 108.277 ms. After
dropping all three transmissions of an anchor and the first send of a data
source, nine packets from later groups arrived first; ordinary FEC subsequently
recovered both old sources. The model used the archived input admission times.
[All inputs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/fixed-anchor-model-all.json)
and [costed and forced-loss prefix](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-62af965/fixed-anchor-model-costed-384.json).

The Linux comparison used one frozen release, one native TCP CUBIC flow,
4 MiB application outstanding credit, 90 Mbit/s offered load, 100/10 Mbit/s,
35 ms per direction, and 15% loss per direction with seed 31248. Throughput
and retransmissions below cover the same ten-second observation window.

| Forward headers | Application Mbit/s | First-write-to-read P99 ms | Repeated TCP segments at A | First arrivals at B rejected by PAWS, among repeated segments | A TUN drops | Final TCP gaps |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Chained | 14.075 | 5043.194 | 292 | 105* | 0 | 0 |
| Fixed anchor | 20.697 | 2248.718 | 518 | 406* | 0 | 0 |

\* The join counts repeats for which every repeated byte had already arrived
at B, the observed cumulative ACK still lagged, and the receiver kernel
reported PAWS on each first-arriving skb covering those bytes. It counts
repeated TCP segments in the sample. The full-flow kernel ledger counts
dropped skbs. Both outer recovery directions reached zero after EOF.
[Chained run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-49fd4e2/arm-evidence.json)
and [fixed-anchor run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-49fd4e2/arm-evidence.json).

Over the first 512 KiB of TCP sequence space the common analysis covered
524,284 original bytes. Earliest mathematical availability of the packet's
own sources to observed native readiness had P99 76.904 ms with chained
headers and 1.599 ms with fixed anchors. Admission, UDP service and ACK timing
also varied across runs. The earlier chained run on another build achieved
51.568 Mbit/s. A single fixed seed identifies loss by physical packet ordinal;
these paired observations do not qualify a throughput improvement.
[Matched startup intervals and cohorts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/negotiated-record-pair-with-bins-49fd4e2.json).

On the fixed-anchor run, the second transmission of TCP offset 3,587,988
left A TUN 243.136 ms after its original and reached B TUN 6.615 ms before
it. It filled the current receive gap with a newer TCP timestamp. B then
rejected later-arriving segments with older timestamps, including previously
unseen payload. Their retransmissions in turn advanced the accepted timestamp.
Twelve timestamp-advancing skbs trace back to that first race across all 413
observed PAWS drops in this run. For the 406 steady repeats with matched
first-arrival kernel drops, B's cumulative ACK covered the bytes a median
173.193 ms after the rejected arrival. Among the slowest 1% of application
writes, the paired means were 2,239.803 ms before the first corresponding
bytes appeared at A TUN and 2,280.064 ms to completed application read.
[Steady repeats and kernel verdicts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-49fd4e2/repeat-verdict-join.json),
[timestamp-changing attempts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-49fd4e2/timestamp-cascade.json)
and [paired application delays](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-49fd4e2/record-byte-delay.json).

The original fixed-anchor packet at offset 3,587,988 spent 17.717 ms from
admission to Packed output, 284.715 ms from Packed output to B native
readiness, and 0.028 ms from readiness to B TUN. The retry traversed the
middle interval in 48.256 ms. The original entered A TUN after the capture
had exhausted its 4,096-packet outer ledger. The remaining events establish
the delay interval; the per-source send, loss and repair events inside that
interval are unresolved. Record 2873, which used the same anchor 2872 as
the missing record 2874, was already ready by 2204.929 ms. Records 2875
through 2878 followed by 2205.236 ms. This excludes the missing anchor
and waiting for earlier header deltas as causes for at least the last
173.852 ms of record 2874's wait. In the chained arm the original at offset
1,177,068 reached A TUN at 1228.829 ms. Named retries made its two sources
available by 2319.797 ms. Its context chain became solvable at 2803.576 ms,
31 ms after the inner retry had already reached B TUN.
[Per-attempt forward custody and shared-anchor witnesses](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/paws-root-wire-and-context-49fd4e2.json).

The workspace check completed the new protocol cases, Clippy and formatting.
Two existing real-time tests failed during its workspace test stage. The
one-second TLS pairing case saw EOF and the raw liveness case counted one
extra control packet. Each passed on an isolated rerun of the same binary.
The remaining original check stages completed separately, including 1,734
simulator tests and two subtests. The original command exited with status 1.
[Workspace check](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-9/result.json),
[TLS rerun](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-9/retry-base-deadline.log),
[liveness rerun](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-9/retry-raw-liveness.log)
and [remaining stages](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-9/remaining-commands.json).

### Single-flow socket credit and the two directions of recovery

The C48 Python study now accepts `--application-credit-bytes`. Its optional
producer writes fixed-size records on the probe's absolute offer schedule.
It charges both unsent and transmitted unacknowledged bytes against socket
credit. The TCP controller separately limits which written bytes it sends.
Written bytes can still be sent during drain. Reports count offers missed at
cutoff and written bytes outstanding at the drain deadline separately.
The simulator assumes immediate, successful socket writes when it has credit.
It still sends one TCP segment per 512-byte write and uses cumulative NewReno
recovery. Linux can combine application writes into MSS-sized segments and
uses SACK. See the [producer](../../simulator/src/l2tunnel_sim/tcp_application.py)
and [study entry point](../../simulator/studies/packed_spare_c48.py).

One 90 Mbit/s offered flow with 4 MiB credit on the 100/10 Mbit/s, 70 ms
RTT, 15% iid loss paths gave these results. Throughput counts completed
application payload during seconds 2–12. The P99 covers completed records
through the drain deadline. Unconfirmed includes socket-unsent records.

| Python release policy | Steady Mbit/s | Issue to read P99, ms | Write to read P99, ms | TCP repeats through drain | Unconfirmed records at end |
| --- | ---: | ---: | ---: | ---: | ---: |
| FIFO, historical TCP producer | 77.464 | 482.817 | unavailable | 0 | 0 |
| FIFO, paced application | 77.783 | 548.009 | 921.903 | 0 | 0 |
| Early independent delivery, paced application | 0.421 | 966.539 | 59,215.496 | 233 | 3,066 |

The paced FIFO case completed all 215,830 writes. The early-release case
issued 6,600 of 9,663 writes by the end of drain and completed 6,599 reads.
Its growth in write latency includes bytes held at the socket by the model
TCP sender. It recorded 121 established-DATA timestamp rejections.
These experiments establish how release order changes this simulator's
endpoint behavior. They do not qualify a Linux congestion controller,
the production early-release requirement, or a Rust throughput change.
[Historical producer control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-control-fifo.json),
[paced FIFO](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-c48-fifo-4m.json) and
[paced early-release adapter](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-c48-early-4m.json).

An independent application replay consumed the *captured* cumulative ACKs
and the receiver's actual completion times. Its ideal writes predicted
write-to-read P99 of 5,043.282, 2,256.035 and 723.994 ms for the chained,
fixed-anchor and extended-trace captures respectively. Measured values
were 5,043.194, 2,248.718 and 723.727 ms. This validates the aggregate
timestamp interpretation conditional on those ACKs and reads. Individual
write times differed. The replay takes both network and receiver service
as inputs, so it cannot predict throughput.
[Chained](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-49fd4e2/application-credit-replay.json),
[fixed](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-49fd4e2/application-credit-replay.json),
[extended](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-b34b58c/application-credit-replay.json).

In the extended fixed-anchor Linux run, source 3407 completed the TCP
packet at offset 3,196,604. Its first transmission had no WAN observation.
Four covering repairs opened before recovery; the available equations did
not solve this source. A named retransmission left at 953.350 ms and B
opened it at 988.872 ms. B's first covering cumulative ACK appeared at
990.773 ms. A retransmitted the inner segment at 1047.155 ms and saw that
ACK at 1085.353 ms. The 94.580 ms ACK path includes at least 56.99 ms
outside B egress to A WAN; the trace does not locate that remainder on
either endpoint. The earlier outer gap request itself had two plausible
physical packets. Each queued behind at least 15,146 bytes of reverse data,
explaining about 12.3 ms of its outbound wait at 10 Mbit/s. No PAWS drops
were recorded in this arm. It delivered 59.546 Mbit/s with 177 steady
repeats. Capture limits excluded the corresponding source events from the
older 284.715 ms case.
[Per-source evidence](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-b34b58c/wire-gap-with-extended-observer.json)
and [return-path timing](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-b34b58c/root-reverse-physical-queue-49fd-extended.json).

Across the slowest 1,705 of 170,446 completed writes in this Linux arm,
mean write-to-read time was 734.84 ms. Paired means were 620.91 ms from
application write to A TUN, 80.57 ms until B saw the write's own bytes,
33.28 ms for the preceding bytes to become contiguous and 0.08 ms for the
application read. P99 across all writes was 723.73 ms. B had already
cumulatively acknowledged the entire repeated range before the inner
retry left A in 158 of 177 cases. The remaining 19 had that ACK at B
before the repeated copy arrived there.
[Paired record times](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-b34b58c/record-byte-delay.json)
and [sender and receiver timing counts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-b34b58c/arm-evidence.json).

The extended trace covered all outer packet numbers through 2.166 s after
application start. The slowest 111 traced sources included 83 carrying a
first fragment and 28 carrying only last fragments. Removing received
named source retransmissions while keeping all other equation arrivals
delayed all 111; only 36 subsequently became solvable before the trace
ended. Replacing the 48 paid near-eight repair slots with one already
available final-fragment source each saved 28,751 IP bytes on this tape.
Of 7,498 fully traced records, five would become solvable earlier and 205
later. The group containing source 3407 had no paid slot to replace.
[Physical byte counts and conditional rank replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-b34b58c/fragment-role-and-paid-slots.json).

In the earlier chained Linux arm, both copies of missing context 1351
reached B WAN during a 334.625 ms native-write service interval. B opened
112 of 268 arriving outer packet numbers after a long wait and never opened
the following 156, including those two copies. The same socket's drop count
and the namespace UDP receive-buffer error count both grew by 304 across
the run. Three samples found the daemon main thread in `rq_qos_wait`.
A matched observer run captured all 56,510 TUN writes at B, none over 5 ms,
and had zero UDP buffer errors. The original stall did not recur, leaving
its exact blocking call unresolved. The observer run delivered 54.473 Mbit/s
with 750.494 ms write-to-read P99 and 207 steady repeats. Both runs drained.
[Original socket evidence](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-forward-records-verdict-seed31248-49fd4e2/receive-socket-stall-v2.json)
and [matched syscall observations](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate5-cubic-revq-forward-records-verdict-tunwrite-seed31248-49fd4e2/native-write-comparison.json).

A historical reverse-ledger capture on tree `b78b47d` identifies exactly
where one three-block SACK waited. Its 80-byte IPv4 packet became record
3463 on B. At MUX admission, the 343 earlier records on its flow had
entered the MUX and were still waiting for packer admission. B took
81.093 ms to admit this record to the packer. It took another 1.347 ms
to admit the other seven records in its source, then 18.090 ms until
physical selection. Meanwhile B selected all three copies of each of the
ten preceding short sources and two repairs. Across the 81.093 ms interval,
B submitted 101,637 IP bytes at egress, including 60,194 bytes in second
and third copies. A WAN to A TUN took 0.164 ms for the direct carrier packet.
An aggregate codec-stage refusal count cannot locate a refusal for this
specific record. There were 2,918 SACK records with a matching native digest
and complete stage evidence. Their median and P99 residence from B MUX to
packer were 25.668 and 79.781 ms. This arm used chained forward headers.
[Per-record queue, physical stages and cohort](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-records-verdict-seed31248-b78b47d/reverse-sack-r3463-queue.json).

During the 100.624 ms from MUX admission to the first socket acceptance
for R3463, the B egress hook counted 125,417 IP bytes. Second and third
copies used 73,474 bytes. Of the 53 sources sent for the first time in
that interval, 46 reached the WAN on their first copy, six on the second,
and one on the third. Reassigning equal-length slots with a maximum 2 ms
copy deferral and the observed loss sequence would advance this ACK's first
WAN arrival by 3.224 ms. A 1 ms bound would delay it by 0.912 ms. These
conditional changes include all three copies and do not simulate the TCP
response. [Physical byte ledger and slot replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-records-verdict-seed31248-b78b47d/r3463-reverse-byte-window.json).

An offline byte experiment ran the frozen Rust Packed encoder on the
captured ACKs. It applied one independently decodable LZ4 block per pure
short-ACK source, with a three-byte compressed header and raw fallback.
All 4,092 original IPv4 packets round-tripped byte for byte. Of 749
identified sources, 686 compressed and 63 stayed raw. Their 2,248 actual
physical sends, including all copies and one named retry, would shrink
from 1,126,164 to 617,544 IP bytes. The 527 groups beyond the native
identity horizon and two mixed groups retained their historical cost.
Repairs and feedback also kept their measured cost. For the fully
covered 1.379 s prefix this saves 38.71% of all reverse IP bytes.
Across R3463's two waits, the savings total 53,709 IP bytes, equivalent
to 42.97 ms of service on a continuously busy 10 Mbit/s link. This
experiment prices packets on a fixed trace; compression CPU costs,
feedback, kernel congestion control and native goodput require a closed-loop
measurement. The measured Rust deployment used the existing wire format.
[Byte-exact source replay and IP accounting](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/immediate4-cubic-revq-records-verdict-seed31248-b78b47d/reverse-packed-lz4.json).

The optional Rust Records trace now accepts
`L2TUNNEL_RECORD_TRACE_DIRECTION=both`. The matched harness exposes
`--trace-both-records`. Each direction has its own capped ledger on the
same connection, and each endpoint emits one UDP send-yield ledger.
`native_ready` samples the monotonic clock after native preparation returns.
Older traces used the start tick of that service turn. A bidirectional UDP
fixture checks both native packet digests and the identities committed after
device writes. The earlier Linux measurements above used one direction per
run. [Runtime observer](../../crates/l2tunnel-runtime/src/secure_udp/transport_reverse_trace.rs)
and [UDP fixture](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_clock_tests.rs).

### Negotiated reverse Packed ACK compression

The Rust candidate and control use the same forward near8 fixed anchors.
The directional descriptor changes byte 1243 from 5 to 9 in the reverse
direction. Reverse selection is observable through the shared service
status. The measured plan reserves an additional 19,446 bytes across both
roles. Each sender caches one immutable source representation. Authentication
precedes restoration of the complete source, including every checksum, SACK
block and timestamp. The three copies and named retries retain their identities.
The endpoint tests cover a budget one byte below the true compressed cost,
all three copies lost, named retry recovery, and recovery from an ordinary
equation identical byte for byte to the uncompressed control.
[Codec](../../crates/l2tunnel-codec/src/packed_envelope/ack_lz4.rs) and
[rolling integration](../../crates/l2tunnel/src/rolling_records/ack_lz4.rs).

The Python C48 study accepts `--reverse-ack-lz4` with the paced application
writer. The model keeps Ethernet headers in its native records, uses its
existing compact framing, and models cumulative ACK recovery. It runs a
real bounded-size LZ4 block codec; CPU service time for this block is not
modeled. Wire size, reverse loss, retransmission credit and link serialization
use the selected representation. FEC still sees the canonical source bytes.
Under the fixed single-flow workload the FIFO reference produced no multi-unit
reverse sources and saved zero IP bytes. Its 77.783 Mbit/s and 921.903 ms
write-to-read P99 were unchanged. The early-release run reduced reverse
source and retry traffic by 190,540 IP bytes versus sending those same
attempts without compression. Its steady throughput rose from 0.421 to
0.472 Mbit/s, through-drain TCP retries fell from 233 to 220, and 3,053
writes still lacked cumulative ACK at the drain deadline. This simulator
does not recreate the Linux SACK traffic seen on the native reverse path.
[FIFO receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-fifo-4m-ack-lz4.json) and
[early-delivery receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-early-4m-ack-lz4.json).

A Linux TUN/UDP pair used the same frozen executable, one CUBIC flow,
4 MiB of unsent plus unacknowledged application data, 90 Mbit/s offered,
85 Mbit/s sender TUN pacing, and 100/10 Mbit/s links. Each direction
had 35 ms delay and 15% loss. Both runs used seed 31248, two seconds of
warmup and a ten-second steady measurement.

| Metric | Fixed anchors | Fixed anchors with reverse ACK compression |
| --- | ---: | ---: |
| Forward application goodput (Mbit/s) | 35.447 | 57.603 |
| First application write to full read P99 (ms) | 1,044.429 | 769.205 |
| Scheduled write to full read P99 (ms) | 7,845.389 | 4,888.248 |
| Inner TCP repeats at sender TUN during measurement | 117 | 109 |
| Sender TUN payload attempts during measurement | 30,632 | 49,902 |
| Reverse systematic source IP size, mean / P99 (bytes within trace) | 349.46 / 778 | 247.75 / 381 |
| Reverse SACK TUN-to-TUN P99 (ms, full flow) | 43.973 | 44.215 |
| Sender TUN drops / final TCP gaps | 0 / 0 | 0 / 0 |

Throughput and repeated payload attempts use the ten-second steady window.
Application percentiles cover writes through drain. Within the steady
window repeated payload accounted for 169,416 of 44,355,136 TCP bytes in
the control and 157,832 of 72,258,096 in the candidate.

In the candidate, 997 source identities containing 4,088 native ACKs
account for 2,993 physical sends. Their observed IP lengths all matched
the encoder. The same attempts would have used 1,215,647 bytes in the
original representation and used 726,779 bytes on the wire. Both arms
drained to zero in both directions and delivered all written bytes with
matching hashes. The single pair establishes closed-loop operation and
the measured byte saving. Reordering the send stream changes which
packets a seeded link drops, so this pair cannot establish a stable
goodput gain or general carrier parity.
[Control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor6-cubic-revq-both-records-verdict-seed31248-2a41a18/arm-evidence.json),
[candidate](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-both-records-verdict-seed31248-2a41a18/arm-evidence.json)
and [packet length audit](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/ack-lz4-paired-physical-2a41a18.json).

For 81 of the candidate's 109 steady inner repeats, the receiver had
already sent a covering cumulative ACK that was still on its way back.
One covering ACK had reached the sender TUN. For the remaining 27, seven
original byte ranges were present behind an earlier gap and 20 arrived
after the sender initiated the repeat. The receiver generated a covering
ACK for every range before its repeated copy arrived. Among the slowest
1% of application records, 592.331 ms on average elapsed between writing
at the sender and seeing its covering bytes at the sender TUN. This is a
paired-record mean, distinct from the overall latency percentile above.
The sender's socket had a median 2,635,776 unsent bytes.
[TCP sequence, ACK, socket and EOF audit](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/matched-tcp-window-2a41a18.json).

The forward originals behind those 109 repeats took 160.830–300.321 ms
from A TUN to B TUN (median 237.783 ms). After the byte prefix closed,
B emitted its first covering ACK in a median 0.045 ms. The first covering
ACK returned to A in a median 36.470 ms. For each retry, subtracting the
minimum 35 ms return propagation from its departure gives the last possible
time B could generate a covering ACK. Among the 108 repeats still lacking
an ACK at A, 75 were missing both the range and at least one preceding
range at that deadline, 16 were missing only the range, 14 were waiting
only for earlier bytes and three already had a covering ACK on the return
path. These counts evaluate an earlier instant than the 81 in-transit
ACKs at retransmission time. Linux recorded fast recovery and zero
phase timeouts. The trace does not attribute a specific loss detector to
an individual retry.
[Per-range arrival and return deadlines](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-both-records-verdict-seed31248-2a41a18/retry-forward-deadlines.json).

All 109 ranges were overtaken by at least 42 later first-send segments
within the next 64 MSS. At the 35 ms return deadline, the 75 cases
missing both their own bytes and earlier data lacked a median of four
earlier segments (maximum 12), all already past A TUN. The targeted
receiver already groups up to eight source IDs per selection. These
observations locate a cluster of older forward data that needs to
arrive sooner. The capped outer ledger does not distinguish first
source send, first usable equation and named retry for the steady
cohort. An earlier 16,384-PN ledger overlaps 165.753 ms of that arm's
steady sample and contains zero steady retries.
[Overtaking TCP sequences](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-both-records-verdict-seed31248-2a41a18/retry-forward-neighbors.json)
and [coverage of the extended ledger](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/anchor4-cubic-revq-forward-records-verdict-seed31248-b34b58c/steady-16384-forward-trace-coverage.json).

The bounded startup ledger identifies one forward example separately from
these steady counts. The inner segment at relative bytes [28292, 29740)
needed sources 40 and 42 and fixed anchor 36. The anchor and source 40
were available by 142.803 ms. The systematic copy of source 42 never
appeared at B. At 152.194 ms one received repair equation still had
two unknowns, 42 and 43. The named repeat reached B at 225.157 ms. B
delivered the original reconstructed segment about 0.072 ms later.
Linux had already repeated it at A at 212.949 ms. Delaying the
cumulative ACK or delivering already-decoded later records more quickly
could not supply the missing byte range.
[Source packets, repair supports and TCP sequence](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-both-records-verdict-seed31248-2a41a18/longest-covered-forward-missing-at-retry.json).

An offline sensitivity reduced the support of alternating startup local
rows by one source, preserving the observed packet slots, global/tail
rows and named sends. One parity made source 42 identifiable 72.963 ms
earlier on the run that suggested the change. Across 5,271 complete
records in three held-out runs with the same seed, just one became
solvable earlier, by 0.017 ms, and all three P99 values were unchanged.
The opposite parity delayed five records by up to 121.862 ms. These are
first-solution times, including the record's exact fixed anchor.
[Independent arrival-tape comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/early-local-end-independent-summary.json).

The workspace check found one stale descriptor test that still classified
selector 9 as unknown. The corrected fixture tests an unassigned selector
and verifies that the known ACK-compression selector is rejected for the
incompatible Ethernet profile. The focused descriptor test, formatting,
Clippy and all remaining check stages passed, including 1,739 simulator
tests and two subtests. The original workspace invocation recorded the
fixture failure.
[Original run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-12/result.json) and
[verification after the fixture correction](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-12/resume-result.json).

### Inner TCP packetization and steady forward recovery

The C48 Python study can now offer the original 512-byte application writes
to a byte stream and segment available written data up to an explicit TCP
MSS. Under window pressure several writes can share one segment, and a
write that crosses a segment boundary completes when its last byte becomes
contiguous. Retries retain the original stream offsets and lengths. The
4 MiB application limit charges unsent and unacknowledged bytes. A separate
option applies the Linux UDP planner's 1,251-byte Packed limit and eight-unit
cap before physical copies or repair. The existing model's 1,460-byte FEC
storage supports the smaller records with zero extension. These two options
are independent, and the historical study parameters stay available.
[Stream writer](../../simulator/src/l2tunnel_sim/tcp_application.py),
[Packed geometry](../../simulator/src/l2tunnel_sim/packed_wire.py) and
[study entry point](../../simulator/studies/packed_spare_c48.py).

With one flow, 90 Mbit/s in 512-byte offers, a 4 MiB application limit,
100/10 Mbit/s, 70 ms propagation RTT, 15% loss in each direction, and
reverse ACK compression, the following simulator runs use the same
1,251-byte packing geometry. The throughput window is ten seconds.
Application P99 spans completed writes through drain. The forward recovery
share is the sum of requested or probe repeats, ordinary repair and near8
repair IP bytes divided by all forward IP bytes offered through drain.
It excludes extra systematic copies charged as sources.

| Python delivery | Segment size | Mbit/s | Write-to-read P99 ms | Inner retries through drain | Written records awaiting cumulative ACK at drain | Forward recovery share |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| FIFO | One 512-byte write | 77.783 | 921.903 | 0 | 0 | 17.30% |
| FIFO | Up to 1,448 bytes | 68.583 | 676.904 | 0 | 0 | 25.43% |
| Early | One 512-byte write | 0.383 | 59,528.677 | 209 | 3,028 | 29.95% |
| Early | Up to 1,448 bytes | 1.289 | 29,221.391 | 98 | 0 | 32.74% |

The FIFO stream run emitted 69,796 full-size segments out of 70,488.
It fragmented 69,925 native records, including context records. The
one-write FIFO control fragmented zero. The model still uses synthetic
TCP with cumulative ACK/NewReno recovery. Linux uses real TCP segments,
SACK and kernel timers. All four rows are simulations, and throughput
qualification against the original FIFO reference remains open.
[FIFO one-write](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-fifo-native1251-512-sealed.json),
[FIFO stream](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-fifo-native1251-1448-sealed.json),
[early one-write](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-early-native1251-512-sealed.json)
and [early stream](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-early-native1251-1448-sealed.json).

A Linux run of the fixed-anchor, reverse-ACK-compressed UDP profile
extended the optional forward record trace through the entire steady
interval. It joined 30/30 repeats and 30/30 original IP packets to A
packing, every source fragment's physical send and B native output. Both
ledgers had zero overflow. Goodput was 52.530 Mbit/s and write-to-read
P99 was 774.334 ms, with zero sender TUN drops, zero phase timeouts and
zero final TCP gaps. The trace can affect scheduling. This sample has
its own loss realization and does not identify the 109 earlier repeats.
The forward rank replay consumed 97,094 authenticated B arrivals and
checked 3,091,359 coefficients against the frozen Rust field. At A's
retry time B had already issued a covering cumulative ACK in 21 cases,
was waiting for an earlier byte range in five, and still lacked the
repeated bytes in four. All 30 covering ACKs preceded the repeated
copies at B.
[Coverage](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-forward-records-verdict-seed31248-9335271/steady-trace-coverage.json),
[causal replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-forward-records-verdict-seed31248-9335271/steady-forward-retry-causal-join.json)
and [Linux measurements](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-forward-records-verdict-seed31248-9335271/arm-evidence.json).

For the 21 segments already cumulatively acknowledged at B when A retried,
the covering ACK reached A a median 2.008 ms after the repeat (range
1.172–7.689 ms). Its return trip across all 30 cases had a median of
37.041 ms. Among the original segments, the median time from A TUN to
the last first systematic socket acceptance was 171.044 ms. The median
from that acceptance to the earliest solution using authenticated B opens
was 130.420 ms. Separately, B native-ready to completed TUN write had
a median of 0.096 ms. These are stage distributions, and summing their
quantiles does not give a frame latency quantile.

For record 53,804 the three required sources had authenticated at B by
10,729.409 ms, yet B produced the native packet at 11,055.603 ms. Its
own head source 68,494 shared a one-second observation interval with
365 refused sources and 14 refused repairs. That run's open event precedes
FIFO admission and cannot identify individual refused packets. Removing
only the original of 68,494 from the algebra replay moved first solution
151.157 ms later. It still preceded actual readiness by 175.037 ms. B
produced 646 higher records on the same channel during the original
interval. The remaining delay cannot be assigned to one lost packet or
to a channel-wide in-order barrier from that capture.
[Receive interval](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-forward-records-verdict-seed31248-9335271/steady-receiver-longest-window.json),
[refusal counters](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-forward-records-verdict-seed31248-9335271/steady-receiver-refusal-bracket.json)
and [single-input sensitivity](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-forward-records-verdict-seed31248-9335271/steady-receiver-omit-pn97227.json).

On A, MUX admission to packer acceptance accounted for 158.436 ms at
the median and 167.766 ms at P99 among the 30 later-repeated originals.
A median 696 frames actually entered the packer ahead of each original
after its admission. The 45,141 steady originals that never repeated also
waited 88.215 ms at the median and 167.334 ms at P99. In 45 approximately
100 ms intervals with at least 90 ms median MUX delay, A's main thread
used about one core over 4.513 s, accumulated 5.497 ms runnable wait and
had zero process major faults. Six snapshots saw the downstream fresh queue
at eight of eight slots. Outer IP accepted by A's socket averaged
73.49 Mbit/s in the 8.056 s status interval. These observations locate
user-space backpressure; attributing the CPU time to individual functions
requires a profile. Shortening the MUX alone can move this wait upstream.
[Same-run sender stages and CPU](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-forward-records-verdict-seed31248-9335271/sender-stage-custody.json).

Holding each observed B ACK emission and A retransmission time fixed, a
35 ms return trip at the configured propagation floor would still have
missed 21 of the 30 retransmissions. Five segments already present at B
were waiting for earlier TCP bytes. Even with the ideal return trip, their
contiguous prefix would have needed to complete 59.871–61.303 ms earlier.
This timing bound does not change Linux TCP's SACK or congestion response.
[Per-sequence timing bounds](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-forward-records-verdict-seed31248-9335271/inner-retry-ack-propagation-floor.json).

The next build fixes a full-FIFO case in which the decoder is already idle.
It transfers the old data head to the available decode slot before admitting
the new input, preserving FIFO order, the original deadline and the work
grant. It also skips already-delivered record bodies during anchor scans.
Each forward authenticated open in the diagnostic now has an admission
outcome for the same epoch and packet number. Successful ownership includes
staged and duplicate inputs. Algebra over those inputs is an earliest-solution
bound; actual native readiness is recorded separately.

The manifest remained byte-identical. One Linux run delivered 55.757 Mbit/s
with 1,164.158 ms write-to-read P99 and 1,459 steady inner repeats. A TUN
recorded no drops, the TCP phase recorded no RTO, and final TCP holes and
both directions' outstanding sources were zero. The extra diagnostic events
and the changed closed-loop packet schedule preclude attributing the
difference from the preceding run to the idle-head change.
[Results](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/arm-evidence.json)
and [complete coverage](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/steady-trace-coverage.json).

B authenticated 105,351 input packets and refused 1,818 at the full FIFO,
including 1,156 first transmissions, 437 named retries, 214 second or third
copies, and 11 regular repairs. For source 10,416, its original and the next
four requested sends all crossed the WAN and authenticated at B. All five
were refused. The fifth requested send was accepted at 2,395.134 ms; inner
TCP had already repeated the affected bytes at 2,128.651 ms. The first
accepted covering equation had 316 unknown inputs with nonzero coefficients,
and increased rank by one without determining the source. Holding all
arrivals fixed and excluding the actually refused inputs moved the first
solution from before the inner retry to after it for 420 of the 1,459
repeat events. A total of 810 were delayed by more than 100 ms by this
admission difference. Several TCP repeats can depend on the same source.
Of 49,012 TCP attempts sent during steady time, 942 waited at least another
100 ms from accepted-input first solvability to native readiness. P99 over
all 49,012 attempts was 105.738 ms. The trace also recovered 12,113 sources at least
128 IDs behind the observed frontier, the oldest 3,201 IDs behind.
[Packet dispositions](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/per-pn-refusal-attribution.json)
and [accepted-input rank replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/steady-forward-retry-causal-join.json).

The 1,459 repeats break down further at the inner TCP boundary. For 880
the repeated byte range had yet to appear at B's TUN. For 229 it had
appeared but an earlier range was missing. For 53 the covering ACK had
already left B. In the remaining 297, the full prefix had appeared at
B's TUN and no covering ACK had been emitted. At 296 of those retry
times, kernel observations on both sides of the timestamp showed the
same outstanding first byte. For each of those bytes B had already
discarded a segment containing it with reason `TCP_RFC7323_PAWS`.
The 296 events share six distinct gaps. One more retry fell between
kernel samples. Across the whole flow 1,145 segments had this timestamp
verdict; each observed timestamp baseline had been advanced by an inner
retransmission. This is a second loss mechanism after authenticated tunnel
admission: a late original can reach TUN byte-exact and still fail Linux
TCP's timestamp check.
[Kernel receive cursor at each retry](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/kernel-prefix-at-retry-paws.json)
and [same-packet kernel verdicts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/receiver-verdict-gaps.json).

The densest 100 ms in this run explains how local drops can recur despite
successful WAN delivery. B opened 970 packets, accepted 407 and refused
563. The WAN-to-open P99 for the refused packets was 1.287 ms, and Linux
reported zero UDP receive-buffer errors. Incoming writes could fill the
256-slot recovery queue within a burst: 22 consecutive authenticated packets
were refused within 117 microseconds. Two complete main-thread samples
inside the longer 361.893 ms refusal interval recorded 199.995 ms on CPU
over 200.489 ms elapsed. In the 100 ms peak, native ready-to-write-completion
intervals occupied 47.460 ms of wall time. The traced Linux TCP function
occupied 5.683 ms of it. The remaining time cannot be assigned to GF work or
kernel syscalls from these observations. The previous UDP loop could read up
to 256 packets before returning to service Rolling work. At quiet times it
usually exhausted the socket sooner.
[Receiver service intervals](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/receiver-fifo-pressure.json)
and [batch configuration and counts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/b-udp-batch-before-pressure-yield.json).

Both runs sent periodic 128/8192 repair and named retransmissions. During
their respective interior status intervals they sent no additional near8
rows. The local spare-capacity gate closed on all 6,664 and 7,341 group
opportunities. Measured application reads and A socket IP acceptance in the
same intervals were 52.21/73.49 and 58.83/81.63 Mbit/s, respectively.
Flight and receive-buffer changes across interval boundaries affect these
ratios. [Prior interval](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz46-cubic-revq-forward-records-verdict-seed31248-9335271/status-window-accounting.json)
and [per-packet disposition run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/status-window-accounting.json).

The following original-UDP build returns to normal decoder service when a
read batch reaches the recovery FIFO's existing three-quarter threshold
and a Targeted decode job is active. It processes at least one packet in
each selected batch. The receiver can also use the remainder of its work
grant after ordered handoff to validate a contiguous Packed unit range and
deliver an already-solved unit. In the 12-source protocol example, source
7 was delivered on the recovery turn, previously seven service turns later.
Ordered handoff still advanced to source 12 and each native payload was
delivered exactly once.
[Ordered handoff regression](../../crates/l2tunnel/src/rolling_records/targeted_scheduling_tests.rs)
and [UDP pressure regression](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_targeted_tests.rs).

| Linux one-flow sample | Steady Mbit/s | Write-to-read P99 ms | Steady TCP repeats | B recovery FIFO refusals (whole flow) | B UDP socket drops | B WAN-to-authenticated-open P99 ms (steady) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Per-packet disposition / idle-head fix | 55.757 | 1,164.158 | 1,459 | 1,818 | 0 | 1.048 |
| UDP pressure and contiguous unit fix | 61.442 | 728.437 | 48 | 222 | 22 | 2.878 |

Both used the same negotiated plans, application credit, offer, loss seed
and link settings. Independent native packet timing changes which packets
encounter losses and which TCP responses follow. Treat each row as a
single Linux observation. A TUN had zero drops in both. In the second run
the new code yielded a UDP batch 2,269 times. The bound socket dropped
22 datagrams; 21 identified forward data packets reached the B WAN tap
and never opened. All 21 arrived in a 4.11 ms interval. The other socket
drop could not be identified by packet number. Among packets that opened,
56 steady arrivals took at least 10 ms and none took 100 ms. The socket
drop counters and the application-level FIFO refusals measure different
loss sites. [Linux results](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/arm-evidence.json),
[batch yields and residence](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/b-udp-pressure-read-custody.json)
and [bound socket counters](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/b-udp-bound-socket-drops.json).

Of the 48 repeats, 15 lacked the repeated bytes at B TUN, one awaited an
earlier byte, 23 had a B cumulative ACK in flight, and nine already had a
covering ACK at A TUN when the repeated segment appeared there. The A TUN
timestamp is a capture boundary; the kernel may have scheduled the repeat
earlier. All 48 were cumulatively acknowledged at B before their repeated
copy reached B. The source first needed for two adjacent ranges (16,394)
was among the 21 packets visible at B WAN without an authenticated open.
Across these 48, filtering the 222 known FIFO refusals did not change
mathematical first recovery. Both directions drained to zero outstanding
sources, with no final TCP holes. The replay solved 12,206 sources that
were at least 128 IDs behind the observed frontier.
[Per-packet replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/steady-forward-retry-causal-join.json)
and [refusal sensitivity](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/per-pn-refusal-attribution.json).

For these 48 originals the time from A's last first systematic socket send
to accepted-input first solvability had median 210.268 ms and P99 322.749 ms.
From first solvability to native-ready it was 13.243/41.106 ms, and from
native-ready to completed TUN write 0.095/0.377 ms. For source 16,394
the first named resend left A 132.233 ms after the first send. None of the
three named sends arrived before first solvability. Repair PN 23,974 added
one independent equation over 134 unknown sources. A later systematic
packet, PN 25,750, unlocked the retained equations. The two affected TCP
ranges had appeared again on A TUN 8.419 and 2.921 ms before this recovery.
[Socket loss and TCP range join](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/b-udp-bound-socket-drops.json).

Acceptance-to-delivery remains slow for a different population. Of the
53,191 TCP attempts emitted at A during steady time, 7,376 waited at least
100 ms from accepted-input first solvability to native readiness (P99
157.329 ms across all attempts). For every one of these 7,376, B had also
accepted a direct systematic copy of every required source and fixed anchor
at least 100 ms before readiness. For record 54,231 the direct sources
68,768 and 68,769 and the anchor source 68,760 were all present 193.995 ms
before readiness. These timings establish availability of the data to the
ingress owner. They do not timestamp its subsequent validation or the
record receiver's commit. This cohort has a longer P99 than the preceding
sample (105.738 ms), despite improved application P99 and throughput.
[Direct source and anchor evidence](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/direct-source-readiness.json).

On this same captured dispatch order, 7,333 of the 7,376 slow attempts had
a first accepted direct copy of every source and fixed anchor at least
100 ms before native readiness, with each such ID strictly above every
previously accepted systematic ID and outside the support of every prior
accepted equation. This count identifies candidates for a guarded direct
preview. It does not measure a speedup. Admission uses the call's dispatch
tick, and does not instrument completion of the decoder's validation.
[Per-source frontier replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/direct-source-frontier.json).

In a public-API fixture with two independent Packed sources (1 and 7)
and zero repair rank, the normal endpoint returned only source 1's frame
on the first fully funded turn. Although the record codec could already
prepare source 7's exact 40-byte TCP frame, the endpoint started another
decoder job for it. The fixture subsequently delivered all 12 frames once
and recovered source 0 from a repair alone. A separate counterexample
fed the endpoint a checksum-valid systematic source that contradicted a
previously accepted equation. The normal endpoint rejected the conflict
before releasing that frame. Any earlier delivery must preserve this
property as well as fragment, anchor, ordering and duplicate checks.
[Offline fixture output](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/targeted-direct-custody-probe.log).

### Where the remaining receiver delay accumulates

In the 61.442 Mbit/s sample, the application encountered its 4 MiB credit
cap 8,322 times. Across all 1,843 steady TCP_INFO samples Linux still had
at least 1,397,856 unsent bytes, with a median of 2,272,568 bytes. The
advertised receive window exceeded the congestion window in every sample.
Estimated flight was at least 95% of cwnd in 1,423 samples. The median
same-sample cwnd times MSS divided by SRTT was 61.26 Mbit/s. Increasing
application credit would not supply a missing input to the kernel at any
sampled instant. The estimate is descriptive and excludes intervals
between samples.
[Window and RTT measurements](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/steady-credit-cwnd.json).

Every one of the 7,376 slow attempts belonged to a TCP frame whose own
payload and anchor were mathematically available while an older outer
source remained unsolved. Of these frames, 2,890 were prepared before the
entire earlier source prefix became solvable. The other 4,486 were
prepared afterwards. For record 54,231 the first such gap was source
67,338. The prefix through the frame's last required source became
solvable 178.724 ms after the frame and its anchor. The actual runtime
prepared the frame a further 15.271 ms later. These events bound the
opportunity for earlier independent delivery. They do not timestamp the
decoder's internal source commit.
[Outer source prefix replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/direct-source-prefix.json).

All 7,376 frames used fixed-anchor deltas. During their wait the receiver
continued to prepare records on the same channel (median 566 other native
packets). In 4,714 cases an earlier TCP byte remained unavailable at B
TUN for over 1 ms after the target was prepared. The receiver therefore
already passed some earlier holes. At P99 the last required direct
packet took 5.243 ms from B WAN to authenticated open, and native prepare
to B TUN took 0.136 ms. The long interval includes FIFO, FEC commit,
Packed admission, anchor validation and selection of a frame for output.
[Per-record timing and kernel prefix](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/record-prefix-timing.json).

An ordinary repair cannot enter a busy decoder ahead of an older source.
The longest observed data residence in the ingress FIFO was 68.720 ms.
Using a later repair and a subsequent authenticated dispatch on the same
B thread gave a conservative time by which the earlier source had left
the FIFO and its first decode job had finished. Of the slow frames, 6,739
still waited at least 25 ms beyond that bound, and 278 still waited at least
100 ms. The bound allows capacity rollback and does not prove that a
particular record was already complete inside the codec.
[Later repair checkpoints](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/ingress-repair-checkpoint.json).

Reassigning the 62,907 captured forward native data slots to ready
segments in increasing TCP sequence order did not move any of the 48
steady repeated ranges across the point where its full earlier byte prefix
was present at B. The replay kept each slot's actual time, IP size and
TCP payload size. It gave eligible direct sources their earliest
authenticated dispatch time as a candidate for earlier delivery.
The measured and replayed first-attempt-to-prefix P99 were 339.626 and
340.321 ms. This comparison holds the sender and the receiver's service
opportunities fixed and does not regenerate TCP or predict throughput.
[Native slot replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/direct-slot-prefix-replay.json).

The targeted receiver now spends part of its residual metadata and copy
grant on the last fresh systematic source when it was staged just after
the previous FIFO head published. A pending feedback output or due feedback
keeps priority. The receiver also uses spare work after an ordered handoff
to preview a formally committed source above the decoded prefix. When a
partial preview is live, an ordered handoff can use a disjoint suffix of
the same symbol slab. A full-width head still gets the slab, and preview
restarts from the original committed source. The normal record receiver
checks equal identities and byte content, including contributions from
different outer sources. The independent-source fixture delivered S1 and
S7 in one turn, using zero field operations, 2,336 copy units and 1,991
metadata units. S0 was recovered from its equation alone.
[Endpoint fixture and byte checks](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/direct-systematic-fifo-public-probe.log).

For a diagnostic run on original UDP, setting
`L2TUNNEL_ROLLING_GAP_TRACE` to a local output prefix enables up to 65,536
scalar events per endpoint for named gap requests. The recorder uses the
negotiated rolling parser and coding direction. Selected output, physical
acceptance, authenticated input and application have distinct events. The
feedback serial, cumulative prefix, start and mask identify the requested
sources, without retaining packet payload. The observer writes on teardown
and reports any overflow. The baseline predates this observer. For source
16,394, B accepted its first input with a strictly higher source horizon
41.536 ms after the first source send. A sent its first named copy a further
90.697 ms later. These two events alone cannot separate request preparation,
reverse-path loss and sender service.
[Baseline gap timing](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/named-gap-custody.json).

The first Linux sample with both receiver changes and named feedback
tracing reached 22.051 Mbit/s, with 1,626.523 ms first-write-to-complete-read
P99 and 178 steady TCP repeats. The preceding sample reached 61.442 Mbit/s,
728.437 ms and 48 repeats. Both used one stream, 4 MiB of application
credit, a 100/10 Mbit/s path, 70 ms base RTT and 15% loss in each direction.
There were zero sender TUN drops and zero receiver UDP socket drops or
coding FIFO refusals in the 22.051 Mbit/s run. All data was recovered.
First mathematical solvability to native preparation fell to 48.106 ms
P99 on 19,425 steady attempts. The preceding sample carried 53,191
attempts. The two service-time distributions describe different loads.
[Linux result](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/arm-evidence.json)
and [first-solvability replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/steady-forward-retry-causal-join.json).

During steady load the median congestion window was 199 MSS and the median
smoothed RTT was 90.4 ms, compared with 1,175 MSS and 221.5 ms in the
preceding run. The sender had a median 3.83 MB already written but unsent
in Linux. At the second transmission of 165 of the 178 ranges, B had
already generated a cumulative ACK, which was still in transit to A. In
four more cases a covering ACK was already visible at A TUN. All 178
ranges were cumulatively acknowledged at B before the second copy arrived.
Across startup, steady load and drain, A counted 37 SACK recovery episodes,
577 fast retransmissions and zero TCP timeouts. All 418 duplicate SACK
reports captured at B were matched byte for byte at A. The namespace
counted 230 DSACKs ignored without an undo marker and 29 ignored as old.
Those counters do not attribute an undo decision to a particular segment.
[Socket window samples](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/steady-credit-cwnd.json)
and [kernel counters and duplicate ACKs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/tcp-duplicate-ack-counters.json).

The receiver physically submitted 5,277 named-request packets. The sender
authenticated 4,459 and applied all 4,459. For critical sources with a
named request, receiver acceptance of a higher source horizon to first
request selection took 11.135 ms at the median and 54.393 ms at P99.
The successful reverse crossing took 35.241 and 36.809 ms. After applying
the request, A physically submitted the named data in 0.236 and 4.104 ms.
The higher horizon is a lower-level observation and does not mark when
the decoder committed it. For source 8,675 both initial request copies
failed to reach the sender. The next successful request was selected
79.241 ms later.
[Named requests and transport boundaries](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/named-gap-custody.json).

Restoring the old receiver schedule while keeping the same named feedback
observer yielded 31.169 Mbit/s, 1,297.582 ms write-to-complete-read P99
and 314 steady repeats. The median congestion window was 318 MSS, with
117.037 ms median SRTT. The application, TCP and coding layers all drained
successfully. The receiver admitted every authenticated data input and the
bound UDP socket recorded 18 drops. All three samples used the same
configured impairment seed. The two schedules produced different packet
sequences and different actual impairment histories. The three single
runs leave the independent effects of observation, startup variability
and receiver scheduling on throughput unresolved.
[Three native runs and binary verification](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-cubic-revq-forward-records-verdict-seed31248-f805267/matched-receive-comparison.json).

The first sustained burst of TCP repeats in the 22.051 Mbit/s run began
with bytes starting at relative TCP sequence 1,500,908. From A TUN read
completion to MUX enqueue took less than the clock resolution. The record
waited a further 70.688 ms for handoff to the Packed sender. Neither of
its two initial systematic transmissions was authenticated at B. B sent
a request for both. The replacements reached B within 114.319 ms of the
later initial transmission. After the second replacement B prepared the
native frame in a further 18.143 ms. B generated a covering cumulative
ACK at 862.755 ms from the flow origin. A retransmitted at 893.940 ms,
and saw the ACK at 901.956 ms. The first kernel PAWS rejection occurred
later, at 1,011.498 ms. Startup thus contains both substantial forward
queuing and a race with an ACK that had already left B.
[Startup TCP, source and request chronology](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/paired-startup-cubic-1da52ce-017c72c.json).

At MUX admission, 272 older records from the same stream preceded this
record. All 272 were handed to Packed before it, and 189 new records
entered while it waited. The sender submitted 558 outer packets during
that interval. The fixed anchor was independently solvable at 760.612 ms,
well before the two replacement fragments. The remaining 18.143 ms
therefore starts after both the record and its anchor became solvable.
The first full sender status sample followed this queue episode, so the
aggregate codec staging refusal count cannot identify the refusal cause
at every point in this interval.
[Per-record sender queue and fixed-anchor replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/startup-r1201-queue-017c72c.json).

Of the 558 forward outer data and recovery sends during this wait, 475
were matched by packet number to 468,711 IP bytes at A WAN. Even charging
the other 83 their full 1,500-byte IP MTU, the submitted cohort occupied
at most 67.136 Mbit/s of the configured 100 Mbit/s over the 70.688 ms
interval. The lower bound was 53.046 Mbit/s. This bound uses the time of
socket submission and excludes other traffic classes. It does not treat
the surviving bytes seen at the qdisc in the same wall-clock interval as
the rate at which A submitted this cohort.
[Submitted forward byte bounds](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/startup-r1201-forward-byte-bounds.json).

The 70.688 ms MUX episode occurred in startup. Among the 178 unique
originals corresponding to steady repeats in this same run, MUX to Packed
had a median of 0.560 ms and P99 of 19.357 ms. The last initial outer
send to first mathematical recovery took 119.036 and 149.984 ms. Once
solvable, those originals took 8.505 and 19.607 ms to reach native
readiness. For the 165 repeats whose covering ACK was in transit, A
received that ACK a median of 6.934 ms after sending the repeat, with
a P99 of 24.625 ms. These are separate distributions on the captured
cohorts and cannot be summed to predict the effect of a scheduling change.
[Steady original packet intervals](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/retry-sender-residence.json)
and [covering ACK timing](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/retrans-races.json).

### Sender credit and authenticated gap discovery

In the same 22.051 Mbit/s capture all 138 critical source IDs had a higher
authenticated systematic input in the receiver FIFO at least 2 ms before
their first named request. Median headroom from that time to actual request
selection was 8.975 ms and P99 was 52.393 ms. For 51 sources an earlier
physical request already covered their 32-bit span and had room for their
ID without changing the mask length. This calculation has hindsight on
which source matters, keeps the original request names and ignores
competition for the eight-ID batch. It bounds an opportunity and does
not predict the effect on TCP.
[Critical-source event replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/queued-gap-opportunity.json).

The Rust receiver now uses a higher authenticated systematic input in its
bounded FIFO as evidence that earlier source IDs were issued. Gap discovery
uses the existing metadata grant, 2 ms delay, 80 ms repeat interval and
per-batch limit. Held copies suppress a request for their own ID. A pending
repair can continue while a named request is serialized from committed
state. Only the decoder can advance cumulative receipt. In a protocol test
the receiver named a missing source outside the active equation at the first
eligible tick, kept queued originals out of the mask and later recovered the
older missing source from that equation. The Common UDP sender also refills
its existing physical byte bucket at the same sampled instant it uses for
send eligibility. The first eligible poll can use credit earned during the
send batch.
[Targeted protocol tests](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/queued-horizon-targeted.log).

Running the unchanged preceding release with packet captures, per-packet
runtime telemetry and kernel tracing disabled gave 71.517 Mbit/s, 661.422 ms
first-write-to-complete-read P99 and 35 steady inner retransmissions. The
four-MiB single-flow application and the kernel impairment configuration
were unchanged. The sender kernel had a median congestion window of 1,341
MSS. Both native devices recorded zero TX drops and both endpoint UDP
receive-error counters stayed at zero. The application hash matched and
both recovery directions drained. The 22.051 Mbit/s full-trace run and
this observation are different closed-loop packet histories. Their
difference does not isolate observer cost.
[Lower-overhead reference run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-seed31248-017c72c/light-arm-evidence.json).

Across the 8.083 s between the first and last steady API samples in that
run, A submitted 98,540,102 outer IP bytes (97.526 Mbit/s). All 8,858
completed groups were above the ordinary backlog threshold and none sent
a near8 row during those samples. The earlier bound of 67.136 Mbit/s
describes a different interval in the instrumented startup trace.
[Steady socket acceptance and repair charges](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-seed31248-017c72c/status-window-accounting.json).

With MSS 1,448, four MiB of application credit and FIFO delivery in Python,
enabling explicit gap discovery from admitted FIFO sources changed goodput
from 68.583 to 68.588 Mbit/s. Write-to-read P99 changed from 676.904 to
671.054 ms and TCP issue-to-read P99 fell from 564.194 to 541.667 ms.
The sender transmitted 19,618 named retries, down from 21,377. Ordinary
plus near8 FEC consumed 15.089% of forward IP bytes, up from 14.042%.
FEC plus retransmissions consumed 25.408%, down from 25.431%. Both runs
drained all sources and all application bytes. Closing the new option
reproduced the prior result's measured fields.
[Same-seed Python comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/fifo-gap-observation-comparison.json).

With independent delivery enabled in the same MSS-1448 model, the
control reproduced 1.289 Mbit/s, 29,221.391 ms write-to-read P99 and 98
inner retries through drain. Discovering gaps at FIFO admission gave 1.250
Mbit/s, 27,238.528 ms and 80 inner retries. Both runs drained their written
application data. Their write-to-TCP-issue P99 values were 29,173.228 and
27,192.711 ms. The original 77.783 Mbit/s model reference used per-channel
FIFO delivery and one 512-byte record per inner segment.
[Independent-delivery control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-early-native1251-1448-gap-committed.json)
and [queued-gap comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-early-native1251-1448-gap-queued.json).

### Single-flow startup and overflow-funded near8

The low-observation trials below used one Linux CUBIC socket, a 90 Mbit/s
application offer, a 4 MiB application outstanding limit, an 85 Mbit/s
forward TUN pacing limit, 100/10 Mbit/s links, 70 ms RTT and independently
seeded 15% loss in both directions. Each row is one trial. The application
and FEC state drained in all four. The retransmission column counts the
sender socket's counter increments between actual reads at the edges of
the ten-second measurement. The final read on the 55.413 Mbit/s control
was 10.356 ms late.

| Frozen source | Forward selector | Goodput (Mbit/s) | First write to complete read P99 (ms) | Inner retransmissions |
| --- | ---: | ---: | ---: | ---: |
| 017c72c | 6 | 71.517 | 661.422 | 35 |
| bc47251 | 6 | 10.996 | 6827.692 | 2 |
| 4897f74 | 6 | 55.413 | 724.970 | 796 |
| 4897f74 | 10 | 67.509 | 694.060 | 84 |

In the slowest trial the sender reported 27 retransmissions and a congestion
window of 17 MSS at its first half-second sample. At the start of steady load
it had already retransmitted 35 segments. Its median steady window was 54
MSS and at least 3.64 MB remained unsent in the kernel at every steady
sample. Matching all 35,816 successful 512-byte writes to the sender's
sampled unsent-byte frontier gives a lower bound on the time until each
record's first byte left the kernel's unsent queue. Across the complete
population the P99 lower bound is 6787.909 ms. At least 2,648 records waited
six seconds before their first byte could enter the tunnel. The corresponding
P99 lower bounds for the other three trials were 226.865, 611.912 and
304.480 ms, respectively. The light observations do not identify the first
missing outer source in the slowest startup.
[Four-arm run evidence](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/headroom1-light-seed31248-4897f74/light-four-arm-summary.json)
and [per-record kernel queue bounds](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-seed31248-bc47251/light-tcp-send-wait.json).

For 189 individual records, that lower bound already exceeded the
application's 6827.692 ms P99. This identifies at least 189 members of the
slowest 358 records using sender evidence alone.
[Record indices and first-send bounds](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-seed31248-bc47251/light-tcp-send-wait-tail.json).

In the 55.413 Mbit/s trial, 363 of the 796 measured retransmissions fell
between 8.010 and 8.510 seconds from application start. The sender reported
cwnd values of 583 and 411 MSS at those interval edges. Across the whole
steady measurement its retransmitted-to-sent TCP byte ratio was 1.653%.
The 10.996 Mbit/s trial had a 0.021% ratio after startup. The former run
has no per-segment ledger to attribute the 363 repeats. An earlier
instrumented run with 178 steady repeats did have that evidence: B had
already emitted a covering cumulative ACK in 169 cases when A repeated the
segment. In 165 cases B's ACK had yet to reach A. Its median B-to-A
transit was 36.758 ms on the 35 ms reverse propagation path.
[Kernel counter intervals](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/light-four-socket-retransmissions.json)
and [earlier matched TCP sequences](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/retrans-races.json).

A single rerun of the frozen bc47251 executable observed TUN headers and
sender TCP_INFO during the opening 1.5 s. It reached 69.525 Mbit/s with
801.392 ms write-to-read P99 and 1,893 steady inner retransmissions. The
sample at 501.709 ms showed cwnd at 112 MSS. The earlier 10.996 Mbit/s
run had shown 17 MSS at that point. Changing observation and rerunning
the same seed produced a different closed-loop history.

The first receiver hole, bytes [10068,11516), closed in 0.039 ms. In a
later cluster, B exposed a gap at [33236,36132) at 183.925 ms. A saw a
SACK above it at 219.958 ms. B had the full interval by 222.086 ms but
A's first covering cumulative ACK arrived at 258.724 ms. Between 227.770
and 232.826 ms A counted its first two retransmissions. Another gap at
[37580,43372) remained open at B during that interval. The TUN observer
recorded inbound data at B and returning ACKs at A. It missed local
outgoing headers, so the socket counter does not identify which sequence
Linux retransmitted. By 313.760 ms A's slow-start threshold had returned
to its initial unlimited value. This records a transient recovery episode
and leaves the trigger of the earlier persistent small window unresolved.
[Startup header chronology and observation bounds](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-startup-seed31248-bc47251/startup-headers-causal.json).

The corrected startup observer binds the TUN and filters IPv4 TCP after
subscribing to both packet directions. In a small separate namespace
fixture it observed data and pure ACKs in both directions on both TUNs,
matched the ten TCP header digests across endpoints, and reported zero
socket drops. The original trial retains its inbound-only observations.
[Bidirectional TUN observer fixture](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/startup-headers-duplex-fixture.json).

Selector 10 uses overflow from first-original credit to fund a separate
eight-source equation when recent physical load permits. The decoder and
ordinary 8192/128 repair windows are shared with selector 6. On the frozen
instrumented packet history an offline replay could fund 172 extra rows
costing 225,877 to 230,730 IP bytes. Under an independent seeded 15% loss
process for these new rows, 41 of 138 critical sources became solvable
earlier, including 20 by at least 10 ms. All 40,956 sources eventually
solved. For startup record R1201, three missing originals shared one group.
The extra equation advanced its recovery by just 0.040 ms. Replay keeps
the ordinary packet history fixed and omits competition for the live GF
service budget.
[Frozen-tape experiment](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/near8-headroom-window-017c72c.json).

On Linux, both endpoints selected the requested profiles. By application
EOF the ID10 sender had seen 12,349 qualifying groups, withheld 12,338 for
physical load and abandoned 11 before sending. It submitted zero additional
rows and charged zero additional IP bytes. The measured throughput
difference between these two same-binary runs cannot be attributed to the
delivery of an extra equation. The other selector and both reverse paths
retained their ordinary accounting. The same-binary control also reported
45 UDP receive-buffer errors on B, compared with zero on B in the selector
10 trial. Steady goodput and P99 remain open against the named Python
references. No per-packet trace was enabled for these four observations.
[Same-binary counters, byte and time definitions](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/headroom1-light-seed31248-4897f74/light-pair-comparison.json).

### Single-flow TCP recovery on the same packet history

One Linux selector-6 run on frozen `bc47251` used a 4 MiB outstanding cap,
90 Mbit/s offer, 85 Mbit/s TUN pacing, 100/10 Mbit/s carrier, 70 ms RTT
and independent 15% directional losses. It delivered **33.145 Mbit/s** over
the ten-second steady interval, with a **1329.651 ms** first-write to
complete-read P99 and **441** inner TCP retransmissions. Unconfirmed sources
at application EOF were 1/17. Both endpoints subsequently reported zero in
two consecutive samples after 347.312 ms.
[Linux run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-startup-duplex-seed31248-bc47251/light-arm-evidence.json).

Both TUNs recorded the first 1.5 seconds. Each of the 2,780 forward and
2,700 reverse headers received within the cutoff matched a unique sending
header. The first three-segment hole began at relative byte 19,604. A sent
the original at 98.700 ms, received a SACK at 179.915 ms and retransmitted
at 201.569 ms. The original reached B at 211.628 ms. Its covering cumulative
ACK reached A at 247.703 ms and the repeated segment reached B at 304.549 ms.
All 16 ranges retransmitted in the first 500 ms arrived first in their
original transmission. Across the longer window, originals arrived first
for 405 of 536 repeated ranges and a retransmission arrived first for 131.
These counts also hold through the last timestamp covered by both readers,
1490.132 ms. Individual outer repair and named-request events were outside
this capture. [Four-direction event tape](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-startup-duplex-seed31248-bc47251/startup-duplex-events.ndjson.gz)
and [TCP sequence and ACK joins](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-startup-duplex-seed31248-bc47251/startup-duplex-replay.json).

One matched run with same-turn native delivery (`d057c14`) reached 29.780 Mbit/s with a 1602.276 ms write-to-read P99 and 567 steady inner TCP retransmissions, including 452 in the first 1.505 seconds of the steady interval. [Sender socket timeline](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-startup-duplex-seed31248-d057c14/steady-socket-recovery-comparison.json).

The Python receiver replay used the 2,776 actual startup DATA arrivals.
Linux emitted 2,735 ACKs, including 2,285 with forward SACK blocks. The
model emitted 2,544 cumulative ACKs. Both ended at byte 3,113,980. Across
the 30 early holes, the median Linux-minus-model delay to the ACK covering
the first missing byte was 0.021 ms. This compares receiver ACK generation
with arrivals held fixed. [Receiver replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-startup-duplex-seed31248-bc47251/python-receiver-same-arrivals.json).

The optional Python sender checks whether the first advancing partial ACK
echoes a timestamp strictly older than the first retry. On the three
observed entries into Linux Recovery the production predicate returned true,
true and false. For the first, the echo was 103 ticks older. Linux still
reported 9 and 10 outstanding retransmissions on the samples bracketing ACK
arrival and kept its threshold at 21 MSS. The threshold returned to its
previous value between 253.864 and 258.865 ms. For the third, the echo
equaled the retry timestamp and the retransmission delivered the range
first. The trace bounds the high sequence edge and observes cumulative ACK
processing through TCP_INFO. It cannot resolve the private undo marker or
the kernel function invoked for an individual ACK. Throughput and latency
parity remain open. [Simulator predicate and measured inputs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-startup-duplex-seed31248-bc47251/startup-partial-ack-predicate.json)
and [Linux v6.8 partial undo](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_input.c#L2753-L2784).

Closed-loop Python trials kept the early-delivery C48 configuration, 1448-byte
TCP MSS and application writer fixed. On the initial seed, enabling the
option raised steady goodput from 1.250 to 65.531 Mbit/s, reduced write-to-read
P99 from 27,238.528 to 732.615 ms and reduced TCP retransmissions from 80 to
29. On the held-out seed, goodput rose from 1.164 to 2.012 Mbit/s and P99
fell from 26,926.018 to 13,451.347 ms. Retransmissions increased from 90 to
110, with 39 model window restores. All four trials ended with zero
unconfirmed sources in both directions. The large throughput increase on the
initial seed did not reproduce on the held-out seed.
[Initial control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-early-partial-undo-off.json),
[initial option](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-early-partial-undo-on.json),
[held-out control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-early-partial-undo-off-held-out.json)
and [held-out option](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-early-partial-undo-on-held-out.json).

The held-out endpoint trace explains the first long simulated recovery.
The receiver buffered segments 7–9, then accepted a retry of segment 0
at 106.792 ms and advanced its recent timestamp. When originals 1–6 arrived
at 187.407 ms, their older timestamps failed PAWS. Each partial cumulative
ACK released one further NewReno retransmission. The first episode lasted
662.049 ms. A later episode took 4079.523 ms with 36 partial ACKs. The run
recorded zero RTO expiries. The Linux capture above contains SACK ranges
that this Python endpoint does not send. In the FIFO control, enabling the
option left throughput, measured latency, physical byte charges and retransmissions
identical. [Endpoint events](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/socket-writer-recovery-mechanism.json)
and [paired byte accounting](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/partial-undo-two-seed-comparison.json).

A separate native join used the first SACK relevant to R1201 on the earlier
`017c72c` build. Its cumulative edge was byte 1,370,588 in R1098. Source 1452
left the sender socket at 683.609 ms. Its first packet had no downstream
capture entry. A named repeat left at 782.049 ms, made the source solvable
at 817.608 ms and the TCP segment appeared on B TUN at 825.124 ms. B advanced
its ACK at 825.393 ms. When A received the older SACK at 856.337 ms, B had
already filled this gap. A received the advancing ACK at 866.284 ms. These
timestamps distinguish a missing forward fragment from an ACK still in flight.
[Source identities and identical ACK hashes at both TUNs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/prefix-at-r1201-sack-017c72c.json).

B admitted the first higher source at 725.692 ms. It submitted the first
request for 1452 at 737.555 ms. A applied that request at 773.003 ms and
submitted the repeated source 9.046 ms later. Both physical copies of the
request reached A. This splits the forward-loss example into observable gap
detection and scheduling, reverse transit, resend scheduling and forward
transit. The request trace does not identify which part of the initial
11.863 ms elapsed inside the decoder.
[Authenticated request and repeat](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/prefix-r1098-gap-request-017c72c.json).

Of 138 traced sources with an applied request and a subsequent selected
retry, the request-to-socket median was 0.236 ms and P99 was 4.175 ms.
R1098 accounted for the 9.046 ms maximum. Between applying its request and
submitting the retry, A selected and submitted 27 direct sends, 11 other
named sends and one repair. [Physical sends while the request waited](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/named-retry-accepted-queue-017c72c.json).

In the two later Linux single-flow runs, every steady TCP_INFO sample had
unsent application data. Dividing congestion-window bytes by the smoothed
RTT from the same sample gave medians of 35.419 Mbit/s (baseline) and
31.583 Mbit/s (candidate). All 1777 and 1790 samples respectively were
below the 77.783 Mbit/s reference by that calculation. The advertised
receive window could cover the required bandwidth-delay product at every
sample. On the candidate, median unsent data was 3,662,856 bytes. The P99
lower bound from the record's first socket write to its first byte leaving
the TCP unsent queue was 1124.499 ms. The measured write-to-read P99 was
1602.276 ms. These quantiles cannot be subtracted to time an individual
record. [Paired socket window and residence measurements](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/single-stream-socket-window-budget.json).

The baseline and candidate spent 1.501 and 1.497 forward IP bytes per
delivered application byte by the first observation after EOF. If those
costs persisted at full link utilization, a 100 Mbit/s link would carry
66.62 and 66.81 application Mbit/s respectively. Reaching the original
77.783 Mbit/s target at that link rate allows about 1.286 forward IP bytes
per application byte. Both the sender's flight and the measured wire cost
therefore need attention. The final drain occurred later than this byte
snapshot. [Paid IP bytes and application totals](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/duplex-completed-flow-wire-cost.json).

A receiver prototype applied the same SACK logic to both archived startup
arrival histories at the observed ACK times. It reconstructed the entire
SACK option on 2727 of 2735 ACKs on the baseline and all 892 on the
candidate. The baseline's options added 61,920 bytes across its ACKs.
A separate finite Python experiment carried actual variable-length options
over the existing reverse MUX/Packed path. All ten transmitted ACK frames
matched the reconstructed bytes, including after loss and FEC recovery.
The sender in that experiment continued using cumulative ACKs for recovery.
[Baseline option replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-startup-duplex-seed31248-bc47251/receiver-sack-contract.json),
[candidate option replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-light-startup-duplex-seed31248-d057c14/receiver-sack-contract.json)
and [reverse wire experiment](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/c48-sack-wire-fixture.json).

#### Single-flow fragment cost and stale gap requests

The Linux run at tree `017c72c` contained 26,088 full-MSS TCP data segments.
Each carried 1,448 bytes of application payload. Re-encoding their original IP
bytes with the frozen fixed-anchor codec produced record bodies of 1,454 to
1,464 bytes. At an IPv4 MTU of 1,500 the selected UDP and protection headers
leave 1,451 bytes before any Packed metadata. Every full-MSS record split,
including in the offline count at a larger 1,313-byte symbol. The original
1,251-byte calculation reproduced the recorded fragment count on all 29,843
records. A coding unit and an outer packet have different counts because one
outer source can carry tails from several records.
[Native record and fragment counts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/forward-symbol-geometry-017c72c.json).

The receiver now rechecks each unpublished part of a split gap request against
the decoder before freezing the next feedback. The check consumes the existing
metadata budget. A public receiver regression recovers source 35 from an actual
equation while the first request for source 0 is frozen. The next request
contains only the remaining hole 37. In a frozen-arrival replay of the entire
Linux run, removing requests already solvable at B saved at most 371,141
forward IP bytes under instantaneous decoder commits. It preserved the first
mathematical solution time of all 40,956 sources. Actual commit and delivery
times determine the runtime effect.
[Receiver regression](../../crates/l2tunnel-fec/src/rolling/scheduler/targeted_tests.rs)
and [fixed-arrival replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/paid-mask-pair-017c72c.json).

Two closed-loop Python seeds used early delivery, MSS 1,448, actual SACK option
bytes passing through the reverse transport and the original 4 MiB application
credit. Matching the Rust sender's existing 500 µs tail-packing rule allowed
full first fragments to pass a held batch of compatible tails. On the initial
seed this raised throughput from 65.82 to 72.36 Mbit/s and reduced application
P99 from 627 to 616 ms. On the held-out seed it raised throughput from 8.90 to
21.81 Mbit/s, with P99 still 6,642 ms. All four arms drained. A separate
sender experiment using selective ACKs to retransmit additional inner gaps
increased retries from 28 to 257 and 82 to 406 on the same two seeds. These
are simulator measurements and the original frozen Python target remains open.
[Fragment packing comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/c48-tail-packing-early-sack-comparison.json)
and [SACK sender comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/c48-sack-early-sender-comparison.json).

In the archived `f805267` run, 94 TCP retransmissions occurred between 2 and
3.5 seconds of application time. During 62 of them the entire byte prefix had
reached B's TUN, but B's kernel receive cursor still pointed at one of three
earlier gaps. For each gap a previous inner retransmission had advanced the
receiver timestamp. The late original then failed Linux's PAWS check. The
three gaps took 371.537, 219.482 and 177.777 ms to close after rejection. Their
covering ACKs took 36.835, 36.858 and 37.020 ms to return to A. Of the 62
retransmissions, 39 had only PAWS-rejected copies of their own byte range
at B, 15 had evidence of prior out-of-order retention, and eight had ambiguous
retention. Seventeen further retransmissions occurred after B had sent its
covering ACK. Six preceded arrival of their own range at B and nine preceded
arrival of an earlier part of their prefix.
[Kernel verdicts and ACK identities](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-receiver-paws-exact-events-f805267.json)
and [individual range retention](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-receiver-paws-retention-f805267.json).

An instrumented Linux control at `d057c14` completed at 13.099 Mbit/s,
with a 4,561.96 ms application P99 and two steady TCP retransmissions. A
run of the gap-request fix at `8dc0344` exited before it completed the
measurement. In the 2–3.5 s interval, 449 of its repeated byte ranges
referenced 421 distinct originals seen at A's TUN with no Rust read record.
The interface accumulated 1,065 drops over the wider phase. That count
does not assign a kernel drop reason to each original. Among the packets
that Rust did read, the TUN-to-read P99 was 143.351 ms. At application
time 3.180 s, B found one 52-byte reverse ACK past its 20 ms hold cap. Of
the 484 repeats observed in the interval, 483 preceded that terminal check.
A full workspace check overlapped the failed arm and did not overlap the
control. No complete candidate goodput or application P99 is available
from this pair. The two local launchers now hold the same host lock while
measuring an arm or running the workspace gate.
[Failure timeline and byte identities](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-targeted-pair-failure-v2.json)
and [completed control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-d057c14/burst-application-evidence.json).

During the failed arm's 461.478 ms burst, the TUN saw 72.436 Mbit/s of
inner TCP payload, Rust read 62.088 Mbit/s and the MUX supplied Packed at
61.987 Mbit/s. Reconstructing byte occupancy for this flow showed
insufficient free space at all 1,153 delayed admissions. With a 1 MiB
flow limit, P99 occupancy left 24 bytes free. Of the 421 unread originals,
300 arrived while Rust held the preceding packet for admission. Once
enough bytes became available, admission took 15 µs at P50 and 509 µs at
P99. Admitted packets waited 139.638 ms at P99 for Packed. These
measurements locate the sustained backlog upstream of packing. The failed
arm cannot determine how much of its service rate was lost to competing
work on the host.
[Per-flow occupancy and sender stages](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-sender-read-gaps.json).

The ACK coalescer records the first service call after a held ACK becomes
due, the count and times of capacity refusals on flush, and the last
completed service call. An ACK that supersedes an older candidate inherits
the existing hold's service history and deadline. These observations use the
injected clock and the existing bounded flow slots. The timeout diagnostic
prints them with the original hold, due and expiry times. The protocol tests
exercise both a full downstream queue and a missed service window.
[Diagnostic source change](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/ack-due-service-diagnostics-8dc0344.patch).

The next Linux candidate at `1ee5ce3` ran without a concurrent workspace
check. It completed the same single-flow workload at 67.184 Mbit/s with a
667.147 ms write-to-read P99 and 170 steady inner retransmissions. Both
TUNs reported zero drops, neither UDP socket reported a receive-buffer
error, and both endpoints drained to zero. The control above had 78 MSS of
median TCP cwnd, versus 1,186 MSS for this candidate. On the candidate,
all 1,850 steady TCP_INFO samples had at least 817,392 bytes already queued
and unsent in the kernel. Median smoothed RTT was 212.116 ms and the median
paired cwnd/RTT rate was 64.44 Mbit/s. The original 77.783 Mbit/s
throughput target remains open. This single completed
draw does not identify how much throughput came from the gap-request fix.
The host observer found a compiler or build-process PID in all 19 control
samples and none of the 20 candidate samples. Its ownership and CPU use
during the control run were not recorded.
[Completed native trial](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-1ee5ce3/burst-application-evidence.json)
and [steady socket samples](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-socket-window-comparison.json).

In the completed candidate's 2.0–3.5 s capture, all 17 retransmitted TCP
ranges already had a covering cumulative ACK in flight from B when A
retransmitted. The covering ACKs reached A in 36.380 ms at P50 and
36.699 ms at P99 from their appearance at B. This attribution covers the
17 captured events. The full steady interval contained 170 kernel-counted
retransmissions. At shutdown, after both endpoints drained, the forward
socket had accepted 138,187,841 outer IPv4 bytes for 99,259,392 unique
application bytes, a ratio of 1.3922. FEC accounted for 7.51% of forward
socket-accepted IPv4 bytes and 17.41% in reverse. Including named and
quiet retries and extra copies brought those shares to 21.32% and 64.70%.
The API read after EOF returned a periodic snapshot published before EOF.
[Capture identities, terminal byte counters and interval definitions](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-clean-ack-service-accounting-v2.json).

#### Sender service cost and repeated gap feedback

In the completed Linux arm at `1ee5ce3`, the 58,624 steady admissions
waited 80.369 ms at P50 and 144.797 ms at P99 for Packed. In the longest
wait (158.915 ms), Packed took 662 other frames. Its longest interval
without taking a frame during that wait was 15.641 ms. These measurements
locate queue buildup but do not measure how the sender divided CPU time
among encoding, recovery and other work.
[Queue service and timestamps](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/packed-mux-service-timeline-1ee5ce3.json).

Two forward runtime snapshots at 3.131 and 11.133 s bound an 8.002 s
interval wholly inside the steady measurement. The socket accepted
94,770,975 IPv4 bytes (94.75 Mbit/s). The inner TCP sender confirmed
67,536,168–67,640,424 payload bytes, bracketed by measured socket writes
and output-queue reads and cross-checked against 20 TCP_INFO samples.
The forward cost was 1.401–1.403 IP bytes per acknowledged payload byte.
At the same mix, spending 100 Mbit/s on accepted IP would buy
71.26–71.37 Mbit/s of acknowledged TCP payload. Reaching 77.783 Mbit/s
at that budget requires a ratio of 1.286 or lower. In this interval
ordinary FEC used 6,962,955 bytes, named retries 11,504,779 bytes and
extra copies 1,609,490 bytes. Changing service speed alone cannot close
the gap if those byte proportions persist.
[Matched snapshot and TCP boundaries](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-1ee5ce3/snapshot-paid-rate.json)
and [byte categories](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-clean-ack-service-accounting-v2.json).

Two implementation changes reduce work per unit. The native TCP encoder
reuses an exact header reconstruction to validate both checksums, and sums
network-order words in blocks. Packed writes only the meaningful bytes of
its aligned scratch unit. The fixed-width Aligned serializer zeroes its
own trailing bytes. The 125,617 first-send units in the steady trace
previously cleared a total of 157,146,867 scratch bytes before filling
them. That count measures writes requested by the source code. The
isolated TCP header replay measured 1,916 ns per packet before and 341 ns
after, with identical encoded bytes on all 34,889 packets.
[Scratch writes](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/packed-symbol-clear-accounting-1ee5ce3.json)
and [header timing](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/header-cost-pair-1ee5ce3.json).

The 17 repeats in the prior capture fell into two groups. Both physical
copies of the first requests covering sources 11,545 and 12,561 were lost.
The next successful requests for those gaps reached A roughly 80 ms later.
A fixed-arrival replay appended an unresolved request to the second copy
of the next different request, subject to an 8 ms age bound. This added
18,247 reverse bytes in 4.5 s. With the recorded forward loss outcomes and
spare service assumed at the sender, the 17 byte prefixes became available
25–74 ms earlier. All 31,348 sources retained their final solve status.
Charging all extra serialization with no reverse idle time delayed other
requests by up to 14.598 ms.
[Feedback packet identities, source solutions and cost assumptions](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-prior-gap-echo-1ee5ce3.json).

The matched Linux run at `f62e45e` included only the encoder and scratch
changes. The descriptor and both generated plans matched the prior arm.
Goodput reached 69.927 Mbit/s, application write-to-read P99 was
577.295 ms, and the 10 s steady TCP retransmission count was 15. Both
TUNs had zero drops, both UDP receive-buffer error counts stayed at zero,
and both endpoints confirmed all sources. The steady MUX-to-Packed
P50 was 88.963 ms and P99 was 130.857 ms. The forward socket accepted
97.89 Mbit/s from 3.468 through 11.469 s, with 1.381–1.382 IPv4 bytes
per acknowledged TCP payload byte. This implies 72.36–72.42 Mbit/s
at a 100 Mbit/s sending budget if the byte composition persists.
The prior arm saw 67.184 Mbit/s, 667.147 ms and 170 steady retransmissions.
An unrelated compiler used one host CPU during this run. Each build
has one observation under this configuration.
[Single-flow accounting](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/matched-codec-cpu-accounting.json),
[socket byte rates](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/snapshot-paid-rate.json)
and [per-record MUX waits](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-sender-residence-pair-f62e45e.json).

In the same candidate, the inner sender reported 265 retransmissions in
startup (0–2 s), 15 in steady state (2–12 s), and 280 by its last sample.
The full-phase namespace counter was 283. Both TUN captures cover the
startup interval. Of its 265 repeats, 167 followed B's covering ACK but
preceded its arrival at A. Another 86 had reached B with an earlier part
of the TCP byte prefix still missing, 11 had not reached B, and one had
its covering ACK already visible at A's TUN. Sixty-nine of the 86 waited
behind a single original range, [4,328,940, 4,330,388). That original
reached A TUN at 819.793 ms and Packed at 877.145 ms. Its required source
4,497 was submitted at 877.863 ms. B observed a higher source at 913.396 ms,
issued a request 3.149 ms later, and its successful request took 45.172 ms
to reach A. A submitted the retry 0.508 ms later. Another systematic source
unlocked an existing equation at 1,060.215 ms, before B observed either
named retry. The original TCP range reached B TUN at 1,066.647 ms.
[Startup native and algebraic events](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/startup-forward-rank.json),
[request and physical-send timeline](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/startup-named-gap.json)
and [steady retransmission windows](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/steady-inner-retrans-time.json).

A had already received SACK evidence for higher sequence numbers in all
265 startup cases. For 251 of the retransmitted ranges, B had also sent a
positive acknowledgment for the affected range (167 cumulative ACKs and
84 SACKs) that A had yet to receive. For 212 of those 251, the interval
from B sending that acknowledgment to A retransmitting was shorter than
the configured 35 ms one-way propagation. Eliminating reverse queueing
would still leave those acknowledgments in flight at the recorded retry
times.
[Per-range acknowledgment identities and timing](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/startup-prior-sack-and-prefix-v2.json).

The steady 8.001 s snapshot interval included 9,871 forward named retries.
Replaying 125,763 receiver admissions against two independent reducers
recovered the contiguous range of all 104,350 sources. There were 4,905
named copies that first solved their source, 1,389 without a receiver
admission in the ledger, 425 sent after their own source was solvable at
B, and 3,152 overtaken in flight. In each of those 3,152 cases a packet
for another source unlocked an equation. The median lead over the named
copy's arrival was 2.6 ms. Even charging the MTU for each of the 425
already-solvable and 3,152 overtaken sends gives only 5.366 MB. The
observed interval would need to save 6.750–6.825 MB to preserve its
acknowledged payload while achieving the reference byte ratio. Those
amounts are conditional on the recorded packet sequence. The time when
A can learn about a solution at B is a separate constraint.
[Full receiver replay and named-send categories](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/named-necessity-races.json).

The 3,152 overtaken retries were unlocked by 625 distinct named packets
for other sources. Of these races, 747 involved the same logical request
and 2,405 an earlier request. At the receiver's first recorded selection of
the target request, the packet that ultimately unlocked the data would
by itself have been sufficient in zero cases. At selection of the request
that authorized the target send, this held for three cases. Identifying
the eventual helper retrospectively is insufficient to skip the target
while preserving its original recovery timing.
[Request-time equations](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/named-unlock-causal.json)
and [per-source witnesses](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/named-unlock-witness.json).

The candidate's 8,384 ordinary forward repair datagrams combined a median
of 128 source datagrams with nonzero coefficients (range 5 to 8,175).
Every source in this count was matched to its own first-send UDP packet
number. For example, repair PN 6,774 covered 4,740 distinct source
datagrams, including sources 4,449 and 4,497, and B admitted this repair
at 940.992 ms. Source 4,497 was absent from the received datagram ledger.
The subsequent named copy of source 4,449, PN 8,305, made 4,497 solvable
with the equations already present. This lab injected datagram erasures.
It did not inject Ethernet FCS failures.
[Nonzero source membership by repair](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/fec-datagram-support.json)
and [physical packet observations](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/startup-physical-winners.json).

Per 1,000 newly acknowledged TCP payload bytes in the 8.001 s interval,
the forward socket accepted 1,381–1,382 IPv4 bytes (rounded).
Named retries used about 167 bytes, FEC used 102, extra copies used 23,
and first transmissions plus all other forward traffic used about 1,089.
Each category includes its own UDP/IP and tunnel framing.
[Non-overlapping byte counters and denominators](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/payload-price-breakdown.json).

The C48 Python study now accepts `--fragment-tail-packing` as an explicit
option for both directions. It uses the normal packing queue, coding
window, copy selection and deadline. Focused tests cover a lost original
and first named retry, an exact timer tie, different copy classes, a full
coding window, exhaustion of recoverable source identities, and a real
CLI run with both endpoints confirmed. The checked-in packing vectors
retain their previous event and byte contents.
[Study entry point](../../simulator/studies/packed_spare_c48.py)
and [tail-packing regressions](../../simulator/tests/test_packed_fragment_tails.py).

A separate closed-loop Python comparison priced the optional previous-gap
echo against a corrected control. Both arms issued two authenticated-size
requests for forward-data gaps and one for reverse-data gaps, and applied
repeated serials idempotently. Both charged reverse datagrams and actual
forward retries, with bounded control parsing. On the initial seed
goodput changed from 72.103 to 72.141 Mbit/s, P99 from 605.553 to
609.705 ms and inner retransmissions stayed at 30. On the held-out seed
goodput changed from 1.505 to 1.504 Mbit/s, P99 from 52.033 to 46.139 s
and inner retransmissions from 193 to 93. Both held-out arms timed out
33 times. All four arms drained. The measured goodput gives no basis
for selecting the echo in the Rust runtime.
[Two-seed study, paid bytes and scope](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/c48-prior-gap-closed-comparison.json).

### Mixed packets and local erasure recovery

The new experimental group carries original and redundant data in each
physical packet. For an example with three packets and one allowed
erasure, split A, B and C into two pieces each. Send A with `B0 XOR C1`,
B with `C0 XOR A1`, and C with `A0 XOR B1`. If A is lost, the other
two packets expose B and C directly and supply both missing pieces of A.
The actual codec uses cyclically distributed systematic Cauchy stripes,
so its guarantee extends to multiple erasures. Both implementations
recover nonuniform originals and their exact length from every choice of
eight out of ten packets. Duplicate arrivals contribute once. An intact
group requires zero recovery calls.
[Rust codec and subset tests](../../crates/l2tunnel-fec/src/striped/tests.rs)
and [Python codec and subset tests](../../simulator/tests/test_striped_cauchy.py).

The compact member includes a shape byte, the group's first logical source
ID as a canonical varint, an ordinal, and the two-byte original length.
A split singleton also carries its complete logical length. The effective
parity count for an ordinary short group follows from the configured
geometry and shape. Every packet carries its own data through the true
extent plus its whole parity suffix. Restoring the omitted systematic
zeros requires no field operations. The parser separately bounds physical
and expanded lengths before admitting the body. After outer authentication,
the caller must bind direction, session, epoch, group identity and geometry
throughout the lifetime of the group.
[Compact wire and bounds](../../crates/l2tunnel-fec/src/mixed_datagram.rs).

The earlier source 4,497 was the sole missing original in either the five-
or ten-source cohort that contains it. Four of the five old UDP packets
had arrived at B's WAN by 913.176 ms, and eight of the ten by 913.070 ms.
The original C48 equations first solved it at 1,060.215 ms. All constituents
of these groups were available at A before the first historical socket send.
Other startup groups needed up to 71.995 or 75.367 ms after their first
historical send to acquire all their constituents. These are observations
on the original transmission schedule. Repacking at the MTU changes packet
sizes, serialization and loss opportunities.
[Recorded source IDs, timestamps and group-fill distributions](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/source_packet_price_stripe_f62e45e.json).

At an MTU of 1,500 with 49 bytes of enclosing UDP/IP and protection, a
ten-packet group with two parity cells per member and a two-byte group ID
admits at most 1,155 original bytes per packet. At 100 Mbit/s its best
equal-size full-group rate is 77.026 Mbit/s of original bytes, before
inner metadata, control or retransmission. At independent 15% erasure
probability, 17.98% of ten-packet groups lose more than two members.
Those groups still need late originals or a named retry. The group size,
parity fraction and 500 µs experimental hold need measurement against
throughput and the TCP tail under the same bidirectional loss.
[Physical budget calculation and tested geometries](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed_mds_shaped_budget.json).

The Rust sender takes caller-supplied ticks. Once the first source is
admitted, later arrivals cannot extend its hold. A full group can be
polled immediately. At expiry the sender prices the actual short group.
If the whole batch exceeds the MTU, it emits the longest fitting contiguous
prefix. If no multi-source prefix fits, it splits the first source. The
remaining sources keep the same deadline and are considered together again.
This keeps full groups eligible for larger originals. In a two-member
split the sole Cauchy coefficient is one.
Either physical packet therefore contains both halves, and the receiver
can verify their lengths, reconstruct the single logical source and
commit it exactly once on the first arrival. A single-byte record checks
the byte in both cells. The short-group tests exercise old-hole recovery
while a later generation is independently delivered.
[Lifecycle implementation and tests](../../crates/l2tunnel-fec/src/striped_group/tests.rs).

On one host CPU, a release build sent a group of five containing long
and short originals in 2.58 µs at P50 and 4.33 µs at P99. Receiving the
intact group took 2.99/11.34 µs, and receiving four members followed by
recovery took 5.59/14.22 µs. These include the measured group allocation,
coding, wire processing and local commits. Group assembly wait, carrier
authentication, sockets and kernel delivery are separate. For a single
52-byte logical record a surviving split packet exposed the full record
in 0.33 µs at P50.
[Method, sizes and CPU timings](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed_cpu_results.md).

The first two-seed, two-direction Python 5/4 study uncovered an asymmetric
delay for singleton records. When ordinal zero arrived first, the study
could wait for another arrival or its 1 ms recovery timer. Reading the
other half from the first valid parity cell removed that wait. With this
fix, on the initial and held-out seeds respectively, steady application
goodput was 0.953 and 2.663 Mbit/s. The same endpoints and links with the
rolling comparison delivered 72.357 and 21.808 Mbit/s. The mixed profile
confirmed all of its outer sources in both directions and the received
native frames matched the submitted frames. The simulated application
still had 7,171 and 6,976 outstanding 512-byte writes when drain ended.
Its completed-write P99 values, 46.753 and 55.651 seconds, exclude those
outstanding writes. The runs recorded 221/179 inner retransmissions and
40/41 timeouts over the full simulation. The first timeout on either seed
was after the 2–12 s throughput window. These runs charged every physical
datagram, used the previous receiver service curve and omitted simulated
sender CPU time.
[Initial mixed run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-normal-v2-initial-mixed5.json),
[held-out mixed run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-normal-v2-held-mixed5.json),
[initial rolling comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-normal-v1-initial-spare.json)
and [held-out rolling comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-normal-v1-held-spare.json).

In the initial mixed seed, the first sustained pause in cumulative ACKs
involved inner TCP segment 18. Its first copy required sources 20 and 23.
Group 18–22 lost sources 20 and 22, leaving three distinct packets at B
when four were required. Source 23 was already available at 113.257 ms.
The inner sender entered fast recovery at 150.265 ms. Both sources of
its retransmitted segment were available at B by 188.858 ms, and TCP
accepted that segment at 262.190 ms. The older copy arrived at 266.084 ms
after the outer named retry of source 20, and TCP rejected the duplicate's
older timestamp. This first PAWS rejection was for data already accepted.
The A-side cumulative ACK pause lasted 148.138 ms. The original rolling
comparison had no pause as long as 140 ms in the first 2.5 s of this seed.
[Mixed startup and first-send erasures](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed_startup_witness_initial_mixed5_12s.json)
and [rolling startup](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed_startup_witness_initial_spare_2.5s.json).

The receiver issued the first request for sources 20 and 22 at 115.919 ms.
It was lost. The repeat at 195.919 ms reached A at 230.965 ms. TCP segment
19 exposes a second dependency. Its own sources 21 and 23 were ready at
113.257 ms, but the chained header decoder needed the preceding record,
whose source 20 arrived at 266.084 ms. By then B had accepted the inner
retransmission of segment 18 with a newer TCP timestamp. B's PAWS check
rejected segment 19's still-needed bytes. For this segment, readiness of
its own sources preceded TCP delivery eligibility by 152.827 ms. In the
2–12 s measurement window the initial seed rejected 73 distinct previously
unreceived TCP segments on timestamps, with zero retransmission timeouts
during that window. The held-out seed rejected 334 such segments.
[Initial packet and request chain](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed_startup_witness_initial_mixed5_12s_paths.json)
and [held-out chain](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed_startup_witness_held_mixed5_12s_paths.json).

Charging measured Rust sender and receiver time in Python yielded the
following single-flow steady goodput, in initial/held-out seed order.
The 5/4 group achieved 0.451/1.256 Mbit/s and the 16/14 group achieved
0.126/3.468 Mbit/s. The P99 of completed writes in the 5/4 runs was
58.852/55.927 s, with 2,210/4,385 application write records still
outstanding at the end. No full reverse group formed in any of these
four arms. The study charged microsecond-scale processing from a
separate pinned-core benchmark and approximate costs for intermediate
sizes. These runs provide no basis to select either geometry as a
new default. The normal Common/Linux workload for the mixed layout
remains outstanding.
[Study comparisons, custody and byte counters](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-normal-three-versions.json).

One complete reverse ACK in the CPU-priced 5/4 initial seed took 1,441.527 ms.
B admitted its 94 native bytes at 5.623007 s. Both 158-IP-byte members carrying
source 206 left by 5.624260 s and were erased. Nine successive quiet probes
then retried older source 204. Without another group, A could not infer the
missing group boundary. Source 207 finally arrived at 6.992403 s, after the
inner TCP timeout at 6.920244 s. The request for 206 reached B 37.005 ms
later and the retransmitted member yielded the original ACK at A after another
35.127 ms. Most of the delay was between the last original departure and the
first visible evidence of the gap (1,368.142 ms). This single ACK is a separate
event from the earlier forward segment 19.
[Physical departures, erasures, requests, and byte-exact delivery](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-v3-initial-5-4-first-rto-original-ack.json).

A separate two-seed model study charged and independently lost every copy of a
gap request. In the initial seed, duplicating the request for group 18–22
advanced receipt of its fourth distinct member from 266.089 to 186.344 ms.
Requesting just source 20 sufficed to reconstruct source 22. Neither reducing
the requested list to the group's missing rank nor duplicating each request
consistently improved single-flow goodput and tail latency across both seeds.
The study excludes preliminary runs which failed to select the reference
header codec.
[Matched runs and actual feedback byte counts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-deficit-v2-summary.json).

The actual short-group distribution also matters for capacity. In the
initial 5/4 v2 run, 761 full forward groups carried 3,805 sources, and
3,113 forward sources were each sent as a two-member split. Another two
sources shared one short group. Of the reverse sources, 1,468 used the
two-member split and only 18 shared a group with another source. The
forward first transmissions carried 6,067,576 original bytes and
3,696,615 parity bytes in 10,327,906 IP bytes, before named or quiet
retries. Nominal 4-of-5 geometry alone therefore understates the observed
cost. These are lifetime counts for this seed and layout.
[Group shapes and physical byte counts by direction](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-normal-v2-initial-mixed5.json).

The next control sent the forward TCP frames with the existing self-contained
header representation. It preserved the original reverse path, FEC, loss
process and byte prices. All 45,344 initial-seed and 4,768 held-out forward
frames matched the original native bytes and reached TCP during the call that
completed their own sources. Relative to chained compression on the same
frames, the cost after accounting for fragments and context records was
51.526 and 51.673 additional bytes per forward TCP frame, respectively.

| Seed | Chained → self-contained goodput, Mbit/s (2–12 s) | Completed-write P99, s | Inner retransmissions (2–12 s) | Outstanding application writes at drain |
| --- | ---: | ---: | ---: | ---: |
| Initial | 0.953 → 43.520 | 46.753 → 22.396 | 108 → 50 | 7,171 → 0 |
| Held out | 2.663 → 1.754 | 55.651 → 16.920 | 84 → 54 | 6,976 → 0 |

One reverse outer source remained unconfirmed in the initial self-contained
run. Both chained arms and the held-out self-contained run confirmed all
outer sources. Removing the preceding-record dependency reduced useful DATA
rejections by the TCP timestamp check from 73 to 39 and from 334 to 27 in
the measurement window. The opposite throughput changes on the two seeds
leave independent header delivery as one identified cause, alongside recovery
of excess or entire-group loss. This control does not test Rust fixed-anchor
header compression.
[Matched runs, same-frame header cost and three separate end-of-run ledgers](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed_standalone_header_comparison.json).

Replaying the two frozen 5/4 runs captured all 677 and 825 forward short
batches that exceeded the MTU. Pricing every contiguous partition under
the same deadline and wire grammar found no cheaper alternative to their
existing split layout. In the initial run, minimizing packet count instead
would save 118 packets but add 10,520 IP bytes. The held-out run would save
104 packets and add 10,242 IP bytes. A short record shares the parity cell
width required by the longest record in its group. The comparison covers
first transmissions on the captured send schedule.
[Initial-seed partition costs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-short-v2-initial-cost.json)
and [held-out partition costs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-short-v2-held-cost.json).

The optional Python switch `--striped-fair-reverse-probes` alternates the
oldest pending source with another eligible retained source in the existing
reverse quiet-probe slots. Each slot retains its physical byte ceiling.
In the CPU-priced 5/4 initial seed, the same source 206 ACK arrived at
6.078887 s, 841.357 ms before the original first timeout. Application
goodput went from 0.451 to 1.131 Mbit/s, P99 of completed writes from
58.852 to 29.591 s and application debt from 2,210 to zero. Inner
retransmissions rose from 232 to 419 while timeouts fell from 30 to zero.
The held-out run changed no measured goodput, P99 or debt. Its first
different probe was at 59.749 s, long after the throughput window. All
four arms confirmed their outer sources. The matched comparisons verify
the frozen receiver, SACK wire, physical charges and CPU bindings.
[Matched runs and deterministic replay of the missing ACK](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-quiet-v4-comparison.json).

The Rust receiver now constructs its Cauchy coefficients on entry to an
actual recovery. Intact reception, duplicate filtering, and committing a
split singleton need no field coefficient lookup. The CPU calibration
above measured the earlier eager construction. No timing improvement
has been inferred from this code change.

The local workspace check passed, including 1,786 Python tests and two
subtests. The final lazy-coefficient change also passed the nine focused
Rust striped tests and the FEC crate's all-target Clippy check with warnings
denied. A privileged Linux Common carrier run for this mixed profile is open.
[Workspace check receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-29/result.json).

#### Cross-group custody and authenticated UDP

The Rust sender retains the original mixed member across carrier backpressure
and named retries. Its credit counts staged inputs and sealed groups until
their cumulative confirmation and physical output commitments permit release.
The sender accepts an early cumulative receipt for a whole group after the
kth distinct physical member has been accepted. The receiver makes complete
records from later groups available while reserving expanded-byte capacity
for the oldest missing group. After all originals of a later group have been
handed off, it releases the decoder rows immediately and keeps its interval,
shape and width for duplicate handling. Native completion and the highest
physically observed source are tracked separately from the last ID implied
by the group's authenticated shape.

A two-socket UDP loopback check runs the maintained established Common record
protection with ChaCha20-Poly1305 in both directions. Two members of the
first 3-of-4 group and one of the next are discarded before decryption.
The second group commits before a single named retry recovers the first.
The two peers use the same sockets for the request, freshly protected retry
and final cumulative receipt. Replaying that retry is rejected. The fixture
now runs from source `u64::MAX - 7` through the inclusive last source.
The production feedback grammar can carry a cumulative receipt and one
64-position named mask together. The receiver bounds logical feedback
replay independently of the enclosing carrier replay window.
[Sender custody](../../crates/l2tunnel-fec/src/striped_group/transmit.rs),
[receiver byte-credit and ordering tests](../../crates/l2tunnel-fec/src/striped_group/receive_window/tests.rs)
and [UDP record composition](../../crates/l2tunnel/tests/secure_record/striped_udp.rs).

#### Mixed native records in the functional Common Engine

Tag 10 encodes both complete directional policies in the existing catalog.
The Engine uses the shared MUX, real Packed native encoder and receiver,
mixed transmit and receive windows and ordinary physical completion tokens.
In the functional integration test, 54-byte and 55-byte IPv4 packets became
two units in one Packed source. A shortened group emitted two mixed members.
The first was erased. The other independently restored both native packets.
Both units were committed once. An old physical token could not confirm the
second transmission even with equal public emission fields. The native
bridge also exercises context tag 8 followed by fixed-anchor deltas 11/11,
missing predecessors, retained device writes and split record lifetimes.
[Engine integration](../../crates/l2tunnel/src/record_engine/striped_tests.rs)
and [native record tests](../../crates/l2tunnel/src/striped_records/tests.rs).

An additional loopback run carried native Engine outputs through the
actual authenticated Records and UDP sockets. All 18 members in the
group began with `0x11`, the same leading byte as two cumulative receipts.
The authenticated class disambiguated them. The 18 packets reached native
delivery once each. Reversing two cumulative receipts preserved the final
prefix. Every emitted IP charge equaled the received UDP payload length
plus 28 bytes of IPv4/UDP headers, including the 21-byte Records overhead
already present in the payload.
[Overlapping tags, physical prices and delayed receipt](../../crates/l2tunnel/src/record_engine/striped_tests/overlap.rs).

Packing stops polling unchanged serialized bytes on FEC credit refusal.
A physical member whose exact IP cost misses the current budget by one
byte keeps its identity and reports that cost to the runtime token bucket.
Feedback scheduling quotes the size of the selected cumulative/missing
fields. A repeat quiet probe also shares service with an older outstanding
named request when write opportunities are sparse.
[Physical scheduling](../../crates/l2tunnel-fec/src/striped_group/schedule.rs)
and [Engine packet preparation](../../crates/l2tunnel/src/striped_records/endpoint.rs).

The service exporter selection `--striped-5-4` exercised normal storage
preflight with all four carrier parameters. UDP, raw TCP, TLS and QUIC
each returned `ReservedStripedLayout` before startup. The functional owner
reserves the sender's staging, group metadata, physical member ring and
encoder scratch before using them. At a 1,500-byte MTU, 49 outer bytes
and 8,192 source slots, these four allocations total 19,378,888 bytes.
The remaining recovery indexes, receiver custody and GF work storage still
need allocation bounds compatible with each simultaneously retained epoch.
No native throughput measurement for tag 10 follows from this preflight.
[Service admission results](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-service-catalog-v1/manifest.json)
and [actual sender capacity](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-transmit-custody-capacity.json).

The functional sender now reserves its native Packed encoder from the same
plan used in preflight. At the UDP geometry above this encoder needs 36,438
bytes per direction. The native decoder plan, including early replay and
fixed anchors, quotes 266,771,147 bytes forward and 266,697,419 bytes
reverse. These are per-direction component capacities. The exporter reports
the expanded repair-row allowance separately. A complete endpoint must price
its local send and receive directions and any overlapping epochs before
the service can accept this profile.
[Per-carrier and per-direction storage plans](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-service-resources-v2/manifest.json).

#### Native IP header and single-flow model comparison

The Python study now has an explicit `--forward-fixed-anchor` selection.
It strips and locally restores the fixture's fixed Ethernet addresses.
Native IPv4 and IPv6 headers, context record distances, fragments and raw
fallback can be compared at the Rust record boundary. The Rust encoder and
Python emitted the same 17,904 bytes in 56 units for 40 inputs on two
channels. This checks wire encoding on those inputs. The simulated sender,
network timing and TCP loss response require separate comparisons.
[Python integration](../../simulator/src/l2tunnel_sim/fixed_anchor_packed.py)
and [Rust golden-vector check](../../simulator/tests/test_fixed_anchor_ip.py).

| Forward recovery and header | Initial goodput, Mbit/s | Held-out goodput, Mbit/s | Initial / held-out completed-write P99, s |
| --- | ---: | ---: | ---: |
| 5/4 mixed, native-IP fixed anchor | 62.498 | 1.182 | 1.282 / 37.337 |
| 5/4 mixed, native-IP raw | 60.839 | 0.761 | 1.248 / 39.823 |
| Rolling near8, historical chained header | 72.357 | 21.808 | 0.616 / 6.642 |
| Rolling near8, native-IP fixed anchor | 1.029 | 11.783 | 40.319 / 18.600 |

These single-flow model runs use a 4 MiB application credit limit, 100/10
Mbit/s, 70 ms RTT and independent 15% loss in each direction. Goodput uses
seconds 2–12. P99 covers completed writes including drain. Both 5/4
native-IP configurations confirmed all application writes and outer sources.
Based on the same frames in each fixed-anchor run, the fixed-anchor code
saved 38.513 and 37.621 bytes per forward frame relative to native-IP raw.
The two rolling rows also change the original Ethernet/native-IP record
boundary. They do not isolate the header dependency alone. A common seed
does not preserve which packets get erased when a change modifies packet
sizes, send order or generated feedback.
[Paired results, byte charges, complete configurations and all three debt measures](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/fixed-anchor-closed-loop-comparison.json).

In the held-out fixed-anchor 5/4 model, the receiver had the exact header
context before TCP segment 260 arrived. At 2,358.751 ms source 448 was
recovered and the segment was passed to TCP in the same callback. Just
0.381 ms earlier, a duplicate of segment 259 had refreshed the model's
recent TCP timestamp. PAWS rejected the older segment 260. A received the
covering-prefix ACK and SACK evidence for higher bytes at 2,393.905 ms.
After undoing recovery on that partial ACK, its cumulative-only sender
ignored eleven duplicate ACKs at the unchanged edge below its prior
recovery boundary. Its retransmission timer expired at 3,393.905 ms.
For segment 475 the repeated ACK edge equaled the old boundary, without
a partial-ACK undo. The sender waited a second there too.
[Exact-input stall and TCP event trace](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/fixed-anchor-held-first-steady-stall-exact.json).

The simulator now exposes `--tcp-newreno-ack-heuristic`. On the third
duplicate ACK it can reenter fast recovery when the window exceeds one
SMSS and the last cumulative ACK advanced by at most four SMSS, measured
in actual stream bytes. The earlier cumulative-only selection remains
available. On the held-out run this advanced retransmission of segment
260 by 998.510 ms. Across the ten-second sample inner retransmissions
fell from 45 to 39 and RTOs from two to zero. Goodput moved from 1.182
to 1.128 Mbit/s and completed-write P99 from 37.337 to 27.441 s. One
already received reverse source still awaited cumulative confirmation
after drain. On the initial seed, goodput moved from 62.498 to 61.789
Mbit/s, P99 from 1.282 to 1.160 s and inner retransmissions from 18 to
34. Both runs confirmed all application writes. The tested heuristic
describes a NewReno sender. Linux SACK/RACK recovery and PRR use
additional evidence and state.
[RFC 6582, section 4.1](https://www.rfc-editor.org/rfc/rfc6582.html#section-4.1)
and [paired control, candidate and bounded ACK replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/newreno-ack-heuristic-comparison.json).

With rolling fixed anchors, the previously measured Linux run reached
69.927 Mbit/s and repeated 15 inner segments during seconds 2–12. The two
Python rolling fixed-anchor runs reached 1.029 and 11.783 Mbit/s and
repeated 23 and 91 segments in that interval. Linux transmitted a SYN and
the probe's four-byte connection identifier before timing began. The
Python models began with established, empty connections and consumed
cumulative ACKs while transmitting and pricing SACK blocks. Record identity,
loss history and congestion-window state therefore differ before the first
measured application write. Neither seed is a replay of the Linux capture.
[Same-window comparison and first observable input difference](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/rolling_fixed_linux_python_compare.md).

Replaying the Linux startup receiver through physical packet number 8,305
provides a packet-level comparison independent of the two TCP senders. The
replay used 7,058 actual B admission events in order. It reconstructed
systematics and repair right-hand sides from captured A TUN input,
retained Packed identities and the coding supports. Packet lengths matched
the observed B datagrams. Neither capture retained the plaintext of the
authenticated repair bodies. The production Rust rolling receiver and an
independent Python GF(256) decoder both solved the context source 4,495 on
packet 6,416, the trailing source 4,502 on packet 7,547 and the missing
source 4,497 on packet 8,305 at 1,060.215 ms. That packet supplied source
4,449 to an existing equation. The reconstructed 1,500-byte IP datagram
matched the native captures at both ends. The observed receiver made it
ready at 1,066.642 ms. This isolates algebraic readiness from the subsequent
6.427 ms of receiver delivery work and the earlier 57.212 ms between A's
MUX admission and packing.
[Physical identities, byte verification and limitations of the replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/pn8305_receiver.json).

Request 622 had already authorized both source 4,489 and source 4,497
when A sent two 1,309-byte datagrams in slots 7,535 and 7,541. The first
arrived and the second was lost. Exchanging their payloads on the same
recorded slots made source 4,497 available 61.527 ms earlier and delayed
source 4,489 by exactly as much. At each of the 7,058 admissions, the
contiguous TCP byte prefix obtainable from the restored IP packets was
identical in both replays. This comparison freezes subsequent traffic and
assumes immediate native delivery. It measures the effect of this one
equal-cost exchange on available bytes. It leaves closed-loop Linux ACK
timing and other retry schedules open.
[Equal-cost swap, source identities and cumulative-byte comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/pn8305_paid_slot.json).

The local workspace gate `python3 tools/check.py` passed with these Rust
and simulator changes. Its Python suite reported 1,797 tests and two
subtests passed. The gate covers the two-socket fixture above and excludes
privileged TUN throughput runs and remote CI.
[Local command and exit status](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-32/result.json).

#### Inner TCP SACK evidence and repeated congestion recovery

The selectable simulator scoreboard consumes SACK ranges after actual
reverse TCP frames arrive. It prices those frames in both experiment arms.
It uses the SACK loss evidence and conservative pipe accounting documented
in the simulator. It keeps the existing NewReno window response. It does
not model the complete Linux TCP sender. In a 5/4 single-flow run it selected
segment 33 just after the tunnel had physically sent the requested repair.
The repaired original reached TCP 1.364 ms before the inner retransmission.
Another extra retransmission, of segment 43, advanced delivery by 79.636 ms.

The first scoreboard experiment exposed an invalid timestamp undo after
multiple different segments had already been retransmitted. Restricting
that proof to its original single retransmission took the initial seed
from six lifetime retransmission timeouts to zero. Frequent congestion
responses still reduced its window to five segments by second two.
The candidate is an explicit comparison policy.

| Seed, fixed-anchor 5/4 | Wire-only SACK goodput, Mbit/s | Scoreboard goodput, Mbit/s | Completed-write P99, wire to scoreboard | Steady inner retransmissions, wire to scoreboard |
| --- | ---: | ---: | --- | --- |
| Initial | 61.789 | 0.753 | 1.160 to 40.648 s | 34 to 43 |
| Held out | 1.128 | 0.953 | 27.441 to 39.983 s | 39 to 43 |

All application data completed. In the held-out scoreboard run one already
received forward source was still awaiting its cumulative confirmation.
The bytes in split traffic vary with the offered TCP work that actually got
sent. In the initial control the forward path spent 21.37 MB of 142.12 MB
on split members and the reverse path spent 6.80 MB of 8.39 MB. The receipt
separates physical header, original, parity and retry bytes per direction.
[Paired runs and costs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/maintained-sack-comparison.json)
and [initial sender sequence and window trace](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/maintained-sack-startup-initial-scoreboard-v3.json).

The first local workspace run exposed two tests that still used the newly
allocated tag 10 as an unknown tag. They now use 11. An impaired OpenVPN
shutdown also exceeded its five-second deadline after delivering all 112
packets. The last fresh control packet arrived 2.618 seconds into shutdown
and restarted the 3.009-second quiet interval. The same binary passed in
isolation. The second workspace run passed, including 1,801 Python tests and
two subtests. A focused run of all ten striped Engine and native tests and
Clippy on both affected crates also passed for the final reservation changes.
[First workspace run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-engine-gate-01/result.json),
[isolated shutdown](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-engine-gate-01/isolated-openvpn-1795154261168737207.json)
and [second workspace run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-engine-gate-02/result.json).

#### Reserved mixed-packet service and first native single flow

The four carrier plans now accept tag 10. With UDP at MTU 1,500, the
receive window reserves 11,892,396 bytes of row storage, 917,952 of metadata
and 7,838 for one shared GF transaction. Each native dependency index set
uses 5,832,704 bytes. The complete local Engine costs 321,247,543 bytes at
the initiator and 321,321,271 at the responder. The service retains a
separate budget for overlapping epochs. Sender custody, recovery deadlines
and native dependencies use preallocated storage. The actual socket and
device handoffs preserve the data, group and native record identities.
[Per-role and per-direction plans](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-reserved-bank-v2/manifest.json).

Both production endpoints authenticated and transferred 18,967 512-byte
records over one Linux CUBIC connection. The UDP trial used 4 MiB of
application credit, 100/10 Mbit/s, 70 ms RTT and 15% loss each way with
forward seed 31248. It delivered **3.647 Mbit/s** in seconds 2–12, with
**97** inner retransmissions during that interval. First attempted application
write to complete read through drain had **9,190.783 ms P99**. Both stream
hashes matched. The original wire metrics validator omitted the new mixed
coverage class. Revalidating the same sender files accounted for all 28,930
and 12,512 accepted records. The original service status omitted the final
outstanding mixed source count.
[First native arm and offline wire validation](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-01/offline-validation.json).

Joining the embedded write times and byte ranges across both native captures
accounted for all 18,967 records. Among the 190 slowest by receiver prefix
availability, the average time from write attempt to first matching byte at
the sender TUN was **9,083.875 ms**. The rest of the record appeared there
in another **1.178 ms**, and its whole cumulative prefix at the receiver TUN
in **136.332 ms** more. Those three means refer to exactly the same records.
The first forward retransmission followed loss of both fresh singleton
members for source 34. The named retry left the carrier before TCP's
selective retry and arrived 24.6 ms after that retry began. The receiver had
the native record ready 18 microseconds after the named packet opened.
Of 4,020 traced forward fresh members, 3,978 were split members. No full
five-member group occurred in that initial trace.
[Application-to-TUN timing](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-01/application-capture-stages.json)
and [first holes aligned to physical members, native ranges and SACKs](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-01/mixed-member-first-holes.json).

The second same-seed arm offered already-ready Packed sources up to one
mixed group per Engine turn. It split the leading source of an oversized
short group only when no ordinary contiguous prefix fit. The remaining
sources retained their deadline. Among 4,007 fresh physical members within
the first 4,096 data PNs, 3,896 still came from split singletons, 102 from
two-member groups, four from a four-member group and five from one full
group. It delivered **2.455 Mbit/s**, with **15,664.545 ms** application
P99 and **81** inner retransmissions in seconds 2–12. All 15,091 writes
completed. Two reciprocal post-EOF readings confirmed all sources in
both directions, including the last forward ID 11,631 and reverse ID 5,101.
[Second native measurement](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-02/offline-validation.json).

For the second arm the slowest 151 records by receiver-prefix availability
averaged 15,618.254 ms from first attempted application write to first
sender TUN visibility. The two arms had nearly identical median smoothed
RTT (78.62 and 78.58 ms), but median congestion windows of 27 and 18.5 MSS.
The first physical packet carrying the opening SYN was observed by the peer
in the first arm and absent in the second. The Linux byte segmentation
also diverged before the first data ACK. The same RNG seed did not assign
identical erasures to the same TCP bytes. Comparing two completed runs
therefore establishes the measured regression but does not isolate the causal
effect of either scheduling change.
[Matched record timings](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-02/application-capture-stages.json)
and [per-sequence, socket and congestion-window comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-02/paired-regression.json).

Over the complete second transfer the forward UDP sender spent 18,500,132
IP bytes on 7,726,592 application bytes. Holding that composition fixed
would cap goodput at 41.77 Mbit/s on a 100 Mbit/s link. At 70 Mbit/s the
budget is 1.429 forward IP bytes per application byte. At 78.58 ms RTT
and MSS 1,448 this rate needs about 475 segments in flight. Across the
steady samples the available inner send window and the actual IP traffic
were well below that level. The 4 MiB application cap has room for the
required flight. Replaying the actual captured sender byte stream at its
observed staging times and 1,073-byte Packed limit also produced zero full
groups in the Python baseline. Several naturally simulated groups received
all five sources at one simulated timestamp. The source clocks, protection
mix and TCP responses all matter to the comparison.
[Measured IP cost and window budget](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-single-flow-cap-price.json)
and [common-input replay and historical Linux control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-same-input-and-live-controls-v1.json).

Five steady service samples in the second arm held 32–77 unconfirmed forward
logical sources (median 38) and 14–31 reverse (median 17). The negotiated
aperture is 8,192 per direction. Among the captured successful transmissions,
the measured time from UDP send acceptance to peer authentication put a
mean 22.31 forward and 12.50 reverse datagrams in flight over the traced
parts of the steady window. The corresponding time-weighted P99s were 36
and 23. Lost datagrams have no observable discard timestamp in this join.
Linux TCP had a median of 25 segments awaiting cumulative ACK, with 18
estimated in flight after its selective-ACK and loss accounting. The
median TCP payload queued but not yet sent was 4,157,824 bytes.
[Directional custody, socket and physical packet populations](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped-single-flow-inflight.json).

Counting only fresh split members in those packet-number prefixes, the
forward direction paid 3,078,115 IP bytes for 1,423,671 bytes of direct
Packed data. This comprised 1,432,782 parity bytes, 30,758 mixed header
bytes and 190,904 outer bytes. Relative to each member's direct half, the
mean additional cost was 424.65 B and P99 was 599 B. Reverse fresh splits
paid 549,219 IP bytes for 158,841 direct bytes, with mean additional cost
97.79 B and P99 144 B. This denominator excludes Packed metadata savings,
feedback and retries. Physical lengths agreed on all 3,326 forward and
3,429 reverse fresh split members visible on the respective WAN captures.
[Split-member price audit](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-02/split-byte-prices.json).

To separate the byte cost from the slow TCP start, a continuous replay fed
8,589 native packets from a previously fast Linux flow into the mixed encoder
at their captured times. With the production 1,073 B Packed limit, 68.27% of
first transmissions belonged to full groups, yet their combined IP cost across
all shapes was 1.5302 bytes per unique TCP payload byte. The most efficient of
the four tested limits was 768 B, at 1.4401. The resulting first-transmission
ceilings on the 100 Mbit/s link were 65.35 and 69.44 Mbit/s respectively,
before any retransmission. At a 540 B limit, 90.63% of packets belonged to full
groups, but a typical 1,448 B TCP payload required three fragments and the
ceiling fell to 67.43 Mbit/s. The replay held the native arrival times fixed.
It measures packetization cost and cannot predict a live TCP window or P99.
[Continuous input and width comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-high-linux-ingress-widths-v1.json)
and [two-fragment boundary](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-high-linux-ingress-mss-half-v1.json).

Both WAN captures of the second live arm measured forward IPv4 datagram
lengths of 469 B at P50, 1,139 B at P99 and 1,495 B maximum. In reverse
these were 122, 230 and 777 B. Neither capture contained an IPv4 fragment.
The single TCP connection occupied MUX channel 0. In the only full group
in the forward trace prefix, four members carried complete records 10–13;
the fifth carried the first of two fragments of record 14. Across the 990
forward native records with complete fragment coverage, the time from codec
staging to first UDP send acceptance was 1.257 ms at P50 and 3.329 ms at P99.
By 4.591 ms at P99 at least one fresh member for every fragment had reached
the sending socket. These local intervals exclude network transit and repair.
[Directional IP and UDP lengths](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-02/wan-datagram-sizes.json)
and [group membership and local sender timing](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-02/group-native-composition.json).

Replaying the captured sender IP bytes through the Rust fixed-anchor encoder
identified the exact context of every forward delta in this prefix. Among 990
complete native joins, 14 waited over 10 ms after their own fragments became
solvable. Seven depended on context 448 and seven on 1104. The largest wait
was 212.023 ms for context 448. From the last required fragment **and** context
becoming solvable to native readiness, forward P99 was 0.325 ms. The opposite
direction had 2,164 complete joins and P99 0.215 ms from solvability of the
frame's own fragments to native readiness.
[Captured solvability, encoder dependencies and TUN writes](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-bank-02/mixed-after-solvable.json).

The sender now advances a staged fragmented native record under the existing
per-turn quota before trying to stage the next queued native. The Linux mixed
runtime uses a reusable monotonic timerfd for short deadlines. On receive,
first-time gap notifications have their own 1 ms deadline while repeats
still use 35 ms from physical acceptance. On the second arm's frozen
authenticated arrivals, first visibility to first naming of its 40 fully lost
forward split pairs changed from 33.863 ms P99 to 1.000 ms P99. The replay
keeps later arrivals fixed and cannot determine actual TCP throughput.
[Sender and wake checks](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-sender-turns-v1.json)
and [same-arrival Rust gap scheduler replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-feedback-first-visibility/result.json).

### Linux single-flow service after mixed scheduler changes

With one CUBIC flow, 4 MiB socket credit, 100/10 Mbit/s, configured RTT
70 ms and 15% loss in each direction, the 500 µs group hold produced
53.032 and 52.742 Mbit/s in two successive runs of the same binary. The
subsequent binary exposed per-class charges. Its 500 µs arm reached only
4.454 Mbit/s. Its 1,500 µs arm changed only the forward FEC deadline in
the negotiated descriptor. Packed and reverse FEC holds stayed at 500 µs.
All four runs matched the complete byte streams and observed zero
bidirectional source debt twice after EOF. The same netem seed does not
align erasures to identical TCP segments.

| Forward FEC hold / run | Receiver goodput, 2–12 s (Mbit/s) | Attempted write to complete read P99 (ms) | Steady inner retries | Median cwnd (MSS) | Lifetime forward IP B / delivered application B |
| --- | ---: | ---: | ---: | ---: | ---: |
| 500 µs, scheduler 03 | 53.032 | 933.772 | 8 | 828.5 | 1.892 |
| 500 µs, scheduler 04 | 52.742 | 871.904 | 64 | 759.5 | 1.900 |
| 1,500 µs, priced 05 | 52.720 | 1,006.528 | 20 | 856 | 1.857 |
| 500 µs, priced 06 | 4.454 | 8,476.936 | 67 | 32.5 | 2.313 |

In the fast priced arm, the sender paid 110,827,409 forward IP bytes for
fresh data, 33,927,684 for named retries, 3,957 for quiet retries and
126,549 for recovery feedback. Their sum equals the independently joined
terminal wire counters. First transmissions alone consumed 1.420 IP bytes
per delivered application byte. In the slow priced arm, the corresponding
ratio was 2.244 and the median TCP RTT was 75.945 ms. The fast arm had
16,293 full forward groups. The slow arm had four. Both policies remain
available and the 70 Mbit/s gate stays open.
[Scheduler 03](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-scheduler-03/verified.json),
[scheduler 04](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-scheduler-repeat-04/verified.json),
[priced 05](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-1500us-s1-seed31248-05/verified.json)
and [priced 06](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-500us-s1-seed31248-priced-06/verified.json).

Within the fast priced arm's first 4,096 forward data packet numbers, 543
named retries reached the receiver. The target source was already solvable
on 442 of these arrivals; 101 were the first to make at least one source
solvable. Removing same-source retries paid within 70 ms of a prior retry
delayed four forward sources on frozen arrivals. In reverse, one source
lost its only observed recovery inside the trace. A physically feasible
reverse notification backed by actual native readiness could have preceded
at most 42 forward retry selections in this prefix. Its attainable
benefit also depends on the NACK having reached the sender first.
[Physical retry attribution](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-1500us-s1-seed31248-05/named-rtt-replay.json)
and [return notification opportunities](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-1500us-s1-seed31248-05/selective-availability.json).

The priced arms each carried one TCP connection on MUX channel 0. An outer
IPv4 datagram had a 1,500 B limit, including 20 B of IPv4, 8 B of UDP and
21 B of protection. The remaining 1,451 B includes the mixed header, direct
data and parity. Captured IPv4 lengths at A for forward / reverse traffic
were 1,406 / 150 B at P50 and 1,498 / 1,461 B maximum in arm 05. In arm 06
they were 1,138 / 142 B at P50 and 1,495 / 785 B maximum. Neither WAN sample
at A contained a fragmented UDP datagram.

Within the bounded forward traces, arm 05 group 330 carried parts of six
native records in five physical members. Its first member included units
from records 222 and 223. The other members included units from 224 through
227. All belonged to channel 0. In arm 06, 1,996 of 2,001 fully traced groups
split one logical source into two independently recoverable members. For the
first TCP hole at relative sequence 23012, both members of source 30 were
lost. Its other fragment reached the peer at 139.236 ms. A named retry made
the missing part available at 209.997 ms and the original segment appeared
on the peer TUN at 210.036 ms. The inner TCP sender had retried at 197.060 ms.
Across 1,162 forward records with complete dependency joins, P99 from all
necessary fragments and header context being available to native readiness
was 0.630 ms. P99 from the last data fragment alone was 102.795 ms across
1,168 records.
[Arm 05 group 330](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-1500us-s1-seed31248-05/forward-records-a-4153661.tsv),
[arm 06 first holes](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-500us-s1-seed31248-priced-06/single-flow-startup-first-holes-v1.json)
and [arm 06 native dependencies](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-500us-s1-seed31248-priced-06/startup-after-solvable.json).

Three frozen or simulated comparisons extend this diagnosis. Sending an
extra copy of each early forward header context in Python helped application
P99 on one seed and hurt it on the other. This candidate remains opt-in.
With the Rust encoder and the same recorded arrivals, a full 12/10 group
could recover two erasures. The byte budget for this geometry reached
70.84 Mbit/s only under a model that requests the earliest missing members
needed to fill the rank deficit and avoids duplicate payments. Its short
groups can still require feedback after two losses. On the separate Linux
ACK tape, the optional sender-side reordering observer reproduced the
first three sampled distances of 3, 96 and 300 segments. The observer
does not implement Linux RACK timers or change the TCP loss decision.
[Two-seed context comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-startup-anchor-v1-comparison.json),
[geometry budgets](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-scheduler-03/rust-native-geometry-price-v2.json),
[survivor-subset checks](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-scheduler-03/rust-native-geometry-rank-witness-v1.json)
and [Linux reordering comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-scheduler-03/sender-visible-reordering-observer-v2.json).

### Single-flow congestion window and header dependency

The 12/10 forward candidate (arm 07) delivered 4.018 Mbit/s in the
2–12 s interval, with a 9,469 ms first-write-to-complete-read P99 and
44 inner retransmissions. Both directions drained. Zero forward groups
reached 12 members. The 5/4 arm 05 delivered 52.720 Mbit/s on the same
configured network. The seed fixes the loss generator, while changes in
traffic timing and geometry can change which native segments encounter loss.
[Arm 07 application and drain](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/verified.json)
and [arm 05 application and drain](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-1500us-s1-seed31248-05/verified.json).

| TCP sender observation | 12/10 arm 07 | 5/4 arm 05 |
| --- | ---: | ---: |
| cwnd at 1.5 / 3 / 4 / 12 s (segments) | 22 / 28 / 15 / 46 | 843 / 846 / 849 / 886 |
| Median cwnd / pipe in 2–12 s (segments) | 27.5 / 26.5 | 856 / 851 |
| Median pipe as a fraction of cwnd | 97.5% | 99.5% |
| Median sender smoothed RTT (ms) | 78.413 | 197.674 |
| Cumulative TCP bytes acknowledged at A in 2–12 s (Mbit/s) | 3.995 | 53.094 |

All 20 steady samples in arm 07 had at most two unused congestion-window
slots. The sender had at least 4.08 MB queued but unsent. Both socket
limitation counters showed zero time under the peer receive window or
the sender buffer limit. There were no retransmission timeouts during
the measured interval. Between 3.504 and 4.005 s, the sampled cwnd fell
from 24 to 15 segments with seven more kernel retransmissions. Sender
ACK progress recovered from 2.39 Mbit/s in seconds 4–5 to 5.72 in
seconds 10–11. The socket samples give half-second observations.
[Arm 07 snapshots and both native captures](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/inner-tcp-window-and-acks-v2.json)
and [arm 05 snapshots and captures](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-1500us-s1-seed31248-05/inner-tcp-window-and-acks-v2.json).

In arm 07, native record 42 carried TCP bytes [36980, 38428). Its own
Packed fragments were solvable at 189.115 ms. Its compressed IP/TCP
header referenced native context record 40, whose first usable copy
arrived at 259.099 ms. The original IP packet reached the peer TUN at
259.264 ms. The sender had already retransmitted at 239.309 ms.
Of 22 distinct ranges first retransmitted in the first half second,
13 had all their own fragments before the header dependency resolved.
The other nine still needed data. With a hypothetical independent header,
all 13 had time for a selective ACK under the propagation floor. Earlier
data holes still prevented a cumulative ACK covering any of these 13
before its retry. A separate raw header replay of the same native inputs
through 500 ms increased fresh forward IP bytes by 6.78% on arm 07 and
7.81% on arm 05. These are encoded byte costs before retry feedback.
[Native and outer events](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/first-half-second-retransmissions-v1.json),
[ACK timing bounds](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/header-ack-counterfactual-bounds-v1.json),
[arm 07 encoding](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/native-header-cost-full-prefix-v1.json)
and [arm 05 encoding](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-1500us-s1-seed31248-05/native-header-cost-full-prefix-v1.json).

In the 2–12 s interval, 12 of the 44 retransmissions left A before the
original reached B's TUN. Another 25 left A with less than the 35 ms
minimum return delay elapsed since the original arrived at B. In one
traced episode, logical source 1711 lost both fresh split members and
the first three named copies. The fourth named copy opened at 3,568.467 ms.
The inner retransmission for TCP offset 1,351,764 reached B at 3,503.002 ms,
before the delayed original. The resulting ACK carried a newer echoed
timestamp. Five later originals across this recovery sequence elicited
ACKs within 3–15 µs with unchanged cumulative and selective coverage.
Their newer retransmissions advanced coverage within 7–27 µs. These
captures are consistent with PAWS rejection of the late originals.
Per-packet kernel drop reasons were unavailable.
[Steady retry accounting](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/steady-inner-retry-ack-races-v1.json),
[individual member transmissions](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/steady-first-drops-forward-attempts-v1.json)
and [TCP timestamp and ACK sequence](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/steady-inner-late-paws-evidence-v2.json).

At the start of the measured interval a different gap showed the propagation
limit directly. The two fresh packets for source 1105 and its first named
copy all disappeared between the sender and receiver WAN captures. The
second named copy reached the receiver at 2,397.600 ms. B's TUN observed
the original for TCP offset 850,756 at 2,397.757 ms and its cumulative ACK
21 µs later. A had sent its inner retry at 2,401.437 ms, over 32 ms before
that ACK arrived at A. Speeding up ACK processing at B alone could not
prevent this retry. Source 1105 carried the remaining fragments of two
adjacent native segments.

A fixed-arrival replay swapped two equally sized second copies without
moving the first copy of either source. For sources 1711 and 1712 it
advanced the whole frame's first decodability from 3,568.467 to
3,354.290 ms. Across 199 eligible pairs in the covered portion of arm
07's measured interval the same rule rescued three frames but introduced
five new first-pass misses. At the observed packet-number limit, arm 05
provided startup coverage only for this comparison. The send order stays
experimental. [Equal-byte send-order replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-05-07-equal-price-split-interleave-v2.json).

The separate raw-IP arm 09 completed carrier authentication. Its initiator
reported peer timeout 58.995 ms before the native SYN, and neither daemon
read a TUN packet. This arm provides no application or throughput sample.
The missing liveness exchange begins before WAN capture.
[Arm 09 startup diagnosis](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-header-09/startup-causal-diagnosis-v1.json).

The optional Python `rack-dsack` sender now counts newly SACKed data once
for eligible window growth after learning high reordering, uses pre-loss
cwnd for its multiplicative decrease and charges transmissions against
proportional rate reduction during recovery. On arm 03's sender ACK tape,
nine first-time SACKs raised the model window from 38 to 47. The first
recorded original exceeding calculated model send credit moved from 352.508
to 365.785 ms. Later forced originals violate that credit, so this replay
cannot qualify closed-loop throughput parity.
[First credit difference](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-scheduler-03/first-frozen-original-credit-high-reorder-ss-v7.json)
and [sender replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped5-s1-seed31248-scheduler-03/sender-rack-timer-high-reorder-ss-v7.json).

### Erasure protection at the short-group deadline

In Linux UDP/TUN arm 07, TCP offset 1,351,764 left A at 3,317.443 ms.
The original reached B's TUN at 3,568.512 ms, 251.069 ms later. Linux had
already sent an inner retransmission, which arrived at B at 3,503.002 ms.
The first six physical members (PN 3001–3006) protected three consecutive
Packed sources of 1,079, 1,079 and 820 bytes as three separate pairs. Both
members of source 1711 disappeared, while the four members of 1712 and
1713 arrived. None contained a check equation for 1711. Its first three
named transmissions reached the sender socket but never opened at B. The
fourth opened at 3,568.467 ms. The native record also needed a fragment
from 1713, which had already arrived. A sent the inner retry at 3,466.211 ms.
B acknowledged through TCP offset 1,402,444 at 3,503.029 ms, 27 µs after
that retry reached its TUN. The same ACK reached A at 3,539.365 ms. TCP
had therefore confirmed this range before the tunnel delivered the original.
[Per-source physical attempts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/steady-first-drops-forward-attempts-v1.json).

The third and fourth named sends were 71.577 ms apart. Two reverse datagrams
reached A 71.581 ms apart, immediately followed by those sends (126 and
122 µs to socket submission). Three intervening reverse packet numbers were
paid by B and absent from both WAN captures. Their encrypted masks were
not retained, so the individual lost request cannot be identified.
[Forward retries and reverse packet numbers](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-source1711-reverse-feedback-gap-07-v1.json).

A shortened ordinary three-member group at this base and length needs
1,675 IP bytes in its largest member, above the configured 1,500-byte MTU.
The actual wire confirms the independent pairs. Arm 07 did not log how many
sources were available to each sealing decision. The optional Rust
`mixed_seal` event now records the oldest deadline, actual seal tick,
offset, remaining input count, longest remaining source and selected count
against the first selected physical member. The three-input component
fixture reproduced two MTU splits and a trailing singleton. A local UDP
endpoint test joined seal, member and socket records.
[Component and UDP trace verification](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-group-seal-trace-contract-v1.json).

Replaying the preserved Rust Packed encoder on the sender's native read
timestamps puts all three sources at one 3,319.017 ms deadline. The same
replay on native stage timestamps puts them at one 3,319.033 ms deadline,
with the tail ready at 3,318.033 ms. The first actual physical member was
accepted by the sender socket at 3,319.142 ms. Both reconstructions use the
three exact source hashes. Their modeled availability supports a same-deadline
repair, while the historical capture leaves its FEC admission instant open.
[Sealing bounds under both clocks](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/split-triple-eligibility-clocks-v1.json).

The opt-in Python `--striped-split-triples` study protects three available
sources on the same deadline when the ordinary prefixes do not fit. It sends
six members. Each directly carries its entire source and one parity shard
for its two neighbors. Any four distinct members recover all three exact
sources. The normal receiver service fixture drops the first two members,
delivers both unaffected sources first, then restores the first from the
remaining four before a retransmission. Named and quiet retries retain the
source after a loss beyond this bound. The study keeps the reverse format
unchanged and requires `--striped-short-prefix`.

In the arm 07 fixed-arrival replay, source 1711 became solvable at
3,354.431 ms, 214.036 ms before its observed named recovery. The six IP
packets cost 7,936 B versus 6,312 B. This replay keeps the recorded packet
positions and arrival times. A live sender would pay the extra serialization
and may encounter different losses. All 15 four-member subsets and the
other nonempty receipt sets were checked on the actual source bytes.
[Source hashes, packet lengths and solve times](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/split-triple-cross-parity-v1.json).

The paired Python runs used one TCP flow, 4 MiB application credit, 100/10
Mbit/s, 70 ms RTT and 15% loss in both directions. Both sides used the
modeled Rust single-flow feedback schedule and named all missing logical
sources. The cross-source receiver excludes sources it already holds when
asking for retries. Rates and inner retries cover the steady interval.
P99 is application attempted write to completed read.

| Seed and short-group policy | Application Mbit/s | Application P99 (ms) | Inner retries | Final application debt |
| --- | ---: | ---: | ---: | ---: |
| Initial, independent pairs | 13.403 | 7,177 | 17 | 0 |
| Initial, full copies plus cross parity | 7.648 | 8,017 | 17 | 0 |
| Held, independent pairs | 56.922 | 1,571 | 33 | 0 |
| Held, full copies plus cross parity | 56.928 | 1,427 | 93 | 0 |
| Initial, paired halves with 6/4 Cauchy | 10.305 | 7,420 | 29 | 0 |
| Held, paired halves with 6/4 Cauchy | 10.206 | 5,127 | 10 | 0 |

The cross-source policy formed 351 and 17 eligible cohorts respectively
and actually recovered 200 and 8 sources by cross parity. Both directions
drained. These results leave the native performance gate open. The full-copy
cross-source candidate is implemented in the Python study only.
[Baseline and residual request controls](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-paid-timing-rank-v2-summary.json),
[initial seed](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/split-triple-rust-single-flow-initial-cross-v2.json)
and [held seed](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/split-triple-rust-single-flow-held-cross-v2.json).

The separate paired-halves experiment cut the same six first-pass IP packets
to 4,982 B and recovered 1711 at the same 3,354.431 ms fixed-arrival
boundary. Each packet immediately exposed its half. Two matching halves
or four distinct physical members were sufficient for a full source.
Twelve of the fifteen possible two-member subsets exposed no complete
source. The second seed completed far less application data during the
measurement despite a smaller fresh group and fewer inner retries.
[Byte-exact six-member comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/split-triple-half-cauchy-v1.json)
and [paired throughput and latency](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-half-triple-closed-comparison-v1.json).

A variable-length XOR candidate retained full-source delivery from every
single member and reduced the sample to 7,805 IP bytes. A separate
half-stripe candidate sent one complete first copy per source (6,470 IP
bytes). Both restored 1711 upon the fourth surviving member in the
fixed-position replay. Neither beat the baseline throughput on both seeds.
[Full-source XOR](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-variable-triple-closed-comparison-v1.json)
and [one full first copy](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-hybrid-triple-closed-comparison-v1.json).
Of 50 sources missing after first transmission in the covered steady
prefix, 15 qualified for the three-source layout and 10 would be restored by
the recorded first-pass arrivals. This fixes only part of the observed class
of failures. [Measured coverage and bounds](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-05-07-full-copy-triple-coverage-v2.json).

The complete 07 captures include only one inner TCP connection and one
bidirectional UDP socket tuple. The TUN and WAN IP MTUs were both 1,500 B.
Forward native packets had a 1,500 B P99, and forward WAN IP packets had a
1,495 B P99 and 1,496 B maximum. No captured IP datagram on either interface
had the more-fragments flag or a nonzero fragment offset. Native records
1126 and 1127 put their leading and trailing fragments into three Packed
sources, with both trailing fragments in 1713. This measures aggregation
of multiple record fragments per source on one carrier. Striping one inner
TCP connection across several established carrier tuples requires its own
integration and performance evidence.
[MTU and wire lengths](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/inner-outer-mtu-capture-v1.json)
and [observed carrier and native tuples](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-geometry-07/actual-native-and-carrier-flows-v1.json).

A separate Linux loopback experiment used six connected UDP pairs with
distinct port tuples. Each external member carried a 250-byte fragment
from each of three captured 1,500 B inner IP packets, alongside cross-member
parity and an actual 16 B authentication tag. The six 6/5 members measured
975 IP bytes each. All six single-erasure cases restored all three original
packets. The six 6/4 members measured 1,200 IP bytes each, and all fifteen
two-erasure cases restored all originals. Erasures were injected after UDP
receipt and before decoder admission. The fixture verifies the physical
mapping and threshold. Independently timed per-connection batching, cumulative
and selective acknowledgements across connections, piggybacking, and
single-flow performance on an impaired underlay remain unverified for
this mapping. [Six physical sockets and captured packet lengths](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-six-connected-udp-loopback-v1.json).

Linux arm 08 had a separate limitation. B advertised 5,888 B in all 271
steady ACKs. A spent 9.514 s receive-window limited. The receive threshold
of 5,792 B equals four advertised MSS, and the 256-byte scaling quantum
accounts for the wire value. Both endpoints captured matching packets.
The socket and system pressure state at the initial contraction was not
sampled. The socket probe now includes receive threshold, advertised MSS,
and available TCP pressure counters. The arm ended during a status query
before final drain and supplies no complete application P99.
[Socket and wire evidence](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-08-rwnd-4mss-provenance-v1.json)
and [measurement failure](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/striped12-s1-seed31248-rank-08/failed-measurement-diagnosis-v1.json).

### Independent physical paths for one inner flow

The horizontal-fragment experiment first encodes each complete native IP
packet into N indexed members. Any K distinct members restore that packet.
Every member contains its direct portion and, for K < N, cyclic Cauchy
parity protecting other portions. A single authenticated outer DATA message
can carry members from several native IP packets. Each physical path has
its own packet sequence, payload budget and oldest-entry flush time. A
blocked socket retains its frozen datagram while other sockets can proceed.

An A1 feedback batch carries cumulative and selective receipts for several
physical paths. A logical confirmation block covers committed native records.
The sender keeps unconfirmed group bodies across physical ACKs. A3 requests
name missing ordinals by stable group ID, allowing retries over any active
path. Fully decodable later records may enter TUN before older gaps. Missing
tail groups still require an oldest-unconfirmed retry when the receiver has
no later group from which to infer a gap.

The Rust UDP socket fixture exercises both 6/5 and 6/4. Three 1,500 B native
records aggregate into one datagram per path, measuring 979 and 1,204 IPv4
bytes respectively from the observed UDP payload sizes. Backpressure and
erasures are injected. Separate shared fixtures check the Python/Rust member
bytes. The six-socket fixture provisions test keys. The regular service still
needs authenticated path membership, resource preflight for combined epochs,
and requested/effective configuration.

The single-flow Python control uses one 100/10 Mbit/s shared bottleneck,
70 ms RTT, and a 4 MiB application credit. The model charges wire bytes in
both directions and assumes zero coding CPU time. With 6/5, named repair and
spare-bandwidth copies, two seeds produce 74.58 Mbit/s without loss, above
74.4 with 15% reverse-only loss, and 9.90 to 12.16 with 15% loss each way.
Among the slowest 1% from Kth arrival to cumulative TCP ACK, waiting at the
receiver for earlier TCP sequence numbers accounts for 79.13% and 82.93%
of the aggregate elapsed time. Every first blocking segment in these two
tails received fewer than K distinct ordinals on its first flight.
[Paired experiments, metric definitions and packet-stage timing](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-six-causal-and-ack-stage-v1.md).

The first impaired Linux comparison uses the Rust measurement endpoint and
six connected UDP tuples drawn from the same directional capacity. One
inner CUBIC stream uses a 4 MiB combined unsent/unacknowledged credit,
35 ms one-way delay and 15% loss each way. On both sides the A3 control
uses a 500 µs path hold, 1 ms initial gap delay, 70 ms repeat, 140 ms quiet
check and no unsolicited spare copies. Goodput and retransmissions cover
the ten-second sample. P99 covers first successful application write through
complete read of each accepted record, including warmup and drain.

| Endpoint | Single-stream goodput (Mbit/s) | Application P99 (s) | Inner retransmissions | Final outstanding groups |
| --- | ---: | ---: | ---: | ---: |
| Linux, seed 31248 | 0.956 | 31.965 | 55 | 0 in both directions |
| Python, initial seed | 1.529 | 19.246 | 48 | 0 in both directions |
| Python, held seed | 2.025 | 17.587 | 47 | 0 in both directions |

Linux recorded six active five-tuples. Of 10,934 accepted application writes,
all reached the reader. The sender's sampled congestion window ranged
from 5 to 14 segments while about 4.18 MB remained unsent in the TCP socket.
No time accrued against the TCP receive-window or send-buffer limit during
the sample. Neither adapter reported refused UDP sends or exhausted native
admission, and neither TUN reported a transmit drop. These observations
locate the seconds-long backlog before native transmission. The encrypted
captures alone cannot associate an individual congestion event with an
ordinal or a particular delayed reverse TCP ACK. The service handshake,
other carriers/platforms and the 70 Mbit/s performance target remain open.
[Linux measurement](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-single-seed31248-01/result.json),
[sender TCP_INFO analysis](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-single-seed31248-01-sender-tcp.json),
[Python initial](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-initial-rank-paid-flush-linux-pair-v6.json)
and [Python held](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-held-rank-paid-flush-linux-pair-v6.json).

The traced Linux repeat recorded 0.980 Mbit/s, a 36.506 s application P99
and 64 steady inner retransmissions. Native captures matched both endpoints'
local monotonic events with zero missing events. Among 926 forward groups
admitted in the sample, 715 reached K on their first flight. The other 211
needed named or quiet repair (22.79%). With independent 15% datagram loss,
the probability that at least two of six first-flight members disappear is
22.35%. Co-packing makes outcomes for different records in the same lost
outer datagram correlated.

Forward native admission through peer TUN delivery had a 36.20 ms P99 for
first-flight completions and a 248.23 ms P99 for named completions. After K
was reached, TUN handoff had a 0.165 ms P99. All 64 retransmitted original
TCP ranges lacked five first-flight members. At the instant of retransmission,
28 originals still needed rank, 14 had reached the peer before it emitted a
covering ACK or SACK, and 22 had covering feedback in flight. In 21 of those
22, the feedback had been in flight for less than the 35 ms one-way delay.
This limits what changing the ACK packing deadline alone can accomplish.
[Trace and TCP_INFO](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-single-seed31248-trace-02/result.json),
[population of first-flight and repaired groups](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-single-seed31248-trace-02-groups.json)
and [native sequence and ACK join](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-single-seed31248-trace-02-native-join.json).

In that control the receiver reported per-path observations, but the sender
only scheduled group-level named and quiet repairs. For native group 289,
six different slots paid six DATA members over 29 µs. The peer opened
ordinals 0, 2, 3 and 5 on the first flight. Two requests for ordinal 1 were
lost; a quiet retransmission on another path supplied it. The experiments
with a physical sender ledger address this additional path-ACK requirement.
The control did not log the physical ACK blocks. An offline bound combining
three later receipts or a 90 ms timer leaves enough time in 48 of the 64
cases for both repair and the returning inner TCP ACK, assuming successful
delivery and no extra scheduling delay.
[Original group and individual sends](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-single-seed31248-trace-02-native-join.json)
and [counterfactual timing bound](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-single-seed31248-trace-02-physical-ack3-bounds.json).

The optional path-ARQ lab profile retains up to 256 physical DATA packets
per slot. Three different higher positive receipts on that slot or a 90 ms
paid-send timeout trigger same-path retransmission under a fresh packet
number. Confirmed native delivery can cancel outstanding members. The sender
keeps bounded old packet identities for late ACKs. Named repair, oldest-group
recovery and independent delivery remain active. The sender's quiet check
now uses the oldest group's actual payment; the Python reference also pages
dirty physical ranges and logical ACK ranges. These experiment parameters
have not been selected as service defaults.

Linux arm 03 used 6/5, single-copy requests and replies and no unsolicited
spare copies. It delivered 28.633 Mbit/s, a 1.369 s first-write to full-read
P99 and 83 inner retransmissions in the ten-second window. All 44,715,008
application bytes verified; all six physical windows in both directions and
all native group custody drained. The two current Python seeds with path ARQ
yielded 16.194 and 16.654 Mbit/s, against their respective matched controls
of 2.632 and 2.431. Linux retained committed batch bytes after the last
mutable staging boundary, while Python could still remove a covered retry
when sealing its path batch. Linux socket handoff time and modeled departure
also differ. Independent random drop sequences and endpoint TCP behavior
limit direct numerical comparisons.

The complete forward lifetime cost in arm 03 was 158,762,868 paid IPv4 bytes,
or 3.551 per verified application byte. Named repair bodies alone cost
63,724,634 bytes. Physical retry entries, including entry metadata, cost
23,861,769 bytes. The maximum observed overdue forward batch was 511 ms.
The optional trace filled on both endpoints. Its overlapping uncensored
prefix supports event-level analysis, while complete lifetime and probe
measurements come from separate counters.
[Linux arm](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-path-arq-s1-seed31248-trace-03/result.json),
[initial Python candidate](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-initial-path-arq-dirty-ack-paired-v9.json)
and [held Python candidate](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-held-path-arq-dirty-ack-paired-v9.json).

The two diagnostic traces cover the same first 6.295 s of the steady
measurement. Of 113,055 forward named repair entries paid during that
interval, 53,182 (47.04%) preceded the original ordinal's first payment
and 33,377 (29.52%) followed decode at the peer. The sets can overlap.
Generation 4331 on slot 3 first paid its systematic member 511.471 ms
after native admission, 36.564 ms after the peer had already reached K.
Each Linux path reached its 256-packet physical credit at some point in
the full run. On slot 3 the reconstruction puts full credit at about 92 ms
of that 511 ms delay. That path paid 1,451 other DATA datagrams during the
interval, of which 658 carried only repairs. The sender gives queued repair entries access to the two
path buffers before filling them with new native data. These timings
identify a scheduling cost that changing N/K alone cannot remove.
[Matched event prefix and payment totals](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-path-arq-03-common-prefix.json)
and [per-path credit reconstruction](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-path-arq-03-credit-prefix.json).

The two complete native captures match all 83 steady TCP retransmissions
to overlapping TCP sequence ranges. All occurred within the first 1.867 s
of the sample. At retransmission, 10 original segments had yet to reach the
receiver's TUN, 42 had covering feedback in flight, and 31 had a covering
ACK or SACK already visible at the sender's TUN. The captures do not expose
the instant at which the endpoint TCP stack updated its scoreboard.
Thousands of named repairs per second still preceded their own systematic
payments in subsequent whole seconds. [TCP sequence and feedback events](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-path-arq-03-native-ranges.json).

The offline geometry study estimates per-path physical loss, first-flight
rank failure, expected missing rank and retry packet/byte fractions from the
complete arm 02 capture. It accounts for packing, unequal path marginals,
adjacent records sharing datagrams and common-loss sensitivity. For a 70
Mbit/s payload objective, a 5% first-flight failure ceiling and a 5% repair
byte ceiling admit different geometries. Its optimistic full-batch 12/10
point uses 4.39% repair bytes among modeled DATA and needs 98.90 Mbit/s
forward before control. At the observed forward occupancy of 1.608 fresh
entries per fresh-only datagram, neither 5% target fits both link budgets
in the evaluated geometry range. A runtime feedback controller and an
authenticated geometry switch still need integration and validation.
[Loss-to-geometry study, assumptions and reproduction](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-geometry-math/README.md).

The next optional `--fair-members` comparison shares pending member custody
between natural first flights and recovery producers. An A3 can take over a
first flight that has not entered a physical batch, preserving its original
deadline and suppressing the later natural copy. Prepared bytes remain frozen.
Explicit copies keep separate payment receipts. Fresh, physical-retry and
named/quiet entries rotate per path. Overdue entries assembled at one injected
instant may share a packet, but a later assembly turn cannot extend that
packet's deadline. Persistent socket blockage has a bounded cross-path rescue
triggered by subsequent authenticated A3 requests, including when a previous
rescue was erased and physical ARQ is disabled. Payment accounting identifies
the first actual handoff once even if the blocked original later completes.

The first Python shared-member attempt (`fresh-service-paired-v10`) paid too
many consecutive packets on one path. It lowered first-flight service age but
reduced goodput to 7.969 and 8.408 Mbit/s. The corrected
`slot-rounds-paired-v11` candidate has an open and ready MTU buffer per slot,
at most 64 entry opportunities per visit, one DATA per slot per round and
at most 16 rounds before returning to the event loop. It leaves the 1 ms
gap timer unchanged. The same-source controls include the original admission
deadline correction and must not be represented as reused v9 results.

| Python seed | Control goodput | Shared-member goodput | Control / candidate steady inner retransmissions | Control / candidate write-to-read P99 |
| --- | ---: | ---: | ---: | ---: |
| initial | 16.194 Mbit/s | 12.643 Mbit/s | 15 / 12 | 7.219 / 7.646 s |
| held | 16.662 Mbit/s | 47.916 Mbit/s | 6 / 667 | 6.296 / 1.603 s |

All four simulations drain. The candidate has no stable performance acceptance.
The held seed spends 9.84 Mbit/s of modeled reverse IP capacity during steady
measurement. Rust still starts the physical timer at UDP socket acceptance,
whereas the model starts it at complete wire serialization. TUN input bursts,
kernel queueing, actual CPU work and endpoint implementations are additional
differences. [Initial candidate](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-initial-shared-slot-rounds-paired-v11.json)
and [held candidate](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-held-shared-slot-rounds-paired-v11.json).

Linux arm 04 retains six paths, K=5, one TCP connection, 4 MiB application
credit, 100/10 Mbit/s shared links, 70 ms base RTT and 15% directional loss.
Goodput rises from arm 03's 28.633 to **40.064 Mbit/s**, while steady kernel
TCP retransmissions rise from 83 to **1,339** and write-to-read P99 rises
from 1.369 to **2.028 s**. Both endpoints drain every native and physical
obligation. This is a failed performance acceptance, not a new default.
[Complete arm 04 receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-path-arq-fair-s1-seed31248-trace-04/result.json).

Both metadata ledgers are complete in arm 04. They reserve 4,194,304 records
per endpoint, outside the transport queue budget, and drop zero observations.
For native groups admitted in the steady interval, forward member-payment
age has P99 23.580 ms and maximum 88.327 ms. No member's first payment follows
a paid repair of that same member or its peer's Kth arrival. The maximum
whole-run deadline lateness falls from 510.971 to 87.828 ms. Forward
admission-to-peer-TUN-write P99 remains 236.170 ms. Reverse member-payment
P99 is 2.678 ms, but reverse admission-to-peer-TUN-write P99 is 617.218 ms;
Kth-arrival-to-TUN-write P99 is only 9.228 ms. These are distinct from the
application's bounded TCP send queue and write-to-read measurement.
[Cohort timing and wire counters](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-path-arq-fair-04-metrics.json).

Whole-run physical timeout counts are 91,700 forward and 55,910 reverse,
compared with 4,320 and 1,088 selective-gap triggers. Forward physical-retry
entries consume 73,885,029 encoded bytes; reverse entries consume 4,466,579.
These counts do not identify network erasures: lost feedback and queueing
beyond the fixed 90 ms timer can also trigger them. A native capture join
finds 1,355 repeated payload packets in the sample, a separate observation
denominator from the kernel's 1,339 segments. At the capture timestamp,
1,047 have a covering ACK emitted at the peer but not yet at the sender;
277 already have a covering ACK/SACK visible at sender TUN, 30 originals
remain undecodable, and one is decoded but not yet written to TUN. Capture
visibility does not establish when the kernel consumed its ACK scoreboard.
[TCP range join](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-path-arq-fair-04-native-ranges.json).

The reverse timeout reconciliation joins original DATA, both WAN captures,
peer authentication and the first positive physical ACK by path, sequence and
authentication PN. Of 44,977 distinct reverse DATA paid in steady measurement
and later reported as timed out, 26,570 were already authenticated at the peer
before the local timeout. Another 9,092 arrived later; 9,315 are absent from
both WAN captures. These are conditional timeout-cohort counts, not a link
loss estimator. For 22,254 records, the first positive ACK that eventually
returned had already been handed to the peer's UDP socket at least 35 ms
before expiration. UDP handoff did not mean that the ACK was on the wire.

For this timeout cohort, original socket-to-local-WAN delay has P50 35.026 ms
and P99 417.151 ms. That interval includes the configured **35 ms netem
delay**, shaping and kernel scheduling; it is not wholly queue residence.
The surviving return ACK's corresponding interval has P50 71.728 ms and
P99 97.475 ms, also including 35 ms. Marginal percentiles cannot be added.
For reverse auth PN 10632, timeout occurs at 90.077 ms after socket payment,
the packet reaches WAN at 253.882 ms, and its positive ACK is consumed at
354.902 ms. Of 168,150 physically paid reverse retry entries during steady
measurement, 72,989 (43.4%) were sent after the peer had already obtained K
members for their native group. This establishes excess work and feedback
queueing; it does not by itself apportion every cause of a timeout.

The six paths also have correlated missing first flights under load. Among
16,379 steady reverse native groups, 177 lose all six original physical
packets and 420 retain only one. Independent calculations using each
one-second interval's measured per-path marginals predict about 11.23 and
98.96 respectively. Adjacent groups can share aggregated DATA, so these are
descriptive comparisons, not independent significance tests. The saved UDP
and qdisc counters identify additional local drops, but the captures alone
do not attribute each one to a particular queue. An adaptive geometry must
distinguish link erasures from local overload and late/lost receipts rather
than treating physical retry frequency as the erasure probability.

The 95.599/7.920 Mbit/s steady WAN IP rates count surviving traffic after the
local qdisc. The Python serializer charges bytes before its loss draw. The
saved HTB/netem topology therefore needs an explicit accounting comparison
before those occupancy rates can be treated as the same link-cost model;
single-packet token charging was not traced in this arm.
[Reproducible reverse ACK and timeout reconciliation](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-path-arq-fair-04-reverse-timeout-reconciliation-v1.json).

The next source audit identified two separate feedback obligations: replay a
bounded set of physical selective observations after lost ACK pages, and
rescan logical deliveries that occur below an active page cursor. The latter
rescan exists in Python but is absent from the current Rust laboratory Book.
An A3 payment can also postpone a standalone ACK when DATA has no room for
piggybacking. These source findings require correction and focused validation;
they do not explain away the measured queueing behind the fixed 90 ms timer.

This batch passes 23 focused Rust tests and 30 focused Python checks. The
full `python3 tools/check.py` invocation passed formatting, Clippy and all
workspace test targets except one existing OpenVPN impaired-close test,
which returned `IncompleteClose`. Its unchanged exact rerun passed. Only
that test and the checks after the failed workspace-test command were then
executed: codec without default features, documentation, CLI probes, remaining
harness tests and the full simulator suite (1,876 tests and two subtests).
The original failed invocation remains recorded and must not be relabeled
as a clean single-pass full gate. No Windows or Android runtime measurement
was performed. [Original gate](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-bundle-gate-04/result.json)
and [targeted follow-up](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-bundle-gate-04-followup/result.json).

### Shared egress budget and shaper-before-loss comparison

The optional `--paced-recovery` laboratory policy adds one shared directional
IP-plus-14-byte budget with a one-frame burst. ACK, named-request and DATA
classes rotate within that budget; native TCP ACKs remain ordinary DATA.
Frozen datagrams are charged only after complete socket acceptance. A genuine
`WouldBlock` leads to writable polling without spending bytes or monopolizing
other paths. Physical RTT samples come from new positive packet receipts,
including late originals in bounded history. The initial/minimum RTO is 90 ms,
the maximum is 500 ms, and the clock granularity is 1 ms. A selective observation
can be repeated once after 8 ms; logical delivery below an active ACK page cursor
causes another scan. These are implemented experimental policies, not service
defaults or a performance-qualified profile.

The explicit `--loss-after-shaper` harness places endpoint HTB/pfifo before
router netem. Each direction still shares 100/10 Mbit/s, 35 ms one-way delay
and 15% random loss. Source WAN capture is after shaping and before loss;
peer WAN capture is after loss. The previous symmetric-capture assumption does
not apply. All qdiscs live in the owned namespaces. The initial arm 05 failed
during qdisc setup, before data admission, and cleaned its namespaces. Replacing
the child kind requires deleting the previous child before adding pfifo; the
corrected control is arm 05b. The failed receipt remains preserved.

Both measured arms use release SHA-256
`1b11eb9d1cdbed9c2a3f9ac0464e5683faaeafd96bc5276838a4513694404e1a`,
six paths, K=5, fair member scheduling, path ARQ, one CUBIC flow and a 4 MiB
combined unsent/unacknowledged application cap. The sample lasts ten seconds
after two seconds of warmup. Application P99 includes drain and starts at the
first successful application write; it is not a per-packet tunnel latency.

| Linux policy | Sample goodput Mbit/s | Write-to-read P99 ms | Steady TCP retransmissions | Actually written/read records |
| --- | ---: | ---: | ---: | ---: |
| 05b, fixed 90 ms recovery without byte pacing | 27.074 | 1,618.370 | 189 | 82,251 |
| 06, paced recovery | 3.979 | 10,117.525 | 50 | 18,293 |

Both stream hashes match, all accepted native and physical debt drains, both
metadata traces drop zero observations, and namespace cleanup is verified.
The offered population is 263,672 records in each case; 181,421 and 245,379
records respectively remain unsubmitted at offer cutoff. Completion does not
mean the offered workload met its throughput target. This candidate fails
performance acceptance.
[Control receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-shaper-first-control-seed31248-trace-05b/result.json)
and [paced receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-shaper-first-paced-seed31248-trace-06/result.json).

The half-second TCP_INFO samples locate an early divergence. In arm 06 the
warmup samples show cwnd 12 and ssthresh falling to 8; the steady samples then
grow from cwnd 13 to 49. Arm 05b reaches cwnd 751 during warmup. Arm 06's sender
never blocks on its native group window and retains at most 69 groups, compared
with 817 in the control. These samples locate the onset and continued slow
growth, but do not identify the individual recovery-triggering ACK or the
instant of a kernel scoreboard update.
[Reproducible TCP window comparison](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-shaper-first-05b-06-tcp-window.json).

The Python v12 paired experiment includes the same 14-byte link accounting
and recovery policy. Its initial seed changes from 6.823 to 11.034 Mbit/s,
while the held seed changes from 7.348 to 40.160 Mbit/s. Candidate write-to-read
P99 is 7.310 s and 1.354 s; steady TCP repeats are 12 and 211. Every actually
accepted record drains, but not every offered record is accepted. Maximum
socket-to-complete-serialization delay is 122 us forward and 1,212 us reverse
for the candidates. That version did not record queue-delay P99; the later
histogram instrumentation cannot supply that missing observation retroactively.
These are simulator observations, not kernel performance or stable parity.
[Initial paired receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-initial-paced-ethernet-paired-v12.json)
and [held paired receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-6-5-held-paced-ethernet-paired-v12.json).

The complete source/peer WAN join distinguishes queue removal from TCP recovery.
In arm 05b the steady socket-payment-to-source-WAN P99 is 57.992 ms forward
and 251.311 ms reverse. In arm 06 source capture precedes the post-send payment
timestamp by a few microseconds for every matched steady packet; no positive
queueing is resolved at that observation precision. Source-to-peer WAN P99
remains approximately 35.1 ms. Actual steady IP-plus-14 payment is 98.93/9.77
Mbit/s in 05b and 7.16/1.53 Mbit/s in 06. The latter has no reverse pacing
deferral. All 300 forward steady physical timeouts and 329 of 330 reverse ones
in 06 correspond to original DATA absent at the peer WAN, with earliest firing
90.002 ms after payment. These steady observations exclude a general premature
timeout or saturated reverse link as explanations of arm 06's low throughput.
[Queue and payment audit](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-shaper-first-05b-06-pacing-audit-v1.json)
and [individual timeout audit](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-shaper-first-05b-06-timeout-audit-v1.json).

The earliest arm 06 payload retransmission is traced to native group 22.
Its six first-flight members leave the source WAN; ordinals 0 and 1 disappear
between WAN captures, leaving only four at the receiver. Two subsequent named
repairs also disappear between the captures. Four expanding SACK reports arrive
at the sender without advancing the cumulative ACK. Linux retransmits the
original byte range 146.4 ms after its first native read; the original group's
physical repair reaches K at 187.1 ms, after the inner repeat. All 50 steady
inner retransmissions also correspond to original groups short of K on their
first flight. Of 43 cases with a covering ACK already emitted but not returned,
41 emitted that ACK less than the 35 ms propagation delay before retransmission.
Outer ARQ is active, but its successful delivery does not always precede inner
recovery. The packet traces establish this ordering, not which kernel loss
detector or exact SACK triggered the transition.
[Warmup sequence, shard and ACK timeline](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/shaper-first-06-ack-timeline.json)
and [complete rank/native join](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/shaper-first-06-rank-native.json).

Replay of the authenticated physical ACK blocks explains why the first lost
members do not time out at 90 ms in that warmup episode: 90 ms is the floor,
while their payment-time adaptive RTOs are approximately 200.5 and 216.2 ms.
The third higher positive receipt arrives at about 151 ms and the observed
selective-gap transfer follows within 9--12 us. Named payment on another path
does not erase either original physical obligation. Even a successful fixed
90 ms retry would require about 70 ms more for delivery and its covering inner
ACK, later than the observed 146 ms inner retry. The first named repair was
early enough for that ideal bound but was lost. The trace therefore does not
support treating this episode as a missed 90 ms wake or assuming a shorter
timer alone eliminates it.
[ACK and adaptive-deadline replay](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/shaper-first-06-g22-rto.json).

The follow-up offline Python geometry study preserves N data portions, with
each member carrying its own portion plus cross-member parity and any K distinct
valid ordinals sufficient for recovery. It separately models missing rank,
retry DATA bytes, retry fraction of all link bytes and holes across consecutive
native admissions. In arm 06 forward, 21.13% of admitted groups lack K on their
original flight; 84.5% of overlapping windows of 13 native admissions contain
such a group. These are not reconstructed simultaneous TCP flights. Actual
retry bytes allocated their share of common packet headers are 13.31% of DATA.
Changing N/K under captured occupancy and feedback rates is a conditional
sensitivity, not an achieved new throughput or a physical impossibility bound.
The independent, burst and correlated models retain separate byte denominators,
report infeasible candidates, and propose confidence gates and hysteresis for
later authenticated epoch integration. Example retry targets are study inputs,
not owner-selected defaults. Three focused mathematical invariants pass.
[Model, assumptions and reproduction](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-geometry-05b-06-retry-budgets.md).

The frozen batch passes one complete `python3 tools/check.py` invocation with
`RUST_TEST_THREADS=1`, the shared target, three build jobs and bounded rustdoc
memory. Its Rust workspace, Clippy, documentation, external CLI and harness
stages pass, followed by 1,886 simulator tests and two subtests. This is local
Linux verification; it does not qualify native Windows/Android, remote CI,
production bundle joining or the failed single-flow performance target.
[Complete batch gate 05](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/multipath-bundle-gate-05/result.json).

### Native delivery order and sender pacing in the Linux path bundle

These arms used one inner Linux TCP connection over TUN in owned namespaces.
Each native IP packet creates one direction-local FEC group. At 12/8 it has
12 different coding ordinals and any eight recover that packet. Each connected
UDP path can pack its ordinals from several native packets into one datagram.
The configured outer IPv4 MTU was 1,500 bytes. Socket payment counts every
IPv4 byte plus 14 modeled Ethernet bytes. The seed was 31248, the link rates
were 100/10 Mbit/s, the base RTT was 70 ms and each direction had 15% loss.
The probe used a 4 MiB outstanding application-payload limit. The adapter
retained an independent bounded window of 8,192 logical group positions and a
256-packet physical window per path. Endpoint Linux TCP controlled its own cwnd.

The independent policy writes each complete native packet as soon as it is
eligible. The strict policy writes by direction-local group sequence. The
TCP-data-order policy additionally allows a validated, payload-free TCP ACK
to reach TUN while an earlier group is missing. Every such
ACK first uses the same FEC and path budget. Each successful TUN write commits
one logical group. Pending or blocked writes retain custody. The scheduled
arms also service funded socket sends on wake and between bounded rounds of
ingress. Each round processes at most eight received datagrams before revisiting
egress and resumes the next busy round on the following physical path.

| Geometry and Linux policy | Application goodput Mbit/s | Application P99 ms | Steady inner retransmissions | Native read to first payment P99 ms |
| --- | ---: | ---: | ---: | ---: |
| [6/5 independent](../../work/fec-native-order-20261121/independent-v1/result.json) | 15.882 | 2,544.641 | 13 | — |
| [6/5 strict](../../work/fec-native-order-20261121/ordered-v1/result.json) | 11.377 | 5,390.348 | 0 | — |
| [12/8 strict, previous sender](../../work/fec-native-order-20261121/ordered-12-8-v1/result.json) | 18.540 | 2,546.780 | 0 | 378.113 |
| [12/8 strict, scheduled sender](../../work/fec-native-order-20261121/scheduled-ordered-12-8-v1/result.json) | 21.369 | 2,262.222 | 0 | 407.742 |
| [12/8 TCP-data order, scheduled sender](../../work/fec-native-order-20261121/scheduled-data-12-8-v1/result.json) | 23.334 | 1,849.551 | 0 | 478.519 |

Goodput counts unique receiver application bytes over ten seconds after two
seconds of warmup. Application P99 starts at a record's first successful
write and includes completed reads in the drain. The last column follows
groups admitted in steady state to the first actual socket payment containing
one of their ordinals. This join covers every admitted group in each 12/8
row. The two 6/5 runs both repeated their initial SYN before the probe started.
All five rows ended with zero retained source and receiver groups and matching
peer confirmation prefixes. These completed runs qualify the selected
established-path Linux lab adapter. Production Common carrier binding and the
single-flow throughput target remain open.
[Setup and inner TCP trace](../../work/fec-native-order-20261121/startup-rank-diagnosis.md)
and [12/8 payment join](../../work/fec-native-order-20261121/scheduled-pacer-diagnosis.json).

For the three 12/8 arms in table order, the paid forward Ethernet rates were
45.661, 54.089 and 58.447 Mbit/s. In the last arm, already selected packets
spent 4.660 s eligible for payment before the successful socket handoff over
the whole run. On 26,128 timer-only poll returns, 1.955 s of this delay had
already elapsed, averaging 74.8 µs per timeout. The counters leave event wakes
and subsequent processing times combined. Over the ten-second steady window
the one-frame bucket discarded 4.155 link-seconds of earned credit; 3.982
link-seconds accrued in intervals that began with an admitted group past its
500 µs hold and awaiting a first payment. One frame replenishes in 121.12 µs
forward. This measurement combines scheduling, packet size and repair cost.
[Counter definitions and replay](../../work/fec-native-order-20261121/scheduled-pacer-diagnosis.py)
and [focused scheduler/ordering checks](../../work/fec-native-order-20261121/scheduled-v1/cargo-focused.log).

The lab source now accepts `--pacing-burst-frames 1..8` with paced recovery.
The default capacity is one frame, and all selections start with exactly one
frame of credit. A two-frame capacity can retain one additional 1,514-byte
frame earned after the first successful send. The same shared rate applies to
data, feedback and repairs. The optional `--physical-rank-suppression` policy
requires physical path ARQ and fair member scheduling. Its acceptance requires
distinct positively acknowledged paid ordinals, immutable prepared packets,
and an oldest-group probe when every logical delivery receipt was lost.
Physical rank can suppress redundant repair work. Only confirmation of a
native write can release the sender's source. All five rows above used one
frame and the earlier repair policy.

The next three Linux arms used the same release, two frames of earned capacity
and TCP-data ordering. All ended with zero retained groups, matching peer
prefixes and zero steady inner TCP retransmissions. The byte columns cover
the ten-second steady interval. Paid Ethernet bytes include every DATA and
control datagram in each direction. Repair bodies count actual named, path
and quiet shard bodies and exclude entry and packet headers.

| Selection | Goodput Mbit/s | Application P99 ms | First payment P99 ms | Paid Ethernet bytes A→B / B→A | Repair body bytes A→B / B→A |
| --- | ---: | ---: | ---: | ---: | ---: |
| [12/8 control](../../work/fec-native-order-20261121/burst2-12-8-v1/result.json) | 23.484 | 2,021.144 | 463.254 | 75,016,604 / 5,128,338 | 22,425,403 / 205,685 |
| [12/8 with positive rank](../../work/fec-native-order-20261121/rank-burst2-12-8-v1/result.json) | 24.814 | 1,698.937 | 508.076 | 74,018,721 / 4,989,436 | 19,241,599 / 144,237 |
| [6/5 with positive rank](../../work/fec-native-order-20261121/rank-burst2-6-5-v1/result.json) | 21.575 | 4,185.231 | 164.686 | 52,033,627 / 3,344,010 | 13,402,413 / 125,485 |

At 12/8 the change saved 3,183,804 forward repair body bytes in the observed
window. The sender suppressed 34,476 repair intents after learning the group
had enough distinct ordinals, and 20,378 after learning the specific member
had arrived, across the entire run. These are intent counts. Actual arm
payments provide the byte comparison. PBL-02 and PBL-03 have focused and
isolated Linux evidence. Whole-workspace verification for the current batch
and the single-flow performance target remain open.
[Per-direction cost reconciliation](../../work/fec-native-order-20261121/burst2-three-arms-service-cost-v1.json)
and [frozen release and focused checks](../../work/fec-native-order-20261121/rank-burst-v1).

In the earlier one-frame 12/8 TCP-data-order capture, the median interval from
first to eighth original payment was 81.862 ms. The source WAN capture measured
81.865 ms over the corresponding original payments. The deciding member took
a median 35.022 ms between WAN captures and 0.034 ms from opening to recorded
rank completion. Of 20,997 groups, 20,526 eventually received at least eight
originals. At half-second sample times the fastest and slowest paths differed
by a median 248 groups in their most recently paid canonical first members.
The eighth member's path paid a median 166 older original entries and 67 repair
entries between the group's first and eighth payments. The capture establishes
which traffic used that path during the interval. It lacks per-entry enqueue
timestamps for the two path buffers.
[Group-by-group payment, WAN and decoding join](../../work/fec-native-order-20261121/scheduled-data-12-8-original-rank-v2.json).

The explicit PBL-04 candidate `--pace-original-frontiers` requires shared
pacing and fair member scheduling. For up to three paid DATA turns it prefers
the oldest overdue original group that a healthy path can actually offer.
Every fourth successful DATA handoff goes to an independent ordinary
round-robin cursor when all paths remain eligible. A socket refusal leaves
the cursor in place. Frozen heads, the physical repair and named repair
queues, and the established ACK and request class rotations retain their
existing service rules. Focused checks cover an uneven number of original
entries per paid datagram, a blocked path, recovery of older gaps and a
bounded scan that resumes after retired groups. The frozen candidate passed
12 facade cases, 27 endpoint cases and four unprivileged harness cases.
[Focused commands and outcomes](../../work/fec-native-order-20261121/frontiers-v1/commands.jsonl)
and [frozen candidate hash](../../work/fec-native-order-20261121/frontiers-v1/binary.sha256).

Both matched Linux comparisons kept the two-frame capacity, rank policy,
TCP-data ordering, seed and link settings above. The payment span starts at
the first original and ends when the sender socket accepts the Kth distinct
original for the same group, irrespective of arrival or repair. The TUN
interval runs from local native read to the actual remote native write.

| Geometry and DATA selection | Goodput Mbit/s | First-to-K original payments P50 / P99 ms | TUN-to-TUN P99 ms | Application P99 ms | Steady inner retransmissions |
| --- | ---: | ---: | ---: | ---: | ---: |
| 12/8 ordinary control | 24.814 | 82.348 / 124.891 | 642.597 | 1,698.937 | 0 |
| [12/8 oldest overdue original](../../work/fec-native-order-20261121/frontiers-12-8-v1/result.json) | 36.925 | 1.538 / 6.240 | 461.026 | 2,127.583 | 0 |
| 6/5 ordinary control | 21.575 | 8.377 / 113.312 | 352.994 | 4,185.231 | 0 |
| [6/5 oldest overdue original](../../work/fec-native-order-20261121/frontiers-6-5-v1/result.json) | 32.091 | 0.574 / 2.017 | 300.288 | 3,649.643 | 0 |

All four arms drained their retained groups and matched the peer confirmation
prefixes. The final two runs improve goodput and shorten the time to pay K
originals, while the single-flow throughput goal remains open.
[Original payments and authenticated arrivals](../../work/fec-native-order-20261121/frontier-pair-vs-rank-original-paid-open-v1.json).

At 12/8, application P99 increased even though the tunnel delivered native
packets sooner. A separate join followed records with a complete application
timestamp visible inside the 96-byte sender capture. In 1,672 control and
2,296 candidate records, P99 from the first application write to appearance
of the contiguous TCP byte prefix at the sender TUN increased from 1,600.386
to 2,031.658 ms. For those same records the corresponding sender-to-peer TUN
prefix P99 fell from 641.579 to 461.936 ms. This locates the longer tail
upstream of the sender TUN in that sample. The capture does not identify the
specific kernel wait for every byte or the individual application read time
for all records. Current whole-workspace verification remains pending.
[Matched application records and TCP byte-prefix observations](../../work/fec-native-order-20261121/frontier-four-arms-application-header-native-prefix-v1.json).

### Egress selection during input processing (PBL-05)

At 12/8, the frontier trace contained 2,261 intervals with a full shared byte
budget, an admitted group past its first-send deadline and at least two distinct
input events between UDP payments. They totalled 0.997 s, including 0.635 s
after the second input witness. At 6/5 the corresponding counts were 905
intervals, 0.301 s total and 0.138 s after the second witness. The traces did
not record which ciphertext head was eligible at every checkpoint. The previous
implementation could pay an existing reservation during input but selected its
successor only after the input quantum. [Interval definitions and counts](../../work/fec-native-order-20261121/frontier-admitted-full-bucket-input-witness-v1.json).

The paced adapter now checks for one egress opportunity after a successful
UDP receive, native write or native admission. A reservation owns that
opportunity until funded or the carrier refuses the handoff. With no reservation,
a read-only hint checks the current batch/fresh head per path, pending control
and recovery deadlines. A hit invokes regular class and path selection once.
It can pay a packet, reserve it for later credit, or finish without a handoff.
The receipt counts each outcome separately. The normal egress pass remains
responsible for work hidden behind selectively retired or delegated groups.
The matched isolated Linux runs used one forward TCP flow, 4 MiB of probe
credit, shared 100/10 Mbit/s shaping followed by 35 ms delay and 15% loss
in each direction, and the preceding frontier settings. Goodput uses unique
receiver bytes over the 10-second steady window. Application P99 spans the
first write to the complete read of submitted application records, including
drain. TCP retransmissions use the difference between the steady-window
TCP_INFO counters. [Commands for both arms](../../work/fec-native-order-20261121/checkpoint-native-batch-v1.json).

| Geometry | Goodput before → after (Mbit/s) | Application P99 before → after (ms) | Steady TCP retransmissions before → after | New forward selections paid / attempted |
| --- | ---: | ---: | ---: | ---: |
| [12/8](../../work/fec-native-order-20261121/checkpoint-12-8-v1/result.json) | 36.925 → 42.318 | 2,127.583 → 1,256.857 | 0 → 0 | 44,876 / 62,821 |
| [6/5](../../work/fec-native-order-20261121/checkpoint-6-5-v1/result.json) | 32.091 → 43.513 | 3,649.643 → 2,285.294 | 0 → 0 | 26,753 / 39,563 |

The remaining forward selections at 12/8 reserved 17,544 packets for future
credit and ended 401 attempts without a handoff. At 6/5 those counts were
10,277 and 2,533. Successful handoffs of *previously* reserved packets are a
separate counter, 37,705 at 12/8 and 32,029 at 6/5. Each arm ended with zero
retained sender or receiver groups at both endpoints and matching peer
confirmation prefixes. The measured TCP retransmission counter already stood
at one at the start of each steady window. These two single-seed Linux
observations leave the 70 Mbit/s single-flow target open.
[12/8 sender counters](../../work/fec-native-order-20261121/checkpoint-12-8-v1/a-stats.json)
and [6/5 sender counters](../../work/fec-native-order-20261121/checkpoint-6-5-v1/a-stats.json).

A separate trace join priced each successful socket handoff at IPv4 length
plus 14 Ethernet bytes. The 12/8 forward/reverse rates rose from
69.624/4.622 to 78.944/6.636 Mbit/s. The 6/5 rates rose from 52.751/3.405
to 71.082/4.151 Mbit/s. With the same join applied to all four traces,
neither candidate had an interval with a full forward budget, overdue
first-send debt and two distinct input events without payment. Full budgets
still coincided with overdue first sends for 2.106 s of the 12/8 steady
window and 1.328 s of the 6/5 window. The traces do not identify the cause
of each remaining interval.

From native read to the first paid member, 12/8 P50 increased from 113.163
to 231.132 ms while P99 fell from 356.412 to 311.413 ms. At 6/5 both
increased, from 5.901 to 85.417 ms at P50 and from 146.673 to 328.191 ms
at P99. This stage still has a substantial queue despite improved
application goodput and P99. [Matched socket payments, input events and source delays](../../work/fec-native-order-20261121/checkpoint-paid-witness-pair-v1.json).

The affected verification passed 13 facade tests, 29 isolated endpoint tests
and strict all-target/all-feature Clippy for the three affected crates.
The frozen batch also passed `python3 tools/check.py` in the Linux workspace.
[Focused commands](../../work/fec-native-order-20261121/checkpoint-v1/commands.jsonl)
and [full gate 03](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-03/result.json).

### Repeated ACK processing (PBL-06)

The sender validates each logical delivery report against admitted groups
and the count of distinct paid ordinals. A report that retires a live group
cleans the recovery queues and path ledgers. Repeating a report with no new
retirements advances each path's clock without walking its flight and member
maps. A later payment of already frozen DATA records the physical send and
its RTT history. Only members with continuing logical custody enter its
retry ledger. A mixed report still applies all physical positives, selective
gaps and expired-history signals. The estimator commits each new physical
RTT sample even when its effective timeout stays unchanged. Timeout flights
only need new deadlines when that effective timeout changes. Eleven physical
ledger tests and 31 endpoint tests passed, along with strict Clippy on the
affected crates. [Focused checks and candidate build](../../work/fec-native-order-20261121/ack-cost-v1/commands.jsonl).

The next two Linux arms used the same link, seed, probe credit, pacing and FEC
geometry as their PBL-05 controls. Steady rates and retransmissions cover ten
seconds. Application P99 includes completed records through drain. Each
candidate delivered its submitted bytes, matched both peer confirmation
prefixes and ended with zero retained groups at both endpoints.
[Commands and exit codes](../../work/fec-native-order-20261121/ack-cost-native-batch-v1.json).

| Geometry | Goodput before → after (Mbit/s) | Application P99 before → after (ms) | TCP retransmissions in steady window | Forward / reverse paid rate after (Mbit/s) | Logical path scans skipped over full run (A / B) |
| --- | ---: | ---: | ---: | ---: | ---: |
| [12/8](../../work/fec-native-order-20261121/ack-cost-12-8-v1/result.json) | 42.318 → 49.559 | 1,256.857 → 1,237.736 | 0 → 0 | 90.312 / 5.716 | 360,888 / 204,516 |
| [6/5](../../work/fec-native-order-20261121/ack-cost-6-5-v1/result.json) | 43.513 → 26.526 | 2,285.294 → 4,761.157 | 0 → 0 | 43.790 / 3.224 | 99,834 / 40,566 |

One skipped path scan represents one physical ledger whose member and flight
maps would have been searched for a duplicate logical delivery report. The
constant-time clock check still ran. On the forward sender at 12/8, 30,074
duplicate reports skipped cleanup and 6,222 reports retired new groups. At
6/5 the counts were 16,639 and 3,353. The path scan counts measure work
avoided. They do not measure its CPU duration.

The 6/5 candidate regressed despite a shorter sender-TUN-read to first-member
payment P99, 328.191 → 66.406 ms. Its full forward bucket occupied 5.621 s
of the steady window, including 0.421 s with an admitted source waiting
past its first-send deadline. At 12/8 the corresponding P99 grew from
311.413 to 476.820 ms while goodput rose. These single-seed runs establish
the two outcomes. During warmup, the Linux namespace recorded one CUBIC
HyStart delay detection in each 6/5 run. The sender slow-start threshold
was 213 segments in the control and 48 segments in the candidate after that
detection. At the same time, steady-window P99 for physical and logical
ledger processing on ACKs with no new logical coverage fell from 413.34 to
86.44 microseconds at 6/5 and from 371.76 to 89.05 microseconds at 12/8.
The traces identify an earlier TCP slow-start exit in the slower arm. They
do not establish which change in packet timing triggered that exit.
The single-flow throughput target remains open. This ACK-cost source batch
passed full Linux workspace gate 04, including the Rust and Python checks,
Clippy and documentation. [Full gate 04 receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-04/result.json).
[Matched payment, source delay and ACK stage observations](../../work/fec-native-order-20261121/ack-cost-paid-ack-stage-pair-v2.json).

### Passive startup ARP observation (PBL-OBS-01)

The optional `--capture-neighbor-events` harness flag starts four ARP-only
Ethernet captures after topology setup and before either adapter starts. Each
end of the two routed veth pairs has its own capture. The harness waits for
all four listeners, reads the IPv4 neighbor tables, and repeats those
read-only table snapshots after the workload. ARP observations use separate
files and never enter UDP payload or paid-byte statistics. No packets are
injected. Runs that omit the flag keep the existing WAN and TUN filters.

In one matched 6/5 Linux namespace arm all four IPv4 neighbor tables were
empty before adapter startup. Each had one REACHABLE next-hop entry after
the workload. On each interface the raw tcpdump log reported four captured,
four received by filter, and zero kernel drops. An independent offline
tcpdump decode matched every timestamp and request/reply field described by
its packet text. The four distinct process identities matched the owned
namespace journal, remained live through the workload and exited with code
zero after SIGINT. All five owned namespace mounts and the runtime state
directory were absent after cleanup. These are per-interface sightings of
traffic on two links. The saved pcaps alone cannot establish which frames
were discarded before an AF_PACKET observation or reconstruct every kernel
neighbor-state transition.
[Observer run](../../work/fec-native-order-20261121/arp-observer-6-5-v1/result.json)
and [independent capture and cleanup audit](../../work/fec-native-order-20261121/arp-observer-6-5-audit-v1.json).

This harness change passed six focused unprivileged tests and the one
privileged namespace arm. Aggregate gate 04 covers the preceding source
batch. A full workspace gate after the observer change remains pending.

### Authenticated UDP path readiness before the native TCP probe (PBL-07)

The optional `--authenticated-path-ready` setting binds a new identifier
to the preprovisioned-key lab profile and requires shared pacing. Each
endpoint chooses a fresh 128-bit challenge per connected UDP path using
the system CSPRNG. Requests and echoes carry an 18-byte body under the
existing direction keys, session digest, per-packet number and authenticated
path ID. Every successful handoff costs 67 IPv4 bytes and 81 bytes including
the Ethernet header. Each accepted socket payment is counted in both the
general wire ledger and separate readiness counters. A failed send earns no
credit. The harness waits for both local proofs of all configured paths before
opening the measured inner TCP connection. Startup time and bytes remain
observable outside the inner-TCP window.

Authenticated incoming DATA can occupy the existing bounded receiver while
a local path is still being verified. Local native reads and writes wait for
all local paths. Requests from a later peer remain serviceable after local
readiness. An unverified endpoint fails at its original five-second deadline.
The evidence covers possession of this run's preprovisioned keys and current
path reachability. Fresh production key exchange and handshake integration
remain separate. All 38 endpoint tests and eight harness tests passed, along
with strict runtime Clippy. The native custody test recovers an early FEC
group, receives three independent path proofs and exercises a refused native
write before the successful delivery advances the logical prefix.
[Focused results and frozen release](../../work/fec-native-order-20261121/authenticated-ready-v1/commands.jsonl).

Both single-flow Linux arms observed both readiness markers before starting
the TCP probe. Each endpoint confirmed all of its paths. Neither endpoint
received authenticated non-readiness traffic before its marker. Whole-run
readiness payments count successful request and echo datagrams, including
late replies. Time to local readiness runs from state initialization until
the last required echo. TCP goodput uses the ten-second steady window.
Application P99 measures first write to complete read, including drain.

| Native arm | Time to local readiness A / B (ms) | Paid setup IPv4 A / B (bytes) | Paid setup with Ethernet A / B (bytes) | TCP goodput (Mbit/s) | Application P99 (ms) | Steady inner retransmissions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [6/5](../../work/fec-native-order-20261121/authenticated-ready-6-5-v1/result.json) | 2,090.573 / 2,145.378 | 10,854 / 17,487 | 13,122 / 21,141 | 24.002 | 4,805.606 | 0 |
| [12/8](../../work/fec-native-order-20261121/authenticated-ready-12-8-v1/result.json) | 1,097.475 / 1,149.565 | 12,864 / 18,894 | 15,552 / 22,842 | 35.503 | 3,462.064 | 0 |

Both TCP retransmission counters read zero at both steady edges. All submitted
bytes drained and both ends matched their peer's confirmation prefix. The
ungated 6/5 run with ARP observers reached 44.542 Mbit/s at 2,192.098 ms
application P99. The prior ungated 12/8 run without ARP observers reached
49.559 Mbit/s at 1,237.736 ms. Both previous arms entered the steady window
with one TCP retransmission already counted. Readiness moves resolution and
its real control traffic ahead of the inner connection. With the same netem
seed, those additional packets also change which loss draws the later TCP
traffic encounters. The observations establish a working startup barrier
and its costs. Neither measurement reached the single-flow throughput target.
The [full local workspace gate 05](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-05/result.json) passed for the readiness batch.
[Ungated 6/5](../../work/fec-native-order-20261121/arp-observer-6-5-v1/result.json)
and [ungated 12/8](../../work/fec-native-order-20261121/ack-cost-12-8-v1/result.json).

### One additional round during idle startup capacity (PBL-08)

The isolated UDP experiment accepts `--low-load-forward-round` with
`--paced-recovery`, `--fair-members`, `--path-arq` and
`--physical-rank-suppression`. Each direction has its own budget and its
own first 128 group IDs. Both peers bind the selected option under their
existing authenticated session. The option defaults to off.

A group becomes eligible after all N distinct original shards have actually
been sent. The time allowed for new selections ends 35 ms after the first
original payment. An idle sender may select each original ordinal at most
once more while its positive physical receipt, sufficient group rank and
native confirmation are still outstanding. Each repeat carries the original
coded shard in a new authenticated packet. The coding matrix and decoding
threshold stay the same. Ordinary work and old-hole recovery take priority.
Both directions charge actual socket payments against the same pacing budget
as other traffic. A frozen packet that completes after its selection deadline
is counted separately. Each direction can pay at most 128 × N repeated members.

Optional copies advance physical sequence and RTT accounting with an empty
retransmission obligation. Their loss cannot create another copy or postpone
the old group's quiet probe. Their ACK alone does not increase known member
rank; original and ordinary-repair receipts and native confirmation retain
their existing meanings. A constant-time eligibility check avoids scanning
the retained window once the optional work has ended.

The first native candidate completed both directions with zero final debt
and zero steady inner TCP retransmissions. With 6/5, goodput was 37.803 Mbit/s
and application P99 was 2513.013 ms; with 12/8, these were 34.578 Mbit/s and
2013.596 ms. Extra forward/reverse IP bytes were 258,556/52,991 and
323,871/88,228, respectively. These are individual closed-loop trials, not
matched packet-loss histories or a qualified throughput improvement.
[6/5 receipt](../../work/fec-native-order-20261121/low-load-round-6-5-v1/result.json)
and [12/8 receipt](../../work/fec-native-order-20261121/low-load-round-12-8-v1/result.json).

The 12/8 trace exposed unfair optional scheduling: while G84 and G85 each
needed another distinct member, 84 available payments completed twelve
copies each for seven older groups. Neither later group received a copy
before expiry. The revised policy prioritizes groups with fewer actual
optional payments and then the oldest group ID. Frozen payment identity,
ordinary traffic priority and all original limits remain unchanged. The
authenticated option binding is version 2. The former binary and captures
remain the comparison baseline.
[Fixed-slot counterfactual and limitations](../../work/fec-native-order-20261121/low-load-fixed-slot-replay-v1.json).

Version 2 passed 45 focused endpoint tests, strict Clippy and both native
cases. All application bytes arrived, both directions drained, and the owned
namespaces were removed. Its finite observations are:

| Geometry | Goodput (Mbit/s) | Application P99 (ms) | Steady inner retries | Extra forward/reverse Ethernet bytes |
| --- | ---: | ---: | ---: | ---: |
| 6/5 | 46.8028352 | 2134.949004 | 0 | 271734 / 63770 |
| 12/8 | 34.4114304 | 3607.989159 | 0 | 337578 / 84560 |

For the first 128 forward groups, originals plus optional copies sufficed
for 127 groups with 6/5 and all 128 with 12/8. In the 12/8 case every group
received at least five copies before expiry; version 1 left ten groups
without any. The 12/8 application P99 nevertheless regressed. Each row is a
single closed-loop history; these results do not qualify a general throughput
improvement or the broader performance target. The option remains off by
default. [Six-arm measured comparison](../../work/fec-native-order-20261121/initial-128-actual-low-load-six-arm-v1.json).

The 12/8 version-2 run also contains a measured underlay stall. Matching the
same UDP payloads at both endpoint WAN captures places 277 already-sent
forward packets at A during steady seconds 1.881--1.916 and at B during
4.734--4.769. Both captures reported zero drops. This observation spans the
controlled network between those measurement points; it is not a measured
2.85-second FEC decode. Router queue and host scheduling attribution remain
unresolved. CPU samples bracket, rather than sample inside, that interval.
[Packet identities and observation limits](../../work/fec-native-order-20261121/fair-low-load-12-8-v2-wan-stall-witness-v1.json).

The [full local gate 07](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-07/result.json)
passed, including 1,895 Python tests and two subtests. The prior gate 06 failure
is retained; it exposed the independently corrected raw setup-input custody
race described in [the Common raw carrier](raw-common-carrier.md).

### Current single-flow Common rolling UDP baseline

The current Linux Common daemon delivered **71.330496 Mbit/s** with the
`packed-c48-near8-fixed-anchor-ack-lz4-udp` profile. It carried one inner
Linux CUBIC connection through 16 logical MUX channels on the selected UDP
carrier. The link used 100/10 Mbit/s, 70 ms RTT and independently seeded
15% loss in each direction. The application kept its 4 MiB unconfirmed limit.
The forward TUN used an 85 Mbit/s FQ limit and a 768-packet transmit queue.
[Current execution receipt](../../work/common-rolling-light-replay-20261121-v1/run-v1/evidence.json).

The receiver verified 89,163,120 unique application bytes during the ten
steady seconds. Application first-write-to-complete-read P99 was
**704.014891 ms**, including drain. The kernel counted 77 retransmitted inner
segments by the steady start and 101 by its end, giving **24 steady
retransmissions** and zero additional retransmissions through the last
sample. All accepted bytes reached EOF and both recovery directions drained.

Historical source tree `017c72c` delivered 71.517 Mbit/s with 35 steady
retransmissions. Tree `f62e45e` delivered 69.927 Mbit/s with 15. All three
selected the same authenticated protocol descriptor and catalog. The current
plan's retained-memory budget is 512 bytes below the `f62e45e` estimate.
The current probe has a different file hash from the `017c72c` probe. Its
additional startup sampling was disabled for the replay. The `f62e45e`
receipt includes additional forward-record and rolling-gap observations.
[Historical light run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-seed31248-017c72c/light-arm-evidence.json)
and [historical startup-traced run](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-f62e45e/burst-application-evidence.json).

This replay establishes a current measured baseline near 70 Mbit/s for the
selected Common profile. The PBL trials above measure a separate experimental
adapter that spreads shards across several UDP paths. They have their own
throughput and tail-latency qualification.

### Passive underlay observations and named repair custody

`--observe-underlay` is an optional Linux lab observer and requires
`--loss-after-shaper`. Two owned-router packet taps complement the endpoint
WAN captures. A bounded sampler reads both netem queues every 100 ms and the
two adapters' scheduler counters every 25 ms. Actual sample intervals, process
and namespace identities, packet drops, file bounds and clean completion are
recorded. These taps bracket forwarding and output queuing; they do not directly
timestamp individual qdisc enqueue/dequeue calls.

The [12/8 observer execution](../../work/fec-native-order-20261121/underlay-observed-12-8-v1/result.json)
reused the fair low-load v2 binary and delivered 42.975482 Mbit/s, application
first-write-to-read P99 1508.651927 ms and zero steady inner TCP retransmissions.
The [four-surface packet audit](../../work/fec-native-order-20261121/underlay-observed-12-8-four-surface-audit-v1.json)
matched forward packets across all four interfaces: endpoint-to-endpoint delay
P99/max was 35.090/38.404 ms, with a configured 35 ms one-way delay. Reverse
P99/max was 35.096/36.582 ms. The previous multi-second stall did not recur.
This excludes that stall from the successful packets of this execution; it
does not retrospectively identify the previous kernel or scheduling cause.
An observer can affect scheduling, so the throughput difference is not credited
to an algorithm change.

The optional `--transfer-named-path-debt` policy addresses independently
observed overlap between named and per-path repair. In the fair 6/5 control,
10,080 members had a named payment followed by another path's retry within
35 ms. Simply deleting those later sends would delay some reconstructions.
The new policy therefore keeps the latest named payment's physical recovery
ledger and original deadline. It coalesces only an unstaged old-path member
when a different path positively retains that actually paid named member or
has acknowledged it. Two expired paths cannot cancel each other's queued work.
Frozen sends, independent replicas, original shards and logical gap recovery
retain their existing rules. Optional low-load copies carry no such recovery
debt and cannot justify this transfer.

The policy defaults off, requires fair members, per-path ARQ and physical-rank
suppression, and appends `/transfer-named-path-debt-v1` to the authenticated
lab configuration binding. Requested/effective selection and the count
`path_debts_transferred_to_named` are reported separately. The focused endpoint
checks pass; native performance qualification is recorded under PBL-09.

The [6/5 comparison](../../work/fec-native-order-20261121/named-transfer-pair-v1.json)
measured 46.802835 to 47.575488 Mbit/s and application P99 2134.949 to
1734.863 ms. Both runs had zero steady inner retransmissions, matching stream
hashes and zero final logical and physical debt. Forward IP plus Ethernet
bytes per delivered application byte fell from 1.624237 to 1.571076. Observed
same-member named-to-other-path retry pairs within 35 ms fell from 10,080 to
zero forward and 2,993 to zero reverse. The longest period as the oldest
unconfirmed forward group increased from 94.799 to 142.825 ms. The first steady
TCP congestion window also differed, 248 versus 340 segments; one seeded pair
cannot establish the size of a throughput benefit. The option remains off.

The [remaining idle-time audit](../../work/fec-native-order-20261121/named-transfer-idle-v1.json)
identifies 469.600 ms of full forward pacing credit with an admitted group
older than 500 microseconds that had not paid its first shard. The observed
per-path flight peak was 169, below the configured 256 limit, and no socket
send returned WouldBlock. Current traces cannot distinguish staging delay,
poll wake delay and arbitration for these individual intervals.

All 46 focused endpoint checks and 15 harness/observer checks passed. The
[aggregate local gate 08](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-08/result.json)
ran `python3 tools/check.py` successfully, including the Rust workspace,
Clippy, documentation and 1,895 Python tests with two subtests. These results
qualify the stated Linux lab behavior, not a Common runtime integration of
this experimental multipath policy or a Windows/Android execution.
