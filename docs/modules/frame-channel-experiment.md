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
