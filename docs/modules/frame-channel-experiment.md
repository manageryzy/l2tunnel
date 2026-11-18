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
windows. [Capture byte accounting and packing bound](../../work/c48-parity-20261119/native/fresh-attribution/breakdown.json).

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
