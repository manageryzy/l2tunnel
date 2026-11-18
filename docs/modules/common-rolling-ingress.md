# Common Rolling authenticated input custody

Status: implemented in the current worktree with finite component and protected UDP integration checks. Source-stable Build39 passes five affected packages; Cases25 passes all34 selected changed-path and directly affected regression cases. The actual-preview native-progress correction is already committed. This is not an owner-selected default or complete full8192 qualification.

An explicit optional `rolling_ingress` Common resource policy selects independent complete-input slots and a complete Queue heap allowance for each local role. None preserves all previous resource digest and portable status bytes. Both complete role policies are included in the existing authenticated envelope/H0 resource commitment; existing canonical C values and wire records are unchanged. Old standalone Rolling queue coupling and its128 guard are a distinct unfinished path.

Each actual Rolling Endpoint generation owns one real reusable `native_storage::Queue` for already authenticated source/repair plaintext. The original Records owner commits replay exactly once. Retained metadata carries the original arrival, caller operation/session cap and optional actual Records number for observation; it grants no authentication or replay authority. Feedback continues directly to the existing sender. Full queue produces explicit retryable refusal, not success or native delivery.

Plans preflight all P+2 Queue reservations and actual complete packet geometry before selected allocation. Observed capacity/allocations join Endpoint heap usage and existing Engine/Bank totals once. The queue participates in drain, hard expiry and bounded work service. One input per turn may enter the maintained decoder, retaining bytes on Busy. Its existing maximum-sized input copy is a separate bounded ingress action; supplied GF/copy/metadata caps still bound the existing directional scheduler work and preview work. No hidden second decoder or mutable payload escape is introduced.

Original received time determines job/debt deadlines and the retained external cap can shorten them; observation and retries cannot renew them. The existing record/native lifetime and physical completion contracts remain separate. Portable status exposes requested paired limits, actual active Queue limits, actual layouts, occupancy, original arrival/Records number and deadline. An inactive non-Rolling generation allocates no wire-input queue.

- [ ] [RWI-01] Validate actual per-generation pooled input custody, exact complete Plan/Usage and one-short refusal, source/repair Busy retention, independent feedback, original received/caller-cap expiry, replay before queue admission, and current/staged/draining ownership using actual owners.
- [x] [RWI-02] Validate strict paired optional plan parsing, complete authenticated resource/H0 divergence, unchanged None bytes, exact requested versus effective observations and actual protected same-flow native delivery/drain across negotiated family switches. Evidence: [Cases25](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-25/validation.json).
- [ ] [RWI-03] Complete full FIX03/PBA named8192/local128/every16 full/half pressure with native local2, actual old holes beyond local128, real short copies, feedback loss/debt/ring reuse and original deadlines. Exact1460-symbol/MTU1500 installation requires the separate explicit versioned fragmentation/reassembly prerequisite; queues or changed-MTU tests cannot close it. Preserve all existing mode/native/resource/platform/performance gates.

The earlier GFI-01..03 draft remains historical and required at its original full scope. Full PBA/FIX03, source-copy, ACK, SW-11, all47 mode parity and80Mbit/s qualification remain open. The initial stage was authored without execution. Root subsequently ran the source-stable build and [Cases25](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-25/validation.json): actual queue refusal/retention and original caps, decoder deadline regressions, protected UDP burst/replay/native delivery/drain/switching, and strict paired CLI resource binding pass. This does not include fresh new-policy service establishment, privileged TAP/TUN, full named8192 composition, simulator equivalence or throughput qualification. Batch acceptance checks remain pending.

RWI-01 remains open for complete queued repair/independent-feedback pressure and simultaneous staged/draining ownership coverage. The current34 passing leaves establish source queue custody and a completed protected runtime switch; they do not prove every listed pressure composition.

### Local queue residence

A validated data input enters the decoder immediately when the queue is empty
and the decoder accepts it. Busy inputs retain their arrival time and original
cap. Older queued data gets service first. A completed admission can stage a
job, recognize a duplicate or recognize a stale input. Fixed histograms count
these admissions separately from inputs still retained when a session terminates.
Queue residence starts at authenticated arrival and ends at successful decoder
admission. Decoder completion and native delivery are separate events.

The target is zero data inputs with local ingress residence of 100 ms or more,
including retained input ages at termination. The first instrumented baseline
recorded 849 completed admissions and 253 still-retained inputs at or above
100 ms on the forward path. The reverse path had zero threshold crossings.
The baseline used the original Rolling UDP plan and work budgets.

In subsequent same-plan Linux namespace runs, the receiver cached the exact
oldest deadline and retention counters. Independent new originals bypass dense
row elimination. Each busy FIFO head waits for decoder completion before its
next attempt. Bounded GF multiply-add uses a shared read-only table and skips
zero words while charging the original work budget. The third run admitted
17,994 forward and 2,543 reverse inputs. Maximum residence was 68.595 ms
forward and 8.136 ms reverse. Both terminal ingress queues were empty. The
client then hit a separate CodecStage deadline. That run supplies local queue
evidence only. See the [native receipt](../../work/aligned-extents-20261117/native24-rolling3/receipt.json).

The sender and receiver share the same GF multiply-add implementation. When
a fresh source is available, it can take precedence over tail repairs that have
yet to start. Already started repairs, physical output and earned regular repair
credit keep their existing ownership. CodecStage tracks the earliest original
admission among the bytes currently held by the packer. A fragment tail keeps
its original age across source handoffs. A later frame stops inheriting the
deadline of a fully transferred frame.

The fourth run on the same plan exceeded the queue target again. Forward
admissions reached 4.415 s, including 1,159 of 4,429 at or above 100 ms.
All 196 data inputs retained at termination were also over threshold.
The maximum completed staged FIFO-head Busy interval was 27.370 ms. The
residence metric includes time behind preceding inputs. Sender EncoderDebt
expired first. The [measured populations](../../work/aligned-extents-20261117/native24-rolling4/queue-summary.json)
are independent of the earlier CodecStage failure.

The decoder checks singleton rows against the nonzero count of their
transaction-selected coefficient bank. A full census of 2,048 occupied rows
with 8,192 columns requires 2,049 metadata visits, including the final
transition. The former scan charged 16,779,265 visits. The field, copy and
metadata maxima per step stay fixed. Encoding charges GF work over each
original's two-byte length and actual body. Its canonical zero suffix makes
no contribution to the dense equation. Aligned wire extent, repair support
and original expiry retain their previous definitions.

The sixth baseline run used the original 10 ms tail trigger, work caps and
256 input slots. Of 10,080 forward admissions, 1,659 spent at least 100 ms
in local ingress. Mean residence was 114.884 ms and maximum residence was
1,310.351 ms. The forward p99 falls between 1,048.576 and 1,310.351 ms
using the inclusive histogram bucket and observed maximum. All 930 reverse
admissions were below threshold, with a maximum of 11.684 ms. Both queues
were empty at their terminal samples. The receiver reported 256 retained
inputs during the run. The longest completed staged head Busy interval was
23.188 ms. The client terminated on EncoderDebt with unconfirmed range
[6728, 9972). This run does not qualify end-to-end forwarding or queue
residence. [Sixth baseline queue summary](../../work/aligned-extents-20261117/native24-rolling6/queue-summary.json).

A separate Linux control changed only the tail trigger from 10 ms to 140 ms
on the fifth baseline binary. The typed descriptor audit checked both
directions. Mean forward ingress residence was 214.652 ms in the original
run and 95.255 ms in the control. Maximum residence was 4,343.737 ms and
1,754.829 ms respectively. The control still recorded 1,302 of 9,281 forward
admissions at or over 100 ms and terminated on client EncoderDebt. Each arm
used a separate network loss realization. This comparison does not establish
Python equivalence or a forwarding pass. [Control evidence](../../work/aligned-extents-20261117/native24-tail140-control2/queue-summary.json).
