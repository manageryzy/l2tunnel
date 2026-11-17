# Buffer occupancy and observed backpressure

Status: implementation in progress. This is an engineering coverage inventory for
all internal buffering, not a reduced definition of the owner's request. A
snapshot API, a counter and a measured runtime interval are different evidence.
Existing queue bounds, authentication, recovery and original deadlines remain
unchanged. Public protocol libraries use injected ticks or read-only snapshots;
actual clocks and diagnostic export remain at runtime boundaries.

## Measurement contract

For each actual owner/buffer, record sampled current items/bytes, operational
capacity, high-water samples, actual refusals/drops, progress and independently
identified blocking causes. Begin a wait only when eligible work actually cannot
advance. Repeated polls preserve the first refusal time and count as repeated
refusals, not new episodes. Close only the corresponding cause on observed
progress. A terminal event freezes unresolved intervals as censored; it is not
recovery. Report completed, open and censored durations, episode count and maximum.
Refusal-to-observed-progress intervals include scheduling delay.

Occupancy, queued residence, deliberate packing/ACK hold, missing-source/peer-credit
dependency, work-budget pauses, socket/TLS pending and physical-receipt callback
lag are distinct. An idle input read is not backpressure. Candidate rejection is
a drop/refusal counter, not an interval. Static scratch/context/replay storage has
capacity but no independent queue wait. Unknown/provider-private fields remain
unavailable, not zero. Per-owner/channel identities must survive aggregation;
count-only aggregate channel refusals do not establish channel wait duration.

The collector uses bounded scalar state and a fixed site/lane/class/reason
catalog, with no payloads, keys, per-packet logs, per-event allocation or export
I/O. It computes an owner-local union of active intervals. Never sum overlapping
site durations or different owners into end-to-end elapsed time. Clock regression,
counter overflow and impossible occupancy are visible diagnostic invalidity,
not new protocol errors. Opt-in allocation/configuration failures are explicit:
existing adapters return constructor errors before forwarding; proxy timing and
initialization diagnostics emit bounded sanitized unavailable notices and preserve
the original operation.

## Current hook inventory

All rows retain their complete scope until actual runtime export and focused
validation pass. "Implemented" below describes source, not a passing check.

| ID | Owner / retained storage | Current source and remaining coverage |
|---|---|---|
| BP-01 | Pipeline/MUX packet/byte/flow/DRR bounds | Actual Engine admission refusal callback implemented; aggregate refusal counts wired. Per-flow occupancy, reason-specific interval and DRR/policy attribution pending. |
| BP-02 | ACK ingress candidates/slab | Common held-input capacity wait implemented; internal deliberate coalescing hold and per-flow replacement age export pending. |
| BP-03 | Bank epoch slots/native window/output tokens | Existing resource usage retained; typed native-window refusal implemented. Per-generation wait and drain/export pending. |
| BP-04 | Aligned/Packed sender stage, fragment cursor, assembling/sealed container | Read-only actual codec gauges and typed refusals implemented. Per-owner runtime gauge/timing export pending. |
| BP-05 | Aligned receiver proofs/ordered records/fragments/native output | Read-only head/lookahead gauges implemented. Missing context/source vs consumer intervals and runtime export pending. |
| BP-06 | Reliable partial block/outgoing/restored/generations/physical tokens | Existing storage observations; dedicated builder, recovery/output and whole-write intervals pending. |
| BP-07 | Normal/Compact ARQ retention/reorder/transmission history | Existing timing/storage facts; actual capacity/ACK/RTO/physical/output-budget attribution and export pending. Exhaustion remains an error, not an invented wait. |
| BP-08 | Swift packing/sources/retries/repairs/history/rows/stream | Per-channel read-only gauges and actual packing refusal implemented. Independent channel timing/export pending. |
| BP-09 | Block FEC generations/equations/restored output | Rank/storage limits and bounded scratch remain; dedicated gauges/refusals/export pending. |
| BP-10 | Rolling/Research vectors/rows/jobs/feedback/ordered handoff | Existing status and work-used facts; nested codec gauges implemented. Recovery/work/feedback intervals pending. |
| BP-11 | Legacy sliding/recursive/parity pending/flight/jobs/batches/receive | Existing source/repair status; complete buffer intervals/export pending. These owners remain in scope. |
| BP-12 | Rolling/fragment groups/tokens/reassembly/completion | Existing original deadlines and ingress snapshots; explicit blockage attribution/export pending. |
| BP-13 | Connections owner/incarnation and per-owner recovery/native slots | Actual retirement/source-free refusal and codec identities implemented. Independent owner timing/export pending. |
| BP-14 | Common native read slab and exclusive unsealed/sealed User slot | Sampled runtime occupancy, actual held-input capacity and User send/receipt waits implemented. Raw metadata preparation reasons and full receipt latency decomposition pending. |
| BP-15 | Native output pool/device credit/receipts | Runtime occupancy, actual pool-acquire refusal counts and device-write WouldBlock intervals implemented. A refused scan lease does not prove useful native output exists, so its interval remains unmeasured. Native credit/controller internals remain BP-03. |
| BP-16 | Management message/recovery/reassembly/semantic/dispatch slots | Existing expiry snapshots retained; stream-specific occupancy and submission/dispatch/dependency timing pending. |
| BP-17 | Proxy channels/writer/Bridge/ring/measured ledger/relay buffers | Actual selected-frame receipt-ring refusal intervals and bounded receipt/import/callback timing export implemented. Focused current validation is recorded separately; writer/channel/relay occupancy, publication-to-import timing and complete measured-ledger attribution remain pending. |
| BP-18 | Raw candidate classes/pinned input/bitmap/prepared/tracked/receipts | Typed prepare reasons, per-class gauges/counters and terminal scalar retention implemented. Exact opt-in per-lane PacketIo intervals and Common scalar export pass focused local fixtures; native interval qualification is pending. Quota/pacing and prepare refusals remain separate untimed counts. Candidate residence, custody and peer-credit wait attribution remain incomplete. Bitmap is coverage state, not buffered packet bytes. |
| BP-19 | OpenVPN submissions/held datagrams/receive/setup buffers | Class/channel fullness, socket waits and receive drops pending. |
| BP-20 | Retained TLS class/writer/prefix/body/input/completion slots | Actual class refusal, write/flush Pending and work-budget waits implemented; bounded occupancy sampled. TLS Pending does not prove kernel queue saturation. |
| BP-21 | QUIC permits/tickets/DATAGRAM wait/cache/provider queues | Actual class-slot refusal and pending-send intervals, permit/cached-input gauges and provider available-payload samples implemented. Public RTT/cwnd/congestion/loss and UDP counters now have bounded per-lane sampled export with passing focused validation and the finite native10 observation below. Exact provider send/receive occupancy remains unavailable; capacity minus available is not a valid occupancy calculation. Actual QUIC FIFO permit/capacity fixture passes; native9 exercises earlier diagnostic export but its finite QUIC case exhausts the original bound. |
| BP-22 | Maintained carrier wrapper User/Control/cache slots | Common User completion wait implemented as combined wrapper/carrier wait. QUIC wrapper class admission, pending send and receipt-slot gauges implemented; remaining backend-specific attribution pending. |
| BP-23 | Local request, bootstrap and joining retry buffers | Existing bounded owners retained. Opt-in constructor/readiness stages and accepted local API read/handler/reply durations implemented; listener backlog delay and full bootstrap/retry-buffer blockage attribution remain unmeasured. |
| BP-24 | Static scratch, codec contexts, replay maps and receive bitmap | Capacity accounting only; no independent queue-wait metric. Eviction/refusal still requires an explicit counter where applicable. |

### Proxy receipt and callback populations

The `proxy_bridge` owner uses the same terminal `.bmetrics` schema and carries
bounded timing summaries under `proxy`. Receipt-ring waiting begins only when an
already selected frame cannot reserve a third unacknowledged receipt. Passive
retention alone is not backpressure. Repeated refusals retain the first timestamp;
acknowledgement clears the interval, and terminal unresolved waits are censored.
Occupancy and high water are samples at these boundaries, not continuous gauges.

Whole-frame acceptance-to-Common-observation samples include every validated
complete frame. Ledger-import samples include all writer Data ordinals, including
transparent native traffic, but only after successful atomic provenance checks.
Repeated watch reads do not duplicate imports. Gate samples are repeated
**gate-by-pending-entry** observations, not one latency sample per packet.
Successful callback samples require actual Controller confirmation; a failed
deadline gate never counts as a successful callback. These populations overlap
and have different counts, so their means or maxima must not be added.

Actor stage summaries are wall time, including waits, scheduling and terminal
cleanup in an interrupted final stage; they are not buffer-blocked durations.
`terminal_ledger_observed` distinguishes a completed terminal ledger scan from a
cancelled owner with unavailable final ledger coverage. Publication-to-import
remains explicitly null because watch publication can race with actor import.
The optional diagnostic owns bounded fallible heap storage, while the disabled
handle contains only three machine words. Setup/allocation failures emit at most
one sanitized unavailable notice per reason per process, without paths or payloads.

## Export and validation

`L2TUNNEL_BUFFER_METRICS` selects an output prefix. If absent, explicitly selected
`L2TUNNEL_WIRE_METRICS` also enables this companion diagnostic. Each actual runtime
owner emits a separate terminal `.bmetrics` JSON file. Its extension prevents the
existing record histogram reader from mixing these populations. Diagnostic heap
and path capacity are reported separately from authenticated protocol quotas;
inline owner sizes remain in their normal resource plans. No disabled observer
allocates its collector. Optional provider snapshot storage is heap-backed and reserved at construction, avoiding large disabled owner/future layouts.

Collector tests exercise repeated refusal, overlapping causes, terminal censoring,
clock rejection, bounded allocation and counter validity. Actual retained-TLS and
Common blocked-write fixtures exercise the production hooks. The frozen batch check is recorded in
[`required-buffer-checks2-env1.json`](../../work/aligned-extents-20261117/required-buffer-checks2-env1.json)
and its [continuation](../../work/aligned-extents-20261117/required-buffer-checks2-continuation1.json).
The first batch stage uses the existing `/tmp/l2tunnel-quic-venv` dependency environment;
the system Python attempt failed dependency preflight and is retained separately.
After two lint corrections, strict Clippy/rustdoc and the external Common CLI probe
pass. Runtime tests pass 301 cases; client tests pass 195 with the existing measured
QUIC callback deadline failure still open. Report-tool and native-harness unit
checks pass. Unchanged codec no-default validation is reused from the first buffer
batch, not rerun or presented as a new native measurement.

The initial inline raw snapshot caused a stack overflow. Bounded preallocated
retention removes that failure without changing test stacks or protocol deadlines.
The [isolated corrected Frame run](../../work/aligned-extents-20261117/buffer-stack-fix2.json)
passes Full/TAP and Full/TUN then fails Half/TAP liveness; the subsequent full runtime
run passes that same fixture. This intermittent result does not close the Half
scheduling/liveness issue. The native9 diagnostic evidence below does not close
any full BP row or establish all-buffer acceptance.

### Finite native9 diagnostic evidence

The [native9 buffer report](../../work/aligned-extents-20261117/buffer-native9-report1/report.json)
parses 12 valid `.bmetrics` files with no rejected inputs. Its
[source binding](../../work/aligned-extents-20261117/matrix-source-binding-9.json)
records commit `06aed308c9e95b3021797ec6ea7511793df1c170` and release binary
SHA256 `23102e85e8307b18af9b0804e447fe26a2f35a737034fe583bf5c75483c10b6d`.
All four selected cases fail or exhaust their original bound: QUIC forward reaches
the case bound, raw forward reaches ARQ retry exhaustion, TLS reverse reaches the
original record send cap, and UDP forward reaches ARQ retry exhaustion followed
by peer liveness expiry. This exercises real diagnostic export under failure;
it does not qualify successful throughput.

Within one retained-TLS owner, the observed flush wait union is 78.532% of that
owner's observation span. Within one maintained-QUIC owner, observed admission
wait is 90.230%. These are separate, overlapping owner observations, not an
end-to-end sum or proof of the originating bottleneck. Both UDP Common owners
report zero observed timed wait despite the recovery failure: unhooked internals
remain unmeasured, not zero. Raw reports no actual PacketIo `WouldBlock`, while
the two owners report 527 and 296 candidate-capacity drops. That demonstrates
bounded receive-queue pressure in this run without establishing the cause of
each exhausted source. The exact raw timing extension below was not in native9;
its validation remains separate.

### Sampled public Quinn transport statistics

The opt-in maintained-QUIC observer samples the actual connection's public
statistics at its first observation and at most once per 100 ms thereafter,
using existing diagnostic poll points. It creates no timer or driver wake and
changes no transport configuration. Each original lane retains first/last
connection counters, sampled RTT/cwnd extrema, congestion-event and lost-packet
counts, lost bytes, sent QUIC packets, and transmitted/received UDP datagrams
and UDP payload bytes. Connection counters include setup. UDP datagrams are not
QUIC packets or Common records; received QUIC-packet count remains unavailable.

These fixed scalar summaries occupy the existing opt-in provider backing and are
included in its diagnostic heap count. Disabled owners do not query provider
statistics. Clock/counter regressions and diagnostic overflow remain explicit;
the last sample can precede terminal observation. Sampled extrema do not measure
time spent congestion-limited, and the observers do not infer private queue
occupancy. The native9 record has no such statistics; it cannot by itself resolve
congestion versus local scheduling contributions to its admission waits. Focused
cadence/counter-regression validation passes; native10 below exercises the actual
export. This does not supply exact provider-private queue occupancy.

### Exact raw PacketIo timing

When buffer diagnostics are enabled, the actual ready raw owner reserves one
timing cell per original lane before installing any cell. Disabled owners retain
empty vectors. Optional backing is reported per lane in
`send_io.diagnostic_heap_bytes`, separately from the Common observer's own backing
and unchanged authenticated protocol quotas.

Only an actual inner PacketIo `WouldBlock` begins an episode. Local work-quota
and pacing refusals neither begin nor close it. Actual successful sends close at
the existing physical acceptance timestamp; later receipt consumption does not
extend the socket interval. Cancelling the retained packet censors its episode,
and the first terminal carrier failure freezes open episodes before capturing
the existing terminal snapshot and releasing original I/O. Every edge updates
bounded arithmetic directly; periodic Common snapshots do not reconstruct timing
from counter deltas.

The `send_io.timing` object separates completed, cancelled, terminal-censored and
open portions, maximum observed duration, actual refusal count and invalid-clock
or overflow flags. Timing enabled while already blocked marks its unknown earlier
start explicitly and reports the observed portion as a lower bound. Lifetime
count-only observations can include earlier setup; timed observations begin when
the ready owner is instrumented. A Common pre-settlement sample can retain an
open raw interval if Common stopped before raw owner failure; it is not recovery.
Per-lane durations can overlap and are not added to the Common collector's union.

Local source validation passes for deterministic edge/censoring and invalidity,
the actual GateIo quota/pacing/refusal fixture, genuine Full/Half retained-ciphertext
and exact-deadline receipts, and JSON censoring export. The native10 raw attempt
fails before the ready owner, so it supplies no fresh native timing qualification.
BP-18 retains its remaining scope.

### Initialization and local API timing

`L2TUNNEL_INITIALIZATION_TIMING=1` enables fixed-size per-owner stage summaries
in stderr. Actual Common planning, auxiliary storage construction, Bank construction
(including its own validation/allocation), activation, transaction construction and
Driver assembly are separate stages. First-running readiness has a separate owner.
Local API observations start at listener acceptance, followed by request read,
handler and reply. They do not measure pre-accept backlog or identify CPU time.
Request duration overlaps these stages and must not be added to them. Early owner
exit is censored. No original deadline or scheduling policy changes.

Diagnostic state is fallibly reserved only when enabled; allocation refusal emits
a bounded unavailable notice and preserves the original operation. Reports are
bounded to 32 owners and 34 cumulative reports per owner, including sparse local
API checkpoints. An owner absent from output is not evidence of zero duration.

The native harness retains timed-out command PID/exit/timing observations and
capture stop signals. An INT-resistant capture receives TERM within the original
three-second graceful allowance, then the existing bounded KILL cleanup. A killed
capture remains unqualified; complete counters alone do not override its exit.

### Saved observation report

`python3 tools/buffer_metrics_report.py --output NEW_DIRECTORY FILE.bmetrics ...`
reads at most 64 saved files of at most 4 MiB each and writes `report.json` and
`report.md`. It preserves each owner and source hash separately, ranks observed
reason durations, and separates count-only refusals and sampled occupancy. Only
that owner's exported interval union is divided by its observed span; overlapping
sites and different owners are never summed. Invalid observations suppress the
percentage. Malformed sources remain rejected inputs; exit status 2 flags rejected
or invalid observations. Successful parsing still means partial coverage. Raw and
QUIC provider metadata is preserved without inventing exact internal queue usage.

### Follow-up validation and receive-service repair

The [second affected-owner continuation](../../work/aligned-extents-20261117/required-buffer-checks3-continuation2.json)
passes strict workspace Clippy/rustdoc, changed codec/recovery/reliable/Aligned/
record/runtime tests, and codec no-default tests. The runtime passes 306 cases;
raw timing and actual Half lane receive fairness passed in the preceding
[shared continuation](../../work/aligned-extents-20261117/required-buffer-checks3-continuation1.json).
These are local Linux fixtures. The previously failed measured QUIC proxy remains
open; no full aggregate-green or native-performance claim follows.

Raw Common now drains already received bounded custody within the existing
receive-work allowance and rotates First/Second only after consuming a pinned
verification result. It does not repoll PacketIo to manufacture a new budget.
The actual Half fixture exercises more than one original key interval, continuous
First traffic, Second control service, unchanged metadata pinning and no extra
PacketIo reads while draining. Native throughput qualification is separate.

The native9 Aligned receiver consumed approximately one user-space CPU core
while its periodic status publication stalled. Source inspection found repeated
short-record preview admission over retained recovery sources; every duplicate
rechecked all expiry proofs. The receiver now reuses an already accepted tick's
successful expiry check. Sticky failure and time regression still precede the
fast path, original deadlines remain unchanged, and rollback restores the
corresponding ledger/time state. Exact-expiry and failed-batch regressions pass
for both reserved and allocating owners. Remaining source enumeration is still
bounded linear work; this is not proof that all receiver CPU cost is resolved.

CompactARQ now retains scalar state at the actual RetryExhausted transition,
including the failed source/attempt/physical acceptance/RTO and last applied peer
feedback. The existing terminal diagnostic exposes at most two shared epochs.
The snapshot is immutable across later terminal physical settlement, contains no
payload or bitmap history, uses injected times, and is charged in existing
reserved state. Its two failure-path tests pass. It changes neither retry policy
nor wire format.

The [diagnosed proxy fixture](../../work/aligned-extents-20261117/proxy-timing-validation3/receipt.json)
retains six valid owner reports and still fails its original callback deadline.
The [same-token analysis](../../work/aligned-extents-20261117/proxy-timing-validation3/failed-token-analysis.json)
shows ordinal46's Common observation already 45.704 microseconds beyond its
original 50ms deadline. Receipt-ring refusal count is zero. This observation
rules out a callback-only repair for that particular attempt; it does not locate
all pre-acceptance delay. Gate ages, actor stage wall times and unrelated maxima
must not be added into a fabricated per-packet delay.


### Native10 observations and remaining bottlenecks

The source-bound [release10 build](../../work/aligned-extents-20261117/matrix-source-binding-10.json)
uses commit `8e6c4f5` and binary SHA256
`7ee66c8faede978977f0d8b1c929c8fb8362f2ef04365d44ed26c72675ed5be1`.
The [updated complete report](../../work/aligned-extents-20261117/matrix-report-repairs10-complete1/report.md)
retains all 35 input roots: 80 combinations, 13 passed, 186 failed, 32
bound-exhausted and 9 not-run selected phases. These are mixed source-bound
versions, not a same-build qualification. The offline reporter now permits at
most 128 explicit roots so adding receipts does not discard earlier attempts;
this changes no protocol or lab limit.

The QUIC/Swift forward phase passes at 0.243264 Mbit/s, from 304,080 unique
application bytes in the ten-second window. Sender maintained-QUIC admission
wait covers 89.4423% of its observation span; Common receipt wait covers 90.3374%
of its own span and overlaps it. The sender samples RTT 70.165–74.265 ms and
cwnd 2,944–12,529 bytes. Between first and last samples it observes 405 congestion
events, 494 lost QUIC packets and 466,335 lost bytes. These demonstrate real
congestion/loss and admission backpressure, but do not prove every wait is
congestion-window limited or identify a runtime defect. Cleanup follows transfer:
one owner is Aborted and its peer reports close/Other; successful data validation
does not establish bilateral graceful shutdown.

The UDP/Aligned Compact forward attempt still fails, at source 36,229 after
nine transmissions. The exact terminal snapshot preserves the last applied peer
feedback and physical acceptance. The receiver retains 8,039 sources, with
`deliver_next=28241`, `receive_prefix=36229` and `highest_received=36287`.
Its 2,033 native backpressure drops are authenticated input refusals; 14,246
successful native writes and zero observed device `WouldBlock` do not implicate
the TUN write queue. RecoveryPressure and the one-packet-per-turn native drain
are under repair. The final window includes source 36,229, so that terminal
snapshot alone cannot prove exactly which earlier receive refusal lost it.
There is no qualified throughput for this failed phase.

The UDP sender's owned-process CPU profile has 623 samples. Flat samples place
20.87% in Compact selection, 17.66% in compact receive, 5.62% in Aligned custody
deadline and 4.65% in send-store length. The receiver profiler was forcibly
terminated and produced an invalid header; it is a tool failure, not usable
receiver CPU evidence. This was a profiled native run, and profiling overhead is
not assumed to be zero.

The raw/Aligned Compact attempt exhausts the original 30-second setup deadline
on both peers before Common/Noise membership observations. The current
Configuration stage spans multiple setup owners and cannot identify the blocking
substage. It does not exercise or qualify the ready raw receive fix. A bounded
terminal setup snapshot is being added without changing retries or deadlines.

For the failed UDP run, accepted source emissions have actual IPv4 bytes outside
the codec body averaging 60.0945 bytes (p99 61) forward and 58.7294 bytes (p99 59)
reverse. Common protection itself remains 21 bytes; UDP/IPv4 contributes 28.
Canonical variable-length source/attempt identities and the codec envelope account
for further framing. The observed systematic coded-fill histogram is zero in
both directions. These source populations include retransmissions and exclude
feedback; the body still contains native codec fields, so these are **not** full
native encapsulation-overhead percentiles. QUIC outer packet attribution is still
unavailable, even though its inner record overhead is measured.

The actual [six buffer exports](../../work/aligned-extents-20261117/buffer-native10-report1/report.md)
parse as valid partial observations. They do not close BP-01 through BP-24,
full-native overhead quantiles, or the complete throughput matrix.

### Constant-time recovery occupancy

Reserved and indexed ARQ send/receive stores now maintain occupied counts at
successful insertion and actual retirement. Failed admission, repeated removal,
retain filtering and reused circular slots preserve the count. Length and empty
queries no longer scan the complete configured window; slot/payload allocation,
retry ordering, protocol bytes, bounds and deadlines are unchanged. These scalar
fields live in the owner rather than new heap allocations.

The [scoped recovery receipt](../../work/aligned-extents-20261117/occupancy-validation1/receipt.json)
passes the complete recovery tests and strict recovery Clippy, with unchanged
recovery source during the commands. Broader validation and native effect remain
separate; selection, feedback history and other scans have not been removed.


### Native refill, setup and proxy timeline checkpoint

The actual Common native writer now refills after successful Engine commit within
one unchanged turn allowance. Each attempted output or empty eligible scan uses
that allowance; `WouldBlock` stops with the original packet, token and deadline.
The native10 configuration has write batch 64 and disables NativeWindow on both
sides, so delivery-receipt admission does not gate these refills. Configurations
that explicitly enable delivery receipts retain their existing receipt gate.
No unconditional per-turn write count is promised.

Raw PacketSetup now exposes fixed scalar progress for at most two lanes and
retains its first failed/ready observation before releasing original owners.
The extra preallocated slot is charged against the existing metadata ceiling.
The client failure trace also observes the earlier service deadline or future
cancellation before destruction. Gate sampling uses `try_lock`; other existing
status accessors can acquire bridge locks, so the whole snapshot is not claimed
to be lock-free. The trace contains stages/counters/flags, not key material.

The existing proxy provider retains two ordinal rows joined to Bridge generation
and Common record identity. It distinguishes ledger handoff from bounds around
actual queue publication, observed writer dequeue, Common admission, and whole
acceptance/observation. Queue publication can race dequeue. Missing facts remain
null, and a mismatched identity cannot replace valid facts. These are scalar
stage observations, not additional blocked-interval samples.

The [required batch attempt](../../work/aligned-extents-20261117/required-buffer-checks4-attempt1/validation.json)
passes 82 Python preflight cases and stops on a new test's denied `expect_err`.
After correcting that assertion, the [continuation](../../work/aligned-extents-20261117/required-buffer-checks4-continuation1.json)
passes strict workspace Clippy/rustdoc and external Common CLI checks. Raw passes
175 cases with two ignored and recovery passes 62. Client has 194 passed and two
measured-proxy failures. Runtime has 307 passed and two failures: the new native
fixture's readiness wait and a raw Frame transaction custody timeout.

The new fixture had simulated `WouldBlock` while leaving its real socket writable.
It now fills and drains the actual Unix socket queue within a fixed bound and
keeps all four original one-second readiness caps. The [focused continuation](../../work/aligned-extents-20261117/required-buffer-checks4-focused1/receipt.json)
passes strict runtime Clippy and the actual multiwrite/blocked-custody regression.
The raw Frame Full/Half TAP/TUN case also passes this diagnosed rerun; the earlier
aggregate custody failure remains unexplained. Both real TLS and QUIC measured
proxy cases reproduce HandoffExpired with the new joined timelines. All twenty
saved buffer exports parse as valid partial observations. There is no aggregate
pass, native-performance qualification, or completed BP parent row.

A failure-only trace now prints the six original generic custody deadline
candidates separately: operation, retained outcome, sealed and unsealed User,
raw control, and deferred feedback. It preserves the existing minimum/deadline
semantics. Raw per-slot identities are unavailable at this boundary; the trace
does not infer them from a later sample.

### Native11 and bounded scheduling follow-up

The source-bound [release11 receipt](../../work/aligned-extents-20261117/matrix-source-binding-11.json)
identifies checkpoint `4c237db`; both renewed native cases fail. Raw remains in
PacketConfirmation at the original 30-second service cap. Its client consumed all
32 shared transition copies on Hello before the delayed peer Hello arrived, so
no first Commit could be sent. The current correction reserves two of those same
32 attempts for the role's Commit/CommitAck, keeps the 250ms cadence and original
absolute cap, and avoids advertising an expired Hello wake while waiting for a
peer prerequisite. It reduces maximum Hello copies to 30; arbitrary losses can
still exhaust the original bound. Both focused transition regressions now pass;
the actual native correction remains unqualified. The
[phase-budget investigation](../../work/aligned-extents-20261117/raw-native11-root-cause1/report.md)
joins packet extents with retained owner state. `hello_reply` requests a local
Hello resend; it is not a separate wire message or required peer-ack stage.

UDP/Aligned fails at source 7127 after nine attempts. Both endpoints report zero
authenticated-input pressure drops, authentication rejects and replay rejects.
The [packet/counter analysis](../../work/aligned-extents-20261117/native11-udp-failure-analysis.json)
finds the final-attempt candidate at both complete WAN capture surfaces. Its
identity is inferred from the selected one-copy attempt/packet numbering and exact
length, not decrypted payload. Receiver delivery still stops at 7127. Kernel UDP
queue loss is a hypothesis, not established by these receipts. The observer now
samples owned-namespace SNMP, UDP socket tables and sockstat with before/after
qdisc observations; these are counters/gauges, never blocked intervals.

The failed-run CPU sample spans 3.910751 seconds: sender user/kernel time is
2.16/1.09 seconds and receiver 2.98/0.58 seconds. Host-wide load is separate. The
[current mixed-version matrix](../../work/aligned-extents-20261117/matrix-report-repairs11-complete1/report.md)
still retains every prior phase; this is not complete same-build qualification.
The [two native buffer reports](../../work/aligned-extents-20261117/buffer-native11-report1/report.md)
have no observed timed episode; unhooked internal waits remain unavailable.

The next source batch removes two avoidable costs without changing protocol caps:
CompactARQ samples/retires only the newly echoed contiguous history span instead
of scanning all 131072 allocated slots, and maintained carriers settle already
retained whole-send receipts before their cooperative yield. The latter preserves
normal identity/Research-order checks, fresh observation time and cancellation
before new I/O; it does not backdate a callback or qualify the 50ms proxy deadline.
The [history validation](../../work/aligned-extents-20261117/history-range-validation1/receipt.json)
passes 68 recovery tests, one doctest and strict Clippy, including same-source
retry wrap and encoder refusal/error without serial holes.

Authenticated Aligned/nested-Connections input pressure now retains typed aggregate
ARQ receive/send capacity, receive horizon and transmission-history refusal counts
in the existing provider. Dropped inputs do not start timed waits. These counters
aggregate epochs/connection owners and do not implement per-owner occupancy or
all BP-05/BP-07 intervals. Other BP rows and full overhead mean/p99 remain open.

The [required check5 attempt](../../work/aligned-extents-20261117/required-buffer-checks5-attempt1/validation.json)
passes preflight, strict workspace Clippy, all 310 runtime tests and all 196 client
core tests, including the retained TLS and genuine QUIC measured-proxy cases.
Its only aggregate failure is the new delayed-Hello regression. Separate focused
clock/copy diagnostics retain that failure instead of discarding it. Strict
rustdoc, CLI plan/rejection and the real external Common CLI probe subsequently
pass in the [remaining-stage receipt](../../work/aligned-extents-20261117/required-buffer-checks5-remaining1.json).
That continuation records concurrent changes only to the raw test fixture; none
of its commands compile that test module. Unchanged codec no-default and Python
harness/simulator checks retain their earlier receipts. These scoped results do
not constitute a fresh all-green aggregate or native performance qualification.

The [final focused raw continuation](../../work/aligned-extents-20261117/raw-reservation-final1/receipt.json)
passes formatting, strict raw all-target/all-feature Clippy and both transition
regressions, including all four first-Commit/first-CommitAck loss combinations.
The initial fixture negotiated only 8576 bytes from 16 packet slots, so its
21-copy stop was correct credit enforcement before the intended budget boundary.
Only this new fixture now selects 32 initial packet slots and asserts its actual
peer horizon can hold all 32 Hello payloads. Shared defaults, production limits,
250ms cadence and the original 10-second absolute test cap remain unchanged.
Failed attempts and their exact credit observations remain retained. Required
check5 plus its focused and remaining-stage continuations provide scoped passing
coverage; the original aggregate process remains recorded as failed.
