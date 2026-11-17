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
| BP-04 | Aligned/Packed sender stage, fragment cursor, assembling/sealed container | Actual codec gauges and typed refusals implemented. Bounded per-epoch/owner sampled export and exact retained-source capacity/window refusal-to-admission timing are implemented; validation is recorded below. Packing hold, fragment cursor and other stage waits remain pending. |
| BP-05 | Aligned receiver proofs/ordered records/fragments/native output | Head/lookahead/proof/native-output gauges have bounded sampled runtime export. Missing context/source versus consumer intervals remain pending; occupancy does not establish blocking. |
| BP-06 | Reliable partial block/outgoing/restored/generations/physical tokens | Existing storage observations; dedicated builder, recovery/output and whole-write intervals pending. |
| BP-07 | Normal/Compact ARQ retention/reorder/transmission history | Reliable ARQ retention has sampled runtime export, and exact staged-source capacity/sequence-window refusal-to-admission timing is implemented. History use and remaining ACK/RTO/physical/output-budget attribution remain pending. Exhaustion remains an error, not an invented wait. |
| BP-08 | Swift packing/sources/retries/repairs/history/rows/stream | Per-channel read-only gauges, actual packing refusal and bounded runtime export are implemented, including asymmetric channel identities and shared packing scope. Coordinated local validation passes below; native export qualification and independent channel timing remain open. |
| BP-09 | Block FEC generations/equations/restored output | Rank/storage limits and bounded scratch remain; dedicated gauges/refusals/export pending. |
| BP-10 | Rolling/Research vectors/rows/jobs/feedback/ordered handoff | Nested codec gauges and three exact retained-operation intervals are implemented: source admission, decoded handoff and ready-feedback budget. Optional bounded storage and runtime export are charged before I/O. Coordinated local validation passes below; native qualification, work slices, feedback construction, ingress and missing-source dependencies remain open. |
| BP-11 | Legacy sliding/recursive/parity pending/flight/jobs/batches/receive | Existing source/repair status; complete buffer intervals/export pending. These owners remain in scope. |
| BP-12 | Rolling/fragment groups/tokens/reassembly/completion | Existing original deadlines and ingress snapshots; explicit blockage attribution/export pending. |
| BP-13 | Connections owner/incarnation and per-owner recovery/native slots | Actual retirement/source-free refusal and codec identities implemented. Sampled codec/recovery export preserves full independent owner incarnation; exact staged-source admission waits retain the same identity. Remaining lifecycle/source-free/native wait timing is pending. |
| BP-14 | Common native read slab and exclusive unsealed/sealed User slot | Sampled runtime occupancy, actual held-input capacity and User send/receipt waits implemented. Raw metadata preparation reasons and full receipt latency decomposition pending. |
| BP-15 | Native output pool/device credit/receipts | Runtime occupancy, actual pool-acquire refusal counts and device-write WouldBlock intervals implemented. A refused scan lease does not prove useful native output exists, so its interval remains unmeasured. Native credit/controller internals remain BP-03. |
| BP-16 | Management message/recovery/reassembly/semantic/dispatch slots | Bounded per-stream occupancy and exact frozen Transaction submission refusal-to-admission timing are implemented and pass focused actual-owner tests. Ordinary reused-ID submissions are count-only; fragment, receipt, dispatch and dependency intervals remain pending. Runtime terminal export qualification remains separate. |
| BP-17 | Proxy channels/writer/Bridge/ring/measured ledger/relay buffers | Actual selected-frame receipt-ring refusal intervals and bounded receipt/import/callback timing export implemented. Focused current validation is recorded separately; writer/channel/relay occupancy, publication-to-import timing and complete measured-ledger attribution remain pending. |
| BP-18 | Raw candidate classes/pinned input/bitmap/prepared/tracked/receipts | Typed prepare reasons, per-class gauges/counters and terminal scalar retention implemented. Exact opt-in per-lane PacketIo intervals and Common scalar export pass focused local fixtures; native interval qualification is pending. Quota/pacing and prepare refusals remain separate untimed counts. Exact commit/physical/observation/upper-take custody latency passes coordinated local validation; it is separate from blocked time. Candidate residence and peer-credit wait attribution remain incomplete. Bitmap is coverage state, not buffered packet bytes. |
| BP-19 | OpenVPN submissions/held datagrams/receive/setup buffers | Class/channel fullness, socket waits and receive drops pending. |
| BP-20 | Retained TLS class/writer/prefix/body/input/completion slots | Actual class refusal, write/flush Pending and work-budget waits implemented; bounded occupancy sampled. Actual queued-class writer selection and partial-input missing-byte intervals now pass focused framing tests; native qualification is pending. TLS Pending does not prove kernel queue saturation. |
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

### Native12 observed carrier waits and kernel receive loss

The [stable release12](../../work/aligned-extents-20261117/matrix-source-binding-12.json)
builds checkpoint `d0692ae`. Four affected owned-namespace phases run in parallel
under the unchanged 100/10Mbit/s, 35ms one-way delay and 15% per-direction loss
configuration. [The phase summary](../../work/aligned-extents-20261117/native12-summary1.md)
records raw/Aligned Compact forward at 5.4178368Mbit/s, genuine QUIC/Swift ARQ
forward at 0.2629568Mbit/s, and retained TLS/Swift ARQ reverse at 0.2154624Mbit/s.
These three ten-second data samples pass. Raw and TLS disconnect both peers;
QUIC's second disconnect fails. UDP/Aligned Compact fails without qualified
throughput. Every owned namespace is removed after identity/empty-PID checks.

The [twelve buffer exports](../../work/aligned-extents-20261117/buffer-native12-report1/report.md)
parse as partial observations. The QUIC sender's carrier wait union is
50.232816 seconds over 60.655126 observed seconds (82.817%); the TLS sender spends
45.551866 seconds in observed FlushPending over 64.994978 seconds (70.085%).
These owner-lifetime intervals include warmup and drain, not only the ten-second
application sample. The Common receipt intervals overlap them and must not be
summed. They locate observed stalls but do not prove a unique congestion cause.

UDP has no timed event in the currently attached singleton hooks. Its receiver
namespace nevertheless records 2005 additional Udp.RcvbufErrors and InErrors.
This is actual kernel receive-buffer loss beyond configured netem loss; tuple
and packet-population attribution is retained separately from namespace totals.
Zero observed user-space intervals therefore cannot establish absence of pressure.
Receive service cost and unhooked protocol-owner waits require further work.

The [updated mixed-version matrix](../../work/aligned-extents-20261117/matrix-report-repairs12-complete1/report.md)
contains 15 passed, 186 failed, 32 bound-exhausted and 7 not-run selected phases.
It preserves prior receipts and does not qualify all 80 combinations on release12.
Full original-native overhead quantiles and BP-01 through BP-24 remain open.


### Exact staged-source waits and source-proven CPU work

The next source batch adds opt-in `protocol_buffers` to each Common observer.
Two preallocated epoch tables use the catalog maximum of actual independent
connection owners (at most 256); shared multi-channel endpoints use one row.
Full epoch, configuration digest and connection incarnation remain explicit.
Sampling occurs at most once per 100 ms when the loop is serviced, plus a
forced sample at the original pre-settlement metric stop.
Current/capacity/high-water observations are sampled gauges, not continuous
occupancy or wait time. Unknown transmission-history use remains null, and
unsupported recovery families produce no fabricated zero-use owner. Diagnostic
backing is charged by its actual allocated row capacity and remains separate
from protocol resource limits.

Aligned/Packed now observe real retryable recovery admission refusals for the
exact retained source ID and length. Repeated attempts preserve the first refusal
time; only admission of that same source closes its episode. Send-capacity and
sequence-window reasons can overlap; their owner-local union is recorded
separately. Original injected time remains the only clock in public libraries.
Owner failure freezes an unresolved episode; the runtime censors a fresh snapshot
at its original pre-settlement metric stop. Between-sample owner retirement can
still lose the unsampled tail, and bounded generation replacement is explicit.
These limitations keep the complete BP-04/BP-07/BP-13 scope open.

The report tool now validates known provider identities, bounds, invalid flags,
occupancy and wait totals while preserving unavailable fields. Provider-specific
waits are not added to generic collector percentages. The actual Common fixture
must drive its MUX input through the real first recovery emission before checking
ARQ retention; a nonempty queue alone must not create an admission wait.

The separate [diagnostic profile](../../work/aligned-extents-20261117/diagnostic-udp-native12-perf1/profile-binding.json)
uses the unchanged release12 binary, with both owned-daemon perf processes exiting
zero and no lost samples. Sender selection accounts for 42 of 126 CPU-clock self
samples. Receiver `memcmp` accounts for 22.29% of 157 samples under repeated
Aligned preview admission. These small sampled CPU populations identify work;
they are neither blocked-time percentages nor qualified goodput measurements.
The [sender draft evidence](../../work/aligned-extents-20261117/compact-selection-draft/proposal.md)
and [receiver evidence](../../work/aligned-extents-20261117/receiver-service-draft13/notes.md)
explain the integrated changes: reuse one Compact ARQ selection across its exact
length/budget preflight and actual emission, skip reparsing only successfully
observed immutable recovery sources, and use the existing allocation-free
canonical Common configuration digest. Selection/error precedence, authentication,
conflicting-duplicate rejection, original deadlines and every resource bound
remain unchanged. Remaining full-window iteration and deadline scans are open.

The required [check6 attempt](../../work/aligned-extents-20261117/required-buffer-checks6-attempt1/validation.json)
passed preflight and failed on a new test-only Result alias compile error; that
error was corrected. Its [continuation](../../work/aligned-extents-20261117/required-buffer-checks6-continuation1.json)
passes strict Clippy/rustdoc and the actual external Common CLI probe. Runtime
has 312 passes and two failures: the new fixture sampled before real ARQ admission,
and the existing raw Half/IP switch case again expired. The fixture is corrected
in source; final focused validation follows separately. The exact raw test
[passes one focused rerun](../../work/aligned-extents-20261117/raw-frame-check6-diagnosis1.json)
through all four Full/Half TAP/TUN combinations, leaving its aggregate failure
unresolved. Its `RAW_FAILURE_LANE dropped` field counts transport object destruction,
not injected packet loss. Original failed receipts remain unchanged.

[Native12 encapsulation layers](../../work/aligned-extents-20261117/native12-overhead-analysis1/report.md)
retain both directions and their independent populations. Aligned UDP IP bytes
outside the same emission's codec body are 58.979/60 B mean/p99 forward and
58.536/59 B reverse; raw TCP is 71.820/73 B and 70.788/71 B respectively. Those
joined framing measurements are not full original-native overhead. Genuine
TLS/QUIC physical-packet extents remain unavailable at inner Records acceptance;
all recorded Records protection samples are 21 B. Full-native mean/p99 and the
complete same-build throughput matrix remain required.


The same batch reads actual original Common UDP `SO_RCVBUF` and `SO_SNDBUF`
once at runtime entry when diagnostics are enabled. `udp_socket` retains the
actual local/peer tuple, independent option readback/error metadata and explicit
allocation failure. No setter is called. Linux values remain kernel accounting
byte limits rather than inferred payload capacity, current use or blocked time.
The readback is runtime-owned and adds no OS dependency to public protocol crates.

The [affected-source continuation](../../work/aligned-extents-20261117/buffer-hotpath-validation13c/receipt.json)
passes recovery, reliable, codec, record integration, all twelve measured client
cases, codec without default features and strict rustdoc. Two new Aligned fixture
configurations initially selected an invalid 128-byte threshold for a 128-byte
symbol; the fixtures now use a valid 100-byte threshold. The
[final continuation](../../work/aligned-extents-20261117/buffer-hotpath-validation13d/receipt.json)
passes strict workspace Clippy, both corrected preview tests and all 318 runtime
tests. The report provider's thirteen Python tests also pass. Each continuation
records unchanged source during execution. Unchanged simulator and harness
receipts are reused rather than rerun. This is scoped passing coverage, not a
single fresh all-green aggregate process.

The original intermittent raw aggregate failures remain open. An opt-in bounded
terminal trace now distinguishes the original User/Control adapter custody
deadlines and pending receipt identities, without polling I/O or extending any
limit. The final runtime continuation did not reproduce that failure, so the new
trace has no observed failure sample yet. Native throughput qualification of this
batch is still separate.

### Native13 service-cost repair and observed remaining limits

The [stable release13](../../work/aligned-extents-20261117/matrix-source-binding-13.json)
binds checkpoint `4bacdc1` and binary `dc5d38f0b75f3789104f5175d630e87cbd4339a4ce6efb389b29abeac1872718`.
Two affected forward phases run in parallel under the unchanged 100/10 Mbit/s,
70 ms RTT and 15% independent loss per direction.
[The source-bound comparison](../../work/aligned-extents-20261117/native13-raw-udp-analysis1/report.md)
qualifies ten-second receiver goodput of 30.9297344 Mbit/s for Aligned Compact UDP
and 5.803584 Mbit/s for raw TCP. Both setup and requested bilateral disconnect
pass, and all owned namespaces are removed. Native12 UDP failed before a complete
sample; native12 raw measured 5.4178368 Mbit/s. Two runs with different service
code and different finite loss realizations do not isolate a causal speedup.

The same persistent UDP receiver socket records 105 additional kernel drops,
also reflected in namespace RcvbufErrors/InErrors, versus native12's 2005. Client
socket drops remain zero. Capture and kernel-counter windows differ, so the
small packet-count mismatch is retained rather than forced into an exact join.
Original UDP receive/send socket limits both read 212992 kernel accounting bytes.
No socket limit or protocol timeout was enlarged.

The [four current buffer exports](../../work/aligned-extents-20261117/buffer-native13-report1/analysis.md)
validate their known fields. Raw sender receipt wait occupies 75.727% of its
observed lifetime; receiver wait occupies 37.199%. These are combined adapter/
carrier intervals, not demonstrated kernel blocking. Neither UDP owner records
an interval at the currently timed singleton hooks. Sampled UDP sender retention
reaches 5009/8192 sources; raw reaches 7620/8192. None records an exact staged-source
capacity/window refusal. Missing timed hooks remain unknown.

All four exports expose a terminal coverage gap: last protocol samples precede
generic observer stop by 25352--627037 microseconds, and staged terminal markers
are absent. The client disconnect cancels the owning future before its normal
metrics epilogue. These samples do not qualify fresh final protocol censoring;
the diagnostic-only cancellation fix is tracked in the following source batch.

[Native13 measured layers](../../work/aligned-extents-20261117/native13-overhead-analysis1/report.md)
retain separate emission populations in both directions. Same-emission IP bytes
outside the codec body are 60.626/61 B mean/p99 forward and 60.044/61 B reverse
for UDP; raw is 71.903/73 B and 70.799/71 B. Full original-native overhead remains
unavailable. The [updated mixed-source matrix](../../work/aligned-extents-20261117/matrix-report-repairs13-complete1/report.md)
contains 16 passed, 185 failed, 32 bound-exhausted and 7 not-run selected phases;
most selected sessions retain older binaries. It is not a same-build matrix.

### Management-stream buffer instrumentation

The following source batch samples actual three/four-stream MessageOwners and
wrapper retention at most once per 100 ms plus terminal observation. Stream
identity includes the fixed control binding and actual control epoch. ARQ
confirmation, semantic ACCEPTED, queued confirmation custody, held reassembly,
wrapper dispatch and policy allowance remain separate. Sampled high-water values
are not continuous maxima. No payload, message digest or key is exported.

Only the exact immutable frozen Transaction reservation receives a timed
refusal-to-admission episode. Repeated wrapper/message capacity refusals retain
the original start and deadline. Admission completes it; genuine cancellation,
observed owner failure or metric stop censors it with a distinct label. Ordinary
submissions can reuse an unadmitted ID for different bytes, so their refusals are
count-only. Other internal management waits remain required under BP-16.

The opt-in observer uses fallible bounded backing; fixed Timing storage is charged
through the existing Streamed layout. The
[focused continuation](../../work/aligned-extents-20261117/management-focused14b/receipt.json)
passes strict management/runtime Clippy, fifteen actual control fixtures and
nineteen report-tool tests. The first attempt retained two lint errors, corrected
without suppressions. Report validation preserves unavailable fields and never
adds management intervals to the overlapping generic union. Final cancellation
sampling now passes actual-owner fixtures as described below; current native
export and the complete BP-16 gate remain open.

### Same-turn raw progress and cancellation sampling

This coordinated source batch corrects a raw adapter scheduling dependency.
An initial completion poll could consume the adapter's single-poll marker before
new User/Control output was committed. The newly committed packet then waited
for another Driver turn even when PacketIo had not blocked. The adapter now
allows fresh output to use the existing remaining physical work quota; the
carrier continuation does not replenish the original 32-unit allowance. Exact
custody tokens, original deadlines, lane fairness and pacing remain unchanged.
Real Full/Half owner regressions cover same-time physical completion and quota
exhaustion. Both regressions pass the required local check below; native
qualification remains separate.

An unfinished Common Driver now samples actual protocol and management owners
from Drop before releasing those fields. It verifies the fresh runtime timestamp
uses the original Driver/observer time domain and reuses the existing terminal
freeze ordering. No I/O, receipt settlement, protocol tick or deadline renewal is
performed. The export distinguishes normal loop stop, Driver destruction and
observer-only fallback. Missing source access or a failed forced observation
remains explicitly unavailable; old snapshots are never extrapolated. Actual
dropped-future and fallback regressions pass the required local check. Raw and maintained
carrier owners outside Driver retain separate terminal coverage.

The batch also short-circuits Compact gap evidence after three qualifying keys,
the only threshold consumed by the existing decision. Immutable iteration and
a pure predicate make the boolean decision identical; existing actual Python
differential and bounded-fast-retry cases remain its validation boundary. No
performance effect is claimed before renewed measurement.

The [complete required local check14](../../work/aligned-extents-20261117/required-buffer-checks14-attempt1/validation.json)
passes on unchanged source: 2267 Rust cases including doctests, 448 Python tooling
cases, and 1658 simulator cases. The same process passes formatting, strict
workspace Clippy and rustdoc, codec no-default-features checks, and the external
Common CLI. Earlier failed receipts remain retained. This fresh local pass does
not establish native throughput, full buffer coverage or remote platform support.
The next native run checks all three Aligned Compact raw/UDP directions plus
Swift ARQ TLS reverse and QUIC forward under the original impairment and bounds.

### Native14 scheduling and terminal observations

The [stable release14](../../work/aligned-extents-20261117/matrix-source-binding-14.json)
binds checkpoint `68f395e` and executable
`343bce983a51ecd5708d6355c1223f4816ee6d76fcfbad79c4d002a3602b1d72`.
Four carrier lanes ran concurrently with unchanged source, original bounds,
100/10 Mbit/s, 70 ms RTT and 15% independent loss in each direction. Each data
phase uses sixteen TCP flows and a ten-second unique receiver sample.

| Mode/carrier | Forward Mbit/s | Reverse Mbit/s | Simultaneous forward / reverse Mbit/s | Separate terminal outcome |
|---|---:|---:|---|---|
| Aligned Compact raw | 15.7461312 | 7.332672 | 8.873344 / 6.8195008 | Both original 120 s leases expired before requested disconnect |
| Aligned Compact UDP | 31.9289792 | 7.5516096 | Unqualified: capture-ring drops | Both requested disconnects passed |
| Swift ARQ TLS | Not requested | Unqualified: original record cap expired | Not requested | Server timeout followed by client reset |
| Swift ARQ QUIC | 0.324352 | Not requested | Not requested | Server peer-close Transport after data phase; bilateral close unqualified |

The [raw/UDP analysis](../../work/aligned-extents-20261117/native14-raw-udp-analysis1/report.md)
verifies persistent UDP socket identities: both drop counters and namespace
receive-buffer errors remain zero through all three phases. The failed UDP
simultaneous capture loses 6408 packets at client WAN and 1589 at client native;
these diagnostic ring drops are not tunnel receive-socket drops. Original
artifacts and invalid phase qualification remain retained. Capture output now
uses buffered file writes rather than a forced per-packet flush, preserving the
8192 KiB ring, immediate capture, packet timestamps and all completeness checks.
Its renewed native qualification is pending.

Raw sender cumulative receipt-wait fraction is 38.75%, with mean completed wait
214.22 microseconds, versus native13 75.73% and 601.43 microseconds. These cover
118.7 seconds/three phases versus 40.2 seconds/forward only. They support reduced
observed receipt latency alongside the same-turn source correction, not an
isolated phase-matched causal measurement. Actual raw PacketIo WouldBlock,
quota, pacing and peer-horizon refusals remain zero; wrapper custody refusals
remain separate from kernel blocking. The passing data phases do not turn the
later lease expiry and failed disconnect into a passing shutdown test.

The [twelve buffer exports](../../work/aligned-extents-20261117/buffer-native14-report1/findings.md)
have no known-field invalidity. All eight Common owners have protocol and
management final timestamps equal to their actual terminal-source attempt,
including Driver-drop cancellation, with no source-unavailable event. Raw and
UDP staged-source waits retain exact terminal markers. Raw sender/receiver
sequence-window completed waits total 13.091722/6.444917 seconds; UDP receiver
records 6.920781 seconds and sender zero at these hooks. These intervals overlap
other sites and must not be summed into end-to-end blocked time. Exact frozen
management submission waits are zero; internal management dependencies remain
untimed. Swift provider timestamps are fresh but contain no Swift gauge rows
in release14, so they do not qualify BP-08. TLS server FlushPending occupies
63.09% of that owner span. QUIC client carrier submission occupies 88.85% and
Common receipt waiting 89.62% in separate owners; they are not additive.

[Measured layer extents](../../work/aligned-extents-20261117/native14-overhead-analysis1/report.md)
retain all four carriers and both directions with their own counts. Records
protection remains 21/21 B mean/p99. Same-emission IP outside codec body is
60.783/61 B forward and 60.737/61 B reverse for UDP, and 72.736/73 B and
72.706/73 B for raw. These lifetime populations include retries and feedback,
not only throughput-window data. Full original-native mean/p99 and maintained
TLS/QUIC outer-packet attribution remain unavailable. The
[mixed-source matrix](../../work/aligned-extents-20261117/matrix-report-repairs14-complete1/report.md)
now selects 18 passed, 182 failed, 32 bound-exhausted, one tool-failed and seven
not-run phases. Most combinations still select historical binaries; no current
all-modes qualification is claimed.

### TLS dependencies and exact Rolling expiry attribution

The next source batch measures actual retained TLS class output waiting for the
other class's active frame to release its writer. Selection of that same class
ends the ownership interval before its independent socket/TLS write wait. It
also measures actual partial input waiting for missing bytes after read Pending;
idle reads remain unobserved. Original tokens, I/O order, deadlines and quotas
are unchanged. One bounded failure-only metadata export observes the original
pending offsets, caps and active lanes before release, with no payload or key.
Wait totals freeze before diagnostic I/O. Its snapshot timestamp follows the
failing call; expired candidates are not invented as
unique root causes. All fourteen focused TLS cases, including the two new
actual framing regressions, pass in
[focused15 attempt2](../../work/aligned-extents-20261117/focused-buffer15-attempt2/receipt.json).
Native interpretation remains pending.

Rolling/Research pure owners now retain a bounded first actual failed-check fact
and expose read-only lifetime candidates under injected ticks. Runtime failure
tracing visits at most two actual retained epochs. This distinguishes a winning
check from another expired timer and preserves native failure identity after
settlement. Three focused FEC regressions pass. The original new precedence
fixture failed Busy because its original tail was due; the corrected fixture
services that actual tail and verifies the unchanged outer-output check wins
over an earlier nested debt deadline. The failed attempt is preserved.
No timer, cap, recovery action or wire format was changed. The
[Python comparison](../../work/aligned-extents-20261117/rolling-expiry-draft14/notes.md)
shows Rust's retained cohort debt abort is extra policy, not Python parity;
partial confirmation does not clear the original cohort bound. Current native
winning-expiry evidence and actual BP-10 buffer wait intervals remain required.

### Swift channel export and Rolling retained-operation waits

The next coordinated batch forwards the actual Swift shared-packing snapshot and
every independent send/receive channel, preserving asymmetric availability and
full epoch/configuration identity. The maximum is 65 rows, charged before I/O
within the existing bounded provider catalog. Sampling is gated before channel,
source and equation scans. Shared packing and channel gauges overlap; repair
work debt is not retained packet capacity. No wait duration is inferred from
these samples. BP-08 feedback/history/control/RTO/source/rank/stream intervals
remain required.

The maintained Rolling/Research Endpoint now records actual sealed-source
recovery Busy/Capacity until the same source commits, actual decoded-source
record refusal until the same source hands off, and ready immutable feedback
packet/byte refusal until that exact output is debited. Each site preserves its
original identity, geometry and available deadline. Repeated refusals do not
restart the wait. Independent reasons may overlap; only the site-local union
is reported, with no invented endpoint-wide total. Failure or a fresh terminal
observation censors unresolved work, distinct from successful progress.

The pure owner uses injected time and an optional fallibly reserved singleton.
Both initial and replacement Engine plans charge that storage before applying
the original retained-byte limit; diagnostics do not enlarge the limit. Runtime
exports at most one snapshot per retained epoch. Disabled owners allocate no
diagnostic heap. Actual-owner and parser regressions are implemented; coordinated
compilation, checks and native qualification remain pending. This initial slice
does not close BP-10 work-slice, feedback-build, authenticated-ingress or
missing-source/dependency coverage.

### Raw token custody latency

The same pending batch follows the real User/Control RecordToken through commit,
original physical acceptance, first wrapper observation and exact upper receipt
take. Four fixed lane/class rows and two live slots preserve original timestamps,
deadlines and receipt identity. Repeated observations cannot double count. Owner
release freezes unresolved stages before lower resources drop, without polling
I/O; terminal age before observation does not prove no packet was transmitted.

The optional raw-specific collector reserves bounded storage before I/O and
exports separately from generic buffer waits. It adds no per-event allocation
or size to unrelated observers. Successful stage latency and unresolved terminal
ages are separate populations, with mean/max and no fabricated p99 or blocked
percentage. Candidate, verifier and stable-demand peer-credit timing remain open.
Focused actual Full/Half integration and parser cases are included in the pending
coordinated check; source review alone does not qualify runtime behavior.

### Coordinated local buffer batch15 validation

The [full required attempt](../../work/aligned-extents-20261117/required-buffer-checks15-attempt1/validation.json)
passes preflight, parser suites, strict workspace Clippy and all Rust cases except
two newly added fixtures. The Rolling feedback fixture had staged input without
servicing decode before its feedback timer. The Swift fixture incorrectly expected
a Reliable/Rolling output token instead of its actual Common sealed ciphertext.
The fixes only change those fixtures: no production deadline, cap or scheduling
policy changes. The failed receipt remains preserved.

The [scoped continuation](../../work/aligned-extents-20261117/required-buffer-checks15-continuation1/validation.json)
passes both affected suites, formatting/Clippy and every remaining required stage,
including strict rustdoc, codec no-default tests, external Common CLI and 1,658
simulator cases. Its source stays unchanged throughout; the only source differences
from the failed attempt are those two test files. Passing unchanged workspace
cases are reused rather than rerun. This is a passing scoped continuation, not a
pristine all-green invocation or native validation. New raw custody, Swift channel,
Rolling retained-wait and TLS dependency exports now have actual-owner fixture
coverage. All full BP gates and native/matrix qualifications remain open.

The [saved native14 QUIC analysis](../../work/aligned-extents-20261117/native14-quic-swift-analysis/analysis.md)
separately attributes the strongest observed stall to actual Quinn admission
waiting. Sampled Cubic windows of 2,944--17,184 bytes are consistent with the low
rate under 15% loss, but there is no captured BytesInFlight or matched window-time
histogram to quantify causality. The source also exposes Swift starting retry
timing before carrier acceptance; correcting that behavior is pending. It does
not justify bypassing congestion control, enlarging caps or treating a Python
fixed-rate link as an equivalent genuine-QUIC experiment.

### Release before offline capture analysis

The [native14 raw lease audit](../../work/aligned-extents-20261117/raw-lease-analysis16/report.md)
shows fresh verified control immediately before the deliberately absolute
120-second session cap. Final live-observation commands completed after the
latest possible lease expiry, so the later disconnect failed. This evidence
does not establish liveness starvation or justify renewing the lease.

The harness now stops captures and retains terminal counters/window identities
between phases, but defers full pcap analysis/hash until after requested disconnect
and owned-process/namespace cleanup. Immediate capture drops still prevent later
phases; deferred malformed-file validation invalidates the corresponding phase
without discarding independently completed later evidence. A separate shutdown
outcome can fail the case while preserving qualified data-phase results. It
measures API4 requested local release, not bilateral protocol drain. Original
lease, workload/EOF/tail, capture bounds and validation remain unchanged.

All 30 affected harness/report tests pass in the
[Python-only continuation](../../work/aligned-extents-20261117/matrix-live-cleanup-check16-attempt1/validation.json).
Rust/protocol sources are byte-identical to the passing batch15 continuation,
so those checks and its release binary are reused. Native confirmation of the
new live-cleanup ordering is pending. Long live workloads may still reach their
original absolute cap; this change does not remove that outcome.
