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
| BP-01 | Pipeline/MUX packet/byte/flow/DRR bounds | Actual Engine admission refusal callback and aggregate counts are wired. Exact selected FIFO-head refusal-to-admission intervals, keyed by epoch/configuration/FlowId/channel, pass coordinated local validation with bounded omission and first-observed cause segments. Native16 exports pass parser validation for actual Swift and Rolling refusals. Per-flow occupancy, ingress capacity, flow-table and DRR/policy attribution remain pending. |
| BP-02 | ACK ingress candidates/slab | Common held-input capacity wait implemented; internal deliberate coalescing hold and per-flow replacement age export pending. |
| BP-03 | Bank epoch slots/native window/output tokens | Existing resource usage retained; typed native-window refusal implemented. Per-generation wait and drain/export pending. |
| BP-04 | Aligned/Packed sender stage, fragment cursor, assembling/sealed container | Actual codec gauges and typed refusals implemented. Bounded per-epoch/owner sampled export and exact retained-source capacity/window refusal-to-admission timing are implemented; validation is recorded below. Packing hold, fragment cursor and other stage waits remain pending. |
| BP-05 | Aligned receiver proofs/ordered records/fragments/native output | Head/lookahead/proof/native-output gauges have bounded sampled runtime export. Missing context/source versus consumer intervals remain pending; occupancy does not establish blocking. |
| BP-06 | Reliable partial block/outgoing/restored/generations/physical tokens | Typed builder/output/restored/decoder gauges and exact sealed-head refusal intervals implemented with coordinated local batch17 validation below and finite native17 Aligned Cauchy export. Restored-source and whole-write durations remain open. |
| BP-07 | Normal/Compact ARQ retention/reorder/transmission history | Reliable ARQ retention has sampled runtime export, and exact staged-source capacity/sequence-window refusal-to-admission timing is implemented. History use and remaining ACK/RTO/physical/output-budget attribution remain pending. Exhaustion remains an error, not an invented wait. |
| BP-08 | Swift packing/sources/retries/repairs/history/rows/stream | Per-channel read-only gauges, actual packing refusal and bounded runtime export are implemented, including asymmetric channel identities and shared packing scope. Coordinated local validation passes below; native export qualification and independent channel timing remain open. |
| BP-09 | Block FEC generations/equations/restored output | Live generation/rank/history/reservation gauges and actual capacity-refusal counters implemented with coordinated local batch17 validation below and finite native17 generation-capacity observations. Missing-equation and restored-source wait duration remain open. |
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
so those checks and its release binary are reused. Native15 below exercises the
new live-cleanup ordering. Long live workloads may still reach their original
absolute cap; this change does not remove that outcome.

### Native15 dependencies and failure attribution

The [source-bound six-case analysis](../../work/aligned-extents-20261117/native15-analysis1/report.md)
uses runtime commit `79d7bc8`, harness commit `bbb0db7` and release SHA256
`84ce4638e4e8e0d92bd0d2baa7776f672d096f239ba433acca09098aa2689476`.
The original 100/10 Mbit/s, 70 ms RTT, independent 15% loss per direction,
16-flow and ten-second receiver sample definitions remain unchanged. All owned
namespaces are removed. Results are finite Linux integration evidence:

| Selected case | Qualified data result | Remaining failure |
|---|---|---|
| Aligned Compact UDP simultaneous | 9.0517376 / 7.0928832 Mbit/s | None in this selected case; capture qualification and requested disconnect pass |
| Aligned Compact raw all directions | Forward 16.6485248 Mbit/s | Reverse ARQ source 77598 retry exhaustion; simultaneous not run; shutdown fails |
| Rolling UDP forward | Unqualified | Receiver DecoderJob expiry, then client EncoderDebt expiry |
| Rolling raw forward | Not run | Bootstrap handoff Proof failure |
| Swift ARQ real TLS reverse | Unqualified | Original stage/case bound exhausted; requested shutdown passes |
| Swift ARQ real QUIC forward | 0.2826496 Mbit/s | Server peer-close failure makes the overall case fail |

All sixteen buffer exports parse without validation issues. QUIC bulk Common
receipt waiting occupies 49.152431 of 56.211528 observed seconds (87.442%). TLS
bulk Common receipt waiting occupies 53.640638 of 63.047531 seconds (85.080%);
the retained-TLS owner union is 53.551252 of 63.831593 seconds (83.895%). Its
User FlushPending contributes 53.549397 seconds, and management writer ownership
waiting contributes 46.142097 seconds. These intervals overlap and must not be
summed; they do not independently prove kernel queue saturation. Swift now
exports distinct sampled gauges for all sixteen channels per Common endpoint;
independent per-channel wait duration is still unavailable.

Rolling's receiver first fails DecoderJob at Tick 11426261 against its original
11426143 deadline, RepairId 425, support 0..784. The client independently fails
EncoderDebt at Tick 14702337 against deadline 14701894, sources 391..1015.
Those are different peer clocks, not a shared causal timeline. Source admission
on the client has 207 completed waits totaling 5.958300 seconds and one terminal
censored wait of 3.605311 seconds; passive stored symbols are not counted as
waiting. Decoder service and retained debt need correction without extending
their original caps. Raw token custody, Swift channel gauges and TLS writer
dependencies now have actual native exports, but their broader BP rows remain open.

The companion layer table records 21-byte Records protection and exact 28-byte
UDP or 40-byte raw outer extents. It preserves separate recovery populations
and same-emission joins instead of adding quantiles. Full original-native
overhead and real TLS/QUIC physical-layer distributions remain unavailable.
The mixed-version continuation selects 17 passed, 181 failed, 33 bound-exhausted
and 9 not-run phases; it is not a complete current-build matrix.

### Selected Pipeline FIFO-head intervals

The optional provider reserves at most 256 diagnostic flow rows before I/O,
separately charged from protocol capacity. Full epoch/configuration/FlowId/channel
identity and actual retained-head metadata join a real downstream refusal to the
same Pipeline FIFO head's successful pop. Repeated refusal retains the original
start; DRR ineligibility, occupancy and deliberate packing delay do not create
waits. Consecutive identical packet metadata remains separate through the actual
pop boundary. Per-flow first-observed cause segments partition that head's total,
while different flows and generic owner waits must not be summed.

Live rows are never evicted. Diagnostic saturation counts omitted refusals;
fresh terminal sampling censors unresolved heads, while observer-only fallback
stops at the last actual event and marks terminal coverage unavailable. This is
implemented and locally validated below, not complete BP-01 coverage or a native
throughput result.

### Pending acceptance and bounded decoder dispatch correction

Swift now prepares one immutable output witness and consumes the existing
Common carrier completion before setting source/retry send times. An ACK for an
older copy can retire debt while the pending witness remains valid; completing
it must not recreate that debt. Frozen feedback commits only its prepared
receive state and preserves later input. Existing synchronous pure helpers
perform an explicit same-tick prepare/confirm; Common uses deferred confirmation.
The existing bounded body and pending slot are reused. This implements the
[SWR-19 correction](swift-record-engine.md#deferred-carrier-acceptance-checkpoint), with local validation below and
native qualification pending; it neither changes real QUIC congestion control nor
establishes complete Python parity.

Rolling decoder CopyRow, Clear and Load now process bounded contiguous chunks
instead of re-entering the state-machine match once per byte. Each chunk retains
exactly one copy and one metadata charge per byte, including the original
separate phase transition and pause costs. Checked disjoint bank slices preserve
transaction storage. GF operations, scheduling, caps, deadlines and all wire
bytes remain unchanged. Bytewise-reference, rollback, recovery and original-cap
fixtures pass locally below; native performance evidence is pending.

### Coordinated local buffer batch16 validation

The [required source-stable attempt](../../work/aligned-extents-20261117/required-buffer-checks16-attempt1/validation.json)
passes formatting, strict workspace Clippy, early Python tooling and 2,173 Rust
cases including the passing cases in the failed target. All new Swift pure/Bank/
protected-UDP, Pipeline-owner and Rolling bytewise-equivalence/rollback/expiry
fixtures pass. One prior Common blocked-output fixture still asserts Swift has
no carrier witness; that obsolete assertion is the sole failure.

The [source-stable continuation](../../work/aligned-extents-20261117/required-buffer-checks16-continuation1/validation.json)
changes only that fixture to compare the actual Bank witness while retaining
byte/nonce/single-debit and independent Control assertions. The affected case,
formatting/strict Clippy, codec no-default branch, strict rustdoc, CLI checks,
external Common CLI, remaining tooling and all 1,658 simulator cases pass.
Unchanged passing workspace tests are reused. This is scoped required coverage,
not a pristine full-suite invocation, native speedup or closure of full BP gates.

The [native15 raw/QUIC follow-up](../../work/aligned-extents-20261117/native15-raw-quic-analysis1/report.md)
also confirms every recorded raw custody token completed without mismatch or
terminal censoring. Raw reverse separately loses 1,258 packets in the server
WAN capture and remains unqualified. Neither raw endpoint reaches the original
120-second lease. Peer service pauses and QUIC requested-local-abort ordering
need further attribution; transport close alone is not bilateral drain.

### Concurrent requested local shutdown

The native15 QUIC receipt shows the harness finishing endpoint A's local abort
before it submits B's request. B can already have observed the resulting peer
close and entered Failed; the later local request then correctly rejects that
state. The harness now submits both existing local disconnect commands before
waiting for either result. Each original per-command and absolute cleanup bound
is unchanged. Startup errors and peer-close races still fail the corresponding
endpoint and case; there is no retry, ignored error or normal-close-to-drain
conversion. Full Common peer shutdown/drain semantics remain separate.

All 32 affected matrix/report tests pass in the
[Python-only receipt](../../work/aligned-extents-20261117/matrix-parallel-disconnect-check16-attempt2/validation.json),
including an actual two-worker barrier and preservation of a concurrent peer
failure. The first preflight compared different hash inventories and ran no
tests; its tool-failure receipt is retained. Runtime source and release16 binary
are unchanged, so required batch16 Rust checks are reused. Native qualification
of concurrent local release remains pending.


### Native16 observed admission waits and unresolved failures

The [four-case source-bound report](../../work/aligned-extents-20261117/native16-analysis1/report.md)
uses runtime commit `1cd5e4a`, harness `f6ae9ba`, and one release16 binary.
All four original-policy lanes run concurrently; none yields qualified throughput.
Swift raw fails at PacketConfirmation Proof before its first confirmation copy.
Rolling UDP expires at the original Ingress custody boundary; the earlier decoder
job deadline is a candidate, not the winning checked failure. Swift TLS reverse
and QUIC forward exhaust the original stage/case bound. Concurrent requested local
disconnect succeeds for TLS and QUIC; this is not bilateral protocol-drain proof.

All ten buffer exports parse without validation issues. QUIC bulk Common waits
56.150440 seconds for carrier receipts over a 62.337622-second observation;
maintained QUIC User admission waits 55.933472 seconds. TLS bulk Common waits
49.334208 seconds over 62.149241 seconds; its retained User flush waits 49.265735
seconds, while management writer dependency totals 43.131199 seconds. Censored
final intervals remain separate in the underlying exports. These same-owner and
cross-owner durations overlap and must not be added or interpreted as proof of
kernel queue saturation.

The Pipeline provider exports sixteen exact flow-head identities on each bulk
Swift endpoint and the Rolling sender. Actual packing/codec-stage refusals and
same-head admission are observed, with no omitted rows, identity/clock errors or
unavailable terminal sample. This qualifies these finite export paths only;
remaining BP-01 and all-buffer coverage are unchanged. Full original-native
mean/p99, real TLS/QUIC physical overhead and the complete current-build matrix
remain open. The mixed-version continuation retains latest requested failures
and selects 15 passed, 181 failed, 34 bound-exhausted and 10 not-run phases.


### Execution-stage and output-write wall timing

Coordinated local validation passes below; native qualification is pending.
The bounded runtime timing accumulator now
observes actual Common admission, protocol work, control service, send/receive,
native I/O, expiry checks, sampling and publication. Consecutive turn-start spacing
also includes intentional idle waiting and scheduler delays. Stage totals and
maxima are wall durations, not CPU time or backpressure. Each maximum retains its
own start/end within one owner clock; maxima from different owners are not one
joined event. Original protocol tick samples and error precedence are unchanged.

Execution timing opts in with `L2TUNNEL_EXECUTION_TIMING=1` or the existing
buffer/wire metric prefix. Disabled work paths do not read another clock or
allocate an aggregate. Enabled state is fallibly allocated off the async future
and remains subject to the existing bounded owner catalog. No per-packet log or
unbounded event history is added. Missing diagnostics remain unavailable.

CLI projection, JSON serialization, bounded flush and actual file writes are
separate populations; successful writes are measured too. Their nested times
must not be added. CLI snapshots use existing bounded output custody and can be
omitted on saturation, failure or cancellation. The no-I/O construction/rendering
seams let foreground output retain allocation failure through its health fields
without synchronous error logging. Common execution has no automatic stderr
report: its prepaid state moves at the exact original loop-stop instant into the
existing buffer observer. Frozen output excludes later settlement, rendering and
persistence. Cancellation before that handoff is explicitly unavailable. Common
execution export requires the buffer/wire prefix; the execution flag alone does
not create a sink. Existing observer file persistence and unrelated direct stderr
diagnostics remain synchronous and outside these stage samples.


### Bounded regular-file output isolation

Coordinated local validation passes below; native qualification is pending. Regular stdout
and stderr each retain one dedicated writer thread across explicit reconnects.
The existing four-line/512-KiB custody includes the worker's partial line; the
channel is not extra payload capacity. Actual accepted prefixes release byte
custody, and each coalesced grant permits at most four writes and 64 KiB. The
foreground never performs the regular-file write or joins a worker. Duplicating
the inherited file description preserves its flags and shared offset.

One forty-millisecond absolute diagnostic cleanup bound is an implementation
choice, separate from protocol deadlines. Expiry/cancellation preserves unresolved
custody and never invents completion. Failure and abnormal unwind remain visible
through bounded health snapshots; final publication can be unavailable. The
writer records actual write wall time on its own thread. Shared offsets do not
make independent emitters' partial lines atomic, and unrelated direct diagnostic
emitters retain their existing behavior. This removes a source-proven blocking
coupling; it does not establish that logging caused a previous native hiatus.


### Reliable and Block FEC actual buffer observations

Batch17 passes coordinated local validation below. Optional diagnostic state is
prepaid through Reliable, Aligned/Packed and Engine plans, with one bounded
provider snapshot per existing epoch slot. Disabled state does not allocate or
scan decoder generations. Existing Compact R0 storage observations remain.
Builder count/deadline, sealed output, restored admission, live generation/rank/
history and physical-slot gauges separate occupancy from actual refusal. Live
logical reservation is used storage against its configured admission limit;
preallocated backing is a different capacity, with unknown actual used bytes.

An actual sealed output-head packet/byte-budget refusal starts an interval keyed
by its immutable generation, symbol and extent. Repeated refusal does not renew
it; only emission of that same head completes it. Packet and byte reasons overlap,
and the separate head union must not be added to either reason or other owners.
Emission is not physical carrier acceptance. Fresh terminal sampling censors
unresolved heads; cached retired state retains its earlier boundary. Direct ARQ
explicitly has no sealed FEC output queue. Actual decoder and restored capacity
failures are count-only, not inferred durations. Partial-block hold, missing
equations, restored-source waits and repair-work timing remain unmeasured here.
BP-06 and BP-09 remain open. Protocol bytes, limits, deadline sampling and error
precedence are unchanged.

### Raw confirmation proof diagnostic boundary

Batch17 adds bounded first-failure scalars and booleans at the original raw
confirmation predicates, with coordinated local validation below. Early protected-Hello
release and authenticated complementary-window proof failures are distinguished.
Local raw/scaled advertised windows and observed peer windows are available;
keys, session values, transcripts and full sequence numbers are not exported.
The original authentication, predicate order, errors and all retry/window/deadline
bounds remain unchanged. Contention on the diagnostic lock cannot replace Proof.

Native16's saved capture shows the final TLS segment initially advertising 32763
and its retries 32768, with window scale five. This supports a frozen-window
mismatch candidate, but the exact failed predicate is not yet proven by that
receipt. The new injected-stale-window fixtures exercise actual authenticated
Hello/retry processing, not a natural smoltcp race reproduction. A conservative
window reconciliation would also have to account for already allocated extents
and both authenticated handoff states; no such protocol change is included.


### Coordinated local buffer batch17 validation

The [required attempt](../../work/aligned-extents-20261117/required-buffer-checks17-attempt1/validation.json)
passes 114 Python cases and preflight, then stops at compile errors. The first
continuation preserves later Clippy fixture failures. After these corrections,
the [workspace continuation](../../work/aligned-extents-20261117/required-buffer-checks17-continuation2/validation.json)
passes strict Clippy and 2,193 Rust cases, including passing cases in failed
targets. Three fixtures fail: two expose incorrectly reported operational bounds
for lazy encoders, and one expects the inner Proof instead of its existing
PacketIo error wrapper. All output writer, cancellation/failure, execution freeze,
Block FEC refusal and actual-provider fixtures pass in that run.

The [scoped continuation](../../work/aligned-extents-20261117/required-buffer-checks17-continuation3/validation.json)
corrects the bound observation using the validated send policy and retains the
original semantic-equivalence assertions. One added actual-owner fixture covers
no-FEC, send-only, receive-only and asymmetric coding. Raw expects the exact
existing I/O wrapper while retaining all authenticated proof, retry, original-cap
and terminal-release assertions. All 48 Reliable cases, affected raw/provider
cases, formatting, strict Clippy, no-default codec, strict rustdoc, external CLI,
remaining tools and 1,658 simulator cases pass. Unchanged earlier passing checks
are reused; this is scoped required coverage, not a pristine single invocation.
All recorded checks are source-stable. A wrapper import failure before execution
is retained separately and is not a protocol or test result.

This qualifies local Linux behavior and bounded diagnostic paths only. Native
throughput improvement, complete current-build carrier coverage, all BP rows and
full original-native encapsulation overhead remain open.

### Native17 observed dependencies and residual FEC fill

Source `6bab236126f1eea5c344bf96b91e4cdce8e38e25` and binary SHA256
`4ddec3316c76649f76857f36199a9594239dd03c21bf044b7d121a820c337861`
remain unchanged throughout the five-case, four-lane owned-namespace batch. The
[source-bound report](../../work/aligned-extents-20261117/native17-analysis1/report.md)
retains original 100/10 Mbit/s, 70 ms RTT, independent 15% loss each way and
16 flows, with no deadline/window/retry expansion. Qualified data phases are raw
Swift reverse 7.7867648, genuine QUIC Swift forward 0.324352 and Aligned Cauchy UDP
forward 0.2224128 Mbit/s. TLS reverse exhausts its original workload bound and
fails requested local disconnect; Rolling UDP fails original runtime expiry.
Raw's passing occurrence produces no failing proof facts and does not resolve
the previous intermittent frozen-window candidate.

All sixteen buffer exports validate. QUIC bulk Common receipt waits total
50.023106 seconds over 68.932471 seconds; independently, maintained QUIC observes
49.783870 seconds. Both sampled Quinn minimum congestion windows are 2944 bytes.
TLS bulk Common records 43.090995 seconds completed and 7.220097 seconds censored;
its independently observed retained-TLS wait overlaps. Do not add these owners
or infer exact kernel/provider queue occupancy. TLS turn-start gaps reach about
6.9 seconds while its longest measured work stage is below 9 milliseconds. No
CPU, disk or scheduling cause follows from those wall-time populations alone.

Rolling protocol progress consumes 5.572930/7.050376 seconds of local wall time;
partial owned-process CPU samples are 65.01%/82.69% of one CPU. The actual winning
expiry checks are client EncoderDebt and server DecoderJob, not diagnostic
control/ingress candidates. These observations motivate targeted computation
attribution, without establishing a specific hot function.

Aligned Cauchy receiver live generations reach 16/16 with 1078 actual generation
capacity refusals. Systematic sources can still pass to ARQ on that branch, so
this is not a count of lost user packets. Client sealed-head wire-budget waits
complete 61 episodes totaling 11.885 milliseconds. Actual accepted-wire counters
and source inspection prove residual Block FEC systematic fill: 1,864,271 bytes
across 1848 nonzero-fill emissions. The source-emission joined IP-outside-codec
body mean/p99 is 526.096/1265 bytes forward and 69.547/83 bytes reverse; these are
not original-native packet populations. Removing this serialized padding remains
required and is not satisfied by the earlier Aligned codec extent correction.

Common execution timing is available at normal TLS/Rolling loop stops but marks
`loop_stop_not_observed` for successful raw/QUIC/Cauchy future cancellation. Fresh
protocol terminal sampling is separate. The native regular-file writer emits
valid observed JSON and zero sampled write/drop/timeout errors, but SIGTERM
cleanup supplies no final actual-write duration or terminal writer custody proof.
Cancellation-safe timing and full writer-duration observation remain open.

The mixed historical report now selects 18 passed, 181 failed, 32 bound-exhausted
and 9 not-run phases from 62 attempt directories over 80 combinations. This is
not a complete current-build matrix. Full BP-01..BP-24, original-native overhead
mean/p99, complete carrier/algorithm qualification and functional failures remain
open. No parent acceptance definition is reduced by these partial results.

### Cancellation timing and bounded execution validation

Implemented with coordinated local batch18 validation below. A stack-only guard retains
existing prepaid Common execution timing and transfers it to the existing
Observer on future destruction before Driver source sampling. Normal loop stop
retains its original cutoff and disarms the cancellation transfer. The exported
boundary distinguishes `driver_future_drop` from `loop_stop_before_settlement`;
interrupted entered stages remain censored. No extra diagnostic heap, output I/O,
queue or protocol action is introduced by this transfer. The actual authenticated
Driver cancellation fixture now checks timing and fresh source sampling together.

The offline reporter now validates the execution extension's bounded stage list,
owner/schema, boundary/checkpoint, outcome counts and maximum interval. Endpoint
microsecond truncation may differ by one from separately truncated elapsed time.
Unavailable/invalid timing remains visible; execution spans are rendered separately
and never added to blocked unions or interpreted as CPU time. Complete BP coverage
and native qualification of cancellation transfer remain open.

### Finite-field operation implementation

Implemented with coordinated local batch18 validation below. GF(256)
multiplication uses a compile-time 768-byte log/exp table for the same 0x11d field.
This adds process-static read-only storage, no per-session heap or initialization,
and changes no GF/copy/metadata work charge, pause cursor, deadline, protocol byte
or caller. The existing independent Python products/inverses and added exhaustive
polynomial-reduction oracle cover all 65536 input pairs. This is error-correction
arithmetic, not a cryptographic primitive or constant-time API.

The [finite primitive microbenchmark](../../work/aligned-extents-20261117/field-microbench18/receipt.json)
measures about 78 ms versus 14.4--14.9 ms for 8388608 operations with equal checksums,
three alternating-order rounds and no workload I/O. It does not establish native
throughput improvement. Two additional original-binary Rolling diagnostic attempts
exhaust startup API bounds before data; the first captures mainly kernel
`clear_page_rep` during construction, and the after-readiness profiler in the
second never starts. Those failed receipts remain separate from native17 and
cannot establish a data-path GF hotspot.

### Empty receiver-pool initialization

Implemented with coordinated local batch18 validation below. The
[source-bound startup audit](../../work/aligned-extents-20261117/allocation-review18/notes.md)
finds 8.096/8.141-second Bank construction in native17 Rolling, versus about
11.5--12.9 seconds in the two later failed startup attempts. The sampled kernel
page-clearing evidence does not join every sample to an individual allocation.

The actual reserved Aligned receiver initialized each free record/proof payload
with zeros and immediately cleared its live length. It now uses the existing
fallible reserve-only vector constructor for these empty pools. For the observed
Rolling plan this removes 265,970,832 discarded constructor byte writes per
endpoint; all 55,392 reservations, capacities, allocation order, accounting,
transaction versions and limits remain unchanged. This is a source-level write
count, not measured RSS, physical commitment or a native speedup.

Actual acquisition initializes record and fragment-bitmap extents before reading;
proof and journal copies initialize their entire live extent. An actual-owner
regression poisons idle/recycled storage, admits reordered fragments, verifies
missing ranges, rolls back malformed input and delivers meaningful trailing zeros
with unchanged pointers and usage. No spare capacity is read and no unsafe code
is introduced. Full preallocation/resource and platform acceptance remain open.

### Coordinated local buffer batch18 validation

The [required attempt](../../work/aligned-extents-20261117/required-buffer-checks18-attempt1/validation.json)
passes 118 Python checks and preflight, then exposes one new FEC fixture passing
owned vectors to a borrowed-slice constructor. The fixture correction changes no
production behavior. The [scoped continuation](../../work/aligned-extents-20261117/required-buffer-checks18-continuation1/validation.json)
reuses those unchanged checks and passes formatting, strict workspace Clippy,
2,326 Rust cases including doctests/no-default codec, strict rustdoc, external
Common CLI, 356 remaining Python checks and 1,658 simulator cases. Source remains
unchanged during each receipt; the only intervening edit is that test fixture.
This is a passing required continuation, not a pristine first invocation.

Actual-owner tests cover cancellation timing with fresh Driver source sampling,
dirty recycled receiver backing and unchanged accounting, real lost-source
recovery with exact systematic extents, physical byte charging and rejection of
old v4 authenticated transaction digests. Independent exhaustive field oracles
pass. No protocol deadline, retry, queue, window, authentication or configured
work allowance is increased. Native18 verification and full BP/matrix/native
overhead gates remain open; simulator passes do not qualify kernel throughput.

A [read-only native17 supplement](../../work/aligned-extents-20261117/bp-next-triage18/report.md)
extracts an existing actual staged-source provider previously omitted from the
concise report. The Cauchy sender has 103 completed refusal-to-admission waits,
45.455953 seconds total and a 6.649802-second maximum. Sequence-window and
send-capacity reason intervals overlap. The maximum identity is unavailable in
that version; temporal proximity to a Pipeline maximum does not identify the
same packet. Exact cross-layer provenance remains required.

### Native18 exact source fill and remaining admission stalls

The [source-bound analysis](../../work/aligned-extents-20261117/native18-analysis1/findings1.md)
and [population report](../../work/aligned-extents-20261117/native18-analysis1/extracted1/report.md)
retain source `d92d25601713fca822caf6d349b85f1e22e4734d` and executable SHA256
`b8074cebeba4219ef7c919bc87e9f4b24ce7e5f76f8eac3afd3a015d2d298d3d`.
The original 100/10 Mbit/s, 35 ms per direction, independent 15% per-direction
loss, 16-flow TUN workload and all original deadlines remain unchanged. The
fresh plan exporter increases four derived resource fields as current owner
sizes change. Its incompatible comparison is preserved; the separate
[validated continuation](../../work/aligned-extents-20261117/matrix-plans18-baseline-quota-validation1.json)
restores the exact original configured quotas and policy bytes, retains actual
current capacity metadata and uses current v5 configuration/catalog digests.
All three real constructors accept those original quotas. This does not imply
every one of the eighty planned combinations has been run on this build.

| Forward case | Data outcome | Qualified Mbit/s | Requested local shutdown |
|---|---|---|---|
| Aligned Cauchy UDP | Original workload bound exhausted | Unavailable | Passed |
| Swift real QUIC | Original workload bound exhausted | Unavailable | Passed |
| Rolling UDP | Original protocol expiry | Unavailable | Failed |

The unsuccessful QUIC phase records an unqualified 0.37648 Mbit/s sample; it
does not become a passing throughput result. Missing Cauchy throughput is not
zero. Eight buffer owner files and six wire reports validate without invalid
flags. All six Common execution providers now retain valid wall spans: four
`driver_future_drop` boundaries for Cauchy/QUIC and two
`loop_stop_before_settlement` boundaries for Rolling. All final protocol and
management source samples are fresh with no source-unavailable events.

Selected Cauchy systematic emissions contain exactly zero serialized algebraic
fill: 6,000 a-to-b and 2,706 b-to-a emissions. This verifies that observed source
population, not every fragment or repair. Meaningful source zeros remain data.
Same-emission framing around the encoded codec body is measured as follows;
warmup, retries and drain remain included in these lifetime populations.

| Case / direction | Codec-covered emissions | IPv4 bytes outside codec body mean / p99 |
|---|---:|---:|
| Cauchy a-to-b | 7,187 | 69.198831 / 73 |
| Cauchy b-to-a | 2,941 | 67.006460 / 72 |
| Rolling a-to-b | 934 | 60.267666 / 68 |
| Rolling b-to-a | 62 | 69.870968 / 105 |

Record protection is 21 bytes mean/p99 in all six accepted-emission populations.
These figures are not full original-native overhead. Swift stream/native joins
and genuine QUIC physical packet mapping remain unavailable; independent
percentiles are never added.

Rolling Bank construction measures 96.832/101.935 ms versus native17's
8.096277/8.140896 s. This finite result is consistent with removal of redundant
receiver zero writes but does not isolate concurrent host effects or qualify
data performance. Cauchy construction measures 33.106/37.941 ms and Swift QUIC
42.595/45.672 ms. Rolling still expires first on server DecoderJob RepairId404,
support [723,851), and client EncoderDebt [295,934). These independent clocks
must not be compared as a shared timeline. No protocol cap was increased.

Cauchy a-to-b has 152 completed staged-source refusal-to-admission episodes,
57.016339 s total, maximum 2.802700 s, plus one unresolved episode censored at
157.639 ms. Its capacity and sequence-window reason intervals overlap; the
generic runtime table's zero entries do not erase this separate provider.
Rolling source-admission waiting totals 6.395946/0.005407 s. Exact staged-source
identity and ARQ frontier, TLS selection/poll/wake observations, and QUIC ticket
acceptance-to-upper-take attribution remain required to distinguish these
dependencies. Occupancy and temporal proximity alone do not establish causality.
BP-01 through BP-24, all current-build matrix directions and full original-native
overhead remain open.

### Exact staged identity and selected-wake observations

Batch19 implementation passes the coordinated local checks below; the finite
native19 findings are recorded below. The existing staged-source wait remains the only duration aggregate.
Optional prepaid Reliable metadata retains the pending, last, maximum completed
and maximum censored source identities, with actual first/latest count, byte and
sequence-span admission predicates. Oldest retained flight state distinguishes
an acknowledged physical retry from an actually retired source. A bounded last
retirement fact comes from a real retention decrease during input or physical
confirmation; it is context, not proof that it alone enabled admission.

Shared Aligned unit identity is attached to the actual earlier native record.
Flow and arrival/admission/deadline provenance is attached only after successful
Pipeline-to-codec admission, so a later refused FIFO head cannot overwrite it.
Packed multi-unit, independent Compact and per-connection native attribution
remain unavailable in this slice. Actual optional Snapshot sizes remain charged
by existing resource plans; no event queue, payload copy or per-packet allocation
is introduced. This does not close BP-01, BP-04, BP-07 or BP-13.

The Common execution observer now separates wake planning, actual selection
poll calls and Pending-return-to-next-poll-entry wall spans. The existing biased
shutdown/request/I/O order, native/carrier alternation, guards and timer instant
remain unchanged. Maximum resume lateness uses winning poll entry minus the
original planned wake; it excludes work inside that poll. Cancellation retains
the original planned wake and freezes unresolved Pending time without inventing
a winner. Pending includes intentional I/O/timer suspension and scheduling;
it is not itself buffer backpressure or evidence of a kernel defect. The CLI's
single real service snapshot is now inside its existing projection span.
Execution schema2 has twenty stages and bounded selection facts; historical
schema1 keeps seventeen stages and explicitly unavailable selection facts.

### Exact maintained QUIC ticket custody

Batch19 implementation passes the coordinated local checks below; the finite
native19 findings are recorded below. Two fixed live cells and eight fixed lane/class/consumer summaries
observe successful lower submission, first actual lower poll, returned queue
acceptance, lower result storage, Common wrapper observation and actual upper
take. Exact owner/serial/class identity and the original Common User epoch,
configuration, packet number, byte count and deadline survive the move-only
lower token. Direct bootstrap consumers remain a separate population.

Late queue acceptance is retained even when the operation returns an expiry
error. Missing acceptance remains unavailable. The provider censors unresolved
phases at Carrier Drop before field cleanup, independently of the generic
collector's earlier error stop; neither its cutoff nor durations extend the
generic blocked union. Completed phase samples do not imply successful whole
operations or physical IP transmission. Provider queue occupancy is still
unavailable. Optional storage remains prepaid and charged by actual size; a
non-QUIC or absent provider returns before clock conversion or ticket identity
retention. Existing terminal exporter I/O remains synchronous. BP-21 and BP-22
retain their full remaining scope.

### Same-budget Rolling encoder batching

Batch19 replaces repeated encoder dispatch for contiguous zero/GF bytes within
one source with bounded slices. Each slice consumes exactly the original byte
and metadata visits, including the already-paid outer visit. It cannot cross a
source or spend beyond the original copy/field/metadata allowance. Cached
coefficients, per-call cursor, immutable output, memory reservation, expiry and
failure ordering remain unchanged. Passing focused coverage checks exact
partial-work cursors/charges, zero allowances, an independently generated Python
equation and the original expiry. Native19 still reaches the original Rolling
expiry; this source-level reduction does not establish a throughput gain.


### Coordinated local buffer batch19 validation

The required `python3 tools/check.py` sequence completes across preserved
[initial](../../work/aligned-extents-20261117/required-buffer-checks19-attempt1/validation.json),
[workspace](../../work/aligned-extents-20261117/required-buffer-checks19-continuation3/validation.json)
and [final continuation](../../work/aligned-extents-20261117/required-buffer-checks19-continuation6/validation.json)
receipts. Failed new fixture/type and test-layout attempts remain recorded.
Unchanged passing stages are reused: the last continuation reruns the sole
failed facade case, then every previously unrun required stage. That fixture
now uses a valid four-record window and the subsequent actual output poll:
filling a window alone is not a failed admission or a wait episode.

Strict workspace Clippy, all workspace tests, no-default-feature codec tests,
strict rustdoc, real external Common CLI probes, tooling and 1,658 simulator
cases pass their local scopes. Actual maintained QUIC ticket custody/cancellation,
Common selection priority and expiry, staged native provenance/held retries,
and same-budget encoder cursors have passing focused regressions. This is
local protocol and process evidence, not privileged network performance.

A subsequent [76-case affected continuation](../../work/aligned-extents-20261117/required-buffer-checks19-continuation7/validation.json)
removes a duplicate send-slot traversal from the optional admission snapshot:
non-Compact span base reuses the already captured oldest retained flight while
Compact keeps its explicit base. Only that private implementation body changes;
formatting, affected strict Clippy, recovery tests and staged diagnostic callers
pass. No benchmark policy, work allowance, deadline or memory quota changes.
Full buffer coverage and the full current-build native matrix remain open.

### Native19 exact admission barriers and lower QUIC acceptance

The [source-bound findings](../../work/aligned-extents-20261117/native19-analysis1/findings1.json)
and [canonical extraction](../../work/aligned-extents-20261117/native19-analysis1/extracted1/analysis.json)
cover four finite cases from `e00e0856817202e22bf109bc398ec2f4a3ff3cca`.
All retain Full/TUN, sixteen real kernel TCP flows, 100/10 Mbit/s, 35 ms delay
and 15% independent loss each way, two-second warmup, ten-second sample and
the original quotas and deadlines. Source, binaries and helpers remain stable;
owned namespace cleanup and output ownership restoration complete.

| Case | Direction | Qualified goodput | Outcome |
|---|---|---:|---|
| Aligned Cauchy UDP | Forward | Unavailable | Original workload bound exhausted |
| Rolling UDP | Forward | Unavailable | Original recovery expiry |
| Swift genuine QUIC | Forward | 0.2826496 Mbit/s | Data phase and local disconnect pass |
| Swift genuine TLS | Reverse | Unavailable | Original workload bound exhausted |

Cauchy and TLS sample-window values, 0.4089152 and 0.2583232 Mbit/s, are
unqualified because their whole phases fail. Requested local disconnect passes
for Cauchy, QUIC and TLS; it fails for Rolling and does not prove bilateral
protocol drain. One QUIC pass is not repeated stability or throughput-improvement
evidence. Twelve buffer owners, eight wire owners and eight Common schema 2
execution snapshots validate without rejection.

Cauchy client staged-source admission waits total 57.247704 seconds completed
and 0.170968 seconds censored. Its maximum completed wait, source 1844 / Flow 12 /
channel 11 / native record 58, lasts 9.003333 seconds. Oldest source 1780 stays
unacknowledged while retained count falls from 19 to 1 of 64; only the sequence-span
predicate blocks. Attempts rise from 1 to 7, with no held physical transmission
at either endpoint observation. A real input retires one 1252-byte source 38 us
before admission. This establishes the oldest-hole admission barrier, without
distinguishing lost source, lost feedback or feedback semantics. ACK prefix and
bitmap remain unavailable in this executable. Overlapping reason intervals are
not added to this wait total.

QUIC client User tickets record 51.924798 seconds across 2,877 completed intervals
from first lower poll to returned queue acceptance, maximum 3.074046 seconds.
Creation-to-first-poll totals 31,592 us, maximum 807 us; acceptance-to-latch totals
1,827 us, latch-to-upper-observation 11,996 us and upper-observation-to-take 30,320 us.
The boundary is Quinn `send_datagram_wait`: it is DATAGRAM queue acceptance,
not STREAM flow control or physical IP transmission. Provider queue, congestion
and pacing dependencies require separate evidence; independent populations and
percentiles must not be summed. TLS winning-poll-entry lateness maxima are
2,382/2,245 us for a/b; these wall-clock maxima alone do not establish kernel
or network causality.

Record protection remains 21 bytes mean/p99 in all eight emission populations.
Systematic source fill remains zero in Cauchy's 5,024/2,475 and Rolling's 1,150/81
a/b emissions. Same-emission IPv4 bytes outside codec body have mean/p99 of
69.399692/73 and 68.164140/72 B for Cauchy a/b, and 60.207826/68 and 71.740741/105 B
for Rolling. These warmup/retry/drain populations are not full original-native
overhead. Swift stream/native and TLS/QUIC physical-packet joins remain unavailable.
BP-01 through BP-24, the full 20-algorithm by 4-carrier by 3-phase current-build
matrix and full original-native overhead remain open.
