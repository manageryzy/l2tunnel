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
not new protocol errors. Opt-in allocation/configuration failures remain explicit
constructor errors, before forwarding.

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
| BP-17 | Proxy channels/writer/Bridge/ring/measured ledger/relay buffers | Existing exact admission/acceptance/observation/callback timestamps retained. Full buffer intervals and callback lag export pending. |
| BP-18 | Raw candidate classes/pinned input/bitmap/prepared/tracked/receipts | Typed prepare reasons and per-class gauges/counters implemented; terminal scalar state retained. Common scalar export implemented; exact PacketIo interval timestamps remain pending. Quota, pacing and actual PacketIo refusals are separate counts. Bitmap is coverage state, not buffered packet bytes. |
| BP-19 | OpenVPN submissions/held datagrams/receive/setup buffers | Class/channel fullness, socket waits and receive drops pending. |
| BP-20 | Retained TLS class/writer/prefix/body/input/completion slots | Actual class refusal, write/flush Pending and work-budget waits implemented; bounded occupancy sampled. TLS Pending does not prove kernel queue saturation. |
| BP-21 | QUIC permits/tickets/DATAGRAM wait/cache/provider queues | Actual class-slot refusal and pending-send intervals, permit/cached-input gauges and provider available-payload samples implemented. Exact provider send/receive occupancy remains unavailable; capacity minus available is not a valid occupancy calculation. Actual QUIC FIFO permit/capacity fixture passes; native diagnostic validation remains pending. |
| BP-22 | Maintained carrier wrapper User/Control/cache slots | Common User completion wait implemented as combined wrapper/carrier wait. QUIC wrapper class admission, pending send and receipt-slot gauges implemented; remaining backend-specific attribution pending. |
| BP-23 | Local request, bootstrap and joining retry buffers | Existing bounded owners retained. Opt-in constructor/readiness stages and accepted local API read/handler/reply durations implemented; listener backlog delay and full bootstrap/retry-buffer blockage attribution remain unmeasured. |
| BP-24 | Static scratch, codec contexts, replay maps and receive bitmap | Capacity accounting only; no independent queue-wait metric. Eviction/refusal still requires an explicit counter where applicable. |

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
scheduling/liveness issue. Native runtime diagnostic export remains pending, and no
full BP row or all-buffer acceptance is claimed from component APIs or compilation.

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
