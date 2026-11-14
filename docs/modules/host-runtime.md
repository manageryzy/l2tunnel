# Explicit host-runtime comparison

Status: **implemented and contract-tested** for the scoped host adapter; a finite native
comparison has been recorded, with qualification gaps retained. The draft below was recorded before production edits. This is a scoped
SNL-11/FIX-04 performance investigation, not a new carrier, control backend,
negotiated peer setting, default migration or owner decision. All 47 P-* modes,
full SW-11, other record profiles/carriers, recovery and platform gates retain
their existing scope.

## Evidence and hypothesis

The [pre-experiment owned-process kernel observation](../../work/secure-udp-performance-analysis-20261113/current-kernel-summary-attempt-2/analysis.md)
retains 1542 samples, 72.7155% kernel cycle-period weight and 475848 per-task switch
records over an actual 14.9078s event span. CPU/switch work concentrates in each
main task and one Tokio worker observed in epoll/reactor work. The selected CLI
currently executes its root future with a multithread runtime's `block_on`;
Tokio may hand reactor readiness back to that caller. Co-locating the root future
and I/O/timer driver is a testable hypothesis, not a proven throughput cause.
Kernel contexts overlap and do not measure disk waiting. Existing conditional
wire-efficiency estimates do not waive the 80Mbit/s target.

## Draft v0 host interface and ownership

`connect` and `serve` accept optional
`--runtime-model multi-thread|current-thread` only for the currently implemented
Linux `quic-like`/`media-like` plus `--record-profile swift` composition. Omission
keeps the existing multithread builder and output behavior. Explicit multithread
uses that same builder without worker overrides. Current-thread changes only the
builder flavor. Both enable the same I/O/time drivers and execute the same root
future directly; do not additionally spawn it or change task placement, blocking
pool, quotas, pacing, deadlines, security, control backend or record settings.

The private `host_runtime_cli` adapter owns strict parsing, removal of the host
option before existing protocol-option validation, runtime construction and a
bounded observation. Unsupported commands/profiles/platforms fail before device
or network setup. Local API commands retain their existing current-thread path;
key generation stays synchronous. Unknown/duplicate/missing values remain errors.
There is no runtime hot-switch command. Reconnect remains within its process host.

For explicit selection only, emit one JSON startup event on stderr:
`{event:"host_runtime",schema:1,requested:MODEL,effective:ACTUAL,worker_threads:N}`.
`effective` comes from the constructed runtime's actual `runtime_flavor`; worker
count comes from Tokio metrics. The lab accepts integer worker counts 1..2048,
with current-thread metrics exactly 1. These are host observations, not OS
thread-count claims. No secret, argument vector, real clock, peer identity or packet is logged.
Keep strict local API v1/v2 bytes and authenticated configuration digests unchanged.
The GUI/shared service contract is unchanged; this host adapter does not qualify
a new GUI or SUC-06. No pure protocol crate acquires a Tokio or OS dependency.

Public-facing runtime-independent protocol APIs are unchanged. The existing
client-core CLI is already a runtime/platform adapter. The new private helper's
reviewed contract is `take(&mut BTreeMap<String,String>) -> io::Result<Option<Model>>`
and `build(Option<Model>) -> io::Result<(Runtime,Option<Observation>)>`; successful
`take` consumes only the host field, while malformed/unsupported selection does
not mutate the option map. Observation has exactly the five startup fields above.

## Native harness contract

`plan(lab_id, cover, path, workload, runtime_model=None)` preserves the old plan
and daemon argv when omitted. Explicit selection records `runtime_model`, adds
the host flag to both daemon commands, forwards it to the copied worker and
verifies exactly one matching startup event per original daemon. Startup metadata
stays outside strict tunnel status-v2. Existing PID/starttime/executable/namespace
ownership, original socket, credentials, captures, control, probes, throughput,
time and resource bounds remain authoritative.

Add optional bounded `Threads` observation from the already-read `/proc/status`
only for explicit experiments, retaining before/after PID identity checks and
a 1..2048 thread-observation cap. Observe
it after readiness, during reference/policy samples and after reconnect. Do not
assume the host-specific 255-thread baseline. Actual current-thread process count
is measured separately from Tokio worker count; unexpected extra threads must be
reported, not hidden by redefining worker count. Existing nonexperiment resource
parsing and raw historical receipts remain supported.

Record `TOKIO_WORKER_THREADS` provenance. The controlled experiment refuses an
inherited override rather than silently treating a one-worker multithread pool as
a current-thread runtime. Do not modify host environment or kernel sysctls.

## Tests, measurements and acceptance

Parser/builder tests cover omitted/explicit choices, invalid/missing/duplicate
input, unsupported commands/profiles/platforms, option removal and unchanged
protocol values. Inspect actual constructed runtime flavor/worker count. Run the
same real shared-service lifecycle fixture under current-thread and multithread:
both covers, original UDP owners, exact user bytes, strict API versions, actual
policy commit, unsupported action refusal, disconnect/reconnect and new sessions.
Keep every original timeout and assertion; existing readiness/backpressure and
liveness/deadline tests remain required.

Run 16 fresh uninstrumented native cases with one immutable source/build/binary:
A=explicit multithread, B=explicit current-thread; each of QUIC/media crossed
with clean/impaired paths receives A-B-B-A. Reverse condition order in rounds2/4
to reduce time drift. Impaired remains35ms each way (70ms nominal RTT),15% loss
per direction,16 forward flows,100/10Mbit/s shaping,99/9.9Mbit/s policy,5s warmup
and20s receiver-unique measurement. Every case retains the original80 acceptance
verdict, integrity/control/capture/cleanup and requested/effective observations.
No parallel heavy build/test/perf workload runs during native measurements.

Record timestamp-bracketed process/thread CPU, context switches, actual thread
counts and host PSI/I/O; distinguish main-task counters from all-thread totals.
Bound detailed task snapshots and their observer cost. Compare runtime
queue/pacing/credit/recovery and conservative same-window WAN bytes with useful
receiver bytes. These sampled counter intervals are not substituted for exact20s
goodput. Host counters remain unattributed. Perf, if needed, is a separate
instrumented diagnostic. Finite ABBA results are descriptive, not statistical
significance or proof of a unique bottleneck.

Integrator owns this document/master ledger, shared-service test extension,
measurements, all Cargo/fmt/tests/builds/native execution and Git. Worker ownership
is disjoint: CLI/helper source; native harness source; native harness tests.
Freeze all recorded inputs during focused/aggregate/build/native snapshots.

## Acceptance ledger

- [x] [HRT-01] Record/review the host-only selector, unchanged default/protocol contracts, finite measurement design and failure/provenance boundaries before implementation. Evidence: [recorded draft](../../work/host-runtime-20261114/design-v0.md) and [source-stable focused snapshot](../../work/host-runtime-20261114/focused-attempt-1/validation.json).
- [x] [HRT-02] Implement strict scoped host selection and actual runtime observations without changing default, local API bytes, root-future placement or protocol configuration; pass meaningful parser/builder regressions. Evidence: [seven host-selector/parser/builder tests and strict checks](../../work/host-runtime-20261114/focused-attempt-1/validation.json).
- [x] [HRT-03] Run the actual shared-service lifecycle fixture under both runtime flavors, preserving both-cover bytes/control/policy/version/reconnect/deadline assertions and existing backpressure/liveness checks. Evidence: [both-flavor lifecycle and original runtime tests](../../work/host-runtime-20261114/focused-attempt-1/validation.json).
- [x] [HRT-04] Implement/test source-pinned native selector forwarding, startup-event matching and bounded actual thread observations, retaining old omitted-selector behavior and all prior acceptance checks. Evidence: [95 native harness regression tests](../../work/host-runtime-20261114/focused-attempt-1/validation.json).
- [ ] [HRT-05] Record the 16-case source-stable ABBA matrix with original integrity/control/capture/cleanup/80 verdicts and bounded CPU/switch/thread/wire/pressure evidence; preserve negative and tool-failure outcomes.
- [x] [HRT-06] Evaluate scheduling efficiency versus useful throughput, wire/pacing/recovery constraints and semantic failures; retain honest limitations and all parent performance/mode/lifecycle/platform gates. Evidence: [negative outcomes and finite comparisons](../../work/host-runtime-20261114/native-analysis-attempt-2/validation.json); overall qualification remains failed.
- [x] [HRT-07] Pass focused tests, strict Clippy/rustdoc, required frozen-source checks and evidence-only reconciliation; save an actual coherent local checkpoint before closing this item. Evidence: [required check](../../work/host-runtime-20261114/aggregate-attempt-2/validation.json), [reconciliation](../../work/host-runtime-20261114/aggregate-attempt-2/postcheck/ledger-2/validation.json), and [actual source checkpoint](../../work/host-runtime-20261114/commit-binding-attempt-1/validation.json).

## Focused implementation evidence

The [source-stable focused receipt](../../work/host-runtime-20261114/focused-attempt-1/validation.json)
passed 95 native harness tests, 7 private host-selector/parser/builder tests, 5 shared
secure-UDP service tests including the identical full lifecycle fixture under
both actual runtime flavors, and 95 existing runtime tests covering admission,
backpressure, control, liveness and deadlines. Strict targeted Clippy and rustdoc
also passed. The [fixture body check](../../work/host-runtime-20261114/shared-service-body-preservation.json)
records preservation of the original async assertions; the executed tests,
rather than this static check, provide the runtime evidence. Independent source
reviews found no material issue in CLI scope/default preservation, native
forwarding/event/thread validation or shared fixture preservation. No native
throughput result is implied by these tests.

## Recorded comparison and limits

The [immutable optimized build](../../work/host-runtime-20261114/native-build-attempt-1/build-receipt.json)
passed with 956 stable input hashes. All 16 cases executed the same binary
`1dcc3eaec72fa777b24218279a60f6e5e0bb77b176bfcd949c48a307191b93f9`.
The [byte-exact archive](../../work/host-runtime-20261114/native-observations-attempt-1/archive-validation.json)
preserves 3,285,407,022 original bytes across 730 files, plus separately manifested
measurement helpers. The [sparse observer smoke](../../work/host-runtime-20261114/observer-smoke-attempt-1/validation.json)
passed actual owned-child snapshots/deltas and identity/parser refusal checks.
Independent reviews found no material ownership, scheduling, deadline or cleanup
issue in the frozen observer/helper. The original namespace and daemon cleanup
passed in every case; no host network or kernel setting was changed.

The [second independent analysis](../../work/host-runtime-20261114/native-analysis-attempt-2/validation.json)
retains status **failed**, not a matrix qualification. It verifies all archived
file identities and records all 16 results:15 have independently checked exact
reference bytes/hash/EOF and full owned task deltas;12 retain the complete
original capture evidence. The [first analysis](../../work/host-runtime-20261114/native-analysis-attempt-1/validation.json)
is preserved. It additionally misclassified retained management queue occupancy
as monotonic counters. The [classification regression](../../work/host-runtime-20261114/analysis-counter-classification-attempt-1/validation.json)
checks that occupancy may decrease while a real cumulative wire-packet decrease
still fails; the second analysis changes only that classification and output
location. No native receipt, capture, acceptance threshold or source was changed.

These are finite20s useful-byte observations, not16 successful native tests:

| Condition | Multithread Mbit/s | Current-thread Mbit/s | Evidence limitation |
|---|---:|---:|---|
| QUIC-like clean |92.254 mean of2 |92.170 mean of2 | one current-thread capture audit failed |
| Media-like clean |92.218 mean of2 |92.201 mean of2 | both multithread capture audits failed |
| QUIC-like impaired |77.986 one observed |78.498 mean of2 | other multithread case never reached ready/reference; no matched mean ratio |
| Media-like impaired |78.165 mean of2 |78.428 mean of2 | complete functional/capture ABBA; all four original80 targets failed |

Actual startup metrics report 254 workers/255 OS threads per multithread daemon,
and 1 worker/1 OS thread per current-thread daemon. Both-cover full lifecycle
checks ran through the same API and original owners in the 15 ready cases.
Across the complete media-impaired comparison, the sum of both daemons' sampled
system-CPU rates falls from about 0.428 to 0.233 cores; matched-task context switches
fall from about 20,885 to 7,172 per second. Clean comparisons also show lower CPU
and switch cost, with mean useful throughput essentially unchanged. These
process/task brackets are contained samples, not the exact20s goodput interval.
Detailed all-task observation costs about 150–158ms total wall time per
multithread case versus 4–5ms per current-thread case; observer cost, uncontrolled
loss draws and shared host activity limit causal precision. No statistical
significance, unique bottleneck or default migration follows.

Available impaired captures show roughly 83–84Mbit/s of successfully emitted
post-qdisc forward IP bytes and about 93–94% useful-byte/IP-byte efficiency. The
associated actual runtime charged rate is near its 99Mbit/s policy. This supports
investigating packing/outer overhead, pacing and recovery geometry after the
measurement failures are fixed. Emitted post-qdisc bytes already exclude egress
loss; do not multiply that measured efficiency by 85% again. Same-window emitted
and received bytes may represent different propagation cohorts. No conditional
geometry estimate relaxes the original80Mbit/s target. Daemon storage-read
accounting remains zero in available sampled intervals; host I/O pressure is
shared and does not prove disk waiting caused or could not affect a result.

Cases 02/09/15 retain their capture-drain and final-audit failures: the shared
parser rejects a native background IPv4 packet with a 24-byte header and Router
Alert option. The exact 54-byte frame is preserved. It was not skipped, filtered
out or retrospectively passed. A future bounded IHL/option repair must preserve
all full-MTU echo keys and fixed-layout protected WAN checks.

Case 03 retains setup-not-ready with no reference/task endpoints. Both daemon
logs collapse the typed failure to `secure UDP setup failed`; this does not
identify whether admission, Noise, membership, attachment or driver readiness
failed. The [bounded saved-capture analysis](../../work/host-runtime-20261114/setup-analysis-attempt-1/validation.json)
and [readable timeline](../../work/host-runtime-20261114/setup-analysis-attempt-1/analysis.md)
observe Gate traffic and bootstrap source prefixes classified as Noise
initiations, with no visible response flight. This is structural evidence, not
MAC/Noise/AEAD verification or proof of peer rejection/loss/cookie expiry.
Proposed follow-up is bounded nonsecret stage/reason/counter evidence before
changing retry or expiry behavior.

HRT-05 stays open: the recorded16-case attempt contains missing qualification
and measurement evidence. HRT-06 records the evaluation of those outcomes, not
a performance pass. HRT-07 records the required frozen-source check, evidence reconciliation and
actual local source checkpoint below; it does not close HRT-05. SNL-08/09/11, FIX-04,
full SW-11, all 47 P-* modes, lifecycle/platform and ISP gates retain their scope.
The omitted runtime default and all selected protocol semantics are unchanged.

## Required workspace check

The [second frozen-source check](../../work/host-runtime-20261114/aggregate-attempt-2/validation.json)
passed `python3 tools/check.py` through its recorder: 1,627 Rust cases including
doctests, 340 Python tooling cases and 1,658 simulator cases. All recorded inputs
remained stable. The [first attempt](../../work/host-runtime-20261114/aggregate-attempt-1/validation.json)
stopped before Rust execution because the new checked ledger lines lacked their
required inline `Evidence:` links; that documentation-only defect was corrected
before the second attempt. No test, deadline, threshold or assertion was removed.
These local Linux checks are separate from the failed finite native qualification,
remote CI, Windows/Android builds and real-device/ISP tests. The actual source checkpoint below binds the required check and subsequent
evidence-only reconciliation.

The [first evidence-only reconciliation](../../work/host-runtime-20261114/aggregate-attempt-2/postcheck/ledger-1/validation.json)
passed checklist and local-link checks with every non-document input identical
to the required aggregate. The [second reconciliation](../../work/host-runtime-20261114/aggregate-attempt-2/postcheck/ledger-2/validation.json)
passed before the source checkpoint was created; its non-document identities
remain identical to the required check.

The [actual source-checkpoint receipt](../../work/host-runtime-20261114/commit-binding-attempt-1/validation.json)
records local commit `e1d93f3496e9f27579b58b51d36e8651bbb5cc4c`, its parent/tree,
all seven committed file hashes, matching aggregate/reconciliation identities and
a clean worktree at that point. HRT-07 is closed using this existing receipt;
HRT-05 and every failed/unverified native and parent gate remain open. This
follow-up changes ledger evidence only. Nothing was pushed or published.
