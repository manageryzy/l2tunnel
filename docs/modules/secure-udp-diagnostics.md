# Secure UDP capture and setup diagnostics

Status: **implemented, contract-tested and finitely Linux integration-tested**;
the fresh 16-case matrix has complete evidence, with all eight impaired cases
still failing the original 80 Mbit/s target. Separate kernel observations are
recorded below. The contract below was recorded before production edits. This correction follows
HRT-05/SNL-11/FIX-04 evidence gaps. It does not change carrier, cryptography,
protocol bytes, recovery, accepted deadlines, retry limits, cookie lifetime,
default runtime, control backend or any parent requirement. Historical HRT/NCD
receipts retain their original failed or passed verdicts. Full SW-11, all 47
mode-parity gates, the impaired 80 Mbit/s target and platform/lifecycle work remain
in scope.

## Observed defects

The [source-bound HRT attempt](../../work/host-runtime-20261114/native-analysis-attempt-2/validation.json)
records three native capture failures on an IPv4 packet with a 24-byte header
and Router Alert option. The previous shared live/final parser required byte
`0x45`. The failed setup case has no ready/reference observation; its saved
[structural timeline](../../work/host-runtime-20261114/setup-analysis-attempt-1/validation.json)
does not establish whether a receiver authenticated or rejected a packet. The previous
service retained only `io::ErrorKind`, and its CLI printed one generic
setup failure. `PermissionDenied` is not proof of authentication failure.

## Bounded capture correction

Keep `_captured_ipv4(frame, original) -> (ip, total)` and the same shared parser
for the growing cursor and final audit. Derive IHL from the IPv4 header, require
version 4, IHL 20..60 bytes, a completely captured declared header, total length
at least IHL, the original Ethernet/IP extent rule and checksum over the entire
header. Inspect at most 40 option bytes. EOL requires remaining zero padding;
NOP consumes one byte. Other options need a present length byte, length at least
2 and a complete extent within IHL. This lab parser explicitly supports Router
Alert type 0x94, length 4, value 0; other option semantics remain unsupported.
These header rules follow [RFC 791](https://www.rfc-editor.org/rfc/rfc791) and the
selected Router Alert format in [RFC 2113](https://www.rfc-editor.org/rfc/rfc2113).
This is bounded IPv4-header validation, not an IGMP implementation.

Native non-ICMP background packets remain counted and validated; never skip the
offending record or change the capture filter. Keep explicit 20-byte IPv4-header
requirements before fixed-offset protected WAN/ICMP-quote and native echo
validators. Preserve all 24 exact full-MTU/DF/prefix probe keys, ownership checks,
partial-record/EOF behavior, packet/byte/time caps, final audits, capture-counter
equality, zero-drop requirement, wire accounting and original 80 target.

Regressions include the exact saved 54-byte frame followed by the existing
24-key capture, valid NOP/EOL/Router Alert and 60-byte header boundaries, malformed
version/IHL/header/total/option lengths/padding/checksum/extents, and valid-option
WAN/echo packets rejected before fixed-offset parsing. All existing 95 native
harness tests and original parser/deadline/failure tests remain required.

## Bounded runtime observations

Add a runtime-only `secure_udp::diagnostics` module with Copy fixed-field
observations and static stage/reason enums. No string from an error, packet,
credential or provider is retained. Add observed establishment/member variants;
existing entry points delegate to them through a no-op observer. A synchronous
`FnMut(Observation) + Send` callback publishes actual Configuration/Admission/
Noise/Membership transitions and available existing statistics before suspension,
error and handoff. It is not a protocol input, authority, timer or retry owner.

Classify typed establishment/Gate/recovery/Noise failures before the factory
flattens them into I/O categories. Distinguish original/bootstrap deadline,
admission attempts, bootstrap recovery attempts, Joining attempts, configuration,
entropy, actual authentication rejection, protocol/cover failure, local I/O and
unknown failures. Do not classify by matching error text. Member-specific known
branches publish their typed reason before returning their unchanged I/O error.

Bootstrap statistics and current bootstrap-control retention are optional until
their actual owners exist. Member attempt counters are optional until constructed.
Server gate observations are cumulative retained-admission-owner accounting,
including a retained-session gauge; do not label them per-attempt monotonic
counters. No missing observation is synthesized as zero. Retained send/receive
bytes are gauges. Existing success statistics and all original protocol state
transitions remain unchanged. Each observed establishment/member phase holds one
concrete pinned setup future on the heap, bounding nested caller stack storage;
this adds setup-only allocations and does not alter packet-path ownership.

## Shared service and CLI contract

Keep `Failure { kind }`, `Completed`, `Snapshot` and strict local API v1/v2 bytes.
Add one optional fixed-size `SetupObservation` to each existing retained service
operation (the existing 32-entry history), with no additional queue/history.
Expose `Handle::setup_observation(OperationId) -> Result<Option<SetupObservation>,
SubmitError>` to every local embedding frontend. Nonsecure operations return None;
future/retired IDs follow the existing lookup contract.

The observation contains only its operation ID, actual stage/outcome, optional
static reason and actual I/O kind, sampled elapsed/original-timeout microseconds,
and optional runtime counters. Service stages include Accepted, SocketBind,
SocketConnect, AdmissionOwner, Configuration, Admission, Noise, Membership,
Attachment, DriverReadiness and ReadyPublication. Authentication is not readiness.
Publish updates outside provider/I/O work; no observer callback runs while the
service mutex is held. Terminalize atomically with actual completion, readiness,
cancellation or owner drop. A late callback cannot overwrite another operation
or a terminal record. Reads do not refresh terminal times or extend deadlines.
Reconnect starts a fresh observation; old retained evidence remains tied to its
original operation until normal retirement.

On actual setup failure, the CLI emits one bounded `secure_udp_setup_failed`
stderr JSON event from this same shared observation, then retains its existing
nonzero exit/error behavior. Reuse the current bounded nonblocking output sink
through a stderr constructor; preserve inherited file-description flags/offsets,
line/queue/write caps and logger-health fields. Logging is best effort and cannot
change the operation outcome or delay protocol cleanup. Never serialize provider
Display/Debug text, arguments, paths, keys, nonces, cookies, packet bodies, public
peer identifiers or a real-time timestamp. The operation-bound service result is
authoritative when stderr is unavailable. No API version or wire format changes.

## Verification and ownership

Exercise actual covered UDP under both appearances: admission/bootstrap/Joining
failure classifications, unchanged deadline boundaries, authentication followed
by attachment failure, driver failure before readiness, queued expiry without
socket/device effects, cancellation/drop, reconnect isolation and history
retirement. Preserve existing success bytes/policy/version/liveness fixtures.
Test sentinel-bearing provider errors, bounded/full/broken stderr and byte-exact
local API compatibility. Observer counters are evidence, never protocol decisions.

ROOT owns this document/master ledger, service/CLI integration, every fmt/Cargo/
focused/full/build/native command and Git. Workers own disjoint files: native
capture source; native capture tests; runtime observed adapters and shared client
factories. Workers do not execute tests, builds or native workloads. Freeze every
recorded source input during checks, builds and measurements.

After focused checks, use one immutable build for a fresh 16-case HRT ABBA
attempt, retaining the original 35 ms each way/15% loss, 16 flows, 100/10 shaping,
99/9.9 policy, 5 s warmup, 20 s measurement and 80 target. Preserve every negative
outcome and any unavailable measurement; do not fill missing ABBA cells. New
parser replay may validate saved packet structure separately but cannot rewrite
old native verdicts. Complete HRT-05 only when its stated evidence exists. Run
`python3 tools/check.py`, reconcile actual evidence and save a coherent local
checkpoint before closing the corresponding deliverables.

## Focused evidence and preserved failures

The [frozen-source focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json)
records all 104 native harness tests, all 233 client-core unit tests and 19 public
API tests, all 101 secure-UDP runtime tests, strict Clippy and rustdoc. The new
coverage includes six runtime, ten real shared-service and seven bounded output
tests; strict local API compatibility remains in the full client-core run.
[Attempt 1](../../work/secure-udp-diagnostics-20261114/focused-attempt-1/validation.json)
retains a new test closure-lifetime compile failure;
[attempt 2](../../work/secure-udp-diagnostics-20261114/focused-attempt-2/validation.json)
retains the existing streamed crossing fixture's default-stack overflow; and
[attempt 3](../../work/secure-udp-diagnostics-20261114/focused-attempt-3/validation.json)
retains lint failures after functional tests passed. The bounded setup-future
allocation fixes stack composition without increasing the test stack or changing
any original assertion, retry or deadline. Counter/key-use exhaustion retains
its distinct typed reason. No failed receipt is overwritten.

The user-requested kernel investigation used separate MT and CT impaired
QUIC-like runs on the same immutable build. It attached only to the two receipt-owned
processes' verified existing TIDs, retaining 99 Hz mixed user/kernel cycles,
address-only frame-pointer callchains, per-task switch records and bracketed
process/task CPU/I/O plus host PSI counters. Preserve the original measurement
seconds 2..18 recorder bound, 64 MiB event cap, 128 MiB file guard and bounded
exact-child cleanup, without changing host settings. Actual event span, counter
brackets and 20-second useful-byte clock are separate denominators. This is an
instrumented diagnostic, not the uninstrumented ABBA or 80-target acceptance.

## Fresh native and kernel evidence

The [immutable optimized build](../../work/secure-udp-diagnostics-20261114/native-build-attempt-1/build-receipt.json)
and [required frozen-source workspace check](../../work/secure-udp-diagnostics-20261114/aggregate-attempt-1/validation.json)
bind the same non-document inputs. The check passed 1,650 Rust cases including
doctests, 349 Python tooling cases and 1,658 simulator cases, plus formatting,
strict Clippy, rustdoc and CLI checks. These are local Linux results, separate
from remote CI, Windows/Android builds and real-device/ISP qualification.

The [fresh independent matrix analysis](../../work/secure-udp-diagnostics-20261114/native-analysis-attempt-1/validation.json)
verifies all 16 saved cases, including exact useful bytes/hash/EOF, authenticated
control, policy, manual reconnect, capture, task observations and owned cleanup.
Its status `verified` describes evidence validation, not performance acceptance.
All eight clean cases passed; all eight impaired cases failed only the original
80 Mbit/s target, at 77.664–78.215 Mbit/s. The complete A-B-B-A means are:

| Condition | Multithread Mbit/s | Current-thread Mbit/s |
| --- | ---: | ---: |
| QUIC-like clean | 92.047 | 92.199 |
| Media-like clean | 92.149 | 92.300 |
| QUIC-like impaired | 78.009 | 77.836 |
| Media-like impaired | 77.707 | 78.128 |

Every case used binary
`4098fb37bb6c223e4f15b10389123a84ed5fdd774e61da3fd0ace17e860c40c9`.
Actual observations remained 254 Tokio workers/255 OS threads per multithread
daemon and 1 worker/1 OS thread per current-thread daemon. The
[byte-exact archive](../../work/secure-udp-diagnostics-20261114/native-observations-attempt-1/archive-validation.json)
preserves 3,407,337,028 bytes across 761 files. No source, acceptance threshold,
host network or kernel setting changed during measurement. This finite attempt
has no setup/capture evidence gap; it cannot diagnose the old setup failure or
establish automatic recovery, cookie-expiry causality or full session lifecycle.

The [separate same-binary kernel comparison](../../work/secure-udp-diagnostics-20261114/kernel-summary-attempt-1/analysis.md)
records 68.848% kernel cycle-period weight for multithread and 62.266% for
current-thread. Across their distinct counter brackets, summed system CPU falls
from 0.6094 to 0.3131 mean cores and matched `/proc` task context switches from
18,733 to 6,942 per second. Instrumented useful throughput is 78.246 versus
77.637 Mbit/s; both original 80 targets fail. This is one instrumented case per
runtime, with unquantified differential profiler overhead. It establishes lower
observed scheduling cost, not a causal throughput improvement or default decision.

Resolved kernel callchains include scheduler, epoll, TUN write and UDP send/receive
contexts; their inclusive percentages overlap. Both daemons together account for
zero storage read bytes and about 0.36 MiB writes in each counter bracket. This
does not establish a disk bottleneck or exclude buffered I/O or indirect shared
host contention. Host PSI remains unattributed, and disabled scheduler/delay
accounting remains unavailable.

The original multithread full raw validator remains **failed**: one SWITCH pair
on TID 2778560 moves backward by 5,760 ns. Its cause is unproved. The separate
[component validation](../../work/secure-udp-diagnostics-20261114/kernel-components-01-multi-thread-quic-like-impaired-attempt-1/validation.json)
passes raw geometry, ownership, zero-loss markers, cycle samples and process
counters while omitting inferred durations for that TID. Current-thread full
raw validation passed. Six offline regression cases retain the exact inversion;
no timestamp was sorted or clamped. The first unprivileged current-thread symbol
report remains preserved with mostly unknown kernel leaves; only the subsequent
resolved reports support the hotspot descriptions. Neither partial switch
pairing nor evidence verification promotes a failed native performance result.

These observations complete HRT-05's matrix-recording deliverable, not its parent
80 Mbit/s requirement. SNL-08/09/11, FIX-04, complete SW-11, all 47 P-* modes,
RLNC/parity/rolling/packed/proxy, other carriers, lifecycle, platforms and ISP
measurement remain in scope. Next performance analysis must distinguish attempted
and post-qdisc bytes, packing/repair/feedback overhead and propagation cohorts;
post-qdisc bytes must not be charged with the configured loss a second time.

The [first evidence-only reconciliation](../../work/secure-udp-diagnostics-20261114/aggregate-attempt-1/postcheck/ledger-1/validation.json)
passed checklist and 288 local-link checks after recording these outcomes;
every non-document input remains identical to the required workspace check.
Actual local checkpoint binding is still required for SGD-08.

## Acceptance ledger

- [x] [SGD-01] Record/review the capture, observation, shared API, failure/privacy/deadline and finite validation contracts before production edits. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-02] Correct bounded IPv4-header/options parsing in the shared cursor/final validator, preserving fixed-layout WAN/echo checks and every original capture gate. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-03] Pass meaningful exact-saved-frame, 24-key drain/final-audit/counter, malformed-option/extent/checksum and protected-layout regressions alongside all existing harness tests. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-04] Implement observed runtime/factory variants with actual typed stages/reasons and optional bounded counters, preserving original protocol bytes/state/deadlines/retries and no-op legacy behavior; pass focused runtime failure/success tests. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-05] Implement the operation-bound bounded shared-service API, atomic terminal evidence and nonblocking CLI failure projection without strict local API changes; pass expiry/cancellation/drop/reconnect/retirement/provider-error/output regressions. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-06] Record the fresh source-stable 16-case native ABBA attempt with original functional/capture/cleanup/80 verdicts and requested/effective/thread/CPU/wire/setup evidence; preserve failures and missing observations without claiming full qualification. Evidence: [complete evidence-verified matrix with eight failed 80 targets](../../work/secure-udp-diagnostics-20261114/native-analysis-attempt-1/validation.json) and [byte-exact archive](../../work/secure-udp-diagnostics-20261114/native-observations-attempt-1/archive-validation.json).
- [x] [SGD-07] Evaluate the original and new setup/capture/performance evidence, preserving all HRT/SNL/FIX/SW-11/mode/platform/lifecycle gates and distinguishing structural observation from authenticated runtime results. Evidence: [fresh matrix](../../work/secure-udp-diagnostics-20261114/native-analysis-attempt-1/validation.json), [bounded kernel comparison and limits](../../work/secure-udp-diagnostics-20261114/kernel-summary-attempt-1/validation.json), and [preserved historical structural setup evidence](../../work/host-runtime-20261114/setup-analysis-attempt-1/validation.json).
- [ ] [SGD-08] Pass focused tests, strict lint/rustdoc, required frozen-source workspace checks and evidence-only reconciliation; save an actual coherent local checkpoint before closing this item.
