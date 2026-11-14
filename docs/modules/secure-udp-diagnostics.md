# Secure UDP capture and setup diagnostics

The original SGD-01..SGD-08 evidence below describes its named checkpoint.
The subsequent native capture-observation correction has its own contract and
ledger at the end; historical failed receipts remain unchanged.

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
The [second reconciliation](../../work/secure-udp-diagnostics-20261114/aggregate-attempt-1/postcheck/ledger-2/validation.json)
passed before the [actual source checkpoint](../../work/secure-udp-diagnostics-20261114/commit-binding-attempt-1/validation.json)
was created. Local commit `49ea663697b6e33a5511ce58e85dfdbd6727655e` binds all
19 committed file hashes, its parent/tree, focused/required/build/native/kernel
receipts and a clean worktree at that point. SGD-08 closes using that existing
proof; this follow-up changes only ledger evidence. Nothing was pushed or published.

## Acceptance ledger

- [x] [SGD-01] Record/review the capture, observation, shared API, failure/privacy/deadline and finite validation contracts before production edits. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-02] Correct bounded IPv4-header/options parsing in the shared cursor/final validator, preserving fixed-layout WAN/echo checks and every original capture gate. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-03] Pass meaningful exact-saved-frame, 24-key drain/final-audit/counter, malformed-option/extent/checksum and protected-layout regressions alongside all existing harness tests. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-04] Implement observed runtime/factory variants with actual typed stages/reasons and optional bounded counters, preserving original protocol bytes/state/deadlines/retries and no-op legacy behavior; pass focused runtime failure/success tests. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-05] Implement the operation-bound bounded shared-service API, atomic terminal evidence and nonblocking CLI failure projection without strict local API changes; pass expiry/cancellation/drop/reconnect/retirement/provider-error/output regressions. Evidence: [recorded contract](../../work/secure-udp-diagnostics-20261114/design-v0.md) and [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json).
- [x] [SGD-06] Record the fresh source-stable 16-case native ABBA attempt with original functional/capture/cleanup/80 verdicts and requested/effective/thread/CPU/wire/setup evidence; preserve failures and missing observations without claiming full qualification. Evidence: [complete evidence-verified matrix with eight failed 80 targets](../../work/secure-udp-diagnostics-20261114/native-analysis-attempt-1/validation.json) and [byte-exact archive](../../work/secure-udp-diagnostics-20261114/native-observations-attempt-1/archive-validation.json).
- [x] [SGD-07] Evaluate the original and new setup/capture/performance evidence, preserving all HRT/SNL/FIX/SW-11/mode/platform/lifecycle gates and distinguishing structural observation from authenticated runtime results. Evidence: [fresh matrix](../../work/secure-udp-diagnostics-20261114/native-analysis-attempt-1/validation.json), [bounded kernel comparison and limits](../../work/secure-udp-diagnostics-20261114/kernel-summary-attempt-1/validation.json), and [preserved historical structural setup evidence](../../work/host-runtime-20261114/setup-analysis-attempt-1/validation.json).
- [x] [SGD-08] Pass focused tests, strict lint/rustdoc, required frozen-source workspace checks and evidence-only reconciliation; save an actual coherent local checkpoint before closing this item. Evidence: [focused pass](../../work/secure-udp-diagnostics-20261114/focused-attempt-4/validation.json), [required check](../../work/secure-udp-diagnostics-20261114/aggregate-attempt-1/validation.json), [reconciliation](../../work/secure-udp-diagnostics-20261114/aggregate-attempt-1/postcheck/ledger-2/validation.json), and [actual source checkpoint](../../work/secure-udp-diagnostics-20261114/commit-binding-attempt-1/validation.json).

## Native capture observations

Status: **implemented, contract-tested and workspace-checked**, with a fresh
evidence-verified native matrix; its eight impaired performance targets fail.
Evidence is reconciled and an actual local source checkpoint is saved. This contract was recorded before
production edits in the [saved design](../../work/native-capture-observations-20261114/design-v0.md). The later
[receive-fairness matrix](../../work/swift-receive-fairness-20261114/native-analysis-attempt-1/validation.json)
retains two capture gaps. Case02 lost 24,979/22,768/12,017 packets in its three
capture observers, but raising before returning erased their parsed numeric
projection from the receipt. Case03 rejected a native ICMP type3/code3 quote as
an invalid echo. Its saved snapshot permits structural inspection only; a late
UDP reply to a closed socket is a hypothesis, not an established cause. The
80 Mbit/s failures and original capture verdicts remain unchanged.

Keep `capture_counts`' exact successful three-counter dictionary and existing
ObservationError/BoundExhausted failure categories. Parse bounded ASCII decimal
uint64 counters from exactly one unambiguous complete line per field. Do not
invent missing zeroes. Attach a copied complete observation to qualification
exceptions as `capture_counter_observation`: schema1, counters, actual return
code, complete parse status, passed/rejected qualification and all applicable
static reasons (`packet_cap`, `kernel_dropped`, `process_exit`). Keep original
first-failure precedence/message while retaining every applicable reason.

The receipt's separate `capture_counter_observations` map retains complete
parsed observations on success or rejection. Existing strict counter fields
remain absent for rejected captures. Stop/log/parse failures without a complete
triple remain unavailable; publication failure must not bypass other owned
stops, final audit or cleanup, or discard an earlier error. Preserve the old
count-equality-only `capture_complete` calls; add an explicit strict option used
by real `run_case` requiring complete valid counters, zero drops and packet cap.
Any supplied nonzero/invalid drop count is rejected even in count-only calls.
Neither received=captured nor captured+dropped=received is assumed.

Keep `_native_icmp_sample` and its echo dictionary/key grammar unchanged. A new
shared cursor/final dispatcher separately validates classic native UDP
port-unreachable messages: fixed complete outer/quoted IPv4 headers, reversed
owned HOST endpoints, no reserved/fragment flags, type3/code3, zero unused word,
valid quoted IP checksum, complete quoted UDP header, matching IP/UDP extents,
one port24461 and a distinct nonzero client port, and actual probe UDP lengths
8/9/26/72/520/1208/1480. Bound outer IP extent to56..1500 and no more than
28+quoted IP extent. Unsupported types, options, quotes and extensions fail
explicitly. The classic layout follows [RFC792](https://www.rfc-editor.org/rfc/rfc792);
longer original-datagram quotes are compatible with [RFC1812 section4.3.2.3](https://www.rfc-editor.org/rfc/rfc1812#section-4.3.2.3).
This lab subset does not implement [RFC4884 multipart extensions](https://www.rfc-editor.org/rfc/rfc4884).

Verify the full ICMP checksum when its declared extent is captured. Otherwise
report `not_observed_truncated_snapshot`, never full checksum/payload validity.
Historical probes do not retain ephemeral socket instances; quote recognition
proves supported structure, not exact probe membership, authentication or cause.
Store only flat header observations in separate `native_icmp_errors` with
count/samples/omitted; echo sample shape stays exact. Both live/final parsers
share a hard128 total ICMP-record bound and store at most16 error summaries.
The 129th observation fails before cursor/key/count commit. Errors satisfy none
of the24 exact echo keys. Persist available error observations in drain reports.

Root owns production, check registration, docs, execution, build/native commands
and Git. One worker owns only the new focused test module; other workers review
constraints and future generic-control integration without repository edits.
Preserve all104 existing harness tests. New tests cover the exact saved160-byte
snapshot, complete checksum cases, malformed/unsupported headers/quotes, shared
bounds, live/final parity, all24 keys, EOF/deadlines/identity, numeric rejected
counters and orchestration cleanup/publication failures. Freeze sources during
recorded old/focused/full/build/native checks. A fresh16-case observation retains
original35ms each way/15% loss,16 flows,100/10 shaping,99/9.9 policy,5s warmup,
20s measurement and80 target. No filter, snap length, capture buffer, deadline,
retry, host setting, default, protocol byte or parent requirement changes.

- [x] [SGD-09] Record/review the native quote/counter-observation contract, exact saved provenance, unchanged hard gates and implementation ownership before production edits. Evidence: [pre-edit contract](../../work/native-capture-observations-20261114/design-v0.md), [exact known-record extraction](../../work/native-capture-observations-20261114/fixture-extraction.json) and [old-source failures](../../work/native-capture-observations-20261114/old-source-attempt-1/validation.json).
- [x] [SGD-10] Preserve old-source failures and implement focused exact-snapshot, strict-negative-counter, shared-bound, malformed/EOF/deadline and cleanup/publication regressions alongside every existing harness test. Evidence: [old-source failures](../../work/native-capture-observations-20261114/old-source-attempt-1/validation.json), [27 new tests](../../tools/test_secure_udp_capture_observations.py) and [all131 harness cases passing with frozen source](../../work/native-capture-observations-20261114/focused-attempt-1/validation.json).
- [x] [SGD-11] Implement one shared bounded native ICMP dispatcher with separate error observations and unchanged echo/WAN grammar,24-key witness and final audit requirements. Evidence: [shared implementation](../../tools/secure_udp_native.py) and [frozen-source focused pass](../../work/native-capture-observations-20261114/focused-attempt-1/validation.json).
- [x] [SGD-12] Retain complete parsed negative counter observations without successful strict counter fields; preserve original errors, stop/final audit/cleanup and enforce explicit zero-drop qualification in real runs. Evidence: [shared counter/finalization implementation](../../tools/secure_udp_native.py) and [counter, finalization and retained harness regressions](../../work/native-capture-observations-20261114/focused-attempt-1/validation.json).
- [x] [SGD-13] Pass frozen-source focused and required checks; record a fresh immutable16-case native attempt and independent analysis with original targets and all failed/unavailable outcomes retained. Evidence: [required second aggregate](../../work/native-capture-observations-20261114/aggregate-attempt-2/validation.json), [all16 evidence-verified observations](../../work/native-capture-observations-20261114/native-analysis-attempt-1/validation.json), [additive field validation](../../work/native-capture-observations-20261114/additive-observation-analysis-attempt-1/validation.json) and [byte-exact archive](../../work/native-capture-observations-20261114/native-observations-attempt-1/archive-validation.json). Eight clean native cases pass; all eight impaired80 targets retain failed verdicts.
- [x] [SGD-14] Reconcile actual source/build/native evidence, distinguish structural/functional/performance/platform claims, and save an actual local checkpoint before closing this correction. Evidence: [non-document inputs unchanged after reconciliation](../../work/native-capture-observations-20261114/aggregate-attempt-2/postcheck/ledger-2/validation.json) and [actual source checkpoint5df423ae05e0cb1e84dbbc6cef971b0c5851bf7e](../../work/native-capture-observations-20261114/checkpoint-attempt-1/validation.json). This closes the scoped observation correction; all original failed80 targets and parent gates remain open.

The [source-stable focused check](../../work/native-capture-observations-20261114/focused-attempt-1/validation.json)
passes all104 retained harness cases and27 new cases plus Python compilation.
Compared with the [old-source assertion failures](../../work/native-capture-observations-20261114/old-source-attempt-1/validation.json),
its only non-document input difference is `tools/secure_udp_native.py`; all
regression assertions are unchanged. Both parsers accept the exact saved
snapshot as one structural error with no echo key. Rejected numeric observations,
complete checksum failures, shared bounds, identity/EOF/deadlines and owned
cleanup/publication are finite tooling contracts, not new native or throughput
results. The 200-byte fixture and provenance are under
[hashed tooling inputs](../../tools/fixtures/native_capture/port-unreachable-20261114.json),
so old/focused/full/build source maps bind their exact bytes without changing
historical receipt formats.

The [first required aggregate](../../work/native-capture-observations-20261114/aggregate-attempt-1/validation.json)
failed the existing OpenVPN runtime impaired-close test with `IncompleteClose`.
Its [preserved analysis](../../work/native-capture-observations-20261114/aggregate-attempt-1/close-failure-review.md)
finds that the last activity plus the existing maximum-RTO quiet interval can
exceed the unchanged five-second budget. It does not establish a production
close defect or causation by this Python correction. One unchanged-source
[isolated diagnostic](../../work/openvpn-close-single-20261114/isolated-attempt-1/validation.json)
and the [second required aggregate](../../work/native-capture-observations-20261114/aggregate-attempt-2/validation.json)
pass; neither erases the first failure or claims to repair it. The second
aggregate records 1,671 Rust cases including doctests, 376 tooling cases and
1,658 simulator cases, formatting, strict Clippy, rustdoc and CLI checks, with
all inputs stable. No assertion, close budget or retry was relaxed.

The [fresh immutable build](../../work/native-capture-observations-20261114/native-build-attempt-1/build-receipt.json)
binds binary `cbcabdf19368ee9979a60215ff7e0902414f52367cc4750a3b50537b9a87ddae`
to those same frozen inputs. Its completed 16-case ABBA observation retains the
original paths, shaping, policy, measurement intervals and targets. All16
capture, exact-payload, control, policy, manual-reconnect, thread and cleanup
observations are verified. Eight clean cases pass at92.174–92.469 Mbit/s. Eight
impaired cases fail only the original80 Mbit/s target at77.190–78.680 Mbit/s.
This records finite local Linux integration evidence, not full performance,
carrier, lifecycle, platform or ISP qualification. Previous capture failures
retain their original verdicts.

The [additive observation audit](../../work/native-capture-observations-20261114/additive-observation-analysis-attempt-1/validation.json)
checks all48 strict stderr-counter projections and the available native-error
summaries without upgrading any original verdict. Its final and exact committed
drain-prefix PCAP audit reproduces the pinned production parser; it is not an
independently implemented protocol parser. Recorded process return codes are
source-bound observations and cannot be reconstructed from stderr. Structural
ICMP observations do not prove authentication or exact probe membership.
All fresh native ICMP-error counts are zero; positive quote recognition is
covered by the retained exact fixture and focused contracts, not these runs.
Initial observer receipt-not-yet-created errors remain recorded; final artifact
custody and completed observations are verified separately.

The separate [same-binary kernel comparison](../../work/native-capture-observations-20261114/kernel-summary-attempt-1/analysis.md)
passes both complete raw-record and resolved-symbol validators with zero lost
events. Multi-thread/current-thread goodput is78.140/78.140 Mbit/s; both80 targets
fail. Kernel event-period shares are67.77/64.55%; measured system-time means are
0.590/0.310 cores, and matched-thread switch rates are19,152/6,862 per second.
These use their recorded, distinct sampling/counter intervals rather than
substituting the20-second goodput denominator. Both processes together record
zero storage-read bytes and372,736 storage-write bytes in each case. Shared
host I/O PSI is low and unattributed. Scheduling, epoll, TUN writes and UDP paths
are observed inclusive contexts; their percentages overlap. One instrumented
observation per model with unquantified profiler overhead establishes neither
a unique bottleneck nor a default change. All original parent gates remain open.
