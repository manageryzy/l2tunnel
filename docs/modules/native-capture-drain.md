# Bounded native capture tail witness

Status: **implemented with focused tests and four finite Linux native observations**.
The initial contract below was recorded before production edits. This is a
scoped secure-UDP lab correction under SNL-06/SNL-08/SNL-11 and the still-open
SBC-04. It does not change protocol/carrier bytes, crypto, channel admission,
shaping, throughput targets, probe deadlines or platform support. It is an
integrator implementation choice, not an additional owner decision.

## Source-bound failure and scope

The [preserved diagnosis](../../work/swift-bulk-copy-20261113/clean-capture-diagnosis-attempt-1/diagnosis.json)
finds a structurally complete clean-A pcap with 20 of24 expected native ICMP
records. Its final record precedes the final two reverse-origin requests by
about197/397 ms. Tcpdump reports492425 captured versus492457 received by filter,
zero kernel drops and no packet/file/sample ceiling exhaustion. This is consistent
with an unread capture tail at SIGINT, not proof of its location or transport loss.
That earlier source stopped all noncapture producers, then immediately interrupted
captures in `run_case` finally. Both old clean A/B failures remain immutable.

Only the current source-pinned native harness, its focused tests and this ledger
are in scope. Existing reusable namespace/throughput helpers and simulator receipts
remain unchanged. Root owns all builds, lab execution, aggregate checks and Git.
Worker production ownership is `tools/secure_udp_native.py`; test ownership is
`tools/test_secure_udp_native.py`. All new comments/documentation use English.

## Reviewed interface and ownership

`drain_native_capture(process, path, phases, deadline, *, clock=time.monotonic,
sleeper=time.sleep) -> dict` runs after noncapture producers stop but before any
capture SIGINT. It observes only the already owned native-a capture process/file;
it sends no traffic and opens no new socket/namespace. The supplied absolute case
deadline is never replaced or extended. Waiting uses short sleeps clamped to its
remaining time; scans of already saved data progress without a fixed sleep.

`_NativeCaptureCursor(path).poll(terminal=False, max_records=4096)` keeps one
read-only file descriptor, an accepted byte cursor, packet/read counters and at
most128 native ICMP header samples. `close()` runs in the draining helper's
finally on every path. A poll handles at most4096 records; only a complete,
validated record commits its cursor and observation. A live partial global header,
record header or body means need-more, including a trailing partial record after
all24 exact keys are already present. An EOF read cannot certify readiness when
the final file check has already observed unread appended bytes. After producer exit the same incomplete
extent is terminal truncation. Complete malformed headers/extents fail immediately.
Each complete record is scanned once; only a bounded incomplete record may be
reread. Never reread the whole capture on every poll or retain native payloads.
Observed path/fd device+inode replacement, symlinks and shrinkage are refusals.
These guards do not claim to detect arbitrary same-inode in-place rewriting by
an unrelated privileged actor; the writer is the harness's owned tcpdump process.

The reader accepts the same four pcap byte-order/timestamp magics, version2.4,
Ethernet link type and160-byte snapshot contract as the existing auditor. It
preserves the current1M-packet,256MiB-file and128-native-ICMP limits. Reuse small
header/native-ICMP validation/key helpers with the final audit when practical;
never use the polling reader as a substitute for the final audit.

## Exact witness and terminal behavior

The new witness requires all four completed three-request ICMP results: initial
and after-reconnect, each originating side a/b. Every result retains endpoint
status, sent/unique counts and sequences1..3. Build24 distinct exact expected
request/reply fingerprints with phase/side provenance, source/destination, type,
identifier, sequence, payload prefix,1500-byte IP extent and DF on requests.
Counts alone, duplicates, wrong payloads or unrelated packets cannot satisfy it.
The existing `icmp_capture_complete` partial-scope unit contract stays unchanged.
If setup/probes did not complete, reject immediately rather than waiting for
invented markers; preserve the original earlier error and continue owned cleanup.

Check the absolute deadline before and after each bounded poll, so an observed
late append or already-ready data at expiry cannot succeed. A producer that exited
may still have a large complete saved prefix: scan its saved chunks before deciding
whether keys are absent. At saved EOF, missing keys fail explicitly. Observing all
keys is only a drain witness, not a successful capture or native qualification.

Whether drain succeeds or fails, record its scoped observation/error and proceed
to the existing capture SIGINT/wait, final tcpdump counters, full `audit_capture`,
parsed-record equality, nonzero-drop rejection, native ARP/ICMP matching, outer
layout/epoch/MTU/fragment and common20s WAN-cost checks. Keep original case/cleanup
bounds and every earlier error. No new retries, sleeps that claim success without
reading, return-code waiver, counter-equality relaxation or capture-loss waiver.
Extra tail records retain their original timestamps and cannot enter the fixed
reference20s window merely because capture stops later.

## Validation and provenance

Use deterministic append fixtures to reproduce the old last-four-key absence,
partial live header/body and exact expiry; cover producer exit, malformed extent,
all resource limits, file replacement/shrink and bounded incremental progress.
Keep all old capture assertions. An orchestration regression must prove drain
failure still stops/audits owned captures and preserves its failure. Fake files
and ordinary subprocesses are tooling evidence, not privileged TAP qualification.

A changed copied helper requires a fresh immutable daemon build receipt carrying
its actual helper/source maps, even when unchanged Rust produces the same binary.
Never rewrite or transplant old A/B receipts. Fresh current-source qualification
runs both appearances on clean and impaired forward16 paths with the original
integrity/control/lifecycle/capture checks and80Mbit/s outcome. These four cases
do not replace the full SNL-08 matrix or retrospectively qualify old A/B captures.
SBC-04 stays open until its own matched before/after deliverable is proven.

## Preserved initial current-source observations

The [initial immutable build](../../work/native-capture-drain-20261113/native-build-attempt-1/build-receipt.json)
pins the initial matrix helper/source inputs. Its Rust binary is byte-identical to the
previous bulk-copy candidate; no Rust data-plane or protocol bytes changed.
The [initial four uninstrumented observations](../../work/native-capture-drain-20261113/native-analysis-attempt-1/analysis.md)
retain original20s receiver-unique measurement,16 forward flows, policy changes,
manual fresh reconnect, exact payload/hash/EOF, ARP/full-MTU ICMP/UDP, final
capture counters and owned cleanup. Every drain matches24 keys before its
original case deadline; every stopped full audit and zero-loss counter check passes.

| Appearance | Path | Forward Mbit/s | Original native verdict |
| --- | --- | ---: | --- |
| QUIC-like | clean | 89.7285 | passed |
| media-like | clean | 88.2116 | passed |
| QUIC-like | 70ms RTT,15% loss each way | 77.9001 | failed80 only |
| media-like | 70ms RTT,15% loss each way | 77.3597 | failed80 only |

The separate [kernel diagnostic](../../work/secure-udp-performance-analysis-20261113/current-kernel-summary-attempt-2/analysis.md)
uses the same current binary with bounded PID/TID-only perf. Its77.6672Mbit/s is
instrumented, separate from these four observations. Neither the witness nor the
new successful captures reverses any historical failure, establishes a native
bulk-copy gain, or closes the historical matched A/B deliverable. A witness is
not a write barrier; stopped full capture/counter audits remain authoritative.
Independent review then found an observed-growth/EOF edge; its focused regression
and correction are included in the current source. The initial matrix above stays
unchanged. Fresh final-source native observations are recorded separately below. The required
whole-workspace check and evidence-only reconciliation now pass; the local
checkpoint is still pending. The [first aggregate](../../work/native-capture-drain-20261113/aggregate-attempt-1/validation.json)
was intentionally interrupted for that review fix with frozen inputs; its
[exact-child interruption record](../../work/native-capture-drain-20261113/aggregate-attempt-1/interruption.json)
remains a separate failed/incomplete observation.

## Final-source observed-growth follow-up

The [final immutable build](../../work/native-capture-drain-20261113/native-build-attempt-2/build-receipt.json)
pins the reviewed EOF/observed-growth correction and all current inputs. Its Rust
binary remains byte-identical to the initial build and previous bulk-copy candidate.
The [final-source matrix verification](../../work/native-capture-drain-20261113/native-analysis-attempt-2/validation.json)
rechecks every saved helper/binary/pcap, final24-key witness, stopped audit/counter,
exact native payload, original20s/reference window, under-load policy/manual
reconnect and owned cleanup. All four pass those evidence/functional checks.

| Appearance | Path | Forward Mbit/s | Original native verdict |
| --- | --- | ---: | --- |
| QUIC-like | clean | 90.6326 | passed |
| media-like | clean | 90.0291 | passed |
| QUIC-like | 70ms RTT,15% loss each way | 76.9351 | failed80 only |
| media-like | 70ms RTT,15% loss each way | 78.4729 | failed80 only |

These are fresh uninstrumented observations, not a matched throughput-improvement
study. The initial matrix, profiled diagnostic, old capped profile and historical
A/B failures remain separate immutable results. The kernel diagnostic carries its
own helper revision; compiled Rust inputs and executable bytes match this final
follow-up. No new algorithm, wire behavior or default changed.

## Required aggregate outcome

The [required frozen-source aggregate](../../work/native-capture-drain-20261113/aggregate-attempt-2/validation.json)
passes with1619 Rust cases including doctests,319 Python tooling cases and1658
simulator cases. Formatting, strict workspace Clippy, rustdoc and CLI checks pass;
all before/after source inputs match. The intentionally interrupted first attempt
remains failed/incomplete, with its actual command/log and interruption reason.
This pass adds no platform, carrier, full SW-11, historical A/B or80Mbit/s acceptance.
NCD-05 records the actual passed evidence-only reconciliation. NCD-06 remains
open until the local source checkpoint exists.

## Acceptance ledger

- [x] [NCD-01] Record/review the bounded incremental reader, exact witness, unchanged final audit and failure/cleanup/provenance contract before production edits. Evidence: the [initial contract snapshot](../../work/native-capture-drain-20261113/contract-v0-snapshot/native-capture-drain.md), recorded integrator/worker handoff and [focused source-bound validation](../../work/native-capture-drain-20261113/focused-attempt-1/validation.json).
- [x] [NCD-02] Implement the reader, full expected-fingerprint witness and actual run_case finalization integration without changing old assertions, limits, traffic or protocol behavior. Evidence: [incremental cursor and finally integration](../../tools/secure_udp_native.py) and the [final four source-pinned native observations](../../work/native-capture-drain-20261113/native-analysis-attempt-2/validation.json) and the final-source [focused regression pass](../../work/native-capture-drain-20261113/focused-attempt-2/validation.json).
- [x] [NCD-03] Pass discriminating delayed/partial-tail, deadline, file identity, producer exit, resource and finally-cleanup regressions alongside all existing native tooling tests. Evidence: all74 [focused cases pass with stable source](../../work/native-capture-drain-20261113/focused-attempt-2/validation.json), including24 new [capture-tail regressions](../../tools/test_secure_udp_native.py). A complete24-key prefix with a partial25th record must wait for its valid boundary, including growth observed after an EOF read; failure/receipt-publication paths still stop and audit all captures.
- [x] [NCD-04] Run fresh source-pinned current-daemon clean/impaired observations on both appearances, retaining exact native/control/capture/cleanup and unchanged80 target outcomes; do not substitute them for historical matched A/B qualification. Evidence: the [final-source matrix](../../work/native-capture-drain-20261113/native-analysis-attempt-2/validation.json) passes all capture/control/cleanup checks, with two unchanged80 failures. The initial matrix remains preserved separately; historical SBC-04 stays open.
- [x] [NCD-05] Pass the required frozen-source workspace check and reconcile final documentation against exact non-document inputs, preserving failed attempts and all parent gates. Evidence: [passed required aggregate](../../work/native-capture-drain-20261113/aggregate-attempt-2/validation.json) and [completed evidence-only reconciliation](../../work/native-capture-drain-20261113/aggregate-attempt-2/postcheck/ledger-1/validation.json), with298 checked local links, no missing links and exact non-document inputs.
- [ ] [NCD-06] Save a coherent exact-byte local source checkpoint after its actual checks/reconciliation pass; close this item only after the commit exists.

Full SNL-08/SNL-09/SNL-11, SBC-04, FIX-02/FIX-04/FIX-09, SW-11, all47 P-* modes
and the remaining carrier/lifecycle/platform requirements retain their full scope.
