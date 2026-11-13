# Swift deque byte-transfer correction

Status: **implemented, protocol-tested and CPU-measured; native qualification
incomplete**. This scoped FIX-09/SNL-11 correction preserves copied byte volume,
protocol bytes, security, deadlines and requested functionality. It changes the
two existing deque-to-vector append loops into bounded slice copies. It is an
integrator implementation choice, not an additional owner decision. All parent
performance/mode/platform gates remain open.

The production-engine CPU comparison gives baseline/candidate elapsed ratios
of 4.34–4.55 in the finite ABBA workloads with exact functional equality. The native observations establish no
throughput improvement: both impaired appearances remain below the unchanged
80 Mbit/s target. Both clean observations fail the existing native ICMP capture
completeness assertion despite passing payload throughput, endpoint probes and
cleanup. No failed case is relabeled a successful native qualification.

## Source-bound motivation

The preserved build9 impaired kernel observation classified **63.7058% of sampled
CPU PERIOD weight as kernel** and about 9.90% of all sampled PERIOD weight in the
byte-at-a-time `VecDeque::Drain<u8>` append loop. PERIOD-weighted samples are not
CPU wall time or blocked-wait duration. The two direct compiled callers are Swift
sender packing and receiver extraction; the available optimized frame-pointer
chains cannot divide that cost between them. All 86 attributed leaf samples lie
in the byte-iteration loop, with none in the reserve-call branch. This identifies
executed byte-copy work, not allocation frequency or a unique bottleneck.

The original profiler wrapper remains failed after reaching its requested event
data-size threshold slightly before its planned stop. Separate validation accepts
only the finite, measurement-contained partial record, with its exact timestamp
range and loss checks. Preserve both statuses. Kernel PMU/MSR bookkeeping samples
remain observer candidates rather than tunnel algorithm optimization targets.
Evidence: [partial-record validation](../../work/secure-udp-performance-analysis-20261113/build9-quic-impaired-kernel-analysis-attempt-2/validation.json),
[leaf attribution](../../work/secure-udp-performance-analysis-20261113/build9-quic-impaired-kernel-reports-attempt-1/vec-attribution.json)
and [compiled direct callers](../../work/secure-udp-performance-analysis-20261113/build9-quic-impaired-kernel-reports-attempt-1/vec-direct-callers-validation.json).

## Implemented behavior and correctness evidence

`byte_queue::append_prefix` checks the complete prefix length before changing
either buffer, reserves capacity for that admitted prefix, copies the deque's
existing physical slices and discards exactly the copied prefix. It preserves a
destination's existing bytes and the queue's exact remaining order. It introduces
no unsafe code, public API, clock, I/O, whole-history snapshot or new recovery
algorithm.

The sender still owns the same source payload, sequence, spare-buffer lifetime,
retransmission custody, partial-flush timestamp and repair/probe state. The
receiver retains its original output clearing and complete length/body checks.
Incomplete and malformed packets keep their existing no-consumption behavior.
Wire bytes, authentication, replay protection, MUX assignment, shaping rates,
recovery geometry and policy deadlines are unchanged.

Six new focused tests exercise actual wrapped storage, every prefix including
empty/full prefixes, invalid-length atomicity, existing destination bytes,
retained-source retransmission, partial flushes, split length/body boundaries and
incomplete/malformed receive behavior. Trusted-local rearrangement changes only
physical storage after real packet admission or real source reception. Production
sequence/decoder/history state is retained. Evidence:
[helper](../../crates/l2tunnel-swift/src/byte_queue.rs),
[helper tests](../../crates/l2tunnel-swift/src/byte_queue_tests.rs),
[sender tests](../../crates/l2tunnel-swift/src/sender_byte_queue_tests.rs),
[receiver tests](../../crates/l2tunnel-swift/src/receiver_byte_queue_tests.rs)
and [focused validation](../../work/swift-bulk-copy-20261113/focused-attempt-1/validation.json).
That source-stable focused receipt passed 47 Swift library cases, 2 example cases,
95 selected common-UDP runtime cases, 30 selected client cases, strict three-package
Clippy and rustdoc. These finite Linux checks are not native/platform qualification
or the final required workspace aggregate.

## CPU measurement evidence

Both immutable executables use the same benchmark example, compiler, build
environment and command. The compiled-source delta is restricted to the private
helper, its module declaration, the two call sites and their tests. The recorded
baseline preserves the pre-copy production bytes; the new shared example is
explicitly part of both builds rather than being called an untouched checkout.

The direct deque cases observe actual contiguous and wrapped slice geometry.
Their iterator and two-slice implementations are fixed algorithm references in
both executables. They do not measure the before/after production implementation;
in particular, the reference slice path is not the production helper's complete
reserve/call sequence. Production workload names indicate wrap stimulation, not
an observation of private queue geometry.

The production cases execute actual `Sender::poll`, receiver source/repair
processing, feedback, explicit retransmission and `Receiver::pop_packet`, using
reused preallocated caller outputs. Every delivered packet is compared for exact
order, length and bytes, including arbitrary data, all-zero payloads and trailing
zeros. The replay fingerprints are noncryptographic cross-run aids, not the byte
comparison authority. Exact payload lengths retain trailing zeros without trimming.

Each 20,000-packet case delivers 13,167,500 native bytes and transfers 13,207,500
packed bytes from the sender queue, including the two-byte native length prefixes.
The receiver copies 13,167,500 bytes into native outputs. These byte totals are
unchanged before/after. Zero observed growth of caller output capacities is not
an allocator-call count and does not measure private allocations, GF output writes
or cryptographic writes. This correction is not end-to-end zero copy.

The initial three-round comparison passed full functional-JSON equality after
omitting only the top-level label and the five named timing fields. It retains
capacity observations, logical time, geometry, body/feedback/payload fingerprints
and all counters. The subsequent eight immutable-binary invocations use
`A B B A A B B A`, 20,000 packets and one round each, with no retry after failures.
All functional fields again match. Overall production elapsed medians:

| Queue workload | Scripted source/feedback loss | Before median | After median | Before/after ratio |
| --- | --- | ---: | ---: | ---: |
| Empty between batches | No |78.441 ms |17.309 ms |4.532 |
| Empty between batches | Yes |78.851 ms |18.103 ms |4.356 |
| Retained-tail refill | No |78.232 ms |17.194 ms |4.550 |
| Retained-tail refill | Yes |78.368 ms |18.052 ms |4.341 |

The ABBA artifact retains minimum/maximum and all raw invocations, not just these
medians. Per-call sender/receiver times include `Instant` measurement overhead;
overall elapsed also includes feeding, exact checks, hashing, feedback and GF
work. ABBA reduces one ordering concern but is not a statistical isolation of
native performance. Evidence: [initial comparison](../../work/swift-bulk-copy-20261113/cpu-comparison-attempt-1/validation.json),
[ABBA comparison](../../work/swift-bulk-copy-20261113/cpu-abba-attempt-1/validation.json),
[immutable baseline build](../../work/swift-bulk-copy-20261113/cpu-baseline-build-attempt-1/build-receipt.json)
and [immutable candidate build](../../work/swift-bulk-copy-20261113/cpu-candidate-build-attempt-1/build-receipt.json).

## Native observations and preserved failures

The [initial observer attempt](../../work/swift-bulk-copy-20261113/native-observations-attempt-1/01-a-quic-like-impaired/receipt.json)
failed before topology/daemon startup: its inherited 4 MiB `RLIMIT_FSIZE` prevented
copying the immutable daemon. Its primary status remains `tool_failure`, with
native cleanup `not_started_or_unverified`; the observer waited its launcher.
It is not a throughput observation. The separately archived r2 observer allows
256 MiB during launcher preparation; the unchanged native worker then resets its
original 4 MiB soft/256 MiB hard limits, with separately capped capture children.
Unexpected exceptions and deferred interrupts stop after owned child cleanup.
No host routes/qdiscs, harness sources, workload limits or capture assertions change.

The [second matrix](../../work/swift-bulk-copy-20261113/native-observations-attempt-2/results.json)
uses pre-copy production checkpoint 423201f plus the declared shared new benchmark
and documentation as A, and only the private helper/two-call-site/test delta as B.
All 399 pre-existing tracked Rust files in A match the baseline commit. Immutable native
binary SHA-256 identities are A `976e2f84266d5236a14a77385047999896b3d22e13503a962f2c5c99d73456a1`
and B `7aebb2f22e6b4caca8e21923b027aa52a0b0cb81df5935836368940f1a5ad8af`.
Matching [baseline](../../work/swift-bulk-copy-20261113/native-baseline-build-environment.json)
and [candidate](../../work/swift-bulk-copy-20261113/native-candidate-build-environment.json)
toolchain/environment records supplement the source-stable build receipts.

All six use the actual explicit CLI Swift carrier with legacy control selection,
not the separate library-selected streamed-control backend. They retain the
16-flow forward TCP/ACK-return workload, 100/10 Mbit/s HTB, 99/9.9 Mbit/s inner
full-IP budgets, original socket/five-tuple and all lifecycle/probe deadlines.
Impaired means 70 ms RTT and independent 15% loss each way. Runs are sequential:
QUIC impaired A/B, media impaired B/A, then QUIC clean A/B. Loss traces are not
identical and each variant has one observation per pair.

| Appearance/path | A forward Mbit/s | B forward Mbit/s | Original 80 gate | Native case result |
| --- | ---: | ---: | --- | --- |
| QUIC-like impaired |77.678250 |77.302349 |Both failed |Only throughput target failed |
| Media-like impaired |78.421942 |78.297994 |Both failed |Only throughput target failed |
| QUIC-like clean |92.060365 |92.400355 |Both passed |Both failed ICMP capture completeness |

The [read-only evidence analysis](../../work/swift-bulk-copy-20261113/native-analysis-attempt-1/analysis.json)
verifies binary/build/all seven copied helpers, exact payload/hash/EOF and original
20-second goodput fields, raw-input hashes and all six owned cleanups. Analysis
status `verified` is separate from the six original native `failed` statuses.
For clean A, the native audit lacks the final two reverse-origin ICMP request/reply
pairs after reconnect, although the endpoint validates all replies. Its 20 stored
ICMP samples are below the 128-sample ceiling; capture packet/file bounds are not
exhausted. Clean B also fails the same assertion. Preserve these failures; native
capture completeness and SBC-04 remain open pending a bounded diagnosis and fresh
qualification. Endpoint success cannot waive capture evidence. The separately saved
[capture-tail diagnosis](../../work/swift-bulk-copy-20261113/clean-capture-diagnosis-attempt-1/diagnosis.json)
finds complete pcap records ending about 197 ms before the second missing request
and 397 ms before the third. Tcpdump reports 492425 captured versus 492457
received by its filter and zero kernel drops. An unread reader/capture tail when
SIGINT stops collection is consistent with this evidence but remains a hypothesis;
it neither qualifies the capture nor proves tunnel packet loss.

The process/host intervals are separately contained about 19.09–19.10 seconds
inside each native 20-second reference window. QUIC impaired A records endpoint
a user/system CPU 2.02/4.17 seconds and b 2.80/3.80; B records a 1.54/4.10 and
b 2.66/4.10. These are cumulative process tick deltas, not sampled PERIOD weights.
The artifact reports their own interval rates and timestamp brackets; do not divide
them by the full native payload window or transplant build9 percentages onto them.
All endpoint storage `read_bytes` deltas are zero and `write_bytes` are 200–208 KiB
per contained interval. These are process storage counters, not total host disk
completion, capture I/O or UDP wire bytes. Host I/O PSI `some` varies about 0.020–2.870%
across the six intervals and is not attributable to the tunnel. Shared-host load,
random loss and single observations prevent a small causal goodput conclusion.

## Remaining limits and validation

The CPU change reduces executed byte-iteration work without reducing byte volume
or wire cost. Per-call timing includes `Instant` overhead, and the actual pipeline
also includes feeding, exact checks, fingerprints, feedback and GF work. The
native kernel/network/scheduler work remains material. Use existing same-interval
wire class/credit/retransmission/packing/occupancy counters before choosing another
optimization; CPU-per-byte needs byte counters over the same CPU interval.
The existing [conditional geometry estimate](../../work/secure-udp-performance-analysis-20261113/hash-geometry-attempt-1/conditional-ceiling.json)
is not a strict finite-window bound or permission to lower the target, change
security/rates/defaults, or remove any requested mode.

The [source-stable focus](../../work/swift-bulk-copy-20261113/focused-attempt-1/validation.json)
passed 47 Swift library/2 example, 95 runtime and 30 client cases, strict Clippy and
rustdoc. Seven synthetic native-analysis checks passed with
`PYTHONDONTWRITEBYTECODE=1 python3 /tmp/test_l2tunnel_copy_native_analysis_20261113.py`.
The [required frozen-source aggregate](../../work/swift-bulk-copy-20261113/aggregate-attempt-2/validation.json)
passed 1619 Rust cases including doctests, 295 Python tooling cases and 1658
simulator cases, with no source changes during verification. The two example
cases were additionally run in the focused receipt; do not add them twice to the
aggregate count. The [first aggregate attempt](../../work/swift-bulk-copy-20261113/aggregate-attempt-1/validation.json)
failed before Cargo at the checklist formatting gate because newly checked SBC
rows lacked inline evidence links. Adding those links preserved every task
ID/definition and all tests, deadlines and thresholds. That failure remains
preserved. SBC-06 stays unchecked until evidence-only reconciliation and an
exact-byte coherent local checkpoint have both actually completed.
These are local Linux checks, not Windows/Android builds/devices, remote CI,
ISP QoS classification or the complete platform/native matrix.

## Acceptance ledger

- [x] [SBC-01] Implement bounded checked at-most-two-slice prefix transfer and use it in both production Swift drain sites without changing protocol bytes, ownership, timers or configuration. Evidence: [helper and callers](../../crates/l2tunnel-swift/src/byte_queue.rs) and [focused validation](../../work/swift-bulk-copy-20261113/focused-attempt-1/validation.json).
- [x] [SBC-02] Test physical wrap, split length prefixes/bodies, incomplete and malformed atomic behavior, exact remainders, reused outputs and retained-source retransmission; retain existing recovery/wire tests. Evidence: [six regression cases](../../crates/l2tunnel-swift/src/byte_queue_tests.rs) and [focused validation](../../work/swift-bulk-copy-20261113/focused-attempt-1/validation.json).
- [x] [SBC-03] Execute source-stable paired CPU-only measurements with identical real-engine workloads/example bytes and immutable pre/post executables; preserve raw results and distinguish copied bytes, capacity growth and unmeasured allocations. Evidence: [immutable ABBA measurements](../../work/swift-bulk-copy-20261113/cpu-abba-attempt-1/validation.json).
- [ ] [SBC-04] Run finite matched native pre/post observations for both impaired appearances and a clean control; retain complete integrity/control/cleanup, source/binary identity, pressure/CPU scope and the unchanged80Mbit/s acceptance result. Evidence: [six terminal observations](../../work/swift-bulk-copy-20261113/native-analysis-attempt-1/analysis.json). The finite matrix is recorded, but both clean capture completeness checks failed, so this gate remains open.
- [x] [SBC-05] Evaluate whether observed CPU/native differences support the correction, identify remaining wire/queue/scheduling limits and preserve failures without claiming a unique bottleneck or closing parent performance/mode gates. Evidence: [CPU comparison](../../work/swift-bulk-copy-20261113/cpu-comparison-attempt-1/validation.json) and [native/resource analysis](../../work/swift-bulk-copy-20261113/native-analysis-attempt-1/analysis.json).
- [ ] [SBC-06] Pass focused tests, strict Clippy/rustdoc, the required frozen-source workspace check and evidence-only ledger reconciliation; commit a coherent local checkpoint with exact validated bytes.

The full SNL-08/SNL-09/SNL-11, FIX-02/FIX-04/FIX-09, SW-11, carrier/lifecycle/platform
and all 47 P-* requirements remain required at their existing scope. Historical
simulator/native/perf receipts remain unchanged.
