# Reusable Swift numbered records

Status: **implemented; focused pure and legacy-runtime tests passed**,
2026-11-13. The design was written and reviewed before implementation. This subordinate
FIX-13/SW-14 extraction makes the existing runtime's complete data algorithm
available beneath either the retained Swift v2 protection or the common secure
record composition. It does not implement a new connection mode, handshake,
carrier, control protocol or default. The existing [Swift ledger](swift.md),
[common session contract](secure-session.md) and full SW-11 remain authoritative.

## Boundary and compatibility

The existing pure `Sender`/`Receiver`, GF arithmetic, connection classifier and
exact header compression remain unchanged. `l2tunnel_swift::records` composes
them into the same ordered channels currently owned by the legacy runtime. It
owns the common packing-byte budget, per-channel header contexts, urgent
retransmission preference, round-robin new-data scheduling, channel-tagged data,
concatenated feedback, native delivery, cumulative algorithm counters and
directional drain/reset hooks.

The record engine accepts injected monotonic microseconds and an externally
owned full 64-bit `RecordNumber`. That number is the exact authenticated data
record number, including gaps occupied by Swift feedback or other channels.
It remains the repair coefficient seed. A caller must not substitute a truncated
outer QUIC/RTP number, per-channel sequence, recovery source ID or new local
counter. The same number passed to `poll` must protect its returned body, and
`accept` receives the number actually verified by the corresponding receiver.
The caller checks counter exhaustion and the maximum output/cover budget before
polling; failure after algorithm progress is terminal or an explicitly retained
attempt, never a reason to encrypt the body with a different number.

The caller authenticates, checks replay, selects User authority and validates
the active/draining scope before `accept`. This engine cannot grant authority
from a kind byte, Ethernet field or apparent control payload. Swift feedback is
data-algorithm feedback inside User records; authenticated management remains
the separate session service. The engine contains no keys, replay window,
handshake identity, secret export, Tokio, OS handle, privilege, real clock,
device setup, pacing budget or socket ownership.

Legacy v2 wire bodies remain byte-for-byte unchanged: kind in the low two bits,
channel in the high six, unchanged source/repair headers and GF seed, and the
same concatenated feedback blocks. Header compression still validates its own
reconstruction and uses literal fallback for arbitrary bytes, unusual headers,
wrong checksums and zero tails. Each accepted native packet follows the same
connection-affinity channel and shares the configured admission budget.

## Public API

```rust,ignore
Layer::{Ethernet, Ip}
Config { codec: swift::Config, channels: usize, layer: Layer, max_native: usize }
RecordNumber(pub u64)
Admission::{Accepted, Full, PacketSize}
Stats { sender: swift::SenderStats, receiver: swift::ReceiverStats,
        native_read: u64, native_dropped: u64, header_bytes_saved: u64 }
Error::{Configuration, Codec(swift::Error), NotDrained, Admission}

Engine::new(config: Config) -> Result<Engine, Error>
Engine::{send_config, receive_config}(&self) -> Config
Engine::body_limit(&self) -> usize
Engine::has_room(&self) -> bool
Engine::offer(&mut self, now: u64, packet: &[u8]) -> Result<Admission, Error>
Engine::poll(&mut self, now: u64, number: RecordNumber, allow_data: bool)
    -> Result<Option<&[u8]>, Error>
Engine::accept(&mut self, now: u64, number: RecordNumber, body: &mut [u8])
    -> Result<(), Error>
Engine::pop(&mut self) -> Result<Option<&[u8]>, Error>
Engine::data_ready(&self, now: u64) -> bool
Engine::{data_deadline, feedback_deadline}(&self) -> Option<u64>
Engine::{send_drained, receive_drained, deliverable}(&self) -> bool
Engine::unconfirmed(&self) -> usize
Engine::{source_floor, feedback_floor}(&self) -> RecordNumber
Engine::replace_send(&mut self, config: Config, feedback_from: RecordNumber)
    -> Result<(), Error>
Engine::replace_receive(&mut self, config: Config, source_from: RecordNumber)
    -> Result<(), Error>
Engine::stats(&self) -> Stats
Engine::channel_stats(&self, index: usize) -> Option<ChannelStats>
```

`channel_stats` observes only current directional engines without allocation,
polling, time sampling or wire mutation. Indices cover0..<max(send,receive), at
most64; a missing asymmetric direction is `None`, and an index beyond both is
absent rather than silently truncated. Current RTT/RTO, queued packing bytes,
unconfirmed sources and pending retransmission/repair debt exclude retired
engines. Aggregate `stats` retains retired totals and its existing maximum RTT
semantics; it is not a current-channel or average RTT.

Configuration validates checked native/header expansion, existing codec bounds
and 1..=64 channels before allocation. Layer and native packet bound are fixed
physical-session properties; directional codec budgets/channel counts can
differ. Replacements must retain that physical format. `offer` rejects packet
size or shared-queue pressure before changing a compressor context. A packing
engine refusing a pre-admitted compressed record is an explicit terminal
invariant error, not a silently dropped context update.

`poll` considers due feedback first regardless of `allow_data`, preserving the
legacy feedback priority. That flag controls only source/repair/retransmission
production. The outer owner charges every emitted body, including feedback, to
the same selected-carrier budget; it supplies actual overhead and transport
backpressure. It combines the separate wake components with its pacing and
transaction deadlines. The library supplies no extra uncharged bandwidth.

`accept` may strip channel tags in its mutable authenticated workspace. A
malformed authenticated body is a terminal protocol error; partially processed
feedback is not promised to roll back. It validates nonempty retained body
bounds, channel indices, feedback block lengths and existing inner grammar.
Returned native bytes remain valid until the next mutable call.

## Drain and policy changes

`send_drained` means all packing queues are empty and every retained source is
confirmed. `receive_drained` means no ready native packet, incomplete native
bytes or unadvanced source debt remain. Replacements require the corresponding drained state,
accumulate old algorithm/header counters, reset only that direction's channel
and header contexts, and install the caller's authenticated number floor. Late
old sources increment the existing duplicate observation; old feedback cannot
update fresh senders. Security counters, replay state and keys remain outside
and are never reset by these operations.

The legacy runtime keeps proposal/digest agreement, admission stopping,
per-direction barriers, terminal control-write custody, the original absolute
transaction deadline, requester outcomes and native-write accounting. It uses
these hooks only at its existing barrier points. No local reset authorizes a
peer switch. Migration of that private TLS policy grammar into the stable common
control service remains SW-15/FIX-11 work, including duplicate/lost replies,
matching digests, bounded retries, original deadlines and drain barriers.
SW-13 internal policy changes do not replace SW-11 switching between Swift and
the other record profiles. RLNC, parity, rolling, packed, proxy and all 47 P-*
mode-parity gates remain in scope.

## Known legacy limits and evidence plan

The existing channel-feedback packer reserves the worst-case 140-byte block
before asking a receiver for feedback. Codec configurations accept 64..139-byte
datagram bodies, but that composition cannot emit a feedback block at those
bounds. This extraction preserves those accepted bounds and that behavior;
it does not silently impose a new minimum or claim those small budgets work.
The current client requires path MTU at least 576 and avoids this limit. A new
common selected profile may reject such an unsupported composition at setup
until separately specified and tested feedback packing supports it.

The legacy client already fixes native layer and maximum packet size for both
directions and across policy changes. Enforcing that physical-format invariant
does not remove an implemented client option. New carrier composition must keep
requested/effective settings and unsupported combinations observable.

The [extracted implementation](../../crates/l2tunnel-swift/src/records.rs) and
[eight focused regressions](../../crates/l2tunnel-swift/src/records/tests.rs) are
on disk, and the [legacy runtime consumer](../../crates/l2tunnel-runtime/src/swift.rs)
delegates its data algorithm to that implementation. The source-stable
[focused receipt](../../work/swift-record-engine-20261113/focused-validation.json)
records eight passing record-engine regressions and all 16 existing Swift
runtime regressions, strict package Clippy and warning-denied rustdoc. The inputs
include those packages and resolved local dependencies, with concurrent
undeclared `runtime/src/secure_udp/**` and documentation explicitly outside that
focused input scope. Earlier failed compile/lint attempts remain alongside the
successful receipt. The subsequent [full aggregate](../../work/shared-session-client-20261113/validation.json)
also passed, including the [actual shared-factory composition](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs).
Selected service/native integration remains a separate gate. The tests preserve the exact
source/repair/feedback bytes and number-dependent GF behavior; exercise IP and
Ethernet literal/compressed packets with arbitrary zero tails; check shared
queue/header-context admission, multi-channel loss/reorder/repair and fairness;
bound malformed channel/feedback parsing; and prove drained directional
replacement preserves counters and rejects old feedback/data. Existing runtime
transfer, policy-switch and paused-deadline tests then exercise the extracted
consumer. The common same-socket fixture must use this complete record engine,
not only a raw single Swift stream. Tests and loopback receipts remain distinct
from native devices, Windows/Android, actual OpenVPN/HTTPS composition, ISP
classification and performance qualification.

- [x] [SWR-01] Review the pure record API, exact channel/body/number contract, physical-format invariant and preserved limits before implementation. Evidence: this design preceded the [implementation](../../crates/l2tunnel-swift/src/records.rs); the reviewed API is an implementation boundary, not an owner choice of a new wire protocol or default.
- [x] [SWR-02] Extract actual packing, exact header records, channel affinity, data/feedback scheduling, native delivery and cumulative statistics without duplicate crypto or control ownership. Evidence: [pure record engine](../../crates/l2tunnel-swift/src/records.rs) and [legacy consumer](../../crates/l2tunnel-runtime/src/swift.rs), with eight pure and 16 runtime regressions passing in the [focused receipt](../../work/swift-record-engine-20261113/focused-validation.json).
- [x] [SWR-03] Prove byte-exact source/repair/feedback, full-number GF semantics, arbitrary native bytes, queue/context admission, channel bounds and loss/reorder behavior with focused regressions. Evidence: eight passing [record regressions](../../crates/l2tunnel-swift/src/records/tests.rs), including frozen source/feedback and independently calculated GF repair bytes at seed `0x1_0000_0007`, 16-channel loss/reorder/duplicates, IP/Ethernet zero tails, context-preserving queue refusal and malformed bounds.
- [x] [SWR-04] Preserve negotiated directional drain/reset hooks, late old-data/feedback rejection and cumulative counters without resetting security state; retain full SW-11 and original transaction deadlines. Evidence: passing pure directional-reset/floor/stat tests and all existing [runtime switch/deadline regressions](../../crates/l2tunnel-runtime/src/swift.rs), including silent proposal/barrier and blocked terminal-control-write cases. These are hooks and retained Swift-internal policy behavior; full SW-11 remains open.
- [x] [SWR-05] Consume the record engine from the legacy runtime and remove its duplicate data algorithm while preserving public runtime APIs, v2 wire, pacing/charged feedback, native accounting, policy barriers and terminal-report behavior. Evidence: the [consumer delegates packing/recovery/header work](../../crates/l2tunnel-runtime/src/swift.rs); all 16 legacy runtime tests passed, including actual two-runtime loopback traffic and paused-clock deadline/terminal reporting. This does not qualify a native device or the target common carrier runtime.
- [x] [SWR-06] Compose the complete extracted engine through common protected records on the original selected UDP socket, with authenticated User/Control dispatch, exact bytes, loss/reorder, bounded control and separate common-session lifecycle gates. Evidence: the [real factory composition](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) uses the full extracted Engine, actual Noise/member roots, common AEAD, fixed reliable control and original UDP pair for both covers/profiles; exact bidirectional bytes, charged loss/duplicates/reordering and key generations passed in the [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json). Local data-scope staging is not negotiated SW-11.
- [x] [SWR-07] Record source-stable focused tests, formatting, warning-denied workspace checks and the required aggregate result; distinguish finite library/runtime fixtures from native and platform validation. Evidence: the earlier [pure/runtime focus](../../work/swift-record-engine-20261113/focused-validation.json) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json) passed with explicit source identities. Native devices, network performance and Windows/Android execution remain separate.
- [x] [SWR-08] Expose bounded, nonmutating per-channel packing/recovery observations, including current RTT/RTO, retransmission and retained-source debt; preserve exact wire bytes, directional replacement and separate retired aggregate statistics. Validate asymmetric channel counts and all64 channel indices before reporting this child complete. Evidence: [Sender observations](../../crates/l2tunnel-swift/src/sender.rs), [current-channel API](../../crates/l2tunnel-swift/src/records.rs) and12 passing [record tests](../../crates/l2tunnel-swift/src/records/tests.rs) in the [source-stable focused check](../../work/secure-udp-performance-focused-20261113/attempt-4/validation.json). Tests prove observed/unobserved exact wire equivalence, asymmetric1/64 directions, out-of-range rejection, replacement/current-versus-retired statistics and retained retransmission custody.

## Bounded cross-channel receive service

Status: **implemented and contract-tested**, with finite protected-UDP/native-
descriptor integration tests. Immutable TAP observations are recorded below;
their full capture qualification remains incomplete and all eight impaired
performance observations fail the original 80 Mbit/s target.
The contract was recorded before its production edits. This is an
engineering contract for a discovered scheduling defect, not an owner decision
or a claim that it causes the remaining native throughput shortfall. The previous
`pop` always selects the lowest ready channel and leaves that channel marked
ready after success. Continuously replenishing it can postpone another complete
channel indefinitely, despite independent ordered recovery and bounded outer
native work. The existing send-side round robin and SUR-11 descriptor fairness
do not establish receive-channel fairness.

Add one bounded receive cursor, independent of send and feedback cursors. Start
the ready-bit search at that cursor and wrap once; a successful complete native
packet advances to the following receive channel. A channel without a complete
packet loses its ready hint for this call; subsequent accepted data can mark it
again. With C configured receive channels and successful `pop` calls continuing,
a continuously complete channel must be selected within C successful returns,
even if a lower channel is replenished between every call. Empty hints or an
incomplete record must not block another complete channel. Each call inspects
at most C ready hints; no additional queue, allocation, clock or I/O is introduced.

Preserve exact per-channel packet order, header contexts, compressed/source/
repair/feedback bytes and full record-number semantics. Cross-channel dequeue
order is intentionally fairer; there is no global native order across channels.
Reset this cursor only at construction or an already-drained `replace_receive`;
`replace_send` must not change receive position. Preserve all queue/work/credit
limits, native completion, authenticated barriers, floors and original deadlines.
Both retained-v2 and common-session consumers use the same pure engine.

First execute a deterministic public-API regression against the old selector:
actual classified low/high flows become ready through `offer`/`poll`/`accept`,
with a new low packet before each later dequeue. Preserve its negative receipt.
Then cover cyclic service across all 64 channels, sparse/partial ready channels,
per-channel exact order and asymmetric/drained directional replacement. Exercise
the actual protected UDP driver under both covers with bounded native output,
including blocked output and existing expiry/control/cancellation tests. Tests
prove the scheduling contract; only separate immutable native observations can
support a throughput claim. The original 80 Mbit/s target, SNL-11/FIX-04, full
SW-11, all 47 P-* modes and carrier/lifecycle/platform work remain open.

- [x] [SWR-09] Record/review the additive receive-service bound and unchanged protocol, per-channel ordering, ownership, reset and performance boundaries before production edits. Evidence: [pre-edit contract](../../work/swift-receive-fairness-20261114/design-v0.md) and [source-stable old-selector regressions](../../work/swift-receive-fairness-20261114/old-selector-attempt-1/validation.json).
- [x] [SWR-10] Reproduce low-channel starvation with actual public record APIs against the old selector; preserve a source-bound negative receipt and pass deterministic cyclic/sparse/partial/order/reset regressions after correction. Evidence: [old-selector failures with final fixtures](../../work/swift-receive-fairness-20261114/old-selector-attempt-2/validation.json) and [source-stable focused pass with unchanged assertions](../../work/swift-receive-fairness-20261114/focused-attempt-2/validation.json).
- [x] [SWR-11] Implement bounded receive round robin in the shared pure engine and verify actual both-cover protected-driver delivery with bounded output, retaining original control/backpressure/deadline/cancellation checks and separate performance claims. Evidence: [shared pure engine](../../crates/l2tunnel-swift/src/records.rs), [actual protected UDP and one-packet physical handoff fixture](../../crates/l2tunnel-runtime/src/secure_udp/transport_receive_service_tests.rs), and [source-stable focused pass](../../work/swift-receive-fairness-20261114/focused-attempt-2/validation.json).
- [x] [SWR-12] Pass source-stable focused and required workspace checks, record immutable native functional/performance observations with original targets, reconcile evidence and save an actual local checkpoint before closing this correction. Evidence: retained [focused receive-service](../../work/swift-receive-fairness-20261114/focused-attempt-1/validation.json) and [partial-custody](../../work/swift-partial-drain-20261114/focused-attempt-1/validation.json) checks, [current required pass](../../work/native-capture-observations-20261114/aggregate-attempt-2/validation.json), [fresh16-case observations](../../work/native-capture-observations-20261114/native-analysis-attempt-1/validation.json), [reconciliation](../../work/native-capture-observations-20261114/aggregate-attempt-2/postcheck/ledger-2/validation.json) and [actual source checkpoint](../../work/native-capture-observations-20261114/checkpoint-attempt-1/validation.json). Eight original impaired80 targets remain failed; this scoped evidence/checkpoint deliverable does not close their parent performance requirement or full SW-11.
- [x] [SWR-13] Reject receive-direction replacement while any partial native length prefix or payload remains, even when all received sources have advanced and pending-source count is zero. Preserve exact suffix recovery, header contexts, history/feedback semantics and authenticated drain barriers; verify partial-prefix/payload/gap and replacement refusal without treating source receipt as native completion. Evidence: [six independent old-source failures](../../work/swift-partial-drain-20261114/old-source-attempt-1/validation.json), [unchanged record/policy/runtime regressions](../../work/swift-partial-drain-20261114/focused-attempt-1/validation.json) and [required frozen-source workspace pass](../../work/swift-partial-drain-20261114/aggregate-attempt-1/validation.json). This closes the scoped pure receive-custody correction, not native performance, SWR-12 or full SW-11.

The [old-selector run](../../work/swift-receive-fairness-20261114/old-selector-attempt-1/validation.json)
reproduces both intended assertion failures with stable inputs and the production
engine byte-identical to the preceding commit. The pure public-API test returns
another low packet rather than the complete high packet; the actual protected
UDP/one-packet native-output fixture likewise observes the wrong second physical
handoff. This is a correctness/fair-service defect, not a measured explanation
of the historical throughput gap. No prior test assertion or deadline changed.

The first corrected-source focused attempt exposed a new fixture readiness
defect after the pure regressions passed: simulated WouldBlock clears reactor
readiness without making the underlying socket unwritable. The fixture now
re-registers that same owned device on unblocking, retaining all assertions and
timeouts. A [second old-selector run](../../work/swift-receive-fairness-20261114/old-selector-attempt-2/validation.json)
again reproduces both original fairness assertions with those exact corrected
fixtures. Both earlier negative runs and the failed focused attempt are retained.

The [second focused attempt](../../work/swift-receive-fairness-20261114/focused-attempt-2/validation.json)
passes all 55 Swift library tests, 102 secure-UDP runtime tests, retained Swift
runtime tests, the complete shared client-core/API suite, strict Clippy and
warning-denied rustdoc. Compared with the second old-selector run, its only
non-document input difference is the production record selector. All regression
assertions and timeouts are byte-identical. This verifies the scheduling
correction and finite descriptor custody, separately from native performance.

The [required frozen-source workspace check](../../work/swift-receive-fairness-20261114/aggregate-attempt-1/validation.json)
passes 1,659 Rust cases including doctests, 349 Python tooling cases and 1,658
simulator cases, plus formatting, strict Clippy, rustdoc and CLI checks. Its
non-document inputs match the [immutable optimized build](../../work/swift-receive-fairness-20261114/native-build-attempt-1/build-receipt.json),
binary `f4a55068de79621b44737b33c26c4648042fd4e66b34e70a2074d406cc4f56ba`.
These are local Linux checks, not remote CI, Windows/Android or real-device tests.

The [fresh independent native analysis](../../work/swift-receive-fairness-20261114/native-analysis-attempt-1/validation.json)
retains all 16 observations on that binary. Exact useful bytes/hash/EOF,
authenticated control, policy, manual reconnect, thread observations and owned
cleanup verify in every case. Full case/capture evidence verifies in 14 cases;
the overall analysis remains **failed/incomplete**. Case02, multithread media-like
clean, retains `tool_failure`: its WAN-a, WAN-b and native-a tcpdump logs report
24,979, 22,768 and 12,017 packets dropped by the kernel. A complete 24-key probe
drain does not waive those losses. Case03, multithread QUIC-like impaired, retains
a native ICMP-validator rejection in both drain and final audit; zero reported
kernel drops do not establish capture completeness. Neither failure is discarded
or reclassified as a qualified native pass.

Seven cases pass native acceptance, eight fail and one is a tool failure. All
eight impaired goodput observations fail 80 Mbit/s, at 76.627–78.681 Mbit/s; the
76.627 observation also retains its capture failure. All clean payload observations
exceed 80, while case02 still lacks capture qualification. The
[byte-exact archive](../../work/swift-receive-fairness-20261114/native-observations-attempt-1/archive-validation.json)
preserves 3,338,119,834 bytes across 761 files. Runtime A-B-B-A observations on
one binary are separate from a matched, interleaved comparison of old and new
selectors. No causal fairness speedup or default change follows. SWR-12 remains
open with its original deliverable; these gaps do not reduce its acceptance scope.

The owner's requested [fresh kernel perf comparison](../../work/swift-receive-fairness-20261114/kernel-summary-attempt-1/analysis.md)
uses two separate impaired QUIC-like runs on the same current binary. Both full
raw validators and root-resolved symbol reports pass, with zero lost perf events;
both native runs preserve their sole failed 80 Mbit/s target, exact payloads and
owned cleanup. These instrumented observations are separate from the matrix:

| Runtime | Goodput Mbit/s | Kernel cycle-period weight | System mean cores | Matched-thread switches/s |
| --- | ---: | ---: | ---: | ---: |
| Multithread | 78.182 | 69.970% | 0.6812 | 18,348.5 |
| Current-thread | 78.216 | 61.800% | 0.3298 | 6,911.9 |

Resolved inclusive kernel contexts include scheduler, epoll, TAP write and UDP
send/receive; their percentages overlap. Lower observed scheduling cost does not
produce a material throughput difference in this finite pair. The owned daemons
record zero storage read bytes and 385,024/356,352 written bytes in their
respective counter brackets. Host I/O activity and pressure remain unattributed;
these counters neither establish a storage bottleneck nor exclude buffered I/O
or indirect contention. Actual event spans (14.775/15.298 s), process-counter
brackets (16.971/16.466 s) and the 20 s useful-byte denominator are separate.
Profiler overhead is unquantified; this is not a causal bottleneck proof, a new
default or ISP/platform qualification. The previous binary's partial multithread
SWITCH-pairing failure remains unchanged in its historical receipt.

The separate [source-bound accounting report](../../work/swift-receive-fairness-20261114/source-accounting-attempt-1/validation.json)
reconciles all 16 preceding cases' two-sided telemetry within each side's own
elapsed interval. Impaired forward source fill is 99.16–99.38%; feedback/control
bytes and capped credit have explicit costs. For example, case03 has 125,887
sources, 22,424 retransmissions and 104 tail repairs, exactly its 148,415 User
attempts. Its 33,538,822-byte combined recovery residual cannot distinguish
retransmission from repair byte costs. These are not exact 20-second application
or post-qdisc capture cohorts. The positive `header_bytes_saved` delta counter
does not subtract literal-record tags, so it alone cannot reconstruct exact
admitted native bytes. No loss multiplier or throughput acceptance changes.

The [offline sender TCP_INFO comparison](../../work/swift-receive-fairness-20261114/tcp-info-comparison-attempt-1/validation.json)
independently decodes the saved 248-byte Linux counter values for all eight
impaired cells in each of the previous and current matrices. Each socket's
first/last read bracket is contained in its original measurement; sums retain
those distinct intervals. Current-case retransmitted-byte sums range from
3,281,168 to 4,740,752 bytes across 16 sockets. They are sender-kernel counters,
not observed TAP overlaps, delivered duplicates, Swift recovery bytes or an exact
20-second aggregate. No subtraction from differently timed wire/application
counters or causal before/after conclusion is valid. The current matrix's failed
capture and performance verdicts remain unchanged.

The preceding independent source review found a distinct incomplete-stream drain concern:
`Receiver::pending` counts source debt, while a partial native record can remain
in its stream after source advancement. The former engine drain predicate did
not inspect those bytes. SWR-13 below corrects that separate custody defect;
the earlier review did not establish a native corruption or honest policy-switch failure.

The parent acceptance gates are not completed by these scoped results.

## Partial native receive custody

Status: **implemented, contract-tested and workspace-checked** for SWR-13.
The following contract was recorded before
production edits in the [saved design](../../work/swift-partial-drain-20261114/design-v0.md). Source review
confirms that `Receiver::advance` transfers contiguous source bytes into its
ordered stream and advances `base`. `pending()` intentionally counts only
`end - base` source debt. A partial native length prefix or payload can remain
after that count reaches zero. Once `Engine::pop` clears the incomplete channel's
ready hint, the previous drain predicate can incorrectly allow replacement to
discard those bytes. This is distinct from receive-channel scheduling and is
not evidence of a native corruption or honest policy-switch failure.

Add an immutable, allocation-free internal receiver query requiring both no
unadvanced source debt and an empty ordered byte stream. The shared record
engine must require that query for every receiver in addition to its existing
cleared ready hints. Keep public `pending()` semantics and observation units
unchanged. A source gap, partial prefix, partial payload or unconsumed complete
native packet prevents receive replacement. Rejection must preserve packet
custody, configuration, number floors, receive cursor, header contexts and
counters; a later valid suffix must recover the exact original bytes once.

Retained history below `base`, reusable storage and ordinary owed/repeated
feedback do not alone prevent replacement after native delivery. Preserve
duplicate/history/feedback behavior, full record numbers and the existing
reset accounting. No clock, queue, key, wire format, timer, deadline or policy
state is added or reset by this correction.

Before editing production, preserve independent old-source failures for the
partial-prefix and partial-payload drain query and replacement refusal using
actual offer/poll/accept/pop APIs. A genuine split-prefix witness packs a
244-byte literal packet, its one-byte literal tag and two-byte length prefix
into 247 bytes of a 248-byte source, leaving one byte of the following record's
length prefix. A 400-byte literal packet provides the partial-payload witness.
Also verify exact suffix recovery after refused replacement, real source-gap
debt, header state, retained history, ordinary feedback and successful reset
only after consumption. No test injects private stream/source/ready state.

A correct sender must drain both queued bytes and unconfirmed sources before
its authenticated barrier. Unemitted or unconfirmed suffix bytes therefore
prevent its completed drain. An inconsistent authenticated barrier is an
adversarial protocol-contract case, not a normal sender outcome. Preserve the
coordinator's existing protocol rejection when receive flushing has neither a
deliverable packet nor a drained direction; it must not reset reception or emit
BarrierAck in that case. Existing valid two-peer policy transitions must still
complete within their original deadlines. No new wait/retry state is proposed.

Root owns production, this ledger, formatting, all tests/builds/native commands
and Git. A worker owns only the new pure regression module and its declaration;
other workers review policy hooks and capture diagnostics without repository
edits. Freeze sources during recorded old/focused/full checks. Run the required
workspace check after focused recovery/record/policy/runtime regressions. Native
performance, capture gaps, SWR-12, 80 Mbit/s, full SW-11, all 47 catalog gates
and carrier/lifecycle/platform requirements retain their original scope.

The [old-source negative receipt](../../work/swift-partial-drain-20261114/old-source-attempt-1/validation.json)
reproduces six independent intended assertions with unchanged committed
production and stable inputs: prefix/payload drain query, replacement refusal
and actual Coordinator/record-engine policy hooks. In the latter two cases the
old implementation returns success after resetting reception and queuing
BarrierAck for deliberately inconsistent peer control. This is not an observed
honest-sender or native failure.

The [source-stable focused pass](../../work/swift-partial-drain-20261114/focused-attempt-1/validation.json)
passes all 67 Swift library tests, 102 secure-UDP runtime tests, 16 retained
Swift runtime tests, 233 shared client-core unit tests and 19 public API tests,
strict Clippy and warning-denied rustdoc. The only non-document differences
since those old-source failures are the receiver custody query and shared
record-engine drain predicate; all regression assertions/timeouts are unchanged.
The 12 new [record](../../crates/l2tunnel-swift/src/records/tests/partial_drain.rs)
and [real policy-hook](../../crates/l2tunnel-swift/src/policy/tests/partial_drain.rs)
tests verify partial prefix/payload, exact suffix/header recovery, source ACK
versus native completion, source gaps, opposite-direction preservation, history,
feedback and replacement state. Policy tests call the logical authenticated
message boundary directly; they are not new encrypted socket or native evidence.
After a protocol fault they inspect the retained engine directly, without
asserting that a runtime may continue the failed session. Existing real two-peer
loss/barrier and protected runtime tests also pass.

The [required frozen-source workspace check](../../work/swift-partial-drain-20261114/aggregate-attempt-1/validation.json)
passes 1,671 Rust cases including doctests, 349 Python tooling cases and 1,658
simulator cases, plus formatting, strict Clippy, rustdoc and CLI checks. All
recorded inputs remain unchanged during that check. This is local Linux
verification; no new immutable release/native/performance measurement,
Windows/Android build, remote CI or real-device/ISP result is asserted. The
preceding binary's native/perf receipts remain tied to that binary. SWR-12 and
all original parent performance, carrier, lifecycle, full SW-11 and catalog
requirements remain open.

The subsequent [capture-observation correction](secure-udp-diagnostics.md#native-capture-observations)
now records a [required frozen-source pass](../../work/native-capture-observations-20261114/aggregate-attempt-2/validation.json)
and a [fresh immutable16-case native matrix](../../work/native-capture-observations-20261114/native-analysis-attempt-1/validation.json)
that includes this receive-service and partial-custody code. All16 capture,
exact-payload, control, policy, manual-reconnect, thread and cleanup observations
are verified. Eight clean cases pass; eight impaired cases fail only the
unchanged80 Mbit/s target at77.190–78.680 Mbit/s. The
[additive field audit](../../work/native-capture-observations-20261114/additive-observation-analysis-attempt-1/validation.json)
retains original verdicts and distinguishes counter projection checks from
reproduction of the pinned production PCAP parser. The historical two capture
gaps remain failed observations. The separate
[same-binary kernel comparison](../../work/native-capture-observations-20261114/kernel-summary-attempt-1/analysis.md)
observes lower system CPU and switching with current-thread and unchanged
78.140 Mbit/s goodput; one instrumented observation per model establishes no
causal throughput gain or default change. The
[actual source checkpoint5df423ae05e0cb1e84dbbc6cef971b0c5851bf7e](../../work/native-capture-observations-20261114/checkpoint-attempt-1/validation.json)
completes SWR-12's scoped reconciliation/observation/checkpoint deliverable.
Parent80, full SW-11,47-mode and carrier/lifecycle/platform gates remain open.
