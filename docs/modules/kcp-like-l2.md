# KCP-like recovery for Ethernet

Status: implemented, with protocol checks, authenticated Linux-hosted service
integration and native Linux UDP/TAP execution. The ordering and feedback
follow-up passed the [aggregate local gate](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-03/result.json),
including strict Clippy, Rust tests, documentation and 1,895 Python tests with two
subtests. The isolated fast-ACK correction is checkpointed in commit `11528b1`;
that commit does not include the wider native-policy integration.
Native single-flow performance fails the 70+ Mbit/s target. Other carrier plans
have configuration inspection evidence, not this mode's native execution;
Windows and Android runtime support is not qualified by this work.

## Selection and ownership

`CompactRecovery::KcpLike(KcpLikeConfig)` selects one recovery policy in the
existing Compact ARQ owner. Common still owns authentication, replay protection,
management, channel admission, aggregate pacing, physical send receipts and
negotiated configuration epochs. No second ARQ owner, FEC engine, C FFI, OS handle
or real clock is added to a protocol library. Existing recovery policies remain
unchanged. The packet grammar remains the current compact algorithm union; this
profile is not interoperable with a KCP endpoint.

The new policy adds no fixed per-data-packet KCP header. It uses the existing
Compact source/attempt union and authenticated feedback; native unit headers,
fragment descriptors, packing and carrier protection still consume actual bytes.

The canonical recovery discriminator is 4. Its existing 16-byte policy slot holds
four big-endian u16 fields (`fast_resend`, `interval_ms`, `minimum_rto_ms`,
`maximum_rto_ms`) followed by eight required zero bytes. The descriptor size is
unchanged. The complete authenticated configuration digest covers all fields;
peers lacking this discriminator reject it. Existing catalog membership and drain
barriers apply to switching. This is not fresh-DH rekey integration.

## Recovery behavior

The reference is the repository's pinned upstream C KCP revision
`8004f7eba5d1bf33f0691eef5f887f2cd3140cb5`, especially `ikcp_update_ack`,
`ikcp_parse_fastack` and `ikcp_flush`. KCP-like borrows conservative fast ACK and
the nodelay=1 timeout increment while retaining Compact's cumulative prefix,
selective bitmap, receiver-delay subtraction and exact transmission serials.

A fresh, distinct echoed attempt contributes at most one fast-ACK event to a
missing attempt. Within a receive batch, a higher source with a later attempt
serial supersedes the prior candidate; a late lower source does not erase that
evidence. The echoed source must itself be acknowledged, and its actual payment
must postdate the missing attempt. Periodic repeats preserve positive receipts
but do not create additional fast-ACK evidence. The negotiated threshold schedules a selective
retry without waiting for the ordinary timeout. ACK batching uses the separately
negotiated feedback interval and packet threshold; `interval_ms` is the estimator
granularity, not an unconditional retransmission period or hidden poll loop.

Before a sample the RTO is 200 ms, clamped to the requested range. Subsequently it
is `SRTT + max(interval, 4 * RTTVAR)`, also clamped. Timeout retries increase the
previous attempt's RTO by one half; fast retries preserve that attempt's timeout.
Timers start at whole physical acceptance, never encoding or application enqueue.
No source is silently discarded on exhaustion: existing explicit terminal errors,
finite attempt limits, custody and byte/count/span bounds remain authoritative.

This policy has no additional congestion window. Existing Common admission and
configured wire-rate limits still apply; disabling an extra congestion controller
does not remove capacity limits. A future adaptive outer congestion controller is
not claimed here. Genuine TLS/TCP and reliable QUIC streams retain their own
transport recovery and head-of-line behavior beneath this policy.

## Native encoding and delivery

The reusable client builder exposes three explicit Ethernet encodings:

| Encoding | Bytes and dependencies | Delivery |
| --- | --- | --- |
| Raw Ethernet | Exact frame bytes | Complete frames may bypass earlier missing records |
| Ethernet headers | Existing eligible Ethernet/IPv4/TCP context and delta encoding; exact raw fallback | Context dependencies remain ordered |
| LZ4 Ethernet | Independently compressed complete frame only when smaller, otherwise raw | Complete frames may bypass earlier missing records |

Raw and LZ4 additionally support explicit `NativeDelivery::ChannelOrdered`.
Complete later frames remain received, acknowledged and reconstructed while a
gap prevents writing them to the native device on that MUX channel. Other
channels can still deliver. Channels shared by multiple flows share this wait.
The original independent option remains `ProfileDefault`. Compact native-policy
bytes 0x84 and 0x85 select the new Raw/LZ4 combinations; original bytes and the
ARQ tag-4 reserved bytes keep their meanings. Descriptor lengths and packet
geometry do not change. Unsupported native/recovery combinations are rejected.

Fragments are created only to fit the negotiated body geometry, not to force
every frame into six pieces. Packed sources can contain multiple native units,
with a bounded flush deadline. Partial frames are never delivered. Stateless
early delivery includes reassembled large frames; the contiguous source/record
frontiers, original deadlines and deduplication tombstones remain separate, so old
holes can still recover. Header compression is not falsely advertised as
independent of its context. These behaviors differ from upstream KCP's ordered
message delivery and are deliberately labeled.

## Validation boundaries

Required focused checks cover canonical parameters and rejection, stale feedback,
actual-payment timers, timeout backoff, lost original sources, complete later
fragmented frames, late recovery, duplicate suppression and zero FEC ownership.
The shared service test must use real authenticated carrier establishment and
native byte exchange with unprivileged packet devices, plus an actual negotiated
profile switch and disconnect cleanup. This qualifies that Linux-hosted service
fixture, not physical TAP performance or Windows/Android runtimes.

The explicit exporter produces raw, header-compressed and LZ4 plans for UDP,
raw TCP, real TLS and real QUIC. Plan construction only proves representability
and storage/geometry validation. Each carrier still needs its own execution
evidence; raw TCP needs the existing privilege and namespace boundary.

The pinned C KCP study is a separate reference using real KCP bytes and a modeled
100/10 Mbit/s, 70 ms RTT, bidirectional 15% loss link. It must report seeds, all
wire bytes, accepted versus offered input, delivery distribution and undrained
debt. Open-loop Ethernet delivery is not Linux TCP throughput, and a payload
compression win on synthetic frames is not evidence for opaque TCP payloads.
The single-flow 4 MiB native TCP comparison remains a separate performance gate.

## Configuration example and distinct window domains

Generate explicit plans without opening a device:

```sh
cargo run --locked -p l2tunnel-client-core --example common_benchmark_plan -- \
  --output-dir NEW_DIRECTORY --kcp-like-l2
```

The manifest contains three encodings across four carriers. Each row supplies
the exact shared CLI flags, Common configuration and any required carrier policy.
The real daemon's `inspect-common-transaction-plan` validates these together with
the normal member/Noise credentials. Connecting or serving still requires the
selected device and the existing authenticated runtime setup.

The example uses 8192 recovery source slots and a separate 4 MiB encoded-source
byte bound in each direction, with 500 microsecond packing, at most eight packed
units, 1 ms/16-event feedback and fast-resend threshold two. These are explicit
example values, not new defaults. They are not interchangeable with either the
native pending-write queue or the TCP workload's application-unconfirmed limit.
The upstream C comparison's 4 MiB limit counts original Ethernet frames until all
of their KCP segments are acknowledged, a different byte domain.

Stateless Packed KCP-like receivers reserve one preview-completion bit per
recovery source slot (1024 bytes for 8192 slots), inside the planned workspace.
Repeated preparation skips successfully parsed sources while a prefix is lost.
Capacity refusal leaves the bit unset; ordered recovery acquisition clears it
before slot reuse. This removes repeated parsing/copying, but still scans retained
source metadata and is not a constant-time receive-work claim.

## Upstream reference observations

The [two-window pinned C study](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-like-l2-pinned-c-raw-lz4-w8192-4m-v2.json)
uses two seconds of warmup, five seconds of measurement and twelve seconds of
finite draining. It runs real unmodified KCP and generated Ethernet/IPv4/UDP
frames, including compressible content; it does not run an inner TCP endpoint or
execute the modeled authentication. Its raw 8192-segment arms exceed the 256
packet modeled output queue during KCP flush bursts and retain substantial debt.
LZ4 arms deliver about 69.7/69.6 Mbit/s at a 70 Mbit/s offered rate, with 532/473 ms
admission-to-delivery P99 and zero accepted-frame debt. The
[128-segment control](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-like-l2-pinned-c-raw-lz4-w128-4m-v2.json)
is window-limited. Neither establishes Rust parity or a compression benefit for
opaque TCP payloads. Local queue drops are reported separately from the specified
15% link erasures; offered, admitted, delivered and acknowledged work stay separate.

## Native integration findings

The first native runner attempt failed in its credential-only preflight before
creating a namespace. The runner now represents that stage explicitly without
traffic-layer fields; actual traffic rows still require complete, matching CLI
policies. The failed receipt is retained.

The [first Linux TAP three-encoding run](../../work/kcp-like-l2-native-20261120-v2/results.json)
completed the dependent header-compression arm at 7.673 Mbit/s, 7433.121 ms
first-write-to-complete-read P99 and zero steady inner TCP retransmissions. All
27,651 fully submitted application records were read; 236,021 offered records
were not submitted before the offer cutoff. Raw and LZ4 arms terminated with a
protocol error before a valid complete measurement. All captures reported zero
capture drops and every owned namespace was removed.

A three-source protocol regression reproduced the stateless failure: receive
source 2, then 0, while 1 remains absent and no native poll has run yet. The
ordinary validated-batch rehearsal used ordered preparation over the entire
retained receiver, mistaking already complete source 2 for an unresolved context.
The independent path needs the same exact decoding and rollback validation with
independent complete-frame preparation. Silently swallowing `UnresolvedContext`
or removing semantic validation would not fix that ownership mismatch. The
dependent profile's original validation contract remains required.

The fix adds an explicitly selected independent validation rehearsal using the
same bounded journals and real body decoding. The original validated-batch API
retains its strict behavior. A temporarily full native unit-ID window is also
retryable during independent preview; ordered envelope identity checks are still
mandatory after the gap closes. The minimal three-source regression, a two-unit
window case and a 128-frame two-channel DATA/ACK loss replay pass. The full codec
and aligned library checks pass together (60 aligned and 151 codec tests, with
one preexisting ignored codec test). These tests use actual fragment/feedback
bytes, physical send confirmation, exact-once native completion and final drain;
they do not infer native TCP throughput from virtual time.

The [affected Raw/LZ4 native retest](../../work/kcp-like-l2-native-20261120-v3/results.json)
uses release SHA-256
`c182c109318de6d90c858faa1c5897134923f5b41236d89ad8a212f5bd770db2`.
Both arms complete without the former protocol termination and verify every
fully submitted application record, then remove their owned namespaces. The
unchanged dependent-header arm retains its earlier binary/receipt; it was not
expensively rerun to imply a new performance result.

| Linux TAP encoding | Steady single TCP goodput | First-write to complete-read P99 | Steady inner TCP retransmissions | Fully submitted and read / offered records |
| --- | ---: | ---: | ---: | ---: |
| Raw, corrected v3 | 1.173 Mbit/s | 28,589.874 ms | 57 | 11,575 / 263,672 |
| Header deltas, v2 | 7.673 Mbit/s | 7,433.121 ms | 0 | 27,651 / 263,672 |
| LZ4-or-raw, corrected v3 | 1.182 Mbit/s | 32,779.766 ms | 61 | 11,728 / 263,672 |

These use one CUBIC socket, a 4 MiB application-unconfirmed limit, 100/10 Mbit/s,
70 ms RTT and independent configured 15% loss in each direction. Goodput counts
application bytes received during the ten-second measurement after two-second
warmup. P99 covers all fully submitted/read timestamped 512-byte records,
including subsequent draining, so it includes kernel/application queue residence
and is not an isolated tunnel decoder latency. Unsubmitted offered records are
not counted as completed work. The runner's functional `passed` status does not
mean the 70+ Mbit/s performance goal passed: all three results fail that goal.
Only UDP has this native execution evidence; other carrier plans and the
Linux-hosted service fixture are separate evidence categories.

The [packet-by-packet latency diagnosis](../../work/kcp-like-l2-native-20261120-v3/native-latency-diagnosis.md)
reconstructs every submitted 512-byte application record from both native
captures and checks the complete streams against the probe hashes. For Raw/LZ4,
first attempted write to first appearance on the sender TAP has P99
28,475.376/32,680.747 ms. First sender-TAP appearance to complete TCP prefix on
the receiver TAP has P99 254.181/259.906 ms. These are separate distributions,
not percentiles that can be added. The slowest one percent of the same records
also spend most of their time before the sender TAP.

Twenty steady TCP_INFO samples per arm show median unsent socket payload of
4,173,012/4,172,296 bytes and median CUBIC windows of 9/11.5 MSS. Native captures
confirm selective ACKs and the measured 57/61 inner retransmissions. In 55/54 of
those retransmissions, the prior copy reaches the receiver TAP before the
retransmitted copy. Thus the multi-second application queue is predominantly
before tunnel ingress, while independently delivered later segments expose gaps
to inner TCP. These observations do not prove which outer packet or particular
Linux loss-detection rule caused each repeat. The header-compressed arm changes
encoding, fragmentation and delivery dependencies as well as its realized loss
history, so it is not a controlled order-only comparison. An outer-identity trace
is required before attributing individual repeats or claiming a scheduling fix.

## Completed local verification

The [full local gate receipt](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-like-l2-gate-01/result.json)
records exit code zero for `python3 tools/check.py`, executed through the retained
bounded-resource wrapper with the simulator environment, shared Cargo target,
three build jobs and one Rust test thread. Formatting, Clippy, workspace tests,
codec no-default-features tests, rustdoc, external authenticated CLI, tool checks
and the full simulator suite pass. The simulator reports 1895 tests and two
subtests passed. This command does not run privileged or remote CI checks.

The additional native UDP/TAP runs are documented separately above, including
their failures and corrected retests. The actual shared-service test covers all
three Ethernet encodings, management, a negotiated Aligned-to-Packed epoch switch
and disconnect cleanup. Twelve generated plans and 24 client/server daemon
inspections cover selection across the four carriers. None of these closes
`TEST-12`, the pinned C `P-kcp-baseline` gate or unexecuted platform requirements.

## KCP behavioral and single-flow follow-up

- [x] [KCP-02] Correct reordered-batch fast-ACK evidence and distinguish positive receipt repeats from new fast-ACK evidence, preserving missing-source recovery. Evidence: [actual pinned C vectors and Rust checks](../../work/kcp-like-fast-feedback-vectors-20261121.md); no native performance benefit is inferred from these checks.
- [x] [KCP-03] Validate explicitly selected per-channel native ordering through authenticated Linux TAP execution, while retaining independent delivery, cross-channel progress, immediate source receipts and late-hole recovery. Evidence: [focused protocol checks](../../work/kcp-like-parity-20261121/cargo-kcp-policy-focused-03.log) and the [raw ordered UDP/TAP run](../../work/kcp-like-parity-20261121/native-raw-v1/kcp-like-l2-raw-ordered-udp/result.json) pass. This finite single-flow run does not qualify every carrier or platform.
- [ ] [KCP-04] Compare current Rust and pinned upstream C KCP with the same inner Linux TCP workload and link policy, explain remaining recovery/queue differences and demonstrate comparable measured performance. Preserve byte, window, authentication and implementation-scope differences rather than claiming full KCP equivalence.

The new [native upstream C reference](../../tools/kcp_native_reference.md) carries
actual Linux Ethernet/TCP through the unmodified pinned implementation. Its
first successful raw run reports 4.853696 Mbit/s and zero steady inner TCP
retransmissions, with all accepted data drained and namespace cleanup verified.
Application first-write-to-read P99 is 9726.520 ms over the complete accepted
cohort including drain. This one observation is not a KCP performance ceiling or
an implementation-wide parity result. The corresponding current Rust raw arm
measures 1.180410 Mbit/s with independent native delivery and 57 steady inner TCP
retransmissions. Explicit per-channel native ordering measures 6.741888 Mbit/s,
zero steady inner retransmissions and application P99 8543.182 ms. All accepted
records drain. These runs use one Linux CUBIC connection, a 4 MiB application
outstanding cap, two seconds of warmup and ten seconds of measurement on the
100/10 Mbit/s, 70 ms RTT, bidirectional 15% loss link. This is a favorable finite
Rust/C comparison, not a 70+ Mbit/s result or a universal KCP equivalence claim.
[Native C receipt](../../work/kcp-native-reference-20261121-raw-v2/result.json)
and [independent Rust receipt](../../work/kcp-like-parity-20261121/native-raw-v1/kcp-like-l2-raw-udp/result.json).

The C reference retains ordered KCP messages, its own segmentation, an 8192
segment receive window and a 4 MiB encoded-message send cap. Rust retains Common
framing, authentication, source/attempt identity and byte/count/span admission.
The windows therefore have different byte domains. Neither implementation owns
the inner endpoint's congestion window. Both ordered runs show inner TCP growth
limited by its congestion window despite zero steady retransmissions. Earlier
TCP_INFO receipts do not contain HyStart detector counters, so they cannot prove
which Linux mechanism selected the early slow-start threshold. Finite repeats
and causal analysis remain necessary for KCP-04.

### Upstream C timeout evidence

The native C reference now supports an optional bounded per-segment trace
with authenticated UDP packet numbers, KCP ACK/UNA coverage, segment deadlines
and the actual send-branch classification. The first traced attempt encountered
a harness metadata error and cleaned its namespaces. Its replacement passed
with complete traces from both peers, zero terminal debt, zero steady inner TCP
retransmissions, 6.405952 Mbit/s forward goodput and 8,445.958 ms application
P99. That P99 spans fully submitted records through drain. The diagnostic guide
defines the full and partial trace outcomes. [Diagnostic guide](../../tools/kcp_native_reference.md#optional-segment-trace) · [Failed attempt](../../work/kcp-native-reference-trace-20261121-raw-v1/result.json) · [Completed native run](../../work/kcp-native-reference-trace-20261121-raw-v2/result.json)

Of 7,714 forward timeout retries, 2,162 fired before the peer had received
any prior copy. For another 1,726, every covering feedback datagram sent by
the timeout remained absent from sender KCP input. In 2,417 cases successful
covering feedback was still on its way to the sender WAN tap and in 1,409
it had arrived at that tap but awaited KCP input. No already processed
covering ACK preceded a timeout retry. A separate 1,557 forward PUSHes were
fast retries. These figures cover the whole run. [Per-segment counts, packet witnesses and timer distributions](../../work/kcp-native-reference-trace-20261121-raw-v2/timeout-custody-audit-v1.json)

For Rust/C comparisons, retain the actual send deadline, peer feedback payment,
sender WAN arrival and sender feedback processing time as separate events.
For the pinned C wrapper, the update clock used in explicit ACK sampling
trailed the monotonic input time by a median 6 ms. This observation alone
does not establish a C defect, a Rust equivalent or a throughput benefit.
KCP-04 remains open. The six C-reference checks passed within the combined
17-test verification. The aggregate local gate also passed, including 1,895
Python tests and two subtests. This does not close KCP-04's performance gate.
[Focused verification log](../../work/kcp-native-reference-trace-build-20261121-v1/focused.log) · [Aggregate gate 08](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-08/result.json)
