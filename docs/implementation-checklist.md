# Implementation checklist and evidence ledger

The planned [meter CSR](modules/meter-csr.md) (MCSR-01..14, owner decisions
2026-11-24) gives every meter a named read-only register. One management API
reads them locally and from the authenticated peer. It covers buffers
(BP-01..BP-24 at full scope), recovery, carrier and MUX/flow meters. The
local slice (always-on collectors, local API, CLI) is contract-tested; the
meter families, the in-band remote read and the GUI remain open.

The isolated Reliable retry-enrichment draft is described in
[the receive contract](modules/reliable.md#receive-path-and-authentication-boundary).
It reuses canonical direct sources in uniquely mapped existing FEC generations;
no generation, deadline, work or ARQ cap changes. Compilation, focused checks and
native qualification remain pending. Existing CWC and Python parity gates stay open.

The selected [Block FEC systematic extent correction](modules/compact-wire-cleanup.md#exact-block-fec-systematic-extents-2026-11-17)
removes separately observed coded fill and passes the required batch18 continuation.
The [native18 observations](modules/buffer-observability.md#native18-exact-source-fill-and-remaining-admission-stalls)
confirm zero systematic fill in the observed Cauchy population and fresh cancellation
timing. All three selected data phases remain unqualified. CWC-03 and every
full-matrix gate remain open.

Current Aligned exact-source extent correction and scoped evidence are tracked in
[the cutover ledger](modules/compact-wire-cleanup.md#exact-aligned-source-extents-2026-11-17).
This removes serialized Aligned tail padding; it does not close the full CWC
acceptance gates, the remaining proxy framing work or the native performance matrix.

The current [native matrix and observer](modules/compact-wire-cleanup.md#native-matrix-and-accepted-record-observer-2026-11-17)
records eighty initial algorithm/carrier cases and separately fills independent
directions. Runtime failures and unmeasured full encapsulation quantiles remain
open; accepted-record histograms and a successful plan are not full qualification.

The [repair4 consolidation](modules/compact-wire-cleanup.md#repair4-consolidation-and-remaining-failures)
records finite QUIC forward progress, the still-failed TLS control path with
source0 acknowledged, focused receipt/error-reporting checks and passing raw
planner/preflight plus large-horizon bootstrap checks. That required Rust
aggregate retained four failures. Baseline failures, source-bound phase provenance,
full-overhead limitations and every CWC acceptance gate remain unchanged.

The [release6 continuation](modules/compact-wire-cleanup.md#terminal-settlement-and-fixed-port-tls-reconnect)
adds finite TLS reverse data evidence, observable local TCP queue control, QUIC
terminal error preservation and a focused fixed-port TLS reconnect repair. Raw
receive-range capacity is repaired in the subsequent release7 batch below;
measured-proxy deadline failures remain open. No broader acceptance gate closes
through these finite results.

The [release7 continuation](modules/compact-wire-cleanup.md#exact-raw-receive-ranges-and-release7-results)
replaces the exhausted 128-interval raw receive tracker with an exact bounded
bitmap. Swift raw forward and reverse pass at 20.3322368 and 7.6720832 Mbit/s;
simultaneous startup and Aligned Compact raw control still fail. Required checks4
pass all raw and runtime tests but retain both measured-proxy failures. The
complete selected matrix has 14 passed, 186 failed, 32 bound-exhausted and
8 not-run phases across multiple source-bound versions. Full overhead mean/p99
remains unmeasured; these results do not qualify the complete matrix.

The next [joined framing and native-admission batch](modules/compact-wire-cleanup.md#joined-framing-and-successful-native-admission-observations)
implements correlated schema3 observations and actual successful-codec admission
metadata. The buffer continuation retains the
[required batch check](../work/aligned-extents-20261117/required-buffer-checks3-attempt1/validation.json)
and [remaining-stage receipt](../work/aligned-extents-20261117/required-buffer-checks3-continuation1.json):
305 runtime and 173 raw cases pass; 195 client cases pass with the measured QUIC
callback deadline failure still open. Strict Clippy/rustdoc and the external
Common CLI probe pass. The subsequent
[diagnosed proxy run](../work/aligned-extents-20261117/proxy-timing-validation3/receipt.json)
passes 70 proxy component cases but reproduces that original deadline failure;
it does not qualify native throughput. The [affected-owner follow-up](../work/aligned-extents-20261117/required-buffer-checks3-continuation2.json)
passes the Aligned scan repair, exact CompactARQ failure snapshots and sampled
QUIC transport statistics with 306 runtime cases and strict Clippy/rustdoc.
Native validation remains separate.

The [release10 native batch refill](modules/compact-wire-cleanup.md#bounded-native-batch-refill-after-release10)
repairs a source-proven single-packet-per-turn restriction within the unchanged
native write allowance. Its actual Common/Aligned custody regression is added;
required checks and renewed native qualification remain pending.

The requested all-buffer backpressure instrumentation is tracked in the
[complete buffer coverage inventory](modules/buffer-observability.md). Nonempty
queues, residence time and downstream blockage remain distinct. The first real
export covers 12 owner reports across four failed/bound-exhausted native9 cases;
no complete BP row, full overhead quantile or full matrix gate closes through
partial diagnostic coverage.

The [native10 buffer follow-up](modules/buffer-observability.md#native10-observations-and-remaining-bottlenecks)
records a finite QUIC/Swift forward pass at 0.243264 Mbit/s, UDP/Aligned retry
exhaustion with a receiver delivery backlog, and raw setup timeout before Common.
The complete mixed-version report retains 13 passed, 186 failed, 32 bound-exhausted
and 9 not-run phases. Constant-time recovery occupancy and native batch refill pass scoped checks.
Raw setup and proxy timeline diagnostics pass their focused fixtures; the
[checkpoint evidence](modules/buffer-observability.md#native-refill-setup-and-proxy-timeline-checkpoint)
retains both measured-proxy failures and the unexplained aggregate raw custody
expiry despite its passing focused rerun.
No parent gate closes through these observations.
The [native11 continuation](modules/buffer-observability.md#native11-and-bounded-scheduling-follow-up)
retains failed UDP retry/raw setup cases, identifies shared raw transition-budget
starvation, and implements bounded phase reservation, pre-yield retained-receipt
settlement, prefix-only ARQ history work and typed count-only receive refusals.
History, runtime/client and final focused raw checks pass. The failed aggregate
and its passing focused/remaining-stage continuations remain separate receipts;
renewed native validation is pending. BP-01..BP-24 and full matrix/overhead gates
remain open.

The [native12 follow-up](modules/buffer-observability.md#native12-observed-carrier-waits-and-kernel-receive-loss)
passes affected raw/Aligned forward, genuine QUIC/Swift forward and TLS/Swift
reverse data phases. UDP still fails with 2005 receiver-kernel buffer drops;
QUIC bilateral shutdown remains unqualified. Timed carrier waits locate substantial
QUIC submission and TLS flush stalls. All-buffer intervals and full matrix/overhead
qualification remain required.

The [exact-stage and CPU-work batch](modules/buffer-observability.md#exact-staged-source-waits-and-source-proven-cpu-work)
adds per-epoch/per-incarnation sampled occupancy and true retained-source
refusal-to-admission intervals, validates unavailable/invalid provider data, and
removes source-proven duplicate ARQ selection and Aligned preview work. Required
check6 and its failed raw aggregate are retained. The final scoped continuation
passes strict workspace Clippy, corrected preview tests and all 318 runtime tests;
the intermittent raw failure remains unresolved. Native qualification is separate.
No complete BP or CWC gate closes.

The [native13 comparison](modules/buffer-observability.md#native13-service-cost-repair-and-observed-remaining-limits)
qualifies Aligned Compact forward UDP at 30.9297344 Mbit/s and raw at 5.803584
Mbit/s under the original impairment, with both requested disconnects passing.
UDP receiver kernel drops remain 105; raw sender receipt waits remain substantial.
The new exports reveal missing final protocol sampling on future cancellation.
[Management stream instrumentation](modules/buffer-observability.md#management-stream-buffer-instrumentation)
passes fifteen focused actual control fixtures and nineteen report tests;
actual cancellation sampling and same-turn raw remaining-quota scheduling now
pass the [complete required local check14](../work/aligned-extents-20261117/required-buffer-checks14-attempt1/validation.json)
with unchanged source (2267 Rust, 448 tooling and 1658 simulator cases). Native
qualification and remaining BP-16 intervals stay open. No complete BP gate closes.

The [native14 result](modules/buffer-observability.md#native14-scheduling-and-terminal-observations)
qualifies all three raw data phases, UDP forward/reverse and Swift QUIC forward.
UDP simultaneous has capture-ring drops; TLS reverse expires its original record
cap. Raw original lease expiry and QUIC peer-close remain separate failed close
observations. All eight Common final protocol/management samples are fresh;
full Swift per-channel coverage and remaining buffer intervals remain open.
[The next diagnostics](modules/buffer-observability.md#tls-dependencies-and-exact-rolling-expiry-attribution)
add actual TLS writer/input dependencies and exact Rolling failure attribution,
with focused passing coverage. The same pending batch adds bounded Swift per-channel
export and exact Rolling/Research source, decoded-handoff and feedback-budget
waits, plus exact raw token custody latency across physical completion and upper
take. The [scoped required continuation](modules/buffer-observability.md#coordinated-local-buffer-batch15-validation)
passes after two fixture-only corrections; native qualification is pending.
The [capture cleanup correction](modules/buffer-observability.md#release-before-offline-capture-analysis)
defers offline parsing until after disconnect without changing original caps;
30 affected harness/report tests pass. The [native15 continuation](modules/buffer-observability.md#native15-dependencies-and-failure-attribution)
qualifies UDP simultaneous and raw/QUIC forward data, while retaining raw reverse
retry exhaustion, Rolling decoder/debt and raw bootstrap failures, TLS original
bound exhaustion and QUIC peer-close failure. Sixteen native buffer exports pass
parsing; complete BP coverage and the full current-build matrix remain open.
The [selected Pipeline FIFO-head provider](modules/buffer-observability.md#selected-pipeline-fifo-head-intervals)
adds actual per-flow refusal-to-pop intervals with explicit omitted/terminal
coverage; coordinated local validation passes below, with native qualification pending.
The [same batch](modules/buffer-observability.md#pending-acceptance-and-bounded-decoder-dispatch-correction)
implements Swift actual carrier-acceptance timing and bounded Rolling copy-phase
dispatch with unchanged work charges and deadlines. Their [scoped required checks](modules/buffer-observability.md#coordinated-local-buffer-batch16-validation)
pass after correcting one obsolete Swift no-witness fixture. Native qualification,
native failure corrections and full original mode gates remain open.
The [concurrent local-shutdown harness](modules/buffer-observability.md#concurrent-requested-local-shutdown)
passes 32 affected Python tests and retains original bounds and every endpoint
failure. It removes serial request ordering, without claiming bilateral drain.
No parent gate closes, and historical failed receipts remain preserved.
The [native16 receipt](modules/buffer-observability.md#native16-observed-admission-waits-and-unresolved-failures)
validates actual Pipeline wait exports and concurrent TLS/QUIC local disconnect,
but all four selected data cases remain failed, bound-exhausted or not run.
No native throughput, full BP row or same-build matrix gate closes.
The [batch17 observations](modules/buffer-observability.md#execution-stage-and-output-write-wall-timing)
add execution wall timing, bounded regular-file output isolation, actual Reliable/
Block FEC gauges and sealed-head waits, and first-failure raw proof diagnostics.
These pass [coordinated local validation](modules/buffer-observability.md#coordinated-local-buffer-batch17-validation);
native qualification, full buffer coverage, original native overhead and the
requested current-build matrix remain open.

The [native17 evidence](modules/buffer-observability.md#native17-observed-dependencies-and-residual-fec-fill)
qualifies three finite raw/QUIC/Aligned-Cauchy data phases and validates sixteen
buffer exports. TLS workload/close and Rolling original-expiry failures remain.
It also confirms residual serialized Block FEC systematic padding and missing
execution-timing handoff on successful future cancellation. Both require
correction; full BP, original-native overhead and same-build matrix gates stay open.

The follow-up cancellation guard, bounded execution-report validation, static
GF multiplication and reserve-only empty receiver pools pass the
[required batch18 continuation](modules/buffer-observability.md#coordinated-local-buffer-batch18-validation). Their [source and measurement boundaries](modules/buffer-observability.md#cancellation-timing-and-bounded-execution-validation)
retain original caps and distinguish primitive microbenchmarks, constructor
write counts and actual native performance. No complete gate closes.

The [native18 continuation](modules/buffer-observability.md#native18-exact-source-fill-and-remaining-admission-stalls)
retains the original benchmark quotas despite changed derived owner sizes.
Rolling Bank construction falls from about 8.1 seconds to about 0.10 seconds,
but its decoder/debt expiry remains. Cauchy records 57.016339 seconds of completed
staged-source admission waiting; Cauchy and QUIC exhaust their original workload
bounds. Exact identity/frontier and selected-wake/QUIC ticket observations remain
the next implementation work. No passing throughput or full BP row is inferred.

The [batch19 staged-source and selected-wake implementation](modules/buffer-observability.md#exact-staged-identity-and-selected-wake-observations)
and [QUIC ticket custody](modules/buffer-observability.md#exact-maintained-quic-ticket-custody),
plus [same-budget Rolling encoder batching](modules/buffer-observability.md#same-budget-rolling-encoder-batching),
pass [coordinated local validation](modules/buffer-observability.md#coordinated-local-buffer-batch19-validation).
The [native19 continuation](modules/buffer-observability.md#native19-exact-admission-barriers-and-lower-quic-acceptance)
qualifies one finite QUIC forward phase at 0.2826496 Mbit/s; Cauchy/TLS exhaust
their original workload bounds and Rolling reaches its original recovery expiry.
It identifies a 9.003333-second Cauchy oldest-hole admission barrier and 51.924798
seconds of QUIC User ticket first-poll-to-queue-acceptance waiting. All twelve
buffer owners validate. Identity attachments do not create another wait union,
and selected Pending time is not buffer backpressure. All original algorithm,
resource and coverage gates remain.

The [batch20 implementation](modules/buffer-observability.md#batch20-ack-coverage-and-decoder-progress)
adds exact successful ACK coverage to the same staged-wait identity and batches
Rolling decoder GF work under the original byte allowances. Original decoder
arrival/admission and returned-only expiry phase details distinguish earlier
residence from retained job custody. The affected local continuation passes 813
Rust and 45 Python cases, strict Clippy and rustdoc; unchanged passing check19
stages are reused. [Native20](modules/buffer-observability.md#native20-ack-retirement-and-rolling-pre-admission-residence)
qualifies one Cauchy forward case at 0.6046848 Mbit/s and identifies exact ACK
retirement at its maximum staged waits. Rolling still expires: the matching job
spent 4.947542 seconds before decoder admission and 53.286 ms in decoder custody.
All original caps and open parent gates remain, including the documented
Cauchy/Python recovery-policy differences.

The [batch21 continuation](modules/buffer-observability.md#batch21-scanning-and-actual-pending-context)
integrates same-budget Rolling coefficient scans and bounded genuine QUIC
DATAGRAM Pending context, plus exact restored-source ARQ refusal-to-admission
intervals with prepaid per-slot identities. Scoped local validation passes all affected
suites, strict Clippy/rustdoc, formatting and report validation.
[Native21](modules/buffer-observability.md#native21-actual-pending-and-restored-admission-observations)
qualifies one genuine QUIC forward case at 0.3231936 Mbit/s and observes an actual
763,391 us Pending ticket. Cauchy still exhausts the original phase bound; both
restored-source observers validate with zero actual refusals. Rolling still
expires after 4.962090 seconds before decoder admission. All original quotas,
deadlines and parent gates remain; these finite results do not close full BP or
matrix acceptance.

The [batch22 receiving-boundary continuation](modules/buffer-observability.md#batch22-exact-receiving-ownership-boundaries)
adds actual ordered recovery-source handoff refusal/release for shared
Aligned/Packed and Compact variants, plus actual Rolling/Research data-head Busy
timing. Optional state and runtime snapshot copies are prepaid; Compact facade
construction preserves the exact validated plan. Scoped local validation passes
569 affected Rust cases, 63 report cases, strict Clippy/rustdoc and formatting.
[Native22](modules/buffer-observability.md#native22-receiving-refusal-observations)
validates fresh Cauchy receiver-handoff exports with zero actual refusals and
Rolling server data-head Busy intervals totaling 6.730421 seconds across 895
staged episodes. Cauchy still exhausts its original phase bound; Rolling still
expires, with no qualified throughput in either case. Full BP-05/BP-10 and
matrix coverage remain open. No original quota, timer, work allowance, recovery
behavior or full parent definition changes.

The [six-blocker batch](modules/python-behavior-alignment.md#six-blocker-correction-batch-2026-11-18)
implements source-bound named-reference checks, explicit selection of independent
CompactARQ rather than ordinary Cauchy, retry enrichment of live Cauchy generations,
and cooperative Rolling/Research work continuation. The queue-service correction
preserves the original budgets and lifetimes. Cauchy passed one native forward run. Rolling still exhausted the decoder lifetime after 4.991 seconds in local ingress. The named Compact workload exhausted its local status query. The initial aggregate hit three proxy handoff deadlines. All three passed isolated on the same binary, and the remaining check stages passed separately. The two updated recovery suites passed 242 cases and workspace Clippy passed. Full PBA, BP and matrix acceptance remain open.

The [Rolling queue residence](modules/common-rolling-ingress.md#local-queue-residence)
measurement covers direct and queued decoder admissions and terminal retained ages.
The first measured forward run exceeded the 100 ms target. The third run
recorded zero threshold crossings in both directions and later terminated at a
separate sender CodecStage deadline. The fourth run exceeded the forward
queue threshold again and the sender exhausted EncoderDebt. The sixth original-plan
run exceeded 100 ms on 1,659 of 10,080 forward admissions after the row-accounting
and GF updates. All 930 reverse admissions met the threshold. RWI-03 remains open.

RWI-03 also has a [full-FIFO regression](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-queue-idle-head-green.log).
A duplicate at the head can finish without starting a new decode job. When
the targeted FIFO fills with the decoder idle, the endpoint now stages its
oldest data input before accepting the arrival. The regression checks the
old input's identity, arrival, expiry and storage bound. Native throughput
and the count of avoided refusals require a run of the changed endpoint.

This remains the persistent progress ledger. Unchecked work is required;
a design, enum, successful build or deleted implementation does not complete a
runtime deliverable. Preserve stable IDs and distinguish planned, protocol-tested,
implemented and integration-tested evidence. The [CWC-01 through CWC-18 ledger](modules/compact-wire-cleanup.md#full-implementation-and-acceptance-ledger)
retains its complete acceptance definitions and open parent gates.

The owner-authorized [current cutover](modules/compact-wire-cleanup.md) removes
obsolete production entry points and wire encoders; Git retains their history.
The owner explicitly approved deletion before every replacement capability is
ready. **Common active TUN credit and the Windows Common service entry remain
pending.** Their former entry points are not evidence that the current format
implements them. Portable helpers and Linux-hosted fixtures do not qualify a
Windows or Android runtime. No full mode or platform gate closes through deletion.
The subsequent explicit old-Records removal also retires the fixed and
refreshable final-wire wrappers. Fresh-DH integration with the sole current
Compact owner remains a required gap; the lower handshake/security primitives
and full lifecycle acceptance are retained. This is separate from negotiated
data-profile epoch switching.

Current Common Records use a five-byte kind/reader and packet-number prefix.
Data protection adds a 16-byte ChaCha20-Poly1305 tag by default (21 bytes total),
a 32-byte HMAC-SHA256 tag (37 bytes), or an explicitly selected four-byte CCM tag
or unkeyed CRC32C check (9 bytes). Management and recovery feedback use their
independent full-tag domain (21 bytes). Proxy records carrying lifecycle or
credit controls use the strong authenticated-data arm when ordinary data selects
a short check. These are record costs: algorithm union fields, packing, fragments
and the selected carrier remain additional. Raw IPv4/TCP adds 40 bytes, giving
49, 61 or 77 bytes before algorithm fields for the respective data selections;
its bootstrap geometry is separate. Genuine TLS and QUIC retain their mandatory
outer protection and transport behavior.

Rolling, Research and sliding repairs serialize the maximum encoded source
extent in their complete support. The receiver restores omitted zero columns in
bounded symbol storage; meaningful trailing zeros and the encoded source length
remain present. Current repair grammar and configuration versions must agree.
The [Rolling version regression](../work/compact-cutover-20261117/fec/rolling-version-parser-attempt2.log)
passes both current source formats and rejects prior version identifiers. The
actual UDP lost-source fixture and capture also pass, including meaningful
trailing zeros, held repair custody and actual byte charging. Runtime failures
from the broad attempt now have passing focused continuations; remaining client
service checks and aggregate closure are tracked in the cutover ledger.

See the [current verification and remaining work](modules/compact-wire-cleanup.md#evidence-and-remaining-work)
for source-bound receipts, failed attempts, captures and required aggregate-check
status. Ordinary overhead targets are not guarantees for every packet or mode.
The shared CLI/GUI service keeps requested and observed configuration separate;
API4 switches complete authenticated Common catalog entries, including native
compression policy, while API1 retains current proxy controls. Historical
checkpoint descriptions below do not preserve retired defaults or qualify the
current revision. All 47 P-* definitions, full SW-11, native/platform, raw-kernel,
resource, protocol-identification and measured QoS/performance gates remain in
scope.

The Batch16/17 closeout integrates authenticated same-owner reuse through API4,
precise Research feedback/physical ordering on original carriers, legacy
admission-time repair credit and actual source/repair batch packing, measured
Common physical receipt retention, and fixed/full raw TCP proxy composition with
bounded Aligned units. See [the closeout receipt](../work/parallel-features-20261115/parallel-closeout-scoped-validation.json).
Finite component and authenticated shared-service cases pass through preserved
scoped continuations. Raw cases use owned injected PacketIo; they do not qualify
kernel raw/TUN behavior. The required batch check and remaining stages are retained,
including 1,658 simulator passes. Its existing standalone OpenVPN impaired-close
failure remains open; no pristine full-suite result is claimed. Default-stack
construction and new fixture errors were repaired without renewing original caps.
The legacy 21-row oracle stops before physical completion, so its complete
feedback differential remains LAA-03. Full PCOR/PCO/PBA/RRP/PCOM, all47, SW-11,
native/platform/resource/performance gates retain their complete definitions.
Prior numbered checkpoint descriptions below retain their historical scope.

The Batch15 checkpoint integrates the existing measured TCP proxy controller
through retained Common original UDP and its explicit CLI/API1 presenter, bounded
Windows foreground status/disconnect/reconnect, and pure legacy sliding/hybrid
FEC components. See [the scoped Batch15 receipt](../work/parallel-features-20261115/parallel-batch15-scoped-validation.json).
The five measured selection/service/CLI cases, 14 legacy recovery and three explicit
coefficient cases, and 31 portable Windows cases pass. Required check stages and
affected Windows GNU lint/link pass through preserved continuations. The aggregate
QUIC timeout retains its passing same-binary retry with cause unqualified; optional
configuration stack growth and a Unix helper guard were repaired. This is not a
pristine single-invocation pass or native Windows execution. External receipts
remain source-bound history.
Legacy admission/packer timing still differs from the corresponding Python model
and is an active correction, not a completed parity claim. Native Windows, full
proxy/native-window, all47, SW-11, resource and performance gates remain open.

The Batch14 checkpoint implements explicit retained proxy EOF/ARQ retirement
and Common proxy CLI selection, plus actual Research Engine/Bank, original UDP
runtime and shared-service composition. The private per-connection reuse
prerequisite is protocol-tested; authenticated runtime reuse remains unfinished
and its capability stays false. See [the scoped Batch14 receipt](../work/parallel-features-20261115/parallel-batch14-scoped-validation.json).
All 14 new focused cases pass, including actual protected-UDP/shared-service
integration. The required full attempt and scoped continuations preserve initial
integration errors, a drain-fixture repair and a default-stack API repair; the
remaining required stages and affected Windows GNU lint/link pass. This is not
a pristine single-invocation suite pass or native Windows execution. Async Research
carrier ordering, complete PCOM/PCO/RRP deliverables, all47, SW-11 and full native,
platform, resource and performance gates retain their original definitions.

The preceding Batch13 integration brings three reviewed feature deltas into this
checkout: the existing fixed/full single-channel TCP proxy actor through actual
Common records and the shared service; the Windows foreground TCP/TLS TUN entry
point with a safe-dependency Wintun device; and pure recursive parity, fallback
and rolling-accumulator owners using the maintained GF/storage engines. See
[Common proxy](modules/common-tcp-proxy.md), [Windows Wintun](modules/windows-wintun.md)
and [research components](modules/research-recursive.md). External source-bound
receipts remain historical; current root validation is recorded separately in the
[Batch13 receipt](../work/parallel-features-20261115/parallel-batch13-scoped-validation.json).
The integrated checkpoint passes all 66 selected new/affected cases and the
remaining required check stages. The first full attempt retains two existing
runtime failures; each passed one same-binary recheck without a code change.
Their causes remain unqualified, so this is not a pristine full-suite pass.
Affected Windows GNU lint/link checks pass; native execution remains unverified. Windows native device
execution and complete proxy/Common acceptance remain open at their full existing
definitions. Batch14 above adds scoped retained close and Research runtime composition.
No new default carrier, periodic key exchange or reduced parity gate is implied.

The preceding Batch12 implementation installs the selected independent Compact
collection in the actual Engine/Bank/Common runtime and shared service, including
bounded source-free ACK custody with original arrival/deadline and observable
fixed-cohort limitations. It adds explicit authenticated Rolling input custody and
selected fragment Engine/Bank/runtime composition, with whole-group charging,
fresh per-fragment protection and physical completion. The original raw TCP
Full/Half owners now feed the same Common service and strict CLI, with genuine
TLS/member and initial Noise/member admission, fresh lower reconnect and unchanged
setup caps. These are implemented slices with finite protocol/protected-I/O
receipts, not complete named Python profiles or kernel/platform qualification.

The [Batch12 scoped receipt](../work/parallel-features-20261115/parallel-batch12-scoped-validation.json)
retains actual source identities, failed attempts, focused continuations and the
required batch check separately. See [independent owners](modules/connection-records.md),
[Rolling ingress](modules/common-rolling-ingress.md),
[record fragmentation](modules/common-record-fragmentation.md) and
[raw Common carrier](modules/raw-common-carrier.md). Full flow reuse, the named
1460/1500/global8192/local128/every16/copies/ACK composition, native/platform/
resource/performance, all47 and complete SW-11 remain open. External Windows,
recursive-FEC and TCP-proxy/Common commits were excluded from that preceding
checkpoint; they are integrated in Batch13 above.

The preceding Batch11 implementation adds explicit bounded benchmark ACK ingress
through actual Engine/Bank/Common ownership, requested/effective APIv4 policy and
paired resource binding; decoded-channel reverse learning in the same Pipeline;
and a pure fixed-cohort collection of independently reserved Compact owners.
Finite cases pass actual ACK backpressure and record switching, independent-owner
source/feedback loss, genuine catalog-bound Compact service setup/switching and
Rolling silent-tail native progress. These are distinct compositions: the complete
independent16 profile, raw TCP/Common installation and named8192/128/copies/ACK
profile remain open. See [ACK ingress](modules/common-ack-ingress.md),
[independent owners](modules/connection-records.md) and
[Compact composition](modules/compact-endpoint.md).

The [Batch11 scoped receipt](../work/parallel-features-20261115/parallel-batch11-scoped-validation.json)
retains109 distinct focused passing leaves and the exact failed attempts. Full
workspace formatting and Clippy pass; successful Rust targets/doctests total1,750,
with524 additional runtime passes and one streamed UDP WouldBlock failure. That
unchanged case passes an isolated rerun; its concurrent failure cause remains
unresolved. Affected rustdoc passes. The full check remains failed and its later
stages were not reached. This is not full Python, native or throughput acceptance.

The preceding [Batch10 scoped checkpoint](../work/parallel-features-20261115/parallel-batch10-scoped-validation.json)
installs explicit AlignedCompact/PackedCompact policies through actual reserved
Engine owners and the original UDP Driver. Finite integration covers lossy source
and feedback, retained authenticated feedback across delayed physical receipts,
L3 TCP context/delta/replay, exact native bytes and negotiated record switching.
All16 affected Common cases pass. Both Compact forms refuse unsupported physical
copy counts before provisioning while retaining the complete requested policy.

The full check passed workspace Clippy and formatting, with1,739 passing Rust cases
in successful targets plus522 runtime passes; one legacy Packed pressure case
failed. Its production staging loop now stops retrying unchanged sealed work in
the same burst: all22 affected Aligned/Packed cases pass with original limits and
timeouts. The two Compact endpoint/capability cases and affected strict checks
also pass. Earlier failures remain preserved; these continuations are not a full
check pass, and later full-check stages were not reached. Genuine new-profile
service setup, complete named Python topologies, native/platform/resource/
performance, all47 and full SW-11 remain open. See [actual composition](modules/compact-endpoint.md).

The [TCP scoped checkpoint](../work/parallel-features-20261115/parallel-tcp-scoped-validation.json)
adds independent verified SNI, retained raw send observations, supported CLI naming
and actual fixed/measured shared-service readiness/cleanup. Affected strict checks
and finite TLS/Unix-device cases pass; failed attempts remain preserved. Production
proxy CLI migration, Python behavior alignment and complete native/platform/
resource/performance gates remain open. See [naming](modules/tcp-carrier-naming.md),
[proxy service](modules/tcp-proxy-service.md) and [Python alignment](modules/python-behavior-alignment.md).

The preceding [Wave8 checkpoint](../work/parallel-features-20261115/parallel-wave8-scoped-validation.json)
implements [physical ARQ send confirmation](modules/arq-physical-send.md) through
Reliable/Aligned/Packed/Common, [same-flow transient UDP recovery](modules/common-flow-recovery.md),
[explicit short-source copy selection](modules/source-copy-policy.md), and
[committed Rolling feedback snapshots](modules/rolling-storage.md).
Affected protocol/runtime cases and strict checks pass; failed aggregate attempts
remain preserved. Real8192/local128/every16 old-hole recovery is finite component
evidence. Copy selection is implemented in the codec; authenticated policy and
repeated physical sends remain SCP-04. Same-flow recovery retains the original
socket/session and deadlines; replacement/restart reconciliation remains SEC-08.
No periodic fresh-DH or new cryptographic replay domain is selected. Reconnect
remains in the underlying service. Native and full-stage evidence is recorded
separately; all47 mode gates, full SW-11, complete resources, Windows/Android and
80 Mbit/s performance remain open.

This is a scoped checkpoint with open aggregate failures. The batch
`tools/check.py` invocation failed in the legacy Packed pressure case and runtime
fixture stack limits; its successful stages and exact continuations are retained.
The full simulator passed 1,658 cases. Three current Linux native cases passed;
the fourth requires a retry after bounded receipt-publication tooling was fixed.
Unverified legacy actor and fixture repairs are excluded from this checkpoint.
No full-suite pass or completed four-case current native matrix is claimed.

The preceding [scoped checkpoint](../work/parallel-features-20261115/parallel-wave7-scoped-validation.json)
adds implemented and protocol-tested [Rolling independent-short delivery](modules/rolling-records.md)
and four finite [production Common native CLI cases](modules/common-carrier-cli-native.md).
TAP/TUN with both inner appearances pass genuine outer TLS/member and inner
Noise/member authentication, all64 catalog inspection/paging, four-family
switching, exact bytes/liveness, runtime-failure API survival, fresh-session
reconnect, capture and cleanup. One representative per family is activated;
this is clean Linux IPv4 integration evidence, not full catalog or early-short
native acceptance. The shared service retains the management API after an
established backend fails. Automatic retained-state recovery, optional fresh-DH
installation, full SW-11, all47 modes, complete resources, Windows/Android and
80 Mbit/s performance remain open. No periodic exchange or new replay-domain
wire decision is introduced.

The preceding [record checkpoint](../work/parallel-features-20261115/parallel-wave6-scoped-validation.json)
provides explicit ARQ-only Aligned/Packed and finite Packed short gap/expiry
evidence. Its receipts retain their original Unix packet-device/pure scope.
Earlier checkpoint descriptions below report their then-qualified scope; current
native evidence is the finite CCN-01/02 leaf above, not completion of its parents.

UDP framing terminology is aligned with the
[datagram API and format](modules/datagram.md#project-specific-prefixes-and-exact-draft-format):
the cover names identify project-specific prefix layouts, with explicit
handshake and interoperability limits. This wording update changes no wire format,
profile selection or task status. Local check outcome and exact source hashes are
recorded in the [wording validation receipt](../work/udp-framing-wording-20261113-final/validation.json).
That receipt reports a failed aggregate check; it is historical evidence, not a
pass for this architecture update. The owner-confirmed target and unresolved
implementation choices are separated in the
[shared secure-session contract](modules/secure-session.md).

Stable IDs must not be reused. If a task splits, keep its ID as a parent gate and
add child IDs. Update this ledger and the detailed checklists with every change.
`tools/check.py` checks ID uniqueness, evidence markers and all 47 mode entries.

Follow the [parallel development workflow](development-workflow.md) for module
design, interface agreement, concurrent implementation and integration.

The additive [OpenVPN outer-wire carrier](modules/openvpn-wire-carrier.md) now
has an independently validated checkpoint: six pure wire/control cases and seven
focused runtime-crate cases, plus strict affected Clippy/rustdoc/format checks.
Its explicit opaque substrate carries the existing inner Noise/security bytes
without exporter resealing over the original UDP socket, retaining actual outer
TLS/member control. This does not install the Common Driver/service or qualify
standard dissectors, native devices, ISP treatment or any full carrier/mode gate.
The [scoped receipt](../work/parallel-features-20261115/openvpn-scoped-checkpoint-validation.json)
preserves failed unrelated aggregate attempts and exact finite evidence reuse.

The [pure mixed-record checkpoint](../work/parallel-features-20261115/pure-scoped-checkpoint-validation.json)
implements the actual reserved mixed-profile Bank, shared native pool and real
per-channel native event counts. Compact records now compose the actual rolling
recovery owner; explicit unpacked independent-short records can complete across
an older gap. Bounded Swift feedback retains complete canonical blocks under a
smaller allowance without consuming unsent debt. Focused protocol evidence is
reused by actual inputs and semantic deltas; five changed pure packages pass
strict formatting, Clippy and rustdoc. This is not full rolling installation,
complete resource admission, full SW-11 or native/platform/performance acceptance.

The [Common runtime/service checkpoint](../work/parallel-features-20261115/common-runtime-scoped-checkpoint-validation.json)
installs that same actual Bank behind the existing leased State and sole I/O loop.
Explicit typed shared-service selection passes real authenticated same-UDP
Swift→Aligned→Packed→Swift, bidirectional Unix packet-device delivery and liveness.
Held native and sealed User ownership, original caps, requested/current/physical
observations and bounded old-reader feedback retain finite affected evidence.
The standard-stack service failure was corrected by constructing the same
fallible Driver cell before polling its borrowed continuation. Complete resources,
fresh-DH/retained recovery, portable Common IPC/CLI, rolling integration, full
SW-11 and native/platform/performance gates remain open. See the unchanged
[CTS-* acceptance definitions](modules/common-transaction-state.md).

The subsequent parallel batch adds three actual prerequisites:
[rolling as a fourth pure record family](modules/rolling-common-records.md),
[managed initial Noise/member handoff](modules/managed-initial-handoff.md) and
[original datagram physical custody](modules/original-datagram-custody.md).
It retains27 distinct positive case results through one26/27 batch and an exact
single literal-fixture repair, plus source-stable strict checks for six affected
packages. The failed batch remains failed. Actual Common rolling work/completion,
timed-v2/fresh-DH Lifecycle installation and OpenVPN complete bootstrap/Parts/
Driver/service selection remain required, as do all unchanged full parent gates.

The next parallel implementation adds the
[selected Common rolling service](modules/common-rolling-runtime.md),
[actual OpenVPN complete inner factory](modules/openvpn-common-factory.md),
[explicit Lifecycle control](modules/lifecycle-control.md) and
[Common v4 shared local API/CLI](modules/common-client-api.md). The
[scoped checkpoint](../work/parallel-features-20261115/parallel-wave3-scoped-validation.json)
records60 distinct positive cases and four-package strict checks, retaining the
failed51/55 batch and its exact narrow repair. Actual selected-backend setup
dispatch removes unused backend poll scratch while reusing the existing one
setup box; standard-stack service and APIv4 cases pass. These leaves do not close full lifecycle,
carrier Driver/service, complete resources, mode parity or native/platform gates.

The preceding [original-carrier Common service
leaf](modules/common-carrier-service.md) now has actual typed four-family
service delivery and external full-64 offline CLI inspection, with requested E0
and effective authenticated E1/catalog kept distinct. Its [scoped
receipt](../work/parallel-features-20261115/parallel-wave5-scoped-validation.json)
includes affected strict checks and preserves earlier failures. Full
tools/check.py was not rerun; production native CLI startup, automatic retained
recovery, managed fresh-DH, complete resources and all unchanged
47-mode/SW-11/native/platform/performance gates remain open.

The preceding finite wave4 adds [initial-only carrier Common execution](modules/managed-common-runtime.md),
[typed failed-backend fresh reconnect](modules/generic-client-service.md) and
[external Common control/inspection CLI](modules/common-client-api.md) using
actual authenticating programmatic shared owners. The [last passed receipt](../work/parallel-features-20261115/parallel-wave4-cases-attempt-3/validation.json)
records nine exact cases in 7.936 s plus the both-cover probe in 4.131 s; the preserved
wave4 attempts together provide 26 distinct positive cases, not 26 new features.
Exact clock and structural stack regressions are repaired; pure managed
contract/controller cases do not qualify managed runtime refresh. The [final scoped validation](../work/parallel-features-20261115/parallel-wave4-scoped-validation.json) records successful runtime-only Build4,
both final affected regressions and affected strict Clippy/rustdoc/format
checks, plus checklist and diff checks. Full `tools/check.py` was not run,
avoiding unrelated suites. Initial-only adds no
periodic fresh-DH, and reconnect remains underlying carrier/session service work.
Production connect/serve/TAP startup, full carrier service, automatic retained
recovery, complete resources, all 47 modes and full SW-11/RLNC/parity/rolling/packed/
proxy/native/platform/performance gates retain their unchanged definitions.

The next common-session foundation is tracked by
[directional Aligned/Packed owners](modules/directional-record-endpoints.md),
[Swift admission/emission adapters](modules/swift-record-adapter.md),
[fallible control wrapper storage](modules/control-wrapper-storage.md),
[complete configuration encoding](modules/transaction-configuration-encoding.md),
[common configuration](modules/record-configuration.md),
[transactional queue handoff](modules/record-admission-handoff.md),
[FEC/Reliable backing](modules/record-recovery-storage.md),
[Aligned/Packed backing](modules/aligned-record-storage.md),
[common engine prerequisites](modules/common-record-engine.md),
[actual common queue storage](modules/common-queue-storage.md),
[reserved Scheduler](modules/qos-storage.md),
[reserved Pipeline](modules/pipeline-storage.md),
[reserved common Engine](modules/common-engine-storage.md) and
[in-session fresh-DH](modules/session-refresh.md).
The subsequent [mixed Bank](modules/common-record-bank.md),
[native counts](modules/common-native-counts.md),
[shared native storage](modules/shared-native-storage.md) and
[compact rolling records](modules/rolling-records.md) have their own finite ledgers.
The subsequent [actual rolling scheduler storage](modules/rolling-storage.md)
adds complete requested/observed nested heap admission over the same existing
owners. Three focused cases and strict affected checks pass; literal allocation
failure and complete record/runtime integration remain required and open.
Their leaf evidence does not close full SW-11, complete resource admission or
retained-state recovery. Existing mode, native, platform and performance gates
retain their full definitions.

The preceding actual shared queues, reserved FEC/Reliable/Aligned/Packed libraries and
explicit functional common Engine now have
[affected local evidence](../work/common-record-engine-20261114/scoped-checkpoint-validation.json).
At that checkpoint the Engine composed real profiles and queues without a selected
runtime or reserved mixed-generation Bank. Complete resources, pacing/credit/
proxy owners, full SW-11 and required stage/native/platform/performance gates
remain open. Unchanged suites are reused explicitly; passing individual tests
do not relabel a failed aggregate.

The [reserved common Engine checkpoint](../work/common-reserved-records-20261115/scoped-checkpoint-validation.json)
adds actual fixed FlowTable/MUX/Scheduler/Pipeline backing and one movable Swift
owner, then composes the selected real reserved Swift/Aligned/Packed owner.
It passed142 distinct affected cases, including32 new cases, with four bounded
parallel test processes and exact single-test repairs. Current/prepared/draining
mixed Bank was not yet installed. Complete external/nested allocation admission,
selected reserved runtime acceptance and the required full-stage gate remain open. No unaffected simulator,
platform, native or performance campaign was repeated at this checkpoint.

The [preceding448-case affected checkpoint](../work/record-composition-20261114/scoped-checkpoint-validation.json)
qualifies the selected scalar/CompleteV2/common-configuration and first pure
fresh-DH behavior with explicit reuse. Actual selected fresh-DH runtime,
reserved mixed-profile Bank/runtime, full SW-11, complete resources, retained recovery and
required full stage/native/platform acceptance remain open. The saved failed
attempts and precise repair are not relabeled as passing aggregates.

## Blocking behavior corrections — execute before new feature work

These are the highest-priority implementation TODOs from the behavior and layering audits.
An audit note, an added capability flag or a passing component test cannot close
them. Each fix requires a regression that rejects the previous behavior and
validation through its actual selected client/runtime path. Existing leaf checks
remain evidence for their stated scope, not a percentage of product completion.

- [ ] [FIX-14] Complete source/configuration-specific Python behavior alignment through the actual selected runtime, following [PBA-01..06](modules/python-behavior-alignment.md). Keep independent per-connection CompactARQ and shared directional Packed candidates distinct; replace wrong selected Rust recovery/feedback/retry behavior. Implement CompactARQ serial/RTT/receiver-delay/guarded fast retry, complete global8192/local128/every16 with physical short copies and ACK coalescing, and prioritize L3 TCP while preserving L2. Common migration and finite component tests do not close this gate; retain authentication, management, all47 modes and every existing full requirement.

The preceding [batch9 scoped checkpoint](../work/parallel-features-20261115/parallel-batch9-scoped-validation.json) added protocol-tested CompactARQ with actual Python event traces, explicit Reliable R0, protected Rolling source copies, shared proxy CLI lifecycle and native-IP TCP codec construction. Complete selected Compact configuration/runtime, named recovery topologies, full Packed composition and native performance remain open. The legacy Packed QUIC pressure failure is preserved; these finite leaves do not close FIX-14.
- [ ] [FIX-13] Replace the target Swift-specific TCP/TLS-bootstrap plus independent UDP path with the shared point-to-point secure session over the explicitly selected carrier. Preserve Swift's AEAD data behavior while moving authentication/key exchange, protection, replay, rekey and stable control behind reusable boundaries. Implement the owner-selected WireGuard-like direction through the [SEC-* gates](modules/secure-session.md), keeping original connection/socket/five-tuple continuity, HTTPS-like TLS-to-packet requirements, bounded default recovery and all record-profile functionality. No library, wire format, key migration or timeout value is selected by this documentation change; historical slices remain evidence for their original scope.
- [ ] [FIX-09] Minimize packet-path copies through explicit bounded buffer ownership. Eliminate whole-history and whole-equation-bank transaction snapshots; reuse immutable payloads and transfer owned buffers across codec, recovery, carrier and native handoffs. Count allocations and copied bytes separately from necessary GF output and cryptographic writes. Preserve bounds, original deadlines, cancellation and exact bytes under loss/pressure; do not claim end-to-end zero copy without measurement. The [sparse rolling transaction](modules/local-global-rlnc.md) now copies only modified equation rows, with bounded preallocated versions and atomic commit/abort; rank-zero originals bypass empty algebra and window scans. Its focused before/after work and correctness checks do not qualify native throughput or remaining packet-path copies. The [Swift bulk-prefix correction](modules/swift-bulk-copy.md) preserves copied bytes with measured CPU savings; impaired 80 Mbit/s and clean native capture qualification remain open.
- [ ] [FIX-01] Separate local storage from authenticated byte/record flight budgets in every packet runtime, including base UDP, its QUIC owner and raw; size delivery credit from bandwidth and causal feedback RTT. Rolling, aligned/packed and now base UDP/QUIC/raw have focused implementations; [shared packet delivery](modules/packet-delivery.md) and [raw integration](modules/raw-runtime.md) prove native flight larger than the local queue. The [source28 aggregate](../work/implementation-wave28/validation.json) passed; new native profile qualification remains open. Keep recovery retained-source byte/record limits a third independently configured and observed domain: the base ARQ default/cap of64 can remain an RTT bottleneck after native credit grows. Validate small local queues with larger real outstanding debt, exact mixed-size bytes, receiver pressure, original deadlines and full/half operation. Carry actual first-send and authenticated delivery timestamps through bounded queues; enqueue is not physical-send completion.
- [ ] [FIX-10] Separate carrier delivery semantics from user-data recovery. OpenVPN-like bootstrap may retain reliable TLS control, but `DataState` must not force every user packet through `SelectiveRepeat`. Expose authenticated datagrams and compose the selected recovery above them. Require the same selected recovery contract over supported UDP, QUIC and OpenVPN-like owners and the planned appearance profiles, explicit unsupported-combination rejection, original deadlines and shared wire accounting; capability flags alone do not complete this fix. Swift remains a data algorithm within this composition, not an independent carrier or an implicit default.
- [ ] [FIX-11] Freeze a session control envelope independently of data MUX/FEC/codec. Extract the legacy parser from the UDP owner without changing existing wire identities, then implement a negotiated stable envelope with separately typed recovery feedback. The [additive pure envelope](modules/management.md) has borrowed parsing, explicit active/draining scopes and recovery tags; its admission tests do not implement negotiation or runtime dispatch. Keep authentication, epoch/digest checks, bounded service and retry/drain barriers alive while switching data modes. Migrate Swift's private policy-control messages into this shared service without treating SW-13 as SW-11. Moving functions alone does not complete this gate; test delayed old-mode feedback, lost replies and control progress during a real switch on the selected carrier.
- [ ] [FIX-12] Move connection lifecycle and local command execution out of private CLI dispatch into a shared service API. CLI and future GUI must use the same typed profile, connect/disconnect/reconnect/apply operations, ownership and terminal results. Preserve original handshake deadlines and distinguish accepted operations from completed peer changes. The [managed TCP service slice](modules/client-runtime.md) now owns the actual CLI connection, cancellation, abort/reconnect and compression-apply path; uncertain peer outcomes remain explicit. Portable command types are separated from Unix IPC. The [swift profile](modules/swift.md) runs through the same owner and adds local `disconnect` and `reconnect` commands that report actual completion. The remaining profiles, clean peer-confirmed drain, a non-CLI frontend and platform qualification remain open; an enum or wrapper around CLI arguments is insufficient.
- [ ] [FIX-02] Make the Python high-performance composition reachable as one authenticated client profile: the explicitly named shared Packed reference with common connection-RR MUX16, actual local/global RLNC, correct retained-source bounds, compact records and the selected short-frame/ACK policy. Trace every selected option to the running data plane; do not substitute TCP/TLS frame forwarding or isolated library tests. Remove fixed-width systematic-source tail padding with explicit authenticated wire versioning, then compose compact records with the actual rolling owner; current FrameCodec/LX composition turns a 1500-byte TUN packet into two full 1500-byte outer IPv4 datagrams for the audited MTU1500 geometry. Preserve old wire bytes, arbitrary real zero tails, exact emitted-byte charging and native completion only after every physical fragment sends. The [source-pinned accounting](../work/rolling-fast30/next-step.md) is static evidence, not a native bandwidth result.
- [ ] [FIX-03] Qualify the reference local support128/global support8192/every16 geometry, retained unconfirmed sources and bounded row/history storage as distinct limits. Current `window` is global support, so adding8192 retained debt behind support128 would strand old loss. Measure and remove the decoder's full-bank copy bottleneck, then prove old-source recovery, memory/work bounds and delayed feedback before replacing the runtime global-support128 ceiling. Before widening the guard, decouple wire-ingress queue storage from recovery support; the current queue grows with `window * physical_lanes`. Qualify actual full8192 support, old losses outside local128, ring reuse, receiver Busy/Capacity, original deadlines and authenticated full/half pressure with local2. Measure global-repair GF work and feedback-induced Busy loss; clean originals and rank-one witnesses with three sources are insufficient. Design evidence: [ownership audit](../work/rolling-bdp27/fix03-retention-design.md) and [remaining geometry gates](../work/rolling-fast30/next-step.md).
- [ ] [FIX-04] Run a matched native performance workload on that composition: record the exact reference profile, sixteen forward bulk flows and its ACK-return policy, 100/10 Mbit/s,70ms RTT and15% loss; compare clean/delay controls, exact payload/confirmation, same-window wire cost and latency. Keep simultaneous reverse-bulk stress as a distinct workload. Actual forward80Mbit/s remains required. The explicit [swift profile](modules/swift.md) ran the matched workload on TAP in unprivileged namespaces at 79.7–80.5 Mbit/s, 98.8–99.7% of the simulator at equal per-datagram overhead, using the simulator's documented selective-repeat candidate rather than the FIX-02 composition; real-device qualification is open, so this item stays unchecked.
- [ ] [FIX-05] Reproduce and correct any valid management retry/buffered-arrival sequence that trips the base runtime's256-record local-arrival limit. Keep original transaction deadlines and bounded authenticated control service; use actual delayed control delivery, not a success-only local state fixture.
- [x] [FIX-06] Make the complete simulator check reject unavailable/broken required adapters and unexpected skipped tests. Preserve optional dependency behavior for ordinary simulator users; reproduce the old false pass and replace it with a failing full-gate result. Evidence: [guard regressions](../tools/test_check_simulator.py) distinguish real import/skip failures from ordinary optional use; [complete source27e check](../work/implementation-wave27e/validation.json),1658 simulator cases with no skips.
- [ ] [FIX-07] Finish the requirement-to-runtime/test audit, repair each confirmed behavior discrepancy, and remove superseded designs, duplicated progress prose and tests that do not distinguish correct behavior. Retain meaningful parser/security/deadline regressions and all historical experiment receipts.
- [x] [FIX-08] Reject packed MUX channel256 at composition setup, before any flow is created; preserve packed255/unpacked256 delivery and correct the documented Python integer repair-credit behavior. Evidence must include the formerly accepted invalid composition and valid boundary transfers. Evidence: [composition regressions](../simulator/tests/test_mux_tcp.py) reject packed256 before flow construction and confirm packed255/unpacked256 both-direction delivery; [corrected repair-credit description](modules/local-global-rlnc.md), [complete source27e check](../work/implementation-wave27e/validation.json).

## Reading order and detailed task lists

The explicit fixed and measured Common proxy slices retain complete follow-up in
[PCOM-01..PCOM-09](modules/common-tcp-proxy.md), including the finite
[measured retained composition](modules/common-tcp-proxy-measured.md). Parent proxy,
switching and platform gates retain their definitions.

Session receiver credit (owner decisions 2026-11-23) is tracked in
[MOD-RCREDIT-01..07](modules/receiver-credit.md): a processed window and drain
rate in an unreliable authenticated Credit message, gating data datagrams of
every Common profile after native Packed overran its receiver. Implemented and
contract-tested; native Packed with 16 flows at 0% loss now passes (89.0 and
71.7 Mbit/s, receive-buffer drops 0 and 1.3% instead of 31%), and Aligned
with 16 flows rose from 74.3 to 85.5 Mbit/s
([results](../work/credit-20261123b/RESULTS.md)). A burst-loss blackhole found in
the record receiver's key-generation range is closed by a sender range bound
and a range floor, now a clamp with a warning (MOD-RCREDIT-08..11). The UDP
data socket requests a receive buffer of the credit byte ceiling, which ended
Packed receive-buffer drops in native cells (MOD-RCREDIT-12). Full native
qualification is open.

Rolling TUN native release order and the return-traffic guard are tracked in
[DP-01..DP-08](modules/delivery-policy.md). DP-01..DP-07 are contract-tested;
the owner's native qualification DP-08 is open, so FIX-04 is unchanged.

The current behavior-alignment work is tracked in
[named Python compositions](modules/python-behavior-alignment.md), alongside
[TCP carrier naming](modules/tcp-carrier-naming.md) and
[fixed/measured proxy service](modules/tcp-proxy-service.md). These child ledgers
retain their complete parent gates and distinguish authored code from validation.

The common-session implementation wave is tracked in
[packet security](modules/packet-security.md),
[Noise handshake](modules/noise-handshake.md),
[carrier appearance](modules/carrier-appearance.md),
[protected record composition](modules/secure-records.md) and
[fixed reliable control delivery](modules/control-delivery.md), with
[finite CPU measurement recording](modules/secure-record-performance.md).
The subsequent same-carrier integration is tracked in
[existing-member identity](modules/session-identity.md),
[reusable Swift records](modules/swift-record-engine.md),
[real UDP establishment](modules/secure-udp-establishment.md),
[member admission and tail custody](modules/shared-udp-session.md),
[shared client factory](modules/client-secure-udp.md) and its
[real-factory composition tests](modules/common-session-client-tests.md).
The actual runtime/service integration additionally tracks
[directional scopes and typed control](modules/directional-control.md),
[one reusable Swift policy coordinator](modules/swift-policy-coordinator.md) and
[shared secure-UDP service integration](modules/secure-udp-service.md).
[Generic selected-UDP transactions](modules/generic-secure-udp.md) now track
GSU-01..GSU-10: asymmetric sender fences, complete canonical configuration,
borrowed control proofs, actual engine/device custody and selected runtime/API
integration. Explicit directional peers and complete canonical values now have
focused protocol evidence; the authenticated client construction has real
factory tests. The explicit runtime-library entry point now passes finite
same-socket/device tests, two nonzero switches and native operation-cap guards.
Explicit shared Prepared/service/APIv3 selection now passes finite paired-owner
and IPC status/switch checks. Complete-plan CLI selection/inspection/APIv3 commands
now have finite external-process evidence; production CLI TAP/TUN startup, the
complete generic IPC matrix, remaining runtime faults and full resources remain pending;
[GDI-01..GDI-03](modules/generic-secure-udp.md) retain their complete scope.
Detailed fault rows are tracked by
[GDF-01..GDF-09](modules/generic-driver-faults.md), shared Prepared/APIv3
selection by [GCS-01..GCS-09](modules/generic-client-service.md), and actual
sole-loop input charging by [RBF-04/RBF-05](modules/generic-secure-udp.md).
The explicit generic CLI plan, complete-C command and bounded inspection are
tracked by [GCL-01..GCL-08](modules/generic-transaction-cli.md), retaining the
full GCS-09 external-selection and compatibility acceptance.
The next parallel functionality batch retains production CLI/native acceptance
under [GCN-01..GCN-08](modules/generic-cli-native.md), actual generic service
failure/lifecycle cases under [GSF-01..GSF-12](modules/generic-service-failure-matrix.md),
complete control-message storage under [CMS-01..CMS-07](modules/control-message-storage.md),
and known construction admission under [KCA-01..KCA-05](modules/runtime-construction-admission.md).
The combined source-stable checks now pass2011 Rust cases including doctests,
406 tooling cases and1658 simulator cases. The finite GSF service deliverable
is qualified; native CLI acceptance and complete resource parents remain open.
See the [current aggregate](../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json).
The later APIv3 completion reply repair passes [77 affected service/local tests](../work/generic-functionality-20261114-batch2/completion-projection-focused-attempt-1/validation.json)
with4 test threads and strict client-core Clippy. The unchanged full baseline is
reused, not rerun or relabeled. The [two-lane native attempt](../work/generic-functionality-20261114-batch2/native-matrix-attempt-3/matrix-receipt.json)
retains all four failures with verified cleanup; initial QUIC-like/TUN bytes
passed, but complete native switching/reconnect/capture acceptance remains open.
The [CRS-01..CRS-07 contract](modules/control-recovery-storage.md) retains actual
fallible management ARQ backing and its now-selected three-stream consumers,
with actual partial backing release,130 complete receive-window reuse cycles,
byte-pressure and differential cases now component-tested. Reserved-control
pressure/liveness and constructor-boundary cleanup pass; literal later-stream
dependency reservation failure and full resource admission remain open.
The [required source-stable batch](../work/generic-transaction-cli-20261114/aggregate-attempt-2/validation.json)
passes1960 Rust cases including doctests,376 tooling cases and1658 simulator
cases, including strict Clippy/rustdoc and34 external CLI processes per cover.
Its service fixtures use UnixDatagram PacketDevices, not production TAP/TUN
startup. This wave adds no native/performance measurement.
Read-only preparation is tracked by
[MPR-01..MPR-05](modules/transaction-preparation.md), actual fallible native
completion storage by [NQP-01..NQP-05](modules/runtime-native-storage.md),
prepared generations by [EGB-01..EGB-03](modules/runtime-engine-bank.md), and
bounded custody integration by [TCS-01..TCS-03](modules/runtime-transaction-state.md).
These retain complete GSU-04/GSU-05 and SRS-07 acceptance.
Full SW-11, other profiles and every original
mode/native/platform/performance gate retain their complete definitions.
The [original-socket native driver](modules/secure-udp-runtime.md) has its own
bounded transport and runtime validation gates. The
[source-pinned native lab](modules/secure-udp-native.md) separately tracks actual
CLI/TAP payloads, policy/lifecycle, capture and matched performance acceptance.
These child ledgers preserve FIX-13, full SW-11 and every mode/native/platform
gate; an authenticated factory is not a running selected native client profile.
The [same-socket client aggregate](../work/shared-session-client-20261113/validation.json)
passed with stable inputs: 1437 Rust cases including doctests, 245 Python tooling
cases and 1658 simulator cases. It covers actual Noise and
Ed25519 admission, complete extracted Swift records and fixed control over the
original UDP pair. The [evidence-only ledger reconciliation](../work/shared-session-client-20261113/postcheck-ledger-validation.json)
verifies the final prose and unchanged non-document inputs. The subsequent
[runtime/service focused receipt](../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json)
passed real socket/device and paired-service checks, credential/profile/CLI
validation, versioned local API, policy and manual reconnect cases, strict Clippy
and rustdoc. The subsequent [required aggregate](../work/secure-udp-runtime-service-20261113/attempt-1/validation.json)
passed with stable inputs: 1487 Rust cases including doctests, 271 Python tooling
cases and 1658 simulator cases. Subsequent [immutable CLI/TAP baselines](modules/secure-udp-native.md#initial-immutable-native-baseline)
passed exact bytes, policy/lifecycle checks and clean/delay QUIC-like performance;
both impaired appearances failed the unchanged throughput target. The complete
native matrix and restarted-peer recovery remain open. The later deadline/wakeup
correction passed its [source-stable required aggregate](../work/secure-udp-native-progress-20261113/attempt-1/validation.json): 1498 Rust cases including doctests, 285 Python tooling cases and 1658 simulator cases. Its native attempts remain failed, with full evidence retained.
The later [counter-guided checkpoint](modules/secure-udp-native.md#counter-guided-performance-correction)
adds SUR-10/SUS-10/SWR-08 observations and separately tested burst/output-order
corrections, while preserving original retry/deadline behavior. Its
[focused check](../work/secure-udp-performance-focused-20261113/attempt-4/validation.json)
passed. Build7 impaired QUIC-like goodput is70.6236Mbit/s with reported native
pressure removed; SNL-09/SNL-11 and FIX-04 remain open. SUR-11 separately tracks
native-read fairness under saturated UDP ingress. Complete SW-11,47-mode parity,
OpenVPN/raw HTTPS, retained recovery and Windows/Android are unchanged gates.
SUS-11 subsequently corrects one-shot IPC helper scheduling with an
[expanded focused pass](../work/secure-udp-performance-focused-20261113/attempt-5/validation.json)
and [actual byte/thread-count comparison](../work/secure-udp-ipc-runtime-proof-20261113/comparison.json).
Build8 impaired QUIC-like is77.3464Mbit/s and still fails80; the daemon's scheduler,
wire rates, retry limits and original deadlines are preserved.
SUR-11 then proves and corrects UDP/native-read starvation without changing those
budgets or deadlines. Its [focused check](../work/secure-udp-performance-focused-20261113/attempt-8/validation.json)
passes, and [build9 forward/reverse measurements](modules/secure-udp-native.md#saturated-ingress-fairness)
cover both appearances. Forward16 measures78.6206/78.2435Mbit/s and fails80;
separate reverse stress passes functional checks. SNL-10 is scoped to those
bidirectional observations; SNL-08/SNL-09/SNL-11 and all parent gates remain open.
The [preceding required aggregate](../work/secure-udp-performance-progress-20261113/attempt-3/validation.json)
passed with stable source maps:1526 Rust cases including doctests,295 Python
tooling cases and1658 simulator cases, plus formatting, strict Clippy, rustdoc
and CLI checks. Complete serialized Rust execution preserves all assertions and
deadlines. Both earlier aggregate failures and all native target failures remain
unchanged; these local results do not close any parent mode/platform/lifecycle gate.
The fairness checkpoint's [required aggregate](../work/secure-udp-fairness-progress-20261113/attempt-2/validation.json) subsequently passes
1528 Rust cases including doctests, 295 Python tooling cases and 1658 simulator cases; all input maps remain stable. Its earlier
aggregate Deadline failure and unchanged isolated recheck remain separate
receipts. No test, original deadline, performance target or mode scope is reduced.
Swift now consumes the common library's explicit legacy compatibility owners;
the legacy CLI profile uses retained TLS plus a separate UDP data socket. A new
same-UDP-pair integration fixture exercises Noise, both appearance codecs,
Swift recovery and fixed control with scripted loss and key generations. That
fixture does not close FIX-13, native performance, credential migration, default
recovery, OpenVPN/HTTPS composition or full SW-11. Explicit QUIC-header/media-like
Swift selection is now wired through the shared service; actual native/impairment
acceptance is separate. The [local wave receipt](../work/shared-session-primitives-20261113/validation.json)
records its exact tested inputs and result: 1392 Rust cases including doctests,
245 Python tooling cases and 1658 simulator cases passed with stable inputs.
The subsequent [evidence-only ledger reconciliation](../work/shared-session-primitives-20261113/postcheck-ledger-validation.json)
checks updated prose and verifies that all non-document inputs still match that
aggregate snapshot. Historical receipts remain unchanged.

The subsequent [bounded capture-tail correction](modules/native-capture-drain.md)
has74 passing focused cases and four source-pinned current Linux observations.
Both clean cases pass all native checks; both impaired cases still fail80Mbit/s.
The separate [current PID-scoped kernel diagnostic](../work/secure-udp-performance-analysis-20261113/current-kernel-summary-attempt-2/analysis.md)
retains validated samples, switch records and paired I/O observations. It does not
close SBC-04, SNL-08/SNL-09/SNL-11 or any parent mode/lifecycle/platform gate.

The capture correction's [required aggregate](../work/native-capture-drain-20261113/aggregate-attempt-2/validation.json)
subsequently passes with stable inputs:1619 Rust cases including doctests,319
Python tooling cases and1658 simulator cases, plus formatting, strict Clippy,
rustdoc and CLI checks. The interrupted first check and native performance
failures retain their original outcomes; final reconciliation/checkpoint are separate.

The later [capture/setup diagnostics](modules/secure-udp-diagnostics.md) retain
bounded operation-specific failure observations through the shared service API.
Their [required frozen-source check](../work/secure-udp-diagnostics-20261114/aggregate-attempt-1/validation.json)
passes 1650 Rust cases including doctests, 349 tooling cases and 1658 simulator
cases. The [fresh 16-case matrix](../work/secure-udp-diagnostics-20261114/native-analysis-attempt-1/validation.json)
has complete evidence: eight clean cases pass; eight impaired cases fail only
80 Mbit/s. The separate [kernel comparison](../work/secure-udp-diagnostics-20261114/kernel-summary-attempt-1/analysis.md)
observes lower scheduling cost with current-thread and no throughput gain. Its
partial multithread switch-pairing evidence and all historical failures remain
explicit. Full SW-11, all 47 modes and the parent performance/platform gates remain open.

The [Swift receive-service correction](modules/swift-record-engine.md#bounded-cross-channel-receive-service)
now tracks SWR-09..SWR-12 separately from send-side scheduling and SUR-11 descriptor
fairness. Source-stable pure and real protected-UDP/native-output regressions
reproduce the old lowest-channel selector starving a complete higher channel.
The corrected shared selector passes the focused pure/runtime/service checks
with unchanged assertions, preserving per-channel order, wire bytes and bounds;
its [required frozen-source workspace check](../work/swift-receive-fairness-20261114/aggregate-attempt-1/validation.json)
passes 1659 Rust, 349 tooling and 1658 simulator cases. The
[fresh 16-case native analysis](../work/swift-receive-fairness-20261114/native-analysis-attempt-1/validation.json)
verifies all payload/control/policy/manual-reconnect/thread/cleanup observations,
but retains two capture gaps and an overall failed/incomplete verdict: 14 cases
have complete evidence, and all eight impaired 80 Mbit/s targets fail at
76.627–78.681 Mbit/s. Native throughput benefit remains unproved and SWR-12
remains open. The distinct partial-native-stream drain concern is addressed by
the scoped SWR-13 correction below. The separate [kernel comparison before this drain correction](../work/swift-receive-fairness-20261114/kernel-summary-attempt-1/analysis.md)
passes both full perf validators with zero lost events. Current-thread reduces
observed system CPU and context switching while measured goodput remains
78.182/78.216 Mbit/s; both original targets still fail. Host I/O is unattributed
and the instrumented observations do not establish a unique bottleneck or default.

The separate [partial native receive-custody correction](modules/swift-record-engine.md#partial-native-receive-custody)
now preserves incomplete prefix/payload bytes across refused directional reset.
Six [old-source assertions](../work/swift-partial-drain-20261114/old-source-attempt-1/validation.json)
reproduce the defect; [focused pure/policy/runtime/service checks](../work/swift-partial-drain-20261114/focused-attempt-1/validation.json)
pass with the same assertions after the two production predicates change.
The [required frozen-source workspace pass](../work/swift-partial-drain-20261114/aggregate-attempt-1/validation.json)
records 1671 Rust, 349 tooling and 1658 simulator cases. SWR-13's scoped custody
deliverable is complete. This finite correctness result neither closes
SWR-12/capture gaps nor claims a native performance gain or full
SW-11/profile/platform completion; preceding native/perf receipts retain their
original binary identities and verdicts.

The next [native capture-observation correction](modules/secure-udp-diagnostics.md#native-capture-observations)
tracks SGD-09..SGD-14: retain complete rejected tcpdump counters and separately
validate the saved native UDP port-unreachable grammar. It preserves all24
echo keys, zero-drop/final audit requirements and every original performance,
carrier, mode, lifecycle and platform gate. The
[focused131-case harness check](../work/native-capture-observations-20261114/focused-attempt-1/validation.json)
passes with unchanged regression assertions after reproducing both old-source
failures. The [second required frozen-source aggregate](../work/native-capture-observations-20261114/aggregate-attempt-2/validation.json)
passes1,671 Rust,376 tooling and1,658 simulator cases; the first OpenVPN close
failure remains preserved without a claimed production fix. The
[fresh same-build16-case matrix](../work/native-capture-observations-20261114/native-analysis-attempt-1/validation.json)
has complete capture/payload/control/policy/thread/cleanup evidence: eight clean
cases pass and eight impaired cases fail only80 Mbit/s at77.190–78.680 Mbit/s.
The [additive field audit](../work/native-capture-observations-20261114/additive-observation-analysis-attempt-1/validation.json)
passes without reclassifying historical failures. The separate
[kernel comparison](../work/native-capture-observations-20261114/kernel-summary-attempt-1/analysis.md)
observes lower system CPU and switching with current-thread, with unchanged
78.140 Mbit/s goodput. The [actual source checkpoint5df423ae05e0cb1e84dbbc6cef971b0c5851bf7e](../work/native-capture-observations-20261114/checkpoint-attempt-1/validation.json)
saves the reconciled correction and evidence. SGD-14 and the scoped SWR-12
observation/checkpoint deliverable are complete; parent performance, full
SW-11,47-mode and carrier/lifecycle/platform gates remain open.

The next [native record identity prerequisite](modules/swift-record-engine.md#native-record-identity-and-physical-custody)
tracks SWR-14..SWR-18 separately: checked per-channel admission/extraction
identities precede actual authenticated-scope and physical-device completion
fences. Exact owned edits were transferred from the isolated worktree after the
native checkpoint. [Focused pure/runtime/consumer commands](../work/swift-native-identities-20261114/focused-attempt-1/validation.json)
pass before a retained test-iterator lint failure; the
[test-only cleanup follow-up](../work/swift-native-identities-20261114/focused-attempt-2/validation.json)
passes Swift tests, strict Clippy and rustdoc. The
[required frozen-source pass](../work/swift-native-identities-20261114/aggregate-attempt-1/validation.json)
records1,692 Rust,376 tooling and1,658 simulator cases. SWR-15/SWR-16/SWR-18A's
pure API and selected local-custody precursor are verified to their stated
scope and saved in [actual source checkpoint2ccbaa8caa88afe86f0499843f01ca8b479911f4](../work/swift-native-identities-20261114/checkpoint-attempt-1/validation.json).
This
does not qualify generic switching, other record profiles or full SW-11.

| Workstream | Detailed checkbox IDs | Specification | Depends on |
| --- | --- | --- | --- |
| Connection/authentication | CONN-* and UDP-* | [Architecture](architecture.md), [carriers](overlay-and-carriers.md) | BASE schema/security decisions |
| Shared point-to-point security | SEC-01..SEC-12 | [Secure session](modules/secure-session.md) | maintained implementation/API review, opaque records, injected time, preserved data protection |
| Common original-carrier native CLI | CCN-01..CCN-03 | [Finite native qualification](modules/common-carrier-cli-native.md) | genuine outer/inner authentication, complete catalog, shared APIv4, owned TAP/TUN and unchanged full acceptance gates |
| Complete configuration wire bounds | TCE-01..TCE-05 | [Explicit encoding](modules/transaction-configuration-encoding.md) | actual typed limits/Peer/lease; selected runtime/resource/API integration remains open |
| Complete directional record policies | RCF-01..RCF-06 | [Canonical record configuration](modules/record-configuration.md) | complete field-preserving values/catalogs; representation does not install a runtime capability |
| Common record engine composition | CRE-01..CRE-08 | [Actual-owner adapter](modules/common-record-engine.md) | real functional three-profile Engine tested; complete policy/width/fence/resource/Bank/Driver acceptance remains open |
| Actual transactional queue admission | RAH-01..RAH-06 | [MUX/DRR/Pipeline handoff](modules/record-admission-handoff.md) | actual queues pass49 local protocol tests and real-profile functional consumers pass; complete resources and runtime/native integration remain open |
| Actual FEC/Reliable reserved backing | RRS-01..RRS-06 | [Record recovery storage](modules/record-recovery-storage.md) | real reusable encoder/decoder/duplex Reliable tested; complete nested allocator/drop qualification remains open |
| Actual Aligned/Packed reserved backing | ARS-01..ARS-08 | [Aligned record storage](modules/aligned-record-storage.md) | actual codecs/duplex endpoints tested; full inventory/matrix and reserved Engine/Bank/runtime integration remain open |
| Actual FlowTable/MUX storage | CQS-01..CQS-06 | [Common queue backing](modules/common-queue-storage.md) | actual fixed backing and borrowed handoff tested; complete Bank/runtime resources remain open |
| Actual reserved Scheduler | QSR-01..QSR-08 | [Scheduler backing](modules/qos-storage.md) | one actual DRR over reserved slots tested; combined resource/stage gates remain open |
| Actual reserved Pipeline | PQS-01..PQS-08 | [Pipeline backing](modules/pipeline-storage.md) | real nested queues/metadata and borrowed common Engine consumers tested; full nested failure/Bank/runtime remain open |
| Actual reserved common Engine | CSE-01..CSE-08 | [Complete Engine backing](modules/common-engine-storage.md) | one actual selected Swift/Aligned/Packed owner and complete queues tested; mixed Bank/runtime and full resources remain open |
| Authenticated fresh-DH lifecycle | SREF-01..SREF-08 | [Session refresh](modules/session-refresh.md) | real selected initial/refresh authority, continuing counters/replay; runtime and retained recovery remain separate |
| TUN active flow control and QoS | FC-01..FC-25 | [Flow control](flow-control.md) | bounded records, authenticated feedback; TCP proxy needs owned TCP legs |
| Internal L2 management/reload | MG-01..MG-08 | [Management protocol](overlay-and-carriers.md) | authenticated session; stable control framing before hot data modes |
| Whole-message control custody | SCM-01..SCM-08 | [Control messages](modules/control-messages.md) | existing ARQ/fragmentation, explicit completion custody and original deadlines |
| Independent common control streams | SCS-01..SCS-08 | [Control streams](modules/control-streams.md) | explicit negotiated binding, independent liveness and shared wire allowance |
| Streamed Swift runtime control | SUC-01..SUC-08 | [Selected runtime custody](modules/streamed-swift-control.md) | authenticated explicit backend, original caps and semantic custody; generic switching remains open |
| Swift byte-transfer correction | SBC-01..SBC-06 | [Bounded bulk transfer](modules/swift-bulk-copy.md) | source-bound perf evidence, exact ownership/bytes and immutable pre/post measurements |
| Swift fallible engine storage | SRS-01..SRS-07 | [Owned engine storage](modules/swift-storage.md) | complete capacity/failure/pool reuse before actual generic driver preparation; GSU-05 and full SW-11 remain open |
| Read-only leased preparation | MPR-01..MPR-05 | [Preparation preflight](modules/transaction-preparation.md) | actual Gate/Peer validation before resource construction; selected driver consumption remains open |
| Native completion storage | NQP-01..NQP-05 | [Owned native pool](modules/runtime-native-storage.md) | fallible physical-output custody in the existing driver; full combined memory/API/native gates remain open |
| Generic duplex generations | EGB-01..EGB-03 | [Two-generation bank](modules/runtime-engine-bank.md) | actual prepared/current/draining engines; physical control/native proofs remain external |
| Generic transaction custody | TCS-01..TCS-03 | [Actual State consumer](modules/runtime-transaction-state.md) | one leased Peer, real prepared allocation and whole-message proofs; selected driver integration remains open |
| Native capture tail | NCD-01..NCD-06 | [Bounded capture witness](modules/native-capture-drain.md) | exact final probe fingerprints before capture stop; original final audits and performance gates retained |
| Host-runtime comparison | HRT-01..HRT-07 | [Explicit process host](modules/host-runtime.md) | scoped selector tested; fresh complete evidence-verified 16-case ABBA; eight impaired 80 targets and parent gates remain open |
| Secure UDP diagnostics | SGD-01..SGD-14 | [Capture and setup evidence](modules/secure-udp-diagnostics.md) | implemented bounded IPv4/options/setup/quote/counter observations; all16 fresh captures verified and checkpoint saved; finite native/kernel evidence retains eight failed80 targets |
| VXLAN | VX-01..VX-09 | [Overlay design](overlay-and-carriers.md) | L2 frame validation, tenancy and MTU accounting |
| UDP covers | UDP-01..UDP-16 | [Carrier design](overlay-and-carriers.md) | selected authenticated bootstrap; UDP-only is its own gate |
| CLI/GUI/native clients | CL-01..CL-39 | [Client plan](client-design.md) | shared client-core/local API; native adapters independently qualified |
| Python parity | P-* below | [Parity matrix](mode-parity.md) | actual byte codecs/recovery and test traces |
| Kernel/native verification | TEST-* and RELEASE-* | [Test plan](testing.md) | implemented runtime, no mock-only acceptance |
| Swift algorithm and current profile | SW-01..SW-16 | [Swift module](modules/swift.md) | current TLS-bootstrap evidence; planned shared security/carrier migration and full SW-11 |

Current composition work is tracked in the narrower module ledgers:
[packed sender](modules/packed-sender.md),
[context-aware batch validation](modules/packed-validation.md),
[packed recovery](modules/packed-recovery.md),
[packed runtime design](modules/packed-runtime.md),
[proxy client](modules/proxy-client.md),
[native proxy qualification](modules/proxy-native.md),
[standalone UDP native qualification](modules/openvpn-native.md) and
[native UDP drain](modules/openvpn-native-drain.md),
[raw packet-phase design](modules/raw-packet-phase.md) and
[raw owner handoff](modules/raw-owner-handoff.md). Their finite checkpoints
do not automatically complete the broader parent or P-* gates below. New active composition ledgers are
[rolling local/global recovery](modules/local-global-rlnc.md),
[measured proxy client](modules/proxy-measured-client.md) and
[raw TLS transition](modules/raw-tls-transition.md). Completed follow-on bundles
are tracked in [raw packet runtime](modules/raw-runtime.md),
[QUIC owner cleanup](modules/quic-owner-cleanup.md), and
[measured proxy native checks](modules/proxy-measured-native.md). The next raw
composition uses [original native packet opening](modules/raw-native-packet.md)
and the [shared raw client](modules/raw-packet-client.md), with the
[owned raw packet native harness](modules/raw-packet-native.md) tracking its
separate execution gates. The [rolling-frame runtime](modules/rolling-runtime.md)
tracks common MUX, authenticated UDP/QUIC composition and exact shared budgets;
its finite tests do not close the complete Python-family gates.
The [rolling client](modules/rolling-client.md) records explicit API/CLI activation,
and the [rolling native harness](modules/rolling-native.md) tracks owned device,
loss and cross-capture acceptance separately.
The [pressure capture allocation](modules/proxy-pressure-capture.md) records the
bounded native evidence collection required for the corrected proxy pressure run.
The [independent review follow-ups](review-followups.md) track control pacing,
aligned flow retirement and the original base handshake deadline. The
[HTTPS carrier](modules/https-carrier.md) has a separate integration ledger.
The [native window investigation](modules/native-window-qualification.md) separates
actual TCP receive-window control from relay targets and requires sustained
TAP/TUN measurements. The [base deadline](modules/base-handshake-deadline.md) and
[aligned/packed retirement](modules/aligned-flow-retirement.md) passed the
[source22 combined check](../work/implementation-wave22/validation.json).
[Proxy control pacing](modules/proxy-control-pacing.md) and
[rolling/raw retirement](modules/rolling-raw-flow-retirement.md) passed the
[source23b combined check](../work/implementation-wave23b/validation.json).
The [native throughput harness](modules/native-throughput.md) records matched
TAP/TUN delay/loss, actual directional goodput and sampled TCP windows; its
privileged measurement gates are separate from loopback accounting tests.
The [managed profiling and performance gate](modules/managed-profiling.md) tracks
the observed slow native baseline and the required 80 Mbit/s forward target.
The [delivery-window contract](modules/delivery-window.md) separates bandwidth/RTT
outstanding credit from local queue capacity. Its pure tests do not imply runtime
integration or performance acceptance.

## Tested native vertical slice

- [x] [SLICE-01] Retain verified TLS 1.3 through member authentication and application data, with replay/configuration rejection tests. Evidence: [auth tests](../crates/l2tunnel-auth/src/tests.rs).
- [ ] [SLICE-02] Complete native Linux TAP/TUN half/full duplex at 70 ms RTT / 15% loss, including exact-byte IPv4 and IPv6 TCP and owned cleanup. The [historical six-case receipt](../work/native-wave4/receipt.json) covers clean full/half and impaired half only; IPv6 coverage is ICMP, not TCP. Add the missing full-duplex impaired and IPv6 TCP cases before checking this deliverable.
- [x] [SLICE-03] Compose bounded scheduling, MUX, wire and VXLAN without granting management authority to user Ethernet bytes. Evidence: [facade integration](../crates/l2tunnel/tests/pipeline.rs).
- [x] [SLICE-05] Qualify point-to-point Linux kernel VXLAN with explicit offload completion, VNI admission and native IPv4/IPv6/TCP traffic. Evidence: [VXLAN receipt](../work/vxlan-qualified/receipt.json).
- [x] [SLICE-06] Qualify coordinated Off/LZ4/Off compression epochs through the private local API during native TAP/TUN/VXLAN TCP transfer, including impaired half-duplex links. Evidence: [nine-case native receipt](../work/native-managed-logical/receipt.json).
- [x] [SLICE-07] Qualify TLS-bootstrapped UDP forwarding for both custom covers and both suites through native TAP/TUN/VXLAN, with captured MTU bounds, retained control and UDP failure/restoration. Evidence: [36-case independent audit](../work/native-udp-matrix-audit.json).
- [x] [SLICE-08] Integrate systematic Cauchy repair plus ARQ fallback in the authenticated UDP native runtime and qualify both covers/suites, native layers and actual repair transmission. Evidence: [runtime tests](../crates/l2tunnel-runtime/src/udp_tests.rs), [36-case native Cauchy audit](../work/native-fec-matrix-audit.json).
- [x] [SLICE-09] Integrate fixed-bootstrap transparent-TUN flow credits, weighted DRR and CRC MUX into retained TLS and qualify both duplex modes with None/LZ4 and impaired links. Evidence: [runtime tests](../crates/l2tunnel-runtime/src/active_tests.rs), [plain receipt](../work/native-active-plain/receipt.json), [LZ4 receipt](../work/native-active-lz4/receipt.json).
- [x] [SLICE-10] Integrate authenticated measured demand/RTT/native delivery feedback and exact idle retirement; qualify more flows than slots with None/LZ4. Evidence: [None audit](../work/native-active-measured-audit.json), [LZ4 audit](../work/native-active-measured-lz4-audit.json), six native TUN cases, finite measured-growth/retirement scope.
- [x] [SLICE-11] Qualify genuine standalone QUIC authentication and packet forwarding on TAP/TUN/VXLAN with outer TCP blocked, full/paired-half and impaired links. Evidence: [36-case QUIC audit](../work/native-quic-matrix-audit.json), None/LZ4, ARQ/Cauchy, maintained QUIC AEAD, exact probes/TCP payloads, UDP path failure/restoration, actual MTU 1228 with offloads disabled and owned cleanup.
- [x] [SLICE-12] Qualify explicit fixed-credit native TUN TCP proxy in clean full and paired-half modes, with independent IPv4/IPv6 TCP legs, transparent bypass, exact bytes/FIN/native fences and original TLS lane closure. Evidence: [two-case independent audit](../work/native-proxy-clean-audit.json), [stable binary build](../work/native-proxy-full-build/receipt.json); adaptive window growth, impairment and broad platform support remain separate.
- [x] [SLICE-13] Qualify packed records over authenticated custom UDP in six clean Linux TAP/TUN/VXLAN full/half cases with exact payloads, bidirectional complete-packet aggregation, MTU/capture checks and owned cleanup. Evidence: [parallel six-case result](../work/packed-clean-matrix14b/receipt.json), [independent audits](modules/packed-native.md#clean-parallel-native-qualification); other carriers, impairment and complete Python packed parity remain separate.
- [x] [SLICE-14] Qualify explicitly selected measured-proxy TUN connectivity in clean full/half modes with exact IPv4/IPv6 bytes, transparent bypass, actual measurement traffic, native fences and owned cleanup. Evidence: [full audit](../work/native-proxy-measured-full15-audit3.json), [half audit](../work/native-proxy-measured-half15-audit3.json), [scope and failed pressure gates](modules/proxy-measured-native.md). The exact observation build has separately recorded aggregate failures; these clean cases do not qualify adaptive windows or fairness.
- [ ] [SLICE-04] Integrate active credit/QoS, distributed reload, recovery and VXLAN with authenticated native forwarding.

## Existing foundation versus outstanding M0 work

- [x] [BASE-01] Initialize 14 Rust packages with runtime-independent public library boundaries. Evidence: [workspace](../Cargo.toml), [scaffold receipt](../work/implementation-scaffold/validation.json).
- [x] [BASE-02] Define formatting, lint, documentation and local checks plus CI jobs; remote CI remains unexecuted. Evidence: [checks](../tools/check.py), [workflow](../.github/workflows/checks.yml).
- [x] [BASE-03] Contract-test bounded inner framing and FIFO/round-robin MUX admission, including malformed sizes and queue limits. Evidence: [wire tests](../crates/l2tunnel-wire/src/lib.rs), [MUX tests](../crates/l2tunnel-mux/src/lib.rs).
- [x] [BASE-04] Contract-test local epoch/attempt guard, conflict rejection and no rollback after possible commit. Evidence: [guard tests](../crates/l2tunnel-session/src/lib.rs).
- [x] [BASE-05] Inventory every Python mode family and separate source evidence from analytical/oracle diagnostics. Evidence: [catalog](../config/mode-catalog.toml), [parity audit](mode-parity.md).
- [x] [BASE-06] Prepare dry-run-only-by-default bridge/TAP/netem topology and unprivileged ownership tests. Evidence: [lab](../tools/netns_lab.py), [tests](../tools/test_netns_lab.py).
- [x] [BASE-07] Contract-test TUN/TAP TCP ownership, system/custom QoS boundary, explicit carrier selection and required UDP cover without claiming runtime implementations. Evidence: [traffic-policy tests](../crates/l2tunnel-core/src/traffic.rs), [carrier tests](../crates/l2tunnel-transport/src/lib.rs).
- [ ] [BASE-08] Freeze a strict runtime configuration schema, canonical encoding, digest and version/migration rules; the mode catalog is not a daemon config.
- [ ] [BASE-09] Specify common resource limits, typed errors, cancellation and observable capabilities before engine integration.
- [ ] [BASE-10] Create runtime, flow-control, QoS, TCP-proxy, management and VXLAN crates when their first real behavior is implemented; avoid empty success stubs.
- [ ] [BASE-11] Introduce pinned audited crypto/runtime dependencies and isolate native unsafe/FFI exceptions from protocol crates.

## M1 connection and authentication

- [ ] [CONN-01] Implement retained TCP/TLS socket ownership through handshake, member auth and user traffic for that compatibility profile; capture the absence of an auth-boundary reconnect. Separately qualify the selected carrier's original connection/socket/five-tuple through common authentication and data, including the requested HTTPS-like TLS-to-packet transition; a separate TCP bootstrap plus UDP data flow cannot satisfy it.
- [ ] [CONN-02] Implement server pin/CA verification, no-SNI profile and independently configured cover name without accept-all certificate checks. The [TCP naming and physical-send contract](modules/tcp-carrier-naming.md) tracks the additive implementation and its separate focused gates.
- [ ] [CONN-03] Implement transcript/exporter-bound member authentication, capability selection, role separation and 0-RTT rejection in retained TLS profiles; integrate shared WireGuard-like session authentication with equally explicit peer/carrier/configuration binding under SEC-01..SEC-04. Preserve existing credential requirements until a reviewed binding/migration is specified.
- [ ] [CONN-04] Implement session creation, single-use lane join tokens, expiry, replay rejection and per-lane identity.
- [ ] [CONN-05] Implement bounded framing, byte/count budgets, timeouts and pre-auth work/connection limits.
- [ ] [CONN-06] Implement AEAD/MAC protection, direction/lane/key domains, unique packet numbers, replay windows and rekey/exhaustion handling.
- [ ] [CONN-07] Implement default paired half-duplex carriers and full-duplex carriers with independent direction budgets and reverse feedback.
- [ ] [CONN-08] Implement explicit raw/TCP/UDP selection and visible, configured fallback; permission absence cannot silently change selected semantics.
- [ ] [CONN-09] Implement and qualify the requested HTTPS-like real TCP/TLS handshake followed by ACK-independent custom TCP-shaped packets on the original ports and sequence space, with configurable SNI and independent own-server trust. Preserve the separate real HTTPS framing/ALPN compatibility work and its MOD-HTTPS-* gates; it is not a substitute for the raw path. Separately implement and qualify the requested L2TP cover.
- [ ] [CONN-10] Complete UDP-* gates for OpenVPN-like, QUIC-header appearance and the new minimal media appearance, including standalone same-socket authentication; TCP-bootstrapped UDP alone is incomplete. Preserve the original OpenVPN wire-handshake gate and genuine QUIC compatibility evidence as distinct contracts.
- [ ] [CONN-11] Qualify raw TCP packet ownership, sequence/ACK/options/RST/PMTU/NAT behavior in isolated target-path tests. The original-carrier Common composition has separate [RCC-01..04](modules/raw-common-carrier.md) implementation and acceptance gates.
  [Standalone ACK handling and Linux closeout evidence](modules/raw-common-carrier.md#standalone-acks-after-packet-handoff) cover the original bootstrap and the established raw packet phase on owned endpoints.
- [ ] [CONN-12] Publish effective carrier/cover/security/duplex capabilities and reasons for unsupported combinations.
- [ ] [CONN-13] Complete SEC-01..SEC-12 for the shared point-to-point secure session, common AEAD/protection and fixed management service; require selected-carrier continuity, bounded automatic recovery and exact failure/restart/key-generation semantics before enabling a new client path.

## M2 record pipeline and interoperability

- [ ] [FRAME-01] Implement native TAP Ethernet and TUN IPv4/IPv6 records with explicit layer tags and full-byte fallback.
- [ ] [FRAME-02] Implement VLAN/ARP/IPv4/IPv6/TCP/UDP/fragment classification, checksums and bounded unsupported-header handling.
- [ ] [FRAME-03] Implement CRC32/connection-RR affinity with simultaneous-open arbitration, idle eviction and collision tests.
- [ ] [FRAME-04] Separate inner flows, MUX channels, physical lanes and QoS classes in configuration, scheduling and counters.
- [ ] [FRAME-05] Preserve the common user channel budget for bulk, TCP control packets and measurement probes.
- [ ] [FRAME-06] Implement fragmentation, bounded reassembly, context recovery, valid-length/padding semantics and actual PMTU budgeting.
- [ ] [FRAME-07] Freeze golden byte vectors and protocol versioning, including management/user-origin separation and arbitrary payload bytes.
- [ ] [FRAME-08] Implement full-frame, delta/timestamp, shared/aligned/packed codecs with no source-ledger access during recovery.
- [ ] [FRAME-09] Complete MG-* stable internal L2 control and VX-* pass-through/VTEP gates before claiming hot reload or VXLAN support.

## M3/M4 active data plane and switching

- [ ] [DATA-01] Implement real-payload ARQ/FEC, bounded decoder work and every applicable P-* recovery requirement.
- [ ] [DATA-02] Complete FC-* active credit/QoS and actual TCP proxy gates; transparent TUN credit alone is not actual TCP-window acceleration.
- [ ] [DATA-03] Keep TAP endpoint TCP/ACK/window behavior unchanged; system QoS bindings are independently tested.
- [ ] [DATA-04] Implement optional compression and exact ACK/packing optimizations only in their permitted profiles; preserve a transparent baseline.
- [ ] [DATA-05] Implement PREPARE/READY/BARRIER/COMMIT/ACK/RETIRE through internal management with retries, staged readers and attempt freshness.
- [ ] [DATA-06] Fault-test every hot-switch boundary, simultaneous requests, peer restart and uncertain commit without unilateral rollback.
- [ ] [DATA-07] Keep control decoding/service fixed while data codecs/FEC/MUX change; account control budget and TCP HOL limitations.
- [ ] [DATA-08] Drain old credits/contexts before shrink; retain old packet tombstones; do not reset packet/key counters.
- [ ] [DATA-09] Define reconnect-required changes: device layer, existing TCP ownership, trust/peer identity and incompatible carrier/control wire changes.

## M5 clients and validation

- [ ] [APP-01] Complete CL-01..CL-16 shared client core, versioned local API and full CLI operations before adding GUI-specific protocol logic.
- [ ] [APP-02] Complete CL-17..CL-21 desktop GUI with a documented toolkit choice and shared service/API behavior.
- [ ] [APP-03] Complete CL-22..CL-31 Linux/Windows/Android service/device/credential lifecycle and Android GUI integration.
- [ ] [APP-04] Complete CL-32..CL-36 native receipts, CLI/GUI parity and packaging/update policy.
- [ ] [TEST-01] Extend isolated lab with daemon launch, TUN routing, TAP bridge and external Linux VXLAN VTEPs; retain ownership-safe cleanup.
- [ ] [TEST-02] Calibrate rate/delay/loss/offloads/MTU before protocol comparison; record actual kernel/qdisc settings and captures.
- [ ] [TEST-03] Run fixed 100/10 Mbps, 70 ms RTT, 15% IID loss plus clean, burst, reorder, duplication and PMTU profiles.
- [ ] [TEST-04] Sweep payloads 64/256/512/1024/1228/1448 and 1/2/4/16/64 demand-bearing flows, including many idle connections.
- [ ] [TEST-05] Exercise both duplex policies, all selected carriers, both original UDP covers and the new minimal media cover; measure full wire overhead and terminal confirmation. Preserve separate genuine QUIC, retained TLS/HTTPS and requested HTTPS-like packet-phase evidence.
- [ ] [TEST-06] Measure few-flow ramp, queue delay, active backpressure, receiver stalls, QoS shares/starvation and external TCP fairness.
- [ ] [TEST-07] Verify TAP byte/TCP transparency and contrast transparent TUN with explicit TCP proxy lifecycle/failure semantics.
- [ ] [TEST-08] Test spoofed management-looking user frames, cross-VNI injection, FDB/BUM limits and bridge loop prevention.
- [ ] [TEST-09] Inject lost/late/duplicate management and credit messages under saturated traffic and each supported hot switch.
- [ ] [TEST-10] Run real OS TCP, QUIC and pinned KCP baselines with matching channel/probe policies and labeled congestion settings.
- [ ] [TEST-11] Fuzz parsers, reassembly, management, VXLAN and flow/context boundaries; enforce memory/CPU/time limits.
- [ ] [TEST-12] Save source/config hashes, same-window goodput/byte cost/latency, CPU/RSS, queues, drops, confirmation and unsupported outcomes.
- [x] [PBL-01] Measure independent and strict native handoff at 6/5, then strict and TCP-data ordering with the scheduled 12/8 Linux lab endpoint. Record same-window single-flow goodput, inner TCP retransmissions, application P99 and final group custody. Evidence: [Five Linux rows and scope](modules/frame-channel-experiment.md#native-delivery-order-and-sender-pacing-in-the-linux-path-bundle).
- [x] [PBL-02] Validate the explicit earned-credit capacity, including a one-frame start, actual socket charging and unchanged custody on blocked sends. Measure the two-frame selection with the same 12/8 workload and report first-payment delay, application P99 and goodput. Evidence: [Linux control](../work/fec-native-order-20261121/burst2-12-8-v1/result.json) and [focused example](../work/fec-native-order-20261121/rank-burst-v1/example-attempt2.log).
- [x] [PBL-03] Validate optional positive physical-rank suppression across multiple paths, mixed-group datagrams, frozen sends, lost logical receipts and old gaps. Measure paid repair bytes, logical drain and same-window single-flow performance on Linux. Evidence: [Paid costs in three Linux arms](../work/fec-native-order-20261121/burst2-three-arms-service-cost-v1.json) and [focused custody checks](../work/fec-native-order-20261121/rank-burst-v1). The throughput and broader integrated gates remain open.
- [x] [PBL-04] Validate opt-in preference for the oldest overdue unpaid canonical group across paths. Retain bounded ordinary DATA service, control and old-hole recovery, and compare actual original payment span, goodput, application P99 and inner TCP retransmissions at 12/8 and 6/5. Evidence: [Matched Linux comparison](../work/fec-native-order-20261121/frontier-pair-vs-rank-original-paid-open-v1.json), [same-record TCP prefix timings](../work/fec-native-order-20261121/frontier-four-arms-application-header-native-prefix-v1.json) and [focused scheduling checks](../work/fec-native-order-20261121/frontiers-v1/example-attempt2.log). Throughput qualification remains open.
- [x] [PBL-05] Service one due egress opportunity after a successful input on the paced Linux path-bundle adapter. Preserve the shared byte budget, immutable reservations, bounded fair selection and socket-writability handling. Measure sender payments, application P99, goodput and inner retransmissions against both frontier controls. Evidence: [12/8 Linux result](../work/fec-native-order-20261121/checkpoint-12-8-v1/result.json), [6/5 Linux result](../work/fec-native-order-20261121/checkpoint-6-5-v1/result.json) and [focused checks](../work/fec-native-order-20261121/checkpoint-v1/commands.jsonl). The single-flow throughput target remains open.
- [x] [PBL-06] Avoid redundant logical member scans and identical timeout deadline updates for repeated ACKs in the isolated Linux adapter. Preserve new logical retirement, physical RTT/selective-gap processing, old-hole recovery, late frozen payment and clock validation. Compare the same 12/8 and 6/5 native arms with the input-checkpoint controls. Evidence: [focused checks](../work/fec-native-order-20261121/ack-cost-v1/commands.jsonl), [native traces, costs and counters](../work/fec-native-order-20261121/ack-cost-paid-ack-stage-pair-v2.json) and [full Linux workspace gate 04](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-04/result.json). 12/8 improved and 6/5 regressed in this single-seed pair. Throughput qualification remains open.
- [x] [PBL-OBS-01] Capture optional pre-adapter IPv4 ARP observations at both ends of both owned underlay veth pairs. Verify process identity, timestamps, loss counters, cold and final neighbor-table snapshots and namespace cleanup without adding UDP traffic. Evidence: [matched 6/5 observer arm](../work/fec-native-order-20261121/arp-observer-6-5-v1/result.json) and [independent audit](../work/fec-native-order-20261121/arp-observer-6-5-audit-v1.json).
- [x] [PBL-07] Gate the isolated established-key UDP experiment's native handoff on authenticated per-path challenge replies and start the TCP probe only after both peers report readiness. Preserve shared pacing, late peer replies and bounded cleanup. Account every paid setup byte separately and compare startup with the ungated control. Evidence: [focused endpoint and harness checks](../work/fec-native-order-20261121/authenticated-ready-v1/commands.jsonl), [6/5 readiness and payment](../work/fec-native-order-20261121/authenticated-ready-6-5-v1/result.json) and [12/8 readiness and payment](../work/fec-native-order-20261121/authenticated-ready-12-8-v1/result.json). The [full local gate 05](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-05/result.json) passed. Throughput qualification remains open.
- [x] [PBL-08] Evaluate one optional repeat round for the first 128 groups per direction after all original shards have been paid. Preserve shared pacing, priority of ordinary traffic and old-hole recovery. Verify actual payment, rank cancellation, the 35 ms eligibility deadline and both matched native throughput and latency controls. Evidence: [six-arm actual payment and recovery comparison](../work/fec-native-order-20261121/initial-128-actual-low-load-six-arm-v1.json), [full local gate 07](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-07/result.json) and [policy boundaries](modules/frame-channel-experiment.md#one-additional-round-during-idle-startup-capacity-pbl-08). The fair 6/5 case reached 46.803 Mbit/s with zero steady inner retries; 12/8 latency regressed. The option remains off and throughput qualification remains open.
- [x] [PBL-OBS-02] Add optional bounded router UDP packet taps and queue/process scheduling observations to the owned shaper-before-loss lab. Validate namespace identity, incomplete-sample refusal, packet drops and cleanup. Evidence: [four-surface native audit](../work/fec-native-order-20261121/underlay-observed-12-8-four-surface-audit-v1.json) and [observer checks](../work/kcp-native-reference-trace-build-20261121-v1/observer-focused.log). This run does not establish the cause of the earlier host-wide sampling gap.
- [x] [PBL-09] Evaluate explicitly selected transfer of stale unfrozen physical repair members to a different path's actually paid named repair. Preserve new-path loss recovery, independent replicas, frozen sends, original shards and old-gap custody. Verify mixed-member retirement and measure same-parameter throughput, application P99 and actual repair bytes before any default decision. Evidence: [focused checks](../work/fec-native-order-20261121/named-transfer-v1/focused-rust.log), [native comparison](../work/fec-native-order-20261121/named-transfer-pair-v1.json) and [aggregate gate 08](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-fec-scheduler-gate-20261121-08/result.json). Wire cost decreased, but the longest old-gap wait increased. This finite evaluation keeps the option off and does not close the single-flow throughput target.
- [ ] [TEST-13] Run remote Linux/Windows CI and Android compile gates; keep native device execution as a separate gate.
- [ ] [TEST-14] Run native Windows TAP/Wintun and Android VpnService/protect/lifecycle tests, not only cross-compilation.

TEST-12 now has a [causal frame-channel experiment and PackedWire service study](modules/frame-channel-experiment.md)
with independently ordered frames, bounded admission, lossy gap requests,
actual XOR reconstruction, serialized decoding and per-direction IP accounting.
The [PackedWire targeted-recovery comparison](modules/frame-channel-experiment.md#targeted-recovery-in-the-original-packedwire-workload)
exercises these gap requests with the named C48 workload, calibrated receiver
service, independent channel delivery and retained-source recovery.
The [C48 original-frame latency study](modules/frame-channel-experiment.md#original-frame-latency-in-the-calibrated-c48-run)
measures MUX admission, source recovery, decoder queueing and ordered release
on the same slowest TCP originals, and tests sharing regular FEC bytes with
explicit retries while preserving old-source custody.
The same study includes the ranked baseline originals and a sender policy
that adjusts the byte budget using local MUX queue age in each direction.
Matched kernel validation and the existing named runtime acceptance gates remain open.

TEST-12 and PBA-03/06 also track the
[Rust Packed/Rolling C48 candidate](modules/frame-channel-experiment.md#rust-implementation-of-the-c48-candidate).
The authenticated selected Common engine implements named retries, bounded
old-gap custody, independent channel release and MUX-age-based repair accounting.
Protocol tests and a two-peer UDP failure-injection test cover these mechanisms.
The exact-source control remains selectable for matched native measurements.
The [C48 native measurements](modules/frame-channel-experiment.md#matched-linux-tunudp-observation)
also exercise the bounded Rolling decoder, receiver admission and runnable
work scheduling. The isolated protocol checkpoint recorded a 3.395 s input
residence and failed native load. The scoped hot-path checkpoint completed
the UDP candidate at 26.53 Mbit/s, with terminal unconfirmed counts of 0/0
and maximum forward input residence of 93.545 ms. The exact control expired
and application P99 was 1.319 s for the candidate. RWI-03 and full native
parity remain open.

TEST-12 and PBA-03/06 additionally track
[fresh-source service during C48 recovery](modules/frame-channel-experiment.md#scheduling-fresh-sources-during-c48-recovery).
The targeted sender retains old gaps while admitting a bounded queue of fresh
sources. The two-peer regression loses the same original twice, delivers an
unaffected channel during the retry backlog, then checks ordered recovery and
cumulative confirmation. The physical-send batch experiment and its liveness
failure are recorded separately in the same study.

TEST-12 and PBA-03/06 also track the
[receiver TCP half-close investigation](modules/frame-channel-experiment.md#receiver-tcp-half-close-and-the-483-record-tail).
Four historical stream reconstructions and a separate Linux kernel trace
identify why a FIN-covering ACK arriving early stalled native TCP delivery.
The targeted Packed/Rolling owner now preserves channel order for that ACK,
and the one-way measurement peer waits for incoming EOF before half-closing.
The study distinguishes the two changes, application latency, cumulative ACK
latency and bilateral recovery drain. Broader carrier and performance gates
remain open.

TEST-12 and PBA-03/06 track the
[matched C48 measurements and sender MUX residence](modules/frame-channel-experiment.md#sender-mux-residence-and-the-c48-throughput-gap).
The four-flow Linux trace joins original TCP byte ranges to native reads, MUX
admission, recovery and application completion. Performance parity remains open.
The same study records the local/global decoder work reduction, the
per-device-write ACK service regression and end-to-end 50.44 Mbit/s repeat.
Another draw exceeded the original ACK deadline. A later receiver preview
cache reduced full source parses from 79.0 to 8.9 per ordered handoff on the
receiving endpoint. Two four-capture native runs delivered 50.95 and 52.26
Mbit/s and drained both endpoints. The same-turn sender can also reuse a
remaining work grant after physical acceptance. TEST-12 remains open against
the original 75.78–75.94 Mbit/s Python reference. Interleaving source sends
with a full global equation passed scalar byte comparison on 69 repairs and
two clean UDP runs at 52.14 and 53.03 Mbit/s. Charging projected native
authentication and UDP sizes in the Python model yielded 75.73 and 76.06
Mbit/s. The [global repair and short TCP segment study](modules/frame-channel-experiment.md#global-repair-scheduling-and-small-tcp-segments)
also records the 54.71/51.56 Mbit/s sender experiment and its grouped local
supports. The receiver traces match small out-of-order TCP ranges to specific
SACKs using the native captures from both ends. The
[repair-selection and socket admission measurements](modules/frame-channel-experiment.md#repair-selection-and-tcp-socket-admission)
verify all 1,673 source-earned repair equations against an independent oracle.
The original R19 native pair delivered 42.49/43.00 Mbit/s. Enforcing the
Python per-stream payload budget in a separate native workload control yielded
64.09/66.96 Mbit/s and scheduled-to-read P99 of 3.48/2.86 s. Both pairs drained
every source. TEST-12 remains open for the original throughput and latency targets.

The [sender global-repair replay and four native trials](modules/frame-channel-experiment.md#sending-originals-during-a-mature-global-repair)
preserved the original equations and old-hole recovery. The original-socket
pair delivered 42.85/47.96 Mbit/s and the strict payload-credit pair delivered
63.86/65.44 Mbit/s. All four drained. These trials leave TEST-12 open.

TEST-12 also records a [four-direction TUN trace and same-event Python
replay](modules/frame-channel-experiment.md#single-flow-tcp-recovery-on-the-same-packet-history).
The single-flow selector-6 Linux run delivered 33.145 Mbit/s with a
1329.651 ms application P99 and 441 steady inner retransmissions. It drained
both directions. The replay checks receiver ACK timing and the optional
sender timestamp predicate. Throughput and latency parity remain open.

## Per-mode parity implementation gates

Each P-* gate means the named algorithm/codec/workload adapter is implemented and
has its matrix-specific focused tests. Integration coverage is additionally gated
by TEST-* and release checks. Workload-only ACK/TCP knobs and research diagnostics
must keep their documented scope; never enable them by mutating TAP endpoint TCP.
A checkbox must agree with `config/mode-catalog.toml` status. Each entry below
records its own completion scope. New mode IDs require new checklist entries automatically.

- [ ] [P-legacy-arq] Implement and validate `legacy-arq` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-legacy-block-fec] Implement and validate `legacy-block-fec` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-striped-cauchy] Integrate and validate the `striped-cauchy` physical packet profile (M3), including both wire directions, actual authenticated carrier admission, bounded shortened groups, immediate systematics, residual retries, and the single-flow throughput and latency comparison. [Component and model evidence](modules/frame-channel-experiment.md#mixed-packets-and-local-erasure-recovery).
  The UDP single-flow implementation distinguishes new-gap naming from paid
  repeats and reports how many groups split for lack of inputs, MTU, or a
  remaining singleton after a partial seal. [Captured packet and dependency evidence](modules/frame-channel-experiment.md#mixed-packets-and-local-erasure-recovery).
  The 12/10 UDP/TUN run reached 4.018 Mbit/s and the raw-header control
  ended before data admission. The single-flow target remains open.
  [Window evolution and individual retransmissions](modules/frame-channel-experiment.md#single-flow-congestion-window-and-header-dependency).
  The Rust sender exposes each actual sealing decision. The Python short-group
  study can protect three sources across six mixed members on the same
  deadline. Linux wire integration of this format and the target throughput
  remain open. [Short-group erasure replay and paired results](modules/frame-channel-experiment.md#erasure-protection-at-the-short-group-deadline).
- [ ] [P-legacy-sliding-fec] Implement and validate `legacy-sliding-fec` (M3); preserve its [parity contract](mode-parity.md). Additive real-byte protocol component: [legacy scheduling, wire and integration limits](modules/legacy-sliding.md); complete Common/runtime/platform/performance gates remain open.
- [ ] [P-legacy-hybrid-fec] Implement and validate `legacy-hybrid-fec` (M3); preserve its [parity contract](mode-parity.md). Additive real-byte protocol component: [legacy scheduling, wire and integration limits](modules/legacy-sliding.md); complete Common/runtime/platform/performance gates remain open.
- [ ] [P-compact-rlnc] Implement and validate `compact-rlnc` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-compact-arq] Implement and validate `compact-arq` (M3); preserve its [parity contract](mode-parity.md).
- [x] [P-kcp-like-l2] Implement and validate explicitly selected KCP-like raw/compressed L2 over Common, including negotiated parameters, paid-attempt retry timing, bounded old-hole custody, independent stateless delivery, real shared-service lifecycle and comparison evidence. Evidence: [design and validation](modules/kcp-like-l2.md#completed-local-verification), including the full local gate and Linux UDP/TAP execution. Native performance fails the target; this does not close `P-kcp-baseline`, `TEST-12` or other carrier/platform execution gates.
- [ ] [P-first-flight-arq] Implement and validate `first-flight-arq` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-bounded-gap-arq] Implement and validate `bounded-gap-arq` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-compact-block-fec] Implement and validate `compact-block-fec` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-local-global-rlnc] Implement and validate `local-global-rlnc` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-path-scheduling] Implement and validate `path-scheduling` (M3); preserve its [parity contract](mode-parity.md).
  - The independent physical-path bundle implements configurable N/K, a separate
    batch capacity and deadline per path, cumulative/selective batched receipts,
    ACK piggyback and named repair. Six connected UDP sockets exercise the
    Rust components. The 6/5 controlled Linux TUN comparison drained both
    directions at 0.956 Mbit/s with 55 steady inner TCP retransmissions.
    The optional physical selective-repeat sender reached 28.633 Mbit/s
    with 83 steady inner retransmissions and drained all physical and native
    debt. An offline geometry study evaluates configurable loss/retry goals.
    An optional shared-member/fair scheduler is implemented for comparison;
    transmitter custody and overdue-batching regressions pass. Performance
    acceptance remains open: its fixed 6/5 Linux arm reached 40.064 Mbit/s
    but had 1,339 steady inner retransmissions and a 2.028 s application P99.
    The two Python seeds also diverge substantially. All measured native and
    physical debt drains; these outcomes do not close the performance gate.
    The explicit paced experiment implements a shared directional byte budget,
    bounded physical ACK repetition, logical page rescanning and RTT-based
    deadlines. Its shaper-then-loss harness preserves erased-byte charging;
    the same-binary control and candidate both drain all accepted debt, but
    candidate goodput falls from 27.074 to 3.979 Mbit/s and application P99
    rises from 1.618 to 10.118 s. Source-side queueing is resolved in this draw;
    the early TCP window collapse and performance acceptance remain open.
    Keep production session joining, service configuration,
    and the impaired single-flow performance gate open.
    [Component and closed-loop evidence](modules/frame-channel-experiment.md#independent-physical-paths-for-one-inner-flow).
- [ ] [P-legacy-fragment-packing] Implement and validate `legacy-fragment-packing` (M2); preserve its [parity contract](mode-parity.md).
- [ ] [P-compact-cross-frame] Implement and validate `compact-cross-frame` (M2); preserve its [parity contract](mode-parity.md).
- [ ] [P-full-l2] Implement and validate `full-l2` (M2); preserve its [parity contract](mode-parity.md).
- [ ] [P-tcp-header-codecs] Implement and validate `tcp-header-codecs` (M2); preserve its [parity contract](mode-parity.md).
- [ ] [P-independent-record-arq] Implement and validate `independent-record-arq` (M2 + M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-shared-context-mux] Implement and validate `shared-context-mux` (M2); preserve its [parity contract](mode-parity.md).
- [ ] [P-shared-records] Implement and validate `shared-records` (M2); preserve its [parity contract](mode-parity.md).
- [ ] [P-aligned-records] Implement and validate `aligned-records` (M2); preserve its [parity contract](mode-parity.md).
- [ ] [P-independent-short-records] Implement and validate `independent-short-records` (M4); preserve its [parity contract](mode-parity.md).
- [ ] [P-compact-wire] Implement and validate `compact-wire` (M2 + M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-packed-wire] Implement and validate `packed-wire` (M4); preserve its [parity contract](mode-parity.md).
- [ ] [P-unified-duplex-mux] Implement and validate `unified-duplex-mux` (M2); preserve its [parity contract](mode-parity.md).
- [ ] [P-payload-compression] Implement and validate `payload-compression` (M4); preserve its [parity contract](mode-parity.md).
- [ ] [P-inner-ack-controls] Implement and validate `inner-ack-controls` (M4 + M5); preserve its [parity contract](mode-parity.md).
- [ ] [P-ack-coalescing] Implement and validate `ack-coalescing` (M4); preserve its [parity contract](mode-parity.md).
- [ ] [P-ack-copies] Implement and validate `ack-copies` (M4); preserve its [parity contract](mode-parity.md).
- [ ] [P-aggregate-acks] Implement and validate `aggregate-acks` (M4); preserve its [parity contract](mode-parity.md).
- [ ] [P-reverse-fec] Implement and validate `reverse-fec` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-direct-tcp-baseline] Implement and validate `direct-tcp-baseline` (M5); preserve its [parity contract](mode-parity.md).
- [ ] [P-quic-baseline] Implement and validate `quic-baseline` (M5); preserve its [parity contract](mode-parity.md).
- [ ] [P-kcp-baseline] Implement and validate `kcp-baseline` (M5); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-age-support] Implement and validate `research-age-support` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-age-coefficients] Implement and validate `research-age-coefficients` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-mixed-degree] Implement and validate `research-mixed-degree` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-recursive-parity] Implement and validate `research-recursive-parity` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-recursive-fallback] Implement and validate `research-recursive-fallback` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-rolling-accumulator] Implement and validate `research-rolling-accumulator` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-spatial-coupling] Implement and validate `research-spatial-coupling` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-checkpoint-repair] Implement and validate `research-checkpoint-repair` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-feedback-gate] Implement and validate `research-feedback-gate` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-selective-fallback] Implement and validate `research-selective-fallback` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-bitmap-fallback] Implement and validate `research-bitmap-fallback` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-subpacket-convolutional] Implement and validate `research-subpacket-convolutional` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-lrsc-staircase] Implement and validate `research-lrsc-staircase` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-partial-repair] Implement and validate `research-partial-repair` (M6); preserve its [parity contract](mode-parity.md).
- [ ] [P-research-source-bridge] Implement and validate `research-source-bridge` (M6); preserve its [parity contract](mode-parity.md).

## Completion and public release gates

- [ ] [RELEASE-01] Verify every selected release capability is implemented and integration-tested; expose remaining planned/research capabilities as unavailable.
- [ ] [RELEASE-02] Complete all P-* research ports for a full-parity claim; a narrower release must list exclusions explicitly.
- [ ] [RELEASE-03] Choose project license, stable API/wire/config support policy, security contact, dependency audit and changelog.
- [ ] [RELEASE-04] Publish reproducible native build/test receipts and reviewed artifacts only after separate release authorization.


TEST-12 and PBA-03/06 also track the
[opt-in C48 eight-source forward repair](modules/frame-channel-experiment.md#negotiated-eight-source-forward-repair).
Its new forward wire grammar, independent FEC history, physical byte budget and
gated Linux UDP sender are implemented. Protocol and Python comparisons cover
dropped originals and distinct retained repair identities. The original C48
performance and broader carrier gates remain open.
The combined-backlog Linux UDP comparison completed ordinary v5/v6 and
strict-512 v5 with verified stream contents and bilateral drain. The first
strict-512 v6 attempt hit an original held-ACK deadline in warmup. The
[individual attempts](modules/frame-channel-experiment.md#combined-backlog-gate-on-linux-udp)
track this failure separately from completed samples and modeled throughput.
A same-binary strict v6 repeat completed with 66.27 Mbit/s and zero in-window
eight-source rows. A later [decoder checkpoint](modules/frame-channel-experiment.md#servicing-a-held-ack-during-a-rolling-decode)
passed the focused hold/expiry regression. Its strict v5 control completed,
and its strict v6 attempt missed the same hard deadline in buffer sampling.
Strict v6 qualification and Python-level throughput remain open.
The indexed Aligned/Packed receiver snapshot matches the capacity-scan oracle,
including variable-length proofs and rollback. One strict v6 Linux run on
this release delivered 63.41 Mbit/s and verified bilateral drain. Repeated
deadline stability and the 512-write throughput target are still open.

FIX-04 and TEST-12 also require forward application goodput on one inner TCP
connection at the 80 Mbit/s target. The sixteen-flow aggregate remains a
separate comparison. The [single-connection credit study](modules/frame-channel-experiment.md#single-tcp-connection-and-outstanding-payload-credit)
tracks the payload credit, kernel TCP windows and recovery behavior for this gate.
The [sender TUN loss and single-flow retest](modules/frame-channel-experiment.md#sender-tun-loss-before-packed-source-assignment)
locates both historical gaps before source assignment. The owned Linux
matrix records device TX drops separately from qdisc drops and accepts a
bounded native ring depth and optional per-flow pacing on the sender TUN.
The [same-step source handoff and measurements](modules/frame-channel-experiment.md#bounded-sender-handoff-and-native-ingress-pacing)
cover the sender grant boundary and the independent single-flow performance gate.

FIX-04 and TEST-12 now track [early native TCP delivery across a compression gap](modules/frame-channel-experiment.md#early-ip-tcp-delivery-across-a-compression-gap).
Targeted TUN delivers independently reconstructed TCP segments across missing
records and preserves missing-source recovery and ordered compression state.
Linux namespace trials verified SACK, exact payload and final drain. The
same-release light observer measured 1.035 ms P99 from all dependencies ready
to completed TUN write. End-to-end single-flow throughput and application P99
regressed against the FIFO control, leaving performance qualification open.

FIX-04 and TEST-12 also track the [receiver admission and lost gap request on a single TCP stream](modules/frame-channel-experiment.md#receiver-admission-and-a-lost-gap-request-on-a-single-tcp-stream).
The same authenticated event tape distinguishes a lost reverse request and
insufficient received equations from a locally refused systematic source.
Receiver changes, closed-loop measurements and outstanding targets are recorded
under that experiment.

FIX-04 and TEST-12 track the [single-flow sender TUN ring investigation](modules/frame-channel-experiment.md#sender-tun-ring-pressure-on-one-linux-tcp-flow).
Common retries an already-read packet when sending frees capacity in its
issuing MUX. The native experiment distinguishes kernel ring loss, admission
backpressure, and TCP delivery latency. Single-flow performance qualification
remains open.

FIX-04 and TEST-12 track the [byte-level race between outer repair, inner
retransmission and the returning cumulative ACK](modules/frame-channel-experiment.md#inner-tcp-retransmissions-in-the-single-flow-near8-run).
Two native steady intervals account for every repeated sender TCP segment
in the sample. These observations leave the single-flow goodput and latency
acceptance gates open.

FIX-04 and TEST-12 also cover systematic input refused by the full receive
FIFO while a global repair is active. In one traced native run, repair 3968
held the decoder for 20.726 ms. The later refusal of source 36123 prolonged
recovery of a TCP segment that Linux retransmitted. The
[decoder tests](../crates/l2tunnel-fec/src/rolling/decoder/independent/tests.rs)
exercise independent commitment beyond the repair's support, the original
deadline, old-gap recovery, conflicting duplicates and capacity rollback.
The receiver uses the existing source storage and work allowance. The
same-release pair using this receiver had zero coding FIFO refusals and
zero sender TUN drops. The bounded-delivery run fell to 11.18 Mbit/s after
CUBIC left slow start at 48 MSS. The immediately delivered control reached
34.83 Mbit/s after exiting at 353 MSS. A first [original-UDP
confirmed-prefix comparison](modules/frame-channel-experiment.md#confirmed-source-bytes-in-global-equations)
verified the negotiated format, application hash and old-gap drain and
delivered 13.19 Mbit/s. The native throughput and latency gates remain open.

FIX-04 also covers a local repair that held the decoder when the same
source 36123 was refused. Ten earlier queued repairs extended beyond the
active job's horizon. On this saved FIFO, earlier originals covered every
one of those repair ends before a later original crossed it. The receive
scan now applies this rule to local and global regular repairs, preserves
the debt cap of the original that first evidenced each range and leaves
overlapping sources in FIFO order. A pending repair that first observes a
new range stops the scan. A contract test fills the FIFO, frees slots
during the active local repair and checks all ten native packets after
recovery. [Original FIFO geometry](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kernel-decoder-fences.json)
and [receive regression](../crates/l2tunnel/src/rolling_records/ingress_tests.rs).

FIX-04 and TEST-12 also track the targeted sender's full fresh-source
FIFO. The sender retains the sealed original across zero-progress turns,
reopens on the first slot release and preserves its admission deadline.
The Common service API reports the resource that refused native input.
The scheduling regression covers repeated turns, residual work and the
original expiry. Single-flow throughput and application latency remain open.
[Sender and observation details](modules/frame-channel-experiment.md#crossing-buffered-repairs-with-independent-sources).

FIX-04 and TEST-12 now have a protected UDP regression for a ready short
physical copy. Both immediate affordability and a one-byte credit deficit
are covered. End-to-end single-flow performance qualification remains open.
[Short-copy wake and capture evidence](modules/frame-channel-experiment.md#waking-the-sender-for-the-next-short-physical-copy).

FIX-04 and TEST-12 include a bounded ACK-holder cursor that revisits a sole
pending original at its deadline. The protected UDP runs now tie reverse
source/copy labels and socket acceptance to real TUN packets and CUBIC startup
samples. Linux single-flow throughput, steady inner retransmissions and
application P99 remain open.
[Reverse-carrier measurements](modules/frame-channel-experiment.md#following-an-inner-ack-through-the-reverse-carrier).

The same tasks cover classification reuse and the real FlowBytes wait for a
retained TUN packet. The focused test checks same-turn reopen without growing
the queue. Frozen b78b47d measured 44.02 and 39.79 Mbit/s across two reverse
burst choices; both recovered all observed byte gaps. Native throughput and
latency targets remain open.

The retained-packet wait now also covers profiles without ACK coalescing
(2026-11-22). Previously that plain path read a TUN packet and stopped the
whole session with `Engine(Pipeline(Budget(FlowBytes)))` when the per-flow
queue was full. In the 2026-11-22 campaign this ended Swift FEC and Aligned
Cauchy single-flow runs at 15% loss. A finite Pipeline queue or flow-table
refusal now keeps the packet as the one pending original. The plain path
stops reading and retries the packet after sends or at ingress service,
within the same stall deadline as the coalesced path.
[Plain-path retention test](../crates/l2tunnel-runtime/src/secure_udp/transport_common_ingress_tests.rs).

The base ARQ now accepts windows of up to 8192 records (2026-11-23,
MOD-REC-WIDE-01/02). Its 64-bit bitmap ACK limited every Aligned and Packed
row to 64 records in flight, about 4.5 Mbit/s on the 70 ms lab with no loss.
A direction above 64 records uses a canonical wide ACK derived from the same
authenticated direction configuration. Windows of at most 64, and all control
channels, keep the original bytes. The benchmark rows size the window from
bandwidth × RTT. [Wide ACK design](modules/recovery.md#wide-ack-for-large-windows).

Wide directions also got O(1) amortized scheduling and an adaptive RTO with
once-per-RTT fast resend (2026-11-23, MOD-REC-WIDE-03/04). A reserved Reliable
pair now moves 60,000 sources in 32 ms at window 2048 (933 ms before; 66 ms at
window 64). Native UDP cells, owned namespaces, 100/10 Mbit/s and 70 ms RTT
([receipts](../work/wide-ack-20261123c/ab-summary.txt)): Aligned ARQ 16 flows
74.7 Mbit/s at 0% loss and 32.2 at 15% (4.5 and none before); Aligned Cauchy
4 flows 19.2 at 15% (1.25 before); Aligned ARQ single flow 2.4 over UDP and 8.2
over raw at 15% (timed out before). Packed ARQ still fails natively with
`RetryExhausted` at 0% loss and stays open. Those runs and the last gate shared
the host with unrelated jobs at load average 190–252: five deadline-based
loopback tests failed under that load and pass when run alone, so a clean gate
receipt is still owed.

Three follow-up fixes (2026-11-23, MOD-REC-WIDE-04/05): fast resend now
waits for three later acknowledged single-copy transmissions instead of one
smoothed RTT (queue-inflated RTT caused the Packed `RetryExhausted`); a wide
ACK visits only the sources it covers; Aligned/Packed preview reads a reserved
receipt journal instead of rescanning every receive slot. Reliable also
rechecks the outbound budget before each FEC-loop poll, because a larger
retry after a fresh block source used to fail the owner with `Exhausted`. A
clean full gate passed ([log](../work/wide-ack-20261123d/gate.log), load
average about 10). Native reruns ([results](../work/wide-ack-20261123d/prof/RESULTS.md)):
Aligned unchanged within noise (74.3 / 29.7 / 8.3 / 8.4); Aligned Cauchy 4
flows 33.7 and 18.9 on two runs; Packed single flow 46.4 at 0% loss (failed
before); Packed 16 flows passed once at 20.1 and once failed with
`PeerTimeout`, because the Packed receiver's owner thread drops 31% of
datagrams at its UDP socket and the control ARQ loses a liveness ping on every
retry. That receiver overload stays open.

FIX-04 and TEST-12 include a same-skb Linux receive verdict and a bounded
UDP receive-service change. A matched 64 KiB reverse-burst workload on the
candidate measured 8.34 Mbit/s and 6961.44 ms first-write-to-read P99.
The earlier tree measured 56.80 Mbit/s and 690.82 ms under the same
observation. All final byte gaps closed. The single-flow gate remains open.
[Native byte-level comparison](modules/frame-channel-experiment.md#receive-service-and-inner-tcp-timestamp-validation).

FIX-04 and TEST-12 now have a same-packet-number ordinary-repair rank
replay and a controlled Linux-TCP-through-Python check. The traced native
single flow delivered 51.568 Mbit/s with 864.720 ms write-to-read P99,
369 steady inner repeats and zero final debt. Exact row membership locates
two holes whose named retries made their missing source solvable. The
throughput, latency and retransmission qualification remains open. An
isolated sender refresh-interval comparison produced 49.642 Mbit/s,
768.998 ms write-to-read P99 and 91 steady repeats with zero final debt.
[Rank replay and endpoint observations](modules/frame-channel-experiment.md#separating-insufficient-repair-rank-from-linux-retransmission-timing).

The [fixed-anchor native-IP comparison](modules/frame-channel-experiment.md#fixed-anchor-ip-header-compression)
adds protocol coverage for explicit context selection and old-hole recovery,
plus a Linux UDP single-flow pair. Fixed anchors delivered 20.697 Mbit/s,
2248.718 ms first-write-to-read P99 and 518 steady inner repeats. A receiver
kernel verdict matched the original data for 406 repeats to TCP timestamp
rejection. FIX-04 and TEST-12 retain their throughput and latency gates.

For FIX-04 and TEST-12, fixed-anchor lookahead now skips the body of a frame
already delivered out of order when scanning later records. Three archived
output sequences replayed 21,504 matching native frames with byte-exact
delivery and zero retained records at the end. In the longest replay,
preparation took 31.425 ms over 14,336 frames, down from 37.741 ms.
This isolated receiver measurement schedules complete records in the observed
delivery order. The Linux latency gate remains open.

For FIX-04 and TEST-12, a focused rolling Endpoint regression withholds
sources 0 and 7 from a 12-source flight. One repair and the eventual arrival
of source 0 recover source 7. With spare receive work, the endpoint delivers
source 7 on the recovery turn, seven service turns earlier than in the
previous implementation. All 12 records deliver once and ordered handoff
advances on every turn. Linux timing for this change remains unmeasured.

FIX-04 and TEST-12 now have separate Python socket-credit and TCP-issue
clocks, validated against three recorded Linux application workloads.
The FIFO producer comparison drained at 77.783 Mbit/s; the early-delivery
simulator retained 3,066 unconfirmed writes at its drain deadline. Linux
showed both receive socket starvation and late reverse cumulative ACKs.
Single-flow Linux throughput, tail latency and inner retransmission parity
remain open. [Producer, matched runs and recovery timing](modules/frame-channel-experiment.md#single-flow-socket-credit-and-the-two-directions-of-recovery).

The FIX-04/TEST-12 UDP observer supports both directions on one connection,
with a post-preparation sample and a separate observed device write. A
bidirectional UDP fixture passed. In a historical single-flow Linux trace,
343 preceding records waited in the reverse MUX when one SACK arrived.
Its wait from MUX entry to packer admission reached 81.093 ms.

FIX-04 and TEST-12 now track [negotiated reverse Packed ACK compression](modules/frame-channel-experiment.md#negotiated-reverse-packed-ack-compression).
The bounded source codec, physical-byte charging, independent copies,
named retry and ordinary repair paths are implemented. The protocol tests
recover all native ACKs after losing three systematic copies. The new
configuration has its own authenticated selection. One [Linux TUN/UDP
pair](modules/frame-channel-experiment.md#negotiated-reverse-packed-ack-compression)
integration-tested physical send sizes, positive byte delivery with zero
final holes and drained recovery state. The candidate reached 57.603 Mbit/s
with 769.205 ms write-to-read P99 and 109 steady sender-TUN repeats.
Single-flow goodput, retransmission and latency qualification remains open.

FIX-04 and TEST-12 now compare independent application writes and inner
stream segmentation. The [model runs and complete Linux steady
trace](modules/frame-channel-experiment.md#inner-tcp-packetization-and-steady-forward-recovery)
identify actual fragment counts and reconcile every steady inner repeat
in the traced run. The original throughput and delivery targets stay open.

One subsequent original-UDP run exercised the full-FIFO/idle-decoder fix.
Per-packet admission and same-SKB Linux verdicts distinguish local recovery
FIFO drops, network losses and the TCP timestamp rejection of late originals.
All 1,459 steady TCP repeats had trace coverage, including 296 repeats
where the first byte Linux still lacked had previously arrived at its TUN
and failed PAWS. Its 55.757 Mbit/s and 1,164.158 ms write-to-read P99
leave FIX-04, RWI-03 and single-flow TEST-12 performance open.
[Full replay](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/per-pn-refusal-attribution.json)
and [kernel receive cursor](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz47-cubic-revq-forward-records-verdict-seed31248-65b207a/kernel-prefix-at-retry-paws.json).

FIX-04/RWI-03 now have one [Linux integration sample](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz48-cubic-revq-forward-records-verdict-seed31248-1da52ce/arm-evidence.json)
that exercised both UDP pressure yields and the updated native receiver.
Goodput was 61.442 Mbit/s, write-to-read P99 was 728.437 ms and 48 steady
TCP repeats were captured. Actual socket drops (22) and the 157.329 ms P99
from accepted-input first solvability to native readiness still need work.
The original single-flow throughput requirement remains open.

FIX-04 and TEST-12 now exercise a final queued systematic source and a
committed fixed-anchor TCP delta during ongoing ordered handoff. The
receiver uses the remaining turn budget and the existing symbol slab.
One test recovers an older source exclusively by repair. A second releases
a delta while a lower source is missing and verifies exact once-only
delivery after that hole is filled. A diagnostic observer correlates named
gap requests at each physical and authenticated boundary.
[Fixed-anchor regression](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/committed-anchor-preview-order-gate.json)
and [source and repair checks](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/direct-systematic-fifo-public-probe.log).

The first native run of this receiver plus named feedback tracing regressed
to 22.051 Mbit/s, 1,626.523 ms write-to-complete-read P99 and 178 steady
inner repeats. The final TCP and FEC gaps cleared. FIX-04, RWI-03 and the
single-flow TEST-12 performance requirement remain open.
[Native sample](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/arm-evidence.json)
and [crossing acknowledgments](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-cubic-revq-forward-records-verdict-seed31248-017c72c/steady-forward-retry-causal-join.json).
The old scheduler with the same observer reached 31.169 Mbit/s and
1,297.582 ms P99 with 314 steady TCP repeats. Each configuration has a
single sample under this comparison.
[Matched configurations and limits](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz50-cubic-revq-forward-records-verdict-seed31248-f805267/matched-receive-comparison.json).

FIX-04/RWI-03 and TEST-12 also track the physical-poll credit refill and
bounded gap discovery from authenticated receiver FIFO inputs. The protocol
fixture covers an in-progress equation, an older missing source and two held
copies of distinct originals. A lower-overhead native reference on the
preceding release achieved 71.517 Mbit/s, 661.422 ms write-to-read P99 and
35 steady inner repeats. Single-flow throughput and retransmission parity
with the original Python reference remain open.
[Protocol and native evidence](modules/frame-channel-experiment.md#sender-credit-and-authenticated-gap-discovery).

FIX-04/RWI-03 and TEST-12 retain their original single-flow targets.
The independent forward selector 10 completed a Linux same-binary comparison
with the original selector 6. Its additional physical IP byte count was
zero. A separate low-window run localized at least 6787.909 ms of P99
first-byte send delay to the Linux TCP unsent queue. The first causal outer
loss in that particular run remains unidentified.
[Startup bounds, recovery counters and gate status](modules/frame-channel-experiment.md#single-flow-startup-and-overflow-funded-near8).

Two default-stack setup regressions while constructing other Common record
engines exposed the cost of embedding the optional near8 owner in the
shared engine type. Construction now reserves a single fallible heap slot
only when near8 is selected and includes it in planned and observed storage.
Both original setup cases passed on their normal stacks. The same-batch UDP
clock regression checks that subsequent polls earn elapsed credit exactly
once and do not charge an already sealed source twice. The local workspace
gate passed after these changes. The Linux bandwidth results above used
the preceding frozen builds.
[Local workspace gate](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-19/result.json).

TEST-12 remains open. On the later matched Linux single-flow trial the
post-decode delivery change passed native byte and drain checks. Its steady
goodput was 29.780 Mbit/s with 567 inner retransmissions and a 1602.276 ms
write-to-read P99. The baseline was 33.145 Mbit/s with 441 retransmissions
and a 1329.651 ms P99. The Python endpoint option and finite SACK transport
prototype are separate simulator evidence.
[Window, wire cost and recovery evidence](modules/frame-channel-experiment.md#single-flow-tcp-recovery-on-the-same-packet-history).

The later full local check returned exit 1 on the Common Compact TCP proxy
graceful drain deadline. The identical binary passed the isolated proxy
case. The simulator passed 1754 tests and two subtests separately.
[Full run](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-23/combined-check.log),
[isolated proxy case](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-23/proxy-isolated.log)
and [simulator run](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-23/simulator-only.log).

FIX-04/RWI-03 now have a public receiver regression for an unpublished
named-retry span whose member is decoded while an earlier span is frozen.
TEST-12 retains the single-flow throughput, latency, inner retransmission
and final drain gates. Larger symbols left all 26,088 full TCP segments
fragmented in the checked Linux input. Matching fragment-tail packing in
Python improved goodput on two seeds, with a 6.64 s P99 on the held-out seed.
[Receiver and packetization evidence](modules/frame-channel-experiment.md#single-flow-fragment-cost-and-stale-gap-requests).

The full local gate passed on the gap-request change. The Linux candidate
stopped on the reverse ACK hold deadline before completing its 10 s steady
window. FIX-04 and TEST-12 remain open.
[Local gate](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-24/result.json)
and [failed Linux arm](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/burst-targeted-pair-failure-v2.json).

The follow-up Linux arm with ACK service diagnostics completed independently
of the full workspace gate. It reached 67.184 Mbit/s at 667.147 ms
application P99 with 170 inner retransmissions, zero TUN drops and complete
drain. The original 77.783 Mbit/s Python comparison remains open.
[Single-flow run](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/acklz49-light-burst-custody-seed31248-1ee5ce3/burst-application-evidence.json)
and [completed local workspace gate](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-25/result.json).

FIX-04 and TEST-12 now have an exact capture comparison of the native
header encoder, a source-level accounting of avoided Packed scratch
writes, and a dated request-loss explanation for 17 inner retransmissions.
The comparison keeps the 4 MiB application limit, per-flow MUX admission,
independent delivery and old-gap recovery.
[Sender and recovery evidence](modules/frame-channel-experiment.md#sender-service-cost-and-repeated-gap-feedback).

The three-file Rust candidate reached 69.927 Mbit/s with 577.295 ms
application P99 and 15 steady retransmissions in one completed Linux
single-flow run. The opt-in Python fragment-tail behavior is accessible
from the normal C48 study CLI. The experimental previous-gap echo did
not improve goodput consistently across two Python seeds. FIX-04 and
TEST-12 retain their full acceptance scope.
[Native and Python experiments](modules/frame-channel-experiment.md#sender-service-cost-and-repeated-gap-feedback)
and [local workspace check after source bindings were finalized](../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/full-current-27/result.json).

FIX-04 and TEST-12 also track an independent mixed-packet erasure profile.
The Rust and Python codecs have exhaustive small-group recovery evidence
including every eight-of-ten subset. Intact members expose their original
bytes immediately. Cross-group Rust custody, explicit physical acceptance,
authenticated named retries and cumulative receipts now have a two-socket
UDP loopback check. The tag 10 descriptor and functional Common Engine bind
the full-width feedback, both timers and actual native record custody.
The normal service now accepts the complete reserved owner for both roles
on all four carriers. A second impaired Linux UDP/TUN arm completed all
15,091 application writes and both outer source ledgers drained. It delivered
2.455 Mbit/s. [Native integration and outstanding performance gate](modules/frame-channel-experiment.md#reserved-mixed-packet-service-and-first-native-single-flow).
The fixed-anchor simulator also has a byte-exact Rust record fixture
and two-seed model results for rolling and mixed recovery.
[Packet layout and evidence](modules/frame-channel-experiment.md#mixed-packets-and-local-erasure-recovery).
