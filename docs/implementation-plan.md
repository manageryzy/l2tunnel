# Implementation plan and source projects

The owner requested implementation and testing of an explicit KCP-like mode for
raw or compressed Ethernet. The [KCP-like L2 design](modules/kcp-like-l2.md)
tracks the recovery policy, native delivery, shared API selection, local runtime
checks and separately qualified upstream comparisons. `P-kcp-like-l2` is additive;
existing FEC modes, the pinned `P-kcp-baseline`, management, platforms and the
single-flow throughput target retain their original requirements.

Status: finish the current-format cutover, resolve affected regression failures,
and run the required aggregate check before calling this batch complete. Current
runtime integration and remaining capability work are separate deliverables;
removing an obsolete entry does not implement its replacement.

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

Selected Block FEC systematic records also transmit only their exact original
length-prefixed source extent. Existing reserved decoder rows restore the omitted
algebraic zero tail; repair equations retain their complete actual generation
width. Common configuration/catalog domains are v5 with unchanged policy bytes.
The [batch18 local evidence](modules/buffer-observability.md#coordinated-local-buffer-batch18-validation)
passes. [Native18](modules/buffer-observability.md#native18-exact-source-fill-and-remaining-admission-stalls)
observes zero Cauchy systematic fill; its selected data phases still fail their
original acceptance criteria. Native throughput and full acceptance gates remain open.

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

The preceding [Batch9 scoped evidence](../work/parallel-features-20261115/parallel-batch9-scoped-validation.json)
adds finite selected CompactARQ/Python-event differential and Reliable R0 passes,
actual UDP Rolling three-copy delivery/switching, shared production proxy CLI
adapter/Unix lifecycle checks, and native-IP codec/Aligned/Packed protocol tests.
These are separate finite compositions: selected Compact Common installation and
L3 runtime/native integration remain open. The exact Aligned FIFO pressure repair
passes, while Packed pressure still fails under its original caps. Full-check
attempt2 passed 1,735 Rust cases and 65 Python tooling cases before a runtime loss
fixture stack overflow aborted its test binary; the simulator stage was not reached.
That fixture now stores its actual Driver in the existing fallible StateCell:
all five affected loss/liveness cases pass with unchanged stack limits, timeouts
and assertions. The earlier Clippy failure is also corrected. Affected format,
strict Clippy and rustdoc pass; these continuations are not a whole-batch pass.
Full Python behavior, native, resource, platform, all47 and SW-11 gates retain
their complete definitions.

The preceding [TCP scoped checkpoint](../work/parallel-features-20261115/parallel-tcp-scoped-validation.json)
adds independent verified SNI, retained raw send observations, supported CLI naming
and actual fixed/measured shared-service readiness/cleanup. Affected strict checks
and finite TLS/Unix-device cases pass; failed attempts remain preserved. At that
checkpoint, production
proxy CLI migration, Python behavior alignment and complete native/platform/
resource/performance gates remained open; the finite CLI follow-on is recorded
above. See [naming](modules/tcp-carrier-naming.md),
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

That Wave8 checkpoint preserved open aggregate failures. Its
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

Use the [implementation checklist](implementation-checklist.md) as the durable
progress ledger. Detailed FC, MG, VX, UDP and CL checklists cover the new TUN active
flow control, QoS, internal L2 management, VXLAN, carrier covers and GUI/CLI work.
Update checkbox evidence and capability status with every implementation change.

The preceding parallel carrier batch adds genuine requested-to-effective Common
profile binding, the actual original-carrier shared service and explicit
complete-plan CLI selection. The [finite carrier
ledger](modules/common-carrier-service.md) and [scoped
evidence](../work/parallel-features-20261115/parallel-wave5-scoped-validation.json)
distinguish actual four-family service delivery from external offline
inspection. Automatic retained recovery, full managed lifecycle, production
native CLI startup and every unchanged mode/resource/platform/performance
acceptance gate remain required.

The preceding finite wave4 now provides [initial-only carrier Common execution](modules/managed-common-runtime.md),
[typed failed-backend fresh reconnect](modules/generic-client-service.md) and
[external Common control/inspection CLI](modules/common-client-api.md) against
actual authenticating programmatic shared-service owners. Its [last passed receipt](../work/parallel-features-20261115/parallel-wave4-cases-attempt-3/validation.json)
records nine exact cases in 7.936 s and both-cover CLI execution in 4.131 s, including
exact clock and structural stack repair evidence. The preserved wave4 attempts
contain 26 distinct positive cases, not 26 delivered features; managed contract/
controller evidence is finite pure protocol testing. The [final scoped validation](../work/parallel-features-20261115/parallel-wave4-scoped-validation.json) records successful runtime-only Build4,
both final affected regressions and affected strict Clippy/rustdoc/format
checks, plus checklist and diff checks. Full `tools/check.py` was not run,
avoiding unrelated suites. Initial-only does not schedule
periodic fresh-DH; reconnect is underlying carrier/session service responsibility.
Production CLI connect/serve/TAP startup, full carrier service, automatic retained
recovery, complete resources, all 47 modes, full SW-11/RLNC/parity/rolling/packed/
proxy and native/platform/performance acceptance remain unchanged required work.

The next [Compact consumer slice](modules/compact-endpoint.md) installs genuine
Compact recovery in the existing Aligned/Packed/Engine owners. Its focused
validation is in progress, including selected native-IP runtime integration.

## Target architecture and migration scope

The approved target is a fixed point-to-point tunnel between an owner's client
and server. A reusable common inner secure session must provide peer authentication,
key exchange, record protection, replay defense, rekeying and authenticated
management across every selected carrier, including TCP/HTTPS. This is a
WireGuard-like separation of responsibilities, not a decision to use WireGuard's
wire protocol, a particular library, provisioning scheme, packet format or cipher
negotiation. Those contracts remain open in the
[secure-session design and SEC-01..SEC-12 ledger](modules/secure-session.md).
Account systems, multi-device enrollment and multi-peer product workflows are
not assumed by this point-to-point design.

The operator selects the outer carrier/cover independently of the data algorithm:
OpenVPN-like UDP, QUIC header cover, minimal RTP audio/video-like UDP, or the
original HTTPS TCP/TLS-to-raw path. Swift provides packing, ordering and recovery
inside the selected carrier; it is not an independent default carrier. Its
existing AEAD behavior must survive moving security into the common session.
All other recovery, codec, packed, rolling, proxy and 47 Python-parity requirements
remain in scope, including SW-11 switching between Swift and other record profiles.
QUIC header cover does not require the native QUIC congestion controller. Existing
genuine QUIC remains a separate implemented transport/reference capability. The
RTP cover is a minimal media-like encapsulation, not full WebRTC.

Carrier handshake, common inner authentication, data and management continue on
the same carrier connection or UDP socket and five-tuple. Separate TCP/TLS
bootstrap followed by another UDP data flow is historical implementation evidence,
not the target. The HTTPS requirement remains a real TCP/TLS handshake followed
by raw TCP-shaped packets on the same ports and sequence space without ordinary
TCP ACK-driven transport. Valid HTTPS/H2 streaming is an optional distinct
compatibility profile; it does not satisfy that raw requirement. Each cover needs
its own explicit wire/handshake contract and parser validation. Parseability,
endpoint interoperability and measured ISP classification remain separate claims.

Default automatic recovery is required with bounded timers, retained state and
retry work. A temporary outage retains bounded logical session, delivery and
recovery state for authenticated reconciliation. Peer restart requires fresh
authentication and a new cryptographic session; never blindly replay old-session
packets or reuse their nonces. State retention, expiry, terminal failure and any
fresh carrier connection must be observable. This does not promise preservation
of the old five-tuple when recovery must create a new carrier connection.

These are planned migration requirements. Current certificate-root/name and
exporter-bound member APIs, finite Linux receipts, and existing custom UDP/raw
formats do not implement the common target. Configurable cover SNI now has finite maintained-TLS and supported CLI evidence;
complete effective IPC naming and pin-based verification remain unfinished. Preserve simulator
outputs, source-bound receipts and independently useful existing transports.

## Current execution priority: named Python behavior and L3 TCP

Follow [PBA-01..06](modules/python-behavior-alignment.md) and FIX-14 before
accepting any claim that the Common migration matches the simulator. Bind each
profile to exact Python source/configuration, recovery ownership, ACK path and
measurement units. The per-connection CompactARQ sensitivity and shared Packed
C46/C47/C48 candidates are separate required comparisons, not interchangeable
performance baselines. This changes no default selection.

The additive C48 near8 comparison under TEST-12 uses a separately negotiated
forward descriptor. Measure both socket admission settings against the original
C48 on the same release. Record the measurement window's row count, IP cost,
application latency and final confirmation separately. The original C48 target
and the independent platform and carrier gates retain their existing criteria.

The L3 TCP throughput target also applies to one inner TCP connection using the
selected tunnel. Measure application goodput on that connection with enough
offered traffic to exercise the 80 Mbit/s target. Keep the sixteen-connection
aggregate comparison for the existing FIX-04 workload. Report the socket-level
outstanding payload cap, send and receive buffers, congestion window and peer
advertised window alongside the tunnel's recovery settings.

For the physical-path bundle, compare one inner TCP connection over multiple
connected UDP tuples sharing one directional service budget. Use identical
N/K, byte limits, path holds, lossy feedback, gap timers and endpoint workload
in the Python model and Linux lab. Distinguish an accepted socket send,
observed arrival, successful TUN write and cumulative inner TCP ACK. Report
single-flow goodput, application P99, native TCP retransmissions, per-direction
IP bytes and final debt. Production integration needs authenticated association
of each path with a parent session, slot, epoch and negotiated geometry,
bounded rejoin/drain, and service-visible effective settings under CONN-04.
[Experiment and readiness](modules/frame-channel-experiment.md#independent-physical-paths-for-one-inner-flow).

The [native order and pacing comparison](modules/frame-channel-experiment.md#native-delivery-order-and-sender-pacing-in-the-linux-path-bundle)
records the established-path Linux results for PBL-01 through PBL-03. PBL-04
compares actual original payment progress across physical paths at 12/8 and
6/5. Retain the one-frame control, source custody, old-gap probes and original
deadlines, and report payment spread separately from receiver rank delay.

Compare physical-ACK-driven retries against named requests at identical
geometry and credit, with loss on both feedback and DATA. Collect the
sender's paid packet number, reported ACK window and ranges, timeout,
replacement handoff and native cumulative ACK. Evaluate how N/K changes
first-flight rank, redundancy bytes and the fraction of paid retransmission
bytes. Keep first-flight group failures, retransmitted datagrams and
retransmitted member bytes as separate measurements when datagrams mix
several records.

For the optional shared-member scheduler, measure first-flight service age,
repair entries paid before their natural first flights, pending intent merges
and physical bytes alongside throughput. Compare at fixed geometry and credit.
Do not equate fewer inner retransmissions or shorter first-flight queues with
improved goodput. Keep an independent physical retry obligation when another
path holds an unpaid copy, and check recovery through a healthy path when the
original path remains blocked. Same-turn assembly may combine overdue entries
without postponing their original send deadline.

The first Linux shared-member arm removes delayed duplicate first flights but
increases timeout-driven physical repairs and inner TCP retransmissions.
Audit physical ACK repetition after a lost ACK page, logical delivery arriving
below an active pagination cursor, and actual socket-to-wire queue time before
selecting an RTO or an adaptive coding geometry. A timeout count is not an
independent estimate of link erasure probability. Preserve bounded path-local
recovery, original packet delivery and logical cancellation in any correction.

Compare the optional paced-recovery policy with a same-binary control on an
explicit shaper-then-loss topology. Preserve the historical topology receipts.
Use the same N/K, source credit, endpoint workload, lossy feedback and directional
rates. Reconcile sender payment, source-side post-shaper capture and peer-side
post-loss capture so erased bytes are charged before loss in both implementations.
Report actual byte-pacing waits and physical RTT, and distinguish shorter kernel
queues from debt merely moved into the native admission or batch queues.

The completed 05b/06 pair reduces measurable socket-to-wire queueing but fails
the throughput and application-latency criteria. Before another runtime change,
join the early warmup congestion-window divergence to original native sequences,
distinct shard arrivals and returning ACK/SACK packets. Extend the offline
geometry model with measured loss, retry-byte goals and the probability of a
hole across a consecutive TCP window. Preserve the distinction between a small
repair-byte fraction and infrequent endpoint loss recovery; do not select a
default geometry from one seed or hide an infeasible bandwidth/latency target.

The single-flow study identified a dependency on earlier TCP-header deltas
after all of a record's fragments had arrived. A research candidate encodes
each delta relative to its channel's latest full context. Evaluate the
complete cost of identifying that context, repacking fragments, recovering a
missing context and retiring it safely across an epoch change. Compare
throughput, application P99 and inner retransmissions with the current
chained-delta profile. The implemented fixed-anchor policy uses an explicit
record distance and a separately reserved receiver history. The matched UDP
experiment selects it only in the forward direction. Record same-release TUN
and application measurements separately from receiver replay.
[Header dependency experiment](modules/frame-channel-experiment.md#fixed-anchor-ip-header-compression).

Keep two independent near8 comparisons. The bounded-reordering comparison
changes the receiver's TCP delivery timing and keeps the repair grammar and
sender recovery schedule fixed. The confirmed-prefix comparison keeps immediate
TCP delivery and negotiates a distinct repair grammar. It excludes sources
already cumulatively confirmed at the sender when a global equation is frozen.
Keep the 8192-source maximum, 128-source local repairs, global cadence and named
recovery for old holes. Check equation residuals against captured original
bytes, then measure single-flow goodput, delivery P99 and inner retransmissions
on the same native workload.

Run independent implementation lanes in parallel: actual CompactARQ serial/RTT/
receiver-delay/guarded-retry behavior; flow ownership, learned reverse affinity
and ACK custody; L3 codec and actual rolling/copy execution. The integrator owns
authenticated configuration/wire revisions and selected runtime composition.
Finish the pending TCP carrier/shared-proxy service batch while those bodies are
implemented. Its completion cannot close Python parity gates.

Then integrate the complete global8192/local128/every16 candidate with actual
short copies and ACK coalescing, prioritizing real L3 TCP and preserving L2.
Replace the legacy reliable algorithm-feedback side path for the lossy named
profiles while retaining independent authenticated management on the same
carrier. Explicit lossy ACK bypass needs truthful retirement/drain semantics;
shared Packed ACK recovery remains a separate composition.

Run changed-behavior differential/runtime cases together, reusing unchanged
source-bound results. Run the required full suite at batch acceptance; native
performance follows installed behavior with matched configurations and counters.
Do not substitute component checks, a compile, an enum, RawIp packing or an API
migration for end-to-end delivery. All existing full acceptance gates remain.

## Source projects

| Project | Responsibility | Current state |
| --- | --- | --- |
| `crates/l2tunnel` | Public embedding facade | Exports actual pure reserved Swift/Aligned/Packed/Rolling Engine/mixed Bank, complete rolling tag4, shared native pool/counts and explicit carrier/native completion; full resources/runtime qualification remains separate |
| `crates/l2tunnel-core` | Typed IDs, capabilities, policy and config validation | Initial mode types and structural validation |
| `crates/l2tunnel-wire`, `crates/l2tunnel-session` | Versioned records, parsers, session contracts | Bounded wire/framing and local reload guard; distributed transactions live in management |
| `crates/l2tunnel-auth` | Verified TLS and member authentication | Retained TCP/TLS and generic I/O TLS, exporter/member/config binding and negative tests |
| `crates/l2tunnel-identity` | Reusable existing-member keys and possession proofs | Pure Ed25519 extraction and explicit Noise-bound member gate; same-carrier runtime integration has its own ledger |
| `crates/l2tunnel-security` | Shared opaque protection and explicit Swift v2 compatibility | Pure AEAD/HMAC, domains, metadata, replay and adjacent ratchets; existing Swift runtime consumes byte-compatible owners |
| `crates/l2tunnel-handshake` | Maintained fixed-pattern Noise adapter | Protocol-tested pinned-peer proof, caller entropy/time and final-confirmation custody; explicit managed initial runtime handoff now passes actual UDP/member cases. Production Common timed-v2/fresh-DH installation and full lifecycle remain open |
| `crates/l2tunnel-cover` | Explicit QUIC-header/RTP-like appearance | Bounded pure codecs, without standard transport validity, identification or ISP classification claims |
| `crates/l2tunnel-swift` | Reusable packing/recovery, numbered records and policy negotiation | Pure full-record and directional policy engines, plus bounded canonical feedback; legacy TLS and common-UDP adapters share the coordinator |
| `crates/l2tunnel-transport` | Carrier selection semantics | Capability-aware explicit fallback contract; actual adapters below |
| `crates/l2tunnel-mux`, `crates/l2tunnel-packet`, `crates/l2tunnel-pipeline` | Classification, connection affinity, common admission | Real parsed frames, bounded affinity/channel scheduling and DRR composition |
| `crates/l2tunnel-codec` | L2/L3 fragmentation and compression | None/LZ4 frame bytes, bounded reassembly, Python timestamp/delta and aligned body primitives; complete mode integration pending |
| `crates/l2tunnel-recovery`, `crates/l2tunnel-fec`, `crates/l2tunnel-reliable` | Feedback, ARQ, actual FEC and shared budgets | Selective repeat plus actual Cauchy payload repair and finite compositions; all catalog families pending |
| `crates/l2tunnel-flow-control`, `crates/l2tunnel-qos`, `crates/l2tunnel-active` | Tunnel credit, QoS, demand and measured adaptation | Bounded credits/DRR, authenticated retirement and optional measured target control; no endpoint TCP-window ownership |
| `crates/l2tunnel-management` | Fixed authenticated control framing and mode transactions | Prepare/drain/commit/retire state machine; runtime compression switching qualified; pure whole-message custody, stream gates and leased final-reply authority have protocol/original-UDP fixtures; explicit Swift runtime integration is tracked separately from generic dispatch |
| `crates/l2tunnel-datagram`, `crates/l2tunnel-udp` | Protected custom UDP envelopes and lanes | AEAD/integrity profiles with retained TCP/TLS bootstrap/control; native tests passed |
| `crates/l2tunnel-quic` | Genuine standalone QUIC carrier | UDP-only maintained QUIC/member auth and 36 native TAP/TUN/VXLAN cases with physical MTU captures |
| `crates/l2tunnel-udp-control`, `crates/l2tunnel-openvpn-wire`, `crates/l2tunnel-openvpn` | Preserved standalone control; pure standard OpenVPN outer wire and actual retained TLS/member carrier | Historical custom-gate receipts remain separate. Same-socket outer layouts, opaque transport and actual physical send tickets have focused evidence; actual Common bootstrap/member/Parts/Driver/service selection has finite Linux TAP/TUN evidence; complete lifecycle/native/platform and dissector qualification remain open |
| `crates/l2tunnel-raw-tcp`, `crates/l2tunnel-raw-io` | Single-owner userspace TCP and native adapter | Retained TLS-to-protected-packet transition, runtime and explicit shared client are implemented; original native packet captures and startup sampling are under separate qualification; congestion control, clean drain and broader path behavior remain open |
| `crates/l2tunnel-tcp-proxy` | Explicit TCP ownership and reliable relay | Maintained-TCP legs and ACK-based fixed credit; clean Linux TUN full/half native split, exact-byte/FIN and lane-close tests passed; adaptive proxy windows pending |
| `crates/l2tunnel-device` | Packet-device abstraction and adapter capability rules | Native packet-layer validation and trait |
| `crates/l2tunnel-runtime` | Tokio/clock/I/O orchestration | Retained TCP/TLS, managed compression, active TUN, protected UDP and standalone QUIC; explicit same-socket Common Driver uses the actual four-family Bank and leased State in the sole loop, with finite Unix packet-device switching/liveness/custody and explicit rolling work evidence. Actual OpenVPN inner factory/opaque Parts, Driver/service and four production TAP/TUN cases now have finite initial-only integration evidence |
| `crates/l2tunnel-platform-linux`, `crates/l2tunnel-platform-vxlan`, `crates/l2tunnel-vxlan` | Native device/VTEP boundaries and portable VXLAN codec | Linux TAP/TUN and fixed-peer VXLAN qualified; broad VTEP switching/offloads pending |
| `crates/l2tunnel-client-core` | Shared CLI/GUI lifecycle and local API | Managed TCP, base UDP and Swift paths use the shared service; explicit Common Prepared/Handle and APIv4 carry full configuration/status/catalog/keyed operations, with finite authenticated original-UDP/local-socket cross-profile evidence. Existing APIv1/v2/v3 bytes remain unchanged; Common CLI is wired to the same Prepared/Run and has strict full64 plan/inspection evidence. Four production Linux TAP/TUN cases pass external CLI execution and runtime-failure API survival. Complete failure/resource/lifecycle/native matrices, default retained recovery and GUI remain open |
| `apps/l2tunneld`, `apps/l2tunnel-linux` | Linux server/client entry points | Real authenticated packet forwarding and supported local administrative actions |
| `apps/l2tunnel-windows` | Windows service/client, Wintun or TAP | Explicit foreground TCP/TLS TUN via shared service and owned Wintun; portable/cross-build evidence only, native/service/L2 gates open |
| `apps/l2tunnel-android` | Rust Android embedding library; later narrow JNI | rlib/cdylib staging crate, no JNI |
| `apps/l2tunnelctl` | Local status and reload control | Private Unix status/compression requests; full versioned deployable config parser pending |
| `simulator/` | Existing reference algorithms, experiments and golden oracle generation | Preserved existing Python project |
| `tools/` | Local checks, isolated topology and native qualification | Source-hashed checks, immutable binary snapshots, TAP/TUN/VXLAN/netem, payload/path/cleanup receipts |
| `config/` | Mode requirement catalog; later versioned deployable profiles | Catalog is an inventory, not a daemon config |

The [shared UDP client factory](modules/client-secure-udp.md) passed the
[frozen-source local aggregate](../work/shared-session-client-20261113/validation.json),
including actual same-socket cookie/Noise establishment, existing-member proof
and protected Swift/control over both appearances. The
[Swift record extraction](modules/swift-record-engine.md) removes duplicated
packing/channel/header processing from the legacy runtime. Their ledgers record
the actual checks. Neither source presence nor factory authentication completes
the selected shared-service/native data path or remaining carrier/lifecycle
requirements.

The [new common-UDP runtime/service focused checks](../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json)
passed with unchanged compiled-source inputs, including actual original-socket
transport, native readiness/backpressure fixtures, authenticated Swift policy
changes, explicit credential/CLI validation, versioned local API and manual fresh
reconnect. This follows the factory checkpoint; it does not qualify actual
CLI/TAP throughput. The [separate native lab](modules/secure-udp-native.md) retains
clean, delay, 1%/15% loss, sixteen-flow ACK-return, reverse-bulk stress, payload,
policy/lifecycle and capture acceptance without reducing parent gates.
The [preceding deadline-correction aggregate](../work/secure-udp-native-progress-20261113/attempt-1/validation.json)
passed with stable source inputs. The subsequent [immutable CLI/TAP baselines](modules/secure-udp-native.md#initial-immutable-native-baseline)
exercise exact bytes, real policy commits and manual reconnect for both appearances.
Clean/delay QUIC-like cases passed; both impaired cases failed the unchanged
80 Mbit/s target. Source-backed deadline/wakeup corrections and the remaining
matched matrix require new recorded qualification; these finite observations do
not close FIX-04, FIX-13 or full SW-11.

The [counter-guided correction](modules/secure-udp-native.md#counter-guided-performance-correction)
now has [source-stable focused evidence](../work/secure-udp-performance-focused-20261113/attempt-4/validation.json)
for production class/credit/native observations, shared bounded reports/logging,
original control-loss bounds and output-drain scheduling. The initial-rate burst
and write pre-drain improve finite impaired QUIC-like goodput to70.6236Mbit/s,
with reported native-pressure rejection removed;80Mbit/s remains unqualified.
The later [expanded focus](../work/secure-udp-performance-focused-20261113/attempt-5/validation.json)
and actual immutable CLI proofs validate the IPC-only helper scheduler correction;
build8 reaches77.3464Mbit/s impaired and still fails80. Kernel perf and simultaneous
process I/O observations do not establish disk I/O as the primary cause.
SUR-11 now reproduces and corrects the independent saturated native-read fairness
defect, with a [passing focus](../work/secure-udp-performance-focused-20261113/attempt-8/validation.json)
and both-cover forward/reverse native observations. Build9 forward16 measures
78.6206/78.2435Mbit/s, still failing80; the separate reverse-stress receipts pass
their functional gates. Simulator
overhead sensitivity, sampled CPU/credit and historical-binary replay remain
separate evidence, not a reduction of any mode, lifecycle or performance gate.
The [preceding source-stable aggregate](../work/secure-udp-performance-progress-20261113/attempt-3/validation.json)
passed the complete ordinary workspace checks. Both earlier failed aggregate
attempts remain preserved; actual native80Mbit/s acceptance remains open.
The scheduler checkpoint's [required aggregate](../work/secure-udp-fairness-progress-20261113/attempt-2/validation.json) also passes
1528 Rust cases including doctests, 295 Python tooling cases and 1658 simulator cases, without changing assertions or deadlines. The
conditional wire-capacity estimate in the native ledger preserves the target
and requires separate validation of any future framing/rate proposal.


The additive [generic Swift runtime](modules/generic-secure-udp.md#current-explicit-runtime-checkpoint)
now has explicit runtime-library and shared Prepared/service/APIv3 selection in
that same sole I/O loop. Finite Unix tests use actual original UDP sockets,
maintained authentication, canonical H0/D0 scopes, reserved engines and physical
native writes through two nonzero asymmetric switches. The actual shared service
also passes both-cover traffic, complete-C/key operations, IPC v3 status/switch,
liveness and fresh-session reconnect with periodic reporting disabled. Actual
observations precede successful completion; requested/current/physical values
and incomplete resources remain distinct. All three generic control streams
now use actual reserved ARQ backing; sole-loop inputs are charged and moved once.
The additive [complete-plan CLI](modules/generic-transaction-cli.md) now exposes
explicit generic selection, complete-C APIv3 commands and bounded full-catalog
inspection. Its [source-stable batch](../work/generic-transaction-cli-20261114/aggregate-attempt-2/validation.json)
passes1960 Rust cases including doctests,376 tooling cases and1658 simulator
cases. The external probe executes34 real CLI processes per cover against
actual authenticated shared-service owners and UnixDatagram PacketDevices,
including2 switches and fresh reconnect. It does not qualify successful
production CLI TAP/TUN startup. Existing defaults and fixed v1/v2 bytes remain
preserved. The complete generic IPC/negative-service/fault matrix, full
reservation, cross-profile SW-11 and broader carrier/lifecycle/platform/performance
acceptance remain open. No new native or performance run is inferred.

Additional unfinished source and integration boundaries:

| Unfinished boundary | Responsibility |
| --- | --- |
| Native Windows/Android adapter crates | Reviewed driver/FD/JNI boundaries and native device lifecycle |
| `apps/l2tunnel-linux` (`gui` feature), `clients/android` | Desktop GUI (`l2tunnel-linux-gui`, egui) and future Kotlin Android GUI/VpnService shell |
| Cross-carrier secure-session lifecycle | Complete the existing pure security/Noise/control implementation draft across every carrier, including fresh-DH exchange and default retained-state recovery; parent SEC-* gates remain open |
| Additional carrier and appearance composition | Preserve implemented QUIC-header/RTP codecs and the selected UDP driver while qualifying native use and other carriers; no native QUIC controller or full WebRTC is implied |

[Client design](client-design.md) assigns service/runtime/platform responsibilities;
[flow control](flow-control.md) and [overlays](overlay-and-carriers.md) define protocol
contracts. The second table identifies unfinished boundaries; it does not imply
that another empty package or duplicated secure protocol is needed.

Split actual OS implementations into dedicated adapter crates when native FFI
appears, keeping `unsafe` exceptions outside protocol crates. The runtime crate
owns Tokio orchestration and telemetry. Avoid exposing Tokio
or platform handles in public pure APIs. Add `testkit/` golden fixtures and a Rust
in-memory integration driver at M2; add `bench/` baseline adapters at M5. These
additional projects are planned, not empty claims of functionality.

## Approved parallel execution order

On 2026-11-15 (Asia/Tokyo), the owner approved the following execution order.
Run three implementation lanes with one integrator; independent work may overlap
batches after its shared interfaces are frozen. Preserve the existing milestones,
stable task IDs and complete acceptance definitions below.

1. Finish the current GCN/GSF/CMS/KCA functionality batch: actual production CLI,
   service failures/lifecycle, complete control-message storage and known
   construction admission. Integrate before combined checks and the four
   quic-like/media-like TAP/TUN functional cases.
2. Extend the common session foundation and lifecycle in parallel: reusable
   record-profile interfaces/configuration, authenticated fresh-DH exchange and
   bounded retained-state recovery, and remaining control/resource/fault work.
3. Integrate existing reliable/aligned/packed/rolling/RLNC/parity components and
   the generic engine lifecycle. Complete actual Swift-to-other-profile switching
   under the full SW-11 definition, including typed feedback and native fences.
4. Complete production recovery/record families alongside TUN active credit,
   QoS, explicitly selected TCP proxy and VXLAN isolation/attachment.
5. Compose the common session through the remaining carriers. Preserve the
   original OpenVPN wire-handshake and HTTPS TCP/TLS-to-ACK-independent packet
   requirements, with feasibility, ownership and failure gates before exposure.
6. Deliver shared CLI/GUI and Linux/Windows/Android integration after schema/API
   stability. Retain the existing toolkit decision and actual-device evidence
   gates; public protocol libraries remain independent of runtimes and OS handles.
7. Complete all 47 P-* parity gates, including the15 causal research families.
   Their independent work may start once interfaces stabilize rather than waiting
   for platform work. Existing primitives are reused after source/evidence audit.
8. After functionality, concentrate native performance, kernel profiling, original
   80Mbit/s acceptance and controlled real-path carrier/QoS comparisons in matched,
   immutable campaigns. Preserve negative results and historical receipts.

Each coherent source batch receives cross-review and affected regression checks.
Combine the full frozen-source aggregate and required native acceptance at stage
boundaries. Repair failures with focused dependency-aware checks; do not repeat
unaffected suites after each leaf. Run independent functional tests with bounded
parallelism, retaining shared-resource isolation and explicit reused evidence.
Performance campaigns remain deferred and controlled. This scheduling approval does not change
any mode requirement or select unresolved wire formats, timeout values, a desktop
toolkit, package publication or a project license. Engineering interface choices
remain distinct from owner decisions.

The [current scoped foundation](../work/common-foundation-20261114/scoped-checkpoint-validation.json)
provides the [directional record owners](modules/directional-record-endpoints.md),
[Swift adapter](modules/swift-record-adapter.md) and actual
[control wrapper backing](modules/control-wrapper-storage.md). It retains full
stage acceptance and common cross-profile composition as open work. Complete
directional Aligned/Packed encoding exceeds the transaction configuration's
legacy512-byte bound. The explicit
[CompleteV2 extension](modules/transaction-configuration-encoding.md) and shared
scalar validation now pass a [119-test affected batch](../work/record-composition-20261114/foundation-attempt-1/validation.json).
The [complete configuration](modules/record-configuration.md) source preserves
every selected field and independent direction. The
[448-case affected checkpoint](../work/record-composition-20261114/scoped-checkpoint-validation.json)
also protocol-tests the [fresh-DH contract's](modules/session-refresh.md) selected
initial/managed Joining/member/refresh/Records path. The subsequent
[actual common Engine and backing checkpoint](../work/common-record-engine-20261114/scoped-checkpoint-validation.json)
implements transactional real-queue admission, reserved FEC/Reliable/Aligned/Packed
libraries and the explicit functional three-profile Engine. It passes affected
library and selected downstream caller tests with bounded parallelism. Reserved
mixed-profile Bank and selected runtime/resource/API composition, full stage acceptance, runtime fresh-DH
lifecycle and complete retained recovery remain open. Passing unaffected
checks are reused; a failed new expected literal was repaired with one exact
test rerun rather than repeating the whole batch.

The [actual reserved common Engine checkpoint](../work/common-reserved-records-20261115/scoped-checkpoint-validation.json)
adds complete real queue backing, borrowed admission and one move-only Swift
owner. Actual reserved Swift/Aligned/Packed Engine constructors pass142 distinct
affected cases, including32 new cases, with paired TAP/TUN, asymmetric roles,
full64 byte/identity/witness/charge comparisons and exact Full/Busy retries.
Initial failures and exact reuse bindings remain preserved. Complete mixed Bank,
shared external owners, nested allocator/drop qualification, selected runtime,
full-stage/native/platform/performance acceptance remain open. Unchanged tooling,
simulator and unrelated performance suites were not repeated.

## Ordered milestones and exit gates

### M0: contracts, inventory and tooling

The initial foundation supplied the workspace, library boundaries, CLI
scaffolds, first parser/MUX/reload primitives, a 47-family parity inventory, code
conventions, CI definitions and dry-run network topology. Complete M0 before M1
by reviewing the architecture, freezing canonical config encoding and adding a
strict versioned TOML loader/schema. The current catalog is checked as TOML but is
not the runtime schema; unsupported options must not be silently accepted.

Local exit evidence: fmt, Clippy with warnings denied, unit/doc tests, rustdoc,
mode-catalog consistency, CLI status/non-running behavior and lab-plan safety
checks. Remote CI is a separate receipt; no remote is configured here.

### M1: authenticated connection and transport

1. Freeze the common secure-session contract under SEC-01..SEC-12 before choosing
   a maintained implementation. Specify peer trust/provisioning, authenticated
   capability/digest binding, authenticated lane joins, key domains, record
   protection and common management
   without changing the existing Swift AEAD guarantee. Keep optional inner
   confidentiality versus mandatory integrity/replay protection explicit; no final
   packet format or cipher negotiation is selected by this plan.
2. Compose that same inner session through every selected carrier, including
   TCP/HTTPS. Preserve the original connection/socket and five-tuple through its
   handshake-to-data boundary; UDP must work without a second TCP bootstrap flow.
   Keep existing TCP/TLS and staged UDP receipts as historical scoped evidence.
3. Specify and validate the OpenVPN-like, QUIC-header and minimal RTP audio/video
   cover contracts independently. Header-only QUIC does not require native QUIC
   congestion control; genuine QUIC stays a separate capability/reference. RTP
   does not imply WebRTC signaling, ICE or a full WebRTC stack. Prove bounded
   pre-authentication work, replay, role/lane separation, packet-number exhaustion,
   rekeying, downgrade rejection and exact protected MTU/wire budgets.
4. Qualify the original HTTPS TCP/TLS-to-raw transition with one packet owner,
   retained ports and sequence space, configurable SNI independent of our server
   trust, sequence/window/options behavior, kernel ACK/RST fencing, privileges,
   firewall/conntrack/NAT behavior and
   bounded failure recovery. Keep required peer management alive on that same
   carrier after leaving TLS record transport. Do not substitute H2 streaming or
   ordinary TCP ACK-driven delivery for the raw requirement.
5. Preserve retained TCP/TLS and optional valid HTTPS/H2 compatibility paths with
   their kernel ACK/retransmission/HOL limitations. HTTPS/H2 must honor selected
   ALPN and bounded unauthenticated HTTP handling. Any fallback needs explicit
   operator configuration and an observable effective profile; raw unavailability
   cannot silently select incompatible semantics. Existing genuine QUIC and other
   requested carrier acceptance gates remain independently tracked.
6. Implement the requested L2TP cover adapter with a real protocol contract and
   interoperability tests; do not call TCP prefix bytes L2TP.
7. Implement bounded default automatic recovery, authenticated state reconciliation
   after temporary outage, and fresh authentication after peer restart. Exercise
   retained-state expiry, retry exhaustion, duplicate/late packets and uncertain
   management commits without nonce reuse or blind old-session replay.

Exit: actual selected-carrier handshake/data/control integration, exact bytes and
identity/config binding, hostile/replayed input, original deadlines and bounded
memory/work, captures of connection continuity, and independent cover/raw/platform
qualification. Cover parser acceptance does not prove endpoint interoperability
or improved ISP QoS; the latter needs controlled path measurements. No throughput
target is accepted using only simulation or encryption-byte counters.

### M2: frame bytes, shared MUX and basic codecs

Implement TAP/TUN packet records, arbitrary Ethernet fallback, IPv4/IPv6/VLAN/ARP
classification, symmetric hashing and connection-RR with deterministic simultaneous
open arbitration. Separate physical lanes from MUX channels. Carry business frames
and test SYNs through the same common arbiter, window and channel pool.

Introduce fixed internal L2 management framing independent of data modes, with
user-origin isolation and bounded reliable service in both TUN/TAP sessions. Add
VXLAN pass-through plus an explicit VTEP adapter with VNI/domain isolation, FDB/BUM
limits, loop controls and MTU accounting. MG-* and VX-* define the acceptance gates.

Port full-frame, timestamp/delta header, cross-frame, shared and aligned codecs.
Specify fragmentation, valid-byte/padding semantics, wraparound and context
recovery. Freeze byte-exact Python/Rust vectors for supported reference formats;
version/auth additions use a documented enclosing envelope. Account for changed
MTU overhead. Add bounded queues by bytes and record counts, decoder work limits
and injected-time integration tests before high-load tests.

Exit: random opaque payload round trips, unsupported-header fallback, all truncation
and malformed-length tests, no cross-channel context leakage, no probe privilege,
reorder/dedup/fragment/timeout cases, stable callback ownership and backpressure.

### M3: every production recovery family

Port selective ARQ, first-flight, bounded-gap, systematic block, sliding, hybrid,
elastic RLNC, rank-feedback block and local/global-window recovery; preserve the
catalog's legacy modes as selectable comparison profiles. Implement actual GF(256)
payload arithmetic with byte-exact recoveries, not only rank accounting. Port
feedback batching, cumulative/bitmap/rank acknowledgments, timed partial flushes,
interleaved repairs, reverse FEC, retransmission guards and pacing/path scheduling.

Use finite per-peer budgets and causal feedback only. Define congestion behavior
for UDP/raw under competing traffic; the simulator's known link capacity is not a
production measurement. Reliable TCP normally uses `carrier_only`; an explicitly
selected overlay mode may run for parity experiments but cannot remove outer HOL.

Exit: all M3 catalog entries have golden vectors plus trace-based decisions and
real-payload reconstruction tests. Measure CPU cost and retention bounds; compare
loss/reorder/burst traces with fixed input budgets and honest terminal confirmation.

Implement TUN active tunnel credit and per-flow QoS with few-flow probing,
receiver reservations and active backpressure (FC-*). TAP continues endpoint/system
TCP behavior and system-backed QoS. Keep TCP windows, tunnel credit and carrier
congestion control independent and observable. Real TCP-window acceleration is
implemented through the explicitly selected TCP proxy in M4, not header rewriting.

### M4: small packets, compression and coordinated hot switching

Port independent-short release, generic short-source copies, context-only selective
copies, packed sources, exact reverse ACK records and aggregate ACK encodings.
Keep simulator-only ACK-generation/congestion-controller knobs in workloads;
production ACK coalescing needs a safe parsed-frame rule with unchanged fallback.
Add optional bounded payload compression as new work, with expansion fallback and
explicit compression-context epochs.

Implement `tun_tcp_proxy`, owned TCP leg lifecycle and buffer-backed window
advertisement; document ACK responsibility, source addressing, recovery/failure and
unsupported-flow semantics. Do not migrate existing transparent TCP flows into a
proxy on reload. Complete all FC-* active-flow and QoS gates.

Implement the full PREPARE/READY/DRAIN/COMMIT/RETIRE protocol from architecture.md
over the stable internal L2 management channel of the common secure session.
Allow compatible MUX, codec and recovery changes without breaking outer sockets.
Handle duplicate/lost control messages, old frames, commit uncertainty, shrink
limits, staged state expiry, simultaneous proposals and peer restart. Packet/key
counters cannot reset during a switch. Device-layer/trust/endpoint changes use a
controlled reconnect and must be reported as such.
SW-11 explicitly includes negotiated epoch switching between Swift and other
record profiles. An in-Swift policy change does not close that requirement or
reduce any RLNC, parity, rolling, packed or proxy acceptance gate.

Exit: two-endpoint fault-injection tests at every transition, exactly-once frame
release, no old/new context mixing, all M4 inventory modes exercised, saturated
small-packet tests with measured CPU and bounded memory. Enabling an enum or a
local ReloadGuard is not this milestone.

### M5: platform clients and real local validation

Build the shared client-core/local control API and full CLI, then desktop GUI
and Android GUI using the same operations, schema and capability reporting. Follow
CL-01..CL-39, including common secure-session selection, bounded outage recovery,
asynchronous reload progress, privilege separation and
CLI/GUI parity. Select a desktop toolkit at its explicit design gate.

Complete Linux TAP/TUN wrappers, Windows Wintun/TAP driver/service handling, and
Android Kotlin VpnService plus JNI/FD ownership/socket protection. Keep control and
library APIs reusable by another application. Validate actual Windows and Android
devices; CI target checks alone are insufficient.

Use [the isolated bridge/route/netem plan](testing.md), then add daemon launch,
traffic generation and receipts. Baseline fixed 100/10 Mbps, 70 ms RTT, 15% IID loss,
MTU 1500; extend 0/10/20% loss, burst, reorder, duplication, jitter and PMTU changes.
Test payloads 64/256/512/1024/1228/1448, 1/2/4/16/64 demanding flows, half/full duplex, idle tails,
competing TCP and hot switches. Include actual OS TCP, QUIC and pinned upstream
KCP comparisons. KCP's no-congestion-control reference is labeled, not a safe
internet default. Keep inner TCP over QUIC/KCP on the same ordered stream/queue as
its probes when matching that campaign.

Exit: recorded configuration/source hashes, kernel/tool versions, captures,
qdisc stats, CPU/RSS, same-window goodput/byte cost/SYN P99, complete delivery and
outer confirmation, CI/native-device receipts, fuzz/parser robustness, and a
reviewed public API/license/release process. Optimize only after baseline validity.

### M6: causal research algorithms

Port the 15 causal research families listed in the catalog as explicit experimental
strategies, with their own real-payload and protocol-integration gates. Preserve
negative results and analytic diagnostics. Oracle/converse/counterfactual results
remain test/research tools and are never runtime modes or performance guarantees.
M6 is required for complete research parity, but does not block an honestly scoped
M1–M5 release that identifies its supported modes.

## Release and progress rules

For FIX-04 and TEST-12 qualify the reverse `TargetedExactAckLz4` experiment
against the same fixed-anchor Linux UDP control, on one TCP flow with 4 MiB
of application credit. Verify the physical reverse sizes of all copies, the
original bytes recovered after loss, the ACK return time, application goodput,
write-to-read P99, inner retransmissions and terminal recovery. Report the
corresponding FIFO and early-release model results with their TCP semantics.
The original Packed parity and platform gates remain separate.

For the same single-flow comparison, preserve both the historical one-write
TCP segment and stream segmentation up to the observed Linux MSS. Price each
physical copy after Packed fragmentation. Compare MUX admission to physical
send, receiver admission to first solvability, native delivery, and the first
covering TCP ACK for each steady retransmission. Treat authenticated inputs
refused by the recovery FIFO as local losses in the same-event replay.
Keep the original throughput target and validate out-of-order delivery and
old-hole recovery under the same capacity bounds.

For FIX-04 and TEST-12 distinguish a missing source at B from the wait
between FEC input, record admission and native preparation. Compare
application credit with actual TCP unsent bytes, congestion window, SRTT
and flight on the same samples. Trace the first named gap request from B
selection to physical acceptance, A authenticated input and application,
and the first corresponding named data send. Keep request losses and
ambiguous request-to-retry matches visible.

For the same Linux flow, compare the old receiver schedule with the candidate
under identical observation. Trace the first sustained TCP recovery episode
from its original outer sources to the first covering cumulative ACK at both
endpoints. Include startup congestion-window changes and duplicate SACK reports
when interpreting steady goodput. Keep receiver service time paired with its
offered load.

For the independently selected near8 headroom profile, compare the existing
forward selector 6 and selector 10 with the same reverse ACK compression.
Account for additional equations at physical IP acceptance, preserve the
ordinary source, repair and named-retry schedules, and inspect the effective
selector and its counters before attributing a throughput difference to FEC.

For FIX-04 and TEST-12, qualify the optional simulated TCP endpoint against
captured DATA arrivals and ACKs at both TUNs. Validate the cumulative edge,
ordinary SACK blocks, duplicate SACK blocks, their order and their actual
option bytes with timestamps enabled. For the closed-loop comparison, carry
those bytes through the selected reverse MUX and Packed codec. Count feedback
only after receiver-side reconstruction. The sender study must bound how many
holes it retransmits by its congestion window and estimated outstanding data.
Record data still missing when PAWS rejects an older copy, real and redundant
retransmissions, paid reverse bytes and final confirmation. Keep the historical
FIFO reference, immediate TUN delivery and old-gap recovery as distinct checks.

Compare record splitting and actual Packed source counts separately at MSS
1,448. In the frozen Linux input all full-sized data segments still required
two aligned units at the largest symbol that fits the current advertised
worst-case union in one datagram. Use the Rust 500 µs tail-packing rule in
the matched Python control. For repetitions whose full byte prefix appeared
at the receiver TUN, correlate the first uncovered byte with the kernel's
receive cursor, individual packet verdict and first returning cumulative ACK.
Count repeated ranges separately from distinct blocking gaps.

At fixed application credit, compare socket-accepted forward IP bytes
with inner TCP acknowledged bytes at the same steady snapshot boundaries.
Price regular FEC, named retries and copies separately. Before changing
the default request policy, compare repeated gap masks with identical
directional physical copies and per-source deduplication in both model
arms. Include serialization, actual retries, control service and final
drain in the experiment.

For the mixed-packet profile, compare every admissible erasure subset at
representative group sizes against actual-byte Rust and Python codecs.
Exercise loss above the threshold followed by a late member, early direct
delivery, the oldest input's deadline and shortened groups under the physical
MTU. Report useful, parity, metadata and repeated bytes independently for
both directions. In the single-flow workload measure time to seal, kth distinct
arrival, first decodability, actual native delivery and cumulative TCP ACK.
Keep authentication, named recovery, application credit and independent
delivery in the normal carrier integration gate.

The authenticated UDP fixture exercises full-width named feedback and
inclusive confirmation through the last possible source. Tag 10 binds both
directional policies and the functional Common Engine uses the mixed owners,
physical completions, timers and actual native codec. The Bank now supports
the mixed owner's complete reserved storage. UDP, raw TCP, TLS and QUIC
pass normal service resource preflight. Two impaired Linux UDP/TUN single-flow
runs transferred every application record. The second arm also drained all
directional source custody. The single-flow goal above 70 Mbit/s remains
open. Compare paid bytes at matched native input times as well as the
closed-loop response of the inner TCP sender.
Use the sender's cwnd, effective flight and ACK progress across the entire
measurement. Join late retries to their direct or recovered data, required
header context and both native TCP timestamp histories. The 12/10 run
shows separate failures at each of these boundaries.
[Linux window and retry evidence](modules/frame-channel-experiment.md#single-flow-congestion-window-and-header-dependency).
Qualify shortened groups by physical membership as well as negotiated
geometry. Check a double loss from the same source, submit time, seal
eligibility and MTU against the six original sends. Compare any cross-source
alternative at the same offered application load, with serialized repair
bytes and a second loss seed, before selecting a Rust wire profile.
[Short-group measurements](modules/frame-channel-experiment.md#erasure-protection-at-the-short-group-deadline).
For TCP parity, report whether the sending endpoint consumes SACK ranges,
how it reenters recovery after a partial ACK, and how the connection starts.
Use the exact native record codec and a common event trace when attributing
a difference to receiver scheduling.

Every catalog item progresses from `planned` to `implemented` only with an actual
algorithm and focused tests, then to `integration-tested` with a receipt naming
carrier/platform/configuration. Record unsupported combinations explicitly. Keep
API semver, wire version, configuration schema and algorithm IDs independent.

The eventual public library needs a chosen license, minimal dependency/features
policy, supported toolchain/platform matrix, security contact and changelog. No
license was chosen on behalf of the owner; crates currently prohibit publishing.
Runtime dependencies will be locked and audited at introduction. Add cargo-deny,
fuzz targets and dependency advisory checks when those dependencies exist; the
current pinned dependencies do not imply a completed advisory/security audit.
