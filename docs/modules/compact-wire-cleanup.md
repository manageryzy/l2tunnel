# Compact final wire format and implementation cleanup

Status: **cutover in progress; focused current captures passed; aggregate validation pending**.
The owner requires removal of the old implementations and obsolete format-only
tests, without retaining compatibility copies. Git provides source history.
Existing algorithm and platform requirements remain requirements; a deleted
entry point does not prove that its replacement is implemented.

## Required cutover and repair extent (2026-11-17)

All actual client/service entry points must use the same current record engine.
Swift, Aligned, Packed, Rolling and Research are recovery/record selections inside
an explicitly selected carrier. Initial appearance and authentication retain the
original carrier ownership. No TCP/TLS bootstrap followed by a separate plain
UDP data flow remains an acceptable production alternative.

The final record prefix is one kind/reader byte and a four-byte packet number.
The selected algorithm contributes only its active union arm; a maximum-size Rust
enum does not impose wire padding. Authenticated local context binds session,
direction, lane, epoch and configuration without repeating them in each packet.

| Protection | Record prefix and check | Meaning |
| --- | ---: | --- |
| ChaCha20-Poly1305 | 21 bytes | Default authenticated encryption |
| HMAC-SHA256 | 37 bytes | Clear body, full authentication |
| AES-CCM4 | 9 bytes | Explicit short-tag authenticated encryption |
| ChaCha20/CRC32C | 9 bytes | Explicit encryption with an unkeyed error check |
| Management and recovery feedback | 21 bytes | Independent full-tag domain |

Opaque proxy records also contain credit and lifecycle controls. When ordinary
data selects a short check, these records use the authenticated-data union arm
with a full 16-byte tag and 21-byte overhead. This arm shares the strong feedback
counter and replay window, with a distinct authenticated route; it cannot acquire
feedback authority by changing the public selector. Actual geometry and status
must reflect this exception before authenticated establishment. HMAC and full-tag
data selections already provide strong protection.

The proxy application adapter removes the old 44-byte repeated tunnel header.
Its current local stream boundary contains a four-byte length and a one-byte
Data/Control union. Application flow records, record packing, ARQ/repair fields,
fragment fields and physical carrier costs are additional and separately counted.

### Repair extent

Rolling, Research and sliding repairs carry the maximum encoded source extent
in the entire selected support. The encoded original length and meaningful
trailing zero bytes are included. A receiver restores omitted zero columns into
its bounded configured symbol slab before GF decoding. Coding width and memory
bounds remain fixed; the serialized equation and byte charge use its effective
extent. A sender cannot charge a full-width repair and emit a shorter one, or
charge an unfinished equation. Held output keeps its original deadline.

The wire versions and canonical configuration digest domains change together;
old padded repair grammars are not accepted as a fallback.

## Evidence and remaining work

The preceding cutover receipts are under `work/compact-cutover-20261117/`.
They describe the source before the additional old-Records removal below.

- FEC component run: 142 tests passed; actual Records extent/lost-source fixture
  passed. A 112-byte equation is serialized as 115 bytes with its union fields,
  rather than extending it to the configured 1,026-byte equation width.
- Native delivery window: four facade cases and one authenticated UDP/device
  integration passed. The integration holds native output and verifies that ARQ
  ACKs do not release delivery credit; Aligned-to-Packed switching waits for debt.
- Native LZ4: seven codec/facade/Aligned/Packed cases passed, including loss,
  reordering, exact native recovery, malformed lengths and disabled-feature refusal.
- Current data protection: seven focused security tests and the compact Records
  integration tests passed, including the full-tag authenticated-data proxy route.
  Proxy regression passed 59 of 62 cases initially; three stale byte-count
  assertions still expected the removed 44-byte header. Their corrected literal
  expectations passed a focused three-case rerun. Both attempts are retained.
- Raw replacement matrix: the current Full/Half TAP/TUN injected-I/O matrix
  passes after separating recoverable receive-cache maintenance from immutable
  outgoing custody deadlines. A further actual-runtime regression exposed missing
  FEC maintenance while output was held; its correction and four original-cap
  regressions pass. Earlier failed attempts are retained. None of these checks
  qualify kernel raw/TAP/TUN behavior.
- Current owned-namespace captures passed for real maintained TLS and QUIC
  four-family switching and original UDP lost-source repair. The first TLS/QUIC
  attempt failed because the Rolling configuration decoder still accepted old
  source versions; the current decoder accepts 3/4 and rejects 1/2. Its focused
  parser test and both actual-carrier reruns passed.
- The UDP loss fixture discards the physically sent source, holds a repair across
  WouldBlock, recovers the original native bytes including meaningful trailing
  zeros, and checks actual byte charging. For its 100-byte native frame, capture
  observes a 136-byte UDP payload / 164-byte IPv4 packet: 115 algorithm bytes,
  21 protection bytes and 28 IP/UDP bytes. This is not a universal packet size.
  Capture analysis does not decrypt ciphertext; interpretation uses the exact
  passing endpoint fixture. See `capture-attempt2/summary.json` in the receipt
  directory, with per-case packet CSVs and binary/capture hashes.
- Portable Common readiness has one Linux-hosted bounded-polling test. This is
  neither a Windows build nor a Windows/Android runtime qualification.
- Current final-route checks pass all 64 strong-data reader slots and keep
  them disjoint from supported bootstrap prefixes: seven security cases, eight
  raw cases and three QUIC/OpenVPN cases pass. Half receive validation now uses
  the same Records parser for ordinary and strongly authenticated user data;
  its focused direction/control regression passes. No wire bytes were added.
- The current client continuation has resolved raw preflight geometry, exact
  current-configuration no-op switching, catalog rejection and test-port
  conflicts. Actual maintained-proxy failures exposed peer close with retained
  management debt, measured physical handoff expiry and an inner ARQ retry
  exhaustion. The last error occurred with no Quinn-reported packet loss;
  that observation does not prove that Common consumed every received datagram.
  Current end-to-end outcomes remain separate from the focused checks below.
- Measured whole-write completion now wakes the actual actor callback rather
  than waiting only for a periodic turn. Three focused checks pass: a receipt
  before the unchanged handoff cap wakes its callback, genuinely late callback
  and Bridge observations still fail, and coalesced receipts retain exact
  identities and ownership. This correction does not by itself qualify the
  complete measured maintained-carrier path.
- Proxy retirement now includes retained management obligations. Full final
  source ACK, physical output, peer EOF and actor-join evidence stop only new
  periodic probes; existing challenges, pongs and control recovery keep their
  original deadlines. Four focused checks pass, including explicit rejection
  of remaining control debt at the original cap and physically retained final
  retries. Typed peer-close handling preserves non-close errors, partial input,
  receipt failures and the original local retirement cap.
- The final focused client batch (`client-final-attempt6/results.json`) passes
  real TLS Full fixed proxy, real QUIC Half fixed proxy and the original UDP
  fixed/measured protection matrix. Both maintained measured cases still fail
  their original 50 ms handoff deadline, with the oldest physical receipt
  absent in this attempt. An earlier TLS attempt had a physical receipt before
  the cap but a callback after it; the complete admission-to-callback path is
  therefore still unqualified. Before old-Records deletion, the accumulated client inventory had 188 passing
  names out of 190, with these two names unresolved. Reused passes and focused
  reruns are indexed in `scoped-verification.json`; they are not one pristine
  execution of the current full suite.
- Before old-Records deletion, the runtime inventory had passing retained/focused
  receipts for all 372 names. Final formatting, workspace all-target/all-feature Clippy, affected
  package warnings-as-errors rustdoc, checklist validation and diff whitespace
  checks pass. The complete `tools/check.py` gate remains unpassed because the
  maintained measured client cases remain failures; no full-suite success is
  inferred from the inventory coverage.

Deletion work and current-route integration are separate from these finite
checks. The owner explicitly approved deleting old entry points while recording
Common active TUN credit and the Windows Common service as pending gaps; neither
requirement is removed. The owner explicitly reiterated removal of the old Records owner on 2026-11-17.
The fixed/refreshable record wrappers and their obsolete runtime consumers are
removed under that authorization; current deletion receipts are stored in
`work/old-record-removal-20261117/`. The former automatic-review rejection is
historical, not a requirement to preserve those implementations. Fresh-DH
integration through the removed refreshable wrapper must be reimplemented for
the current owner; lower cryptographic primitives and complete lifecycle
requirements remain in scope. Other obsolete harness command generators are
tracked separately from final-record removal.
`tools/check.py` and current external CLI processes must pass before the cutover
is called complete. The first required-check attempt lacked system-Python
`aioquic`; the existing `/tmp/l2tunnel-quic-venv` passes dependency checks. Later
attempts reached formatting and all-target Clippy failures during the cutover.
The workspace test run then exposed stale assertions, a real authenticated-data
route/bootstrap prefix collision, raw final-buffer geometry errors and two
default-stack fixture overflows. Focused corrections are being verified without
repeating unchanged successful scopes. The runtime continuation initially passed 123 of
126 previously unfinished cases. Both maintained TLS Half shutdown failures and
the raw output deadline failure now have passing focused corrections. The held
output FEC-maintenance regression also passes without extending deadlines.
Current external CLI verification passes 100 actual process invocations across
QUIC-like and media-like UDP, including catalog, switching and fresh authenticated
reconnect. The two maintained measured-proxy service failures remain unresolved; their
correction is outside this old-Records deletion batch.
The full simulator passed
1,658 cases, the Python harness tail passed 356 cases, codec no-default-feature
checks passed 113 cases, and warnings-as-errors documentation compilation passed.
These are separate stage receipts, not a pristine aggregate pass.
Standard protocol parseability, interoperability, identification resistance and
ISP/QoS effects remain separate claims. Maintained TLS and QUIC retain their own
transport overhead and recovery; their send counters describe local acceptance,
not NIC transmission.

## Old Records removal (2026-11-17)

The current facade has only Compact owners. The fixed and refreshable wrappers,
old route/framing module, old CPU benchmark, standalone Legacy/Generic runtime
constructors and their exclusively old-format fixtures are removed. Current
Common contracts require an explicit selection; final receive dispatch uses the
current Engine parser for Swift, Aligned, Packed, Connections, Rolling and
Research. Initial-only Noise authentication remains a separate layer.

The owner explicitly approved the remaining obsolete core send/receive/wake and
SwiftPolicyV1 runtime cleanup while retaining Common functionality. Current
Common control, liveness, physical receipts, original deadlines, byte admission
and negotiated epoch transitions remain required. The shared driver's inactive
old native/control state is not retained as an alternative execution path.

The frozen facade check passed 24 secure-record and three same-UDP-session cases.
One shared build then ran the runtime and client suites concurrently: 264/270 and
187/190 passed. Three runtime fixtures still assumed the old feedback counter,
old source layout or larger record overhead. Their corrections passed focused
checks, including a real multi-fragment source at the unchanged 1500-byte MTU.
The two QUIC Half switching failures passed unchanged-binary isolated reruns.
The raw Full/Half TAP/TUN matrix failed again in isolation, then passed a further
run with failure-only diagnostics. No production timing fix or relaxed deadline
explains these passes; the earlier intermittent failures remain unresolved.
The accumulated runtime inventory now has a passing receipt for all 270 names;
this is not one pristine full-suite execution.

Three maintained-proxy client cases remain failures: fixed QUIC Half and measured
QUIC Half exhaust inner ARQ retries; measured TLS Full reaches its original
physical-handoff deadline in isolation. Prior passes do not close these current
failures. The raw status correction derives observed overhead from the actual
runtime snapshot and accounts for the proxy strong-data arm in requested output.
Raw native and proxy service continuations pass with the actual requested and
effective status assertions. No native kernel, Windows or Android execution was
performed for this deletion batch.

The required `tools/check.py` attempt stopped at compilation; those compiler
errors were repaired and the strict workspace Clippy/rustdoc stages were run
separately. The full aggregate remains unpassed. Unchanged simulator and saved
experiment evidence were preserved rather than rerun or overwritten. See
`work/old-record-removal-20261117/validation.json` for source inventories, actual
commands, focused continuations and every failed attempt. The prior 372-runtime
inventory above refers to the removed-backend source and is not the current count.

Fresh-DH refresh must be integrated with the current record owner separately.
Common active TUN credit and the Windows Common service remain explicit gaps.
Deleting their old entry points does not reduce SEC, SW-11, platform or any of the
47 Python-mode acceptance definitions.

## Current overhead audit and maintained receive correction (2026-11-17)

Fresh receipts are under `work/overhead-failures-20261117/`. Captures use the
source at `4ef12d8`, before the receive-only correction below. Three actual
fixtures passed in separate owned loopback namespaces: retained TLS, genuine
QUIC and UDP lost-source repair. Capture drops were zero. Native endpoints in
these fixtures are Unix devices, not kernel TAP/TUN. Captures do not decrypt the
inner records; algorithm interpretation is joined to the exact endpoint fixture.

Record protection is only one term. The following IPv4 costs exclude algorithm
fields, packing, padding, repair copies, feedback and connection setup. They
include the 21-byte strong record protection; ordinary 9-byte protection saves
12 bytes, while HMAC adds 16. Proxy control-bearing data and feedback cannot use
the ordinary short-check deduction.

| Current final carrier | Carrier plus strong record overhead | Evidence and conditions |
| --- | ---: | --- |
| QUIC-like or media-like UDP; OpenVPN-established final UDP | 49 bytes | 20 IP + 8 UDP + 21 record; final data has no repeated mimic envelope or OpenVPN opcode |
| Raw TCP after TLS bootstrap | 61 bytes | 20 IP + 20 raw TCP + 21 record; source/injected-I/O evidence, no fresh kernel raw capture |
| Retained real TLS | 100 bytes | 20 IP + observed 32 TCP + 5 framing + 22 TLS 1.3 + 21 record, conditional on one record per TLS record and TCP segment |
| Genuine QUIC DATAGRAM | 78-81 bytes | Conditional single short-header packet/DATAGRAM, observed 8-byte CID, 1-4 packet-number bytes, 16-byte QUIC tag and 2-byte DATAGRAM length |

TLS/QUIC segmentation, coalescing, padding and outer ACK traffic prevent a
universal fixed packet cost. The QUIC range is derived from the pinned encoder
and visible CID, not decrypted packet-number/frame measurements. The TLS capture
contains 224 pure TCP ACK packets and observes 32-byte TCP headers on ordinary
packets. Configured TLS 69/70-byte and QUIC 156-byte admission allowances are not
measurements. IPv6 adds 20 bytes to the UDP examples. Full/Half has the same
per-packet grammar; Half additionally establishes and manages another connection.

For RawIp/literal native packets, the existing native CLI fixtures explicitly use
Swift source capacity 1016, Aligned symbols 256 and Packed symbols 320. There is
no single product-wide default symbol. Early IDs occupy one varint byte and
source copies are one. These are current encoder derivations, not fresh captures
of each algorithm:

| Algorithm | 100-byte native: algorithm / strong record / IPv4 UDP total | 1400-byte native: strong records / IPv4 UDP total |
| --- | ---: | ---: |
| Swift | 108 / 129 / 157 bytes | 1455 / 1511 bytes, two packets |
| Aligned direct ARQ | 259 / 280 / 308 bytes | 1680 / 1848 bytes, six packets |
| Packed direct ARQ | 112 / 133 / 161 bytes | 1578 / 1718 bytes, five packets |

Aligned still serializes the entire symbol; the 100-byte example has 150 zero
bytes. Packed serializes the effective unit extent. Two 100-byte native packets
coalesced into one Swift source total 232 strong-record bytes; Packed totals 246.
Separate source records cost 258 and 266 respectively. Ordinary ARQ does not
concatenate independent retransmissions into a new record; multiple native
packets already in one source retransmit together.

The fresh UDP loss capture observes the 100-byte fixture's source as 133 UDP
payload / 161 IPv4 bytes and each repair as 136 / 164 bytes. The repair's 115
algorithm bytes include its effective equation extent, not a configured
maximum-width slab. This does not remove Aligned source padding. Block FEC still
extends shorter sources to the generation's actual maximum source width.

Other branch costs remain explicit. With `v(x)` denoting canonical varint width
and `P` the actual recovery body, direct ARQ adds `1+v(source)`, Compact ARQ adds
`1+v(source)+v(serial)`, Rolling repair adds `1+v(repair)+v(end)` to its effective
equation width, and Research adds `v(confirmed)` further. Block FEC adds
`1+v(generation)+v(symbol)+v(source_count)+v(width)+source_count` to the actual
generation width. Per-connection Compact adds a 10-byte route. Optional outer LX
fragmentation adds 40 bytes per fragment, before each fragment's record/carrier
cost. Feedback adds its own algorithm fields and a separate strong record;
retransmission, repair and configured copies incur the complete emitted cost.

Proxy Data retains 56 relay bytes, 24 flow-envelope bytes and the 5-byte local
length/union, all passed into Common: 81 bytes before codec/recovery. The failing
maintained proxy fixtures explicitly select 1024-byte Aligned symbols. A
100-byte application chunk therefore has 837 zero bytes and becomes a 1048-byte
strong record before carrier overhead. A 1400-byte chunk becomes two records
totalling 2096 bytes. These application-byte examples must not be compared as
native IP packet sizes. Proxy currently requires Aligned/direct ARQ; Packed's
smaller cost is not its implemented behavior.

Failure tracing reproduced all three maintained proxy failures. The bounded
receive loop repeatedly called a cache-only receive method: after one record,
later iterations returned WouldBlock even when the maintained owner could yield
more input. The correction promotes at most one ready maintained record per
existing batch iteration, using the real task waker without waiting on Pending.
It preserves receive/ingress quotas, original arrival timestamps, send receipts,
deadlines and Half routing; it adds no queue or timeout extension.

The corrected deterministic three-frame/two-record-budget regression and original
partial-input deadline test pass. Fixed QUIC Half proxy passes with tracing and
again without tracing. Measured QUIC Half and TLS Full still fail without tracing
at their original handoff cap. In the diagnostic QUIC run, admission-to-selection
already exceeded 50 ms. In TLS, acceptance was at 47.9 ms, receipt observation at
49.7 ms and actor callback at 50.7 ms against the original 50 ms cap. Those timing
samples include diagnostic overhead; they locate stages, not production latency
guarantees. Queue/admission/selection and callback scheduling remain unresolved.
Temporary per-packet diagnostics were removed after preserving the traces.

The first new regression attempt exposed an incorrect synthetic TLS frame length;
its corrected length includes the discriminator. All attempts and source/binary
hashes are retained. The required system-Python `tools/check.py` attempt stops at
missing `aioquic`; it is not an aggregate pass. Formatting, strict all-target
workspace Clippy and the checklist validator pass separately. Existing simulator
evidence is unchanged. This focused correction does not close CWC-01/17/18, the broader
cutover, native platform gates or the previously intermittent raw/switch cases.

## Exact Block FEC systematic extents (2026-11-17)

The source-bound native17 Cauchy UDP case passes its finite forward data and
requested disconnect, but sends 1,864,271 bytes of systematic coded fill on the
client side. The prior exact Aligned codec correction did not remove this second
layer: Block FEC equalized systematic vectors to the generation's longest actual
ARQ source before serializing them. The precise observation and its limits are
saved in `work/aligned-extents-20261117/native17-udp-review1/`.

The current selected systematic grammar now retains the declared coded width
while serializing exactly the original two-byte length prefix and ARQ source.
The canonical parser rejects truncated original bytes and old padded systematic
aliases. Repair equations still carry the complete generation width, which is
based on the actual longest source rather than a configured maximum. Meaningful
source trailing zeros remain part of the declared original extent; repair tails
are never trimmed by inspecting their byte values.

The FEC decoder restores only the omitted algebraic zeros inside its existing
reserved transaction rows. Its allocation plan, generation/window bounds,
deadlines and atomic rejection remain unchanged. The regular complete-symbol
API remains strict; only the explicitly selected compact API accepts short
systematic vectors. Exact emitted lengths flow through retained output witnesses,
byte budgets, final Records and carrier acceptance. Configuration and catalog
hash domains advance to v5; CompleteV2 field bytes and the final Records prefix
are unchanged. An older padded-systematic peer cannot share the new authenticated
catalog domain.

Focused source-loss, trailing-zero, malformed extent, duplicate, allocation,
physical-charge and actual Common UDP fixture checks pass the
[required batch18 continuation](buffer-observability.md#coordinated-local-buffer-batch18-validation).
No new native speed or complete CWC/BP qualification is claimed. Historical packets, receipts and simulator formats are
unchanged. CWC-03 and the full overhead/matrix gates remain open.

## Exact Aligned source extents (2026-11-17)

The preceding overhead table describes the pre-correction source. Current
Aligned sends the exact meaningful unit returned by its codec, including real
trailing zero bytes. It no longer serializes the configured symbol tail. The
record boundary provides the extent; no new length field is added. Fragment
stride and bounded receiver storage retain their negotiated geometry. The
receiver validates context-dependent payload lengths against the actual slice;
it must not synthesize missing predictive payload by padding a truncated input.

The complete configuration and catalog digest domains advance to v4 to bind
these semantics. CompleteV2 descriptor fields and the five-byte final Records
prefix are unchanged. Historical simulator vectors and receipts are unchanged.
The independent configuration hash fixtures are recomputed with Python hashlib.

Focused evidence is under `work/aligned-extents-20261117/`: 120 codec cases pass,
including the existing 2,588 sender vectors and new exact-extent checks. The
Aligned run passes 41 of 42 initially; the new Compact ARQ test's feedback-drain
assertions are corrected and its focused continuation passes. Configuration v4
tests pass. The actual UDP IP-header/context-loss/delta/replay and Aligned-to-Packed
test passes, also under capture in an owned fresh namespace: 130 packets,
zero capture drops. This fixture uses Unix packet devices, not kernel TUN.

For an early one-byte identity and direct ARQ, the 100-byte raw native fixture
now emits 109 algorithm bytes, 130 strong Records bytes and 158 IPv4/UDP bytes,
instead of 308 IPv4/UDP bytes. Its loss/retry test checks exact retained and
charged bytes, meaningful zero tails and native delivery. These are fixture
observations and arithmetic, not workload mean/p99 or throughput results.
Proxy's separate 81-byte relay/flow/local framing remains an open cleanup item.
TLS Full and QUIC Half fixed proxy cases pass after this correction; both
maintained measured proxy cases still fail `HandoffExpired` at their original
cap. Aggregate and full native performance qualification remain open.

The historical approximately 80 Mbit/s receipts select Swift. The Aligned
receipt verifies ping and a 65,536-byte TCP transfer, with no throughput gate.
Historical impaired shaping is 100/10 Mbit/s, 35 ms each way and 15% loss each
way (nominal RTT 70 ms). No Aligned 80 Mbit/s pass is established by those
receipts. The requested current algorithm/carrier/direction matrix is a separate
measurement deliverable; configured carrier allowances are not captured bytes.

## Native matrix and accepted-record observer (2026-11-17)

The current `common_benchmark_plan` example exports twenty explicit implemented
algorithm configurations across UDP, kernel raw TCP, retained real TLS and real
QUIC: eighty canonical plans. Every planner accepts its row; this is not runtime
qualification. The owned Linux Full-duplex TUN workload uses sixteen kernel TCP
flows,100/10 Mbit/s,35 ms each way,15% loss each way,2 s warmup and10 s measurement.
Header coding is on, payload compression off, and data protection is full-tag
ChaCha20-Poly1305. Ordinary Aligned/Packed ARQ retains its existing shared64-source
limit; this is not the8192-source Compact or per-connection simulator profile.

The first complete carrier pass is retained in
`work/aligned-extents-20261117/matrix-{udp,raw,tls,quic}-attempt1/` with canonical
inputs, copied binary hashes, actual qdisc/offload readback, four capture surfaces,
probe byte/hash receipts and process user/kernel counters. A failed phase leaves
later phases `not_run`; independent direction sessions fill those cells without
retrying the failed phase. Explicit carrier lanes have disjoint namespace names
and eight-CPU affinity sets, but share host memory, storage and kernel resources.
These are finite concurrent-host observations, not production capacity maxima.
See [the runner contract](../../tools/common_native_matrix.md).

The initial opt-in bounded runtime observer records algorithm bytes, final Records bytes
and their exact difference only at socket acceptance, TLS stream flush or Quinn
DATAGRAM acceptance. Its fixed histograms and separately reported diagnostic heap
are not protocol admission credit. No packet contents or keys are logged. These
schema1 observations establish Records overhead, not total encapsulation:
codec/source attribution, retry allocation and TLS/QUIC physical header quantiles
remain unmeasured. Captured IP packet-size p99 must not be renamed overhead p99.
`common_matrix_report.py` preserves every attempt, selects the latest explicitly
requested phase, keeps independent-session provenance and separates validated
rates from failed partial observations. The terminal diagnostic preserves the
original error before the public portable status category loses detail.

The first pass has one complete three-phase case, Swift ARQ over UDP. Its forward,
reverse and simultaneous goodputs are59.8985472,7.871328 and10.303968/7.7404288 Mbit/s.
Swift FEC UDP forward passes at68.6328832 Mbit/s before reverse liveness failure;
Packed Cauchy UDP forward passes at0.5896256 before reverse drain exhaustion;
per-connection recovered-ACK UDP forward passes at4.5455616 before reverse failure.
The ordinary Aligned cases continue delivering native packets but do not finish
tail drain within their original60 s phase cap. The other carriers expose raw
expiry, whole-message control expiry, authenticated liveness expiry, retained TLS
record expiry and algorithm retry/age failures. These observations do not close
CWC-01/06/16/18 or establish80 Mbit/s acceptance. The report records exact errors
separately from source-based root-cause hypotheses.

The required local gate was run with the existing simulator environment. Its
initial Clippy type error was corrected; subsequent strict workspace Clippy,
formatting, rustdoc, no-default-codec and external CLI probe stages pass. All
remaining Python tool suites and1658 simulator tests pass. The complete Rust
workspace run retains seven failures: two measured maintained proxy handoff
expiries, one integration port collision, three QUIC switching transport errors
and one raw control expiry. No Aligned exact-extent assertion fails, but there is
no aggregate green gate. Original failed attempts remain evidence.

The independent direction fill is now complete as attempted coverage, with
235 case sessions covering all80 combinations and240 selected phase outcomes:
10 passed,192 failed,33 exhausted their original bounds, and5 failed during
startup before their selected workload ran. All ten passing phases use UDP.
Additional passing observations are Swift FEC simultaneous8.6555648/6.6978688,
Aligned Cauchy reverse0.2988672, Packed ARQ reverse0.191136, and Packed Cauchy
simultaneous0.4737856/0.411232 Mbit/s. Independent phases do not establish a
continuous three-phase session. The complete source-bound table, exact errors,
directional byte totals and original observations are retained in
[the complete baseline report](../../work/aligned-extents-20261117/matrix-report-directions-complete1/report.md).

Two targeted transport corrections follow these observations. Raw Common now
retries an outstanding authenticated liveness challenge at the existing250 ms
transition interval; new challenge cadence, original15 s expiry, held ciphertext
age and actual-send receipt accounting remain unchanged. Twelve affected raw
protocol/injected-I/O tests pass. Common QUIC now bounds its maintained outgoing
FIFO to at most two maximum-record byte allowances, applying backpressure before
further DATAGRAM acceptance; the configured receive/custody queue remains intact.
Seven focused QUIC tests pass. This is neither strict control priority nor a
two-packet limit, and excludes already transmitted congestion flight. The first
repair binary passes raw forward0.874592 and reverse0.8873344 Mbit/s; the third
phase of that session reaches the original120 s lease with live control. A fresh
independent simultaneous session passes0.6904064/0.6938816 Mbit/s at unchanged
bounds. QUIC still fails authenticated liveness expiry. These finite results
qualify the raw loss-retry correction, not throughput targets or one continuous
three-phase session. No failed baseline is relabeled. The subsequent source fix
also restores Control-before-User polling in both maintained output and runtime
receipt selection; its focused checks and release4 phase are recorded below.

The opt-in observer now uses allocation-free canonical outgoing
extent inspection: route, outer-fragment, recovery, systematic coded fill and
codec envelope/container/unit header lengths. Counters commit only on actual
whole-send acceptance. Each histogram has its own sample population. Swift
stream codec attribution, codec-body compression fields, retries versus initial
sources and physical TLS/QUIC overhead remain separate unmeasured quantities;
these partial extents must not be presented as total encapsulation overhead.
This work advances CWC-01/06/09/13/17/18 without closing their broader gates.

The stable matrix ID `swift-arq` means proportional repair ratio zero, not removal
of all FEC: the existing Swift tail probe still emits a repair equation to reveal
the newest sequence and solicit recovery feedback. Actual repair counts remain
included. Compact ARQ has a separate nine-attempt configured bound; the cited
Python candidate has no attempt-count limit. A minimal TLS failure includes a
TCP contiguous-byte gap despite only approximately1 KiB accepted per direction.
The [capture audit](../../work/aligned-extents-20261117/tls-compact-hol-audit1/audit.md)
cannot identify encrypted feedback contents. An opt-in bounded scalar trace
(`L2TUNNEL_COMPACT_ARQ_TRACE`) distinguishes source0 selection, whole acceptance,
authenticated feedback arrival and actual application/retention results. It
preserves original timers and caps and records no payloads or keys.

### Repair4 consolidation and remaining failures

The [current combined report](../../work/aligned-extents-20261117/matrix-report-repairs4-complete1/report.md)
retains 240 case sessions and selects 240 phase outcomes across the same eighty
algorithm/carrier combinations: 14 passed, 187 failed, 32 exhausted their
original bounds and 7 did not run. Selection is the latest explicitly requested
attempt per phase, not the fastest or most successful attempt. Each phase keeps
its own executable, input and receipt provenance; independent sessions are not
a continuous three-phase pass. All failed baseline attempts remain available.
Untouched combinations are not requalified by a newer repair binary.

Release4's `swift-arq-quic` forward phase passes at 0.341728 Mbit/s after bounded
Control-before-User scheduling was restored. The
[focused priority/trace receipt](../../work/aligned-extents-20261117/trace-priority-focused2.json)
also passes pending management before User after a full actual QUIC FIFO,
original-arrival feedback retention and bounded scalar tracing. This is finite
forward evidence at the original matrix settings, not QUIC all-direction or
performance acceptance. The prior liveness failures remain in the report.

Release4's `aligned-compact-tls` reverse phase fails with client
`whole-message control error: Expired` at elapsed 23.190915 seconds, followed by
server `UnexpectedEof`. It does not reproduce source0 `RetryExhausted`: both
peers applied positive source0 feedback, one after its first attempt and the
other after one retry. The
[hashed trace analysis](../../work/aligned-extents-20261117/compact-arq-trace4-analysis.json)
separates local acceptance, authenticated arrival and application. Both bounded
512-event traces overflow before the terminal control failure; their successful
source0 prefix cannot explain the later expiry or erase the earlier failure.
Compact ARQ still has its configured finite attempt bound, unlike the cited
Python candidate. This TLS trace changed no retry, window, lease or handoff cap.

Raw actual-horizon/reserve status passes its affected lower-owner and two paired
service checks in the
[raw status receipt](../../work/aligned-extents-20261117/raw-status-and-rustdoc-focused1.json).
The subsequent policy-derived native receive-buffer/slot planner and typed
`PacketPhaseConfig::preflight::<PacketOwner>` pass all three client capacity and
all three raw-io preflight tests in the
[required-check continuation](../../work/aligned-extents-20261117/required-repair-checks2-continuation1.json).
The actual paired compact raw service passes both suites with a 1 MiB policy,
asserting genuine local and peer horizons above 65,535 bytes and no greater than
the policy cap, rather than an exact effective cap. Configuration, payload and
concrete metadata bounds are checked before opening I/O. This is caller-owned
PacketIo/bootstrap evidence; earlier native captures do not qualify these new
allocations. The
[raw module](raw-common-carrier.md#shared-service-installation) records the exact
planner and the separate, already tested liveness retry correction.

The [receipt/proxy focused batch](../../work/aligned-extents-20261117/receipt-and-proxy-errors-focused1.json)
passes actual UDP receipt correlation, dual proxy-error preservation and the
report's offline checks. Metrics commit only after identity, scope, length and
charge correlate, but retain a genuine late accepted send before its deadline
error. Proxy failure reports preserve both runtime and joined actor causes
without changing primary precedence, joins or the measured handoff deadline.
Neither correction establishes that the remaining measured-proxy or control
expiry is repaired. The required aggregate check remains open.

The same required-check continuation passes formatting, strict workspace
all-target/all-feature Clippy and workspace rustdoc. Its Rust workspace run still
fails four cases: Swift TLS reconnect reports `AddrInUse`, the measured QUIC
proxy reports `HandoffExpired`, and Full QUIC CCM/CRC switching fails at terminal
handling after the exercise passes. Measured TLS proxy and both Half QUIC
switching cases pass in this attempt; their earlier failures remain preserved
and are not explained by this continuation. No pristine aggregate pass or full
proxy/carrier qualification is claimed.

Schema2 histograms describe cumulative accepted emissions for each actual owner,
not a single phase when that owner served several phases. Canonical recovery,
systematic-fill and supported codec-envelope/header fields have separate sample
populations. Swift stream attribution, codec-body compression fields, initial
versus retried source attribution and physical TLS/QUIC overhead quantiles remain
explicitly unmeasured. The fixed 21-byte full-tag Records cost is one layer;
neither it, captured IP packet-size p99, nor a sum of independent histogram
quantiles is total encapsulation overhead. Same-window WAN/application ratios
include ACKs, retransmissions and boundary-crossing flight and are not matched
packet overhead. All CWC acceptance gates remain open.

### Local TLS queue optimization and finite validation

The current source installs and reads back `TCP_NOTSENT_LOWAT` on each original
Full/Half TLS socket before retained ownership is split. The derived local
request is `2 * (max_record_bytes + 5)`, or 2,870 bytes for the current matrix.
This is an unsent-data threshold with possible kernel overshoot, not a hard
queue/flight bound. Wire formats, authenticated policy digests, send-buffer
sizes and deadlines remain unchanged. Linux/Android option errors are setup
errors; other platforms preserve existing TLS functionality and explicitly
report unavailable capability. Shared status separates requested thresholds
from actual readbacks. See the [maintained carrier module](maintained-common-carriers.md#bounded-io-and-receipts).

Focused threshold, actual Full/Half readback, local-binding independence and
status tests pass in
[required checks3](../../work/aligned-extents-20261117/required-repair-checks3.log).
The aggregate still fails four cases, including measured TLS proxy
`HandoffExpired`; the
[continuation](../../work/aligned-extents-20261117/required-repair-checks3-continuation1.json)
passes workspace rustdoc and the external Common CLI/service process probe.

The [release6 AlignedCompact TLS reverse receipt](../../work/aligned-extents-20261117/matrix-tls-repair6-reverse-attempt1/aligned-compact-tls/result.json)
passes the finite 16-flow byte/hash/EOF workload at 0.1946112 Mbit/s
(243,264 unique application bytes in 10 seconds). Both Full sockets report the
actual 2,870-byte LOWAT readback; capture drops and schema2 extent errors are
zero. The 100/10 Mbit/s, 35 ms and 15% loss each-way configuration and original
bounds are unchanged. Completion required 33.31 seconds of post-window drain,
with only about 0.59 seconds remaining before the probe cap. Server EOF occurred
after the client's explicit disconnect, so orderly bilateral shutdown is not
qualified. The earlier control-expiry failure remains a separate receipt; these
independent runs neither isolate causality nor measure a hard queue bound.
This advances CWC-06/13/17/18 without closing their acceptance definitions;
full carrier, measured-proxy and platform qualification remain pending.

### Terminal settlement and fixed-port TLS reconnect

Terminal Common settlement now consumes only already-retained carrier failures
following cancellation; normal service still samples live failures. Exact
first-error identity, retained User/Control receipts and original clock/custody
deadlines remain authoritative. The three deterministic cancellation/observed
failure/first-cause regressions and all four genuine QUIC Full/Half CCM/CRC switch
cases pass in `required-repair-checks3.log`. That aggregate still records four
failures: raw Half switching, both measured proxies and TLS reconnect binding.
It is not an aggregate pass.

The Unix TLS client now enables `SO_REUSEADDR` before the original and replacement
binds; Windows behavior is unchanged. The
[focused receipt](../../work/aligned-extents-20261117/tls-reuseaddr-focused1.json)
records a real Linux ordered-FIN, exact-tuple `TIME_WAIT` bind regression and the
genuine same-port Swift TLS switch/refusal/no-op/release/reconnect case passing.
The first proves local-port rebinding, not unrestricted immediate reuse of an
identical TCP four-tuple. Earlier aggregate failures remain preserved.

The [release6 combined report](../../work/aligned-extents-20261117/matrix-report-repairs6-complete1/report.md)
selects 12 passing, 187 failed, 32 bound-exhausted and 9 not-run phases. It includes
multiple source-bound versions; older untouched combinations are not requalified
by a new binary. Raw forward still fails before a qualified sample. Its new
bounded diagnostic records a live Liveness source with neither source confirmation
nor semantic ACCEPTED at expiry, while local message work continued. This does
not support the proposed confirmed-but-unswept-source explanation.

### Exact raw receive ranges and release7 results

The former raw tracker could retain only 128 disjoint byte intervals inside an
otherwise valid negotiated receive horizon. Loss could exhaust that metadata
capacity and reject new packets before Records authentication. The implementation
now uses a circular bit per byte, allocated once before consuming original raw
I/O. The maximum 1 MiB horizon costs 131,072 bytes per lane. Authentication remains
between read-only validation and commit; unauthenticated input cannot age the
window. Overlap rejection, monotonic floors and original horizon/deadline rules
remain unchanged. Both bootstrap and compact gates use this tracker. Actual
retained capacities enter raw preflight, allocation counts and shared status;
this does not claim completeness for other nested allocations.

The [diagnosis](../../work/aligned-extents-20261117/raw-range-capacity6-analysis.md)
records the source defect and capture evidence. The older 849-receive plateau
was consistent with interval exhaustion, but missing pre-capture state prevented
an exact reconstruction of all prior internal intervals. New protocol tests
cover more than 500,000 sparse gaps in the maximum horizon, stable allocation,
wrap and overlap, authentication refusal, reordered bootstrap packets, actual
Full/Half capacities and a byte-set oracle.

The [source-bound release7 binary](../../work/aligned-extents-20261117/matrix-source-binding-7.json)
uses SHA-256 `2a2f44b629f1a43b299554453ef3860ae374bf9ad6e9b8cca700df238bbc83d0`.
The original 100/10 Mbit/s, 35 ms delay and 15% loss each-way workload and all
caps are unchanged:

| Selected native run | Result |
| --- | --- |
| [Swift ARQ raw forward](../../work/aligned-extents-20261117/matrix-raw-repair7-forward-attempt1/swift-arq-raw/result.json) | Pass, 20.3322368 Mbit/s; 25,415,296 unique application bytes in 10 seconds |
| [Swift ARQ raw reverse](../../work/aligned-extents-20261117/matrix-raw-repair7-swift-arq-raw-reverse-attempt2/swift-arq-raw/result.json) | Pass, 7.6720832 Mbit/s; 9,590,104 unique application bytes in 10 seconds |
| [Swift ARQ raw simultaneous](../../work/aligned-extents-20261117/matrix-raw-repair7-swift-arq-raw-simultaneous-attempt2/swift-arq-raw/result.json) | Authenticated startup fails; data phase not run, no qualified rate |
| [Aligned Compact raw forward](../../work/aligned-extents-20261117/matrix-raw-repair7-aligned-compact-raw-forward-attempt2/aligned-compact-raw/result.json) | Client whole-message control expiry at 18.978261 s; server liveness expiry at 18.979204 s; no qualified rate |

The last case receives more than 4,000 authenticated records at each endpoint,
including traffic near termination. It no longer exhibits the older total raw
receive plateau, but control-source/semantic confirmation remains incomplete.
The earlier attempted parallel configuration was refused by the runner before
starting workloads; corrected runs retain its original exclusive raw namespace
and CPU-lane contract.

[Required checks4](../../work/aligned-extents-20261117/required-repair-checks4-environment1.json)
run with the existing aioquic environment after the default Python invocation
failed dependency preflight. Formatting, strict workspace Clippy and preceding
tool/vector checks pass. Raw tests pass 163 with two existing ignored cases;
runtime tests pass 285. Client tests pass 193 and fail the two existing measured
TLS/QUIC proxy `HandoffExpired` cases. The actor-first coordinator scheduling
change is implemented but does not close those failures. The
[continuation](../../work/aligned-extents-20261117/required-repair-checks4-continuation1.json)
passes strict workspace rustdoc, debug daemon build and the external Common
CLI/service probe. There is no aggregate-green claim; unchanged earlier codec,
simulator and tool evidence is reused rather than represented as newly run.

The [release7 combined report](../../work/aligned-extents-20261117/matrix-report-repairs7-complete1/report.md)
selects 14 passed, 186 failed, 32 bound-exhausted and 8 not-run phases across all
80 combinations. Every attempt remains linked; untouched combinations retain
older binary provenance. Passing data phases with failed endpoint disconnects
are listed separately. Per-layer schema2 extents are not full encapsulation
mean/p99, and no CWC parent acceptance gate closes through this batch.

### Bounded native batch refill after release10

The release10 UDP Aligned Compact run reaches source 36,229 before exhausting
its unchanged nine-attempt bound. The receiver retains 8,039 recovery sources,
with receipt prefix 36,229 and ordered handoff cursor 28,241. Its 2,033
`native_backpressure_drops` count authenticated input refusals, not failed TUN
writes: the existing observer records 14,246 complete native writes and no device
WouldBlock. These facts do not identify every failed source transmission or prove
that each refusal was the same resource limit.

Source review found that the sole loop prepared at most one native packet per
epoch before its write batch, and successful writes never refilled that batch.
The implementation now shares a bounded write/refill helper between cached
writability and the readiness-event branch. Each write or empty-queue scan uses
the existing remaining turn allowance; successful physical completion must
release the exact Engine token before another packet is prepared. Blocked writes
retain their bytes, token and original deadline. The focused actual
Common/Aligned regression checks multiple deliveries within one grant, the cap,
blocked custody and a failed clock sample after an already completed write.
The corrected real-socket fixture and strict runtime lint pass in the
[focused continuation](../../work/aligned-extents-20261117/required-buffer-checks4-focused1/receipt.json).
The required aggregate retains measured-proxy failures and an unexplained raw
custody timeout whose focused rerun passes; new native evidence is pending. It does not close CWC-17, the throughput matrix or any
per-mode acceptance gate, and changes no queue, retry, lifetime or wire limit.

### Joined framing and successful native-admission observations

The next implementation batch adds observer schema3. Each joined value uses one
correlated accepted emission before histogramming: exact Records or actual
UDP/raw IP length minus that same emission's codec body. The actual IP extent
comes from its original send receipt; TLS/QUIC charging allowances are never
substituted. Schema1/2 receipts remain readable. These joined values still leave
codec-body syntax, context and fragmentation inside the body, and exclude Swift
stream and outer-fragment attribution. They are not full native encapsulation
mean/p99. No component quantiles are added or subtracted.

The actual codec and Swift admission paths now return original input, context,
encoded body and generated unit/fragment or stream-prefix lengths, actual
encoding kind and signed gain. This return-only observation propagates through
Aligned/Packed, Rolling/Research, recovered Connections, explicit native bypass,
Engine and Bank to the existing Common admission loop. It adds no retained pure
queue or allocator. Admission samples count each original input once; retries
and source copies do not manufacture another sample. Proxy-record inputs stay
separate from native packet inputs. Literal/context expansion remains negative,
and LZ4 whole-input gain is not called header compression. Existing Swift gross
delta-savings counters are explicitly documented as excluding literal expansion.
The observer aggregates these admission facts independently of physical-send
success, including a runtime that fails before its first accepted emission.
Per-native gain quantiles and complete per-emission byte-range provenance remain
open. The required checks5 continuation passes strict workspace Clippy, codec
no-default-features tests and strict rustdoc with unchanged source hashes.
Workspace tests retain two failures: measured QUIC Half proxy handoff expiry
and raw Frame native mode-switch lifetime expiry. TLS measured proxy and the new
codec, native-observer and raw candidate-scheduling tests pass. This is not an
aggregate-green claim. The source-stable release8 build and external Common
CLI/service process probe pass; native validation remains pending. Receipts:
`work/aligned-extents-20261117/required-repair-checks5-continuation1.json`,
`required-repair-checks5-cli-continuation1.json` and
`matrix-source-binding-8.json` in that same directory.

Raw candidate verification now reserves upper Control capacity separately from
Data/Feedback and cycles through carrier control, upper control and bulk heads.
A selected candidate stays pinned through authentication; rejected candidates do
not gain authenticated credit. The 64-packet upper/bulk allowance splits into
4 Control and 60 bulk slots, in addition to the existing 4 carrier-control slots.
A one-slot configuration retains its explicit shared-slot limitation. This is a
bounded attempt-opportunity guarantee, not a deadline or flood-delivery guarantee.
Measured Common proxy actors now yield after a ready turn; this repairs a
scheduler starvation opportunity but does not close the remaining QUIC deadline
failure or relax its original 50 ms cap.

The [paired-capture audit](../../work/aligned-extents-20261117/raw-capture-scope7-analysis.md)
corrects a tool description: both endpoint WAN captures in this owned
veth/HTB/netem lab observe post-qdisc survivors. All 11,216 TCP segment identities
match one-to-one, with packet/frame-byte sums equal to netem transmitted deltas;
1,221 forward and 786 reverse drops are absent. Captured IP bytes are distinct
from socket-admitted bytes and from full physical-wire bytes. Historical captures
are retained; their interpretation is corrected without rewriting observations.

The owner also requested backpressure timing for all internal buffers. The full
inventory must distinguish occupancy from downstream blockage, identify actual
capacity and high-water occupancy, record cumulative and longest continuous
blocked intervals plus transition reasons, and retain which owners are unmeasured.
Overlapping buffer wait intervals must not be summed as elapsed wall time.
Public protocol libraries retain injected time; no real clock, runtime dependency,
per-packet log or unbounded trace is introduced. This requested instrumentation
is being implemented through the [BP-01 through BP-24 coverage inventory](buffer-observability.md).
A first subset cannot qualify all internal buffers; unmeasured owners and
count-only aggregate refusals remain explicit.

## Accepted direction and open engineering choices

The subsequent source-stable
[release5 raw remeasurement](../../work/aligned-extents-20261117/matrix-raw-repair5-attempt1/swift-arq-raw/result.json)
observes the requested1,048,576-byte horizon in both directions, with1,036,896
Data bytes after the unchanged11,680-byte reserve. It fails before a qualified
forward sample: client and server whole-message control expiry occur at10.511245
and10.787993 seconds, before their liveness deadlines. Reverse and simultaneous
phases do not run. This proves the bootstrap capacity correction reached the
native owners, not a throughput improvement or completed control repair. The
[latest complete report](../../work/aligned-extents-20261117/matrix-report-repairs5-complete1/report.md)
therefore selects11 passing,188 failed,32 bound-exhausted and9 not-run phases;
older raw passes remain historical attempts rather than current-version rates.
The unchanged isolated TLS reconnect syscall probe passes both same-port
connections, so TIME_WAIT remains an unproved explanation for aggregate
`AddrInUse`. No timeout, retry, window-policy or original workload bound was
relaxed to obtain these observations.

The ordinary-data target is at most 24 bytes, with 20 bytes or less an optimization
target. Neither is a universal bound for coefficient vectors, context records,
feedback or fragments. Report actual branch costs, logical-record amortization
and physical-packet costs; do not hide nested fields in a payload subtotal.
Management and reliable-retiring feedback remain authenticated. Requested versus
effective carrier, protection, policy and capabilities remain observable through
the shared CLI/GUI/service API. SW-11 negotiated epoch switching and every P-*
mode definition remain in scope. Automatic periodic key exchange is not a new
default; reconnect remains the lower carrier/session owner's responsibility.

## Full implementation and acceptance ledger

- [ ] [CWC-01] Bind a current byte/ownership inventory to actual selected call paths, with separate native/application, logical-record, unit, packet, control, feedback and physical totals; distinguish static derivation from executed observations.
- [ ] [CWC-02] Complete the first structural codec/recovery/security/facade cleanup at real call sites with one authoritative transition/encoding path per existing behavior, preserved behavior/error precedence and focused affected regressions; complete the authorized removal of obsolete production encoders and default branches after migrating their functionality.
- [ ] [CWC-03] Implement actual typed algorithm outputs and the variable-length final header union, including source/repair/feedback/context/fragment semantics, borrowed bounded custody and checked dispatch from authenticated context, without maximum-arm wire padding or private nested envelope serialization.
- [ ] [CWC-04] Specify and implement canonical final parsing/encoding with checked lengths, reserved/unknown-field refusal, truncation and ambiguity tests, and byte-exact branch vectors; measure the ordinary 24-byte and optional 20-byte targets including every algorithm/check/mimic cost, and explicitly resolve unsupported larger branches without truncation or scope reduction.
- [ ] [CWC-05] Resolve and authenticate the explicit data-check/protection selection, including the AES-CCM4 and ChaCha20/CRC32C candidates' different guarantees, maintained provider/dependency support, nonce/replay/forgery/key-use limits and failure behavior; remove obsolete production formats without weakening existing authentication or silently selecting the unkeyed data check; make no custom-primitive claim.
- [ ] [CWC-06] Preserve authenticated replay-protected management and reliable-retiring ACKs, same-carrier lossy feedback, repeat/loss policies, original deadlines and independent bounded service through user pressure; qualify forged/replayed/stale feedback without weakening control to the data-check contract.
- [ ] [CWC-07] Bind full session/role/direction/lane/epoch/configuration/operation/incarnation context while keeping short selectors and distinct packet/source/serial/record/native counters correct under reordering, wrap ambiguity, mode changes, retries and key exhaustion; no alias, nonce reuse or implicit lifetime reset.
- [ ] [CWC-08] Install explicitly selected initial-only carrier appearance and one final data encoding on the same original connection/socket/five-tuple; remove continued inner mimic wrappers and obsolete final-data format branches from all migrated production entry points and separately qualify handshake parseability, continuing protocol consistency, interoperability limitations and measured ISP/QoS assumptions. **Progress:** current implementation and verification scope are recorded above; the complete acceptance definition remains open.
- [ ] [CWC-09] Implement the actual raw authenticated bootstrap-to-single-final-protection handoff without a pre-Noise key cycle, retaining phase transactions, original deadlines, byte sequence/window retirement, independent control progress, whole-write facts, held ciphertext and retained reliable close semantics on the existing owner/loop. **Progress:** current implementation and verification scope are recorded above; the complete acceptance definition remains open.
- [ ] [CWC-10] Qualify raw kernel ACK/RST/firewall handling, privileges, same ports/sequence space, options/PMTU/NAT, failure/recovery and supported Linux/Windows/Android boundaries in owned environments; pure parsing, compilation and injected PacketIo cannot close native/platform gates.
- [ ] [CWC-11] Recompute and validate native MTU, packet/group bursts, actual repair/fragment/copy costs and original-age reassembly before allocation/admission; implement effective repair extents, bounded receiver zero-extension, meaningful trailing-zero preservation and exact emitted-byte charging; preserve fixed1460/MTU1500/global8192/local128/every16/short-copy/ACK requirements and exact physical confirmation without double debit or early whole-record release.
- [ ] [CWC-12] Integrate actual selected owners through Engine/Bank/Pipeline and resource plans with bounded reusable buffers, complete inline/nested usage counted once, meaningful pressure/rollback/drop checks and no dummy reservation, duplicate queue, unused algorithm owner or allocator-completeness fiction.
- [ ] [CWC-13] Negotiate explicit version/capability/configuration through the shared CLI/GUI/service API, migrate existing functionality and remove obsolete wire/dispatch choices, retain explicit configuration migration diagnostics, expose complete requested/effective wire/protection/carrier/algorithm state and bounded catalog/status, and refuse unsupported selection without fallback or synthetic readiness. **Progress:** current implementation and verification scope are recorded above; the complete acceptance definition remains open.
- [ ] [CWC-14] Preserve full SW-11 epoch switching, authenticated management, staged/draining readers, complete barriers/native fences, idempotent retries and retained source/feedback/ciphertext custody across all required profiles; test loss, reordered old traffic and original-cap failures without removing regular switching.
- [ ] [CWC-15] Preserve every 47-mode P-* definition and all RLNC/parity/rolling/packed/proxy, codec, independent/shared recovery, source-copy and named Python requirements; qualify meaningful exact-byte/behavior differentials rather than redefining an unsupported mode or counting enum coverage as implementation.
- [ ] [CWC-16] Install and exercise the new format through actual authenticated runtime and shared service carriers, real bidirectional native/application bytes, control liveness, physical receipts, switch/drain, cancellation/failure/reconnect and observed release; distinguish protocol, user-space integration, privileged native and platform evidence.
- [ ] [CWC-17] For each coherent source-stable batch, run meaningful parser/security/counter/custody/current-vector and directly affected integration regressions in bounded parallel once, reuse unchanged source-bound evidence honestly, then run the required tools/check.py stages; retain all failed attempts, exact commands/binaries/source hashes and unrun stages before reporting completion.
- [ ] [CWC-18] Validate real wire overhead, payload goodput, latency, loss/reorder/feedback recovery, resource/copy/kernel CPU counters and requested QoS/80-Mbit/s goals under controlled owned conditions; compare exact named Python assumptions separately and do not infer ISP classification, platform readiness or full performance from a header model.
