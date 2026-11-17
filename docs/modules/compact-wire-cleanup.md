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

An opt-in bounded runtime observer records algorithm bytes, final Records bytes
and their exact difference only at socket acceptance, TLS stream flush or Quinn
DATAGRAM acceptance. Its fixed histograms and separately reported diagnostic heap
are not protocol admission credit. No packet contents or keys are logged. These
observations currently establish Records overhead, not total encapsulation:
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

## Accepted direction and open engineering choices

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
