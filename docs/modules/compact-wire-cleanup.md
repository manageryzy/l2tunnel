# Compact final wire format and implementation cleanup

Status: **structural prerequisite implemented; regression qualification remains
open; compact format planned**. The owner authorized implementation after
reviewing the current encapsulation costs. The first batch consolidates actual
codec, recovery, security and facade call sites while preserving existing wire
bytes. It does not install or qualify the compact format described here. Two
runtime regression gates remain unresolved below, so CWC-02 and every other CWC
task remain unchecked. Existing receipts and formats remain historical evidence.

## Accepted direction and open engineering choices

The accepted direction is one final packet encoding with one selected protection
operation, an algorithm-specific header union, and appearance confined to the
selected initial handshake. Swift remains a record/recovery algorithm inside an
explicit carrier. There is no new default connection mode, automatic periodic
key exchange, or reconnect controller inside Swift/Records. Reconnection belongs
to the existing lower carrier/session service.

The working ordinary-data target is at most **24 bytes**, with **20 bytes or
less** an optimization target, using the actual selected arm's variable length.
This is not a proven universal ceiling for arbitrary coefficient vectors,
feedback, context records or fragments. Accounting may subtract only the actual
base IP/UDP/TCP headers. Continued mimic headers, TCP options, algorithm fields,
length/fragment metadata and the selected data check remain explicit costs.
Original symbol-internal packing/context lengths must also be counted at their
real packet/record granularity; moving metadata into a field called payload
cannot establish the target. Report logical-record, amortized and physical-packet
overhead separately. A branch that does not fit must report its concrete limit
or required design change; it cannot silently truncate, reduce functionality or
invent an unchecked exception.

The four-byte data-check candidates discussed are **AES-CCM with a four-byte
tag** and **ChaCha20 with CRC32C**. Neither a dependency/provider, exact primitive
API, wire bit assignment, nonce layout nor default has been selected by this
document. These candidates have different security properties: CRC32C is an
unkeyed corruption check, not authentication, and ChaCha20 plus CRC32C must not be
described as AEAD or as satisfying the existing authenticated-packet contract.
The chosen threat, forgery/replay, key-use and failure bounds require an explicit
contract before data-path installation. Use maintained implementations; do not
invent a primitive or truncate a provider's tag without supported semantics.
Management and acknowledgments that retire reliable debt remain authenticated
and replay-protected, including when carried by a lossy feedback stream. A
four-byte data-check proposal does not reduce their authentication contract.

The typed Rust union and the wire format are distinct. An engineering proposal is
a discriminated enum of typed source, repair and feedback views whose serializer
emits only the selected branch. The authenticated epoch/configuration context
determines the algorithm; no maximum-arm padding or repeated algorithm identifier
is needed merely to mirror Rust's memory layout. Packet-kind distinctions still
need an unambiguous validated representation. Exact types, bit allocations and
optional-field rules remain engineering work, not recorded owner decisions.

## Current source and first batch

At checkpoint `625c485`, the finite fixed/full raw proxy fixture requests a
1024-byte symbol, physical MTU 1500 and native MTU 1280. A source has the static
byte cost `1024 + Aligned48 + ARQ44 + Reliable8 + Common48 + raw152 = 1324`
IP bytes. Common48 is route9, security prefix10, tag16 and QUIC-like cover13.
Raw152 is IPv4/TCP40, phase48 and protected datagram64. This is a source-derived
example, not a newly executed throughput or packet-capture result. The actual raw
owner seals the already protected Common packet again. The distinct
Common/OpenVPN opaque path does not have that extra exporter data-protection
layer. Direct TLS is another path; TLS record overhead must not also be added to
raw-phase data.

Source anchors are the [raw fixture](../../crates/l2tunnel-client-core/src/service/tests/proxy_common_raw.rs),
[Common sealing](../../crates/l2tunnel/src/secure_record.rs),
[raw physical geometry](../../crates/l2tunnel-raw-io/src/handoff/pairing/packet.rs)
and [raw packet emission](../../crates/l2tunnel-raw-io/src/handoff/pairing/packet/transaction.rs).
The [closeout receipt](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json)
qualifies its named legacy-format cases only. It is not compact-wire evidence.

The initial implementation batch must consolidate authoritative preparation,
encoding and dispatch paths that are already called, retaining typed ownership,
error order, old constructors, complete canonical configurations and existing
goldens. Root owns security/facade union and dispatch consolidation; parallel
codec/recovery work owns its actual boundary deduplication. An unused enum, new
wrapper or compile-only adapter cannot satisfy the final packet-format tasks.
New compact capability/status must remain absent until the actual selected path
exists and has its own acceptance evidence.

## Single encoding and authority boundaries

Algorithm owners produce typed meaningful fields and borrowed/caller-output
bytes, rather than serializing a complete private wire envelope for another
owner to wrap. The final encoder resolves the selected context once, writes the
selected algorithm branch and actual carrier fields, and performs one selected
protection operation. Receive validates complete bounds, selected context,
check/authentication and replay policy before committing recovery, credit or
lifecycle changes. No parallel recovery engine, packet loop, shadow queue or TCP
controller is introduced.

Keep full session, role, direction, physical lane, epoch, complete configuration
digest and operation/incarnation identity in the established context. Compact
wire selectors identify only registered contexts; they do not truncate that
authority. Packet/nonce counters, recovery source IDs, transmission serials,
record IDs and native-write counts remain separate typed domains. Short serial
reconstruction needs explicit bounded ambiguity/wrap rules and failure behavior;
it cannot reset a nonce/replay owner on a mode switch or reconnection retry.

Control, reliable-retiring ACKs and lossy algorithm feedback use the same selected
carrier and actual shared admission/wire budgets. Their authentication,
idempotency, feedback-loss/repeat policy and original deadlines remain available
while user data is blocked, staged or draining. Source-free ACKs and carrier
retirement must not masquerade as reliable source confirmation or native delivery.

## Raw TCP and initial-only appearance

The raw target retains real TLS authentication followed by raw TCP-shaped data on
the original ports, sequence space and five-tuple. Current raw TLS/member and
phase setup finish before the inner Noise/member session. Replacing both layers
with a final Common key without changing that dependency creates a key/setup
cycle. Specify an explicit authenticated bootstrap-to-final-data handoff using
the existing owners and original accepted setup cap. Do not require the final
key before the exchange that establishes it, create an unauthenticated gap, or
leave two steady-state data protectors installed.

Raw phase transaction/commit proof, physical byte offsets, peer retirement,
negotiated horizon/window scaling, lane/direction and replay identity must
survive. Full immutable context may be established once. Changing retirement
facts can use a compact authenticated control/union branch or authenticated
piggyback; they cannot simply disappear. Bind relevant canonical sequence,
ACK/window, flags and length fields in the one protection operation, or validate
their exact relationship to authenticated metadata before credit/replay commit.
Do not treat an unauthenticated TCP ACK as recovery authority. Checksums and
mutable/NAT-rewritten fields need explicit handling, not circular tag/checksum
AAD or an assumed identical peer-visible address tuple.

Allocate sequence space and full-wire quota using the final physical bytes once.
WouldBlock retains the same complete bytes, nonce, original deadline and token;
whole physical acceptance and later observation remain independent facts. Keep
bounded Window/management progress, Full shared-slot fairness and Half lane
ownership. Neither physical receipt, raw retirement nor local Engine drain proves
peer session close; retained EOF/reliable debt, native fences and actor release
keep their existing requirements.

Initial-only appearance means the selected handshake has its stated real or
limited mimic behavior; the planned final data format removes continued inner
QUIC13/media14 wrapping. It does not promise continuing standard-protocol
parseability, endpoint interoperability or ISP classification/QoS improvement.
Each is a separate claim and requires its own capture/measurement. Kernel ACK/RST,
firewall ownership, privileges, options/PMTU/NAT and recovery remain pending raw
runtime/platform gates. Base IPv4/TCP alone costs 40 bytes; the 24-byte target is
never a claim that total raw physical overhead is 24 or 16 bytes.

## Configuration, resources and compatibility

Select/version the final format in the authenticated establishment/configuration
contract. Preserve existing formats, exact legacy bytes, constructors and mode
catalog evidence. No automatic downgrade, trial parsing or silent fallback is
allowed. CLI and GUI use the same actual service API and expose requested versus
effective carrier, appearance phase, record algorithm, wire version, protection,
capabilities, complete configuration and refusal reason. Offline inspection does
not fabricate authentication or effective readiness.

Plan actual final packet and group sizes before admission. Count every physical
copy, repair, fragment, latency probe and control packet, with fresh protection
identity where required and one final full-wire debit per actual packet. Preserve
source/native debt and the original age/cap through held output and reassembly.
Account actual owners and nested buffers once, including union/metadata extents;
do not replace allocation evidence with scalar budget arithmetic or allocate
unused algorithms to simplify a union. Native MTU, fixed1460/MTU1500 and requested
global8192/local128/every16/short-copy/ACK semantics remain required, not silently
reduced to fit a header target.

SW-11 retains authenticated epoch/configuration switching between Swift and other
profiles, staged/draining readers, matching barriers and idempotent retries.
RLNC, parity, rolling, packed, proxy, per-connection/shared recovery and every
existing codec/carrier/platform requirement remain in scope. All 47 Python mode
IDs and their complete P-* definitions stay unchanged. This wire work adds no
replacement P-* mode and closes no parent by itself.

## Execution batches

These batches order the work; they do not select new format bits, cryptographic
providers or defaults. A batch checkpoint does not automatically close every task
assigned to that batch.

1. **Structural cleanup (CWC-01, CWC-02, CWC-17).** Establish the byte/ownership
   inventory and consolidate actual codec, recovery, security and facade paths.
   Codec, recovery and framing work can proceed in parallel behind frozen shared
   interfaces. Preserve legacy bytes, defaults and custody. The first checkpoint
   implements the structural prerequisite; the complete inventory remains open.
2. **Selected compact wire and budgets (CWC-03 through CWC-07, CWC-11 through
   CWC-13, CWC-17).** Develop typed algorithm views, control/feedback contracts,
   canonical parsers, geometry/resource plans and portable API work in parallel.
   Resolve the protection contract before installing its serializer/sealer, and
   freeze actual final lengths before admission integration. Native and carrier
   integration portions continue in the third batch.
3. **Raw handoff and integration (CWC-08 through CWC-10, CWC-14 through CWC-18,
   plus the integration gates above).** Install initial-only appearance and the
   authenticated bootstrap-to-single-protection handoff. Against the frozen wire
   contract, parallel tracks cover carrier custody, shared service/API status,
   full mode switching/parity, native/platform behavior and controlled performance
   measurements. All original deadlines, 47 modes and unfinished platform gates
   retain their full definitions.

CWC-17 applies to every batch. Run affected regressions in bounded parallel,
reuse unchanged source-bound evidence explicitly and complete the required
`tools/check.py` stages. Preserve failures and unrun gates.

## First structural checkpoint evidence

The actual Compact source/feedback emitters and parser now share the borrowed
`CompactPacketView` legacy codec. Aligned and Packed source envelopes share their
typed identity codec while retaining different exact offsets and geometry.
Common v1/v2 use one checked capacity, route and covered-record boundary; their
separate security owners, prefix lengths and maintenance domain remain intact.
There is no new wire selection, data protector or reduced packet size in this
checkpoint. New byte-exact vectors and short-buffer/counter/replay regressions
pass, including the real authenticated refresh-session fixture.

Validation uses the retained [aggregate receipt](../../work/compact-wire-cleanup-20261116/batch1-summary.json)
and its source hashes, commands and linked logs:

- The required `tools/check.py` attempt found two obsolete test-helper references
  during Clippy. Those references were corrected; the failed attempt is retained.
- The resumed full Rust workspace run reported **2,435 passed and 6 failed**.
  The recorder's older pass counter excludes passing cases in failed binaries;
  the aggregate explicitly includes those 911 passing cases. This is not a clean
  full-workspace result.
- The remaining required stages passed: codec no-default-features (109 cases),
  rustdoc, CLI plan/refusal, actual two-process UDP and external CLI probes,
  Python tooling/harness checks and **1,658 simulator cases**. Initial passed
  tooling/golden stages were reused only with unchanged relevant inputs.
- One bounded same-binary recheck retained all six initial failures and found
  four still failing. Four fixture corrections then preserved all final delivery
  assertions and original caps: consistent injected Common time, distinct
  attempted/accepted socket accounting, the inherited raw eight-packet key
  generation interval, and removal of a circular native-read/echo prerequisite.
  The affected two-package Clippy/build passed. Five of six directly affected
  cases passed, including both raw duplex modes, streamed accounting, Compact
  connection custody and wire ingress. An interrupted wrapper selected no stale
  tests; the executed binary paths came from the actual new Cargo build output.
  A final measured-proxy fixture change reserves the original final 16,384 forward
  bytes until pressure clears, creating actual follow-up demand on the same TCP
  flow. Total bytes, original caps and all final acceptance assertions remain
  unchanged. Its affected Clippy/build passed; its single-case regression did not.

Two runtime gates remain open and prevent CWC-02 regression qualification:

- `measured_common_real_udp_native_pressure_measurements_and_retained_close` now
  delivers both exact streams (32,769 and 16,387 bytes) and clears pressure. The
  first corrected run observed both echo/ACK measurements but no post-pressure
  target growth. The final staged-demand run still timed out at the unchanged
  15-second cap with one echo measurement missing and no observed target growth.
  Both sides ended with empty native byte queues and Idle targets. The subsequent
  close assertions remain unexecuted. These observations do not establish whether
  the remaining issue is measurement, observation timing or target behavior; do
  not equate exact bytes with full measured-proxy acceptance.
- `packed::tests::actual_byte_flight_exceeds64_with_local2_and_real_native_pressure`
  failed its original three-second pressure observation in the workspace run and
  bounded same-binary recheck. That unchanged case was not repeatedly rerun. This
  remains the finite functional flight/queue/pressure gate, not an 80-Mbit/s
  throughput result. Its protocol deadlines and final assertions are unchanged.

Earlier connection-refusal/setup-deadline failures remain in the receipts; a later
passing case does not establish their cause. Host load was observed, not proven
to explain any failure. No privileged lab, packet capture, QoS measurement,
Windows/Android native execution or new performance qualification was run.

## Full implementation and acceptance ledger

- [ ] [CWC-01] Bind a current byte/ownership inventory to actual selected call paths, with separate native/application, logical-record, unit, packet, control, feedback and physical totals; preserve historical receipts and distinguish static derivation from executed observations.
- [ ] [CWC-02] Complete the first structural codec/recovery/security/facade cleanup at real call sites with one authoritative transition/encoding path per existing behavior, unchanged legacy bytes/defaults/error precedence and focused affected regressions; do not advertise compact runtime from this prerequisite.
- [ ] [CWC-03] Implement actual typed algorithm outputs and the variable-length final header union, including source/repair/feedback/context/fragment semantics, borrowed bounded custody and checked dispatch from authenticated context, without maximum-arm wire padding or private nested envelope serialization.
- [ ] [CWC-04] Specify and implement canonical final parsing/encoding with checked lengths, reserved/unknown-field refusal, truncation and ambiguity tests, and byte-exact branch vectors; measure the ordinary 24-byte and optional 20-byte targets including every algorithm/check/mimic cost, and explicitly resolve unsupported larger branches without truncation or scope reduction.
- [ ] [CWC-05] Resolve and authenticate the explicit data-check/protection selection, including the AES-CCM4 and ChaCha20/CRC32C candidates' different guarantees, maintained provider/dependency support, nonce/replay/forgery/key-use limits and failure behavior; retain old formats and make no unselected default or custom-primitive claim.
- [ ] [CWC-06] Preserve authenticated replay-protected management and reliable-retiring ACKs, same-carrier lossy feedback, repeat/loss policies, original deadlines and independent bounded service through user pressure; qualify forged/replayed/stale feedback without weakening control to the data-check contract.
- [ ] [CWC-07] Bind full session/role/direction/lane/epoch/configuration/operation/incarnation context while keeping short selectors and distinct packet/source/serial/record/native counters correct under reordering, wrap ambiguity, mode changes, retries and key exhaustion; no alias, nonce reuse or implicit lifetime reset.
- [ ] [CWC-08] Install explicitly selected initial-only carrier appearance and one final data encoding on the same original connection/socket/five-tuple; remove continued inner mimic wrappers only in that selected new version and separately qualify handshake parseability, continuing protocol consistency, interoperability limitations and measured ISP/QoS assumptions.
- [ ] [CWC-09] Implement the actual raw authenticated bootstrap-to-single-final-protection handoff without a pre-Noise key cycle, retaining phase transactions, original deadlines, byte sequence/window retirement, independent control progress, whole-write facts, held ciphertext and retained reliable close semantics on the existing owner/loop.
- [ ] [CWC-10] Qualify raw kernel ACK/RST/firewall handling, privileges, same ports/sequence space, options/PMTU/NAT, failure/recovery and supported Linux/Windows/Android boundaries in owned environments; pure parsing, compilation and injected PacketIo cannot close native/platform gates.
- [ ] [CWC-11] Recompute and validate native MTU, packet/group bursts, actual repair/fragment/copy costs and original-age reassembly before allocation/admission; preserve fixed1460/MTU1500/global8192/local128/every16/short-copy/ACK requirements and exact physical confirmation without double debit or early whole-record release.
- [ ] [CWC-12] Integrate actual selected owners through Engine/Bank/Pipeline and resource plans with bounded reusable buffers, complete inline/nested usage counted once, meaningful pressure/rollback/drop checks and no dummy reservation, duplicate queue, unused algorithm owner or allocator-completeness fiction.
- [ ] [CWC-13] Negotiate explicit version/capability/configuration through the shared CLI/GUI/service API, preserve old byte-exact formats and commands, expose complete requested/effective wire/protection/carrier/algorithm state and bounded catalog/status, and refuse unsupported selection without fallback or synthetic readiness.
- [ ] [CWC-14] Preserve full SW-11 epoch switching, authenticated management, staged/draining readers, complete barriers/native fences, idempotent retries and retained source/feedback/ciphertext custody across all required profiles; test loss, reordered old traffic and original-cap failures without removing regular switching.
- [ ] [CWC-15] Preserve every 47-mode P-* definition and all RLNC/parity/rolling/packed/proxy, codec, independent/shared recovery, source-copy and named Python requirements; qualify meaningful exact-byte/behavior differentials rather than redefining an unsupported mode or counting enum coverage as implementation.
- [ ] [CWC-16] Install and exercise the new format through actual authenticated runtime and shared service carriers, real bidirectional native/application bytes, control liveness, physical receipts, switch/drain, cancellation/failure/reconnect and observed release; distinguish protocol, user-space integration, privileged native and platform evidence.
- [ ] [CWC-17] For each coherent source-stable batch, run meaningful parser/security/counter/custody/old-vector and directly affected integration regressions in bounded parallel once, reuse unchanged source-bound evidence honestly, then run the required tools/check.py stages; retain all failed attempts, exact commands/binaries/source hashes and unrun stages before reporting completion.
- [ ] [CWC-18] Validate real wire overhead, payload goodput, latency, loss/reorder/feedback recovery, resource/copy/kernel CPU counters and requested QoS/80-Mbit/s goals under controlled owned conditions; compare exact named Python assumptions separately and do not infer ISP classification, platform readiness or full performance from a header model.
