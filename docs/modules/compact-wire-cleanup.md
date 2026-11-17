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
