# Implementation checklist and evidence ledger

Stable task IDs across this file and `docs/modules/*.md` are validated by
`tools/check_checklists.py`. Checkboxes are ticked only with passing `Evidence:`
links. Current implemented scope is summarized in
[implementation status](implementation-status.md); historical receipts remain
preserved in `work/` and `simulator/`.

## Blocking behavior corrections — execute before new feature work

These are the highest-priority implementation TODOs from the behavior and layering audits.
An audit note, an added capability flag or a passing component test cannot close
them. Each fix requires a regression that rejects the previous behavior and
validation through its actual selected client/runtime path. Existing leaf checks
remain evidence for their stated scope, not a percentage of product completion.

- [ ] [FIX-14] Complete source/configuration-specific Python behavior alignment through the actual selected runtime, following [PBA-01..06](modules/python-behavior-alignment.md). Keep independent per-connection CompactARQ and shared directional Packed candidates distinct; replace wrong selected Rust recovery/feedback/retry behavior. Implement CompactARQ serial/RTT/receiver-delay/guarded fast retry, complete global8192/local128/every16 with physical short copies and ACK coalescing, and prioritize L3 TCP while preserving L2. Common migration and finite component tests do not close this gate; retain authentication, management, all 49 catalog modes and every existing full requirement.

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
- [x] [SLICE-08] Integrate systematic Cauchy repair plus ARQ fallback in the authenticated UDP native runtime and qualify both covers/suites, native layers and actual repair transmission. Evidence: [cutover record](modules/compact-wire-cleanup.md), [36-case native Cauchy audit](../work/native-fec-matrix-audit.json).
- [x] [SLICE-09] Integrate fixed-bootstrap transparent-TUN flow credits, weighted DRR and CRC MUX into retained TLS and qualify both duplex modes with None/LZ4 and impaired links. Evidence: [cutover record](modules/compact-wire-cleanup.md), [plain receipt](../work/native-active-plain/receipt.json), [LZ4 receipt](../work/native-active-lz4/receipt.json).
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
