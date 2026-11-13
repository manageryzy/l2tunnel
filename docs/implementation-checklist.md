# Implementation checklist and evidence ledger

This is the persistent entry point for implementation progress. An unchecked item
is required work, not a forgotten suggestion. Completing a design/enum does not
complete its runtime feature. Only tick an item when its named deliverable and
acceptance test exist; add `Evidence:` with a code/test/receipt link on that item.
Mark planned, contract-tested, implemented and integration-tested scope explicitly.
Do not check remote/native/privileged gates on the basis of local builds.

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

## Blocking behavior corrections — execute before new feature work

These are the highest-priority implementation TODOs from the behavior and layering audits.
An audit note, an added capability flag or a passing component test cannot close
them. Each fix requires a regression that rejects the previous behavior and
validation through its actual selected client/runtime path. Existing leaf checks
remain evidence for their stated scope, not a percentage of product completion.

- [ ] [FIX-13] Replace the target Swift-specific TCP/TLS-bootstrap plus independent UDP path with the shared point-to-point secure session over the explicitly selected carrier. Preserve Swift's AEAD data behavior while moving authentication/key exchange, protection, replay, rekey and stable control behind reusable boundaries. Implement the owner-selected WireGuard-like direction through the [SEC-* gates](modules/secure-session.md), keeping original connection/socket/five-tuple continuity, HTTPS-like TLS-to-packet requirements, bounded default recovery and all record-profile functionality. No library, wire format, key migration or timeout value is selected by this documentation change; historical slices remain evidence for their original scope.
- [ ] [FIX-09] Minimize packet-path copies through explicit bounded buffer ownership. Eliminate whole-history and whole-equation-bank transaction snapshots; reuse immutable payloads and transfer owned buffers across codec, recovery, carrier and native handoffs. Count allocations and copied bytes separately from necessary GF output and cryptographic writes. Preserve bounds, original deadlines, cancellation and exact bytes under loss/pressure; do not claim end-to-end zero copy without measurement. The [sparse rolling transaction](modules/local-global-rlnc.md) now copies only modified equation rows, with bounded preallocated versions and atomic commit/abort; rank-zero originals bypass empty algebra and window scans. Its focused before/after work and correctness checks do not qualify native throughput or remaining packet-path copies.
- [ ] [FIX-01] Separate local storage from authenticated byte/record flight budgets in every packet runtime, including base UDP, its QUIC owner and raw; size delivery credit from bandwidth and causal feedback RTT. Rolling, aligned/packed and now base UDP/QUIC/raw have focused implementations; [shared packet delivery](modules/packet-delivery.md) and [raw integration](modules/raw-runtime.md) prove native flight larger than the local queue. The [source28 aggregate](../work/implementation-wave28/validation.json) passed; new native profile qualification remains open. Keep recovery retained-source byte/record limits a third independently configured and observed domain: the base ARQ default/cap of64 can remain an RTT bottleneck after native credit grows. Validate small local queues with larger real outstanding debt, exact mixed-size bytes, receiver pressure, original deadlines and full/half operation. Carry actual first-send and authenticated delivery timestamps through bounded queues; enqueue is not physical-send completion.
- [ ] [FIX-10] Separate carrier delivery semantics from user-data recovery. OpenVPN-like bootstrap may retain reliable TLS control, but `DataState` must not force every user packet through `SelectiveRepeat`. Expose authenticated datagrams and compose the selected recovery above them. Require the same selected recovery contract over supported UDP, QUIC and OpenVPN-like owners and the planned appearance profiles, explicit unsupported-combination rejection, original deadlines and shared wire accounting; capability flags alone do not complete this fix. Swift remains a data algorithm within this composition, not an independent carrier or an implicit default.
- [ ] [FIX-11] Freeze a session control envelope independently of data MUX/FEC/codec. Extract the legacy parser from the UDP owner without changing existing wire identities, then implement a negotiated stable envelope with separately typed recovery feedback. The [additive pure envelope](modules/management.md) has borrowed parsing, explicit active/draining scopes and recovery tags; its admission tests do not implement negotiation or runtime dispatch. Keep authentication, epoch/digest checks, bounded service and retry/drain barriers alive while switching data modes. Migrate Swift's private policy-control messages into this shared service without treating SW-13 as SW-11. Moving functions alone does not complete this gate; test delayed old-mode feedback, lost replies and control progress during a real switch on the selected carrier.
- [ ] [FIX-12] Move connection lifecycle and local command execution out of private CLI dispatch into a shared service API. CLI and future GUI must use the same typed profile, connect/disconnect/reconnect/apply operations, ownership and terminal results. Preserve original handshake deadlines and distinguish accepted operations from completed peer changes. The [managed TCP service slice](modules/client-runtime.md) now owns the actual CLI connection, cancellation, abort/reconnect and compression-apply path; uncertain peer outcomes remain explicit. Portable command types are separated from Unix IPC. The [swift profile](modules/swift.md) runs through the same owner and adds local `disconnect` and `reconnect` commands that report actual completion. The remaining profiles, clean peer-confirmed drain, a non-CLI frontend and platform qualification remain open; an enum or wrapper around CLI arguments is insufficient.
- [ ] [FIX-02] Make the Python high-performance composition reachable as one authenticated client profile: common connection-RR MUX16, actual local/global RLNC, correct retained-source bounds, compact records and the selected short-frame/ACK policy. Trace every selected option to the running data plane; do not substitute TCP/TLS frame forwarding or isolated library tests. Remove fixed-width systematic-source tail padding with explicit authenticated wire versioning, then compose compact records with the actual rolling owner; current FrameCodec/LX composition turns a 1500-byte TUN packet into two full 1500-byte outer IPv4 datagrams for the audited MTU1500 geometry. Preserve old wire bytes, arbitrary real zero tails, exact emitted-byte charging and native completion only after every physical fragment sends. The [source-pinned accounting](../work/rolling-fast30/next-step.md) is static evidence, not a native bandwidth result.
- [ ] [FIX-03] Qualify the reference local support128/global support8192/every16 geometry, retained unconfirmed sources and bounded row/history storage as distinct limits. Current `window` is global support, so adding8192 retained debt behind support128 would strand old loss. Measure and remove the decoder's full-bank copy bottleneck, then prove old-source recovery, memory/work bounds and delayed feedback before replacing the runtime global-support128 ceiling. Before widening the guard, decouple wire-ingress queue storage from recovery support; the current queue grows with `window * physical_lanes`. Qualify actual full8192 support, old losses outside local128, ring reuse, receiver Busy/Capacity, original deadlines and authenticated full/half pressure with local2. Measure global-repair GF work and feedback-induced Busy loss; clean originals and rank-one witnesses with three sources are insufficient. Design evidence: [ownership audit](../work/rolling-bdp27/fix03-retention-design.md) and [remaining geometry gates](../work/rolling-fast30/next-step.md).
- [ ] [FIX-04] Run a matched native performance workload on that composition: record the exact reference profile, sixteen forward bulk flows and its ACK-return policy, 100/10 Mbit/s,70ms RTT and15% loss; compare clean/delay controls, exact payload/confirmation, same-window wire cost and latency. Keep simultaneous reverse-bulk stress as a distinct workload. Actual forward80Mbit/s remains required. The explicit [swift profile](modules/swift.md) ran the matched workload on TAP in unprivileged namespaces at 79.7–80.5 Mbit/s, 98.8–99.7% of the simulator at equal per-datagram overhead, using the simulator's documented selective-repeat candidate rather than the FIX-02 composition; real-device qualification is open, so this item stays unchecked.
- [ ] [FIX-05] Reproduce and correct any valid management retry/buffered-arrival sequence that trips the base runtime's256-record local-arrival limit. Keep original transaction deadlines and bounded authenticated control service; use actual delayed control delivery, not a success-only local state fixture.
- [x] [FIX-06] Make the complete simulator check reject unavailable/broken required adapters and unexpected skipped tests. Preserve optional dependency behavior for ordinary simulator users; reproduce the old false pass and replace it with a failing full-gate result. Evidence: [guard regressions](../tools/test_check_simulator.py) distinguish real import/skip failures from ordinary optional use; [complete source27e check](../work/implementation-wave27e/validation.json),1658 simulator cases with no skips.
- [ ] [FIX-07] Finish the requirement-to-runtime/test audit, repair each confirmed behavior discrepancy, and remove superseded designs, duplicated progress prose and tests that do not distinguish correct behavior. Retain meaningful parser/security/deadline regressions and all historical experiment receipts.
- [x] [FIX-08] Reject packed MUX channel256 at composition setup, before any flow is created; preserve packed255/unpacked256 delivery and correct the documented Python integer repair-credit behavior. Evidence must include the formerly accepted invalid composition and valid boundary transfers. Evidence: [composition regressions](../simulator/tests/test_mux_tcp.py) reject packed256 before flow construction and confirm packed255/unpacked256 both-direction delivery; [corrected repair-credit description](modules/local-global-rlnc.md), [complete source27e check](../work/implementation-wave27e/validation.json).

## Reading order and detailed task lists

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
The [latest required aggregate](../work/secure-udp-performance-progress-20261113/attempt-3/validation.json)
passed with stable source maps:1526 Rust cases including doctests,295 Python
tooling cases and1658 simulator cases, plus formatting, strict Clippy, rustdoc
and CLI checks. Complete serialized Rust execution preserves all assertions and
deadlines. Both earlier aggregate failures and all native target failures remain
unchanged; these local results do not close any parent mode/platform/lifecycle gate.
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

| Workstream | Detailed checkbox IDs | Specification | Depends on |
| --- | --- | --- | --- |
| Connection/authentication | CONN-* and UDP-* | [Architecture](architecture.md), [carriers](overlay-and-carriers.md) | BASE schema/security decisions |
| Shared point-to-point security | SEC-01..SEC-12 | [Secure session](modules/secure-session.md) | maintained implementation/API review, opaque records, injected time, preserved data protection |
| TUN active flow control and QoS | FC-01..FC-25 | [Flow control](flow-control.md) | bounded records, authenticated feedback; TCP proxy needs owned TCP legs |
| Internal L2 management/reload | MG-01..MG-08 | [Management protocol](overlay-and-carriers.md) | authenticated session; stable control framing before hot data modes |
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
- [ ] [CONN-02] Implement server pin/CA verification, no-SNI profile and independently configured cover name without accept-all certificate checks.
- [ ] [CONN-03] Implement transcript/exporter-bound member authentication, capability selection, role separation and 0-RTT rejection in retained TLS profiles; integrate shared WireGuard-like session authentication with equally explicit peer/carrier/configuration binding under SEC-01..SEC-04. Preserve existing credential requirements until a reviewed binding/migration is specified.
- [ ] [CONN-04] Implement session creation, single-use lane join tokens, expiry, replay rejection and per-lane identity.
- [ ] [CONN-05] Implement bounded framing, byte/count budgets, timeouts and pre-auth work/connection limits.
- [ ] [CONN-06] Implement AEAD/MAC protection, direction/lane/key domains, unique packet numbers, replay windows and rekey/exhaustion handling.
- [ ] [CONN-07] Implement default paired half-duplex carriers and full-duplex carriers with independent direction budgets and reverse feedback.
- [ ] [CONN-08] Implement explicit raw/TCP/UDP selection and visible, configured fallback; permission absence cannot silently change selected semantics.
- [ ] [CONN-09] Implement and qualify the requested HTTPS-like real TCP/TLS handshake followed by ACK-independent custom TCP-shaped packets on the original ports and sequence space, with configurable SNI and independent own-server trust. Preserve the separate real HTTPS framing/ALPN compatibility work and its MOD-HTTPS-* gates; it is not a substitute for the raw path. Separately implement and qualify the requested L2TP cover.
- [ ] [CONN-10] Complete UDP-* gates for OpenVPN-like, QUIC-header appearance and the new minimal media appearance, including standalone same-socket authentication; TCP-bootstrapped UDP alone is incomplete. Preserve the original OpenVPN wire-handshake gate and genuine QUIC compatibility evidence as distinct contracts.
- [ ] [CONN-11] Qualify raw TCP packet ownership, sequence/ACK/options/RST/PMTU/NAT behavior in isolated target-path tests.
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
- [ ] [TEST-13] Run remote Linux/Windows CI and Android compile gates; keep native device execution as a separate gate.
- [ ] [TEST-14] Run native Windows TAP/Wintun and Android VpnService/protect/lifecycle tests, not only cross-compilation.

## Per-mode parity implementation gates

Each P-* gate means the named algorithm/codec/workload adapter is implemented and
has its matrix-specific focused tests. Integration coverage is additionally gated
by TEST-* and release checks. Workload-only ACK/TCP knobs and research diagnostics
must keep their documented scope; never enable them by mutating TAP endpoint TCP.
A checkbox must agree with `config/mode-catalog.toml` status. All are currently
planned. New mode IDs require new checklist entries automatically.

- [ ] [P-legacy-arq] Implement and validate `legacy-arq` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-legacy-block-fec] Implement and validate `legacy-block-fec` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-legacy-sliding-fec] Implement and validate `legacy-sliding-fec` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-legacy-hybrid-fec] Implement and validate `legacy-hybrid-fec` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-compact-rlnc] Implement and validate `compact-rlnc` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-compact-arq] Implement and validate `compact-arq` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-first-flight-arq] Implement and validate `first-flight-arq` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-bounded-gap-arq] Implement and validate `bounded-gap-arq` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-compact-block-fec] Implement and validate `compact-block-fec` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-local-global-rlnc] Implement and validate `local-global-rlnc` (M3); preserve its [parity contract](mode-parity.md).
- [ ] [P-path-scheduling] Implement and validate `path-scheduling` (M3); preserve its [parity contract](mode-parity.md).
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
