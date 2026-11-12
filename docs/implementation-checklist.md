# Implementation checklist and evidence ledger

This is the persistent entry point for implementation progress. An unchecked item
is required work, not a forgotten suggestion. Completing a design/enum does not
complete its runtime feature. Only tick an item when its named deliverable and
acceptance test exist; add `Evidence:` with a code/test/receipt link on that item.
Mark planned, contract-tested, implemented and integration-tested scope explicitly.
Do not check remote/native/privileged gates on the basis of local builds.

Stable IDs must not be reused. If a task splits, keep its ID as a parent gate and
add child IDs. Update this ledger and the detailed checklists with every change.
`tools/check.py` checks ID uniqueness, evidence markers and all 47 mode entries.

Follow the [parallel development workflow](development-workflow.md) for module
design, interface agreement, concurrent implementation and integration.

## Reading order and detailed task lists

| Workstream | Detailed checkbox IDs | Specification | Depends on |
| --- | --- | --- | --- |
| Connection/authentication | CONN-* and UDP-* | [Architecture](architecture.md), [carriers](overlay-and-carriers.md) | BASE schema/security decisions |
| TUN active flow control and QoS | FC-01..FC-25 | [Flow control](flow-control.md) | bounded records, authenticated feedback; TCP proxy needs owned TCP legs |
| Internal L2 management/reload | MG-01..MG-08 | [Management protocol](overlay-and-carriers.md) | authenticated session; stable control framing before hot data modes |
| VXLAN | VX-01..VX-09 | [Overlay design](overlay-and-carriers.md) | L2 frame validation, tenancy and MTU accounting |
| UDP covers | UDP-01..UDP-11 | [Carrier design](overlay-and-carriers.md) | selected authenticated bootstrap; UDP-only is its own gate |
| CLI/GUI/native clients | CL-01..CL-36 | [Client plan](client-design.md) | shared client-core/local API; native adapters independently qualified |
| Python parity | P-* below | [Parity matrix](mode-parity.md) | actual byte codecs/recovery and test traces |
| Kernel/native verification | TEST-* and RELEASE-* | [Test plan](testing.md) | implemented runtime, no mock-only acceptance |

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
while [pressure capture allocation](modules/proxy-pressure-capture.md) records the
bounded native evidence collection required for the corrected proxy pressure run.

## Tested native vertical slice

- [x] [SLICE-01] Retain verified TLS 1.3 through member authentication and application data, with replay/configuration rejection tests. Evidence: [auth tests](../crates/l2tunnel-auth/src/tests.rs).
- [x] [SLICE-02] Forward native Linux TAP/TUN in half and full duplex, including corrected IPv4/IPv6/TCP tests under 70 ms RTT / 15% loss with owned cleanup. Evidence: [corrected native receipt](../work/native-wave4/receipt.json).
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

- [ ] [CONN-01] Implement retained TCP/TLS socket ownership through handshake, member auth and user traffic; capture the absence of an auth-boundary reconnect.
- [ ] [CONN-02] Implement server pin/CA verification, no-SNI profile and independently configured cover name without accept-all certificate checks.
- [ ] [CONN-03] Implement transcript/exporter-bound member authentication, capability selection, role separation and 0-RTT rejection.
- [ ] [CONN-04] Implement session creation, single-use lane join tokens, expiry, replay rejection and per-lane identity.
- [ ] [CONN-05] Implement bounded framing, byte/count budgets, timeouts and pre-auth work/connection limits.
- [ ] [CONN-06] Implement AEAD/MAC protection, direction/lane/key domains, unique packet numbers, replay windows and rekey/exhaustion handling.
- [ ] [CONN-07] Implement default paired half-duplex carriers and full-duplex carriers with independent direction budgets and reverse feedback.
- [ ] [CONN-08] Implement explicit raw/TCP/UDP selection and visible, configured fallback; permission absence cannot silently change selected semantics.
- [ ] [CONN-09] Implement real HTTPS framing/ALPN behavior, then separately implement and qualify the requested L2TP cover.
- [ ] [CONN-10] Complete UDP-* gates for both cover profiles, including standalone UDP bootstrap; TCP-bootstrapped UDP alone is incomplete.
- [ ] [CONN-11] Qualify raw TCP packet ownership, sequence/ACK/options/RST/PMTU/NAT behavior in isolated target-path tests.
- [ ] [CONN-12] Publish effective carrier/cover/security/duplex capabilities and reasons for unsupported combinations.

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
- [ ] [TEST-05] Exercise both duplex policies, all selected carriers and both UDP covers; measure full wire overhead and terminal confirmation.
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
