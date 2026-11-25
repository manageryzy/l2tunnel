# Implementation status

This document summarizes the current implemented scope of the Rust workspace and
explicitly separates contract-tested, Linux integration-tested, cross-compiled,
and open qualification gates. Historical experiment receipts remain preserved
unchanged under `work/` and `simulator/`.

The implementation is incomplete and is not a finished production VPN: 48 of 49
entries in `config/mode-catalog.toml` remain `planned` (`kcp-like-l2` is
`implemented`), and native Windows/Android device runs, full 80 Mbit/s
all-carrier native qualification, and public ISP classification studies remain
open. Priority blocking items are tracked at the top of
[docs/implementation-checklist.md](implementation-checklist.md#blocking-behavior-corrections--execute-before-new-feature-work).

## Implemented subsystems

| Subsystem | Status | Scope & key references |
| --- | --- | --- |
| **Compact Common wire & security** | Implemented, contract-tested, finite Linux native | 5-byte compact data framing, strong 21-byte control/feedback records, ChaCha20-Poly1305 / AES-128-CCM-4 / ChaCha20+CRC32C data suites, Noise IK/IKpsk2 + Ed25519 member auth (`l2tunnel-handshake`, `l2tunnel-identity`, `l2tunnel-security`, [compact-wire-cleanup.md](modules/compact-wire-cleanup.md)). |
| **Common record engine & hot switching** | Implemented, contract-tested, finite Linux native | Reserved two-slot `Engine`/`Bank` hosting `Swift`, `Aligned`, `Packed`, `AlignedCompact`, `PackedCompact`, `PerConnectionCompact`, `Rolling`, `RollingCopies`, `Striped`, `Research`, and Common TCP proxy (`l2tunnel`, `l2tunnel-runtime`, [common-record-engine.md](modules/common-record-engine.md)). Authenticated `L2SC` PREPARE/READY/DRAIN/COMMIT/RETIRE switching across protocol families. |
| **Carriers & covers** | Implemented, finite Linux native | Same-socket UDP (`quic-like`, `media-like`, `tls-like`, `openvpn-like` standard outer handshake), `raw-packet` TCP-to-raw with synchronous fast-path send and optional `--udp-cover tls-like`, maintained `tcp` (TLS 1.3, configurable named SNI via `--sni`), and genuine Quinn `quic` ([maintained-common-carriers.md](modules/maintained-common-carriers.md), [raw-common-carrier.md](modules/raw-common-carrier.md), [https-carrier.md](modules/https-carrier.md)). |
| **Swift high-BDP ARQ & FEC** | Implemented, contract-tested, finite Linux native (100/10); in-process simulation (200–1000 Mb/s) | Systematic sliding-window coding with SIMD GF(2^8) (`tape-reed-solomon`), base-first rotating gap requests, tighter RTT retry spacing, and bounded HoL retry copy protection ([swift.md](modules/swift.md)). Historical 100/10 Linux TAP `selftest.py` measured `79.7–80.5 Mbit/s` at 70 ms RTT / 15% loss; in-process release simulation at 70 ms RTT / 15% loss reaches `76.0–78.5%` of wire budget across `200/20`, `300/30`, `500/50`, and `1000/100 Mbit/s` for both ARQ and FEC (not kernel qualification). |
| **Session receiver credit & live speed budget** | Implemented, contract-tested | `L2CR` processed-window + drain-rate pacing (`l2tunnel-flow-control::session_credit`), quiescent idle heartbeat backoff (`250 ms` up to `10 s`), UDP `SO_RCVBUF`/`SO_SNDBUF` sizing, high-BDP pacing bursts/ceilings, and authenticated live speed-budget tuning (`ProfileTag::RateBudgetV1`, `1 Mbit/s..=10 Gbit/s`, scaling wire bursts, credit ceilings, and runtime work batches; [receiver-credit.md](modules/receiver-credit.md), [live-tuning.md](modules/live-tuning.md)). |
| **Live tuning & dynamic MTU** | Implemented, contract-tested, loopback-tested | Noise M1/M2 live-tuning catalog generation (`l2tunnel::live_tuning`), synchronized device MTU updates, and multi-protocol local API/GUI FEC & MTU tuning across `Swift`, `Aligned`, and `Packed` ([live-tuning.md](modules/live-tuning.md)). |
| **CSR meters (local & remote)** | Implemented, contract-tested, loopback-tested | Typed control/status register snapshots, prefix/cursor paging, catalog inspection, and in-band remote peer reads over `Liveness` (`ProfileTag::MetersV1`) exposed in `l2tunnelctl meters` and the GUI Statistics page ([meter-csr.md](modules/meter-csr.md)). |
| **In-process tunnel speed & ping tests** | Implemented, contract-tested, loopback-tested | Authenticated `ProfileTag::TunnelTestV1` address agreement + embedded `smoltcp` TCP/ICMP tester/responder (`l2tunnel-tunnel-test`) with 4 MiB buffers and adaptive upload/download send-queue caps; packets cross the tunnel without touching TUN/TAP or the host stack ([tunnel-tests.md](modules/tunnel-tests.md)). |
| **Local API v5, CLI & Desktop GUI** | Implemented, contract-tested, Linux GUI verified | Versioned Unix socket and Windows named-pipe IPC (`l2tunnel-client-core::local`), 17 grouped `l2tunnelctl` commands (including `socks show\|set\|flows` and `carrier show\|switch`), `daemon` profile store (Common and TCP-proxy profiles), RFC 1928/1929 SOCKS5 over TCP-proxy (`DGUI-08`), live make-before-break UDP carrier/cover switching (`ProfileTag::CarrierSwitchV1`, `DGUI-14`), rtnetlink device/route management, `pkexec` systemd per-user installer, and `egui`/`eframe` desktop GUI (`l2tunnel-desktop-ui`, `l2tunnel-linux-gui`, `l2tunnel-windows-gui`, 13/14 `DGUI-*` closed) ([local-operations.md](modules/local-operations.md), [desktop-gui.md](modules/desktop-gui.md)). |
| **KCP-like L2 profile** | Implemented, contract-tested | TAP-layer Ethernet profile (`raw`, `headers`, `lz4`, plus `ChannelOrdered` variants) over Common `PackedCompact` with KCP-like recovery (`config/mode-catalog.toml`: `status = "implemented"`, [kcp-like-l2.md](modules/kcp-like-l2.md)). |
| **VXLAN pass-through & VTEP** | Implemented, contract-tested, Linux namespace qualified | Pure RFC 7348 codec & clock-injected multi-domain VTEP engine (`l2tunnel-vxlan::vtep`: FDB aging/move limits/static precedence, aggregate BUM accounting, split-horizon, non-fragmenting IPv4/IPv6/jumbo MTU budgets), live `VxlanDevice` & `VxlanVtepDevice` UDP adapters (`l2tunnel-platform-vxlan`), Common CLI `--vxlan-bind`/`--vxlan-peer`/`--vni` attachment on `--layer tap`, and owned Linux namespace qualification covering mixed untagged/802.1Q VLAN filtering (`vlan_filtering 1`), dual isolated VNIs, 15% loss/25% reorder + concurrent DSCP QoS, and direct kernel-VXLAN VTEP interop (`VX-01..VX-08`, `MOD-VX-06`). Windows/Android L2 qualification (`VX-09`) remains open ([vxlan.md](modules/vxlan.md), [overlay-and-carriers.md](overlay-and-carriers.md#vxlan-support), [receipt](../work/vxlan-live-20261125/receipt.json)). |
| **Windows & Android platforms** | Cross-compiled / partial | `l2tunnel-windows` + `l2tunnel-platform-windows` implement the Common UDP Windows service (`install|start|install-start|uninstall|run`, `foreground`), Wintun L3, named-pipe API v1/v4/v5, and `l2tunnel-windows-gui` (cross-compiled and Wine-tested; no native Windows run). `l2tunnel-android` builds `l2tunnel-android-service` with an abstract-Unix-socket FD broker (`ScmRights` TUN + `protect`); Kotlin app and JNI shell remain open ([windows-local-service.md](modules/windows-local-service.md), [windows-wintun.md](modules/windows-wintun.md)). |

## Open qualification gates

- **Real kernel/netns high-BDP performance:** Real Linux namespace qualification at `200/20`, `300/30`, `500/50`, and `1000/100 Mbit/s` under 70 ms RTT / 15% loss (and `SO_RCVBUF`/`SO_SNDBUF` tuning beyond Linux's default 212 KiB `rmem_max`/`wmem_max`) remains open.
- **Mode parity:** 48 of 49 catalog entries in [mode-parity.md](mode-parity.md) remain `planned` pending full native/impairment qualification.
- **Flow control & TCP proxy:** Per-flow transparent TUN active credit (`FC-*`) and adaptive TCP-proxy receive-window ownership remain open beyond the existing session receiver credit and fixed-buffer proxy.
- **Session lifecycle & carrier gaps:** State-retaining logical-delivery outage recovery (`CL-38` — bounded automatic fresh-authentication reconnect on lease expiry, counter exhaustion, and peer timeout is now implemented in `l2tunnel-client-core::service::recovery` with distinct `terminal_reason` and `recovery` status, while preserving in-flight delivery state across outages remains open), in-session fresh-DH rekey (`SREF-*`), cross-protocol live carrier migration (`UDP <-> TCP/TLS <-> QUIC`), elevated root/UAC installer qualification (`DGUI-13`), and TLS pin verification remain open.
- **Platforms & deployment:** Native Windows execution (driver, ACL, sleep/resume), Android JNI/Kotlin VpnService app, standard OpenVPN dissector qualification, and controlled ISP classification campaigns remain open.

## Historical evidence boundary

Older per-wave checkpoint summaries and immutable receipts (including the initial
Git import at [docs/checkpoints/2026-11-12.md](checkpoints/2026-11-12.md),
completed review follow-ups in [docs/review-followups.md](review-followups.md),
and local validation archives in `work/`) remain preserved as historical records
bound to their recorded source hashes and are never rewritten to claim later
changes passed.
