# Client architecture and delivery checklist

Status: full client delivery plan with substantial Linux implementation and
cross-compiled Windows/Android components. This document expands the client work
in [the implementation plan](implementation-plan.md), using the protocol
boundaries in [the architecture](architecture.md) and the mode requirements in
[the parity inventory](mode-parity.md). Broad checkboxes below remain open until
their complete cross-platform contract is met.

Implemented today:
- Common CLI (`l2tunneld`, `l2tunnel-linux`, `l2tunnelctl`) and `daemon` profile
  store over local API v5 (async keyed operations, event ring, compare-and-set
  profiles, host device/route management, live tuning, live speed-budget tuning,
  local/remote CSR meters, in-process tunnel speed/ping tests, redacted
  diagnostics export, and elevated `pkexec` systemd service install/restart).
- Shared `egui`/`eframe` desktop GUI (`crates/l2tunnel-desktop-ui`, built as
  `l2tunnel-linux-gui` and `l2tunnel-windows-gui`) implementing Overview,
  Connection (live tuning, speed budget, catalog switch, tunnel tests), Devices,
  Routes, Statistics (rolling charts + CSR meters), Management (profiles, keys,
  service info/update/stop, server sessions), and Events (diagnostics export).
  SOCKS5 and live carrier switching remain open.
- Windows Common UDP service host (`apps/l2tunnel-windows`,
  `crates/l2tunnel-platform-windows`: Wintun L3, named-pipe API v1/v4/v5,
  `service install|start|install-start|uninstall|run`, `foreground`, GUI),
  cross-compiled and Wine-tested; native Windows execution remains open.
- Android `l2tunnel-android-service` binary with abstract-Unix-socket
  `ScmRights` TUN descriptor handoff and outer-socket `protect` callback;
  Kotlin application and JNI shell remain open.

See [local operations](modules/local-operations.md),
[desktop GUI](modules/desktop-gui.md), [Windows local service](modules/windows-local-service.md),
and [implementation status](implementation-status.md) for current evidence.

Keep task IDs stable when splitting work into issues. Completing a design does
not complete its implementation item. Each completed item needs an evidence link
and a label: `contract-tested`, `implemented`, or `integration-tested`. Record the
tested OS, carrier, packet layer and configuration with integration evidence.

The approved deployment is fixed point-to-point between an owner's client and
server. The planned [common inner secure session](modules/secure-session.md) must supply
authentication, key exchange, record security and management across the selected
carrier, including TCP/HTTPS. This WireGuard-like responsibility split does not
choose a WireGuard library, wire format, provisioning flow or cipher negotiation.
Do not assume account administration, multi-device enrollment or multi-peer
workflows. Outer carrier selection, inner security and data record/recovery
selection are separate configuration domains. Swift remains an algorithm inside
the selected carrier; moving security to the common layer must preserve its
existing AEAD behavior and all other requested modes.

## Source projects and ownership

Proposed names below are source boundaries, not packages already implemented.
Create new packages only when introducing their first concrete behavior. Public
protocol crates remain independent of Tokio, OS handles, clocks and privileges.

| Source project | Responsibilities | Consumers and boundary |
| --- | --- | --- |
| Existing `crates/l2tunnel*` protocol crates | Packet processing, authenticated session, peer management, MUX, QoS, recovery, CSR meters, tunnel tests and codec state machines | Portable embedding API; injected time and I/O |
| Existing `crates/l2tunnel-client-core` | Common lifecycle/service, `daemon` profile store, host device/route management, elevated service install, live tuning, live speed-budget tuning, CSR meters, tunnel tests, grouped CLI | Shared service/client core on Unix sockets and Windows named pipes; no widgets |
| Existing `client-core::local` | Versioned local API (v1/v4/v5): async keyed operations, bounded event ring, profiles, tuning, meters, tunnel tests, diagnostics | Service/client boundary; distinct from the peer wire protocol |
| Existing `crates/l2tunnel-runtime` | Async Tokio execution, timers, carrier/socket ownership, session credit, meters, live tuning/MTU, speed budget, tunnel tests | Runtime outside public protocol API; injected backend interfaces for client-core |
| Existing `crates/l2tunnel-platform-linux` | TAP/TUN descriptors (`ioctl`), rtnetlink device/route management (`netconf.rs`) | Linux-only adapter with narrow documented FFI boundary |
| Existing `crates/l2tunnel-platform-windows` | Wintun L3 adapter (`tun-rs`), Windows named-pipe ACL/owner-check FFI (`local_pipe.rs`) | Windows-only adapter with narrow documented FFI boundary; cross-compiled/Wine-tested, native run open |
| Existing `apps/l2tunnel-linux` & `apps/l2tunnel-windows` | Runnable Linux client/service/GUI and Windows Common UDP service/foreground/GUI host | Shared `client-core`/`desktop-ui` reuse; Windows native qualification remains open |
| Existing `apps/l2tunneld` | Listener/server lifecycle and administrative endpoint | Reuses `client-core`; rejects client-only operations |
| Existing `apps/l2tunnelctl` | Grouped CLI commands and machine-readable `--json` output | Uses local API v5 over Unix sockets and Windows named pipes |
| Existing `crates/l2tunnel-desktop-ui` (`l2tunnel-linux-gui`, `l2tunnel-windows-gui`) | Nonprivileged `egui`/`eframe` desktop GUI (profiles, connection, live tuning, speed budget, tunnel tests, devices, routes, statistics/meters, management, events) | Calls local API v5 only; no second protocol engine; SOCKS5 & live carrier switch remain open |
| Existing `apps/l2tunnel-android` | `rlib`/`cdylib` plus `l2tunnel-android-service` binary with abstract-Unix-socket `ScmRights` TUN handoff & `protect` callback | No JNI or Kotlin shell yet |
| Planned `clients/android` | Kotlin application, VpnService lifecycle, permission UI, notifications and platform credential adapter | Calls the shared Rust core; Android GUI is independent of desktop toolkit choice |
| Existing `tools/fake_local_service.py` & unit fixtures | Fake v5 local service backend and scripted client workflows | CLI/GUI contract parity tests before privileged native validation |

### Shared core and local control API

- [ ] [CL-01] Define typed client states (`disconnected`, `preparing`,
  `authenticating`, `connected`, `reconfiguring`, `reconnecting`, `stopping`,
  `failed`), permitted transitions and ownership of every device/socket/task.
  Include cancellation, service restart and resumable UI attachment. Test the
  state machine with injected clocks and fake I/O before wiring a service.
- [ ] [CL-02] Specify a versioned local control API with negotiation, minimum
  supported version, strict bounded decoding, typed errors and feature discovery.
  Keep local API version, configuration schema, wire protocol and application
  version independent. An unsupported method fails explicitly.
- [ ] [CL-03] Implement local IPC with OS identity/ACL authorization: Unix-domain
  sockets on Linux, named pipes on Windows and an app-private Android binding.
  Separate read-only status permission from profile edits, credential operations
  and service/device administration. Do not expose a TCP admin listener by default
  or use browser-origin trust as authorization.
- [ ] [CL-04] Make connect, disconnect, diagnostics and configuration apply
  asynchronous operations with an ID, deadline, progress, result and idempotency
  key. Bound event history and subscription queues; use event cursors plus a full
  snapshot to recover dropped events. UI disconnect must not implicitly cancel
  a running tunnel or an operation already accepted by the service.
- [ ] [CL-05] Define crash-safe desired/applied configuration revisions and a
  single writer per service instance. Track peer transaction ID, current/staged
  epoch, digest, drain progress and commit certainty. A possible remote COMMIT
  forbids local rollback; expose `reconciling` or `reconnect_required` until the
  peer outcome is known. Test restart after each durable write and control stage.

The local control API requests changes from the service. The service translates
peer-sensitive changes into the authenticated internal L2 management protocol
described in [the architecture](architecture.md). A local GUI/CLI success only
means a request was accepted until the distributed transaction commits. This
management envelope must also work inside a TUN session; it does not require
injecting Ethernet management frames into an IP device. Neither the local API
nor the peer management messages are forwarded to a user's TAP bridge or VXLAN.

### Profiles, capabilities and traffic policy

- [ ] [CL-06] Implement one strict versioned profile schema and canonical digest
  shared by file loading, CLI and GUI. Validate unknown fields, ranges, conflicts
  and unsupported combinations; provide a side-effect-free plan/diff operation.
  Use compare-and-set against a configuration revision to reject stale edits.
- [ ] [CL-07] Expose explicitly selected `raw_tcp`, ordinary TCP and UDP carrier
  choices with an operator-configured fallback policy, requested/effective carrier,
  privilege availability,
  implementation/qualification status and the reason for fallback. Keep default
  half duplex, full duplex, physical lanes and MUX channels distinct. No preference
  setting may silently weaken authentication or enable an unimplemented backend.
- [ ] [CL-08] Expose OpenVPN-like, QUIC-header, TLS-like, and minimal RTP audio/video-like UDP
  cover choices separately from the original HTTPS TCP/TLS-to-raw path, retained
  TCP/TLS, optional HTTPS/H2 streaming, genuine QUIC and L2TP profiles. Show actual
  handshake/outer-layout, parseability and compatibility status; a project-specific
  framing profile is not a claim of OpenVPN/QUIC interoperability. QUIC header
  cover does not require native QUIC congestion control; minimal RTP does not
  imply full WebRTC. Keep endpoint address, trust/pin, SNI policy and optional
  cover name separate, with a strict no-SNI option. Configurable independent
  cover SNI (`ClientSni::Named`, `--sni`) is implemented; pin verification
  remains open.
- [ ] [CL-09] Add TUN/TAP settings and explicit VXLAN attachment settings: local
  device, addresses/routes, MTU, bridge, VNI, endpoints, UDP port, learning/flood
  policy and tenant limits. Advertise supported combinations from the backend;
  distinguish carrying Ethernet for a VXLAN attachment from using UDP as the
  tunnel carrier. Android standard VpnService must report TAP as unsupported.
- [ ] [CL-10] Add L3 active flow-control settings for the negotiated TCP-aware
  mode: active-flow threshold, initial/min/max window or credit, growth bounds,
  target queue delay, receiver memory limit, pressure signal, decrease/recovery
  behavior and fallback. Display requested and effective control mode and the
  reason for any fallback. Window ownership and any TCP termination remain the
  architecture's responsibility; a client setting must not authorize unsafe ACK
  rewriting. TAP uses endpoint/system TCP behavior without tunnel TCP-window
  changes, while retaining bounded common MUX admission and system-backed QoS.
- [ ] [CL-11] Expose shared QoS profiles with classifier rules, weights, minimum
  service, maximum rates, burst/queue limits and per-flow fairness. Validate total
  budgets, account for repairs/retries/control overhead and show queue pressure,
  drops, active flows, current window/credit, RTT and latency by class/direction.
  TCP ACKs, SYNs and probes remain subject to the same user-traffic admission
  policy; reserved peer-management service is bounded and not a payload bypass.

The profile editor should provide a basic connection workflow and an expandable
advanced editor backed by the same schema. Show unsupported settings with a reason
instead of hiding why a saved profile cannot run on another platform. Every
[mode inventory](mode-parity.md) entry needs a capability/status mapping; only
implemented and qualified combinations may be activated. Retain explicit
experimental labels and benchmark-only labels.
All 49 P-* parity entries and every requested recovery, packed, rolling and proxy
profile retain their full acceptance definitions. SW-11 includes Swift-to-other-
record-profile epoch switching; exposing only in-Swift parameter changes does not
complete it.

### Common secure session and fixed-peer recovery

- [ ] [CL-37] Integrate the SEC-01..SEC-12 common inner secure-session contract
  through the same typed client/service API for every selected carrier, including
  TCP/HTTPS. Separate requested/effective carrier/cover, security and data-record/
  recovery policy, with implemented/tested/platform capability limits and failure
  reasons. Preserve Swift AEAD behavior when security moves to the common layer,
  mandatory integrity/replay protection and stable management across mode changes.
  Do not present undecided library, key-provisioning, packet-format or cipher-
  negotiation choices as owner decisions or available controls.
- [ ] [CL-38] Make bounded automatic recovery the default for the fixed peer:
  retain bounded logical session/delivery/recovery state during temporary outage,
  reconcile it only with authenticated continuity evidence, and expose retry
  count, deadlines, retained-state limits, pending outcome and terminal expiry.
  Peer restart requires fresh authentication and a new cryptographic session;
  never blindly replay old-session packets, reuse nonces, or report a replacement
  carrier as the retained old connection. Test outage, peer restart, expiry,
  exhausted retries, cancellation and uncertain mode-switch outcomes. The current
  optional Swift reconnect that starts fresh ordering state does not satisfy this
  state-retaining recovery contract.
- [ ] [CL-39] Validate carrier continuity and cover limits through identical CLI/
  GUI service operations: carrier handshake, inner authentication, user data and
  management use the same connection or UDP socket and five-tuple. Report the
  original HTTPS real TCP/TLS-to-raw path's same-port/sequence-space behavior,
  ACK/RST/firewall/privilege limitations and recovery separately from optional H2
  streaming. Validate OpenVPN-like/QUIC-header and minimal RTP audio/video layouts
  against their selected parser contract, with no native QUIC controller or full
  WebRTC prerequisite. Keep parser acceptance, interoperability and controlled
  ISP QoS measurements distinct; separate TCP bootstrap plus UDP data cannot
  satisfy this target.

### CLI delivery

- [ ] [CL-12] Specify command groups for profile list/show/import/export/validate,
  connect/disconnect, status, capabilities, mode/QoS apply, operation watch/cancel
  and diagnostics. Keep machine output versioned (`--json`), exit codes stable,
  errors actionable and secrets absent from arguments/history/output. Do not
  present proposed commands as available until implemented.
- [ ] [CL-13] Implement an offline validation/plan path with no device, route,
  credential or network side effects. Print the effective profile, unsupported
  combinations, required privileges and whether a proposed change is local,
  coordinated hot switching or a controlled reconnect.
- [ ] [CL-14] Implement the connected CLI through the shared local API, including
  operation IDs, watch deadlines and idempotent retries. A watch timeout reports
  an operation still running; it does not claim failure or issue a second apply.
- [ ] [CL-15] Keep all service operations available through the API/CLI when a
  GUI feature is added. Test CLI and GUI adapters against the same request/response
  fixtures, including conflicts, unsupported features and uncertain commit.
  Android may expose a developer/test harness for these operations without
  promising a normal Android shell-installed binary.
- [ ] [CL-16] Add redacted diagnostic export with selected logs, versions,
  negotiated/effective settings, counters and operation outcomes. Bound capture
  duration/size; explicit packet capture remains a separate action. Export excludes
  private keys, tokens and user payload by default and uses an explicit destination.
  Progress (2026-11-23, Linux, fake service and unit tests): `l2tunnelctl
  diagnostics export` and the GUI Events page write the
  [shared report](../crates/l2tunnel-client-core/src/local/diagnostics.rs)
  (versions, status, capabilities, counters, devices, routes, retained events,
  recent operation outcomes) to a new owner-only file, addresses redacted by
  default. Selected service logs and bounded capture remain open.

### GUI delivery and framework decision

- [ ] [CL-17] Record a desktop toolkit decision before adding dependencies.
  Compare a Rust-native UI (for example Slint or iced), a thin Tauri/webview UI,
  and native platform shells using a small prototype. Evaluate accessibility,
  packaging/signing, resource usage, licensing, localization, Linux desktop
  coverage, service IPC and maintenance.
  Owner selection 2026-11-23: `egui`/`eframe` (implemented in
  `crates/l2tunnel-desktop-ui`; see [desktop GUI](modules/desktop-gui.md)). The
  formal multi-toolkit comparison matrix was skipped by owner decision, so this
  box stays open.
- [ ] [CL-18] Implement a nonprivileged desktop GUI over the local API: service
  discovery, profile workflow, connect/disconnect, effective state, errors and
  reconnect handling. Run privileged setup through the platform service/helper;
  do not launch the whole GUI with administrator/root privileges.
- [ ] [CL-19] Implement the advanced transport/device/mode/QoS editors from the
  shared schema. Show capability/fallback reasons, authentication trust settings,
  VXLAN attachment scope and the consequences of a reconnect before applying.
  Preserve unknown newer profile versions without silently rewriting them.
- [ ] [CL-20] Implement hot-switch progress with requested/applied revision,
  both-peer readiness, drain state, epoch/digest and final outcome. Disable only
  conflicting edits while a transaction runs; support reattachment after GUI
  restart. Cancellation must show when commit makes cancellation unsafe.
- [ ] [CL-21] Add bounded live metrics, accessible keyboard navigation,
  localization hooks, log redaction, tray/background behavior where available,
  and explicit close-versus-disconnect behavior. Test with a fake service first;
  native display, accessibility and packaging checks need separate OS evidence.

### Linux service and privilege lifecycle

- [ ] [CL-22] Implement foreground and managed-service operation using the same
  runtime, with a documented privilege split. A narrow helper may create an owned
  TAP/TUN device or raw socket and pass handles; the frontend cannot submit
  arbitrary shell commands. Support precreated devices and ordinary TCP/UDP
  without raw-socket privilege when the configured device path permits it.
- [ ] [CL-23] Track ownership of routes, DNS changes, bridges, VXLAN attachments
  and device handles. Prepare/commit or undo only owned changes on failure; never
  remove preexisting user configuration. Cover stale process records, duplicate
  service start, sleep/resume, interface loss and interrupted setup/teardown.
- [ ] [CL-24] Store credential references in profiles and private material in
  the configured OS credential provider or explicitly permission-restricted
  service store. Define headless unlock/rotation/revocation behavior and secret
  redaction; do not require an interactive desktop keyring for unattended service.
  Progress (2026-11-23, Linux): the `daemon` keeps profiles in
  `<state-dir>/profiles/` (0700/0600); profiles hold only credential file
  references (owner decision: validated run options). A service-owned key
  store, rotation and revocation remain open.

### Windows service and native adapters

- [ ] [CL-25] Implement an installed Windows service plus a nonprivileged
  CLI/GUI connection. Scope named-pipe ACLs and administrative actions explicitly;
  isolate installation, driver setup and service control from ordinary connection
  management. Test user changes and concurrent interactive sessions.
  Progress (2026-11-23, cross-compiled and unit-tested on Linux only, with no
  native Windows run): [Windows local service](modules/windows-local-service.md)
  implements the `l2tunnel-windows` service host (install/uninstall/run and
  foreground mode, one directly hosted service owner), local API v1/v4/v5 on
  the named pipe `\\.\pipe\l2tunnel` with a *proposed* DACL awaiting owner
  confirmation, a client-side pipe-owner check, and the nonprivileged
  `l2tunnelctl` and `l2tunnel-windows-gui` frontends. Native, ACL and
  multi-session evidence is tracked as WLS-02..WLS-08.
- [ ] [CL-26] Qualify separate Wintun L3 and TAP L2 adapters, handle lifetimes,
  driver distribution requirements, MTU and address/route cleanup. Determine
  VXLAN attachment support independently; do not infer it from TAP support.
  Native FFI requires its own documented unsafe boundary and review.
- [ ] [CL-27] Implement Windows credential storage, bounded event logging,
  service recovery, sleep/resume and network-change handling. Validate cleanup
  after crashes and driver errors without disturbing existing routes/adapters.
  Record native Windows tests separately from cross-compilation.

[Wintun's official documentation](https://www.wintun.net/) identifies it as an L3
adapter and supplies distribution guidance; the release implementation must check
the chosen driver artifact and terms before packaging.

### Android application and VpnService

- [ ] [CL-28] Implement the Kotlin shell and user authorization through
  `VpnService.prepare()`, an IP interface through `Builder`, required service
  lifecycle/notification behavior for supported Android versions, and revocation
  handling. Standard operation is TUN/L3; no root, raw-socket or TAP capability is
  presumed. Keep unsupported L2/VXLAN attachment scenarios explicit.
- [ ] [CL-29] Protect every outer/control socket with `VpnService.protect()`
  before connecting/sending through the VPN path, including newly joined lanes
  and reconnect sockets. Specify JNI ownership, descriptor close/dup rules,
  callback threads, cancellation and process death. Fail connection setup when
  protection or the descriptor handoff fails.
- [ ] [CL-30] Implement Android network-change, background/foreground, permission
  revocation and reconnect behavior with bounded work and battery-aware retry
  limits. Test Wi-Fi/mobile transitions and app recreation without duplicate
  tunnels, retained packet descriptors or route loops. Validate always-on/lockdown
  behavior only if included in the declared supported configuration.
- [ ] [CL-31] Add Android credential-provider integration and a UI using the
  same configuration/operation contracts as desktop. Select supported key types
  and storage behavior after provider capability testing; never assume that a
  nonexportable OS key can satisfy every Rust crypto API. Keep credentials out of
  backups/logs and define unlock, rotation and removal behavior.

The [official VpnService reference](https://developer.android.com/reference/android/net/VpnService)
is the platform contract for permission, IP-device creation and socket protection.
Native lifecycle behavior must be validated on the declared Android API levels.

### Acceptance, packaging and completion receipts

- [ ] [CL-32] Run common contract tests for version mismatch, authentication/
  authorization failure, malformed requests, bounded queues, stalled subscribers,
  stale revisions, duplicate commands, deadlines and service reconnects.
  Test secrets never appear in errors, telemetry or exported profiles.
- [ ] [CL-33] Exercise identical scripted CLI and GUI workflows against fake and
  real services: connect, profile validation, fallback, QoS apply, coordinated
  mode change, cancellation, uncertain commit and reattachment. Validate requested
  versus effective status across both peers, rather than just button responses.
- [ ] [CL-34] Extend [the isolated local lab](testing.md) with client-driven TAP
  bridge, TUN routing and VXLAN attachment scenarios under `tc`/netem. Cover
  congestion, 1/16/64 flows, QoS starvation bounds, active L3 growth/backoff,
  unsupported TCP features, carrier fallback and hot switching under load.
  Keep all privileged network changes inside owned namespaces.
- [ ] [CL-35] Produce separate Linux, native Windows and Android device receipts
  for installation, user permissions, lifecycle, packet forwarding, connectivity
  changes and cleanup. Include driver/API/kernel versions, effective profiles,
  logs and known unsupported combinations; compile-only jobs are not device tests.
- [ ] [CL-36] Define distributable artifacts, signing/update/rollback policy,
  dependency/driver license review, supported OS versions and migration behavior.
  Preserve explicit owner decisions for project license and publication. Freeze
  supported CLI/local-API compatibility only after the above behavioral gates;
  do not ship scaffold-only controls as working features.

## Delivery order

Deliver CL-01 through CL-16 alongside M0–M4 protocol work so native services have
one reusable lifecycle and administrative API. Deliver CL-37 through CL-39 with
the common secure-session and carrier migration; they do not supersede existing
CL, SW, SEC or P-* gates. CL-17 is a decision gate; GUI
implementation follows working service operations. Linux service and isolated
lab validation provide the first real device path. Windows and Android progress
in parallel after the common API stabilizes, with independent native gates.
CL-32 through CL-36 apply continuously and close M5 only for explicitly tested
platform/carrier/device combinations.
