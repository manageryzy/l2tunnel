# Linux desktop GUI over local API v5

Status: implemented for Linux (`l2tunnel-linux-gui`, shared `l2tunnel-desktop-ui`)
and cross-compiled for Windows (`l2tunnel-windows-gui`), covering the sidebar frame,
Overview, Connection (protocol catalog hot switching, live make-before-break UDP
carrier/cover switching, live FEC/MTU tuning, live speed-budget tuning, and
in-process tunnel speed/ping tests), Devices, Routes, SOCKS5 (RFC 1928/1929
listener over TCP-proxy profiles with CIDR allowlist and live flow table),
Statistics (rolling charts, lane/channel/flow/device tables, and local/remote CSR
meters with wait-latency percentiles), Management (carrier-aware profile editor
including TCP-proxy profiles, keys, service info/stop, server sessions), Events,
and elevated service installation/restart. Elevated root/UAC installer execution
(`DGUI-13`) and native Windows execution (`WLS-07`) remain open (13/14 `DGUI-*`
tasks closed). This does not by itself complete CL-18..CL-23 or CL-33 in
[client design](../client-design.md).

## Recorded decisions (owner, 2026-11-23)

- CL-17 toolkit: Rust, egui/eframe (`=0.35.0`, glow renderer, X11 and
  Wayland). The GUI links `l2tunnel-client-core` and calls the version-5 API
  in-process (`local::request_operation` and the shared `local::client`
  submission step that the CLI also uses); it does not spawn `l2tunnelctl`.
- Placement: the GUI lives in the shared crate `crates/l2tunnel-desktop-ui`.
  Thin binaries call it: `l2tunnel-linux-gui` in `apps/l2tunnel-linux` and
  `l2tunnel-windows-gui` in `apps/l2tunnel-windows`, each built only with
  `--features gui`, so the headless builds have no GUI dependencies.
- Windows: an installed Windows service holds the Wintun/route privileges and
  serves local API v5 over a named pipe with an ACL (CL-25). The GUI and
  `l2tunnelctl`, the same CLI on both platforms, run unprivileged.
- Scope of the full GUI, all functions also in the CLI: TUN/TAP device
  management, route management, a SOCKS5 entry, a statistics panel, and a
  management area covering profiles, keys, the service, peer/session
  administration, and protocol and carrier switching.
- Privilege: the service (`l2tunnel-linux` as a managed service holding
  CAP_NET_ADMIN) creates devices and changes routes. GUI and CLI stay
  unprivileged and submit typed version-5 operations; the service records what
  it owns and undoes only that (CL-22, CL-23). No frontend shell commands
  (amended 2026-11-24: the frontends may launch the elevated installer below
  through pkexec or UAC; that is the only process they start).
- Layout: sidebar pages with a persistent top bar.
- Roles: one role-aware GUI for client services and `l2tunneld` servers.
- SOCKS5 rides the explicit TCP-proxy profile: the client service accepts
  SOCKS5 CONNECT and opens a proxy flow; the server opens the real TCP
  connection.
- Statistics: a polled `metrics` snapshot of cumulative counters; the
  frontends compute rates and keep their own bounded history.
- Profiles: a service-owned, permission-restricted store reached through the
  local API (CL-12, CL-24).
- Profile form: a profile is a named, versioned set of the same validated
  `connect`/`serve` run options (without `--control-socket`, `--state-dir`,
  `--runtime-model`). Keys stay files the options name; typed editors
  (CL-19) can follow later.
- Profile activation: in-process. One long-running service
  (`daemon --control-socket PATH --state-dir DIR`) owns the API, the store,
  devices/routes and keys, can start idle, and connects a stored profile as
  a keyed connect, or replaces a live session (a controlled reconnect, never
  a hot switch). It connects a remembered default profile on start.
- Keys: keys stay ordinary files that profile options name; there is no
  service-held key store. Frontends generate key files locally and
  unprivileged (member identity, Noise pair, 32-byte secret), and the
  service reports which key files a stored profile names, whether they are
  usable, and their public keys or certificate SHA-256 (`profile_keys`).
  Trusted peers are the public keys a profile pins (`--allow-key`,
  `--noise-peer-key-file`).
- Server sessions: mapped to the existing point-to-point model; no
  protocol-core change. A server generation admits one pinned member, so
  `session_list` holds at most the live session (generation, configured
  peer, uptime, stored profile, trusted member key, authenticated byte
  counters). `session_kick` is a keyed operation that ends the session and
  listens again with the same retained plan (a server reconnect; the same
  member may come back). `member revoke` is two keyed operations composed by
  the frontends (`local::client::revoke_member`): save the running server
  profile with the new `--allow-key` (revision-checked), then replace the
  session with it, so the old member cannot reconnect.

## Recorded decisions (owner, 2026-11-24)

- Elevated start: the GUI (and `l2tunnelctl service start`) starts the
  service itself after the platform administrator prompt; the frontend
  process stays unprivileged and attaches once the service answers.
- "Just start an installer": the prompt runs a short installer/starter, never
  the network-facing service. On Linux, `pkexec PROGRAM system-service
  install|start --uid UID` copies PROGRAM to the root-owned
  `/usr/local/libexec/l2tunnel/l2tunnel-linux`, writes
  `/etc/systemd/system/l2tunnel-UID.service`, and runs `systemctl restart` on
  install/upgrade so an already-running service adopts the new binary; systemd
  runs the daemon as UID with only CAP_NET_ADMIN (ambient and bounding set),
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, serving
  `/run/l2tunnel-UID/api.sock` (private runtime directory, so the same-UID
  socket rule is unchanged) with state in `/var/lib/l2tunnel-UID`. On startup
  the GUI compares its binary version against `service_info` and shows an
  `"Install & restart service…"` banner if the installed service is outdated.
  It starts on request only (no `[Install]` section) and `service stop` leaves
  it stopped. On Windows the UAC prompt runs `l2tunnel-windows.exe service
  start`, or `service install-start` to register it first (the existing
  LocalSystem, manual-start service). One prompt per start on both
  platforms. Implementation: `local::elevate` (shared), `system-service`
  (Linux, root side), `service start|install-start` (Windows); the UAC launch
  uses the maintained `runas` crate, which owns the ShellExecuteExW FFI.

## Implemented first slice

- `model.rs` holds all state without egui or Tokio. Each attachment and each
  event follower has a generation; results from an earlier one are ignored.
- `worker.rs` runs exchanges on one thread with a single-threaded Tokio
  runtime and wakes the UI through `request_repaint`. A long-poll `events`
  follower (`--service` identity, 30 s holds) drives coalesced status
  refreshes; completion events fetch `operation_get` for the result line; a
  gap reply resynchronizes from the status it carries. A refused or lost
  follower schedules a resynchronization every 3 seconds.
- Connect/Reconnect submits the local `reconnect` operation, which connects
  when idle and replaces a live session. Request keys come from the service's
  advisory `next_request_key` through `local::client::submit`, the same step
  the CLI uses, so lost-reply classification (`outcome unknown`, with the key
  to reattach) is identical.
- The log keeps at most 200 lines. Closing the window aborts only the
  worker's exchanges; it never disconnects.

## Windows binary

`l2tunnel-windows-gui` (`apps/l2tunnel-windows/src/gui/main.rs`, a thin
`[[bin]]` with `required-features = ["gui"]` and an optional
`l2tunnel-desktop-ui` dependency, mirroring `apps/l2tunnel-linux`) calls the
same `main_entry`. In this crate only the cfg gates changed
(`any(unix, windows)`); the model and its tests are unchanged. `--socket`
takes the service pipe name, for example `\\.\pipe\l2tunnel`, and the
shared client opens it with the access mask and pipe-owner check described in
[Windows local service](windows-local-service.md). The binary uses the
Windows GUI subsystem (no console window). Status: cross-compiled only. It has
not run on Windows (WLS-07), and the worker test that binds a Unix socket is
Unix-only.

## GUI design and current layout

### Shared frame

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ● Connected · demo-client · client · UDP / quic-like · swift · ARQ       │
│ Service: /run/l2tunnel-1000/api.sock  [Change service…]                  │
├─────────────┬────────────────────────────────────────────────────────────┤
│ Overview    │                                                            │
│ Connection  │                  selected page                             │
│ Devices     │                                                            │
│ Routes      │                                                            │
│ SOCKS5      │                                                            │
│ Statistics  │                                                            │
│ Management  │                                                            │
│ Events      │                                                            │
├─────────────┴────────────────────────────────────────────────────────────┤
│ operation 7 (common_switch): completed, committed (epoch 7)              │
└──────────────────────────────────────────────────────────────────────────┘
```

- The top bar shows phase, active profile, role, the **requested versus
  effective** carrier/UDP cover, and the active protocol badge, with the
  service socket selector behind `"Change service…"`.
- The service reports its role and capabilities. Pages the service cannot
  serve are shown disabled with the service's reason (for example "SOCKS5
  needs the tcp-proxy profile", "server role only"), never hidden silently.
- Every state-changing action is a version-5 operation: it returns an
  operation ID at once, shows progress in the status line, can be reattached
  after a GUI restart, and is cancellable while the service allows it.
  Conflicting controls are disabled while an operation runs (CL-20).
- Lists are paged under the 32 KiB reply bound.

### Overview

Shows connection state, generation, epoch, peer, carrier, uptime, quick
connect/disconnect/profile selector, recent throughput, and recent events.

### Connection (protocol, live tuning, speed budget, and tunnel tests)

Three-card layout:

1. **Status summary card**: phase, profile, uptime, epoch, peer address,
   effective carrier, active protocol descriptor, and current upload/download
   plan speed budget.
2. **Protocol & Live tuning card**:
   - **Live tuning**: FEC toggle, repair-rate picker, and inner device MTU /
     outer path MTU pickers resolved by `tuning_get` / `tuning_switch` across
     Swift, Aligned, and Packed catalog entries.
   - **Speed budget**: Upload and Download Mbit/s inputs (`1..=10000 Mbit/s`)
     plus quick presets (symmetric 50 / 100 / 250 / 500 Mb/s / 1 Gb/s and
     asymmetric presets), applied live on both peers via `rate_budget_set`.
   - **Protocol catalog**: human-readable entries from the negotiated session
     catalog (up to 64 members) with hot switch (`switch_common_configuration`)
     and collapsible session details.
3. **Test the tunnel card**: in-process TCP speed test (Upload/Download,
   streams, duration) and ICMP ping test (probes, interval) with live metric
   tiles (Average, Last 1 s, Peak, Transferred), progress bar, and throughput
   chart ([tunnel tests](tunnel-tests.md)).

- Switching within the negotiated catalog is a hot switch
  (`switch_common_configuration`): negotiated epoch, matching digests, drain
  barrier, and the explicit point after which cancelling is unsafe (CL-20).
- Live make-before-break UDP carrier/cover switching (`carrier_switch_get`,
  `carrier_switch`, `ProfileTag::CarrierSwitchV1`) migrates UDP cover
  (`quic-like`, `media-like`, `tls-like`) onto a fresh verified standby UDP
  socket pair without dropping the session or inner flows; cross-protocol
  `tcp`/`quic` choices are shown disabled with their explicit reason (requiring
  TLS credentials and a listener via profile reconnect). Switching to another
  profile outside the catalog remains a reconnect with stated consequences
  (session replaced, inner flows dropped).

### Devices

```
 name       layer  MTU   up   addresses        owner
 fake-eth0  —      1500  yes  192.0.2.10/24    preexisting   not removable
 l2t0       TUN    1400  yes  10.88.0.2/24     service       [Configure] [Delete]
 New device: name [ ]  (TUN | TAP)  MTU [1400]  addresses [ ]  [x] bring up  [Create]
```

- Create/configure/delete are keyed operations that run in the service
  (`device` action). The service creates persistent TUN/TAP devices and
  records them in `<state-dir>/host-state.json`; only recorded devices can
  be configured or deleted. Preexisting devices are listed and never changed
  (CL-22, CL-23). Delete needs a second click to confirm.
- A failed create removes the partly created device and its record.
- The list shows TUN/TAP devices plus every device the service owns.

### Routes

```
 destination      gateway    device     metric  owner
 0.0.0.0/0        192.0.2.1  eth0       100     preexisting
 198.51.100.7/32  192.0.2.1  eth0       —       service (peer exception)
 0.0.0.0/1        —          l2t0       —       service (all traffic)
 128.0.0.0/1      —          l2t0       —       service (all traffic)
 10.20.0.0/16     —          l2t0       5       service              [Remove]
 Send all traffic through the tunnel: [l2t0 v] [Send all traffic | Stop sending all traffic]
 Add route: destination [ ]  device [l2t0 v]  gateway [ ]  metric [ ]  [Add]
```

- Routes belong to the running session: route changes are refused with
  `state` unless the session is connected, and the service removes every
  route it added when the session ends (disconnect, reconnect, failure). On
  start it also removes routes a crashed run left in its record.
- "Send all traffic" never replaces an existing route. It adds the two
  half-default routes (`0.0.0.0/1`, `128.0.0.0/1`, or `::/1`, `8000::/1`)
  through the tunnel device, which win over any `/0` by prefix length, plus
  a host route keeping the peer's outer address on the route it uses now,
  so the carrier cannot route into itself. If any step fails, the routes
  this request added are removed again.
- Only service-owned routes are removable; existing routes are never changed.

### SOCKS5

```
 Status     listening 127.0.0.1:1080        needs: tcp-proxy profile ✓
 Listen     [127.0.0.1] : [1080]   Auth (none | username/password)
 Clients    allowed [127.0.0.1/32]                       [Apply]
 Active flows (inner flows, not lanes or channels)
   #41  127.0.0.1:53122 → example.org:443   ↑ 3.1 MB  ↓ 41 MB  open
```

- Listening defaults to loopback only; a wider listen address requires an
  explicit allowed-client list.
- Each SOCKS5 CONNECT becomes one TCP-proxy flow with remote-open admission
  by the server; the server's egress policy can refuse it, and the refusal
  is shown on the flow.

### Statistics

- Window selector (`60 s` / `10 min`, 1 s samples) with four rolling charts:
  sent on the network, packets received from the network, packets into the
  tunnel, and packets out of the tunnel.
- Separate tables for **Carrier lanes**, **MUX channels**, **Inner flows**, and
  **Device** counters (keeping the three domains separate per `AGENTS.md`).
  Rates are derived from cumulative counters and the service's monotonic
  timestamp; a counter reset (new service instance or session generation)
  starts a new series instead of producing a negative rate.
- Collapsible **CSR meters (flow control, runtime, MUX)** panel with
  Local / Remote peer toggle, prefix filter, manual `Read`, optional
  `Auto (2 s)` refresh, rate deltas, and log2 wait-latency p50/p99
  percentiles ([meter CSR](meter-csr.md)).

### Management

Four sections (the server role adds **Peers and sessions**):

- **Profiles**: service-owned cards with carrier-aware 5-group editor
  (Connection, Security & keys, Tunnel device, Protocol, Live tuning; plus
  "Other options") distinguishing blocking save errors from non-blocking
  warnings. Import/export never copies private key material; exports carry
  credential references (CL-24). A profile edit never silently rewrites an
  unknown newer profile version (CL-19).
- **Keys**: local generation of member identity, Noise pair, and 32-byte
  secret files, plus service-side key inspection (`profile_keys`).
- **Service**: version, role, API level, instance ID, uptime, and confirmed
  `Stop service` (offline pages offer `Start service…`).
- **Peers and sessions (server role)**: lists at most the one live
  point-to-point session (resampled every second while open), with confirmed
  `Kick session` and `Revoke member` actions.

### Events

The complete bounded log with filters (operation, lifecycle, device, route,
SOCKS5, session) and a redacted diagnostic export (CL-16).

## CLI parity and planned API

Every GUI action has the same CLI command and version-5 action. Reads are
queries; everything that changes state is a keyed operation.

| GUI | `l2tunnelctl` | v5 action | State |
| --- | --- | --- | --- |
| Top bar, Overview | `service status`, `service info` | `status`, `service_info` (role, capabilities with reasons) | implemented |
| Connect / Reconnect / Disconnect / Cancel | `service connect\|reconnect\|disconnect`, `operation cancel` | existing | implemented |
| Connection: catalog, hot switch | `config catalog`, `config switch` | `catalog`, `switch_common_configuration` | implemented |
| Connection: live carrier / UDP cover switch | `carrier show`, `carrier switch --target quic-like\|media-like\|tls-like` | `carrier_switch_get`, `carrier_switch` | implemented (UDP Common make-before-break standby socket + cover migration over `ProfileTag::CarrierSwitchV1`; `tcp`/`quic` shown disabled with explicit TLS-credential reason) |
| Connection: live FEC/MTU tuning | `tune show`, `tune set` | `tuning_get`, `tuning_switch` | implemented (Swift, Aligned, Packed) |
| Connection: live speed budget | `tune budget --symmetric MBPS \| --upload MBPS --download MBPS` | `rate_budget_set` | implemented (Common sessions, 1 Mbit/s..=10 Gbit/s; warns when kernel clamps `SO_RCVBUF`/`SO_SNDBUF`) |
| Connection: tunnel speed & ping tests | `test speed\|ping\|status\|cancel` | `test_start`, `test_get`, `test_cancel` | implemented (Common TUN sessions) |
| Connect with profile | `service connect\|reconnect --profile NAME` | keyed `profile_connect{name, replace}` | implemented (daemon, including TCP-proxy profiles) |
| Devices | `device list\|create\|configure\|delete` | `device_list`; keyed `device{change}` (`op`: `create`, `configure`, `delete`) | implemented and CAP_NET_ADMIN private-namespace tested on Linux (`--state-dir`) |
| Routes | `route list\|add\|remove`, `route default on\|off` | `route_list`; keyed `route{change}` (`op`: `add`, `remove`, `default`) | implemented and CAP_NET_ADMIN private-namespace tested on Linux (`--state-dir`) |
| SOCKS5 | `socks show\|set\|flows` | `socks_get`, `socks_set`, `socks_flows` | implemented (client TCP-proxy sessions; RFC 1928/1929 listener, CIDR allowlist, bounded live flow table) |
| Statistics | `stats show`, `stats watch` | `metrics` | implemented (counters the runtime does not report are listed as `unreported`) |
| CSR meters | `meters read\|catalog\|watch` | `meters_read`, `meters_catalog` | implemented (local + Common remote over `Liveness`, GUI wait-latency p50/p99 percentiles; MCSR-04..07 runtime families open) |
| Profiles | `profile list\|show\|validate\|export\|import\|delete\|default` | `profile_list`, `profile_get`, `profile_validate`; keyed `profile{change}` | implemented (daemon, Linux); GUI editor edits options as rows |
| Keys | `key generate` (member), `key generate-noise`, `key generate-secret` (local); `profile keys NAME` | `profile_keys` | implemented; rotation/revocation are file edits plus a profile save (owner decision: files only) |
| Service | `service info`, `service stop` | `service_info`, keyed `service_stop` | implemented; stop only in the daemon (capability `stop`): disconnect, release session routes, exit |
| Start service (offline panel) | `service start [--program PATH] [--wait S] [--install ...]` | none: `local::elevate` runs the administrator prompt, then waits on `status` | implemented; Linux installer and unit verified unprivileged only, Windows cross-checked only |
| Peers and sessions | `session list\|kick`, `member revoke --allow-key FILE` | `session_list`, keyed `session_kick`; revoke = keyed `profile` save + keyed `profile_connect` (replace) | implemented (server role; revoke needs a session from a stored profile) |
| Events, export | `events`, `diagnostics export --output FILE [--include-addresses]` | `events`; the export is assembled client-side from read-only queries (no new action) | implemented |

Work outside this frontend (owned by the protocol-core session): native
integration of the TCP-proxy session dispatcher for SOCKS5 and runtime
counters for `metrics`. Several members per server, or kicking one member
while the listener keeps running, would need a runtime session table; the
owner chose the point-to-point mapping instead.

## Tasks

- [x] [DGUI-01] Drive status, connect/reconnect, disconnect, cancel and live events over version 5 with bounded replies and restart resynchronization. Evidence: [model](../../crates/l2tunnel-desktop-ui/src/model.rs), [model tests](../../crates/l2tunnel-desktop-ui/src/model_tests.rs), [worker and real-endpoint test](../../crates/l2tunnel-desktop-ui/src/worker.rs).
- [x] [DGUI-02] Provide a fake version-5 service accepted by the strict Rust client for GUI/CLI development. Evidence: [fake service](../../tools/fake_local_service.py), [CLI tests against it](../../tools/test_fake_local_service.py).
- [x] [DGUI-03] Run the GUI against the real loopback daemon pair (`tools/local_real_pair.py`) and record connect, disconnect, reconnect and the real backend rows. Evidence: [GUI worker real-endpoint test](../../crates/l2tunnel-desktop-ui/src/worker.rs) (`cargo test --locked -p l2tunnel-desktop-ui`: 33 passed) and isolated-namespace real-TUN `l2tunneld` + `l2tunnelctl` receipt `work/quick-close-20261125/receipt.json` (connect, `stats show`, remote CSR meters, `service disconnect` stopping TUN ping, `service reconnect` restoring TUN ping at `3.24 ms`).
- [x] [DGUI-04] Shared frame: sidebar pages, top bar with requested/effective carrier, role and capability discovery, disabled pages with reasons. Evidence: [desktop window](../../crates/l2tunnel-desktop-ui/src/app.rs), [sidebar pages](../../crates/l2tunnel-desktop-ui/src/pages.rs), [Linux GUI binary](../../apps/l2tunnel-linux/src/gui/main.rs), [service capabilities](../../crates/l2tunnel-client-core/src/service/info_local.rs), and `cargo test --locked -p l2tunnel-desktop-ui` (35 passed); native Windows execution remains tracked under WLS-07.
- [x] [DGUI-05] Connection page: profile selection, catalog hot switch with progress, reconnect with stated consequences. Evidence: [Connection page](../../crates/l2tunnel-desktop-ui/src/pages.rs), [live tuning panel](../../crates/l2tunnel-desktop-ui/src/tuning_panel.rs), [tunnel test panel](../../crates/l2tunnel-desktop-ui/src/test_panel.rs), [model switch tests](../../crates/l2tunnel-desktop-ui/src/model_tests.rs), and real-TUN session receipt `work/quick-close-20261125/receipt.json`; live in-session carrier switching remains tracked under DGUI-14 and native Windows under WLS-07.
- [x] [DGUI-06] Devices: service-owned TUN/TAP create/configure/delete, preexisting devices selectable only; GUI and CLI. Evidence: [host operations](../../crates/l2tunnel-client-core/src/service/host.rs), [Linux host](../../crates/l2tunnel-client-core/src/service/host_linux.rs), [netlink](../../crates/l2tunnel-platform-linux/src/netconf.rs), [CLI](../../crates/l2tunnel-client-core/src/cli_groups_host.rs), [GUI page](../../crates/l2tunnel-desktop-ui/src/pages.rs), [fake-service CLI test](../../tools/test_fake_local_service.py), and passed CAP_NET_ADMIN private-namespace netlink test `service::host_linux::tests::owned_devices_and_session_routes_in_a_private_namespace` (`sudo unshare -n`, 1 passed).
- [x] [DGUI-07] Routes: owned route add/remove, default route with peer exception, undo on disconnect/failure; GUI and CLI. Evidence: [host operations](../../crates/l2tunnel-client-core/src/service/host.rs), [Linux host](../../crates/l2tunnel-client-core/src/service/host_linux.rs), [netlink](../../crates/l2tunnel-platform-linux/src/netconf.rs), [CLI](../../crates/l2tunnel-client-core/src/cli_groups_host.rs), [GUI page](../../crates/l2tunnel-desktop-ui/src/pages.rs), [fake-service CLI test](../../tools/test_fake_local_service.py), and passed CAP_NET_ADMIN private-namespace netlink test `service::host_linux::tests::owned_devices_and_session_routes_in_a_private_namespace` (`sudo unshare -n`, 1 passed).
- [x] [DGUI-08] SOCKS5 entry over the TCP-proxy profile: settings, allowed clients, flow list; GUI and CLI. Evidence: [local SOCKS5 DTOs](../../crates/l2tunnel-client-core/src/local/socks.rs), [service RFC 1928/1929 SOCKS5 engine](../../crates/l2tunnel-client-core/src/service/socks_local.rs), [Common TCP-proxy + SOCKS5 end-to-end test](../../crates/l2tunnel-client-core/src/service/tests/proxy_common.rs) (`common_proxy_client_enables_socks5_and_tears_down_on_disconnect`), [CLI](../../crates/l2tunnel-client-core/src/cli_groups_socks.rs), [GUI SOCKS5 page](../../crates/l2tunnel-desktop-ui/src/socks_panel.rs), [GUI model test](../../crates/l2tunnel-desktop-ui/src/model_tests.rs) (`socks5_settings_and_flows_flow`), and [fake-service CLI test](../../tools/test_fake_local_service.py) (`test_simulated_socks5_settings_and_flows`).
- [x] [DGUI-09] Statistics: `metrics` snapshot, separate lane/channel/flow tables, bounded client history and charts; GUI and CLI. Evidence: [service metrics view](../../crates/l2tunnel-client-core/src/service/metrics_local.rs), [CLI stats](../../crates/l2tunnel-client-core/src/cli_groups_stats.rs), [bounded client history](../../crates/l2tunnel-desktop-ui/src/stats.rs), and [GUI Statistics & CSR meters panel](../../crates/l2tunnel-desktop-ui/src/pages.rs) (`wait_percentiles_computes_p50_and_p99_from_csr_histograms`, `stats::tests::*`, and live TUN receipt `work/quick-close-20261125/receipt.json`); per-channel/flow runtime CSR population remains tracked under MCSR-07.
- [x] [DGUI-10] Management: service-owned profiles, keys and trusted peers, service info/stop; GUI and CLI. Evidence: [profile store](../../crates/l2tunnel-client-core/src/service/profile_store.rs), [keyed profile operations](../../crates/l2tunnel-client-core/src/service/profiles.rs), [daemon hosting Common and TCP-proxy profiles](../../crates/l2tunnel-client-core/src/cli_daemon.rs), [local key generation and service inspection](../../crates/l2tunnel-client-core/src/local/keys.rs), [CLI](../../crates/l2tunnel-client-core/src/cli_groups_profile.rs), [GUI](../../crates/l2tunnel-desktop-ui/src/profiles.rs), [service stop owner](../../crates/l2tunnel-client-core/src/service/owner.rs), and [real-daemon tests](../../tools/test_profile_daemon.py) (`test_stored_profiles_round_trip_and_connect` and `test_tcp_proxy_profile_reaches_proxy_plan_validation_in_daemon`).
- [ ] [DGUI-13] Elevated service start through an installer (owner decisions 2026-11-24); GUI and CLI. Status: implemented and contract-tested ([shared start and unit](../../crates/l2tunnel-client-core/src/local/elevate.rs), [Linux installer](../../crates/l2tunnel-client-core/src/cli_system_service.rs), [CLI](../../crates/l2tunnel-client-core/src/cli_groups_start.rs), [GUI panel](../../crates/l2tunnel-desktop-ui/src/start.rs), [Windows service start](../../apps/l2tunnel-windows/src/service.rs), [fake-pkexec test](../../tools/test_service_start.py)). Open: a real pkexec install and start on Linux (root), and UAC on native Windows.
- [x] [DGUI-11] Server role: session list, kick and member revoke; GUI and CLI. Evidence: [service](../../crates/l2tunnel-client-core/src/service/sessions_local.rs), [admission test](../../crates/l2tunnel-client-core/src/service/tests/atomic_local.rs), [shared revoke](../../crates/l2tunnel-client-core/src/local/client.rs), [CLI](../../crates/l2tunnel-client-core/src/cli_groups_sessions.rs), [GUI](../../crates/l2tunnel-desktop-ui/src/pages.rs), [fake-service CLI test](../../tools/test_fake_local_service.py), [real-daemon server checks](../../tools/test_profile_daemon.py), and isolated-namespace real-TUN authenticated pair receipt `work/quick-close-20261125/receipt.json` (`session list` 1 live session, `session kick --detach` drops & allows reconnect, `member revoke --allow-key` rotates `--allow-key` and blocks old member reconnect).
- [x] [DGUI-12] Events page with filters and redacted diagnostic export. Evidence: [shared export](../../crates/l2tunnel-client-core/src/local/diagnostics.rs) (address redaction, new 0600 files only), [CLI](../../crates/l2tunnel-client-core/src/cli_groups.rs), [GUI model test](../../crates/l2tunnel-desktop-ui/src/model_tests.rs), [CLI test against the fake service](../../tools/test_fake_local_service.py).
- [x] [DGUI-14] Connection page: live protocol and carrier switching without editing the profile (owner request 2026-11-24). Evidence: protocol catalog hot switch ([Connection page](../../crates/l2tunnel-desktop-ui/src/pages.rs), [readable names](../../crates/l2tunnel-client-core/src/local/describe.rs), [plan merger](../../tools/merge_common_plans.py), [merger tests](../../tools/test_merge_common_plans.py)); authenticated in-band make-before-break UDP carrier/cover switching (`ProfileTag::CarrierSwitchV1`, [session control](../../crates/l2tunnel-management/src/session_control.rs), [control gate](../../crates/l2tunnel-management/src/control_streams/gate.rs), [runtime state machine](../../crates/l2tunnel-runtime/src/secure_udp/transport_carrier_switch.rs), [local API DTOs](../../crates/l2tunnel-client-core/src/local/carrier.rs), [service view](../../crates/l2tunnel-client-core/src/service/carrier_local.rs), [CLI `l2tunnelctl carrier show|switch`](../../crates/l2tunnel-client-core/src/cli_groups_carrier.rs), [end-to-end two-peer test](../../crates/l2tunnel-client-core/src/service/tests/secure_udp_transaction.rs) `live_carrier_switch_migrates_udp_socket_and_cover_without_dropping_session`, [GUI model test](../../crates/l2tunnel-desktop-ui/src/model_tests.rs) `live_carrier_switch_updates_view_and_refreshes_status`, [fake-service CLI test](../../tools/test_fake_local_service.py) `test_simulated_live_carrier_switch`, and isolated-namespace real-TUN receipt `work/carrier-switch-20261125/receipt.json` showing 3 live switches `quic-like -> media-like -> tls-like -> quic-like` in 120–196 ms on the same generation with `30/30` ICMP packets and `0%` loss). Cross-protocol UDP<->TCP/TLS/QUIC migration requires TLS credentials (`--cert/--key/--ca`) and a separate listener and is explicitly reported as unavailable with that reason.

## Development services

- `tools/fake_local_service.py` is a FAKE version-5 service: it simulates the
  real setup stage names, connect/reconnect/disconnect, cancellation and an
  optional setup failure (`--fail-connect`), a profile store, simulated
  devices and routes, and the server role with one session (`--server`).
  Nothing is authenticated or
  forwarded, and the carrier rows stay empty against it.
- `tools/local_real_pair.py` prepares and runs the REAL `l2tunneld` server and
  client on 127.0.0.1 UDP (auto-selecting the release build when present, with
  `--symmetric-rate` defaulting to 125,000,000 B/s = 1 Gbit/s, 10 s ping
  interval, and `--replace` to swap a running server cleanly). Each side needs
  a persistent user-owned TUN device created once with root (`sudo ip tuntap
  add dev l2tdemo-a mode tun user $USER`, likewise `-b`).
  On loopback the devices stay down and nothing is forwarded. `prepare
  --forwarding` instead puts the server's carrier on a veth pair to the owned
  namespace `l2tdemo`, which also holds `l2tdemo-b`; the TUN ends get
  10.231.255.1/30 and 10.231.255.2/30, so host traffic to 10.231.255.2 really
  crosses the tunnel. `local_real_pair.py network` prints the root commands
  that build and remove that layout (it never runs them), and `run --side b`
  prints the namespaced command for the server.

Local PyCharm run configurations (untracked `.idea/`) build the binaries and
start the fake demo, the real pair and `l2tunnel-linux-gui` against either.

## Usability review (2026-11-24)

The owner found the GUI hard to use and configure. A screenshot review of
every page against the real installed service and demo server found, and
this change fixed (owner: "go ahead in that order"):

1. Sessions ended after exactly 120 s with TimedOut. Cause, from the
   protocol-core session: benchmark plans set a 120 s logical-session lease
   that nothing renews. `tools/local_real_pair.py prepare` now writes a
   one-hour lease (as in `secure-udp-service.md`). Open on the protocol side
   (owner's call): renewal or reconnect at lease end, and a distinct "lease
   expired" reason instead of a generic TimedOut.
2. The window opened "not attached" although the per-user service was
   running. It now attaches to this user's socket by default and offers
   Start service when nothing answers; the socket moved behind
   "Change service…".
3. The profile editor showed raw flags in boxes about 40 px wide. It is now a
   window with labeled fields grouped as Connection, Security and keys,
   Tunnel device and Protocol (role-aware labels;
   [field table](../../crates/l2tunnel-desktop-ui/src/profile_fields.rs)), dropdowns for
   fixed values, a built-in file chooser with a found/missing mark, and the
   list of what to fix next to Save. Options without a field stay editable
   under "Other options". The service still decides whether a plan runs.
4. Failures were unexplained ("failed (failed (timed_out))", stale notices).
   [Plain-language headline](../../crates/l2tunnel-desktop-ui/src/present.rs)
   with the reason and next step, a Reconnect button, notices that expire
   after 20 s.
5. A connect card on Overview and Connection: choose a profile and Connect,
   follow setup with Cancel, Disconnect or switch to another profile; the
   running profile and uptime show in the top bar (new optional status
   fields `profile`, `connected_ms`).
6. Devices and Routes lead with tunnel devices and l2tunnel's own routes
   (with which profile uses a device); other interfaces and system routes
   are collapsed. "Send all traffic" offers only tunnel devices, preselects
   the running profile's device (it had defaulted to another VPN's device),
   and a warning says when that device is down or has no address.
7. Plain words on Overview and Statistics (details collapsed; idle charts
   show zero instead of "collecting samples"); the SOCKS5 page no longer
   points to a command that does not exist.
8. Layout: profiles as wrapping cards, key values shortened with hover and
   click-to-copy, events newest first, a larger default window.

## Connection page switching (2026-11-24)

Owner: "I want a quic profile hot switch panel without editing profile.
Connection panel should provide some configuration like changing protocol /
changing carrier". Asked how a carrier change should work (reconnect with
a temporary override, live carrier switch, or carrier stays in the
profile), the owner chose a live carrier switch as protocol work.

- Protocol: the page lists the running plan's catalog in words (for example
  "aligned · ARQ + FEC (2 repair per group) · MTU 1500 · full"), marks the
  one in use, and "Switch protocol" submits the keyed hot switch. Catalogs of
  up to 32 members load as one list; the list reloads when the generation or
  catalog root changes.
- Carrier: the summary card shows the effective carrier in use; live carrier
  switching remains planned protocol work (the earlier placeholder disabled
  carrier-switch widget was removed when the Connection page moved to the
  three-card layout).
- Limitation: a hot switch can only choose a member of the shared plan's
  catalog. Plans exported for benchmarks have one member. For the local
  demo pair, six UDP rows (swift/aligned/packed, each ARQ and FEC) with an
  identical runtime were merged by hand into one plan outside the repository.

Executed (local Linux): `cargo test -p l2tunnel-desktop-ui` 22 passed
(catalog merge and staleness); client-core lib 251 passed, 1 ignored; Clippy
(`--no-deps`), rustdoc and the Windows check clean. Real run on the demo
pair (installed per-user service as client, standalone server, loopback,
TUN devices down so no user traffic): the merged plan connected with 6
catalog members; three switches from the GUI committed in the same session
(generation 6, epochs 2, 3 and 4: aligned ARQ+FEC, packed ARQ+FEC, swift
ARQ) without a reconnect.

## Device list and demo forwarding fixes (2026-11-24, local Linux)

Owner report: a device created from the Devices page appeared under "Other
TUN/TAP interfaces" as down with no address, and the demo TUNs were down.

- Cause in the GUI: reads were coalesced by kind, so the refresh that a
  completed change triggers was dropped while an earlier read of the same
  list was in flight, and that earlier reply (taken mid-change, before the
  service recorded the device as its own) stayed on screen. Reads asked for
  during an in-flight read of the same list are now sent again when it
  answers (devices, routes, profiles, sessions, info, profile, keys,
  checks; not periodic metrics or test polls). Test
  `a_refresh_asked_during_the_same_read_is_sent_when_it_answers`.
- The service side was correct: `l2tunnelctl device create l2tcheck --layer
  tun --mtu 1400 --addresses 10.231.0.2/24` listed it as service-owned, up,
  addressed, and recorded in `host-state.json`; it was deleted again.
- Demo forwarding: the layout above was built by hand on this host (sudo, owned
  namespace and veth only), the server ran in the namespace as the user, and
  the client service reconnected (generation 23). `ping 10.231.255.2`: 5/5,
  6.7-9.7 ms. A 5 s kernel TCP stream to 10.231.255.2:5201 inside the
  namespace: 20.4 MB, 28.4 Mbit/s (swift ARQ, debug build; a one-off local
  observation, not a performance result). `tools/test_local_real_pair.py`
  covers the address rewrite and that the printed commands only create owned
  objects.

## Executed checks (2026-11-24, local Linux)

Usability slice:

- `cargo test -p l2tunnel-desktop-ui`: 21 passed (presentation wording,
  field table and fix-before-save problems, editor split/merge, file
  chooser listing). `cargo test -p l2tunnel-client-core --lib`: 251 passed,
  1 ignored. Clippy (`--no-deps`, all targets) clean; rustdoc clean; Windows
  `cargo check` passes.
- Fake-service CLI tests passed; `tools.test_service_start` passed (its
  prompt-contract cases skip while a real per-user service runs).
  `tools.test_profile_daemon` was NOT rerun: it binds UDP 127.0.0.1:24441,
  which the running demo server holds (its server failed to listen for that
  reason); rerun once the demo pair is stopped.
- Real run: the installed service was reinstalled from this build through
  `system-service install` and reports `profile demo-client` and
  `connected_ms`. A session with the one-hour lease stayed connected past
  9 minutes. Under Xvfb, without `--socket`, the GUI attached by itself;
  every page, the editor and the file chooser were captured; Disconnect from
  the top bar and Connect from the Overview card completed against the real
  demo server.

## Executed checks (2026-11-24, local Linux, earlier)

Elevated start slice (nothing installed, started or run as root):

- `cargo test -p l2tunnel-client-core --lib elevate` and `cli` filters: request
  checks before any prompt, Windows argument encoding round trip (spaces,
  quotes, empty arguments), the unit grants only CAP_NET_ADMIN to the user and
  has no `[Install]` section, `service start` parsing.
- `cargo test -p l2tunnel-desktop-ui`: 16 passed (start form to request, one
  start at a time, attach to the started socket, dismissed notice).
- `cargo test -p l2tunnel-windows`: 19 passed (`service start`,
  `service install-start ENCODED`, refusals).
- `python3 -m unittest tools.test_service_start`: 3 passed against a FAKE
  pkexec: the prompt runs exactly `PROGRAM system-service install --uid UID`
  (or the installed program with `start`), 126 → dismissed, 127 → refused,
  installer output and exit code shown, no service → exit 4, Windows host
  options refused before any prompt, the root-only installer refuses to run
  unprivileged.
- `systemd-analyze verify` on the generated `l2tunnel-1000.service`: only
  complaint is the not-yet-installed program path.
- GUI under Xvfb with the fake pkexec: the offline panel shows on every page,
  Start service ran the installer command above and showed "Service not
  started: the administrator prompt was dismissed".
- Clippy (`--no-deps`, Linux, all targets) clean; `cargo check --target
  x86_64-pc-windows-gnu` for client-core, l2tunnelctl and l2tunnel-windows
  (`gui`) passes.

## Executed checks (2026-11-23, local Linux)

Service stop and server sessions slice:

- `cargo test -p l2tunnel-client-core --lib --locked`: 247 passed,
  1 ignored. New: session list/kick admission with an installed server
  generation (client plans refused as `unsupported`, a server with no live
  generation refused as `state`, the kick queued as a reconnect with the
  identical retained plan, exact replay, conflict with another action on the
  key, `busy` while it runs, cancellable).
- `.venv/bin/python -W error::ResourceWarning -m unittest
  tools.test_profile_daemon`: 1 passed. Additions on the real daemon: a
  server profile connect listens (`authenticating` with a listening
  address), role `server` with the `sessions` capability, an empty session
  list, kick refused with `state`, revoke refused with no live session, the
  pending profile connect cancelled (`cancelled`), then `service stop`:
  `service stopped`, daemon exit status 0 and empty stderr.
- `.venv/bin/python -m unittest tools.test_fake_local_service`: 5 passed,
  including the simulated server role through the real `l2tunnelctl`:
  list, kick (new generation, same member), revoke with a relative path
  refused as usage, revoke saving revision 2 and replacing the session.
- `cargo test -p l2tunnel-desktop-ui --locked`: 14 passed (the opened
  session list is resampled with metrics, one query in flight).
- GUI against the fake server under Xvfb, driven with XTest: Kick →
  Confirm gave generation 3; typing a new member key and Revoke → Confirm
  saved revision 2 with the new `--allow-key` and replaced the session
  (generation 5, new trusted member), confirmed afterwards with
  `l2tunnelctl profile show` and `session list`.
- Fixed on the way: `operation_cancel` refused profile connects (and would
  have refused kicks) as `cancel_unsupported`, because it only accepted the
  plain connect/reconnect fingerprints.
- Clippy `--no-deps -D warnings --all-features` on client-core, desktop-ui,
  l2tunnel-linux, l2tunneld, l2tunnelctl: clean. Windows `cargo check` of
  l2tunnel-windows (gui): passes. Rustdoc `-D warnings`: clean.

Profiles slice:

- `.venv/bin/python -m unittest tools.test_profile_daemon`: 1 passed. The
  real `l2tunneld daemon` with plans and credentials from
  `local_real_pair.py prepare`: import of client and server profiles,
  validation building real plans, refused stale revision and unrunnable
  document (unreadable Noise key), export equal to the imported document
  (0600, never overwritten), default profile, a profile connect that fails
  admission with no peer while the service stays reachable and retains the
  plan, `invalid_profile` for a missing profile, restart with the default
  profile connected on start, delete. No device or network state changed.
- `cargo test -p l2tunnel-client-core --locked`: 245 lib tests passed
  (1 ignored: the privileged netns test) and 7 integration tests passed.
  New: in-memory store keyed operations (replay, conflict, unrunnable
  profile connect keeps the key and never re-prepares on replay), file
  store revisions, default handling and newer-version preservation,
  strict documents and names.
- `cargo test -p l2tunnel-desktop-ui --locked`: 13 passed (editor documents
  checked like the service). Xvfb screenshots of Management (profile table)
  and Connection (profile picker) against the real daemon; the editor was
  not clicked through (no input automation on this host).
- Clippy `--no-deps -D warnings --all-features` on client-core, desktop-ui,
  l2tunnel-linux, l2tunneld, l2tunnelctl: clean. Windows `cargo check` of
  client-core, desktop-ui and l2tunnel-windows (gui): passes.
- Fixed on the way: `--state-dir` was refused by the `connect`/`serve`
  option check; both now share one `run_options` list.

Diagnostic export: `cargo test -p l2tunnel-client-core --lib --locked --
diagnostics` (redaction of every address-valued string, refusal to overwrite,
mode 0600), the desktop-ui model test (single flight, result notice) and
`tools.test_fake_local_service` (4 passed: a redacted export through the real
`l2tunnelctl`, refused overwrite, `--include-addresses`). The report holds
status, service info, metrics, devices, routes, up to 256 retained events and
the results of up to 16 recent completed operations; it carries no keys or
payload because no version-5 reply does.

Devices and routes slice:

- `cargo test -p l2tunnel-client-core --lib --locked`: 240 passed, 1 ignored
  (the fake-host keyed-operation test: unavailable without a host, invalid
  change keeps the key, exact replay, conflict, host refusal, routes refused
  while disconnected, phase unchanged; strict CLI parsing; strict ownership
  record and state-directory checks). The ignored test is the real netlink
  run, to be executed only as `sudo unshare -n <test binary> --ignored
  --exact service::host_linux::tests::owned_devices_and_session_routes_in_a_private_namespace`;
  it refuses to run where any interface other than `lo` is visible. It was
  not run: unprivileged user namespaces are blocked on this host.
- `cargo test -p l2tunnel-desktop-ui -p l2tunnel-platform-linux --locked`:
  11 and 4 passed (form validation matches the CLI; prefix arithmetic).
- `.venv/bin/python -m unittest tools.test_fake_local_service`: 3 passed,
  including simulated devices and session routes through the real
  `l2tunnelctl` (create, refused delete of a preexisting device, routes
  refused while disconnected, default routing with the peer exception,
  routes released on disconnect).
- Clippy `--no-deps -D warnings` on client-core, desktop-ui and
  platform-linux: clean on Linux. Windows (`x86_64-pc-windows-gnu`):
  `cargo check` of client-core, desktop-ui and l2tunnel-windows passes;
  Clippy reports dead-code warnings for Unix-only proxy/maintained paths
  that this slice did not touch.
- Xvfb screenshots of the Devices and Routes pages against the fake service.

First slice:

- `cargo test -p l2tunnel-desktop-ui --locked`: 5 tests passed
  (4 model tests; the worker driving the model against a real
  `Server::serve_service` endpoint, including a refused reconnect and loss of
  the service).
- `cargo clippy -p l2tunnel-linux --no-deps --all-targets --all-features
  --locked -- -D warnings`: clean. `cargo tree` shows no egui/eframe/winit in
  the default `l2tunnel-linux` build.
- `.venv/bin/python -m unittest tools.test_fake_local_service`: 2 tests passed
  (the real `l2tunnelctl` against the fake service: progress, cancel, failure,
  refusal exit codes, restart detection).
- The egui window ran under Xvfb against the fake service; screenshots showed
  setup progress and the connected state from events submitted by a separate
  `l2tunnelctl`. The scripted lost-service screenshot did not apply: the
  background fake ignored SIGINT in the non-interactive script, so the service
  was never stopped. Loss of the service is covered by the worker test.
