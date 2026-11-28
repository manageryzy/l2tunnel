# Windows local service and named-pipe local API

Status: **implemented and cross-compiled only.** The code builds for
`x86_64-pc-windows-gnu`, its portable logic is unit-tested on Linux, and two
Windows test binaries were also run under Wine 9.0 on Linux (see
[executed checks](#executed-checks)). Nothing has run on native Windows yet:
there is no evidence from a native run, a service install, an ACL check
against a real logon or a Wintun device. CL-25 in
[client design](../client-design.md) stays open.

## Owner decisions this implements (2026-11-23)

1. An installed Windows service (`l2tunnel-windows`) holds the administrator
   rights needed for Wintun and routes, and serves local API v5 over a named
   pipe with an ACL. The GUI and the CLI run unprivileged.
2. The GUI is the shared `l2tunnel-desktop-ui` crate. `l2tunnel-windows-gui` is
   a thin `[[bin]]` in `apps/l2tunnel-windows` that needs the `gui` feature.
3. `l2tunnelctl` is the CLI on both platforms, with the same grouped commands
   and exit codes. On Windows `--control-socket` takes the pipe path.

Everything else below is a choice made in this change. Points that need the
owner are listed under [owner review](#awaiting-owner-review).

## Design

### One service owner (WLS-04)

The service process creates the shared service with
`service::channel_with_plan(profile.prepare(attachment))` and runs its
lifecycle `Run` in the same Tokio runtime as `local::Server::serve_service`.
It does not route requests through the former private `common-worker` child,
which used framed API4 on stdio.

The child is replaced rather than kept behind the service for three reasons:

- One process holds the only `Handle`/`Run`, so there is exactly one service
  owner and one record of request keys, operations and events.
- Version-5 operations (keyed submissions, `operation_get`/`wait`/`cancel`,
  `events`) reach the owner unchanged. The stdio channel accepted only API4
  `status`/`reconnect`/`disconnect`, so a relay would have had to fork or
  shrink the protocol.
- The service already runs with the rights Wintun needs, so a second
  privileged process and its IPC hop add nothing.

The `common-worker` subcommand is removed from `l2tunnel-windows`. The Wintun
attachment, profile loading and the joined blocking setup are kept as they
were. The portable `local::serve_private_common_stream` remains in
`l2tunnel-client-core`, but no binary uses it any more.

### Shared transport (WLS-02)

`crates/l2tunnel-client-core/src/local/transport.rs` contains one serve loop
for both platforms, with the same framing (4-byte big-endian length plus
strict JSON, requests up to 4096 bytes, replies up to 8192 or 32768), the
same decode/dispatch for versions 1, 4 and 5, the same 5 s read and write
deadlines, at most `CONCURRENT_CONNECTIONS` (8) served connections with
further connections closed unread, and the same client deadlines. Only these
parts differ by platform (`transport/unix.rs` and `transport/windows.rs`):

| Hook | Unix | Windows |
| --- | --- | --- |
| `Listener::bind` | private socket in an owned 0700 directory | first pipe instance (`FILE_FLAG_FIRST_PIPE_INSTANCE`), proposed DACL, `PIPE_REJECT_REMOTE_CLIENTS`, byte mode |
| `poll_accept` | `UnixListener::poll_accept` | waits on one listening instance; once a client connects, creates the next instance before returning, so a listening instance always exists; a failed connect on one instance is skipped |
| `authorize` | peer UID equals server UID | always true: the kernel already checked the DACL when the client opened the pipe |
| `connect` | socket connect plus server UID check | named-pipe open with `CLIENT_ACCESS`, identification-only QoS and the owner check; retries `ERROR_PIPE_BUSY` every 20 ms for up to 5 s, then reports `ConnectionRefused` (nothing was sent) |

At most `CONCURRENT_CONNECTIONS + 2` (10) pipe instances exist: 8 being
served, 1 listening, and 1 just connected that is being handed over or
refused.

On the client side, an invalid or remote pipe name, a missing pipe and a
failed owner check map to `NotFound` or `PermissionDenied`. As a result
`local::client::unsent` treats them as "nothing was sent", the same way the
CLI and GUI already treat them on Unix.

### Pipe name (WLS-01)

The default is `\\.\pipe\l2tunnel` (`local_pipe::DEFAULT_PIPE_NAME`). A name is
accepted only if it is exactly `\\.\pipe\` followed by 1 to 200 ASCII letters,
digits, `.`, `_` or `-`, and is not made of dots only. Both server and client
check this before any I/O. This rejects remote (`\\HOST\pipe\...`),
device-namespace and nested names, so a client cannot be steered into opening
an SMB pipe on another host.

The service uses the default unless it is installed with `--pipe`. The GUI
(`l2tunnel-windows-gui [--socket \\.\pipe\NAME]`) defaults to
`\\.\pipe\l2tunnel` (matching the per-user default on Linux); `l2tunnelctl`
takes `--control-socket` explicitly (or defaults to `\\.\pipe\l2tunnel` on
Windows).

### Pipe ACL: proposal awaiting owner confirmation (WLS-03)

This DACL is **the implementer's proposal, not an owner decision**:

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)
```

| Entry | Principal | Access |
| --- | --- | --- |
| `D:P` | n/a | Protected DACL: nothing is inherited |
| `(A;;GA;;;SY)` | LocalSystem (the installed service) | full |
| `(A;;GA;;;BA)` | BUILTIN\Administrators (elevated foreground testing, administration) | full |
| `(A;;0x12019b;;;IU)` | NT AUTHORITY\INTERACTIVE | `FILE_GENERIC_READ \| FILE_GENERIC_WRITE` without `FILE_APPEND_DATA` (= `FILE_CREATE_PIPE_INSTANCE`) |

No other principal gets access. That excludes network logons, Everyone,
Authenticated Users, anonymous callers and other services.
`PIPE_REJECT_REMOTE_CLIENTS` refuses remote clients separately.

Interactive users are not given `FILE_CREATE_PIPE_INSTANCE`. If they had it,
a nonprivileged user could add a competing server instance of the service's
pipe. Because `GENERIC_WRITE` maps to that bit, a client opened with
`GENERIC_WRITE` would be refused. Clients therefore request exactly
`CLIENT_ACCESS = FILE_GENERIC_READ | FILE_WRITE_DATA` (`0x12008b`), which is a
subset of the interactive grant and includes `READ_CONTROL` for the owner
check. The portable test
`proposed_dacl_is_explicit_and_withholds_instance_creation` keeps the SDDL,
the masks and these relationships consistent. On Windows targets a second
test compares the masks with the `windows-sys` definitions.

Known consequences of this proposal:

- Every interactive session can control the tunnel, including concurrent
  sessions on a terminal server, and so can processes those users run.
  CL-25 requires tests with changing users and concurrent sessions. A
  narrower option is a specific group (for example a dedicated local
  "l2tunnel users" group), which the owner would need to choose.
- Administrative actions (install, uninstall, service start and stop) go
  through the service control manager and need administrator rights. They
  are not available over the pipe.

### Server identity check (client side)

`open_local_api_pipe` reads the owner of the pipe object through the client
handle (`GetSecurityInfo`, owner only) and accepts only LocalSystem or
BUILTIN\Administrators. When the service creates the first instance, it runs
the same check on that instance, so a foreground host started without
elevation fails before it serves anything.

What the check protects against: a nonprivileged user who creates
`\\.\pipe\l2tunnel` before the service starts (name squatting). The service
cannot then start, because `FILE_FLAG_FIRST_PIPE_INSTANCE` makes its create
fail, and clients refuse the squatter's pipe because the squatter's SID owns
it. Once the service owns the pipe, a nonprivileged user cannot add instances.

Limits, as far as Windows allows:

- The check does not prove which executable serves the pipe. Any LocalSystem
  or elevated administrator process passes. Administrators are trusted, since
  they can replace the service binary anyway.
- A possible stronger check: compare `GetNamedPipeServerProcessId` with the
  process ID the service control manager reports for the `l2tunnel` service.
  This is not implemented: it does not work in foreground mode and needs more
  FFI.
- This assumes an elevated administrator's objects are owned by
  BUILTIN\Administrators, which is the Windows default. If the policy "System
  objects: Default owner for objects created by members of the Administrators
  group" is set to "Object creator", foreground mode is refused. The
  installed (LocalSystem) service is not affected. This has not been verified
  natively.

### Narrow unsafe boundary

`crates/l2tunnel-platform-windows/src/local_pipe/ffi.rs` is the only module
in the workspace that may contain `unsafe` for this feature. The crate's
`[lints]` table copies the workspace lints but sets `unsafe_code` to `deny`
instead of `forbid`, so that module alone can carry `#[allow(unsafe_code)]`.
The module also denies `clippy::undocumented_unsafe_blocks`. It makes four
kinds of foreign call:

1. `ConvertStringSecurityDescriptorToSecurityDescriptorW` converts the fixed
   SDDL. A `LocalDescriptor` owns the result and frees it exactly once with
   `LocalFree`.
2. Tokio's `create_with_security_attributes_raw` receives a stack
   `SECURITY_ATTRIBUTES` whose descriptor outlives the call.
   `CreateNamedPipeW` copies the descriptor.
3. `GetSecurityInfo` and `IsWellKnownSid` work on a borrowed live handle. The
   owner SID points into a descriptor that outlives its last use.
4. `NamedPipeClient::from_raw_handle` takes sole ownership of a handle freshly
   opened with `FILE_FLAG_OVERLAPPED` through safe `std::fs::OpenOptions`
   (`access_mode`, `security_qos_flags(SECURITY_IDENTIFICATION)`) and
   released with `into_raw_handle`. Tokio closes it if registration fails.

No pointer escapes these functions, and no `Send`/`Sync` is asserted.
`docs/modules/windows-wintun.md` requires owner approval for each local FFI
boundary. **This exact boundary is submitted for that approval and has not
been approved yet.**

The service code itself (`apps/l2tunnel-windows`) contains no `unsafe`. The
maintained `windows-service` crate owns the service-control-manager FFI,
including the `extern "system"` entry point generated by its
`define_windows_service!` macro, the same way `tun-rs` owns the Wintun FFI.

### Service host and commands (WLS-05)

```
l2tunnel-windows service install HOST_OPTIONS   # administrator
l2tunnel-windows service uninstall              # administrator
l2tunnel-windows service start                  # administrator; waits until running
l2tunnel-windows service install-start HEX      # UAC entry for GUI / `l2tunnelctl service start --install`
l2tunnel-windows service run HOST_OPTIONS       # service control manager only
l2tunnel-windows foreground HOST_OPTIONS        # elevated console, Ctrl+C stops
HOST_OPTIONS: --profile ABSOLUTE_DIR --wintun-dll ABSOLUTE_DLL
              --wintun-sha256 HEX64 --address IPV4/PREFIX [--pipe \\.\pipe\NAME]
```

- Parsing (`host::Options`, `service::parse`) is portable and opens nothing.
  It checks bounds (values up to 4096 bytes, no NUL, no duplicates), requires
  an absolute profile path, validates the pipe name, and checks the shape of
  the DLL path, pin and address. Unknown commands and unexpected options after
  `uninstall` or `start` are refused. `service start` starts an already
  installed service and waits for it to run; `service install-start HEX`
  decodes the hex-encoded install arguments used by the elevated UAC starter
  (`local::elevate`).
- `install` loads the profile first, to validate the complete configuration
  including MTU and peer/subnet conflict. It then registers the service
  `l2tunnel` ("l2tunnel local service") as an own-process LocalSystem service
  with **manual start**, launched as `<current exe> service run <options>`,
  with the pipe always recorded explicitly. `uninstall` stops the service if
  it is running and marks it for deletion.
- `service run` hands the process to the service control manager. Started any
  other way, it fails explicitly (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`,
  1063, observed under Wine). The service reports `StartPending`, then
  `Running` once the pipe exists, and accepts Stop and Shutdown.
- Stop (or Ctrl+C in foreground) first drops the pipe server, so no new
  request races the shutdown. It then submits a disconnect and waits up to
  `STOP_LIMIT` (10 s) for it to actually complete, while the owner keeps
  running, and then drops the owner. The service reports exit code 0, or the
  service-specific code 1 on failure. Windows event logging is still CL-27,
  so the exit code is currently the only failure signal of the installed
  service.
- The service starts **disconnected**. A client submits `service connect`
  (v5) to open the Wintun adapter and the peer session from the provisioned
  plan.
- Unsupported paths fail explicitly. On other operating systems `execute`
  returns `Unsupported` after validation. The retained `connect --carrier
  tcp-tls` validator still returns `Unsupported`.

The operator must trust the installation paths. The service runs the
installed executable, loads the profile and loads the pinned DLL as
LocalSystem, so all three must be in directories only administrators can
write to (for example `Program Files` and a restricted `ProgramData` folder).
The code does not check those directory ACLs (WLS-08).

### Frontends (WLS-06, WLS-07)

- `l2tunnelctl` compiles its grouped v5 commands (`cli_groups.rs`) and the
  flat v1/v4 local commands on Windows too, with the same parsing, output and
  exit codes (0 completed, 1 failed, 2 usage, 3 unreachable, 4 running, 5
  outcome unknown, 6 unsupported). The help names the default pipe. `profile
  inspect` still delegates to the Unix-only plan inspection and fails
  explicitly on Windows.
- `l2tunnel-windows-gui` (`apps/l2tunnel-windows/src/gui/main.rs`, feature
  `gui`) calls `l2tunnel_desktop_ui::main_entry`. In `l2tunnel-desktop-ui` only
  the cfg gates changed (`any(unix, windows)`): `--socket` takes the pipe name
  and the model is unchanged. The binary uses the Windows GUI subsystem, so
  no console window opens, and `--help` or start-up errors are not visible
  when it is launched from Explorer. The headless `l2tunnel-windows` build
  does not pull in eframe.

## Dependencies

| Crate | Pin | Published | Where |
| --- | --- | --- | --- |
| `windows-service` | `=0.8.1` | 2026-05-08 | `apps/l2tunnel-windows`, `cfg(windows)` |
| `runas` | `=1.2.0` | 2024-06-11 | `l2tunnel-client-core`, `cfg(windows)` (elevated UAC starter `ShellExecuteExW`) |
| `windows-sys` | `=0.61.2` (already locked through Tokio) | 2025-10-06 | `l2tunnel-platform-windows`, `cfg(windows)`; features `Win32_Foundation`, `Win32_Security`, `Win32_Security_Authorization`, `Win32_Storage_FileSystem` |
| `tokio` | `=1.53.1` (already used), feature `net` | n/a | `l2tunnel-platform-windows`, `cfg(windows)` |

## Tasks

- [ ] [WLS-01] Portable pipe-name validation, default pipe name, proposed DACL constants and host/service option parsing with unit tests on every host.
- [ ] [WLS-02] Named-pipe endpoint of the shared local API transport (same framing, bounds, concurrency, v1/v4/v5 dispatch), busy retry and unsent classification; run its Windows tests on native Windows.
- [ ] [WLS-03] Owner approval of the narrow `local_pipe::ffi` unsafe boundary and of the proposed DACL; native verification that interactive users can connect, other principals and remote clients are refused, and no nonprivileged process can create an instance.
- [ ] [WLS-04] One service owner hosting the shared `Handle` directly; native evidence that v5 status/connect/disconnect/events work through the pipe against a provisioned Wintun profile.
- [ ] [WLS-05] Service install/uninstall/run and foreground mode; native install, start, stop (orderly disconnect within `STOP_LIMIT`), shutdown, restart and uninstall evidence.
- [ ] [WLS-06] `l2tunnelctl` grouped commands and exit codes against the installed service from a nonelevated interactive session.
- [ ] [WLS-07] `l2tunnel-windows-gui` against the installed service from a nonelevated interactive session.
- [ ] [WLS-08] Concurrent interactive sessions, user switching, squatting attempts before service start, and checks that the installation directory, profile and DLL directories are administrator-only (CL-25).

WLS-01 has passed on Linux and under Wine, but its box stays open until the
owner confirms the proposed DACL, because the DACL constant is part of that
deliverable.

## Acceptance matrix

| Case | Where it must pass | Current evidence |
| --- | --- | --- |
| Pipe names: local prefix, bounds, charset, remote/device/nested refused | every host | Linux unit test; Wine run |
| DACL string, masks, no instance creation for IU, client mask is a subset | every host, plus Windows constant parity | Linux unit test; Wine run (including `windows-sys` parity) |
| Host options strict; launch arguments reproduce options; pipe always recorded | every host | Linux unit tests; Wine run |
| Host commands explicit; other OS returns `Unsupported` | every host | Linux unit tests |
| Shared serve loop, framing, bounds, concurrency, v5 dispatch | Unix sockets and Windows pipes | Unix: existing transport and v5 tests. Windows: cross-compiled only |
| v5 status over a real pipe; second first instance refused | Windows | Wine: refused by the owner check before serving (Wine's pipe owner is neither SYSTEM nor BA), so not yet passed |
| Remote, device and missing pipe names send nothing (`NotFound`) | Windows | Wine: passed |
| `l2tunnelctl` unreachable/invalid/missing-option exit codes | Windows | Wine: 3, 3, 2 observed |
| `service run` outside the service control manager fails explicitly | Windows | Wine: error 1063, exit 2 |
| Elevated foreground, LocalSystem service, nonelevated clients, DACL refusals, squatting, stop and disconnect, GUI | native Windows | **none** |

## Executed checks

All checks ran on Linux (x86_64) on 2026-11-23 with the pinned Rust 1.92 and
the cross target `x86_64-pc-windows-gnu`. The other parts of the working
tree were being edited concurrently, so results apply only to this source
state.

- `cargo test -p l2tunnel-desktop-ui -p l2tunnel-windows -p l2tunnel-platform-windows --all-features --locked`:
  passed (10 GUI, 19 application and 6 platform tests).
- `cargo test -p l2tunnel-client-core --locked --lib`: every `local::` and
  `cli::groups` test passed, including the Unix transport and v5 tests that
  exercise the shared serve loop. The first full run had 231 passed and 1
  failed. A later run had 217 passed and 17 failed, after concurrent
  receiver-credit work elsewhere in the tree began rejecting compact-wire and
  maintained-carrier plans ("record-receive range below four session credit
  window ceilings") and one measured-proxy runtime test failed
  (`Record(HandoffExpired)`). This change touches none of those code paths.
- `cargo clippy -p l2tunnel-client-core -p l2tunnel-desktop-ui -p l2tunnel-linux -p l2tunnelctl -p l2tunnel-windows -p l2tunnel-platform-windows --no-deps --all-targets --all-features -- -D warnings`:
  passed.
- `cargo check --target x86_64-pc-windows-gnu -p l2tunnel-windows --features gui -p l2tunnelctl -p l2tunnel-client-core -p l2tunnel-desktop-ui -p l2tunnel-platform-windows --all-targets`:
  passed.
- `cargo clippy --target x86_64-pc-windows-gnu -p l2tunnel-windows --features gui -p l2tunnelctl -p l2tunnel-platform-windows -p l2tunnel-desktop-ui --all-targets --no-deps -- -D warnings`:
  passed. With `-p l2tunnel-client-core` the same command fails only on
  Windows-target dead-code and unused-import warnings in client-core's
  protocol, proxy and service modules (`secure_udp/*`, `service/*`, `proxy*`).
  Those warnings predate this change; none is in `local/` or the CLI files.
- `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --locked` for
  `l2tunnel-client-core`, `l2tunnel-desktop-ui`, `l2tunnel-windows`,
  `l2tunnel-platform-windows` and `l2tunnelctl` (Linux), and for the last three
  with `--target x86_64-pc-windows-gnu`: passed.
- `python3 tools/check_checklists.py`: passed.
- Wine 9.0 (a separate prefix, not native Windows): the
  `l2tunnel-platform-windows` test binary passed all 8 tests, and the
  `l2tunnel-windows` test binary passed all 18. The client-core
  `local::transport` Windows tests passed 1 of 2: the v5-over-pipe test was
  refused by the server's own owner check (`PermissionDenied`), as described
  above. Wine's security model is not evidence about Windows ACLs.

The full `tools/check.py` was not run, because the local virtual environment
lacks the simulator's optional dependencies.

## Recent Windows parity & hardening additions (2026-11-27)

Still **cross-compiled and Wine-tested only** (native Windows hardware qualification
remains open until `Verify-L2TunnelWindows.ps1` runs on a real Windows host):

- **Multi-profile daemon mode (`--state-dir`):** `l2tunnel-windows daemon` and
  `l2tunnel-windows service install --state-dir DIR --wintun-dll DLL --wintun-sha256 HEX`
  attach the shared cross-platform `FileStore`, `WindowsHost` (IP Helper routing),
  and `AutoRecoveryPolicy::default_enabled()` so `l2tunnelctl` and
  `l2tunnel-windows-gui` have full multi-profile, Share URI, and route parity with Linux.
- **All non-raw Common carriers on Windows:** `quic-like`, `media-like`, `tls-like`,
  `openvpn-like`, maintained `tcp` (TLS 1.3 with custom `--sni`), and genuine `quic`
  (Quinn) prepare and attach cleanly to Wintun L3 (`raw-packet` and `--layer tap`
  remain explicitly refused with `Unsupported`).
- **Live Wintun MTU (`MtuController` / `WindowsDevice`):** `Device::open_with_mtu`
  exposes live MTU read/update to `service::device_mtu::DeviceMtuHost` for live
  `Internal MTU > Capsule MTU` switches.
- **Narrow documented FFI modules in `l2tunnel-platform-windows` (awaiting owner
  approval alongside `local_pipe::ffi`):**
  - `routes::ffi`: `iphlpapi.dll` (`CreateIpForwardEntry2`, `DeleteIpForwardEntry2`,
    `GetIpForwardTable2`, `GetBestRoute2`) with crash-safe `<state-dir>/host-state.json`
    ownership tracking and automatic peer anti-loop bypass routes.
  - `dpapi::ffi`: `CryptProtectData` / `CryptUnprotectData` (`L2DP` envelope +
    zeroizing buffers, `l2tunnel-windows dpapi seal`, transparent unsealing in
    `credentials::read_secret` / `read_member_der`).
  - `security::ffi`: `GetNamedSecurityInfoW` + DACL audit (`WLS-08`) verifying
    admin-only ownership and no non-admin write ACEs on install/state/DLL folders.
  - `event_log::ffi`: Windows Event Log (`RegisterEventSourceW`/`ReportEventW`)
    paired with bounded rotating `<state-dir>/service.log` (`CL-27`).
  - `net_watch::ffi`: `NotifyIpInterfaceChange` + SCM `ServiceControl::PowerEvent`
    (`ResumeAutomatic`/`ResumeSuspend`/`ResumeCritical`) through `TransitionLimiter`
    (`1.5 s` debounce, `6 / 5 min` cap).
- **Windows L2 TAP & driverless VXLAN (`CL-26`, `VX-09`):** `l2tunnel-platform-windows`
  adds `TapConfig` and `TapDevice` (OpenVPN TAP-Windows6 `tap0901` via `tun-rs`
  `Layer::L2`, zero new `unsafe` FFI) with optional adapter alias, optional IPv4/prefix
  (unnumbered L2 supported for bridging), optional unicast `--tap-mac`, and live
  `MtuController` resizing. `l2tunnel-client-core::secure_udp::native_client::prepare_profile_document`
  supports `--layer tap` with either `TapDevice` or driverless cross-platform VXLAN L2
  (`--vxlan-bind`, `--vxlan-peer`, `--vni` via `l2tunnel-platform-vxlan::VxlanDevice`).
  Native Windows TAP-Windows6 and VXLAN hardware qualification remains open (`CL-26`, `VX-09`).
- **TLS / QUIC server certificate SHA-256 pin verification (`CONN-02`, `CL-08`):**
  `--server-pin HEX64` enforces exact leaf certificate DER SHA-256 matching inside the
  TLS 1.3 / QUIC handshake verifier alongside CA chain and `server_name` verification
  for `openvpn-like`, `tcp`, `raw-packet`, and `quic` carriers on both Linux and Windows,
  and is exposed in the Desktop GUI profile editor.
- **One-click auto-install & Windows rendering (Linux GUI parity):**
  `l2tunnel-windows-gui.exe` stays unprivileged and attaches to `\\.\pipe\l2tunnel`
  just like `l2tunnel-linux-gui`. When no service answers, clicking **"Start service…"**
  prompts UAC for `l2tunnel-windows.exe service start`, which automatically installs
  the multi-profile LocalSystem daemon service into `%ProgramFiles%\l2tunnel` (hardening
  directory ACLs with `icacls.exe`, copying an adjacent `wintun.dll` if present, and
  creating `%ProgramData%\l2tunnel\state`) whenever the service is missing (`ERROR_SERVICE_DOES_NOT_EXIST`).
  Zero-argument `service install-start` reinstalls from the current binary and restarts
  the service (backing the GUI's **"Install & restart service…"** update banner and
  `Advanced -> Reinstall`). On Windows the GUI prefers hardware OpenGL `glow` first for
  smooth frame pacing with automatic clean-process `--renderer wgpu` fallback
  (DX12 / DX11 / Vulkan / Microsoft WARP with `AutoNoVsync`), and displays a native Win32
  `MessageBoxW` plus `%LOCALAPPDATA%\l2tunnel\gui-startup.log` on startup errors. Launching
  `l2tunnel-windows.exe` with no arguments spawns the sibling `l2tunnel-windows-gui.exe`
  when present.
- **Packaging & native qualification scripts:** `scripts/build-windows-bundle.sh`
  produces `dist/l2tunnel-windows-x86_64.zip` containing release `l2tunnel-windows.exe`,
  `l2tunnel-windows-gui.exe` (supporting `l2tunnel://` deep-link arguments),
  `l2tunnelctl.exe`, default 1500/1500 and jumbo 4096>1300 Common plans, and
  `scripts/windows/{Install,Uninstall,Verify}-L2Tunnel*.ps1`.
- **2026-11-27 Wine 9.0 & cross-check evidence:**
  - `cargo clippy --target x86_64-pc-windows-gnu -p l2tunnel-platform-windows -p l2tunnel-windows --features gui -p l2tunnel-desktop-ui -p l2tunnelctl --all-targets --no-deps --locked -- -D warnings`: passed (0 warnings).
  - `RUSTDOCFLAGS='-D warnings' cargo doc --target x86_64-pc-windows-gnu --no-deps --locked -p l2tunnel-platform-windows -p l2tunnel-windows -p l2tunnel-desktop-ui -p l2tunnelctl`: passed.
  - Wine 9.0: `l2tunnel-platform-windows` **14/14 passed** (including native `CryptProtectData`/`CryptUnprotectData` DPAPI round-trip), `l2tunnel-windows` **19/19 passed**, release `l2tunnelctl.exe` (`policy lookup`, `policy test`, `plan tune --device-mtu 4096 --path-mtu 1300`) and release `l2tunnel-windows.exe` (`dpapi seal`, `plan`) all passed.

## Awaiting owner review

- The proposed DACL (IU read/write without instance creation), or a dedicated
  group instead.
- Approval of the `local_pipe::ffi` unsafe boundary.
- Service start type (manual start was chosen) and whether the service should
  connect automatically when it starts (it does not).
- Removing the now-unused `local::serve_private_common_stream`.
