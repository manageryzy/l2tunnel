# Windows application status

`l2tunnel-windows` is the Windows service host. An installed service
(LocalSystem, manual start) owns the shared Common client service for a
provisioned original-UDP profile with an explicitly pinned Wintun L3 adapter.
It serves local API versions 1, 4 and 5 on a named pipe, by default
`\\.\pipe\l2tunnel`. The nonprivileged frontends `l2tunnelctl` and
`l2tunnel-windows-gui` (feature `gui`) reach it through that pipe. Design,
the proposed pipe DACL, the unsafe boundary, tasks and executed checks are in
[Windows local service](../../docs/modules/windows-local-service.md).

**Status: cross-compiled for `x86_64-pc-windows-gnu` and unit-tested on Linux
(some Windows test binaries also ran under Wine). Nothing has run on native
Windows: there is no evidence from a native run, a service install, an ACL
check or a Wintun device.** The proposed DACL and the `local_pipe::ffi` unsafe
boundary are awaiting the owner's confirmation.

```
l2tunnel-windows service install HOST_OPTIONS   # administrator
l2tunnel-windows service uninstall              # administrator
l2tunnel-windows service start                  # administrator; waits until running
l2tunnel-windows service install-start HEX      # UAC entry of the GUI and `l2tunnelctl service start --install`
l2tunnel-windows service run HOST_OPTIONS       # service control manager only
l2tunnel-windows foreground HOST_OPTIONS        # elevated console, Ctrl+C stops
HOST_OPTIONS: --profile ABSOLUTE_DIR --wintun-dll ABSOLUTE_DLL
              --wintun-sha256 HEX64 --address IPV4/PREFIX [--pipe \\.\pipe\NAME]

l2tunnelctl service status --control-socket \\.\pipe\l2tunnel
l2tunnelctl service connect --control-socket \\.\pipe\l2tunnel --watch 60
l2tunnel-windows-gui --socket \\.\pipe\l2tunnel
```

The service starts disconnected and opens the adapter only when a client
submits connect or reconnect. The former private `common-worker` child
(framed API4 on stdio behind a GUI host) is replaced by the service, which
hosts the shared service handle directly, so there is one service owner.
`plan`, `--help` and `--version` have no side effects. The retained
`connect --carrier tcp-tls --layer tun ...` command only validates the
requested configuration and returns `Unsupported`.

## Retained components

- `cli` validates argument bounds, peer address, TLS naming, pinned DLL
  inputs, packet size and the outer-peer/on-link-subnet conflict before any
  I/O. The service host reuses its device validation.
- `l2tunnel-platform-windows` keeps the Wintun configuration and device
  adapter and now also holds the named-pipe security boundary.
- `setup::Setup` owns and joins a blocking setup worker, including results
  that arrive after cancellation. The service's deferred Wintun attachment
  uses it.
- `input` parses bounded local status/disconnect/reconnect commands.
  `diagnostics::Diagnostics` provides bounded best-effort text output. Neither
  is the control path any more; the named pipe is.

## Required follow-up

| ID | Deliverable | Current status |
| --- | --- | --- |
| WFG-06 | Bounded local status/disconnect/reconnect through the shared service | Implemented through the service host and local API v5 on the named pipe (WLS-02, WLS-04, WLS-06), cross-compiled only. Native evidence from a nonelevated client against the installed service is pending. |
| WFG-07 | Old-generation release before replacement device and authoritative operation completion across cancellation races | The shared service now owns this on Windows as well. The service stop path waits up to 10 s for a submitted disconnect to actually complete. Native evidence is pending. |
| WFG-08 | Native Windows console/device lifecycle qualification | Open. Portable tests, Wine runs and cross-compilation are not native device evidence. |

The original requirements remain in scope:

- CL-25: Windows service ownership, nonprivileged UI/CLI operation, an
  authorized named pipe and ACLs. Implemented as a proposal and cross-compiled;
  open until native and multi-session tests pass and the owner confirms the
  ACL (WLS-03, WLS-08).
- CL-26: Wintun and TAP L2, complete setup/teardown/routing ownership,
  privilege failures and native device qualification.
- CL-27: credential vault integration, Windows event logging (the installed
  service currently reports failure only through its exit code), recovery,
  sleep/wake and the complete platform lifecycle behavior.
- All required Common/raw carriers, algorithm profiles and mode parity remain
  subject to the shared implementation plan.

Native validation must cover: service install/uninstall/start/stop/shutdown;
nonelevated `l2tunnelctl` and GUI sessions; refused principals and remote
clients; squatting before service start; pinned-DLL and permission failures;
real two-way traffic; explicit disconnect/reconnect; failed authentication and
device I/O; release of the original adapters, sessions, events, libraries and
sockets before a replacement; late setup cleanup; and routing ownership.
Record the Windows version, Wintun DLL identity, account and privileges,
commands, and the observed handles and traffic. Historical receipts apply only
to their recorded source states.
