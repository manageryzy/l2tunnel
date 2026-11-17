# Windows application status

The obsolete managed TCP/TLS foreground service path has been removed. The
Windows application has not yet been bound to the current Common client/service
API. A syntactically valid `connect` request returns `Unsupported` before opening
credentials, sockets, standard input or a Wintun device. It does not report an
effective carrier. `plan`, `--help`, and `--version` remain side-effect-free.

The accepted `connect --carrier tcp-tls --layer tun ...` options provide bounded
requested-configuration validation only. They do not select a working legacy
fallback. TLS identity verification and optional SNI remain separate requested
values; neither is used to create an authenticated owner by this application.

## Retained components

- `cli` validates argument bounds, peer address, TLS naming, pinned DLL inputs,
  packet size and the outer-peer/on-link-subnet conflict before any I/O.
- `l2tunnel-platform-windows` retains the Wintun configuration and device adapter.
  Its independent implementation does not constitute application integration.
- `setup::Setup` owns and joins a blocking setup worker, including late results
  after cancellation. Dropping it may wait for the underlying OS call.
- `input` parses bounded local status/disconnect/reconnect commands. No Common
  service command executor is installed. The input-only reader retains no device,
  credential or transport owner; a blocked standard-input read may last until
  process exit.
- `diagnostics::Diagnostics` provides bounded best-effort text output, without
  retaining tunnel owners or delaying their release when output blocks. It is
  not a reliable IPC or Windows Event Log implementation.

The independent parser, setup ownership and diagnostics tests remain. Fixtures
that exclusively constructed the removed `Prepared::client`/`server` managed
service and its old foreground owner have been removed with that implementation.
Current aggregate validation is owned by the repository integrator; no native
Windows execution or fresh Windows qualification is claimed by this cleanup.

## Required follow-up

| ID | Deliverable | Current status |
| --- | --- | --- |
| WFG-06 | Bounded local foreground status/disconnect/reconnect through the shared service | Pending migration to the current Common service. Bounded command parsing remains separately implemented and component-tested. |
| WFG-07 | Old-generation release before replacement device and authoritative operation completion across cancellation races | Pending Common application integration. The joined setup worker remains independently implemented and component-tested. |
| WFG-08 | Native Windows console/device lifecycle qualification | Open; prior portable tests and cross-compilation do not provide native device evidence. |

The original requirements remain in scope:

- CL-25: Windows service ownership, nonprivileged UI/CLI operation, authorized
  named-pipe control and ACLs.
- CL-26: Wintun and TAP L2, complete setup/teardown/routing ownership, privilege
  failure and native device qualification.
- CL-27: credential vault integration, Windows event logging, recovery,
  sleep/wake and the complete platform lifecycle behavior.
- All required Common/raw carriers, algorithm profiles and mode parity remain
  subject to the shared implementation plan; removing the obsolete entry does
  not complete or remove these requirements.

After the current service binding is implemented, native validation must cover
pinned-DLL/permission failures; real two-way traffic; console Ctrl+C/EOF during
setup; explicit disconnect/reconnect; failed authentication and device I/O;
release of original adapters, sessions, events, libraries and sockets before
replacement; late setup cleanup; routing ownership; and blocked/broken stdio.
Record the Windows version, Wintun DLL identity, privileges, command and observed
handles/traffic. Historical receipts apply only to their recorded source states.
