# Shared client and headless entry point

Status: partial shared service implementation. Managed TCP/TLS system traffic with
frame records now uses `service::{Prepared, Handle, Run}` from the Linux CLI and
non-CLI embedding tests. It owns connect, explicit local abort, reconnect after
original-owner cleanup, and the existing compression apply operation. Other
profiles still have private CLI lifecycle paths; FIX-12 and the broad CL service,
GUI and cross-platform gates remain open.

The caller parses credentials before constructing an immutable Prepared plan.
Acceptance reserves one operation and starts the original setup deadline before
queued socket/device work; authentication, both half lanes, pairing and device/
actual-runtime readiness share that bound. One retained Run owns the inline
managed futures; dropping handles, waiters or local IPC cannot cancel them.
Disconnect is an abort, never clean drain. Reconnect releases the old TLS/device
owners before replacement setup. Apply uses `session_control::Control` and only
reports success after its real peer transaction result. Owner/runtime loss during
apply reports OutcomeUnknown, never rollback or successful cancellation.

Cloned Prepared plans retain an opaque identity token; credentials and device
factories are never compared or hashed. Contiguous monotonic request keys have
32 retained results plus a retirement watermark, so old forgotten keys cannot
silently execute again. Profilers are published only with their actual connected
generation; temporary listener addresses carry their setup operation identity.
The local serde schema and shared service/control API are portable; Unix socket
transport remains separately gated. This is not a Windows build, IPC or device
qualification. Exact commands, negative observations and limits are in the
[scoped service receipt](../../work/service29/validation.json).
These checks use actual loopback TLS and injected packet devices; they do not
qualify new native TAP/TUN lifecycle behavior, Windows or Android.

`ConnectionConfig` binds native layer, duplex and maximum packet size into a
canonical SHA-256 authentication digest, including the stateless compression policy. `connect` and `accept` load only supplied
TLS/member policy, perform every lane's handshake, then complete pair binding.
`connect` never falls back to a different transport or weaker authentication.
`accept` admits exactly one configured member per pair, using bounded handshake
and second-lane deadlines. The authenticated connection is kept for user packets.

The CLI uses explicit `serve`/`connect`, device name, TAP/TUN layer, DER certificate
and PKCS#8 key paths. Half duplex is the default; full requires an explicit option.
`keygen` creates fresh private/public member files without overwriting paths and
uses private permissions. No private keys appear in status or command arguments.
An explicit --vxlan-bind/--vxlan-peer/--vni alternative selects a point-to-point
Ethernet VTEP instead of a native device. No route, bridge or firewall changes
are performed by the CLI.

- [x] [MOD-CLI-01] Implement shared canonical configuration and authenticated connect/accept functions. Evidence: [implementation/tests](../../crates/l2tunnel-client-core/src/lib.rs).
- [x] [MOD-CLI-02] Wire Linux daemon/client entry points to real device forwarding. Evidence: [implementation/tests](../../crates/l2tunnel-client-core/src/cli.rs).
- [ ] [MOD-CLI-03] Verify strict option parsing, immutable identity paths and safe key provisioning.
- [x] [MOD-CLI-04] Record native half/full duplex TAP/TUN smoke tests. Evidence: [implementation/tests](../../work/native-wave4/receipt.json).
- [ ] [MOD-CLI-05] Add structured status/events and shared local service API for CLI/GUI.
- [ ] [MOD-CLI-06] Add reconnect/cancellation, multi-peer lifecycle, Windows and Android native wrappers.
- [ ] [MOD-CLI-07] Implement shared typed profile validation and runtime construction, used by the CLI and a non-CLI embedding test; reject unsupported combinations before opening devices or sockets.
- [ ] [MOD-CLI-08] Implement service-owned connect/disconnect/reconnect/apply operations with bounded status, cancellation, original deadlines and explicit accepted/terminal outcomes; test actual half-pair cancellation, reconnect after cleanup and failed peer apply through the public API.
- [x] [MOD-CLI-08A] Move existing compression/active-policy session dispatch out of CLI parsing and presentation into a public typed handle. Reject unsupported versions before submitting commands and preserve pending/busy/closed outcomes. Evidence: [shared dispatch tests](../../crates/l2tunnel-client-core/src/session_control.rs), three focused tests passed; full connection lifecycle remains MOD-CLI-08.

- [x] [MOD-CLI-08B] Implement the actual managed TCP/system/frame lifecycle slice used by CLI and a typed embedding frontend: bounded identity/key replay, accepted versus completed results, original deadline, real half-auth cancellation, full/half reconnect after device/TLS release, exact replacement bytes and actual compression apply/uncertain interruption. Evidence: [service tests](../../crates/l2tunnel-client-core/src/service/tests.rs), [CLI adapter](../../crates/l2tunnel-client-core/src/service_cli.rs), [scoped receipt](../../work/service29/validation.json). Other profile lifecycle paths and broad MOD-CLI-08 remain open.
- [x] [MOD-CLI-08C] Separate unchanged strict local DTOs from Unix transport, preserving legacy local exports/serde bytes and compiling the shared service/control API without a Unix export gate. Evidence: [portable schema and literal tests](../../crates/l2tunnel-client-core/src/local/schema.rs), [exact extraction proof](../../work/service29/portable-candidate/schema-extraction-proof.json), [local checks](../../work/service29/portable-local-first.log). Linux-only checks do not qualify Windows or Android.
