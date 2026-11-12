# Shared client and headless entry point

Status: implementation in progress. Public asynchronous connection functions and
configuration are shared by CLI and future GUI/service wrappers. Linux device
attachment is confined to the command-line adapter. This first version serves one
peer for one process lifetime; it does not claim reconnect, GUI or multi-peer service.

The public per-profile authentication helpers are reusable, but the complete
service boundary is not yet implemented: private `cli::execute` still chooses
the runtime and opens devices. Existing compression/active-policy command
dispatch now lives in public `session_control::Control`, used by the CLI and
callable directly by an authorized embedding frontend. `local::Action`
provides status, selected switches and drains, not connection lifecycle. This is
the blocking FIX-12 correction, not a completed CLI/GUI service architecture.

The replacement boundary must accept a typed, validated profile and injected
credential/device providers, never a CLI option map. A service owns the attempt,
all lane/device tasks and its original deadline. Connect, disconnect, reconnect
and profile apply return bounded operation identities with observable terminal
results. Disconnect waits for owned cleanup; reconnect cannot overlap an old
owner; profile apply uses authenticated peer negotiation when required. Local
API detachment does not cancel a service operation. CLI parsing and output remain
outside this boundary. Existing per-profile wire bindings must remain exact.

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
