# Shared client and headless entry point

Status: implementation in progress. Public asynchronous connection functions and
configuration are shared by CLI and future GUI/service wrappers. Linux device
attachment is confined to the command-line adapter. This first version serves one
peer for one process lifetime; it does not claim reconnect, GUI or multi-peer service.

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
