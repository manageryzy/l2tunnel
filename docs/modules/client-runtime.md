# Shared client and headless entry point

Status: partial shared service implementation. Managed TCP/TLS system traffic with
frame records now uses `service::{Prepared, Handle, Run}` from the Linux CLI and
non-CLI embedding tests. It owns connect, explicit local abort, reconnect after
original-owner cleanup, and the existing compression apply operation. The same
owner can also hold a base system/frame UDP session through its typed embedding
API only; the CLI still runs UDP through its private path. Genuine QUIC and all
other profiles still have private CLI lifecycle paths; FIX-12 and the broad CL
service, GUI and cross-platform gates remain open.

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

## Base UDP in the same owner (embedding API only)

`Prepared::udp_client` and `Prepared::udp_server` take the existing parsed TLS/member
credentials, `udp::Settings` and a mandatory `managed::DeliveryConfig`. Preparation
repeats the factory's pure settings and canonical-binding checks before any
credential use, bind or device work. Setup calls the unchanged public
`udp::connect`/`udp::accept` under the already accepted absolute deadline; the
factory's own later handshake timer cannot extend it. The device opens after
authentication.

The live session is one private backend sum with a managed or a UDP variant; its
presence is the live-session predicate. `Snapshot.runtime` is now the typed
`service::Observation`: `Managed(managed::Status)` or `UdpFrame`, the latter with
requested settings, the effective runtime profile returned by the authenticated
factory, the delivery policy and the latest lane snapshot. Connected is published
only after the real runtime has published the required lane shape: exactly the
first lane in full duplex, both lanes in half duplex.

A UDP session has a fixed profile. A new `apply` key is rejected as Unsupported
before it consumes the key, an operation slot or a queued command, and nothing is
sent. Retained managed keys keep replaying their original acceptance and result
after a later generation uses a different backend. The local v1 `Status` request
answers `unsupported` for a UDP session because that schema describes managed
sessions; no new IPC wire was added.

The service runs UDP through the additive `runtime::udp::run_observed_inline`,
which owns the per-lane control and datagram readers/writers inside the runtime
future instead of spawned tasks. Abort, cancel, setup expiry and dropping `Run`
therefore release the bootstrap TLS streams, UDP sockets and device before the
result is published. `run`/`run_observed`, the CLI and genuine QUIC keep their
spawned children and existing scheduling. Inline ownership puts all lane I/O on
one task; its throughput and fairness are unmeasured.

Evidence so far is local Linux only: four focused tests in
[service/tests/datagram.rs](../../crates/l2tunnel-client-core/src/service/tests/datagram.rs)
over real loopback TLS and UDP with injected devices, in both duplex modes. With
the spawned runtime substituted, the release test fails with AddrInUse.

Not done in this slice:

- Genuine QUIC is not accepted by the service. Its Quinn endpoint drivers release
  sockets asynchronously after the last owner drops, so a synchronous release claim
  needs an endpoint release witness in `l2tunnel-quic` first.
- The CLI does not use the service for UDP, so FIX-12's shared CLI/GUI requirement
  is unmet for this profile. `--control-socket` stays rejected for UDP.
- No test of control progress under saturated data, half-lane fairness, loss,
  backpressure or more than 64 native packets through the inline runtime.
- No cancellation exactly between first and second lane authentication for UDP.
- No native TAP/TUN, privileged lab, Windows or Android run.

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
- [ ] [MOD-CLI-08D] Own base UDP and genuine QUIC through the same service from both the CLI and a typed embedding frontend: synchronous original-owner release for both carriers, requested versus effective profile status, apply rejection without side effects, and qualification of the inline UDP runtime under loss, pressure and half-duplex fairness. Base UDP currently has the embedding API and focused loopback tests only; QUIC ownership, CLI migration and pressure qualification are open.
