# Explicit fixed-credit proxy client

Status: typed factories, strict parsing and explicit CLI/private local control are
implemented and integration-tested for the finite clean Linux TUN profile. The
[proxy runtime](proxy-runtime.md) has a stable aggregate and actual authenticated
loopback tests. [Owned native full/paired-half receipts](proxy-native.md) now
qualify IPv4/IPv6 fixed-credit split flows, transparent bypass and exact closure.
Adaptive window growth and a reload protocol remain separate. The post-wave7 startup correction and client
slice passed the [source-stable wave8 aggregate](../../work/implementation-wave8/validation.json);
the later native receipts are separate from that aggregate.

## Typed configuration and ownership

New `l2tunnel_client_core::proxy` owns these interfaces:

```text
Settings { routes: RoutePolicy, channels: u16, time_wait_reset_policy }
Settings::new(routes: RoutePolicy) -> Settings
Settings::from_json(&[u8]) -> io::Result<Settings>
runtime_config(ConnectionConfig, &Settings) -> io::Result<runtime::proxy::Config>
connect(address, &ClientTls, server_name, &MemberKey,
        ConnectionConfig, &Settings) -> io::Result<Session>
accept(&TcpListener, &ServerTls, &MemberAllowlist,
       ConnectionConfig, &Settings) -> io::Result<Session>
Session::config(&self) -> &runtime::proxy::Config
Session::run(self, PacketDevice<Error=io::Error>, Control)
    -> io::Result<runtime::proxy::CloseReport>
```

Reexport the authoritative runtime `Handle`, `Control`, `DrainWaiter`,
`CloseReport`, `Status`, `Phase` and `control_channel`; no second controller or
drain state machine is created. `Session` privately owns the actual authenticated
link and its exact immutable runtime configuration. The caller cannot substitute
a managed TCP Link or supply a different profile to `Session::run`.

Require TUN/IP and `Compression::None`. `ConnectionConfig` supplies native MTU,
duplex and local handshake timeout; its existing native queue/poll defaults are
preserved. `Settings::new` selects 16 CRC-affinity channels and the maintained
TIME-WAIT policy. Every other fixed queue/credit/native-stack/work/timer bound
comes from `runtime::proxy::Config::new`, including 16 lifetime proxy owners,
1,024 policy entries, fixed relay targets and the existing shutdown deadline.
No active-credit settings or other transport/record modes are inferred.
`runtime_config` validates before opening sockets or accessing a native device.

Routes authorize original source/destination ownership; they do not configure
OS addresses/routes or authorize transparent routing. An empty explicit route
list denies every new proxy owner. No implicit route or catch-all is added.
Both authenticated peers must use the same canonical policy. The runtime digest
binds every resulting operator-controlled policy and the fixed role rule
`authenticated TLS client = originator`; different local role booleans are not
hashed separately. `Maintained` remains the default TIME-WAIT behavior;
`ignore_in_time_wait` is an explicit opt-in with the runtime's documented limits.

## Strict policy document

The optional parser accepts at most 65,536 input bytes and 256 route entries.
All fields are required, duplicate object fields and unknown fields are errors;
there is no fallback to defaults on a malformed document. Strings containing
whitespace, noncanonical CIDR host bits, malformed address/prefix lengths, mixed
families, zero/reversed ports, invalid channels or unknown policy values fail.
Identical route entries are canonicalized by the authoritative `RoutePolicy`;
order and duplicates cannot change the digest. IPv4 and IPv6 addresses are literal
addresses, without DNS lookups or scoped IPv6 syntax.

```json
{
  "version": 1,
  "channels": 16,
  "time_wait_reset": "maintained",
  "routes": [
    {
      "source": "10.112.0.0/24",
      "destination": "10.113.0.0/24",
      "ports": { "first": 443, "last": 443 }
    }
  ]
}
```

There is no secret material in this document. Existing credentials/trust roots
remain separate. Parsing and construction do not open devices, perform DNS,
change host routes, or read additional files. The explicit CLI reads one named
bounded policy file and passes its bytes to this parser; no default file is searched.

## Original setup deadline and retained authentication

Factories validate configuration first, establish one absolute setup deadline
from `ConnectionConfig::handshake_timeout`, and pass only the remaining duration
to each TCP/TLS/member handshake. Full duplex retains one authenticated object;
half duplex retains two independently authenticated objects and invokes the
existing proxy pair constructor. The whole factory, including TCP connect or
listener accept, both authentications and pair proof, runs under that same
deadline. A successful first lane cannot grant a fresh full timeout to the
second lane. The single-session `accept` helper therefore bounds even its first
accept; a long-lived daemon's idle listen/retry policy remains an outer concern.

Server certificate/name verification, default no-SNI, Ed25519 member allowlist,
configuration binding and the original TLS objects remain authoritative. No
raw TCP, UDP or QUIC fallback is attempted. Connect rejects a zero-port,
unspecified, multicast or broadcast remote endpoint before opening it. Accept
uses the caller's listener; peer authority comes from authenticated identity,
not an assumption that an address is an identity. A failed second lane, wrong
member, role, profile or pair proof drops both owned lanes and never opens TUN.

## Controller and future frontend boundary

The frontend retains `Handle` while polling `Session::run`. A requested drain
does not abort the run future. Dropping its optional waiter neither cancels the
runtime-owned operation nor proves completion. Dropping every Handle or dropping the run
future is abnormal cancellation, with no claim of delivery or TLS close.
The runtime owns one original drain deadline; client status polling, repeated
requests and frontend timeouts cannot renew it. A successful `CloseReport`
separates clean flows and stopped/refused flows; it is not a statement that every
application stream succeeded.

## Frozen CLI and asynchronous local control

Select `--traffic proxy --proxy-policy FILE` with TUN, TCP/TLS, frame records and
compression off. Explicit incompatible active/adaptive/catalog, aligned, FEC,
UDP/QUIC/standalone options are rejected before policy/credential/device I/O.
The policy is read and validated before authentication; the native device opens
only after the exact typed full/half factory succeeds. Other profiles reject
`--proxy-policy`, so no operator field is silently ignored.

`drain-proxy --control-socket PATH` sends strict `Action::DrainProxy {}`. It
returns `accepted` promptly after the bounded runtime command is owned. The
service records acceptance, drops only the optional waiter, and keeps polling
`Session::run` with its Handle alive. Repeated calls return `already_accepted`
without another submission or deadline renewal. Status carries an optional
strict `Snapshot.proxy` object; omission preserves legacy response bytes. It
includes actual runtime phase/counters, immutable configuration digest, local
acceptance and optional terminal outcome. Nested unknown/duplicate fields are
rejected. Other runtime profiles answer DrainProxy with `unsupported`.

Terminal success or error comes only from the actual `Session::run` result.
Waiter drop, acceptance, RPC timeout, disconnect and status phase alone cannot
populate it. Terminal errors are bounded to 256 Unicode scalar values and the
existing 8,192-byte reply limit still applies. After actual runtime completion,
the CLI prints the finite outcome and serves only local status for a fixed
five-second grace, then exits with the actual result. Network/device owners have
already completed or dropped; this local grace cannot extend network drain.
Without a socket the CLI retains its Handle and awaits the runtime or peer drain.
Process termination remains abnormal; no signal-based drain is implied.

Existing private-directory/UID checks, socket mode, bounded messages and inode-safe
cleanup remain authoritative. The 65-second RPC deadline is unchanged: DrainProxy
acknowledges submission rather than waiting on the runtime's 120-second drain.
Future GUI callers can use the typed factory/controller or this local schema.

## Files and acceptance

Approved files are new `client-core/src/proxy.rs`, `proxy_tests.rs`, `proxy/cli.rs`,
this document, and narrow shared CLI/local schema/tests and module integration.
The post-wave7 runtime startup correction requires actual local Ready flush
before user admission; its focused regressions are recorded separately in
[proxy-runtime](proxy-runtime.md). Pure proxy and other carriers are unchanged.
The only added dependency is the existing workspace `l2tunnel-tcp-proxy` crate
for its authoritative TIME-WAIT policy type; no external package is added.

- [x] [MOD-PROXYCLIENT-01] Implement strict bounded v1 policy parsing and canonical authoritative runtime configuration; test all incompatible/literal/length/count/unknown-field cases. Evidence: [parser and factories](../../crates/l2tunnel-client-core/src/proxy.rs), [strict/maximal mixed IPv6/canonical digest tests](../../crates/l2tunnel-client-core/src/proxy_tests.rs).
- [x] [MOD-PROXYCLIENT-02] Implement retained full/half factories under one original setup deadline; test actual certificate/member/config auth, pair failure, first/second-lane timeout and no native-device admission before success. Evidence: [original-deadline factories](../../crates/l2tunnel-client-core/src/proxy.rs), [actual authentication and pair failures](../../crates/l2tunnel-client-core/src/proxy_tests.rs).
- [x] [MOD-PROXYCLIENT-03] Implement typed Session plus existing controller ownership; test real loopback forwarding, exact finite drain, cancellation and no silent managed-profile reuse. Evidence: [typed Session](../../crates/l2tunnel-client-core/src/proxy.rs), [prequeued native/full-half and cancellation tests](../../crates/l2tunnel-client-core/src/proxy_tests.rs).
- [x] [MOD-PROXYCLIENT-04] Run focused strict checks, existing client regressions, independent review and a coordinated stable aggregate before client implementation completion. Evidence: [wave8 stable aggregate](../../work/implementation-wave8/validation.json), 587 Rust tests including doctests and 46 Python tests with unchanged source hashes; independent factory/startup/service/schema reviews found no blocker.
- [x] [MOD-PROXYCLIENT-05] Implement the reviewed explicit CLI/private asynchronous local control selection, strict incompatible-option rejection and distinct terminal outcomes. Evidence: [frontend/service](../../crates/l2tunnel-client-core/src/proxy/cli.rs), [selection tests](../../crates/l2tunnel-client-core/src/proxy/cli_tests.rs), [strict local schema](../../crates/l2tunnel-client-core/src/local.rs).
- [x] [MOD-PROXYCLIENT-06] Qualify actual owned Linux TUN routing/packet captures for both roles and duplex modes; adaptive target growth and other carriers remain separate gates. Evidence: [clean full](../../work/native-proxy-full-underlayipv4/tun-full-clean/receipt.json), [clean paired half](../../work/native-proxy-half-clean/tun-half-clean/receipt.json), [strict scope and retained unsupported first attempt](proxy-native.md); fixed credit, maintained TIME-WAIT, exact both-family payload/FIN, original lane closure and cleanup.
- [x] [MOD-PROXYCLIENT-07] Test prompt acceptance while runtime remains active, repeated requests without deadline renewal, strict nested schema, terminal provenance and local-only grace. Evidence: [actual TLS/private Unix tests](../../crates/l2tunnel-client-core/src/proxy_tests.rs), [nested schema tests](../../crates/l2tunnel-client-core/src/local/tests.rs), [waiter-drop/bounded-error tests](../../crates/l2tunnel-client-core/src/proxy/cli.rs).

Focused Linux commands: `cargo test --offline -p l2tunnel-client-core --all-targets`
passed 52 tests including actual local sockets and authenticated loopback. Both
client and runtime strict all-target Clippy and warning-denied rustdoc pass;
`cargo test --offline -p l2tunnel-runtime --all-targets` passed 109 tests at this
checkpoint. These counts include concurrent independently owned modules and are
not a stable whole-workspace receipt, native-device evidence or non-Linux CI.
