# Standalone OpenVPN-like shared client and key provisioning

Status: implemented and integration-tested over real authenticated loopback UDP
with memory packet devices; explicit CLI selection is implemented. Native device
qualification remains open; the stable wave-7 aggregate includes this source.
The [finite native checkpoint](openvpn-native.md#finite-outcome-checkpoint) keeps
two failed unchanged two-second restoration runs adjacent to one passing short
recovery and one passing expected-terminal case, all clean TUN/half. It does not
qualify the wider TAP/TUN/VXLAN or impaired matrix.
The first client profile has one system FIFO channel, ordinary frame records,
stateless None/LZ4 compression and mandatory selective repeat. It does not imply
OpenVPN interoperability, active TUN credit, configured MUX, FEC, aligned records,
hot switching, production listener scaling or native qualification.

The additive [native-drain client](openvpn-drain-client.md) is selected explicitly;
this document describes the unchanged legacy default. It does not turn historical
outage outcomes into native clean-close evidence.

## API and ownership

`client-core::openvpn` has its own tests and key-file helper. Narrow shared
changes are its `lib.rs` declaration, Cargo dependencies and explicit CLI branch.
The aligned-client owner has handed off shared client and native harness source.
The existing TCP, UDP
with TCP bootstrap, QUIC and aligned paths retain their public APIs and defaults.

```rust
pub struct Settings {
    pub forward: udp::Endpoints,
    pub reverse: Option<udp::Endpoints>,
    pub protection: l2tunnel_openvpn::Protection,
    pub path_mtu: usize,
    pub authenticated_lease: Duration,
}
pub struct KeyBundle { /* private zeroizing 64 bytes; no Debug/Clone */ }
impl KeyBundle {
    pub fn from_bytes(bytes: [u8; 64]) -> io::Result<Self>;
}
pub async fn connect(
    tls: &ClientTls, name: &str, member: &MemberKey,
    admission: KeyBundle, config: ConnectionConfig, settings: Settings,
) -> io::Result<(runtime::openvpn::Link, runtime::openvpn::DeviceConfig)>;
pub async fn accept(
    tls: &ServerTls, members: &MemberAllowlist,
    admission: KeyBundle, cookie: KeyBundle,
    config: ConnectionConfig, settings: Settings,
) -> io::Result<(runtime::openvpn::Link, runtime::openvpn::DeviceConfig)>;
```

Each bundle contains independent 32-byte forward and reverse keys in that fixed
order. Both roles always store that same logical order, regardless of local send
direction. Full duplex uses the first key and reserves the unused reverse slot;
the reserved slot does not create a second authenticated lane. Paired half uses
both. The admission
bundle is provisioned to this one configured member and its server. The cookie
bundle is separately generated and remains server-only. Reject all-zero lanes,
equal lanes and server cookie/admission reuse. The gate remains a permission to
spend handshake resources, not a substitute for TLS certificate/name validation
and allowlisted member proof. Key bytes never enter public digests, status or
error text. Public typed factories consume the bundles; the initial Linux CLI
loads them through the restricted helper below. Callers of `from_bytes` retain
responsibility for any copies they themselves keep.

Validation precedes socket/device reads. Full duplex forbids reverse endpoints;
half requires distinct fixed local and peer ports in one address family. Canonical
client/server endpoint order derives from the actual factory role. Bind both
sockets before either paired gate starts. The only socket type is UDP: no
`TcpStream`, `TcpListener` or ancillary TCP bootstrap. Failure/cancellation owns
and tears down every successfully opened lane.

The native config uses the existing `ConnectionConfig::runtime()` queue/packet
bounds, reassembly timeout 3 seconds, work limit 32 and shutdown allowance 1 second.
Its exact base feeds each carrier config. The carrier helper derives control/data
source sizes, all byte/count reservations and shared complete-wire allowances
from checked MTU arithmetic, with the existing 32 source slots. Initial whole-IP
MTU is 1200 for IPv4 and 1280 for IPv6; explicit MTU must be at least 576/1280 and
at most 65,535 and must satisfy every carrier/fragment bound. A reviewed additive
`Config::with_path_mtu` helper centralizes this derivation without changing
`Config::new` defaults or any existing canonical vector.

Use `ConnectionConfig.handshake_timeout` as the total whole-factory deadline
(including both gates and pairing), with each immutable bootstrap/auth deadline
bounded by that same configured duration. Cookie TTL is capped by that bound.
The first lease defaults to one hour, with a public positive maximum of 24 hours;
all effective values enter the existing exact carrier digest. There is one fixed
peer/session, or two fixed paired lanes, per frontend instance. No unbounded
listener accept loop, key roster or endpoint learning is introduced.

## Linux key files and CLI

Explicit carrier selection: `--carrier openvpn-like`. This is distinct
from `--carrier udp --udp-cover openvpn-like`, which keeps its existing TCP
bootstrap. Both roles require `--udp-bind` and `--udp-peer`; paired half additionally
requires the two reverse endpoints. This branch rejects `--listen`/`--remote`
because neither names a TCP socket. It also rejects custom UDP cover, FEC,
aligned records, non-system traffic policy and local hot-reload options rather
than ignoring them. Existing TLS root/name, server certificate/key and member
identity/allowlist flags retain their meaning. Optional data integrity-only mode
does not disable control TLS or member authentication.

Add `--admission-key-file FILE` on both roles and `--cookie-key-file FILE` on the
server only. Each is exactly 64 raw bytes. There is no secret literal argument,
environment fallback or automatic key generation during connection. A separate
`openvpn-keygen --admission NEW_FILE --cookie NEW_FILE` command obtains two
independent bundles from `ring::rand::SystemRandom`, creates both exclusively with
mode 0600, writes/syncs them and never overwrites existing files. A partially
created new file remains visible if the second creation fails; diagnostics contain
no key bytes. The cookie file must not be distributed to the client.

The Linux loader uses safe maintained filesystem wrappers with `O_NOFOLLOW` and
`O_NONBLOCK`, then inspects the opened descriptor. It rejects a symlink final
component, non-regular file, owner different from effective UID, group/world
permission bits, short/long contents and bad bundle structure. Reads are bounded
to 65 bytes, even if a file changes concurrently. Secret scratch and owned bundle
storage use the already pinned `zeroize` implementation. Directory ancestors are
not claimed to be immutable; callers still choose a trusted provisioning path.
No equivalent Windows/Android file-permission qualification is implied.

The first CLI exposes sampled adapter counters without secrets when
`--openvpn-stats-ms` is 100..60,000 (default 0 disables diagnostics). It does not map
cancellation or carrier termination to clean native shutdown. A distributed
device quiescence barrier remains the separate `MOD-OVPNDEV-08` gate.

## TLS and allocation review boundary

The pinned rustls 0.23.45 source provides a 64 KiB default outgoing TLS buffer,
16 KiB received-plaintext buffer and a 65,535-byte handshake-message limit. Those
are individual maintained buffers, not a total TLS heap cap. Its default limits
remain enabled; no `set_buffer_limit(None)` is used. The existing auth factories
allow bounded local DER counts/lengths, disable resumption/early data, retain
certificate verification with no SNI and expose no unverified application data.
The CLI loads one bounded DER certificate/root and bounded private/member keys.

The driver additionally has finite reliable-control rings and duplex adapters,
one/fixed-two actual TLS connections, a total bootstrap deadline and authenticated
lease. Local certificate encoding, retained peer certificate chains, crypto
scratch and allocator overhead remain distinct from application queue accounting.
Do not advertise the control stream's 8 KiB capacity as total TLS memory usage.
A multi-client listener or TLS-version upgrade needs a fresh aggregate resource
review; it is outside this fixed-peer slice.

## Verification gates

The full client suite passed 33 tests, including eight new standalone/factory,
provisioning and CLI tests. The carrier suite passed 29 tests after adding checked
MTU derivation and the test-only close-ACK trigger regression. Strict client and
carrier Clippy passed. These are local Linux loopback/memory-device checks; native
TAP/TUN/VXLAN, non-Linux platforms and performance are not qualified here.

- [x] [MOD-OVPNCLI-01] Write concrete shared API, socket/key ownership, CLI distinction and finite TLS review before enabling selection. Evidence: [API contract](#api-and-ownership), [provisioning](#linux-key-files-and-cli), [TLS boundary](#tls-and-allocation-review-boundary).
- [x] [MOD-OVPNCLI-02] Implement checked MTU/native/carrier derivation and role-canonical full/paired fixed endpoints, with no TCP socket. Evidence: [factories](../../crates/l2tunnel-client-core/src/openvpn.rs), [checked MTU derivation](../../crates/l2tunnel-openvpn/src/config.rs).
- [x] [MOD-OVPNCLI-03] Implement zeroizing key bundles and strict descriptor-based Linux key reads plus exclusive generation tests. Evidence: [key-file helper and adversarial tests](../../crates/l2tunnel-client-core/src/openvpn/keys.rs), [private bundles](../../crates/l2tunnel-client-core/src/openvpn.rs).
- [x] [MOD-OVPNCLI-04] Add explicit shared CLI selection after source handoff; reject unsupported combinations and missing/wrong-role keys before native I/O. Evidence: [strict CLI and rejection tests](../../crates/l2tunnel-client-core/src/openvpn/cli.rs).
- [x] [MOD-OVPNCLI-05] Test real full/paired IPv4/IPv6 TLS/member connections, native transfer, wrong admission/config, cookie-key reuse, second-lane failure and cancellation cleanup. Evidence: [independent loopback factory tests](../../crates/l2tunnel-client-core/src/openvpn/tests.rs).
- [x] [MOD-OVPNCLI-06] Run strict focused checks and a coordinated all-workspace aggregate receipt. Evidence: [stable wave 8, 587 Rust and 46 Python tests](../../work/implementation-wave8/validation.json).
- [ ] [MOD-OVPNCLI-07] Qualify owned native TAP/TUN/VXLAN and impaired paths with immutable binaries, UDP-only socket/capture/MTU evidence, bounded termination and cleanup; retain failures separately.
