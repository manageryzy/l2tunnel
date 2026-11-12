# Standalone OpenVPN-like packet-device adapter

Status: implemented and integration-tested with real authenticated loopback UDP
carriers and independent memory packet devices. [Explicit shared client selection](openvpn-client.md)
is implemented; native device qualification remains open. The [carrier runtime](standalone-openvpn-runtime.md)
owns actual TLS/member control, protected selective repeat, paired directional
lanes, one shared wire ledger and finite lifetime/close state.

The additive [distributed native drain](openvpn-native-drain.md) now has a separate
`openvpn::drain` API, locally tested with genuine carriers and mock devices. Its
OVC2 profile has an explicit opt-in [client/CLI selection](openvpn-drain-client.md);
legacy defaults remain unchanged and privileged clean-close qualification stays open. Legacy `run` retains its explicit incomplete semantics.

## API and source ownership

`l2tunnel-runtime::openvpn` lives in `src/openvpn.rs`, with focused tests in
`src/openvpn_tests.rs` and only the required module/dependency declarations in
runtime `lib.rs`/`Cargo.toml`. Those shared changes were coordinated with the proxy
runtime owner. Client `lib.rs`/`cli.rs` and native-smoke files remain owned by the
aligned-client work until its handoff.

```rust
pub struct DeviceConfig {
    pub native: RuntimeConfig,
    pub duplex: Duplex,
    pub reassembly_timeout: Duration,
    pub work_limit: usize,
    pub task_shutdown_timeout: Duration,
}
impl DeviceConfig {
    pub fn validate(self) -> io::Result<()>;
    pub fn base_session_config(self) -> io::Result<SessionConfig>;
}
impl Link {
    pub fn full(carrier: l2tunnel_openvpn::Carrier,
        transport: l2tunnel_openvpn::Config,
        config: DeviceConfig) -> io::Result<Self>;
    pub fn observer(&self) -> Observer;
    pub fn paired(carrier: l2tunnel_openvpn::PairedCarrier,
        transports: [l2tunnel_openvpn::Config; 2],
        config: DeviceConfig) -> io::Result<Self>;
}
pub async fn run<D: PacketDevice<Error = io::Error>>(
    device: D, link: Link, config: DeviceConfig) -> io::Result<()>;
```

Before any device receive, Link verifies the actual authenticated session digest,
carrier's exact canonical config, complete native base binding, native layer,
full/paired mode and direction. A caller cannot supply a public session ID or
exporter assertion as proof. The canonical native base binds packet/queue byte and
count limits, compression, driver polling, reassembly lifetime, per-iteration work (1..1024) and task
shutdown timeout (positive, at most 30 seconds). Native output reservation is the
checked product `queue_packets * max_packet`, capped at 64 MiB. The frame ceiling
is the existing RuntimeConfig maximum, 65,519 native bytes plus its 16-byte frame
header. Fragment geometry allows at most 256 fragments per message, one incomplete
message, one encoded-record reservation and a fixed 64-message duplicate window.
All fixed protocol choices enter the versioned native binding; each complete
carrier config subsequently binds that native base along with its own bounds. Full and paired
Link variants own their original carrier Control/PairControl for the entire run.

## One recovery owner, bounded native ownership

The carrier already supplies ordered, recovered complete source records. Reuse
existing `FrameCodec` (None or stateless LZ4), `Fragmenter` and `Reassembler` only;
do not call the current UDP `run_datagrams` helper because it creates another
recovery engine and wire ledger. A complete encoded native frame may exceed one
carrier source and is fragmented at `transport.arq.max_source_bytes` including
the existing fragment header. Each actual directional carrier session and fixed
epoch binds its fragment context. The fragment format uses only the first 64 bits
of that session as a local framing discriminator; the enclosing carrier keys and
profile enforce the full 128-bit session and direction. The truncated field is
not standalone authentication. Message IDs are monotonic, never wrap, and the
receiver rejects gaps, malformed fragments, expired assembly or invalid decoded
native lengths. No native TCP window or checksum is rewritten.

One bounded reader task and one bounded writer task own the carrier packet
handles. Each uses a one-source handoff; a writer completion acknowledgement prevents
queuing another source while the previous source remains actor-owned; the writer retains its exact source
until carrier admission resolves. A single task owns the nonblocking PacketDevice
and polls actual device receive/transmit. It retains at most one encoded outbound
native frame and its count-bounded fragment batch, one incomplete inbound frame,
and a configured count/byte-bounded native output queue, in addition to explicitly
bounded carrier storage. A maximum-plus-one device read buffer detects oversize
input before negotiated MTU admission. No unbounded per-packet task spawning. A clonable read-only Observer reports
actual native ingress/delivery and successful source admission/receive counts,
outbound fragment count/bytes, incomplete reassembly count/reserved bytes, native
queue count/bytes and actual carrier TLS-message progress. Retention and TLS
fields describe the last completed actor iteration and can lag a mid-iteration
error or cancellation, including when `stopped` is true. They do not promise an
exact final retained inventory. Event counters advance at their documented
handoff. These observations are not remote delivery credits or performance metrics.

Reserve a handoff before consuming its source. A full native output queue stops
reassembly/receiver consumption; a blocked carrier stops native ingress. Native
WouldBlock retains the exact original frame. Actual native-delivery counters
advance only after `PacketDevice::transmit` succeeds. Carrier receipt/application
handoff is not native delivery. Reverse user data and retained TLS control remain
independently serviced while one native direction is blocked. A stall lasting
beyond configured retry/lease/reassembly bounds is an explicit error, never silent
drop or evidence of adaptive active credit.

Initial scope is one common FIFO data channel with system traffic policy. All
user packets, including TCP control/probes and Ethernet ARP/opaque frames, use
that same bounded path. TAP preserves endpoint/system algorithms. TUN active
credit, weighted MUX, FEC, aligned records and hot switching need separate reviewed
adapters and are not implied by making this carrier device-capable.

## Termination and later client/native gates

`run` is a long-lived pump. Unexpected EOF, malformed authenticated records,
expired reassembly, terminal carrier state and device errors end with explicit
failure. On error, task abort and joins share one `first_error + task_shutdown_timeout`
deadline; task handles remain owned until joined. Cancellation drops its bounded
JoinSet and original control owner; it
is not a clean native-shutdown receipt. The carrier's explicit close still proves
its own source/application handoffs, not the adapter's pending native packets.
A future distributed upper-layer quiescence barrier is required before promising
clean native shutdown while peers may still originate device packets.
Its additive typed capability and exact fence proposal is now recorded in the
[native distributed quiescence design](openvpn-native-drain.md); it is not implemented.

The one-slot source handoff carries either one complete source or its actual
reader error. The reader reserves this slot before receiving and publishes an
error before returning that same error through task supervision. Selecting
source readiness before task readiness therefore cannot erase the reported
cause. Both copies preserve `io::ErrorKind` and any `raw_os_error`; non-OS
diagnostic copies are limited to 512 UTF-8 bytes. The independent owner health
check reports the observed full/paired lane terminal enums and closing flags.
`Timeout` denotes an actual carrier deadline outcome without identifying which
deadline expired. Unreported EOF remains EOF; it is never guessed to be
inactivity. This diagnostic fix does not change any queue or deadline.

After the adapter passes real paired/full memory-device tests, propose explicit
shared client settings and mandatory separately provisioned admission/cookie key
files. Keep the existing `--carrier udp` TCP-bootstrap behavior distinguishable
from standalone selection. No secret bytes in status, error text, canonical public
digests or command-line values. Provisioning permissions, TLS buffer limits and
listener-wide resources require review before exposing a client flag.

Native qualification uses journal-owned namespaces, immutable helper binaries,
TAP/TUN or fixed VXLAN devices, unchanged host routes/qdiscs, and retained captures.
Receipts must prove only UDP outer sockets, complete path MTU with offloads disabled,
actual payload integrity, paired directions, impairment/backpressure behavior,
finite cancellation and cleanup. Finite native tests do not establish arbitrary
middlebox acceptance, performance, interoperability or active-probe invisibility.
The first [finite native observations](openvpn-native.md#finite-outcome-checkpoint)
now retain two failed unchanged two-second restoration probes beside one passing
short-recovery case and one passing expected-terminal idle-loss contract. All are
clean TUN/half with successful namespace cleanup; the wider native gate stays open.

## Verification checkpoint

`cargo test -p l2tunnel-runtime --offline openvpn -- --test-threads=1` passed
six focused tests. They include eight full/paired × TAP/TUN × None/LZ4 combinations
with byte-exact transfers up to 65,000 native bytes; both duplex profiles under a
blocked native receiver with reverse packet and fresh TLS-message progress;
binding rejection before device reads; authenticated malformed, gapped and
expired fragments; explicit incomplete close with pending native packets; and
cancellation followed by rebinding every original UDP socket. These are local
Linux loopback/memory-device observations, not kernel TAP/TUN or performance
qualification. The source was added after the wave-6 aggregate receipt; a fresh
coordinated `tools/check.py` receipt is now recorded in [wave 7](../../work/implementation-wave7/validation.json):
549 Rust tests including doctests and 39 Python tests, with stable source hashes.
After that snapshot, `cargo test --offline -p l2tunnel-runtime openvpn::tests --
--nocapture` passed eight focused tests including deterministic source-first and
task-first terminal observation, native OS error preservation, bounded Unicode
diagnostics, and unreported EOF versus actual lane terminal state. A fresh
coordinated aggregate for this diagnostic change passed in
[wave 8](../../work/implementation-wave8/validation.json): 587 Rust tests including
doctests and 46 Python tests, with stable source hashes.

- [x] [MOD-OVPNDEV-01] Approve exact native API, canonical policy and source ownership before implementation. Evidence: [frozen API and ownership contract](#api-and-source-ownership), [queue and wire bounds](#one-recovery-owner-bounded-native-ownership).
- [x] [MOD-OVPNDEV-02] Bind actual full/paired carrier capabilities to native layer/config and reject mismatch before device reads. Evidence: [Link verification](../../crates/l2tunnel-runtime/src/openvpn.rs), [binding tests](../../crates/l2tunnel-runtime/src/openvpn_tests.rs).
- [x] [MOD-OVPNDEV-03] Compose checked frame codec/fragmentation/reassembly without a second recovery or pacing owner. Evidence: [single-recovery adapter](../../crates/l2tunnel-runtime/src/openvpn.rs), [fragment failure tests](../../crates/l2tunnel-runtime/src/openvpn_tests.rs).
- [x] [MOD-OVPNDEV-04] Retain bounded originals and source handoffs under native/carrier pressure; keep reverse/control service alive. Evidence: [bounded ownership and pressure tests](../../crates/l2tunnel-runtime/src/openvpn_tests.rs).
- [x] [MOD-OVPNDEV-05] Test genuine full/paired TAP/TUN None/LZ4, large fragmented packets, stalled consumers, invalid/gapped/expired records and cancellation ownership. Evidence: [six focused tests](../../crates/l2tunnel-runtime/src/openvpn_tests.rs), [finite checkpoint](#verification-checkpoint).
- [x] [MOD-OVPNDEV-06] Review provisioning/TLS bounds and add explicit shared client selection after concurrent CLI ownership is released. Evidence: [provisioning and TLS review](openvpn-client.md), [client and CLI](../../crates/l2tunnel-client-core/src/openvpn.rs).
- [ ] [MOD-OVPNDEV-07] Run owned native full/half TAP/TUN capture/MTU/payload/cleanup qualification and record exact finite results.
- [ ] [MOD-OVPNDEV-08] Add a distributed native quiescence barrier before claiming clean device-level shutdown.
- [ ] [MOD-OVPNDEV-09] Integrate TUN active credit, common configured MUX/QoS, FEC/aligned and hot-switch profiles through separately tested adapters.
- [x] [MOD-OVPNDEV-10] Refresh coordinated all-workspace formatting/lint/test/rustdoc and Python checks for this adapter source. Evidence: [stable wave 8 aggregate including terminal-order diagnostics](../../work/implementation-wave8/validation.json).
