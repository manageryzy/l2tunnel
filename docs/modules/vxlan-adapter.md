# Point-to-point UDP VXLAN device adapter

Status: implemented and tested with real loopback UDP sockets on Linux,
2026-11-12 (Asia/Tokyo). The design was written before code. This adapter connects one
configured UDP VTEP to the existing `PacketDevice` Ethernet boundary. It uses
[the portable VXLAN codec](vxlan.md) and implements only the configured-peer subset
of [the overlay design](../overlay-and-carriers.md). It does not learn peers/MACs,
implement a forwarding database, replicate BUM traffic or authenticate raw VXLAN.

## Public API and ownership

```rust
VxlanDevice::bind(bind_addr: SocketAddr, config: VxlanConfig)
    -> io::Result<VxlanDevice>;
VxlanDevice::from_socket(socket: UdpSocket, config: VxlanConfig)
    -> io::Result<VxlanDevice>;
VxlanDevice::local_addr() -> io::Result<SocketAddr>;
VxlanDevice::peer_addr() -> SocketAddr;
VxlanDevice::max_frame_bytes() -> usize;
VxlanDevice::stats() -> VxlanStats;
```

`VxlanConfig` has `peer: SocketAddr`, `vni: Vni`, `max_frame_bytes: usize` and
`receive_budget: usize`. `PacketDevice<Error = io::Error>` reports
`PacketLayer::Ethernet`, receives one whole opaque Ethernet frame and transmits
one complete VXLAN datagram. Example runtime settings are a 1600-byte frame limit
and 32 datagrams of receive work per call. The caller must choose a frame limit
consistent with the actual underlay path budget.

`bind` explicitly owns a new UDP socket; port zero is allowed for a local ephemeral
bind. `from_socket` takes ownership of a prebound, unconnected socket and makes it
nonblocking. The caller must not retain another active clone of that socket.
The configured peer destination port must be nonzero and its address must be
unicast/non-unspecified. Bind and peer address families must match. No code opens
TAP/TUN, changes routes, configures a bridge, elevates privileges or starts threads.

## Receive filtering and bounded work

Each receive call attempts at most `receive_budget` datagrams, bounded to 1..4096.
`WouldBlock` returns `Ok(None)`. Reaching the work budget after discarded datagrams
also returns `None` and increments a distinct counter; the runtime can poll again.
Other socket errors are returned as `io::Error` and counted.

Accept input only from the configured remote IP, then apply strict base VXLAN
header validation, the configured VNI and the inner frame bound. Deliberately do
not require a fixed remote **source port**: Linux VXLAN may select that port using
inner flow entropy. Egress always targets the configured destination port. An
IP/VNI allowlist is an ingress filter, not cryptographic peer authentication.
All accepted bytes are ordinary user Ethernet, including VLAN-tagged and
management-looking payloads; no EtherType/MAC grants session-control privileges.

The portable UDP payload ceiling is 65,507 bytes; subtracting the eight-byte VXLAN
header limits configured inner frames to 65,499 bytes. The receive scratch buffer
is exactly `max_frame_bytes + 8 + 1` bytes. That extra sentinel byte means a
truncated or oversized datagram cannot be mistaken for an exact in-bounds frame:
any returned length above the configured datagram bound is discarded. Platforms
that return a socket error for truncation expose that error instead of accepting
partial bytes. All allocation sizes follow validated local configuration.

Malformed, foreign-IP, wrong-VNI and oversized packets are dropped with separate
saturating counters. Classification uses the first failed filter. If a valid frame
cannot fit the caller's output, it is consumed/dropped, counted and returned as
`InvalidInput`; output remains unchanged. No hidden queue retains it. Provide a
buffer of at least `max_frame_bytes()` to avoid this failure. Counters distinguish
successful Ethernet bytes from UDP receive attempts; no truncated wire-byte total
is reported as complete traffic accounting.

## Transmit behavior and limits

Validate complete Ethernet minimum length and configured maximum before encoding.
The portable codec writes one bounded VXLAN packet into reusable scratch storage;
one `send_to` targets the fixed peer. A short UDP write is an explicit error.
`WouldBlock` is returned to the caller for its existing bounded queue/retry policy;
the adapter neither retries invisibly nor creates duplicate user packets.

This adapter performs no userspace IP fragmentation, PMTU discovery, congestion
control or dynamic MTU change. Disabling kernel-generated IP fragmentation and
handling platform PMTU signals need a separate safe socket-option integration
before claiming full RFC 7348 path behavior. Current buffer bounds are memory/wire
format limits, not proof that arbitrary jumbo frames fit a physical underlay.

## Kernel checksum and segmentation boundary

`PacketDevice` carries complete Ethernet bytes and no kernel checksum/GSO metadata.
In an initial isolated Linux kernel-VTEP smoke run, ICMP crossed the adapter while
TCP SYNs arrived with an unfinished inner TCP checksum. The source VXLAN device
had transmit checksum and segmentation offloads enabled; the byte-only userspace
UDP path did not preserve the associated offload metadata. That observation does
not justify rewriting arbitrary inner packet checksums in this adapter.

Kernel-VTEP laboratory qualification must explicitly disable checksum and
segmentation offloads on the lab's owned VXLAN/veth interfaces, record the actual
`ethtool` settings and validate captured complete packets. This is a controlled
test precondition, not general offload support. A future integration must either
guarantee fully materialized inner packets at its boundary or carry and correctly
consume the required metadata through a separately reviewed device contract.
Never change offloads on unrelated host interfaces for this test.

## Work checklist

- [x] [MOD-VTEP-01] Implemented validated explicit bind/prebound ownership and nonblocking Ethernet PacketDevice methods. Evidence: [native adapter](../../crates/l2tunnel-platform-vxlan/src/lib.rs), [socket tests](../../crates/l2tunnel-platform-vxlan/src/tests.rs).
- [x] [MOD-VTEP-02] Implemented fixed peer-IP/VNI filtering, variable source-port acceptance and one-datagram egress. Evidence: [native adapter](../../crates/l2tunnel-platform-vxlan/src/lib.rs), [socket tests](../../crates/l2tunnel-platform-vxlan/src/tests.rs).
- [x] [MOD-VTEP-03] Implemented receive-work/allocation bounds, truncation sentinel, atomic output and explicit counters/errors. Evidence: [native adapter](../../crates/l2tunnel-platform-vxlan/src/lib.rs), [boundary tests](../../crates/l2tunnel-platform-vxlan/src/tests.rs).
- [x] [MOD-VTEP-04] Tested real loopback bidirectionality, VLAN/opaque frames, malformed/wrong-VNI/foreign-IP input and size limits on Linux. Evidence: [native socket tests](../../crates/l2tunnel-platform-vxlan/src/tests.rs).
- [x] [MOD-VTEP-05] Integrate native CLI/runtime selection and isolated Linux kernel-VTEP interoperability receipts. Evidence: [Common CLI VXLAN selection](../../crates/l2tunnel-client-core/src/secure_udp/cli.rs), [end-to-end Common VTEP tests](../../crates/l2tunnel-client-core/src/service/tests/secure_udp_vxlan.rs), local Linux isolated-namespace kernel-VTEP lab receipt `work/vxlan-live-20261125/receipt.json` (185.37 Mb/s clean, 44.60 Mb/s ARQ / 66.44 Mb/s FEC under 100/10 impaired, 0 corrupt bytes).
- [ ] [MOD-VTEP-06] Add safe platform DF/PMTU behavior, underlay MTU change handling and IPv6/native Windows qualification.
- [x] [MOD-VTEP-07] Implement separately reviewed multi-peer FDB/BUM/provenance/loop controls and authenticated domain configuration if required. Evidence: [pure multi-domain VTEP engine](../../crates/l2tunnel-vxlan/src/vtep.rs), [multi-peer UDP VTEP adapter](../../crates/l2tunnel-platform-vxlan/src/vtep.rs), [socket and multi-peer tests](../../crates/l2tunnel-platform-vxlan/src/tests.rs).
- [ ] [MOD-VTEP-08] Specify and qualify checksum/segmentation offload handling across the byte-only device boundary; retain explicit owned-interface offload settings in kernel lab receipts.

Loopback UDP tests are native socket evidence only. They do not establish kernel
VXLAN bridge interoperability, external reachability/authentication, PMTU behavior,
Windows/Android support, or the complete VX-* acceptance checklist.

## Local verification receipt

The following commands passed on the local Linux host:

```sh
cargo fmt --package l2tunnel-platform-vxlan
cargo test --offline --package l2tunnel-platform-vxlan
cargo clippy --offline --package l2tunnel-platform-vxlan --all-targets -- -D warnings
cargo doc --offline --package l2tunnel-platform-vxlan --no-deps
```

All eight tests passed using actual ephemeral loopback UDP sockets. The tests
exercise exact 14-byte and 65,499-byte inner frames, rejected smaller/larger
transmits, 65,507-byte UDP payloads, both directions, varying source ports,
foreign 127.0.0.2 input, wrong VNIs, malformed headers, oversized/truncated receive,
finite work budgets and caller-buffer failures. Linux-specific truncation and
foreign-loopback behavior are explicitly gated; native Windows/Android and kernel
VTEP tests remain separate evidence. No privileges or host routes were changed.
