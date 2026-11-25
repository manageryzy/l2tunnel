# VXLAN codec and VTEP module

Scope: a portable bounded standard VXLAN header/Ethernet codec (`l2tunnel-vxlan`),
a pure clock-injected multi-domain VTEP policy engine (`l2tunnel-vxlan::vtep`),
and the safe nonblocking UDP device adapters (`l2tunnel-platform-vxlan`:
point-to-point `VxlanDevice` and multi-peer `VxlanVtepDevice`) attached to the
Common authenticated session runtime (`--vxlan-bind`, `--vxlan-peer`, `--vni`
on `--layer tap`). Public protocol crates remain free of Tokio, OS handles, and
real clocks; privileged Linux kernel bridge/VXLAN/netem interoperability remains
tracked separately under `VX-08`.

## Key interfaces

- `Vni::new(u32) -> Result<Vni, Error>` validates the 24-bit wire value. Zero is a
  structurally valid value; deployment policy decides whether it is usable.
- `encode(vni, ethernet_frame, output) -> Result<usize, Error>` writes an 8-byte
  VXLAN header plus a complete Ethernet frame, without changing the output on a
  validation/capacity error. No FCS is inserted or removed.
- `decode(datagram, max_frame_bytes) -> Result<Packet<'_>, Error>` borrows the frame
  and performs no allocation. Accept the base VXLAN I flag and reject unsupported
  flags/reserved fields; VXLAN-GPE/GBP are explicitly different unsupported formats.
- `DomainMap::new(max_entries)`, `authorize(vni, domain)`, `lookup(vni)`, `remove(vni)`
  bound the configured mapping. A different domain for an existing VNI is rejected
  until explicit remove/reconfigure. This does not authenticate a network peer.
- `vtep::Vtep` (`crates/l2tunnel-vxlan/src/vtep.rs`) implements pure,
  clock-injected (`now_micros: u64`) multi-domain VTEP switching: mode/layer
  capability validation (`validate_mode`, rejecting TUN+VTEP and recursive VXLAN),
  outer UDP checksum semantics (`validate_outer_udp_checksum`), non-fragmenting
  `OverheadBudget` path-MTU calculations (IPv4/IPv6 + UDP + VXLAN + tunnel
  overhead, inner L3 vs VLAN L3 vs frame bounds, jumbo support), explicit
  `VlanPolicy`, bounded per-domain and global FDB with aging/MAC-move rate limits,
  static entry precedence, deterministic oldest-dynamic eviction and peer-removal
  purging, aggregate BUM byte/packet/replica/per-peer rate limiting, split-horizon
  (`EgressSource::RemotePeer`), and loop-forming endpoint validation.
- `VxlanDevice` and `VxlanVtepDevice` (`crates/l2tunnel-platform-vxlan`) own
  nonblocking unconnected IPv4/IPv6 UDP sockets implementing `PacketDevice`
  (`PacketLayer::Ethernet`) and Unix `AsRawFd`, allowing direct attachment to
  authenticated Common sessions via `l2tunnel-client-core`.

A packet's source identity is supplied by an authorized runtime; decoding cannot
prove that a sender may inject into a VNI. User frames resembling internal L2
management remain ordinary Ethernet bytes. Internal management never uses this
codec to reach a user bridge.

## Limits and errors

Minimum Ethernet length is 14 bytes. Maximum accepted frame size is a caller
policy up to 65,535 bytes. The codec has no heap allocation on decode and writes
only after all input/length checks pass. MTU/UDP length, fragmentation, authentication
and checksum policy belong to the caller. Domain entries are finite and count
limits are enforced before insertion. Parsing verifies all header bytes and does
not inspect Ethernet contents beyond length; unsupported inner EtherTypes preserve
full bytes rather than being rejected.

## TODO and acceptance

- [x] [MOD-VX-01] Implement byte-exact base VXLAN encoding/decoding and checked VNI values. Evidence: [implementation/tests](../../crates/l2tunnel-vxlan/src/lib.rs).
- [x] [MOD-VX-02] Test truncated headers/frames, flags/reserved fields, exact limits and undersized-output atomicity. Evidence: [implementation/tests](../../crates/l2tunnel-vxlan/src/lib.rs).
- [x] [MOD-VX-03] Implement bounded explicit VNI/domain mapping with conflict and capacity errors. Evidence: [implementation/tests](../../crates/l2tunnel-vxlan/src/lib.rs).
- [x] [MOD-VX-04] Test mapping isolation/updates and preservation of arbitrary VLAN/IPv6/management-looking inner bytes. Evidence: [implementation/tests](../../crates/l2tunnel-vxlan/src/lib.rs).
- [x] [MOD-VX-05] Add facade export and cross-module validation under the complete workspace checks. Evidence: [integrated check receipt](../../work/implementation-wave1/validation.json).
- [x] [MOD-VX-06] Implement remote peer allowlists, live UDP/VTEP, FDB aging, BUM accounting and loop prevention; qualify Linux interoperability separately. Evidence: [pure VTEP engine](../../crates/l2tunnel-vxlan/src/vtep.rs), [multi-peer UDP VTEP adapter](../../crates/l2tunnel-platform-vxlan/src/vtep.rs), [loopback VTEP tests](../../crates/l2tunnel-platform-vxlan/src/tests.rs), [Common CLI VXLAN wiring](../../crates/l2tunnel-client-core/src/secure_udp/cli.rs), [authenticated Common + VTEP integration tests](../../crates/l2tunnel-client-core/src/service/tests/secure_udp_vxlan.rs), and [Linux bridge/VLAN/VXLAN/netem namespace receipt](../../work/vxlan-live-20261125/receipt.json) ([VX-08](../overlay-and-carriers.md#vxlan-support)).

Reference: [RFC 7348](https://www.rfc-editor.org/rfc/rfc7348.html). The codec implements
that base packet envelope, not an alternative UDP transport cover for l2tunnel.
