# VXLAN codec module, draft interface v0

Scope: a portable bounded standard VXLAN header/Ethernet codec and an explicit
VNI-to-domain authorization table. It is the first concrete part of VX-03/VX-04,
not a live VTEP. The runtime continues to own UDP sockets, authorized remote peer
identity, FDB learning, BUM replication and bridge/device setup.

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
- [ ] [MOD-VX-06] Implement remote peer allowlists, live UDP/VTEP, FDB aging, BUM accounting and loop prevention; qualify Linux interoperability separately.

Reference: [RFC 7348](https://www.rfc-editor.org/rfc/rfc7348.html). The codec implements
that base packet envelope, not an alternative UDP transport cover for l2tunnel.
