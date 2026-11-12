# Packet classification and flow assignment

Status: implemented and locally tested parser/affinity primitive; design preceded
code. The checklist below records the verified subset. This is classification, not a
firewall, checksum verifier, IP reassembler, TCP proxy or complete MUX parity.
Parent requirements: [M2 and unified-duplex-mux](../mode-parity.md),
[architecture](../architecture.md), [implementation plan](../implementation-plan.md).

## Interfaces and ownership

`l2tunnel-packet` exposes the following runtime-independent API:

```rust
classify(PacketLayer, &[u8], ParseLimits) -> Result<Classification, ParseError>;
FlowKey::canonical_bytes() -> KeyBytes;
FlowKey::python_tcp_bytes() -> Option<[u8; 13]>;
FlowKey::crc32() -> u32;
FlowTable::new(FlowTableConfig) -> Result<FlowTable, FlowError>;
FlowTable::assign(FlowKey, Duration) -> Result<Binding, FlowError>;
FlowTable::learn(FlowKey, u16, Duration) -> Result<Binding, FlowError>;
FlowTable::preview_assign(FlowKey, Duration) -> Result<Binding, FlowError>;
FlowTable::preview_learn(FlowKey, u16, Duration) -> Result<Binding, FlowError>;
FlowTable::prepare_assign(FlowKey, Duration) -> Result<PreparedAssignment<'_>, FlowError>;
FlowTable::prepare_learn(FlowKey, u16, Duration) -> Result<PreparedAssignment<'_>, FlowError>;
FlowTable::lookup(&FlowKey) -> Option<Binding>;
FlowTable::oldest_idle(Duration) -> Result<Option<(FlowKey, Binding)>, FlowError>;
FlowTable::retire_idle(&FlowKey, Duration) -> Result<Binding, FlowError>;
FlowTable::remove_drained(&FlowKey) -> Option<Binding>;
```

Use the existing device `PacketLayer` and core `Mapping` types. Classification
borrows caller bytes and returns only fixed-size values; it allocates no packet,
per-extension or per-option storage. `Classification` contains the canonical key,
packet kind, optional Ethernet/IP/transport/ARP metadata and original/declared
lengths. IPv4/IPv6 expose DSCP and ECN without changing either. TCP flags/window
are observations only. Every original byte, including padding and unknown
protocol payload, remains owned and forwarded unchanged by the caller.

## Parsing and opaque fallback

- Ethernet has a checked 14-byte header, up to four configured VLAN tags, and a
  separately bounded captured packet length. VLAN identity includes TPID and VID;
  PCP/DEI are observations rather than new flow identities. IEEE 802.3 LLC and
  unknown EtherTypes retain opaque Ethernet classification.
- ARP validates its variable address lengths. Ethernet/IPv4 ARP uses canonical
  protocol-address pairs; other ARP formats use opaque Ethernet affinity.
- IPv4 validates version, IHL, total length and actual capture bounds. IPv6
  validates its fixed header and non-jumbo payload length. TCP data offset and
  UDP declared length are checked against the IP payload, never frame padding.
  TCP options and IP options are retained rather than decoded or rewritten.
- IPv6 walks hop-by-hop, routing, destination and AH header lengths within
  configured count/byte limits (hard ceilings 16 headers and 4096 bytes).
  Fragment headers are eight bytes. ESP and unknown next headers remain opaque.
  Extension option semantics, routing and IPsec verification remain outside this
  classifier. Zero payload length with hop-by-hop next-header is reported as an
  unsupported jumbogram candidate; no jumbo length or transport tuple is trusted.
- Both first and later IPv4/IPv6 fragments use address/protocol/fragment-ID keys
  without ports. IPv6 atomic fragments are reported explicitly and also use this
  conservative fragment key. No transport port read crosses a fragment boundary.
- Structurally truncated or inconsistent supported headers return typed errors.
  Valid unsupported protocols and configured VLAN/extension-depth exhaustion
  return `OpaqueReason`, preserving forwarding with coarser affinity. Opaque
  fallback is not a validation claim for the uninspected suffix.
- Declared IP lengths exclude Ethernet padding; observed length covers the entire
  caller packet. Checksums are neither checked nor modified because device
  offload metadata is not part of this API. A valid structural result must not be
  represented as authenticated or checksum-verified traffic.

Header references: [IPv4](https://www.rfc-editor.org/rfc/rfc791.html),
[IPv6](https://www.rfc-editor.org/rfc/rfc8200.html),
[jumbograms](https://www.rfc-editor.org/rfc/rfc2675.html).

## Canonical keys and channel parity

Sort complete endpoint address/port pairs lexicographically, never addresses and
ports independently. Include family, protocol and VLAN domain in equality.
Fragment IDs are directional datagram identifiers; normal transport keys are
bidirectional connection identities. Opaque IP protocols share an address/protocol
bucket; opaque Ethernet traffic shares MAC/EtherType/VLAN buckets. These deliberate
coarse buckets preserve admission and bounded state without inventing ports.
IEEE 802.3 length fields use one LLC protocol bucket instead of creating a new
identity for every packet length. Fragment source/destination order is retained
to separate opposite-direction datagrams that happen to use the same ID.

For untagged IPv4/TCP (TAP or TUN), CRC32 input is exactly the simulator's 13 bytes:
`06 || lower_ipv4 || lower_port_be || upper_ipv4 || upper_port_be`.
Other keys use explicit version-1 fixed-buffer canonical encoding. CRC collisions
may share a channel; equality still compares the complete key. CRC32 is affinity,
never integrity or authentication. Python byte/hash/channel golden vectors are
generated independently using its actual
[`DuplexMux._channel`](../../simulator/src/l2tunnel_sim/mux.py) implementation.

The executed Python inputs and resulting CRC32/channel-16 values were:

| Serialized input hex | CRC32 hex | Channel (16) |
| --- | --- | --- |
| `060a00000130390a00000201bb` | `0d5c7acc` | 12 |
| `06c00002090001c0000209ffff` | `fb02d3d2` | 2 |
| `0600000000ffffffffffff0000` | `55d18bd5` | 5 |
| `060a080001c0000a0800090050` | `67e9c1d3` | 3 |

The Rust golden test also checks 1/3/256 channels and both endpoint orders.
Python's complete-frame parser additionally checks IPv4/TCP checksums and rejects
all other traffic; that parser behavior is not claimed as Rust classifier parity.

Each flow table belongs to one tenant/session/epoch; VNI isolation is imposed by
the caller, not inferred from untrusted packet bytes. Capacity and channel count
are checked (1..65536 flows, 1..256 channels). IDs increase without wrap or reuse,
including after retirement. New capacity exhaustion is explicit and never evicts
an active entry. All table time is injected monotonic `Duration`.

Round-robin assigns new local entries to successive channels; learned reverse
entries do not advance the local assignment cursor, matching Python. `learn`
accepts only an already-authenticated decoded channel and rejects conflicts
before changing state. Locally observed reverse endpoints use the same key and
ID. Independent peers can still choose conflicting channels for simultaneous
opens: resolve by a negotiated owner/barrier at integration, never silently move
queued traffic. Deterministic CRC mode does not require assignment learning.

Idle age is only an eviction candidate. The caller must establish that recovery,
credit, QoS and codec state are drained before `retire_idle`/`remove_drained`.
Neither expiry nor capacity creates permission to discard outstanding traffic.
Retention is bounded by entry count and fixed-size keys, with B-tree allocator
overhead; no exact RSS claim is made.

Previews do not reserve or mutate IDs, channels or timestamps. Pipeline admission
uses an exclusively borrowed `PreparedAssignment`: `binding()` observes the
preview, dropping it changes nothing, and `commit()` installs/refreshes the exact
binding without further fallible checks. The borrow prevents intervening table
mutation while another component performs its own queue admission.

## Checklist and test matrix

- [x] [MOD-PKT-01] Define fixed-size classifier/key APIs, pure time-injected table and explicit unsupported behavior before coding. Evidence: [interfaces and ownership](#interfaces-and-ownership), [public API](../../crates/l2tunnel-packet/src/lib.rs).
- [x] [MOD-PKT-02] Implement checked Ethernet/VLAN/ARP with opaque LLC/EtherType/unsupported-format preservation. Evidence: [parser](../../crates/l2tunnel-packet/src/parse.rs), [packet tests](../../crates/l2tunnel-packet/src/tests.rs).
- [x] [MOD-PKT-03] Implement IPv4/TCP/UDP metadata and checked declared lengths, options and fragments. Evidence: [parser](../../crates/l2tunnel-packet/src/parse.rs), [packet tests](../../crates/l2tunnel-packet/src/tests.rs).
- [x] [MOD-PKT-04] Implement IPv6 traffic class, bounded extensions, fragments and explicit unsupported jumbo handling. Evidence: [parser](../../crates/l2tunnel-packet/src/parse.rs), [packet tests](../../crates/l2tunnel-packet/src/tests.rs).
- [x] [MOD-PKT-05] Canonicalize endpoint pairs and VLAN domains; return stable allocation-free encoding. Evidence: [FlowKey encoding](../../crates/l2tunnel-packet/src/lib.rs), [identity tests](../../crates/l2tunnel-packet/src/tests.rs).
- [x] [MOD-PKT-06] Match Python IPv4/TCP CRC bytes, hashes and channels against independently executed golden vectors. Evidence: [Python inputs and outputs](#canonical-keys-and-channel-parity), [golden test](../../crates/l2tunnel-packet/src/tests.rs).
- [x] [MOD-PKT-07] Implement bounded RR/CRC flow table, learned-channel conflict detection and monotonic IDs. Evidence: [flow table](../../crates/l2tunnel-packet/src/flow.rs).
- [x] [MOD-PKT-08] Test all supported-header truncations, malformed lengths, depth exhaustion and unsupported forwarding. Evidence: [focused tests and finite mutation corpus](../../crates/l2tunnel-packet/src/tests.rs).
- [x] [MOD-PKT-09] Test first/later/atomic fragment affinity without false ports and reversed transport identities. Evidence: [fragment and reverse endpoint tests](../../crates/l2tunnel-packet/src/tests.rs).
- [x] [MOD-PKT-10] Test table capacity, idle boundary, monotonic time/ID exhaustion and simultaneous reverse conflicts. Evidence: [table behavior tests](../../crates/l2tunnel-packet/src/tests.rs), [terminal ID test](../../crates/l2tunnel-packet/src/flow.rs).
- [x] [MOD-PKT-11] Run formatting, focused tests and warning-denied Clippy; record actual local receipts. Evidence: [local verification receipt](#local-verification-receipt).
- [ ] [MOD-PKT-12] Integrate classification into common MUX and transparent-TUN QoS; TAP system TCP remains unchanged.
- [ ] [MOD-PKT-13] Negotiate simultaneous-open ownership and drain-safe distributed RR binding lifecycle.
- [ ] [MOD-PKT-14] Add fuzz corpus and native offload/fragment/VLAN/IPv6 qualification; no complete parity claim before these gates.
- [x] [MOD-PKT-15] Add nonmutating assign/learn previews and borrow-bound prepared commits for pipeline admission transactions, with exact next-binding tests. Evidence: [transaction implementation/tests](../../crates/l2tunnel-packet/src/flow.rs), [pipeline-wave receipt](pipeline.md#local-verification-receipt).

## Local verification receipt

Executed on local Linux, 2026-11-11 UTC:

```text
cargo fmt -p l2tunnel-packet
cargo test --offline -p l2tunnel-packet
  17 unit tests and 1 doctest passed
cargo clippy --offline -p l2tunnel-packet --all-targets -- -D warnings
  passed
PYTHONPATH=simulator/src python3 (inline golden generator)
  actual DuplexMux._channel and zlib.crc32 matched four vectors in both directions
```

The finite mutation test changes each byte of a 217-byte tagged IPv6 extension/TCP
frame through all 256 values and checks successful-result bounds. This is local
deterministic coverage, not a completed fuzzing or native packet-path gate.
The root integration pass owns `python3 tools/check.py`, native bridge/netem,
Windows/Android verification and complete MUX/parity status.
The subsequent pipeline transaction wave passes 18 packet tests and the same
doctest; its combined formatting/test/Clippy receipt is linked above.
