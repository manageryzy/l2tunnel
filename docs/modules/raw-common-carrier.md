# Original raw TCP carrier with Common records

Status: implemented in the actual original-owner runtime and shared client/service
API/strict CLI. Finite caller-owned PacketIo/Unix-device checks exercise real outer
TLS/member and inner initial Noise/member authentication, four record families,
liveness, requested/effective state and original owner release. This is not
kernel, production native CLI, platform or throughput qualification. Exact failed
attempts and their affected continuations are retained in the
[Batch12 receipt](../../work/parallel-features-20261115/parallel-batch12-scoped-validation.json).

## Reused original owners

`RawOuter::from_packet` consumes the maintained `PacketCarrier` produced by the
real TCP/TLS/member transition. Copied `AuthenticatedRaw` observations cannot
construct that capability. Initial cookie/Noise and member admission reuse the
existing setup and Joining state machines through a narrow generic I/O backing.
Their original factory deadline and actual clock origin survive every transfer.
`RawInitialParts` retains the actual adapter, private root and original tail owners.

`run_common_on_raw` consumes those parts into the existing fallible retained Driver
cell and the same Common loop. It creates no second TCP connection, socket owner,
record recovery algorithm or periodic key exchange. Swift, Aligned, Packed and
Rolling remain record algorithms inside the explicitly selected carrier.

The request binding is acyclic. Before TLS, `raw_requested_configuration` commits
the base policy/envelope, complete catalog, both role resources, complementary
covers and transaction settings into the original PairConfig digest. After the
real original transition, `new_on_raw_paired` validates the accepted packet policy
and derives the Common envelope/setup binding from that request and genuine outer
proof. Catalog geometry is explicit; constructors do not silently shrink records
or alter the requested policy.

## Actual wire and physical completion

The raw adapter retains one actual PacketCarrier, a User witness, a separate
bounded Control buffer and one bounded copied input with its original arrival.
Maintained raw RecordGeometry supplies exact IPv4/TCP and protection costs. Every
Common record retains authentication/replay and the raw phase's existing outer
protection; TCP-shaped packet traffic is not ordinary ACK-driven TCP/TLS data.
Raw physical observations do not increment UDP-byte counters.

Only the maintained sent-record token and acceptance timestamp confirm physical
completion. Encoding, bounded admission and a pending send do not confirm it.
Both occupied lanes are observed before a terminal cause propagates. Original
arrival is separate from later observation for Compact feedback and queued Rolling
input. A held ciphertext keeps its original bytes, identity, charge and deadline.
The adapter counts its actual inline owner and two buffer capacities; nested
raw/TLS/backend heap qualification remains open and the full-preallocation flag
stays false.

## Shared service installation

`Profile::new_raw` selects complete explicit raw geometry and preflights both
bootstrap directions and every catalog entry before opening I/O. `bind_raw`
accepts only observations from a genuine original owner and derives the effective
E1/configuration; it cannot import a public digest as authentication authority.
`Prepared::secure_udp_common_raw_client` and `secure_udp_common_raw_server` reuse
the existing service actor, attachment, readiness, control and cleanup lifecycle.
The strict `raw-common-carrier-v1` policy contains only carrier settings; independent
recovery/delivery remains in the complete Common catalog. The original accepted
setup deadline can only tighten the raw factory deadline before inner admission.

Portable status adds optional `raw_carrier` observations with the requested and
effective configurations, complete packet policies, actual Full/Half occupied
lanes and exact physical geometry. Original OpenVPN observations remain distinct.
The genuine paired Half shared-service case, fresh lower reconnect and accepted
setup-cap-before-I/O cases pass in
[Cases30](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-30/validation.json).
Strict raw profile parsing and requested-only CLI observations pass in
[Cases28](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-28/validation.json).
Those receipts remain failed aggregates because of other rows; production native
CLI/privileged setup and the complete RCC-03 matrix remain separate requirements.

The retained Bank is constructed directly into the existing fallible StateCell
through a callback, and raw authentication/setup has a separate boxed future from
runtime construction. These remove large simultaneous constructor/async stack
intermediates without adding threads or changing limits. Genuine service,
reconnect and existing OpenVPN checks pass on their default stacks.

Each original lane returns only genuine authenticated upper-record retirement.
Let `M = MTU - 40` be its maintained maximum protected TCP payload, `H` its actual
negotiated/scaled local horizon and `U = H - 8M` the peer DATA allowance after the
existing eight-cell reserve. The checked standalone-report threshold is
`T = max(1, (U - M) / 2)`. Existing validation proves `H >= 9M`; integer unreported
retirement `D < T` therefore leaves `D + M <= U`. Another maximum record fits
before reporting becomes eligible, including the minimum horizon where any real
upper record triggers a report. Ordinary successful output piggybacks the actual
retirement snapshot; a standalone Window uses the same bounded lane slot, quota
and horizon only when the derived threshold is reached. Physical whole-send
success alone advances the reported snapshot. WouldBlock retains the same bytes
and nonce, and Window/Ping/Pong create no reciprocal report debt.

A Window is attempted before the lane's existing physical poll, leaving newly
freed output available to upper Control. On Full, an already retained User also
gets its actual same-lane retry before a new Control can repeatedly claim that
slot; it waits for any older Control's real receipt without replacing bytes or
renewing its original cap. Half keeps its independent data/Control lane priority.
No new timer, packet loop, queue, key budget, horizon or lease is introduced.
Carrier retirement remains separate from recovery acknowledgment and native
write completion.

The exact original Full and Half runtime fixtures, direct one-way/WouldBlock and
Full upper-feedback piggyback cases, and genuine shared-service/reconnect/setup-cap
continuations pass in
[Cases36](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-36/validation.json).
The Full fixture drives real outer TCP/TLS/member and inner initial Noise/member
admission, bidirectional exact native bytes through Swift, Aligned, Packed,
Rolling and return to Swift, authenticated switches and Pong observation, unchanged
original tuples/SYN counts, and one drop of every original owner. This is finite
caller-owned PacketIo/Unix-device evidence. Earlier failed Full attempts in
Cases31/32/33/34/35 remain preserved; they are not relabelled as passes. Kernel,
production native CLI, the full blocked/late/failing Half matrix and throughput
qualification remain open.

## Preserved full requirements

- [x] [RCC-01] Pass genuine original Full TCP/TLS/member transition, initial Noise/member admission, bidirectional native bytes, authenticated four-family switches and liveness through the same Common loop, with original tuples, no new SYN and exact owner release. Caller-owned PacketIo/Unix-device evidence is distinct from kernel qualification. Evidence: [Cases36 exact Full runtime row](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-36/validation.json); finite caller-owned transport only.
- [ ] [RCC-02] Install and validate genuine original Half pair ownership, correct directional data/Control routing, original deadlines and blocked/late/failing physical receipts across both occupied lanes. A Full-only constructor is not completion.
- [ ] [RCC-03] Install the actual raw Common selection through the shared client/service API and CLI, including requested/effective carrier/configuration/capabilities, original setup/reconnect/drop behavior and preserved naming/trust policy. A runtime constructor alone is insufficient.
- [ ] [RCC-04] Complete the original raw kernel ACK/RST/firewall, privilege, sequence/PMTU/NAT, native TAP/TUN, platform/resource and matched performance gates. Preserve CONN-09/11, complete SW-11, all47 modes and the existing raw-native requirements.

Existing raw protocol/native receipts remain historical and do not qualify the
new Common composition. The caller-owned packet fixture does not prove real ISP
classification, interoperability or resistance to identification. Full/half,
service, native and performance evidence must remain separately identified.
