# Swift profile: packed ordered channels over paced protected UDP

Status: integration-tested on Linux TAP in owned unprivileged network
namespaces. The explicit `--record-profile swift` CLI profile carried sixteen
verified CUBIC flows within 2% of the Python simulator, rerun at the tunnel's
real per-datagram overhead, on all four self-test paths: 79.7–80.5 Mbit/s
against 80.72 on the 100/10 Mbit/s, 70 ms, 15% loss reference path. These are
finite runs in one environment. Real devices, privileged host namespaces, IPv6
underlay runs, Windows/Android, remote CI and long-duration soak are not
covered.

- [x] [SW-01] Pure bounded engine: pack native packets across fixed-capacity source symbols, send each once, recover by receiver-requested retransmission with optional sliding-window GF(256) repairs, and deliver one exact ordered stream. Evidence: [engine](../../crates/l2tunnel-swift/src/lib.rs) with [loss, reordering, tail, flush, back-pressure and malformed-input tests](../../crates/l2tunnel-swift/src/tests.rs).
- [x] [SW-02] Stateless connection classification into ordering channels for Ethernet (one VLAN tag) and raw IPv4/IPv6, with fragments kept together and unknown input on channel zero. Evidence: [classifier and tests](../../crates/l2tunnel-swift/src/flow.rs).
- [x] [SW-03] Exact TCP/IPv4 header records on an ordered channel: delta fields, reconstructed length and checksums, compressor self-verification and literal fallback. Evidence: [codec and exactness, mutation and rejection tests](../../crates/l2tunnel-swift/src/header.rs).
- [x] [SW-04] Runtime: ChaCha20-Poly1305 datagrams keyed from the TLS exporter, packet-number replay window, IP-byte token-bucket pacing, readiness-driven device and socket I/O, aggregated feedback and bounded delivery batches. Evidence: [runtime with protected-engine, channel-independence, pacing, replay and two-endpoint loopback tests](../../crates/l2tunnel-runtime/src/swift.rs).
- [x] [SW-05] Shared client module and CLI selection with the complete policy bound into the authenticated session digest and rejected before credentials or sockets when invalid. Evidence: [client module](../../crates/l2tunnel-client-core/src/swift.rs), [CLI frontend](../../crates/l2tunnel-client-core/src/swift/cli.rs).
- [x] [SW-06] Unprivileged Linux TAP self-test under HTB and netem with verified payload, clean close, same-window wire accounting and layer-2 checks in both directions (ARP, full-MTU unfragmented ping, UDP from 1 to 1472 bytes). Evidence: [tool](../../tools/selftest.py), [helper tests](../../tools/test_selftest.py), [clean](../../work/swift-selftest41/clean.json), [delay](../../work/swift-selftest41/delay.json) and [1% loss](../../work/swift-selftest41/loss1.json) receipts.
- [x] [SW-07] Match the simulator at equal byte overhead within 2.5% on every self-test path. Evidence: [three reference runs](../../work/swift-selftest41/impaired-1.json), [kernel-default RTO run](../../work/swift-selftest41/impaired-kernel-rto.json), [simulator on the reference path](../../work/swift-simulator-reference38/output.log) and [on the control paths](../../work/swift-simulator-reference40/output.log).
- [x] [SW-12] Read-only `status` over the private local control socket, reporting phase and counters of the live session. Evidence: [response and tests](../../crates/l2tunnel-client-core/src/swift/cli.rs); every [self-test receipt](../../work/swift-selftest41/impaired-1.json) queries both endpoints with the real `status` command.
- [ ] [SW-08] Route swift through the shared service API with disconnect and reconnect; today the CLI owns the session directly and its control socket answers status only.
- [ ] [SW-09] Qualify on real devices and privileged host namespaces, IPv6 underlay, TUN, long soak, CPU and memory.
- [ ] [SW-10] Rekeying and packet-number or source-sequence rollover without reconnecting; a session ends when its 32-bit per-channel source sequence is exhausted.
- [ ] [SW-11] Negotiated epoch switching between swift and the other record profiles; the profile is startup-only.

## Why this design

`simulator/README.md` documents the 80/20 candidate as compact selective-repeat
ARQ with the reversible `tcp_delta` header profile over independent per-flow
ordering, not as a coded stream. At 15% independent loss every scheme needs at
least 17.6% extra datagrams; retransmitting exactly what was lost reaches that
bound, while proportional repairs sized for 15% cost about 20.5% and still leave
a residue. The engine therefore defaults to retransmission only and keeps
sliding-window repairs as an explicit option for latency-sensitive use.

Three measurements shaped the rest:

- One ordered stream for all connections let every loss delay every
  connection. Sixteen channels restored independent ordering.
- A partial symbol sent immediately costs a full datagram header for a few
  bytes. Partial symbols wait up to 1 ms for more native bytes.
- In-order delivery releases long runs at once. Recovered packets are written
  to the device in batches of 32 between socket reads, and the socket requests
  an 8 MiB receive buffer, which the kernel clamps to its configured maximum
  (416 KiB effective in the recorded runs). Before this the receiver itself
  dropped about 1.4% of datagrams.

## Wire format

Every UDP payload is `[packet number u64][ciphertext][tag 16]`. The packet
number is the AEAD nonce, the replay identity and the repair coefficient seed.
Keys are `KeyPurpose::Data` exporter secrets for each direction on lane 0. The
plaintext body starts with one byte holding the kind in bits 0–1 and the channel
in bits 2–7.

| Kind | Body after the leading byte |
| --- | --- |
| 0 source | sequence `u32`, 1 to `symbol_bytes` packed bytes |
| 1 repair | end sequence `u32`, covered count `u8`, GF(256) combination of `[length u16][payload]` vectors |
| 2 feedback | base `u32`, end `u32`, missing in newest window `u16`, request count `u8`, request offsets `u16` each; one block per channel, concatenated |

Packed bytes are records `[length u16][record]`. A record is tag `0` literal,
`1` literal that also sets a connection context, or `2` delta: a flag byte and
only the changed fields (identification, sequence, acknowledgement, control
word, timestamp value and echo) as modular varints. With a 1500-byte path MTU
the datagram body is 1448 bytes and a source symbol carries 1440.

## Bounds and failure behavior

Per channel: at most 4096 unconfirmed sources, at most `2 * window` pending
equations, one unfinished packet of receive stream beyond the flow bound, eight
header contexts. Across channels: one shared packing-queue budget of about 20 ms
of the send budget. A packet that does not fit is refused before compression so
the two header contexts cannot diverge.

Unauthenticated, replayed or mis-sized datagrams are counted and ignored.
Authenticated data that is structurally inconsistent ends the session with an
error. Socket errors that describe the path (full buffer, unbound peer,
firewall or connection-tracking drop, missing route) are treated as loss; the
loopback test first exposed this as a transient `EPERM`.

## Measured results

Unprivileged namespaces, `tools/selftest.py`, sixteen CUBIC flows, release
build, TAP devices bridged to the traffic hosts, shaper counting IP bytes,
tunnel budget 99% of the shaped rate:

| Path | Inner minimum RTO | Forward goodput | Simulator at equal overhead | Ratio |
| --- | --- | --- | --- | --- |
| 100/10 Mbit/s, 70 ms, 15% loss | 1000 ms | 79.74, 80.50, 79.91 Mbit/s | 80.72 Mbit/s | 98.8–99.7% |
| same | kernel default 200 ms | 79.23 Mbit/s | 79.04 Mbit/s | 100.2% |
| 100/10 Mbit/s, 70 ms, 1% loss | 1000 ms | 93.41 Mbit/s | 94.55 Mbit/s | 98.8% |
| 100/10 Mbit/s, 70 ms, no loss | 1000 ms | 93.69 Mbit/s | 94.61 Mbit/s | 99.0% |
| 100/10 Mbit/s, 2 ms, no loss | 1000 ms | 92.80 Mbit/s | 94.58 Mbit/s | 98.1% |

Each run measured 30 s after a 10 s warm-up; payload was verified, all sixteen
flows closed cleanly, the layer-2 checks passed in both directions and both
endpoints answered `status`. The simulator numbers are the mean of three
replications. An earlier set of the same runs is kept in
`work/swift-selftest39/`. The tunnel paces at 99% of the shaped rate while the
simulator uses all of it, which accounts for most of the remaining difference.

Retransmissions were 17.5–17.7% of sources on the 15% path. The simulator's
published candidate uses a 36-byte outer header and no authentication bytes and
reaches 82.3 Mbit/s; this tunnel's datagram carries 57 bytes of IPv4, UDP,
packet number, AEAD tag and source header, so the comparison above reruns the
same study function with `authentication_bytes=21`. Before this profile the
existing rolling profile measured 18.1 Mbit/s on the clean path in the same
harness.

Simultaneous reverse bulk traffic on the 15% path gave 58.2 and 8.1 Mbit/s: the
10 Mbit/s reverse budget is then shared between reverse data and forward
acknowledgements. That is a distinct workload, not the reference.
