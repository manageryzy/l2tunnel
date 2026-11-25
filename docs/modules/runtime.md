# Authenticated stream runtime

Status: implementation in progress. This crate is an I/O boundary, not a pure
protocol crate. It uses Tokio and the maintained TLS authentication adapter.

## Interface and ownership

`RuntimeConfig { layer, duplex, max_packet, compression, queue_packets, poll_interval }` is
validated before device I/O. `Duplex::Half` is the default. Full duplex uses one
authenticated TCP/TLS connection. Half duplex uses two authenticated connections,
one bulk direction per connection; reverse TLS/control traffic remains legal.

`client_link(first, second)` and `server_link(first, second)` complete a bounded
pairing exchange before yielding a `Link`. The first connection conveys a fresh
random pairing token under TLS; the second echoes it under separately verified
TLS/member authentication. Both lanes must have matching layer/configuration and
member identity. The token is single use for this pair, never logged, and is not a
replacement for member authentication. Full duplex uses `Link::full(connection)`.
`run(device, link, config)` owns its device and authenticated streams until error,
EOF or cancellation. Initial runtime supports one peer per process.

The authenticated stream is retained: no socket replacement, sequence reset or
TLS-to-plaintext transition follows authentication. A u32 length prefix encloses
one existing checked wire record. Session/epoch/lane/direction-local packet
numbers are checked before delivery. A persistent reader future owns partial
stream reads, so cancellation of a coordinator poll never discards framing bytes.
Queues are bounded by count and maximum packet size; write backpressure pauses
device reads. Nonblocking device writes retain the pending whole packet on
`WouldBlock`. Errors terminate the link; no packet is reported delivered early.

This runtime sends explicit bounded native-layer records with optional stateless
LZ4 using carrier reliability. Management, QoS and adaptive credit integration
are explicit later gates. Half-duplex reverse TLS reads remain active for
post-handshake control. No data sequence number resets at the auth boundary. It does
not implement raw TCP, UDP, proxy TCP, automatic reconnect or privileged routing.

## Test and implementation ledger

- [x] [MOD-RT-01] Implement bounded persistent record reader/writer and validate session, sequence and layer. Evidence: [implementation/tests](../../crates/l2tunnel-runtime/src/lib.rs).
- [x] [MOD-RT-02] Implement paired authenticated half duplex and explicit full duplex. Evidence: [implementation/tests](../../work/native-wave4/receipt.json).
- [x] [MOD-RT-03] Test packet forwarding, backpressure, partial streams, invalid records and EOF using an injected device. Evidence: [implementation/tests (retired in Common cutover)](compact-wire-cleanup.md).
- [x] [MOD-RT-04] Exercise real TLS and native Linux TAP and TUN through the same runtime. Evidence: [implementation/tests](../../work/native-wave4/receipt.json).
- [ ] [MOD-RT-05] Integrate codec, management, credit, QoS and validated hot switching.
- [ ] [MOD-RT-06] Add bounded multi-peer service, reconnect and platform wrappers.
