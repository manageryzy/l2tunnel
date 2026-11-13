# Bounded carrier appearance codecs

Status: **implemented and protocol-tested pure codecs**, 2026-11-13 (Asia/Tokyo).
The design/API was recorded before restoring implementation code and accepted in
parent implementation review; this does not record an owner design selection.
The source-stable local aggregate checker passed. Actual selected-client runtime
composition and native/ISP evidence remain separate gates below.
The [architecture](../architecture.md), [carrier contracts](../overlay-and-carriers.md),
[secure session](secure-session.md) and full mode-parity requirements remain in
force. No genuine QUIC, OpenVPN or HTTPS implementation is replaced by this work.

## Scope and frozen API

Implement two real bounded byte codecs: QUIC-like header appearance and the
minimal RTP-like media cover. Both wrap opaque, independently authenticated bytes;
they do not implement cryptography, replay, reliability, congestion control, socket
ownership, clocks, TAP/TUN or a runtime. The library is allocation-free, `no_std`
and forbids unsafe code. It neither asserts that a handshake succeeded nor grants
management privileges based on any outer field.

The immutable checked configuration is:

```rust
Config::new(
    appearance: Appearance,       // QuicLike | MediaLike
    ids: ConnectionIds,           // local/peer ConnectionId([u8; 8])
    media: MediaConfig,           // local/peer Ssrc(u32), seven-bit payload_type
    limits: Limits,               // max_packet_bytes, max_protected_bytes
) -> Result<Config, Error>;
```

The packet operations are:

```rust
Config::appearance() -> Appearance;
Config::limits() -> Limits;
Config::overhead(phase: Phase, protected_bytes: usize) -> Result<usize, Error>;
Config::encode(meta: PacketMeta, protected: &[u8], output: &mut [u8])
    -> Result<usize, Error>;
Config::decode(packet: &[u8]) -> Result<Decoded<'_>, Error>;
```

`PacketMeta` contains `Phase::{Handshake, Established}`, `PacketNumber(u32)` and
`MediaTimestamp(u32)`. The caller supplies all fields; the codec has no counters
or clock. The timestamp is the caller's wrapping media timestamp, not a sampled
wall clock. `Decoded` borrows the exact `protected` body and reports its declared
phase, `OuterSequence::{Quic(PacketNumber), Media(u16)}` and an optional media
timestamp. It never reconstructs missing RTP sequence high bits. These outer
numbers are not the secure session's nonce, replay identity or delivery receipt.

Each endpoint uses complementary configuration: outgoing QUIC destination is
`peer`, incoming destination must be `local`; Initial source IDs are also checked.
Media emits `local_ssrc` and requires `peer_ssrc` on receive. Identifiers and SSRCs
are routing/structural checks, not trusted peer identities. Zero-valued identifiers
are representable. The selected profile, IDs and resource bounds must be bound by
the common secure-session configuration before this becomes a runtime capability.

## QUIC-like exact layout

Handshake packets use this fixed profile of a QUIC v1 Initial-looking long header:

| Field | Bytes | Value |
| --- | --- | --- |
| First byte | 1 | `0xc3`: long/fixed bits, Initial type, four-byte packet number |
| Version | 4 | Big-endian `1` |
| Destination ID length and ID | 9 | `8`, then the peer's eight-byte ID |
| Source ID length and ID | 9 | `8`, then the local eight-byte ID |
| Token length | 1 | Canonical zero varint; no token bytes |
| Length | 1, 2 or 4 | Canonical QUIC varint for `4 + protected.len()` |
| Packet number | 4 | Big-endian caller value, without header protection |
| Protected body | variable | Exact opaque input |

Handshake overhead is 29 bytes for bodies of 1..=59 bytes, 30 for 60..=16,379,
and 32 for larger permitted bodies. The private profile rejects noncanonical
lengths, eight-byte length fields, tokens, alternate ID widths, versions or flags.
The declared length must consume the entire datagram; coalesced packets are not
accepted. Established packets contain `0x43`, eight-byte destination ID, four-byte
packet number and the exact body: 13 bytes of overhead.

The short header has no outer body-length field. Removing or appending body bytes
can therefore produce another structurally acceptable established packet, subject
to the configured nonempty/body bounds. Inner authentication must reject altered
records; this codec neither infers the original length nor trims zero tails.

This is explicitly header appearance, not a standards-conformant QUIC connection.
There is no QUIC TLS/CRYPTO exchange, packet/header protection, transport frame
interpretation, native ACK/congestion machinery or automatic 1200-byte Initial
padding. A standard dissector may recognize a header yet fail protected-packet or
frame decoding. The common secure session supplies our authentication/protection;
the genuine maintained QUIC carrier and its receipts remain separate.
[QUIC packet formats](https://www.rfc-editor.org/rfc/rfc9000.html#section-17),
[QUIC packet protection](https://www.rfc-editor.org/rfc/rfc9001.html#section-5)

## Minimal media exact layout

The baseline uses a 12-byte RTP v2 header with no padding, extension or CSRC list:

| Field | Bytes | Value |
| --- | --- | --- |
| Version/P/X/CC | 1 | `0x80` |
| Marker and payload type | 1 | Marker `1` for Handshake, `0` for Established; configured seven-bit PT |
| Sequence | 2 | Low sixteen bits of the caller's packet number, big-endian |
| Timestamp | 4 | Caller-supplied wrapping value, big-endian |
| SSRC | 4 | Local SSRC, big-endian |
| Private body length | 2 | Big-endian nonzero protected-body length |
| Protected body | variable | Exact opaque input |

The two-byte length belongs to our private RTP payload, not the RTP header. It
allows rejection of truncated bodies and trailing datagram bytes without trimming
real zero tails. Total overhead is 14 bytes. All seven-bit PT values are structurally
representable; deployments should explicitly choose the payload-type contract.
Marker-as-phase is this private profile's framing convention, not RTP codec
semantics or proof of authentication. There is no implicit fragmentation/padding.

This provides the requested minimal audio/video/RTP-like outer layout, not valid
encoded media or complete WebRTC. ICE/STUN/TURN, DTLS-SRTP, SCTP, SDP, codec payload
formats and browser interoperability are not implemented here. RTP header parsing,
media endpoint interoperability and classifier behavior are separate claims.
[RTP fixed header](https://www.rfc-editor.org/rfc/rfc3550.html#section-5.1)

## Bounds, errors and trust

`max_packet_bytes` is the complete encoded UDP payload ceiling, excluding IP/UDP
and any further encapsulation. It is at most 65,507. The protected-body bound is
nonzero, at most 65,535, and must fit the configured packet ceiling including the
largest header needed for that appearance. For QUIC-like, the same configuration
must support its largest body in both phases. Callers subtract actual underlay
overhead from path MTU before choosing this ceiling; no IP fragmentation is added.

Configuration, empty/oversized body, complete-packet overflow, undersized output,
truncated required fields, invalid flags/version/length and identifier mismatch
are explicit `Error` variants. Encoding checks every fallible condition before
modifying output. Decoding performs bounded structural checks and returns a
borrowed slice; it cannot authenticate that slice or its outer metadata. Neither
failure nor success updates session/replay/control state. Authenticate the inner
record and its negotiated context before acting on it. Header recognition cannot
prove ISP priority, indistinguishability or the initial-classification hypothesis.

OpenVPN's actual wire-handshake gate and real TCP/TLS-to-raw HTTPS-like requirement
remain unchanged. This codec does not enable either profile or imply a runtime
fallback. All user data still uses the common MUX/channel budget; management
remains authenticated session control with its existing bounded service contract.

## Focused test matrix and acceptance

Only the stated deliverable is checked. The executed local Linux package checks
were:

- `cargo fmt --package l2tunnel-cover` and `cargo fmt --package l2tunnel-cover -- --check`: passed.
- `cargo test --offline --package l2tunnel-cover`: passed in the parent build slot, 21 unit tests and zero doctests. The first `--locked` attempt stopped before tests because another new local workspace crate needed lock reconciliation; the integrator reconciled those local entries.
- `cargo clippy --offline --locked --package l2tunnel-cover --all-targets -- -D warnings`: passed.
- `RUSTDOCFLAGS='-D warnings' cargo doc --offline --locked --package l2tunnel-cover --no-deps`: passed.

These are package/source checks, not CI, Windows/Android builds, a privileged
network lab, a standard endpoint/dissector qualification or ISP measurements.

- [x] [CVR-01] Freeze the pure API, exact two-profile layouts, limits, error behavior, opaque-record/trust boundary and evidence scope before restoring implementation code. Evidence: the [frozen API design](carrier-appearance.md#scope-and-frozen-api) was written before code restoration, and the parent accepted it in implementation review.
- [x] [CVR-02] Implement actual caller-buffer encoding and borrowed strict decoding for QUIC-like Initial/established headers and minimal RTP-like media, with no allocations, crypto, real clocks, I/O or unsafe code. Evidence: [pure codec source](../../crates/l2tunnel-cover/src/lib.rs), source review and focused package checks above.
- [x] [CVR-03] Verify byte-exact headers, both phases/directions, canonical varint thresholds, RTP sequence/timestamp wrap and arbitrary protected bodies including all-zero/trailing-zero bytes. Evidence: [focused unit tests](../../crates/l2tunnel-cover/src/tests.rs), 21 passed.
- [x] [CVR-04] Verify every header/body truncation, trailing bytes where length-delimited, malformed flags/version/ID widths/tokens/PT/SSRC/lengths, wrong peers, empty/oversized packets and output preservation on error. Explicitly document that a short QUIC established packet has no outer body-length field. Evidence: [parser/capacity tests](../../crates/l2tunnel-cover/src/tests.rs) and short-header trust limit above, 21 passed.
- [x] [CVR-05] Pass focused formatting, warning-denied Clippy/rustdoc and unit tests, followed by the required source-stable repository checker. Record commands actually run and keep integration/CI/platform claims separate. Evidence: focused commands above and the passing [parent aggregate receipt](../../work/shared-session-primitives-20261113/validation.json), including warning-denied workspace rustdoc. Post-check ledger prose is qualified separately in the master ledger.
- [ ] [CVR-06] Compose real common-session handshake/data/control traffic through the selected cover on the original socket; qualify exact MTU/wire accounting, runtime negative paths, captures and controlled classifier/QoS comparisons without reducing OpenVPN/HTTPS/SW-11/full mode-parity scope. Codec tests alone cannot complete this task.
