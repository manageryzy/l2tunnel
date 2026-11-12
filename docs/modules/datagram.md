# Protected UDP datagram codec

Status: implemented, unit-tested and tested over real loopback UDP sockets on
Linux, 2026-11-12 (Asia/Tokyo). The design was written before implementation.
This is a bounded packet-protection library for a session already authenticated
elsewhere. It owns no socket, clock,
handshake or platform device. [The UDP carrier requirements](../overlay-and-carriers.md)
and [authentication architecture](../architecture.md) remain authoritative.
Independent UDP bootstrap, lane joining/path validation and native tunnel
integration are required later; this module does not make a UDP-only client.

## Keys, ownership and APIs

`PacketSealer::new(config, exporter_secret: &[u8; 32])` and
`PacketOpener::new(config, exporter_secret: &[u8; 32])` derive matching protection
keys from authenticated TLS-exporter material. Supply the existing auth adapter's
`export_key(KeyPurpose::Data, direction, lane_id).expose_bytes()` only after member
authentication. This crate does not depend on the auth runtime or make that call.

`DatagramConfig` contains `KeyContext { session: SessionId([u8; 16]), direction,
lane: LaneId(u32), generation: KeyGeneration(u32) }`, a `CoverProfile`, a
`Protection` selection, path MTU, complete outer overhead, maximum payload bytes,
maximum packets per key and maximum payload bytes per key. Directions are global
`ClientToServer` and `ServerToClient`, not local send/receive names. Session,
direction, lane, generation, cover and protection mode are all bound into both
key derivation and the authenticated header. A protection downgrade cannot be
selected by an incoming packet; the opener accepts only its configured suite.

The sealer starts packet numbering at zero and has no reset, Clone or key export.
Exactly one sealer may own a given derived sending key. Do not reconstruct it with
the same exporter/context after a crash or profile reload: establish a fresh
authenticated session or a never-reused key generation. Generation wrapping and
authenticated rekey coordination remain runtime work. QoS/codec hot changes must
not reset this counter. Counter exhaustion is checked; failed local length/output
validation consumes no number, while an attempted cryptographic seal consumes its
number and usage budget even if the cryptographic operation fails.

```rust
PacketSealer::seal_into(payload: &[u8], output: &mut [u8])
    -> Result<SealedPacket, Error>; // packet number and total wire length
PacketSealer::seal_vec(payload: &[u8])
    -> Result<SealedDatagram, Error>; // packet number and owned bytes
PacketOpener::open(datagram: &[u8], output: &mut [u8])
    -> Result<OpenedPacket, Error>; // packet number and original payload length
```

Both sides expose copied `Usage { packets, payload_bytes }`. Configuration caps
are at most 2^32 packets and 2^40 payload bytes per derived key, with lower operator
limits supported. These are conservative implementation limits, not a general
cryptographic lifetime proof. Every error leaves caller output unchanged; no error
or Debug implementation includes key material. Caller-owned exporter material
remains the caller's responsibility.

## Maintained cryptography and separation

Use pinned `ring = 0.17.14` for HKDF-SHA256, ChaCha20-Poly1305 and HMAC-SHA256.
HKDF extract salt is the public domain `l2tunnel/datagram/extract/v1`; info is
`l2tunnel/datagram/key/v1`, NUL, suite byte, cover byte, direction byte, session16,
lane u32 big-endian and generation u32 big-endian. Derive a 32-byte key. AEAD and
cleartext-MAC suites therefore never share a traffic key, even when supplied the
same exporter material. Derived temporary key storage uses maintained zeroize;
no claim is made that every internal stack/register copy is erased.

`Protection::ChaCha20Poly1305` encrypts the payload and authenticates the entire
clear header as AAD, adding a 16-byte tag. The 96-bit nonce is four zero bytes plus
the checked 64-bit packet number in big-endian order. Uniqueness follows from the
single monotonic counter scoped to the derived key. `ring::LessSafeKey` remains
private behind this counter owner; arbitrary nonces are not a public sealer API.
The opener must support authenticated reordering, hence accepts a packet number
from its bounded, verified packet format.

`Protection::HmacSha256` leaves payload bytes visible but authenticates every
header and payload byte with a full 32-byte HMAC tag. Verification uses ring's
constant-time API, never a handwritten comparison. There is no unauthenticated
plaintext mode. Confidentiality-off must be negotiated through authenticated
configuration before constructing either endpoint.

Official APIs checked: [ring AEAD](https://docs.rs/ring/0.17.14/ring/aead/struct.LessSafeKey.html),
[ring HMAC verification](https://docs.rs/ring/0.17.14/ring/hmac/fn.verify.html).
Cached ring HKDF source was also inspected. Dependency advisory review and
independent security review remain release gates.

## Custom cover prefixes and exact draft format

These are explicit custom data-header resemblance profiles, not implementations
of OpenVPN or QUIC. They contain no handshake and make no promise about active
probes, TLS concealment, entropy, middlebox acceptance or standard-client
interoperability. [OpenVPN's documented opcode/peer-ID layout](https://build.openvpn.net/doxygen/network_protocol.html)
is only a shape reference; QUIC needs TLS/packet/header protection and transport
state beyond its visible header shape, as explained in the overlay design.

| Cover | Prefix preceding the common header |
| --- | --- |
| `OpenVpnLike` | Four bytes: `0x48` followed by the low 24 bits of the lane ID as a peer-ID hint. The full lane ID remains in the authenticated common header. |
| `QuicLike` | Nine bytes: `0x40` followed by the first eight session-ID bytes as a connection-ID hint. No QUIC header protection, valid QUIC packet-number encoding or handshake is claimed. |

All prefix bytes are authenticated and checked exactly. The common header is
44 bytes; all integer fields are big-endian:

| Bytes | Field |
| --- | --- |
| 0..2 | `LD` magic |
| 2 | Draft version 1 |
| 3 | Cover: 1 OpenVpnLike, 2 QuicLike |
| 4 | Protection: 1 ChaCha20Poly1305, 2 HmacSha256 |
| 5 | Direction: 1 client-to-server, 2 server-to-client |
| 6..8 | Reserved zero |
| 8..24 | Full authenticated session ID |
| 24..28 | Lane ID |
| 28..32 | Key generation |
| 32..40 | Monotonic packet number |
| 40..42 | Nonzero original payload length, u16 |
| 42..44 | Reserved zero |
| 44.. | Ciphertext or plaintext payload, then the suite's exact tag |

The prefix is outside these common-header offsets. Total overhead is 64/80 bytes
for OpenVpnLike AEAD/MAC and 69/85 bytes for QuicLike AEAD/MAC. Maximum datagram
size is `min(path_mtu - outer_overhead_bytes, 65507)`. The caller must account for
the actual IP/UDP and any additional underlay encapsulation in outer overhead.
No fragmentation, PMTU probing or automatic fallback occurs. Local configuration
must leave space for its maximum payload plus complete prefix/header/tag.

## Replay and failure atomicity

The opener owns a fixed 128-packet sliding bitmap. It accepts unseen authenticated
out-of-order packets within that window, rejects duplicates and packets at least
128 behind the highest accepted number, and handles the u64 boundary without
wrapping arithmetic. It computes a candidate replay state without changing the
live bitmap. Invalid format, binding mismatch, bad authentication, insufficient
destination, exceeded usage budget and replay rejection never commit replay state.

Opening performs bounded parsing before allocation, checks exact datagram length,
then authenticates in private scratch storage. Only after complete format/auth
success and available output/usage bounds does it copy plaintext and commit replay
and usage state. AEAD authentication failure may alter scratch but cannot alter
the caller's destination. A forged high packet number cannot advance the window.
Memory and crypto work are bounded by configured datagram size; caller admission
limits must additionally bound unauthenticated datagram rate and total sessions.

## Work checklist

- [x] [MOD-DGRAM-01] Implemented checked fixed headers, cover prefixes, MTU/payload/key-usage limits and typed context identifiers. Evidence: [codec implementation](../../crates/l2tunnel-datagram/src/lib.rs), [boundary tests](../../crates/l2tunnel-datagram/src/tests.rs).
- [x] [MOD-DGRAM-02] Implemented ring HKDF-separated AEAD/MAC protection, private monotonic counter and checked exhaustion. Evidence: [key derivation and protection](../../crates/l2tunnel-datagram/src/lib.rs), [separation/exhaustion tests](../../crates/l2tunnel-datagram/src/tests.rs).
- [x] [MOD-DGRAM-03] Implemented fixed replay-window proposals/commit and failure-atomic plaintext output. Evidence: [opener and replay state](../../crates/l2tunnel-datagram/src/lib.rs), [adversarial tests](../../crates/l2tunnel-datagram/src/tests.rs).
- [x] [MOD-DGRAM-04] Verified independent golden vectors, malformed/tampered inputs, context separation, reordering, replay and counter/usage boundaries. Evidence: [Rust vectors and tests](../../crates/l2tunnel-datagram/src/tests.rs), [independent Python generator](../../crates/l2tunnel-datagram/tests/generate_vectors.py).
- [x] [MOD-DGRAM-05] Exchanged protected payloads over real loopback UDP for both directions, suites and custom covers. Evidence: [native socket test](../../crates/l2tunnel-datagram/src/tests.rs).
- [ ] [MOD-DGRAM-06] Integrate authenticated TLS-exporter UDP lane joining, path validation/rebinding, anti-amplification and native tunnel framing.
- [ ] [MOD-DGRAM-07] Implement separately specified maintained UDP-only handshake, cover initial flights and real capture/state-transition acceptance gates.
- [ ] [MOD-DGRAM-08] Implement authenticated rekey/old-key retirement, process-restart lifecycle, congestion/pacing/PMTU and multi-lane budgets.
- [ ] [MOD-DGRAM-09] Add fuzzing, independent cryptographic review, dependency advisory receipts and native-device/target-path validation.

## Local verification receipt

These commands passed on the local Linux host:

```sh
python3 crates/l2tunnel-datagram/tests/generate_vectors.py
cargo fmt --package l2tunnel-datagram
cargo test --offline --package l2tunnel-datagram
cargo clippy --offline --package l2tunnel-datagram --all-targets -- -D warnings
cargo doc --offline --package l2tunnel-datagram --no-deps
```

All 16 tests passed. Four checked-in packet vectors were independently generated
with Python cryptography 41.0.7 (HKDF and ChaCha20-Poly1305) and Python's standard
HMAC-SHA256; the generator contains only public fixture secrets. Rust tests cover
every payload length 1..1200 in all four suite/cover combinations, exact portable
UDP maximums, one-byte MTU overflow, every truncation and every modified packet
byte, context/key separation, replay/reordering, forged high counters, exact
128-packet window edges, u64 exhaustion and packet/byte usage caps. Authenticated
invalid headers and too-small destinations preserve output and receive state.
The socket test exchanges actual datagrams in both directions for all four
suite/cover combinations. These finite tests do not establish UDP-only handshake,
TLS-to-UDP joining, native-device integration, standard protocol interoperability,
throughput, active-probe resistance or an independently audited security boundary.

## Reviewed additive checked-open contract

Status: implemented and independently reviewed; 20 focused tests, warning-denied
Clippy and rustdoc pass. The source-stable wave8 aggregate includes this addition.
A protected
payload may carry authenticated metadata that must agree with an enclosing raw
header. Rejecting that mismatch after ordinary `open` would already have consumed
the packet's replay slot, allowing a modified outer header to invalidate the
later legitimate packet. Add one transactional validation seam:

```rust
PacketOpener::open_checked<E>(
    &mut self,
    datagram: &[u8],
    output: &mut [u8],
    validate: impl FnOnce(OpenedPacket, &[u8]) -> Result<(), E>,
) -> Result<OpenedPacket, CheckedOpenError<E>>;
// CheckedOpenError<E> = Datagram(Error) | Rejected(E).
```

The shared path checks bounded framing/destination and proposes replay/usage,
authenticates into the existing zeroizing scratch, checks exact plaintext length,
then calls the validator exactly once. Only a successful validator permits output
copy and replay/usage commit. The validator sees immutable authenticated bytes
and provisional metadata; it must only validate, because the opener cannot roll
back external callback side effects. No callback runs on invalid format/context,
replay, insufficient output, exhausted key budget or authentication failure.

A rejected validator preserves all output bytes, replay state and receive usage;
the same authenticated packet remains retryable with corrected surrounding
metadata. Rejection and success both drop the existing bounded zeroizing scratch.
The callback may return a typed error; formatting the wrapper must not implicitly
print plaintext. Existing `open` delegates with an infallible validator and keeps
its exact error/wire behavior. No additional cryptographic primitive, duplicate
replay state, persistent plaintext buffer or unbounded allocation is introduced.

- [x] [MOD-DGRAM-CHECK-01] Implemented the generic checked-open seam and unchanged legacy delegation using one crypto/replay commit path. Evidence: [shared opener implementation](../../crates/l2tunnel-datagram/src/lib.rs).
- [x] [MOD-DGRAM-CHECK-02] Tested callback count, rejection/retry, high-counter rejection, output/state atomicity and both key-usage ceilings across all four suite/cover combinations. Evidence: [four checked-open regression tests](../../crates/l2tunnel-datagram/src/tests.rs).
- [x] [MOD-DGRAM-CHECK-03] Passed original vectors/socket tests, focused strict Clippy/rustdoc and independent code review; aggregate evidence remains separate. Evidence: [focused verification below](#checked-open-verification).
- [ ] [MOD-DGRAM-CHECK-04] Integrate an actual enclosing carrier with authoritative header/schema checks before claiming raw packet-phase capability.
- [x] [MOD-DGRAM-CHECK-05] Passed coordinated source-stable workspace qualification after the additive checked-open change. Evidence: [wave8 receipt: 587 Rust including doctests, 46 Python](../../work/implementation-wave8/validation.json).

### Checked-open verification

After the additive implementation, `cargo fmt --package l2tunnel-datagram`,
`cargo test --offline --package l2tunnel-datagram` (20 tests, 0 doctests),
`cargo clippy --offline --package l2tunnel-datagram --all-targets -- -D warnings`
and `RUSTDOCFLAGS='-D warnings' cargo doc --offline --package l2tunnel-datagram
--no-deps` passed on local Linux. Original exact packet vectors and the real UDP
loopback test ran unchanged; the Python vector generator was not rerun for this
addition. Two independent read-only reviews found no material blocker; one
requested the now-corrected distinction between provisional callback metadata
and committed returned metadata. Scratch clearing follows the existing
`Zeroizing<Vec<u8>>` ownership path; tests do not inspect freed allocator memory.
These checks do not implement or qualify a raw packet carrier.
