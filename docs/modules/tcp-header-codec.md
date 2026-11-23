# Python-compatible TCP header record primitive

Status: primitive implemented and byte-parity tested against the preserved Python
source; negotiated runtime integration remains pending. This module ports the executable
`CompactHeaderCodec` bytes from `simulator/src/l2tunnel_sim/compact.py`, separately
from the existing `FrameCodec` draft format. It does not enable a runtime mode or
advance the complete `tcp-header-codecs` catalog gate. Header compression is a
prerequisite for shared contexts, aligned records and packed-wire production
families; those additional formats remain separate work.

## Exact interface and inner records

The public `l2tunnel_codec::tcp_header` module provides `HeaderProfile` with
`TcpTimestamp` and `TcpDelta`, `HeaderEncoder::new(profile, max_frame_bytes)` and
`HeaderDecoder::new(max_frame_bytes)`. Each owns at most one 66-byte context; all
output storage belongs to the caller. Encoding returns the written byte count and
may emit context plus one frame record. `decode_next(input, output)` consumes one
complete record and returns either a context event or a frame event containing
consumed/written lengths and the record kind. The caller retains incomplete input;
there is no unbounded internal stream accumulator. `reset` clears context only
when the outer authenticated epoch/order contract permits it.

Inner bytes follow Python exactly for valid encoded records:

| Kind | Fields after kind byte | Behavior |
| --- | --- | --- |
| 0 | BE u16 length=66, full original header | Establish context; emit no native frame. |
| 1 | BE u16 payload length, 23 dynamic header bytes, payload | Timestamp profile; regenerate lengths/checksums. |
| 2 | BE u16 complete frame length, raw frame | Lossless fallback; do not change context. |
| 3 | BE u16 payload length, 8-bit field mask, unsigned LEB128 deltas, payload | Modular delta profile; update context after reconstruction. |

A context record costs 69 bytes. Timestamp records cost 26 bytes plus payload;
delta records cost four bytes plus selected varints and payload. The eight delta
widths are 16, 32, 32, 8, 16, 16, 32 and 32 bits. Arithmetic wraps at each field's
width. Python accepts up to five varint bytes (including values wider than the
field) and applies modular reduction; a sixth byte fails. The decoder accepts
both timestamp and delta record kinds, as Python does, and reports the kind so a
future authenticated runtime can enforce its negotiated profile.

## Eligibility, checksums and context safety

Only complete Ethernet/IPv4/TCP packets with IPv4 IHL=5, TCP header length=32,
the exact `NOP,NOP,Timestamp` 12-byte option, no IP fragments, and consistent IP
total length are eligible. Restoring dynamic fields, total length and both Internet
checksums must reproduce the complete original frame exactly before compression
is selected. Invalid/offloaded checksums, IPv6, VLAN, ARP, unusual options and
other bytes fall back without alteration. Payload bytes remain opaque. TUN IP
bytes do not gain a timestamp compression claim from this Ethernet-only profile.

The Internet checksum is a non-cryptographic one's-complement checksum. IPv4
header checksum and TCP pseudo-header/header/payload checksum are regenerated;
there is no change to endpoint sequence/window/ACK behavior. Decoder context
records receive structural and IPv4-checksum validation. Python's permissive
acceptance of arbitrary 66-byte context bodies is intentionally not a hostile-input
contract. Context TCP checksum cannot be independently verified without its
original payload; reconstructed frame checksum is calculated from actual output.

The shared encoder first tries to reconstruct the incoming header from its
existing context. A byte-exact reconstruction verifies the IP and TCP checksums
once. A changed context still requires independent validation before replacing
the original. The checksum implementation preserves odd bytes across slice
boundaries and sums bounded blocks of complete network-order words. An offline
replay compared both revisions on 34,889 captured native packets. Both emitted
identical record streams, and both decoded every input byte. Over eight
interleaved runs per version, median elapsed encoder time per packet fell from
1,916 ns to 341 ns on this host.
[Packet replay and per-run times](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/header-cost-pair-1ee5ce3.json).

This legacy inner format has no epoch, context ID, integrity or replay field.
A valid-looking stale delta can decode against the wrong context. The adapter
therefore requires authenticated ordered delivery within one isolated channel and
epoch; reset then rejects dynamic records until a fresh context arrives. Neither
checksums nor this primitive detect a replay with an otherwise valid context.
Loss/reordering must be resolved by the outer recovery layer before decoding.
Context must never cross peer, channel, direction or epoch boundaries.

Frame sizes are bounded by configured maximum <=65535. This standalone inner
format ceiling does not imply that its largest encoded record fits the existing
FrameCodec envelope; a runtime adapter must budget its own complete framing. Record lengths and output
capacity are checked before copying or committing state. Failure of one encode or
one `decode_next` operation leaves its prior context intact. Earlier successfully
consumed context events remain committed if a later record fails; callers must
close/reset a failed authenticated stream according to their framing contract.
No native device, clock, Tokio, crypto or privilege dependency is added.

## Independent golden evidence

`tools/generate_tcp_header_goldens.py` imports the actual preserved Python codec,
constructs deterministic nonzero packets, invokes its encoder and decoder, and
records complete frame, record and encoder/decoder context bytes. The fixture
contains generator/source provenance and SHA-256 of the source. It is generated
independently from Rust; Rust tests consume the checked-in bytes. Expected cases
include initial context, steady updates, empty payload, retries, modular wraps,
changed static fields, invalid checksums and unsupported raw frames. Historical
simulator files/receipts are not changed or rerun as performance claims.

## Acceptance ledger

- [x] [MOD-TCPHDR-01] Freeze record/API/context safety design and actual Python source provenance. Evidence: [implementation](../../crates/l2tunnel-codec/src/tcp_header.rs), [tests](../../crates/l2tunnel-codec/src/tcp_header_tests.rs), [actual Python fixture](../../crates/l2tunnel-codec/tests/data/tcp-header-goldens.tsv), [generator](../../tools/generate_tcp_header_goldens.py).
- [x] [MOD-TCPHDR-02] Generate independent complete Python byte/state vectors for both profiles and raw fallback, then verify Rust encode/decode byte equality. Evidence: [implementation](../../crates/l2tunnel-codec/src/tcp_header.rs), [tests](../../crates/l2tunnel-codec/src/tcp_header_tests.rs), [actual Python fixture](../../crates/l2tunnel-codec/tests/data/tcp-header-goldens.tsv), [generator](../../tools/generate_tcp_header_goldens.py).
- [x] [MOD-TCPHDR-03] Implement bounded caller-buffer encode/decode, explicit reset and checksum-exact reconstruction without changing FrameCodec. Evidence: [implementation](../../crates/l2tunnel-codec/src/tcp_header.rs), [tests](../../crates/l2tunnel-codec/src/tcp_header_tests.rs), [actual Python fixture](../../crates/l2tunnel-codec/tests/data/tcp-header-goldens.tsv), [generator](../../tools/generate_tcp_header_goldens.py).
- [x] [MOD-TCPHDR-04] Test missing/reset context, malformed/truncated records, five-byte modular varints, overflow, capacity rollback and maximum frame bounds. Evidence: [implementation](../../crates/l2tunnel-codec/src/tcp_header.rs), [tests](../../crates/l2tunnel-codec/src/tcp_header_tests.rs), [actual Python fixture](../../crates/l2tunnel-codec/tests/data/tcp-header-goldens.tsv), [generator](../../tools/generate_tcp_header_goldens.py).
- [x] [MOD-TCPHDR-05] Run focused Rust/Python checks, Clippy/rustdoc and repository aggregate validation with finite scope recorded. Evidence: [stable wave5 aggregate](../../work/implementation-wave5/validation.json).
- [ ] [MOD-TCPHDR-06] Integrate negotiated runtime profile and per-peer/channel/direction/epoch contexts with loss/reorder/switch tests before enabling the full catalog family.


## Local verification

The actual preserved Python source SHA-256 is recorded in the fixture. Generator
`--check` reproduces all 28 vectors without changing simulator sources. Rust tests
compare every frame/record byte and encoder/decoder context, including resets,
nonzero/empty payload, modular wraps, retransmission, static-context changes and
checksum/unsupported fallback. Exhaustive truncation and short-capacity checks
cover every record in that fixture; additional tests cover maximum frame lengths,
malformed contexts/varints, deterministic hostile inputs and the documented valid
stale-context limitation.

`cargo test --offline -p l2tunnel-codec` passed 28 tests (seven added).
The same crate with `--no-default-features` passed 27 tests, including all seven
new tests, without the optional LZ4 dependency. Strict Clippy and denied-warning rustdoc passed. The actual source suite
`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=simulator/src python3 -m pytest -p
no:cacheprovider simulator/tests/test_compact.py -q` passed 11 tests. These tests
are codec behavior evidence; they do not establish native throughput, complete
mode parity, loss/reorder runtime integration or hot-switch safety.

The required `python3 tools/check.py` was attempted: checklist and formatting
passed, then workspace Clippy stopped in concurrent active-epoch work at
`crates/l2tunnel-active/src/epoch.rs:130` (`result_large_err`). No codec error was
reported. The later coordinated [wave5 aggregate](../../work/implementation-wave5/validation.json)
passed `python3 tools/check.py` with unchanged source hashes, 420 Rust tests
including doctests and 28 Python checks. This supersedes the earlier incomplete
attempt; it is local workspace verification, not native or remote CI evidence.
