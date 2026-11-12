# Bounded frame codec and fragmentation

Status: implemented primitives, locally unit-tested on 2026-11-12 (Asia/Tokyo).
The design was written before code. This module implements a new draft
full-frame format; it does not claim byte parity with Python's compact, aligned,
shared-record or header-context formats. Read [mode parity](../mode-parity.md) and
[architecture](../architecture.md) before extending it. No networking, device,
clock or cryptographic implementation belongs here.

## Frame record and compression

`FrameCodec::new(CodecConfig { layer, max_frame_bytes, compression })` constructs a
stateless codec implementing the existing `RecordCodec` trait. `FrameLayer` is
`Ethernet` for TAP or `Ip` for TUN. It identifies the negotiated device layer;
packet bytes remain opaque, and device/classifier validation is a separate step.
Empty records are invalid. The maximum configurable frame is 16 MiB; normal
deployments should set a realistic MTU/jumbo bound well below that ceiling.

`encode_vec` and `decode_vec` offer owned-buffer convenience. Trait `encode` and
`decode` use caller-owned output. Every error leaves that output byte-for-byte
unchanged. Invalid headers and lengths are rejected before allocation. LZ4 decode
uses bounded scratch storage and only copies to the destination after complete,
exact-size success; input bytes never select an unbounded destination allocation.

Draft frame format, all integers big-endian:

| Bytes | Field |
| --- | --- |
| 0..2 | Magic `LF` |
| 2 | Version 1 |
| 3 | Layer: 1 Ethernet, 2 IP |
| 4 | Encoding: 0 raw, 1 stateless LZ4 block |
| 5..8 | Reserved zero |
| 8..12 | Original nonzero frame length, u32 |
| 12..16 | Stored nonzero body length, u32 |
| 16.. | Exact body; no trailing data |

`Compression::None` always sends raw. `Compression::Lz4IfSmaller` selects LZ4 only
when its body is strictly shorter; otherwise the exact original frame is sent.
Both bodies use the same header size. LZ4 has no external dictionary or prepended
untrusted size. Decoders reject compressed records with non-saving body length,
unknown encoding/layer/version, malformed blocks, trailing record bytes and an
output count unequal to the original length. Compression policy controls encoding;
receiving LZ4 additionally requires the `lz4` build feature.

The optional feature uses pinned cached `lz4_flex = 0.14.0` with `std`,
`safe-encode`, `safe-decode` and `checked-decode`, without the frame format.
The [upstream project](https://github.com/PSeitz/lz4_flex) and
[bounded decode API](https://docs.rs/lz4_flex/0.14.0/lz4_flex/block/fn.decompress_into.html)
were checked. Dependency/advisory review remains a release gate, not a claim
implied by this local integration. Authentication must precede decompression.

## Fragment format and MTU budget

`Fragmenter::new(context, config, first_message)` owns monotonically increasing
message IDs for one direction of an authenticated session/epoch. A successful
`fragment(record)` returns `FragmentBatch { message, fragments }` and consumes one
ID; invalid inputs consume none. The last u64 ID is usable once, then exhaustion
is explicit. The caller must never recreate a fragmenter with a reused counter
inside the same direction/session/epoch.

`FragmentContext { session: SessionId, epoch: Epoch }` is supplied out-of-band from
authenticated session state. `FragmentConfig` contains path MTU, total outer
overhead bytes, maximum record size and maximum fragment count. The usable chunk
is `min(path_mtu - outer_overhead_bytes - 40, u16::MAX)`. The caller's overhead
must include real IP/carrier/authentication/record wrappers; this module does not
guess TCP options, TLS overhead or PMTU. Invalid/nonpositive budgets are rejected.

Draft fragment format, all integers big-endian:

| Bytes | Field |
| --- | --- |
| 0..2 | Magic `LX` |
| 2..4 | Version 1, reserved zero |
| 4..12 | Session ID |
| 12..20 | Configuration epoch |
| 20..28 | Message ID |
| 28..32 | Total record bytes, u32 |
| 32..34 | Zero-based fragment index, u16 |
| 34..36 | Fragment count, u16 |
| 36..38 | Full chunk size, u16 |
| 38..40 | This fragment's payload size, u16 |
| 40.. | Exact payload; no trailing data |

Canonical boundaries remove arbitrary offset/overlap ambiguity: count must equal
`ceil(total/chunk)`; all but the last payload have chunk length; the last has the
exact remaining bytes. Empty records, zero dimensions and inconsistent geometry
are invalid. This is fragmentation of one complete frame record before coding,
not cross-frame packing, independent-short delivery or an IP fragmentation engine.

## Reassembly, deadlines and replay scope

`Reassembler::new(context, config)` fixes expected session/epoch and resource
limits. `accept(fragment, now_ticks, output)` returns `ReassemblyStatus::Pending`,
`Duplicate` or `Complete`; output changes only on complete success. `expire(now)`
performs the same deadline cleanup without input. Caller time is monotonically
nondecreasing u64 ticks; backwards time and deadline overflow fail explicitly.
No wall clock is read. A reliable caller should call `expire(now)` before each
`accept` when it needs every expired message ID for recovery: `accept` also performs
defensive cleanup, but returns only the current fragment's status.

`ReassemblyConfig` bounds message size, simultaneous messages, fragment payload,
fragments per message, total reserved fragment slots, total reserved payload
bytes, replay-window width and maximum lifetime. Admission reserves the entire
declared record and fragment bitmap after validating all these caps, even if the
first arrival is a short tail fragment. There is no allocation proportional to
an unchecked peer length. Duplicate identical fragments are no-ops; same-index
different bytes or inconsistent message geometry are conflicts. Neither extends
the first-arrival deadline. Completion releases reservations exactly once.

A bounded sliding message-ID window retains terminal message tombstones. Completed
or expired message IDs cannot be delivered again within the window; IDs below the
window are rejected as stale. An advancing ID cannot evict an incomplete message:
it is rejected until that older message completes/expires. Admission errors do
not advance the replay window. Deadline cleanup runs after complete fragment
validation and before admission, even if an otherwise valid fragment is then
rejected; output still remains unchanged. Expiry is terminal for that message ID.
Reliable recovery must finish before expiry, fail the logical record, or use its
own authenticated logical-record protocol to retry under a fresh message ID.

This window is local message deduplication, not cryptographic replay protection.
The caller must authenticate each fragment and bind direction/session/epoch before
acceptance. Session counters/keys and old-epoch handling remain external. Store
one reassembler per direction/context and destroy only after negotiated drain.

## Work checklist

- [x] [MOD-CODEC-01] Implemented bounded versioned full-frame records and exact opaque TAP/TUN round trips. Evidence: [frame codec](../../crates/l2tunnel-codec/src/frame.rs), [tests](../../crates/l2tunnel-codec/src/frame/tests.rs).
- [x] [MOD-CODEC-02] Implemented optional stateless safe LZ4 with smaller-only selection and bounded exact decode. Evidence: [frame codec](../../crates/l2tunnel-codec/src/frame.rs), [compression tests](../../crates/l2tunnel-codec/src/frame/tests.rs).
- [x] [MOD-CODEC-03] Implemented MTU-aware canonical fragmentation and monotonic message-ID exhaustion. Evidence: [fragment codec](../../crates/l2tunnel-codec/src/fragment.rs), [tests](../../crates/l2tunnel-codec/src/fragment/tests.rs).
- [x] [MOD-CODEC-04] Implemented bounded reassembly, duplicate/conflict handling, lifetime cleanup and replay tombstones. Evidence: [reassembler](../../crates/l2tunnel-codec/src/fragment.rs), [tests](../../crates/l2tunnel-codec/src/fragment/tests.rs).
- [x] [MOD-CODEC-05] Tested format/size boundaries, truncation, malformed compression, expansion, atomic output and no-feature builds. Evidence: [frame tests](../../crates/l2tunnel-codec/src/frame/tests.rs).
- [x] [MOD-CODEC-06] Tested reverse-order fragments, budgets, conflicts, deadlines, session/epoch rejection and ID/window behavior. Evidence: [fragment tests](../../crates/l2tunnel-codec/src/fragment/tests.rs).
- [ ] [MOD-CODEC-07] Integrate authentication, MUX/ARQ/FEC, downstream credit and coordinated context retirement.
- [ ] [MOD-CODEC-08] Port byte-exact Python timestamp/delta contexts and compact/shared/aligned/packed formats with golden vectors.
- [ ] [MOD-CODEC-09] Add fuzzing, measured decoder-work limits, allocation/RSS benchmarks and native TAP/TUN receipts.

QOS- and FC-level scheduling/credit bounds do not replace the codec's limits, and
local codec tests do not close full protocol, Python parity or real-device gates.

## Local verification receipt

The following commands passed on the local Linux host using cached dependencies:

```sh
cargo fmt --package l2tunnel-codec
cargo test --offline --package l2tunnel-codec
cargo test --offline --package l2tunnel-codec --no-default-features
cargo clippy --offline --package l2tunnel-codec --all-targets -- -D warnings
cargo clippy --offline --package l2tunnel-codec --all-targets --no-default-features -- -D warnings
cargo doc --offline --package l2tunnel-codec --no-deps
```

Default LZ4 builds passed 21 tests; compression-disabled builds passed 20 tests.
Cases include every frame length from 1 through 1024 for both layers, the 16 MiB
hard limit, every truncation of representative records, exact decode lengths and
compression expansion attempts, MTU/chunk boundaries, reverse fragment arrival,
reserved bytes/slots, duplicate/conflicting fragments, deadlines, replay-window
blocking and complete opaque TAP/TUN encode-fragment-reassemble-decode paths.
No Python format parity, network/device integration or throughput is claimed.
