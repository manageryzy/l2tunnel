# Python-compatible aligned record bodies

Status: primitive implemented and byte-parity tested. This slice implements the body transforms
from `simulator/src/l2tunnel_sim/aligned_records.py`, building on the separately
verified TCP header codec. It does not implement channel serials, fragment units,
reordering, early short-frame delivery, coding, source packing or a runtime mode.
The complete `aligned-records` and `independent-short-records` catalog gates stay
planned until their enclosing delivery and integration requirements pass.

## Public API and storage contract

`l2tunnel_codec::aligned_body` exposes `Config` with `max_frame_bytes`,
`symbol_bytes`, `elide_payload_length`, `predictive`, `timestamp_pair_dictionary`
and `independent_short_frame_bytes`. `Encoder::new(config)` and
`Decoder::new(config)` validate those settings and allocate fixed bounded scratch
storage once. Both have `reset` and `has_context`. Each instance belongs to one
peer, direction, channel and authenticated epoch. The internal header engine uses
the existing delta profile without changing its bytes or context semantics. Encoder
flags select output; the decoder accepts every supported body kind as the Python
receiver does. A runtime must separately enforce its authenticated mode policy.

`Encoder::encode(frame, output)` returns `EncodedBodies { context_len, body_len,
kind }`. The caller buffer contains optional context bytes at
`0..context_len`, followed immediately by exactly one body at
`context_len..context_len+body_len`. The ranges are disjoint by construction;
`max_encoded_len()` gives a sufficient output allocation. There is no symbol
padding in that output. A context and body are separate records even though they
share the caller buffer; a transport must give them distinct ordered record IDs.
A body that exceeds the configured symbol capacity remains an ordinary explicit
header record for the future fragment adapter; it is never truncated. Every body
must still fit the Python u16 encoded-record limit (65535 bytes).

`Decoder::decode_body(input, Padding::{Exact, ZeroExtended}, output)` accepts one
body and returns a context/frame event with its semantic input length and native
output length. `Exact` rejects trailing bytes and permits a reassembled explicit
record larger than one symbol. `ZeroExtended` requires exactly
`symbol_bytes - 3` bytes, validates every byte after the semantic body as zero,
and excludes that padding from the consumed body length. Compact kinds with
implicit payload length must fit one symbol even under `Exact`. The three-byte
channel/serial prefix is owned by a future adapter and is not passed here.

All configurations and lengths are bounded. Native maximum is 1..65535, symbol
size is 9..65535, dictionary requires prediction, and a nonzero independent short
threshold must be at most `symbol_bytes - 6`. Encoder scratch is at most
`max_frame_bytes + 29`; decoder scratch is at most twice the native maximum plus
44 bytes. Input beyond a maximum encoded record/symbol is rejected before copy.
An error leaves the prior context and caller output unchanged; successful earlier
context events remain committed. Caller storage never aliases safe Rust inputs.

## Exact transforms and fallback

| Body kind | Encoding and prerequisite |
| --- | --- |
| 0, 1, 2, 3 | Existing context, timestamp, raw and delta records; unchanged. |
| 6 | Omit the explicit u16 payload length from kind 3 when it equals context payload length and the result fits a symbol. |
| low three bits 7 | One kind/mask byte predicts IPID +1, SEQ +previous payload length, unchanged ACK; high bits preserve flags/window/urgent/timestamp presence. Requires same payload length and no context refresh. |
| low three bits 5 | Exact fixed 32-entry timestamp-delta pair table from Python, selected only when predictive flags/window/urgent differences are absent and the original predictive candidate already fits. |

The timestamp pair table is the Cartesian product of timestamp deltas 18/19 and
echo deltas 0/1/17/18/19/20/36/37/38/55/56/74/75/92/93/111 in that order. Modulo
arithmetic, zero payload and exception fallback follow the actual Python source.
Prediction is attempted before payload-length elision; otherwise the ordinary
header record remains. A new context may allow kind 6 but never kind 5/7.

The generic short threshold counts complete native frame bytes. Matching input is
forced to kind 2, bypassing header context changes. This is a serialization policy,
not permission to bypass common MUX admission, deliver out of order, suppress gaps
or forget duplicate tombstones. No SYN-specific classification is introduced.

Payload-length elision changes record header bytes. Symbol padding is a separate
zero-extension operation after channel framing and is never counted as payload.
The decoder reconstructs an ordinary delta record and delegates checksum/header
reconstruction to the existing header codec. Its stricter malformed-context
validation remains in force. Neither legacy body format authenticates input or
identifies an epoch; valid stale bodies remain undetectable against a wrong valid
context. Ordered authenticated delivery and negotiated drained resets are required.

## Independent evidence and acceptance

The generator must instantiate the actual Python `AlignedRecordTransport` and
`AlignedRecordReceiver`, record emitted complete body bytes and context states,
and preserve source hashes. It must not implement a second reference transform.
Fixture generation is codec evidence, not a throughput experiment. Tests compare
Rust encode/decode against those bytes, then separately exercise hostile bounds.

- [x] [MOD-ALIGNEDBODY-01] Freeze body/API/storage design and actual Python provenance before implementation. Evidence: [implementation](../../crates/l2tunnel-codec/src/aligned_body.rs), [tests](../../crates/l2tunnel-codec/src/aligned_body_tests.rs), [Python fixture](../../crates/l2tunnel-codec/tests/data/aligned-body-goldens.tsv), [generator](../../tools/generate_aligned_body_goldens.py).
- [x] [MOD-ALIGNEDBODY-02] Generate actual Python vectors for all 32 predictive masks and timestamp pairs, elision, zero payload, wraps, fallback/recovery, short frames and small-symbol capacity boundaries. Evidence: [implementation](../../crates/l2tunnel-codec/src/aligned_body.rs), [tests](../../crates/l2tunnel-codec/src/aligned_body_tests.rs), [Python fixture](../../crates/l2tunnel-codec/tests/data/aligned-body-goldens.tsv), [generator](../../tools/generate_aligned_body_goldens.py).
- [x] [MOD-ALIGNEDBODY-03] Implement transactional bounded body encode/decode and exact versus zero-extended padding without changing existing header/FrameCodec bytes. Evidence: [implementation](../../crates/l2tunnel-codec/src/aligned_body.rs), [tests](../../crates/l2tunnel-codec/src/aligned_body_tests.rs), [Python fixture](../../crates/l2tunnel-codec/tests/data/aligned-body-goldens.tsv), [generator](../../tools/generate_aligned_body_goldens.py).
- [x] [MOD-ALIGNEDBODY-04] Test truncation, malformed padding/context, capacity rollback, oversized explicit records, reset, generic short context preservation and unsupported header fallback. Evidence: [implementation](../../crates/l2tunnel-codec/src/aligned_body.rs), [tests](../../crates/l2tunnel-codec/src/aligned_body_tests.rs), [Python fixture](../../crates/l2tunnel-codec/tests/data/aligned-body-goldens.tsv), [generator](../../tools/generate_aligned_body_goldens.py).
- [x] [MOD-ALIGNEDBODY-05] Run focused Rust/Python, strict Clippy/rustdoc and coordinated repository validation; record the finite evidence scope. Evidence: [stable wave5 aggregate](../../work/implementation-wave5/validation.json).
- [ ] [MOD-ALIGNEDBODY-06] Add bounded channel serial/fragment/reorder/tombstone delivery and authenticated runtime/epoch integration before enabling a complete catalog family.

## Local verification

`PYTHONDONTWRITEBYTECODE=1 python3 tools/generate_aligned_body_goldens.py --check`
reproduced 328 actual Python body/context vectors. These include all 32 predictive
presence masks, all 32 dictionary entries at zero/one/64-byte payloads, symbol
capacity boundaries, large explicit-record fallback, modular wraps, exceptional
fields followed by successful prediction, unsupported/checksum fallback, short
frames that retain context and new static contexts. The fixture stores hashes of
the three preserved Python source modules; no historical simulator files changed.

`cargo test --offline -p l2tunnel-codec` passed 34 tests (six aligned-body tests).
The same crate with `--no-default-features` passed 33 tests, including all six
aligned tests. Strict targeted Clippy and denied-warning rustdoc passed. The original Python
`test_aligned_records.py` and `test_compact.py` suites passed 312 tests; one report
export test was skipped because its optional `aioquic` dependency was unavailable.
Every fixture body truncation, short caller output, nonzero/exact padding failure,
reset, malformed context/varint and configured maximum has explicit coverage.
The large-symbol/small-native-limit test verifies bounded parsing without copying
unbounded padding into scratch storage.

The coordinated [wave5 aggregate](../../work/implementation-wave5/validation.json)
passed `python3 tools/check.py` with unchanged source hashes, 420 Rust tests
including doctests and 28 Python checks. This is local workspace verification.
Body parity does not establish runtime delivery, native throughput, loss/reorder recovery,
early short-frame release or complete catalog implementation.
