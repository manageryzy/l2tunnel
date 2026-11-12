# Bounded full-payload GF(256) block engine

Status: implemented and locally tested on Linux, 2026-11-12 (Asia/Tokyo). The
design preceded the code. This module is a reusable sealed
block encoder/decoder, not a complete recovery transport. It follows the
[architecture](../architecture.md), [implementation plan](../implementation-plan.md)
and [mode parity requirements](../mode-parity.md). No runtime, socket, clock,
cryptographic primitive or sender payload ledger belongs in this crate.

## Reference boundary and finite field

The simulator's [coding.py](../../simulator/src/l2tunnel_sim/coding.py) uses
GF(256) with polynomial `x^8+x^4+x^3+x^2+1` (`0x11d`), XOR addition and byte
coefficients. Its systematic Cauchy row is `inverse(column XOR (k+repair_index))`,
valid only when `k+repair_index < 256`. The simulator's
[compact coefficient function](../../simulator/src/l2tunnel_sim/compact.py)
mixes a 32-bit seed and absolute source index using wrapping multiplications
`0x9e3779b9`, `0x85ebca6b`, `0xc2b2ae35`. Zero coefficients are possible.

[Compact block generations](../../simulator/src/l2tunnel_sim/compact_block.py)
close at their source count, idle timer or maximum age, then schedule initial
repairs and later rank-deficit repairs. Their receiver performs coefficient-rank
elimination and obtains original bytes elsewhere. This engine implements actual
payload-vector elimination using only received equations. It does not claim to
implement those scheduling, feedback, in-flight subtraction or sender-retention
policies. Fixed sealed blocks are the first basis for legacy block, sliding,
hybrid and compact families; each complete family retains its own acceptance gate.

No maintained compatible GF/FEC crate was available in the local dependency
cache. Implement finite-field multiplication with eight bounded polynomial
steps and inverse by exponentiation to 254. This is error-correction arithmetic,
not cryptography. Independently generated Python products, coefficient rows and
full wire vectors verify the field and packet definition. RFC 8681 is background
for RLNC, not a wire-compatibility claim: [official specification](https://www.rfc-editor.org/rfc/rfc8681.html).

## Public ownership and APIs

`FecContext { session: SessionId([u8; 16]), epoch: Epoch(u64), channel:
ChannelId(u32), direction: Direction }` identifies one authenticated coding stream.
Directions are global client-to-server/server-to-client. The caller authenticates
and replay-checks the enclosing record before `Decoder::accept`; matching context
bytes alone do not authenticate a peer. Generation IDs never repeat in this
context. Changing epoch means a different decoder and a negotiated drain barrier.

```rust
BlockEncoder::new(context, generation: GenerationId, config: BlockConfig,
                  sources: &[&[u8]]) -> Result<BlockEncoder, Error>;
BlockEncoder::systematic(source: SourceId) -> Result<EncodedSymbol, Error>;
BlockEncoder::repair(coefficients: &[u8]) -> Result<EncodedSymbol, Error>;
compact_coefficients(seed: u32, first_source: u32, count: u16)
    -> Result<Vec<u8>, Error>;
cauchy_coefficients(sources: u16, repair_index: u16)
    -> Result<Vec<u8>, Error>;
Decoder::new(context, config: DecoderConfig) -> Result<Decoder, Error>;
Decoder::accept(authenticated_packet: &[u8], now_ticks: u64)
    -> Result<AcceptStatus, Error>;
Decoder::take_decoded(generation: GenerationId) -> Result<DecodedBlock, Error>;
Decoder::expire(now_ticks: u64) -> Result<Vec<ExpiredGeneration>, Error>;
```

The encoder copies and seals its nonempty source list at construction. Every
source is nonempty and source indices are 0..k. Systematic symbol IDs equal source
indices and their coefficients are the corresponding identity row. Repair IDs
start at k and increase without wrapping; repairs carry explicit nonzero vectors.
The source list cannot grow after any symbol has been emitted. A repeated
systematic request gives identical bytes. No retry creates a new repair identity
implicitly; retain and resend the existing encoded symbol for transport retries.

`AcceptStatus` distinguishes innovative rank increases, consistent dependent
equations, exact repeated symbol IDs and complete retained generations. Decoder
state never references encoder state. `take_decoded` returns source byte vectors
in index order exactly once, or explicit `InsufficientRank`; completion does not
automatically evict output before the caller can retrieve it. Completed delivery
and expiry produce bounded terminal tombstones. Late terminal generations cannot
be recreated. Explicit `expire` returns each expired generation's rank and required
rank; `accept` rejects an expired live generation without silently deleting it.
The caller must call `expire` to reclaim it. Injected time must not move backwards.

## Valid length, padding and draft wire format

For k sources choose `width = 2 + max(source_length)`. Each source coding vector
contains its original length as big-endian u16, its exact bytes, then zeros to
width. Coefficients multiply this entire vector, including both length bytes.
The decoder validates every identifiable source's length and all zero padding
before committing an equation. At full rank, the maximum recovered source length
plus two must equal the declared width; gratuitous all-zero extension is rejected.
There is no plaintext repair-length shortcut and
no use of source lengths fetched from a sender ledger.

The draft header is 56 bytes, all integer fields big-endian:

| Bytes | Meaning |
| --- | --- |
| 0..2 | `FE` magic |
| 2 | Version 1 |
| 3 | Kind: 0 systematic, 1 repair |
| 4 | Direction: 1 client-to-server, 2 server-to-client |
| 5 | Reserved zero |
| 6..8 | Source count k |
| 8..24 | Session ID |
| 24..32 | Epoch |
| 32..36 | Channel ID |
| 36..44 | Generation ID |
| 44..48 | Symbol ID |
| 48..50 | Coded-vector width |
| 50..52 | Coefficient count, exactly k |
| 52..56 | Reserved zero |
| 56..56+k | Explicit coefficient bytes |
| 56+k.. | Exactly width coded bytes |

Systematic packets must carry the canonical identity coefficient row for their
symbol ID; repair IDs must be at least k and coefficients must contain a nonzero
entry. The parser checks complete/exact lengths, every reserved field, all local
dimensions and the configured context before allocating. Every packet in one
generation must agree on count and width. Source count and width are not allowed
to expand based on later equations. Total wire length is `56+k+width`; caller
MTU planning subtracts actual outer framing/authentication before setting the
maximum FEC packet size. There is no implicit fragmentation here.

## Bounds, elimination and transaction rules

`BlockConfig` caps source count (at most 256), source bytes (at most 4096), packet
bytes and field-operation work per symbol. `DecoderConfig` additionally caps live
generations, accepted symbol identities per generation, reserved coding bytes,
generation lifetime and the generation-ID window. All limits are nonzero and
subject to fixed hard ceilings. Packets never choose allocation caps.

A generation reserves `(3*k + max_symbols_per_generation) * (k+width)` logical
bytes before allocation: at most k retained basis rows, k staged rows, k decoded
source vectors and the bounded exact received-symbol history. Counts separately
bound vector/map metadata. This is a conservative retained/scratch byte-accounting
contract, not allocator or process-RSS measurement. Empty dimension slots and
container metadata remain finite through their count limits.

For one input, the conservative work charge is `(2*k+1)*(k+width)` GF byte operations
plus a fixed inverse budget, regardless of sparse zeros. Reject a symbol whose
charge exceeds the configured bound before elimination or admission. Each
multiply takes eight polynomial steps. A fixed received-symbol cap bounds repeated
dependent inputs as well as innovation; the caller must also rate-limit repeated
rejected/duplicate packets and total authenticated sessions.

Eliminate into a private candidate basis, normalize the new pivot, and clear that
pivot from all other rows. A zero coefficient row with zero payload is dependent;
a zero coefficient row with nonzero payload is conflicting and is rejected.
Repeated IDs require exactly equal coefficients and coded bytes. Changed bytes,
generation descriptors or inconsistent equations reject without basis/history/rank
mutation. Validate newly identifiable source lengths/padding before committing.
Caller output is returned only by successful complete decoding.

The highest accepted generation defines a fixed count window; advancing it cannot
evict any live generation. Return an explicit window-blocked error instead. IDs
below the floor are stale, and retained completed/expired IDs are terminal. Time,
admission, descriptor, ID, capacity, deadline and work failures preserve decoder
state. Expiry is an explicit separate mutation and does not manufacture recovered
bytes or pretend insufficient rank is delivery.

## Work checklist

- [x] [MOD-FEC-01] Implemented safe polynomial GF(256), exact compact/Cauchy coefficient helpers and independently generated arithmetic vectors. Evidence: [field arithmetic](../../crates/l2tunnel-fec/src/field.rs), [independent Python fixture generator](../../crates/l2tunnel-fec/tests/generate_vectors.py).
- [x] [MOD-FEC-02] Implemented sealed systematic block encoding with coded valid lengths, zero padding, explicit vectors and strict wire/context parsing. Evidence: [encoder](../../crates/l2tunnel-fec/src/lib.rs), [wire parser](../../crates/l2tunnel-fec/src/wire.rs).
- [x] [MOD-FEC-03] Implemented real received-payload elimination, innovative/dependent/duplicate/conflict states and complete byte reconstruction without sender state. Evidence: [decoder](../../crates/l2tunnel-fec/src/decoder.rs), [repair-only and loss-subset tests](../../crates/l2tunnel-fec/src/tests.rs).
- [x] [MOD-FEC-04] Implemented generation/symbol/byte/work caps, failure-atomic input, injected deadlines, insufficient-rank results and bounded terminal history. Evidence: [decoder limits/state](../../crates/l2tunnel-fec/src/decoder.rs), [failure-boundary tests](../../crates/l2tunnel-fec/src/tests.rs).
- [x] [MOD-FEC-05] Verified byte-exact vectors, nonuniform payloads, loss/reorder, bad lengths/padding/context, conflicts, deadline/window/resource limits and decoder independence. Evidence: [17 focused tests](../../crates/l2tunnel-fec/src/tests.rs), [checked fixture files](../../crates/l2tunnel-fec/tests/fixtures).
- [ ] [MOD-FEC-06] Integrate authenticated carrier framing, MUX/wire budgets, sender retention, feedback and repair scheduling with actual end-to-end payload tests.
- [ ] [MOD-FEC-07] Implement separate sliding/elastic/hybrid/rank-feedback adapters and every relevant Python mode's trace/byte parity gate.
- [ ] [MOD-FEC-08] Add fuzzing, larger measured CPU/RSS/latency tests and native loss/reorder/PMTU qualification before enabling transport capabilities.

## Local verification receipt

These commands passed on the local Linux host:

```sh
python3 crates/l2tunnel-fec/tests/generate_vectors.py
python3 crates/l2tunnel-fec/tests/generate_vectors.py --check
cargo fmt --package l2tunnel-fec
cargo test --offline --package l2tunnel-fec
cargo clippy --offline --package l2tunnel-fec --all-targets -- -D warnings
cargo doc --offline --package l2tunnel-fec --no-deps
```

All 17 tests passed. The independent Python generator uses carryless polynomial
products followed by high-to-low reduction, compares all 65,536 products against
the existing simulator table, and compares compact/Cauchy coefficient rows before
writing full-payload wire fixtures. Rust verifies those fixtures and all product
entries. Receiver tests cover all 20 subsets of three among six systematic/Cauchy
symbols, repair-only compact RLNC with dropped/reordered equations, original
lengths 1..436 in that deterministic block, and a 4096-byte source. Encoder state
is dropped before receiver reconstruction in the loss tests. This proves the
finite cases' actual byte recovery, not complete Python transport parity,
congestion behavior, wire interoperability, native tunnel integration or throughput.
