# Bounded aligned channel receiver

Status: bounded primitive implemented and Python event-parity tested. This slice ports the observable receiver
behavior of `simulator/src/l2tunnel_sim/aligned_records.py` onto finite storage and
explicit native-delivery ownership. It reuses the verified aligned-body codec.
Runtime integration, sender scheduling, coding and full catalog gates stay planned.

## Authenticated identity and wire boundary

The legacy symbol is unchanged: channel u8, serial u16 big endian, then one aligned
body or kind-4 fragment. Fragment fields are kind=4, total u16 and offset u16,
followed by a full-capacity piece or zero-padded final piece. All fragments of a
record share its channel, absolute record identity and geometry. Protected symbols
have exactly the negotiated symbol length, including implicit zero extension.

`Scope { session: [u8;16], epoch: Epoch, direction: Direction }` and
`SymbolIdentity { scope, source: SourceId(u64), record: RecordId(u64) }` are supplied
by the authenticated enclosing adapter. The entire symbol, including channel,
must be authenticated together with that metadata. This pure receiver cannot
establish that fact. It compares scope, checks channel bounds and requires the
inner u16 serial to equal the absolute record ID's low 16 bits. Source/record
identities never wrap or reset within a scope. A stale absolute record cannot be
reintroduced under a fresh source ID after a 16-bit serial wrap.

This extra absolute identity is a new enclosing protocol requirement, not part of
the Python bytes and not a claim of existing authenticated wire compatibility.
Future runtime negotiation and MTU/wire budgets must account for its actual
encoded overhead. The carrier must preserve original source identity on retries
and recovered copies; a changed symbol under a still-retained source ID conflicts.

## Public API and ownership

`Receiver::new(scope, Limits)` validates bounds. Limits contain common body Config,
channel count, initial absolute source/record IDs, a per-channel forward record
window <=32767, source replay window, lookahead record/byte/fragment budgets,
maximum fragments per record and injected-tick lifetime. One expected record slot
and its full maximum body/fragment reservation are reserved per channel in addition
to lookahead budgets. Later records cannot consume the capacity needed to fill an
older gap. `SourceId`, `RecordId`, `ChannelId` and `Tick` are distinct typed values.

`admit_authenticated(identity, symbol, now)` checks scope/geometry/bounds and
retains one source/record contribution transactionally. Duplicate, stale source,
stale record and accepted outcomes are distinct. No native output or header
context change occurs during admission. A complete body may still depend on an
earlier context; its semantic validation occurs only when it becomes decodable.
Admission failure consumes no replay ID or queue reservation.

`prepare(channel, now, max_records)` performs bounded work on that channel. It
processes in-order context records and already delivered short-record tombstones,
then exposes at most one native frame via `pending()`. The caller's common
admission/QoS arbiter chooses the channel. While an immutable pending frame exists,
prepare returns that same item; device WouldBlock cannot overwrite or retire it.
`commit_delivery(now)` is called only after the native device accepts the complete
frame. It first checks the same monotonic deadline, then commits staged decoder context and advances/retire the expected record,
or marks an independently delivered short frame while preserving the gap.

A single preallocated staging decoder/native buffer supports preparation. The
committed per-channel decoder is unchanged until native delivery commits. Context
records have no native output and may commit during bounded prepare work. A later
bad record does not roll back earlier successful events; it terminates the scope.
No hidden vector of delivery callbacks or unbounded output queue is returned.

## Ordering, fragments, duplicate proofs and retirement

Ordinary records, including all compressed kinds, release FIFO within each channel.
Independent-short mode is explicitly selected by the body threshold and only
applies to complete unfragmented kind-2 records at or below that generic frame-byte
threshold. It does not classify SYNs or reserve an extra QoS path. After successful
early native delivery the full raw body and tombstone remain charged until the
contiguous watermark reaches it. The header context is unchanged and a second
copy cannot redeliver it. Other channels can continue through their own prepare
calls while this channel retains a gap.

`prepare_with_early_filter` lets the owner inspect the reconstructed native
bytes before exposing an independent short record ahead of a gap. A rejected
candidate consumes one visit. Later filtered calls skip that candidate until
its ordered turn, and other eligible short frames on the channel can advance.
An already exposed frame retains custody through device backpressure. The
[Packed/Rolling half-close study](frame-channel-experiment.md#receiver-tcp-half-close-and-the-483-record-tail)
describes the native TCP policy that uses this interface.

At the first fragment, reserve the entire declared body and every fragment slot.
Allocate one zeroed body buffer plus a fixed received-piece bitmap. Require total
length to exceed ordinary symbol body capacity, aligned offsets, canonical final
piece size and zero final padding. Overlapping/mismatched total or piece bytes
conflict. Completion validates exactly one ordinary explicit record; implicit
length/predictive bodies are never fragmentable. No fragment can expand its
reservation after the first piece. Completed records keep the same reservation
until actual retirement.

The source replay window is a fixed set of slots indexed by absolute source ID.
Out-of-window sources cannot evict unresolved holes. Each occupied slot retains
identity and exact symbol bytes for duplicate/conflict checks. Contiguous admitted
source IDs automatically advance a nonwrapping floor and release those duplicate
proofs; accepted record bodies remain independently owned. IDs below the floor are
stale and never reinterpreted. Fresh-source copies of already retired absolute
records are stale records and cannot deliver again. Source receipt progress is
separate from channel/native delivery progress.

## Resource and failure accounting

Bounds cover all payload allocations and metadata counts: per-channel head body
reservation plus lookahead bytes; head fragment slots plus lookahead fragment
slots; fixed record slots for channel heads plus lookahead records; fixed source
slots and at most `source_window * symbol_bytes` exact duplicate-proof bytes;
fixed per-channel decoders and one staging decoder/native buffer; and one bounded
final-fragment parser copy of at most 65535 bytes. Construction checks products/sums and hard limits
before allocation. Source proof allocation cannot consume the record progress
reserve. Record/source slot metadata is represented by bounded fixed vectors;
platform allocator overhead is separate from these exact payload/count bounds.

Caller time is monotonic. First admission establishes a record/source-proof
deadline; duplicates do not extend it. Expiry of an unresolved record, tombstone,
held native delivery or source hole is terminal. A receiver never discards a hole
and continues compressed interpretation. Wrong scope, malformed geometry,
conflicting duplicates, incompatible context and exhausted counters fail
explicitly. Retryable capacity/backpressure does not mutate admitted state.
A new session/epoch receiver requires separately authenticated, drained lifecycle
coordination; there is no unsafe local reset API.

## Evidence plan

Generate source-symbol and delivery-event traces by invoking the actual Python
transport/receiver: delayed context, independent generic short frame ahead of a
gap, per-channel independence, reordered fragments, duplicate copies and serial
wrap. Absolute outer identities in fixtures are derived from the actual sender's
record serial at creation, not inferred from arrival order. Compare complete
native bytes, context events and contiguous watermarks. Rust-only hostile tests
cover the stronger bounded/transactional/absolute-identity contract. Python's
unbounded maps and immediate callbacks are not copied as production behavior.

- [x] [MOD-ALIGNEDRX-01] Freeze authenticated absolute identity, progress reservations, prepare/commit and terminal expiry contract. Evidence: [implementation](../../crates/l2tunnel-codec/src/aligned_receiver.rs), [tests](../../crates/l2tunnel-codec/src/aligned_receiver_tests.rs), [actual Python traces](../../crates/l2tunnel-codec/tests/data/aligned-receiver-goldens.tsv), [generator](../../tools/generate_aligned_receiver_goldens.py).
- [x] [MOD-ALIGNEDRX-02] Generate independent actual Python symbol/event traces for reordered contexts/fragments, short release, duplicates, independent channels and wraps. Evidence: [implementation](../../crates/l2tunnel-codec/src/aligned_receiver.rs), [tests](../../crates/l2tunnel-codec/src/aligned_receiver_tests.rs), [actual Python traces](../../crates/l2tunnel-codec/tests/data/aligned-receiver-goldens.tsv), [generator](../../tools/generate_aligned_receiver_goldens.py).
- [x] [MOD-ALIGNEDRX-03] Implement bounded geometry/source admission and whole-record reservations without evicting source holes. Evidence: [implementation](../../crates/l2tunnel-codec/src/aligned_receiver.rs), [tests](../../crates/l2tunnel-codec/src/aligned_receiver_tests.rs), [actual Python traces](../../crates/l2tunnel-codec/tests/data/aligned-receiver-goldens.tsv), [generator](../../tools/generate_aligned_receiver_goldens.py).
- [x] [MOD-ALIGNEDRX-04] Implement per-channel FIFO, staged native prepare/commit and retained short tombstones with exact byte/context parity. Evidence: [implementation](../../crates/l2tunnel-codec/src/aligned_receiver.rs), [tests](../../crates/l2tunnel-codec/src/aligned_receiver_tests.rs), [actual Python traces](../../crates/l2tunnel-codec/tests/data/aligned-receiver-goldens.tsv), [generator](../../tools/generate_aligned_receiver_goldens.py).
- [x] [MOD-ALIGNEDRX-05] Test loss/reorder/retries, all budgets/backpressure, conflicting fragments, replay under fresh source IDs, scope/epoch/wrap/exhaustion and terminal deadlines. Evidence: [implementation](../../crates/l2tunnel-codec/src/aligned_receiver.rs), [tests](../../crates/l2tunnel-codec/src/aligned_receiver_tests.rs), [actual Python traces](../../crates/l2tunnel-codec/tests/data/aligned-receiver-goldens.tsv), [generator](../../tools/generate_aligned_receiver_goldens.py).
- [x] [MOD-ALIGNEDRX-06] Run focused strict checks, actual Python tests and coordinated aggregate validation with finite evidence recorded. Evidence: [stable wave5 aggregate](../../work/implementation-wave5/validation.json).
- [ ] [MOD-ALIGNEDRX-07] Integrate authenticated identity encoding, common MUX/QoS and sender/recovery/runtime epoch lifecycle before enabling complete catalog modes.

## Local verification and remaining boundary

`PYTHONDONTWRITEBYTECODE=1 python3 tools/generate_aligned_receiver_goldens.py --check`
reproduced 51 actual Python source-receive trace steps across seven traces. Rust
compares complete native event bytes/identities, both channel watermarks and exact
early-delivery tombstones after each step. Cases cover delayed contexts, reverse
fragment arrival, independently releasing channels, early generic short frames,
duplicates under original/fresh source IDs, empty raw frames and 16-bit wrap.
The fixture records hashes of the preserved Python sources.

`cargo test --offline -p l2tunnel-codec` passed 44 tests, including ten receiver
checks. The no-default-feature build passed 43 tests, including all ten receiver
checks. Strict targeted Clippy and denied-warning rustdoc passed. The preserved Python aligned-record,
independent-short-record and compact suites passed 363 tests, with one optional
`aioquic`-dependent report export test skipped. Hostile Rust tests separately cover
all input truncations, whole-fragment reservations, lookahead saturation with head
progress, immutable WouldBlock output, context commit after actual delivery,
wrong scopes, absolute stale identity, window/exhaustion, duplicate conflicts,
malformed final completion rollback and nonrenewable terminal deadlines. These are
finite deterministic checks, not formal proofs or native throughput measurements.

The decoder pool and adapter remain separate from any runtime. The new absolute
outer identities still need authenticated encoding, version/capability negotiation
and real wire-budget charges. Source receipt progress does not acknowledge native
delivery. Callers must keep polling injected time while idle, stop on a terminal
error, and call `commit_delivery(now)` only after whole-frame device acceptance.
The receiver provides no local reset, live reload or sender schedule. The
coordinated [wave5 aggregate](../../work/implementation-wave5/validation.json)
passed `python3 tools/check.py` with unchanged source hashes, 420 Rust tests
including doctests and 28 Python checks. This is local workspace verification;
no native integration or catalog gate is advanced.
