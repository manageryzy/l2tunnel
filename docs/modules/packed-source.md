# Bounded Python-compatible source packing

Status: pure container/timer implementation and focused tests pass. This is a pure container and timed
sender primitive; it does not yet compose packed units with authenticated
absolute identities, source feedback, receiver rollback or native devices.

The preserved reference is `simulator/src/l2tunnel_sim/packed_wire.py`, especially
`_validate_unit`, `packed_units`, `_queue_source` and `_seal_pack`. The first
implementation lives in `l2tunnel_codec::packed`, without runtime or clocks.

## Interfaces and invariants

`parse(payload, symbol_bytes)` validates every packed unit and zero padding before
returning a borrowed iterator. The exact Python format is reserved channel 255,
u8 unit count (2..255), then u16 big-endian length and complete aligned bytes for
each unit. A single unit is sent unchanged. Native channels are 0..254. Fragments
must have exact capacity-aligned offsets and lengths. Explicit records must end
exactly; implicit bodies retain Python's context-dependent second-stage check.
Container validation does not install a decoder context or authenticate input.

`Config { symbol_bytes, hold_micros }`, `Packer::new`, `push(unit, copies, now)`,
`tick(now)`, `flush`, `pending`, `commit` and `status` form the bounded sender.
Injected monotonic time is integer microseconds; 500 means the reference 0.5 ms.
Hold must be 1..1000 microseconds. The packer owns one preallocated symbol buffer,
never an unbounded source queue. Adjacent units share a source only with identical
physical copy counts (1..4). Copy eligibility is supplied by the enclosing
configured policy and must not be inferred from a packet being a latency probe.

The first unit fixes the deadline; replacements/additions cannot extend it.
Capacity, copy-policy change, 255 units, a large unit, deadline or explicit flush
seals the source. The generic large-unit threshold is exactly
`unit.len() > (symbol_bytes - 6) / 2`. If adding a unit must first seal the previous
source, `push` returns a retry outcome without accepting that new unit. The caller
drains and retries the unchanged input. Sealed bytes remain immutable until
`commit`, which means actual bounded recovery ownership, not native delivery.
Repeated polling or downstream backpressure never creates additional copies.

All geometry, time arithmetic and clock regression are checked before mutation.
Packing itself does not allocate source IDs or acknowledge channel records. A
later integration must authenticate each unit's absolute channel-record identity,
assign one authoritative recovery source ID to the entire container, retain all
per-channel final record boundaries until valid source-prefix feedback, and
atomically validate/rollback every affected receiver context. The Python
`source * 256 + slot` convention cannot replace authenticated outer identities.

## Acceptance checklist

- [x] [MOD-PACK-01] Implement complete borrowed container validation and exact single/multi-unit bytes with Python-generated golden vectors. Evidence: [implementation](../../crates/l2tunnel-codec/src/packed.rs), [focused tests](../../crates/l2tunnel-codec/src/packed_tests.rs), [actual Python generator](../../tools/generate_packed_goldens.py).
- [x] [MOD-PACK-02] Implement one-buffer timed packing, equal-copy policy, capacity/large-unit/count flush, immutable pending source and explicit recovery handoff. Evidence: [implementation](../../crates/l2tunnel-codec/src/packed.rs), [focused tests](../../crates/l2tunnel-codec/src/packed_tests.rs), [actual Python generator](../../tools/generate_packed_goldens.py).
- [x] [MOD-PACK-03] Differential-test actual Python source emissions, fixed first-unit deadline and copy-policy transitions; test malformed units, padding, clock regression, overflow and backpressure. Evidence: [implementation](../../crates/l2tunnel-codec/src/packed.rs), [focused tests](../../crates/l2tunnel-codec/src/packed_tests.rs), [actual Python generator](../../tools/generate_packed_goldens.py).
- [x] [MOD-PACK-04] Run strict focused checks, independent review and stable aggregate validation. Evidence: [stable wave7 receipt](../../work/implementation-wave7/validation.json), [focused tests](../../crates/l2tunnel-codec/src/packed_tests.rs).
- [ ] [MOD-PACK-05] Compose source ownership and per-channel feedback with bounded transactional multi-unit receiver decoding, authenticated envelope and actual recovery; retain failure rollback and deduplication.
- [ ] [MOD-PACK-06] Integrate runtime/client selection, common MUX accounting, both directions/duplex policies and native impaired qualification before claiming packed-wire catalog parity.

## Focused evidence and remaining composition

The codec suite passed 54 tests, including five packing-specific tests. The
preserved Python implementation produced 28 scheduling observations and 169
parser outcomes. Strict all-target/all-feature Clippy and warning-denied rustdoc
passed; independent read-only review found no material blocker. The later
[source-stable wave7 aggregate](../../work/implementation-wave7/validation.json)
also passed with these primitives included.

The fixture invokes actual `_queue_source`, `_seal_pack` and `packed_units`;
it does not reconstruct their encoding algorithm. Python computes timer instants
with binary floating point, so an observation after `100us + 500us` uses 601us.
Rust separately verifies the exact integer 600us boundary. Source hashes and
unchanged inner bytes are preserved in the checked-in fixture. This is not a
simulator performance rerun, native throughput result or full packed-wire gate.

The integer geometry extends beyond Python's fixed1460-byte production profile.
At large symbols, the Rust sender seals at 255 units before the u8 count would
overflow. That explicit bound is an additional production safeguard. Scope,
authentication, per-unit record identities, source-prefix credit and atomic
multi-context receiver handling remain the next composition work.
