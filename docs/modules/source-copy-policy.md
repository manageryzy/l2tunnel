# Explicit short-source copy selection

Status: additive pure codec policy and actual sender integration are implemented
and protocol-tested with source-bound affected strict checks. Full Python-family, common
configuration, recovery/runtime, physical-copy, native and performance acceptance
remain required and open. No existing default or wire identity changes.

## Maintained reference and finite policy

The actual reference is
`simulator/src/l2tunnel_sim/compact_wire.py::_source_copy_count`: the threshold
counts the exact meaningful aligned unit, including its three channel/serial
bytes and body header, before L2PK identity metadata or outer framing. Zero
disables extra copies. `all_short` selects every valid unit within the threshold,
including a fragment. `context_and_independent` selects only a complete kind2
raw record or a complete kind0 context with its explicit body length66. The
whole unit must have exactly `6 + encoded_length` bytes. Selection is generic
size/record role; TCP flags, probes and application identity confer no privilege.

`packed_wire.py::_queue_source` classifies each unit before packing. Adjacent
units with different selected counts seal separate sources. `_source_copy_count`
then requires one homogeneous count for the packed source; the combined source
is not reclassified by its larger total length. `_aligned_source` allocates one
source ID/ledger entry and emits the same source wire bytes repeatedly, charging
each complete physical packet. Copies do not mint recovery identities, native
credit or new repair credit.

The additive pure module is `l2tunnel_codec::source_copy`:

- `Scope::{AllShort, ContextAndIndependent}`.
- `Policy { max_unit_bytes: usize, copies: u8, scope: Scope }` with
  `Policy::default()` selecting threshold0/count1/AllShort.
- `Policy::validate(symbol_bytes)` checks the exact configured geometry,
  threshold0..symbol_bytes and count1..4 before allocation or sender mutation.
- `Policy::copies_for_unit(unit, symbol_bytes)` uses the maintained canonical
  unit validator, then applies the reference rule to exact meaningful bytes.
  Invalid policy/unit input returns a typed error; it is never clamped.

The existing Rust packer supports1..4 physical copies. Python accepts an
arbitrarily large positive integer; values above4 remain an explicit unsupported
range in this finite Rust slice, not a completed parity claim.

## Actual sender seam and custody

The actual aligned sender adds `pending_copies(policy)` over its existing
`pending_unit`; inspecting it does not advance record/fragment/context ownership.
The actual packed sender adds `new_with_copies(scope, config, policy)` and
`new_reserved_with_copies(scope, config, limits, policy)`. They validate the
immutable selected policy first. Existing constructors and internal reserved
construction keep the exact one-copy policy; Config encoding/digests are unchanged.
The existing heap-only Plans retain the same allocations; embedding owners count
the actual additional inline policy through their real layout.

`packed_sender::Sender::poll` classifies each actual unit and passes its selected
count to the existing Packer. Copy-policy boundaries use its existing
FlushRequired/Backpressure transition, leaving the new unit/frame with the actual
aligned stage and retaining the original sealed source/deadline. `pending_copies`
reports the retained sealed source's count. `write_pending` preserves exact
source/unit/record IDs and wire bytes across repeated inspection and output
pressure, including multiple-copy selections. `commit_source` still means one
actual recovery owner copied that source; it does not mean all physical copies
were written and must not be called repeatedly to allocate duplicate sources.

No second recovery engine, payload queue, crypto or clock is introduced. The
caller must authenticate a selected policy before shared profile installation,
retain one actual source identity across its required physical copies and charge
each complete enclosing packet under the existing budget/custody rules. Merely
returning a count is not that recovery/runtime/physical-send integration.

## Stable acceptance

- [x] [SCP-01] Implement canonical generic-size and context/independent copy classification, exact threshold and malformed-input handling, preserving the explicit1..4 supported range and unchanged one-copy default. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [x] [SCP-02] Integrate selected counts into the actual bounded aligned-unit/packed-source sender, preserving copy-boundary retry, exact wire/IDs, immutable pending source/deadline and both existing constructor paths without new heap allocations. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [x] [SCP-03] Pass focused actual sender tests for generic/context/raw/fragment selection, homogeneous multi-unit packing, policy-boundary backpressure, exact output retry, reserved/compatibility ownership and unchanged defaults; run affected strict checks with source-bound evidence. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [ ] [SCP-04] Install authenticated copy policy and actual repeated physical-source custody in recovery/common profiles/runtime/service with per-copy full wire accounting, feedback/drain/native behavior and complete fault/resource/native/performance matrices. This full follow-on is not satisfied by the pure policy/sender deliverable.

All existing P-* definitions, M4, complete packed/rolling/resource gates and
SW-11 remain unchanged. Historical simulator receipts are preserved, not rerun or
reinterpreted as kernel evidence.

The three executed focused cases classify exact canonical units at threshold boundaries
and reject malformed/unsupported inputs; drive actual context-to-body copy-policy
flush with retained source/frame and output pressure through both constructor
paths, then reconstruct the original through the existing receiver; and verify
generic counts before multi-unit packing, byte-identical default output, unchanged
reserved capacities and actual fragment classification. All three pass.
The initial aggregate remains failed at175/177; only its named positive cases
are reused. Later exact runtime repairs and affected strict checks are recorded
separately. SCP-04 remains required and open.
