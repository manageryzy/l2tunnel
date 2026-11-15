# Reliable output custody until whole-carrier acceptance

Status: implemented and protocol-tested with affected strict checks. It composes the existing
[ARQ physical-attempt contract](arq-physical-send.md), without new wire bytes,
configuration digests, recovery engines or default timing changes.

`Reliable::enable_physical_send_confirmation()` explicitly selects the mode
before traffic. Legacy constructors retain poll-time transmission semantics.
Selected mode retains one inline `PreparedOutput` witness with private checked
owner/serial and optional actual ARQ `PhysicalTransmission`; public metadata is
`bytes`, `wire_bytes` and authoritative `RecordKind`. `pending_output()` observes
it, and `confirm_output(now, witness)` consumes exactly that witness after one
whole carrier write. Wrong, foreign or repeated witnesses change no time/custody.
`confirm_output_at(observed, accepted, witness)` separately retains the actual
whole-write instant when its receipt is observed later; the original method uses
the same instant for both. Accepted time must lie between the witness's original
preparation and observation, for repair/feedback as well as source output. ARQ
RTO starts at actual acceptance, not delayed callback observation. Invalid time
still consumes the exact physical custody once and fails the owner explicitly.

The existing `poll`, `poll_data` and `poll_feedback` share one wrapper around the
existing polling state machine. While an output is held, polling services
original time/receive state but returns no new packet, rewrites no caller bytes
and charges no new wire allowance. Before emission, local serial capacity is
checked. The maintained actual record inspector identifies direct/systematic
sources; only then is the ARQ owner's already-prepared source token attached.
Collecting an ARQ source into a partial FEC block is not a physical send and
creates no Reliable output witness. Repair and feedback outputs receive their
own real caller-held witness without inventing an ARQ source token.

Confirmation consumes matching physical custody even if later original-time
validation fails. Actual ARQ confirmation runs before wrapper/native deadline
checks, so an ACK-confirmed held retry is released once rather than resurrected.
Original recovery payload slots, FEC outputs and caller buffers remain the only
payload owners; no extra queue/allocation is introduced. Existing exact heap
plans account the actual ARQ backing, and embedding owners count changed inline
headers once. Historical scalar layout mirrors remain unchanged.

While a caller output is held, soft output-ready/ACK/retry/partial-flush wakeups
must not create an immediate busy-poll deadline for an output that cannot be
emitted. Actual FEC cleanup, native/receiver/handoff/session/operation bounds
remain independent; no original deadline is renewed. The caller's physical
writer and its original output cap provide the next I/O opportunity.
`expiry_deadline()` exposes only real receive-coding expiry in Reliable and adds
original receiver/handoff expiry in Aligned/Packed. It remains independent of
whether this owner or another retained generation holds the physical output.

Aligned and Packed Endpoint expose the same enable/pending/confirm methods over
their one actual Reliable owner. Their confirmation consumes Reliable custody
before checking local original native/receiver/handoff bounds. Common Engine/Bank
integration wraps the exact issuing generation's witness; neither codec extraction nor queue admission is physical acceptance.

Two executed focused cases exercise actual legacy/reserved partial FEC,
delayed acceptance observation, unchanged held bytes/debit, real peer ACK during
a held retry, foreign/repeated witnesses and unchanged legacy timer behavior.
Both pass, alongside the affected Reliable/Aligned cases and strict checks.
Their pure confirmation calls are trusted physical-boundary inputs; actual
Common blocked-output, mixed-family and finite native evidence remains separately
identified in the Wave8 receipt. Full RPC-04 remains open.

- [x] [RPC-01] Implement explicit Reliable physical-output custody over actual direct/FEC source, repair and feedback emission, with authoritative source-token lookup, unchanged bytes/debit on held output and unchanged legacy defaults. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [x] [RPC-02] Forward exact enable/pending/confirm through actual Aligned/Packed owners, preserving original receiver/native caps and exact one-time physical observation even on later timing failure. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [x] [RPC-03] Pass focused delayed-partial-FEC and blocked-output timing, held retry/ACK race, exact/foreign/repeated witness, real peer/native reconstruction and legacy-compatibility cases, plus affected strict checks. Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
- [ ] [RPC-04] Qualify actual Common Engine/Bank/runtime completion under the complete carrier, mixed-family, fault/resource/native/platform matrices and unchanged compact-arq/full SW-11 definitions. This finite pure slice does not close that gate or APC-02/03 by itself.
