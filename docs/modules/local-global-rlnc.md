# Fixed-window local/global full-byte recovery

Status: the pure encoder/decoder, additive causal scheduler and finite full-byte
recovery slices are implemented; their separately scoped evidence is recorded
below. Existing sealed block FEC, ARQ, wire formats and defaults are unchanged.
The complete local-global-rlnc/compact-wire catalog gates remain open.

The reviewed work direction is recorded in
[the dependency note](../../work/next-recovery-family14.md) and
[bounded ownership design](../../work/rolling-equation-design14/DESIGN.md).
The first API is `l2tunnel_fec::rolling::{Config, Encoder, Decoder}` with typed
scope/source/repair identities, injected integer time and explicit WorkBudget.
It accepts caller-authenticated descriptors; it supplies no authentication proof,
network framing, ARQ, runtime scheduler, native adapter or configuration switch.

The encoder retains confirmed columns still inside a fixed global support.
Regular support is local except each configured global slot; tail support is
always global with an explicit seed. The maintained compact coefficient formula
is reused. Original vectors contain a u16 length, exact bytes and zero padding.
The initial primitive carries complete vectors; repair-padding trimming is absent.

The decoder keeps historical and future known columns across nearly 2W slots,
plus bounded rows and duplicate history. It stages changed metadata in two-version
cells and copies only equation rows first mutated by a job. One preallocated
transaction decision publishes those versions atomically; abort leaves the prior
committed versions selected. Known payloads occupy one shared preallocated ring;
staging never overwrites an identity still referenced by committed history.
Rank-zero systematic input skips row copies. Unchanged rows and metadata are
neither copied nor swept at publication. Fixed version descriptors and decision
references/free slots are included in `Decoder::memory_bound` before allocation.
Every useful repair end is bounded by decoded-prefix+W before work. Repairs ending
at/before the decoded prefix are stale. Recovered source handoff is separate from
native delivery; only the upper owner can prove native delivery. The public `decoded_prefix` is the contiguous **published receipt** prefix,
capped at `handoff_prefix + handoff_sources`; additional algebraically decoded
future columns remain in the same bounded known bank. This avoids deadlocking a
batch that fills more than one output slot. A successful upper handoff (with no
pending decode job) or a budgeted idle step publishes the next already-known
source without new peer input. During a job only the separate handoff watermark
moves, preserving its bank snapshot. Existing batch handoff deadlines survive
that interleaving and never restart. Prefix advancement is not native delivery.

A small-window test is not W8192 deployment or full Python parity. The simulator's
rank/source ledger is not used for Rust payload recovery. No performance/fairness
claim is made. Python support/seed/extent fixtures remain distinct from the new
enclosing length-vector format.

- [x] [MOD-LGR-01] Implement checked fixed-window support/seed policy and exact original-length vectors without modifying sealed-block limits. Evidence: [stable focused checks](../../work/rolling-recovery-checkpoint15/validation.json), 39 unit and 3 independent-endpoint integration cases, strict lint/docs and formatting; [independent equation/failure fixtures](../../crates/l2tunnel-fec/src/rolling/tests.rs) found the deadline regression fixed and described below.
- [x] [MOD-LGR-02] Implement bounded encoder retention, real payload equations, immutable pending output and injected-time work limits. Evidence: [stable focused checks](../../work/rolling-recovery-checkpoint15/validation.json), 39 unit and 3 independent-endpoint integration cases, strict lint/docs and formatting; [independent equation/failure fixtures](../../crates/l2tunnel-fec/src/rolling/tests.rs) found the deadline regression fixed and described below.
- [x] [MOD-LGR-03] Implement shadow-bank rolling decode, historical/future known-column bounds, duplicate/replay rules and atomic source publication. Evidence: [stable focused checks](../../work/rolling-recovery-checkpoint15/validation.json), 39 unit and 3 independent-endpoint integration cases, strict lint/docs and formatting; [independent equation/failure fixtures](../../crates/l2tunnel-fec/src/rolling/tests.rs) found the deadline regression fixed and described below.
- [x] [MOD-LGR-04] Test independent actual-byte recovery, old confirmed columns, local/global/tail schedules, serial wrap, bounded work, pressure and original deadlines. Evidence: [stable focused checks](../../work/rolling-recovery-checkpoint15/validation.json), 39 unit and 3 independent-endpoint integration cases, strict lint/docs and formatting; [independent equation/failure fixtures](../../crates/l2tunnel-fec/src/rolling/tests.rs) found the deadline regression fixed and described below.
- [x] [MOD-LGR-05] Run focused strict checks and independent review; record exact scope and limitations. Evidence: [stable focused checks](../../work/rolling-recovery-checkpoint15/validation.json), 39 unit and 3 independent-endpoint integration cases, strict lint/docs and formatting; [independent equation/failure fixtures](../../crates/l2tunnel-fec/src/rolling/tests.rs) found the deadline regression fixed and described below.
## Version-one bounded structural wire codec

The additive `rolling::wire::{inspect, encode_source, encode_repair, View}` codec
uses a fixed 64-byte `L2RW` version-one header and the complete negotiated vector.
It is structural parsing only: the caller must authenticate/replay-check the
complete enclosing record and compare its scope before rolling-owner admission.
Existing block/compact wire bytes and profile defaults are unchanged.

All integers are unsigned big-endian. Header offsets are: magic 0..4, version 4,
kind 5 (source 1 / repair 2), tail flag 6, reserved zero 7, session 8..24,
epoch 24..32, stream 32..36, direction 36, reserved zero 37..40, full identity
40..48, support start 48..52, exclusive end 52..56, seed 56..60, complete vector
length 60..62 and reserved zero 62..64. Unknown flags/version/kind and all nonzero
reserved bytes fail closed. Source support is exactly `[id,id+1)` with seed zero
and no tail flag. Repair support and seed follow `Config::support` using the full
nonwrapping identity. Source bodies carry `u16 length || exact original || zero
padding`; repair bodies carry the full equation width. Trimming is absent.

The codec and nine focused tests implement subgate 06A. Independent complete
Python-packed source/repair literals recover each missing original through the
actual decoder with small work budgets. TODO: authenticated transport framing,
runtime composition of the pure scheduler, large-window qualification and runtime
selection remain open under gates 06/07.

## Bounded causal scheduler API (06B)

The additive pure layer is `rolling::scheduler::{Policy, Sender, Receiver}`.
`Policy` embeds the unchanged rolling Config, an exact repair numerator /
denominator (0 <= numerator <= denominator <= 65536), explicit positive tail
and feedback tick intervals, a bounded feedback event threshold, and a total
owner memory ceiling. There are no inferred RTTs, clocks or I/O handles.

`Sender` owns the actual Encoder and one immutable systematic/repair descriptor.
`admit_source`, budgeted `step`, borrowed `pending_output`, failure-atomic
`encode_pending`, and identity-checked `confirm_output` separate local admission,
real caller handoff and repair work. Only successful source handoff earns repair
credit. A regular repair is serviced before another source; full nonwrapping
repair IDs retain the existing local/global/seed rules. Tail service uses the
latest authenticated deficit (at least one, at most W), repeats after actual
tail handoff, and stops only at a cumulative receipt. Polling, zero work,
WouldBlock and duplicate feedback do not reset original debt/output deadlines.
New successful source handoff supersedes the idle-tail due time, as Python's
source serialization finish supersedes its tail generation. A due time is a
service trigger; original debt/output deadlines remain hard expiry bounds.

`Receiver` owns the actual Decoder, one budgeted feedback scan and one immutable
feedback output, without a sender payload ledger. Complete received source/repair
wire bytes enter through the existing codec. Feedback carries full Scope, an
independent nonwrapping feedback ID, actual published cumulative prefix,
committed observed end and `max(unknown sources - independent rank, 0)` deficit.
Count or first-event timeout triggers feedback; a repeated/stale tail can cause
a fresh cumulative receipt after feedback loss. Feedback scans freeze new decode
admission while visiting at most W known-column identities under metadata work;
serialization advances under byte-copy work. A retained feedback output does
not freeze independent decoder progress and never changes bytes. Its original
handoff deadline remains fixed. Receiver handoff remains distinct from native
delivery. An additive fixed 64-byte structural `L2RF` version-one feedback codec
carries these fields; all reserved bytes and unsupported versions/kinds fail.
Outer authentication/replay/domain binding remains mandatory caller authority.
Feedback header offsets are magic `L2RF` 0..4, version 1 at 4, kind 3 at 5,
reserved zero 6..8, session 8..24, epoch 24..32, stream 32..36, direction 36,
reserved zero 37..40, feedback ID 40..48, prefix 48..52, observed end 52..56,
deficit 56..60 and reserved zero 60..64. Integers are unsigned big-endian.
A prefix/deficit is checked against actual successful source handoffs before
sender retention changes. Same retained identity/body is a duplicate, a changed
body conflicts, and older identities/regressed prefixes cannot change debt.

`encode_pending` writes a complete data record to caller-reserved storage using
the unchanged wire codec; it does not consume the borrowed descriptor. This is
a separate bounded atomic serialization call (at most 4162 bytes), like the
primitive's bounded input copy. `step` contains only resumable GF/metadata/copy
work. `Encoder::confirm_repair` provides identity-checked no-copy consumption
only after full external handoff; undersized encode attempts and WouldBlock
never invoke it. No additional payload queue or packet allocation is introduced.

Python references are CompactTransport `_source`, `_tail`, `_advance`,
`_feedback`, `_receive_feedback`, SharedRecordTransport `_repair`, and fixed
CompactWireTransport support/retention. Engineering differences are deliberate:
an explicitly bounded numerator/denominator interface (Python also accumulates
integer credit using `Fraction(str(repair_ratio))`), explicit caller handoff instead of
simulated serialization finish, bounded resumable work/output storage, identified
feedback with strict stale/conflict handling, original hard deadlines, full-byte
GF recovery and structural enclosing wire. No inferred known link RTT, source
ledger materialization, implicit packet packing or complete Python-family parity
is supplied. Gates 06/07 remain open after this finite subgate.

- [ ] [MOD-LGR-06] Add causal repair-credit/tail/feedback scheduling, authenticated wire framing and large-window qualification as separate gates.
- [x] [MOD-LGR-06A] Implement and test the additive bounded structural source/repair wire codec without granting authentication or replay authority. Evidence: [focused wire checks](../../work/rolling-wire15/validation.json), nine literal/parser/output-atomicity and independent received-wire recovery tests, strict FEC Clippy, warning-denied rustdoc and Cargo formatting. This is a structural contract, not authenticated transport integration.
- [x] [MOD-LGR-06B] Implement causal bounded repair-credit/tail/identified cumulative feedback scheduling over actual rolling owners and wire; verify independent two-owner exact bytes under data/repair/feedback loss, reorder, output pressure, tiny work and original expiry. Evidence: [scoped exact-file receipt](../../work/rolling-scheduler16/validation.json), 49 FEC unit and 16 independent integration cases (13 scheduler / 3 existing stream), strict FEC lint/docs and formatting. New maintained-Python repair/feedback literals pin actual deficit/rank and full structural bytes; W8 budget1/17/65536 exchanges cross eight windows. This finite pure slice does not complete either parent gate.
- [x] [MOD-LGR-06C] Remove complete known-payload bank copies while preserving bounded work, retained history and atomic recovery publication. Evidence: [focused optimization receipt](../../work/fix03-shared26/RECEIPT.md),69 FEC tests, strict Clippy and formatting; partial rank-positive recovery preserves exact committed payload/rows/identities through original expiry. At G8192/width1450 the reservation drops23,756,800 bytes. This is a pure-module checkpoint; FIX-03 still requires measured large-window service cost and runtime qualification.
- [x] [MOD-LGR-06D] Remove whole-capacity equation and metadata transaction snapshots with preallocated two-version cells, first-mutation row copies and constant-size publish/abort. Verify actual W8192/2048-row clean and rank-one work, repeated Capacity rollback/retry, partial-copy original expiry, delayed-handoff ring wrap and commit-token reuse/exhaustion. Evidence: [scoped before/after report](../../work/rolling-sparse29/REPORT.md), [exact receipt](../../work/rolling-sparse29/validation.json). This pure work reduction leaves the runtime global-support128 guard, remaining algebra/window scans and FIX-03/FIX-09 parent gates open.
- [ ] [MOD-LGR-07] Integrate explicit aligned/packed selection, runtime/client/native qualification and complete Python family parity.

The implementation checks the configured reservation before allocating two row
versions, versioned metadata, a bounded decision/reference/free-slot pool,
input/candidate scratch and exact repair history. The bound includes owned vector
capacities and inline metadata, excluding allocator bookkeeping, caller buffers
and the bounded call stack. Construction is fallible. No per-job allocation is
introduced. First row mutation copies the selected committed version under copy
budget; later mutations reuse the staged version. Zero-change decisions are
immediately reclaimed; aborted versions release their references when overwritten.
Nonwrapping transaction serial exhaustion is checked before decision allocation.
A cursor evicts only newly expired known identities, including prefix advancement
that occurred during idle handoff service. Row copies and GF elimination advance
under separate byte, field and metadata budgets; a budget of one still progresses.
Candidate clearing, coefficient normalization/reduction/counting and row scans
remain dense work. W8192 native service rates and matched Python throughput remain
unqualified; finite work counters are not CPU or real-kernel measurements.

Independent received-byte fixtures use literal maintained Python GF equations,
including four lost originals, zero coefficients, exact zero tails and nearly 2W
history/future retention. A separate two-owner stream crosses sixteen windows
(128 sources) under loss/reordering and handoff bounds 1, 3 and 8. The receiver
never reads a sender payload ledger. Review found and fixed an original batch
handoff deadline renewal (500 becoming 600 after a pending-job handoff); its
regression retains 500. Runtime tick overflow latches terminal before owning new
input, and high repair identities take modulo before converting to platform size.
