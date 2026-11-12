# Fixed-window local/global full-byte recovery

Status: the pure encoder/decoder and finite end-to-end recovery slice are implemented; focused checks and aggregate evidence are recorded below. This is a separate pure rolling equation
primitive; existing sealed block FEC, ARQ, wire formats and defaults are unchanged.
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
plus bounded rows and duplicate history. It prepares a preallocated shadow bank
using resumable copy/metadata/field work, and publishes accepted state atomically.
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
causal repair scheduling, large-window qualification and runtime selection remain
open under gates 06/07.

- [ ] [MOD-LGR-06] Add causal repair-credit/tail/feedback scheduling, authenticated wire framing and large-window qualification as separate gates.
- [x] [MOD-LGR-06A] Implement and test the additive bounded structural source/repair wire codec without granting authentication or replay authority. Evidence: [focused wire checks](../../work/rolling-wire15/validation.json), nine literal/parser/output-atomicity and independent received-wire recovery tests, strict FEC Clippy, warning-denied rustdoc and Cargo formatting. This is a structural contract, not authenticated transport integration.
- [ ] [MOD-LGR-07] Integrate explicit aligned/packed selection, runtime/client/native qualification and complete Python family parity.

The implementation checks the configured reservation before allocating two fixed
banks, input/candidate scratch and exact repair history. The bound includes owned
vector capacities and inline metadata, excluding allocator bookkeeping, caller
buffers and the bounded call stack. Construction is fallible. Bank copies and
GF elimination/normalization advance under separate byte, field and metadata
budgets; a budget of one field operation still progresses. The initial dense
two-bank algorithm is correctness-oriented; W8192 memory/CPU performance and
runtime service rates are not qualified by small-window tests.

Independent received-byte fixtures use literal maintained Python GF equations,
including four lost originals, zero coefficients, exact zero tails and nearly 2W
history/future retention. A separate two-owner stream crosses sixteen windows
(128 sources) under loss/reordering and handoff bounds 1, 3 and 8. The receiver
never reads a sender payload ledger. Review found and fixed an original batch
handoff deadline renewal (500 becoming 600 after a pending-job handoff); its
regression retains 500. Runtime tick overflow latches terminal before owning new
input, and high repair identities take modulo before converting to platform size.
