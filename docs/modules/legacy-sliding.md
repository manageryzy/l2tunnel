# Legacy sliding and hybrid FEC protocol components

Status: **implemented pure component with root finite protocol evidence**.
[Batch15](../../work/parallel-features-20261115/parallel-batch15-scoped-validation.json)
passes all 14 legacy cases and three affected explicit-coefficient cases.
The [frozen delivery](../../work/parallel-features-20261115/batch15-staging/external-legacy-fec/final-manifest.json)
retains the external commit and results. Explicit admission-aligned and actual
source/repair batch owners are now integrated. Their finite closeout passes are
recorded below; complete feedback-trace and end-to-end P-* alignment remain open.
This additive component targets real-byte legacy sliding/hybrid recovery with
periodic and causal feedback repairs plus residual selective ARQ. The public boundary is
[`l2tunnel_fec::legacy_sliding`](../../crates/l2tunnel-fec/src/legacy_sliding/mod.rs);
actual validation commands and results belong to the integrating change.
The complete `P-legacy-sliding-fec` and `P-legacy-hybrid-fec` tasks remain unchecked;
this component does not install Common/native runtime, a carrier or a default.
See the unchanged [mode contract](../mode-parity.md#recovery-and-scheduling).

## Exact Python reference semantics

The source is [model.py](../../simulator/src/l2tunnel_sim/model.py), specifically
`Flight` (196–205), `Tunnel.add_to_code`/`flush_code` (299–339), `queue_repair` and
transmission/retry handling (341–390), receive/decode (392–416), feedback batching
(445–469) and causal repair selection (471–497). Configuration defaults and limits
are [config.py:Strategy](../../simulator/src/l2tunnel_sim/config.py), lines 57–120.
The existing simulator and saved observations remain unchanged.

Periodic support is the latest `long_window` admitted source symbols, including
acknowledged symbols still in that history. Sliding always selects that whole
window. Hybrid selects its `short_window` suffix except every `long_every`th
**generated periodic repair**, which selects the long window. Feedback repairs
neither increment nor reset that periodic counter. Support freezes when the repair
is queued; later admissions or feedback do not rewrite it.

For ordinary batching, a full `repair_every` source group emits
`repairs_per_group` repairs. A timed partial group emits
`ceil(fec_count * repairs_per_group / repair_every)`. The FEC timer begins at the
first source of the current group; each flush increments its generation so an
older timer cannot flush a newer group. Python flushes its source packer before
queuing repairs. The oldest outstanding group timer is not renewed by later
sources in that group.

With `interleave_repairs`, every source contributes `repairs_per_group` integer
credits and reaching `repair_every` triggers a flush. A flush emits
`max(1, credit / repair_every)` repairs and subtracts their credit with saturation.
Consequently a timer flush emits one repair even with insufficient integer credit.
This low-load behavior is part of the reference and must not be replaced by a
strict long-run ratio or a silent no-op. Periodic row j within one flush is queued
at `flush_time + (j+1)*repair_spacing`; feedback repairs use zero spacing.

`queue_repair` draws one independent **nonzero** coefficient with
`Random.randrange(1,256)` per selected source. These are not the compact counter
coefficients, which can be zero. The production `CoefficientSource` boundary fills explicit bounded
coefficient bytes from the caller and validates them before ownership changes.
An injected trace can reproduce the exact Python draws. The component does not
claim that a different PRNG shares Python's Mersenne Twister seed sequence, add a
custom crypto primitive or use FEC as authentication.

## Causal feedback repair and residual ARQ

Delivered feedback first retires its cumulative prefix and selective source IDs.
The sender's highest observed receipt then becomes the maximum of its previous
value, this prefix and the greatest selective ID. Causal feedback repair considers
pending sources in increasing order strictly below that high watermark, with at
most `long_window` candidates. Each candidate must satisfy all these conditions:

- Exactly one source transmission attempt has completed.
- No early feedback repair has already selected this source.
- No queued repair still covers it, including spacing and packing waits.
- The current time is at least `max(sent_at + path_rtt, repair_until)`.
- The selected candidate cohort fits the configured repair payload budget.

Python checks `max(candidate_source_size) + 4*candidate_count <= MTU-88` before
adding each candidate. An oversized candidate is skipped while later smaller
ones may still qualify. For m candidates the reference queues **m distinct repair
rows over the same sparse candidate set**, marks every candidate `early`, then
flushes the repair packer. It does not send only one row, infer a receiver rank
or use instantaneous loss knowledge. Later copies of feedback cannot grant a
second early-repair opportunity to the same source.

`queued_repairs` increases when a row is queued and decreases on its transmission.
Every transmitted repair updates each still-pending covered source's
`repair_until = max(old, finish + path_rtt + feedback_wait)`. Only a
**feedback-triggered** repair whose expected receipt time is at least `retry_at`
rearms that source's timeout to `expected + rto_min`. A periodic repair never
postpones the source timeout. In particular, a due timeout still retransmits
while a spaced periodic repair remains queued; `queued_repairs` and
`repair_until` gate early feedback repairs, not the independent timeout handler.

For each original or retry, Python records the selected path's serialization
finish as `sent_at`, stores that path's RTT, increments attempts, and arms
`finish + max(rto_min, path_rtt*rto_factor)`. Every retry uses that same formula;
there is no exponential backoff, Karn sampling, SRTT estimator or ACK-delay
subtraction in this family. Timer callbacks carry the expected retry deadline;
old callbacks cannot act after a newer deadline replaces it. Acknowledged sources
cannot be resurrected by late retry callbacks.

The ordinary selective-repeat engine has configured exponential backoff and a
64-source bitmap window; Compact ARQ has serial echo, measured RTT and distinct
fast-retry rules. Neither unchanged engine implements this legacy state machine.
The new component reuses existing byte/GF/storage/decoder capabilities and keeps
its small legacy flight metadata explicit instead of relabeling a Reliable wrapper.

## Feedback generation and caller ownership

Every newly decoded source marks its ID for feedback. A duplicate known systematic
source marks that ID again, allowing recovery from a lost feedback datagram.
A dependent repair that learns no source creates no such event. The first pending
ID starts the feedback timer. Feedback flushes at the configured batch or its
wire capacity, and IDs are sorted and deduplicated. A cumulative profile advances
its contiguous **received** prefix and omits selective IDs at/below that prefix;
a selective-only profile sends the exact collected IDs. Python's inclusive `-1`
initial prefix maps to the Rust optional/exclusive prefix representation.

Receipt is independent of upper/native handoff. Out-of-order committed known
sources must remain eligible for selective feedback. Speculative decoder rows may
never enter a receipt snapshot. Feedback travels on the actual opposite-direction
lossy budget; no reliable management side channel or free confirmation is implied.

The production output boundary uses immutable prepared records and explicit
complete carrier-custody acknowledgment. The caller injects original creation,
actual acceptance, observation and path RTT times. Preparation and WouldBlock
must not pretend that an original or retry has physically departed. Rational RTO
factors use checked arithmetic and round upward to the caller's integer tick;
`5/2` exactly represents the Python default factor 2.5 before tick quantization.

The compatibility constructor retains its historical physical first-send credit
boundary and is not a Python-alignment selection. The explicit
`Sender::new_admission` / `new_reserved_admission` owner instead uses
`admit_source_with_coefficients`: source credit, periodic group readiness and
frozen coefficients/support are published at coding admission, before physical
completion. Its original first-group timer can flush while an earlier source or
repair output remains immutable. The selected owner admits additional originals
into a fixed metadata-only unsent queue; actual source bytes remain single-owned
in the existing encoder. Every unsent source retains its original creation-based
output cap, and requested/observed storage includes the queue exactly once.
Coefficient or capacity refusal before publication consumes no source ID or row.

The explicit encoder path can add a later source during a frozen repair only
when it cannot overwrite any active or queued equation column or unsent original.
Ordinary rolling/Research admission behavior is unchanged. A new admission,
WouldBlock, retry or duplicate completion never changes the held packet bytes,
earliest debt, timer generation or physical source-attempt count. Authenticated
feedback may retire an original only after its systematic output, or an equation
actually covering it, has physically completed; local coding admission is not
receipt authority.

The admission owner is implemented and its three finite admission cases passed
in the first closeout check. Compatibility L2LS v1 remains one record per physical
output. The separately selected batch owner below implements actual source/repair
packet custody, first-item timers, shared packet loss and exact framing charges;
metadata readiness alone is not its completion criterion. Full Python feedback
trace and runtime/native compositions remain unqualified.

## Actual bytes, bounds and integration limits

The additive draft `L2LS` version-one header is 72 bytes. A source costs
`72 + original.len()`, a repair `72 + 5*term_count + max_payload + 2`, and feedback
`72 + 4*selective_count`; the cumulative prefix lives in the fixed header.
Each repair term is an absolute source ID plus its nonzero coefficient. The coded
vector includes the real two-byte length, payload and zero padding. Meaningful
trailing zero bytes survive recovery. Actual enclosing authentication, carrier and
copy overhead must be added by the caller; every emitted source, repair, retry
and feedback record consumes the same selected admission/channel/wire budget.

These charges are different from Python's analytical 88-byte outer header and
four-byte feedback identifiers. A separate `feedback_payload_budget` preserves
the Python candidate and feedback batching constraints. `max_record_bytes` must
independently hold the entire largest explicit equation and configured feedback
record; it cannot silently crop selected terms. Near-MTU framing and packing
still do not have byte-identical behavior merely because their coefficients agree. The simulator's coefficient/rank decoder and source ledger
are not actual payload or kernel performance evidence.

The represented legacy windows, outstanding source horizon and per-group counts
are bounded at 255. The decoder retains up to two such windows of committed source
history while upper handoff stalls; receipt deduplication uses that same horizon.
`Strategy` already bounds the periodic windows and counts; the finite outstanding
source horizon is an additional production resource limit. Periodic
source history and unconfirmed/ARQ retention remain distinct bounds. The frozen
repair queue has at most 1024 slots, payloads at most 4096 bytes, and each source
has an explicit finite attempt limit. Sparse feedback candidates can include older pending holes outside the
latest periodic window. Full-byte recovery reuses the existing GF(256) polynomial,
rolling source slots, bounded decoder transactions, duplicate history and injected
work budget. Payload, term/span, row, queue, retry, memory and original-lifetime
caps must be validated before allocation/admission. Pressure returns explicit
errors or terminal failure; it may not silently shorten an equation or refresh
an original deadline. Caller buffers and allocator/RSS overhead remain separate
from retained-capacity accounting.

All payload algebra, decoder transaction copies and exact coefficient-history
publication consume the existing `WorkBudget`. Protocol metadata operations have
separate fixed bounds: at most 255 flights, 1024 queue slots and 65,025 coefficient
entries per atomic sender batch; receiver scans visit at most 510 committed IDs
per input, one budgeted metadata visit per ID. Each visit may search at most 255
pending receipts. An atomic feedback snapshot performs at most 65,025 comparisons
and copies at most 255 IDs. Input parsing/staging copies at most 255 explicit
terms plus one bounded payload; output serialization copies one bounded record.
These fixed control copies are not reported as incremental GF copy work.

Original source creation bounds its first output and recovery debt. Retries and
repair scheduling never renew that debt. The earliest debt of a continuously
nonempty sender episode remains conservative even after that particular source
is acknowledged; it clears only when all originals are acknowledged. Queued
repair expiry remains owned after ACK. Receiver job/feedback expiry inherits the
original authenticated arrival and caller cap, while its feedback batching timer
starts when committed recovery becomes visible. The earliest finite operation
cap remains until input, recovery handoff and reverse feedback all drain.

`Sender::is_drained` requires no unacknowledged original, partial FEC group,
queued repair or physical output. `Receiver::is_drained` requires all observed
sources handed off and no staged/scan/feedback state. Retained coding/duplicate
history alone is not outstanding work. Neither completion predicate asserts
native device delivery. The caller services `next_wakeup`, observes `deadline`,
reserves `Output::charge`/`Feedback::charge` against the appropriate direction,
and confirms the exact custody ID only after complete physical output.

Reordered feedback snapshots merge their selective/cumulative ACK evidence while
retaining the latest snapshot fingerprint. An exact duplicate of the latest ID
is idempotent; a different body under that ID is refused. Older snapshot replay
binding belongs to the authenticated enclosing transport. Repair replay checks
retain exact coefficients and coded bytes for `repair_history` identities;
older stale repairs cannot resurrect retired sources. Ordinary loss is recovered
by actual equations or constant-rule residual source retransmissions, bounded
by the configured attempt and original-age limits.

The caller authenticates/replay-checks whole incoming records and binds the
complete immutable configuration to its session/epoch. Public libraries retain no
Tokio dependency, OS handles or real clock. Common Engine/Bank/capability wiring,
native frame fragmentation/reassembly and end-to-end batch installation, ordered
lanes, selected-carrier loss,
full resource/fault/native/platform qualification and all end-to-end P-* gates
remain open.

## Focused source-bound oracle

[generate_legacy_sliding_vectors.py](../../crates/l2tunnel-fec/tests/generate_legacy_sliding_vectors.py)
extracts actual Python class/functions through AST and injects a small event clock,
fixed serialization/RTT inputs and `Random(7349)`. It emits
[legacy-sliding-policy.txt](../../crates/l2tunnel-fec/tests/fixtures/legacy-sliding-policy.txt)
without importing an experiment runner or editing simulator/history. The finite
fixture covers proportional partial flush, interleave timer minimum, hybrid long
cadence, retained acknowledged history, sparse feedback replacement rows, queued
repair guards, unchanged periodic RTO, feedback-delayed retry and repeated source
feedback. Its payload rows use actual Python GF multiplication on variable
nonzero/trailing-zero source bytes. This is a small oracle, not a replacement
simulator or a complete event/runtime equivalence claim.

The [scoped receipt](../../work/legacy-sliding-20261116/attempt-1/validation.json)
records the actual local Linux commands and stable source hashes. These passed:

- `python3 crates/l2tunnel-fec/tests/generate_legacy_sliding_vectors.py --check`
- `cargo fmt -p l2tunnel-fec -- --check`
- `cargo test -p l2tunnel-fec --lib legacy_sliding --offline`
- `cargo test -p l2tunnel-fec --lib rolling::explicit::tests --offline`
- `cargo test -p l2tunnel-fec --lib research_real_payload_loss_reorder_reset_fallback_and_ack_history --offline`
- `cargo clippy -p l2tunnel-fec --lib --tests --offline -- -D warnings`
- `RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-fec --no-deps --offline`

All Cargo checks used the root-managed `CARGO_TARGET_DIR=/tmp/l2tunnel-recursive-target`.
The legacy cases compare actual Python periodic events and nonzero coefficient
vectors, recover exact variable/trailing-zero originals from received bytes after
dropping the encoder, and cover causal feedback/RTO, custody, queue pressure,
original expiry, malformed wire and bounded replay. One existing Research
payload regression checks the directly affected default decoder path; its files
were not modified.

`python3 tools/check_checklists.py` failed on the pre-existing Research `RRP-01`
checked item missing an evidence link. The [base comparison](../../work/legacy-sliding-20261116/baseline-ledger-check.json)
reproduces the identical failure at `a8da1e2154c58c9da652630da3049708a9db8a06`
and verifies the two complete legacy gates remain unchecked. This failure is
preserved, not waived or silently repaired in another component's ledger.
`git diff --check` passed separately. The user-requested narrow validation scope
excluded `tools/check.py`, whole-workspace tests, performance sweeps, privileged
labs, remote CI, Windows/Android and native-device execution.

The only shared recovery changes are opt-in explicit-coefficient entry points
and exact optional coefficient history in `rolling/encoder.rs`, `decoder.rs` and
`explicit.rs`; default owner heap layouts are preserved. The patch is based on
the exact commit above. Baseline decoder SHA-256 is
`254dd40b581029dcedeed2b0edcd677cb8bf719cdacaf6ee48bc69aed7844f16`,
and encoder SHA-256 is
`bd1b8bdba49689940ea9e7649a49aee87e60d958581bb0f8c247001c17e83d02`.
Reconcile these narrow hooks with any later parallel decoder work; do not replace
the decoder wholesale. `research/*`, `rolling_records/*`, Engine/config/Common,
the simulator and prior receipts are unchanged.

## Admission alignment follow-up ledger

- [x] [LAA-01] Implement and validate admission-time source credit, immutable periodic coefficient/support snapshots and original FEC timers under held physical output, with bounded single-owned unsent originals, exact storage refusal/reuse, causal feedback and unchanged v1 compatibility behavior. Evidence: [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json).
- [x] [LAA-02] Implement and validate real source and repair batch packing and physical custody matching the Python first-item timer, size/count flush, source-before-repair ordering and spacing. Charge every actual versioned header/item byte once and retain one physical receipt per represented batch. Evidence: [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json).
- [ ] [LAA-03] Compare a source-bound actual Python congested/packed admission,
  FEC/packer timer and feedback trace; preserve explicit analytical-wire,
  native/runtime/auth/resource/platform and full P-* gaps.

The three finite admission cases passed: held original with later admission and
timer snapshots; atomic invalid coefficient refusal; and admission while a real
frozen repair is held with unsent-feedback rejection. Evidence is the
[first closeout check log](../../work/parallel-features-20261115/closeout-batch-check-1/check.log).
The [aggregate receipt](../../work/parallel-features-20261115/closeout-batch-check-1/validation.json)
remains failed; focused continuation passes LAA-01/02, while LAA-03 stays open.

## Explicit actual batch extension

Status: **implemented pure owner with finite admission, actual batch and
held-retry custody checks passed**. The explicit
`legacy_sliding::batch::BatchSender` owns the same admission-aligned Sender
and reserves real packet slabs, per-packet token metadata and two packer cursors.
It does not install a Common profile or change default L2LS-v1 parsing/encoding.
`Packing` selects source/repair counts, the original pack wait, analytical MTU,
actual packet ceiling, slot count and full owner allowance.

Source additions obey the Python count/size flush and retain the first-item timer.
FEC flush closes the source packer before repair output is eligible. Repair
cohorts reserve their exact slab positions at original queued due/order events
before incremental GF finishes, so work pressure cannot move an equation into
a later cohort. A closed packet remains unavailable until every reserved payload
is complete. One pinned active packet keeps its ID and complete bytes immutable
while other admissions, timers or GF turns progress. Original source/job caps
remain active; packet waits, retries and timer polls do not renew them. Callers
service due timer events through `step`; equal-tick input ordering is explicit
call ordering, rather than an implicit real clock or an old callback identity.

The new L2LB-v1 wire grammar is an eight-byte magic/version/class/count envelope
plus a two-byte length and unchanged L2LS-v1 record for every represented item.
The parser validates the entire bounded envelope and every inner record using
the maintained canonical parser before iteration; it grants no authentication.
`PacketOutput::charge` includes every actual framing byte and the caller's real
outer overhead. Analytical 88-byte/four-byte costs only decide Python grouping;
actual capacity must independently fit that cohort. No record is cropped and no
analytical cost substitutes for real traffic. Reverse feedback remains a separate
authenticated, reverse-budgeted record. Common/native/carrier batching and its
original-arrival input custody remain full required integration work.

Encoder scratch transfer into a packet is not a physical send: sources retain
unsent/attempt custody and repairs retain their actual jobs until the whole packet
receipt. `BatchSender::confirm_output(id, accepted, observed, rtt)` needs no RNG.
It consumes every represented source/repair physical fact exactly once, even if
the first item or callback is late, then latches the first timing failure. Real
physical counters and the whole-packet Receipt survive that failure; output cannot
be reissued. First-send RTO derives from actual acceptance. Feedback that could
refer to a locally held physical receipt returns Busy without ACK mutation;
`receive_feedback_at` retains original authenticated arrival for later retry and
rejects an arrival before any physical source/equation supporting its claim.
It never turns a claimed source ID into authentication or a clock/cap extension.

The exact Plan/Usage includes the existing source/GF owner once, one fixed packet
byte slab, packet metadata and per-item custody tokens. Packet paths allocate no
backing. Wrapper fixed size and nested heaps are compared to the explicit complete
allowance; allocator/RSS, caller buffers and full runtime external inventory are
not covered. Incremental GF work uses WorkBudget. Packet serialization and
cohort reservations are separately bounded metadata/copy operations: at most1024
repair assignments per call, each scanning at most1024 jobs and255 terms, plus
scans bounded by configured packet_slots and one actual record copy. WorkUsed
does not claim to meter those parser/packing CPU operations.

The source-pinned [congestion oracle](../../crates/l2tunnel-fec/tests/generate_legacy_admission_vectors.py)
uses actual unchanged Python Packer/Tunnel methods and Random(7349), a250-us
existing link reservation,100-us serialization and1000-us RTT. Its 21-line
[fixture](../../crates/l2tunnel-fec/tests/fixtures/legacy-admission-packing.txt)
captures admission credit/generations, periodic support/coefficients, source
cohorts and a two-equation repair cohort before any physical completion. The Rust
case compares those snapshots and immutable actual packets, drops one entire
source packet, recovers exact trailing-zero original bytes from the real equations
and applies actual receiver feedback. Separate cases cover original pack timer,
exact wire/storage refusal, accepted-versus-observed RTO, malformed batch refusal,
foreign/duplicate receipts and all-item physical facts on late source/repair
packets. All three cases passed in the
[first closeout check log](../../work/parallel-features-20261115/closeout-batch-check-1/check.log),
and `generate_legacy_admission_vectors.py --check` verified all 21 rows. The oracle
stops before the first physical completion: it contains no delivered feedback,
feedback loss, late ACK or timeout/retry ordering trace. The Rust loss/recovery
and actual feedback assertions are finite component evidence, not an executed
Python feedback differential. LAA-03 therefore remains open.

An additional acknowledged-held-retry/selective-ACK case failed in that first
check because its selective-only profile was given a cumulative ACK. The
correct selective ACK now passes the same held-slot regression in [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json).
The failed aggregate is retained and must not be described as passed.

LAA-01/02 are finite completed leaves; LAA-03 and both full legacy P-* gates
retain their complete definitions and remain unchecked. Actual selected Common/config/management/authentication, reverse
MUX loss, native fragmentation/ordered lanes, platforms, full resources and
performance remain open. Historical component receipts and simulated throughput
are unchanged; they do not validate this extension.
