# Recursive parity and rolling-accumulator protocol components

Status: **implemented pure components and original-UDP Common composition with finite protocol and runtime integration evidence**.
The [Batch14 receipt](../../work/parallel-features-20261115/parallel-batch14-scoped-validation.json)
adds Engine/Bank, protected original UDP and catalog-bound shared-service cases.
The closeout integrates bounded asynchronous ordering and passes finite original
OpenVPN and injected raw shared-service cases; see [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json).
Complete named Python acceptance remains open.
The [Batch13 receipt](../../work/parallel-features-20261115/parallel-batch13-scoped-validation.json)
records the affected research/shared-rolling cases, unchanged Python oracle check,
and first full-check failures/continuations separately from external history.
The isolated feature checkpoint is `a8da1e2154c58c9da652630da3049708a9db8a06`; its preserved passing and failed receipts below describe that external source, not a new check of this integration. The new `l2tunnel_fec::research` owners encode actual arbitrary source bytes,
recover from received bytes, schedule charged repairs and emit cumulative receipt
feedback. Those standalone owners supply no runtime authority. The selected composition
below installs the actual Common family and original-UDP shared service; native
mode qualification remains separate. The complete `P-research-recursive-parity`,
`P-research-recursive-fallback` and `P-research-rolling-accumulator` definitions
remain required and unchecked in the [main ledger](../implementation-checklist.md).

## Python reference and selected policies

The implementation follows these unchanged simulator sources:

| Reference | Preserved behavior |
| --- | --- |
| [rtt_recursive_parity.py](../../simulator/studies/rtt_recursive_parity.py), lines 36–89 | SHA256 tap locations/weights, source support, expanded parity and periodic reset. |
| [rtt_recursive_fallback.py](../../simulator/studies/rtt_recursive_fallback.py), lines 32–71 | Periodic fresh-prefix replacement and unchanged intervening recursive history. |
| [rtt_rolling_accumulator.py](../../simulator/studies/rtt_rolling_accumulator.py), lines 27–38 | Repeated lane coefficients, acknowledged local supports and every-sixteenth fresh global repair. |
| [rtt_checkpoint_repairs.py](../../simulator/studies/rtt_checkpoint_repairs.py), lines 55–108 | Delivered cumulative feedback, packet-triggered feedback interval and exact 26/125 repair credit. |

The named recursive configurations use `(taps, width, reset)` of `(3,8,256)`,
`(3,12,256)` and `(4,8,256)`. Fallback variants use `(4,8,256)` and fresh intervals
8, 16 or 32. Accumulators use `(lanes, window)` of `(1,128)`, `(3,128)`, `(7,128)`,
`(15,128)` and `(7,256)`. The corresponding dense controls remain explicit:
recursive taps/width/fresh interval zero, or accumulator lanes zero.

[Profile](../../crates/l2tunnel-fec/src/research/policy.rs) also accepts bounded
configurations under the same algorithm. It does not silently choose a profile.
Recursive source `s` has first eligible check `floor(26*s/125)+1`; each tap uses
exactly `SHA256("recursive-parity-v1/{source}/{edge}")`. The first two big-endian
u32 digest words select the band offset and nonzero GF(256) weight. Maintained
`sha2` implements the hash; no new cryptographic primitive or authenticator is
introduced. The source expansion XORs all eligible tap weights since
`floor((serial-1)/reset)*reset+1`.

A fallback slot replaces only the transmitted equation. The next recursive
output still includes checks from that slot. Periodic resets consume no extra
packet and do not clear future tap assignments. Recursive support ignores ACK
prefixes, including acknowledged sources whose expansion is still live. Fresh
fallback/global supports start at the actual sender-confirmed prefix. Accumulator
local support is `[max(confirmed,end-window),end)`; lane `serial % lanes` uses seed
`0xa5b30000 + lane`. Every sixteenth slot uses fresh counter coefficients over the
whole unconfirmed prefix. Packet seeds use the full nonwrapping serial multiplied
by 2654435761 modulo 2^32; a seed wrap does not wrap the repair identity or reset
its scheduling counter.

## Actual byte ownership and scheduling

[Sender](../../crates/l2tunnel-fec/src/research/sender.rs) owns the existing rolling
encoder and one immutable output. Admission or encoding earns no repair credit.
Only `confirm_output` after complete external carrier custody earns 26 numerator
units for a source. At 125 units, the sender freezes an actual repair before
allowing the next source. A completed N-source schedule therefore contains
`floor(26*N/125)` repairs, including zero-valued dependent equations. Each slot
has end `ceil(125*serial/26)`. There are no extra idle/tail repairs or retransmits.

The caller processes feedback already causally available at the source completion
time **before** confirming that source output. This corresponds to the Python
feedback drain before repair construction. A repair then retains its frozen
confirmed prefix and support through later feedback, WouldBlock and repeated
serialization. A receipt cannot cancel an earned repair. `OutputId`, borrowed
output, exact length/charge methods and explicit confirmation separate local work
from external custody. They do not prove a physical/native write on their own.

[Receiver](../../crates/l2tunnel-fec/src/research/receiver.rs) feeds actual received
vectors into the existing rolling decoder. It never reads sender originals or a
simulator source ledger. Recovered lengths, meaningful trailing zeros and padding
are checked by the existing engine. Upper source handoff remains distinct from
committed receipt and native delivery. Cumulative feedback uses only committed
state. A qualifying received packet triggers a snapshot no more often than the
configured interval; choose five milliseconds in the caller's tick unit for the
study policy. Lost feedback needs a later packet event; there is no reliable
feedback side channel or timer-only receipt retry. The embedding carrier supplies
real propagation, serialization and feedback loss; the library invents no RTT.

Exact retained duplicate identities are idempotent; changed retained equation
content conflicts. Bounded stale input cannot resurrect retired originals.
Out-of-order source/repair admission reuses the existing history, rank and
transaction rules. Loss may leave insufficient rank indefinitely until the
original configured hard deadline reports failure. No complete-loss-recovery or
35 ms delivery guarantee follows from these finite heuristic policies.

## Wire, accounting and security boundary

[wire](../../crates/l2tunnel-fec/src/research/wire.rs) defines additive draft `L2RS`
version 1, separate from existing rolling bytes. Its fixed 80-byte header binds
scope, identity, support, full coded width and the exact twelve-byte algorithm
descriptor. Repairs additionally carry the frozen sender-confirmed prefix.
All fields are checked against the configured profile; unknown versions, reserved
bytes, invalid lengths, support or schedule identities are rejected.

Exact protocol charges are `80 + original.len()` for a source,
`80 + max_payload + 2` for a repair and 80 for feedback. `Output::charge` and
`Feedback::charge` add caller-supplied actual enclosing overhead with checked
arithmetic. The source contains exact original bytes; a repair contains the full
coded `u16 length || payload || zero padding` vector. No all-zero repair or
fallback slot is exempt from transmission/accounting. This component does not
fragment packets: the caller must choose a payload bound that fits actual PMTU
after all enclosing overhead, or explicitly integrate bounded fragmentation.

These charges differ from the Python analytical 1496/1500/46 IP-byte charges.
The simulator's throughput and fixed byte ratio must not be reused as production
wire/performance evidence. The caller must reserve every actual source, repair
and feedback byte through the same selected MUX/channel/pacing policy, including
outer authentication, cover and physical copies if separately implemented.

Parsing and matching `Scope` are structural checks. The caller authenticates and
replay-checks the complete enclosing record, negotiates/binds the full immutable
configuration and preserves epoch/drain barriers before admitting it. This module
provides no key exchange, packet encryption, replay authenticator or hot switch.

## Bounds, deadlines and shared implementation dependency

`Config` embeds existing rolling payload/history/rank/time/memory bounds, a
validated `Profile`, positive feedback interval and complete wrapper memory cap.
Maximum support is 8192, maximum original payload 4096, taps at most 16 and lanes
at most 256. A configured window must meet the conservative recursive history
bound `ceil((reset+taps*width)*125/26)+5`. ACK loss may require a larger retained
prefix; pressure explicitly refuses or terminates work, never clips its equation.
Confirmed originals needed by future recursive expansion remain retained.

The GF arithmetic, compact counter coefficient, vector storage, transactional
decoder, duplicate history and source handoff are reused from
[rolling](local-global-rlnc.md). Only explicit-profile equation hooks are added to
its encoder/decoder; existing policy and wire entry points retain their behavior.
`storage::Plan` uses the actual existing nested allocation inventory, checks both
original and wrapper conservative guards, and compares observed capacities after
construction. It excludes allocator bookkeeping, caller buffers, stack and RSS.

All time is caller-injected. Source output/debt caps start at original creation;
received work preserves original arrival and an external operation/session
cap through feedback and upper handoff. The earliest finite cap conservatively
bounds all outstanding state until jobs, observed sources, events and feedback
have all been discharged. Busy, polling, partial feedback and repeated output do not renew those hard
deadlines. Bounded GF/copy/metadata service uses existing `WorkBudget`; one
coefficient metadata evaluation performs at most 16 single-block SHA256 hashes,
or one existing compact mix. This is an explicit finite CPU bound, not a claim
that hash cost equals one byte operation. Public admission and serialization
perform separately bounded copies of at most one fixed-width vector/record;
these synchronous copies are not charged to a later step budget. No Tokio, native handles or real clocks
enter the public protocol component.

The isolated implementation starts at
`99f45488f01f0f215e7b6c3bbb58b3c9a7d74360`. It preserves the concurrent decoder
original-arrival deadline prerequisite as separate commit
`ef2c6ebd3d6f92dfff61cdc6fd2437955de37e29`; that commit's
`crates/l2tunnel-fec/src/rolling/decoder.rs` SHA256 is
`ffcfafc22468600128ce250a0695e68b5082a0b5be3cf42978af4d58927ad2a1`.
The additive equation hooks depend on that exact prerequisite; they are not a
replacement for other concurrent rolling decoder/scheduler work.

## Selected pure record composition (protocol-tested)

The additive `research_records` selection instantiates the maintained packed
record body with the actual research Sender/Receiver. The existing rolling codec,
native custody, bounded ingress and optional fragment/reassembly transitions are
shared through a sealed typed recovery policy. The old default selection remains
the actual rolling scheduler; research observations have their own real status.
CompleteV2 tag9 commits both full directions, all codec/source/native/time/memory
bounds, the maintained12-byte algorithm descriptor, exact outer geometry and
coding stream. Tags1..8 and their existing bytes are preserved.

The actual reserved Engine/Bank path owns these research backings and charges
L2RS source, repair and feedback through the shared Pipeline/output budget.
Physical output and whole fragment-group tokens are retained until matching
complete custody, without recharging a held output. Source/stage/input/debt/native
caps remain original. The staged finite cases exchange native bytes with real
source and feedback loss for recursive/fallback/accumulator policies, exercise
an actual fallback repair, exact canonical/storage admission and real Bank output
custody. These three cases pass in the root Batch14 check/continuations. Existing
external component receipts above remain historical finite evidence.

A delayed physical completion cannot use feedback that arrived after its actual
acceptance to choose repair support. The actual research completion helper checks
accepted versus observed time and the latest applied feedback time. A noncausal
ordering explicitly terminates the owner and retires the irreversible physical
token/count exactly once; it invents no past receipt prefix, clock rewind or cap
extension. The selected runtime must process genuine completion receipts before
later authenticated feedback, or install a bounded authenticated arrival-order
owner. The focused delayed-receipt/late-feedback case passes in Batch14.

The pure candidate alone left runtime/shared-service/carrier/CLI selection
unsupported. The dependent original-UDP candidate below removes only its actual
installed branches; the subsequent asynchronous composition below removes its
actual OpenVPN/raw selection refusal while retaining separate integration gates. Caller-authenticated
pure fixtures establish no production Noise/TLS/native lab qualification. RRP-03 and all
three original P-* gates remain fully open until their complete runtime,
feedback-loss/resource/failure and native acceptance requirements pass. The new
L2RS80-byte wire does not establish Python analytical byte/performance parity.

## Original-UDP runtime composition

The separate dependent candidate installs tag9 in the same Common Driver,
Bank, Records, Control and shared-service path. The exact Research send policy
parses reverse feedback; the independent receive policy parses source/repair.
Both roles require explicit authenticated bounded scheduler work. The existing
reserved ingress queue and fragment policy also select the actual Research owner;
there is no alternate queue, recovery algorithm or default. Canonical catalog
and v4 requested/effective observations retain the complete tag9 descriptor.

Original UDP confirms its whole physical send synchronously before subsequently
opening another authenticated input. Already authenticated feedback remains in
its observed order. An unread OS packet has no known physical network arrival
here: this is not exact network-clock/Python event equivalence. Asynchronous
OpenVPN/raw Research selection was refused at the Batch14 checkpoint until bounded
retained-arrival/physical-receipt ordering. The Batch16 composition below installs
that ordering, with finite root execution in [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json). Blindly polling receipts
before input would also invert valid earlier-feedback order and is not a fix.

Three finite root cases pass in Batch14:
actual protected UDP loss/reorder, native pressure and switches for all three
Research policies; retained sealed bytes/PN/token/debit and original-cap whole
write; and genuine catalog-bound initial Noise/member shared service followed by
all three Research selections and Swift return on the original sockets. The
first two use imported actual secure test Parts and do not claim a new initial
catalog-bound handshake. RRP-03, all original P-* definitions, the asynchronous
carrier ordering requirement, complete native/platform/failure/resource and
Python wire-byte/throughput gates remain open pending their full acceptance.

## Hole abandonment (owner decisions 2026-11-24)

Status: **contract-tested** (RRP-04..07); native evidence (RRP-08) pending.

### Problem

Every research row failed every native cell of `work/full-matrix-20261123`,
including 0% loss. Traced cause (`work/credit-20261123c/cells/r1`, the same on the
pre-credit build `o1`): the sender's `ResearchDebt` deadline is the earliest
`created + debt_ticks` since its pipe last fully drained and is cleared only when
`prefix == next_source`; the nested `rolling::Encoder::new` and the receiver's
`rolling::Decoder::new` keep the same since-drain deadline. Continuous traffic
never fully drains, so a healthy session dies `debt_ticks` (10 s in the plans)
after the workload starts; the trace showed 888 sources in flight with the
receiver confirming promptly. Making the deadline per-source alone is not
enough: this family has no retransmission, so one source the FEC cannot repair
blocks in-order handoff and expires the session anyway.

### Decisions

- The receiver gives up on a hole it cannot repair ("receiver skips"); a lost
  packet becomes ordinary loss that inner TCP retransmits end to end. Data loss
  alone never ends the session.
- The give-up point is adaptive with a time cap: `abandon_ticks`, a new
  research `Config` field bound into the authenticated configuration, default
  1 s in exported plans. It occupies the formerly reserved zero word 16 of the
  tag-9 descriptor, so zero (every earlier vector) means abandonment is off.
- Equations that include an abandoned source are eliminated, and later repairs
  that include it are dropped ("Eliminate, drop late", owner decision
  2026-11-24). Keeping such equations in place is impossible because the
  decoder reuses the column for source `h + W`.

### Abandon rule

Only the oldest missing source `h = prefix` is ever abandoned, at the first of:

1. **Definite**: no repair the sender can still send includes `h`, and no
   staged job remains. For `Recursive { fresh_interval: 0 }` with taps, a
   repair's support starts at `recursive_start(serial)`, independent of
   receipts; once a received repair serial has `recursive_start > h`, no later
   one includes `h`. Profiles with fresh, global or dense slots (fallback,
   accumulator, dense controls) always cover the unconfirmed prefix, so this
   test never fires for them.
2. **Projected**: with `D` the decoder deficit over `[prefix, observed)` (unknown
   columns minus rank, `feedback_state`) and `r` the measured arrival rate of
   repairs whose support includes `h`, the hole is abandoned when
   `age(h) + D / r >= abandon_ticks`. Each covering repair adds at most one rank,
   so the cap would be reached anyway. Without a covering arrival since the hole
   appeared, `r` is unknown and only the cap applies.
3. **Cap**: `age(h) >= abandon_ticks`, where age starts when a later source or
   repair first shows `h` missing (`observed > h`).

Repairs are earned only as sources are sent; with no traffic no repair arrives,
and the cap bounds the stall. A later hole in the same cohort (below the
observed end when the cohort's first hole was seen) keeps the cohort's age, a
conservative lower bound. The covering-repair rate restarts for each new oldest
hole. The receiver exposes the cap time as a soft wake (`abandon_wake`) and a
due abandonment as receive work, so the record endpoint services it without
traffic. Each abandonment schedules a receipt.

### Decoder mechanics (`rolling/decoder/abandon.rs`)

- Abandonment is its own atomic decoder transaction (one decision ticket),
  refused with `Busy` while a GF job is staged.
- Every retained row pivots on an unknown column at or above the prefix and is
  reduced on every other pivot, so the oldest unknown column `h` is nonzero at
  most in the row pivoted on it. That row is dropped (rank falls by one).
- Column `h` is then marked known with a zero-length vector. No valid original
  has length zero, so the marker needs no extra storage. Prefix, eviction and
  `feedback_state` arithmetic treat it as resolved.
- `pending_source` and `decoded_source` never expose it; the handoff skips it.
  A late original for it is `Stale` (counted), never a conflict.
- A later repair with a nonzero coefficient on it is dropped whole while
  substituting known columns. It still commits its history and observation.
- The receipt's `prefix` means "recovered or abandoned"; the wire is unchanged.

### Deadlines

- Sender: the nested encoder tracks per-source debt (the existing
  `source_deadlines` tree used by the targeted and sliding constructors), and
  the research sender's `debt_end` follows the oldest unconfirmed source. It
  then fires only when receipts stop for `debt_ticks`.
- Receiver: the nested decoder uses the existing per-source `lifetimes::Sliding`
  debt. With abandonment `prefix` advances at least every `abandon_ticks`, so it
  fires only when the sender stops.

### Observability

`ReceiverStatus` adds abandoned sources by reason (definite, projected, cap),
dropped repairs and rows, late originals, the current hole and its age, and the
covering-repair count. The runtime snapshot carries it as `research_receiver`
and Common status reports it as `research_recovery`.

### Record layer after abandonment (owner decision 2026-11-24)

Abandoning a source also loses the record units it carried. The first native
15% runs showed both daemons ending with `Rolling(Identity)`: the record
endpoint required unit continuity between handoffs. Decision "Anchored
compression": research rows use `FixedAnchorIpHeaders`, whose deltas name an
explicit anchor within 8 records, instead of chained header contexts. The
sender does not react; the receiver alone:

- detects a handoff gap (`next_handoff`) and declares the lost unit range to the
  record receiver (`aligned_receiver::Receiver::abandon_sources`), which clears
  stale unit proofs, advances the contiguous floor, discards incomplete records
  and enters loss mode;
- in loss mode lets each channel's expected record jump to the next retained
  record (`skip_lost_head`), discards a delta whose anchor was lost, and marks a
  later fragment of a record whose first fragment was lost `StaleRecord`; the
  endpoint accepts that outcome only for an owner that abandons holes;
- counts abandoned units, dropped and skipped records in `LossStatus`, which
  every rollback path (journal and owned batch) restores.

Configuration rejects abandonment with a context-chained policy
(`EthernetHeaders`, `IpHeaders`, `NativePolicy::survives_record_loss`) and an
`abandon_ticks` that is not below the peer's `codec_stage_micros`, since a hole
waiting for the cap must not expire the held send stage first.

### Receipt repeats (owner decision 2026-11-24)

Receipts are triggered only by arriving packets. A window-blocked sender whose
last receipt was lost therefore received no packet that could trigger another,
and both sides waited until the send-stage cap ended the session (reproduced by
the deterministic 15% loss engine test with both receivers fully caught up).
Decision "Receiver repeats":

- After each taken receipt the receiver schedules a repeat at doubling
  intervals of 4, 8, 16, then 64 `feedback_ticks`, eight repeats at most (about
  0.4 s in all at the plans' 1 ms). Any arriving input, or a receipt with new
  information, restarts the sequence; duplicates are harmless at the sender.
- A notice suppressed by the `feedback_ticks` rate limit used to be dropped.
  It is now reported at the end of the window when the receipt would carry new
  information (for example an abandonment), and still dropped for duplicates.
- Both are soft service wakes (`service_wake`, `service_due`), never expiries.
  `ReceiverStatus.receipt_repeats` counts the repeats.

### Parity

The Python references define coefficients, supports, scheduling and receipt
cadence (`studies/rtt_*.py`); none models hard deadlines or abandonment, so
coefficient and support parity are unchanged. Loss behavior now differs from
the study's "insufficient rank until the hard deadline" note above, which this
section supersedes for runtime behavior.

### Tasks

- [ ] [RRP-04] Per-source sender and receiver debt: research sender and nested encoder follow the oldest unconfirmed source; the receiver's decoder uses sliding per-source debt. Test: continuous traffic for longer than `debt_ticks` with prompt receipts never expires; stopped receipts still expire at `debt_ticks`.
- [ ] [RRP-05] Decoder abandonment: versioned `abandoned` flag, header count, prefix and handoff skip, `feedback_state`, late-decode discard, eviction cleanup. Tests: abandon a pivot and a free column; a later repair containing the abandoned column still recovers others; eviction with lingering rows; atomicity against a pending job.
- [ ] [RRP-06] Research receiver abandon rule: `abandon_ticks` config field (validated, digest-bound), definite, projected and cap triggers, covering-repair rate. Tests per trigger and per profile family.
- [ ] [RRP-07] Status and metrics: abandoned by reason, late decodes, hole age, rate, through Common status.
- [ ] [RRP-08] Runtime and native evidence: a lossy Common research session longer than `debt_ticks` delivers with abandoned counts and no terminal; the four research rows rerun natively at 0% and 15%.
- [ ] [RRP-09] Record-layer loss after abandonment: handoff-gap detection, `abandon_sources`, channel head skip, orphaned delta and fragment discard, `LossStatus` with rollback, configuration refusal of chained policies; research plan rows use `FixedAnchorIpHeaders`. Tests: codec loss and rollback cases; engine test under 15% loss with anchored and raw IP policies.
- [ ] [RRP-10] Receipt repeats and trailing rate-limited receipts. Tests: bounded doubling repeat schedule; duplicates generate nothing; an abandonment inside the rate window is reported at its end.

## Component ledger

These component gates do not complete or narrow the parent P-* mode tasks.

- [x] [RRP-01] Implement full-payload recursive taps/reset, periodic fresh-prefix fallback and repeated-lane accumulator using existing GF/storage/decoder capabilities; validate exact Python policy and coded-byte vectors. Evidence: [external scoped receipt](../../work/parallel-features-20261115/batch13-staging/recursive-fec/external-evidence/attempt-2/validation.json); root component validation passes in [Batch13](../../work/parallel-features-20261115/parallel-batch13-scoped-validation.json).
- [x] [RRP-02] Implement charged 26/125 source-completion scheduling, immutable output/feedback custody, bounded original deadlines, exact replay checks and actual heap admission; validate loss, reorder, reset and failure paths. Evidence: [external scoped receipt](../../work/parallel-features-20261115/batch13-staging/recursive-fec/external-evidence/attempt-2/validation.json); root component validation passes in [Batch13](../../work/parallel-features-20261115/parallel-batch13-scoped-validation.json).
- [ ] [RRP-03] Integrate the selected profiles with Common Engine/Bank/configuration, authenticated carrier/MUX accounting and completion callbacks; preserve all full P-* acceptance requirements.

## Scoped verification and remaining integration

The [AST-only oracle generator](../../crates/l2tunnel-fec/tests/generate_research_vectors.py)
extracts the actual Python functions without importing experiment runners or
editing simulator/history. Its fixture covers all thirteen named/control
configurations, exact tap/support/coefficient behavior, reset/fallback boundaries
and 91 actual payload vectors using Python GF multiplication. Final Rust commands,
results and source hashes are preserved in the
[passing scoped receipt](../../work/parallel-features-20261115/batch13-staging/recursive-fec/external-evidence/attempt-2/validation.json).
All 20 research/hook cases and ten selected directly affected rolling cases pass.
The three-profile production-owner fixture sends 1600 variable-length originals
per profile, drops sources 0/17/600/1225/1240 and repairs 2/256, reorders source 10,
duplicates packets and delays actual feedback arrival by 70 caller ticks. Every
original is recovered exactly, including across reset/fallback and ring reuse;
observed allocations remain unchanged. This is finite byte-recovery evidence,
not a universal recovery or throughput bound.

Executed with `CARGO_TARGET_DIR=/tmp/l2tunnel-recursive-target`:

```sh
cargo fmt --package l2tunnel-fec -- --check
python3 crates/l2tunnel-fec/tests/generate_research_vectors.py --check
cargo test --offline --package l2tunnel-fec --lib research
# The receipt records the exact ten --exact rolling test selectors.
cargo clippy --offline --package l2tunnel-fec --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --offline --package l2tunnel-fec --no-deps
git diff --check
```

The [earlier failed compile receipt](../../work/parallel-features-20261115/batch13-staging/recursive-fec/external-evidence/attempt-1/validation.json)
and final receipt's earlier-attempt notes are retained. They record a corrected
storage delimiter, missing serial-17 fixture generation and an accidental test
argument after the descriptor API change. Per the task's scoped-check instruction,
`python3 tools/check.py` and the full repository suite were **not** run.
No whole-repository, privileged, native, Windows/Android, CI or performance
acceptance is implied by this component checkpoint.

Complete qualification of Common configuration/capability binding, actual
Engine/Bank/runtime/shared-service consumption, every authenticated carrier,
shared admission/pacing, production feedback loss, resource/fault behavior and
native execution remains open beyond the finite authored candidates. The three full P-* tasks and their end-to-end acceptance definitions are
unchanged. The draft wire requires explicit future integration; no default or
existing mode is switched by adding these components.


## Asynchronous carrier ordering composition

The source-bound [ordering handoff](../../work/parallel-features-20261115/python-parity-staging/research-async-order/handoff-v0.json)
now reaches the actual Sender, Engine/Bank, Common Driver and maintained carriers.
The public `CausalTime` is caller-injected local nanoseconds, not a clock or wire
authenticator. Complete feedback availability is the maximum accepted distinct
fragment arrival; lifetime still starts at the minimum original arrival and keeps
its existing cap. Runtime derives precision from its retained Instant origin,
including distinct events inside one microsecond. Old coarse APIs remain wrappers.

The selected generation's existing bounded ingress slots retain authenticated
feedback with original precise arrival and cap while a physical output is held.
A bounded initial-cohort scan preserves the relative FIFO of other inputs. Earlier
feedback is applied before source confirmation; later feedback follows it.
No new payload queue or capacity increase is introduced. Unselected/no-ingress
paths retain their existing single pending feedback limit. Full custody exhaustion
is an explicit bounded refusal, never silent feedback loss. One physical receipt
is consumed once even if later validation fails. Common control remains independent.
Raw receipt publication first serves older authenticated input already in its
bounded inventory; unread kernel queues are not physical arrival observations.

Finite cases pass actual multi-fragment equal-tick ordering, two genuine retained
feedbacks around one physical receipt, original initial-only OpenVPN bytes and
liveness for all three policies, and an injected raw Half shared-service switch
through those policies. Evidence: [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json). These cases do not close complete
pressure/failure/native/platform/resource, Python byte/performance, RRP-03 or any
full P-* gate. Public time remains caller injected and simulator history is intact.
