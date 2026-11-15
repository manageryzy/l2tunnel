# Selected CompactARQ protocol implementation

Status: implemented and protocol-tested in finite focused and Python-derived
behavioral differential cases. The actual Reliable Compact R0 consumer also
passes focused protocol cases; selected Common/runtime installation remains open.
This is an engineering implementation contract, not an owner default decision.
Historical simulator observations and receipts remain unchanged.

## Exact selected API

The recovery crate reexports CompactRecovery::{Guarded,FirstFlight,BoundedGap},
CompactBounds, CompactTiming, checked CompactArqConfig and CompactRepeat.
CompactArqConfig::new(bounds,timing,maximum_feedback_bytes,history_entries,
maximum_attempts,recovery) validates explicit fields; getters preserve them.
Source size and both source spans support1..=65535, including8192. Nominal RTT
may be zero; ordinary feedback and bounded-gap intervals are positive. Finite
history_entries and maximum_attempts are explicit policy bounds, never inferred
timeouts or silently evicted history.

CompactRepeat::new/new_duplex always fallibly provision the same selected backing;
new_duplex_reserved takes the existing storage::Limits and CompactPlan.
There is no dynamic/nonreserved fallback. Existing RecoveryEngine methods and
poll_feedback/poll_source, source_confirmed, received_sources, deadlines and
next_source_id expose the one underlying Engine. pending_transmission and
confirm_transmission[_at] reuse its actual move/custody verification.

receive_at(packet,received,observed) preserves original authenticated arrival for
RTT sampling while observed remains monotonic for owner operations. A feedback
whose echo or positive acknowledgement depends on unobserved local physical
acceptance returns FeedbackAwaitingPhysical BEFORE any ACK, RTT, history, retry
intent, timestamp or counter mutation. This includes a newer accepted echo that
would otherwise erase an earlier still-pending physical history entry. The
consumer must retain the exact input, original arrival and original operation cap.

## Reused ownership and explicit wire

Existing arq::Engine owns the sole send/receive payload storage, source allocator,
ordered delivery, physical instance/tokens and terminal attempt/time state. Its
selected policy dispatches into compact.rs; legacy v1 construction/bytes/timing
stay on their existing path. Compact adds no FEC/second ARQ, crypto, MUX, OS,
socket, Tokio, privilege, real clock or timeout worker.

L2ARv2 uses the existing32-byte context header (version2; profile1 Guarded,
2 FirstFlight,3 BoundedGap). A source adds source u64, attempt u64, payload length
u32 and exact payload:52 fixed bytes. Feedback adds prefix/start u64, count u16,
reserved-zero u16, echo/delay-us/feedback-serial u64 and ceil(count/8) bytes:76
fixed bytes. Bitmap bits are low-order first; unused high bits are zero. Source,
attempt, feedback and context counters are not cryptographic packet numbers.
The codec validates context/opposite role, selected directional profile, exact
length/reserved bits and checked serial/window claims before mutation. Positive
receipts and new echo sampling remain effective even for stale feedback serials.

Every source attempt reserves a new nonwrapping serial/history slot before
writing output. The same existing Flight retains its original payload. Selection
freezes that attempt's adaptive RTO; only actual confirm_transmission_at arms it
from accepted, even if the receipt is observed after it is already due. Source
attempts do not re-emit while held. An ACK for an already accepted source with a
physically held retry marks receipt but retains its actual payload/slot until the
same physical token is confirmed. Wrong/repeated/foreign tokens remain rejected.

Fast retry is one intent on the current source attempt, emitted by ordinary
poll_source. Qualification requires three later one-bits in that bitmap, a fresh
feedback serial and newer echo. Guarded uses max(nominal,SRTT)+2*feedback interval;
FirstFlight and BoundedGap exempt only attempts==1. The actual new attempt clears
the intent and changes its serial. No exponential timeout backoff is added.

Each source receipt, including a duplicate, arms the ordinary feedback event path
and two additional charged repeats. Bitmap start rotates independently of prefix.
BoundedGap adds one early intent per advancing qualified gap and checks time since
ANY last feedback. New events preserve an already earlier feedback deadline.

## Timing and actual resources

Estimator arithmetic follows Python binary64 seconds, using old SRTT in RTTVAR
before updating SRTT. Receiver delay is round_ties_even microseconds. Scheduling
converts binary64 seconds with Duration::try_from_secs_f64 to nearest representable
nanoseconds; behavioral comparisons permit at most1ns quantization tolerance.
This is not bit-exact equality of Python floats or a NIC departure timestamp.
Caller whole-carrier acceptance is the available physical boundary.

Selected Sent/Received variants reuse the same actual payload slots with tagged
source-modulo-slot lookup; bitmap lookup is O(1), avoiding O(window*bitmap).
Admission inventory length and service/ACK scans remain bounded linear in
configured window/history/bitmap counts; this slice makes no constant-time total
or native performance claim. No packet-time allocation occurs on the selected
path.

Legacy Engine retains only an empty Vec<State> header. CompactPlan separately
charges one actual fallibly reserved capacity1 State singleton, send/receive slot
arrays, all idle payload buffers, per-send retry metadata and finite history.
Construction verifies actual Usage and exactly5+send_slots+receive_slots explicit
nonzero reservations. Inline Engine/parent owner size is excluded from heap Usage
and remains the enclosing owner's separate actual charge. One-short budgets fail
before allocation; exact and +1 limits preserve the same measured capacity.
Resource accounting is requested layouts, not RSS/allocator overhead/overcommit
or complete nested allocator-failure qualification.

## Focused executed cases

All seven focused protocol cases pass in the finite Batch9 evidence:

- v2_exact_fields_full64_parser_and_physical_timer_from_original_acceptance
- held_physical_feedback_is_transactional_then_original_arrival_samples_receiver_delay
- exactly_three_later_bits_first_flight_once_and_stale_feedback_new_echo
- rotating_feedback_reaches8192_and_keeps_three_charged_tail_reports_and_strict_padding
- history_refusal_does_not_burn_output_attempt_or_serial_and_attempt_limit_is_honest
- bounded_gap_uses_any_last_feedback_and_only_advancing_qualified_prefix
- newer_echo_cannot_retire_an_earlier_unobserved_physical_history_entry

They exercise actual owners/bytes/custody, literal v2 fields, injected original
arrival and delayed physical observation, feedback loss/reorder assumptions,
source-window8192 with rotating one-byte bitmap, finite history/attempt bounds,
and real Plan/Usage. The8192 case retains a four-byte payload and is a protocol
bitmap/window boundary test; it is not full native8192/128 retention proof.

The differential consumer also passes five deterministic event traces generated
from the actual maintained Python classes: receiver-delay/RTT and reordered echo,
guarded and first-flight retry, duplicate-feedback repeats/rotating bitmap, and
bounded-gap timing. `tools/generate_compact_arq_events.py --check` validates the
pinned source hashes and generated literals; provenance lives under
`crates/l2tunnel-recovery/tests/data/compact-arq/`. This compares protocol events
and timing, not Python cost-model bytes with the new v2 serialization or native
TCP throughput. See [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).

The same Reliable owner now selects `CompactReliableConfig` through
`new_compact_duplex`/`new_compact_duplex_reserved`, with actual crossed-direction
source/feedback geometry and no FEC backing. Three focused R0 cases and two
lane-aware wake/directional-boundary cases pass. Additive independent deadlines
retain the original accepted source timer, suppress only a held lane's soft wake,
and leave combined legacy getters unchanged. No authenticated Complete policy,
Aligned/Packed/Common selected adapter or production carrier installation is
qualified by these pure owner tests.

## Finite implementation leaves

- [x] [CAR-01] Validate explicit v2 config/codec, full64 fields, exact lengths, padding/profile/context and complete65535 representability. Evidence: [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).
- [x] [CAR-02] Reuse actual Engine/payload/physical owner with adaptive serial history and original-acceptance timers; transactional feedback race handling. Evidence: [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).
- [x] [CAR-03] Implement guarded/first-flight/bounded-gap qualification, rotating feedback, duplicate events and two charged repeats with source-bound events. Evidence: [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).
- [x] [CAR-04] Provision actual indexed storage and selected singleton, exact limits/Usage and no packet-time growth, with honest refusal/attempt limits. Evidence: [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).
- [x] [CAR-05] Pass focused Rust cases and independently source-derived Python differential traces; serialized v2 vectors are new, not existing Python bytes. Evidence: [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).
- [ ] [CAR-06] Install both complete policies through versioned Reliable R0,
  Aligned/Packed/Common configuration/catalog/Engine/Driver and ordinary selected
  carrier feedback, retaining authentication, management and physical custody.

CAR-01..05 record finite protocol and behavioral differential evidence. Literal
allocator failures, versioned complete configuration/consumer installation,
actual lossy feedback carrier, reverse affinity, per-connection/shared recovery
topologies, full8192/128 native/copies/ACK coalescing, TCP ownership, all47 modes,
SW-11, RLNC/parity/rolling/packed/proxy and platform/resource/performance gates
remain fully required and open. The reverse-affinity proposal is separate.
