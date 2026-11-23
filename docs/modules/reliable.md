# Reliable selective repeat with optional systematic block FEC

Selected compact v3 now uses this module through the existing runtime owners.
See [runtime algorithm migration](compact-wire-cleanup.md#runtime-algorithm-migration)
for the selected wire representation, exact-cost boundaries and validation scope.
Legacy constructors and historical receipts below retain their original meaning.

Status: implemented and locally unit-tested. This crate composes the existing
[selective-repeat engine](recovery.md) and [full-byte block FEC](fec.md). It is a
bounded protocol primitive, not native integration or completion of the Python
block/sliding/hybrid families in [mode parity](../mode-parity.md). The
[architecture](../architecture.md) and [implementation plan](../implementation-plan.md)
remain authoritative. No socket, clock or cryptographic implementation is added.

The additive selected CompactARQ path also accepts an encoder of the actual
borrowed `CompactPacketView` through `poll_compact_with` and its data/feedback
variants. `CompactOverheads` separates data from strongly authenticated feedback
cost before an attempt is committed. Encoder error or `None` retains original
custody; accepted output retains the existing physical witness until confirmation.
This path omits the eight-byte Reliable envelope and exposes `receive_compact_view_at`
without reparsing a private legacy wrapper. The 40-case suite and direct final
record/UDP composition are recorded in the [compact checkpoint](compact-wire-cleanup.md#selected-checkpoint-evidence).
The configuration and envelope costs below describe preserved compatibility
paths; this addition does not migrate Aligned/Packed or the other FEC profiles.

## Canonical configuration and API

`Reliable::new(config: ReliableConfig, context: RecoveryContext)` owns one ARQ
engine, one receive FEC decoder, one partial source block, one sealed outbound
block and one bounded sorted restored-source queue. The peer has an independent
instance and receives only authenticated copied wire bytes.

`ReliableConfig` embeds `ArqConfig` and `fec::DecoderConfig`, plus repairs per
full generation, partial-block flush duration, restored packet/byte limits and
external wire overhead. FEC maximum source bytes must equal the complete ARQ
source header plus ARQ maximum payload; FEC source count is the generation target
and cannot exceed the ARQ windows. The maximum source is at most 4096 coded input
bytes, so upper records larger than 4052 bytes require earlier fragmentation.
The maximum emitted packet is `8 + 56 + target_sources + 2 + 44 + max_payload`:
the reliable envelope, FEC header, coefficient vector, coded length, ARQ header
and maximum original payload. The configured FEC packet limit must accommodate
that complete inner FEC packet. Callers subtract actual protection/IP/UDP overhead
from path MTU before selecting these limits. Contradictory or excessive limits fail
construction; `max_packet_bytes()` reports this exact worst-case emitted size.

Explicit `repair_symbols = 0` selects the existing selective-repeat engine alone.
It sends the existing kind-1 direct source envelope on the first eligible poll,
without collecting a block or waiting for `flush_after`. Original IDs, selective
receipts, retained-source bounds, retry deadlines and exhaustion are unchanged.
The exact maximum is `8 + max(44 + max_payload, 48)`. Each direction selects this
independently; a no-FEC sender can receive real FEC in the opposite direction.
The complete represented FEC policy is still validated and authenticated, but
inactive encoder/decoder, block/output queues and generation-expiry slots reserve
no heap capacity. Restored staging, scratch and actual ARQ custody remain counted.
Positive-repair defaults and their existing packet bytes are unchanged. This is
not completion of compact-arq RTT/serial/ACK-echo or any complete P-* contract.

```rust
Reliable::submit(source: &[u8], now: Duration) -> Result<u64, Error>;
Reliable::receive(authenticated_packet: &[u8], now: Duration) -> Result<(), Error>;
Reliable::poll(now: Duration, output: &mut [u8], budget: &mut OutboundBudget)
    -> Result<Option<usize>, Error>;
Reliable::poll_delivered(output: &mut [u8]) -> Result<Option<(u64, usize)>, Error>;
Reliable::poll_feedback(now, output, budget) -> Result<Option<usize>, Error>;
Reliable::poll_data(now, output, budget) -> Result<Option<usize>, Error>;
Reliable::inspect_output(packet: &[u8]) -> Result<RecordKind, Error>;
Reliable::inspect_peer(authenticated_packet: &[u8]) -> Result<RecordKind, Error>;
Reliable::deadline() -> Option<Duration>;
Reliable::drained() -> bool;
```

`OutboundBudget { packets, wire_bytes }` is mandatory on every poll. Each emitted
systematic, repair, retransmission and ACK decrements the same caller budget by
one packet and its actual reliable/FEC/ARQ bytes plus configured outer overhead.
It is an allowance from the external scheduler/congestion controller, not a
replacement congestion controller. Source collection may conservatively require
room for the maximum wire packet before advancing the underlying ARQ sender.
Insufficient allowance emits nothing and consumes no allowance. Feedback can use
its exact smaller allowance; it has no budget bypass.

Only `submit` allocates a new ARQ source ID or consumes a logical source admission.
FEC repairs and retries never call submit and do not consume fresh logical credit.
External flow-credit ownership remains with the embedding caller. Returned poll
bytes belong to that caller until the carrier accepts them; retries of a failed
socket write retain those exact bytes rather than repolling as a new transmission.

## Send path, partial blocks and feedback service

The recovery crate exposes separate `poll_feedback` and `poll_source` methods
using its authoritative parser and emission state. Its existing combined poll
retains its current alternating ACK/data behavior. A public borrowed packet view
lets this composition validate ARQ records without duplicating packet offsets.

First source emissions are collected as complete encoded ARQ packets. A sealed
FEC block emits its canonical systematic symbols followed by Cauchy repairs.
Source count closes a full block; an injected deadline from the first collected
source closes an idle/partial block. `flush_after` is positive and shorter than
the initial RTO. Partial repairs are `ceil(actual_sources * full_repairs / target)`;
one source therefore emits one systematic plus at least one genuine coded repair.
The total Cauchy source/repair count cannot exceed 256.

ARQ timers start when its encoded source is handed to this composition. A bounded
partial-block delay and external send backpressure are therefore part of elapsed
RTO; this is not a claim of precise physical-send RTT sampling. Only one sealed
outbound generation is queued, and its packets are never silently discarded.
Timeout retries are sent as direct ARQ source packets with their original source
ID, rather than entering a new FEC generation. Timer retry exhaustion remains a
visible terminal failure.

ACKs are direct ARQ feedback records and do not wait for a source generation to
fill, decode or expire. Due feedback and available data alternate when both have
service, using the same wire budget. A zero or exhausted budget stops both.
The split `poll_feedback` and `poll_data` APIs support a retained TLS feedback lane
and UDP data lane. They use the same mandatory `OutboundBudget`; the adapter must
allocate bounded service to each and retain a returned packet across carrier
backpressure. Feedback-only polling does not collect or seal an outgoing block.
`inspect_output` strictly validates the local sending role/session/epoch and
authoritative ARQ/FEC encoding before returning `RecordKind::{Source, Feedback,
Systematic, Repair}`. It is routing metadata, not an authentication operation.
`inspect_peer` applies the same parser to the receiving context after lower-layer
authentication, so control/data dispatch does not duplicate private wire offsets.
In particular the feedback body now includes the reliable envelope and is 56
bytes, so an adapter must negotiate that format rather than assume ARQ's 48 bytes.

## Receive path and authentication boundary

The eight-byte draft envelope is `L2RF`, version byte 1, kind byte (1 direct ARQ
source, 2 ARQ feedback, 3 FEC symbol), then two reserved zero bytes. Packet length
is supplied by its enclosing authenticated record; trailing bytes are rejected
by the authoritative inner parser. ARQ and FEC bindings both use the supplied
session, epoch and peer direction. The FEC channel is fixed to zero for this
single-channel primitive; separate instances provide separate authenticated
channel domains in a future adapter.

Verify AEAD/MAC and replay at the lower session layer before calling receive.
FEC is not an integrity check. A corrupted protected datagram must fail there
before it can alter either recovery engine. Tests exercise that composition with
the maintained datagram codec; this crate itself has no crypto dependency.

A valid systematic FEC symbol exposes its exact complete ARQ source immediately,
without waiting for full block rank. When repair equations complete a block,
validate every reconstructed ARQ packet and its contiguous original source-ID
sequence, then feed those packets into the same ARQ receiver. That engine provides
ordered delivery, duplicate suppression, cumulative/bitmap ACKs and exactly the
original source identity; there is no sender ledger or invented source data.

Restored packets are staged by source ID in a byte/count-bounded queue. Conflicting
same-ID payloads fail, exact duplicates merge, and application backpressure retains
staged packets until the ARQ receive window can accept them. Whole reconstruction
capacity is checked before accepting an equation that may complete a block. ACK
input is serviced independently of restored-data pressure. The configured staging
headroom covers one sender window plus one complete block; peer window negotiation
and matching configuration remain integration requirements.

The isolated retry-enrichment correction keeps one optional source range in each
existing generation/deadline cell. An accepted systematic fixes the range under
the existing contiguous decoded-ID constraint; every later accepted systematic
and full decode must agree. After original direct ARQ admission succeeds, an
exact retry can enter one unambiguous retained generation as its original
systematic equation. No range, repair-only state, ambiguous overlap or optional
staging/symbol pressure leaves the direct source path unchanged. The original
generation deadline, work cap and full-rank commit remain authoritative; no
incomplete generation is evicted. Inconsistent authenticated equations or source
ranges can fail earlier than before. Completion still installs the existing
terminal tombstone, so the existing terminal ignore boundary can begin earlier
when newly available direct source bytes complete the generation. Future unseen
conflicting repairs are then ignored exactly as after any ordinary completion;
retained conflicting equations are checked before that commit.
The existing scratch reservation includes the largest receive coded extent, and
expanded deadline-cell metadata is included in the complete reserved plan. The
outer runtime retained-byte allowance remains unchanged and authoritative.
Five retry-enrichment regressions passed. A native Cauchy UDP forward run completed at 0.9869568 Mbit/s. The result does not quantify how many generations the enrichment released.

FEC capacity/window/expiry loss is observable and falls back to ARQ. A systematic
packet can still supply its ARQ source when optional FEC state cannot be retained;
a skipped repair never causes a source ACK. Structural conflicts, invalid decoded
length/padding or reconstructed ARQ records fail closed. Such protocol failures
are terminal because already accepted equations cannot be safely rolled back.
No claim of whole-engine transactional rollback is made after a fatal authenticated
protocol violation; no newly reconstructed bytes from that failed block are released.

## Resource and lifetime accounting

The ARQ engine keeps its existing byte/count/span limits. The source-building
buffer is capped by one configured generation, and the sealed outbound queue by
that generation's systematic plus repair count and exact maximum packet size.
FEC receive state uses its existing generation/equation/reservation/work limits.
Restored packet metadata and payload bytes have independent caps. Decoder scratch
and completed output are bounded before ownership moves into restored staging.

Monotonic Duration is injected. FEC deadlines use checked millisecond ticks; no
system clock is read. Explicit expiry observations increment counters and release
optional coding state, never fabricate delivery. `deadline` includes partial flush,
ARQ feedback/retries and FEC cleanup. `drained` requires confirmed ARQ send state,
application delivery, partial/outbound/restored queues and active FEC generations
to be empty. Terminal tombstones remain bounded and do not prevent drain.
Source/generation exhaustion is explicit and does not wrap identities. A last
sealed generation can continue direct ARQ retries; admitting new sources after
generation exhaustion fails. A caller must negotiate a fresh drained context
before exhausting counters; no automatic context or key reset is performed.

## Work checklist

- [x] [MOD-REL-01] Add independently pollable bounded ARQ feedback/source paths and authoritative borrowed packet inspection, preserving existing combined-poll behavior. Evidence: [ARQ APIs and regression tests](../../crates/l2tunnel-recovery/src/arq.rs).
- [x] [MOD-REL-02] Implement canonical composition configuration, draft envelope, source-ID preservation and single outbound wire-budget charging for every copy. Evidence: [implementation](../../crates/l2tunnel-reliable/src/lib.rs), [budget/configuration tests](../../crates/l2tunnel-reliable/src/tests.rs).
- [x] [MOD-REL-03] Implement real systematic/Cauchy block output, injected partial flush and bounded direct-ARQ fallback with independent ACK service. Evidence: [sender and split routing APIs](../../crates/l2tunnel-reliable/src/lib.rs), [deadline/fallback tests](../../crates/l2tunnel-reliable/src/tests.rs).
- [x] [MOD-REL-04] Implement systematic early delivery, independent real-byte reconstruction, bounded restored-source staging and explicit FEC expiry/degradation. Evidence: [receiver implementation](../../crates/l2tunnel-reliable/src/lib.rs), [backpressure/expiry tests](../../crates/l2tunnel-reliable/src/tests.rs).
- [x] [MOD-REL-05] Test no loss, source loss repaired before RTO, insufficient-rank ARQ fallback, duplicate/reorder, partial/one-source blocks, budgets/caps and lower-layer corruption rejection. Evidence: [17 focused tests](../../crates/l2tunnel-reliable/src/tests.rs), [local validation](#local-validation).
- [ ] [MOD-REL-06] Integrate negotiated configuration/flow credit/MUX, authenticated carrier adapters, measured CPU/memory and real loss/reorder/native-device receipts.
- [ ] [MOD-REL-07] Port distinct Python generation scheduling/rank-feedback/sliding/hybrid families and their byte/trace parity gates; do not infer them from this baseline.
- [x] [MOD-REL-08] Implement explicitly selected direct ARQ-only emission through the existing owner, independently per direction, with exact no-FEC backing, strict coding-record refusal, shared wire charging and original retry/exhaustion behavior. Evidence: [three affected loss/storage/failure cases](../../work/parallel-features-20261115/parallel-wave6-reliable-cases-attempt-1.json), passed locally in 0.006 s; this is finite protocol evidence.
- [ ] [MOD-REL-09] Validate ARQ-only Aligned/Packed through complete authenticated Common configuration, actual shared carrier service/API switches and original native custody; retain full mode, native-platform and performance acceptance separately. **Finite Common configuration and actual carrier API/Unix packet-device cases now pass** in the [affected batch](../../work/parallel-features-20261115/parallel-wave6-cases-attempt-1/validation.json), whose two Packed fixture failures remain failed. Production native CLI/device qualification remains open.

## Local validation

Executed on local Linux: `cargo fmt -p l2tunnel-reliable -p l2tunnel-recovery`,
`cargo test -p l2tunnel-reliable -p l2tunnel-recovery --offline` (17 reliable tests,
14 ARQ tests and one ARQ doctest),
`cargo clippy -p l2tunnel-reliable -p l2tunnel-recovery --all-targets --offline -- -D warnings`,
and `RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-reliable -p l2tunnel-recovery --no-deps --offline`
passed. `python3 tools/check.py` also passed; its local aggregate receipt is
`/tmp/l2tunnel-reliable-check.log`. The recovery tests use independent endpoint states and received nonzero
packet bytes. Their finite loss traces and protected-codec composition are not
native socket/device, congestion-fairness, CPU-performance or cross-platform receipts.
