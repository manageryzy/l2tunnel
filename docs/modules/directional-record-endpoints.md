# Directional Aligned and Packed endpoints

Status: interfaces frozen by the integrator against clean checkpoint
`a0b9bd073d861aa6082f8465dea2a722fa52fe70`. Pure directional implementation is protocol-tested in150 direct package cases;
required full stage acceptance, common runtime composition and native
qualification remain open. This is a prerequisite for the
common record-profile composition, not a new transport, runtime or independent
connection mode. The pre-edit source binding is
[DRE source binding](../../work/common-foundation-20261114/directional-record-endpoints/source-binding-v0.md).

Follow the [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[implementation checklist](../implementation-checklist.md) and
[mode parity](../mode-parity.md). Existing
[Aligned](aligned-envelope.md), [Packed](packed-recovery.md),
[recovery](recovery.md) and [FEC](fec.md) implementations are reused. Their
historical tests and native receipts retain their original scope. Full SW-11,
RLNC, parity, rolling, packed, proxy, all 47 P-* entries, platform and 80 Mbit/s
gates remain unchanged and open where their own ledgers say so.

## Current implementation and precise gap

`l2tunnel_aligned::Endpoint` already owns one actual Aligned/Packed sender, one
Reliable composition and one Aligned receiver. `Reliable` already owns one
selective-repeat engine, an outgoing Cauchy encoder pipeline and an incoming FEC
decoder. They use caller-supplied time and bytes; no runtime, clock, OS handle,
authentication or native device belongs in these public libraries.

At the pre-edit checkpoint each accepted only one complete configuration. That value supplies both
directions' source/body geometry, limits, packing options and parser maxima.
Two full endpoints with one unused half each would duplicate actual owners and
still conceal direction-specific policy. A new variant tag around those owners
would not solve this gap either.

The prerequisite instead gives those same owners independent directional policy.
It introduces no actor, socket, AEAD counter, control stream, retransmission
algorithm or alternate source allocator. The common Driver/Bank/transaction work
remains separate and retains its existing two-generation lifecycle.

## Frozen additive interfaces

The integrator froze the additive interfaces below before production edits.
This engineering approval records no new owner scope decision. Existing public
methods, field sets, defaults, error types and wire versions stay available.

```rust
// l2tunnel_recovery
SelectiveRepeat::new_duplex(send: ArqConfig, receive: ArqConfig,
    context: RecoveryContext) -> Result<Self, RecoveryError>;
CarrierOnly::new_duplex(send: ArqConfig, receive: ArqConfig,
    context: RecoveryContext) -> Result<Self, RecoveryError>;
SelectiveRepeat::new_duplex_reserved(send: ArqConfig, receive: ArqConfig,
    context: RecoveryContext, limits: storage::Limits)
    -> Result<Self, storage::Error>;
storage::DuplexPlan::for_arq(send: ArqConfig, receive: ArqConfig)
    -> Result<storage::DuplexPlan, storage::Error>;
storage::DuplexPlan::{send_config, receive_config}(&self) -> ArqConfig;
storage::DuplexPlan::capacity_bytes(&self) -> usize;

// l2tunnel_fec: expose the existing scalar validator; no new decoder
DecoderConfig::validate(self) -> Result<(), Error>;

// l2tunnel_reliable
ReliableConfig::validate(self) -> Result<(), Error>;
Reliable::new_duplex(send: ReliableConfig, receive: ReliableConfig,
    context: RecoveryContext) -> Result<Self, Error>;

// l2tunnel_aligned and l2tunnel_aligned::packed respectively
Endpoint::new_duplex(send: Config, receive: Config,
    context: RecoveryContext) -> Result<Self, Error>;
```

All three endpoint layers add `send_max_packet_bytes()` and
`receive_max_packet_bytes()`. Existing `max_packet_bytes()` remains a conservative
caller-buffer maximum over the two values; it is never a parser admission limit.
For equal configurations it returns the same existing value. Directional poll
output checks use the send maximum; incoming data inspection uses the receive
maximum. Fixed ACK records remain subject to their exact grammar and context,
not a maximum source size chosen from the opposite direction.

Existing `new(config, context)` delegates to the equal-direction construction.
Existing selective-repeat `new_reserved` and `storage::Plan::for_arq/config()`
retain their symmetric public contract. A separate `DuplexPlan` avoids making
the existing single-configuration getter ambiguous. The legacy and reserved
backings continue to share the same actual ARQ transition functions.

## Complete configuration meaning and direction projection

Each complete `Config` describes one global data direction, including the sending
and receiving policies for that direction. It is not a cropped local endpoint
configuration. Let A describe initiator-to-responder data and B describe
responder-to-initiator data. The initiator constructs `(send=A, receive=B)`;
the responder constructs `(send=B, receive=A)`. Both complete values are retained
and independently validated. No field is removed, defaulted, hashed away or
substituted by a maximum to fit a common configuration encoding.

For one local owner:

| Actual operation or retained state | Authoritative directional value |
| --- | --- |
| Sender body/native policy, channels, first record, symbol geometry | send Aligned/Packed Config |
| Send source size, record/byte retention, ID span, RTO/backoff/retries | send ARQ Config |
| Outgoing Cauchy target, repair ratio and original partial-block flush | send Reliable Config |
| Incoming source size, receive byte/count/window admission | receive ARQ Config |
| ACK coalescing deadline for incoming data | receive ARQ Config |
| Incoming FEC block dimensions, decoder lifetime/history/work/storage | receive Reliable Config |
| Restored source staging and recovery-to-codec handoff | receive Reliable/Aligned Config |
| Receiver body/native policy, channels, record/source windows and lifetime | receive Aligned/Packed Config |
| Incoming ACK claims for local data | the one actual local send ledger |
| Every local emission's external overhead, including ACKs about incoming data | send Reliable Config |

For example, `send.arq.receive_records` is the peer receiver's bound in the send
direction, not the local receive bound; it still participates in full validation
and eventual complete negotiation. Existing Reliable constraints such as sender
window not exceeding that direction's receiver window are preserved for each
complete direction. They are not incorrectly applied between A and B.

An ACK physically travels opposite the data it acknowledges. Its scheduling uses
the incoming data direction's ACK policy, its claims update the local send ledger
on receipt, and its local wire charge uses the local physical egress overhead.
Receiving ACKs must not use a second sender, create a source or renew a deadline.
Distinct overhead values describe the two physical directions; they are not two
charges for one packet. Caller `OutboundBudget` remains the shared per-call
allowance, not an additional pacing bucket.

Pure endpoints may represent differing native policies in the two directions.
An embedding runtime must separately reject a policy incompatible with its
actual native device before creating/using that device. This design does not
silently relax the runtime's native-layer contract.

## One owner and directional layout

The ARQ engine has one `Sent` owner sized by send limits, one `Received` owner
sized by receive limits, one local source allocator and one peer receive/delivery
prefix. Store both complete policies in that engine. Do not synthesize an
`ArqConfig` that loses one source maximum or misroutes ACK timing. CarrierOnly
retains its own profile grammar and ordered-carrier restriction; adding the same
constructor shape does not authorize it over unreliable UDP.

For reserved ARQ the checked requested persistent heap layout is exactly:

```text
send.send_records * size_of::<SendSlot>()
+ receive.receive_records * size_of::<ReceiveSlot>()
+ send.send_records * send.max_source_bytes
+ receive.receive_records * receive.max_source_bytes
```

Each slot payload is reserved at its own direction's size. Actual retained
capacity and allocation count must match the plan; idle capacity counts once.
Budget refusal precedes the first selected allocation; a partial failure drops
all completed reservations. Equal-direction construction must match the existing
Plan and actual Usage. Charges describe requested Rust layouts, not allocator
overhead, RSS, physical pages or OS overcommit guarantees.

Reliable keeps one ARQ owner, one receive decoder and one outgoing encoder
pipeline. Sending `building`/`outgoing` capacities use send FEC dimensions;
`restored`/`fec_deadlines` and decoder limits use receive policy. Its scratch may
need the maximum of local ARQ output and incoming delivered source sizes, but
each parser and admission path retains its own exact bound. If scratch is split,
both actual capacities must be inventoried; no fictitious second ARQ charge is
allowed. The new duplex constructor does not establish full fallible Reliable,
FEC or Aligned allocation admission: those distinct resource gates remain open.

Aligned keeps one sender and one receiver. `send_buffer` uses the send original
source size; `receive_buffer` uses the receive original source size. Receiver
handoff expiry uses the original receive lifetime and never restarts on capacity
retries. Sending loops use send limits; receive pumping uses receive limits.

Packed keeps the same owner with separate send and receive `Options`.
`hold_micros`, `work_limit`, pack-unit count and send envelope come from send;
receive envelope geometry, preflight unit limits and unpack scratch come from
receive. Receive hold/work settings remain part of the complete remote sender
contract, not a local unpack timer. `packed_symbols` is sized only for receive
units and receive symbol width. Existing ordinary/Packed profile selection stays
explicit, with no byte sniffing or fallback. Mixed Aligned/Packed directional
families need an explicit later common-profile contract; this prerequisite does
not claim that combination or remove it from SW-11 scope.

## Identity, credit and wire preservation

`RecoveryContext` still supplies one session/epoch/local role. Global data
directions derive from that role exactly as before. Send and receive source IDs
are independent; neither is a packet security number. FEC contexts, envelope
scopes and local/peer inspectors use their respective existing global directions.
Packed unit IDs remain separate from ARQ source IDs. Original Aligned
`RecordIdentity` and channel remain attached to native bodies, including context
records, fragments and independent-short behavior. `outgoing_units` inspects the
actual send geometry and reports only real direct/systematic first-flight
witnesses; repair equations do not mint original native units.

`prepare/pending/commit_delivery` retain the existing native custody boundary.
Neither recovery receipt nor queue enqueue is a physical device completion.
This prerequisite adds no native credit counter and must not turn RecordId+1
into a body-completion prefix. The common adapter must preserve selective native
receipts/tombstones and distinct admission/extraction ordinals. Old-generation
feedback and outstanding native custody continue to pin the actual two-slot
Bank lifecycle until negotiated retirement.

L2AR, Reliable, FEC, Aligned and Packed wire versions are unchanged. Existing
`Config::digest` domains and complete scalar ordering are unchanged, including
duration precision. Equal-direction constructors must reproduce existing bytes,
deadlines, errors, delivery order and actual identities. There is no new duplex
digest or wire configuration in this prerequisite.

Complete Aligned fields currently occupy 332 canonical bytes per direction;
Packed adds 24, for 356. Two independent directions require 664/712 bytes before
the common profile/carrier fields. The current transaction Configuration bound
is 512 bytes. The integrator must version and validate the real complete common
encoding and its dependent message/API bounds; omitting fields or accepting only
equal directions to satisfy that bound is not an implementation option.

## Validation and error ordering

Extract scalar validation once and reuse it in construction. Expose the existing
FEC decoder validator rather than duplicating its private predicates. Reliable
validation preserves the current order: ARQ validation, checked Reliable geometry
and cross-module predicates, then FEC decoder validation. Aligned retains its
existing receiver/sender geometry, native policy and recovery-horizon checks;
it calls scalar Reliable validation instead of constructing a dummy engine.
Packed retains its existing codec/batch-progress checks and the existing unit
source-window rule. Do not replace that rule with the ordinary Aligned rule.

For a duplex construction, validate the complete send configuration first, then
the complete receive configuration, then existing context checks. Perform all
checked layout arithmetic and budget admission before selected allocations.
Equal-direction legacy entry points retain their existing first error and
configuration-before-context ordering. No construction failure is peer authority.

At packet time retain sticky-failure/time/output preflight ordering, exact
context/role/profile checks and existing distinction between retryable pressure
and fatal authenticated malformed input. Direction selection uses the known
operation and authoritative parsed record kind; an untrusted flag cannot select
a larger cap. Incoming data is checked only against receive geometry, and ACK
claims only against the actual local send ledger. Backpressure retains the
original bytes, source/record identity and deadline without duplicate admission.

## Stable acceptance leaves

DRE-01..07 have focused pure protocol evidence. DRE-08 retains the required
full stage acceptance; no successful component test closes common runtime or
SW-11 composition. The evidence below is a scoped composite, not a new full run.

- [x] [DRE-01] Freeze the complete directional meaning, additive signatures, actual owner/file boundaries, error order and pre-edit source binding. Record engineering approval without treating it as an owner scope decision. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json) and [pre-edit binding](../../work/common-foundation-20261114/directional-record-endpoints/source-binding-v0.md).
- [x] [DRE-02] Make complete Reliable/Aligned/Packed validation allocation-free through authoritative shared validators; preserve legacy acceptance/error order and test invalid geometry before construction/allocation. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); all150 direct package cases pass, with no common-runtime or native qualification inferred.
- [x] [DRE-03] Implement actual duplex ARQ/CarrierOnly state selection and reserved selective-repeat backing. Differentially compare equal-direction legacy, duplex and reserved transitions; test asymmetric exact capacity, one-byte-short budgets, partial-reservation failures and real drop/reuse. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); all150 direct package cases pass, with no common-runtime or native qualification inferred.
- [x] [DRE-04] Implement the single duplex Reliable owner with independent send/receive maxima, FEC geometry/staging/timers and correct ACK routing/wire charge. Test one direction with a smaller cap, different block/repair counts, byte/count windows, ACK delays, RTOs and overheads; reject data accepted only by the larger opposite cap without mutating the wrong state. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); all150 direct package cases pass, with no common-runtime or native qualification inferred.
- [x] [DRE-05] Implement actual duplex Aligned sender/receiver construction, buffers, parser/witness geometry and original native identities. Test paired peers with swapped complete policies, real arbitrary byte delivery in both directions, differing channel/symbol/body/window bounds, fragments, context updates, native pressure, original expiry and wrong scope/epoch/role. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); all150 direct package cases pass, with no common-runtime or native qualification inferred.
- [x] [DRE-06] Implement actual duplex Packed options/envelopes on the shared owner. Test different hold/work/unit/symbol/channel settings, partial flush, source-vs-unit identities, exact native bytes, malformed unit bounds and empty-receiver batch progress. Preserve packed 255/unpacked 256 limits and ordinary/Packed explicit selection. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); all150 direct package cases pass, with no common-runtime or native qualification inferred.
- [x] [DRE-07] Preserve legacy byte/digest/default vectors and compare full equal-direction event traces with the new constructors: outputs, exact errors, budgets, retries, deliveries, IDs, drain/deadlines and statistics. Use independent fixed bytes for promised wire goldens, not encoder roundtrips. Include loss/reorder/duplicate/unsent ACK, conflicting data, time overflow, exhaustion, insufficient output and capacity retry paths. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); all150 direct package cases pass, with no common-runtime or native qualification inferred.
- [ ] [DRE-08] Pass the integrator's one combined required source-stable check with the focused acceptance above and accurately report its scope. Common configuration/facade, Driver/Bank composition, cross-profile negotiated switches, authenticated typed feedback/native fences, native matrices and performance remain distinct unclosed acceptance; none is inferred from DRE.

## Proposed implementation ownership and dependency order

After explicit interface freeze, one record worker owns the actual ARQ,
Reliable and Aligned/Packed directional changes and focused tests. Candidate
production files are `l2tunnel-recovery/src/arq.rs`, `arq/backing.rs` only if its
storage operation needs a directional capacity, `storage.rs`,
`l2tunnel-reliable/src/lib.rs`, `l2tunnel-aligned/src/lib.rs` and `packed.rs`.
The FEC change is only public visibility/documentation of the existing
`DecoderConfig::validate` in `l2tunnel-fec/src/decoder.rs`; coordinate that file
with any resource owner. Prefer dedicated directional test modules in the same
crates and retain existing compatibility fixtures.

Implement shared validators first, actual ARQ/plan selection second, Reliable
third, Aligned/Packed fourth, then focused differentials. The integrator owns
common facade/configuration encoding, manifest/ledger registration, runtime
Bank/Set/native integration, formatting, builds, required checks and Git.
Production/test edits were authorized by the integrator's explicit interface and
ownership freeze, not by this design document alone.

## Authored source and verification

The additive constructors, exact maxima, duplex reserved ARQ inventory and
shared scalar validators are authored in the production files above. Existing
backing transitions are reused unchanged; no edit to `arq/backing.rs` was needed.
Ordinary and Packed output witnesses reuse the existing send buffer so a smaller
receive symbol cannot truncate or overrun local send witness scratch. Existing
configuration fields, default values, digest domains/order and golden data files
are untouched. The extra complete policy is retained inline; conservative Packed
codec memory bounds therefore include the changed actual Endpoint size.

Dedicated tests are registered at
`l2tunnel-recovery/src/arq/directional_tests.rs` (seven cases),
`l2tunnel-reliable/src/directional_tests.rs` (four cases) and
`l2tunnel-aligned/src/directional_tests.rs` (four cases). They exercise actual
asymmetric reserved slot payloads, one-short/invalid-before-allocation refusal,
every partial constructor drop, real byte pressure and original-ID retry,
direction-specific RTO/ACK timing, actual Cauchy recovery under lost/reordered
inputs, exact local data/feedback overhead and source cap isolation. Aligned and
Packed cases exchange arbitrary native bytes with distinct geometry, channels,
native policies and packing options, checking native record/fragment identities
and equal-direction compatibility traces. Existing broader negative/wire/digest
fixtures also ran in the same direct package batch. The direct protocol evidence
does not complete DRE-08 required stage acceptance.

The worker ran no project commands. The integrator ran the150 direct package
cases with bounded parallelism, then reused their unchanged source/dependency
evidence during the runtime-only repair. Strict affected Clippy/rustdoc/format
checks pass. The failed first affected attempt and exact stack negative control
remain preserved; required full stage, native and performance gates stay open.
