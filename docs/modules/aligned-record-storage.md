# Fallible Aligned and Packed endpoint storage

Status: **actual reserved codec/Aligned/Packed owners implemented and protocol-tested;
complete allocator/reuse/runtime integration qualification remains open**.
This contract starts from checkpoint `d988ab4` and the actual directional owners.
It is a prerequisite for the [common record Engine](common-record-engine.md), not
a declaration that mixed-profile runtime generations or full SW-11 work already.
The integrator froze the dependency interfaces and file ownership before
production edits. This document records no owner decision or new default.

Read the [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[checklist](../implementation-checklist.md), [mode parity](../mode-parity.md),
[directional endpoints](directional-record-endpoints.md),
[Aligned receiver](aligned-receiver.md), [Packed recovery](packed-recovery.md),
and [common configuration](record-configuration.md). Existing wire/default/digest
vectors, independent send/receive policies, injected time, physical native
completion and all supported maxima remain authoritative. RLNC, parity, rolling,
proxy, all47 P-* gates, full resource admission, native/platform and performance
acceptance retain their original definitions.

## Actual allocation inventory and boundary

`l2tunnel_aligned::Endpoint` owns exactly one sender, one Reliable owner and one
receiver. `packed::Endpoint` uses that same owner with independent directional
packing policies. It must never construct two duplex endpoints and discard one
half of each. For complete global configurations A and B, an initiator owns
`send=A, receive=B`; the responder owns `send=B, receive=A`.

At the audited checkpoint the following allocations are real:

| Owner | Current allocation and lifetime | Required reserved owner |
| --- | --- | --- |
| Aligned sender | Box header; send-channel vector; one Encoder per channel and one staged Encoder, each with bounded header scratch; native/body and symbol scratch | Fallible actual header and all sender buffers once, retained through source handoff |
| Packed sender | Actual Aligned sender plus fixed Packer source and max-units record-ID vector | Same sender and timed Packer, no duplicate ordinary sender |
| Reliable | Duplex ARQ, outgoing FEC pipeline, incoming FEC decoder, restored-source staging and work buffers | Actual dependency reserved Plan/Usage, counted once |
| Aligned receiver | Receive-channel Decoder vector and staged Decoder; record and source-proof metadata; native output | Fixed actual metadata, decoder workspaces and native output |
| Receiver ingress | Record body/fragment vectors, source-proof symbol copies; final-fragment temporary validation copy | Reused buffers provisioned for every advertised slot, including idle capacity |
| Receiver batch validation | Allocating full validation shadow, record/proof rollback copies and outcome vector | Reused bounded shadow/rollback backing; same admission/validation transitions |
| Endpoint scratch | Send original-source buffer; receive original-source buffer; Packed receive symbol expansion | Fallible directional capacities, including zero-sized ordinary Packed workspace |
| Packed ingress | Fresh vector of borrowed authenticated symbols and returned outcomes per source | Caller-supplied bounded views/outcomes or reusable backing, no retained borrowed peer memory |

`HeaderEncoder`/`HeaderDecoder` context clones copy fixed inline state. They are
not evidence of a heap leak or a substitute for reserving each actual body's
scratch. Conversely, the receiver's `Record`/`Proof` clones include heap payloads
and cannot be counted as fixed context copies.

The outer endpoint alone cannot provide complete backing while the codec still
uses infallible `Box::new`, `vec!`, `to_vec` and per-packet deep clones. The codec
constructor and reusable batch seam are explicit prerequisites, not an accepted
ARQ-only subtotal or an infallible fallback. The integrator extended this
worker's ownership to the listed codec files and dedicated storage helpers/tests;
root codec registration and manifests remain integrator-owned.

## Frozen public endpoint interface

The following additive interface is frozen for implementation. Existing
`new` and `new_duplex` stay allocating and preserve their exact signatures,
configuration/context error order and wire behavior.

```rust
pub mod storage {
    pub struct Limits { pub capacity_bytes: usize }
    pub struct Plan { /* checked private complete directional inventory */ }
    pub struct Usage {
        pub limit_bytes: usize,
        pub capacity_bytes: usize,
        pub allocations: usize,
    }
    pub enum Error {
        Endpoint(super::Error),
        Codec(codec::aligned_storage::Error),
        Reliable(reliable::storage::Error),
        Layout,
        Limit { required: usize, limit: usize },
        Allocation,
        Invariant,
    }
    impl Plan {
        pub fn for_duplex(send: Config, receive: Config) -> Result<Self, Error>;
        pub fn for_packed_duplex(send: packed::Config, receive: packed::Config)
            -> Result<Self, Error>;
        pub fn send_config(&self) -> Config;
        pub fn receive_config(&self) -> Config;
        pub fn send_packed(&self) -> Option<packed::Config>;
        pub fn receive_packed(&self) -> Option<packed::Config>;
        pub fn capacity_bytes(&self) -> usize;
        pub fn reliable_plan(&self) -> reliable::storage::Plan;
    }
}
impl Endpoint {
    pub fn new_reserved(config: Config, context: RecoveryContext,
        limits: storage::Limits) -> Result<Self, storage::Error>;
    pub fn new_duplex_reserved(send: Config, receive: Config,
        context: RecoveryContext, limits: storage::Limits)
        -> Result<Self, storage::Error>;
    pub fn storage_usage(&self) -> Option<storage::Usage>;
    pub fn pending_deadline(&self) -> Option<Duration>;
}
// packed::Endpoint has the same three methods using packed::Config.
```

Plan is allocation-free and validates complete send policy before complete
receive policy. Constructors preserve configuration-before-context validation,
then reject an invalid context, checked layouts and insufficient full budget
before the first selected reservation. `Usage` is an observation of real owned
backing and is never accepted as construction authority. An allocating endpoint
returns `None`, rather than inventing a reserved Usage.

All capacities are retained managed heap layouts. They include actual selected
heap headers/slot metadata, payload, replay/tombstone, scratch, batch and nested
ARQ/FEC/Reliable backing exactly once. They exclude inline `size_of::<Endpoint>`,
allocator overhead, RSS, kernel buffers and caller-owned output. A sender stored
in a heap cell contributes that actual cell layout once; it is not also charged
as part of an imaginary second endpoint. The common Engine separately charges
its own enum/generation/selector and external owners. There is no claim of full
combined Engine/Bank/runtime reservation until its actual consumer sums them.

No caller budget is raised implicitly. Physical per-slot overreservation is
permitted only when its exact requested layout appears in Plan and actual Usage;
the existing logical record/byte/fragment/time admission limits still apply.
Large accepted configurations may therefore need a larger explicit physical
budget; a smaller budget returns `Limit`, never reduced maxima or a fallback.

## Frozen codec dependency contract

Actual existing `aligned_sender::Sender`, `packed_sender::Sender`,
`aligned_receiver::Receiver` and `packed::Packer` need fallible reserved
constructors and actual heap observations. The integrator approved the public
namespace `l2tunnel_codec::aligned_storage`, registered by root, with:

```rust
pub struct Limits { pub capacity_bytes: usize }
pub struct Usage {
    pub limit_bytes: usize,
    pub capacity_bytes: usize,
    pub allocations: usize,
}
pub enum Error {
    Sender(aligned_sender::Error),
    PackedSender(packed_sender::Error),
    Receiver(aligned_receiver::Error),
    Layout,
    Limit { required: usize, limit: usize },
    Allocation,
    Invariant,
}
SenderPlan::for_config(aligned_sender::Config) -> Result<SenderPlan, Error>;
PackedSenderPlan::for_config(packed_sender::Config) -> Result<PackedSenderPlan, Error>;
ReceiverPlan::for_limits(aligned_receiver::Limits) -> Result<ReceiverPlan, Error>;
// Each checked private-field plan exposes config()/limits(), capacity_bytes().
aligned_sender::Sender::new_reserved(scope, config, Limits) -> Result<Self, Error>;
packed_sender::Sender::new_reserved(scope, config, Limits) -> Result<Self, Error>;
aligned_receiver::Receiver::new_reserved(scope, limits, Limits) -> Result<Self, Error>;
// Each actual owner exposes storage_usage() -> Option<Usage>.
aligned_receiver::Receiver::pending_deadline() -> Option<Tick>;
```

Body encoder/decoder and Packer reservation helpers remain crate-private and
share a temporary exact-layout allocator. This is not a new header codec,
decoder, recovery algorithm or transactional state machine. Receiver adds
bounded packet-time `Storage`, `OutputTooSmall` and `Allocation` variants;
construction errors remain in the storage namespace without recursive types.

For send policy, reserve send channel metadata, each channel Encoder scratch,
one staged Encoder scratch, `max_frame_bytes + 29` body workspace and one
`symbol_bytes` symbol. Packed adds its actual Packer source and max-units
RecordId storage. Keep one actual sender, original body/context identity and
immutable source stage across recovery backpressure.

For receive policy let C be channels, R be C plus lookahead_records, S be
source_window, F be max_fragments_per_record and W be symbol_bytes. The complete
inventory includes R record metadata/body/fragment owners, S source-proof
metadata/symbol owners, C channel Decoders plus one staged Decoder, native output
and final-fragment validation scratch. Each decoder's expanded/native scratch
uses its actual configured sizes. Provisioned payload buffers stay owned when a
record/proof slot empties and are recycled on every retirement/error path.
All existing record/source windows, head-slot progress reserves, logical
lookahead bytes/fragments, first-arrival expiry and early-short tombstones remain
unchanged. Fragment flags require explicit byte/bit-layout accounting; do not
assume `Vec<bool>` reserves `F * size_of::<bool>()` bytes. The shared representation
uses explicit 0/1 bytes instead, preserving the existing logical fragment slots
and conservative one-byte-per-fragment bound.

Packed requires the existing semantic batch transaction, not merely parser
preflight. Reserve two first-touch version journals: outer admission rollback
and inner simulated semantic validation. They call the same real single-record
admission/prepare/commit transitions. On first mutation, move the old Record into
the journal and copy only that touched body/flags into a free reserved version.
Removals and proof retirement move old owners without payload copies. Untouched
history is not copied or refreshed per batch. Cleanup iterates bounded touched
orders; naturally a worst-case transaction can touch all configured slots.
Fixed header checkpoints are captured only for actually modified channels.
One native backup preserves exact pre-validation output. Undo inner validation
before committing outer admission, so simulated native commits never escape.
A semantic error must leave live decoder
contexts, record/proof ledgers, pending native bytes, source floor and accepted
time unchanged, apart from the existing sticky preexisting-expiry behavior.
Simulated shadow native commits never become real physical completion. On
success, admit each actual symbol exactly once; no simulated validation may
retire real pending native output.

Exact receiver heap inventory: live arrays R `Option<Record>` and S
`Option<Proof>`; a shared free-pool metadata vector for 3R `RecordBuffer` owners
(two Vec headers, 65535 body bytes and F flag bytes each) and 3S `ProofBuffer`
owners (one Vec header and W symbol bytes each). Actual payloads move among live,
free and journal owners without another reservation. Each of the two journals
reserves R record-undo entries, S proof-undo entries, R/S touched-index vectors,
and C optional fixed channel checkpoints. Journals retain original globals and
staged header context inline. Validation owns one max-frame native backup; final
fragment checking owns one65535-byte scratch buffer. C+1 real Decoder workspaces
each reserve `max_frame_bytes+44` expanded and `max_frame_bytes` native bytes;
Receiver output owns another max-frame buffer. Every metadata element layout,
payload product and aggregate is checked through Rust Layout and usize/isize
bounds. Idle versions remain fully charged. First-touch bookkeeping and buffer
movement preflight capacity before changing live ownership. No fixed limit is
reduced to make these physical reservations smaller.

Add a bounded caller-output batch entry point so the actual endpoint can pass
borrowed symbol views and receive outcomes without a new heap allocation for
each source. Keep the existing Vec-returning APIs for compatibility; any
caller-owned returned allocation is separate from retained endpoint backing.
The selected complete reserved endpoint must use the nonallocating path:

```rust
Receiver::admit_batch_authenticated_into(&mut self, symbols: &[AuthenticatedSymbol<'_>],
    now: Tick, outcomes: &mut [Admission]) -> Result<usize, Error>;
Receiver::admit_validated_batch_authenticated_into(&mut self,
    symbols: &[AuthenticatedSymbol<'_>], now: Tick, outcomes: &mut [Admission])
    -> Result<usize, Error>;
```

Only successful admission writes the caller's outcomes. Existing Vec-returning
convenience methods may allocate caller-owned output and are not used by the
reserved endpoint.

## Reliable dependency and endpoint assembly

The integrator-frozen actual dependency is
`Reliable::new_duplex_reserved(send, receive, context, reliable::storage::Limits)`
with `reliable::storage::Plan::for_duplex`, complete heap capacity and actual
`Reliable::storage_usage()`. Its owner is responsible for ARQ/FEC construction,
outgoing/restored slots, scratch, partial-drop and packet-time reuse. This API
is recorded by [record recovery storage](record-recovery-storage.md).

Endpoint Plan adds only its own real sender/receiver/scratch/cell capacities to
that complete dependency total. Construction consumes each checked sub-budget;
if any later reservation fails, all earlier real owners and buffers drop through
the same production cleanup path. No retained global or per-packet allocator
hook is added. Deterministic construction-local failpoints may observe the
temporary assembly guard, including actual nested-owner drop, but do not prove
dependency-internal allocator failures unless those paths are actually injected.

The send source buffer uses send ARQ original-source bytes. The receive source
buffer uses receive ARQ original-source bytes. Packed expansion is receive
max_units times receive symbol width. All products and Rust element layouts
must be checked, within `isize::MAX`, before allocation. Reservations use
fallible exact-capacity operations and verify actual capacities. Zero-sized
optional workspaces are owned empty buffers, not dummy allocations.

Reserved and allocating backings share actual enqueue/poll/receive/prepare/
commit/tick transitions. Preserve every byte, counter, source/record identity,
deadline, retry, repair and admission refusal. Handoff keeps its original age
while receiver capacity is blocked. `pending` keeps exact native bytes until
actual whole-device acceptance invokes `commit_delivery`; extraction, recovery
ACK and queue enqueue grant no native receipt.

`Receiver::pending_deadline()` reads the original deadline of the actual pending
slot, and returns `None` on failure or without pending native output. Aligned
Endpoint maps those injected milliseconds to Duration; Packed forwards exactly.
It neither mutates custody nor substitutes the general `deadline()`, which can
include earlier retransmission, source-hole, packing and handoff work. A common
Engine may min the pending-only expiry with an external original cap without
mistaking an unrelated recovery wake for native expiry.

Historical `memory_bound_bytes` scalar guards use explicitly documented
compatibility-only original header layouts to preserve prior scalar acceptance.
They are not actual new backing Usage and cannot approve a reserved budget.
The complete Plan uses actual selected headers, journals, pools and nested
owners; it can require a larger explicit capacity than the historical guard.

## Stable acceptance leaves

Every leaf remains unchecked until the integrator executes its stated tests.
The file inventory/source hashes are recorded under
`work/common-record-engine-20261114/aligned-record-storage/` before code.

- [x] [ARS-01] Freeze complete directional Plan/Usage/error/ownership and codec/Reliable dependency APIs, exact inventory, same-transition reuse and source binding before production edits. Record engineering choices distinctly from owner decisions. Evidence: [pre-edit binding](../../work/common-record-engine-20261114/aligned-record-storage/pre-edit-binding-v0.json) and [authored-source freeze](../../work/common-record-engine-20261114/aligned-record-storage/authored-source-freeze-v0.sha256); additive pending-only expiry accessors retain the authoritative owner.
- [x] [ARS-02] Implement actual fallible Aligned/Packed codec backing, including all channel/header/native/body/fragment/source-proof slots, transactional shadow/rollback/outcomes and packing buffers. Recycle provisioned buffers through repeated full-window operation and errors; preserve full existing maxima and all byte/identity/error/deadline behavior without a second decoder or packet-time infallible allocation in the selected path. Evidence: [actual first-touch journals](../../crates/l2tunnel-codec/src/aligned_receiver/storage.rs), eight focused codec storage cases and [93 passing codec cases](../../work/common-record-engine-20261114/records-attempt-1/validation.json); the [92-case no-default-feature branch](../../work/common-record-engine-20261114/codec-no-default-attempt-1/validation.json) also passes. Full allocation-observer/window inventory remains ARS-06.
- [x] [ARS-03] Compose exactly one real reserved duplex Reliable owner, one actual directional sender and receiver and endpoint workspaces. Complete Plan/Usage includes each nested capacity exactly once, validates before reservation, refuses one-byte-short budgets and exposes allocating versus reserved ownership honestly. Evidence: [actual endpoint Plan/constructor](../../crates/l2tunnel-aligned/src/storage.rs), five focused endpoint storage/delivery/differential/cleanup cases and [28 passing Aligned/Packed cases](../../work/common-record-engine-20261114/records-attempt-1/validation.json).
- [ ] [ARS-04] Exercise every local construction refusal with actual production cleanup/drop and success transfer, plus actual dependency constructor refusal and later endpoint reservation failure. Dependency-internal failpoints retain their separate evidence; local hooks must not be represented as universal allocator-failure qualification.
- [ ] [ARS-05] Differentially compare allocating and reserved ordinary/Packed endpoints on real paired exact-byte bidirectional delivery, unequal policies, contexts/fragments/early-short, repairs/retries/loss/duplicate, feedback/native pressure, original expiry and wrong scope. Preserve wire/digest/default vectors, identities, and actual native pending/commit semantics.
- [ ] [ARS-06] Prove exact observed heap/capacity/allocation inventory and stable reuse for repeated full record/source/fragment/batch/packing windows, independent byte/count limits, malformed rollback/cleanup and restoration after pressure. Do not reduce full parser, replay, record or fragment limits to make storage fit.
- [ ] [ARS-07] Consume actual reserved endpoints in the real common Engine and mixed-profile generation resource admission, including current plus prepared/draining owners and their shared external capacity. Scalar configuration or isolated constructor success does not close this integration.
- [ ] [ARS-08] Pass the integrator's affected source-stable checks and required stage acceptance with honest evidence reuse and retained failures. Full native matrices, runtime/CLI/GUI/platform acceptance, complete allocator/resource parents, all mode parity and full SW-11 remain independent gates.

## Ownership and first implementation order

The endpoint worker owns `crates/l2tunnel-aligned/` and this module document.
The FEC/Reliable worker owns those dependency crates and their resource contract.
The integrator explicitly extended this worker's ownership before edits to:
`aligned_body.rs`, `aligned_sender.rs`, `aligned_receiver.rs`, `packed.rs`,
`packed_sender.rs`, new `aligned_storage.rs` and isolated storage helpers/tests.
The integrator owns facade,
common Engine/Bank, manifests, master ledgers and every build/check/format/Git or
native execution. Existing simulator and historical observations are untouched.

First freeze the dependency interfaces and real backing representation; then
implement dependencies and codec reservation/reuse; assemble endpoint Plan and
constructor; author focused refusal/drop/reuse and real paired-delivery
differentials. The integrator ran independent affected suites after source
freeze: [255 five-package library cases](../../work/common-record-engine-20261114/records-attempt-1/validation.json),
[92 codec cases with LZ4 disabled](../../work/common-record-engine-20261114/codec-no-default-attempt-1/validation.json)
and [11 exact downstream callers](../../work/common-record-engine-20261114/downstream-attempt-1/validation.json)
pass with strict affected Clippy. The public-source batch also passes rustdoc and
format checks. These local results do not qualify the open full acceptance gates.

The authored focused evidence consists of eight codec storage tests and five
endpoint storage tests, together with pending-only expiry assertions in the
existing paired fixture. They cover constructor-local reservation failpoints,
one-byte-short budgets, real later-wrapper failure with actual dependency-owner
drop/transfer, touched rollback, full small record/source windows, malformed
final fragments, untouched history, preserved maximum configuration and actual
asymmetric/loss delivery plus legacy/reserved sender traces. Local failpoints
do not prove dependency-internal allocator refusal or universal deallocation.
The pointer multiset observes actual record/proof payload versions, not every
metadata allocation or dependency-internal buffer. Broader differential,
complete-inventory reuse, combined admission and stage checks retain the exact
unchecked acceptance leaves above until actual evidence supports them.
