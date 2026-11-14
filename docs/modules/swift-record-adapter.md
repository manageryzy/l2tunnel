# Swift admission and emission adapter prerequisites

Status: **implemented and protocol-tested, with finite affected runtime/service checks**.
This leaf prepares the existing pure Swift engine for the common record-profile
composition. It does not implement cross-profile switching, replace any requested
algorithm or select another default. Full SW-11, all47 parity gates, RLNC, parity,
rolling, packed and proxy retain their existing acceptance definitions.

Read the [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[mode parity](../mode-parity.md), [existing record engine](swift-record-engine.md)
and [generic runtime](generic-secure-udp.md) together. Root owns this leaf's
production/test files and shared runtime integration. Other workers own
directional Aligned/Packed endpoints, fresh-DH design and wrapper storage.

## Existing implementation and required behavior

`records::Engine::offer_identified` currently chooses a stateless hash channel
inside Swift. A common MUX-selected channel must instead reach the same actual
per-channel sender, header compressor, shared packing-byte admission and native
identity allocator. Add a checked explicit-channel entry point; do not instantiate
another MUX or silently reduce a common256-channel request modulo Swift's64.
Swift's existing accepted width remains1..64, with explicit capability rejection
for a channel absent in its installed sending direction.

The sole UDP driver currently inspects the first emitted byte to classify Swift
feedback for scope selection and wire counters. Return typed emission metadata
from the algorithm's actual producing branch instead. The same body bytes,
external security packet number/GF seed, feedback priority, retransmission order,
pacing quota and native custody remain unchanged. Incoming bytes still pass the
existing authenticated parser; an emission kind is not authentication authority.

## Additive pure interfaces

```rust
// l2tunnel_swift::records
enum EmissionKind { Source, Repair, Feedback }
struct Emission<'a> { /* private kind and borrowed exact body */ }
impl<'a> Emission<'a> {
    fn kind(self) -> EmissionKind;
    fn body(self) -> &'a [u8];
}
Engine::offer_on_channel_identified(
    &mut self, now: u64, channel: ChannelId, packet: &[u8],
) -> Result<IdentifiedAdmission, Error>;
Engine::poll_emission(
    &mut self, now: u64, number: RecordNumber, allow_data: bool,
) -> Result<Option<Emission<'_>>, Error>;
```

These are public documented methods/types using existing pure types, not OS,
runtime, privilege, clock or cryptographic interfaces. `Emission` is Copy with
private construction. Add the same operations to the existing restricted
`storage::Entry`; no mutable Engine/backing escape or second storage owner.

The explicit channel is checked against the actual send width before mutation.
An absent channel is existing `Error::Configuration`, with no drop statistic,
identity, header-context, timer or queue change. Valid-channel packet-size/Full
refusal preserves existing precedence and native_dropped accounting. Accepted
packets use the same admission/counter/compression/queue implementation as the
legacy classified path. Preflight every existing counter before context mutation.
Do not treat an invariant failure after retention as retryable Full.

Existing `offer`/`offer_identified` preserve their signatures, classification,
bytes and errors through the same common private admission helper. Existing
`poll` preserves its borrowed-byte signature through the same emitting path.
At the existing Sender producing branches, a private typed poll result identifies
original/retransmitted Source versus Repair without decoding a just-produced
wire byte. Feedback is selected by the existing receiver-feedback branch.
Do not add retained payload copies, queues, counters, allocations or time reads.

The original-socket driver's private Entry dispatch uses `poll_emission` in both
legacy-policy and explicit generic paths. Select feedback scope and WireKind from
the typed kind, then seal the exact borrowed body with the same inspected next
security number. Keep WouldBlock custody, data-reader restrictions, all work and
wire quotas and original deadlines. This selection alone does not install a
common MUX or another record profile in the runtime.

## Meaningful affected verification

Use actual engines/storage, not fabricated accepted flags. Explicitly force a
valid channel different from the legacy hash, carry real bytes and obtain that
channel's real receive identity. Check asymmetric send-width rejection, independent
channel header contexts, shared queue pressure, exact size and nonwrapping identity
refusal without mutation. Private seeding is limited to unreachable counter ends.

Compare classified and explicitly selected equal channels through source loss,
reordering/duplicates, real feedback, retransmission and repair. Compare emitted
bytes, actual kind, external numbers, received bytes, boundaries and counters.
Feedback must retain priority and remain available with data disabled. Exercise
both legacy allocation and actual reserved storage with pointer/capacity reuse.

Root runs the affected Swift library and original-socket runtime/service filters
with bounded parallelism, required affected formatting/Clippy, and reused unchanged
baseline evidence. Full stage acceptance remains distinct. Do not rerun unchanged
simulator/native/performance suites for this additive interface leaf.

The [first library run](../../work/common-foundation-20261114/swift-library-pass.json)
passes125 Swift tests with four test threads. Its inventory was captured after
execution; it makes no pre/post hash-sampling claim. Existing fixed vectors and
source review preserve the historical wire contract. The live old/new API
comparison shares the refactored producer, so it is API/storage parity rather
than an independently executed pre-change binary comparison.

## Stable tasks

- [x] [SWA-01] Freeze the checked admission/emission interfaces, same-owner behavior, unchanged limits/errors/wire, exclusive files and pre-edit source binding. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); protocol/runtime scope and reused evidence are explicit.
- [x] [SWA-02] Implement explicit-channel admission and restricted storage forwarding through the same actual queue/header/native identity owner; preserve classified wrappers and exact refusal behavior. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); protocol/runtime scope and reused evidence are explicit.
- [x] [SWA-03] Produce typed Source/Repair/Feedback metadata at actual algorithm branches, retain legacy byte APIs and preserve scheduling, seed, storage and retry semantics. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); protocol/runtime scope and reused evidence are explicit.
- [x] [SWA-04] Consume typed emissions in the actual sole UDP driver without changing packet bytes, authentication, quotas, scopes, native custody or capabilities. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); protocol/runtime scope and reused evidence are explicit.
- [x] [SWA-05] Pass the affected actual-owner/differential/boundary/storage/runtime checks and scoped source-stable verification; keep full SW-11, resources, modes, native/platform/performance gates open. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); protocol/runtime scope and reused evidence are explicit.

The typed emission path also passes214 affected original-UDP runtime cases and31
selected service cases. Strict affected Clippy/rustdoc/format checks pass. Full
stage aggregate and complete cross-profile runtime integration remain separate.
