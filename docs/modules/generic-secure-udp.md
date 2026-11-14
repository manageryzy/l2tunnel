# Generic transactions on the selected secure UDP transport

Status: **directional peers and canonical values protocol-tested; authenticated
client construction tested; selected generic driver integration pending**. This
workstream connects the existing generic leased management peer to actual
record engines, common protected records, stable control and physical native
completion on the selected original UDP socket. It is required work beneath
FIX-11/FIX-13, SWR-18 and full SW-11; it does not redefine their acceptance.
All47 catalog requirements, RLNC/parity/rolling/packed/proxy, every carrier,
platform, lifecycle and original80 Mbit/s performance target remain in scope.

The source-reviewed [continuation assessment](../../work/swift-native-identities-20261114/next-integration-review-attempt-1/analysis.md)
identifies missing interfaces. It is an engineering assessment, not an owner
decision. The first frozen interface below is recorded in the
[pre-edit directional contract](../../work/generic-secure-udp-20261114/directional-contract-v0.md)
and [source binding](../../work/generic-secure-udp-20261114/directional-design-binding.json).
Other interfaces remain draft until the integrator records their exact revision
before implementation. A design or public enum does not implement a mode.

## Composition and compatibility

### Verified construction checkpoint

The [required frozen-source check](../../work/generic-secure-udp-20261114/checkpoint-aggregate-attempt-1/validation.json)
passes1747 Rust cases including doctests,376 Python tooling cases and1658
simulator cases, with stable inputs. It includes the directional peer changes,
complete canonical values, immutable runtime inventory and explicit client plan,
including actual original-socket authentication on both appearances. Legacy
runtime digest goldens and existing selected behavior remain covered.

The independently tested but unintegrated Control bridge is excluded from that
checkpoint. Its three source files were archived before the check and restored
byte-exactly afterward in the same worktree, as recorded by the
[isolation receipt](../../work/generic-secure-udp-20261114/checkpoint-isolation-attempt-1/validation.json).
Its earlier [focused runtime log](../../work/generic-secure-udp-20261114/runtime-focused-attempt-1.log)
passes127 selected UDP cases, including11 bridge tests; its
[production lint failure](../../work/generic-secure-udp-20261114/runtime-clippy-attempt-1.log)
correctly records unused integration helpers. The checkpoint does not claim that
those helpers are consumed by a production driver. GSU-03..GSU-10 retain their
complete integration, resource, mode, native, platform and performance scope.

The actual engine storage review also remains a preparation prerequisite.
Sender retained-source debt is `flow_sources`, not the repair window; queue
high-water capacities persist per channel. Receiver history/equation terms,
stream growth, header scratch, shared workspaces and construction transients
must be included with old and prepared engines. Existing destructive directional
replacement cannot supply atomic fallible preparation. A separate allocation or
warmup is not a reservation of the engine's future buffers.

Keep the currently selected SwiftPolicyV1 coordinator and its authenticated
profile bytes for that selection. Add an explicitly authenticated generic
transaction selection, preserving CLI defaults and all supported existing
paths. The selection must bind the complete canonical configuration, supported
catalog, immutable resources/control/trust envelope and transaction limits.
It must not be inferred from payload shape or `streams = Some(...)`.

Use the existing leased `transaction::Peer<C>` and Transaction/Liveness/
DataFeedback message owners. Do not create another transaction FSM, native I/O
loop, cryptographic sender or fallback socket. The actual driver must select
one transaction owner for a transition. Generic control must consume the real
peer's effects and borrowed message proofs, not a mirror of their state.

The initial authenticated setup digest and the canonical management data digest
are different domains. Bind the full initial configuration and supported catalog
to authentication without hashing a catalog's anchored configurations into its
own anchor. Initialize User scope from `configuration_digest(C0)` explicitly;
retain the immutable authenticated setup scope for Control. A new constructor
must validate those actual values rather than relabeling the old digest.

The current peer supports at most64 exact canonical configuration digests.
A selected generic adapter must expose that capability accurately; it cannot
claim arbitrary policy resolution from a finite catalog. Preserve the existing
SwiftPolicyV1 resolver until its complete replacement is implemented. Canonical
encoding must include every selected mutable field and bind all immutable
fields; an omitted field or implicit local default cannot authorize switching.

## Frozen directional fence API v0

```rust
trait Configuration: Clone + Eq {
    // Existing encoding, validation and digest methods remain unchanged.
    fn channels(&self) -> u16;
    fn sender_channels(&self, sender: management::Role) -> u16 {
        self.channels()
    }
}

Peer::new_directional(identity, epoch, initial, supported, settings, now)
    -> Result<Peer<C>, transaction::Error>
Peer::new_leased_directional(identity, epoch, initial, supported, settings, lease, now)
    -> Result<Peer<C>, transaction::Error>
Peer::sender_channels(&self, sender: management::Role) -> u16
```

The new constructors have the same argument types as the existing constructors.
Client/Server are authenticated global sender roles, never local Send/Receive
halves or a role merely claimed by a packet. An immutable private per-peer
selection chooses the legacy single-width or explicit global-sender contract.
Existing `new`/`new_leased` continue using `channels()` even if a new C overrides
the added query; their bytes, error ordering and behavior remain unchanged.

Validate each explicit sender width in1..=256 for initial, catalog and proposed
configurations. The generic maximum stays256; packed255 and Swift64 remain
actual selected-profile constraints. Do not pad both vectors to their maximum
width or shrink the generic limit to Swift's capability. The canonical C must
encode both global widths; a trait query alone does not authenticate them.

Local `staged` validates the old active configuration's local global-sender
width. PREPARE, READY and first leased PREPARE preflight validate the old remote
sender width. Centralize that rule across effectful and immutable checks.
Retained local/peer vectors remain independently exact; `confirm_drained` must
not compare them to one another. Cached old requests and terminal proofs retain
their exact original bytes, scope and cap after target widths change.

Regression example: old Client2/Server3 to target Client4/Server1 must complete
through real encoded two-peer PREPARE/READY/barrier/commit/retire. Wrong role,
old-versus-target width, digest, counts, immutable lease cap and cached retries
must fail at their existing boundaries. Preserve old canonical golden vectors,
constructors, exact retry semantics, injected time and all existing tests.
These are protocol tests; physical delivery requires the runtime below.

## Frozen canonical value interface v0

The [pre-edit canonical contract](../../work/generic-secure-udp-20261114/canonical-contract-v0.md)
and [binding](../../work/generic-secure-udp-20261114/canonical-design-binding.json)
record the complete field inventory and acyclic authenticated digest graph.
Implement the pure value in `l2tunnel::swift_configuration`, which already
composes Swift and management without runtime dependencies. Its actual
authenticated envelope/client/driver consumer remains required by GSU-03.

```rust
EnvelopeDigest::new(bytes: [u8; 32]) -> EnvelopeDigest
EnvelopeDigest::as_bytes(&self) -> &[u8; 32]
Descriptor::new(path_mtu: usize, forward: policy::Direction, reverse: policy::Direction)
    -> Result<Descriptor, Error>
Descriptor::{path_mtu,forward,reverse}(&self) -> ...
Descriptor::direction(&self, sender: management::Role) -> policy::Direction
Configuration::new(envelope: EnvelopeDigest, descriptor: Descriptor)
    -> Result<Configuration, Error>
Configuration::{envelope,descriptor}(&self) -> ...
Catalog::new(initial: Descriptor, supported: &[Descriptor]) -> Result<Catalog, Error>
Catalog::{initial,descriptors,root}(&self) -> ...
Catalog::configurations(&self, envelope: EnvelopeDigest) -> Vec<Configuration>
```

Keep fields private and values checked; EnvelopeDigest is a typed label, not
authentication evidence. The management Configuration implementation uses
`ENCODED_LEN=304` and domain `l2tunnel/swift-transaction-config/v1\0`.
Explicit eight-byte prefix is `L2TC`, version1, Swift tag1, full-duplex tag1,
reserved0. It precedes envelope32, path-MTU BEu64, then forward and reverse
directions, each sixteen BEu64 fields in the saved contract's exact order.
Decode checks every length, tag, reserved value, scalar and integer conversion.
Both original native layers and maxima must agree; session/cover geometry
and envelope authority remain actual adapter checks, not pure parser claims.

The anchor-free descriptor is the same bytes with envelope32 omitted (272B).
Catalog holds1..=64 validated descriptors, sorts those complete bytes, rejects
duplicates and requires exact initial membership. Its SHA256 root hashes
`l2tunnel/swift-transaction-catalog/v1\0`, count BEu16 and sorted bytes, using
maintained ring. No anchored C participates in its own catalog hash. Either
direction mutation changes C's existing management digest. Legacy24-byte mode
configuration, policy grammar and selected runtime defaults stay unchanged.

The pure codec/catalog tests do not establish H0/D0 authentication, preparation
memory admission, runtime selection or full GSU-03. Those remain mandatory and
use this exact canonical value, not an abbreviated or inferred policy.

The explicit client plan now constructs the acyclic envelope/C0/D0/application/H0
graph. Focused actual factories authenticate that selection over both original
UDP appearances, including asymmetric directions and a User digest distinct
from H0. This is authentication/construction evidence; the existing driver still
uses its retained SwiftPolicyV1 scope/owner and does not consume the generic plan.
Before construction, check the actual Client PREPARE and Server READY envelope
maxima separately, including the mandatory eight-byte management response-to
prefix. Use the actual whole-message owner to admit original plus fragment
storage for that maximum; a positive scalar byte budget alone is insufficient.
Regressions derive capacity from real encoded peers/envelopes and actual message
submissions, rather than duplicating the production size formula.

## Runtime envelope inventory revision1

`transport::Config::immutable_contract_digest(&self) -> io::Result<ConfigDigest>`
uses the same validated canonical field inventory as `canonical_digest`, with a
distinct domain and explicit mutable-field classification. Preserve the existing
canonical digest bytes exactly. Normalize channels, rates, algorithm/timer/queue
fields and active/derived path MTU; retain the immutable native layer, maximum
original packet and its encoded maximum, along with all fixed control/security/
work/native/lease/burst settings. This refines the candidate's whole-direction
mask: physical constraints repeated in C stay immutable. Reporting stays local.
The complete client envelope additionally binds the real connection, carrier,
trust, catalog, new preparation limits and selection, rather than treating this
local runtime digest as the full authentication contract.

## Frozen control-owner bridge interface v0

### Authenticated client plan interface v0

The new explicit `secure_udp::transaction_profile::Profile` is a complete
authenticated construction plan, separate from the retained SwiftPolicyV1
`profile::Profile`. Its constructor takes the real `ConnectionConfig`, original
`Settings`, pinned `establish::Peers`, complementary role runtime templates,
the exact `swift_configuration::Catalog` and explicit `Parameters`.
Parameters bind generic transaction timing, the maximum original operation in
milliseconds, and the combined retained-byte ceiling required by the eventual
prepared/current/draining adapter. A validated plan alone is not allocation,
driver admission or native readiness; the driver must enforce that ceiling
before allocating or accepting PREPARE.

The envelope hashes the original complete Settings configuration with its
unmodified application seed, native connection digest/exact setup duration,
both normalized role inventories, catalog root and every parameter. It never
hashes the subsequently derived application or H0. Construct C0 from that E and
the exact catalog initial value, derive D0 with the real management codec, then
derive a distinct selected application from seed/E/K/D0. Authentication through
the existing real factories binds the resulting H0. `configuration()` uses the
constructor's retained pins; `runtime_for(C, role)` admits only matching E and an
exact supported descriptor, revalidating actual native/cover geometry. This
supports asymmetric widths/windows, exact odd rates and rational repairs without
legacy Policy rounding. It does not silently enable a runtime or CLI backend.

The [pre-edit control bridge](../../work/generic-secure-udp-20261114/control-bridge-contract-v0.md)
and [binding](../../work/generic-secure-udp-20261114/control-bridge-design-binding.json)
record lifetime, dispatch, proof and retry invariants. Keep Owner nongeneric;
borrow the driver's actual Peer only for joint dispatch and proof callbacks.
Add explicit crate-local `Owner::new_leased` with required streamed settings,
without changing `Owner::new`, legacy or SwiftPolicyV1 behavior. Only this
selection constructs a transaction-bound Gate and routes Management.

```rust
Owner::dispatch_transaction<C>(&mut self, peer: &mut Peer<C>, now: Duration,
    cap: Tick, effect: &mut Option<PendingEffect<C>>) -> io::Result<DispatchProgress>
Owner::with_accepted<R>(&mut self, incoming: Incoming, now: Duration,
    finish: impl for<'p> FnOnce(&Accepted<'p>) -> io::Result<R>)
    -> io::Result<Attempt<R>>
Owner::with_confirmed<R>(&mut self, token: Token, now: Duration,
    finish: impl for<'p> FnOnce(&Confirmed<'p>) -> io::Result<R>)
    -> io::Result<Attempt<R>>
Owner::freeze_transaction<C>(&mut self, peer: &Peer<C>, command: &[u8],
    now: Duration) -> io::Result<FrozenOutput>
Owner::submit_frozen(&mut self, output: &mut FrozenOutput, now: Duration)
    -> io::Result<Attempt<Token>>
```

PendingEffect owns the exact incoming envelope and actual Effects, retained
without semantic redispatch. FrozenOutput owns the exact original Management
envelope, actual peer operation/context, candidate submission, immutable message
expiry and eventual token. Its fields are private except checked getters.
Reserve one candidate Transaction submission until accepted or explicitly
cancelled under its original authority; failed admission burns no sequence.
Liveness uses its independent sequence. All byte copies are bounded by the
actual selected settings and accounted alongside underlying message storage.

Acceptance backpressure preserves dispatched custody. Actual acceptance removes
the message owner's complete buffer, so the driver retains disjoint immutable
envelope bytes through the synchronous real-proof callback. Callback failure is
terminal and cannot retry acceptance. Mark confirmed output only from the actual
Owner confirmation proof; fulfilled deadlines no longer cause message timeout,
while original operation/session expiry remains enforced. A retained confirmed
logical key suppresses repeated Peer output without a new envelope or deadline.
Superseded tokens retire only after genuine confirmation. The driver must
reserve bounded effect/work/current/cache/predecessor custody before mutation;
this Owner bridge alone does not implement its lifecycle or logical ledger.

Exact generic data-scope retirement is separate from legacy Swift retirement;
only actual leased cached/terminal origin authority permits retained final
control output. No old User, generic feedback or receipt authority is invented.
Focused tests use actual message owners, joint Gate/Peer and borrowed proofs
under pressure, expiry and Liveness scratch reuse. Selected driver and native
integration remain mandatory parts of GSU-04/GSU-06, not inferred from helpers.

## Whole-message and physical custody

Reserve bounded semantic effect, response and staging custody before calling
the joint `Gate::receive_transaction` path. Ordinary `Gate::admit` cannot commit
the stream sequence first. Semantic backpressure must retain one exact incoming
ticket and effects without redispatch. Pass actual borrowed Accepted/Confirmed
proofs with exact retained envelope bytes to the leased peer before retiring
message metadata. A boolean, source ACK, local socket write, Idle phase or
Retired event is not a whole-message proof.

Coalesce repeated logical output under one retained exact envelope/submission
and original absolute expiry. Fresh retry packet numbers must not create
independently expiring copies. Exact old-origin final replies retain only the
leased retry authority; they cannot reopen an old User reader. Keep Liveness
independent through blocked Transaction service, under the shared byte/packet
allowance and existing reserve. All time conversions retain the original cap.

Stage real bounded target engines/readers, stop old native admission, then freeze
the old admitted vector. Account for combined old/prepared/draining resources;
per-engine bounds alone do not bound a multi-epoch adapter. Original packet
origin, channel, identity, bytes and age stay with FIFO custody through pressure.

On Drain, require exact local admitted counts and drained send recovery; require
physical-written counts exactly equal the authenticated peer vector, extracted
equal written, empty native FIFO and no partial receive/source debt. Deficits
wait within the original cap; exceeding a fence fails. Only those facts permit
the real `Peer::confirm_drained`. Source receipt and pure extraction never prove
a device write. Existing PREPARE/READY vectors can carry these boundaries.

Route current/staged/draining data by the actual peer reader and C. Staged data
cannot reach the device before local commit. Commit activates only the exact
prepared configuration while retaining old drain-only custody; retirement
removes only the permitted old reader. Final message custody survives data
retirement until the actual borrowed proof releases the operation. Reject,
precommit abort, uncertain commit and failed-session recovery remain distinct.

Generic DataFeedback and NativeReceipt are separate required dispatch interfaces.
Swift's current protected User feedback remains identified by its real engine
and full security numbers; do not relabel it as another recovery protocol.
Native receipts attest actual physical facts with bounded deduplication and
original scope. Reusing PREPARE/READY fences does not complete those interfaces.

## Ownership and acceptance

The integrator owns this ledger, shared interface agreement, facade/client/driver
integration, formatting, Cargo, tests, builds, native execution and Git. One
worker owns the directional Configuration/Peer/lease files and isolated tests;
other workers design the complete configuration and control-proof bridges until
their interfaces are recorded and exclusive source ownership is assigned.
No worker runs Cargo or edits another worker's files.

- [x] [GSU-01] Record the directional fence interface, exact old-source binding, compatibility/error/custody rules and discriminating regression plan before production edits. Evidence: [frozen contract](../../work/generic-secure-udp-20261114/directional-contract-v0.md) and [pre-edit source binding](../../work/generic-secure-udp-20261114/directional-design-binding.json). This is integrator engineering agreement, not an owner decision or runtime implementation.
- [x] [GSU-02] Implement and protocol-test explicit global-sender fence widths through real unleased/leased peer transactions, malformed first-command preflight, cached retries, old constructor/byte compatibility and generic256/packed255 limits. Evidence: [management source/tests](../../crates/l2tunnel-management/src/transaction/mod.rs) and [source-stable focused pure check](../../work/generic-secure-udp-20261114/pure-focused-attempt-1/validation.json),104 management cases including20 new directional cases; [strict pure Clippy](../../work/generic-secure-udp-20261114/pure-clippy-attempt-1.log) passed. These are injected-time protocol tests, not selected-driver or physical-fence acceptance.
- [ ] [GSU-03] Implement the complete role-independent canonical configuration, immutable resources/trust/control/catalog binding, explicit authenticated selection and initial setup/data digest bridge without self-reference or omitted mutable fields.
- [ ] [GSU-04] Integrate joint transaction dispatch and real borrowed whole-message acceptance/confirmation proofs, bounded semantic effect custody, logical retry coalescing and original absolute caps while independent Liveness progresses.
- [ ] [GSU-05] Integrate actual prepared/current/draining record owners, bounded combined resources, stopped admission, original identities, physical fence equality, commit and retirement without resetting security state or fabricating delivery.
- [ ] [GSU-06] Exercise the actual selected original-socket driver with exact native bytes, asymmetric widths, protected loss/reorder, pressure, staged arrival, old feedback, lost final receipts, cancellation/expiry and liveness during blocked management.
- [ ] [GSU-07] Integrate the shared authenticated client/service API and observable requested/effective selection, catalog/configuration and limitations; preserve existing frontend behavior and full CLI/GUI requirements.
- [ ] [GSU-08] Pass focused regressions, strict formatting/lint/rustdoc and required frozen-source workspace checks; reconcile evidence and save an actual scoped local checkpoint.
- [ ] [GSU-09] Record immutable selected Linux native functional/performance observations with the original targets and preserved failed/unavailable outcomes; qualify other platforms and devices only with their actual evidence.
- [ ] [GSU-10] Integrate and test actual Swift-to-other-profile switching, reliable/packed/RLNC/parity/rolling/proxy engines and complete typed feedback/native receipts with matching security, channel and custody semantics; retain every full SW-11 and47-mode gate until its complete acceptance passes.
