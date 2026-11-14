# Generic transactions on the selected secure UDP transport

Status: **generic Swift transactions and explicit shared service/APIv3 selection
implemented and finite local Unix integration-tested; CLI and complete resource,
fault, profile, native and platform qualification remain open**. This
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

## Current explicit runtime checkpoint

The current [source-stable functionality check](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json)
passes the new shared service/strict status/atomic-admission tests, all eleven
selected Generic cases,42 control cases, both legacy fairness cases,25 recovery
and126 management cases, with strict all-target/all-feature Clippy. The module
ledgers below distinguish full completed leaves from partial fault/resource
requirements. Required aggregate verification passes with the scoped evidence below.

The preceding runtime-library [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json) passes
119 selected transport/component cases, 16 client handoff cases and 121 management
cases, with strict all-target/all-feature Clippy. Its separately reported six
Generic and two legacy fairness cases are subsets of the 119, not extra cases.
The [required source-stable workspace check](../../work/generic-driver-20261114/driver-aggregate-attempt-1/validation.json)
also passes1878 Rust cases including doctests,376 tooling cases and1658 simulator
cases. It includes full workspace format/strict Clippy/Rust tests, codec feature
checks, strict rustdoc, CLI/tool validation and the real simulator/KCP suite.
These are local Linux checks; no privileged lab, remote CI, Windows/Android
native execution or current-source performance result is implied.

The actual public `run_transaction` uses the same sole I/O loop, original
connected socket and Records owner, fixed Control H0 and true canonical User D0.
Its complete-C channel and separate snapshot preserve requested/current values,
actual operation, physical scope, capacities and incomplete resource status.

Both covers pass real Noise/member construction, H0/D0/socket/role/cover/deadline
checks, nonzero native-device/AEAD/UDP traffic on every old/new channel through
2/3→4/1→2/3, liveness and public readiness/cancellation. Physical native writes
at cap−1/cap/cap+1 and successful I/O crossing the exact original cap preserve
irreversible facts without false promotion or duplicate output. Fourteen State
cases include real whole-message pressure, immutable caps, interrupted work,
nonzero fences, cached final retries and callback failure; those component facts
are distinct from the Driver's clean same-socket integration.

Original failed attempts remain saved: incomplete workspace migration, legacy
stack overflow, scripted readiness timeout and strict-lint failures. The owner
never approved a scope reduction. Generic-only State backing is now fallibly
reserved; the sole async loop returns final snapshots rather than Driver through
nested wrappers. Legacy fairness passes without larger stacks or changed limits.

This has explicit runtime-library and shared Prepared/service/APIv3 entry points.
The [service ledger](generic-client-service.md) records actual paired-owner and
IPC status/switch evidence plus remaining full IPC/failure cases. CLI generic
selection, complete Driver loss/reorder/final-proof-pressure qualification,
complete management/Peer reservation, other record profiles/full SW-11,
OpenVPN/raw-HTTPS migration, recovery/fresh-DH, Windows/Android and all47 complete
parity gates remain open. No current-source native/performance run is inferred;
the original80 Mbit/s target is unchanged. Historical checkpoints below retain
their original inputs and isolation boundaries.

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
Its additive fallible owner is tracked in [Swift storage](swift-storage.md),
SRS-01..SRS-07; pure allocation tests do not complete GSU-05.
The [read-only preparation interface](transaction-preparation.md), MPR-01..MPR-05,
connects actual engine preparation before leased Peer/joint admission; it does
not itself implement the selected driver.
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

## Borrowed first-PREPARE view v0

Before any target allocation, the real leased Control owner supplies:

```rust
Owner::preview_transaction<C>(&self, peer: &transaction::Peer<C>,
    now: Duration, cap: transaction::Tick)
    -> io::Result<Option<PendingTransaction<'_, C>>>
PendingTransaction::{incoming,envelope,deadline,preparation}(&self) -> ...
PendingTransaction::into_preparation(self) -> Option<transaction::Preparation<C>>
```

The view has private construction and borrows the actual Transaction message
owner without copying/popping its bytes. It exposes the exact existing Incoming,
original message deadline, complete envelope and optional new-stage intent from
the real joint Gate preview. No view is returned while older leased incoming
effects are held. Backward time, failed/expired owner, expired original message,
or invalid joint preflight is an error without mutation, identity consumption,
new lease or sequence advancement. It grants no acceptance/authentication proof.
The caller freezes the operation cap once, resamples time after real allocation,
and actual dispatch revalidates. Repeated views never extend a deadline.

- [ ] [LTV-01] Freeze and implement the borrowed joint-preflight view; test real
  pending bytes, identity, invalid admission, held work and original deadlines.
- [ ] [LTV-02] Consume the view in the selected real driver with an actual prepared
  engine guard before the joint mutation. No fake resource permit is sufficient.

The existing transport's native payload owner is tracked in
[fallible native completion storage](runtime-native-storage.md), NQP-01..NQP-04.
It is a shared resource prerequisite, not completed GSU-05/SRS-07.

The private two-generation engine owner is tracked in
[owned duplex generations](runtime-engine-bank.md), EGB-01..EGB-03. Its actual
prepared allocation must precede Peer admission; it grants no commit or physical
completion authority.

## Shared transaction settings v0

Move the identical Parameters value from client transaction_profile to public
`transport::TransactionSettings`, and re-export it from the client as Parameters.
Keep its exact fields/protocol validation and authenticated hash order unchanged:
`protocol: transaction::Settings`, `max_operation_ms: u64`, `retained_bytes: usize`.
Provide `validate(self, runtime: Config) -> io::Result<()>` in runtime. This removes
a duplicate cross-layer contract; it does not select a backend or implement a
GUI/driver. Existing golden configuration bytes and call syntax must remain.

- [x] [GST-01] Share the exact settings value at the runtime boundary, preserve Evidence: [frozen focused checks](../../work/generic-driver-20261114/focused-attempt-3/validation.json).
  authenticated field order and validate both role templates with actual tests.

The borrowed view additionally uses the actual message owner's additive
`messages::Owner::check_time(&self, now: Duration) -> Result<(), messages::Error>`.
This readonly seam checks sticky failure first, backward observation, checked
relative nanosecond conversion, and the actual earliest immutable expiry (all
held/outbound/reassembly/session caps). It performs no work, expiry removal,
receipt, counter or time mutation. Preserve existing effectful observe error
ordering and behaviour; this is advisory preflight, never acceptance.

The next private State consumer is specified in
[selected generic transaction custody](runtime-transaction-state.md),
TCS-01..TCS-03. It owns the real prepared engine Bank before admission and uses
actual borrowed message proofs. This interface is an engineering contract, not
a selected implementation or owner decision.

The shared settings relocation retains the existing Parameters alias, exact
field order and validation. Root focused attempt3 passes all14 authenticated
plan cases including existing digest/field-mutation and actual-factory tests.
The selected Driver and separate version3 status now have scoped evidence above.
Full shared resources and frontend/platform acceptance are still required;
GST-01 alone is not a backend or GUI completion claim.

## Explicit runtime handoff contract v0

The actual authenticated Profile supplies a public checked runtime value,
without making runtime depend on client or inferring a backend from streams:

```rust
TransactionContract::new(expected_configuration: security::ConfigDigest,
    role: security::Role, config: transport::Config, cover: cover::Config,
    ipv6: bool, envelope: swift_configuration::EnvelopeDigest,
    catalog: swift_configuration::Catalog, settings: TransactionSettings)
    -> io::Result<TransactionContract>
TransactionContract::{expected_configuration,role,config,cover,ipv6,envelope,
    catalog,initial,data_digest,settings}(&self) -> ...
TransactionContract::resolve(&self, value: swift_configuration::Configuration)
    -> io::Result<transport::Config>
transaction_profile::Profile::runtime_contract(&self, role: security::Role)
    -> io::Result<transport::TransactionContract>
```

All fields are private. Put the runtime value in transport_contract.rs (a child
of the existing transport), and re-export TransactionContract there. Constructor
validates shared settings, exact initial descriptor/role mapping and all finite
catalog descriptors against the original immutable template digest, same native
format, streams, cover/IP/body/MTU geometry. Resolve admits only exact complete
values under E/catalog, updating both directions, active MTU and derived stream
MTUs without changing any immutable field. D0 is the real management digest of
C0, and H0 is retained separately. No reconstruction of the full client H0 hash
graph is claimed in runtime: the real Profile recomputes it from its retained
complete settings/pins at handoff. Actual Driver must still verify H0, role,
cover, IP family, binding, endpoints and original setup deadline against Parts.
No crypto root, OS handle, clock, device, backend fallback or allocation permit
is constructed here. Catalog validation does not reserve engines/control/native
storage. Existing hash fields/order, Profile calls, defaults and v1/v2 bytes stay.

- [x] [GHC-01] Implement the checked runtime handoff and real Profile consumer, preserving the acyclic H0/E/catalog/C0/D0 graph and exact legacy values. Evidence: [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json). Full parent qualification remains open.
- [x] [GHC-02] Test both roles/covers, asymmetric complete values, catalog/native/geometry/envelope refusals and actual original-socket factory handoff; run strict required checks. Evidence: [required source-stable check](../../work/generic-driver-20261114/driver-aggregate-attempt-1/validation.json) and the focused receipt above.
- [ ] [GHC-03] Consume the contract in the explicit selected Driver before any legacy allocation and verify actual Parts/resource/readiness boundaries.

## Fixed runtime byte buffers v0

Shared byte backing is a real preparation dependency, distinct from engine
and logical message retention. Add private `transport_buffers.rs` with checked
fallible constructors and exact retained-layout observation:

```rust
Buffers::new(wire: usize, secure_packet: usize, plain: usize,
    control_packet: usize, control_message: usize, frame: usize) -> io::Result<Buffers>
// pub(super) Vec<u8> fields: wire, seal, open, plain, control_wire, control_input, frame
Buffers::capacity_bytes(&self) -> usize
Inputs::new(native: usize, datagram: usize) -> io::Result<Inputs>
// pub(super) Vec<u8> fields: native, datagram
Inputs::capacity_bytes(&self) -> usize
```

Use checked Layout arrays/sums, try_reserve_exact, reject zero/overflow before
allocation; charge all buffers, including empty frame capacity and duplicate
seal/open scratch. Initialize every workspace to its required length except
frame, which starts empty. Failures drop all partial allocations and publish
no owner. No grow/replace API is introduced. Test every actual allocation
failure index through private constructor injection and exact retained layouts.
Root must still split borrowed Buffer fields correctly and account for these
actual owners alongside native/engine/control/Peer custody before qualification.
This module alone does not reserve all management internals or complete GSU-05.

The actual runtime Counters report `workspace_capacity_bytes` from the seven
owned Buffers and `loop_input_capacity_bytes` from the two owned Inputs. Fill
both observations before the final readiness clock sample. These are retained
byte capacities, not a claim that all Driver/control resources are reserved.
Strict client status v1/v2 layouts remain unchanged.

- [x] [RBF-01] Implement real fallible seven-workspace/two-input allocation and exact requested layout accounting; cover all constructor failure positions. Evidence: [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json). Full parent qualification remains open.
- [x] [RBF-02] Consume the actual owners in the existing I/O loop before its final readiness clock sample, preserving all bytes, quotas and original deadlines. Evidence: [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json). Full parent qualification remains open.
- [ ] [RBF-03] Validate exact combined-owner accounting in the selected generic driver; retain complete GSU-05/SRS-07 and every native/performance gate.

### Actual sole-loop input charge v0

The generic constructor now allocates the real
two-buffer `Inputs` owner before constructing its Bank. Include its observed
capacity in the existing known external subtotal alongside the actual Driver,
State (subtracting Set's already charged inline layout), native pool and seven
workspaces. Retain `Option<Inputs>` in Driver until the sole I/O loop takes that
same owner; a generic missing owner is an explicit invariant error, with no fresh
allocation fallback. The legacy constructor retains its existing later allocation
and ordering. The actual counter is populated from the retained owner, and the
loop transfers it before its original final readiness deadline sample.
Charge the moved live-loop `Inputs` header separately as well: Driver retains
its now-empty Option slot after that move. Other loop/future/stack headers are
not yet a complete reserved-owner qualification.

This closes only a known omitted input charge. It does not reserve management
message/reassembly/Peer/catalog/tail/report resources, claim RSS accounting, or
change `resource_preallocation_complete = false`. Test actual constructor budget
acceptance/refusal and capacity/ownership conservation; preserve every RBF-03,
GSU-05/SRS-07 and native/performance definition.
External owners are still allocated before the final combined Bank admission;
the sound final subtotal is not pre-allocation enforcement of the complete
construction peak. That broader admission requirement remains open.

- [x] [RBF-04] Preallocate and charge the actual generic sole-loop Inputs in the Bank's known subtotal, moving the same owner into the original loop without reallocating or changing legacy behavior. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [x] [RBF-05] Verify exact actual constructor budget boundaries, moved input ownership/capacity and unchanged original readiness/deadline behavior under focused and required workspace checks. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-aggregate-attempt-2/validation.json); broader parent gates remain open.

## Single data/control owner in the existing loop v0

The [source-pinned selected-driver draft](../../work/generic-driver-20261114/selected-driver-integration-v0.md)
identifies actual consumers and authority/borrow constraints. The next additive
refactor introduces private `transport_owner.rs`:

```rust
struct Legacy { engine: records::Engine, coordinator: policy::Coordinator }
enum DataOwner { Legacy(Legacy), Generic(ReservedState) }
ReservedState::new(state: transactions::State) -> io::Result<ReservedState>
enum Entry<'a> { Legacy(&'a mut records::Engine), Reserved(storage::Entry<'a>) }
DataOwner::legacy(&self) -> io::Result<&Legacy>
DataOwner::legacy_mut(&mut self) -> io::Result<&mut Legacy>
DataOwner::engine(&self, epoch: core::Epoch) -> io::Result<&records::Engine>
DataOwner::entry(&mut self, epoch: core::Epoch) -> io::Result<Entry<'_>>
```

Legacy fields are accessible only to the parent, and no Generic constructor
allocates a legacy Engine or Coordinator. The first inline Generic(State)
implementation caused a real legacy fairness test to overflow its default stack
(integrated attempt 2); its exact stack attribution is not yet measured. Revise
this private ownership contract to a fallible exact one-element Vec<State> cell
for Generic only, retaining Legacy inline. The private cell publishes only after
Layout validation, try_reserve_exact(1), exact capacity validation and insertion;
it exposes no vector mutation or extraction. Its immutable length-one invariant
allows private State forwarding and is unrelated to peer input. Account the
actual State backing layout plus Driver inline, subtracting embedded Set once.
No infallible Box or larger test stack may stand in for this ownership repair.
The shared async loop returns only its typed final snapshot, never Driver itself;
the legacy stack failure continued in focused attempt 4 while the complete owner
was still returned through nested wrapper futures. The sole loop retains its owner.
A narrowly explained large-enum lint exception remains permitted for the inline
Legacy variant. No unused-code lint suppression is permitted. Legacy epoch lookup preserves the existing single-engine
directional-scope policy; Generic delegates only to its actual State/Bank.

Entry forwards the actual offer_identified/poll/accept/pop_identified operations
with exact types, without Deref/DerefMut, replacements, Engine extraction or
configuration mutation. A borrowed output stays tied to the live Entry until
its immediate copy/seal; no payload Vec copy is added for the borrow checker.

Replace the actual Driver's two ownership fields with DataOwner, keeping the
existing run/run_clock APIs and exact legacy behavior. Legacy hooks receive
only that actual Legacy engine/coordinator, never the reserved Entry. Change
the private legacy snapshot accessor to io::Result if needed for explicit
wrong-selection errors; do not fabricate legacy policy fields for Generic.
Adapt existing fixtures to real legacy access and preserve every assertion.
The unchanged legacy constructor selects Legacy; the additive explicit generic
constructor selects the actual reserved State. Construction and clean same-socket
integration do not imply complete fault/resource/API/profile qualification.

- [x] [DOW-01] Refactor actual existing Driver ownership and restricted Entry access while preserving its public/default/wire behavior and finite original fixtures. Evidence: [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json). Full parent qualification remains open.
- [ ] [DOW-02] Construct and consume the authenticated Generic variant in that same I/O loop, with one crypto number/seed owner and actual epoch/disposition/native barriers.
- [ ] [DOW-03] Run strict required checks and original-socket/native/API validation on the complete selected path; keep full SW-11/resource/profile/platform/performance scope.

## Explicit generic session integration v0

The selected Driver draft above is an engineering contract, not an owner scope
change. Add a public `run_transaction` beside the unchanged legacy `run` API,
using `TransactionContract`, a complete-Configuration request channel and a
separate `TransactionSnapshot`/`TransactionStopped` result. Both wrappers enter
one selected I/O loop. Generic status reports actual Peer phase/epoch/config,
physically installed data scope, actual Bank usage, common security counters
and fixed byte-buffer capacities; legacy policy fields are never fabricated.

The generic constructor consumes the original authenticated Parts exactly once,
validates H0/role/cover/IP/session/socket/setup deadline, creates one Records
owner with fixed Control H0 and initial User D0, one leased Control owner and the
actual Bank/State. It constructs no legacy Engine/Coordinator. A resource
observation must explicitly distinguish actually charged native/buffer backing
from management/Peer allocations that are not yet fully preallocated; functional
integration cannot close GSU-05/SRS-07 on that subtotal.

An outcome-held server may jointly dispatch only the exact actual cached final
request under the same retained operation and original cap, with no Preparation.
Its byte-identical coalesced current reply needs no additional output slot. This
exception never admits a new operation, Barrier or Commit and cannot allocate
another Bank. Actual final acceptance/confirmation still controls release.

The shared expiry-only guard also observes the actual State retained operation
deadline and any retained outcome cap before/after physical native I/O. It keeps
lease, liveness and native-stall precedence, and does not run a protocol FSM
inside a synchronous native write. An unadmitted queued-request cap remains a
request refusal rather than session-terminal authority.

One bounded parent outcome retains the actual State outcome until the matching
leased Peer operation is released by real whole-message proofs; only then may
a local switch call report success. New admission waits for that custody.

One parent-owned Action retains its exact operation and applied physical work
across Blocked completions. Stage registers the exact reader and freezes the
old admitted fence. Drain requires old Engine send/receive drain, exact local
admission and peer extraction fences, empty old native queue and identical
physical NativeWritten fence. Committed promotes Records, exact local config
and NativeWritten only after that barrier. Retired removes the actual old
reader and Bank. Aborted cancels only a nonpromoted reader. Uncertain never
rolls back. The physical native write completion ordering stays unchanged.

Expose `Peer::peer_fence(&self) -> Option<&transaction::Fence>` as a read-only
borrow of actual pending peer counts; no packet reparse or mirrored fence grants
authority. Check this known fence before native enqueue even during Stage.
Actual target preparation is admitted only at the sole loop clock seam, sampling
again after Bank allocation; ordinary progress does not allocate another Bank.

`Owner::ready_nontransaction()` observes actual eligible Liveness and data-profile
messages without treating retained Transaction input as immediately dispatchable.
It is read-only and leaves Transaction custody with joint State/Owner admission.

Generic ingress checks the real Peer reader, exact C digest and actual Bank
before accepting current/staged/draining data. Staged data cannot be extracted
before local commit; draining data cannot be redelivered. Service both actual
generations with the common wire bucket, fixed Control reserve, global User
record numbers and immediate borrowed seal. Old recovery remains enabled while
new native admission is stopped. Original local request caps survive retries.

- [x] [GDI-01] Construct and explicitly select the real generic owner in the same I/O loop, retaining exact legacy behavior and separate honest status. Evidence: [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json). Full parent qualification remains open.
- [ ] [GDI-02] Apply actual lifecycle actions with independent physical native fences, old/new reader routing and fixed original caps; exercise failure and pressure paths.
- [ ] [GDI-03] Verify actual same-socket sessions, loss/reorder recovery, liveness during switch and at least two nonzero switches; preserve all broader functionality/resource/performance gates.

The [fault contract and GDF-01..GDF-09](generic-driver-faults.md) retain six
distinct actual-driver fault rows and public-loop qualification. The
[shared client/service contract and GCS-01..GCS-09](generic-client-service.md)
track implemented explicit Prepared/APIv3 selection through the existing actor
and its remaining IPC/failure/frontend gates. The
[reserved management recovery ledger](control-recovery-storage.md) tracks actual
three-stream backing and its incomplete resource proof. These engineering
contracts and scoped implementations record no owner scope decision and reduce
no parent requirement.

## Functionality checkpoint validation

The [required source-stable aggregate](../../work/generic-driver-20261114/functionality-aggregate-attempt-2/validation.json) passes1919 Rust
cases including doctests,376 tooling cases and1658 simulator cases, with workspace
formatting, strict Clippy and strict rustdoc. Its inputs remained unchanged during
the check. Final documentation edits record only evidence and scoped task status.
Earlier failed attempts and the exact pre-fix negative control remain preserved.
This is local Linux validation, with no new privileged/native performance, remote
CI, Windows/Android device or GUI qualification. Every still-open task retains
its complete acceptance definition.
