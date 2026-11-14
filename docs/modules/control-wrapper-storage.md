# Fallible runtime control-wrapper storage

Status: **implemented with finite affected runtime/service integration checks;
required full stage acceptance remains open**. This contract covers the actual runtime Streamed wrapper around the
three existing whole-message Owners. It does not create a second control state
machine, change a wire format or record an owner decision about functionality.
The [pre-edit source binding](../../work/common-foundation-20261114/control-wrapper-storage/preedit-v0.json)
records the inspected baseline before production edits. The integrator froze the
interface and exclusive source ownership before implementation consumers began.

Read the [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[mode parity](../mode-parity.md), [complete control-message storage](control-message-storage.md)
and [known construction admission](runtime-construction-admission.md) together.
This is an additional actual-owner prerequisite beneath the existing resource
parents, not a replacement for their acceptance definitions.

## Current source and exact scope

At the pre-edit checkpoint `control::Backend::Streamed` owned `Box<Streamed>`.
That construction used infallible `Box::new`, three `Vec::with_capacity` calls for Outgoing metadata,
and two initialized byte Vecs for envelope/raw scratch. The checked
`Settings::wrapper_capacity_bytes` and actual
`Owner::wrapper_capacity_bytes` already include those requested/retained layouts
in the selected generic constructor's known external subtotal. Accounting for
that subtotal does not make these allocations fallible.

Streamed retains the real three message Owners, inline Gate/replay/scope/held
state, per-stream sequence and scheduling state, and one shared packet/byte
allowance. The Gate and held records add no independent Vec backing. Message
Owner headers are embedded in the Streamed cell and counted there once;
message heap Usage separately includes nested ARQ/reassembly once. Frozen bridge
and incoming-effect envelope copies are separate allocations outside this leaf.

The reserved path must provision the actual wrapper before publishing its
control Owner. It cannot allocate a parallel unused pool, increase a configured
limit, prune a catalog/stream, change fragment geometry, fall back to allocating
storage, or replace the actual message/recovery owners. All currently accepted
stream/message maxima and independent outgoing counts remain supported.

Existing `Owner::new`, `new_leased`, the test compatibility reserved-ARQ path,
and `new_leased_reserved_messages` retain their signatures and selection. Only
the complete reserved-message path selects the new fallible wrapper. Existing
legacy Box ownership remains explicit; no failure on the reserved path enters
it. Validation, authenticated bindings, scopes, original absolute caps,
Accepted/Confirmed meanings, leased proofs, logical retries, Liveness and shared
wire quotas remain owned by their existing algorithms.

An integrator-approved engineering refinement preserves the prior crate-private
`Settings::wrapper_capacity_bytes` and
`Owner::new_leased_reserved_messages` as `cfg(test)` compatibility helpers with
their existing signatures. After the selected production constructor consumes
the typed Plan directly, these two private helpers have only test consumers.
Production retains `wrapper_storage::Plan::new`, the additive planned constructor
and the actual Owner capacity/Usage views. No public API, wire behavior, selected
legacy backend or functionality scope changes; this is not an owner scope decision.

## Safe actual owner strategy

Use a private Streamed storage adapter with two explicit variants: existing
legacy Box backing and reserved singleton Vec backing. The reserved variant
owns one `Vec<Streamed>` with actual length and capacity exactly one. Its private
constructor reserves that cell using safe `try_reserve_exact(1)` and publishes
the completed Streamed into it only after all checked backing is provisioned.
This follows the existing safe `transport_owner::ReservedState` pattern.

Expose restricted internal `Deref`/`DerefMut` to Streamed for the existing
control methods. Do not expose the Vec, permit resizing/removal of the singleton,
retain a second Streamed copy, inflate every Driver with an inline Streamed, or
add unsafe/FFI/custom allocator code. Any extra adapter metadata is actual
inline Driver/control-owner layout, counted once by the existing outer layout
calculation. A reserved-cell allocation is the Streamed heap header charge;
there is no simultaneous Box charge for that variant.

A temporary provisioning guard owns the actual singleton cell, all three
outgoing Vecs and both scratch Vecs from their first successful reservation.
Before publication the real message Owners remain held by the actual constructor
or its captured construction closure. Every partial failure drops all actual
unpublished backing and Owners. A successful guard moves its exact backing into
the sole Streamed owner without cloning, reserving again or resetting protocol
state. Production and tests use identical actual drop statements; local test
metadata observation is the only conditional behavior.

## Private interface to freeze

Implement the new sibling `control_wrapper_storage.rs` as
`control::wrapper_storage`. These items are crate-private runtime interfaces,
not new public protocol-library or facade APIs:

```rust
pub(crate) struct Limits { pub capacity_bytes: usize }
pub(crate) struct Plan { /* exact Settings/base and checked private layouts */ }
impl Plan {
    pub(crate) fn new(selected: Settings, base: delivery::Settings)
        -> io::Result<Self>;
    pub(crate) fn capacity_bytes(&self) -> usize;
}
pub(crate) struct Usage {
    pub limit_bytes: usize,
    pub capacity_bytes: usize,
    pub allocations: usize,
}
```

Plan is allocation-free, Copy if useful, and stores enough exact Settings/base
identity to reject a plan for another construction. It checks every array Layout,
raw-header addition and aggregate addition. It performs no dummy Owner
construction. Layout geometry is not peer authentication or permission to skip
the existing actual settings/context/time validation. Keep all currently
accepted values; add no narrowed maxima or guessed profile capacities.

Within the sibling, a private provision function borrows the checked Plan, takes Limits and
supplies the three actual outgoing Vecs and initialized envelope/raw Vecs to the
parent's one-shot Streamed construction closure. The reserved singleton cell is
already provisioned when the closure is called. The callback cannot be called
on limit/layout/allocation refusal. The closure moves in the already constructed
real message Owners/Gate and existing inline state. Publishing its one result
into the reserved cell performs no new allocation.

The exact integration boundary is additive:

```rust
impl Owner {
    pub(crate) fn new_leased_reserved_messages_with_wrapper_plan(
        base: delivery::Settings,
        selected: Settings,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
        messages: [messages::storage::Limits; 3],
        wrapper: wrapper_storage::Plan,
        wrapper_limit: wrapper_storage::Limits,
    ) -> io::Result<Self>;
    pub(crate) fn wrapper_storage_usage(&self)
        -> io::Result<Option<wrapper_storage::Usage>>;
}
```

The selected constructor validates exact plan/Settings/base agreement, wrapper
limit, existing lifetime/settings/binding/gate inputs and all three existing
message plans before the first new selected controlled allocation. Preserve the
existing error ordering where applicable. Then construct the actual three
message Owners in their existing fixed order and provision/publish the actual
reserved wrapper. An allocation failure after those Owners exist drops them
before returning. The old `new_leased_reserved_messages` computes its exact Plan
and equal wrapper Limit, then delegates to this same path; it is not a second
builder. The known combined admission remains responsible for the total budget.

`Settings::wrapper_capacity_bytes` delegates to Plan. Existing
`Owner::wrapper_capacity_bytes` continues to calculate actual retained wrapper
capacity for both legacy and reserved Streamed backing. The new Usage is Some
only for a truly provisioned reserved wrapper, None for existing legacy backing,
and never accepted as allocation authority.

## Checked layouts, errors and actual Usage

For reserved backing the exact retained byte count is:

```text
actual Vec<Streamed> capacity * size_of::<Streamed>()
+ sum(actual outgoing[i] capacity * size_of::<Outgoing>(), i = 0..3)
+ actual envelope capacity * size_of::<u8>()
+ actual raw capacity * size_of::<u8>()
```

The planned cell count is one, outgoing counts are each stream's unchanged
`max_outbound_messages`, envelope count is the largest unchanged
`max_message_bytes`, and raw count is the existing checked raw-packet geometry.
Capacity is checked against the exact requested count after every actual
reservation. Valid current settings require six nonzero backing allocations;
Usage derives their actual capacities and counts, rather than copying planned
numbers. Idle scratch and free outgoing capacity remain charged. No item includes
message heap backing, bridge copies, allocator metadata or physical pages.

The new sibling may define a private typed Error with Layout, PlanMismatch,
Limit { required, limit }, Allocation and Invariant categories. The frozen
io mapping is InvalidInput for layout/overflow/plan mismatch, Other containing
the typed Limit for the new wrapper-only bound, OutOfMemory containing Allocation
for failed wrapper `try_reserve_exact`, and Other containing Invariant for an
unexpected actual capacity. The new limit is constructor-only and must not
reinterpret a protocol error. Preserve existing message/recovery errors and
their current mapping, existing validation errors, and the selected whole-budget
refusal `io::Error::other(swift::storage::Error::Budget)`. Configured bound
refusal is not evidence of OS allocator exhaustion.

Root's combined construction Plan retains the actual typed wrapper Plan, derives
its known subtotal from `capacity_bytes`, and passes that exact plan/limit to the
new constructor. After construction root compares actual reserved Usage,
compatibility actual capacity and planned capacity, then includes the actual
wrapper once in `construction::external_capacity`. The changed Driver/adapter
inline layout is counted once by the existing real layout term. Keep the full
message Usage and nested ARQ/reassembly checks without adding those nested pools
again. There is one actual Bank and no fabricated external Usage.

This preserves the known construction boundary; setup/tails/crypto and remaining
owners still precede or sit outside it. Do not claim whole construction-peak
admission from this wrapper change.

## Focused regression contract and source ownership

The resource worker exclusively owns `control.rs`, new
`control_wrapper_storage.rs`, new `control_wrapper_storage_tests.rs`, and the
additive constructor forwarding in `control_leased.rs`. Only a tiny child-module
registration in existing `control_storage_tests.rs` is additionally needed so
the new tests can reuse its actual base/selected/binding/scope/message fixtures.
Do not change those existing fixtures or their assertions. Existing
`control_tests.rs` and `control_leased_tests.rs` remain frozen compatibility
inputs unless root separately assigns a demonstrated fix.

Root owns shared `transport_construction.rs`, `transport_generic.rs`, their
aggregate tests/registration, the facade, manifests and master ledgers. The
record-adapter and fresh-DH lanes do not own these control files. Freeze the
signatures above before root's shared consumers edit. Implementation permission
for the wrapper does not include dependency reservation support below.

The focused test set must demonstrate:

- Pure Layout/overflow and mismatched-plan refusal; wrapper one-short refusal
  before allocation/callback, exact and plus-one limits constructing actual
  reserved wrapper/message Owners and matching actual Usage.
- Failure at each of the six actual wrapper reservation sites, including the
  singleton cell and final raw buffer, with successful preceding real Vecs and
  earlier actual message Owners dropped before return. Use a private
  constructor-local refusal/observation seam, no global hooks. Deterministic
  refusal at that site is distinct from naturally exhausting the system.
- Successful transfer without constructor release, no Box/legacy fallback,
  singleton immutability and actual pointer/capacity conservation through repeated
  outgoing/scratch reuse. No observer/failpoint metadata remains in Streamed or
  message owners.
- Existing actual reserved-control quotas, whole-message acceptance/confirmation,
  original leased caps, held/saturated Transaction and Liveness regressions;
  actual legacy/reserved bytes and timer behavior remain equal for the supported
  comparison trace. Wrapper reservation cannot authorize semantics for currently
  unsupported DataFeedback or record profiles.

Root runs impacted control/construction/service tests with bounded normal
parallelism after source freeze, plus strict affected checks. Isolate only
demonstrated shared-resource conflicts. Reuse unchanged wider evidence explicitly;
perform the required complete workspace check at stage acceptance, not after
every leaf repair. No performance/probe/native rerun is selected by this contract.

## Separate design: dependency-visible reservation refusal

This section is design only. It does not implement or authorize feature wiring
or alter the wrapper deliverable. The existing recovery, codec fragment and
management message Allocation helpers have `cfg(test)` local seams. Runtime
tests compile those libraries as dependencies without `cfg(test)`, so a factory
returning Err cannot prove failure inside their actual reservation sites.

A later separately frozen test-support contract can add a default-off
`reservation-test-support` feature in each relevant crate, forwarded explicitly
to dependencies and the runtime test build. Prefer crate-local borrowed Gate
interfaces with management/runtime adapters tagging component and stream; no new
dependency from codec to recovery is needed. A minimal interface is equivalent
to `before_reserve(&self, local_ordinal, Layout) -> ContinueOrRefuse` plus bounded
observation events. The caller owns each finite counter/trace. No environment,
global/thread-local allocator hook, replacement allocator, unsafe code, real
clock, OS handle or Tokio dependency enters a public protocol library.

Invoke refusal only after successful Layout/budget checks and immediately before
the actual nonzero `try_reserve_exact`. Return that component's existing typed
Allocation error. Observe actual successful pointer/capacity/layout and actual
guard drop; no hook or observer survives publication. Constructors without the
feature keep the same builder and normal behavior. Published nested components
are observed at their parent's actual drop; publication alone is not a release
event. Trace bookkeeping must be bounded before entering construction.

Actual full message construction is recovery, then reassembly, then message
outbound/arrival/source/completion backing. A later runtime matrix should refuse
the first and last nonzero reservation of each component in each later stream
(Liveness and DataFeedback): 12 bounded cross-crate rows. Retain existing
all-position local component tests. Verify the current partial component,
successful nested components and earlier whole Owners actually drop before the
collector returns, with no readiness or usable partial owner. An unrefused case
must transfer all three actual complete Owners with exact full/nested Usages.

These rows supply literal nested reservation-site refusal evidence, not natural
OS allocation exhaustion, physical reclamation or native resource qualification.
Root assesses full CRS-06 only with its unchanged all-stream admission, quota,
independent liveness and compatibility requirements. Wrapper tests alone cannot
supply the missing cross-crate evidence.

## Stable child tasks and remaining complete parents

- [x] [CWS-01] Freeze exact safe owner/interface, checked layouts/errors, failure/drop and compatibility contract, pre-edit binding and disjoint source ownership before production edits. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); finite affected scope only.
- [x] [CWS-02] Provision the actual complete-message Streamed cell, outgoing metadata and scratch fallibly with exact measured Usage, no fallback, unchanged algorithm/wire/leased behavior and complete failure-atomic publication. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); finite affected scope only.
- [x] [CWS-03] Integrate the typed wrapper Plan and actual Usage once into the selected generic construction/budget boundary, preserving every full message/nested charge and current constructor/default behavior. Evidence: [scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json); finite affected scope only.
- [ ] [CWS-04] Pass meaningful exact/one-short/overflow/mismatch, every wrapper reservation refusal, actual cleanup/transfer/reuse and unchanged control/legacy tests under scoped checks, then reconcile required stage evidence without closing broader parents.

The following definitions remain unchanged and open:

> GSU-05: Integrate actual prepared/current/draining record owners, bounded
> combined resources, stopped admission, original identities, physical fence
> equality, commit and retirement without resetting security state or
> fabricating delivery.

> SRS-07: Integrate actual storage reservations into the selected generic driver
> and leased management transaction before PREPARE/staging; qualify physical
> custody, shared external owners and original resource/native/performance
> requirements. Pure storage tests cannot close this gate or GSU-05.

> CRS-06: Select all three reserved ARQ owners in the actual generic runtime
> constructor, charge their actual aggregate once before readiness, reject
> insufficient total without catalog pruning, and test later-stream failure
> cleanup, shared quotas, independent liveness and legacy/default compatibility.

Keep `resource_preallocation_complete=false`. Incoming/frozen bridge copies,
Peer/Fence/Effects/configuration storage, catalog copies, reports/frontend owners,
bootstrap/root/tail/crypto transients, actual State cell order and full
construction peak still require their own actual ownership/admission evidence.
Kernel buffers, allocator overhead and RSS are outside requested Rust retained
layouts. Full SW-11, RLNC/parity/rolling/packed/proxy and all47 mode gates remain
in scope. No Linux native/performance/ISP, Windows or Android qualification is
inferred from this runtime-only storage leaf.

## Checkpoint evidence and focused repair

[scoped checkpoint](../../work/common-foundation-20261114/scoped-checkpoint-validation.json) composes125 Swift,216 unchanged direct protocol/message,214 original-UDP
runtime and31 selected service passes, without counting the repeated exact
regression twice. Clippy, rustdoc and formatting pass. It is not a new full
workspace, native, platform or performance pass; CWS-04 retains stage acceptance.

The first affected run exposed a stack overflow even with one test thread. The
repair borrows the large immutable wrapper Plan through the synchronous private
Storage selector and isolates selected-stream construction from the Legacy
constructor stack. It adds no heap owner, cap, test stack override or wire change.
The original failing exact test and all214 affected runtime cases pass afterward.
The private provisioning borrow preserves the owned external constructor API;
test observation state derives Default. Failed receipts are retained unchanged.
