# Known generic runtime construction admission

Status: **implemented and finite local runtime/service integration-tested**.
This leaf corrects the existing ordering of known, already provisioned storage.
It retains the full GSU-05/SRS-07 and CRS resource definitions. It does not claim
that a known subtotal covers every owner or authorize pruning a catalog, changing
algorithms, defaults, operation caps, native acceptance or the80Mbit/s target.

## Current discrepancy and ownership

Before this change, the generic Driver constructed three reserved control ARQ owners, seven
fixed workspaces, the native packet pool and both input buffers before Bank/Set
checked their combined external charge plus its initial engine. A small retained
budget could therefore fail after those allocations. The selected path now checks
its complete known initial subtotal first, provisions complete message Owners and
compares actual Usage afterward. The full remaining-owner inventory below is
still excluded from a complete-preallocation claim.

Root owns this module and production transport_buffers.rs, transport_native.rs,
transport_engines.rs, transport_generic.rs and control_leased.rs. The delegated
source-only test worker owns their existing test siblings, a new construction
test child and its registration under the existing generic fixture. Root also owns the runtime control selection seam
needed by the separately designed complete control-message storage. Workers must
not edit these paths. Public protocol boundaries remain clock/OS/runtime-free.

## Frozen private interfaces

Buffers exposes a private checked `Plan<const N: usize>` containing exactly N
requested byte-array sizes and their checked sum. Fields are private; constructors
reject empty arrays, Layout/isize failure and sum overflow before allocation.

```rust
Buffers::plan(wire, secure_packet, plain, control_packet, control_message, frame)
    -> io::Result<Plan<7>>;
Buffers::with_plan(Plan<7>) -> io::Result<Buffers>;
Inputs::plan(native, datagram) -> io::Result<Plan<2>>;
Inputs::with_plan(Plan<2>) -> io::Result<Inputs>;
Plan::capacity_bytes(&self) -> usize;
```

Existing new/build APIs retain validation and allocation order through those
same plans. Six workspace lengths stay initialized and the frame remains empty
with retained capacity. Inputs include the oversized-datagram witness byte.

Native Queue exposes an unforgeable `Plan<T>` tied to its actual metadata type,
with checked packet/byte/maximum validation and exactly the existing ready deque,
free Vec headers and every payload layout. It adds `Queue::plan(...)`,
`Queue::with_plan(Plan<T>)` and `Plan::capacity_bytes`; existing new/allocate
delegate without changing admission, FIFO, leases or retained metadata layouts.

Bank adds private allocation-free initial `required_capacity(initial, role,
external_bytes) -> io::Result<usize>`, using its existing role-to-engine plan,
actual `size_of::<storage::Set>()` and checked addition. It grants no token and
allocates no Set/engine or owner ID. Bank/Set remain the sole real engine owner
and perform their existing actual capacity admission on construction/preparation.

The private generic `ConstructionPlan` combines those real Plans with the exact
selected control storage plans and known inline external charge. Initially this
is the existing three ARQ Plans; once the complete message storage API is frozen,
the selected path must account for each complete actual message owner once,
including ARQ exactly once. The implementation cannot keep an ARQ-only charge
while selecting the larger complete owner. All supported catalog entries remain.

The same known subtotal includes the actual Streamed header, three outgoing
metadata Vec capacities and envelope/raw byte arrays. The separately tracked
[wrapper storage](control-wrapper-storage.md) now supplies a typed immutable Plan
to the actual selected constructor. Its six fallible reservations back the real
singleton Streamed cell, outgoing queues and scratch; actual Usage must match the
same plan before readiness. Message Owner headers embedded in Streamed are charged
there once and excluded from message heap Plans. Later cloned bridge/frozen
envelopes remain unfinished owner obligations. The original allocating path
retains its boxed header and wire behavior.
The new complete-message constructor uses the existing collector and gate via
an explicit private Legacy/ReservedArq/ReservedMessages backing choice. Existing
public protocol constructors retain their selection and wire behavior. The prior
crate-private runtime ARQ-only constructor remains an explicit test compatibility
seam now that production selects complete owners. No choice is inferred
from packet bytes or from a forged usage value.

Compute security workspace geometry through the actual authenticated Records
owner's checked capacity before constructing control/buffers/native/engine
storage. Existing setup/root/tail ownership precedes this point and is explicitly
outside this finite preflight claim. Maximum control packet geometry must share
the real constructor's checked helper; do not construct/discard a temporary owner
to ask its size. The initial engine Plan uses the exact current complete C and
role, not a rounded legacy Policy or the maximum of unsupported guesses.

`ConstructionPlan::provision(limit, build)` rejects known total insufficiency before the
first selected control/buffer/native/engine allocation. Actual construction
consumes those checked plans, compares every actual retained capacity, recomputes
the identical external sum and passes it once to the real Bank. A plan is never
accepted as proof of allocation. Failure drops every unpublished actual owner;
no fake permit, second Bank, hidden retry or increased budget is permitted.

## Incomplete owners and error semantics

Keep resource_preallocation_complete=false. Bootstrap tail, maintained crypto
transients, wrapper/bridge envelopes, full Peer/configuration/catalog/report and
frontend owners remain explicit unless their separate complete plans and actual
provisioning qualify. Adding complete message storage removes only its real
previously missing subtotal. Layout, InvalidInput, OutOfMemory and actual protocol
errors retain their existing distinctions and original deadline behavior. Do not
infer allocator exhaustion from a configured budget refusal.

The known total is actual requested retained layout, not allocator metadata,
resident pages, kernel socket buffers or a promise about unplanned transients.
This leaf is aligned with full resource admission and does not replace its
remaining construction-peak, failure, ownership and native acceptance.

## Acceptance and stable tasks

Use meaningful exact/one-short and invalid layout/type/overflow cases against
actual owners. Repeated I/O must retain original pointers/capacities and exact
existing behavior. A callback/factory witness must distinguish preflight from
post-allocation refusal, and actual generic authentication/budget failure fixtures
must retain their stage, no false readiness, cleanup and original cap.

Root runs one combined batch after parallel consumers freeze, preserving failed
attempts and exact source hashes. No leaf-specific full-suite reruns or performance
workload is selected by this contract.

- [x] [KCA-01] Freeze checked private plans, actual ownership, incomplete inventory and pre-edit source binding before code without narrowing any parent. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [KCA-02] Implement actual fixed buffer/input and typed native queue Plans with shared existing constructors, exact actual capacities and failure/overflow/reuse evidence. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [KCA-03] Compute and admit the complete known initial engine/external subtotal before the first new selected controlled allocation; verify actual provisioned bytes and charge once through the sole Bank/Set. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [KCA-04] Integrate complete message-owner plans when selected, preserve all catalog members, original deadlines and explicit remaining resource gaps; no ARQ double charge or numeric-only reservation. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [KCA-05] Pass combined layout, failure, actual generic budget/lifecycle/traffic and required source-stable workspace checks; keep full resource/native/performance/mode/platform parents open. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.

## Checkpoint evidence

The [full baseline](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json) passed with unchanged recorded inputs:2011 Rust cases including
doctests,406 tooling and1658 simulator cases. The subsequent [affected completion repair](../../work/generic-functionality-20261114-batch2/completion-projection-focused-attempt-1/validation.json)
passes77 affected service/local cases with4 test threads and strict client-core
Clippy after the narrow APIv3 completion repair. Only owner.rs and its existing
generic failure test changed outside documentation. Unchanged protocol, tooling
and simulator evidence is reused explicitly; the full baseline is not relabeled
as a new post-repair full run. Native acceptance remains separate and unqualified.
