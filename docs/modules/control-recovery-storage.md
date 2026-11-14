# Fallible management recovery storage

Status: **fallible reserved ARQ backing and actual management consumers are
implemented and component/finite Driver integration-tested**. The explicit
generic constructor selects all three reserved stream owners; existing callers
retain the map-backed default. Complete allocation-failure/differential/pressure
qualification remains open. The required source-stable aggregate passes. This is
a resource prerequisite beneath GSU-05/SRS-07, not completion of those items,
full SW-11, native qualification, platforms or the80 Mbit/s gate.

The [remaining-retention assessment](../../work/generic-driver-20261114/next-retention-v0.md)
is the design input. This contract preserves all advertised catalog entries,
record profiles, carrier selections and mode-parity requirements. It records an
engineering interface, not an owner decision about product scope or defaults.

## Current owner and boundary

`l2tunnel_recovery::SelectiveRepeat` owns the actual `arq::Engine`. Its retained
legacy selection holds `BTreeMap<SourceId, Flight>` for sent sources and
`BTreeMap<SourceId, Box<[u8]>>` for received sources. `submit` and a new accepted
source copy payload bytes; ACK removal and application delivery free them. Count,
byte and sequence-window admission are real bounds, but do not reserve future
map nodes or payload allocations.

Keep one actual Engine algorithm and its `RecoveryEngine` implementation. Add a
private backing choice for legacy maps or reserved slot tables. Do not implement
a second ARQ state machine, sequence allocator, ACK owner, retransmission policy
or packet parser. The existing `SelectiveRepeat::new`, `CarrierOnly::new`, all
existing methods and error meanings remain available. The legacy path remains
the default for existing callers. No new wire profile or negotiated field is
introduced. CarrierOnly must retain its successful-poll ownership handoff and
must not start waiting for peer ACKs as a side effect of sharing Engine code.

The recovery crate remains independent of Tokio, OS handles, privileges, keys,
real clocks and device setup. Its only time input remains caller-supplied
`Duration`. No unsafe code, allocator replacement, process-global fail hook,
Swift dependency or dependency cycle is permitted.

## Additive public recovery API

Add `l2tunnel_recovery::storage` with the following interface. Plan has private
fields and cannot be forged. Usage is an observational snapshot returned by the
actual owner; no constructor accepts a caller-supplied Usage as backing authority.

```rust
pub struct Limits { pub capacity_bytes: usize }
pub struct Plan { /* private validated ArqConfig and checked heap layout */ }
impl Plan {
    pub fn for_arq(config: ArqConfig) -> Result<Self, Error>;
    pub fn config(&self) -> ArqConfig;
    pub fn capacity_bytes(&self) -> usize;
}
pub struct Usage {
    pub limit_bytes: usize,
    pub capacity_bytes: usize,
    pub allocations: usize,
}
pub enum Error {
    Recovery(RecoveryError),
    Layout,
    Limit { required: usize, limit: usize },
    Allocation,
    Invariant,
}
```

`Plan` and `Usage` are allocation-free values. `Plan::for_arq` first calls the
same configuration validator used by the legacy constructor. Configuration
failure is `Error::Recovery(RecoveryError::InvalidConfig)`. Layout or checked
arithmetic failure is `Layout`. `Allocation` denotes a failed
`try_reserve_exact`; `Invariant` denotes a reported capacity different from the
validated exact capacity. Error formatting contains no source bytes or context
secrets. Do not add storage variants to the existing `RecoveryError` enum for
constructor-only failures.

```rust
impl SelectiveRepeat {
    pub fn new_reserved(
        config: ArqConfig,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error>;

    pub fn storage_usage(&self) -> Option<storage::Usage>;
}
```

The returned SelectiveRepeat is the sole real engine owner. Its existing public
mutable operations already constrain access to Engine; no mutable backing Vec,
map, slot, replacement or `into_inner` escape is added. `storage_usage()` returns
`Some` only for the reserved constructor and reports actual retained backing,
including idle slots. Legacy returns `None`, not a fabricated zero-byte charge.
`Usage.allocations` is the number of successful explicit nonzero backing
reservations made by that constructor, not OS allocations, pages or allocator
bookkeeping. It remains fixed for the owner's lifetime.

This first leaf reserves SelectiveRepeat, the engine actually used by management.
It does not add a reserved CarrierOnly API or remove its existing functionality.
The private common Engine changes must preserve its existing tests and behavior.

### Frozen validation refinement

The existing `ArqConfig::validate(self) -> Result<(), RecoveryError>` becomes
public with exactly its existing checks and precedence. Management's pure
validation calls it directly instead of constructing a temporary recovery
owner. This additive visibility change grants no storage or authentication
authority and does not change either legacy constructor's validator call.

## Exact retained-layout ledger

Let `A(T,n) = Layout::array::<T>(n).size()`, with checked layout/isize limits and
checked sums/products. Set `M=max_source_bytes`, `S=send_records` and
`R=receive_records`. Current validation requires `M` in 1..=65535 and each of
`S,R` in 1..=64. Preserve those values and all existing byte/timing limits.

Use one permanently owned payload Vec per slot, with no separate free-buffer
pool or auxiliary index allocation. The private reserved send slot contains an
explicit `Option<SourceId>`, its `Vec<u8>` header and the existing attempts,
retry deadline and RTO fields. The private receive slot contains an explicit
`Option<SourceId>` and its `Vec<u8>` header. Payload length zero is valid and
cannot identify an unused slot.

| Retained backing | Exact requested layout | Reservations |
| --- | --- | --- |
| Send slots, including payload Vec headers and send metadata | `A(SendSlot,S)` | 1 |
| Receive slots, including payload Vec headers | `A(ReceiveSlot,R)` | 1 |
| Persistent send payloads | `S * A(u8,M)` | S |
| Persistent receive payloads | `R * A(u8,M)` | R |
| Total heap | `H = A(SendSlot,S) + A(ReceiveSlot,R) + (S+R)*A(u8,M)` | `2+S+R` |

The inline Engine/backing-enum/Service headers belong to their enclosing fixed
owner charge, not H. Actual `size_of`/Layout values are target/toolchain-specific;
H is not a serialized cross-platform constant. The payload headers are counted
inside the slot arrays exactly once. No extra free list, ordered index, temporary
full-pool clone or hidden metadata collection is allowed without revising the
ledger before implementation.

The logical `send_bytes` and `receive_bytes` remain the sum of live payload
lengths and retain their existing admission behavior. They do not replace S*M
or R*M in H. ACKed and delivered slots clear their payload length and metadata
while retaining their buffer capacity. All slot and payload capacity stays
charged until the actual reserved owner drops, including after retry exhaustion.
`Retained` keeps its existing logical-payload definition.

This metric is requested Rust owned allocation-layout capacity. It excludes
allocator rounding/bookkeeping/caches, process RSS, committed physical pages,
thread stacks, socket/device queues and unrelated owners. It is not a guarantee
against operating-system overcommit/OOM. Use safe empty Vecs and
`try_reserve_exact`, then check actual capacity equality before publication.
The checkout pins Rust 1.92.0; the existing exact-capacity storage investigation
must be re-audited on toolchain changes. Reject differing capacity rather than
silently reporting the requested size as observed backing.

## Construction and packet-path failure ordering

Construct a complete validated Plan before the first allocation. Refuse H above
`Limits.capacity_bytes` with `Limit`, before making any backing reservation.
Privately reserve the entire H for construction accounting, then provision both
metadata arrays and each M-byte payload buffer. Each metadata push and payload
copy is guarded by its existing capacity; no implicit grow is permitted. Publish
no Engine until every slot and capacity witness exists. On any failure, drop all
partial backing before returning; no existing engine, source ID, timestamp,
statistics or caller buffer is affected. A numeric plan alone is not backing.

Use a crate-private allocation helper, with a test-only per-construction failure
observer. Failpoint indices cover both slot arrays and every payload reservation,
including the last. No public fake permit, environment variable or global
allocation counter is part of the API. A failed construction must leave zero
published ownership; tests observe release of partially built buffers through
local instrumentation.

The reserved packet path cannot reserve, shrink, clone a payload pool, insert a
map node or fall back to a new Vec/Box when a slot is unavailable. Capacity and
slot checks precede copying or changing authoritative state. If a supposedly
available reserved slot cannot meet admission, return the existing
`RecoveryError::Capacity` for that side without mutation; tests must prove this
is unreachable after valid logical admission and successful construction. It
must never trigger a legacy allocating fallback.

Preserve current protocol/error ordering, including:

- Submission checks sticky failure, monotonic time, source size, checked logical
  bytes, count/byte admission, source span and checked next ID before publishing.
- Receive parses the actual context/profile first. It computes a representable
  ACK deadline before changing duplicate or receive state. Invalid packets,
  conflicts and rejected admission do not advance the receive clock or ACK.
- Validate the entire ACK, including every acknowledged retained source having
  actually transmitted, before recycling any sent slot. A rejected ACK cannot
  remove a subset of sources or release their byte charge.
- Poll chooses feedback/source using the same preference and deadlines. Existing
  retry exhaustion is sticky before output-size preflight; ordinary undersized
  output changes no source attempt or deadline. Successful no-work polling keeps
  its existing last-time update. Do not change these rules for storage convenience.
- `poll_delivered` checks output size and the checked next delivery ID before
  releasing the source. A valid zero-length source returns `Some((id,0))`.

This change does not authorize new sequence arithmetic, ACK/retry behavior,
maximum retries, retry duration, wire encoding, diagnostics or validation rules.
A separately discovered arithmetic defect requires an explicit narrow contract
and discriminating regression, not an unreported change in this storage work.

## Slot operations preserve ordered-map semantics

Bounded linear scans are sufficient for at most64 slots and require no sorting
scratch. Physical slot order must never decide protocol order:

- Find and compare complete SourceId values. Preserve the nonwrapping source
  allocator and the send span `next_source - minimum_retained_source < S`, even
  when selective ACKs free holes. Occupancy count alone is insufficient.
- Choose the minimum due `(retry_deadline,SourceId)` before any first attempt;
  otherwise choose the minimum unsent SourceId. The earliest source deadline and
  acknowledged-prefix/bitmap calculations must match the legacy Engine.
- Keep `receive_prefix` separate from `deliver_next`. ACK receipt may advance the
  former while application output is blocked; those undelivered payloads remain
  stored, charged and bounded relative to `deliver_next`.
- A retained duplicate must match its exact payload, including empty bytes.
  Historical sources below receive_prefix retain the current duplicate/ACK
  behavior without inventing a payload history or changing conflict detection.
- ACK and delivery clear only the exact occupied identity. Reused physical slots
  cannot make an unallocated SourceId confirmed or let an old packet replace a
  new payload. `source_confirmed` keeps its allocated-and-no-longer-retained rule.

## Actual management and selected-runtime consumer

An unused constructor does not deliver this item. Add the following explicit
ARQ-only consumers; existing constructors and existing Error enums remain intact.

```rust
// In management::delivery, using its existing settings/binding/time arguments:
pub enum ReservedArqError {
    Service(Error),
    Storage(l2tunnel_recovery::storage::Error),
}
impl Service {
    pub fn new_reserved_arq(
        settings: Settings, binding: Binding, now: Duration, expires: Duration,
        limits: l2tunnel_recovery::storage::Limits,
    ) -> Result<Self, ReservedArqError>;
    pub fn arq_storage_usage(&self) -> Option<l2tunnel_recovery::storage::Usage>;
}

// In management::messages:
pub enum ReservedArqError {
    Message(Error),
    Storage(l2tunnel_recovery::storage::Error),
}
impl Owner {
    pub fn new_reserved_arq(
        settings: Settings, binding: delivery::Binding,
        now: Duration, expires: Duration,
        limits: l2tunnel_recovery::storage::Limits,
    ) -> Result<Self, ReservedArqError>;
    pub fn arq_storage_usage(&self) -> Option<l2tunnel_recovery::storage::Usage>;
}
```

Share each existing constructor's validation and initialization logic. Preserve
current settings/error precedence and exact role/session/control-epoch binding.
Service failures, including invalid recovery configuration, retain their existing
nested Error representation; only actual storage planning/provision failures use
the new Storage arm. Do not construct a legacy recovery owner then replace it.
The whole-message constructor name deliberately promises only reserved ARQ:
fragment batches, original messages, reassembly, arrival/tombstone maps and
completion/scratch buffers remain separate resource prerequisites.

Factor the existing checks into pure shared validation, usable by selected runtime
preflight without constructing and discarding temporary whole-message owners.
The exact additive validation signatures are:

```rust
// In each of delivery::Settings and messages::Settings:
pub fn validate(
    self, binding: delivery::Binding, now: Duration, expires: Duration,
) -> Result<(), Error>;
```

In delivery, `binding` is the module's own Binding. Validation allocates nothing
and preserves all checks/precedence performed by its existing constructor.
Constructors use that same validated result; the selected control Settings
validator must not retain its current validation-through-Owner-allocation path.
Pure validation is not permission to skip actual reserved construction.

For the private runtime control Owner, add
`new_leased_reserved_arq(base, selected, binding, control_scope, data_scope,
now, expires, limits: [recovery::storage::Limits;3]) -> io::Result<Self>` and
`arq_storage_usage(&self) -> Option<[recovery::storage::Usage;3]>`. Other arguments
and semantics match current `new_leased`. Construct actual Transaction, Liveness
and DataFeedback Owners through their reserved ARQ constructor in that fixed
order. Keep `new_leased`, SwiftPolicyV1 and the legacy control backend available
with existing bytes/default selection. The selected generic constructor must use
the new actual path, not instantiate an unused parallel pool.

The sum of actual three-stream usage must equal their three validated plans and
be added once to the real combined Bank/external admission charge before
readiness. The entire ARQ subtotal is reserved before constructing its first
stream; failure to construct stream2/3 drops earlier unpublished streams.
Do not triple shared service wire credit or merge liveness into transaction
head-of-line. Preserve original session/message/operation deadlines and actual
Accepted/Confirmed proof ownership. ARQ source ACKs still do not prove semantic
application or physical native completion.

Original whole-message bytes, encoded fragment copies and ARQ source copies may
coexist. This pool reserves the ARQ copies only; no zero-copy or ownership-transfer
claim subtracts the other owners. Keep `resource_preallocation_complete=false`
until the remaining fragment/message/bridge/Peer/catalog/bootstrap/report and
combined-admission requirements are actually provisioned and tested. Requested
versus effective generic selection and resource limitations remain observable.

## Verification and stable gates

The contract and pre-edit binding preceded production changes; the implementation
freeze is recorded in the
[storage receipt](../../work/control-recovery-storage-20261114/implementation-freeze-attempt-1.json).
Focused recovery, management and selected runtime checks now exercise the actual
reserved consumers. Root remains the sole Cargo/format/check/native executor.
The [source-stable focused receipt](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json)
records25 recovery,126 management,42 control and11 selected Generic cases,
including the existing legacy paths, with strict Clippy. These command totals
are component scopes, not a full resource-qualification count.

CRS-02 still lacks explicit observation of partial backing release at each
failure. CRS-03's130-cycle test fills all sender slots but drains receive slots
immediately; it does not prove repeated full receive-pool recycling or distinct
receive-byte exhaustion. CRS-04 still needs malformed/profile/mixed-valid-invalid
ACK differential cases. CRS-06 lacks observed later-stream allocation-failure
cleanup and a dedicated reserved liveness-under-Transaction-pressure case.
Their full task definitions below remain open. Actual all-stream charges are
included once before readiness, but external allocation still precedes final
combined Bank admission. Complete construction-peak enforcement remains open.

- [x] [CRS-01] Freeze the additive API, exact retained-layout ledger, failure/error ordering, actual consumer path and pre-edit source binding without claiming an owner scope decision. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [ ] [CRS-02] Implement checked allocation-free planning and actual fallible exact backing, with exact/one-short budgets, invalid configurations/layouts, every constructor allocation failpoint and complete partial-drop evidence.
- [ ] [CRS-03] Use the existing Engine algorithm over reserved send/receive slots. Prove immutable pointer/capacity inventory through more than64 full-window reuse cycles, including empty sources, byte-bound versus count-bound pressure and undelivered receive retention.
- [ ] [CRS-04] Prove byte/error/timer/statistics/retention equivalence of legacy and reserved SelectiveRepeat under loss, reordered/tied retries, selective ACK holes, duplicate/conflicting sources, withheld application output, malformed/context/profile/ACK failures, high/nonwrapping IDs, output pressure, clock/overflow/retry exhaustion and zero retries. Preserve existing CarrierOnly tests and handoff behavior.
- [x] [CRS-05] Implement actual reserved delivery Service and whole-message ARQ consumers plus shared allocation-free validation. Exercise real fragments,45-byte acceptance receipts, real Accepted/Confirmed proofs and original caps through these owners. Preserve their non-ARQ storage limitations explicitly. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [ ] [CRS-06] Select all three reserved ARQ owners in the actual generic runtime constructor, charge their actual aggregate once before readiness, reject insufficient total without catalog pruning, and test later-stream failure cleanup, shared quotas, independent liveness and legacy/default compatibility.
- [x] [CRS-07] Run focused recovery/management/runtime regressions, required formatting, strict Clippy/rustdoc and frozen-source `python3 tools/check.py`; preserve failed attempts and commands actually executed before a coherent checkpoint. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-aggregate-attempt-2/validation.json); broader parent gates remain open.

CRS completion establishes this ARQ resource leaf and its real selected consumer.
It does not close the broader GSU-05/SRS-07 gates or replace their original
checklist definitions. Finite Linux component/driver tests are not privileged
netem qualification, Windows/Android evidence, ISP classification measurements,
performance acceptance or full mode parity.

## Functionality checkpoint validation

The [required source-stable aggregate](../../work/generic-driver-20261114/functionality-aggregate-attempt-2/validation.json) passes1919 Rust
cases including doctests,376 tooling cases and1658 simulator cases, with workspace
formatting, strict Clippy and strict rustdoc. Its inputs remained unchanged during
the check. Final documentation edits record only evidence and scoped task status.
Earlier failed attempts and the exact pre-fix negative control remain preserved.
This is local Linux validation, with no new privileged/native performance, remote
CI, Windows/Android device or GUI qualification. Every still-open task retains
its complete acceptance definition.
