# Common record engine composition

Status: **actual functional Engine implemented and protocol-tested; reserved
mixed-generation/runtime composition remains planned**. The explicit
`new_functional` owner follows the frozen interface below; it is not a runtime
fallback. This document records no new owner decision, default carrier or scope reduction. The
[pre-edit source binding](../../work/record-composition-20261114/common-record-engine/source-binding-v0.json)
identifies the inspected prerequisite inputs. The subsequent
[functional pre-edit binding](../../work/common-record-engine-20261114/functional-engine-preedit-v0.json)
precedes this implementation. Runtime/resource integration is not established.

Compose the actual Swift, duplex Aligned and duplex Packed owners. Do not add
another recovery/FEC algorithm, header codec, classifier, MUX, transaction FSM,
packet protector or carrier. Public types remain independent of Tokio, OS
handles, privileges, native devices and real clocks. Inject time and authenticated
input; physical completion and management authority remain external.

## Current evidence and unchanged scope

| Requirement | Existing source | Required composition |
| --- | --- | --- |
| Selected channel | Swift `offer_on_channel_identified`; Aligned/Packed `enqueue_identified` | Actual common MUX selection without private hash or modulo |
| Independent directional policy | Reserved Swift duplex engine; real Reliable/Aligned/Packed `new_duplex` | Exact role projection and explicit unsupported capability refusal |
| Typed emissions | Swift producer `EmissionKind`; Reliable authoritative `inspect_output`/`RecordKind` | Common Source/Repair/Feedback and retained output metadata |
| Original identity | Swift native-only identity; Aligned/Packed body `RecordIdentity` and `UnitWitness` | Profile identity plus separate local native cursor/physical receipt |
| Native custody | Reserved runtime native pool; Aligned `prepare/pending/commit_delivery` | Profile-aware pending tokens and original expiry through physical write |
| Generation ownership | Actual two-slot Swift Set and runtime Bank | Real mixed-profile prepared/current/draining owners |
| Fallible memory | Swift Set and directional ARQ storage | Complete Reliable/FEC/Aligned/Packed and common Pipeline/MUX backing |

Existing protocol/native receipts retain their original scope. This work does
not qualify another carrier, Windows/Android, ISP classification or performance.
The following parent definitions remain unchanged:

- [SW-11](swift.md): Negotiated epoch switching between swift and the other record profiles, retaining authenticated management, matching digests, drain barriers, bounded retries and old-epoch rejection. Cross-profile selection is currently startup-only. SW-13 does not narrow or complete this gate.
- [GSU-05](generic-secure-udp.md): Integrate actual prepared/current/draining record owners, bounded combined resources, stopped admission, original identities, physical fence equality, commit and retirement without resetting security state or fabricating delivery.
- [SRS-07](swift-storage.md): Integrate actual storage reservations into the selected generic driver and leased management transaction before PREPARE/staging; qualify physical custody, shared external owners and original resource/native/performance requirements. Pure storage tests cannot close this gate or GSU-05.

RLNC, parity, rolling, packed, proxy and all47 mode-parity gates remain in scope.
This adapter initially selects three actual existing families, not substitutes
for the remaining algorithms. Unequal same-family directional configurations
are required. Mixed directional families remain explicit later composition and
encoding work; two complete endpoints with unused halves do not implement it.

## First prerequisite: shared allocation-free scalar validation

The configuration lane must call authoritative validation without constructing
and dropping protocol owners. Freeze this additive interface first:

```rust
impl packet::FlowTableConfig {
    pub fn validate(self) -> Result<(), packet::FlowError>;
}
impl qos::SchedulerConfig {
    pub fn validate(self, classes: &[qos::ClassConfig])
        -> Result<(), qos::ConfigError>;
    pub fn flow_quantum(self, class_weight: Option<u32>, flow_weight: u32)
        -> Result<u64, qos::FlowError>;
}
impl pipeline::PipelineConfig {
    pub fn validate(self) -> Result<(), pipeline::PipelineError>;
}
```

`FlowTable::new` reuses `FlowTableConfig::validate`: capacity1..65536,
channels1..256, then nonzero idle timeout in the existing combined invalid-config
predicate. No flow IDs, channel turns, clocks or entries are created.

`SchedulerConfig::validate` preserves the current constructor error order:

1. Any zero base quantum or one of the seven resource bounds: `ZeroLimit`.
2. Packet exceeds per-flow bytes, per-flow exceeds global bytes, or per-flow
   packet count exceeds global packet count: `InconsistentBounds`.
3. Empty classes: `NoClasses`; too many classes: `TooManyClasses`.
4. For each class in input order: zero weight, checked existing
   `weighted_quantum(config, class.weight, 1)`, then duplicate class ID.

Use a fixed65536-bit local bitmap (`[u64;1024]`,8192 bytes) for duplicate IDs.
It allocates nothing, visits each class once and imposes no new class-count cap.
A bad duplicate's weight/arithmetic error still precedes `DuplicateClass`, as
the old map-insertion loop did. Do not replace it with quadratic prefix scans.
The original weighted arithmetic checks base * class * flow in u64 and
`quantum + max_packet_bytes - 1`; keep that function authoritative.

`SchedulerConfig::flow_quantum` preserves zero flow weight before missing class
before checked weighted arithmetic. `None` means `UnknownClass`; a present class
weight comes from an already validated class. The Scheduler's private lookup
forwards its map result to this method. `register_flow` still checks duplicate
ID, then flow capacity, before that lookup/weight/arithmetic validation.
`set_flow_weight` retains unknown-flow and busy checks before the shared helper.
This scalar method is not a claim that a flow can be registered into live state.

`PipelineConfig::validate` preserves exact current constructor ordering:

1. Shared queue bytes below parser maximum, zero packet count, or native minimum
   below14 bytes for TAP /20 bytes for TUN: `InvalidConfig`.
2. Classify the existing synthetic14-byte opaque Ethernet header with EtherType
   `0x88b5` under the actual `ParseLimits`; preserve `Parse(error)`.
3. Validate the actual FlowTableConfig, preserving `Flow(error)`.
4. MUX scalar acceptance is already implied: queue bytes are nonzero, packet
   count is nonzero and flow validation established channels1..256. No MUX owner
   is allocated during validation and no new MUX predicate is invented.
5. TAP needs no scheduler. For TUN, zero maximum flow weight is `InvalidConfig`
   before any scheduler error. Derive the exact current SchedulerConfig from
   common/per-flow limits with one class, class0 weight1; call its validator and
   preserve `QosConfig(error)`.
6. Call shared `flow_quantum(Some(1), policy.max_weight)`, preserving
   `QosFlow(error)`. This proves the original dummy flow0 registration arithmetic
   without allocating a flow or registering/removing it. Duplicate/capacity/
   removal failures were unreachable for that fresh one-class scheduler.

`Pipeline::new` calls the shared validator then constructs the actual existing
FlowTable/MUX/optional Scheduler. Private derived-policy helpers are shared by
validation and construction. Existing constructors remain API-compatible; no
MUX handoff, traffic policy, flow registration semantics or packet scheduling
changes belong to this prerequisite. Scalar success is not storage reservation
or installed runtime capability.

Focused tests retain explicit expected error values and multiply-invalid
precedence: native minimum before invalid parser; parser before invalid flow;
invalid flow before TUN weight; TUN maximum weight zero before invalid quantum;
scheduler scalar error before maximum-weight arithmetic. Exercise class
zero/arithmetic before duplicate, duplicate/capacity before live flow validation,
both ID endpoints and exact checked-quantum boundaries. Compare actual legacy
construction/registration behavior too, rather than only two validators calling
the same helper. No new test workload is a performance qualification.

## Complete configuration and actual engine API

The configuration lane owns complete canonical v2 values and role projection;
the integrator owns transaction bounds and facade registration. The engine
needs borrowed exact send/receive configs, native policy, channel/source/native/
output geometry, common scheduling/credit policy and immutable existing
session/epoch/local-role context. Representability is distinct from installed
mapping, active-credit or proxy capability; reject unsupported requested behavior
before owner construction or old-owner mutation. Keep Swift's existing matching
native-layer/maximum constraint observable while retaining its independent
codec/channel policies. Never replace unequal directions by their maximum.

The actual functional adapter follows this engineering-frozen pure surface:

```rust
pub struct Tick(pub u64); // injected microseconds
pub struct Channel(u16); // installed send width is checked separately
pub enum ProfileIdentity {
    Swift(swift::records::NativeIdentity),
    Aligned(codec::aligned_receiver::RecordIdentity),
    Packed(codec::aligned_receiver::RecordIdentity),
}
pub struct NativeToken { /* private immutable origin/channel/local cursor */ }
pub enum SourceForm { Swift, DirectArq, SystematicFec }
pub enum EmissionKind { Source(SourceForm), Repair, Feedback }
pub struct Engine { /* exactly one selected actual owner */ }
// offer_selected(now, channel, original_bytes) -> Accepted(identity, token)/Full/size
// poll(now, full64_security_number, allow_data, output, shared_budget, witnesses)
// accept_authenticated(now, full64_security_number, authenticated_kind, body)
// prepare_native(now, finite_work, actual_free_native_output_slot)
// pending_native() -> exact metadata; commit_native(now, exact_token)
// tick(now); deadline(); drain(); resource_qualification()
```

The engine must expose restricted operations, no mutable backing/engine escape.
An explicit unreserved compatibility constructor may compose actual existing
owners for functional library comparisons; it must report that qualification.
It cannot be a default fallback or satisfy complete generic runtime admission.
A reserved constructor may accept a family only after its actual storage exists.
No success-returning reserved stub or dummy branch is permitted.

## Transactional MUX admission

### Frozen functional composition interface

The next integrator-owned slice adds actual `l2tunnel::record_engine`, rather
than another algorithm. Its explicit `Engine::new_functional(configuration,
context, geometry, native_limits)` owns one actual Pipeline and exactly one
Swift, Aligned or Packed duplex record owner. It preserves unequal directions
through the configuration's global-role projection. There is no default/fallback
constructor or selected-runtime capability claim. Swift initially uses one
occupied existing storage Set slot; the second slot remains empty metadata.
This is not the eventual movable mixed-generation reserved owner.

`Context { session:u128, epoch:u64, role:management::Role }` is trusted local
binding input, not authentication authority. Both identities are nonzero. The
actual configuration digest is computed from the complete supplied value.
`Geometry { forward_overhead_bytes:usize, reverse_overhead_bytes:usize }` is the
caller's exact complete-wire overhead contract. Both authoritative output maxima
plus their directional overhead must fit path MTU and burst; Aligned/Packed's
existing outer charge must match exactly. No overhead is charged twice.
`NativeLimits { stall_micros:u64 }` is explicit, positive, immutable and belongs
in the externally authenticated resource envelope before runtime selection.

The functional constructor rejects represented Active/tunnel-credit, TCP-proxy
and native-window requests, because their real owners are not installed here.
It consumes the complete actual Pipeline policy. Directional rate/burst values
remain exact and observable via the immutable complete configuration; connection
pacing and physical half/full-duplex scheduling are external required services.
Every emission requires the same caller-supplied shared packet/wire allowance,
already limited by that external service. This comparison entry point cannot
qualify a configured runtime until those services, complete reserved Pipeline
backing and actual mixed generations consume their full policies. No requested
feature or later acceptance definition is removed by those explicit refusals.

The concrete operation names are `enqueue`, `admit_one`, `poll`,
`accept_authenticated`, `prepare_native`, `pending_native`, `commit_native`,
`tick`, `deadline`, `drained`, `statistics`, `configuration` and `qualification`.
All use caller-injected `Tick(u64)` microseconds. `enqueue` preserves the original
Vec in its typed error. `admit_one` calls the actual Pipeline `offer_front` once,
passes exact PacketMetadata/channel/bytes to the maintained record owner, and
returns the existing `Admitted<ProfileIdentity>` with the original owned packet.
Only actual identified acceptance removes the queue head. Codec refusal is
retryable only where it proves no native admission; partial authoritative codec
failure is terminal and retains queue bytes solely for cleanup.

`poll(now, security_number, allow_data, output, shared_budget, unit_witnesses)`
preflights complete output/witness/allowance geometry before consuming output.
It returns exact bytes, actual typed branch, full wire cost, unchanged full64
security/GF number and witness count. Swift feedback stays live with data off;
Aligned/Packed use actual feedback/data polls and authoritative inspectors.
Swift witnesses are explicitly unavailable; no source number is converted into
a native fragment proof. Caller retains emitted/sealed bytes through physical
WouldBlock; repolling is never a resend operation. Authentication/replay remain
the enclosing selected session's responsibility.

`prepare_native(now, work, original_deadline, output)` preflights a caller-owned
maximum native slot and checked local token before extraction. It returns Idle,
Progress, an already-pending observation or an actual newly prepared immutable
metadata/token. The caller retains that exact output slot until complete device
acceptance. Another prepare cannot overwrite an existing pending slot or renew
its original cap. The retained deadline is the smaller of the supplied original
cap and first prepare plus configured stall; actual Aligned deadlines can expire
earlier and stay authoritative through a pending-only expiry accessor, distinct
from ARQ retry timers. Swift copies its actual borrowed identified
extraction once; Aligned leaves its real pending delivery uncommitted.

`commit_native(now, exact_token)` is a trusted physical-owner operation after a
complete device write. A stale token changes no pending output. It commits the
actual Aligned receiver and local physical count only once; Swift extraction
and device completion remain distinct. Counter capacity is preflighted before
native extraction. A reported whole physical write is counted once even when
completion crosses expiry or an earlier terminal error; that observation does
not complete the failed record owner or qualify a drain fence. Tokens are meaningful only within their
originating Engine; a future Bank must bind its own unique slot/generation too.
Local accepted/prepared/committed totals are observations, never fence authority
or `RecordId+1`. Expired or terminal state cannot be retried as a new preparation.
No adapter payload queue, second classifier, security owner or mutable backend
escape is introduced. Root owns its facade registration, source and actual
three-profile composition tests; the queue lane owns the RAH interfaces.

The [source-stable five-package batch](../../work/common-record-engine-20261114/records-attempt-1/validation.json)
passes255 library cases, including10 initial facade Engine tests. They compose
each actual profile with TAP and transparent TUN in both asymmetric directions,
exercise real Full/Busy then exact retry, preserve original bytes/channel/identity,
retain feedback while data is disabled, check full64 packet numbers, exact shared
wire charges, native pending/one-time completion and terminal deadline handling.
Output ceilings come from the authoritative Reliable scalar maximum, not a
possibly larger configured safety ceiling. New pending-only expiry accessors
retain actual record lifetime independently of recovery retry timers.
The [11 exact downstream regressions](../../work/common-record-engine-20261114/downstream-attempt-1/validation.json)
exercise current legacy runtime/client/Active callers. They do not install this
new Engine into those runtimes. All CRE-02..CRE-08 definitions remain open until
their full composition, width/resource/fence and acceptance conditions hold.
Two [exact follow-up regressions](../../work/common-record-engine-20261114/regressions-attempt-1/validation.json)
verify a loose60000-byte recovery ceiling does not reject an actual fitting
output, and late native preparation retains the original record expiry despite
an earlier ARQ retry deadline. Only these two appended tests were run again;
the previous32 facade cases are reused with a byte-exact unchanged source prefix.

All original traffic, including probes/TCP controls, uses the existing actual
Pipeline classification, configured byte/count budget and selected channel.
TAP retains per-channel FIFO/RR and TUN retains the existing weighted scheduler.
The adapter adds no classifier, private hash, MUX, original-packet queue or QoS
algorithm. Swift packing storage remains downstream recovery, not common MUX.

Check widths before context/counter/timer/identity mutation: Swift1..64,
ordinary Aligned1..256, Packed1..255. The Packed container marker is not a
native channel. Never modulo an incompatible selection. Actual Full/Busy must
retain the original FIFO head, not pop/requeue it.

The current MUX has destructive `pop`; Pipeline TUN's external commit receives
metadata only. A later minimal MUX extension is `offer_front<T,E>(&mut self,
FnOnce(u16,&[u8])->Result<Option<T>,E>) -> Result<Option<T>,E>`: select the real
head, commit removal/counters/RR only on actual `Some(admission)`, retain exact
state on None/error. Prevalidate bookkeeping before the closure. Pipeline
forwards actual bytes plus PacketMetadata; TUN needs a selected-payload borrow
before its existing Scheduler `dequeue_peeked`, not a second queue. Credit
reservation must be reversible through codec refusal. Shared handoff work is
not part of the first scalar-only slice.

## Typed emissions, witnesses and physical custody

Swift dispatches actual `poll_emission` with the unchanged full64 security
record number/GF seed. Aligned/Packed dispatch real data/feedback polls and the
existing authoritative output inspector; retain DirectArq/SystematicFec subtype.
Do not infer kind from an unchecked leading byte. Authenticated outer scope/kind
must match the profile parser. `allow_data=false` still services feedback;
Management and Liveness retain their independent actual control owners.

One allowance charges actual outer wire bytes once. Reliable already includes
its configured outer overhead; validate it against protection/cover geometry
without charging it again. Swift requires output/budget preflight before poll,
then exact emitted-byte charging. Runtime retains the sealed packet, full number,
origin, typed emission and witnesses through EAGAIN; no repoll/reseal/new number
or repeated allowance charge. Actual first-send time is physical carrier
acceptance, separate from poll/admission time; original deadlines never reset.

Aligned/Packed `outgoing_units` supplies only actual direct/systematic original
context/body/fragment units. Preserve complete fragment counts and packed-unit
multiplicity in caller-reserved witness storage. Contexts do not mint native
admissions; retransmission repeats original identity. Repair/feedback has no
original-native delivery witness. Swift stream packing currently exposes no
equivalent native-fragment mapping: report absence, never invent it from ACKs,
repair numbers or emitted packets. Exact Swift per-native first-send/credit
attribution requires actual producer-range observation if needed by FIX-01.

Original profile identity, local admission/preparation cursor and physical receipt
are distinct. Aligned contexts share record space, `first_record` may be nonzero,
and independent-short delivery can precede a gap. `RecordId+1` is neither a
native count nor a contiguous body-completion prefix. Preserve selective
receipts and actual receiver tombstones. Swift native-only identity is unchanged.

Reserve a real native-pool slot and preflight its maximum output/counters before
Swift extraction or Aligned prepare. Copy at most one complete body into that
existing slot; add no adapter payload queue. Retain one pending token per actual
engine. Aligned's real pending stays live until physical completion; context/
tombstone `Progress` mints no native token. Swift's borrowed extraction is copied
before the next mutable engine operation. Repeated prepare/physical WouldBlock
retains the same slot/token/bytes/original age, with no additional extraction.

Only a complete device write commits the original Endpoint delivery and physical
receipt, then recycles the slot. Preserve original expiry checks. Preflight local
bookkeeping before the write. Expiry/error after a physical write is an explicit
terminal uncertain result, not permission to retry those bytes or count a clean
commit. Common accepted/prepared/committed counts are separately checked totals;
receive completion order is not sender admission identity. Total equality is
meaningful only with exact origins/widths, stopped admission, real whole-generation
drain, empty physical custody and original tombstone retirement. The integrator
owns authenticated full-width fence encoding; counts alone never prove drain.

Inject checked microseconds, preserve Swift time and Aligned/Packed's existing
Duration/millisecond conversions. Service actual data/feedback/packing/receiver/
handoff deadlines with finite work. No real clock, timeout restart or per-packet
decoder-bank clone is introduced. Preserve typed underlying errors and terminal
authenticated-parse behavior; resource budget refusal and allocator failure
remain distinct. Physical output and old feedback/proofs outside the engine pin
retirement separately. Install the exact virgin prepared owner under the existing
Peer/Bank barriers, not a reconstruction at commit or local state reset.

## Complete reserved storage prerequisites

Use one common two-slot owner with one actual profile per occupied slot under
one current + building + external budget. A Swift two-slot Set alongside two
other slots, dummy Swift owners or two endpoints with unused halves is not
equivalent. Swift currently permits no owned/mutable escape: an additive opaque
move-only reserved `storage::Owned`, provisioned by the same actual Plan and
restricted Entry, is a prerequisite for common slots. It must preserve the old
Set API without exposing mutable Engine/backing. This API does not exist yet;
its fixed layout/construction stack and heap must be accounted, not assumed free.

Aligned/Packed need actual fallible storage, not only scalar bounds:

| Owner | Actual backing that must be provisioned and reused |
| --- | --- |
| Aligned/Packed sender | Channel/header contexts, body/symbol scratch, packing bytes/unit metadata, retained staged unit |
| Reliable | One duplex ARQ, send FEC originals/outgoing envelopes, receive restored sources/deadlines, complete queue/map metadata and directional scratch |
| FEC | Encoder padding/coefficients/output; decoder rows/payload/history/expiry/transaction work and retained originals |
| Aligned receiver | Channel contexts, record/body/fragment pools, source proofs, early tombstones, native output, atomic-batch preflight/undo; remove current whole-bank clones without weakening atomicity |
| Aligned wrapper | Actual sender singleton, separate send/receive buffers, Packed receive staging/batch inputs and retained handoff |
| Common engine/Set | Two real slots, fixed counters/token metadata, complete config copies and actual witness capacity |
| Pipeline/MUX | FlowTable/affinity, flow/by-id/metadata registrations, TAP channel metadata, TUN DRR and payload backing |
| Runtime external | Native pool, input/output/ciphertext, catalog/Peer/transaction/report/control/bootstrap/bridge owners and physical proofs, each counted once |

A reserved fixed-slot MUX can plan channel/slot/free-list metadata plus checked
`frame_limit * max_frame_bytes` reusable slab, enforcing the original logical
shared byte/count budget independently. Charge actual slab capacity even when
larger than the byte limit. Legacy per-frame Vec-to-Box allocation cannot remain
on a reserved packet path. Reserved MUX alone does not reserve Pipeline maps/QoS.

Checked layouts/isize limits, exact actual capacities and complete build charge
precede allocation. Drop every partial real owner before releasing build charge;
preserve attempted peak and old state. No infallible Box fallback, global hooks,
unsafe code, grow-on-packet, dummy Usage or uncharged temporary workspace.
Requested Rust layout capacity excludes allocator overhead/RSS/stack/kernel/OOM
guarantees. Literal dependency allocator failure is separate from local budget
or constructor-boundary injection; full CRS-06/resource parents remain unchanged.

## Ownership and acceptance

The first scalar slice owns `packet/src/flow.rs`, `qos/src/lib.rs`,
`pipeline/src/lib.rs` and new focused child tests only. No MUX/handoff change.
The next actual adapter slice proposes new facade `record_engine.rs` plus child
native/emission/tests files. The configuration lane owns its new module; root
owns facade/manifests, management bounds and existing runtime integration.
Storage prerequisites require explicit exclusive algorithm-file assignments.

- [x] [CRE-01] Freeze shared scalar signatures/error order and pass allocation-free/legacy-constructor boundary regressions without changing scheduler or MUX behavior. Evidence: [source-stable119-test affected batch](../../work/record-composition-20261114/foundation-attempt-1/validation.json), including58 packet/QoS/pipeline cases and two actual Active-consumer regressions; strict affected Clippy/rustdoc/format checks pass.
- [ ] [CRE-02] Compose actual Swift/Aligned/Packed owners with exact asymmetric config/capabilities, original bytes/errors and public library boundaries; no duplicate algorithms or unused halves.
- [ ] [CRE-03] Integrate actual common selected-channel transactional admission; prove Full/error retains original bytes/head/metadata/budgets/identity and width boundaries never hash/wrap.
- [ ] [CRE-04] Forward real typed emissions/witnesses, feedback with data stopped, retained physical output and exact once-only outer wire allowance.
- [ ] [CRE-05] Implement actual native prepare/pending/physical commit with selective receipts, original identity/expiry, finite work and checked counters; no fabricated fences.
- [ ] [CRE-06] Compose actual reserved mixed-profile generations with complete nested/external ownership and failure cleanup under one budget; no compatibility fallback qualifies.
- [ ] [CRE-07] Integrate actual selected-carrier Driver/Peer/Bank switching, original security/control, physical proof equality, authenticated scopes/digests and retirement without reconstruction.
- [ ] [CRE-08] Pass affected actual-owner tests in bounded parallel groups and source-frozen stage acceptance; distinguish protocol/local-device/native/platform/performance evidence and exact reused checks.

Focused subsequent sequences include real MUX channel different from Swift hash;
held downstream Full then exact FIFO retry; Swift64/Aligned256/Packed255 and
incompatible widths; asymmetric configs/nonzero IDs under loss/reorder/duplicates
and real GF repair; packed context/body/fragment witnesses; retained sealed output
through WouldBlock without extra poll/charge; early-short physical delivery while
an older gap remains; exact pending-native expiry/stale-token/exhaustion; actual
cross-profile preparation with old recovery/physical/feedback held and lost/repeated
control; exact/one-short/+1 reserved capacities and every local/nested allocation
failure with real partial drop, old-owner preservation and pool reuse.

The scalar prerequisite now has source-stable affected build/test/Clippy/rustdoc/
format evidence. No native lab, performance probe, full workspace or platform
qualification was run for this slice. The actual common Engine remains draft;
the checked scalar prerequisite does not replace its complete behavior.
