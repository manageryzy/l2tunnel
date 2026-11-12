# Packed sources over the existing reliable endpoint

Status: pure composition implemented and independently reviewed, with nine focused
packed tests and eight unchanged ordinary aligned regressions passing. Strict
Clippy and warning-denied rustdoc passed. The source-stable
[wave9 aggregate](../../work/implementation-wave9/validation.json) includes this
composition; authenticated runtime/native integration remains open.
It composes the existing Cauchy/ARQ owner without another recovery engine, crypto,
device, clock, scheduler or runtime profile.

## Shared endpoint, distinct public capability

Add `l2tunnel_aligned::packed::{Config, Endpoint}`. Its configuration contains the
existing aligned `Config` fields plus `hold_micros`, `max_units` and `work_limit`.
The receiver's first_source is the packed **unit** sequence (initially zero),
not the reliable source allocator. First record IDs retain existing semantics.
The constructor validates all common policy plus packed envelope geometry and
bounded preflight memory before allocation.

Keep ordinary `l2tunnel_aligned::{Config, Endpoint}` behavior, digest and native
profile unchanged. Share its existing private lifecycle and reliable owner,
using private sender/envelope selection. Public packed construction is explicit;
there is no automatic wire detection, profile fallback or caller-selected raw
input interpretation. Public method names match enqueue_admitted, poll_data,
poll_feedback, receive_authenticated, prepare, pending, commit_delivery, tick,
deadline, drained and status. Add explicit flush for deliberate end-of-batch
drain. It seals existing units without fabricating an empty source.

Digest serialization must include every existing policy field and all new
packing limits under a distinct domain/version. Reuse common field serialization
without changing the existing ordinary digest. Authenticated embedding must
select this exact digest; raw-IP versus Ethernet/header policy stays immutable.

## Sender and receiver ownership

Enqueue accepts only a frame already selected by the common MUX/QoS. The packed
sender owns one aligned frame and one complete packed source. Each service call
performs at most work_limit unit attempts and one source submission. Obtain the
next source from the actual reliable allocator, encode that exact ID, and commit
the packer only after submit returns the matching ID. Send capacity/sequence
pressure retains identical bytes/IDs and first-unit deadline. Physical copies
remain exactly one; retries/repairs belong to the existing reliable engine.

Recovered sources remain globally ordered. One fixed receive buffer holds the
source after poll_delivered; its absolute first-handoff deadline cannot renew
under later polls. Validate the whole canonical envelope, scope, actual recovery
source, negotiated count and contiguous unit floor before accepting any unit.
Zero-extend each exact meaningful unit into preallocated bounded symbol scratch,
then invoke admit_validated_batch_authenticated once for the complete source.
Only all-Accepted results release that handoff. No partial source receipt, codec
context or native credit is invented. Capacity/record-window pressure retains
the exact handoff; semantic, identity or unresolved-complete-context failures are
terminal with owned-state diagnostics. Incomplete fragment tails remain bounded
until completed by a later source under the existing lifetime.

Native policy validation applies to every unit before admission. For raw-IP
profile only exact raw records and their fragments are allowed; the first
fragment proves raw kind. Every complete pending native frame remains immutable
until actual device acceptance. Recovery receipt and simulated semantic
preflight cannot advance native delivery counters.

## Limits and time

Validate packed source bytes against ARQ, FEC and physical recovery packet
ceilings, counting the full identity header and all per-unit absolute record IDs.
Reserve max_units padded symbols and metadata, and include that reservation with
the optional two-receiver preflight ceiling. Require enough otherwise-empty
lookahead record/byte/fragment slots and record window to admit a maximum legal
batch; malformed fragmented declarations remain under existing fragment/body
bounds. Native pressure can still fill storage, but releasing earlier native
ownership must permit retry without dropping or renumbering the source.

Packing uses checked injected integer microseconds; receiver lifetimes keep the
existing millisecond domain and recovery uses Duration. Preserve the original
Duration for monotonic comparisons. Reject unrepresentable time before ownership
changes; exhaustion with already owned packing work remains terminal. Deadline
is the minimum packing/recovery/receiver/retained-source deadline. Never advance
an original deadline to avoid a failed test or busy timer.

All source, feedback, repair and retry output uses the existing OutboundBudget
and its full carrier-overhead charges. No probe/control user lane bypass is added.
Drained requires empty packed/frame staging, reliable ownership, recovered
handoff, receiver records/proofs and pending native bytes with no terminal error.

## Checklist

- [x] [MOD-PACKREC-01] Implement explicit packed capability using the existing reliable owner and unchanged ordinary aligned profile/digest. Evidence: [packed capability](../../crates/l2tunnel-aligned/src/packed.rs), [shared owner](../../crates/l2tunnel-aligned/src/lib.rs), [pinned pre-change ordinary digest](../../crates/l2tunnel-aligned/src/tests.rs).
- [x] [MOD-PACKREC-02] Test real protected two-peer Cauchy/ARQ transfer with packed small frames, context/fragment records, multiple channels, raw-IP and zero tails; prove repair and timer behavior from actual counters. Evidence: [protected two-role transfer and exact native regressions](../../crates/l2tunnel-aligned/src/packed_tests.rs).
- [x] [MOD-PACKREC-03] Test blocked native delivery, full recovery/batch storage, output/budget pressure, malformed late units, source/unit mismatch, rollback, expiry and finite retry exhaustion without false drain. Evidence: [nine packed composition tests](../../crates/l2tunnel-aligned/src/packed_tests.rs), [ordinary output-capacity regression](../../crates/l2tunnel-aligned/src/tests.rs).
- [x] [MOD-PACKREC-04] Run all ordinary aligned regressions and independent ownership review, strict checks and stable aggregate validation. Evidence: [17 focused tests](../../crates/l2tunnel-aligned/src/packed_tests.rs), [stable wave9 aggregate](../../work/implementation-wave9/validation.json); independent ownership review found no remaining blocker.
- [ ] [MOD-PACKREC-05] Add separately authenticated runtime/client selection and scoped native tests before claiming packed-wire parity or exposing a CLI option.

## Focused checkpoint

The exact protected transfer spans both endpoint roles, both custom UDP covers and
AEAD/integrity suites. Twelve units occupy three actual recovery sources; losing
the first source is repaired before RTO and delivers exact per-channel bytes.
Whole protected IP packets fit the configured MTU and all five systematic/repair
emissions use the common wire charge. This is an injected pure composition test,
not a UDP socket/native test or a claim about the simulator's different repair
schedule.

Pressure tests retain one sealed source after the real eight-source send window
fills, and retain a pending native frame while later recovery continues. Another
test has exactly four lookahead slots, an older pending native original and an
incomplete fragmented record; the next four-unit batch completes that record and
admits three later same-channel records. After actual pending commit, all four
deliver byte-exactly. No fake credit or widened reservation is used to unblock it.

Actual reliable packets carrying changed source/unit identities or a late invalid
context fail before native exposure and preserve the live unit floor. Exact native
expiry and two real ARQ retries terminate without reporting drain. Fresh clock
overflow rejects before time/context changes; overflow while fragment work remains
owned is sticky and retains diagnostic state. An independent read-only review
covered identity, memory, semantic preflight, sender commit and deadline ownership;
it found no material blocker. The ordinary digest literal was captured before
the shared serialization refactor and still matches.

The integrator owns the shared pure aligned endpoint changes, new packed module
and focused tests. Runtime/client/native workers must wait for its reviewed
checkpoint before depending on this capability.
