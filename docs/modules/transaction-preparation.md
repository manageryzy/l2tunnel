# Read-only preparation before leased admission

Status: **implemented and protocol-tested; selected runtime consumption pending**. This is a prerequisite
for actual GSU-04/GSU-05 driver integration, not a second management state
machine, an owner decision or completed SW-11. The
[source-reviewed draft](../../work/generic-secure-udp-20261114/preparation-preview-design-v0.md)
describes the existing admission gap and exact source binding. All original
carrier, lifecycle,47-mode, platform and80 Mbit/s requirements remain in scope.

## Additive public interface

```rust
pub struct Preparation<C: transaction::Configuration> { /* private fields */ }
impl<C: transaction::Configuration> Preparation<C> {
    pub fn identity(&self) -> transaction::Identity;
    pub fn ticket(&self) -> l2tunnel_session::Ticket;
    pub fn origin(&self) -> session_control::Scope;
    pub fn expires(&self) -> transaction::Tick;
    pub fn config(&self) -> &C;
}
impl<C: transaction::Configuration> transaction::Peer<C> {
    pub fn preview_propose_until(&self, config: &C, now: Tick, expires: Tick)
        -> Result<Preparation<C>, transaction::Error>;
    pub fn preview_receive_until(&self, verified: Ingress, bytes: &[u8],
        now: Tick, expires: Tick)
        -> Result<Option<Preparation<C>>, transaction::Error>;
    pub fn phase_deadline(&self) -> Option<Tick>;
}
impl control_streams::gate::Gate {
    pub fn preview_transaction<C: transaction::Configuration>(
        &self, peer: &transaction::Peer<C>, verified: Ingress,
        stream: control_streams::Stream, input: &[u8], now: Tick, expires: Tick,
    ) -> Result<Option<Preparation<C>>, control_streams::gate::TransactionError>;
}
```

Preparation is an owned validated intent with immutable getters, no public
constructor and no Clone/Copy requirement. It is not Operation, authentication,
memory reservation, an admitted request, epoch authority or a commit token.
Preview does not advance time, mutate guards/counters/replay/caches, assign a
lease candidate, allocate request/packet IDs or invoke an effectful callback.
Both Peer previews require the explicitly leased contract. They validate the
same original cap and currently admissible configuration/source/ticket as the
actual call, which must revalidate immediately before mutation.

The local preview shares one immutable helper with the real local proposal;
it does not duplicate attempt/epoch arithmetic or configuration validation.
The remote preview first shares the actual AdmissionGate's immutable candidate
checks: binding, frame grammar, retirement/replay candidate, exact repeated
request bytes and bounded request/byte custody. Refactor those checks out of
`admit`, then keep actual fallible body retention and mutation in `admit`.
Factor first-PREPARE decode/semantic validation once for real request, leased
validation and preview. Preserve existing effectful error ordering and wire
bytes, old constructors, exact global-sender widths and256 generic channel limit.

Remote Some means a new first Server PREPARE that actually requires Stage.
Exact repeated/cached PREPARE, valid first REJECT and preflight-valid ordinary
operation input return None. Replayed/conflicting/retired requests, wrong
binding/cap/fence/configuration, unsupported targets or a full ledger return
their existing errors before target allocation. None does not replace actual
semantic admission. A new numbered PREPARE in an active operation must not be
classified as a second target.

The outer Gate preview reuses its actual transaction-bound contract, full
authenticated session/role/lane, stream/grammar, prospective outer sequence,
active/draining/exact-retained origin and original-cap checks before the Peer
preview. Neither sequence is committed. Liveness/DataFeedback/ProfileControl
cannot cause target preparation. Old-origin cached/final exceptions remain
narrow actual Peer witnesses; they never reopen old User authority.

`phase_deadline` returns the existing stored phase deadline when neither Idle
nor Failed, otherwise None. It samples no clock and changes no timer. Existing
`next_deadline` behavior is preserved. Original operation/session/message caps
still apply to Idle final custody and blocked output; overdue phases must be
observed through the real effectful service, not repeatedly reset or spun on.

## Actual runtime consumption required

The selected driver must retain the actual `swift::storage::Set::prepare(Plan)`
EngineId matching the exact intent before `propose_until` or joint receive.
On remote input, the runtime borrows the actual pending whole message, keeping
its ticket, exact original deadline and bytes. No pop/copy-and-forget or second
PREPARE parser is introduced. Preview/gate/resource failure burns no envelope
identity. The original cap is frozen once; blocked views do not recalculate it.
After construction, resample injected time and revalidate. Expiry/failure before
Stage releases only the still-virgin target; after real Stage, normal actual
action/abort/commit/physical-fence rules govern it. Never recreate the old engine
or fake a data/whole-message receipt.

This module does not guarantee arbitrary C Clone allocations, prepare Swift
engines, reserve shared native/control storage or consume runtime I/O. Combined
resource admission and the real driver remain separate GSU-05/SRS-07 gates.
Runtime Control's borrowed pending view and State consumer are tracked in the
parent [generic integration module](generic-secure-udp.md).

## Ownership and tests

The preparation worker owns only management crate source/tests: AdmissionGate,
transaction helpers and control-stream Gate. Root owns runtime/client wiring,
exports outside that crate, ledgers, formatting/build/check execution and Git.
No new dependency, wire version, real clock, socket, OS handle, privilege or
unsafe exception is introduced. Reserve exact bounded work; generic config
length and existing256/packed255/Swift64 distinctions remain unchanged.

- [x] [MPR-01] Record the pre-edit interface, shared validation design, failure/custody rules and source binding before implementation. Evidence: [frozen focused checks](../../work/generic-driver-20261114/focused-attempt-3/validation.json).
- [x] [MPR-02] Implement the shared immutable admission/local-proposal/first-PREPARE validation and both read-only Peer previews with exact nonmutation/error compatibility. Evidence: [frozen focused checks](../../work/generic-driver-20261114/focused-attempt-3/validation.json).
- [x] [MPR-03] Implement outer joint-Gate preview and actual stored phase-deadline observation without changing effectful admission or retained retry authority. Evidence: [frozen focused checks](../../work/generic-driver-20261114/focused-attempt-3/validation.json).
- [x] [MPR-04] Test actual asymmetric peers and encoded envelopes: repeated preview then actual Stage, replay/conflict/full ledgers, cached/final retries, no-Stage REJECT, wrong scope/role/width/digest/cap, phase/operation expiry and exact sequence/ID preservation on refusal. Evidence: [frozen focused checks](../../work/generic-driver-20261114/focused-attempt-3/validation.json).
- [x] [MPR-05] Run focused/strict/required source-frozen checks and save a coherent local checkpoint; retain actual runtime integration and every parent acceptance gate until their complete tests pass. Evidence: [required frozen checkpoint check](../../work/generic-driver-20261114/checkpoint-aggregate-attempt-2/validation.json) and [exact WIP restoration](../../work/generic-driver-20261114/checkpoint-isolation-attempt-2/validation.json).

Tests must drive real Peer/AdmissionGate/outer Gate calls, compare preview with
the subsequent actual effects and verify failing previews leave the same future
request admissible. A mocked reservation, boolean permit, successful compile or
configuration-only constructor cannot close runtime preparation or SW-11.

The root [focused attempt3](../../work/generic-driver-20261114/focused-attempt-3/validation.json)
passes120 management cases (including12 new preparation and4 read-only message
clock cases),142 existing/new selected UDP cases,14 authenticated generic-plan
cases and strict management Clippy with stable compiled inputs. The bridge in
those142 cases is still an independently tested unselected runtime component.
The [source-only review](../../work/generic-driver-20261114/mpr-review-v0.md)
found no material defect; it is separate from executed checks. No native lab,
platform or performance measurement was run for these new helpers.

The required checkpoint check passes1812 Rust cases including doctests,376 tooling cases and1658 simulator cases with stable inputs. This exact checkpoint excludes/restores the unselected three-file Control bridge; unregistered engine-Bank/State work is not compiled or qualified. Strict workspace Clippy, formatting and rustdoc pass. No fresh native lab, Windows/Android build, device test or performance measurement is claimed. Full generic integration and parent gates remain open.
