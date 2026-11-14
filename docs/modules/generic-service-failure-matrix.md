# Actual generic service failure and lifecycle matrix

Status: **implemented and finite local service integration-tested**.
The preceding generic service/CLI checkpoint has finite local integration
evidence. This additive test batch exercises still-missing failure boundaries;
authored tests and successful compilation are not passing runtime evidence.
This contract is not an owner scope decision or a new default.

The test-only fixture seam and15 regressions run beneath the existing paired
service test module. Together with the preserved two-switch success case, all16
pass in the focused and required combined checks. Fixtures use actual
authentication and UDP sockets with UnixDatagram PacketDevices; they are not
production TunTap or GUI tests.

The unchanged parent [GCS-07](generic-client-service.md) remains:

> Exercise two actual shared service owners on both covers with nonzero
> asymmetric native traffic and at least 2 complete configuration switches, plus
> credential/setup/attachment/cancel/reconnect/owner-drop/duplicate-key/failure
> cases; separate typed/IPC evidence from native and GUI claims.

The existing actual two-switch test remains intact. Legacy SwiftPolicyV1 setup
negatives and logical atomic-local fixtures remain separate evidence; they do
not satisfy missing generic runtime cases. This batch does not close GCS-06/09,
native CLI/TAP qualification, full resource admission, all GDF fault/pressure,
full SW-11, other carriers/record profiles, recovery/rekey, GUI/platform or the
80 Mbit/s gate. All47 mode-parity requirements remain unchanged.

## Exact test-only fixture seam

Keep the existing private `transaction_plans(appearance, hosts)` call boundary.
Its explicit test baseline is unchanged:3s accepted setup timeout, IK with no
PSK, matching44-byte-pattern admission inputs, server-only55-byte-pattern cookie,
16MiB retained ceiling, independent original application seed31, no periodic
reports, and complete2/3→4/1 catalog. These fixed public test values are not
provisioning examples or product defaults.

Add privately inside the same test module:

```rust
#[derive(Clone, Copy)]
struct TransactionFixtureOptions {
    setup_timeout: Duration,
    noise_profile: hs::Profile,
    psk: [Option<[u8; 32]>; 2],
    admission: [[u8; 32]; 2],
    retained_bytes: usize,
    report_interval: Option<Duration>,
}
impl TransactionFixtureOptions {
    fn baseline() -> Self;
}
fn transaction_plans_with(
    appearance: Appearance,
    hosts: &[Arc<Host>; 2],
    options: TransactionFixtureOptions,
) -> Result<TransactionPlans>;
```

The old helper delegates with `baseline()`. Apply options to original raw
Settings/ConnectionConfig before the actual transaction Profile constructor.
Keep raw gate bounds unchanged unless explicitly selected above; the original
accepted setup timeout remains an outer bound across those stages. Never feed
an already-derived generic Profile.settings() into another generic digest graph
or mutate Prepared's connection after validation. Keep complete actual validators
and credential constructors. Do not expose secrets through Debug/status.

The baseline report interval stays None. Only the in-flight failure fixtures
select an explicit1ms interval so an actual post-handoff snapshot can prove
Control/socket progress before owner loss; a semantic phase observation can
precede that handoff. Copy the selected cadence into both role templates before
Profile construction. It remains local reporting, excluded by the existing
runtime from peer identity, and grants no protocol or timing authority.

New child files register locally in `secure_udp_transaction.rs` and can reuse
its checked helpers and ancestor Host/Pipe fixtures. No service.rs, owner.rs,
setup.rs or public API mutation is authorized by this test contract. A newly
found production defect requires a discriminating regression and a separately
frozen narrow repair contract before its implementation.

## Bounded actual cases

Use both appearances for each case. Drive actual generic Prepared, real sockets,
Noise/member factories and original service Run owners, except the explicitly
controlled membership peer below. Bounded test harness timeouts do not replace
assertions about the actual accepted or Peer operation deadline.

1. Queue a200ms generic Connect while fixture ports are occupied, advance exactly
   to the original accepted deadline before first polling, and require Accepted
   stage/OriginalDeadline with no socket packet/provider/generation. Separately
   fail an actual occupied bind for both roles and observe SocketBind/LocalIo.
2. Run same-public-H0 generic admission-secret mismatch and IKpsk2 PSK mismatch.
   Observe actual typed stages/reasons without guessing authentication from a
   timeout. A matching-PSK control must authenticate and carry nonzero traffic.
   For actual member rejection, retain one real generic shared-service server;
   a controlled direct test peer uses existing establish::connect with the
   checked actual profile, then member::connect with a second nonallowlisted
   maintained Ed25519 identity. Context comes only from its actual completed
   root/binding/peers. This is one shared owner plus a deliberate protocol peer,
   not two shared owners or fabricated authentication. Wrong member/pins/pattern
   constructor refusals remain existing pure Prepared evidence.
3. After actual membership, fail the deferred opener with a private sentinel;
   separately return a safe InvalidDescriptor(-1); separately use scalar-valid
   retained budget1 so actual reserved admission fails before readiness. Verify
   exact stages, no secret/provider text, device drop and original-port release.
   Budget refusal is not injected allocator exhaustion.
4. Cancel before first poll, during actual Admission, and from the authenticated
   readable opener after it created an actual device. Release partial owners
   before terminal publication, keep actual stage/outcome and reject stale
   observation refresh. Do not install a logical backend as runtime evidence.
5. Drop actual Run before polling, during Admission and after real ready/native
   transfer. Observe OwnerClosed only for pending setup, retain completed setup
   records, and overlay active terminal without altering actual runtime facts.
6. Expire a queued reconnect before polling while the old actual generation is
   still owned. Preserve its socket/device/generation and fresh packet delivery;
   a later valid reconnect must release the old owner before replacement opens.
   The fixture reuses the exact baseline Prepared and its real3s accepted bound,
   with paused time; it does not construct a shorter replacement contract.
   Explicitly check the old lease/Pong caps remain longer. The distinguishing
   behavior is expiry before destruction of the old owner, independent of the
   configured timeout value; this engineering refinement removes no gate.
7. Reuse the exact Prepared clone after cancellation or a temporary local failure,
   then successfully authenticate. Preserve exact retained server admission and
   immutable old setup observations. An independently constructed equivalent
   server Prepared retains a separate admission owner. This is manual fresh
   reconnect, not retained-outage recovery.
8. Verify Connect exact-key replay, equivalent-new-plan Conflict, FutureKey and
   the32-entry/40-operation retirement boundary with actual generic Prepared.
   Clearly label unpolled history-only sections as local admission evidence.
9. Drop an actual apply waiter, replay/conflict the same key, reject cancellation
   of applies, and require one actual switch. After real disconnect/reconnect,
   retained old key replay returns the old operation/result without applying to
   the new session. Fresh foreign-E/unlisted C refuses before key consumption.
10. Observe an actual retained generic operation and outgoing Control/socket
    progress before dropping the applying Run; require OutcomeUnknown and exact
    terminal overlay. Separately cross its snapshotted original operation cap
    with the actual runtime alive and peer unpolled; require runtime failure and
    OutcomeUnknown, never invented rollback/completion. Independent liveness may
    emit, so do not infer zero total packets from local command refusal.
11. Submit a supported C through the actual responder service; require completed
    version3 NotCoordinator rejection and unchanged current C/epoch, distinct
    from pre-admission catalog refusal and lost-custody OutcomeUnknown.

The detailed source-backed sequences and inspected hashes remain in the
[pre-implementation assessment](../../work/generic-transaction-cli-20261114/next-service-failure-matrix-v0.md).
Use original scalar validators and actual observed error categories. A receiver
message's local lifetime, sender frozen deadline and Peer operation cap are
different owners; never equate or renew them for a test.

## Ownership, validation and stable children

The assigned worker owns this module, the test-only fixture seam and locally
registered child test files. Root alone formats, builds, tests, records receipts
and commits. Other functionality can be integrated in parallel, followed by one
combined focused/required aggregate validation. Preserve failed attempts and
report exact source snapshots. No new native/performance workload is selected.

- [x] [GSF-01] Freeze exact test-only fixture/API, actual-owner sequences, ownership and source binding without changing the full GCS-07 parent definition. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-02] Implement fixture options before original Profile derivation, preserving baseline helper inputs, complete validators/catalog and existing two-switch assertions. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-03] Exercise exact queued expiry and actual client/server bind failure with zero unopened provider/socket effects and immutable setup observations. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-04] Exercise actual admission/IKpsk2 failures, matching-PSK success and controlled actual member rejection, preserving precise generic versus controlled-peer provenance. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-05] Exercise authenticated provider, readiness descriptor and actual retained-budget refusal with exact stage, sanitization and owner cleanup. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-06] Exercise queued/in-flight/authenticated-opener cancellation, original deadlines and stable stale-callback refusal through actual generic setup. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-07] Exercise unpolled/in-flight/ready actual Run drop with correct setup terminalization, actual runtime overlay and socket/device release. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-08] Exercise expired queued reconnect preservation, successful recovery from temporary failure/cancel, exact plan/admission authority and old-before-new release ordering. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-09] Exercise exact generic Connect/history and actual apply waiter/key/cancel/catalog/replacement semantics without installing an invented authenticated backend. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-10] Exercise observed actual in-flight apply owner loss and original-cap runtime failure with OutcomeUnknown and unchanged requested/effective truth. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-11] Exercise actual responder NotCoordinator completion separately from catalog pre-admission refusal and OutcomeUnknown. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GSF-12] Run combined new generic, preserved success/legacy/atomic and required source-stable workspace checks, with exact commands, failures and finite-platform limitations before reassessing parent status. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.

## Checkpoint evidence

The [full baseline](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json) passed with unchanged recorded inputs:2011 Rust cases including
doctests,406 tooling and1658 simulator cases. The subsequent [affected completion repair](../../work/generic-functionality-20261114-batch2/completion-projection-focused-attempt-1/validation.json)
passes77 affected service/local cases with4 test threads and strict client-core
Clippy after the narrow APIv3 completion repair. Only owner.rs and its existing
generic failure test changed outside documentation. Unchanged protocol, tooling
and simulator evidence is reused explicitly; the full baseline is not relabeled
as a new post-repair full run. Native acceptance remains separate and unqualified.
