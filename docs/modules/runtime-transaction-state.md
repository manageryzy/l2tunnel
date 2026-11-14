# Selected generic transaction custody

Status: **implemented; fourteen focused State cases and finite selected-Driver integration pass**. Implements
the existing actual leased Peer and Control-owner composition, not another FSM,
I/O loop or crypto sender. Clean original-socket/native integration passes; complete fault/resource/shared-API qualification remains open.
All SW-11/profile/carrier/platform/lifecycle/performance requirements remain.

The [required source-stable check](../../work/generic-driver-20261114/driver-aggregate-attempt-1/validation.json) passes1878 Rust
cases including doctests,376 tooling cases and1658 simulator cases. This local
Linux result does not close the complete parent resource, fault, shared-API,
profile, native, platform or performance acceptance.

The detailed design is the source-reviewed
[transaction state draft](../../work/generic-secure-udp-20261114/transaction-state-design-v0.md),
SHA256 `681259ce9bcc95e4d529dd1422953c4a42e6ead2d2ead8e4e8c63c53711f7bd1`.
Apply its bounded work/output,
real borrowed proofs, terminal custody and immutable cap rules with these exact
integration refinements before production edits:

- `secure_udp/transport_transaction.rs` is private to the existing transport.
  It owns the actual `transport_engines::Bank`, one actual Peer and the draft's
  bounded custody. Owner remains borrowed from the existing parent.
- State::new takes the draft's eight arguments plus an actual Bank as its final
  argument. Revalidate Bank initial/epoch and derived actual delivery binding.
  TransactionSettings is the actual shared runtime value. No fake resource
  callback, boolean permit, separately mirrored phase or fresh engine on commit.
- `propose(owner,value,cap,sample)` takes the actual queued local request's
  once-frozen `cap: transaction::Tick`; the parent retains it across Blocked
  retries. It never computes a later cap for the same local request. The real
  Peer validates that cap against now, max_operation_ms and session expiry.
  `dispatch(owner,sample)` freezes its remote admission cap once as below.
  Both take `sample: impl FnMut() -> io::Result<Duration>`. Sample before preview and again
  after real target allocation. Both actual Peer entry points are still retried
  only after capacity and original-time validation. No clock lives in State.
- Local proposal obtains actual Preparation, allocates actual Bank::prepare,
  resamples and revalidates before real propose_until. Remote dispatch borrows
  Owner::preview_transaction, freezes Incoming+original cap once, allocates only
  for Some(Preparation), releases borrow/resamples and rechecks exact Incoming
  plus intent before joint dispatch. On pre-admission failure cancel only that
  actual virgin target. Never renew the cap or consume a substitute ticket.
- State retains the real Prepared until the Stage action completes. That action
  calls actual Bank::stage followed by Peer::staged only after parent readers
  and stop-admission boundary exist; preflight output/effect capacity before
  mutation. Actual Applied Committed/Retired/Aborted events call Bank commit,
  retire or abort after root performed its physical/crypto action. Uncertain
  never authorizes Bank abort. Cancelled Stage/Drain preserves the actual
  interruption event and releases only a genuinely virgin preparation.
- Stage work and physical action remain guarded: repeated extraction returns
  None; foreign/completed Action fails; Blocked completion never repeats an
  irreversible bank/Peer operation. Admission additionally requires no pending
  lifecycle action and actual Peer admission_allowed.
- Expose forwarding accessors `engine(epoch)`, `entry(epoch)`, `current()`,
  `epoch()` and `usage()` delegating to the actual Bank so the existing loop
  can use that same owner. Do not allocate a second legacy Swift engine.
- The draft's three actual frozen output slots, original Operation, single
  incoming/effect/action/outcome guards, borrowed Accepted/Confirmed callbacks,
  exact logical retry coalescing, terminal proof ordering and narrow retained
  origin retirement rules remain binding. Keep the emergency third slot for
  phase-timeout abort; do not consume it for ordinary semantic advancement.
- Implement service, action/completion/outcome APIs from the draft. Resample and
  observe due phase expiry before ordinary proposal/dispatch/completion, retain
  original operation cap while Peer releases it, and avoid retry busy spinning
  under bounded output pressure. All runtime errors remain explicit.

Bank accounting still includes a caller-accounted external charge. This State
must not claim that control/Peer/shared runtime owners are fully reserved yet.
Combined resource admission and actual generic runtime selection remain separate
mandatory acceptance; do not prune authenticated catalogs to fit memory.

- [x] [TCS-01] Freeze exact custody/resource/proof interfaces before implementation. Evidence: [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json).
- [x] [TCS-02] Consume actual prepared Bank, actual leased Peer and actual Control Evidence: [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json).
  messages/proofs with focused failure/capacity/retry/terminal tests.
- [ ] [TCS-03] Integrate this owner into the existing selected I/O loop and prove
  physical barriers, requested/effective API status and original-socket behavior.

The reliable whole-message owner owns ordinary retransmission once the actual
current logical Peer output has frozen custody. State service must not call
Peer.poll merely to burn a fresh inner packet ID/reallocate an output it will
coalesce. It still observes actual original phase/operation/session expiry and
uses genuine joint dispatch for new input. Test heavy ordinary service beyond
retry time while retaining/confirming the exact first envelope, without a new
inner packet identity; timeout abort/reconciliation still progresses.
