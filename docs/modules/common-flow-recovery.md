# Common same-flow transient UDP recovery

Status: **implemented and integration-tested in finite real paired UDP/Unix
native-device fixtures; affected strict checks pass**.
This is a concrete part of [SEC-08](secure-session.md), not completion of its
retained-state, peer-restart, carrier-replacement or default-policy requirements.

The existing Common Driver retains one Bank, Records owner, Control owner,
native FIFO and leased transaction on its original connected UDP socket.
Receive-side transient path errors already preserve those owners. Previously, a pre-accept
User send error escaped the loop and destroyed them. The correction
retains the actual immutable sealed output, its Engine output token, full packet
number, scope, original cap and already charged wire debit until that same UDP
socket accepts the whole datagram. It does not repoll, reseal, regenerate or
recharge the held output. Physical acceptance remains distinct from enqueue.

## Bounded behavior

- Only pre-accept `ConnectionRefused`, `HostUnreachable`, `NetworkUnreachable`
  and `NetworkDown` from a bare-UDP Common User send enter same-flow recovery.
  `WouldBlock` keeps its existing meaning. Other errors remain terminal.
- Retry service uses the existing explicit receive interval and same sole loop;
  no task, socket, allocation, cryptographic owner or independent FSM is added.
  A held shared carrier slot suppresses soft data/feedback wake opportunities,
  while actual retention/native expiry remains observable for every family.
  An already due Swift probe must not spin the loop before the next retry.
- New native admission and new local proposals stop while the path is unavailable.
  Existing native completion, Control/liveness, retained data and leased-operation
  service continue within their original work and storage bounds. A queued but
  unadmitted proposal keeps its first cap and is rejected when it expires.
- A fresh packet accepted by the existing same-session Records opener restores
  path availability. Failed authentication, replay, setup tails and local send
  success do not supply that evidence. This observation does not settle a data
  debt, transaction, native barrier or a peer-restart reconciliation.
- Original lease, outstanding Pong, native, operation, message and sealed-output
  deadlines keep their precedence. Recovery never extends or resets them.
  Cancellation still terminates the same owner. A failed retry at the cap does
  not consume a new packet number or manufacture a physical completion.
- A fixed inline runtime observation reports availability, actual pre-accept
  failures, actual retry attempts, authenticated resumptions, last I/O category
  and next retry time. APIv4 adds an optional projection; v1/v2/v3 stay unchanged.
  Existing actual owner-size accounting includes this inline state once.

This work does not replace a dead OpenVPN actor or install a new TLS/Noise proof
under an old E1/H0/catalog. Such replacement needs authenticated explicit resume
and reconciliation. It neither chooses the unresolved fresh-DH replay domain nor
enables a periodic key-exchange default. Same-flow packet loss and a fresh manual
reconnect remain distinct from complete automatic retained-state recovery.

## Acceptance

- [x] [CFR-01] Preserve the exact sealed bytes, packet number, scope, original Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
  deadline, Engine output token and debit across each selected transient send
  refusal, with bounded existing-cadence retries and no false physical handoff.
- [x] [CFR-02] Stop new native/proposal admission, continue existing bounded Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
  Control/native/transaction service and reject original expired queued caps.
- [x] [CFR-03] Restore path availability only through actual fresh protected Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
  same-session input; reject replay/authentication failures as recovery evidence.
- [x] [CFR-04] Exercise real paired UDP/native owners with retained nonempty Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
  data and transaction custody, exact resumed bytes, unchanged owner identities,
  continuing security numbers, no duplicate native write and original-cap errors.
- [x] [CFR-05] Expose actual bounded recovery observations through APIv4, keep Evidence: [finite Wave8 checks and preserved failures](../../work/parallel-features-20261115/parallel-wave8-scoped-validation.json).
  old API bytes unchanged, and pass the source-bound affected checks.

The named finite checks passed; the initial failed batch and exact repairs are
preserved separately. Full SEC-08, SREF, retained recovery across replacement/
restart, resource and platform gates retain their complete open definitions.

Executed focused cases are
`same_flow_retry_retains_actual_packed_token_native_debt_and_leased_operation`,
`same_flow_retry_keeps_original_cap_and_permanent_error_is_terminal`, and
`same_flow_recovery_observation_has_exact_bounded_fields_without_authority`.
The first uses genuine established paired UDP owners and a Unix native device;
its pre-accept error is injected at the existing send seam, not a privileged
kernel-outage claim. The old real fixture still requires every normal service
turn to leave the send-error counter unchanged; a test may now carry an earlier
explicitly observed failure without pretending that lifetime counter is zero.

Fresh protected input and replay rejection are exercised by the real-pair case.
Invalid-tag and setup-tail exclusion is additionally established by the existing
receive-path ordering before availability restoration; this is source evidence,
not a newly injected kernel-outage test. The held-Swift wake case proves that
expired soft sender opportunities cannot spin before the bounded retry.
