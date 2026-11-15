# Runtime Lifecycle refresh composition

Status: **implemented and finite composition-tested; actual Driver installation
and retained recovery remain open**, 2026-11-15. This additive controller is a consumer of the existing
[pure fresh-DH owners](session-refresh.md) and explicitly selected
[four-stream Lifecycle owner](lifecycle-control.md). It does not enable a default,
install itself into a Driver or qualify the full SREF/retained-recovery gates.

`secure_udp/session_refresh.rs` borrows the sole Records and Control owners. It
retains the real maintained Noise Exchange, its consuming Prepared guard and
final ConfirmationCache, rather than implementing another exchange/key FSM.
It owns no socket, task, counter or replay window. Reusable credentials are
provided by an explicitly retained runtime provider; every returned local key,
peer pin and PSK is rechecked by the actual Admission before fresh entropy.
Public Info and parsed Lifecycle bytes grant no authority.

The caller injects the original managed-Noise clock, original session/operation
caps, explicit retry/minimum-attempt intervals, attempt/work bounds and separate
seal/packet scratch. Four fallibly reserved fixed output buffers retain exact
typed messages and actual Control tokens. Request and activation are each one
immutable logical message: retries use that same real whole-message owner,
without creating another nested packet or reserving another packet number.
`capacity_bytes` reports those actual heap layouts only; maintained Noise,
Records, Control, credential backing, inline headers and shared scratch remain
separate owners. This is not complete resource admission.

Responder admission comes only from actual Records.open_refresh_request on the
original protected route4 packet. Noise flights are the existing context-bound
fixed bytes. Completion on either a local final write or peer final read prepares
the actual receive keys before that final message can be accepted/confirmed.
Local activation additionally waits for the local final message's whole
Confirmed proof. Retirement waits for actual peer activation, original overlap
and all outgoing Lifecycle custody. It preserves data scopes, continuing packet
numbers and the same replay owners. An expired admitted operation is terminal;
there is no automatic rollback, cap renewal or timeout recovery claim.

## Unresolved required wire-pressure gate

The existing nested request/activation and outer Lifecycle/Liveness records
share the same Management replay owner. Holding a nested packet while 4096 later
Management packet numbers authenticate can age that packet out before semantic
dispatch. The controller intentionally delegates to Records and refuses that
actual replay failure. This is a correctness gap requiring a reviewed domain/wire
solution; terminal failure is not accepted as pressure-progress qualification.
No domain/version change is selected or implemented by this module.

## Acceptance ledger

- [x] [RSF-01] Compile and execute the real-owner controller fixture, including maintained IKpsk2, actual member proof/allowlist/protected acceptance, both covers, reliable fragmented Lifecycle and actual key activation/retirement. Evidence: the three actual `secure_udp::session_refresh::tests` cases passed in the [finite exact-case batch](../../work/parallel-features-20261115/parallel-wave4-cases-attempt-1/validation.json); the separate Common stack failure leaves that aggregate failed.
- [x] [RSF-02] Verify work-per-turn one progresses both completion orientations, repeated refresh reuses output buffers, and data scopes/continuing numbers and replay remain owned by the same Records instance. Evidence: `actual_lifecycle_noise_refresh_preserves_scopes_numbers_and_reuses_fixed_outputs` in the same [exact-case receipt](../../work/parallel-features-20261115/parallel-wave4-cases-attempt-1/validation.json).
- [x] [RSF-03] Verify actual Liveness progresses while Lifecycle is held, the original request token/bytes remain retained, and original-cap expiry refuses continuation without resurrection. Evidence: `held_lifecycle_keeps_actual_request_token_and_liveness_until_original_cap` in the same [exact-case receipt](../../work/parallel-features-20261115/parallel-wave4-cases-attempt-1/validation.json).
- [x] [RSF-04] Verify authenticated Control plaintext without the original nested protection cannot mint a responder Admission or key context. Evidence: `authenticated_lifecycle_plaintext_cannot_mint_a_refresh_admission` in the same [exact-case receipt](../../work/parallel-features-20261115/parallel-wave4-cases-attempt-1/validation.json).
- [ ] [RSF-05] Resolve and test nested replay/key-generation pressure, complete
  same-Driver/socket/device installation, old sealed-output/native/transaction
  fences, full overlap/loss/late-I/O matrices and original retained recovery.

Three focused tests in `session_refresh_tests.rs` passed as an in-memory
composition of actual protocol owners. They do not execute a socket, native
device, installed Driver controller, periodic default or automatic recovery.
All original SREF01..08,
full resource, carrier/platform/native and full SW-11 definitions remain intact.
