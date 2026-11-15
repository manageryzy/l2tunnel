# Managed initial Noise/member handoff

Status: **implemented and focused UDP loopback-tested**, 2026-11-15. Strict
affected-package formatting, Clippy and rustdoc passed; the
[named receipt](../../work/parallel-features-20261115/parallel-wave2-managed-initial-scoped-validation.json)
records the four new cases and three directly affected existing entry cases.
This is prerequisite A of the
[session refresh contract](session-refresh.md), not runtime fresh-DH exchange,
Lifecycle control, retained recovery or complete SREF acceptance.

## Actual ownership

The explicitly selected
[establishment entry points](../../crates/l2tunnel-runtime/src/secure_udp/establish_refresh.rs)
use the existing cookie admission, bootstrap ARQ, socket reader and maintained
Noise loop. Only the actual selected
`finish_refreshable_with_confirmation` result supplies `ConfirmedInitial`.
The distinct opaque establishment type has no legacy-root conversion or public
constructor. Copied `Info`, bindings and endpoint observations cannot mint it.

The [selected member path](../../crates/l2tunnel-runtime/src/secure_udp/member_refresh.rs)
consumes that owner into the actual managed `InitialJoining` pair. The same
[member loop](../../crates/l2tunnel-runtime/src/secure_udp/member.rs) seals the
existing proof, verifies the real Ed25519 proof against the actual Allowlist,
and sends/authenticates the existing protected acceptance. It then consumes
`InitialJoining::retire`, dropping those exact Joining owners while retaining
their domain tombstones. Only this successful path returns selected
`Authenticated`/`Parts` with the opaque `ConfirmedInitial`.

Selected Parts retains the original connected socket, Noise clock origin,
absolute setup deadline, appearance counter and bounded bootstrap/Joining
ciphertext tails. Member work also observes the managed owner's actual minimum
Joining cap, including initial key age; neither a handoff nor a retry renews it.
Legacy entry points, default selection, public root handoff types and original
Joining bytes remain on their existing path. The combined receipt also passes
the existing explicit-streams/legacy native-byte and policy regression.

## Exact evidence and limits

The [case receipt](../../work/parallel-features-20261115/parallel-wave2-cases-attempt-1/validation.json)
records each of these four
[runtime tests](../../crates/l2tunnel-runtime/src/secure_udp/member_refresh_tests.rs)
as `passed`, with valid exact selection and stable source/binaries:

| Case | Qualified finite behavior |
| --- | --- |
| `actual_selected_member_handoff_installs_v2_on_original_socket` | Both covers and IK/IKpsk2, both actual roles, real member acceptance, retained origins/deadlines/pins/endpoints, then fixture consumption into v2 Records and protected User/Control bytes on the original sockets. |
| `selected_member_denial_and_context_mismatch_do_not_release_authority` | Wrong member context is refused before release; an actual unlisted member proof is rejected with typed observations. |
| `managed_joining_wakes_at_retained_key_cap_without_renewing_outer_deadline` | A silent peer retains managed custody, then expires at the retained key cap while the original outer deadline is still in the future. |
| `selected_dropped_acceptance_retries_original_ciphertext_after_key_owner_retirement` | Both covers recover a dropped acceptance using exact original ciphertext from the bounded tail; client release waits for authenticated acceptance. |

The enclosing batch remains **FAILED: 26 of 27 cases passed**. Its one failed
rolling-configuration fixture is retained in that receipt; these four individual
passes do not relabel the batch. The
[build receipt](../../work/parallel-features-20261115/parallel-wave2-build-attempt-2/validation.json)
and immutable test binaries bind this finite evidence. The separate
[source-stable strict receipt](../../work/parallel-features-20261115/parallel-wave2-strict-attempt-1/validation.json)
passes affected Clippy/rustdoc/format checks; no complete required check is inferred.

This handoff does not install selected v2 Records in the Common Driver, run an
in-session fresh exchange, add a Lifecycle stream, qualify authenticated fragment
custody, reserve the whole runtime resource envelope or reconcile retained data/
control/native/mode-transaction debts. The fixture's direct Records consumption
is not production Driver installation. Native devices, performance, additional
carriers, default recovery, CLI/GUI and platform acceptance keep their full gates.

## Narrow acceptance ledger

- [x] [MIH-01] Drive actual selected initial Noise and real member acceptance into opaque selected Parts, and verify original-socket protected v2 User/Control consumption for both covers and Noise profiles. Evidence: [first exact case above](../../work/parallel-features-20261115/parallel-wave2-cases-attempt-1/validation.json).
- [x] [MIH-02] Refuse mismatched member context and actual unlisted member proof without releasing selected member authority. Evidence: [second exact case above](../../work/parallel-features-20261115/parallel-wave2-cases-attempt-1/validation.json).
- [x] [MIH-03] Retain the original time domain and expire managed Joining at its actual key cap without renewing the outer deadline. Evidence: [first and third exact cases above](../../work/parallel-features-20261115/parallel-wave2-cases-attempt-1/validation.json).
- [x] [MIH-04] Retain/retry the exact protected acceptance after actual managed Joining owner retirement, releasing the client only after authentication. Evidence: [fourth exact case above](../../work/parallel-features-20261115/parallel-wave2-cases-attempt-1/validation.json).
- [x] [MIH-05] Complete source-stable strict affected checks and reconcile their exact receipts before checkpoint qualification; preserve failed attempts and all parent SREF definitions. Evidence: [strict checks](../../work/parallel-features-20261115/parallel-wave2-strict-attempt-1/validation.json), [named scope and preserved failed batch](../../work/parallel-features-20261115/parallel-wave2-managed-initial-scoped-validation.json).

MIH is a bounded prerequisite ledger. All original SREF-01..SREF-08 definitions
and unchecked parent status in [session refresh](session-refresh.md#acceptance-ledger)
remain unchanged.
