# Explicit streamed control in the Swift UDP runtime

Status: implemented and integration-tested for the finite local Unix scope below;
focused and required frozen-source aggregate checks passed. This is an additive
runtime checkpoint for SCM-07/SCS-07, not full generic management, SW-11 or native
performance qualification. The integration choices below are not owner decisions
about a final public wire protocol. Historical receipts and legacy defaults remain.

## Selection and authentication

`secure_udp::transport::Config.streams = Some(Settings)` selects three bounded
whole-message owners in fixed Transaction, Liveness and DataFeedback order. `None`
retains the original global L2SC sequence, source-ACK completion and canonical
configuration bytes. CLI construction still selects `None`; this checkpoint adds
no CLI option, GUI frontend or local API wire version.

The shared client Profile authenticates the explicit selection, wrapper version,
stream map, checked recovery-context derivation and every message/resource bound.
Both peers must agree before readiness or native attachment. There is no framing
guess or legacy fallback. Each stream preserves the base delivery settings, with
exactly eight additional wire-overhead bytes for L2CF. A separate aggregate packet
and byte quota, round-robin emission and the existing session IP-byte bucket bound
all three owners together. Independent contexts cannot triple the configured
control budget. Path/security-body validation and the two-packet control reserve
include the wrapper. Swift numeric policy changes retain the selected resource
bounds; a changed path MTU updates each stream's path geometry in both role configs.

One original UDP socket, Control AEAD sender/receiver, cryptographic counter and
replay owner remain responsible for all streams. The new runtime helper owns no
socket, timer, privileges or cryptography. It composes the existing pure message,
fragmentation, reliable delivery and stream-gate implementations with injected
time. No new recovery or cryptographic algorithm is introduced.

## Dispatch, custody and scope

The selected adapter admits SwiftPolicyV1 through Transaction and Ping/Pong through
Liveness. It explicitly rejects generic Management and DataFeedback bodies. The
third independent recovery context is reserved and bounded, not an implemented
generic feedback mode. Actual Swift feedback continues in authenticated User
records with its real source/feedback scopes and record numbers.

One immutable policy output retains its exact whole-message token until both the
peer's complete-message acceptance and original fragment custody are confirmed.
An ARQ ACK alone cannot complete it. Dispatch reserves its incoming ticket once;
receipt backpressure retains that ticket and retries acceptance without applying
the command again. The requester receives its terminal policy outcome only after
remaining source/semantic custody and reader settlement finish.

The original operation deadline remains owned when Swift's coordinator has already
produced an outcome. Refused first proposals also receive a bounded operation cap.
Per-message assembly/held expiry remains independently enforced; a fulfilled
message deadline does not shorten the entire policy operation. Absolute expiry
wakes are separate from credit-dependent emission wakes, so an empty wire bucket
cannot postpone timeout. Terminal failure retains bounded diagnostic custody.
Each newly admitted message uses the earlier of its operation cap, session expiry
and checked local message lifetime; failed local admission consumes no ID. A
fulfilled short-lived message permits later messages under the original operation
cap rather than expiring that whole operation.

The old data reader and stream origin retire only after that original operation's
custody settles. A complete command for the staged target waits in its actual
message owner until the target becomes active; waiting grants no staged authority
and does not block Liveness. Lost final receipts and back-to-back policy changes
must preserve the same connection, original caps, common crypto owners and exact
source IDs. This adapter still uses Swift's existing policy coordinator, rather
than the generic leased `transaction::Peer<C>`; it does not switch to RLNC, rolling,
packed, parity, proxy or another record profile.
Bounded semantic work is serviced on subsequent loop turns without requiring a
new UDP arrival. Budget exhaustion or an eligible complete message schedules an
immediate turn; an unchanged deferred target clears that trigger to avoid spinning.

The runtime Snapshot exposes `control_streams`, `policy_deadline_micros` and
`policy_receipt_pending`, including custody after coordinator `pending` becomes
empty. These embedding observations do not add requested/effective selection or
capability reporting to the existing strict local version1/version2 schemas.
Shared service, CLI and GUI selection/reporting remain an explicit open gate.

## Acceptance ledger

- [x] [SUC-01] Bind explicit backend selection and all resource/geometry fields through both actual authenticated client factories; preserve exact legacy configuration vectors, reject mismatches before readiness and retain numeric Swift policy/MTU support. Evidence: [source-stable focused pass](../../work/streamed-control-runtime-20261113/focused-attempt-4/validation.json).
- [x] [SUC-02] Integrate complete-message custody with actual Swift policy dispatch, original operation caps and delayed requester completion; test lost fragment/whole receipts and refusal before original source ACK on both original UDP cover pairs. Evidence: [source-stable focused pass](../../work/streamed-control-runtime-20261113/focused-attempt-4/validation.json).
- [x] [SUC-03] Integrate independent runtime-generated Liveness through a blocked Transaction beyond 128 envelopes, under one shared service quota, IP-byte budget and Control security owner; recover within the original operation cap. Evidence: [source-stable focused pass](../../work/streamed-control-runtime-20261113/focused-attempt-4/validation.json).
- [ ] [SUC-04] Qualify runtime terminal receipt-admission backpressure, exact expiry, stale feedback and back-to-back switch crossings across the complete bounded scheduling matrix without semantic redispatch or staged authority.
- [x] [SUC-05] Validate helper binding, grammar, capacity, atomic refusal, output pressure, aggregate quota/eligible ACK wakes, immutable expiry and bounded rotating liveness retirement; preserve legacy bytes and tests. Evidence: [source-stable focused pass](../../work/streamed-control-runtime-20261113/focused-attempt-4/validation.json).
- [ ] [SUC-06] Expose explicit requested/effective control-backend selection and complete custody/capability status through one shared service/client API, CLI and a non-CLI frontend, with schema compatibility and actual frontend tests.
- [ ] [SUC-07] Qualify saturated real TAP/TUN traffic, both covers, impaired networks and the full platform/lifecycle matrix with the selected backend; preserve all native performance targets and full SW-11.
- [x] [SUC-08] Pass frozen-source focused tests, strict Clippy/rustdoc and the required workspace check; retain failed attempts, exact commands/source identities and evidence-only ledger reconciliation. Evidence: [focused pass](../../work/streamed-control-runtime-20261113/focused-attempt-4/validation.json), [required pass](../../work/streamed-control-runtime-20261113/aggregate-attempt-1/validation.json) and [evidence-only reconciliation](../../work/streamed-control-runtime-20261113/aggregate-attempt-1/postcheck/ledger-1/validation.json).

SCM-07, SCS-05/SCS-07, FIX-11, SEC-07/08/10, all 47 P-* gates and full SW-11
remain open until their complete stated deliverables pass. This child ledger
does not replace or narrow them. Linux loopback/Unix packet-device tests are
runtime integration evidence, not privileged native or Windows/Android evidence.

## Validation evidence

The first focused attempt is preserved at
[focused attempt 1](../../work/streamed-control-runtime-20261113/focused-attempt-1/validation.json).
Its stable source passes 84 management, 85 selected runtime and 30 shared-client
tests; strict Clippy then rejects five new test-style violations. Those behavior
results do not constitute a full focused pass or cover later crossing/expiry fixes.
The earlier compile failure is also retained separately. No new native workload,
kernel profile, remote CI or non-Linux device result is inferred from these checks.

[Focused attempt 2](../../work/streamed-control-runtime-20261113/focused-attempt-2/validation.json)
passes 84 management, 91 selected runtime and 30 shared-client tests plus strict
Clippy/rustdoc with unchanged source inputs. It covers both-cover actual policy
refusal/custody and reordered final receipts across two policy epochs. Later
semantic-rescheduling and shorter-message-lifetime corrections require their own
fresh validation; the earlier pass is not promoted to those changed bytes.

[Focused attempt 3](../../work/streamed-control-runtime-20261113/focused-attempt-3/validation.json)
retains 84 passing management tests and 94 passing runtime tests, with one failed
new no-ingress fixture before it reached the intended retained-custody state.
The failed setup is preserved; shorter-message-lifetime cases passed, but this
attempt is not an overall focused pass and did not run its later commands.

The [targeted no-ingress pass](../../work/streamed-control-runtime-20261113/no-ingress-targeted-attempt-2/validation.json)
uses a real one-source receive window and a matching Pong that consumes the sole
semantic slot. The next policy command dispatches once on a bounded outer service
turn without another incoming UDP packet, preserving original custody and a
unique semantic receipt. Both covers and three actual work-phase alignments pass.
The preceding targeted attempt, whose fixture never reached the discriminating
cut, remains failed rather than having its coverage assertion removed.

[Focused attempt 4](../../work/streamed-control-runtime-20261113/focused-attempt-4/validation.json)
passes 84 management, 95 selected runtime and 30 shared-client tests, strict
three-package Clippy and rustdoc with unchanged inputs. Nineteen backend tests
cover separate message/operation caps, atomic admission, fixed quota and readiness;
seven streamed transport cases include independent actual run loops, 130 liveness
rounds, exact receipt loss/refusal and both policy-scope crossings. The work-one
crossing uses an explicitly documented paused authenticated receive prefix; it
is not a full native lab. Runtime Parts fixtures use an independently authenticated
fixed test digest; separate actual factory cases bind the real Profile contract.
No single new CLI-selected native composition is claimed from those separate tests.
Generic dispatch, the complete pressure/feedback matrix, API/frontend selection,
native saturation and other platforms remain open.

The [required aggregate](../../work/streamed-control-runtime-20261113/aggregate-attempt-1/validation.json)
passes `tools/check.py` with 1613 Rust cases including doctests, 295 Python tooling
cases and 1658 simulator cases. Formatting, strict workspace Clippy, rustdoc and
ordinary CLI/loopback checks pass with unchanged input maps. The
[environment record](../../work/streamed-control-runtime-20261113/aggregate-environment.json)
retains serialized Rust tests; no assertion, original deadline or workload target
was relaxed. All earlier failed focused/fixture receipts remain preserved. This
local Linux check does not run privileged networking or qualify non-Linux devices.

The [evidence-only ledger reconciliation](../../work/streamed-control-runtime-20261113/aggregate-attempt-1/postcheck/ledger-1/validation.json)
passes after recording these outcomes: every non-document input still matches the
aggregate, changed local links resolve and stable checklist IDs remain unique.
Final checkbox/provenance prose receives a second reconciliation before commit.
