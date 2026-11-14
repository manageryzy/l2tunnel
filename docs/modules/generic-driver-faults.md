# Generic Driver fault validation

Status: **actual-handoff fixture and finite protected loss/reorder/cached-final
cases implemented; the complete fault matrix remains partially verified**.
This is an engineering refinement of the existing
[generic runtime](generic-secure-udp.md) GDI-02/GDI-03 gates. It preserves their
complete definitions, full SW-11/cross-profile requirements, all47 mode-parity
requirements, RLNC/parity/rolling/packed/proxy, independent DataFeedback and
NativeReceipt consumers, every carrier/platform/lifecycle gate, combined resource
reservation, and the original80 Mbit/s target. It selects no new wire format,
default, provisioning, deployment or owner decision.

The preceding runtime-library checkpoint has finite clean original-socket and
physical native-device evidence, including two nonzero asymmetric Swift
transitions. Its existing six Generic and fourteen State cases are not a claim
that this fault matrix, a public-loop impaired session or a privileged native lab
passed. Historical receipts remain unchanged. The ignored
[earlier assessment](../../work/generic-driver-20261114/next-fault-validation-v0.md)
is background; the exact contract below controls this implementation wave.

The current eleven compiled Generic cases include two-buffer budget/ownership
checks, the genuine source-loss/PREPARE-reorder case and protected cached-final
coalescence on both covers. These do not close every row: independent READY/
Barrier loss, selected proportional repair, the full stale/current replay and
staged-target cases, final-acceptance pressure and terminal native-pressure
matrix remain open. The shared-service fixture now supplies the clean actual
public-loop/two-switch/liveness/cancellation subset separately. Required aggregate
verification passes; unresolved fault rows retain their complete definitions.
The [current source-stable focused receipt](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json)
passes all eleven compiled Generic cases and the paired-service/public-loop case,
alongside existing component regressions and strict Clippy. Failed experimental
attempts below remain preserved and do not become passing fault-matrix evidence.

The cached-final case separately requires an actual repeated final SourceId and
identical payload under a newer protected Control number, and a genuine fresh
logical RETIRE reaching the real joint preview with no Preparation. Ordinary
ARQ duplicates can be consumed below semantic dispatch; they are not evidence
that a second joint preview ran. GDF-03 retains its full literal row5 requirement
and remains partial. The assertion does not manufacture a Gate callback.

## Unreached final-acceptance pressure construction

GDF-02 and the complete row4 below remain **unverified**. The
[source-stable fifth focused attempt](../../work/generic-driver-20261114/functionality-focused-attempt-5/validation.json)
passed the other ten Generic cases, including the protected cached-final retry
and source-loss/reorder cases, but failed the experimental final-acceptance
pressure precondition. Its [actual failure log](../../work/generic-driver-20261114/functionality-focused-attempt-5/generic.log)
and [complete unchanged test source](../../work/generic-driver-20261114/gdf02-unreached-attempt-5.rs)
are preserved. The latter has SHA-256
`5a59cb9ec572bf7a4dd8ad52ea40ae9d87b886bac8f9befcaa0109660ab821be`.
Only that unsuccessful experimental test has been removed from the compiled
child; it has no ignored/skipped passing replacement. This defers the test
construction, not its requirement or the GDI-02 parent gate.

The actual five-slot schedule isolated and retained the two Commit sources,
then withheld Transaction ACKs. It stopped with the client in AwaitRetireAck,
the server in FollowerCommitted, no Retire envelope observed, no physical
retirement/outcome and no pending final acceptance. Actual client sources8/9
were the192/90-byte Commit fragments, source10 was a genuine45-byte Accepted
receipt, and source11 was the192-byte first Retire fragment. Those four records
retained519 bytes. The normal message submitter preserved its final receipt
slot, preventing the remaining Retire fragment from being submitted. The older
three-slot attempt likewise stalled before Retire completed. Neither result
exercised final receipt admission pressure.

The current State service order accepts the incoming CommitAck after retaining
an unsubmitted Retire FrozenOutput, then submits its fragment sources in the
next output-service step. Thus an arithmetic sum assuming all Retire fragments
precede that real Accepted receipt does not describe this schedule. The existing
Control receipt-pressure test uses an auxiliary underlying message, while the
passing State cases separately exercise normal output capacity and cached-final
coalescence; none proves the required genuine terminal schedule. Further work
must construct a valid packet/action ordering under the actual source-span,
reserved-receipt and leased-dispatch rules. No infeasibility, owner decision,
implementation correction or reduction of row4 is inferred from these failed
fixture constructions.

## Sole-owner test composition

Implement a new `transport_generic_fault_tests.rs` child of the existing
[Generic runtime tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_generic_tests.rs).
It reuses their actual `parts_pair` Noise/member roots, original connected UDP
sockets, checked `TransactionContract`, production `Driver`, reserved engine
Bank/leased State, common Records security, control Owner and Unix PacketDevice.
The test-only `Box<Driver>` reduces fixture-future stack size; it is not claimed
as production resource admission. No test may construct an additional actual
Peer, recovery owner, crypto reader, native completion ledger or I/O reader to
stand in for the production owner.

The only initially required existing-fixture seam is:

```rust
impl Fixture {
    async fn from_contracts(
        kind: cover::Appearance,
        contracts: [TransactionContract; 2],
    ) -> Result<Self>;
}
```

Existing `Fixture::new(kind)` delegates to `from_contracts(kind, contracts(kind)?)`.
Its original setup, tail expiry, native construction, assertions and successful
cases remain unchanged. The new child builds complementary checked contracts
from the actual existing catalog/templates, with `work.send_batch = 1` and
selected smaller recovery windows established before construction. Each stream's
Delivery settings remain equal to the aggregate base plus its actual8-byte L2CF
overhead. Whole-message bounds must carry the actual canonical PREPARE and READY
through the smaller window. No immutable live configuration is changed to create
pressure. A later proportional-repair case must likewise select that complete
canonical data policy in both contracts before construction.

Direct runtime fixtures retain the setup helper's H0 `[3;32]` and compute the real
canonical D0 separately. They prove the runtime ownership/epoch composition, not
rederivation of the separately tested client Profile authentication graph. Runtime
fault tests do not alter CLI/service defaults or version1/version2 API bytes.

### Frozen new-child fixture API v0

The following names are test-only interfaces, not public runtime APIs:

```rust
enum Route { Deliver, Drop, Hold(u8) }

struct Flight {
    from: usize,                 // checked0 or1
    number: security::PacketNumber,
    wire_bytes: usize,            // complete actually charged IP bytes
    wire: Vec<u8>,                // exact post-handoff ciphertext
    // Bounded diagnostic class/stream/SourceId/fragment/receipt observations.
}

struct FaultFixture {
    inner: Fixture,
    // Bounded held flights and append-only diagnostic attempt ledger.
}

impl FaultFixture {
    async fn new(kind: cover::Appearance, pressure: bool) -> Result<Self>;
    async fn turn(&mut self, route: impl FnMut(&Flight) -> Route) -> Result<()>;
    fn release(&mut self, tag: u8, reverse: bool) -> Result<usize>;
    fn replay(&mut self, captured: &Flight) -> Result<()>;
}
```

`turn` advances injected protocol time by exactly1000 microseconds using checked
arithmetic. It uses the existing production prefix: expiry guard, actual
`admit_transaction`, native collection, `progress_transaction`, selected control
service, submission and `send`. It receives each successful actual socket handoff
from the opposite original socket under the existing one-second I/O bound before
applying the test fault. It then runs actual native collection/write/progress.
No fixture deadline extends the original Peer/message/operation/liveness/native
cap. A predicate may inspect a Flight; it may not mutate protocol state.

`release` and `replay` present captured bytes to that original destination's
production `receive_selected`, with its current injected time and original
Instant origin. They perform no new sender handoff or wire charge. A release
consumes the exact held flight once; replay intentionally repeats ciphertext
and its original full common security number. Any setup probe requiring another
local request uses the existing `request_transaction` and actual reply channel.

Hold at most128 datagrams, each bounded by the selected cover maximum. Record at
most20,000 actual attempts and execute at most3000 turns per ordinary scenario,
with a tighter original protocol cap remaining authoritative. Terminal tests use
an explicit finite final turn at the unchanged original cap. Diagnostic message
assembly is at most4096 bytes per direction/message, at most the selected32
fragments, and at most the actual two retained generations/selected message
bounds. A test fails if its required loss/pressure/staged precondition is not
observed within those limits. Exhaustion is never a successful impairment result.

### Genuine packet observation and faults

With send_batch1, each `send` must produce zero or one handoff. On one, assert
wire/accepted counters and byte costs agree, receive the exact bytes from the
actual destination socket, and compare them with the sender's retained wire
workspace before another send can overwrite it. Describe Control through the
sender's unchanged `control_wire`, real `streams::Frame::decode`, derived stream
binding and `recovery::inspect_packet`, as in the existing streamed fault tests.
This plaintext diagnostic grants no receiver or application authority.

Do not decrypt with the destination's real Records merely to decide whether to
drop a packet: that consumes replay state before a purported network loss.
Classify User/feedback using actual class-specific number/telemetry deltas or
retained sender observations; never guess an encrypted inner source ID.

Record direction, full common packet number, complete actual wire cost, stream,
recovery DATA SourceId or ACK and exact fragment/Accepted bytes. Whole-message
Accepted is `messages::ACCEPTED_KIND` with exact message ID/length/digest; it is
not an ARQ ACK. The shared sequence/replay/key-generation owners never reset.

A Management-kind-specific fault may hold a bounded first flight of a complete
Transaction message and diagnostically assemble only those sender-observed LX
fragments before choosing a loss/release. Use actual LX message/fragment fields
and the existing bounded codec, then exact L2SC/L2MC decoders. This observer may
not ACK, accept, advance the actual Peer or fabricate a completion. Do not assume
the fragmented canonical PREPARE fits one source. A test may instead select an
exact observed Peer phase and must verify the resulting actual command kind.

Every turn checks both original socket tuples. Driver-method drops occur after
actual kernel handoff and before receiver protocol processing. They are genuine
faults in this deterministic protocol-time seam, not evidence that the kernel,
netem or public runtime select loop itself lost or reordered the packet.

## Required six-row matrix

Run every row for both QUIC-like and media-like appearances. Preserve old
Client2/Server3 -> targetClient4/Server1 and nonzero actual native counts. Each
successful row switches back or otherwise proves no retained old slot/reader
blocks the next actual operation. Actual PacketDevice reads admit originals and
actual complete writes advance physical counts; source ACKs and extraction
alone cannot stand in for them.

| Row | Required real fault and discriminating assertions |
| --- | --- |
| 1: recovery and reorder | Lose one first-copy User source and one actual PREPARE fragment, release later source/fragment first, then independently lose READY/Barrier response. Genuine retained recovery must complete exact per-channel native bytes once, old admitted/extracted/physical fences and final proof custody. Liveness continues. Keep both retransmission and a separately selected nonzero proportional-repair variant; observe actual respective SenderStats deltas. A zero-repair fixture cannot qualify the repair subcase. |
| 2: stale epoch and replay | Capture a delivered old datagram and a genuinely emitted but undelivered old feedback/recovery packet. Release both after actual retirement: no reader resurrection, duplicate native write, transaction change or old authority. Missing-scope rejection may precede replay rejection. A subsequent genuine current packet succeeds; replaying it causes actual replay rejection with exact native bytes once. A late old DrainOnly packet cannot exceed its frozen exclusive peer fence or redeliver native data. |
| 3: staged target | Delay actual COMMIT_ACK while the follower has physically committed. Admit and emit real target User data there; the coordinator's actual Peer/Bank/Records retain it under Staged, with unchanged old NativeWritten/FIFO/device output. Release COMMIT_ACK, promote only through actual Committed action, then physically deliver exact target identities/bytes once. Staged retention is not subject to the installed old Written generation or old native-output-full guard. |
| 4: final acceptance pressure | Real prior Accepted receipt plus current Commit/Retire source debt occupy the receipt window; drop corresponding Transaction ARQ ACKs. After real final reply and physical retirement, require held outcome, Peer Idle with operation Some, pending actual acceptance and Empty local switch reply. No new admission or reader/Bank resurrection; Ping/Pong continues. Release actual pressure and require genuine proof release before the matching switch reply succeeds once. |
| 5: cached final retry | Keep actual server COMMIT_ACK and final RETIRE reply unconfirmed while the client remains AwaitRetireAck; both normal output slots must really be held. Actual retransmission, and a separately identified genuine fresh-packet logical retry seam, jointly preview with no Preparation and coalesce the original final FrozenOutput: no extra engine/Bank, third normal output, new SubmissionId/deadline or lifecycle event. Resume real final proofs. Altered request/body/origin/cap fails the existing joint authority boundary. |
| 6: terminal loss and native pressure | Continue Transaction-specific loss through D-1 while genuine Pong exchanges continue, then at immutable D require the documented terminal/uncertain result, no successful switch, rollback or renewed lease. Separately cause an actual PacketDevice WouldBlock on a queued old packet: preserve payload/origin/NativeId/age, keep physical count below peer fence despite source ACK, and maintain opposite native/control work. Release the device and permit Drain only after the actual exact write. Existing exact-D/late-success cases remain intact. |

For row4, the reserved receipt slot makes DATA-only filling insufficient. Prove
that an earlier real receipt occupies custody; never set an occupancy counter or
submit invented sources. Loss of an Accepted packet after real receipt admission
does not by itself retain the coordinator's Accepted proof. It keeps the remote
Confirmed custody pending. Assert each endpoint's actual agreed proof rule.

For row5, ordinary State output custody suppresses another Peer output while its
current FrozenOutput remains retained. A test-only independent actual
`Peer::poll`/Owner.freeze/submit retry must retain the real operation/cap and be
labeled explicitly; it does not prove that production State creates a second
FrozenOutput in that condition. Existing State pressure cases remain preserved,
and the new Driver case must add actual common protection/socket/native evidence.

## Public loop, failure and acceptance boundaries

Add a clean actual two-endpoint public `run_transaction` case using the real
transaction channel, original socket tuples and PacketDevices: nonzero traffic,
two negotiated switches, liveness, cancellation and final status. A second reader
on an owned session socket is forbidden. An auxiliary UDP proxy changes path
identity and cannot be called the same session-socket fixture. Public-loop
impairment needs a bounded selected I/O seam or separately qualified owned netem
lab; this contract does not assume or enable either.

Pressure tests must preserve first incoming message bytes, exact operation and
original expiry, frozen output SubmissionId/deadline, AEAD counters and old native
facts. A late actual device success remains counted physically while the
operation fails at its original deadline. No test increases the test stack,
changes the5-second liveness requirement of the separately configured native
profile, relaxes a protocol cap, disables loss to manufacture clean completion,
or infers permission for a mode/default reduction.

Root alone executes formatting, focused tests, required `python3 tools/check.py`
and source-bound receipts. Keep failed attempts and fixture precondition failures.
Source presence, compilation and an enum are not test completion. Tests here
advance GDI-02/GDI-03 and cannot by themselves close complete reservation,
shared service/API selection, other profiles/DataFeedback/NativeReceipt, full
SW-11, privileged native/performance, carrier/platform or ISP validation gates.

## Progress ledger

The test-only State observations are fixed, read-only custody metadata:
`output_custody_for_test()` returns three optional tuples of actual
`(SubmissionId, original deadline, confirmed, is_final_reply)`. The separate
`independent_final_retry_for_test(now)` invokes the real retained client Peer
only in AwaitRetireAck before its original caps and requires an actual Retire
without lifecycle effects. Neither seam exposes mutable state, fabricates a
packet identity, provides authentication authority or changes production logic.

- [x] [GDF-01] Implement the bounded actual-handoff fixture and immutable preconstruction seams; preserve existing Generic assertions and verify exact wire cost/number/tuple observations without consuming destination replay for fault classification. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [ ] [GDF-02] Pass row4 on both appearances with real receipt admission pressure, retained original proof/outcome custody, independent liveness and no premature local switch success.
- [ ] [GDF-03] Pass row5 on both appearances through actual protected original UDP/native ownership with two real unconfirmed outputs, exact cached coalescence and genuine final proof release.
- [ ] [GDF-04] Pass row1 on both appearances for genuine loss/reorder, nonzero bidirectional physical fences, maintained retransmission and separately selected proportional repair, with a subsequent real transition.
- [ ] [GDF-05] Pass row2 on both appearances for stale/retired scope, current replay and exact no-redelivery/no-authority resurrection.
- [ ] [GDF-06] Pass row3 on both appearances with actual pre-ack Staged target storage and delayed physical promotion/delivery.
- [ ] [GDF-07] Pass row6 on both appearances for exact original terminal loss and actual native WouldBlock/release; retain existing late-success/expiry tests and distinguish abort from uncertainty.
- [x] [GDF-08] Pass actual two-endpoint public run/channel/native/liveness/two-switch/cancellation tests and separately document the still-required public-loop impairment/native qualification; no proxy/second-reader equivalence claim. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [x] [GDF-09] Pass required unchanged-source workspace checks with recorded focused commands, preserved failures and exact scoped evidence. Full GDI-02/GDI-03 and parent requirements retain their complete definitions and independent remaining gates. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-aggregate-attempt-2/validation.json); broader parent gates remain open.

## Functionality checkpoint validation

The [required source-stable aggregate](../../work/generic-driver-20261114/functionality-aggregate-attempt-2/validation.json) passes1919 Rust
cases including doctests,376 tooling cases and1658 simulator cases, with workspace
formatting, strict Clippy and strict rustdoc. Its inputs remained unchanged during
the check. Final documentation edits record only evidence and scoped task status.
Earlier failed attempts and the exact pre-fix negative control remain preserved.
This is local Linux validation, with no new privileged/native performance, remote
CI, Windows/Android device or GUI qualification. Every still-open task retains
its complete acceptance definition.
