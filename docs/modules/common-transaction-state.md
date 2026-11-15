# One leased transaction State over common record generations

Status: **implemented Common Bank/State and selected original-UDP runtime;
finite affected runtime and shared-service checks passed; complete lifecycle,
resource and stage acceptance open**.
The [source-bound engineering proposal](../../work/common-mixed-bank-20261115/transaction/design-v0.md)
preceded production edits. The implementation reuses the existing leased Peer,
Control custody, transaction State and sole I/O loop. Engineering interface review
is not an owner decision or a change of default.

The [first affected runtime/service attempt](../../work/parallel-features-20261115/runtime-cases-attempt-1/validation.json)
ran21 exact cases in four bounded parallel processes:19 passed, the multi-switch
empty-owner fixture lacked the later Aligned+Packed coexistence allowance, and
the first actual Common service path overflowed the standard test-thread stack.
Production admission remains strict. The fixture repair uses actual Engine/Bank
plans and its complete empty-owner sequence passed in the
[affected repair receipt](../../work/parallel-features-20261115/integrated-cases-attempt-2/validation.json).
That receipt still failed overall because the service stack overflow persisted;
the later [helper-only service retry](../../work/parallel-features-20261115/integrated-cases-attempt-3/validation.json)
also failed. These historical failures remain failed.

The structural repair then passed a
[source-stable incremental build](../../work/parallel-features-20261115/integrated-build-attempt-4/validation.json)
and the [exact Common service retry](../../work/parallel-features-20261115/integrated-cases-attempt-4/validation.json)
in 1.521 seconds on the standard, unmodified test-thread stack. Construction had
been nested inside several async poll frames; boxing an enclosing future or
splitting constructor helpers did not remove those simultaneous stack extents.
`run_common` now eagerly checks the actual device/socket and fallibly constructs
the same Driver in a one-element cell before returning its continuation. Errors
still arrive through the returned future. The original Parts setup deadline is
checked before and after construction and again before readiness; a late first
poll cannot renew it. The existing sole `run_driver_clock` borrows that actual
Driver. No second loop, task, crypto owner or transaction FSM is introduced.
Legacy/Swift-generic entries retain their existing constructors and borrow the
same continuation. The Driver payload remains charged once; its actual cell
header is added once to the known external subtotal. Complete resource
preallocation remains explicitly false.

Read the architecture, implementation plan/checklist, mode parity,
[actual transaction State](runtime-transaction-state.md),
[complete configuration encoding](transaction-configuration-encoding.md),
[common record Engine](common-record-engine.md) and
[reserved Engine backing](common-engine-storage.md) first. Existing Swift
configuration bytes, default constructors, selected service/CLI/API schemas and
all original parent requirements remain unchanged.

## Exact reuse and canonical contract

`transport_transaction::TransactionState<F>` contains the existing State
implementation once. A sealed runtime-private Family selects the exact canonical
Value, typed envelope, complete catalog and actual Bank backend. Reservation and
Backend expose only original intent metadata and bounded storage lifecycle.
There is no generic mutable Engine, erased configuration or fallback converter.
The old `State` and `Action` aliases select SwiftFamily, preserving the existing
Swift Driver contract. CommonState and CommonAction select the complete common value.

Each family constructs its exact initial and supported values and checks both
the typed envelope and full canonical catalog membership. Common C remains
CompleteV2 with1304 bytes,1272 descriptor bytes and1..=64 sorted complete catalog
entries. Its digest is never replaced by the304-byte Swift digest or a profile
tag. Both actual old global sender widths come from the same canonical value:
Swift up to64, Aligned up to256 and Packed up to255. They are not padded to a
maximum or derived from the target width. State management decoding uses the
existing type-specific `configuration_limits` helper.

Actual width256 common PREPARE is3474 L2MC bytes,3554 including L2SC80. READY is
2250 whole bytes. These are whole-message admission bounds, not a single-source
or MTU allowance. Existing Control fragmentation, complete original/fragment/ARQ
storage and replay65536 limits stay intact. Actual independent Liveness remains
owned by the same Control owner and common crypto context; unsupported
DataFeedback semantics are not silently enabled by these types.

## Real generations and original authority

`transport_common_engines::Bank` retains exact actual
`Preparation<record_configuration::Configuration>` and the pure `record_bank`
virgin guard together. Validate full session/role/endpoints/lane, source Scope,
checked next epoch, target digest, original expiry, unchanged envelope, duplex
and each direction's native format before constructing a target. A Plan uses
the full128-bit session, exact global role/epoch, immutable directional geometry
and native-stall policy; public labels confer no authentication.

Prepare constructs the actual complete reserved Engine. The same injected-time
resampling and read-only Peer/Owner revalidation precede semantic admission.
Only Stage publishes that same virgin Engine. Commit changes generation handles
and retains the exact old owner as draining. Cancellation releases only the real
virgin/staged target; promotion or Uncertain grants no rollback. Retire requires
the actual Engine to drain in addition to the parent physical/control authority.
No Engine is copied, reconstructed on commit, replaced to create room or reduced
to another profile's configuration.

State keeps the original operation after Peer can release its own handle and
until final incoming/outgoing whole-message custody settles. The three frozen
output slots, exact cached retry context, borrowed Accepted/Confirmed proofs,
original phase/operation/session/message caps and error ordering are shared with
the existing Swift implementation. A second post-allocation sample at the cap
must cancel only the actual virgin target without consuming a Peer operation.

Actual Bank usage counts its two inline Engine extents once, nested heaps once
and caller-accounted external bytes once. The numeric external charge remains a
prerequisite subtotal: it is not proof that native/control/Peer/catalog/bridge/
bootstrap/report owners are completely reserved. Literal nested allocator and
full combined admission requirements retain their original definitions.

## Finite evidence and selected composition

The new CommonBank tests use real leased read-only preparations and actual
reserved Engines. They cover a one-short target allowance with an old queued
packet, foreign cancellation, unchanged current owner/Peer, same-instance
publication and envelope refusal before allocation. These tests do not assert a
physical drain or manufacture a Peer proof.

The CommonState fixture uses two real Peers, actual common Banks and complete
reserved whole-message Control owners. It proposes Swift→Aligned→Packed→Swift,
checks complete canonical PREPARE bytes, processes actual lifecycle actions and
settles borrowed whole-message acceptance/confirmation. Its record Engines stay
empty, so the zero fences are genuine empty-owner facts at each actual old
directional width. Another fixture retains an exact complete PREPARE while16
Ping/Pong pairs accept, confirm and retire on the independent Liveness stream;
the original incoming identity/deadline/envelope and operation cap remain fixed.
Catalog and second-sample cap refusal passed in the first affected attempt. The
complete empty-owner sequence passed after the coexistence-fixture correction in
the affected repair receipt above. Those individual passes do not turn that
receipt's separate failed service case into a pass.

These fixtures supply trusted authenticated ingress at the pure/runtime adapter
boundary. They do not exercise protected sockets or physical devices. Nonempty
switching must use authoritative per-channel Engine events and actual native
completion, preserving profile identity separately. Aligned/Packed context
RecordIds cannot be converted to native counters by adding one; global statistics
cannot form a fence. Count observations alone are not authenticated barrier
authority. The parent must stop ingress, drain the actual common queue and duplex
owner, and clear physical/control custody before asserting equality.

Common Engine has one pending native token per generation. The selected Driver
retains its exact generation, token, bytes, original age and origin through
WouldBlock, and commits only after a whole physical write. Five new selected
runtime cases passed over both appearances: real nonempty Swift→Aligned→Packed
and back, a held physical token blocking switching, sealed User WouldBlock with
one security number/debit while independent Control progresses, bounded
context-only native Progress, and original-cap/late-success physical facts.
These are controlled Unix packet-device/socket fixtures, not TAP/TUN, netem,
standard dissector, remote deployment or performance qualification.

`common_transaction_profile::Profile` binds complete C/catalog/resources into the
actual existing admission/Noise/member factory. `run_common` selects Common State
for the same borrowed `run_driver_clock`; it adds no second runtime or security FSM.
The typed shared service exposes `Prepared::secure_udp_common_client/server`,
`Handle::apply_common`, `Completed::Common` and `SecureUdpCommonFrame`, preserving
requested profile and actual session, current/requested C, epoch, phase, physical
scope, rates, channel widths, counters, terminal state and resource limitations.
The original setup, operation, sealed-output and native caps remain independent.
The exact service retry above passed real Swift→Aligned→Packed→Swift switching
for both UDP appearances and both endpoint roles through that shared API. It
checks real local Unix packet-device delivery and newer authenticated Pong
observations at each stage, unchanged authenticated session and UDP endpoints,
exact current/physical epochs and typed completion observations, retained keyed
replies, out-of-catalog refusal, and disconnect/device/port cleanup. Each original
device is opened once. This is finite loopback/socket service integration,
not privileged TAP/TUN, a full loss/failure/reconnect matrix, remote deployment,
native performance or platform qualification; CTS-07 retains its full scope.

The actual single native queue selects either exact Swift or Common metadata.
Common native event totals do not coerce context-bearing Aligned RecordIds or
fabricate a contiguous receipt. The retained sealed User slot holds exact bytes,
scope, generation, packet number, original cap and one wire debit across socket
WouldBlock, independently of existing fixed Control output.

Existing Swift64 record DTOs and strict local APIv3 remain Swift typed. No Common
1304-byte value is truncated into their304-byte schema. Existing local IPC/CLI
explicitly refuses the Common backend as `unsupported_backend`; full portable
Common status/commands and CLI selection remain required work. Complete resource
preallocation is observable as false: actual Bank/native/control reservations and
the external scalar subtotal do not prove universal nested allocator admission.
Fresh-DH runtime integration, retained-state recovery, other carriers and full
SW-11/fault/resource/native/platform gates remain open.

Retained old readers can owe feedback after complete data drain. A separate
bounded-feedback correction preserves full existing canonical blocks and exact
current burst rather than borrowing the old profile's larger maximum. The
[component pass](../../work/parallel-features-20261115/integrated-cases-attempt-1/validation.json)
and individual feedback/runtime passes in the affected repair receipt cover
literal legacy packing, whole-block credit refusal, retained old-reader feedback
and unchanged native counts. The runtime case negotiates an actual 160-byte
Swift target with its exact body+overhead+reserve burst, authenticates a fresh
security number carrying the old original source, waits for genuine token
readiness, and verifies the resulting small feedback debit on the original UDP
socket. The enclosing earlier receipts retain their failed overall statuses.
This does not qualify the full small-body/missing-request matrix or
packed/rolling independent-short behavior.

## Stable acceptance ledger

- [x] [CTS-01] Freeze the exact one-State Family/Backend/Reservation and actual CommonBank contract before implementation. Evidence: [source-bound engineering proposal](../../work/common-mixed-bank-20261115/transaction/design-v0.md).
  Full deliverable: freeze the actual
  CommonBank/record_bank ownership contract before implementation, with current
  source binding and explicit unchanged Swift compatibility.
  Evidence: the source-bound proposal above and the actual sealed Family/Backend/Reservation
  source used by the runtime interface build and focused attempts.
- [ ] [CTS-02] Instantiate the one actual State/leased Peer over complete common
  C and real reserved common generations; prove exact intent/foreign/stale guard
  handling, instance continuity, two-slot retention, atomic plan/budget/refusal
  and actual cancellation/commit/retire lifetimes, preserving every old Swift
  assertion and byte/schema/default contract.
- [ ] [CTS-03] Prove complete canonical catalog/digest and both directional width
  handling through real common proposal/admission, including original cap and
  post-allocation revalidation, maximum encoded request/response geometry and
  unchanged message/source/replay admission bounds. No target-width padding or
  C-to-Swift coercion.
- [ ] [CTS-04] Prove actual common two-Peer Control custody under lost/duplicate
  messages, held/saturated outputs, delayed final proofs, independent Liveness,
  original deadlines and exact cached-origin retirement. Preserve semantic
  one-dispatch behavior and distinguish source ACK from whole confirmation.
- [ ] [CTS-05] Integrate genuine nonempty cross-profile physical barriers with
  actual per-channel profile-aware boundaries, queued-native WouldBlock/late
  success, old/staged/draining protected reader routing and same-owner native
  commitment. No local count, extraction or enqueue stands for delivery.
- [ ] [CTS-06] Qualify complete actual current+prepared/draining and external
  owner resource admission, all nested constructor/refusal/drop paths, bounded
  work/retention and full declared maxima; numeric subtotals and constructor-local
  failpoints alone do not close universal dependency allocator acceptance.
- [ ] [CTS-07] Install the common owner in the existing sole selected Driver,
  explicit authenticated client/service handoff and complete requested/effective
  API, preserving current Swift/default and v1/v2/v3 compatibility. Prove actual
  protected socket/device behavior and full failure/lifecycle matrix.
- [ ] [CTS-08] Reconcile source-stable required-stage evidence and all parent
  ledgers without inferring full SW-11,47-mode parity, resource, carrier,
  platform, retained-recovery/fresh-DH or native/performance completion from
  these finite component fixtures.

Unchecked gates retain their complete stated acceptance. This module does
not replace or narrow CRE, CSE, GSU-05, SRS-07, CRS-06, SW-11 or any47-mode gate.
