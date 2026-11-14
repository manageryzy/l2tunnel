# Explicit generic Swift client/service selection

Status: **explicit generic Prepared/service selection and additive APIv3 are
implemented and finite local Unix integration-tested**. The existing actor runs
the [generic selected Driver](generic-secure-udp.md) over its original authenticated
socket. CLI selection, the complete generic IPC/failure matrix and broader
qualification remain open; version2 and the existing CLI still select
SwiftPolicyV1. The required source-stable aggregate passes; scoped evidence is recorded below.

This is an engineering integration contract, not an owner decision or a change
to [architecture](../architecture.md), [client requirements](../client-design.md)
or [mode parity](../mode-parity.md). Full SW-11, all 47 catalog gates,
RLNC/parity/rolling/packed/proxy, other carriers, default retained-state recovery,
fresh-DH lifecycle, full resource admission, native performance, GUI and platform
requirements retain their existing definitions. Swift remains the data algorithm
inside an explicitly selected carrier.

## Existing owners and compatibility boundary

`secure_udp::transaction_profile::Profile` already binds both role templates,
the exact finite catalog, E, original settings/trust and transaction resources.
`runtime_contract(role)` recomputes actual setup H0 and provides the checked
runtime handoff. The selected runtime constructs one original-socket Records
owner with fixed Control H0 and canonical User D0, an actual leased Peer and
reserved engine Bank; its separate `TransactionSnapshot` reports real state.

The retained `service::Prepared`, `Transport::SecureUdpSwift`,
`ObservedBackend::SecureUdp`, `SecureUdpFrame`, and `establish_secure_udp` still
use the existing SwiftPolicyV1 constructor/channel. They must remain usable with
unchanged defaults, public entry points, authentication, protocol bytes and
version 1/version 2 request/response bytes. There is no fallback between backends.

Reuse the existing `Handle`/`Run` actor, accepted setup deadline, request-key
history, setup observation, deferred attachment, per-plan server admission owner,
inline runtime future and Completion/stopped paths. Add no second reader, actor,
semantic transaction state machine or management connection.

## Exact shared Rust plan interface v0

The new constructors are Unix-gated, matching the real runtime:

```rust
Prepared::secure_udp_transaction_client(
    profile: transaction_profile::Profile,
    credentials: credentials::Client,
    attachment: Attachment,
) -> io::Result<Prepared>

Prepared::secure_udp_transaction_server(
    profile: transaction_profile::Profile,
    credentials: credentials::Server,
    attachment: Attachment,
) -> io::Result<Prepared>
```

Add private `Transport::SecureUdpTransaction(Arc<transaction_profile::Profile>)`.
Retain the existing `Endpoint::SecureClient` and `Endpoint::SecureServer` owners.
The server's actual `Mutex<Option<secure_udp::Server>>` belongs to the Prepared
plan's retained Arc and survives cancellation/reconnect of that same plan. A new
plan has a new identity; no equivalence comparison adopts another admission owner.

Before accepting a plan or opening any socket/provider, validate exact native
layer/readable capability, Noise pattern, configured client member against the
actual Ed25519 credential, and actual ordered `noise.peers(role)` equality with
`profile.peers()`. Call the real `runtime_contract(role)`. A digest recomputed
under different pins does not satisfy this plan. Do not convert Ed25519 bytes to
Noise material, generate credentials, introduce account/multi-device workflows,
or construct a TLS placeholder. Existing own-trust inputs remain opaque owners.

Extend the internal exact selection query used by setup records and API gating.
It must distinguish Legacy, SecureUdpSwift and SecureUdpTransaction; a generic
plan is not classified as SwiftPolicyV1 merely because both use Swift data.

## Returned frame and observation interface v0

Expected public authentication context is derived through the actual runtime:
`establish::Config::expected_binding(peers, session) -> Result<handshake::Binding,
establish::Error>`. It reuses the existing setup/outer derivation also consumed
by Exchange; it performs no I/O, authentication or clock sampling. The raw
configured outer seed differs from the authenticated outer digest, which includes
the actual gate profile and session. Status checks the latter and the existing
member-policy digest, while reporting the verified member public key separately.

Add the following Unix-gated shared value and accessor:

```rust
pub struct SecureUdpTransactionFrame {
    pub requested: Arc<transaction_profile::Profile>,
    pub info: member::Info,
    pub runtime: Option<transport::TransactionSnapshot>,
    pub generation: u64,
    pub service_terminal: Option<Terminal>,
}

Observation::SecureUdpTransaction(Box<SecureUdpTransactionFrame>)
Observation::secure_udp_transaction(&self)
    -> Option<&SecureUdpTransactionFrame>

SecureUdpTransactionFrame::status(&self)
    -> io::Result<secure_udp::transaction_status::Status>
```

The corresponding private backend retains the exact Arc Profile, actual Info,
`Mutex<Option<TransactionSnapshot>>`, actual `TransactionControlHandle` and
generation. It has no separate committed configuration or protocol epoch.
Snapshots remain absent until actual runtime observation. Requested startup C,
pending requested C, actual Bank C/epoch, actual Peer phase/operation and physical
scope remain distinct. Effective values cannot be copied from a pending request.

Both `owner::stopped` and `Completion::drop` apply the existing service-terminal
overlay to the new frame: running becomes false while the actual last runtime
timestamp, counters, StopReason and configuration remain untouched. No provider
strings, packet bodies, cookies, private keys or secret exporters enter status.

### Original deadline across synchronous observation

A semantic state report is an observation, not permission to extend retained
operation or session custody. Before the generic loop's semantic-change callback,
sample fresh time and call the existing actual expiry guard; an expired report
must not publish running=true. After any successful generic completion or semantic
callback, resample both the Instant and relative timestamp, guard actual expiry,
and use those values for subsequent control submission, socket handoff and wake
calculation. A slow callback may leave a valid earlier observation, but cannot
authorize further effects under its old timestamp. Reuse the original cap and
terminal handling; do not advance a Peer or renew a lease in this guard. Existing
completion checks remain. Legacy callback/sample ordering is unchanged.

The pre-fix source-stable aggregate passed, but independent review found the new
semantic callback lacked these guards and reused the old loop timestamp. Keep
that receipt as evidence for its exact snapshot, not the corrected source. Add
an actual run_selected_clock/Noise/original-socket regression with a genuine
complete-C request and injected time crossing the real operation cap inside the
callback. It must retain truthful terminal/native/counter facts and show no
subsequent socket or native handoff. This refines GCS-03/GCS-08 validation without
closing or reducing any complete failure/pressure gate.

The [actual-loop regression receipt](../../work/generic-driver-20261114/observation-deadline-attempt-2/validation.json)
now passes the corrected loop on both appearances. The exact byte-verified
pre-fix transport is a failing negative control in the first QUIC-like fixture:
after the callback reached the real cap, it handed four further datagrams/1198 IP
bytes to the socket and advanced
Control number0→4. The corrected loop keeps all observed handoff/native/security
facts unchanged and reports PolicyTimeout. The fixed file was restored byte-exactly
after the negative control; its first test-only compile failure is also retained.
This is a local injected-time regression, not native/WAN performance evidence.
Existing initial/periodic callback and per-send-batch/preemption timing are
separate remaining qualification boundaries; this fix does not claim them.

## Actual setup and runtime selection

Reuse/factor the common part of `establish_secure_udp`: actual bind/connect on
the selected fixed path, retained server admission, observed Noise/member
factories and original setup stages. Its input is the exact transaction Profile
settings; the existing SwiftPolicyV1 call still receives its original settings.

After authentication, check actual Info pins, role and H0 against the checked
transaction Profile. Transfer Parts once, then open the deferred readable
attachment. Create `transaction_channel` and run `transport::run_transaction`
inside the same service `RunFuture`, retaining both original tails and socket.
Poll the real future until its own snapshot reports running. Recheck the original
accepted deadline and cancellation before publishing Active. Authentication,
allocation or a constructed/pending future alone is not readiness.

Cancellation/disconnect/reconnect drops the original inline owner before release
or replacement publication. Fresh reconnect authenticates a new root/session and
generation; it does not implement retained-outage recovery, periodic fresh-DH or
blind replay of old-session data. Existing setup observations describe the actual
last stage and typed reason without inventing an authentication diagnosis.

## Exact complete-configuration command v0

Add a Unix-gated typed service method:

```rust
Handle::apply_transaction(
    configuration: l2tunnel::swift_configuration::Configuration,
    key: RequestKey,
) -> Result<Accepted, SubmitError>
```

Use distinct private `Command::Transaction(Configuration)` and
`Fingerprint::Transaction(Configuration)` variants. Lookup retained keys before
fresh backend/catalog checks so an exact accepted retry keeps its result after
the live generation changes. A conflicting C under a retained key is Conflict.
For a fresh key, require the actual generic backend and exact envelope/catalog
membership before consuming the key, queueing work or sending protocol input.
Add `SubmitError::InvalidConfiguration` for a valid canonical value outside that
complete selected contract; wrong backend/version remains Unsupported. Busy,
State, Expired, FutureKey and Closed preserve their existing meanings.

The actor awaits the actual `TransactionControlHandle::switch(C)` while polling
that same runtime future. Runtime original operation caps remain unchanged across
service polling/retries. Applied means actual completed peer/whole-message/native
custody, not service acceptance or source ACK. Runtime exit during apply is
OutcomeUnknown, never rollback. Dropping a waiter does not cancel the operation.

Retain the existing `Failure` and `Completed` shapes. The generic action returns
`Completed::Applied/Rejected(local::Response)` with version3 and actual status;
the typed frame exposes the real C/epoch directly to embedding frontends. Never
patch counters/epoch to fabricate a successful response: the returned runtime
epoch and actual observed complete C must match before reporting Applied.
Completion drop must classify pending Transaction fingerprints as OutcomeUnknown
alongside existing Apply fingerprints.

### Final observation ordering

The generic runtime retains the actual completed reply together with its original
outcome/operation cap until the sole loop has published a real snapshot. A private
`report_transaction_completion(sample, observe)` checks the original cap using
fresh samples before and after the synchronous observer, then releases that
retained reply. It never reconstructs or patches C/epoch/counters. The same
bounded finite Driver fixture consumes this path with its actual snapshot.
Periodic reporting may remain disabled. Observer failure, runtime termination or
expiry cannot publish Applied; cleanup closes the retained waiter and the service
classifies uncertainty. No new operation deadline or second state machine is
introduced by this ordering.

The sole loop also publishes actual semantic changes (Bank epoch, Peer phase and
operation, physical scope, and a newly queued local request) independently of the
optional periodic counter interval. A small nonauthoritative comparison witness
only suppresses redundant reports; it cannot change peer state or deadlines.
The follower's effective status therefore advances even with periodic reports
disabled. Finite fixtures remain explicit observations of their actual Driver.

## Strict local API version3 contract v0

Add `local::TRANSACTION_VERSION = 3` to the supported version set. Add exactly
one complete-value action:

```rust
Action::SwitchSwiftConfiguration {
    configuration: transaction_status::CanonicalConfiguration,
}
```

Its JSON command is `switch_swift_configuration`. `CanonicalConfiguration` is a
checked private-field portable DTO serialized as a string containing exactly 608
lowercase hexadecimal ASCII characters: the exact 304 canonical C bytes. It
provides fallible `from_configuration(C)`, `configuration() -> io::Result<C>` and
`as_str()` accessors. Deserialize checks the exact bound/encoding and calls the
existing C decoder; no rounding, optional patches, serde dependency in the pure
library or alternate policy parser is introduced. The local adapter invokes the
same typed `Handle::apply_transaction` action.

Add `transaction: Option<transaction_status::Status>` to local Snapshot with
default/skip-if-None. All old producers explicitly use None. Existing request and
response fields/ordering and v1/v2 golden bytes remain unchanged. An old
SwiftPolicyV1 partial `SetSwiftPolicy` never mutates the generic backend.

Before any local action, a selected generic generation refuses versions 1/2 with
`requires_version_3`, `ok=false`, and state None. Version3 against any non-generic
backend is `unsupported_version` with state None. An older service/client fails
clearly; no client retries a mutating command under another version. During a
cross-backend reconnect, use the live backend's version until its owner is
released, then the retained plan's version. Never combine a new-plan v3 envelope
with the old generation's v2 frame.

Local lifecycle admission validates the requested version, exact retained plan,
live-backend precedence, next unused local key and submission under one service
state lock. Wrong-version refusal precedes key consumption and owner effects.
Typed keyed methods retain their existing replay-first semantics independently.
Status captures its validated version, backend and refreshed observation under
one lock, then projects only that captured generation after unlocking. Status
builders do not select a replacement backend through a second state read.
If an accepted local lifecycle action completes after its representable backend
version changes, its response keeps the original request version, has no state,
and reports `outcome_unknown`; it does not imply that the accepted action was
refused or retry the mutation under another version. These are compatibility
and linearization rules, not a new protocol mode or owner decision.

`transaction_status::Status` is a portable nonsecret DTO; runtime-dependent
projection is Unix-gated. Its required boundary is:

| Value | Required source and representation |
| --- | --- |
| generation, carrier, algorithm, protection, backend | exact frame/selected Profile; backend is `generic_swift_v1`, not a default carrier |
| running, elapsed_micros, terminal, service_terminal | actual snapshot/overlay; elapsed and runtime terminal remain absent before a real report |
| session, transcript, outer, member, initiator_noise, responder_noise, local, peer | actual authenticated Info; public values only |
| configuration, catalog, catalog_members, initial | recomputed H0, exact root/count and canonical C0 from retained Profile |
| current, requested, epoch, phase, operation | optional actual runtime Bank C/epoch, pending request and real Peer facts; canonical C values use the checked DTO |
| physical_scope | actual runtime scope, separately typed epoch/digest; never inferred from a pending C |
| storage, resource_preallocation_complete | actual Usage; false while the full runtime/control/Peer reservation remains incomplete |
| native_storage_capacity_bytes, workspace_capacity_bytes, loop_input_capacity_bytes | optional actual runtime capacity observations, not RSS or a total-allocation proof |
| wire/socket/native/control/security/liveness summary | actual bounded runtime counters, including physical native_written; no queue/extraction-as-delivery substitution |
| configuration_change, coordinator, cross_profile_switching, retained_state_recovery, fresh_rekey | explicit capabilities and role; only selected finite-catalog switching is newly supported; unfinished capabilities stay false |

Current/requested canonical values retain every mutable field, including odd
rates, repair fractions and asymmetric widths. Frontends use the same checked
decoder/getters to render them; they never derive a SwiftPolicyV1 approximation.
Detailed channel/performance arrays remain separate bounded observations.

The v0 portable status uses optional typed `Scope`, `Operation`, `Storage`,
`Direction`, `Wire`, `Native`, `Control`, `Security` and `Liveness` summaries.
`phase` is an optional finite snake-case enum of the actual generic Peer phases.
Both actual local direction summaries retain all 16 fields without policy-unit
rounding. Original operation expiry is reported in injected milliseconds, while
runtime liveness and elapsed observations retain their existing microsecond unit.
Current/requested/epoch/phase/operation/physical scope and runtime summaries remain
absent until a real runtime snapshot exists. Public session/transcript/pin/digest
arrays retain exact bytes; no complete catalog array is duplicated in status.
The canonical configuration action/value is the checked 608-character string
described above. `service_terminal: Option<String>` is a separate overlay; it
does not replace the retained runtime terminal or timestamp. This DTO refinement
is an engineering serialization contract, not a new protocol or owner decision.

Keep the existing 4096-byte request, 8192-byte reply, local UID/ownership and timeout
bounds. Do not embed 64 complete catalog values in each status. The shared frame
already retains the complete catalog. If IPC catalog discovery is added, it needs
a separate bounded page contract without pruning the authenticated catalog; it
is not implied by this status/complete-C action. Maximum valid v3 request/reply
sizes must be tested, not assumed.

## Implementation ownership and sequence

No production edits are authorized by this document alone. The integrator freezes
this contract before assigning files. Proposed disjoint ownership:

1. Plan worker: `service/prepared.rs`, explicit new Prepared tests, and only
   necessary `secure_udp/transaction_profile.rs` validation helpers. There is no
   reason to create a parallel client `runtime.rs` or authentication factory.
2. Root: `service.rs`, `service/owner.rs`, service tests, setup/Completion wiring,
   local/schema and necessary local DTO literals/registrations/reexports.
3. Separately assigned status/schema worker if available: new
   `secure_udp/transaction_status.rs` and its isolated tests; coordinate exact
   literal/field ownership with root before editing.
4. CLI integration follows the working shared Rust/APIv3 operation, using an
   explicit generic plan/catalog selection. Exact CLI flag/file syntax is a later
   implementation contract; the existing CLI path/defaults must not change.

The source-backed predecessor assessment is retained at
[next-client-selection-v0.md](../../work/generic-driver-20261114/next-client-selection-v0.md).
It is navigation and design context; current sources and fresh receipts decide
implementation/evidence status.

## Verification and stable child tasks

- [x] [GCS-01] Freeze the exact additive plan, typed action, returned observation, APIv3 compatibility and ownership contract before production edits; keep requirements separate from engineering choices. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [x] [GCS-02] Implement explicit transaction Prepared selection and actual credential/attachment/contract validation before socket/provider effects, including exact pin/member/pattern, layer/readiness and resource/canonical negatives. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [x] [GCS-03] Consume actual factory authentication, original socket/tails, deferred attachment and run_transaction through the existing service actor; retain setup caps, per-plan server quarantine, cancellation and truthful readiness/terminal projection. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [x] [GCS-04] Implement complete-C typed commands with actual peer completion, exact key replay/conflict, unchanged operation caps, catalog refusal before effects and OutcomeUnknown on lost custody; preserve all existing action semantics. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [x] [GCS-05] Implement the separate shared frame and bounded truthful version3 status, retaining requested/current/physical distinctions, actual capacities/identities and explicit incomplete resource/lifecycle/profile capabilities. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json); broader parent gates remain open.
- [ ] [GCS-06] Implement strict APIv3 parsing, status, complete-C switch and lifecycle routing over the existing private transport; prove exact v1/v2 bytes, wrong-version zero effects, strict limits and no downgrade/retry writes with real IPC tests.
- [ ] [GCS-07] Exercise two actual shared service owners on both covers with nonzero asymmetric native traffic and at least 2 complete configuration switches, plus credential/setup/attachment/cancel/reconnect/owner-drop/duplicate-key/failure cases; separate typed/IPC evidence from native and GUI claims.
- [x] [GCS-08] Run focused failure/compatibility tests and the required source-stable aggregate on the complete selected shared path; preserve failed attempts and commit exact evidence/status without closing broader parent gates. Evidence: [source-stable scoped checks](../../work/generic-driver-20261114/functionality-aggregate-attempt-2/validation.json); broader parent gates remain open.
- [ ] [GCS-09] Add explicit CLI generic plan/catalog selection and version3 commands through the same shared API, preserving the current CLI path/defaults and manual own-trust credentials; validate actual external requests separately from in-process tests.

## Current finite service evidence and remaining cases

The new paired-service fixture uses actual Noise/member factories, original UDP
sockets and UnixDatagram PacketDevices on both appearances. It carries nonzero
traffic on every channel through2/3→4/1→2/3, checks real completion and follower
state with periodic reporting disabled, exchanges actual Pong, then disconnects
and reconnects with a fresh session/transcript and the same retained admission
owner. Typed complete-C/key replay/conflict/catalog refusal and real Unix IPC v3
status/switch are exercised. Prepared and status tests separately reject wrong
pins/member/pattern/device capability and incorrect derived public bindings.
Seven logical atomic-admission tests include queued complete-C OutcomeUnknown
on service-owner drop; those fixtures do not claim authentication.
The [source-stable focused receipt](../../work/generic-driver-20261114/functionality-focused-attempt-9/validation.json)
records5 Prepared,8 status,7 atomic,16 secure-service and12 local API cases,
the selected runtime/component regressions and strict Clippy. Earlier failed
attempts are retained; this receipt does not imply native/GUI/platform acceptance.

GCS-06 remains open: generic v3 lifecycle and v1/v2 zero-effect refusal have
in-process evidence, but not the complete new-profile real IPC matrix or a fixed
v2 byte golden. GCS-07 remains open: the complete generic credential/setup/device/
cancellation/failure matrix has not been exercised through the actual new owner.
Legacy service negatives do not replace these cases. GCS-09 has no CLI
implementation yet. Full requirements above are unchanged.

The current runtime and service have finite local Unix socket/device evidence.
The shipped CLI native attachment is Linux TunTap. Windows remains a staging
entry point and has no shared named-pipe/device implementation; Android has no
JNI/VpnService/application shell. A portable DTO, cfg(unix) build or Adapter enum
is not platform support. GUI and native cross-platform acceptance retain their
original CL gates.

## Functionality checkpoint validation

The [required source-stable aggregate](../../work/generic-driver-20261114/functionality-aggregate-attempt-2/validation.json) passes1919 Rust
cases including doctests,376 tooling cases and1658 simulator cases, with workspace
formatting, strict Clippy and strict rustdoc. Its inputs remained unchanged during
the check. Final documentation edits record only evidence and scoped task status.
Earlier failed attempts and the exact pre-fix negative control remain preserved.
This is local Linux validation, with no new privileged/native performance, remote
CI, Windows/Android device or GUI qualification. Every still-open task retains
its complete acceptance definition.
