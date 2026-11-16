# Standalone native-drain client and local control

Status: implemented and integration-tested with real authenticated loopback UDP
and injected packet devices. The final [client checkpoint](../../work/openvpn-drain-client/validation.json)
passed 68 tests, strict Clippy and strict rustdoc with unchanged client source
hashes. One earlier broad-suite matrix join timeout remains unattributed; see
[finite evidence](#finite-implementation-evidence). The coordinated new workspace
aggregate and privileged native clean-drain qualification are pending. Legacy
OVC1/default selection is unchanged. The retained carrier/device layer is covered
by the stable [wave-9 aggregate](../../work/implementation-wave9/validation.json).

## Scope and compatibility

Add an explicit native-drain client profile for the existing fixed-peer
OpenVPN-like standalone UDP carrier. It retains the established admission keys,
verified TLS/member allowlist, no-SNI policy, full or actual joined half lanes,
protected selective-repeat data, one system FIFO channel, TAP/TUN and None/LZ4.
No FEC, aligned/packed record, active-window, proxy, reload or interoperability
capability is added. User probes and TCP control packets remain ordinary native
traffic admitted by the same FIFO/fragment path.

The existing `openvpn::{Settings, runtime_config, connect, accept}` signatures,
defaults and configuration domains remain unchanged. New APIs live under
`openvpn::drain`. They construct the existing runtime `DrainConfig`, then call
`client_connect_native`, `server_accept_native`, `client_pair_native` or
`server_pair_native`. The actual returned NativeCarrier/NativePairedCarrier is
moved directly into DrainingLink; no legacy conversion, caller-asserted session
metadata, reconstructed exporter or extra socket reader exists.

A private profile-builder hook may share checked endpoint/MTU/lease derivation
with legacy factories. Its legacy branch must retain exact previous Config and
base digests. The new branch uses `DrainConfig::base_session_config()` before
constructing each original carrier Config, then NativeDrainConfig domain
separation. Both directions bind the same native policy and drain duration;
their actual lane profiles, endpoints, session IDs and join proofs remain distinct.

## Exact shared client API

Reviewed public names and ownership:

```rust
pub mod openvpn::drain {
    pub struct Settings {
        pub transport: super::Settings,
        pub drain_timeout: Duration,
    }

    pub fn runtime_config(connection: ConnectionConfig, settings: Settings)
        -> io::Result<runtime::openvpn::drain::DrainConfig>;

    pub async fn connect(
        tls: &ClientTls, name: &str, member: &MemberKey,
        admission: KeyBundle, connection: ConnectionConfig, settings: Settings,
    ) -> io::Result<Session>;

    pub async fn accept(
        tls: &ServerTls, members: &MemberAllowlist,
        admission: KeyBundle, cookie: KeyBundle,
        connection: ConnectionConfig, settings: Settings,
    ) -> io::Result<Session>;

    pub struct Session { /* actual DrainingLink + exact config + real binding */ }
    impl Session {
        pub fn config(&self) -> &runtime::openvpn::drain::DrainConfig;
        pub fn binding(&self) -> &Binding;
        pub fn into_run<D>(self, device: D) -> io::Result<(Handle, Run)>
        where D: PacketDevice<Error = io::Error> + Send + 'static;
    }

    pub struct Run { /* one pinned owned runtime future + completion guard */ }
    impl Future for Run {
        type Output = Result<NativeDrainReceipt, NativeDrainError>;
    }

    #[derive(Clone)]
    pub struct Handle { /* bounded shared state and one one-shot request */ }
    impl Handle {
        pub fn request_drain(&self) -> io::Result<Acceptance>;
        pub fn snapshot(&self) -> io::Result<Snapshot>;
    }
    pub enum Acceptance { Accepted, AlreadyAccepted }
}
```

Settings are validated before credentials or packet-device I/O. Drain duration
is an integral number of microseconds in 1 ms..120 s, with no hidden timeout
fallback. Full mode forbids reverse endpoints; paired half requires both distinct
fixed endpoints in one IP family. Admission and cookie bundles retain the exact
private-read and independent-key checks; full mode's second bundle slot remains
reserved, not a second lane.

A factory captures one checked absolute setup deadline before any socket bind,
gate, TLS/member exchange or pair join. It prebinds both half-lane sockets, then
uses the actual native-profile factories. Every stage, actual capability assembly
and the final return checks that same original deadline; `timeout_at` by itself
is insufficient for an already-ready future. Failure or cancellation drops all
original owners. Opening a native device stays after actual authentication.

The 2026-11-16 compact-wire regression exposed a default-stack overflow during
paired TLS setup. The existing operation is now boxed/pinned before constructing
its timeout future, keeping the large lane state outside nested poll frames.
This adds one setup allocation, no task or protocol owner. Both deadline checks
remain inside the returned future, preserving first-poll, late-ready and
cancellation behavior. The unchanged private-API/grace test and complete
372-case client suite pass; see the [retained compact checkpoint](compact-wire-cleanup.md#selected-checkpoint-evidence)
for failed attempts and debugger evidence. No stack size or deadline was raised.

`Session::into_run` validates the device layer and exact stored policy before
creating the one runtime request channel. It returns a manually retained future,
not a detached task or an auto-started background service. Its single boxed/pinned
future is bounded by the already checked runtime configuration. The caller polls
Run and retains Handle as long as the session is supervised. There is no extra
client reader/writer, packet queue, recovery engine, task join or cleanup allowance.

## Acceptance, completion and cancellation

Handle serializes a single optional runtime ShutdownRequest with bounded status.
The first request invokes the runtime's one-use `request()` under that lock;
that runtime producer records the original monotonic timestamp before signaling.
Only a successful submission changes `drain_accepted` to true. An exact retry
returns AlreadyAccepted and sends nothing, recreates no timestamp and changes no
deadline. A terminal or dropped runner rejects new requests as closed. These
operations never await native work while holding the local API handler.

The retained Run calls `runtime::openvpn::drain::run_draining` directly. Its native
request, exact source/native fences, delayed secondary Close, original minimum
local/peer deadline, actual native writes and retained carrier task joins remain
owned by that runtime. Client code does not start a fresh timeout around close or
add a post-deadline network join. Peer-only stop can complete without a local
request; in that case drain_accepted remains false and the actual Closed report
is still authoritative.

A completion guard is created before returning Run and exists even if the future
is never first-polled. It publishes Closed only after the actual runtime returns
NativeDrainReceipt, and Failed only after an actual NativeDrainError. Dropping an
unstarted or pending Run drops all original carrier owners and publishes Cancelled
if no terminal result has already been recorded. Dropping a Handle alone is not a
success or a remote stop; Run retains the original request owner until completion.
An already recorded terminal result is immutable. No result is inferred from an
empty queue, local request acceptance, signal delivery or task abort.

## Bounded typed status

Status types are defined in the new client module and are usable by CLI and future
GUI without parsing log strings. Implemented serializable shape:

```rust
pub enum Binding {
    Full { session: [u8; 16], config: [u8; 32] },
    Paired { pair: [u8; 32], configs: [[u8; 32]; 2] },
}
pub struct Snapshot {
    pub binding: Binding,
    pub drain_accepted: bool,
    pub terminal: Option<Terminal>,
}
pub enum Terminal {
    Closed { report: CloseReport },
    Failed { error: Failure, progress: PartialProgress },
    Cancelled,
}
pub struct FenceCounters {
    pub packets: u64,
    pub native_bytes: u64,
    pub sources: u64,
    pub source_bytes: u64,
}
pub struct CloseReport {
    pub local: FenceCounters,
    pub peer: FenceCounters,
    pub carrier: CarrierReport, // Full(one) or Paired(exactly two)
}
```

Binding comes from actual accepted SessionInfo or PairInfo, not a requested
settings digest. The new native policy is explicit in startup/status type names;
these are physical session/config identities, not a reimplementation of the
carrier's private full-mode logical-control scope.

CarrierReport copies the actual close receipts' admitted/consumed source counts,
charged datagrams/IP bytes, transmitted datagrams and TLS-message counts. Its
closed lane cardinality is fixed by the enum. Closed also proves the runtime's
original-deadline checks passed; local response serialization time is not a new
network completion timestamp.

Failure contains a stable error-kind code, optional raw OS error number and at
most 512 UTF-8 bytes of non-secret diagnostic text. PartialProgress is a fixed
projection of the runtime error's accepted native/source prefix, source consumed
prefix, completed/confirmed native counters, retained fragment/reassembly/native
counts and bytes, and admission_in_flight. It labels a pending admission as
unknown until the result is observed; it never substitutes zero for unknown
carrier admission. Cancelled has no invented final progress inventory.

The first client slice intentionally exposes local acceptance and actual terminal
outcome, not live native queue or peer-drain phase telemetry: the current runtime
has no public live native-drain observer. A pending local status therefore says
`running` or `drain_accepted`, with terminal absent. It does not claim the peer is
still admitting or has begun draining. All strings/enums/counts are bounded; a
worst-case full/paired terminal response must fit the existing 8192-byte local
response limit. No rolling history, packet bytes, credentials or wall-clock
claims are retained.

## Explicit CLI selection and private local API

Implemented opt-in options:

- `--carrier openvpn-like --openvpn-close-profile legacy|native-drain`, default
  `legacy`. Omission and explicit legacy preserve current factory/domain behavior.
- `--openvpn-drain-timeout-ms 1..120000`, allowed only with native-drain, default
  5000 ms in that profile. Both peers must authenticate the same exact duration.
- Existing `--control-socket PATH` is newly allowed only for native-drain in this
  carrier. It stays forbidden by the legacy standalone profile.
- Existing `--openvpn-stats-ms 0|100..60000` remains the same local cadence. In the
  new profile it emits the typed client status as `openvpn_drain_status`; it does
  not fabricate the legacy runtime observer's per-iteration queue counters.
- `drain-openvpn --control-socket PATH` submits one typed request and prints the
  bounded structured acceptance result. `status` queries actual terminal outcome.

No control socket is required for programmatic Handle use or peer-initiated stop.
Without one the CLI can finish a peer-triggered drain and prints its actual final
report; operating-system signal cancellation keeps its existing non-clean meaning.
A later signal-to-drain policy requires a separate explicit design and test gate.

The current version-1 private Unix API gets one additive action
`Action::DrainOpenVpn {}` (serialized command `drain_open_vpn`) and an optional
`Snapshot::openvpn_drain: Option<openvpn::drain::Snapshot>` field with default None
and skip_serializing_if None. Old profile responses retain their exact serialized
shape. Old clients are not promised support for querying the new profile: their
strict parser can reject an unfamiliar optional field. Wrong-profile drain
requests return unsupported; no fallback to proxy drain or compression switching
occurs. Existing request/response byte limits, peer-UID policy and owned socket
cleanup stay authoritative.

New handler semantics:

| Action/state | ok/code | State meaning |
| --- | --- | --- |
| Status | true/ok | Bounded actual client state. |
| First successful DrainOpenVpn | true/accepted | One-shot request submitted, not closed. |
| Retry before terminal | true/already_accepted | Same original request/deadline. |
| DrainOpenVpn after terminal | false/closed | Return the immutable terminal snapshot. |
| Other mutating action | false/unsupported | No native/configuration mutation. |

The endpoint process prints Closed/Failed/Cancelled separately from the command
response. Its successful process exit requires actual Closed; an accepted local
request cannot produce process success by itself. If a control socket was opened,
it remains available for a fixed five-second **local status-only grace after the
runtime has returned and all original network owners have finished**. This
matches the existing proxy frontend's observation model. The grace does not hold
native/carrier owners, extend any native deadline, accept new drain work or run
another cleanup join. Without a control socket the endpoint returns immediately
after printing its terminal result. API failure while the runtime is active drops
Run and returns a non-clean error; it does not start a new drain deadline.

## Ownership and implementation order

This agent owns new `client-core/src/openvpn/drain.rs` (and its focused tests),
new `openvpn/drain_cli.rs` if useful, and narrow existing `openvpn.rs` and
`openvpn/cli.rs` integration. No root Cargo or runtime/aligned changes are needed.
The existing serde/Tokio dependencies suffice. Root approved the minimal shared `local.rs`, `local/tests.rs`, CLI command
allowlist/dispatch and unrelated-profile unsupported matches; those client files
are exclusively owned by this slice until handoff. No local lib.rs module entry
is needed if `openvpn.rs` declares its nested module. Existing proxy/aligned/active
behavior must keep its current ownership and defaults.

The contract and shared ownership were reviewed before implementation. First implement
typed native client factories and the owned Run/Handle. Test using real verified
TLS/member full/paired UDP and independent injected PacketDevices. Then register
the optional local action/snapshot and CLI profile with strict parser and actual
private-socket tests. Finish focused strict checks and a coordinated aggregate
before proposing native harness changes. Privileged native qualification is a
separate frozen scope with immutable binaries/receipts; the previous two-second
outage failures and bounded short-recovery observations are preserved.

## Finite implementation evidence

The captured [final client receipt](../../work/openvpn-drain-client/validation.json)
records exact commands, exit codes, logs and equal before/after hashes for every
client Rust source file. `cargo test --offline -p l2tunnel-client-core --lib`
passed 68 tests; all-target Clippy with `-D warnings` and rustdoc with
`RUSTDOCFLAGS=-D warnings` passed. This is Linux local/loopback verification,
not a new full-workspace or privileged native receipt.

The genuine matrix contains eight cases: full/half × TAP/TUN × None/LZ4, using
IPv6 for None and IPv4 for LZ4. This is not the complete four-axis Cartesian
product. Cases compare original bytes in both directions and require actual
native/carrier receipts. Other tests cover peer-only and simultaneous stop,
accepted-versus-terminal, duplicate requests, blocked native writes with reverse
progress, original setup/request deadlines, cookie/admission/member/certificate/
profile/second-lane failures, prebind failure, unpolled/pending cancellation,
wrong device layer, errno/progress, bounded UTF-8 and strict schema, pinned legacy
digest/response bytes, actual private Unix lifecycle and exact five-second local
status grace. Original UDP tuples rebind during that grace. A separate frontend
failure test retains errno and returns nonzero semantics without a false receipt.

The [historical record](../../work/openvpn-drain-client/history.json) preserves
intermediate results. A strict response test found Serde's internally tagged
unit `Cancelled` variant accepted unknown fields; the decoder now uses a strict
empty-struct mirror while retaining the public unit variant and serialized bytes.
Its regression passes.

An earlier broad run passed 67/68 and failed the eight-case matrix's six-second
post-request join with `Elapsed(())`. Its [actual output excerpt](../../work/openvpn-drain-client/original-broad-timeout.txt)
is preserved as a transcribed excerpt, not a reconstructed complete log. That
version did not record case identities or endpoint states, so neither is known.
The configured native bound was five seconds. The test now retains its JoinHandles
through timeout, records both actual client snapshots/case identity on failure,
and aborts/joins remaining test tasks. No deadline or success predicate changed.
One subsequent diagnostic matrix run and the final broad run passed; neither
explains the earlier timeout. Its cause remains unresolved and native expansion
requires separate review of this limitation. No retry-until-pass claim is made.

The separate [native-drain harness proposal](openvpn-drain-native.md) is design
only; it has no implementation or execution authorization yet.

## Checklist and acceptance matrix

- [x] [MOD-OVPNDCLI-01] Inspect existing client, private API and retained native-drain owners; specify additive selection, acceptance/terminal semantics and exact ownership before coding. Evidence: [shared API](#exact-shared-client-api), [lifecycle contract](#acceptance-completion-and-cancellation), [CLI/local schema](#explicit-cli-selection-and-private-local-api).
- [x] [MOD-OVPNDCLI-02] Review exact APIs/flags/schema and coordinate shared file ownership with root before implementation. Evidence: [approved API and ownership contract](#ownership-and-implementation-order).
- [x] [MOD-OVPNDCLI-03] Implement native-profile factories with one absolute setup deadline and real full/paired capabilities; pin legacy profile/digest behavior. Evidence: [native factories and private base hook](../../crates/l2tunnel-client-core/src/openvpn/drain.rs), [legacy digest and setup tests](../../crates/l2tunnel-client-core/src/openvpn/drain/tests.rs).
- [x] [MOD-OVPNDCLI-04] Implement bounded Run/Handle, one-shot idempotent request acceptance, immutable actual terminal status, unpolled/pending cancellation and OS-error-preserving failure projection. Evidence: [retained Run/Handle](../../crates/l2tunnel-client-core/src/openvpn/drain.rs), [bounded projections](../../crates/l2tunnel-client-core/src/openvpn/drain/status.rs), [focused tests](../../crates/l2tunnel-client-core/src/openvpn/drain/tests.rs).
- [x] [MOD-OVPNDCLI-05] Test genuine full/paired IPv4/IPv6 authentication and byte-exact TAP/TUN None/LZ4 injected-device delivery followed by native/carrier receipts, without replacing original owners. Evidence: [eight genuine cases and receipt assertions](../../crates/l2tunnel-client-core/src/openvpn/drain/tests.rs), [finite qualification and unresolved historical timing](#finite-implementation-evidence).
- [x] [MOD-OVPNDCLI-06] Test accepted-not-terminal, peer-only stop, duplicate requests, simultaneous stop, WouldBlock retention/reverse progress, preexpired local request and original deadline persistence through carrier joins. Evidence: [acceptance, blocked-native and deadline regressions](../../crates/l2tunnel-client-core/src/openvpn/drain/tests.rs), [underlying original carrier deadline tests](../../crates/l2tunnel-openvpn/src/native/tests.rs).
- [x] [MOD-OVPNDCLI-07] Test mismatch/admission/member/certificate/second-lane failure, prebind failure and canceled/unpolled factory/runner cleanup; do not release device I/O before authentication. Evidence: [negative factory and ownership tests](../../crates/l2tunnel-client-core/src/openvpn/drain/tests.rs), [device opened only after authentication](../../crates/l2tunnel-client-core/src/openvpn/drain_cli.rs).
- [x] [MOD-OVPNDCLI-08] Add strict opt-in CLI selection and coordinated local action/snapshot registration, retaining legacy response bytes and unsupported behavior on other profiles. Evidence: [strict selector](../../crates/l2tunnel-client-core/src/openvpn/cli.rs), [shared action/dispatch](../../crates/l2tunnel-client-core/src/cli.rs), [exact legacy JSON tests](../../crates/l2tunnel-client-core/src/local/tests.rs).
- [x] [MOD-OVPNDCLI-09] Test actual private Unix acceptance/status/terminal lifecycle, bounded largest failure/receipt responses, unknown/extra field rejection, idempotent retries and owned socket cleanup. Evidence: [actual socket lifecycle](../../crates/l2tunnel-client-core/src/openvpn/drain/tests.rs), [maximal bounded responses and strict parser](../../crates/l2tunnel-client-core/src/local/tests.rs).
- [x] [MOD-OVPNDCLI-10] Test endpoint exit/terminal report semantics and the separate local-only five-second status grace without extending network completion or adding detached tasks. Evidence: [original runner release before local grace](../../crates/l2tunnel-client-core/src/openvpn/drain/local.rs), [real closure/failure/grace tests](../../crates/l2tunnel-client-core/src/openvpn/drain/tests.rs).
- [ ] [MOD-OVPNDCLI-11] Run focused real-TLS/client/API tests, strict lint/rustdoc and coordinated workspace aggregate, recording finite evidence and failures.
- [ ] [MOD-OVPNDCLI-12] Submit a separate native clean-drain harness specification and obtain review before any privileged run or wider matrix claim.
