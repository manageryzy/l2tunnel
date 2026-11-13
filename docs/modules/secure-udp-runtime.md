# Native transport on the authenticated original UDP socket

Status: **implemented and integration-tested for the finite local Unix scope
below**, 2026-11-13; broader acceptance remains open.
The parent integrator reviewed and froze the interfaces below before implementation. These are
integrator choices, not additional owner decisions. This scoped FIX-13/SW-15
driver consumes actual [shared-client authentication](client-secure-udp.md) and
the existing [member handoff](shared-udp-session.md). It does not replace the
OpenVPN wire-handshake, original HTTPS raw-packet, full SW-11, 47-mode parity,
native performance, lifecycle recovery or platform acceptance gates.

The [source-stable focused receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json)
passed 17 transport tests, 21 shared-client secure-UDP tests, retained service/local
API tests, strict Clippy and rustdoc. Transport fixtures use two independent Tokio
runtimes, actual connected loopback UDP sockets, real cookie/Noise/member proof
and nonblocking AF_UNIX `PacketDevice` adapters. The driver matrix currently uses
IK and Ethernet with both covers; it does not qualify the complete IK/IKpsk2,
IP/Ethernet, impairment and final-handoff matrix or privileged TAP/TUN performance.

## Ownership and admission boundary

The Unix runtime receives a nonblocking `PacketDevice + AsRawFd`, the exact
`member::Parts`, one immutable runtime configuration and the expected complete
authenticated configuration digest. It opens no device, changes no routes,
creates no socket, uses no TLS side channel and spawns no socket reader. It owns
the original connected UDP socket, root, bootstrap tail, Joining tail, common
User/Control security owners, full Swift records engine, policy coordinator,
fixed reliable control service and bounded local queues in one loop.

Only actual member-authenticated parts admit native traffic. Before readiness,
check the expected digest against `parts.info.authenticated.configuration`, the
fresh session/root binding and role, actual original socket addresses, device
layer, complete buffer/MTU geometry and every finite resource limit. Construct
the protocol owners and native readiness registration, then sample the original
setup deadline again before publishing the first `running = true` snapshot.
Authentication alone is not native runtime readiness.

The parent shared-client `Prepared` contract computes the exact canonical global
application digest from both role configurations before authentication and
retains those same immutable configurations. A runtime cannot invert an opaque
application digest. Passing a second unchecked digest is not proof that arbitrary
later settings were authenticated. The parent retains that explicit construction
contract; the runtime checks the actual full authenticated digest at attachment.

## Proposed public interface

All types below are in `l2tunnel_runtime::secure_udp::transport`. Public protocol
libraries remain free of Tokio, native handles, clocks and privileges.

```rust,ignore
Config {
    path_mtu: usize,
    send: swift::policy::Direction,
    receive: swift::policy::Direction,
    policy: swift::policy::Settings,
    security: security::Limits,
    control: management::delivery::Settings,
    control_epoch: security::Epoch,
    data_epoch: security::Epoch,
    wire: WireBudget,
    work: WorkBudget,
    native: NativeBudget,
    lifetime: Lifetime,
    report_interval: Option<Duration>,
}
WireBudget { burst_bytes: usize }
WorkBudget {
    receive_interval: Duration, receive_packets: u32, send_batch: usize,
    native_read_batch: usize, native_write_batch: usize,
}
NativeBudget {
    pending_packets: usize, pending_bytes: usize, stall_timeout: Duration,
}
Lifetime { lease: Duration, ping_interval: Duration, pong_timeout: Duration }
Config::validate(&self) -> io::Result<()>
Config::validate_cover(&self, cover: cover::Config, ipv6: bool) -> io::Result<()>
Config::canonical_digest(&self) -> io::Result<core::ConfigDigest>

type Resolver = Box<dyn Fn(&swift::control::Policy)
    -> Option<swift::policy::Resolved> + Send + Sync>;
fn channel() -> (ControlHandle, ControlRequests);
ControlHandle::switch(&self, policy: swift::control::Policy)
    -> impl Future<Output = Result<u64, SwitchError>>;

async fn run<D>(device: D, parts: member::Parts,
    expected_configuration: security::ConfigDigest, config: Config,
    requests: Option<ControlRequests>, resolve: Resolver,
    shutdown: impl Future<Output = ()> + Send,
    observe: impl FnMut(&Snapshot) + Send) -> io::Result<Stopped>
where D: PacketDevice<Error = io::Error> + AsRawFd + Send;

Snapshot {
    running: bool, elapsed_micros: u64,
    info: member::Info, configuration: security::ConfigDigest,
    send: swift::policy::Direction, receive: swift::policy::Direction,
    committed: swift::policy::Committed, pending: Option<swift::policy::Pending>,
    swift: swift::records::Stats, swift_unconfirmed: usize,
    control: recovery::Retained, counters: Counters,
    liveness: Liveness, terminal: Option<StopReason>,
}
Counters {
    wire_packets: u64, wire_bytes: u64,
    socket_accepted_packets: u64, socket_accepted_ip_bytes: u64,
    socket_drops: u64, socket_receive_errors: u64,
    received_packets: u64, rejected_packets: u64, replay_rejections: u64,
    native_read: u64, native_written: u64, native_oversize: u64,
    native_backpressure_drops: u64,
    native_pending_packets: usize, native_pending_bytes: usize,
    user_number: Option<security::PacketNumber>,
    control_number: Option<security::PacketNumber>,
    user_generation: Option<security::KeyGeneration>,
    control_generation: Option<security::KeyGeneration>,
}
Liveness {
    outstanding: Option<u64>, deadline_micros: Option<u64>,
    last_verified_micros: Option<u64>, last_pong_micros: Option<u64>,
}
StopReason::{Cancelled, LeaseExpired, PeerTimeout, NativeStall, PolicyTimeout,
             Protocol, CounterExhausted, Io(io::ErrorKind)}
Stopped { reason: StopReason, snapshot: Snapshot }
```

`ControlHandle` is cloneable; `ControlRequests` is unique. The local queue holds
one request, in addition to one already accepted peer transaction. Busy,
NotCoordinator, Rejected, Invalid and Closed remain explicit. A successful
result is the actual committed epoch; dropping a waiter cannot cancel an
accepted distributed change or imply rollback. The authenticated initiating
role is the coordinator. Absence of local requests does not disable incoming
authenticated control or liveness.

The direction's `bytes_per_second` is the shared complete IP-wire rate, including
control, feedback and tails. There is no second conflicting rate in `WireBudget`.
The parent hashes both local contracts in global initiator/responder order.
Canonical bytes include every directional Swift field/rate, policy resource,
security interval/byte limit, initial epoch, control resource, wire/work/native
bound and lifetime duration. Integers use fixed byte order and durations retain
their exact representation. Only local reporting cadence is excluded. No secret,
real `Instant`, caller role ordering or circular expected global digest is hashed
as configuration input.

Runtime timers represented as microseconds must retain at least one effective
microsecond. Submicrosecond lease, challenge, native-stall, work-refill or report
durations are rejected rather than becoming an immediate expiry or zero quota
interval. Canonical configuration still includes each duration's exact bytes.

Initial send and receive policies may differ. Construct the complete pure engine
from the send policy and install the receive policy while it is drained, using
the initial authenticated number floor. Fixed native layer and maximum packet
size must agree. New policy resolutions must stay within the authenticated
physical/resource ceilings; unsupported geometry is rejected before proposing or
accepting a transition, never silently shrunk.

`Snapshot` will expose `running`, final bounded error/stop category, elapsed time,
the actual `member::Info` and full configuration digest, directional policies,
committed/pending transaction status, Swift counters and source retention,
control retention, native pending packet/byte counts, native writes, security
numbers/generations, rejected/replayed input, shared wire charges, native socket
acceptance/drop counters and the actual original endpoints. Pending native
delivery, Swift recovery retention and the wire budget are separate observations.
The synchronous observer must be bounded and nonblocking. It is called at first
actual readiness, configured reports and explicit return/error. External owner
drop releases all inline resources; the shared service publishes cancellation
after dropping them and never reports peer-confirmed clean closure.

`Stopped` reports an explicit cancellation/lease termination and final snapshot.
Protocol, native-stall, liveness, counter and nontransient I/O failures return
errors and publish their bounded final category. Snapshots are cloneable public
observations, without roots, keys or native handles. These status fields remain
subject to the parent's interface freeze before implementation.

## Complete geometry and immutable security

Swift uses common ChaCha20-Poly1305 protection in this composition. It does not
silently enable optional authentication-only data. The initial common control
scope remains fixed when data policies change; its key purpose, counters, replay
state and reliable service owner are never replaced by a data reset.

Both common record epochs are at least one, as required by L2SC. The pure Swift
coordinator's startup logical policy epoch zero is a different domain. A later
logical policy epoch maps to `config.data_epoch.checked_add(policy_epoch)`;
control epoch is unchanged. Overflow is an explicit failure. Keep distinct
send/source and receive/feedback scopes through a crossing and retain the extra
reader until both directions and their owed reliable control acknowledgments
complete.

Established IPv4 overhead is 76 bytes for QUIC appearance and 77 for media:
9 route bytes, 26 common security bytes, 13/14 cover bytes and 28 IP/UDP bytes.
IPv6 costs 96/97 bytes. The Swift `datagram_bytes` is the opaque body bound and
must fit the explicit path MTU after these costs. The old 1448-byte body cannot
be copied into a 1500-byte path without a setup rejection. Bootstrap overhead is
different and continues to use its existing checked contract.

Derive and validate `delivery::Settings.wire_overhead` against that exact fixed
established overhead. ARQ's 44-byte data header and 48-byte feedback packet are
inside the protected control body. The maximum security body must contain both
Swift bodies and the largest control recovery packet, and the cover/output
limits must contain every complete result. Full L2SC management requires at least
80 envelope plus 112 nested management bytes; a Ping/Pong envelope is 88 bytes.
An opaque tiny control fixture does not qualify the complete management grammar.

The immutable security/cover body capacity is a storage/admission ceiling,
distinct from the active `path_mtu`. Only current actual Swift/control packets
must fit the active path; a larger admitted security capacity must not reject a
smaller initial policy. Later negotiated policies can increase packet geometry
within the declared cover/storage and shared-burst ceilings. They cannot resize
an unauthenticated ceiling or silently alter the original requested geometry.

Before polling Swift, reserve complete output/workspace and shared allowance for
its maximum possible body. Pass `Records.next_number(User)` unchanged to
`swift::records::poll`; seal with that same full number. Its value is the GF repair
seed. Receive uses the full authenticated `Opened.number`, never an outer RTP
sequence, QUIC appearance number, channel index or ARQ identity.

Source/repair and feedback provenance is explicit. The parent facade adds
`Records::seal_user_in` for an exact registered scope; policy hooks choose the
source send scope or feedback receive scope. New sources cannot use the wrong
profile merely because a global active scope changed. Common counters and replay
owners persist across every local reader change. These hooks do not themselves
complete SW-11 or authorize a configuration-file switch.

## Bounded scheduler and native backpressure

One monotonic Tokio origin supplies checked Swift microseconds and reliable
control durations. Bounded receive, send, native-read and native-write batches
prevent a ready descriptor or recovery burst from starving cancellation,
control, reports and timers. Every receive attempt, including path errors and
malformed/oversized packets, consumes the finite ingress-work quota. Read one
extra UDP byte beyond the accepted outer ceiling to detect oversize truncation;
native reads use `device::READ_BUFFER_BYTES` before enforcing the negotiated MTU.

When native read and write interests share a readiness guard, a blocked operation
clears only its own readiness bit. Clearing both bits after one `WouldBlock` can
lose the still-ready opposite direction and stall otherwise valid traffic.

The sole reader structurally decodes the cover, services bounded bootstrap and
Joining tails, then authenticates established User/Control records. Only the
authenticated Control class may construct management `Ingress`. Bad MAC, replay,
unknown routes and malformed unauthenticated input are counted and ignored.
Malformed authenticated Swift/profile control is an explicit failure. Delivered
reliable control sources are strictly parsed and applied before the next
feedback poll can acknowledge them.

A shared full-wire token bucket admits every attempted packet, including both
tails, control sources/receipts, Swift feedback, sources, repairs and retries.
Control additionally obeys its fixed service quota and preserves a validated
source-plus-receipt reserve from user spending. Burst geometry must allow all
legal packet classes and meaningful reserved service. Charge each attempt once
at bounded wire-slot admission; native socket acceptance and transient loss are
different counters. Insufficient allowance/output cannot advance a pure producer,
reserve a nonce, consume an attempt or complete a policy operation.

Tail/control/User output fits one retained complete wire slot. A retry never
re-encrypts that already protected slot. After native acceptance or explicit
counted path loss, the corresponding underlying recovery owner governs its next
attempt. A blocked producer's next wake includes shared token availability;
past pure-service deadlines cannot create a busy loop while allowance is absent.
The driver continues the checked outer counter handed off by authentication.

Native output is retained as complete packets in an independently bounded queue.
`WouldBlock` preserves those bytes and waits for native writable progress while
the socket, control and deadlines remain serviced. The oldest stalled native
packet has one original stall deadline, never renewed by repeated readiness.
No silent native-output drop is copied from the historical Swift runtime.
Reserve a native queue slot/byte capacity before popping a recovered packet.
When native output is full, new User source/repair admission may be intentionally
withheld/dropped under the configured bounded receiver policy while incoming
User feedback and session control continue; no discarded source is acknowledged
as accepted by the Swift receiver. Exact backpressure/drop policy is part of the
freeze and must be observable, not inferred as a peer-device delivery window.

Native application TCP/window state, local storage, native delivery flight and
algorithm recovery retention remain different domains. This driver does not
claim transparent TUN owns endpoint cwnd or that a Swift recovery receipt proves
native device acceptance. TAP retains endpoint/system TCP policy; TCP-proxy,
active-TUN and all existing parity compositions keep their separate gates.

## Policy and lifecycle custody

The pure `swift::policy::Coordinator` retains proposal/digest agreement, admission
fencing, drain barriers, original transaction deadline and idempotent outbound
tokens. The runtime stages/retains exact data readers and supplies actual engine
drain and number evidence through its hooks. It does not replace negotiated
barriers with local `Records::activate_data`.

For the common UDP adapter, retain the bounded `OutboundId` to reliable `SourceId`
mapping until `delivery::Service::source_confirmed(source, now)` reports a
validated recovery acknowledgment. Only then, with a fresh check of the original
policy deadline, call `Coordinator::complete_outbound`. Submission, protection,
wire polling and native socket acceptance alone cannot complete a terminal
BarrierAck. The existing retained-TLS adapter keeps its original actual
write/flush ownership rule. Parent-owned typed L2SC `ProfileControl` preserves
the exact bounded Swift control grammar without turning user EtherTypes into
management authority.

The original `Parts.deadline` bounds setup, first readiness and final-flight tails.
It is not the established session lifetime. Tail expiry retires those owners;
it cannot kill a valid established transport or extend authentication. A separate
explicit finite active lease bounds common reliable control. Ping/Pong challenge
interval and timeout are separate from lease, native stall and policy expiry.
One bounded fresh challenge identity and exact matching Pong provide authenticated
round-trip liveness; ICMP and arbitrary incoming traffic do not prove it. Liveness
uses the same charged reliable Control service throughout data changes.

The precise body-specific L2SC scope rule for mode-independent Ping/Pong and
profile control is now confirmed by the parent integrator: Ping/Pong use the
immutable fixed Control scope; ProfileControl uses its originating Data scope,
which must be an actually registered active/staged/draining scope during a
crossing. Outer `Records` always authenticates these envelopes as fixed-scope
Control. The strict typed dispatcher validates actual session, lane, remote
role, nonwrapping ordered logical envelope counter and body-specific scope
before effects. It does not change the existing generic L2SC gate's semantics.
Do not pretend Swift has the existing SelectiveRepeat feedback tag merely to
reuse that gate. Swift feedback remains authenticated User traffic.

The parent-owned additive wire kind is L2SC kind 6, `ProfileControl`, with
`ProfileTag::SwiftPolicyV1 = 1`. Its body is
`[tag u16 big endian][reserved u16 = 0][exact Swift control frame, 1..43 bytes]`.
Existing L2SC kinds retain their bytes. Fresh verified traffic and a matching new
Pong update only their specified liveness observations; duplicates, cache
responses, invalid or stale Pongs cannot extend the current challenge deadline.

The current driver dispatch implements `Ping`, `Pong` and
`ProfileControl { SwiftPolicyV1, ... }`. Authenticated legacy `Management`,
`NativeReceipt` and the other typed `RecoveryFeedback` bodies are explicit
unsupported-protocol failures in this composition. Validating capacity for their
envelope bounds does not implement those handlers, general management operations
or switching between record profiles. Their existing target requirements remain
open under FIX-11, SW-11 and the other module gates.

Numbered common key generations are available. Fresh-DH rekey/rehandshake,
retained-state outage recovery, peer-restart reconciliation and complete common
mode switching remain distinct required work. This driver cannot advertise them
from a key interval, enum or successful compile. Unsupported requests remain
observable and fail explicitly; no implicit recovery/default/carrier fallback
is added by this scoped change.

## Deadline and ready-work corrections

The [first deadline-focused run](../../work/secure-udp-deadline-focused-20261113/attempt-1/validation.json)
reproduced a matching authenticated Pong clearing its original challenge exactly
at expiry. It also preserved a fixture assertion that assumed the wrong initial
envelope number. The correction requires arrival strictly before the existing
challenge deadline; exact or later arrivals retain the challenge and terminate
with `PeerTimeout` on progress. The fixture now checks relative envelope progress.
The [second focused run](../../work/secure-udp-deadline-focused-20261113/attempt-2/validation.json)
passed all 20 transport tests and strict runtime Clippy with unchanged inputs.
Its new tests use actual Noise/member roots and protected L2SC/control-ARQ
dispatch for both covers with injected driver time. They verify immutable lease
expiry, fresh stale/mismatched Pongs and exact/late matching Pongs without sleeps.

The same source review found a separate native boundary: a writable
device event can win after the original front-packet stall deadline, transmit
and remove that obligation before the next expiry check. The reviewed correction
extracts an expiry-only guard, checks fresh time before event effects and retains
the original native obligation through completion checking. A late physical write
cannot be rolled back or counted as unwritten: it is popped and counted exactly
once, then the original expiry/error is reported. Six deterministic real-root,
real-descriptor tests cover before/exact/after expiry, a call crossing the bound,
completion-clock/check errors, lease admission and original terminal precedence.
All six passed in the [28-test regression run](../../work/secure-udp-deadline-focused-20261113/attempt-3/validation.json),
whose overall result remains failed because of the separate wakeup defects below.

That run reproduced ready retransmissions and earned repairs sleeping until a
later idle probe after the wire bucket was exhausted. The previous runtime
checked data readiness before its idle deadline; the new driver had omitted that
branch. Its correction wakes ready work at the existing full-packet credit time,
while preserving the control reserve, future-data/feedback deadlines and100us
re-observation floor. Wake calculation never emits, consumes credit or advances
nonces/counters. The two regressions construct actual authenticated loss/request
feedback or earned repairs with an empty packing queue and independently prove
that other timers cannot mask the result. The [fourth focused run](../../work/secure-udp-deadline-focused-20261113/attempt-4/validation.json)
passed all 28 transport tests and strict runtime Clippy with unchanged inputs.
The source-stable failed runs remain preserved. Native validation of this final
source remains separate from the earlier baseline performance receipts.

## Acceptance ledger

- [x] [SUR-01] Freeze the exact runtime, immutable canonical binding, control/observer, typed wire, lifecycle, scope and bounded-native ownership APIs before implementation. Evidence: the design/API above was frozen before the [runtime implementation](../../crates/l2tunnel-runtime/src/secure_udp/transport.rs); [canonical-contract/resource regressions](../../crates/l2tunnel-runtime/src/secure_udp/transport_tests.rs) passed in the [focused receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json).
- [x] [SUR-02] Implement real native PacketDevice transport with the original member-authenticated socket, one reader, both retained tails, complete pure Swift records and common AEAD User/Control owners. Evidence: [runtime](../../crates/l2tunnel-runtime/src/secure_udp/transport.rs), [both-cover independent-runtime native fixture](../../crates/l2tunnel-runtime/src/secure_udp/transport_tests.rs), [focused passing receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json). Scope is actual AF_UNIX packet-device and loopback UDP I/O, without TAP/TUN or platform/performance qualification.
- [ ] [SUR-03] Verify full-wire budgeting, fixed control reservation, every receive/work/native bound, parser/output/nonce preflight and original deadline behavior without busy loops or uncharged feedback. Partial evidence: [28 passing transport regressions](../../work/secure-udp-deadline-focused-20261113/attempt-4/validation.json) cover exact token credit, checked geometry/timers, parser-before-pressure, replay/tamper, preauthentication usage-guard rejection, expired tails with no allowance, event-expiry precedence and ready-retransmission/repair credit wakeups. The complete runtime hostile-ingress/quota and charged transient-loss matrix remains required.
- [x] [SUR-04] Verify retained complete native output through WouldBlock and eventual exact device acceptance; bound permanent stalls and distinguish native storage, device completion and recovery retention. Evidence: [real AF_UNIX pressure, permanent-stall and opposite-readiness tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_tests.rs), [initial focused receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json), and the [28-test deadline/wake result](../../work/secure-udp-deadline-focused-20261113/attempt-4/validation.json). The pressure fixture requires actual socket `WouldBlock`, bounded retained ownership and all 64 exact FIFO completions. New real-descriptor event steps prove before/exact/after stall boundaries, a successful call crossing expiry and correct irreversible completion accounting when clock/check errors occur. The expiry-only guard preserves the original terminal precedence and prevents a late writable event from erasing the deadline.
- [ ] [SUR-05] Integrate actual authenticated typed profile control with pure coordinator drain barriers, full digests, scoped source/feedback and confirmed reliable-source custody; no local-only switch or premature Applied result. Partial evidence: the [driver](../../crates/l2tunnel-runtime/src/secure_udp/transport.rs) retains each outbound token until `source_confirmed`; the [both-cover clean negotiated switch](../../crates/l2tunnel-runtime/src/secure_udp/transport_tests.rs) passed. A dropped terminal acknowledgment, delayed crossing feedback and explicit no-premature-`Applied` runtime regression remain required.
- [x] [SUR-06] Implement and test fixed-control authenticated Ping/Pong, finite lease and explicit cancellation/failure/status behavior across data changes without renewing unrelated deadlines. Evidence: [native/policy/liveness, matching-Pong-deadline and cancellation tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_tests.rs) include control progress with blocked native output and prove fresh User traffic does not renew a challenge. The [20-test focused deadline result](../../work/secure-udp-deadline-focused-20261113/attempt-2/validation.json) adds original established-lease expiry, fresh stale/mismatched Pongs and exact/late matching-Pong rejection for both covers through actual protected control dispatch. Native event/completion expiry is independently verified under SUR-04; this scoped liveness gate does not complete recovery or the hostile-input matrix.
- [ ] [SUR-07] Exercise real shared factories, connected sockets and nonblocking PacketDevice adapters in independent runtimes for both covers/profiles, IP/Ethernet bytes, loss/reorder/replay, bounded hostile input, final handoff and policy/liveness cases.
- [x] [SUR-08] Pass focused tests, formatting, warning-denied Clippy/rustdoc and required frozen-source aggregate; preserve failed receipts and distinguish loopback runtime from privileged native/network/device performance. Evidence: the [28-test focused driver check](../../work/secure-udp-deadline-focused-20261113/attempt-4/validation.json) and [required source-stable aggregate](../../work/secure-udp-native-progress-20261113/attempt-1/validation.json) passed. The aggregate records 1498 Rust cases including doctests, 285 Python tooling cases and 1658 simulator cases, with formatting, strict workspace Clippy, rustdoc and unchanged input maps. Failed Pong/wake regression attempts and failed native attempts remain preserved. Full fault/lifecycle/native/GUI/platform qualification stays open.
- [ ] [SUR-09] Qualify shared service/CLI/GUI selection and owned-namespace TAP/TUN transport/performance while retaining all lifecycle, full SW-11, OpenVPN/HTTPS, platform and 47-mode requirements.

The checked tasks above include their scoped implementation/test evidence;
writing a design alone did not complete them. Ownership is limited to this document
and `secure_udp/transport.rs` and `transport_tests.rs`; parent and
other workers own declarations, facade/control/coordinator changes, shared
client/service integration and native qualification.

The parent integrator actually ran:

```text
cargo test --offline --locked -p l2tunnel-runtime secure_udp::transport::tests -- --test-threads=1
cargo test --offline --locked -p l2tunnel-client-core secure_udp -- --test-threads=1
cargo test --offline --locked -p l2tunnel-client-core service::tests -- --test-threads=1
cargo test --offline --locked -p l2tunnel-client-core local:: -- --test-threads=1
cargo clippy --offline --locked -p l2tunnel-runtime -p l2tunnel-client-core --all-targets --all-features -- -D warnings
cargo doc --offline --locked -p l2tunnel-runtime -p l2tunnel-client-core --no-deps
```

The receipt hashes the declared compiled source graph before/after these commands
and records no source changes. Its scope excludes documentation, unrelated tools,
configuration and simulator files; it is not the required whole-tree aggregate.
Earlier failing attempts remain historical receipts and are not overwritten.
