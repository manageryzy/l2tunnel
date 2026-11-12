# Raw owner consume and checked-counter design

Status: the pure tracked engine, counted stream gate and separate switchable I/O
driver are implemented. Pure/mock tests cover local transfer; authenticated TLS
freeze and startup packet-phase integration now have finite full/half mock
evidence in [checkpoint 15](../../work/raw-transition-checkpoint15/REPORT.md);
native transfer remains unqualified. The [reviewed stack getter](raw-stack-handoff.md) observes
logical TCP state; external ownership is a separate proof. Existing `TcpEngine`,
`bridge`, `Driver::run`, `open` and `open_marked` contracts remain unchanged.
No native packet-phase test or client capability is authorized by this document.
The next [authenticated TLS/peer transition contract](raw-tls-transition.md) is
implemented for bounded startup use; its larger TLS/failure/native acceptance
gates remain explicit and open.

## Pure tracked owner

The additive `l2tunnel_raw_tcp::handoff` module is implemented. Its `TrackedEngine` exclusively
owns a boxed `TcpEngine`, exact stream totals and the initial role. Construction
starts tracking from the original connection creation; there is no constructor
adopting an already-used engine, mutable inner accessor or untracked escape hatch.
The fixed box keeps a failed consume result small while returning the original
owner, without allocating a second stack or duplicating TCP validation.

```rust
// Implemented pure API; this does not prove external I/O or authentication.
pub struct StreamProgress {
    pub send_admitted: u64,
    pub receive_consumed: u64,
}
pub struct TrackedEngine { /* private unique maintained engine and counts */ }
impl TrackedEngine {
    pub fn new(config: Config, role: Role, now: Millis) -> Result<Self, Error>;
    pub fn new_ip(config: IpConfig, role: Role, now: Millis) -> Result<Self, Error>;
    // ingest, poll, pop_packet, write, read, close, abort, status delegate to
    // the same maintained engine, with the checked read/write contract below.
    pub fn progress(&self) -> StreamProgress;
    pub fn try_into_quiescent(self, now: Millis)
        -> Result<QuiescentTcp, (Self, HandoffError)>;
}
pub struct QuiescentTcp { /* private fields; no Clone or public constructor */ }
impl QuiescentTcp {
    pub fn snapshot(&self) -> &BootstrapSnapshot;
}
```

`BootstrapSnapshot` owns the maintained getter's exact tuple/frontiers/window and
option fields, immutable raw configuration/role, last poll time and exact stream
totals. It may expose a copied read-only view. That view is not a capability:
future packet-engine construction consumes the unique `QuiescentTcp`, together
with separately authenticated phase configuration and keys. Pure quiescence
alone does not authenticate the peer or prove physical output completion.

Before `write`, check that the whole provided byte slice can be represented in
the remaining `u64` send total, then call the same `send_slice`. Charge only the
actual accepted count. Before `read`, check the maximum possible returned count
(the minimum of caller capacity and current readable bytes) against the remaining
receive total, then call the same `read`. Charge only actual `Data(n)`; Pending,
EOF and errors charge zero. Preflight guarantees the post-I/O addition cannot
fail. Overflow is explicit before changing rings, caller output or counters; no
saturation, wrap, fabricated progress, counter reset or replayed accounting.
A conservative send preflight can reject a large caller slice even if the ring
would accept only a prefix: the caller may submit a representable smaller slice.

Consuming performs only read-only checks. Require `polled`, `now == last_time`,
valid injected time, positive send and receive totals, established/no-close/no-FIN
state, empty engine ingress and egress queues, and a successful maintained
`quiescent_snapshot(now)`. Do not poll,
rewrite timers, close, abort or change the counters inside the consume call.
Failure returns the same original owner and `HandoffError`: `Time`, `StalePoll`,
`QueuedPacket`, `EmptyPrefix`, `NotQuiescent` or `UnsupportedOption`. Tracked
operation errors separately preserve the original engine error or identify the
exhausted `StreamSide`. Successful consume
drops the old in-memory stack without polling and creates the unique snapshot
capability. No destructor sends a packet. Fixed callback/poll budgets remain the
same as the current engine.

The maintained getter can describe an empty established connection. The
implemented `TrackedEngine` consume operation additionally requires positive send
and receive stream totals; the later authenticated supervisor must prove those
are the original ciphertext prefixes. This matters for window scale: immediately after a
scaled passive handshake the last raw advertised window may still come from the
**unscaled SYN-ACK**. A positive fully acknowledged post-handshake send prefix
proves a non-SYN advertisement before interpreting the last window with the
negotiated shift. Test this distinction explicitly; do not change the approved
getter or invent a last-window-kind field in its public data.

## Separate switchable I/O owner

The additive `l2tunnel_raw_io::handoff` module uses the same atomic `PacketIo`.
The existing driver remains independently usable. The separate driver stores all its
retained buffers as owner state, rather than losing access to function-local
buffers on a handoff request.

```rust
// Implemented local ownership API; no runtime/auth-layer activation.
pub fn bridge_switchable<I: PacketIo>(config: Config, role: Role, io: I, limits: SwitchLimits)
    -> io::Result<(TrackedStream, SwitchHandle, SwitchDriver<I>)>;
impl SwitchHandle {
    pub fn status(&self) -> SwitchStatus;
    pub fn request_handoff(&mut self, deadline: Duration) -> io::Result<()>;
}
impl SwitchDriver<I> {
    pub async fn run(self) -> io::Result<SwitchExit<I>>;
}
pub enum SwitchExit<I> {
    Clean(Counters),
    Handoff(HandoffParts<I>),
}
pub struct HandoffParts<I> { /* original I, QuiescentTcp, exact BridgeProof */ }
```

The implementation uses `SwitchLimits { work_limit: usize,
max_handoff_duration: Duration }`, with defaults of 32 operations and 30 seconds.
Work must be 1..=1024 and is still passed through the maintained engine's own
validation; maximum handoff duration must be 1..=30 seconds. Geometry remains the
validated raw configuration: one MTU-sized duplex in each direction, two
MTU-sized retained stream buffers, one 65536-byte raw receive sentinel and at
most one popped raw packet in addition to the bounded engine queues/rings.
A successful result uses one fixed boxed private owner/proof bundle, keeping the
public completion enum small without cloning or reconstructing I/O.

`EndpointProgress` reports actual endpoint `written` and `read` bytes.
`BridgeProgress` reports exact `outbound_read`, `inbound_written`, raw received,
popped and sent packet/byte counts, plus discarded packet count. `SwitchStatus`
is a coalesced observation with state, elapsed time, endpoint/driver progress and
optional maintained status/deadline; it is never a completion capability.
`BridgeProof` exposes read-only endpoint/driver/engine totals and has no public
constructor. `HandoffParts` exposes `snapshot()`/`proof()` and consuming
`into_parts()` for the original I/O, unique `QuiescentTcp` and `BridgeProof`.

Reject handoff before `run()` publishes its start instant. Validate a live
absolute time under the shared gate, not a stale status timestamp. The final
liveness/deadline check, unique engine consume and gate completion occur without
awaiting; a second live deadline check after synchronous consume/allocation must
also pass before commit. Expiry there is terminal and releases the shared gate before dropping the consumed bundle, without rollback
or cleanup packets. Generic packet I/O destructors may reenter handle/status
code, so they must never execute under that mutex. The driver then returns the original
resources immediately. Ready bridge operations charge their actual progress once
and check the original deadline before another I/O turn; the fixed deadline is
also checked immediately before constructing their futures.

`deadline` is an absolute duration since this driver's start, not a renewed
relative timeout. `SwitchLimits` fixes a finite maximum handoff duration, normal
bounded work and buffer geometry before construction.
It does not control the already-existing handshake/idle policy. Reject a stale,
zero/excessive or second handoff request before freezing anything. One private
command slot and one unique handle are enough; there is no request backlog or
unbounded response list. Read-only status uses one coalesced snapshot.

`TrackedStream` wraps the finite duplex endpoint and is compatible with ordinary
`AsyncRead + AsyncWrite + Unpin` TLS bootstrap. A private shared gate serializes
its poll operations with handoff submission. Each successful write counts bytes
accepted from TLS into the duplex; each read counts only the actual `ReadBuf`
filled-length delta. Check the largest possible count before delegating the poll.
A Pending/error poll changes no count. Only actual accepted bytes are charged.
Endpoint preflight conservatively reserves the entire caller slice or remaining
read-buffer capacity; the caller may use a smaller representable buffer near
counter exhaustion. No key or application plaintext is stored in these counters.

The request first reserves its single command slot, then atomically freezes both
tracked stream directions and snapshots their exact totals under the gate. A
failed reservation leaves the stream usable and unchanged. Once frozen, further
read/write/flush/shutdown calls fail explicitly; they must not pretend EOF,
write zero, silently accept new bytes, or remain pending forever. Only the driver
can consume the private command and bind its proof to this bridge instance;
caller-provided integer fences cannot substitute. Request acceptance is not
handoff completion: only the actual `SwitchExit::Handoff` returns ownership.

The TLS supervisor must stop all TLS polling after terminal Seal and before this
request. It retains the original authenticated TLS objects, session metadata and
exported keys. Freezing ciphertext I/O cannot prove that rustls has no buffered
plaintext/ciphertext, pending KeyUpdate/alert or unread application record. Those
are separate authenticated manager/TLS-freeze gates, not assertions made by this
primitive. Current `AuthenticatedIo::into_parts` retains the original TLS object;
no credentials, tuple, TLS handshake or TCP sequence may be reconstructed.

## Exact external proof

The driver maintains checked lifetime counters independent of the old saturating
diagnostic `Counters`. Its private proof must establish all equalities together:

| Direction/boundary | Required equality at transfer |
| --- | --- |
| Outbound original ciphertext | frozen TLS-written = duplex-read by driver = tracked engine send-admitted |
| Inbound original ciphertext | tracked engine receive-consumed = duplex-written by driver = frozen TLS-read |
| Raw emission ownership | packets popped from engine = packets successfully sent through atomic `PacketIo::send` |

Also require zero retained input/output suffixes, no retained raw WouldBlock
packet, empty maintained ingress/egress queues and the logical quiescent consume
proof at the same time. With exactly one producer and consumer on each finite
bridge direction, the byte equalities prove that its hidden duplex queues are
empty. They do not prove remote application consumption or native packet delivery.
Those have their own authenticated barriers.

Reserve counter space before taking a packet from the engine or calling atomic
send. WouldBlock keeps exactly the same owned packet and does not charge a
successful send. A syscall error retains its original `io::Error` kind/errno and
is a terminal failure; do not treat it as a successful drop. Readable old incoming
packets continue through the maintained stack within finite work until the
snapshot can succeed. Unexpected ciphertext beyond the frozen fence is a
failure, not a reason to grow the fence or resume TLS.

The driver can drain ciphertext already written before freeze into the TCP ring
and wait for genuine peer ACKs. It cannot consume additional ciphertext on behalf
of a frozen TLS reader. If its inbound equality cannot hold because bytes were
not actually consumed by TLS, the request fails or reaches its original deadline.
No `DuplexStream::flush`, queue read attempt, elapsed timer or peer ACK count may
be substituted for exact endpoint counters.

The maintained snapshot uses the last checked millisecond poll time. Bounded
synchronous packet/bridge work may occur between that poll and the live-clock
commit check: this is a consistent logical stack boundary, not an atomic
wall-clock snapshot of TCP timers. Deadline checks use the live runtime clock
independently and never substitute that logical poll timestamp for expiry.

On successful consume the same `I` moves into `HandoffParts`; no `open`, mark
change, reservation release, second SYN, close_notify, FIN or RST occurs. The old
stack is no longer polled. `Clean` remains the maintained path's separate actual
FIN/ACK/drain result. A logical handoff is never renamed a clean TCP close. After ordinary `Clean`,
the endpoint can still consume bytes already buffered in the duplex and observe
its real EOF; this path has no `BridgeProof` and does not claim TLS consumption.

## Cancellation, early packets and scope

Before a request is accepted the tracked stream behaves like the retained path.
After freeze, expiry or cancellation is terminal; this primitive provides no
unfreeze or same-tuple rollback. Dropping the stream/handle while a request is
pending invalidates its proof; the driver fails without creating a capability.
Dropping the driver closes its owned I/O through ordinary resource ownership and
never emits a reset through a cleanup poll. The supervisor must join/abort every
worker; no detached driver survives an auth/runtime failure.

Check the fixed deadline on every turn and around any awaited operation. Native
I/O remains nonblocking, retained bridge writes remain cancellation-safe, and a
full peer/native queue cannot postpone the deadline indefinitely. A partially
transferred object is never exposed through a notification before the driver
actually returns its unique handoff result.

That earlier slice did not implement the required pre-Seal authenticated packet
classifier/quarantine, old-prefix responder, all-lane Prepare/Seal/Hello/Commit,
packet crypto metadata validator or native drain. In the final profile, early
protected phase packets must never enter the old TCP/TLS stream. The classifier
must be armed before terminal Seal and share the existing datagram authentication
and bounded work; its missing implementation blocks real packet-phase activation.
Only synthetic/owned test streams may exercise the primitive before that gate.
A one-sided pure transfer cannot answer later old-prefix retransmissions until
the separate responder is implemented; successful local ownership transfer is
not proof that the other peer can finish its transition.

## Implementation checklist

- [x] [MOD-RAWOWNER-01] Reviewed the pure and I/O interface design, exact proof obligations, no-rollback boundary and separate TLS/auth/native requirements; driver bounds still require implementation validation. Evidence: [reviewed contract](#separate-switchable-io-owner), [exact external proof](#exact-external-proof).
- [x] [MOD-RAWOWNER-02] Implemented opt-in TrackedEngine counters, partial/zero progress and overflow-before-mutation tests with unchanged legacy APIs. Evidence: [implementation](../../crates/l2tunnel-raw-tcp/src/handoff.rs), [counter regressions](../../crates/l2tunnel-raw-tcp/src/handoff/tests.rs).
- [x] [MOD-RAWOWNER-03] Implemented failure-atomic consume with original-owner, stale-poll, queued/unread/unacknowledged bytes and positive-prefix window-scale regressions; maintained assembly/timer predicates retain their separate upstream tests. Evidence: [consume regressions](../../crates/l2tunnel-raw-tcp/src/handoff/tests.rs), [maintained predicate evidence](raw-stack-handoff.md#narrow-validation-plan).
- [x] [MOD-RAWOWNER-04] Implemented bounded TrackedStream, unique request gate and SwitchDriver with the legacy driver unchanged. Evidence: [stream gate](../../crates/l2tunnel-raw-io/src/handoff/stream.rs), [driver](../../crates/l2tunnel-raw-io/src/handoff/driver.rs).
- [x] [MOD-RAWOWNER-05] Tested original mock I/O owner identity, exact duplex/engine/raw counters, partial/Pending progress, retained final ACK and actual-send versus logical-emission distinction; no real descriptor transfer is claimed. Evidence: [bounded mock tests](../../crates/l2tunnel-raw-io/src/handoff/tests.rs).
- [x] [MOD-RAWOWNER-06] Passed one-sided/simultaneous freeze, unread ciphertext, EOF/close, bridge/request reuse, exhausted counters, blocked output, cancellation, malformed flood and ready-after-expiry checks without FIN/RST at mock handoff. Evidence: [18 focused regressions](../../crates/l2tunnel-raw-io/src/handoff/tests.rs), [live deadline/commit checks](../../crates/l2tunnel-raw-io/src/handoff/driver.rs).
- [ ] [MOD-RAWOWNER-07] Independently review and pass focused pure/async tests, strict checks and coordinated aggregate before any integration claim.
- [ ] [MOD-RAWOWNER-08] Integrate authentic TLS freeze, all-lane transaction, early-packet quarantine and old-prefix responder before native packet-phase experiments.

## Pure checkpoint validation

On 2026-11-11, `cargo test --offline --package l2tunnel-raw-tcp` passed
19 tests: the existing 12 retained-engine tests and seven new handoff tests.
`cargo clippy --offline --package l2tunnel-raw-tcp --all-targets -- -D warnings`
and `RUSTDOCFLAGS='-D warnings' cargo doc --offline --package l2tunnel-raw-tcp
--no-deps` passed. `cargo fmt --package l2tunnel-raw-tcp` was applied.
The [stable wave9 aggregate](../../work/implementation-wave9/validation.json)
passed for this pure checkpoint. No driver handoff,
authenticated TLS freeze, packet-phase or native test is included in these results.

The pure capability adds only a fixed boxed maintained engine and two checked
`u64` counters. Existing validated ring, packet-slot, MTU and poll-work bounds are
unchanged. There is no snapshot import, progress setter, adopted engine or mutable
inner-engine escape in the public API. The copied `BootstrapSnapshot` fields are
inspectable data, and constructing those fields cannot construct `QuiescentTcp`.

The held-ACK regression intentionally proves the boundary of this capability: a
receiver can be logically quiescent after its final ACK was removed into an
external queue, while the sender still has unacknowledged bytes. This is permitted
for the pure capability and must fail the later driver's physical-send equality
until that exact retained packet is successfully sent. Dropping the pure
capability emits no packet.

## Switchable driver review and validation

On 2026-11-11, `cargo test --offline --package l2tunnel-raw-io handoff`
passed all 18 focused driver tests. The full package command passed 25 tests,
with its one explicit privileged descriptor diagnostic ignored.
`cargo clippy --offline --package l2tunnel-raw-io --all-targets -- -D warnings`
and `RUSTDOCFLAGS='-D warnings' cargo doc --offline --package l2tunnel-raw-io
--no-deps` passed after the final fixes. Package rustfmt was applied, and local
evidence links resolve. The coordinated aggregate for this driver remains pending.

Independent review identified a post-consume deadline edge and destruction of
rejected generic I/O under the gate mutex before the final checkpoint. The
implementation rechecks live time after consume/allocation and around ready
bridge operations, and releases the gate before rejected owner destruction.
Three focused helper regressions use an actual unique consumed bundle, an actual
completed bridge read at expiry, and a destructor that verifies the gate is
unlocked and Failed with `try_lock`. All passed in the final 18-test run. They
establish the shared completion checks without claiming to make synchronous
stack destruction a wall-clock atomic step.

The mocks retain two actual maintained TCP engines and fixed-capacity packet
links. Successful `PacketIo::send` means adapter acceptance, including a mock
physical send subsequently lost in transit; it does not mean peer receipt. A
WouldBlock packet remains byte-identical and owned until that send succeeds.
The identity test uses the original mock owner's allocation, not a Linux file
descriptor. Tests emit no privileged network operations and do not run TLS.

## Startup transition checkpoint 15

The from-birth packet wrapper now moves through actual `HandoffParts` with the
same original I/O, opener/replay state and frozen TLS object. The maintained
snapshot remains authoritative for TCP acceptance/frontiers. Its
`last_window_sent` precedes a pinned smoltcp interface encoder clamp, so the
wrapper additionally records the last **physically successful encoded** ACK/window
and verifies its sequence end and ACK against the final maintained snapshot.
This is a narrow original-send witness, not an independent TCP acceptance model.
The actual emitted window controls the finite receive horizon, old-prefix ACK and
Hello proof. A packet-slot/window profile too small for eight maximum controls
plus one data cell is rejected terminally after consume.

The focused raw crates passed 147 tests (126 raw-I/O, 21 raw-TCP), with one explicit
privileged raw descriptor test ignored. The full/half transition, loss/retry,
replay/range conservation, cancelled WouldBlock, early-data ordering and cached
control expiry details are in the checkpoint report. These are local unprivileged
mock links with real maintained TCP/TLS/authentication, not kernel/native tests.
