# Authenticated TUN TCP proxy runtime

Status: implemented runtime composition with source-stable aggregate and finite
clean native Linux TUN full/paired-half qualification; broader gates remain open.
The [session table](proxy-session.md), [pre-ACK admission](proxy-admission.md)
and [relay leg](tcp-proxy.md) now compose with actual retained TCP/TLS connections
and an injected TUN device. [Explicit client selection](proxy-client.md) and
[owned clean native evidence](proxy-native.md) cover fixed credit, IPv4/IPv6 and
both duplex modes. Adaptive windows and the complete proxy mode remain separate.

## Scope and source boundaries

The first profile is explicit `tun_tcp_proxy`, IPv4/IPv6 TUN, fixed configuration,
CRC32 channel affinity, fixed buffer-backed relay targets and ordinary TCP/TLS.
The authenticated TLS client is the sole proxy originator; the authenticated
server is the acceptor. Either side can still originate transparent connections.
No preexisting or bypassed connection changes TCP ownership during this session.
Full duplex retains one authenticated connection; paired half duplex retains
two independently authenticated connections and the existing pairing proof.

Both directions keep the original native source/destination tuple. Application
bytes, including application TLS, remain opaque. TCP state/options are owned by
the maintained per-leg stack after admission; this is not transparent TCP-header
rewriting. Unsupported SYN profiles stay transparent from the start according to
the pure table. Authorization failure after an Open is owned produces rejection
or termination, never an automatic fallback of an acknowledged stream.

Initial exclusions are TAP/VXLAN, custom UDP or QUIC carriers, raw TCP selection,
compression/header coding, FEC, hot reload, simultaneous proxy origination,
transparent-to-proxy migration and a measured adaptive target controller.
`Compression::None` is mandatory. The existing `TargetController` may later
drive `Table::set_target` only with real ACK/queue/RTT observations and separate
tests; enum selection or timer-only growth must not enable that capability.

Approved implementation ownership:

| File | Change |
| --- | --- |
| `crates/l2tunnel-runtime/src/proxy.rs`, private `proxy/*.rs` | Tokio actor, retained carrier tasks, canonical configuration, route policy, bounded record arbiter and public API |
| `crates/l2tunnel-runtime/src/proxy_tests.rs` | Real authenticated loopback, independent maintained native endpoints and failure tests |
| `crates/l2tunnel-runtime/src/lib.rs` | Only additive `pub mod proxy;` declaration |
| `crates/l2tunnel-runtime/Cargo.toml` | Existing `l2tunnel-tcp-proxy` and `l2tunnel-qos`; maintained `l2tunnel-raw-tcp` host engines are a test dependency |

The pure proxy files remain owned by their current implementation author. No
pure state machine is duplicated. Its owner added the narrowly reviewed
`admission::inspect_open` accessor for authoritative remote tuple/DSCP inspection;
runtime metadata retains the bounded flow-ID-to-tuple mapping. Existing runtime paths,
wire profiles and constructors retain their current behavior.

## Public interface

These names are exported from `l2tunnel_runtime::proxy`.

```text
NativePolicy {
    mtu, send_bytes, receive_bytes, packet_slots,
    ack_delay_millis, keepalive_millis, idle_timeout_millis,
    time_wait_reset_policy: TimeWaitResetPolicy,
}
RelayPolicy {
    max_flows, max_policies, max_record_bytes,
    maximum: Window, initial: Window, admission_timeout,
}
MuxPolicy {
    channels, max_flow_bindings, queue_bytes, queue_records,
    per_flow_bytes, per_flow_records, quantum_bytes,
    dscp_weights: [u16; 64],
}
DeliveryPolicy {
    transparent_bytes, transparent_packets,
    native_queue_bytes, native_queue_packets,
}
Timeouts { startup, control_idle, shutdown }
RouteRule { source: IpPrefix, destination: IpPrefix, ports: PortRange }
RoutePolicy { rules: Vec<RouteRule> }
Config {
    runtime: RuntimeConfig, duplex: Duplex,
    native: NativePolicy, relay: RelayPolicy,
    mux: MuxPolicy, delivery: DeliveryPolicy,
    routes: RoutePolicy, timeouts: Timeouts,
    flow_poll_work, stack_poll_work, control_rate,
}
Config::validate(&self) -> io::Result<MemoryBound>
session_config(&Config) -> io::Result<auth::SessionConfig>
Link::full(auth::AuthenticatedConnection, &Config) -> io::Result<Link>
client_pair(first, second, &Config) -> io::Result<Link>
server_pair(first, second, &Config) -> io::Result<Link>
control_channel() -> (Handle, Control)
Handle::status() -> Option<Status>
Handle::request_drain() -> io::Result<DrainWaiter>
run<D: PacketDevice<Error = io::Error>>(
    device: D, link: Link, config: Config, control: Control
) -> io::Result<CloseReport>
```

The public Link wraps the existing retained TLS Link. Its constructors check the
exact profile before consuming it; `run` checks the same immutable binding before
any native read. The role is inferred from authenticated member metadata, not an
unchecked caller boolean. Pair construction validates both lane identities,
configuration, distinct sessions and the existing random pair proof.

`Status` reports phase, original transparent admission/delivery, lifetime flow
count, combined opening/active count, stopped/retired counts, current common
arbiter/native handoff bytes and records, and a bounded failure string. It does
not yet export per-flow relay counters or all TLS/OS queue occupancy. A TCP ACK
is never reported as application consumption.
The command channel has one queued command slot, at most one active drain reply
and a coalesced status watch. A repeated request receives an explicit rejection
and cannot renew the deadline. Dropping the controller is cancellation, not
successful shutdown.

## Complete authentication and session identity

Use a new canonical digest domain
`l2tunnel/tun-tcp-proxy-runtime/v1/retained-tls/crc32/fixed-credit`.
Bind every operator-controlled field above, including durations in exact integer
units, every weight, route-rule order/canonicalization policy, all work/rate and
memory bounds, IPv4/IPv6 interpretation, fixed frame/record versions, duplex,
and the role rule `TLS client = originator`. Each side hashes the same ordered
role pair; hashing opposite local-role values independently would break pairing.
Unknown, unused or unsupported configuration is rejected, never ignored.

The common logical session is the first authenticated lane's session ID. In
paired mode derive it consistently as client send-session/server receive-session;
do not use whichever lane happens to be the local reader. Physical outer
records retain their own actual lane session and continuous packet-number space.
The proxy table uses the common session, epoch 1 and monotonically allocated
flow IDs. Inner and outer identities must both be verified before table mutation.

`NativePolicy` deliberately contains no placeholder local/peer tuple or random
seed. Actual per-flow tuples come from validated original SYNs and exact route
authorization. The bound seed policy is `local-system-random-u64-v1`: sample a
fresh nonzero local stack seed with the existing maintained CSPRNG after
authentication; RNG failure or zero is an explicit startup failure. It is local
ephemeral entropy, not an operator-controlled or peer-selected config field, and
never appears in logs/status. The initial table uses its one fresh endpoint
seed; a future per-flow seed API requires separate pure-table review. Existing
exporter purposes must not be repurposed to invent a proxy key authority. No
auth-crate change, custom cryptographic primitive or mutable TLS verifier is
required by this design.

The optional `IgnoreInTimeWait` policy is an explicit authenticated field.
Default `Maintained` keeps pinned-stack behavior. The optional policy drops only
already validated RST at each actual TIME-WAIT ingress step, preserves work and
the maintained timer, and never converts reset or unread data into clean close.
This follows the mitigation in [RFC 1337 section 3](https://www.rfc-editor.org/rfc/rfc1337.html#section-3),
while [RFC 9293 section 3.10.7.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4)
retains different reset processing. It is an explicit opt-in policy, not a claim
of full RFC 1337 hazard elimination with the maintained timer.

## Local and remote route authorization

The first route policy is a bounded allowlist of at most 256 same-family source
prefix, destination prefix and inclusive destination-port-range rules. Prefixes
have checked family/length and zero host bits; reject mapped/scoped/unspecified
or multicast proxy endpoints using the existing admission policy. Port ranges
exclude zero. Canonical sort/dedup makes equivalent rule sets hash identically;
overlap means logical OR and does not create priority-dependent behavior.

The originator checks the complete original SYN tuple before permitting a new
table owner. The acceptor independently decodes the bounded authenticated Open,
checks the same original tuple and its own authorization before passing
`permit_open = true`. No private source address is implicitly trusted. The
runtime retains the tuple and mapped DSCP with each monotonic proxy flow ID and
checks every later outer proxy envelope against that association.

Routes here authorize proxy ownership, not OS route creation and not a general
packet firewall. The embedding service must deliberately route the approved
source/destination networks through TUN on both sides. Unapproved local traffic
remains transparent from connection start; remote unauthorized Open is rejected.
Incoming transparent packets must call `observe_transparent` before actual
native transmission, so a reverse-originated flow cannot later be intercepted.
Policy conflicts, malformed packets and ambiguous packets crossing an owned
address pair fail closed. The table's lifetime bypass lockout/tombstones remain
authoritative; route changes require a new session in this profile.

## Authenticated wire draft and bounded startup

Keep the existing outer length prefix plus 44-byte wire header inside the same
TLS stream. Validate exact physical session, epoch, lane, kind, length and
continuous sequence before dispatch. Sequence consumption includes both user
and session-control records; no counter resets after startup or drain.

All user work uses outer `Kind::Data` with a proposed 24-byte envelope:

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 4 | `LTPW` |
| 4 | 1 | Version 1 |
| 5 | 1 | Class: transparent native frame or scoped proxy record |
| 6 | 2 | Zero flags |
| 8 | 2 | Negotiated common MUX channel |
| 10 | 2 | Zero reserved |
| 12 | 8 | Proxy flow ID; zero for transparent packets |
| 20 | 4 | Exact body length |

Transparent bodies use existing FrameCodec with compression None. Proxy bodies
are unchanged canonical `LTPA`, `LTPR` or `LTPX` records. A proxy envelope's flow
must equal its inner scoped flow, and its channel must equal the CRC32 channel
of the retained original tuple. Transparent channels are checked against actual
parsed packet affinity. User bytes can never select a session-control handler.
Require checked `4 + 44 + 24 + maximum_body` bounds before allocation and reject
trailing bytes, oversized record bodies and zero/unknown classes. All added
framing bytes count in the shared queue/scheduler charges.

Outer `Kind::Control` starts with `LTPCTRL1` (8 bytes), kind (u8), zero (u8),
zero reserved (u16), and exact body length (u32 big endian), totaling 16 bytes.
All integer body fields are big endian. The frozen variants are:

| Kind | Body bytes | Body |
| --- | ---: | --- |
| 1 Start, 2 Ready | 56 | config digest (32), logical first-lane session (16), sender role (u8: 1 originator/2 acceptor), duplex (u8: 1 full/2 half), physical lane (u8: 0 first/1 second), zero (5) |
| 3 NativeCredit | 16 | cumulative successfully written original bytes and packets (u64 each) |
| 4 Ping, 5 Pong | 8 | monotonic nonzero probe number (u64); one outstanding probe per physical write direction |
| 6 Quiesce | 8 | zero reserved; one transition per session direction |
| 7 Barrier, 8 BarrierAck | 32 | final user record count, transparent bytes, transparent packets and final allocated proxy flow ID (u64 each) |

Lengths, reserved fields, roles, lanes and cumulative values are strict. Each
physical write direction has its own continuous outer packet-number space.
Paired reverse halves allow only Start/Ready/Ping/Pong; native credit, quiescence
and fences use the respective bulk direction. Start/Ready must complete on all
retained halves. No proxy
Open/Ready/Commit/Credit/Data/Fin/Stop is session control: all are user work.
Startup uses an absolute authenticated timeout, exchanges Start/Ready over the
already paired lanes and allocates/reserves both receive paths before exposing
native readiness. No TUN read or local TCP ACK precedes mutual readiness.

Persistent framing readers survive actor scheduling and partial I/O; never
cancel a partly consumed record to service another event. A fixed small control
queue, coalesced cumulative credit, finite control rate and one pending heartbeat
provide liveness without timer-generated unbounded queues. Paired reverse TLS
halves stay polled and carry only the declared session-control profile; ordinary
reverse user traffic uses the second bulk lane. All physical lanes must remain
authenticated/live until explicit coordinated closure.

## One common record scheduler and exact handoff

Use the existing opaque `l2tunnel_qos::Scheduler` and deterministic
`l2tunnel_packet::FlowTable`; do not fabricate IP packets around relay records to
reuse the native parser. A thin bounded record arbiter supplies typed ownership
metadata, the shared channel pool and per-channel FIFO sequence tokens. DRR
per-flow selection considers only eligible channel heads. This is composition
of the maintained project scheduler, not another fairness algorithm. If a
reusable opaque Pipeline API is preferable, propose that narrow refactor before
coding it. Never run independent proxy and transparent schedulers with separate
unrelated admission ceilings and call the result a common MUX.

Transparent packets, original SYN-bearing Open, Ready/Commit, relay Credit/Data/
Fin/Stop and every probe use the same global record/byte caps, per-flow caps,
configured channels and DSCP-to-weight map. Untrusted DSCP selects only a bounded
operator-configured weight, not privilege. Opposite directions use independent
instances with the same negotiated policy. Channel FIFO can cause head-of-line
delay between colliding flows; no stronger fairness guarantee is claimed.

The table owns one immutable pending record per proxy flow. The arbiter may keep
one bounded copied scheduled record for that flow, explicitly charged in total
memory in addition to the table's pending bytes. A local token identifies this
copy; at final selection compare its exact retained bytes with the table's
current pending output. Expiry/cancellation may replace Open/Ready/Data with Stop
or remove an unsent Open. Such a stale copy must be discarded with accounting
released, not sent or used to confirm a different record. It never consumes a
wire sequence or completes the table's current output.

Only after obtaining a bounded reliable writer permit, validating the selected
copy and committing one common arbiter admission does the actor transfer that
exact immutable record to the writer and synchronously call
`confirm_record_sent(flow, now)`. There is no await, poll or cancellation between
the ownership transfer and confirmation. Scheduler insertion/peek is not carrier
ownership. A bounded writer queue is owned by the same supervised session; any
subsequent writer/TLS error terminates the session and all affected proxy owners.
The local pre-ACK barrier therefore relies on authenticated remote reservation
plus actual reliable writer ownership, not a promise that TCP cannot later fail.

One retained native-to-table packet handles `Backpressure`; one retained
native-to-transparent-arbiter packet handles a full common queue. Stop device
reads while either handoff is occupied. Each table poll and stale-entry cleanup
has explicit work limits. Flow bindings and proxy ownership metadata are bounded
and cannot be evicted while any table, native, arbiter or writer reference lives.

## Native delivery and three independent credit domains

Every native receive call gets `l2tunnel_device::READ_BUFFER_BYTES`, independently
of negotiated max_packet; oversized packets still fail against max_packet.
Native output selection uses the same configured flow weights/channel policy
over transparent packets and table-generated TCP packets, with a finite receive
budget and no dedicated ACK/probe queue. A pending packet remains immutable until
the complete device transmit succeeds. WouldBlock does not pop another native
packet, release its budget or increase any delivery counter.

The domains stay separate:

1. Transparent tunnel credit counts original native bytes and packets. Sender
   cumulative admission cannot exceed bootstrap reservation plus authenticated
   cumulative delivery. Receiver regrant occurs only after successful TUN write,
   after `observe_transparent` and channel validation. Regressing, unearned or
   over-capacity credit fails closed. Admission reserves the complete native
   packet before the writer accepts it, and released credit never resets.
2. Proxy relay byte/record credit remains the existing Leg contract. It bounds
   original application bytes retained remotely and regrants only on actual
   native TCP ACK, not on writer admission, TUN transmission or a shrinking
   queue caused by reset. No extra runtime credit invents proxy capacity.
3. Maintained native send/receive rings and bounded packet queues are physical
   ownership capacity. `confirm_native_written` follows only a complete device
   write. It is not a TCP ACK. Native advertised window and remote congestion
   window remain maintained-stack decisions; fixed relay targets do not claim
   adaptive few-flow growth.

The receiving actor must continue bounded control and proxy processing while a
transparent/native packet is held. Size data queues from negotiated reservations,
not arbitrary peer traffic; reject a peer that exceeds them. Session-control
service is reserved within its own small bound so two stalled native paths can
still exchange credit/drain/liveness. Proxy Credit remains ordinary scheduled
user work. TCP stream HOL remains unavoidable; no overlay ordering guarantee
claims to bypass missing outer TCP bytes.

`MemoryBound::payload_bytes` conservatively reserves the explicit table rings,
relay windows, scheduler copies, reader/writer records, native queues/handoffs
and frame scratch. `metadata_slots` separately bounds queue/table entries; it is
not a byte-accurate allocator/RSS calculation. Control channels have eight slots
per writer and eight shared event slots, with one pending heartbeat/credit state
per direction; their fixed small payloads are separately bounded. Maintained
TLS record buffers and OS socket buffers have separate implementation/OS
allowances and are excluded from this payload estimate, as are allocator and
task overhead. Checked explicit payload reservation is capped at 256 MiB.
`flow_poll_work` limits maintained owners advanced by each `Table::poll` call;
snapshot, scheduling and retirement scans separately visit at most 64 lifetime
owners per actor iteration. It is not a total actor-step work counter.
Use existing kernel TCP congestion control. Queue-byte accounting is not a
physical wire-rate cap: TLS/TCP ACKs, headers and retransmissions need separate
measured accounting if a later pacing policy is added.

## Finite quiescence, shutdown and failure

Startup and control idle have their own bounds. One absolute shutdown deadline
covers quiescence, final barriers, TLS close and task joins. Observing
authenticated Quiesce starts that deadline in the
reader before any potentially blocked FIFO event send; device WouldBlock must
not hide the start. Keep the earliest bound and do not renew it on retries,
heartbeats or later local requests. The same rule applies to final task joins.

Graceful quiescence stops creating new proxy owners on both sides. It must still
ingest native packets for already owned flows, including their ACK/FIN packets,
and drain their scheduled records. Transparent traffic may continue during this
finite phase so mixed device input does not require silently dropping arbitrary
packets to reach an owned ACK. A busy peer/application may therefore exhaust the
quiescence bound; that is failure, not a claim of clean closure.

The originator hands every already allocated Open to the reliable writer before
queuing Quiesce. The writer drains its already owned user slot before flushing
Quiesce, while the actor pauses further user handoffs until that flush is
observed. Existing Ready/Commit transactions keep their original deadlines.
An unannounced Open that expires before carrier ownership fails the session:
its lifetime ID cannot silently disappear or become an invented Skip record.
The reader attaches the count of preceding user records to its local Quiesce
event. The actor must process those records before deciding that no pending Open
can require further native ACK/FIN input. This metadata is not a wire extension.

Only after all proxy owners have reached explicitly retired or fully drained
terminal states, with no pending proxy/native records, freeze further native
admission. Schedule all remaining transparent records, then flush a final
Barrier behind all earlier user work. Its counts include every user record,
transparent original bytes/packets and the final allocated proxy flow boundary.
Receiver acknowledgment requires exact counts, all preceding transparent native
writes, and no still-owned proxy work. A peer Barrier may reach the actor before
its earlier queued users, but remains unacknowledged until exact user and native
delivery counts match. NativeCredit remains legal after one's own Barrier,
because it concerns the opposite direction's native delivery. It cannot renew
the shutdown deadline. A new Open following wire Quiesce is a protocol failure;
no new native leg starts after final Barrier.

After both exact Barrier/Ack handoffs and actual flush, shut down and read EOF on
every original TLS half, including paired reverse halves, then join all owned
tasks under the remaining absolute close deadline. A successful `CloseReport`
proves session drain with explicit clean/rejected/stopped flow counts; it does
not imply every proxied stream succeeded. Report any abnormal flow separately.

On malformed/replayed/scope-mismatched records, premature EOF, TLS error,
deadline or controller cancellation, stop native admission and abort all owners.
Owned tasks are aborted and any join uses the remaining original deadline;
failure cleanup does not promise delivery of a reset packet. Preserve counter
snapshots and terminal reasons. Do not
fall back to transparent transport, fabricate peer ACKs or discard retained
payload while reporting clean. Raw-driver drain is out of this first TCP-only
profile; future generic-I/O support must explicitly supervise that extra owner.

## Acceptance checklist

- [x] [MOD-PROXYRT-01] Review/freeze this interface, wire layouts, role mapping and exact source ownership before implementation. Evidence: [public API](../../crates/l2tunnel-runtime/src/proxy.rs), [frozen wire](../../crates/l2tunnel-runtime/src/proxy/wire.rs).
- [x] [MOD-PROXYRT-02] Implement canonical all-policy digest, routes, common/physical sessions, full/paired constructors and mutual startup; reject mismatches before native reads. Evidence: [configuration](../../crates/l2tunnel-runtime/src/proxy/config.rs), [actual authenticated tests](../../crates/l2tunnel-runtime/src/proxy_tests.rs).
- [x] [MOD-PROXYRT-03] Compose route authorization with actual Open/Ready/Commit ownership and immutable records; retain the pre-ACK admission contract. Evidence: [actor](../../crates/l2tunnel-runtime/src/proxy/actor.rs), [maintained stream tests](../../crates/l2tunnel-runtime/src/proxy_tests.rs), [pre-ACK primitive tests](../../crates/l2tunnel-tcp-proxy/src/tests/admission.rs).
- [x] [MOD-PROXYRT-04] Use common bounded DRR/channel admission for transparent and proxy records, including proxy controls. Evidence: [arbiter](../../crates/l2tunnel-runtime/src/proxy/arbiter.rs), [FIFO/shared saturation test](../../crates/l2tunnel-runtime/src/proxy_tests.rs).
- [x] [MOD-PROXYRT-05] Test queued expiry/replacement, exact writer handoff, stale-copy disposal, FIFO and bounded pressure. Evidence: [retained Ready/Stop and unannounced-ID tests](../../crates/l2tunnel-runtime/src/proxy/actor_tests.rs), [shared queue test](../../crates/l2tunnel-runtime/src/proxy_tests.rs).
- [x] [MOD-PROXYRT-06] Implement native arbitration, sentinel buffer and original-byte/count delivery credit, retaining actual-ACK proxy credit. Evidence: [actor](../../crates/l2tunnel-runtime/src/proxy/actor.rs), [native pressure and maintained-host tests](../../crates/l2tunnel-runtime/src/proxy_tests.rs).
- [x] [MOD-PROXYRT-07] Test real authenticated full/paired sessions and independent maintained IPv4/IPv6 endpoints with exact bidirectional payload/FIN. Evidence: [four-case maintained endpoint test](../../crates/l2tunnel-runtime/src/proxy_tests.rs).
- [ ] [MOD-PROXYRT-08] Test route rejection, reverse-originated sticky bypass, protected/unsupported options, scope/channel/role mismatch, policy exhaustion and malformed/replayed/bounded hostile records.
- [ ] [MOD-PROXYRT-09] Test native/carrier WouldBlock, queued data plus control, wrong/late credit, reset/timeout, peer-only quiescence under blocked native output and bounded task cancellation.
- [x] [MOD-PROXYRT-10] Test finite quiescence/TLS closure, exact fences, staged failure attribution and retained TIME-WAIT policy. Evidence: [runtime shutdown tests](../../crates/l2tunnel-runtime/src/proxy_tests.rs), [reader/writer ordering tests](../../crates/l2tunnel-runtime/src/proxy/actor_tests.rs), [maintained close-policy tests](../../crates/l2tunnel-raw-tcp/src/tests.rs).
- [x] [MOD-PROXYRT-11] Run strict focused checks, unchanged existing runtime regressions, independent review and source-stable `tools/check.py` for the startup correction. Evidence: [wave8 stable receipt](../../work/implementation-wave8/validation.json), 587 Rust tests including doctests and 46 Python tests with unchanged source hashes; native qualification remains separate.

Post-wave7 startup correction: each writer records Ready only after its actual
write and flush; user selection on either writer queue branch is gated by that
evidence. Actor admission requires all local flushed Ready and all peer Ready.
A pre-start local drain fixes its original deadline immediately but cannot emit
Quiesce until startup completes. Focused regressions cover queued Ready plus an
already available user, withheld peer Ready, unchanged drain expiry, and actual
full/half client factories with native packets queued before either runtime starts.

- [ ] [MOD-PROXYRT-12] Add explicit client selection and owned native TUN/route/netem/packet-capture qualification for both roles/layers/duplex modes; no host route/qdisc modifications.

The clean subset of MOD-PROXYRT-12 is qualified by [full](../../work/native-proxy-full-underlayipv4/tun-full-clean/receipt.json)
and [paired-half](../../work/native-proxy-half-clean/tun-half-clean/receipt.json)
receipts; impairment qualification remains open, so the encompassing gate is unchecked.
- [ ] [MOD-PROXYRT-13] Compose real measured target feedback and growth/shrink tests before claiming adaptive proxy-window mode, then separately design safe mode transitions for new flows.

The tests must preserve default-policy reset traces and finite bound-exhaustion
traces as distinct evidence. The optional TIME-WAIT mitigation does not guarantee
drain under arbitrary persistent impairment. Python simulator ACK/coalescing
knobs and mode catalog gates remain separate; this native proxy profile is a
production requirement, not a retroactive Python parity result.

## Focused verification checkpoint

Seventeen proxy tests pass locally after the startup correction. Four actual maintained TCP endpoint cases run
over real certificate-verified/member-authenticated TLS: IPv4/IPv6, full/paired
half, with exact 7,001-byte and 4,099-byte opposite-direction streams and FIN.
Additional real-carrier cases cover transparent denial/reverse origination,
invalid authenticated startup/replay/credit/channel records, controller loss,
startup/profile rejection, native WouldBlock, asymmetric credit after Barrier,
peer-only shutdown timeout and exact TLS close. Deterministic actor/task tests
cover unannounced ID expiry, staged Ready replacement with Stop, Quiesce's
preceding-user watermark, writer queue drain and a Barrier reaching the actor
ahead of its user/native delivery. Shared arbitration tests retain channel FIFO
and common queue accounting under saturation.

Commands actually run: `cargo test --offline -p l2tunnel-runtime proxy::`,
`cargo test --offline -p l2tunnel-runtime --all-targets` (109 tests at the later client checkpoint),
`cargo clippy --offline -p l2tunnel-runtime --all-targets -- -D warnings`,
`RUSTDOCFLAGS='-D warnings' cargo doc --offline -p l2tunnel-runtime --no-deps`,
owned-file rustfmt verification and `python3 tools/check_checklists.py`.
An independent read-only actor/config/wire/arbiter review found no material
ownership blocker; its payload/metadata and work-bound wording corrections are
included above. The subsequent [wave7 stable aggregate](../../work/implementation-wave7/validation.json)
passed `tools/check.py`: 549 Rust cases including doctests and 39 Python cases,
with identical before/after source hashes. The later startup/client correction
passed wave8 as recorded above. The remaining broad failure and impairment
matrix is separate from [clean native qualification](proxy-native.md) and
[explicit client selection](proxy-client.md).
No Windows/Android, native throughput or arbitrary-loss drain claim follows.
