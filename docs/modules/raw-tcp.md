# Raw TCP ownership and userspace stream prototype

Status: bounded userspace stream and lab adapter implemented; finite clean native
TAP/TUN full/half cases integration-tested. Impaired robustness remains open.
Raw TCP remains unavailable in the CLI.
This work first establishes one bounded packet owner from SYN through a real TCP
byte stream. It must not claim the later custom unreliable packet phase merely
because raw sockets can emit TCP headers.

## Ownership and implementation stages

Use maintained `smoltcp` 0.14.0 for TCP state, checksums, retransmission, receive
windows and congestion control. Its MSRV 1.91 fits this workspace. Enable only
std, medium-ip, IPv4, TCP and Reno initially. A pure wrapper owns one fixed IPv4
four-tuple, one socket, finite send/receive rings, finite raw packet queues and
caller-injected monotonic time. It neither opens sockets nor configures interfaces.
All peer bytes are validated before admission. Selective-repeat/FEC remains a
separate upper-layer composition; this stage is a reliable stream.

Current pure API:

```rust
TcpEngine::new(Config, Role, Millis) -> Result<TcpEngine, Error>;
TcpEngine::ingest(&[u8]) -> Result<(), Error>;
TcpEngine::poll(Millis, work_limit: usize) -> Result<(), Error>;
TcpEngine::pop_packet() -> Option<Vec<u8>>;
TcpEngine::write(&[u8]) -> Result<usize, Error>;
TcpEngine::read(&mut [u8]) -> Result<ReadOutcome, Error>;
TcpEngine::close();
TcpEngine::status() -> Status;
```

`Config` fixes local/peer IPv4 address and nonzero port, IP MTU, send/receive byte
capacities, packet queue count, injected unpredictable random seed, keepalive and
idle deadline. Bounds are checked before allocation. A zero-byte write is
backpressure when established; reads distinguish Data/Pending/Eof. Native TCP
ACK/window behavior remains the maintained stack's responsibility. A caller must
retain a popped raw packet across socket WouldBlock, rather than polling another
copy. Each queue has a hard byte bound implied by count times MTU. Poll work is
finite even when the peer supplies a sustained input stream.

The next adapter stage uses Linux protocol-specific raw sockets in an explicitly
owned network namespace. Raw input includes IPv4 headers and is also delivered
to the kernel TCP handler. Consequently the adapter needs independently verified
ownership of the exact tuple and a scoped RST policy; it cannot assume socket
creation transfers kernel TCP ownership. Qualification may install an exact-tuple
RST filter only inside the journal-owned test namespace. Normal client operation
must expose the required capability/ownership contract and fail closed when it
is unavailable. Never install host-wide RST suppression or steal a live socket.

The initial native adapter is `l2tunnel-raw-io` (Linux only). `open(Config, Role)`
returns a bounded Tokio `DuplexStream` plus an explicitly owned `Driver` future.
The caller must supervise `Driver::run` alongside TLS/application I/O; dropping
that future closes its raw socket and reserved ordinary-TCP bind. The adapter
rejects the initial PID-1 network namespace, requires a matching read-only
`iptables -C OUTPUT` exact-tuple RST-drop check, reserves the local TCP address/port
without listening, and never installs rules. Native RST transmission is therefore
also suppressed in this first isolated profile; this is not a general host adapter.
The rule must remain owned and installed for the complete socket lifetime.
The read-only rule check proves rule presence, not precedence over an earlier
ACCEPT rule. The embedding lab must own the namespace and effective rule order;
packet captures/counters remain part of native qualification. Namespace identity
is compared to `/proc/1/ns/net`, not a proof of ownership of an arbitrary foreign
namespace or a host-global security boundary inside a PID namespace.

One initialized 65536-byte receive scratch buffer detects oversized IP input.
`socket2` supplies safe raw read/send calls; the adapter introduces no unsafe code.
The driver retains one popped output packet across WouldBlock and bounds each
ingress/egress turn. Its duplex bridge, pending input/output chunks and maintained
TCP rings are independently finite. A 1 ms timer drives retransmission/ACK work;
no empty busy loop or unbounded channel is used. Foreign/malformed raw packets
are counted and discarded before the pure engine. Unexpected native I/O failure
closes the bridge. The stream's flush means bridge acceptance, not TCP acknowledgment;
upper protocols use their existing explicit delivery/authentication barriers.

- [x] [MOD-RAW-08] Test bounded asynchronous bridge I/O, WouldBlock packet retention, EOF and caller cancellation independently from privileged raw sockets. Evidence: [four bridge tests](../../crates/l2tunnel-raw-io/src/tests.rs), [local verification](#local-verification).
- [x] [MOD-RAW-09] Run isolated raw stream/TLS probes with exact-tuple rule receipts, packet captures and absence-of-kernel-connection evidence. Evidence: [four clean case receipts](../../work/raw-native-final/receipt.json), [passing standalone impaired TAP receipt](../../work/raw-native-diagnosis/receipt.json); the combined run remains failed and is not a robustness pass.

After a correct raw packet/byte stream exists, run maintained rustls TLS over that
same userspace-owned connection and reuse the member-authentication protocol.
Keep the original tuple and coherent sequence evolution through auth and data.
Capture both endpoints to prove there is no second SYN, kernel socket handover or
plaintext user traffic. This phase still supplies TCP reliable semantics.

## Additive IPv6 maintained-engine slice

Implemented and focused tested: retain the public IPv4 `Config`/`TcpEngine::new`
and native raw adapter unchanged. Generalize the configuration's endpoint type with its IPv4
default and expose `IpConfig = Config<SocketAddr>` plus `TcpEngine::new_ip` for
an explicit same-family fixed tuple. The IPv4 constructor delegates by lossless
conversion. This adds the pinned stack's `proto-ipv6` feature, not a new TCP stack.
`Leg::new_ip` in the proxy uses the same bounded ownership implementation.

IPv6 admission accepts only a complete base-header TCP packet with a nonzero
payload length, exact total length, exact tuple and maintained pseudo-header TCP
checksum validation. No extensions, fragments or jumbograms enter this first
slice. Require MTU at least 1280, reject mapped/unspecified/multicast or ambiguous
link-local/scoped endpoints, and preserve family identity. Unsupported packets
must be handled before proxy ownership; they are never reinterpreted as IPv4.
No IP checksum exists in IPv6; TCP checksum validation remains mandatory.
[IPv6 header and checksum specification](https://www.rfc-editor.org/rfc/rfc8200.html)

The fixed validated base-header size selects the actual TCP flags when recording
maintained FIN/RST transitions. Test independent IPv6 owners and proxy legs with
real bytes, pressure, FIN/reset and loss/duplicate/reorder, plus every truncation,
wrong-family/tuple/length/checksum and unsupported-header rejection. Existing IPv4
raw/bridge/proxy behavior must continue passing. This slice provides no native
IPv6 raw socket adapter or complete native TCP proxy.

- [x] [MOD-RAW-IP6-01] Add same-family configuration and maintained IPv6 packet validation without breaking existing IPv4 callers. Evidence: [IpConfig/new_ip](../../crates/l2tunnel-raw-tcp/src/lib.rs), unchanged IPv4 constructor and raw adapter; strict focused Clippy/rustdoc passed.
- [x] [MOD-RAW-IP6-02] Verify IPv6 real-byte impairment, backpressure and close outcomes, plus transactional malformed/unsupported admission failures. Evidence: [11 maintained-engine tests](../../crates/l2tunnel-raw-tcp/src/tests.rs), IPv6 32,773/16,391-byte exchange after actual receive-ring pressure, deterministic loss/reorder/duplicates, clean FIN and reset, malformed/tuple/checksum/header rejection.
- [x] [MOD-RAW-IP6-03] Add IPv6 proxy-leg construction and four-owner relay tests; preserve all IPv4 bridge and relay regressions. Evidence: [eight proxy tests](../../crates/l2tunnel-tcp-proxy/src/tests.rs), four-owner/pressure/blocked-carrier cases now run in both families; four existing asynchronous IPv4 bridge tests also passed.
- [x] [MOD-RAW-IP6-04] Run strict focused and stable aggregate verification; keep native IPv6 raw and proxy admission gates separate. Evidence: [source-stable wave 6](../../work/implementation-wave6/validation.json), 492 Rust cases and 36 Python tool tests; strict focused tests and review are described above.

## Explicit close-state outcomes

The pure wrapper records public maintained state after each individual ingress
and egress/timer step, rather than only after a batch. `Status` exposes
`established`, `peer_fin` and `close_reason: Option<CloseReason>`. Accepted peer FIN
is established by transitions into CloseWait/Closing/TimeWait; a raw flag that the
stack rejects is not enough. LastAck completion requires an accepted non-RST ACK.
Reset, timer failure, local abort and unexpected closure remain explicit errors.

On entering TimeWait, use public `set_timeout(None)` and `set_keep_alive(None)`
so its maintained close timer owns expiration; do not copy private sequence or
timer state or hard-code its duration. If expiration discards unread receive-ring
bytes, report `UndrainedReceive` rather than clean EOF. Reads may drain already
buffered bytes before a terminal error; only accepted FIN permits orderly EOF.

The asynchronous driver requires clean terminal state, drained stream/ring bytes,
and empty retained/native-output packet queues before success. A popped packet
survives WouldBlock even after maintained TCP closure. The existing configured
idle timeout also bounds final bridge/raw-output drain, after which an explicit
timeout is returned. No native socket or capability is enabled by this correction.

- [x] [MOD-RAW-10] Preserve established/accepted-FIN history per maintained transition and expose explicit clean/reset/timeout/abort/undrained outcomes. Evidence: [public maintained-state observation](../../crates/l2tunnel-raw-tcp/src/lib.rs), [close-state regressions](../../crates/l2tunnel-raw-tcp/src/tests.rs).
- [x] [MOD-RAW-11] Retain final native packets and bridge bytes across WouldBlock until clean drain or the explicit finite deadline. Evidence: [driver retention](../../crates/l2tunnel-raw-io/src/lib.rs), [blocked final ACK and deadline test](../../crates/l2tunnel-raw-io/src/tests.rs).
- [x] [MOD-RAW-12] Regress batched ACK/FIN, reset/timeout after local shutdown and blocked final control; run focused checks. Evidence: [pure tests](../../crates/l2tunnel-raw-tcp/src/tests.rs), [bridge tests](../../crates/l2tunnel-raw-io/src/tests.rs), [local verification](#local-verification).

## Custom packet phase is a separate gate

Ignoring ACKs indefinitely is incompatible with ordinary TCP send-window and
recovery semantics. An optional post-auth custom datagram phase requires its own
authenticated transition: both peers agree on final bootstrap sequence fences,
drain retained stream bytes, preserve unique AEAD/MAC packet numbers and stage a
bounded old-phase decoder. Sequence tracking must account for SYN/FIN, wraparound,
retransmissions, gaps, receive window, timestamps/PAWS and resets. Do not reset the
TLS object and call resulting arbitrary datagrams HTTPS.

The public smoltcp socket API does not promise transferable internal TCP state.
Before attempting phase transition, determine whether a supported observer/state
interface is sufficient or whether a separately reviewed minimal upstream change
is required. No unsafe memory access or private-state layout dependency is allowed.
If this ownership/transition cannot be qualified, explicitly retain reliable raw
TCP or select the independently negotiated UDP profile; do not claim missing
custom recovery semantics. Router/conntrack/NAT acceptance is empirical and needs
its own loss/reorder/idle/wrap/MTU tests.

## Acceptance checklist

- [x] [MOD-RAW-01] Freeze bounded userspace stream API and maintained dependency/feature choice before enabling any raw capability. Evidence: [manifest](../../crates/l2tunnel-raw-tcp/Cargo.toml), [API](../../crates/l2tunnel-raw-tcp/src/lib.rs), pinned smoltcp 0.14.0 with IPv4/TCP/Reno features, checked configuration before allocation; no native capability enabled.
- [x] [MOD-RAW-02] Implement one fixed-tuple pure packet/stream owner with checked lengths, checksums, time and finite queues/work. Evidence: [TcpEngine](../../crates/l2tunnel-raw-tcp/src/lib.rs) validates packet checksums and exact tuple before admission, limits packet queues/rings and polling work; focused tests and strict Clippy pass.
- [x] [MOD-RAW-03] Test two independent TCP engines with real bytes, loss/reorder/duplicates, receive backpressure, close/reset and tuple/MTU rejection. Evidence: [eight tests](../../crates/l2tunnel-raw-tcp/src/tests.rs) pass with 16/12 KiB bidirectional lossy streams, 32 KiB receive-pressure recovery, truncations, timer failures and immediate FIN/terminal-outcome regressions; native networking is not covered.
- [x] [MOD-RAW-04] Add a separately reviewed Linux raw adapter and exact-tuple ownership contract; no host-global network changes. Evidence: [lab-only adapter](../../crates/l2tunnel-raw-io/src/linux.rs), [explicit ownership limitations](#ownership-and-implementation-stages), [bounded driver tests](../../crates/l2tunnel-raw-io/src/tests.rs).
- [x] [MOD-RAW-05] Run maintained TLS/member authentication and native packet forwarding over the retained raw-owned stream; capture tuple and SYN continuity. Evidence: [supervised retained-stream helper (retired in Common cutover)](compact-wire-cleanup.md), [clean TAP/TUN full/half cases](../../work/raw-native-final/receipt.json); retained maintained reliable TCP semantics only.
- [ ] [MOD-RAW-06] Specify and implement a supported authenticated transition to a separately protected datagram phase without private TCP-state layout assumptions.
- [ ] [MOD-RAW-07] Qualify sequence/window/options/reset/PMTU/NAT/conntrack and permission failures; expose exact reliable/datagram capability and explicit fallback.

## Native retained-stream qualification design

The dedicated `raw-native` example opens one fixed raw-owned connection for
full duplex, or two independent connections for paired half duplex. The generic
`AuthenticatedIo<S>` TLS/member handshake and runtime Link constructors retain
each original DuplexStream and its supervised Driver throughout authentication
and native TAP/TUN forwarding. Driver termination cancels protocol use; no task is
detached and no raw mode is added to the regular CLI. Session configuration binds
layer, duplex, ring/queue/MTU/timing parameters and lane count.

`tools/raw_native_smoke.py` is dry-run by default. Apply creates only a new
journal-owned `netns_lab` topology, copies an immutable helper binary, creates
ephemeral certificates/member keys, inserts exact four-tuple RST rules at the
start of the owned empty OUTPUT chain and records its complete effective rules.
Capture starts before helper launch. Both endpoint captures must show exactly
one initial sequence number per expected lane and direction (retransmitted SYNs
are allowed), coherent payload sequence overlap, real TLS hello/encrypted records,
no ClientHello SNI and no plaintext probe payload. ACK-only one-byte keepalive
probes at an already peer-acknowledged sequence are counted separately: RFC TCP
keepalive may use a garbage octet, which must not be decoded as stream data.
Ordinary payload retransmissions must still agree byte for byte. Read-only `ss` inspection must
show no kernel ESTABLISHED tuple for the raw lanes. Actual native packet tests
use IPv4/IPv6 ping and bounded SHA-256-checked TCP bytes, with explicit cleanup.
Capture uses immediate mode to avoid stopping a Linux capture ring before block
retirement, a 2048-byte snapshot above the configured packet MTUs, and a finite
4 MiB buffer per capture. Exact counters reject any kernel drops, empty captures or exhausted
4096-packet limits. Both underlay and native synthetic-payload captures are
retained. Per-case progress, errors and neighbor/bridge diagnostics survive
failure; reruns use new output directories and do not replace prior receipts.

- [x] [MOD-RAW-13] Retain generic authenticated I/O through full/paired runtime constructors and a supervised raw-native helper. Evidence: [generic constructors](../../crates/l2tunnel-runtime/src/lib.rs), [supervised helper (retired in Common cutover)](compact-wire-cleanup.md), [first passing retained TLS/TUN case](../../work/raw-native-capture/receipt.json).
- [x] [MOD-RAW-14] Implement dry-run/owned apply harness with immutable helper, effective exact-tuple rules, bounded captures and strict evidence parsing. Evidence: [harness](../../tools/raw_native_smoke.py), [strict parser tests](../../tools/test_raw_native_smoke.py), [native receipt](../../work/raw-native-diagnosis/receipt.json).
- [ ] [MOD-RAW-15] Run isolated TAP/TUN full/half and impaired qualification, record payload hashes/TLS and sequence continuity/no kernel owner, and preserve cleanup/failure receipts.
- [x] [MOD-RAW-16] Reject truncated/lossy captures, incoherent retransmissions, unexpected tuples, second SYN sequences and SNI; distinguish acknowledged keepalive probes and dry-run behavior. Evidence: [ten unprivileged evidence tests](../../tools/test_raw_native_smoke.py).
- [ ] [MOD-RAW-17] Investigate impaired native ping/deadline failures with reproducible impairment schedules and supported maintained TCP recovery settings; qualify robustness without hiding failed attempts or extending acceptance until a pass.
- [ ] [MOD-RAW-18] Establish an explicit finite bidirectional native-helper drain barrier before capture shutdown and qualify complete sequence reconstruction under loss, without ignoring unacknowledged trailing gaps.

## Reviewed finite native drain extension

Design approved before implementation. The ordinary runtime `run` and its wire
behavior stay unchanged. A separate `runtime::drained` profile derives an
authenticated session digest from the ordinary runtime limits, a finite drain
timeout and the caller's existing raw-carrier context digest. Both original TLS
streams and all raw drivers remain owned throughout; there is no new connection,
credential, authentication exchange or sequence reset at drain time.

Implemented public API:

```rust
drained::Config { runtime: RuntimeConfig, duplex: Duplex, drain_timeout: Duration,
                  carrier_context: ConfigDigest }
drained::session_config(Config) -> io::Result<SessionConfig>
drained::run(device, retained_link, Config, oneshot_stop)
    -> io::Result<DrainReport>
```

The report contains local admitted/handed/actually-flushed record counts, the
peer's final record count and actual native confirmations, both authenticated
barrier/ACK outcomes, and the number of fully closed original TLS lanes.
Counter overflow, malformed records, unknown epochs, incorrect session/lane,
duplicate physical sequence numbers and inconsistent fences fail explicitly.

On an explicit local request or a valid peer Barrier, stop new native reads.
The validated remote arrival is also published through one bounded timestamp
watch, so a native WouldBlock cannot hide the absolute deadline behind its FIFO
barrier event. A barrier still unread behind bounded transport/input backpressure
is not falsely reported as received. The paired helper requests both local stops.
Native reads use the device contract's 65536-byte sentinel buffer, then enforce
the separately authenticated packet-size ceiling.
Already admitted originals remain in bounded queues until handed and actually
flushed. The final local Barrier follows those originals on the original data
direction. Its count must equal the exact number of peer data records read.
No peer data may follow its Barrier. A Barrier ACK is sent only after all records
through the peer fence were successfully written to the native device, and after
the local Barrier itself flushed. WouldBlock retains the exact original and
prevents that ACK. Once both matching ACKs are received/flushed, close every
original TLS write half and read clean TLS EOF on every original read half,
including the paired lane's otherwise unused reverse direction.

The distinct inner Control payload is fixed and bounded; data still uses the
existing frame codec and continuous outer packet sequence. There are no
application retries because this profile retains reliable TCP/TLS. The local
device handle stays alive until the actor's report. Undrained kernel packets
never consumed before admission freezes are outside the reported admitted fence;
the report does not claim to drain arbitrary future kernel traffic.

The lab helper exposes one strict drain request on each private local Unix socket.
The harness requests both endpoints before waiting for either. Helper success
requires the runtime report and every supervised raw driver's existing clean
terminal state with empty stream/ring/retained-packet ownership. Driver errors or
finite deadlines fail the case. Only both successful helper exits permit capture
shutdown. Captures still reject gaps, inconsistent retransmissions, truncation,
kernel drops and packet-cap exhaustion; no unacknowledged tail is discarded from
the evidence parser. The fixed initial barrier deadline is 30 seconds, with
45 additional seconds for maintained TCP/driver close and an 80-second harness
completion bound, all explicit and fixed before a native run.

- [x] [MOD-RAW-DRAIN-01] Review the separate negotiated profile, exact two-peer proof and retained TLS/raw-driver ownership before implementation. Evidence: [reviewed finite drain design](#reviewed-finite-native-drain-extension).
- [x] [MOD-RAW-DRAIN-02] Implement bounded exact native/stream barriers, matching ACKs and complete full/paired TLS close with no legacy runtime change. Evidence: [drained runtime (retired in Common cutover)](compact-wire-cleanup.md), [authenticated runtime regressions (retired in Common cutover)](compact-wire-cleanup.md).
- [x] [MOD-RAW-DRAIN-03] Test simultaneous stop, asymmetric paired closure, stale/mismatched fences, unread native output, blocked shutdown, EOF/cancellation and finite deadlines. Evidence: [nine focused runtime tests (retired in Common cutover)](compact-wire-cleanup.md), [two strict helper request tests (retired in Common cutover)](compact-wire-cleanup.md).
- [x] [MOD-RAW-DRAIN-04] Integrate private helper requests and both-driver completion before stopping captures; retain every failed case. Evidence: [helper (retired in Common cutover)](compact-wire-cleanup.md), [harness](../../tools/raw_native_smoke.py), [thirteen unprivileged parser/request/receipt tests](../../tools/test_raw_native_smoke.py).
- [ ] [MOD-RAW-DRAIN-05] Run focused strict checks and owned native qualification without relaxing capture continuity or increasing deadlines after a failure.
- [x] [MOD-RAW-DRAIN-06] Run a coordinated stable aggregate after the drain/diagnostic source checkpoint. Evidence: [wave6 validation](../../work/implementation-wave6/validation.json).

Focused verification for the drain extension: nine runtime tests, four existing
raw-driver tests and two helper request tests passed; thirteen unprivileged harness
tests passed. Runtime/raw-io strict all-target Clippy and warning-denied rustdoc passed at the
source checkpoint after the remote-arrival regression. Native completion
with this new profile remains a separate gate; the older receipts below used the
forced-stop helper and are not retroactively repaired.

The first fixed drain run, [raw-native-drained](../../work/raw-native-drained/receipt.json),
passed all four clean TAP/TUN full/half cases. Each passed eight IPv4/IPv6 pings,
an exact 65536-byte TCP checksum, both peer native/raw-byte fences, all clean driver
exits and complete strict captures; helper drain took approximately 10 seconds.
TAP half at 70 ms/15% completed its pings and payload (23.149 seconds), then failed
at 30.112 seconds awaiting both helper completions. B reported both clean drivers;
A returned bare OS EPERM. Both preserved captures independently reconstruct all
four TLS streams with zero capture drops, but that does **not** supply A's missing
clean-driver proof. TUN impaired was not run after this failure. These observations
retain the failed qualification and do not complete MOD-RAW-18/DRAIN-05.

The approved diagnostic extension preserves every original io::Error kind/errno
and emits bounded operation/tuple/close-ownership metadata only on an actual error;
no keys or payload contents are logged. The helper separately records actual
native/TLS completion and each clean-driver result. Failure receipts read exact
RST-rule counters and `tc -s` only within still journal-owned namespaces before
cleanup. A single selected diagnostic case can run without repeating clean cases.
No drain bound or TCP recovery policy changes accompany this instrumentation.
The one [diagnostic attempt](../../work/raw-native-drained-diagnostic/receipt.json)
failed on its first native ping before drain and did not reproduce EPERM. The
[native ARP audit](../../work/raw-native-drained-diagnostic-audit.json) shows B
responded to the first request in 39.233 ms, but A received the three replies only
3.2078 seconds after its first request, after local neighbor resolution had failed.
The captures therefore establish delayed return ARP delivery; ordered-carrier
recovery/head-of-line delay remains an inference, not decrypted record mapping.
Owned namespace identities and exact RST chains remained intact; netem reported
21/11 drops. Cleanup passed. No further native retry or deadline increase occurred.
The [original independent audit](../../work/raw-native-drained-audit.json) preserves
four clean passes, the failed impaired drain and the unrun TUN impaired case.
The [close flag timeline](../../work/raw-native-drained-fin-audit.json) records
unacknowledged final TLS bytes/FIN retransmissions on the second lane but does not
identify the original errno-producing syscall.

The coordinated [wave6 aggregate](../../work/implementation-wave6/validation.json)
passed 492 Rust checks including doctests and 36 Python tests with matching source
hashes. It includes this drain implementation and diagnostics; it does not turn
either failed native receipt into qualification.


## Finite native observations and unresolved failures

Every run copies its helper binary and harness, creates only a journal-owned
namespace topology, and records cleanup. The helper performs real verified TLS
and member authentication over one userspace-owned raw TCP lane (full duplex) or
two lanes (paired half duplex). The native data path uses the existing bounded
packet runtime, not active TUN credit or custom ACK-independent datagrams.

The four clean TAP/TUN full/half cases in
[the latest combined receipt](../../work/raw-native-final/receipt.json) passed
eight original IPv4/IPv6 pings each (56/1200-byte payloads, both directions) and
65,536-byte SHA-256 verification. Underlay captures preserve each SYN tuple and
TLS/encrypted sequence stream; native captures have zero reported kernel drops.
An independent [TAP half-duplex impairment run](../../work/raw-native-diagnosis/receipt.json)
passed the same probes at configured 70 ms base RTT and 15% per-direction random
loss, with the finite TCP payload completing in 11.19 seconds.

These passes do not erase failures. The
[first combined loss run](../../work/raw-native-qualified/receipt.json) timed out
on one original IPv6 TAP echo after 30 seconds; its exact cause is unresolved.
The [latest combined run](../../work/raw-native-final/receipt.json) passed all
eight impaired TAP pings but its TCP payload exceeded the unchanged 60-second
process deadline. Native capture shows continued payload progress through about
39 KiB, including a roughly 30-second recovery pause. This is evidence of the
maintained reliable TCP-over-TCP profile's current bounded-test limitation, not
proof of corruption or acceptable performance. The impaired acceptance gate
remains open; do not retry until a passing result or weaken the deadline.

The single independent [TUN half-duplex loss attempt](../../work/raw-native-tun-loss/receipt.json)
passed all eight original pings and its 65,536-byte SHA-256 check in 28.20 seconds.
It still failed strict capture qualification: both endpoint captures contain a
44-byte hole at forward stream offset 81,235 followed by later tail records when
the helpers were stopped. Both report zero kernel capture drops. Native delivery
success does not prove complete captured sequence continuity. The
[read-only tail audit](../../work/raw-native-tail-audit.json) finds both observed
peer ACK high-waters stopped exactly at offset 81,235, with later tail records
unacknowledged in the captures. This is consistent with stopping before recovery
and drain; the exact missing-packet disposition is not proven by capture alone.
Do not label the whole run passed or silently ignore the hole. A future explicit
helper drain barrier must address this boundary.

Two instrumentation failures are also retained: the
[initial capture](../../work/raw-native-first/receipt.json) stopped before Linux
capture-ring delivery, and a later [native capture](../../work/raw-native-matrix/receipt.json)
reported two kernel capture drops. Immediate capture and bounded MTU-sized slots
correct those measurement problems; neither failed receipt was overwritten.
No NAT, conntrack variety, Windows/Android native backend, general-host raw
capability, or custom unreliable post-authentication sequence phase is qualified.

## Primary references

- [smoltcp device interface](https://docs.rs/smoltcp/0.14.0/smoltcp/phy/trait.Device.html) and [interface polling](https://docs.rs/smoltcp/0.14.0/smoltcp/iface/struct.Interface.html) define injected packet/time ownership.
- [Pinned dependency manifest](https://github.com/smoltcp-rs/smoltcp/blob/v0.14.0/Cargo.toml) defines MSRV and selected features.
- [Linux raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html) documents capabilities, IPv4 headers and concurrent kernel protocol handling.
- [TCP specification](https://www.rfc-editor.org/rfc/rfc9293.html) defines sequence space, ACK/window behavior and state transitions.

## Local verification

Executed on local Linux, 2026-11-11 UTC:

```text
cargo fmt -p l2tunnel-raw-tcp -p l2tunnel-raw-io
cargo test --offline -p l2tunnel-raw-tcp -p l2tunnel-raw-io
  raw-tcp: 8 unit tests passed
  raw-io: 4 unit tests passed
cargo clippy --offline -p l2tunnel-raw-tcp -p l2tunnel-raw-io --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --offline -p l2tunnel-raw-tcp -p l2tunnel-raw-io --no-deps
python3 -m unittest tools.test_raw_native_smoke -v
  10 unprivileged evidence-parser tests passed
```

The immediate-FIN regression includes both an ACK/FIN batch and a FIN that itself
completes SynReceived. Clean TimeWait completion is tested with a shorter active
idle timeout and with unread receive data. The asynchronous final-ACK test holds
the exact popped packet beyond maintained TimeWait expiry, verifies the driver
stays alive, then separately verifies successful release and finite drain timeout.
These tests use independent pure peers and finite memory packet links; they do
not open privileged raw sockets, authenticate TLS or qualify NAT/conntrack behavior.

## Optional TIME-WAIT reset policy

`TcpEngine::set_time_wait_reset_policy` is additive and may be called only before
the first maintained poll. All existing constructors preserve `Maintained`.
`IgnoreInTimeWait` follows the optional F1 proposal in informational
[RFC 1337 section 3](https://www.rfc-editor.org/rfc/rfc1337#section-3), differing
from the reset handling described in
[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4). It filters an
already tuple/length/checksum-validated RST at each bounded ingress processing
step only if the actual maintained socket is then in TIME-WAIT. A FIN and RST
queued together cannot bypass this policy. The step still consumes work and runs
maintained egress/timers; no sequence or close state is rewritten.

The existing timer is unchanged, so this does not assert RFC 1337's broader
hazard-avoidance assumptions about MSL. Other-state resets and expiry with unread
bytes remain explicit failures. Proxy session selection must be negotiated;
the default raw native helper and historical receipts do not select this option.

- [x] [MOD-RAW-TW-01] Add explicit pre-poll selection with unchanged default and per-ingress maintained-state filtering. Evidence: [engine policy](../../crates/l2tunnel-raw-tcp/src/lib.rs), default `Maintained` and finite work accounting.
- [x] [MOD-RAW-TW-02] Test IPv4/IPv6 queued FIN/RST, frozen policy, unchanged established reset, timer expiry and unread-data failure. Evidence: [focused regression](../../crates/l2tunnel-raw-tcp/src/tests.rs), all 12 raw TCP tests passed; no synthetic clean close.
- [x] [MOD-RAW-TW-03] Include the additive policy and proxy forwarding in a stable aggregate validation. Evidence: [source-stable wave 6](../../work/implementation-wave6/validation.json), 492 Rust cases and 36 Python tool tests; strict focused tests and review are described above.

The [proxy session tests](proxy-session.md) separately preserve the original
periodic-loss post-EOF reset and the optional-policy fixed-bound incomplete case.
Finite-loss clean completion is qualified only for the stated test profile.
