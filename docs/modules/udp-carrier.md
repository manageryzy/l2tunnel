# TLS-bootstrapped UDP carrier

Status: implemented and integration-tested on local Linux TCP/TLS and UDP loopback.
The design below was recorded before implementation. This is a Tokio socket adapter for
`l2tunnel-datagram`, outside the runtime-independent protocol facade. UDP carries
protected data after real TCP/TLS authentication. The same authenticated TLS
connection remains the bootstrap/control path. This is not standalone UDP auth.

## Exact API and key ownership

`Profile` selects `Traffic::FullDuplex` or
`Traffic::HalfDuplex { sender: Direction }`, cover/protection, lane, generation,
path MTU, complete outer overhead, payload ceiling and per-key packet/byte caps.
`session_config(base: auth::SessionConfig, profile: Profile)` hashes the base
native-layer/configuration binding and a strict 40-byte canonical UDP profile
under a separate domain. Both peers must use its result for TLS member auth.

`establish(connection: AuthenticatedConnection, socket: UdpSocket, config: Config)`
consumes the existing authenticated connection and caller-bound UDP socket. Config
contains the base session configuration, profile, fixed configured peer address
and a positive timeout no greater than 120 seconds. This bounds bootstrap, each
UDP operation and the authenticated Control-input idle lease. Role is inferred from actual
auth metadata. The constructor verifies the exact negotiated digest and exchanges
four fixed bounded TLS frames before releasing the carrier. No UDP probes or
unauthenticated endpoint hints choose a peer address.

`Carrier::into_parts()` returns `(Control, UdpSender, UdpReceiver)`. Control retains
the same TLS/TCP object and implements AsyncRead/AsyncWrite. It exposes authenticated
metadata and TCP addresses, but cannot be converted back to the raw authenticated
connection or export keys. Sender and receiver have unique, non-Clone key-state
owners. Dropping Control, observing TLS EOF/error or shutting down Control signals
both UDP parts to stop. The embedding runtime must continuously service Control and exchange authenticated
heartbeats within `Config.timeout`. Positive TLS reads renew its lease; local
writes alone do not. UDP operations check the lease and pending operations wake
on expiry/closure. Late queued TLS input cannot revive expired key owners.
There is no hidden heartbeat task or autonomous network-failure oracle; a pending
Control read alone must still be bounded by its embedding runtime.

`UdpSender::send(payload)` processes at most one bounded datagram per call and
returns the sealed packet number and wire length only on successful socket send.
A cryptographic attempt consumes its nonce/usage even if socket timeout or caller
cancellation follows. `UdpReceiver::receive(output)` requires a full negotiated
payload-sized destination and returns `ReceiveEvent::Packet(OpenedPacket)` or an
explicit discarded-packet reason. It processes one UDP packet per call; malformed
traffic cannot create an unbounded internal retry loop. Output and replay state
remain unchanged on rejected packets. A locally proven exhausted key budget is terminal and requires a
fresh authenticated session; coordinated in-session rekey is not implemented. An unauthenticated packet whose
claimed length exceeds remaining bytes is discarded without closing the session:
that error alone is not authenticated exhaustion evidence, and smaller valid
packets may still fit the remaining budget.

Directional exporter material is obtained only after member auth through
`export_key(KeyPurpose::Data, global_direction, lane)`. The existing datagram
codec further separates session, direction, lane, generation, cover and protection
through maintained ring HKDF. The adapter adds no cryptographic primitive.
Consuming and wrapping the TLS connection prevents ordinary API use from resetting
a sender with the same exporter/context. Raw privileged key copying remains outside
this ownership guarantee.

## Bootstrap format and transport behavior

The canonical 40-byte profile uses network byte order: version/traffic/cover/suite
(one byte each), lane/generation/path-MTU/outer-overhead/max-payload (u32 each),
then packet-use and payload-byte limits (u64 each). Traffic values identify full,
client-to-server half or server-to-client half. Unknown values/reserved variants
are rejected by exact comparison to local configuration.

Each bootstrap message is exactly 64 bytes: `L2UD`, version 1, kind, body length
u16=56, authenticated session ID16 and canonical profile40. Inside the original
TLS session Client sends OFFER, Server sends ACCEPT, Client sends FINISH and
Server sends DONE. Each state requires the exact kind, size and body; a single
total timeout covers all four messages. No application data or raw exporter
material is included. A handshake failure consumes/closes the connection.

Both local and remote socket addresses must be explicit, nonzero unicast endpoints
in the same address family; wildcard local binds are intentionally rejected.
The socket peer is configured once. Packets from any other source address are
rejected before parsing/crypto; valid packet contents do not authorize rebinding.
Receive uses `maximum protected length + 1` bytes, so an oversized UDP packet
cannot be accepted as a valid truncated prefix. Send/receive each has a finite I/O
timeout; underlying Tokio UDP calls are cancellation-safe, while nonce accounting
explicitly occurs before the send await. Both whole MTU and actual IPv4/IPv6 UDP
header overhead are checked; no PMTU discovery or fragmentation occurs here.

Both custom OpenVPN-like and QUIC-like prefixes and both AEAD and integrity-only
suites are supported by the underlying codec. These are custom protected data
formats, with no OpenVPN/QUIC handshake or interoperability claim. The UDP socket
is lossy/unordered: the transport selector must not satisfy ReliableStream with
this adapter. Reverse feedback and management may stay on TLS; a half-mode lane
rejects application sends/receives in its disabled bulk direction. A bidirectional
half-mode tunnel needs separately authenticated/bound directional lanes.

## Acceptance checklist

- [x] [MOD-UDP-CARRIER-01] Implement canonical profile/auth binding, bounded TLS bootstrap and retained Control ownership. Evidence: [real carrier tests](../../crates/l2tunnel-udp/src/tests.rs), [adapter implementation](../../crates/l2tunnel-udp/src/lib.rs).
- [x] [MOD-UDP-CARRIER-02] Implement fixed-peer Tokio UDP send/receive, sentinel MTU checks, bounded I/O and cancellation/nonce safety. Evidence: [real carrier tests](../../crates/l2tunnel-udp/src/tests.rs), [adapter implementation](../../crates/l2tunnel-udp/src/lib.rs).
- [x] [MOD-UDP-CARRIER-03] Test real TCP/TLS plus UDP across both covers, both protection suites and all full/half roles. Evidence: [real carrier tests](../../crates/l2tunnel-udp/src/tests.rs), [adapter implementation](../../crates/l2tunnel-udp/src/lib.rs).
- [x] [MOD-UDP-CARRIER-04] Test source spoofing, integrity/replay/direction/context mismatch, malformed/oversized packets, key-use limits, deadlines and Control closure. Evidence: [real carrier tests](../../crates/l2tunnel-udp/src/tests.rs), [adapter implementation](../../crates/l2tunnel-udp/src/lib.rs).
- [ ] [MOD-UDP-CARRIER-05] Integrate negotiated UDP selection, recovery, packetization and devices into the client runtime; run owned-namespace loss/reorder/MTU tests.
- [ ] [MOD-UDP-CARRIER-06] Implement standalone authenticated UDP bootstrap, authenticated rebinding/rekey/path validation and qualified standard cover handshakes.

Executed locally: `cargo fmt -p l2tunnel-udp`, `cargo test -p l2tunnel-udp
--offline` (12 tests) and `cargo clippy -p l2tunnel-udp --all-targets --offline
-- -D warnings`. The matrix uses actual TCP/TLS member authentication followed
by actual UDP sockets for both custom covers, both protection suites and all
three directional profiles. Additional tests exercise fixed-source rejection,
MTU truncation sentinels, bad integrity/context/replay, real UDP reorder, wrong
bootstrap profiles/headers/deadlines, receive cancellation, injected cancelled
socket work after a real nonce reservation, exact key budgets, forged budget
overrun, output preservation, Control drop/EOF/expiry and late-heartbeat rejection.
The Tokio 1.53.1 cached UDP source was inspected for send_to/recv_from cancellation
and truncation semantics. The injected send-cancellation test is deterministic
state/I/O fault evidence, not a claim that the kernel send queue was saturated.
No UDP TAP/TUN lab, standalone UDP-only bootstrap, standard cover interoperability,
Windows/Android execution or public-listener qualification is claimed.
