# Genuine standalone QUIC carrier

Status: implemented and integration-tested on finite local Linux UDP loopback;
native device/runtime integration remains pending. This is a runtime adapter using maintained
Quinn/rustls over UDP, independently of the existing TCP-bootstrapped custom
`QuicLike` and `OpenVpnLike` packet covers. It does not reinterpret those profiles.
No TCP listener or reachability is required. Native runtime/client integration and
standalone OpenVPN-like bootstrap remain separate gates.

## Interface and verification boundary

`Profile` binds traffic direction (full or one global half-duplex sender), lane,
maximum DATAGRAM payload/queue allowance, control receive window, UDP payload ceiling,
idle/I/O deadlines and a required operator-configured 16-byte `application_id`.
`session_config(base, profile)` hashes this exact canonical profile and the base
native layer/configuration under a distinct versioned QUIC domain. Endpoint-local
`EndpointLimits` cap concurrent sessions, pending handshakes and authentication
wall time. Client/server DER constructors preserve strict roots/name verification,
TLS 1.3 only, disabled SNI, resumption and early data. QUIC always provides AEAD;
this is not an integrity-only profile.

`ClientEndpoint::bind` / `ServerEndpoint::bind` create UDP endpoints. Client
`connect(peer, name, member, base)` and server `accept(members, base)` return an
`AuthenticatedConnection` only after the complete member exchange and receive-token
confirmation on one client-initiated bidirectional stream. `info()` exposes public
identities; `into_parts()` returns a reliable `Control` stream and exclusive
`DatagramSender` / `DatagramReceiver` owners. No raw Quinn connection or preauth
traffic handle escapes. The receiver reports one bounded accepted or discarded
record per call. DATAGRAM operations have finite deadlines. Control uses bounded transport windows;
the caller owns framing and operation deadlines, including cancellation of partial
`read_exact`/`write_all` operations. Dropping Control or observing
its EOF/error closes the connection; callers must poll Control to observe a peer
stream FIN. QUIC transport idle expiry is independent, but ongoing datagrams can
keep a connection alive and do not imply that an unread control FIN was observed.

The auth crate gains `CallerVerifiedChannel`: an explicit caller assertion that
its transport has already verified TLS 1.3 server identity and produced an exporter
from that same connection. Constructing this value is not verification or
cryptographic evidence. Generic member-exchange helpers keep signing internals
private, take the assertion plus a bounded duplex stream, and return SessionInfo.
TCP retains its exact existing labels, framing, transcript and behavior. QUIC uses
separate exporter/transcript domains. Exporter/transcript buffers are zeroized.

## Wire and resource invariants

The application identifier is negotiated as exact ALPN bytes and auth-bound.
There is no tunnel-named default or false HTTP/3 ALPN. QUIC Initial protection does
not conceal ClientHello/ALPN. An opaque configured identifier is still observable;
there is no unprobeability or middlebox acceptance claim.

Only one concurrent client-initiated bidirectional stream is allowed; other bidirectional and
all unidirectional streams have zero advertised credit. A fixed private prelude
inside that encrypted stream makes the client's open visible before server reads.
The bounded existing member protocol then signs fresh nonces, verified server
certificate, member identity, session/config/layer and the QUIC TLS exporter.
Both roles must complete acceptance. Fresh receive capabilities are generated only
after that exchange, exchanged and acknowledged on Control. Thus DATAGRAM bytes
queued before membership cannot become application data merely because auth
subsequently completed.

DATAGRAM draft header: magic `L2QD` (4), version (1), global direction (1), payload
length (2), session ID (16), receiver capability (16), sequence (8): 48 bytes.
QUIC AEAD protects all fields. Session/direction/capability/length checks precede
replay-window mutation or payload release. Sequence starts at zero, never wraps;
a bounded 128-packet bitmap rejects logical duplicates and stale packets. A retry
by a higher recovery engine receives a fresh carrier sequence. Capabilities and
exporters are never logged. Datagrams remain unreliable and unordered; recovery,
MUX admission, fragmentation, FEC and native packet forwarding are outside here.

UDP payload ceiling is explicitly not IP MTU. QUIC requires Initial datagrams of
at least 1200 bytes, implying at least 1228 IPv4 / 1248 IPv6 bytes without options.
The configured ceiling fixes initial/minimum transport MTU with discovery disabled;
maximum negotiated DATAGRAM capacity is checked before exposing traffic. Receive
and send buffers, stream windows, handshake crypto buffers, pending Initial bytes,
concurrent admitted sessions and per-call bytes are bounded. Queue allowance is
`(48 + max_datagram_bytes + 64) * queued_datagrams` bytes, with metadata
headroom; smaller datagrams can use more entries. Quinn receive accounting
includes each entry's metadata. Quinn send accounting caps payload bytes plus
one entry; this adapter's minimum 49-byte record bounds retained send entries by
`queue_bytes / 49`, with additional fixed metadata per entry. Raw Quinn send
handles are private. A full receive queue may discard old
datagrams; it does not apply reliable-stream backpressure. Retry token lifetime
is at least two seconds because Quinn serializes token timestamps at whole-second
precision; the admitted handshake deadline remains independently exact. Server validates
addresses using Retry before expensive accepted handshakes; Quinn enforces QUIC
anti-amplification, congestion control and loss recovery. These finite caps are not
an Internet denial-of-service qualification. Cancellation/failure closes partially
authenticated connections and releases permits.

Endpoint abandonment additionally uses [bounded endpoint-scoped driver ownership](quic-owner-cleanup.md).
Actual sessions and reusable listeners retain the application token; only its
last drop requests the finite final driver polls and resource release. This is
abnormal cancellation, with no successful drain or peer-delivery claim.

## Acceptance ledger

- [x] [MOD-QUIC-01] Freeze public profile, auth binding and primary-source design before implementation. Evidence: [carrier](../../crates/l2tunnel-quic/src/lib.rs), [profile](../../crates/l2tunnel-quic/src/config.rs), [UDP loopback tests](../../crates/l2tunnel-quic/src/tests.rs), [auth tests](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-QUIC-02] Preserve TCP auth bytes/tests and verify generic member exchange rejects cross-domain, exporter, certificate, role and configuration mismatches. Evidence: [carrier](../../crates/l2tunnel-quic/src/lib.rs), [profile](../../crates/l2tunnel-quic/src/config.rs), [UDP loopback tests](../../crates/l2tunnel-quic/src/tests.rs), [auth tests](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-QUIC-03] Real UDP-only TLS/member loopback succeeds for TAP/TUN and full/half roles, with no SNI/early data and configured ALPN. Evidence: [carrier](../../crates/l2tunnel-quic/src/lib.rs), [profile](../../crates/l2tunnel-quic/src/config.rs), [UDP loopback tests](../../crates/l2tunnel-quic/src/tests.rs), [auth tests](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-QUIC-04] Wrong certificate/name/member/config/profile and replayed proof fail closed; malformed/timeout/cancellation paths are bounded. Evidence: [carrier](../../crates/l2tunnel-quic/src/lib.rs), [profile](../../crates/l2tunnel-quic/src/config.rs), [UDP loopback tests](../../crates/l2tunnel-quic/src/tests.rs), [auth tests](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-QUIC-05] Postauth Control and DATAGRAM ownership enforce limits, direction, capability, replay, EOF/drop and saturation behavior. Evidence: [carrier](../../crates/l2tunnel-quic/src/lib.rs), [profile](../../crates/l2tunnel-quic/src/config.rs), [UDP loopback tests](../../crates/l2tunnel-quic/src/tests.rs), [auth tests](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-QUIC-06] Run focused tests, Clippy, rustdoc and aggregate repository checks; record finite Linux scope. Evidence: [stable wave4](../../work/implementation-wave4/validation.json), 352 Rust and 18 Python cases, warning-denied lints/docs and identical source hashes; native qualification is separate.
- [x] [MOD-QUIC-07] Integrate genuine QUIC as a separate client/runtime option and qualify native devices/loss/MTU; do not infer this from carrier loopback tests. Evidence: [36 native cases](../../work/native-quic-matrix-audit.json), TAP/TUN/VXLAN, full/half, None/LZ4, ARQ/Cauchy, TCP blocked before authentication, physical MTU 1228 and no captured IP fragmentation.
- [ ] [MOD-QUIC-08] Implement and qualify independent OpenVPN-like standalone bootstrap; genuine QUIC does not satisfy that profile.

## Primary references

[QUIC TLS and application negotiation, RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html),
[QUIC transport, RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html),
[QUIC DATAGRAM, RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html), and
[Quinn 0.11.11 connection API](https://docs.rs/quinn/0.11.11/quinn/struct.Connection.html).
Implementation review also uses pinned cached `quinn` 0.11.11 / `quinn-proto`
0.11.17 source for stream visibility, exporter/identity access, Retry admission,
flow-control windows, MTU and datagram queue semantics; rustls 0.23.45 uses ring.


## Local verification

`cargo test --offline -p l2tunnel-auth -p l2tunnel-quic` passed 11 auth tests and
nine carrier tests, including real UDP sockets for every carrier exchange.
`cargo clippy --offline -p l2tunnel-auth -p l2tunnel-quic --all-targets -- -D warnings`
passed. The required aggregate checker subsequently passed at
[stable wave4](../../work/implementation-wave4/validation.json). Separate native
qualification is recorded by the [36-case audit](../../work/native-quic-matrix-audit.json).
Windows/Android native execution and production congestion/fairness remain open.
