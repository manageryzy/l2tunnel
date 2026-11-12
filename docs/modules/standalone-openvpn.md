# Standalone OpenVPN-like UDP bootstrap

Status: pure gate, bounded reliable control bytes and verified TLS profile factories
implemented; genuine TLS/member authentication tested over impaired loopback UDP.
The [retained UDP runtime](standalone-openvpn-runtime.md) now has full/paired-half
loopback packet tests; native and production qualification gates remain open. This is a custom
profile with an OpenVPN-like control/data split, not OpenVPN interoperability,
DTLS, QUIC, or a claim of resistance to every active probe. It uses no TCP socket.

## Handshake decision and existing boundaries

Use the existing pinned rustls TLS 1.3 implementation over a bounded reliable UDP
control byte stream. Actual TLS key exchange, server certificate/name validation,
no-SNI policy, disabled resumption/early data, and subsequent exporter-bound
Ed25519 membership remain authoritative. The UDP reliability/envelope is transport
framing, not a new cryptographic key-exchange algorithm. OpenVPN's documented
control channel similarly carries TLS ciphertext over acknowledgment/retransmit
framing, while data uses an independent packet channel.
[OpenVPN protocol](https://openvpn.net/community-docs/openvpn-protocol/)

DTLS remains an alternative requiring a separately reviewed and pinned dependency,
exporter/certificate policy, path cookies, bounded allocation and platform support.
Its application datagrams would still need reliable control delivery. OpenSSL's
documented cookie mechanism validates the return path before handshake allocation;
its exporter can derive application secrets. Neither a DTLS implementation nor
Snow is cached in this workspace at this design checkpoint.
[DTLS cookie validation](https://docs.openssl.org/3.5/man3/DTLSv1_listen/),
[TLS/DTLS exporters](https://docs.openssl.org/3.5/man3/SSL_export_keying_material/)

Noise/Snow would change server provisioning to a static-key policy unless a new
certificate binding were designed. Noise's handshake hash is public channel
binding, not a secret TLS exporter; it must never be used as a packet MAC key.
No private cipher-state extraction or custom Diffie-Hellman implementation is
acceptable. Genuine QUIC already has its own adapter and remains a separate
explicit capability.
[Noise binding and hash semantics](https://noiseprotocol.org/noise.html#channel-binding),
[Snow public handshake API](https://docs.rs/snow/latest/snow/struct.HandshakeState.html)

Existing `l2tunnel-udp` requires `AuthenticatedConnection<TcpStream>` and retains
TLS for liveness, feedback and delivery credit. Its data protection and finite
ARQ/FEC are reusable, but replacing only bootstrap would leave a TCP dependency.
The standalone profile must also keep all later control/feedback/heartbeat traffic
on UDP. Existing TCP/TLS and QUIC auth bytes and exporter domains remain unchanged.

## First implementation slice

Add pure `l2tunnel-udp-control`, using maintained ring HMAC/HKDF/SHA-256 and existing
`SelectiveRepeat`. It owns no clock, socket, task, device or OS privilege. Inject
monotonic time and fresh nonces. The first profile requires a separately
provisioned admission key; no public cookie-only fallback or silent downgrade is
implemented. Admission proves permission to spend bounded handshake resources,
not final membership or server certificate identity. Prefer per-client admission
keys rather than one group key; the initial object owns one configured key and
fixed endpoint tuple, and a future listener must bound the aggregate key/session
roster independently.

Implemented pure API (the single `Config` binds gate and control resource limits):

```rust
ClientGate::new(config, admission_key, client_nonce, now);
ClientGate::poll(now) -> Result<Option<GateFrame>, Error>;
ClientGate::receive_retry(peer, frame, now) -> Result<Option<PathTicket>, Error>;
ClientGate::confirm_peer_control(now); // after ControlEngine authenticated input
ServerGate::new(config, admission_key, cookie_key, now);
ServerGate::receive(peer, frame, server_nonce, now) -> Result<GateEvent, Error>;
ServerGate::finish(session, now); // preserves replay quarantine until cookie expiry
ControlEngine::new(PathTicket, now) -> Result<ControlEngine, Error>;
ControlEngine::write(bytes, now) -> Result<usize, Error>;
ControlEngine::receive(peer, datagram, now) -> Result<ReceiveOutcome, Error>;
ControlEngine::poll(now, output) -> Result<Option<usize>, Error>;
ControlEngine::read(output, now) -> Result<usize, Error>;
ControlEngine::deadline();
ControlEngine::drained();
```

`PathTicket` is opaque and non-cloneable; only successful gate validation creates
one, and engine construction consumes it. It is explicitly *not* an authenticated
member session. Repeated cookie echoes never create a second ticket or reset the
original pending deadline. An engine remains bounded by its original bootstrap
deadline until the trusted owner calls the reviewed one-shot promotion primitive
after actual TLS/member success. The pure method does not verify membership;
[the retained runtime contract](standalone-openvpn-runtime.md) requires a private
actual-authenticated-object activation path and preserves keys/counters/recovery.

## Gate wire and admission invariants

The proposed fixed 144-byte Hello/Retry/Echo record carries an opcode/key-id shape,
strict version/type/reserved bytes, provisioned key identifier, two 16-byte fresh
nonces, server expiry, 32-byte profile digest, 32-byte cookie and 32-byte admission
MAC. The initial Hello requires zero server nonce/expiry/cookie. All MAC inputs
include domain, exact record type, canonical client/server endpoints and profile.
IPv4/IPv6 address families remain distinct; the first IPv6 profile excludes
ambiguous link-local scope IDs. A server validates exact length, version, role,
source tuple, key identifier, profile and admission MAC before state allocation.

An unknown or invalid admission MAC causes no response and no pending allocation.
A valid Hello can receive one 144-byte Retry: **144 response bytes for 144 accepted
request bytes**, before IP/UDP framing, and the corresponding equal-sized IP/UDP
packet for the same address family. A finite global reply count/byte allowance
still applies. The server cookie binds both nonces, endpoints, key ID, profile and
server-local expiry with a separate server-only HMAC key. Echo proves return-path
receipt and knowledge of the admission key; it does not authenticate membership.
No TLS/ARQ allocation is permitted until every echo check passes.

Pending entries and completed-cookie quarantine share one configured count bound.
Each entry has the original absolute deadline; duplicate Hello/Echo cannot extend
it. Finish releases only resources whose cookie can no longer be admitted, or
keeps a bounded tombstone until expiry. Time regression, arithmetic exhaustion,
capacity and deadline failures are explicit. No unbounded per-address map or
replay tombstone collection is allowed.

## Reliable control transport

Derive separate directional outer-control HMAC keys from the admission key using
standard HKDF with a distinct transport domain, both fresh nonces, endpoint tuple,
key identifier and profile. These keys authenticate the bootstrap reliability
records; they are not final data keys. Every record includes explicit version,
role, session, type, monotonic packet number and checked payload length. Authenticate
all bytes before allowing the ARQ engine to parse feedback or allocate payload.
This satisfies `RecoveryEngine::receive`'s external-authentication precondition.

Retries keep the same ARQ source identity and source bytes but consume a fresh
outer packet number. Exact outer replay is discarded without advancing state or
renewing liveness; fresh authenticated retransmissions can regenerate ARQ receipt
feedback. Source IDs, outer replay counters and eventual TLS record counters are
independent. Never reset any counter under the same key/context.

Bound send/receive bytes, source counts (at most the existing 64-record ARQ
window), native bridge capacity, pending output, timer retries, total bootstrap
duration and work per call. Partial stream writes retain unadmitted bytes at the
caller; a small read buffer cannot consume the unread remainder of a recovered
source. A popped datagram is retained across native WouldBlock. No FEC is required
for the bootstrap control stream. TLS library buffering/certificate limits must
be audited separately rather than inferred from the ARQ queue bound.

The control scheduler must reserve a finite ACK/control allowance before admitting
data/control sources, charge actual outer-control header/tag and IP/UDP bytes, and
include retransmissions. The later socket owner shares this same total allowance
with independent user datagrams and preserves mandatory control capacity. User
TCP control frames and probes remain ordinary user admission; only internal
protocol control receives the explicit reservation.

## Verified auth factories and retained UDP runtime

`client_connect_profile_io` and `server_accept_profile_io` perform actual TLS
certificate/name verification and membership using `TlsIoProfile::OpenVpnLikeTls`.
The enum also includes the original `TcpTls` profile; genuine QUIC cannot be
selected by these TLS-record factories. Existing TCP/generic factories delegate
to `TcpTls`. An immutable private profile selects member transcript and secret
data/join/management exporter labels; `AuthenticatedIo::profile()` reports it.
Existing TCP and QUIC domains and membership wire shapes remain unchanged.
Selecting a profile proves its actual TLS/member exchange, not the physical
implementation of caller-supplied I/O. `SessionConfig` holds only a packet layer
and opaque digest, so the factory cannot inspect a carrier field for a preflight
mismatch. The embedding runtime must compute the canonical digest from carrier, cover,
wire version, admission policy/key ID (never the secret key), complete resource
limits, duplex, lane, packet layer and data protection. No early user data.

A later `l2tunnel-openvpn` runtime owns one UDP socket, finite demultiplexer and
supervised driver. It adapts control bytes to `AsyncRead/AsyncWrite`, then keeps
the same authenticated TLS object on that control lane. After membership READY,
purpose-specific TLS exporter secrets create the existing packet sealer/opener.
Control, data, data ACKs/credit and heartbeat all stay on that UDP socket. Paired
half duplex uses explicitly authenticated distinct physical lanes and bounded
pairing; source compatibility for the retained-TCP profile remains separate.

The first profile has fixed tuples, no rebinding, no implicit fallback, no 0-RTT,
no in-place rekey, and no general listener without aggregate admission bounds.
Key-use exhaustion ends the session before nonce reuse. Independent control/data
readers must not race on `recv_from`; one driver demultiplexes validated records.

## Checklist and adversarial test matrix

- [x] [MOD-OVPN-01] Compare maintained TLS-over-reliable-UDP, DTLS and Noise against existing auth/UDP contracts and select the first bounded profile. Evidence: [decision and primary references](#handshake-decision-and-existing-boundaries), [existing auth](../../crates/l2tunnel-auth/src/lib.rs), [existing UDP carrier](../../crates/l2tunnel-udp/src/lib.rs).
- [x] [MOD-OVPN-02] Implement strict gate encoding, distinct admission/cookie keys, fixed-tuple checks and 1:1 pre-validation response accounting. Evidence: [gate implementation](../../crates/l2tunnel-udp-control/src/gate.rs), [truncation/MAC/tuple/quota tests](../../crates/l2tunnel-udp-control/src/tests.rs).
- [x] [MOD-OVPN-03] Bound pending/quarantine entries, cookie expiry, retry count and absolute deadlines; prove duplicate echoes cannot reallocate or extend them. Evidence: [gate lifetime implementation](../../crates/l2tunnel-udp-control/src/gate.rs), [replay/quarantine/capacity/deadline tests](../../crates/l2tunnel-udp-control/src/tests.rs).
- [x] [MOD-OVPN-04] Implement opaque one-use path tickets and domain-separated authenticated control records before ARQ allocation. Evidence: [ticket gate](../../crates/l2tunnel-udp-control/src/gate.rs), [authenticated control parser](../../crates/l2tunnel-udp-control/src/control.rs), [integrity/reflection tests](../../crates/l2tunnel-udp-control/src/tests.rs).
- [x] [MOD-OVPN-05] Compose bounded selective repeat into real ordered bytes with partial read/write ownership, replay handling and monotonic timers. Evidence: [control engine](../../crates/l2tunnel-udp-control/src/control.rs), [independent bidirectional loss/reorder/duplicate simulation and bounded-reader tests](../../crates/l2tunnel-udp-control/src/tests.rs).
- [x] [MOD-OVPN-06] Charge every control/ACK/retry packet and byte with an explicit reserved allowance; prove blocked sources cannot starve mandatory feedback. Evidence: [admission accounting](../../crates/l2tunnel-udp-control/src/control.rs), [two-slot source/ACK reserve and fresh retry number tests](../../crates/l2tunnel-udp-control/src/tests.rs).
- [x] [MOD-OVPN-07] Preserve old auth bytes and add reviewed TLS/member/exporter domains and typed factories for this carrier. Evidence: [typed factories and immutable exporter profile](../../crates/l2tunnel-auth/src/lib.rs), [old/new domains and genuine TLS negative cases](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-OVPN-08] Run genuine TLS/member authentication through independent lossy/reordered/duplicated UDP control peers; verify no-SNI, wrong roots/name/member/profile/domain and cancellation. Evidence: [actual loopback UDP gate and independent TLS control bridges](../../crates/l2tunnel-auth/src/udp_tests.rs), [genuine TLS identity/domain/timeout/cancellation tests](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-OVPN-09] Integrate one supervised UDP socket demultiplexer, retained TLS control and independent exporter-protected user datagrams without TCP reachability. Evidence: [runtime ownership and activation](../../crates/l2tunnel-openvpn/src/runtime.rs), [single socket driver](../../crates/l2tunnel-openvpn/src/driver.rs), [full/paired loopback evidence](standalone-openvpn-runtime.md#focused-verification-and-remaining-limits).
- [ ] [MOD-OVPN-10] Qualify native full/half TAP/TUN, shared pacing/control reserve, path MTU and bounded shutdown with captures and owned-namespace receipts.
- [ ] [MOD-OVPN-11] Independently audit TLS allocation limits, admission-key provisioning/rotation, replay quarantine and listener-wide resource limits before enabling client selection.

Focused tests must include every truncation and malformed reserved field; bad MAC
with otherwise valid cookie; reflected role and different tuple/profile/key ID;
expired cookie and backwards/overflowing time; duplicate echo before/after finish;
capacity under a valid-key flood; no output/state change for unauthenticated
input; duplicate source identity with changed payload; forged/unsent ACK; complete
source retention under WouldBlock; output-too-small atomicity; control reservation
under a full source queue; retry and overall deadline exhaustion. A deterministic
two-peer simulation must transfer actual opaque bytes without reading the other
endpoint's sender ledger. It does not replace actual UDP/TLS or native tests.

Pure checkpoint: `cargo test --offline -p l2tunnel-udp-control` passed 8 focused
tests; targeted `cargo fmt`, all-target Clippy with `-D warnings`, and rustdoc with
`-D warnings` passed locally on Linux. This pure checkpoint introduces no socket,
runtime lease promotion, native qualification or client flag. It was included in
the stable [wave 5 aggregate receipt](../../work/implementation-wave5/validation.json):
420 Rust cases including doctests, 28 Python cases, full `tools/check.py` passed
with matching before/after source hashes. That receipt predates the additive auth
profile factories and loopback UDP test below.
The finite simulation transfers 40,000 and 27,000 independently generated bytes
bidirectionally with deterministic loss, reordered delivery and duplicates.
The partial-read adapter retains at most one additional configured source buffer
beyond the ARQ receive budget; stream reads returning zero are not EOF evidence.

The subsequent auth/control checkpoint passes 14 auth plus 10 UDP-control tests,
targeted formatting, strict all-target Clippy and strict rustdoc. The new test
performs the actual fixed-size gate over two loopback `UdpSocket`s, then passes
TLS ciphertext through two independent control engines with finite 4,096-byte
duplex buffers and at most one held reordered datagram per actor. Deterministic
fault injection drops every seventh emitted control packet, delays eligible
ninth packets by 12 ms, and duplicates eligible eleventh packets. Both directions
report actual drops, delays, duplicates and rejected replays; actual verified
TLS/member exchange completes, followed by 32,768/24,576 bytes of bidirectional
application payload. No TCP socket is created by that test. No-SNI and matching
domain-separated exporters are verified on the resulting TLS objects. Wrong
roots/name/member/config/domain and timeout/cancellation run through separate
genuine TLS memory-I/O cases. This is finite loopback evidence, not throughput,
native VPN, clean shutdown or production TLS-buffer accounting qualification.

The implemented retained runtime keeps the bootstrap deadline until an actual
verified TLS/member capability authorizes one-shot bounded control promotion.
Admission-derived outer MAC keys stay separate from actual TLS-exporter data keys.
The runtime defines bounded EOF/close, retained final-ACK retry service,
cancellation, lease/key-use limits and one shared control/data ledger. Its exact
scope and tests are recorded in [the runtime module](standalone-openvpn-runtime.md).
Independent allocation/provisioning review and native/client selection remain
open under MOD-OVPN-10/11.
