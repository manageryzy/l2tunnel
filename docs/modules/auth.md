# Authenticated TCP module

Status: **implemented and integration-tested on local TCP loopback**, 2026-11-12
(Asia/Tokyo). Design was recorded before implementation.
`l2tunnel-auth` is an OS/runtime-bound transport adapter. It does not move Tokio,
socket or clock requirements into the public protocol core. This iteration
implements real TCP/TLS and post-handshake member authentication, without TAP/TUN
device setup, multistream joining, UDP/raw transport, data-carrier encapsulation
or traffic shaping.

This is the existing TLS adapter's implementation contract. The 2026-11-13
owner-selected target is a [shared WireGuard-like point-to-point secure session](secure-session.md)
over the selected carrier, preserving encrypted/authenticated data and replacing
the separate TLS-bootstrap dependency. That target is planned; this adapter's
exporter-bound member exchange cannot be treated as a bare datagram handshake.
HTTPS-like still requires its real outer TCP/TLS handshake. Existing credentials,
trust tests and historical receipts remain unchanged until a reviewed binding is
specified; no dependency or credential migration is approved here.

The [pure identity extraction](session-identity.md) now supplies one maintained
Ed25519 key/parser, public member type, signature verifier and bounded allowlist.
This adapter retains its public key-generation/loading/error APIs through
delegating wrappers; OS randomness stays here. Existing TLS/member and HTTPS
transcripts and wire bytes remain unchanged. The separately domain-separated
Noise member proof does not turn a TLS exporter into a datagram trust assertion.

## Exact initial embedding interface

- `ClientTls::from_der_roots(&[Vec<u8>])` creates a private TLS 1.3-only rustls
  configuration using maintained certificate/name verification. SNI, resumption,
  early data and TLS key logging are disabled. No accept-all verifier is exposed.
- `ServerTls::from_der(&[Vec<u8>], key_der: &[u8])` consumes an owned certificate
  chain and parses a supported DER private key into the TLS 1.3-only server
  configuration. The key input is borrowed only during construction.
- `MemberKey::from_pkcs8(&[u8])` loads an Ed25519 member private key through ring.
  `public_key()` returns `MemberPublicKey([u8; 32])`. Private key/config types do not
  implement Debug. `MemberAllowlist::new(&[MemberPublicKey])` rejects empty lists
  and more than 1,024 entries.
  `MemberKey::generate_pkcs8()` supplies fresh secret provisioning bytes, which
  callers must store securely and never log.
- `SessionConfig { layer: PacketLayer, digest: ConfigDigest }` specifies the exact
  expected native packet layer and canonical configuration digest on both peers.
- `client_connect(TcpStream, &ClientTls, server_name: &str, &MemberKey,
  SessionConfig, Duration) -> Result<AuthenticatedConnection, Error>` completes
  both TLS and member authentication under one timeout.
- `server_accept(TcpStream, &ServerTls, &MemberAllowlist, SessionConfig, Duration)
  -> Result<AuthenticatedConnection, Error>` accepts a single already connected
  socket under the same bounded handshake contract. Listener concurrency and
  global admission limits remain the runtime's responsibility.
- `AuthenticatedConnection` implements Tokio `AsyncRead + AsyncWrite`, exposes
  `info() -> &SessionInfo`, `local_addr()` and `peer_addr()`, and can be consumed by
  `into_parts() -> (tokio_rustls::TlsStream<TcpStream>, SessionInfo)`. It retains
  the original TCP and TLS object; no reconnect occurs at the auth/data boundary.
- `SessionInfo` contains `session_id: [u8; 16]`, `peer_member` (Some on the server,
  None on the client), the authenticated `member` and `server` identities, and
  matched `config`. `export_key(KeyPurpose, Direction, lane_id)`
  derives 32-byte secrets with purpose labels and session/direction/lane context.
  `Secret` exposes bytes explicitly and does not implement Debug. Key lifecycle,
  caller memory protection and packet protection are separate work.
  Exporter-bearing transcript buffers and returned secrets use maintained
  zeroize 1.9.0 on drop; this does not promise that every stack/register copy is
  erased or protect caller copies of secret bytes.

The client verifies the configured server name against its certificate even when
SNI is absent. The network dial address is supplied by the caller in `TcpStream`
and need not equal that verification name. The fixed configuration intentionally
has no HTTPS/ALPN claim or on-wire tunnel banner before TLS completes.

## Authentication transcript and state machine

Use pinned rustls 0.23.45 with the ring provider and TLS 1.3 only, tokio-rustls
0.26.5, Tokio 1.53.1 and ring 0.17.14. Every connection performs fresh TLS and
fresh member authentication. Nonces/session IDs use ring's operating-system
random source. No custom cryptographic primitive is introduced.

All application handshake messages are inside the established TLS stream. A
fixed 8-byte header contains `L2AU`, draft version 1, message kind and a big-endian
u16 body length. The maximum body is 192 bytes. Each state requires its exact
kind and body length, rejecting unknown, truncated, oversized or out-of-order
messages without allocating from peer lengths. The total timeout covers TLS and
the entire application exchange, not a separately renewed timer per read. It
must be positive and at most 120 seconds.

1. Server sends CHALLENGE: server nonce (32), fresh session ID (16), SHA-256 of
   server leaf DER certificate (32), layer (1), config digest (32): 113 bytes.
2. Client validates layer/digest and the certificate hash against the TLS-verified
   certificate, generates a nonce and sends PROOF: client nonce (32), member
   public key (32), layer (1), config digest (32), Ed25519 signature (64): 161 bytes.
3. The signature input is the fixed domain `l2tunnel/member-auth/v1` plus a NUL,
   32 TLS exporter bytes under the dedicated member-proof label, the exact
   113-byte challenge, and the exact 97-byte proof prefix. This binds both roles
   by their fixed state/field positions, both fresh nonces, the server certificate,
   session ID, member identity, native layer and configuration to this TLS
   connection. Exporter bytes are not sent as application fields.
4. Server checks layer/digest, allowlist membership and the signature before
   sending ACCEPT: session ID (16) and SHA-256 transcript hash (32): 48 bytes.
   A failed check closes the connection without an application diagnostic banner.
5. Client checks ACCEPT and sends FINISH containing the same hash (32). Server
   checks it and sends READY containing the hash (32). Server returns only after
   flushing READY; client returns only after validating READY. Neither public
   factory releases a data stream before these checks complete.

TLS authenticates server acceptance and the completion exchange. The additional
Ed25519 proof authenticates client membership. The transcript hash is an equality
binding inside TLS, not a substitute MAC. A captured PROOF is invalid on another
TLS connection even if its challenge fields were copied, because exporter secrets
differ. TLS-verified certificate identity remains independent of the optional
future cover name. There is no current claim of resistance to all active probes.

## Verification checklist

- [x] [MOD-AUTH-01] Real TCP loopback auth for Ethernet/TAP and IP/TUN bindings, followed by bidirectional data on the same socket. Evidence: [real_tls_tap_and_tun_keep_socket_verify_identity_and_exchange_data](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-AUTH-02] Server-observed no SNI, TLS 1.3, certificate root/name rejection and disabled early-data/resumption configuration. Evidence: [TLS tests](../../crates/l2tunnel-auth/src/tests.rs), [restricted configuration builders](../../crates/l2tunnel-auth/src/lib.rs).
- [x] [MOD-AUTH-03] Unlisted members, invalid signatures and layer/config mismatch fail before stream release. Evidence: [member/configuration and corrupt-proof tests](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-AUTH-04] Malformed/oversized/out-of-state frames fail; total timeouts apply during TLS and member authentication. Evidence: [bounded-handshake tests](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-AUTH-05] Captured proof is rejected on another TLS connection, including direct verification with the old challenge and new exporter. Evidence: [captured_member_proof_cannot_replay_on_another_tls_connection](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-AUTH-06] Peers derive equal exporter keys, while purpose/direction/lane changes separate them. Evidence: [exported_keys_match_and_separate_purpose_direction_and_lane](../../crates/l2tunnel-auth/src/tests.rs).
- [x] [MOD-AUTH-07] Package formatting, nine focused tests, denied-warning Clippy and rustdoc passed locally. Evidence: [implementation and public docs](../../crates/l2tunnel-auth/src/lib.rs), [executed test suite](../../crates/l2tunnel-auth/src/tests.rs).

Executed: `cargo fmt -p l2tunnel-auth`,
`cargo test -p l2tunnel-auth --offline` (9 tests),
`cargo clippy -p l2tunnel-auth --all-targets --offline -- -D warnings`, and
`RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-auth --no-deps --offline`.
These are local Linux checks against real loopback TCP/TLS and development
certificates. They do not establish native-device, remote CI, production PKI,
target-middlebox, public-listener load or independent security-review evidence.

`authenticated_pair` in the [test module](../../crates/l2tunnel-auth/src/tests.rs)
is an executed embedding example: bind/connect actual TCP, call the two factories,
then use ordinary Tokio `read_exact`, `write_all` and `flush` on the returned
connections. It records socket addresses before/after authentication and compares
both peers' session/member/server/configuration identities. The local tests use
fresh rcgen development certificates and do not install trust roots on the host.

## Remaining integration gates

- [ ] [MOD-AUTH-08] Bound listener connection count, concurrent certificate work, per-peer rate and total runtime memory before public exposure.
- [ ] [MOD-AUTH-09] Integrate authenticated management record classification and traffic framing; the raw post-auth byte stream does not supply those mechanisms.
- [ ] [MOD-AUTH-10] Add provisioned credential storage/rotation/revocation policy, authenticated lane joining, key-update lifecycle and session teardown.
- [ ] [MOD-AUTH-11] Independently qualify HTTPS cover, UDP-only/raw carriers, target middleboxes and native Linux/Windows/Android deployments.
- [ ] [MOD-AUTH-14] Integrate the shared point-to-point authentication/key API through SEC-01..SEC-04 and SEC-09, preserving real outer TLS where required, peer/member/configuration binding, supported secret handling, original deadlines and current compatibility tests without private-state extraction or an implicit credential migration.

## Verified-channel reuse

The generic `client_authenticate_channel` / `server_authenticate_channel` helpers
accept bounded duplex I/O and `CallerVerifiedChannel`. This constructor is an
assertion by a transport adapter, not a verifier or cryptographic evidence: the
caller must already verify TLS 1.3 server identity, disable early data, and obtain
the domain-specific exporter from that exact channel. Failure/cancellation must
close that channel. The helpers expose no signing internals or authenticated I/O.
`ChannelTransport::QuicTls` uses separate exporter/transcript domains; TCP retains
its original bytes, labels and all original tests. Exporters/transcripts zeroize.

- [x] [MOD-AUTH-12] Share bounded member exchange with explicitly caller-verified channel binding and separate QUIC domain. Evidence: [implementation](../../crates/l2tunnel-auth/src/lib.rs), [domain/exporter/certificate/config/role and original TCP tests](../../crates/l2tunnel-auth/src/tests.rs).


`client_connect_io<S>` / `server_accept_io<S>` establish actual verified TLS over
caller-owned reliable ordered `AsyncRead + AsyncWrite + Unpin` I/O and return
`AuthenticatedIo<S>`. They preserve the TCP transcript/exporters, TLS settings and
complete deadlines. `AuthenticatedConnection` remains its `TcpStream` alias;
existing socket APIs delegate to these helpers. Failure/cancellation drops the
supplied I/O, whose transport owner must close its connection. This generic helper
does not imply that a userspace raw TCP adapter has been implemented or qualified.

- [x] [MOD-AUTH-13] Retain verified TLS/member state over generic reliable I/O with backward-compatible TCP APIs. Evidence: [generic helpers](../../crates/l2tunnel-auth/src/lib.rs), [actual TLS over bounded duplex and original TCP tests](../../crates/l2tunnel-auth/src/tests.rs).
