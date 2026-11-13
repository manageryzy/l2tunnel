# Shared client factory for the authenticated UDP carrier

Status: **implemented and locally client-library integration-tested**. This FIX-13 client-core
integration composes the real establishment and member-admission runtimes.
The existing CLI and service data drivers are not changed into this profile by
an enum, constructor or compile. Native forwarding, automatic retained-state
recovery and complete mode switching remain required under the parent ledgers.

## Frozen implementation-draft API

`l2tunnel_client_core::secure_udp` owns no private CLI parser and opens no device.
It consumes the caller's original already-connected UDP socket and explicit
local Noise key/remote pin, existing Ed25519 member key, unpredictable admission
secret and server-only cookie secret. The runtime never replaces these with
public hashes, converts Ed25519 keys to X25519, chooses a cover implicitly, or
falls back to another connection mode.

```rust,ignore
Cover { appearance, initiator_connection, responder_connection,
        initiator_ssrc, responder_ssrc, payload_type,
        max_packet_bytes, max_protected_bytes }
Membership { retry_interval, max_attempts,
             receive_interval, receive_packets_per_interval }
Settings { gate: udp_control::Config, cover: Cover,
           profile: handshake::Profile, application: core::ConfigDigest,
           outer: [u8; 32], member: identity::MemberPublicKey,
           membership: Membership, bootstrap_receive_packets_per_interval: u32 }
Settings::configuration(&self, peers: establish::Peers)
    -> io::Result<security::ConfigDigest>

async fn connect(socket: UdpSocket, settings: Settings,
                 identity: establish::Identity, member: &identity::IdentityKey,
                 admission: udp_control::Secret, deadline: Instant,
                 entropy: &mut (impl handshake::Entropy + Send))
    -> io::Result<Session>
Server::new(settings: Settings, peers: establish::Peers,
            admission: udp_control::Secret, cookie: udp_control::Secret,
            origin: Instant) -> io::Result<Server>
Server::accept(&mut self, socket: UdpSocket, identity: establish::Identity,
               deadline: Instant, entropy: &mut (impl handshake::Entropy + Send))
    -> io::Result<Session>
Session::{requested, effective, info}(&self)
Session::into_parts(self) -> member::Parts
```

The complete public `Cover` inputs are in global initiator/responder order.
Role-specific encoder configuration reverses local/peer IDs and SSRCs without
changing the canonical carrier digest. The digest binds appearance, all IDs,
SSRCs, payload type and packet/protected limits using fixed byte order; callers
cannot supply an unrelated carrier hash through this constructor. Both role
views are validated before network work.
`Cover::bootstrap_overhead(ipv6)` reports the required explicit gate overhead:
IP/UDP plus the one-byte bootstrap tag and handshake-phase cover. The supplied
gate must already select that cost and compatible ARQ/MTU bounds. The factory
rejects an incompatible legacy default instead of silently shrinking its source
geometry. Complete covered packet limits count UDP payload bytes, so only the
actual IP/UDP headers are added when comparing that limit with the path MTU.

The versioned configuration digest binds the caller's complete data-application
digest, existing complete gate profile digest, cover digest, Noise profile,
both ordered pinned Noise public keys, configured member identity, outer binding
and every membership retry/receive resource value, plus the explicit bootstrap
receive quota. Duration fields retain
their exact nanosecond representation in the client configuration hash, including
those in the reused gate profile; truncation cannot hide a configuration change.
A separate member-policy
digest binds the expected member and pinned Noise pair. These are authenticated
public inputs, never authentication keys. Noise uses a fresh gate-derived session
ID; membership then signs that actual final Noise transcript and these configured
values, using the exact authenticated prologue retained by the runtime. Its
outer field is the runtime-derived gate/session/ownership binding, not a second
unverified caller replacement. A configuration field change must not silently
retain the old digest.

The `application` field remains the embedding data profile's canonical contract;
it is not a new daemon config parser or proof that a named mode is implemented.
The constructor does not create TLS/certificate evidence for UDP. The explicitly
configured responder Noise pin anchors this carrier's own-server identity;
existing certificate/SNI policy stays required for the TLS/raw carriers.

## Custody, observations and failure behavior

The client checks its actual member public key against `Settings.member` before
emitting a packet. The server accepts that configured fixed point-to-point member
through the existing pure signature gate; the legacy generic allowlist remains
available for retained transports. `Server` retains the reusable admission gate
and replay quarantine across failed/cancelled attempts. No extra account,
multi-device or enrollment workflow is introduced.

One supplied absolute deadline covers the original socket's admission, Noise and
membership stages. Neither helper starts a fresh timeout after a successful
earlier phase. Returned `Session` means completed member authentication, not
native runtime readiness or the service actor's `Connected` state. Requested
settings and effective role-specific bootstrap configuration remain observable,
with no capability fallback. `effective()` reports the validated derivation
inputs; `info().authenticated` separately reports the exact public Noise
prologue, including its fresh session and derived outer binding. Its parts
transfer the root, original socket and
both bounded final-flight tails to the eventual sole data/control reader.

This factory is shared frontend-independent code. Wiring it into the service
actor and actual CLI/native Swift and other data drivers remains a separate
gate, with the requested/effective carrier, cover, policy, protection and capability
limitations reported from actual operation. This checkpoint cannot replace full
SW-11, all 47 P-* modes, OpenVPN wire handshakes, the original HTTPS packet path,
default recovery or Windows/Android execution.

## Acceptance ledger

- [x] [CSU-01] Freeze the explicit fixed-peer trust, canonical global cover/configuration/member binding, original socket/deadline and requested/effective API before source implementation. Evidence: this explicit trust/configuration/custody design preceded the [shared factories](../../crates/l2tunnel-client-core/src/secure_udp.rs). See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [CSU-02] Implement actual shared connect/accept factories using the same-socket runtime and real existing-member proof; retain reusable admission quarantine and all final-flight owners without a separate TCP flow. Evidence: the [connect/accept factories](../../crates/l2tunnel-client-core/src/secure_udp.rs) use actual same-socket Noise/member admission and retain all tails plus reusable quarantine. See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [CSU-03] Test role-invariant canonical digests, every configured public/resource field, invalid cover/budget inputs and wrong member/Noise identities before user release. Evidence: three [configuration regressions](../../crates/l2tunnel-client-core/src/secure_udp_config_tests.rs) cover complementary roles, every policy field, submicrosecond duration changes, invalid budgets and explicit rejection; [factory negatives](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) reject wrong member/pins. See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [CSU-04] Exercise real two-client-core endpoint authentication, then common protected Swift and fixed management over the original UDP pair with exact bytes, both appearances and negative/final-loss cases; do not substitute a fabricated authenticated root. Evidence: the [real factory composition](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) carries full protected Swift/control on the original pair; deterministic final-flight loss is tested at the lower [member runtime boundary](../../crates/l2tunnel-runtime/src/secure_udp/member_tests.rs). See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [CSU-05] Run focused and frozen-source required aggregate checks with exact input/command evidence; preserve failed observations and distinguish local loopback, native labs and platform/ISP qualification. Evidence: focused and required aggregate commands passed with frozen hashes; failed attempts remain beside the passing receipt, and service/native/ISP qualification is separate. See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [ ] [CSU-06] Wire the actual selected carrier into the shared service/CLI and native device drivers, retain all requested compositions and full SW-11, and qualify lifecycle recovery, liveness/rekey and performance under the complete network matrix.

The parent owns this module, document, client-core declarations/manifests and its
integration tests. Establishment, member admission and Swift workers retain their
disjoint file ownership. All design choices here remain implementation drafts;
they are not additional owner decisions.
