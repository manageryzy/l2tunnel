# Same-socket secure UDP establishment

Status: **implemented and locally runtime integration-tested**, 2026-11-13.
The design/API preceded implementation; the frozen-source required aggregate passed. It refines FIX-13 and SEC-04/SEC-09 without
closing their complete client/service, credential, native or lifecycle gates.
No new CLI syntax, default, trust migration, OpenVPN wire-format exception or
HTTPS replacement is inferred. The [shared-session contract](secure-session.md),
[Noise candidate limits](noise-handshake.md) and all mode-parity requirements
remain in force.

## Ownership and explicit credentials

The runtime receives an already connected Tokio UDP socket, verifies its actual
local/peer endpoints against the fixed configured path, and returns that same
socket. It never binds another socket, creates a TCP side connection, changes
routes or spawns a second socket reader. A sole session owner later multiplexes
remaining bootstrap, membership joining and established records.

The draft reuses `l2tunnel-udp-control`'s existing 144-byte admission gate and
MAC/selective-repeat `ControlEngine`. Their legacy domain labels are retained;
they do not turn this new carrier into standards-valid OpenVPN. Reuse requires
an independently provisioned unpredictable admission secret at both peers and
a separate server-only cookie secret, in addition to the pinned X25519/optional
Noise PSK material. Public hashes and pinned public keys cannot replace these
MAC secrets. This credential cost is explicit implementation scope, not an
owner-selected migration or a full WireGuard implementation.

`ServerAdmission` owns one reusable `ServerGate` and its bounded pending/cookie
quarantine across attempts. Callers retain that owner instead of constructing
a fresh gate after every failed attempt. Runtime cancellation does not erase its
replay quarantine. Fixed endpoint matching excludes unknown initial NAT mappings,
rebinding and migration; those capabilities remain separate design gates.

## Frozen runtime API

The parent owns module declarations and dependencies. All types below live in
`l2tunnel_runtime::secure_udp::establish`:

```rust,ignore
Binding { configuration: [u8; 32], carrier: [u8; 32],
          outer: [u8; 32], member: [u8; 32] }
Config { gate: udp_control::Config, cover: cover::Config,
         profile: handshake::Profile, binding: Binding,
         receive_packets_per_interval: u32 }
Identity { local: handshake::LocalSecret, peer: handshake::PeerKey,
           psk: Option<handshake::Psk> }
Peers { initiator: handshake::PeerKey, responder: handshake::PeerKey }

ServerAdmission::new(config: Config, peers: Peers,
                     admission: udp_control::Secret,
                     cookie: udp_control::Secret, origin: Instant)
    -> Result<ServerAdmission, Error>

async fn connect(socket: UdpSocket, config: Config, identity: Identity,
                 admission: udp_control::Secret, deadline: Instant,
                 entropy: &mut (impl handshake::Entropy + Send))
    -> Result<Established, Error>
async fn accept(socket: UdpSocket, identity: Identity,
                admission: &mut ServerAdmission, deadline: Instant,
                entropy: &mut (impl handshake::Entropy + Send))
    -> Result<Established, Error>

Established { socket: UdpSocket, root: security::SessionRoot,
              binding: security::SessionBinding,
              authenticated: handshake::Binding, peers: Peers,
              cover: cover::Config, tail: BootstrapTail,
              next_outer: u32, deadline: Instant, statistics: Statistics }
BootstrapTail::receive(&mut self, decoded: cover::Decoded<'_>, now: Instant)
    -> Result<bool, Error>
BootstrapTail::poll(&mut self, now: Instant, outer: cover::PacketMeta,
                    output: &mut [u8]) -> Result<Option<usize>, Error>
BootstrapTail::{deadline, drained, statistics, max_packet_bytes}(...)
```

`RuntimeEntropy` is an explicit runtime-only `ring::rand::SystemRandom` adapter.
Tests inject deterministic providers; the pure Noise library still owns no OS
randomness, clock or socket. Runtime entropy failures are terminal and do not
fall back to deterministic bytes. Fresh nonzero gate nonces and a fresh Noise
ephemeral are required. A server creates no Noise/DH owner before an accepted
return-path Echo.

The supplied Tokio `Instant` deadline starts outside this function and survives
gate, Noise, final-flight service and later membership joining. Every wait is
capped by it, and explicit checks before/after awaited operations prevent a ready
future from reporting successful completion after expiry. Gate ticket expiry
can shorten bootstrap service, never extend the caller's deadline. A client
uses one runtime clock origin; reusable server admission keeps one unchanged
origin across attempts. Checked elapsed microseconds feed the pure APIs. No
duplicate, retry, interval refill or cache access renews an expiry.

The returned root proves the pinned Noise exchange and explicit key confirmation,
not the existing Ed25519 member identity. Its public session/transcript binding
is read from that actual root. `Established.authenticated` preserves the exact
public binding supplied to Noise, including the derived outer digest and fresh
ticket session. The member owner must compare its requested context against
these authenticated values, rather than reconstructing them from unchecked
caller fields. User data remains gated by the parent's real
membership proof; no public binding hash or boolean substitutes for it.

## Exact selected-cover bootstrap wire

Every gate/control packet, including the first Hello, uses the selected cover
with `Phase::Handshake`. Its protected body begins with exactly one tag:

| Tag | Body after the tag | Admission |
| --- | --- | --- |
| `0x80` | Exact existing 144-byte Hello/Retry/Echo | Existing strict gate MAC/cookie checks |
| `0x81` | Existing complete MAC-protected `ControlEngine` packet | Existing direction/session/MAC/replay checks before ARQ |

Normal established route classes remain User `1`, Control `2` and parent-owned
Joining `3`. They do not collide with these bootstrap tags. This module never
interprets a user record prefix as a bootstrap privilege. Unknown phases/tags,
oversize input, malformed covers and failed admission/MAC checks receive no
automatic response or Noise-state mutation.

The ordered bootstrap byte channel carries only bounded Noise flight frames:
`[version u8 = 1][kind u8][length u16 big endian][exact ciphertext]`. Kind values
are `1` initiation (96 bytes), `2` response (48), and `3` confirmation (73).
Maximum frame size is 100 bytes. Enforce a bootstrap source bound of at least
100 and at most 4096; each emitted local frame is retained whole, and received
stream parsing remains fixed-buffer/length checked. No user payload or early
configuration data is accepted as a Noise payload.

The normalized admission base profile uses a new secure-UDP domain and binds the
caller application/base digest, Noise profile, global ordered pinned public keys,
the configuration/carrier/outer/member digests, both bootstrap tags/framing and
actual cover appearance/limits. The caller's canonical carrier digest must cover
global connection IDs, SSRCs and payload type; `cover::Config` hides those fields,
so the runtime cannot independently derive that part from its public getters.
This is the same explicit trusted-digest boundary as the Noise binding API.
Its construction must be reviewed with the parent configuration owner.

The fresh logical session ID is `PathTicket::session()`, derived by the existing
gate from both fresh nonces and bound context. It is never a hard-coded caller
SID. The Noise outer binding additionally hashes the normalized gate profile,
that fresh ticket ID and caller ownership binding with a distinct domain. This
binds admission to the actual Noise exchange without using a public hash as a key.

## Resource, retry and final-handoff contract

The gate's eligible Retry is exactly 144 bytes for a valid 144-byte Hello. The
same one-byte tag and same-length cover surround each, so the complete selected
UDP/IP response remains 1:1 before return-path validation. Unknown keys or bad
MACs have no response and no pending Noise owner. Existing server response quota,
pending/quarantine count, cookie expiry and finite client attempts remain active.
Server nonce material can be prepared once and consumed only when a Retry is
actually produced, avoiding fresh randomness for each discarded datagram.

Validate path MTU against IP/UDP, the one-byte tag and exact handshake cover cost.
Under the bounded bootstrap source profile every QUIC-like bootstrap packet has
the two-byte Initial length field and 30 cover bytes; media has 14. Therefore
`gate.outer_overhead` must equal family IP/UDP cost plus 1 plus that cover cost.
The worst-case complete ControlEngine source, cover body/output limits, gate
packet/byte quotas and parser buffers are checked before cryptographic work.
No fragmentation or hidden MTU fallback is added.

A finite receive-packet quota per configured interval bounds parsing/MAC/DH work
under a continuously readable socket. Oversize detection uses one extra receive
byte so truncated oversized datagrams cannot be admitted as complete frames.
When the quota is exhausted, the owner services timers/output and waits for the
original refill/deadline instead of continuously draining hostile input. All
retained buffers, pending flights, attempts and automatic replies are bounded.

Noise encryption is invoked once per new logical flight. Exact ciphertext is
then retained by the existing ARQ channel; retries use its fresh bootstrap MAC
packet numbers while preserving Noise ciphertext. The client stops Echo retries
only after fresh authenticated bootstrap input. No TLS-only
`promote_authenticated` method is called or simulated.

Before returning, every locally generated flight is admitted to the bounded
bootstrap transport; any remaining send/retry/receipt responsibility moves into
`BootstrapTail` with the actual Noise `ConfirmationCache`. Local Noise completion
does not claim physical flush or simultaneous peer readiness. The tail holds no
Noise transport keys and cannot re-encrypt. The parent sole owner must continue
polling it while membership joining proceeds on the same socket, and retain each
emitted complete packet until socket handoff or explicit failure.

Tail receive consumes only handshake bootstrap packets and authenticates before
ARQ mutation. New delivered tail plaintext must be the exact previously verified
peer confirmation; other content cannot become joining or management. Polling
returns a complete covered packet into caller storage, with capacity checks
before consuming an attempt. The caller supplies outer metadata and continues
the returned counter across tail and established packets. Tail service never
spawns another reader and has no unbounded duplicate-response loop. Its next wake
honors retry/refill times and never remains in the past after admission is blocked.
At its original expiry the tail drops bootstrap keys, final cache and retained
bytes; expiry cannot silently restart authentication or alter a data epoch.

Transient connected-UDP path errors (including refused/unreachable paths and
temporary socket backpressure) consume the existing bounded attempt and are
treated as packet loss. Exact retained gate/ARQ ciphertext remains available at
its next finite retry; no inline retry loop or deadline renewal is introduced.
Receive errors consume the receive-work quota. Diagnostics distinguish admitted
emissions from native socket acceptance, send drops and receive errors. Tail
polling reports emission ownership; its embedding sole owner records subsequent
native I/O. Nontransient socket errors and authenticated invalid Noise framing
fail explicitly, and tail errors retire retained bootstrap custody.

## Acceptance gates

- [x] [SUH-01] Record/review the exact API, original clock/deadline, tagged selected-cover wire, fresh ticket SID, extra credentials and public-binding/member-release boundaries before implementation. Evidence: the documented API and framing preceded source implementation; credential cost remains an implementation draft, with no owner trust migration inferred. See [implementation](../../crates/l2tunnel-runtime/src/secure_udp/establish.rs), [regressions](../../crates/l2tunnel-runtime/src/secure_udp/establish_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [SUH-02] Implement actual Tokio client/server establishment on the original connected socket with persistent server gate quarantine, existing gate/control crypto and no TLS side channel or unreviewed key derivation. Evidence: the actual establish connect/accept and persistent ServerAdmission execute admission and maintained Noise on the supplied connected socket. See [implementation](../../crates/l2tunnel-runtime/src/secure_udp/establish.rs), [regressions](../../crates/l2tunnel-runtime/src/secure_udp/establish_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [ ] [SUH-03] Verify no response/allocation before valid admission/return path, complete-wire prevalidation amplification bounds, strict tuple/profile/tag/length checks and bounded hostile-input work. Partial evidence: the [tests](../../crates/l2tunnel-runtime/src/secure_udp/establish_tests.rs) verify quiet invalid input, bounded parse work, strict tuple/context and no Noise/DH before accepted return-path admission. Fixed receive/output buffers and one server nonce can exist before Echo; an allocator-instrumented zero-allocation claim is not established. The literal allocation deliverable remains open.
- [x] [SUH-04] Verify finite exact flight retries, final-confirmation custody after root release, authenticated tail service and unchanged original deadlines through loss, duplicates, blocked sends and silent peers. Evidence: the tests cover scripted flight loss/reorder/duplicates, asymmetric root release, exact confirmation cache, output refusal, expiry and terminal retry retirement. See [implementation](../../crates/l2tunnel-runtime/src/secure_udp/establish.rs), [regressions](../../crates/l2tunnel-runtime/src/secure_udp/establish_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [SUH-05] Verify fresh ticket-derived matching sessions, wrong pins/PSK/carrier/member/outer binding, entropy failure, parser failures and no user release from an unfinished or merely admission-authenticated exchange. Evidence: the tests require fresh matching sessions and reject wrong pins/PSK/public binding, entropy failure and authenticated malformed tails before releasing unfinished roots. See [implementation](../../crates/l2tunnel-runtime/src/secure_udp/establish.rs), [regressions](../../crates/l2tunnel-runtime/src/secure_udp/establish_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [SUH-06] Run real paired Tokio runtime/socket cases for both covers/profiles, drop/reorder/duplicate every bootstrap class and final handoff, and retain exact source/command evidence. A helper enum or manual flight fixture cannot check this gate. Evidence: the paired cover/profile matrix uses actual sockets and task-local bounded loss/error injection; a separate two-thread/two-runtime matrix retains each original socket. See [implementation](../../crates/l2tunnel-runtime/src/secure_udp/establish.rs), [regressions](../../crates/l2tunnel-runtime/src/secure_udp/establish_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [SUH-07] Pass focused tests, formatting, warning-denied Clippy/rustdoc and the required source-stable aggregate checker; distinguish local runtime integration from CI/platform/native/ISP evidence. Evidence: focused runtime/client tests and workspace formatting/strict Clippy passed; the required aggregate also passed with stable hashes and warning-denied rustdoc. See [implementation](../../crates/l2tunnel-runtime/src/secure_udp/establish.rs), [regressions](../../crates/l2tunnel-runtime/src/secure_udp/establish_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [SUH-08] Integrate actual member joining and sole-owner shared session/client APIs under the parent ledger, preserving all original 47 modes, SW-11, bounded recovery, genuine OpenVPN handshake and raw HTTPS acceptance gates. Evidence: the member owner and shared client factories now consume this handoff with the actual retained socket and tails; service/native, all modes and lifecycle acceptance remain under their original parent gates. See [implementation](../../crates/l2tunnel-runtime/src/secure_udp/establish.rs), [regressions](../../crates/l2tunnel-runtime/src/secure_udp/establish_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).

Unchecked items retain their complete deliverables. The parent owns membership joining, established
records/data/control service and CLI capability reporting. Linux/Windows/Android
native devices, NAT migration, full rekey/recovery, production credential policy,
standard-protocol validity and ISP/QoS measurements require their existing gates.
