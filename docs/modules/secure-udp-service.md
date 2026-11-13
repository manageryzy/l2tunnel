# Shared service and CLI for the selected secure UDP carrier

Status: **implemented and focused runtime integration-tested on local Linux**,
2026-11-13. The
design below was reviewed and frozen before its source integration. This subordinate
FIX-13/FIX-12 wave connects the existing same-socket authentication factories to
the real service owner and an explicitly selected CLI profile. It does not close
the broader [secure-session gates](secure-session.md), SW-11, default retained
recovery, native performance, Windows/Android, or original OpenVPN/HTTPS work.
No dependency, provisioning policy, CLI spelling or timeout is attributed to an
owner decision by this implementation draft.

## Composition and ownership contract

The user selects QUIC-header or RTP-like appearance and Swift as separate
choices. The original connected UDP socket performs admission, Noise, existing
Ed25519 member proof, protected user records and fixed authenticated management.
No TCP/TLS side connection, implicit carrier fallback, fabricated TLS credential,
public-hash authentication key or replacement member identity is introduced.

The shared `Prepared` plan receives parsed fixed-peer credentials and a deferred
readiness-capable attachment. Validation opens neither a socket nor a device.
One accepted setup deadline covers bind/connect, admission, Noise, membership,
device creation and the driver's actual first ready observation. Existing late
cancellation and generation checks remain the sole readiness publication point.
Authentication completion alone cannot return service `Connected`.

The runtime transport API is coordinated with its owner before source integration.
It consumes all `member::Parts`: original socket/root, actual cover, exact public
authenticated binding, both final-flight tails and continuing outer counter. It
owns the sole UDP reader and native device inline. Dropping that run future
releases the original owners before the service reports cancellation, abort or a
replacement generation. Disconnect remains an explicit local abort, never an
unproved peer-confirmed drain.

The member/Noise deadline is a setup and final-tail expiry, not the forwarding
lifetime. Established control expiry, authenticated liveness and later key/session
expiry have separate explicit bounds. Only accepted authenticated peer activity
may establish liveness. Invalid packets, local sends or an ICMP error do not prove
that a peer is alive or has closed. Bounded path loss consumes configured work
without creating an inline retry loop or renewing an absolute deadline.

## Credentials and persistent admission

New runtime credential owners hold explicit zeroizing 32-byte X25519 static
inputs, optional profile-required PSK, independent admission secret and separate
server-only cookie secret. Each attempt obtains fresh consuming handshake owners;
no raw secret/root getter or Ed25519-to-X25519 conversion is exposed. The existing
Ed25519 client credential remains PKCS#8; the configured server Noise pin anchors
own-server identity. Optional IKpsk2 must be selected explicitly and supplied its
required PSK; an error cannot silently select IK instead.

A server plan retains one reusable admission owner across failed, cancelled and
reconnected attempts. Recreating that owner per attempt would erase its replay
quarantine. Its serialized borrow is bounded by the same accepted deadline.
Explicit reconnect makes a fresh authenticated cryptographic session; it does
not claim automatic retained-state recovery or permit replay of old ciphertext.

Private CLI credential inputs must be owned private regular files. On Unix,
opened-descriptor metadata, `O_NOFOLLOW` and bounded nonblocking reads reject
symlinks, special files, wrong ownership, exposed permission bits and invalid
lengths before network/device work. New raw32 inputs are distinct from existing
OpenVPN-like raw64 bundles. Existing legacy member parsing and CLI behavior stay
available; no credential is automatically generated or overwritten.

The credential leaf API is frozen independently of the coordinated transport:

```rust,ignore
credentials::NoiseIdentity::new(private: Zeroizing<[u8; 32]>,
    peer: handshake::PeerKey, profile: handshake::Profile,
    psk: Option<Zeroizing<[u8; 32]>>) -> io::Result<NoiseIdentity>
credentials::Secret32::new(Zeroizing<[u8; 32]>) -> io::Result<Secret32>
credentials::Client::new(NoiseIdentity, identity::IdentityKey, Secret32)
    -> io::Result<Client>
credentials::Server::new(NoiseIdentity, Secret32, Secret32)
    -> io::Result<Server>
credentials::{read_secret, read_public, read_member}(&Path)
```

These owners expose only public identities/profile/ordered peer observations.
Crate-private attempt constructors make the necessary zeroizing copies into
existing consuming crypto APIs. Public Clone/Debug/raw-key accessors are absent.
Obvious all-zero private inputs, self pins, profile/PSK mismatch and overlapping
purpose credentials fail explicitly. Noncontributory peer DH is additionally
rejected by the maintained handshake adapter before member/device admission.

## Canonical profile and observations

A new profile composes the complete actual global initiator/responder transport
policies with the selected carrier configuration. Its domain-separated application
digest includes both role views, Swift/native geometry, queues, budgets, control
and liveness/resource bounds, protection and epoch policy. The carrier factory
binds this value with its existing full gate/cover/member/pin contract. Local
report cadence and secret bytes do not become a substitute for that digest.

Swift continues to require AEAD. Capacity derives from the actual common-record
route9 + prefix10 + AEAD tag16 + selected cover13/14 + IP/UDP28/48, rather than
legacy Swift's 24-byte packet protection. Both role configurations must validate
and fit before credentials are used or I/O starts. This does not remove generic
authenticated-cleartext requirements from other compositions.

The coordinated profile API retains private immutable construction inputs:

```rust,ignore
profile::Profile::new(connection: ConnectionConfig, session: secure_udp::Settings,
    initiator: transport::Config, responder: transport::Config)
    -> io::Result<Profile>
Profile::settings(&self) -> secure_udp::Settings
Profile::runtime(&self, security::Role) -> transport::Config
Profile::configuration(&self, establish::Peers)
    -> io::Result<security::ConfigDigest>
Profile::resolve(&self, &swift::control::Policy, security::Role, establish::Peers)
    -> Option<swift::policy::Resolved>
```

The constructor hashes the caller's embedding application seed, complete base
connection contract and both transport canonical digests in global role order.
It then supplies that derived application digest to the existing carrier factory.
The two role configurations must have complementary send/receive directions and
matching packet-security intervals, initial scopes and control grammar/resource
contracts. A policy resolution recomputes both role views and the full global
configuration digest using the original embedding seed, never recursively hashes
an already-derived digest or substitutes a digest of just one direction.
Provisioned cover/security ceilings remain distinct from the current symbol MTU;
out-of-ceiling requests are refused explicitly rather than silently reduced.
The existing carrier factory's bootstrap MTU check is refined accordingly:
validate the largest actual gate/control datagram (selected handshake cover,
bootstrap tag, ARQ source/header and IP/UDP), rather than require the entire
provisioned cover storage ceiling to fit the initial bootstrap MTU. The selected
active transport `path_mtu` is validated separately. This permits negotiated
upward changes within the authenticated capacity ceiling without pretending
the original path already supports jumbo datagrams. Oversized actual bootstrap
geometry remains a setup error and receives a boundary regression.

For the initial CLI, public appearance CID8/SSRC4 values derive reproducibly from
the ordered pinned Noise public keys using separate SHA256 domains. These are
header identifiers, never authentication keys or evidence of resistance to
identification. This is an implementation draft, not an owner wire decision.
An explicit maximum path-MTU capacity may differ from the current selected MTU;
both values and their resulting geometry remain authenticated and observable.
The current cover codec has one storage ceiling for both packet phases. QUIC's
handshake header is 17 bytes larger than its established header, so the CLI
provisions that bounded extra storage headroom while preserving the requested
maximum data MTU and security body capacity. Actual bootstrap packets still fit
their original MTU. Reported maximum data MTU derives from the admitted security
body plus established framing, not from the larger phase-neutral storage buffer.
This selected high-level Swift profile requires lossless representation in the
existing complete policy command: integer kilobits, denominator 1000 repair
permille, and common startup MTU/channels/window/repair in both directions.
Unrepresentable inputs fail before authentication; they are never rounded or
flattened by a partial update. Directional rates and queue budgets may differ.
The lower-level transport retains its richer asymmetric direction API, and all
other record-profile requirements remain in their original ledgers.

The service publishes a distinct secure-UDP observation containing requested and
effective carrier, appearance, Swift policy, exact authenticated prologue/final
binding, original endpoints, actual generation and latest driver counters. It
does not relabel the legacy TLS Swift observation. Actual capabilities identify
unimplemented operations explicitly; requested state is not reported as applied.
The common policy controller supplies authenticated agreement, drain and terminal
outcomes before `set-swift` can report success on this carrier. Focused paired-service
tests passed a real policy change from MTU 1500 to 1800 and forward rate 10000 to
12000 kbit/s, preserved the unrequested reverse rate and delivered exact native
bytes afterward. This does not close or narrow SW-11/15/16.

## Local API and CLI compatibility

Keep local `VERSION = 1` and its legacy response bytes. Add explicit version 2
handling for the new observation/actions. A version1 request to a new-profile
service returns `requires_version_2` with no state before any action is submitted.
A version2 request to an old service fails explicitly; there is no automatic
retry, downgrade, fallback or duplicate write. CLI `--api-version 2` opts into
new-profile status/control, and the new profile frontend uses version2 itself.
The private Unix transport accepts only these bounded supported versions and
checks that the reply version matches the explicitly requested version.

The new CLI leaf selects an explicit appearance carrier plus `--record-profile
swift` before legacy Swift parsing. Exact syntax remains an implementation draft.
It validates combinations first, then reads bounded credentials and constructs
the same public `Prepared` plan used by another frontend. Device setup, live state,
connect/cancel/disconnect/reconnect and terminal results remain in the service.

The initial implementation requires explicit forward/reverse wire rates and
Noise pattern. Routine CLI construction values are current MTU 1500, maximum
data MTU 9000, 16 channels, a 64-source window, zero repair permille, one-second
status cadence, a ten-second policy deadline and a one-hour session lease.
Authenticated liveness uses a one-second Ping interval and five-second Pong
deadline. These are bounded implementation defaults, not owner decisions or
performance recommendations; the typed profile retains explicit resource
configuration. Future CLI exposure of every resource setting remains possible.
The profile builder bounds its derived bootstrap cookie lifetime and retry
ceilings by the explicit original setup timeout, including short typed-service
deadlines. This does not extend that timeout or silently replace a requested
transport policy. A short-deadline configuration regression accompanies the
actual negative-trust and pre-readiness cancellation tests.

Source tests cover credential files, complete role-policy binding, explicit CLI
selection, local API version checks and real paired services with readiness-capable
Unix datagram devices. They are present in
[credential tests](../../crates/l2tunnel-client-core/src/secure_udp/credentials_tests.rs),
[profile tests](../../crates/l2tunnel-client-core/src/secure_udp/profile_tests.rs),
[CLI tests](../../crates/l2tunnel-client-core/src/secure_udp/cli_tests.rs),
[local API tests](../../crates/l2tunnel-client-core/src/local/tests.rs) and
[paired service tests](../../crates/l2tunnel-client-core/src/service/tests/secure_udp.rs).
The source-stable [focused receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json)
records 17 runtime transport tests, 21 secure-UDP client tests, 20 service tests
and 12 local API tests, followed by strict package Clippy and rustdoc. These
filters overlap and must not be summed as distinct tests. All six commands exited
zero; their exact vectors, log hashes and equal before/after compiled-source maps
are retained in the receipt. [Attempt 1](../../work/secure-udp-integrated-focused-20261113/attempt-1/validation.json)
preserves the short-setup configuration failure; [attempt 2](../../work/secure-udp-integrated-focused-20261113/attempt-2/validation.json)
preserves the structural Clippy failures. The passing attempt supersedes neither
historical result. The required whole-workspace aggregate subsequently passed;
its exact source scope and counts are recorded under SUS-09.

The runtime/device fixture uses AF_UNIX datagrams with actual original connected
UDP carrier sockets. This qualifies that bounded local composition, not Linux
TAP/TUN execution, Windows/Android, real-network performance or ISP classification.
The focused receipt excludes documentation and unrelated tools/simulator inputs.

## Acceptance ledger

- [x] [SUS-01] Record and review the runtime/profile/credential/service/API contract before code; freeze exact coordinated transport signatures and preserve all parent requirements. Evidence: this [design and API contract](secure-udp-service.md) and the coordinated [runtime interface](secure-udp-runtime.md); this checkbox covers design review only.
- [x] [SUS-02] Implement independent zeroizing manual credential owners and bounded private-file parsing, including invalid lengths, ownership/modes, symlinks, special files, wrong pins/profile/PSK and no secret status export. Evidence: [credential source and tests](../../crates/l2tunnel-client-core/src/secure_udp/credentials_tests.rs), [negative actual trust/service tests](../../crates/l2tunnel-client-core/src/service/tests/secure_udp.rs), and [focused passing receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json). Ownership rejection is tested through the opened-metadata predicate; no cross-UID privileged file lab is claimed.
- [x] [SUS-03] Bind both actual role configurations and selected common AEAD/cover geometry into a canonical application profile; reject invalid policy or attachment before socket/device work. Evidence: [profile geometry, digest and no-rounding tests](../../crates/l2tunnel-client-core/src/secure_udp/profile_tests.rs) and [bootstrap-capacity boundary tests](../../crates/l2tunnel-client-core/src/secure_udp_config_tests.rs) passed in the [focused receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json). The [new-profile attachment regression](../../crates/l2tunnel-client-core/src/service/tests/secure_udp.rs) passed its [separate source-stable check](../../work/secure-udp-attachment-focused-20261113/attempt-1/validation.json): both appearances and roles reject wrong-layer or readiness-incapable attachments with zero opener calls, retained original-port guards and empty receive queues before network/device work.
- [x] [SUS-04] Run real shared Prepared connect/cancel/disconnect/reconnect with deferred device opening, persistent per-plan server quarantine, actual driver readiness, original deadlines and release-before-publication. Evidence: [paired service/cancellation tests](../../crates/l2tunnel-client-core/src/service/tests/secure_udp.rs), including unchanged admission-owner identity across reconnect, plus [shared accepted-deadline tests](../../crates/l2tunnel-client-core/src/service/tests.rs), passed in the [focused receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json). This proves owner retention and local abort/reconnect, not fresh restart quarantine persistence or automatic retained-state recovery.
- [x] [SUS-05] Expose distinct non-secret requested/effective observations and explicit version2 status/control while preserving legacy version1 bytes and rejecting mismatched versions before actions without fallback. Evidence: [literal legacy schema tests](../../crates/l2tunnel-client-core/src/local/schema/tests.rs), [real private-socket version tests](../../crates/l2tunnel-client-core/src/local/tests.rs), [paired service v1 write rejection and v2 status](../../crates/l2tunnel-client-core/src/service/tests/secure_udp.rs), and [focused passing receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json).
- [ ] [SUS-06] Add explicit CLI selection and manual credential inputs through the same service API; test strict options, invalid combinations and version selection without a private data driver. Partial evidence: [strict selector/profile/short-deadline CLI tests](../../crates/l2tunnel-client-core/src/secure_udp/cli_tests.rs) and [local transport version tests](../../crates/l2tunnel-client-core/src/local/tests.rs) passed in the [focused receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json). Actual binary execution of the external CLI's explicit API-version selector remains separate from these library tests.
- [x] [SUS-07] Exercise actual paired services and readiness-capable PacketDevice attachments over the original UDP sockets for both appearances, exact user/control bytes, negative trust, cancellation, late readiness, status and fresh-session reconnect. Evidence: [actual paired service tests](../../crates/l2tunnel-client-core/src/service/tests/secure_udp.rs) and [runtime control/replay/native tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_tests.rs) passed in the [focused receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json). Native attachments are AF_UNIX fixtures; no TAP or ISP result follows.
- [x] [SUS-08] Integrate the real common authenticated Swift policy controller and truthful capability/terminal status; preserve full cross-profile SW-11 and automatic retained-state recovery as separate uncompleted parent gates. Evidence: [actual service policy/capability/terminal assertions](../../crates/l2tunnel-client-core/src/service/tests/secure_udp.rs), [runtime policy/liveness/failure tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_tests.rs), and [focused passing receipt](../../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json). The completed scope is within-Swift policy composition only.
- [x] [SUS-09] Pass focused checks and the required source-stable aggregate with exact commands, hashes and preserved failures; distinguish service/PacketDevice loopback from actual CLI/TAP namespace, native/platform, security-audit and ISP qualification. Evidence: the [required source-stable aggregate](../../work/secure-udp-runtime-service-20261113/attempt-1/validation.json) passed all local workspace checks with 1487 Rust cases including doctests, 271 Python tooling cases and 1658 simulator cases; formatting, strict workspace Clippy and rustdoc passed, and before/after input hashes match. The separately source-bound attachment rejection also passed. These checks qualify local service/AF_UNIX loopback, not actual CLI/TAP throughput, remote CI or Windows/Android execution.

Actual CLI/TAP acceptance uses fresh owned user/network/mount namespaces and new
receipts. Existing simulator observations and native historical receipts remain
unchanged. Library/service fixtures cannot qualify kernel throughput, remote CI,
Windows/Android execution or ISP/QoS treatment.
