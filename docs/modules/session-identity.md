# Reusable member identity and Noise-session binding

Status: **implemented and locally protocol-tested: 8 identity and 16 retained-auth
tests passed**. Strict package Clippy/rustdoc and the required frozen-source aggregate passed.
Same-socket member integration has finite local evidence; restarted-peer,
service/native and broader carrier qualification remain pending. The design
and API below were recorded and reviewed before code. This scoped FIX-13/SEC-03
primitive extracts existing Ed25519 membership operations and adds an explicit
proof of possession for the shared Noise session. It does not select a production
dependency/provisioning policy, replace existing credentials, enable a carrier,
or complete the common-session/client/service/native lifecycle.

## Existing implementation and compatibility boundary

The retained [auth adapter](../../crates/l2tunnel-auth/src/lib.rs) delegates ring
Ed25519 key parsing, public member identity, bounded deduplicated allowlist and
signature operations to the pure identity crate. Its Tokio TLS exchange signs
an exporter-bound transcript; the [HTTPS request helper](../../crates/l2tunnel-auth/src/https_request.rs)
also signs its existing bounded request transcript. Generation uses OS randomness
inside that runtime adapter. Existing clients authenticate the server through
verified TLS roots/name; the server authenticates allowlisted client membership.

The pure `l2tunnel-identity` crate owns the maintained Ed25519 key/parser,
public identity, allowlist and sign/verify helpers. The parent retains the auth
adapter's public `MemberKey::generate_pkcs8`, `from_pkcs8` and `public_key`
signatures/error types through a delegating wrapper and reexports the one public
member-key type. OS generation stays in the runtime adapter. Existing TLS/member
and HTTPS request transcript bytes, domains, proof formats and trust checks stay
unchanged; callers delegate signing/verification rather than wrapping a second
private crypto implementation. This extraction does not implement configurable
SNI or a certificate-pin verifier.

## Frozen implementation-draft API

```rust,ignore
MemberPublicKey(pub [u8; 32])
IdentityKey::from_pkcs8(encoded: &[u8]) -> Result<IdentityKey, Error>
IdentityKey::public_key(&self) -> MemberPublicKey
IdentityKey::sign(&self, transcript: &[u8]) -> Result<[u8; 64], Error>
verify_signature(member: MemberPublicKey, transcript: &[u8], signature: &[u8])
    -> Result<(), Error>
Allowlist::new(members: &[MemberPublicKey]) -> Result<Allowlist, Error>
Allowlist::contains(&self, member: MemberPublicKey) -> bool

NoisePublicKey(pub [u8; 32])
Context { session: security::SessionId, transcript: [u8; 32],
          configuration: [u8; 32], carrier: [u8; 32], outer: [u8; 32],
          initiator_noise: NoisePublicKey, responder_noise: NoisePublicKey }
MemberProof::sign(member: &IdentityKey, context: Context) -> Result<MemberProof, Error>
MemberProof::from_bytes(bytes: &[u8]) -> Result<MemberProof, Error>
MemberProof::as_bytes(&self) -> &[u8; 98]
verify_member(proof: &[u8], context: Context, members: &Allowlist)
    -> Result<MemberPublicKey, Error>

Time(pub u64) // caller-supplied monotonic microseconds
ServerPending::new(root: security::SessionRoot, context: Context,
                   members: Allowlist, now: Time, deadline: Time)
    -> Result<ServerPending, Error>
ServerPending::deadline(&self) -> Time
ServerPending::accept(self, now: Time, proof: &[u8])
    -> Result<AuthenticatedMember, Error>
AuthenticatedMember { pub root: security::SessionRoot, pub member: MemberPublicKey }
```

The PKCS#8 ceiling remains 4096 bytes, and the generic transcript ceiling is
16,384 bytes, comfortably covering current bounded TLS and HTTPS transcripts.
Signature verification requires exactly 64 bytes. No key owner implements Clone,
Debug, private-key getters or generation. Parsing retains only ring's maintained
key object; callers retain responsibility for their borrowed PKCS#8 buffers.
The crate owns no Tokio, clock, RNG, socket, privilege, device or unsafe code.
It does not claim complete erasure of ring's internal secret/stack copies.

`NoisePublicKey` is explicitly distinct from `MemberPublicKey`. It contains only
X25519 public identity supplied by the authenticated handshake/configuration;
the identity crate performs no DH, private-key conversion or Ed25519-to-X25519
reinterpretation. The local/server trust policy must pin the responder Noise
public key from our own trusted configuration before starting Noise. A peer's
advertised key, SNI/cover name or signed self-assertion cannot establish that pin.
The responder also uses its explicitly provisioned initiator Noise pin. This
draft keeps the existing client Ed25519 membership requirement without inventing
a new server Ed25519 identity, account system or enrollment workflow.

## Proof and release contract

The new fixed 98-byte proof is `[version=1][role=initiator][member public 32]
[Ed25519 signature 64]`. It signs the new domain
`l2tunnel/member-noise-binding/v1\0`, its complete 34-byte prefix and the fixed
global-order context: session ID, final Noise transcript, configuration, carrier,
outer binding, initiator Noise key and responder Noise key. Fixed field sizes
avoid ambiguous concatenation. Only the initiator/client membership role is
accepted. This proof is distinct from every retained TLS/HTTPS proof domain.
There is no peer-selected cipher, role, fallback, identity conversion or early
user-data payload in this message.

The final Noise transcript is public authenticated context, not a secret MAC
key. Ed25519 signing proves possession of the existing member private key over
that exact session and both pinned Noise identities. Verification checks the
locally selected context and allowlist, not a peer-supplied replacement context.
The existing pre-Noise `Binding.member` digest remains a policy/prologue input;
its presence is not a membership proof and cannot replace this signature.
Fresh session/transcript selection and trusted pin provisioning remain caller
and maintained-handshake responsibilities.

`ServerPending` consumes the opaque root, requires its supported public
`root.role()` to be Responder, and compares `root.binding()` against the supplied
session/final transcript. It retains the
root, immutable context/allowlist, original deadline and supplied monotonic time.
Only an unexpired, correctly signed, allowlisted proof can consume that gate and
release `AuthenticatedMember`; malformed/signature/context/identity/time failures
consume the pending owner and drop the root. No data or root getter exists while
the gate is pending. This is one admission attempt, not a replay/liveness service.

The parent controller first reserves separate AEAD `Purpose::Joining` send and
receive owners from that root. They remain available while the root is inside
the membership gate. The same selected carrier carries the protected proof and
an authenticated server acceptance. Unauthenticated/malformed outer packets are
rejected before being submitted as an actual membership attempt. The client
retains root custody and releases no user data until verified server acceptance;
the server retains exact acceptance ciphertext for bounded retry after release.
Those controller/ciphertext-custody/reliability mechanisms are parent integration
work, not an invented second state machine inside this identity crate. Existing
management, user-data domains, epoch/counter ownership and record profiles remain
intact. Noise key confirmation alone does not report membership acceptance.

## Acceptance ledger

- [x] [SID-01] Record/review the pure extraction, legacy compatibility, fixed proof/context, own-server trust and root-custody API before code, without attributing dependency/provisioning choices to the owner. Evidence: this [API and trust design](session-identity.md#frozen-implementation-draft-api) preceded the [implementation](../../crates/l2tunnel-identity/src/lib.rs), with parent implementation review. Production provisioning/library qualification is not implied.
- [x] [SID-02] Extract one maintained Ed25519 key/parser/public identity/sign/verify implementation and bounded deduplicated allowlist, with no runtime dependency, OS-randomness call/provider requirement or public secret getter. Evidence: the [pure implementation](../../crates/l2tunnel-identity/src/lib.rs), parent [auth wrappers](../../crates/l2tunnel-auth/src/lib.rs) and [passing focused receipt](../../work/session-identity-20261113/r2/validation.json). Ring's transitive entropy-support dependencies remain present; the parsing/signing/verification paths do not call them.
- [x] [SID-03] Implement the fixed domain-separated client proof, strict lengths/version/role, both pinned Noise identities and every session/transcript/carrier/configuration/outer binding, using maintained Ed25519 operations. Evidence: [proof/context implementation](../../crates/l2tunnel-identity/src/lib.rs) and `fixed_member_proof_is_deterministic_and_rejects_every_context_substitution` plus `proof_parser_and_possession_reject_wrong_roles_members_and_signatures` in the [passing identity tests](../../crates/l2tunnel-identity/src/tests.rs).
- [x] [SID-04] Hold the actual opaque root behind a single-use membership gate, require the responder root role, check its public authenticated binding and original monotonic deadline, and release it only after actual allowlisted signature possession succeeds. Evidence: [ServerPending implementation](../../crates/l2tunnel-identity/src/lib.rs), `pending_root_checks_binding_and_original_deadline_without_data_release` and `protected_joining_works_while_gate_holds_root_and_owners_survive_release` in the [passing identity tests](../../crates/l2tunnel-identity/src/tests.rs). The latter reserves real AEAD Joining owners before root custody and proves ownership reservations survive admission.
- [x] [SID-05] Test fixed known-key signatures, malformed PKCS#8/lengths, signature/transcript bounds, allowlist limits/dedup, wrong key/signature/role/version and every context substitution, with no root release on failure. Evidence: all 8 [focused identity tests](../../crates/l2tunnel-identity/src/tests.rs) passed in the [source-bound local receipt](../../work/session-identity-20261113/r2/validation.json). These are finite protocol cases, not an independent security audit or exhaustive fuzzing.
- [x] [SID-06] Preserve original auth public APIs/wire and HTTPS request proof bytes through parent delegating wrappers; run existing TLS/QUIC/OpenVPN-like/HTTPS negative and loopback checks without bypassing trust. Evidence: the [delegating auth adapter](../../crates/l2tunnel-auth/src/lib.rs), [HTTPS helper](../../crates/l2tunnel-auth/src/https_request.rs), direct-ring legacy-domain parity and retained auth/QUIC/HTTPS/OpenVPN-like negative/loopback tests passed under the [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json). Existing wire/trust behavior is preserved; this does not qualify a native carrier or provisioning migration.
- [ ] [SID-07] Integrate same-carrier protected Joining proof/acceptance, client/server root custody, exact final-acceptance retry, duplicate/late/lost/restarted-peer behavior and original deadlines before user release. Partial evidence: actual [member runtime tests](../../crates/l2tunnel-runtime/src/secure_udp/member_tests.rs) and [factory composition](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) cover protected proof/acceptance, exact final acceptance recovery, custody and deadlines. Restarted-peer lifecycle reconciliation/rejection is not yet exercised.
- [x] [SID-08] Run focused tests, formatting, warning-denied lints/docs and source-bound required aggregate checks, keeping finite protocol/loopback evidence separate from native/platform/security-audit qualification. Evidence: the [identity/auth package receipt](../../work/session-identity-20261113/r2/validation.json) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json) record actual checks, stable inputs and retained failures. Only local Linux protocol/loopback scope is qualified.

The existing [common-session SEC-* gates](secure-session.md) and FIX-13 remain
open beyond these subordinate deliverables. No carrier, SW-11, native/platform,
automatic-recovery or full mode-parity requirement is removed by this extraction.

The [focused regression source](../../crates/l2tunnel-identity/src/tests.rs) uses
the published keys/signature from [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1)
and PKCS#8 v2 public/private consistency checks through ring. Other cases cover
generic transcript/signature/allowlist bounds, every proof truncation, wrong
member/signature/version/role, each context substitution, root-binding/deadline
failure and protected Joining while the membership gate holds the root. The
parent owns the compatibility wrappers and full controller/carrier integrations.

## Focused local validation

The serialized r2 batch ran and passed:

```sh
cargo fmt --package l2tunnel-identity --package l2tunnel-auth
cargo test --offline --locked --package l2tunnel-identity
cargo test --offline --locked --package l2tunnel-auth
cargo clippy --offline --locked --package l2tunnel-identity --package l2tunnel-auth --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --offline --locked --package l2tunnel-identity --package l2tunnel-auth --no-deps
```

The [r2 receipt](../../work/session-identity-20261113/r2/validation.json) records
8 identity and 16 auth cases, commands/logs, and before/after hashes for explicitly
scoped identity/auth/security and local dependency inputs plus workspace manifests
and formatting configuration. Those inputs were unchanged during the checks.
Unrelated runtime/Swift/module edits are not represented as validated by this
receipt. Auth's local TLS and lossy-UDP fixtures retain their named scope; they
do not qualify the new common-session controller or native platforms.

The [first failed receipt](../../work/session-identity-20261113/validation.json)
is preserved. Its added parity test incorrectly asserted that the maximal HTTPS
transcript exceeded 1024 bytes; the actual current canonical transcript is exactly
1000 bytes. The test was corrected, the explicit responder-root role check was
added, and the complete fresh r2 batch above passed. No failed observation or
historical experiment was overwritten. The subsequent source-stable required
aggregate and retained SID-06 carrier checks passed locally. SID-07 restarted-peer
lifecycle and upstream security/audit qualification remain open.
