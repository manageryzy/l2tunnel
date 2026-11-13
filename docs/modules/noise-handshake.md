# Maintained Noise handshake adapter proof

Status: **implemented and locally protocol-tested: 13 focused tests passed**.
The passing scope is the reusable primitive and its packet-security composition,
including final-confirmation custody. The required source-stable local aggregate
validation passed under NHS-06. This status does not claim selected-client runtime
or native-platform integration.
This scoped primitive refines SEC-02/SEC-03. It does not implement a complete
WireGuard lifecycle, admission cookie, retransmission service, common management,
automatic recovery, carrier integration or credential migration. No owner choice
of library, provisioning scheme or production wire format is inferred.

## Exact candidate and source review

The implementation candidate is the released `clatter = 2.3.0`, with default
features disabled and only `use-25519`, `use-chacha20poly1305` and `use-sha`.
The downloaded crates.io archive SHA-256 is
`5b16a94521ffa1f8116782dfa8d0aef3c921c3b73f7072f9a5079899eec13b92`.
Its source identifies Rust 1.81 compatibility and MIT dependency licensing;
this does not choose the project's license. The upstream README explicitly
states that the library has not received a formal audit. No upstream fork or
private-state extraction is used by this proof.

Reviewed released-source interfaces:

| Source | Finding and required adaptation |
| --- | --- |
| `src/handshakestate/nq.rs:67-178` | `NqHandshakeCore::new` accepts explicit static and ephemeral keypairs but constructs `RNG::default()` internally. It does not accept a caller RNG instance. |
| `src/handshakestate/nq.rs:263-267` | Internal ephemeral generation occurs only when the supplied ephemeral keypair is absent. The wrapper supplies a fresh caller-randomness-derived ephemeral on every construction. |
| `src/traits.rs:38-50` | The public `Dh` trait permits a narrow adapter. Its `genkey_rng` is made unconditionally unavailable, so missing supplied material fails instead of reaching an OS RNG or zero-key fallback. |
| `src/crypto_impl/x25519.rs:36-42` | The stock wrapper returns the shared result without rejecting noncontributory input. The adapter must call maintained `x25519-dalek` operations and `SharedSecret::was_contributory()` and reject failure for every DH operation, including peer static and ephemeral inputs. |
| `src/traits.rs:334-408` | Handshake methods check direction and buffer capacity, but excessive message length can panic. Fixed patterns, exact expected lengths and fixed local buffers must be checked before invoking them. |
| `src/transportstate.rs:38-50,346-354` | `finalize()` checks handshake completion; the public consuming `TransportState::take()` returns directional cipher states. |
| `src/cipherstate.rs:20-26,140-146` | Cipher states zeroize on drop; public consuming `CipherState::take()` returns owned key material and its nonce. It clones the secret internally before dropping the original. |
| `src/bytearray.rs:48-96`, `src/symmetricstate.rs:14-23` | Sensitive arrays and symmetric state zeroize on drop. Their upstream Debug/Clone implementations are not exposed through the wrapper. |

The `RngCore` trait has infallible methods, so this wrapper does not pretend that
a failing caller RNG can simply be installed as Clatter's default RNG. Instead,
caller entropy is requested explicitly before construction, and the private DH
adapter refuses every attempt at library-owned key generation. Its private
placeholder RNG is unreachable from cryptographic key generation. Clatter's
`getrandom`/`std`/PQ features must remain disabled. Other dependencies can include
OS-entropy support in their dependency graphs; the reusable adapter and packet
protection code do not call it. The exact enabled features and call paths must
be checked separately.

The additional exact `x25519-dalek = 2.0.1` archive SHA-256 is
`c7e468321c81fb07fa7f4c636c3972b9100f0346e5b6a9f2bd0603a52f7ed277`.
Its `src/x25519.rs:290-325` documents and implements the public constant-time
contributory check. The enabled `zeroize` feature installs drop wiping for
`StaticSecret` and `SharedSecret`; this does not prove complete stack erasure.

## Frozen proof API and boundaries

All types live in `l2tunnel-handshake`, independent of Tokio, sockets, real clocks,
OS randomness and platform devices. The fixed cryptographic profiles evaluated
here are `IK_25519_ChaChaPoly_SHA256` and `IKpsk2_25519_ChaChaPoly_SHA256`.
There is no on-wire cipher negotiation, fallback or default profile. Both endpoints
must explicitly select the same proof profile.

- `LocalSecret` owns a supplied zeroizing X25519 private key. It has no Clone,
  Debug or raw-key getter; only its public key may be observed.
- `PeerKey` names the explicitly pinned remote X25519 public key. This is separate
  provisioning from existing Ed25519 membership. Bytes are never converted or
  reinterpreted between key types.
- `Binding` supplies the fresh logical session ID, canonical configuration digest,
  carrier/appearance digest, outer-handshake/ownership binding and existing-member
  credential-binding digest. The wrapper's fixed prologue includes a version,
  profile, both static public keys in global initiator/responder order and all
  those fields. Role reversal, peer, carrier or configuration substitution fails
  authentication. An external binding digest is a caller assertion; it does not
  itself verify a certificate or establish an Ed25519-to-X25519 mapping.
- `Entropy` fills exactly one fresh 32-byte ephemeral secret per construction,
  or returns an explicit error. Runtime callers must use a cryptographic source;
  deterministic providers are confined to tests. The supplied ephemeral must
  never be reused for a new handshake instance.
- `Handshake::new` takes an explicit role/profile, local secret, pinned peer,
  optional owned PSK, binding, supplied time and absolute deadline, plus caller
  entropy. Invalid configuration, expired deadlines, noncontributory
  pinned peers and failed entropy are rejected before emitting a flight.
- `write(now, output)` emits the next typed `FlightKind` and bounded length;
  `read(now, kind, bytes)` admits only the exact expected flight. Protocol errors
  retire the handshake instead of leaving partially mutated state reusable.
  Duplicate exact input is recognized before another crypto call. Cached outgoing
  bytes are available for caller-driven retransmission without fresh encryption,
  new nonces or deadline renewal.
- `finish_with_confirmation(now)` consumes a locally confirmed handshake and
  returns `Established { root: l2tunnel_security::SessionRoot, confirmation:
  ConfirmationCache }`. The cache owns exactly 73 bytes of final ciphertext,
  its original absolute deadline and last accepted supplied time. Its explicit
  `retransmit(now, output)` copies the exact final flight without cryptography,
  key access, nonce use or deadline renewal. A small output changes neither
  cache nor supplied-time state. Expiry/backwards time wipes and retires it;
  drop wipes the owned ciphertext. No automatic response policy is installed.
  An unfinished, failed, expired or consumed handshake cannot release secrets.
- `finish(now)` returns only the root and intentionally drops confirmation custody.
  It is suitable only when the caller retained the exact final flight elsewhere
  or established reliable completion externally. It is not a generally safe UDP
  handoff when the final datagram can be lost.

The typed flight API is not a carrier packet format. A carrier/runtime must bind
and encode the flight kind, preserve message boundaries, implement original
deadline/retry/admission limits, and keep the same connection/socket and tuple.
Those integrations remain SEC-04/SEC-09 work.

## Confirmation and secret ownership

Noise handshake payloads contain no user records. Initiation and response use
empty application payloads; their expected lengths are 96 and 48 bytes for the
fixed patterns. Both endpoints then exchange one fixed encrypted confirmation
using Clatter's public transport API. The confirmation binds the final handshake
hash, logical session ID and sending role; it never carries early user data.
Only after local confirmation emission and verified peer confirmation may
the finish methods release the common packet-security root. Physical send/flush
success and simultaneous distributed readiness remain runtime responsibilities.
In particular, the local final confirmation can be lost while the peer's reaches
us: local completion does not imply peer completion. `finish_with_confirmation`
preserves its exact ciphertext after split-key consumption, allowing a bounded
retry to finish that peer without re-encrypting or retaining handshake keys.
The runtime owns retry scheduling, readiness evidence and the authenticated
gate for replying; the cache never turns unauthenticated input into a response
or grants amplification credit. It expires at the original handshake deadline.

After confirmation, consume `TransportState::take()` exactly once, then consume
each directional `CipherState::take()`. Transfer owned zeroizing 32-byte keys in
global initiator-to-responder/responder-to-initiator order to:

```rust
l2tunnel_security::SessionRoot::from_split_keys(
    initiator_to_responder,
    responder_to_initiator,
    l2tunnel_security::SessionBinding { session, transcript },
    role,
)
```

The security crate owns all purpose/direction/lane derivation and packet protection.
The wrapper never reuses the original Clatter transport, never derives secrets
from the public handshake hash, and never duplicates an exporter/KDF schedule.
The transcript is public binding context, not secret key material. Existing Swift
AEAD, other record profiles and the separately required MAC-only profile retain
their acceptance requirements; this primitive alone implements none of them.

Owned private keys, ephemerals, PSKs and transferred roots use zeroizing storage.
Drop/expiry/failure must retire live crypto state. This is a logical ownership
guarantee, not proof of erasure of all upstream stack/register copies. In particular,
the released PSK queue contains plain arrays; its copy/retirement behavior must be
recorded honestly, and PSK lifetime qualification remains a security-review gate.

## Acceptance ledger

- [x] [NHS-01] Review and freeze this API, exact released candidate checksum, supported public ownership APIs, RNG limitation and noncontributory-DH adaptation before implementation. Evidence: the exact-source review and frozen API above, [public consuming handoff](../../crates/l2tunnel-handshake/src/lib.rs), and [narrow public DH adaptation](../../crates/l2tunnel-handshake/src/crypto.rs). This is implementation review, not an owner selection of a production library or an independent security audit.
- [x] [NHS-02] Implement bounded fixed-pattern handshake and explicit confirmation with caller entropy/time, no OS fallback, no early data, owned secret transfer and no private-state extraction. Evidence: [implementation](../../crates/l2tunnel-handshake/src/lib.rs), `confirmed_public_split_handoff_opens_opaque_packet_bytes_in_both_modes` and `unfinished_handshakes_never_release_packet_roots` in the [passing focused suite](../../crates/l2tunnel-handshake/src/tests.rs). This proves the primitive boundary, not a complete session lifecycle.
- [x] [NHS-03] Test wrong pinned peer, reflected role, carrier/configuration/session/member/outer binding mismatch and missing/wrong PSK, with no root release after failure. Evidence: `own_peer_prologue_binding_and_role_mismatches_fail_before_roots`, `psk_selection_is_explicit_and_wrong_secret_cannot_complete` and `unfinished_handshakes_never_release_packet_roots` in the [passing focused suite](../../crates/l2tunnel-handshake/src/tests.rs). Caller-supplied binding digests do not verify provisioning or migrate existing member credentials.
- [x] [NHS-04] Test all-zero/low-order static and ephemeral inputs, every flight truncation/oversize, unexpected kinds, duplicate/conflicting flights, deadline edges and failed caller entropy without panic or renewed deadlines. Evidence: `low_order_static_and_ephemeral_inputs_fail_contributory_check`, `fixed_lengths_reject_every_truncation_and_oversize_before_crypto`, `unexpected_kinds_and_authenticated_wrong_confirmation_retire_state`, `duplicates_retransmit_exact_bytes_without_nonce_use_or_new_entropy` and `output_preflight_entropy_failure_and_absolute_deadline_are_nonrenewing` in the [passing focused suite](../../crates/l2tunnel-handshake/src/tests.rs). These are finite parser/state-machine cases, not exhaustive fuzzing or an audit.
- [x] [NHS-05] Verify deterministic caller entropy consumption, fail-closed missing explicit ephemeral, zeroizing owned material and opaque non-Clone secret handoff into actual packet-security owners. Evidence: `output_preflight_entropy_failure_and_absolute_deadline_are_nonrenewing`, `absent_explicit_ephemeral_fails_without_consulting_any_rng`, `owned_key_and_psk_fields_use_maintained_zeroizing_storage` and `confirmed_public_split_handoff_opens_opaque_packet_bytes_in_both_modes` in the [passing focused suite](../../crates/l2tunnel-handshake/src/tests.rs), plus private non-Clone owners in the [implementation](../../crates/l2tunnel-handshake/src/lib.rs). Owned-storage wiping does not qualify upstream PSK copies or complete stack/register erasure.
- [x] [NHS-06] Run parent-serialized formatting, focused tests/lints/docs and required aggregate checks; record exact commands/source hashes and keep runtime/native/platform/complete-WireGuard claims separate. Evidence: [source-stable parent aggregate](../../work/shared-session-primitives-20261113/validation.json) includes all 13 handshake tests, formatting and warning-denied Clippy/rustdoc; the master ledger links the separate post-check prose reconciliation.
- [x] [NHS-07] Preserve final-confirmation ciphertext custody across root release; qualify asymmetric final loss for either role, exact cached retry completing the peer, duplicate admission, unchanged deadlines, undersized output, backwards time and expiry wiping without re-encryption or automatic unauthenticated replies. Evidence: `final_confirmation_custody_survives_asymmetric_loss_and_root_release` covers both roles and both profiles followed by protected management bytes, and `final_confirmation_cache_capacity_deadline_and_time_are_nonrenewing` covers cache failure/retirement, in the [passing focused suite](../../crates/l2tunnel-handshake/src/tests.rs). The [cache implementation](../../crates/l2tunnel-handshake/src/lib.rs) has no key, crypto call or automatic responder; runtime admission/amplification policy remains separate.

The parent reports 13 passing local Linux handshake tests for this source,
including actual AEAD and authenticated-cleartext packet-security composition.
The parent-generated [aggregate validation receipt](../../work/shared-session-primitives-20261113/validation.json)
records exact commands and source binding for those tests. The narrower focused
facade/control receipt does not claim to run the handshake unit suite.
No Windows/Android build, privileged device,
carrier deployment or independent security audit is established by these tests.
Upstream PSK-copy lifetime/security qualification remains explicitly open.
These subordinate completions do not close SEC-*, SW-11 or any P-* gate.

## Primary sources

- [Released crate source](https://docs.rs/crate/clatter/2.3.0/source/)
- [Public transport ownership API](https://docs.rs/clatter/2.3.0/clatter/transportstate/struct.TransportState.html)
- [Public cipher-state ownership API](https://docs.rs/clatter/2.3.0/clatter/cipherstate/struct.CipherState.html)
- [Exact upstream tag](https://github.com/jmlepisto/clatter/tree/clatter-v2.3.0)
- [Noise protocol framework](https://noiseprotocol.org/noise.html)

Source inspection and deterministic proof tests do not replace an independent
security audit, complete lifecycle qualification or a real carrier deployment.
