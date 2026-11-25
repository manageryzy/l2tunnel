# Reusable packet protection

Status: **implemented and locally contract-tested** for `l2tunnel-security`, with
Swift compatibility consumed by the runtime. The parent executed 11 security,
13 handshake-adapter and 16 Swift runtime tests successfully in this change.
The parent-owned [aggregate validation receipt](../../work/shared-session-primitives-20261113/validation.json)
records the complete passing test commands, source identity and results.
The narrower [focused receipt](../../work/shared-session-primitives-20261113/focused-validation.json)
records facade/control tests and workspace Clippy; it is not the command receipt
for the security or handshake unit suites. Post-check ledger prose is qualified
by the separate evidence-only reconciliation linked from the master ledger.
The common version/suite/framing choices remain an implementation draft, not a
new owner-approved wire or handshake decision. This is a packet primitive beneath
data algorithms, not a carrier, reliable control service or completed SEC-05/SEC-06.
The [common session contract](secure-session.md) retains those broader gates.

## Explicit compact v3 extension

The 2026-11-16 additive `security::compact` owners implement the explicitly
selected AES-128-CCM-4 and ChaCha20/CRC32C data profiles using maintained
RustCrypto providers. Strong feedback and management use ring
ChaCha20-Poly1305. CRC is an unkeyed corruption check, not authentication;
four-byte suites cannot obtain management or recovery-control purpose owners.
The original v1 and Swift v2 APIs and bytes described below remain unchanged.

Only the low four bytes of the packet number travel in the security prefix.
The full u64 number remains the nonce identity, with bounded reconstruction,
the existing replay window and adjacent-generation machinery. Complete domain,
suite, negotiated limits and metadata remain in the key/AAD context. Explicit
forward-gap and lifetime failed-check limits do not reset on success or epoch
switch and add no clock or fresh-DH exchange. Short CCM tags retain their actual
32-bit authentication strength. Domain reservation excludes a second legacy or
compact owner for the same purpose/direction/lane.

The current 26-case security suite includes maintained-provider known-answer,
full-counter wrap/reorder, replay, context separation, failure-budget and legacy
byte regressions. Runtime/service evidence and exact outer costs are separately
qualified in the [compact implementation checkpoint](compact-wire-cleanup.md#evidence-and-remaining-work).

## Boundary and ownership

The integration exposes `SessionRoot::binding(&self) -> SessionBinding`
and `SessionRoot::role(&self) -> Role`.
It copies only the already authenticated public session ID and final handshake
hash, enabling existing-member signatures after the supported root handoff.
It returns no key, nonce owner or provider-private state. Callers must never use
this public value as a secret authentication key. The getter neither creates
packet domains nor mutates counters, replay, roles or secret ownership.
The role observation lets consuming membership gates reject a root for the
wrong endpoint role before releasing user-data ownership.

The crate owns ring-based ChaCha20-Poly1305/HMAC-SHA256, standard HKDF, a bounded
replay window and adjacent key generations. It accepts opaque record bytes and
authenticated context, writes into caller-owned buffers and returns explicit
errors. It has no Tokio, real clock, socket, device, privilege, unsafe block,
logging or public secret getter. Secret owners are neither `Clone` nor `Debug`;
owned root/chain byte arrays use `zeroize::Zeroizing`.

The handshake adapter consumes its maintained library's supported split-key
output once. It does not reuse that original transport with the same keys.
The public handoff is:

```rust,ignore
SessionRoot::from_split_keys(
    initiator_to_responder: Zeroizing<[u8; 32]>,
    responder_to_initiator: Zeroizing<[u8; 32]>,
    binding: SessionBinding { session: SessionId([u8; 16]), transcript: [u8; 32] },
    role: Role,
) -> Result<SessionRoot, Error>

SessionRoot::sender(&mut self, purpose: Purpose, lane: LaneId,
                    limits: Limits, protection: Protection) -> Result<Sender, Error>
SessionRoot::receiver(&mut self, purpose: Purpose, lane: LaneId,
                      limits: Limits, protection: Protection) -> Result<Receiver, Error>
```

`Role::{Initiator, Responder}` determines global `Direction`; `Purpose` separates
data, management, joining and recovery-control domains. The session binding's
transcript is public authenticated context, not a secret key. HKDF-Extract combines
the two consumed split keys in the fixed global order, using the canonical
session/transcript binding as salt; HKDF-Expand derives a private session root.
Canonical version, suite, purpose, direction, lane and session binding separate
every packet root. A fixed maximum of 64 sender/receiver domain owners per root
prevents unbounded derivation. A second owner for the same purpose/direction/lane
is refused even if the requested suite differs, preventing an accidental packet
counter or replay-window reset under a reused domain.

## Common packet API and draft framing

```rust,ignore
Sender::next_number(&self) -> PacketNumber
Sender::seal(&mut self, metadata: Metadata<'_>, plaintext: &[u8],
             output: &mut [u8]) -> Result<Sealed, Error>
Receiver::open(&mut self, metadata: Metadata<'_>, packet: &[u8],
               output: &mut [u8]) -> Result<Opened, Error>
```

`Metadata` contains typed `Epoch`, `ConfigDigest` and at most 256 bytes of
additional carrier/header context. The draft common packet prefix is
`[version u8 = 1][suite u8][packet number u64]`, followed by ciphertext and a
16-byte tag for AEAD, or visible payload and the full 32-byte HMAC-SHA256 tag.
The selected suite is fixed by the authenticated configuration; header bits do
not authorize switching or downgrade. Purpose, direction, lane and session are
fixed per owner, rather than repeated in every record. The canonical domain,
prefix, epoch, digest and length-delimited extra context are all authenticated.
An outer staged reader must provide the intended metadata; this primitive does
not negotiate epochs or choose active/draining data readers.

`COMMON_PREFIX_BYTES = 10` and `Protection::overhead_bytes()` expose exact
common overhead (26 AEAD, 42 HMAC bytes), excluding outer framing. Carrier glue
must checked-add its routing/header bytes and prevalidate the path/output budget
before calling `seal`; a rejected outer frame must not consume a packet number.

The common AEAD nonce is four zero bytes followed by the unique 64-bit packet
number; domain-separated keys prevent cross-purpose/direction/lane nonce reuse.
Packet numbers never wrap and are not reset by key ratchets or profile changes.
Packets use at most 65,000 body bytes and the complete protected packet is
checked against the 65,507-byte ceiling before allocation or cryptographic work.
The carrier owner additionally enforces its exact path MTU and framing budget.
`Limits` bounds body length, per-generation
packet use (at most 2^28) and per-generation body bytes (at most 2^40).
Zero/inconsistent limits, oversized metadata, truncation, caller capacity,
counter exhaustion, skipped generations and authentication failures are explicit
errors. `open` requires body-plus-tag workspace in its caller output buffer;
returned plaintext length excludes the tag. Failed AEAD output is cleared.
HMAC verification uses `ring::hmac::verify` and a bounded preallocated
body-plus-metadata workspace; this path does not claim zero-copy verification.

Validation errors do not consume a nonce. A cryptographic seal attempt consumes
its reserved packet number even if the maintained primitive reports failure;
receivers commit packet/replay/key-generation state only after authentication.
A 4096-packet replay window accepts bounded reordering without packet duplication.
Only current, previous and one adjacent candidate generation are retained. A
forged next-generation packet cannot adopt it; a claimed jump beyond the adjacent
generation is rejected before derivation. Previous keys retire once the replay
window no longer reaches them. Byte-use accounting is bounded across retained
generations. Ratcheting is deterministic HKDF, not a fresh authenticated exchange,
time-based expiry, post-compromise recovery or complete rekey protocol.

## Explicit Swift v2 compatibility

`swift_v2::Sender::new` and `swift_v2::Receiver::new` accept an existing directional
TLS exporter secret, a body bound and an authenticated packets-per-generation
interval. The runtime supplies its unchanged `KEY_PACKETS = 2^28`; smaller
intervals are finite-test configurations, not a new CLI setting. Compatibility
owners always use ChaCha20-Poly1305, the existing empty AAD and wire bytes
`[packet number u64][ciphertext][tag 16]`, with exactly 24 protection bytes.
They retain the 4096-packet replay window and the existing HKDF labels:

- `l2tunnel swift v2 datagram key`
- `l2tunnel swift v2 next secret`

Compatibility does not impose the common format's additional early body-byte
cutoff; changing that limit would alter existing large-MTU session behavior.

The compatibility API has no MAC-only switch and accepts no new metadata that
would silently change Swift v2 authentication. It shares the implementation's
bounded replay/key machinery while keeping its legacy KDF and framing explicit.
It does not claim the new common session binding or handshake. Existing saved
receipts remain evidence for their original code. The focused byte-exact vectors
and runtime regressions passed for this extraction; they do not requalify the
historical privileged or real-network experiments against the new source.

The checked-in regression source includes three fixed compatibility vectors for
root byte `9` repeated 32 times and body `00 01 02 00 ff`, at packet numbers
0, 1 and 2^28. They were independently calculated with the installed Python
`cryptography` ChaCha20Poly1305 and standard-library HMAC-SHA256 HKDF-Expand,
using the legacy labels and empty AAD. The executed regressions also cover
metadata, all typed domains, wrong suite/binding, limits, replay, adjacent
generations, retirement and the no-new-byte-cutoff compatibility rule. The Swift
runtime regressions include protected transfer, loss/reordering, ratchets,
transaction switches and original-deadline failure handling. Their finite Linux
loopback/injected-clock evidence does not establish Windows/Android support,
native-device forwarding, full shared-session lifecycle or ISP/QoS behavior.

## Acceptance tasks

- [x] [PKS-01] Implement the pure secret/root, typed domain, bounded ownership and caller-buffer APIs described above, with explicit errors and no secret export, OS or runtime dependencies. Evidence: [crate boundary and errors](../../crates/l2tunnel-security/src/lib.rs), [root/domain ownership](../../crates/l2tunnel-security/src/context.rs), and the passing bounded-owner/domain tests in [security regressions](../../crates/l2tunnel-security/src/tests.rs).
- [x] [PKS-02] Implement common versioned AEAD and authenticated-cleartext/HMAC records, canonical metadata authentication, independent key domains and checked length/capacity/counter/use bounds. Evidence: [seal/open implementation](../../crates/l2tunnel-security/src/record.rs), [maintained key construction](../../crates/l2tunnel-security/src/keys.rs), and passing suite/metadata/domain/limit tests in [security regressions](../../crates/l2tunnel-security/src/tests.rs).
- [x] [PKS-03] Extract bounded replay and adjacent HKDF ratchet/retirement behavior; reject forged or skipped generations without adopting keys or consuming receive credit. Evidence: [4096-packet replay implementation/test](../../crates/l2tunnel-security/src/replay.rs), [adjacent key ownership](../../crates/l2tunnel-security/src/keys.rs), and passing forged-skip, reordering and retirement tests in [security regressions](../../crates/l2tunnel-security/src/tests.rs).
- [x] [PKS-04] Freeze Swift v2 compatibility vectors against the prior ring construction, including zero/nonzero payloads, packet-number boundaries, old/next generations and exact 24-byte overhead; preserve mandatory AEAD and the two existing labels. Evidence: [explicit compatibility API](../../crates/l2tunnel-security/src/swift_v2.rs), passing independent frozen-vector and counter-boundary tests in [record tests](../../crates/l2tunnel-security/src/record.rs), and passing ratchet/reordering tests in [security regressions](../../crates/l2tunnel-security/src/tests.rs). The frozen payload contains both zero and nonzero bytes; compatibility still rejects an empty body.
- [x] [PKS-05] Consume the compatibility owners from the selected Swift runtime and remove its duplicate replay, nonce, chain and opening implementations without changing the original transaction-deadline fix, record protocol or configured interval. Evidence: [runtime integration and its 16 passing regressions (retired in Common cutover)](compact-wire-cleanup.md), including loopback transfer, negotiated internal-policy changes, ratchets and original-deadline/blocked-terminal-write failures. This remains the existing Swift v2 TLS-bootstrap plus separate-UDP runtime, not the target shared carrier/session path.
- [x] [PKS-06] Run focused parser, metadata/domain/suite mismatch, wrong key, replay, reordering, truncation, buffer, counter/use exhaustion and ratchet failure tests plus runtime Swift transfer/switch regressions; record exact source-bound local checks and remaining platform/native limits. Evidence: 11 security and 16 Swift runtime tests passed, including in the parent's [source-stable aggregate run](../../work/shared-session-primitives-20261113/validation.json); see [security tests](../../crates/l2tunnel-security/src/tests.rs), [record boundary tests](../../crates/l2tunnel-security/src/record.rs) and [runtime tests (retired in Common cutover)](compact-wire-cleanup.md). This is local Linux evidence, not a privileged, cross-platform or real-device pass.
- [x] [PKS-07] Integrate supported maintained handshake split-key ownership through `SessionRoot`; qualify wrong role/session/transcript binding and duplicate-owner refusal before any shared-session data release. An isolated packet test does not complete SEC-02 or SEC-03. Evidence: [consuming maintained split-key handoff](../../crates/l2tunnel-handshake/src/lib.rs), 13 passing [handshake regressions](../../crates/l2tunnel-handshake/src/tests.rs), and passing wrong-role/session/transcript and duplicate-owner tests in [security regressions](../../crates/l2tunnel-security/src/tests.rs). The adapter tests exercise both IK/IKpsk2, both packet protections, reverse management and bounded final-confirmation custody; dependency audit/secret-erasure and broader session/runtime gates remain separate in [the handshake module](noise-handshake.md).
- [ ] [PKS-08] Qualify complete shared-session/carrier lifecycle, time expiry, authenticated fresh exchange, management and SW-11/profile switching separately under SEC-05/SEC-06 and the parent ledgers. Packet extraction alone cannot check those gates.
- [x] [PKS-09] Expose only the public authenticated binding after supported handshake root transfer and exercise it in the real same-carrier existing-member proof, with no secret export, private-state extraction or owner/counter reset. Evidence: the public [root observations](../../crates/l2tunnel-security/src/context.rs), actual [member custody](../../crates/l2tunnel-runtime/src/secure_udp/member.rs) and [real factory fixture](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) passed in the [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json). No private key material is exposed; Info also retains the exact public authenticated Noise prologue.

These are new subordinate deliverables. All original mode, AEAD-or-MAC, carrier,
platform, bounded recovery and SW-11 requirements remain in scope.
