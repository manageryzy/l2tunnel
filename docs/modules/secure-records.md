# Pure record protection and cover composition

Status: **implemented, protocol-tested and finite local UDP composition-tested**,
2026-11-13. The initial 41-byte draft passed its original 15-test run; the revised
nine-byte route passed a fresh source-stable 17-test run. Both designs
were written before their implementation changes, and the public API was
accepted in parent implementation review. This module composes the existing
[packet protection](packet-security.md) and [appearance codecs](carrier-appearance.md)
under the [common session contract](secure-session.md). It does not complete the
handshake, negotiation, client/service API, native forwarding or mode-switch gates.

## Explicit compact extension

The 2026-11-16 additive `Records::new_compact` path has six purpose-separated
owners: Data, Feedback and Control in each direction. Its final packet is
`[kind/reader: 1][low packet number: 4][algorithm body][check: 4 or 16]`.
Data costs 9 outer bytes; strong feedback and management cost 21. Initial
appearance is not repeated on this selected established UDP path. Algorithm
metadata, packing and base IP/UDP/TCP bytes are additional costs.

Full scope/configuration remain local protection context. Registered reader
slots follow the same stage/activate/retire lifecycle without resetting packet
or replay owners. `Opened` explicitly reports `feedback` and `authenticated`;
CRC data grants no control, retiring-feedback or authenticated liveness rights.
`capacity_for` reports the exact selected kind cost, while `capacity` conservatively
uses the strong cost. `seal_compact_arq_in` consumes the actual borrowed algorithm
union directly without a legacy recovery or Reliable envelope.

The 23-case final-record suite includes both selected data profiles, exact sizes,
scope-slot reuse, failed-output custody and a real-UDP CompactARQ composition.
The [compact checkpoint](compact-wire-cleanup.md#selected-compact-implementation-checkpoint)
separately records genuine Swift UDP establishment and shared-service evidence.
Other algorithm/runtime and raw TCP migration gates remain open. The ownership,
API excerpt and framing descriptions below document the preserved legacy route.

## Scope and ownership

`l2tunnel::secure_record::Records` consumes one authenticated `SessionRoot` and
owns four maintained packet-security domain owners: data sender/receiver and
management sender/receiver on one physical lane. They separate user and control
keys, directions, packet counters and replay state. The component retains no
root secret getter and never creates fresh owners during a data-scope change.
The session root's original handshake split-key transport must already have been
consumed exactly once under the packet-security contract.

There is one fixed control `Scope`, one active data `Scope`, and at most one
additional data reader. That reader is either staged or draining. Scope changes
alter authenticated metadata, never the data sender or receiver: counters,
ratchets and replay accounting continue across epochs. The immutable security
limits, protection selection and cover configuration apply to all four owners.
The API uses caller-owned bounded buffers, with no allocation per packet, socket,
real clock, randomness, privilege, device or unsafe code in this composition.
Packet-security construction may preallocate its already documented bounded MAC
workspace and domain registry.

## Frozen public API

```rust,ignore
Class::{User, Control}
Scope { epoch: security::Epoch, configuration: security::ConfigDigest }
ReaderState::{Staged, Draining}
DataReader { scope: Scope, state: ReaderState }
Capacity { plaintext_bytes: usize, seal_workspace_bytes: usize,
           open_workspace_bytes: usize, packet_bytes: usize }
Sealed { number: security::PacketNumber, bytes: usize }
Opened { class: Class, scope: Scope, number: security::PacketNumber,
         generation: security::KeyGeneration, bytes: usize }

Records::new(root: security::SessionRoot, lane: security::LaneId,
             limits: security::Limits, protection: security::Protection,
             cover: cover::Config, control: Scope, data: Scope)
    -> Result<Records, Error>
Records::capacity(&self, plaintext_bytes: usize) -> Result<Capacity, Error>
Records::next_number(&self, class: Class) -> security::PacketNumber
Records::control_scope(&self) -> Scope
Records::active_data(&self) -> Scope
Records::additional_data(&self) -> Option<DataReader>
Records::stage_data(&mut self, next: Scope) -> Result<(), Error>
Records::cancel_staged_data(&mut self, next: Scope) -> Result<(), Error>
Records::activate_data(&mut self, next: Scope) -> Result<(), Error>
Records::retire_data(&mut self, old: Scope) -> Result<(), Error>
Records::seal(&mut self, class: Class, outer: cover::PacketMeta,
              plaintext: &[u8], workspace: &mut [u8], output: &mut [u8])
    -> Result<Sealed, Error>
Records::open(&mut self, packet: &[u8], workspace: &mut [u8],
              plaintext: &mut [u8]) -> Result<Opened, Error>
```

`stage_data` requires a strictly newer epoch and a free additional-reader slot;
repeating the exact staged request succeeds without changing state.
`cancel_staged_data` removes only that exact staged reader. `activate_data`
requires the exact staged scope, makes it active for sending, and retains the
old active reader as draining; repeating activation of the current scope is
idempotent. `retire_data` removes only the exact draining reader. The control
scope has no setter. Receive accepts either registered data scope during staging
or draining, and returns the exact authenticated scope for upper-layer dispatch.

These are explicit local reader operations. They neither send management
messages nor authorize an atomic peer switch, barrier completion, rollback after
commit or old-data retirement. The caller must establish the existing negotiated
epoch/digest, authenticated PREPARE/COMMIT, drain and retry requirements first.

## Exact framing and authentication

Integrator wire revision recorded before changing the implementation: the current
draft uses a compact nine-byte route, `[class: u8][epoch: u64 big endian]`.
The public `Scope` API retains the full digest. The receiver resolves the exact
currently registered control, active data, or one staged/draining data scope by
class and epoch, then authenticates that registered full digest through
`Metadata.configuration` and the exact route through `Metadata.extra`.
Concurrent registered data epochs are unique because staging requires a newer
epoch than active data. Control and user scopes may share an epoch because class
selects separate purpose keys. There is no trial decryption across candidate
digests or fallback to another class.

Precommit cancellation may re-register the same future epoch with a different
digest/attempt. No historical epoch tombstone is added: only simultaneous reader
uniqueness is required. Ciphertext from the canceled digest must fail against
the replacement's full authenticated digest without changing replay state;
a subsequent valid replacement packet must still open. Negotiated transaction
attempts, barriers and cancellation authority remain owned by the upper layer.

This removes 32 repeated bytes per record without changing selected tag length,
keys, nonce/replay identity, full digest matching, directions or lane/session
binding. A remote digest mismatch becomes an authentication failure rather than
an explicit unregistered-digest hint; the handshake/control configuration remains
the source of requested/effective digest diagnostics. The new draft is wire
incompatible with the earlier 41-byte layout and has no auto-detection/fallback.
Negotiated configuration must bind the final wire profile before deployment.
This is an integrator implementation choice, not an owner design decision.
Earlier 15-test results apply only to the 41-byte layout; the compact route has
its own fresh 17-test validation. The draft is unpublished, and no historical receipt
is overwritten or relabeled as compact-route evidence.

One established-phase cover payload contains:

```text
[class: u8][epoch: u64 big endian]
[common packet-security prefix: 10 bytes][body][selected authentication tag]
```

The route prefix is exactly `ROUTE_BYTES = 9`. Class values are `1` for User and
`2` for Control. It is a public, untrusted routing hint, not an authentication
decision. The receiver first resolves a registered scope of that class and epoch,
then supplies that scope's full epoch/digest and the entire exact nine-byte route as
`Metadata.extra` to its corresponding data or management receiver. Those bytes,
the common security prefix and the packet-security session/transcript, suite,
direction, purpose and lane domain are authenticated together. An unknown class
or unregistered scope is rejected without deriving or allocating a reader.

The result exposes authenticated class, scope, full 64-bit security packet number,
key generation and plaintext length only after successful protection verification
and replay commitment. The complete authenticated number is preserved for data
algorithms such as Swift repair; an untrusted 32-bit outer cover number cannot
replace or truncate it. User Ethernet bytes,
including management-looking EtherType/MAC or payload prefixes, remain User.
Relabeling their route as Control requires a valid management-domain tag; the
public class byte cannot confer that authority. Local callers are trusted to
choose the correct class when sealing an actual management record.

Both QUIC-like and minimal media covers use `Phase::Established` here. Common
handshake packets are handled by their separate handshake/cover composition.
Handshake-phase input/output is rejected by this record API. Outer packet
numbers, timestamps, marker bits and structural connection identifiers remain
untrusted appearance metadata; they are not secure replay identities or proof
of a negotiated switch. A short QUIC header has no exact body length; the inner
common packet authentication rejects altered/truncated protected records.

## Capacity, failure and trust contract

Common security overhead is `Protection::overhead_bytes()` (26 bytes for AEAD,
42 for HMAC). Seal workspace is `9 + security overhead + plaintext length`.
Open workspace is `plaintext length + selected tag length`, as required by the
security receiver. Final established packet size adds 13 QUIC-like bytes or 14
media bytes. `capacity` uses checked arithmetic and the actual immutable cover
body/packet limits; construction requires the maximum configured plaintext to
fit. No layer adds fragmentation or padding.

With a minimum 20-byte IPv4 header and eight-byte UDP header, established cover,
route and common security add 76 bytes for QUIC-like AEAD, 77 for media AEAD,
92 for QUIC-like HMAC, or 93 for media HMAC. This removes 32 bytes from the prior
draft's respective costs. These totals exclude inner Swift/recovery/record
headers, options, outer Ethernet and additional encapsulation; they are exact
format accounting under the stated assumptions, not measured goodput. The
retained Swift-v2 UDP format separately has 24 protection bytes plus 28 IPv4/UDP
bytes and no new cover or route. Its historical costs and receipts remain intact.

Before calling a security sender, seal validates phase, plaintext, complete
cover size, workspace and complete output capacity. Such validation errors do
not reserve a nonce or modify caller buffers. Once a maintained cryptographic
attempt starts, its packet number is never reused even if it fails. Open checks
the complete structural record and both caller capacities before its receiver can
commit replay state. It copies valid plaintext from receive workspace into the
separate output only after authentication, so failed authentication never exposes
new plaintext through that output. Failed receive workspace follows the security
API's clearing/validity contract and is never an authenticated result.

Errors distinguish malformed route/packet, unknown scope, invalid local scope
transition, non-established phase, excessive body/packet, workspace/output
capacity, underlying cover rejection and underlying packet-security failure.
The wrapper does not retry cryptography under another class or unregistered
scope, and never downgrades the negotiated protection. Generic HMAC support does
not relax Swift's separately retained mandatory AEAD requirement.

## Acceptance and evidence gates

For the prior 41-byte draft, the parent ran
`cargo test --offline --locked --package l2tunnel --test secure_record --test common_session_udp`:
all 15 [secure-record tests](../../crates/l2tunnel/tests/secure_record.rs) and the
parent [same-UDP Noise/Swift/control fixture](../../crates/l2tunnel/tests/common_session_udp.rs)
passed. The former includes its own two-real-UDP-socket fixture for both covers
and AEAD/HMAC in both directions. The parent formatted the facade package.
The fresh compact-route r2 run passed all 17 focused tests, including canceled-epoch
digest replacement, the exact AEAD/HMAC constructor boundaries and rejection of
the former 41-byte layout. The same test command above also passed the parent's
one real-UDP Noise/Swift/control fixture. The r2 receipt reports stable Rust/app,
Cargo, vendor and configuration input hashes throughout the check; it does not
claim concurrent prose/Python-tooling stability. This local run also passed:

- `cargo fmt --all -- --check`.
- `cargo test --offline --locked -p l2tunnel-management`: 34 tests.
- `cargo clippy --offline --locked --workspace --all-targets --all-features -- -D warnings`.

The original r2 output remains at
`/tmp/l2tunnel-shared-session-focused-20261113-r2`. Exact scoped source identities
and executed checks belong to the parent's persistent
[focused receipt](../../work/shared-session-primitives-20261113/focused-validation.json).
The required [source-stable aggregate checker](../../work/shared-session-primitives-20261113/validation.json)
also passed, including warning-denied rustdoc. Its input snapshot predates only
the evidence-only ledger prose update qualified from the master ledger.

- [x] [SREC-01] Record and review the pure API, nine-byte authenticated route, four fixed domain owners, two-reader scope bounds and pre-crypto capacity contract before implementation. Evidence: the [API and integrator wire design](secure-records.md#exact-framing-and-authentication) preceded code changes, and the parent accepted the API and compact-route implementation revision.
- [x] [SREC-02] Implement actual bounded seal/open and typed authenticated User/Control results with no packet allocation, I/O, time, unsafe or secret getters. Evidence: [composition source](../../crates/l2tunnel/src/secure_record.rs) and the fresh 17-test compact-route run.
- [x] [SREC-03] Verify both covers and both common protection selections, opaque/empty/zero-tailed bytes, exact overhead, both directions, truncation/tamper/replay and user-to-control forgery rejection. Evidence: all 17 [focused tests](../../crates/l2tunnel/tests/secure_record.rs) passed for the current compact route in the source-stable r2 run.
- [x] [SREC-04] Verify staged/active/draining transitions, control availability during data changes, old/new scope exactness, no counter/replay resets, fixed reader bounds and preflight failures that do not burn nonces or receive replay credit. Evidence: [scope/replay/preflight tests](../../crates/l2tunnel/tests/secure_record.rs) passed for the compact route in the fresh 17-test run. Authenticated full 64-bit numbers/generations are forwarded without truncation; the finite ratchet test exercises numbers 0..19.
- [x] [SREC-05] Pass focused tests, formatting, warning-denied Clippy/rustdoc and the required source-stable aggregate checker; record exact commands and separate parent composition evidence. Evidence: focused tests, formatting and strict workspace Clippy above, followed by warning-denied rustdoc and the passing [source-stable aggregate](../../work/shared-session-primitives-20261113/validation.json). The master ledger qualifies subsequent evidence-only prose changes separately.
- [x] [SREC-06] Exercise real protected User/Control records on the same two real UDP sockets for both appearances, while keeping this finite loopback fixture distinct from client/service/native, full handshake/liveness/recovery, platform, standard-protocol and ISP/QoS qualification. Evidence: the compact-route [two-socket fixture](../../crates/l2tunnel/tests/secure_record.rs) and parent [Noise/Swift/control fixture](../../crates/l2tunnel/tests/common_session_udp.rs) passed in the fresh local Linux r2 run. This is not a platform/runtime release qualification.
- [x] [SREC-07] Validate the compact nine-byte route with implicit full-digest authentication, unambiguous current/staged/draining lookup, canceled-epoch re-registration under a changed digest/attempt without replay reset, and explicit rejection of the former unpublished 41-byte draft. Evidence: [compact route regressions](../../crates/l2tunnel/tests/secure_record.rs) passed in the fresh source-stable 17-test r2 run; the public Scope API and original functional gates remain unchanged.

The parent owns facade declarations, dependency wiring and runtime consumers.
Source presence or a loopback fixture cannot complete SEC-* lifecycle, full
mode-parity, OpenVPN actual-handshake, original HTTPS raw transition or SW-11
negotiated profile switching requirements. Historical experiments remain intact.
