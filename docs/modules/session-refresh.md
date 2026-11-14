# In-session fresh-DH refresh

Status: **engineering proposal, before implementation or API freeze**, 2026-11-14.
This child retains every deliverable of [SEC-06/SEC-08](secure-session.md),
[the architecture](../architecture.md) and the [master ledger](../implementation-checklist.md).
It specifies a complete first pure Records/Noise slice. It does not enable a
runtime rekey option, a recovery default, a new carrier or full SW-11. The wire
and API choices below are proposed implementation choices, not owner decisions.
No production source or test has been changed or executed for this proposal.

## Current source and the actual gap

- [Handshake](../../crates/l2tunnel-handshake/src/lib.rs) uses pinned Clatter 2.3.0
  IK/IKpsk2, explicit ephemeral entropy, fixed flights and consuming public split
  keys. Both confirmations are required before its root handoff. Its final
  ciphertext cache survives root release. A new confirmed root currently creates
  new packet owners at number zero.
- [Security](../../crates/l2tunnel-security/src/context.rs) provides unique
  purpose/direction/lane owners. [Sender/Receiver](../../crates/l2tunnel-security/src/record.rs)
  and [keys](../../crates/l2tunnel-security/src/keys.rs) implement continuing
  numbers, replay and deterministic adjacent generations. That ratchet introduces
  no fresh DH contribution and supplies no in-session key import.
- [Records](../../crates/l2tunnel/src/secure_record.rs) consumes the root into four
  owners, retaining neither an opaque refresh authority nor old Noise credentials.
  Its two data readers describe mode scopes, not two fresh-DH key contexts.
- [Driver](../../crates/l2tunnel-runtime/src/secure_udp/transport.rs) uses the
  security User packet number as the actual Swift `RecordNumber`/coefficient
  identity. Replacing Records with newly zero-based owners would corrupt that
  retained identity. Its native origins and generic transaction debts must also
  survive a key refresh unchanged.
- [Member Info](../../crates/l2tunnel-runtime/src/secure_udp/member.rs), public
  `Opened`, and management `Ingress` are observations or caller assertions.
  Constructing one is not evidence that old keys authenticated a refresh request.
  Manual service reconnect currently establishes a new session and drops the old
  driver. It is not retained-state recovery.

The current evidence paragraph in [secure-session](secure-session.md#current-source-and-evidence)
supersedes its explicitly historical extraction table. That table must not be
used to claim that the later generic service/CLI integration is still absent.

## Primary cryptographic constraints

The [Noise framework sections 5, 6 and 11](https://noiseprotocol.org/noise.html)
specify transcript-bound prologues, channel binding, unique transport nonces and
application-owned replay handling. Its one-way `Rekey` does not add fresh DH or
reset the nonce. A public transcript is not a secret authentication key. Public
prologue context does not replace a PSK. These facts motivate the authority,
fresh exchange and continuing-counter separation below.

The [existing adapter review](noise-handshake.md) remains authoritative about its
pinned APIs and limitations: Clatter is unaudited, its RNG features stay disabled,
and complete upstream PSK-copy/stack erasure is not established. This proposal
does not upgrade those qualifications or claim standard WireGuard compatibility.

## Explicit selection and initial authority

Keep common v1, legacy Swift v2 and all existing constructors/bytes unchanged.
An additive `Handshake::new_refreshable` commits a canonical refresh selection
to the INITIAL Noise prologue before any flight. It includes common record v2,
the selected protection, lane/security limits, fixed control scope, fresh-key
age/overlap bounds, exchange work/copy bounds and the selected carrier envelope.
The actual setup H0 includes this selection; no post-handshake boolean enables it.
Numeric policy values are explicit inputs, with checked finite bounds and no
default chosen here. Canonical encoding and digest test vectors precede code.

The proposed `security::refresh::Selection` has checked private fields, a checked
constructor and read-only getters. Handshake reexports that same type rather
than maintaining a second representation. Its canonical 132-byte value is:

```text
L2RS[4], version=1:u8, protection:u8, reserved-zero[2],
lane:u32, max_body_bytes:u32, packets_per_key:u64, max_body_bytes_per_key:u64,
fixed_control_epoch:u64, fixed_control_digest[32], envelope_digest[32],
exchange_micros:u64, key_micros:u64, overlap_micros:u64, max_flight_copies:u32
```

All integers are big endian. Body/security maxima stay the current library
maxima. Durations and copy bound must be positive, overlap must be strictly
shorter than exchange and key duration, and time additions are checked. The
selection has one pending attempt/two key contexts as fixed geometry, not
peer-controlled counts. `max_flight_copies` counts first output plus exact
copies, has no implicit retry cadence and never authorizes unlimited work. The
runtime must separately bound attempts/rate and charge all actual bytes. The
envelope digest names a complete locally checked carrier/resource contract; it
is not accepted instead of actual geometry checks. It excludes H0 to avoid a
digest cycle: initial H0 commits this selection and its envelope input.

After both actual initial confirmations, the maintained adapter imports split
secrets together with its actual role/profile/prologue, ordered pins and final
transcript into a private security `RefreshAuthority`. The root owns it until
`Records::new_refreshable` takes it while reserving the four existing domains.
The old root is then dropped. The authority is non-Clone, has no public
constructor from Info/digests/flags, no raw-secret getter and no secret Debug.
Legacy split-key import creates no refresh authority. The new context-bearing
import requires the actual owned split secrets and is the documented trusted
maintained-adapter boundary; it cannot authenticate arbitrary user metadata by
itself. No `attach_context(Info)` escape is added.

Initial unique-domain ownership is checked before any allocation or publication:
the selected constructor refuses a root with any previously minted unmanaged
purpose/direction/lane owner. It cannot forget the root registry, derive a
second set, or assume an external owner was dropped. The first pure constructor
requires an empty domain registry and publishes its four managed domains as one
checked construction. This restriction is observable, not a hidden fallback.

The current member driver derives Joining owners before returning its root.
Consequently it is **not yet a compatible v2 handoff** under that strict rule.
The later runtime integration must introduce an opaque managed Joining-completed
handoff that proves those owners were consumed/retired, or reserve the complete
managed set before the member gate. Public Info, a registry reset, and a claimed
drop flag cannot discharge that dependency. The first pure fixture cannot claim
actual service membership or runtime readiness from a fabricated member value.

The initial member gate continues to hold the actual root until existing member
proof/acceptance succeeds. Refresh does not newly grant membership, change an
allowlist, convert Ed25519 into X25519 or replace own-server trust. The opaque
authority is carried through that existing custody, never reconstructed from the
public member status. A restart that lost this owner cannot mint a continuation.

Both roles have a real authority path:

1. Only the global initiator may locally begin. Records uses its unique retained
   authority to allocate a nonwrapping target `KeyEpoch` and one immutable request.
   It need not receive its own request.
2. The responder obtains an admission only inside the same old Management receive
   operation that authenticates, strictly parses and admits the exact request.
   No public `Opened`, `Ingress` or flag is accepted as that proof.

`Exchange::new` checks supplied `LocalSecret::public_key()` and `PeerKey` against
the authority's actual old pins before entropy or output. IKpsk2 additionally
checks the exact supplied owned PSK against a hidden, zeroizing standard
HMAC-SHA256 commitment captured from the actual initial PSK. Presence alone is
insufficient. Maintained ring verification performs the comparison; no new
primitive or public PSK hash is introduced. IK rejects an unexpected PSK.

The exact PSK-check input is
`HMAC-SHA256(initial_psk, "l2tunnel/refresh-psk-check/v1\0" ||
SHA256(actual_initial_prologue_bytes))`. The stored tag is secret owner metadata,
not a public configuration field. Verification computes the maintained HMAC with
the supplied candidate PSK and verifies against that retained tag. There is no
home-grown equality primitive or password-derived-key claim.

The selected initial prologue appends
`"l2tunnel/refresh-selection/v1\0" || selection_bytes132` to the exact existing
prologue. The ordinary constructor appends nothing. The refresh prologue is
`"l2tunnel/noise-refresh/v1\0" || refresh_context_bytes`, where the canonical
refresh context is the following concatenation, with fixed widths and big-endian
integers:

```text
"l2tunnel/refresh-context/v1\0", original logical session[16],
original final Noise hash[32], original authenticated setup H0[32],
original carrier[32], original derived outer[32], original member-policy[32],
ordered initiator Noise public[32], ordered responder Noise public[32],
Noise profile:u8 (IK=1, IKpsk2=2), selection_bytes[132],
parent_key_epoch:u64, target_key_epoch:u64
```

Here and in every label below, `\0` denotes exactly one terminal zero byte,
not a backslash and digit. The context is exactly 417 bytes (28-byte label plus
389 fixed field bytes); its SHA-256 is the request/header context digest. It is derived from
retained actual initial state, not accepted as a substitute for it. Initial v2
material uses this context with parent=target=0 and its actual initial Noise hash;
fresh material uses the admitted context and new actual final Noise hash.

## Solved record-selector and ratchet-base proposal

The explicitly selected common record v2 prefix is exactly 26 bytes:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 1 | Version 2 |
| 1 | 1 | Previously authenticated suite |
| 2 | 8 | Fresh-DH `KeyEpoch`, big endian |
| 10 | 8 | Immutable per-direction/purpose `ratchet_base`, big endian |
| 18 | 8 | Continuing global `PacketNumber`, big endian |

Here global means one existing directional purpose/lane packet owner, not a
shared counter between User, Control or endpoints. The existing nine-byte
class/data-epoch route and full 16-byte AEAD or 32-byte HMAC tags remain. Every
prefix byte, route, full registered scope digest and original domain context is
authenticated. Fresh root derivation additionally binds target KeyEpoch, the
original logical binding, full refresh context and actual new final Noise hash.
The common nonce remains four zero bytes followed by the full global number.

Fresh import uses maintained HKDF-SHA256: Extract the fixed-order 64 split-secret
bytes with salt `original_session16 || original_hash32 || target_epoch8 ||
refresh_context_digest32 || new_noise_hash32`; Expand with
`"l2tunnel/packet/v2/session-root\0"`. Derive domain seeds with
`"l2tunnel/packet/v2/domain\0" || suite1 || purpose1 || direction1 || lane4`.
Use separate v2 AEAD, MAC and next-chain labels. Their literal labels are
`"l2tunnel/packet/v2/aead-key\0"`, `"l2tunnel/packet/v2/mac-key\0"` and
`"l2tunnel/packet/v2/next-secret\0"`. They do not alter any v1/Swift labels.

The v2 AAD is exactly `"l2tunnel/packet/v2/aad\0" || original_session16 ||
original_hash32 || target_epoch8 || new_noise_hash32 || context_digest32 ||
suite1 || purpose1 || direction1 || lane4 || prefix26 || metadata_epoch8 ||
metadata_digest32 || extra_length2 || extra`. The length is checked before copy;
the existing 256-byte extra limit is preserved. Direction/purpose/lane and
selection are fixed by the owner, never accepted from header hints.
The Extract salt is 120 bytes. Domain-seed info is 33 bytes (26-byte label plus
seven field bytes). AAD is exactly 218 bytes before extra, at most 474 bytes;
the current smaller v1 scratch bound is not reused accidentally.

The initial selected key epoch is zero with base zero. Activation atomically
chooses each sender's base from that EXISTING sender's current next number;
generation is `checked_sub(number, base) / packets_per_key`. The base is in every
packet, so loss of the first new packet does not lose the base. No counter value
is negotiated, supplied through a setter or frozen when the handshake starts.
Old-key control traffic may continue throughout the exchange, even across the
request-time snapshot or a deterministic generation boundary. It stops using
old send keys at activation; old encrypted packets can still arrive reordered.

The receiver pins a prospective base only after successful authentication. It
requires the exact same base thereafter, `number >= base`, and the first new
base above the highest previously authenticated old-key number in that domain.
Once pinned, an old-key packet must have `number < new_base`. Unauthenticated
base/selector/metadata claims cannot create slots, advance a chain, commit replay
or consume byte budgets. An uninitialized new slot starts at generation zero;
only the existing bounded adjacent generation candidate is permitted. Losing
more than that supported generation range is an explicit generation failure,
never a peer-sized loop, root-based historical-key reconstruction or counter reset.

One replay owner spans both fresh-key slots. The same global number cannot be
accepted twice under different key epochs; wrong keys/metadata do not consume it.
No public constructor accepts a caller-selected starting packet number. Checked
exhaustion of the existing global number remains terminal even after fresh DH.
Each fresh key has its own actual byte-use and adjacent-generation state.
Fresh-key epoch allocation never wraps or reuses a previously allocated selector,
including a failed attempt. Gaps are permitted only from burned attempts; stale
requests cannot move the retained high-water mark backward or resurrect a slot.

This adds 16 bytes per protected packet relative to common v1. Exact overhead is
route9 + prefix26 + tag16/32 + actual selected cover/IP/UDP geometry. Existing
path/storage/burst capacities must be checked before ownership or nonce mutation.
No MTU, protection, rate, target or capacity is silently reduced or increased.
It is not a compact-wire proposal and claims no throughput improvement.

## Fixed request and actual Noise lane

The first complete pure slice uses one fixed authenticated request, not a new
management fragment protocol. Its plaintext is exactly 72 bytes:
`L2RQ[4] | version1 | kind1 | reserved-zero2 | logical-session16 |
parent-key-epoch8 | target-key-epoch8 | refresh-context-digest32`.
It uses private established route class **4**, the unchanged fixed control scope
and the EXISTING Management sender/receiver/counter/replay owner. Class3 remains
reserved for the existing Joining tail. Ordinary `Records::open` does not turn a
class4 packet into user bytes or a generic control grant.

The context digest covers the original stable logical SessionBinding, actual
initial authenticated H0/carrier/derived outer/member-policy values, ordered pins,
Noise profile, lane, fixed control scope, selected v2/security/resource contract,
parent and target key epochs. It deliberately does not select or replace current
data-mode epochs/configurations. Those remain authenticated per record and owned
by their existing active/staged/draining transaction state.

The Noise prologue reuses the maintained fixed-pattern adapter with a separate
refresh domain/context digest. Both endpoints bind the exact same canonical
public context. Each new exchange consumes one genuinely fresh supplied ephemeral
and preserves pinned static identities/profile/PSK. It uses no replayable early
user data. A conflicting same-target request or flight cannot replace a live
exchange. Exact requests produce a Duplicate outcome and no second admission.

Refresh Noise flights use the existing cover **Handshake** phase with a bounded
72-byte `L2RH` header carrying version/kind/reserved/session/parent/target/context,
followed by the unchanged 96/48/73-byte Noise flight. The maximum protected cover
body is therefore 168 bytes, separately preflighted against actual Handshake
header geometry. Only a currently admitted exact exchange can process it.
An unsolicited public header cannot start a Noise operation or authorize data.

This is important for asymmetric final loss: retain and retransmit the exact
73-byte Noise confirmation after local material release, without wrapping it in
new common keys that the still-incomplete peer cannot yet install. No new old-key
encryption is needed after activation. The existing consuming Noise transport and
confirmation cache are reused; no Noise cipher is reused for ordinary traffic.
Runtime retry/amplification/work ownership remains required separately.

## Candidate pure interfaces and ownership split

These signatures are the proposed freeze surface, not implemented APIs. All time
is caller-injected monotonic microseconds. Types containing authority/material
have private fields and no Clone/Debug; public copies below are observations.

```rust,ignore
// handshake/src/refresh.rs: actual existing maintained Noise, same fixed flights
Handshake::new_refreshable(config: Config, selection: refresh::Selection,
    local: LocalSecret, peer: PeerKey, psk: Option<Psk>, now: Time,
    entropy: &mut impl Entropy) -> Result<Handshake, Error>;
// Existing finish_with_confirmation consumes actual verified split keys;
// selected construction privately includes authority in its returned root.

refresh::Exchange::new(admission: security::refresh::Admission,
    local: LocalSecret, peer: PeerKey, psk: Option<Psk>, now: Time,
    entropy: &mut impl Entropy) -> Result<refresh::Exchange, refresh::Error>;
refresh::Exchange::write(&mut self, now: Time, output: &mut [u8])
    -> Result<refresh::Flight, refresh::Error>;
refresh::Exchange::read(&mut self, now: Time, input: &[u8])
    -> Result<ReadOutcome, refresh::Error>;
refresh::Exchange::retransmit(&mut self, now: Time, kind: FlightKind,
    output: &mut [u8]) -> Result<refresh::Flight, refresh::Error>;
refresh::Exchange::finish_with_confirmation(self, now: Time)
    -> Result<refresh::Completed, refresh::Error>;
// Completed { material: handshake::refresh::AuthenticatedRefresh,
//             confirmation: refresh::ConfirmationCache }; never another root.
// refresh::Flight {kind: FlightKind, bytes: usize} counts header+Noise bytes.

// secure_record.rs: one existing Records with explicit selected backing
Records::new_refreshable(root: SessionRoot, lane: LaneId, limits: Limits,
    protection: Protection, cover: cover::Config, control: Scope, data: Scope,
    now: Time, session_expires: Time)
    -> Result<Records, Error>;
Records::begin_refresh(&mut self, now: Time, original_deadline: Time)
    -> Result<refresh::Started, Error>;
// Started { admission: Admission, request: Request }; Request bytes are immutable.
Records::seal_refresh_request(&mut self, request: &refresh::Request, now: Time,
    outer: cover::PacketMeta, workspace: &mut [u8], output: &mut [u8])
    -> Result<Sealed, Error>;
Records::open_refresh_request(&mut self, packet: &[u8], now: Time,
    original_deadline: Time, workspace: &mut [u8])
    -> Result<refresh::RequestOutcome, Error>; // New(Admission) or Duplicate
Records::prepare_refresh(&mut self, material: handshake::refresh::AuthenticatedRefresh,
    now: Time) -> Result<refresh::Prepared, Error>;
Records::activate_refresh(&mut self, prepared: &refresh::Prepared, now: Time)
    -> Result<refresh::Activation, Error>;
Records::seal_refresh_activation(&mut self, now: Time, outer: cover::PacketMeta,
    workspace: &mut [u8], output: &mut [u8]) -> Result<Sealed, Error>;
Records::open_refresh_activation(&mut self, packet: &[u8], now: Time,
    workspace: &mut [u8]) -> Result<refresh::ActivationOutcome, Error>;
Records::retire_refresh(&mut self, target: refresh::KeyEpoch, now: Time)
    -> Result<(), Error>;
Records::abort_refresh(&mut self, target: refresh::KeyEpoch, now: Time)
    -> Result<(), Error>; // only before local activation; selector stays burned
// Selected v2 data/control entry points require time; legacy un-timed methods
// must not bypass selected key age, exchange expiry or monotonic-time checks.
Records::seal_at(&mut self, now: Time, class: Class, outer: cover::PacketMeta,
    plaintext: &[u8], workspace: &mut [u8], output: &mut [u8])
    -> Result<refresh::Sealed, Error>;
Records::seal_user_in_at(&mut self, now: Time, scope: Scope,
    outer: cover::PacketMeta, plaintext: &[u8], workspace: &mut [u8],
    output: &mut [u8]) -> Result<refresh::Sealed, Error>;
Records::open_at(&mut self, now: Time, packet: &[u8], workspace: &mut [u8],
    plaintext: &mut [u8]) -> Result<refresh::Opened, Error>;
// refresh::Sealed {record: Sealed, key_epoch: KeyEpoch, ratchet_base: PacketNumber}
// refresh::Opened {record: Opened, key_epoch: KeyEpoch, ratchet_base: PacketNumber}
```

The refresh confirmation cache retains the immutable 72-byte refresh header and
delegates exact 73-byte ciphertext custody to the existing cache; output is 145
bytes. It has no secret key or re-encryption operation. `read` validates the
entire header and admitted operation before calling the maintained Noise read;
`write`/`retransmit` include that header and account for first/cached copies. The
underlying Noise size limits remain 96/48/73, not peer-sized inputs.

`Admission` is minted only by retained old authority and exact atomic admission;
the handshake-owned `AuthenticatedRefresh` only by real confirmed Noise finish.
It exposes no raw key/zero-based root and installs into the security backing by
consumption. This seals the facade's prepare entry against a caller-created
security import object. The lower-level secret import is still a documented
trusted crypto-adapter boundary, as with existing split-key import, not a proof
that arbitrary local application code performed a handshake. Material binds
the exact pending ticket/role/session/epoch/selection/transcript and is consumed
once. Preparing derives all four fresh domain chains before publishing any;
failure drops partial material and leaves existing counters/readers unchanged.
It never exposes a generic root that could recreate zero-based owners. The
security consumer performs its own context comparison, not a caller's boolean.

`RequestOutcome::Duplicate` does not transfer another exchange owner or renew its
deadline. Duplicate activation is idempotent with the same stored bases. A
second target while either pending or overlapping is refused without eviction.
An exact authenticated activation body uses `L2RQ` kind2 and appends the sender's
User and Control bases (88 bytes total); it is sealed under the new Management
key and compared against the packet's authenticated new key epoch. Successful
admission, not a public Activation value, records peer activation internally.

The security lane owns v2 prefix/AAD, four continuing packet/replay owners,
private old authority, consume-once fresh material and bounded key slots. The
handshake lane owns the actual existing Noise wrapper, credential checks,
refresh context/prologue and exact final-flight custody. The facade consumes
both; it does not implement crypto. There is no dependency from security back
to handshake/facade, no private Clatter extraction and no new cipher suite.

## Time, activation, overlap and failures

Local accepted deadlines are absolute in each endpoint's unchanged clock domain.
Do not serialize a local absolute `Time` and interpret it in the peer's unrelated
clock. A peer request cannot extend local original exchange/session/key caps.
At first begin/admission the effective cap is the checked minimum of supplied
original deadline, retained session expiry, old-key expiry and
`now + selection.exchange_micros`; it is stored once. Duplicates reuse that cap.
Fresh keys do not extend the existing logical-session lease or any retained
message, native stall, transaction, phase, operation or reconciliation deadline.
Initial key age begins at the actual initial confirmed split-key handoff, not a
later Records constructor or first packet. Each fresh age begins at its actual
confirmed split-key handoff. The constructor validates that injected time shares
that clock, that the initial key is still usable, and that the supplied original
session expiry is in the future; every later entry retains it unchanged. A
caller cannot lengthen that deadline by moving/reconstructing public status.

There is at most one pending attempt and two fresh-key receive contexts. Each
context retains only the existing bounded adjacent deterministic generations.
That is independent of, and explicitly budgeted in addition to, two data scopes.
Activation switches both local send domains atomically; receive preparation
already installed the matching new contexts. The actual activation time fixes
the overlap deadline once. It must leave the configured overlap inside the
original operation cap, or activation is refused before mutation. Retirement
requires actual new-key peer activation and completion of that overlap; it wipes
the old context without touching global replay, data epochs or logical debts.

Before activation, refusal/expiry may discard the unactivated candidate while
the old context is still valid. After activation, failure cannot roll back keys,
numbers or peer-visible effects: an unresolved original-cap expiry is terminal
for this refresh operation. No ordinary v2 entry point may continue past that
terminal cap. Full retained recovery decides what bounded logical state survives;
this pure slice must not pretend that restarting Records reconciles it.
Explicit preactivation abort likewise burns the allocated selector and cannot
undo numbers already used for request/control output. An abort after activation
is refused; it is not a rollback mechanism.

Deadline/retrograde checks precede semantic work; all lengths/capacities and
checked epoch/number arithmetic precede sender reservation. Cryptographic attempts
burn a global sending number, including provider failure. Authentication failure
does not commit replay/base/generation/byte-use/admission. For the dedicated
request entry point, semantic/context/duplicate/cap preflight occurs inside the
authenticated receive transaction before its final replay/admission commit;
there is no copied replay rollback. A bounded unsuccessful candidate cache is
not adopted state. Output, malformed, unsupported, credential, busy, conflict,
epoch/number exhaustion, generation, usage, age/deadline and crypto failures have
typed bounded errors and no peer/provider strings or secrets.

## First complete implementation slice and dependencies

The first slice implements the actual pure path: initial selected Noise and member
custody -> Records v2 -> authenticated request -> both real fresh Noise roles ->
actual prepared keys -> activation and peer activation -> overlap and retirement.
It carries exact User/Control bytes before, during and after exchange. It retains
old final-confirmation ciphertext and continuing PN/replay; it is not an unused
authority enum. Existing v1/Swift compatibility vectors remain required.

Proposed disjoint implementation ownership after review:

- Handshake: new `handshake/src/refresh.rs` and child tests; narrow lib/finish and
  import factoring, preserving old vectors and maintained public APIs.
- Security: new `security/src/refresh.rs` and child tests plus context/record/key
  factoring for the selected v2 backing, retaining the one existing algorithm.
- Facade: selected Records construction/prepare/activate/retire plus a real
  two-endpoint pure protected-record fixture. Root coordinates public exports.
- Follow-on runtime/control: root-owned sole-reader integration, exact credentials,
  work/byte/cipher caches, original socket/tails, explicit selection/status and
  complete resource admission. No current runtime/control source is changed here.

The follow-on MUST provide independently live lifecycle work while a transaction
is incomplete, using the existing reliable-message/fragment ownership rather than
inventing another management stack. If requests become fragmented, opaque actual
per-source authentication must survive through complete-message custody; current
public `Ingress` is insufficient to mint an Admission. An explicit new stream
contract/context map is required; current L2CFv1 has three streams and derives
`3 * base + stream`. No fourth value is silently inserted into that contract or
DataFeedback repurposed. The fixed single-record admission in this slice is not
evidence for that later fragmented adapter or runtime rekey capability.

Peer restart, default retained-state recovery, unresolved commits, old native
physical fences, additional carriers, production CLI/GUI and platform acceptance
remain full required follow-ons. A restarted peer cannot reuse an old selector,
logical session or counter from public metadata. It needs fresh authentication
and explicit reconciliation or a new logical session; inner TCP survival is not
guaranteed. All mode/parity gates retain their original scope.

## Acceptance ledger

- [ ] [SREF-01] Freeze source-bound v2 selection, initial/refresh authority, exact wire/AAD/derivation, error/time/overlap/capacity and no-reset contracts before production changes; keep parent scope and owner decisions distinct.
- [ ] [SREF-02] Implement actual selected initial authority and both-role admissions; verify wrong local/peer static key, old binding/member/carrier/lane/profile/PSK, reflected role, public-metadata forgery, duplicate ownership and original-cap refusals before fresh output.
- [ ] [SREF-03] Implement actual maintained fresh Noise exchange and consume-once material with deterministic test entropy, fixed flights, exact duplicate/conflict/error handling, real split-key import, asymmetric final loss/cache retry and unchanged legacy vectors.
- [ ] [SREF-04] Implement actual v2 Records prepare/activate/retire: continuing global PN/replay, authenticated base/epoch, packet/byte/generation/age limits, failed-auth atomicity, bounded simultaneous key/data readers, checked exhaustion and partial construction cleanup.
- [ ] [SREF-05] Qualify the complete two-endpoint pure path under loss/reorder/duplicate and both protections/covers, old-key traffic beyond the request snapshot, first-new-packet loss, deterministic generation crossings, key overlap, late/conflicting/retired input, original expiry and preserved data/control/native/transaction identities where their real owners are composed.
- [ ] [SREF-06] Integrate the actual selected runtime sole-reader/credential/lifecycle custody, bounded authenticated fragmented control and independent progress, full current+prepared resource admission, observable status and same-socket retention; preserve all existing modes/defaults and qualify real faults.
- [ ] [SREF-07] Complete default bounded retained-state recovery, actual peer-restart/reconciliation/uncertain-commit behavior and full carrier/platform/CLI/GUI acceptance under unchanged parent gates; fresh DH alone does not check this task.
- [ ] [SREF-08] Run source-stable focused/security/dependency/full required checks and reconcile exact evidence/negative results before a checkpoint; distinguish protocol, loopback, native, CI and real-platform qualifications.

Minimum first-slice matrix: both actual roles; IK/IKpsk2; AEAD/HMAC record domains;
both covers; legacy byte vectors; request duplicates vs conflicting target; every
Noise flight lost/reordered; final cache after material release; old controls
emitted after begin; four independent bases; fresh base substitution; same PN
across slots; canceled/retired epoch; maximum numbers/checked arithmetic; short
outputs and wrong metadata; previous/next generation; fresh and original absolute
deadline boundaries; two data readers with key overlap; no extra allocation or
ownership escape on failure. Broader runtime/native recovery tests are required
by their own rows and cannot be inferred from this matrix.
