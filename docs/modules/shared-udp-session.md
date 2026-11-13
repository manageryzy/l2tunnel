# Same-carrier authenticated UDP session owner

Status: **implemented with finite local member/client integration tests**. This wave advances FIX-13
and SEC-03/04/07/09 using the existing pure security, Noise, appearance and control
components. It does not complete the broader session, native, platform or mode
requirements. The existing TLS/separate-UDP client remains historical runnable
functionality until the selected shared service path is actually wired and tested.

## Ownership and draft interface

The runtime owns exactly one already connected Tokio UDP socket throughout
return-path admission, Noise, existing-member proof and protected records. A
single reader demultiplexes bootstrap tails, joining records, user records and
fixed management. There is no background second socket reader, TCP bootstrap,
automatic carrier fallback or privilege/device setup in these constructors.

The runtime establishment module supplies the reviewed bootstrap framing,
cookie/retry service and original absolute deadline described in
[UDP establishment](secure-udp-establishment.md). Its opaque root handoff is
only Noise completion, not existing-member authentication or user readiness.
Caller-supplied public binding digests alone do not prove member possession.

Before accepting user records, preserve the existing Ed25519 client membership
requirement using the pure [session identity](session-identity.md) proof. The
server's trust anchor for this UDP profile is an explicitly provisioned pinned
X25519 responder key; no arbitrary certificate or cover name grants trust.
The existing member key is not reinterpreted as an X25519 secret. TLS certificate
and configurable SNI requirements remain separate for their selected carriers.

Draft ownership flow:

```text
connected original socket + explicit Noise/admission trust + original deadline
  -> bounded return-path admission and Noise establishment
  -> reserve independent AEAD Joining owners from the authenticated root
  -> retain the root until actual allowlisted Ed25519 proof / server acceptance
  -> create common User/Control records and fixed bounded control service
  -> authenticated original-socket transport, with bounded bootstrap/joining tails
```

`SessionRoot::binding()` exposes only the authenticated public session ID and
final Noise transcript. That value is signed as public context, never used as a
secret key. Joining proof traffic uses the separately derived Joining purpose,
fixed epoch/configuration and AEAD, independent of the later generic data suite.
An authenticated User record cannot become a joining proof or management source.
The establishment handoff also retains `authenticated: handshake::Binding`, the
exact public prologue supplied to Noise, including its derived outer binding.
Membership validates configuration, carrier and outer context against that
actual authenticated handoff rather than trusting a second caller assertion.

The establishment and identity APIs compose through this reviewed
`secure_udp::member` runtime interface, recorded before implementation:

```rust,ignore
Settings { context: identity::Context, retry_interval: Duration,
           max_attempts: u32, receive_interval: Duration,
           receive_packets_per_interval: u32 }
async fn connect(established: establish::Established,
                 member: &identity::IdentityKey, settings: Settings)
    -> io::Result<Authenticated>
async fn accept(established: establish::Established,
                members: identity::Allowlist, settings: Settings)
    -> io::Result<Authenticated>
Authenticated::info(&self) -> Info
Authenticated::into_parts(self) -> Parts
Parts { socket, root, cover, bootstrap: establish::BootstrapTail,
        joining: JoiningTail, next_outer, deadline, info }
JoiningTail::receive(&mut self, cover::Decoded<'_>, Instant) -> io::Result<bool>
JoiningTail::poll(&mut self, Instant, cover::PacketMeta, &mut [u8])
    -> io::Result<Option<usize>>
JoiningTail::deadline(&self) -> Option<Instant>
```

`Info` exposes only member identity, public session/transcript and exact Noise
prologue bindings, fixed Noise peers and original socket addresses. `Parts` transfers every retained
owner to the eventual sole data/control reader; dropping its tails before their
deadlines invalidates the claimed final-response service. It transfers no cloned
key or recreated root. This API is runtime establishment/member admission, not
the complete selected client profile. The shared client/service owns later
device and lifecycle integration; it cannot become a private CLI path.

Joining records use established-phase covered bodies `[route=3][common AEAD
record]`, fixed Joining epoch 1, lane 0 and the context configuration digest.
Additional authenticated metadata is exactly the route byte. The client sends
the strict 98-byte member proof; the server's encrypted acceptance body is
`[version=1][kind=2][accepted member public key 32]`. Each side seals its one
joining flight once at packet number zero. Retries copy that exact protected
record, with a newly numbered appearance header. Proofs arriving before the
opposite Noise handoff are retransmitted; no third socket or public-hash MAC is
introduced. These tags and draft grammar are implementation choices, not owner
wire-format decisions or a replacement for stable post-admission management.

After server root release, its tail remembers only the previously authenticated
proof ciphertext and cached encrypted acceptance. An exact duplicate may schedule
the same acceptance at the configured bounded retry interval; other joining
input receives no reply. No secret Joining owner is needed after that handoff.
The client releases its root only after authenticating the acceptance and checking
its own member identity. All cache sends consume the unchanged operation deadline
and finite attempt allowance. No cache retry resets the appearance counter or
the independently owned data/control counters.
Retry and receive intervals are positive and at most one second. Sending
attempts and admitted packets per receive interval are independently bounded to
1..=1024. Exhausted receive quota waits for refill or the unchanged expiry;
invalid packets cannot create unlimited crypto work in a ready-read loop.

## Deadlines, tails and failure behavior

One accepted absolute deadline covers admission, Noise and member proof. Every
retry, cached output, parse loop and send wait is bounded by that deadline.
Malformed unauthenticated packets have bounded work and cannot reset timers or
release keys/data. Definitive authenticated member/configuration failure retires
the attempted session; cancellation drops the original owners.

Lost final responses require retained exact ciphertext custody after local key
handoff. Bootstrap and member-acceptance tails remain owned by the single session
reader through their original deadline, with bounded retry work/bytes. Duplicate
admission must not perform crypto again, renew a deadline, create another root,
reset replay state or fabricate liveness. Later session expiry, fresh exchange,
peer-restart reconciliation and automatic retained-state recovery remain required
separate lifecycle work; this constructor must not describe a new key ratchet as
that recovery.

## Integration and validation ledger

- [x] [SUDP-01] Freeze the runtime trust, framing, root custody, joining proof/acceptance and single-reader tail APIs before implementation; retain all original carrier/mode/platform requirements. Evidence: this custody/API design preceded the [member implementation](../../crates/l2tunnel-runtime/src/secure_udp/member.rs); all parent carrier/mode/platform gates remain intact. See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [SUDP-02] Extract existing Ed25519 parsing/signing/allowlist behavior into the pure identity library, retaining byte-exact legacy TLS and HTTPS proof behavior through compatibility wrappers. Evidence: the [pure identity library](../../crates/l2tunnel-identity/src/lib.rs), delegated auth/HTTPS wire parity and retained transport tests passed. See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [SUDP-03] Compose actual same-connected-socket admission/Noise and protected member proof/acceptance; neither side releases user transport before its required authentication evidence exists. Evidence: the [member owner](../../crates/l2tunnel-runtime/src/secure_udp/member.rs) and [real factory test](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) release actual Noise roots only after the required protected proof/acceptance. See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [SUDP-04] Preserve exact final-flight custody and original operation deadline through loss, duplicates, malformed traffic, blocked output, cancellation and asymmetric completion; bound pre-authentication work and post-completion tails. Evidence: the [11 member regressions](../../crates/l2tunnel-runtime/src/secure_udp/member_tests.rs) cover cached final acceptance, cancellation, floods, blocked/late completion, original expiry and distinct bootstrap retry exhaustion. See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [ ] [SUDP-05] Exercise real two-runtime original-socket transport for both appearance selections, wrong member/key/context rejection, no early user/control authority and exact protected bytes; keep protocol fixtures separate from actual shared-client/native qualification. Partial evidence: independent Tokio runtimes are exercised through real Noise/tail handoff in the [establishment tests](../../crates/l2tunnel-runtime/src/secure_udp/establish_tests.rs); full member and Swift/control factory composition currently runs within one runtime. The complete two-runtime member/data/control deliverable remains open.
- [x] [SUDP-06] Run focused checks and the required frozen-source aggregate; record exact commands, input identities and remaining lifecycle, CLI/native and cross-platform limits. Evidence: focused runtime/client checks and the full aggregate passed with stable inputs; native/service, restarted peers and cross-platform execution remain outside this finite scope. See [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [ ] [SUDP-07] Integrate the authenticated owner with the shared CLI/GUI service, reusable full Swift record engine and every other requested composition; qualify native performance, complete SW-11, default bounded recovery and controlled ISP/QoS behavior without reducing any parent gate.

The parent owns this document, runtime module declarations, manifests, facade,
legacy auth wrappers and integration consumers. Workers own their disjoint
establishment, identity and Swift-record files. Simulator history and saved
experiment receipts remain unchanged.
