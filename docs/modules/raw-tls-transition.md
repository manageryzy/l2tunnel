# Authenticated raw TLS freeze and peer transition

Status: design checkpoint awaiting review; no implementation or native activation.
The [tracked owner and switchable driver](raw-owner-handoff.md) prove local
ownership using maintained TCP and mock packet I/O. This document specifies the
missing TLS, peer and ingress boundaries needed by the experimental
[raw packet phase](raw-packet-phase.md). Retained TCP/TLS remains the default.
The packet phase is custom TCP-shaped datagrams; it does not retain RFC TCP or
HTTPS semantics and does not guarantee passage through middleboxes.

## Scope and original ownership

The first integration establishes and authenticates the original raw connection,
pairs its lanes, then transitions before admitting any native packet. This avoids
pretending that current type-erased runtime links can be recovered into their
original TLS objects. Switching a running native session is a separate gate:
that later path must additionally prove exact admitted, recovery-owned, handed,
flushed and native-confirmed fences, including retained WouldBlock packets.
Zero startup counters are valid only because the owner has never admitted native
input; a caller-provided `empty: true` assertion is not a proof.

A new runtime owner must construct each lane from birth. It owns the original
packet I/O, classifier wrapper, switchable bridge, tracked stream, real
`AuthenticatedIo`, unique switch handle and driver task. It never accepts an
independently supplied authenticated stream plus a possibly unrelated handle.
Failure or cancellation joins/aborts every owned worker. No detached driver,
mutable raw handle, adopted counter snapshot or status-to-capability conversion
is exposed. The original mark and reserved local tuple move with the I/O owner;
the numeric mark remains local, while the marked-policy kind is authenticated.

The proposed shapes below are review targets, not existing public APIs:

```rust
// Runtime boundary; names and generic auth arguments await the freeze gate.
pub struct RawLane<I> { /* original authenticated TLS, bridge and driver owners */ }
pub struct PairedRaw<I> { /* exactly one full or two ordered half lanes */ }
pub struct Transition { /* validated policy and one original absolute deadline */ }
pub struct FrozenTls { /* original TLS object; no AsyncRead/AsyncWrite/accessor */ }
pub struct PacketSession<I> { /* all original I/O owners, frozen TLS and keys */ }

// Factories construct bridge and TLS together; no public adoption constructor.
async fn authenticate_raw<I: PacketIo>(/* original I, raw/auth config, deadline */)
    -> Result<RawLane<I>, SetupError>;
async fn pair_raw(/* actual owned lanes, role, original setup deadline */)
    -> Result<PairedRaw<I>, SetupError>;
async fn transition(owners: PairedRaw<I>, policy: Transition)
    -> Result<PacketSession<I>, TransitionFailure<I>>;
```

Before either lane can Seal, pairing must authenticate the ordered lane IDs,
both actual TLS session IDs, member/server identities, complementary roles and
full/half configuration. Existing generic `runtime::client_pair/server_pair`
consume streams into a type-erased `Link`; they cannot be used and then reversed.
A narrow typed pairing helper may factor their existing authenticated exchange
while retaining the actual streams. Its output and new all-lane transcript need
review before changing shared APIs. Reconstructing TLS from exporters or session
metadata, or using an assertion-based channel constructor, is excluded.

Use the actual `auth::client_connect_io/server_accept_io` TLS and member
verification path. The raw transition policy has a distinct canonical digest
domain that binds version, all lane roles, packet protection, MTU/MSS policy,
recovery, common MUX, resource/deadline bounds and custom retirement semantics.
Export direction/lane/purpose-separated keys while the authenticated TLS owner
is still accessible; retain zeroizing key owners. Pair information and the fresh
transaction ID are also authenticated in the transition messages. Never reset
a counter or import a peer-provided counter into a local sealer/opener.

## TLS freeze proof: an explicit feasibility gate

The inspected maintained versions are rustls 0.23.45 and tokio-rustls 0.26.5,
as pinned in [Cargo.lock](../../Cargo.lock). Current public TLS operations are
insufficient by themselves to assert an empty inbound deframer:

- `AuthenticatedIo::into_parts` returns the same `TlsStream` and session info;
  it does not prove TLS quiescence. Retain the complete original tokio-rustls
  object, including its wrapper state, rather than splitting it with
  `TlsStream::into_inner` and reconstructing it later.
- A completed top-level TLS `flush` drains rustls output and flushes its actual
  underlying stream. It is not a physical TCP ACK proof; the existing
  `SwitchDriver` counters and maintained snapshot supply that separate proof.
- `wants_write == false`, `is_handshaking == false`, and zero buffered plaintext
  do not expose partial encrypted records or fragmented post-handshake messages.
  `process_new_packets` returns `IoState` with output/plaintext lengths and peer
  close status, but it is a mutating processing operation, not a public read-only
  snapshot of those private buffers. An extra AsyncRead may itself receive more
  ciphertext, process KeyUpdate, or queue output.

The review must resolve one of these concrete approaches before producing any
`FrozenTls` capability:

| Candidate | Required investigation and evidence |
| --- | --- |
| Maintained read-only TLS seam | Enumerate rustls input deframer and handshake-fragment state, queued plaintext/output, pending key-update/alert work, terminal state and negotiated TLS 1.3. Propose an exact additive maintained API, provenance and tests separately. No registry mutation, private-layout access or new vendoring is authorized here. |
| Record-bounded I/O from birth | Prototype an owned adapter below TLS and above `TrackedStream` that observes the five-byte record envelope, bounds its declared length, and never returns bytes past the current record boundary in one read. It must preserve exact partial/Pending accounting with fixed metadata and no untrusted-size allocation. Investigate whether successful terminal application-record processing, zero application remainder and this boundary witness exclude both encrypted-record and post-handshake fragments in the pinned maintained implementation. |

The second candidate observes framing only. It must leave all decryption,
version/content-type acceptance and handshake validation to rustls; it is not a
second TLS implementation. The inspected tokio-rustls read path processes newly
read ciphertext before offering plaintext, and rustls rejects interleaving an
application record with a partial handshake message. Those observations motivate
the investigation, but are not yet a complete freeze proof. Test an extra record
and every partial header/body suffix behind Seal, same-record extra plaintext,
fragmented Seal, fragmented KeyUpdate, queued responses, empty records and close
alerts. A plain stream-byte counter without the record-boundary restriction is
insufficient. If neither approach establishes the proof, the transition remains
unavailable and retained TCP/TLS remains usable.

The eventual private freeze routine requires the final local Seal write and
actual top-level flush, the exact peer Seal parsed and authenticated, no parser
remainder or unread plaintext, no pending TLS output, no EOF/close_notify/error,
and the reviewed backend/framing proof. Only that owner can construct
`FrozenTls`. It then stops all TLS polling, requests the matching stream freeze,
and retains the entire original object. It never calls shutdown, sends
close_notify, or consumes hidden bytes merely to satisfy a counter equality.
Pending post-handshake work must be resolved before the terminal boundary or
cause failure; it cannot be silently discarded after Seal.

## Feasibility investigation checkpoint

A [scratch investigation](../../work/raw-tls-freeze-feasibility-20261112/REPORT.md)
on 2026-11-12 passed 15 actual TLS tests over the original counted bridge and
finite mock packet I/O. The [receipt and source hashes](../../work/raw-tls-freeze-feasibility-20261112/receipt.json)
record that no handoff was requested, no member/pair authentication was tested,
and no production freeze API or native activation exists. Strict scratch Clippy
passed. These results are separate from workspace aggregate evidence.

The simple record-boundary predicate is **refuted**. A tokio-rustls AsyncRead
with spare plaintext buffer capacity can consume a following partial TLS header,
a complete encrypted record holding a partial handshake, or even a deferred TLS
error after returning Seal. Record alignment plus empty public IoState is not
sufficient. Exact remaining-length plaintext reads prevented read-ahead for all
26 prefixes of a following encrypted record, leaving those bytes beyond the
original counted endpoint fence. Same-record extra plaintext remained visible
without additional I/O. Valid post-handshake tickets fragmented at all 17 split
points were accepted; incomplete handshake interleaving before Seal was rejected.

The tests also reproduced a deferred KeyUpdate response that is invisible to
`wants_write`/IoState and survives a successful top-level TLS flush. A public
**backend** `connection.writer().write(&[])` materialized that response without
admitting application bytes or changing the original ciphertext-write fence.
This is a mutating materialize-and-reject check, not an observation. Any output
it exposes after terminal Seal must fail the proposed freeze; it must not be
silently sent or discarded. The same check emitted nothing on the clean case,
and both endpoint roles reproduced the deferred-output behavior.

The report records exact pinned-source locations and a refined candidate based
on from-birth record observation, exact plaintext framing, public error/remainder
checks, deferred-output rejection and retention of the complete original TLS
wrapper. That candidate still needs independent review and production bounds,
partial/Pending/cancellation tests and actual owner-bound integration. No new
rustls seam or production API is authorized by the scratch checkpoint; all
implementation gates below remain open.

The next [bounded record I/O checkpoint](raw-record-io.md) proposes only the
from-birth envelope observer and exact resource accounting. Its design requires
review before implementation; Seal parsing and the TLS owner remain separate.

## Bounded two-peer transaction

Use one coordinator, one transaction ID and the same original local absolute
deadline for the entire all-lane attempt. Each peer starts its own deadline when
it initiates or accepts the first valid Prepare; peer clock values cannot extend
it. Preparation, TLS flush, raw ACK drain, worker joins, Hello and Commit all use
the remaining allowance. Check live time before and after awaited operations and
again after synchronous consume/allocation before publishing success.

The initial negotiated profile fixes at most two lanes, a 30-second transition
bound, 250-ms retry interval and at most 32 logical control attempts per stage.
An earlier configured deadline wins. There is no timeout renewal on duplicates,
raw ACKs, progress notifications or WouldBlock. Maintain explicit partial
write/read offsets; retrying an interrupted TLS write from byte zero is forbidden.
TLS already provides stream retransmission, so a phase retry begins only after
its previous complete application message was handed and flushed.

| Stage | Required action and boundary |
| --- | --- |
| Prepare | Exchange fixed-version bounded transaction, policy digest, ordered actual lane identities and fixed resource ceilings over original TLS. Validate and stage all allocations before acceptance. Native admission is closed. |
| Armed | Install the classifier on every original raw lane and obtain local installation acknowledgments. Exchange the all-lane Armed transcript over original TLS. No peer sends a terminal Seal until both Armed sets match. |
| Seal | Send one terminal Seal per original TLS lane, naming the transaction, complete Armed transcript and the startup native fence. Parse its peer counterpart on that lane and complete the reviewed TLS freeze proof. No subsequent TLS application message, including Abort, is legal. |
| Prefix drain | Request the matching `SwitchHandle` using the remaining original deadline expressed on that driver's actual start clock. Await every actual `SwitchExit::Handoff`; copied status or a finished TLS flush cannot substitute. |
| Hello | With transferred I/O, send protected Hello carrying the actual final ciphertext counts and maintained frontiers for each lane plus the complete pair transcript. Check complementary remote/local fences before any Commit. |
| Commit | Coordinator commits the complete matching lane-proof digest. Follower validates every lane and sends bounded protected CommitAck. Coordinator validates CommitAck. Both retain idempotent reply state through the fixed transition deadline. |
| Active | Coordinator may admit after validated CommitAck; follower may admit after its CommitAck has actually been accepted by packet I/O. The earlier peer must retain at most one authenticated early data packet per lane until its local all-lane activation checks complete. All packets still use the common admission/budget policy. |

A local all-lane commit is atomic; the network cannot supply simultaneous peer
knowledge. A lost CommitAck may leave one peer committed while the other waits.
The responder remains available for bounded retries, but expiry is an explicit
uncertain failure and never permits same-tuple rollback. No user frame is
released on a lane whose local all-lane commit is incomplete.

Seal does not contain its own final ciphertext length. The actual endpoint totals
are measured after the terminal exchange and compared in protected Hello. On each
lane, local frozen-written must equal peer frozen-read, and local frozen-read
must equal peer frozen-written. Maintained local `snd_nxt == snd_una` must match
peer contiguous `rcv_nxt`, and the reverse equality must also hold, using the
exact wire sequence values. The positive duplex ciphertext prefixes establish
post-SYN window advertisements before interpreting scaled windows. Peer tuple
addresses are not compared as identical bytes across NAT; locally configured
tuples remain strict. Sequence-rewriting ALGs and migration are unsupported.

The existing bridge proof additionally requires both stream-direction equalities,
empty retained queues and raw popped bytes/packets equal to actual successful
atomic sends. Physical send acceptance is not peer receipt. Logical snapshots
use the maintained checked poll time; this is not an atomic wall-clock snapshot.
All no-wrap/horizon/window restrictions from the packet-phase design still apply.

## Classifier, quarantine and packet ownership

The proposed `PhaseGateIo<I>` wraps the original packet I/O before bridge
construction. An opaque installation handle is tied to that exact wrapper;
arming it cannot replace `I`, read the socket concurrently or install caller
snapshot values. Before arming it delegates the retained path. After handoff,
the same wrapper, quarantine, opener/replay state and original `I` move inside
the unique `HandoffParts`. No observer owns another receive loop.

At most one physical receive owner parses an IP/TCP packet. Validate exact local
tuple, complete lengths, checksum, supported flags/options and configured MTU
before bounded crypto. A plausible protected prefix only selects an attempt; it
never proves the phase. Use existing `PacketOpener::open_checked` to authenticate,
validate context and proposed phase grammar, and reserve a destination before
committing replay/usage/output. Wrong-header mirrors, wrong transaction/lane,
malformed authenticated bodies and exhausted destination capacity cannot burn
an otherwise valid packet number. There is no second replay implementation.

Before local consume, only an authenticated Hello is a legal quarantined control.
It is provisional until the local snapshot exists: validate its protected header
against its claimed base, then compare the complete complementary proof after
handoff. Do not feed it into smoltcp or rustls while waiting. Reserve one bounded
Hello slot per lane, coalescing only byte-equal logical duplicates with fresh
valid packet numbers; a conflicting authenticated proof fails the transaction.
Other authenticated transition messages arriving at an impossible stage fail.
After local consume use a fixed control queue, never an unbounded early-packet
list. Reserve one separate maximum-MTU early-data slot per lane for the
commit/activation race; capacity rejection preserves opener state.

Unknown/unauthenticated ordinary retained traffic continues through the maintained
TCP path subject to its limits. A candidate that cannot be authenticated because
the per-turn crypto budget is exhausted is dropped or retained in an already
reserved finite input slot; it must not be forwarded to the old stream merely
because crypto was deferred. An authenticated phase candidate rejected for stage,
format or capacity must likewise never fall through into TLS. This can delay
retained traffic that resembles a candidate; it cannot create unbounded work or
a magic-prefix authentication bypass. Flooding and accidental prefix collision
need focused tests.

The proposed transition budget is at most 32 receive/crypto operations per
service, four queued control records per lane, one Hello slot and one early-data
slot per lane, each bounded by the configured IP MTU (at most 1500 for v1), plus
one retained outbound packet per lane. Derive and check the total allocation
before arming; no allocation follows an untrusted record length. All transition,
old-prefix and later recovery/user sends share a finite aggregate outbound
allowance with bounded control reservation. WouldBlock retains the exact sealed
packet, nonce and reserved outer range; retry cannot create a new cryptographic
copy until the original owned send is resolved. A real new logical retry receives
a fresh nonce and outer range under the existing key-use limits.

Classifier counters distinguish physical receive, retained-engine admission,
quarantined phase input, crypto/stage/capacity drops and actual sends. Existing
bridge raw-receive counters do not include packets intercepted inside the wrapper;
report both boundaries honestly. No classifier acknowledgement or queue dequeue
counts as a physical send or native delivery.

## Late old-prefix responder

Local consume can finish while the final bootstrap ACK is subsequently lost.
Therefore each detached lane must retain an explicit small responder until the
original transition deadline. It is not a second maintained TCP engine, and it
never reopens TLS. Its only retained authority is the unique immutable bootstrap
snapshot, exact consumed prefix lengths and original tuple/options policy.

A valid duplicate with payload entirely within the actually consumed bootstrap
range may elicit an ACK of the exact sealed `rcv_nxt`, with the sealed send
frontier and last advertised window. Perform unambiguous checked range tests;
reject a prefix too large to represent safely in the negotiated sequence horizon.
Do not infer receipt from a sequence high-water or acknowledge a segment crossing
the sealed boundary. New payload, SYN, FIN/RST, unsupported options, bad checksum,
foreign tuple or ambiguous wrap cannot extend the old range. ACK-only input does
not solicit ACK-of-ACK responses or modify phase retirement/liveness.

Use one coalesced reply slot, at most four replies per second with burst one, the
shared aggregate outbound budget and the unchanged original expiry. Retain a
WouldBlock reply exactly; count only actual successful sends. No cleanup reset,
pretend send, suppressed errno or driver clean-close claim is permitted. The
same physical owner services the old responder and new phase; no concurrent
socket reader or recreated connection exists. Old replies prove only the old
contiguous prefix and cannot release new-phase/recovery/native credit.

## Failure and cancellation contract

Before Seal, allocation/validation rejection leaves the original retained owner
intact. Resuming retained traffic requires a coordinated Abort/AbortAck proving
both peers are still pre-Seal; rejection alone is not permission to resume. A
lost/uncertain Abort, any locally emitted or received Seal, frozen bridge, consumed
lane or protected phase output makes the transition irreversible for this tuple.
If one lane fails after another transfers, terminate the complete paired session;
do not run a mixed retained/packet session.

`TransitionFailure` must distinguish reusable pre-Seal ownership from terminal
failure. A reusable variant contains the same original all-lane owner, and can
be created only after the authenticated abort proof. A terminal variant reports
failure and bounded cleanup completion, never a reconstructed owner. Caller
cancellation before that returned proof is terminal even if no local Seal was
observed: the caller cannot infer what the peer received. Future fallback opens
a fresh independently negotiated connection; it does not reuse this tuple's
sequence/TLS state.

Every terminal path cancels and joins all tasks, retains ownership until cleanup
or the fixed cleanup bound, and drops packet I/O outside shared locks. Preserve
original I/O error kinds/errno and stage diagnostics without keys or user bytes.
Dropping the frozen TLS wrapper does not poll shutdown; dropping capabilities
does not generate FIN/RST. A timed-out task or local ownership handoff is not a
successful clean TCP close. Existing retained clean-close behavior stays separate.

## Required implementation and validation gates

All work below is planned. Existing local mock handoff evidence does not check
any box here. The failed source-stable wave 10 aggregate remains a failed receipt;
it does not establish the new contract or revoke the focused raw mock results.

- [ ] [MOD-RAWTRANS-01] Review this ownership, startup-only scope, all-peer transaction, finite budgets and no-rollback contract before implementation.
- [ ] [MOD-RAWTRANS-02] Resolve and independently review the exact TLS freeze feasibility proof using maintained buffer inspection or a bounded record witness; test actual TLS and all partial/post-handshake cases before exposing a capability.
- [ ] [MOD-RAWTRANS-03] Implement from-birth raw/auth ownership and typed full/half pairing with actual session/role/config binding, original setup deadline and complete cancellation cleanup.
- [ ] [MOD-RAWTRANS-04] Implement pre-Seal authenticated ingress classification and bounded quarantine with no replay/output mutation on rejected metadata/capacity, and no authenticated candidate entering the old TCP stream.
- [ ] [MOD-RAWTRANS-05] Implement all-lane Prepare/Armed/Seal and exact frozen TLS-to-driver ownership; test mismatched bridges, wrong pair/order, unread plaintext, partial writes, KeyUpdate/alert/EOF and actual final ACK WouldBlock.
- [ ] [MOD-RAWTRANS-06] Implement and test the old-prefix responder under lost final ACK, stale/crossing/ambiguous ranges, spoofed flags, rate/budget exhaustion and unchanged absolute expiry.
- [ ] [MOD-RAWTRANS-07] Implement protected Hello/Commit/CommitAck with complementary measured fences, duplicate/conflicting controls, one-sided completion, queued early data, all-lane failure and no sequence/nonce reset.
- [ ] [MOD-RAWTRANS-08] Test cancellation at every ownership boundary, original deadline at/after ready operations, fixed memory/work counters, retained generic I/O destruction outside locks and no false clean result.
- [ ] [MOD-RAWTRANS-09] Independently review source, run focused tests/strict lint/docs and a source-stable workspace aggregate before integration qualification.
- [ ] [MOD-RAWTRANS-10] Review a separate immutable native experiment; qualify same original descriptors/tuples and continuous bootstrap sequence, actual prefix ACKs, zero unintended FIN/RST and bounded both-peer outcome. No native run is authorized by the design checkpoint.
- [ ] [MOD-RAWTRANS-11] Separately design and qualify transition of an already-running native session with nonzero recovery/native fences; startup-only transition cannot satisfy this gate.
