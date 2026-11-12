# Authenticated raw TCP packet-phase proposal

Status: design only. The custom semantics and authoritative snapshot approach
were reviewed; the concrete dependency seam below awaits separate review.
The maintained-stack getter was separately reviewed, tested and activated in
the pinned local dependency; actual ownership transfer is still unimplemented. No raw handoff, new carrier,
client option or native packet-phase test is implemented. The retained
`TcpEngine`/TLS stream remains the default RFC TCP carrier. Its historical failed
and successful receipts remain separate from this proposed mode. The recent
[marked native audit](../../work/raw-native-marked-audit.json) does not qualify
packet-phase performance, neighbor-discovery latency or middlebox passage.

## Decision and compatibility boundary

An ACK-independent *recovery* path is feasible only if we distinguish recovery
of tunnel records from the meaning of TCP header ACKs. For standard TCP, the
sender has a finite window, and cumulative acknowledgment advances over received
bytes in sequence. A missing range blocks cumulative progress. Ignoring every
ACK eventually exhausts the usable window; increasing the window only postpones
that point. [RFC 9293 §§3.4, 3.8.6, 3.10.7](https://www.rfc-editor.org/rfc/rfc9293.html)

| Candidate | Reliability and window ownership | Decision |
| --- | --- | --- |
| Retained TCP/TLS | Maintained smoltcp retransmission, ACKs, congestion and receive window | Existing default; preserve it |
| Sparse ACKs with true cumulative TCP semantics | Missing outer bytes still require exact reconstruction/retransmission before the cumulative window advances | Possible separate experiment, but it retains outer reliability and can duplicate the existing inner ARQ; not this first packet phase |
| `raw_packet_v1` | Independent protected packets and existing tunnel recovery; authenticated high-water retirement may skip missing outer byte ranges | Proposed explicit experimental profile; custom TCP-shaped datagrams, **not RFC TCP** |

For `raw_packet_v1`, each first transmission continues the original tuple and
increments the original TCP sequence by its actual payload length. A receiver
can retire a hole in this *outer numbering* when a later authenticated packet
arrives. Its emitted TCP ACK then represents that custom retirement frontier,
not proof that every preceding outer byte was received. The fields can remain
within a negotiated numeric window while violating TCP cumulative semantics.
A stream-validating firewall, proxy or sequence-normalizing middlebox can reject
this traffic. No combination of plausible headers, a real earlier TLS handshake
or an arbitrary certificate name proves HTTPS equivalence or universal passage.

The profile minimizes dependence on header ACKs; it does not promise operation
without reverse traffic. Authenticated retirement/window reports periodically
replenish a finite sending horizon. Tunnel ARQ/FEC feedback, logical receiver
credit and carrier byte retirement remain three different mechanisms. A header
ACK alone never acknowledges an ARQ source or a native packet.

## Inspected implementation and feasibility gate

The current [pure engine](../../crates/l2tunnel-raw-tcp/src/lib.rs) owns one pinned
smoltcp 0.14.0 socket, IP interface, finite packet queues and rings. Its public
`status()` reports state and queue sizes; `pop_packet()` transfers one exact raw
packet to the caller. The current [Driver](../../crates/l2tunnel-raw-io/src/lib.rs)
retains that packet across WouldBlock, separately retains bridge input/output,
and consumes itself in `run()`, returning counters only after actual clean close.
A Tokio duplex flush proves bridge acceptance, not peer TCP acknowledgment.

The inspected pinned smoltcp `socket/tcp.rs` exposes state, endpoints, ring sizes,
ACK policy and `timestamp_enabled()`. Sequence frontiers, window scales, peer
MSS, negotiated SACK, last window and timestamp state are private; even
`flight_size()` is private. `send_queue() == 0` is useful but is not a complete
transferable connection state. There is currently **no safe supported handoff**.

Compare two ways to obtain one:

| Approach | Needed proof | Decision |
| --- | --- | --- |
| Minimal maintained-stack quiescent snapshot | Authoritative ESTABLISHED state, exact send/receive frontiers, no outstanding/assembled bytes, negotiated options/window state, no FIN/RST or pending output obligation | Preferred; propose a narrow reviewed upstream/public getter or consume seam, pinned and tested before integration |
| Independent packet observer | Reimplement SYN/options parsing, accepted ACK/window updates, wrap, retransmissions, out-of-order assembly and actual-send versus queued-send distinctions | Useful for independent auditing only; do not make a second TCP implementation authoritative |

No private-layout access, unsafe extraction, timer rewriting or silently vendored
fork is approved. If a supported complete snapshot cannot be obtained, this
phase remains blocked at feasibility and retained TCP continues working. Any
upstream/dependency edit requires a separate review. New public names below are
proposals, not existing capabilities.

The snapshot must include local/peer tuple, authoritative `snd_una`, `snd_nxt`,
contiguous `rcv_nxt`, last emitted ACK/window, accepted peer window, both window
shifts, peer MSS and supported option state. It must prove no receive assembler
ranges, send/ring bytes, pending ACK/timer output or FIN/RST. The pinned socket
has no retained original ISNs or ECN-negotiation field; do not invent either in
an upstream getter. The driver adds checked complete TLS ciphertext/bridge counts,
queued raw packets and its retained WouldBlock packet. Snapshot sequence fields
are not cryptographic packet numbers. See the [concrete stack seam proposal](raw-stack-handoff.md).

## Proposed ownership API

Keep existing `TcpEngine`, `bridge`, `open`, `open_marked` and `Driver::run`
semantics unchanged. Add a separate switchable owner only after review:

```rust
// Pure raw TCP boundary; exact concrete type names await the snapshot gate.
TcpEngine::try_into_quiescent(self, request: BootstrapFence)
    -> Result<QuiescentTcp, (TcpEngine, HandoffError)>;
QuiescentTcp::snapshot(&self) -> &BootstrapSnapshot;
// No Clone; failure returns the original owner. Success never calls close/abort.

// Runtime/OS boundary; original PacketIo, raw descriptor and reservation survive.
bridge_switchable(config, role, io, limits)
    -> Result<(TrackedStream, SwitchHandle, SwitchDriver<I>), io::Error>;
SwitchDriver::run(self) -> Result<DriverExit<I>, io::Error>;
// DriverExit::Handoff(HandoffParts<I>) is distinct from DriverExit::Clean(...).
// HandoffParts owns I, the unique quiescent capability, fixed old-prefix
// responder state and actual bootstrap counters. It does not expose a new socket.

// Proposed pure l2tunnel-raw-packet module, injected time and finite work.
PacketEngine::new(capability, authenticated_config, key_material, now)
    -> Result<PacketEngine, PhaseError>;
PacketEngine::prepare(kind, payload, &mut common_wire_budget, now)
    -> Result<Prepared, PhaseError>;
PacketEngine::pending_packet(&self) -> Option<&[u8]>;
PacketEngine::confirm_transmitted(&mut self, now) -> Result<(), PhaseError>;
PacketEngine::ingest(&mut self, complete_ip_packet, now, work_budget)
    -> Result<Ingress, PhaseError>;
PacketEngine::status(&self) -> Status;
```

`TrackedStream` counts actual ciphertext bytes accepted on each bridge direction.
It must expose a freeze operation rather than interpret caller EOF as handoff.
The supervisor owns TLS, driver and all handles together; no detached task keeps
polling the old stack. On successful transfer, no drop/shutdown path sends FIN,
RST, TLS close_notify or a second SYN. The same `RawSocket`, SO_MARK and unmarked
port reservation move into the new owner. Cancellation at any partial transfer
closes the owned capability and reports failure; it never reports a clean drain.

`prepare` retains one complete sealed IP packet. WouldBlock returns the same
bytes and consumes no additional sequence range, nonce, recovery copy or wire
reservation. Only an exact successful atomic send permits
`confirm_transmitted`. A partial send is an error. Counts distinguish reserved,
sealed and actually sent bytes; a syscall failure preserves the original errno.
No public constructor accepts caller-invented sequence snapshots.

## Authenticated transition and late bootstrap traffic

The initial member-authenticated configuration digest binds the packet-phase
version, full/paired-half role, lane set, protected-datagram suite/header profile,
MTU and MSS policy, recovery configuration, MUX, all resource/deadline limits,
window-retirement semantics and marked-policy kind. The numeric SO_MARK stays
local. Pairing binds both TLS session IDs, roles and lane IDs before either lane
can switch. One coordinator changes the complete paired session, not one lane
silently. Export existing purpose/direction/lane-separated data and management
secrets while the original authenticated TLS object is still owned.

1. **Prepare over original TLS.** Exchange a fixed-version transaction ID,
   matching digest and proposed resource ceilings. Stage every allocation and
   install a bounded authenticated phase-candidate demultiplexer on every raw
   lane. Stop new native admission; retain any already owned native input.
   Both peers remain on normal TCP/TLS until all allocations and pairing pass.
2. **Drain and arm.** Drain accepted native/recovery output and all runtime
   queues with exact admitted/handed/native-confirmed fences. Exchange terminal
   `Seal` application records over each original TLS lane. After its own Seal
   and the peer Seal, no new TLS application record is permitted. Freeze and
   retain TLS; do not reconstruct TLS from an exporter or emit close_notify.
   Any pending TLS post-handshake output, ciphertext, unread application bytes
   or unexpected extra record prevents the proof. The current server disables
   tickets; the general TLS freeze still needs tests for queued KeyUpdate/alerts.
3. **Prove the exact TCP prefix.** Drive the old owner until every ciphertext
   byte through Seal has a real maintained TCP ACK, both contiguous receive
   prefixes were consumed by TLS, both bridge directions are empty, and all
   generated raw ACK/output packets were actually sent. Require
   `snd_una == snd_nxt`, empty rings/assembler/packet queues and no pending
   native send. Checked complete ciphertext counts and complementary peer
   snapshots must agree. Candidate ISNs reconstructed from those counts are
   derived values, not independent SYN evidence; the stack's empty acknowledged
   send ring establishes the prefix ACK proof, not a custom high-water ACK.
4. **Consume once and exchange snapshot proofs.** Transfer the original raw
   owner without FIN/RST. Send a protected `PhaseHello` containing transaction,
   digest and both bootstrap frontiers. Exact complementary send/receive fences
   must match. Header sequence begins at `snd_nxt`, never at zero/new ISN.
   Both peers must see all matching lane proofs before sending Commit.
5. **Commit and activate.** Use bounded idempotent Commit/CommitAck records
   under the exported packet keys. User data remains frozen until all local
   lane commits are confirmed. A peer in the committed/pre-activation interval
   may retain at most one authenticated early data packet per lane in already
   reserved storage; it cannot deliver it before activation. Conflicting,
   future or mismatched proofs fail the whole session.

Step 2 must not predict the ciphertext size of the record carrying its own
fence. Final byte fences are measured after Seal and compared in step 4. This
avoids self-referential TLS length assumptions. The demultiplexer is armed
*before* Seal: an early valid PhaseHello is quarantined and cannot accidentally
enter rustls or smoltcp as TLS stream bytes. Classification requires valid
phase-domain authentication, not magic-prefix resemblance; its crypto work and
queue slots are bounded. Unauthenticated input cannot trigger handoff.

After transfer, retain only a finite old-prefix responder, not a second live TCP
engine. An exact-tuple validated duplicate entirely before the sealed receive
frontier may provoke a rate-limited ACK of that **actual bootstrap frontier**.
It never reaches TLS or changes new-phase credit/replay state. A segment crossing
the boundary, new bootstrap payload, SYN, FIN or reset cannot reopen the prefix.
This responder is needed if the peer's last bootstrap ACK was lost while the
other endpoint already detached. It expires at the original transition deadline;
expiration cannot turn an incomplete peer proof into success. Raw ACKs emitted
by this responder do not reset any authenticated liveness timer.

Before terminal Seal, a coordinated Abort can resume retained mode. After Seal
or any detached owner, an uncertain/expired transition terminates the session;
there is no same-tuple rollback, recreated TLS object, new SYN or automatic
reinterpretation of packet bytes as TLS. Fallback requires a separately negotiated
fresh connection. The existing retained profile remains independently selectable.

## Packet protection, numbering and recovery reuse

Use existing `PacketSealer`/`PacketOpener` from
[l2tunnel-datagram](../../crates/l2tunnel-datagram/src/lib.rs), with fresh
exporter-bound context including the phase configuration. Its fixed cover prefix
can remain the existing custom OpenVPN-like shape inside TCP payload; it is not
OpenVPN, QUIC, TLS or HTTPS. Do not add fake TLS record headers or custom AEAD.
Confidentiality-off selects existing domain-separated HMAC integrity, never
unauthenticated user payload. TLS record counters are retired with TLS; packet
nonces continue monotonically under new, distinct exporter-derived packet keys.

A proposed fixed 48-byte protected phase header contains version/kind/reserved
fields, 16-byte transition ID, 64-bit local byte offset, 64-bit peer retirement
offset, 64-bit advertised receive right edge and exact 16-bit body length plus
reserved bytes. Session, lane, direction, suite, key generation and packet number
are already in the authenticated datagram context. The phase payload carries the
unchanged existing recovery packet or one finite transition/window/close control.
Require canonical sizes/reserved bits and exact outer segment length.

TCP SEQ/ACK/window/flags must match the authenticated header's offsets and
negotiated snapshot. Do not authenticate IP addresses/ports as raw bytes: ordinary
NAT can rewrite them. Do require the actual configured incoming tuple at the
adapter; address migration and payload/sequence rewriting ALGs are unsupported.
A valid protected packet with a modified TCP header must not burn its nonce and
make the legitimate packet a replay. The additive
[`PacketOpener::open_checked`](datagram.md#reviewed-additive-checked-open-contract)
now authenticates into bounded scratch and invokes a validator before committing
replay/usage/output. The raw phase still must implement complete phase grammar,
header-mirror and destination-reservation checks in that validator. The seam alone
does not implement this carrier. No second replay implementation or
decrypt-and-reset workaround is acceptable.

Reuse `SelectiveRepeat` or the real `Reliable` block-FEC composition; call their
authoritative `inspect_peer` and split feedback/data polling APIs. Each emitted
source retry or repair is a new protected carrier packet and a new outer byte
range; its logical source identity stays unchanged. Never retransmit all lost
outer packets through a second general-purpose ARQ. A high-water report frees
only carrier horizon accounting, not a retained source. Recovery acknowledgment
frees recovery ownership; only actual native write success frees native delivery
credit. Corrupt/unauthenticated input never reaches recovery.

All native frames, probes and inner TCP control frames enter the same configured
MUX/channel policy and weighted scheduler. Neither latency probes nor NDP/ARP
receive an unnegotiated bypass. This design makes no claim that moving away from
ordered TCP has already fixed the observed NDP failure. Full and paired-half
profiles share one aggregate byte/packet allowance; user payload stays in each
lane's negotiated bulk direction. Reverse carrier/window/recovery controls are
allowed on each lane with explicit bounded service.

## Sequence, window and admission rules

Maintain checked nonwrapping `u64` phase byte offsets separately from packet
numbers and recovery source IDs. Emission begins at the exact bootstrap sequence;
wire SEQ is `(bootstrap_tx + tx_offset) mod 2^32`. Every protected TCP payload byte
counts, including cover, tags, control, sources and repairs. FIN, when explicitly
closing, occupies its own sequence unit. No different packet may reuse a byte
range. The only identical-range copies are the finite cached transition/close
controls described below; those retain exact ciphertext and nonce.

The first qualification profile stops **before the first wire sequence wrap**.
After snapshot, negotiate the smaller remaining per-direction budget, reserving
space for all bounded transition/drain/close copies. Reject activation if that
budget cannot hold at least the configured minimum useful transfer. Near-wrap
bootstrap uses retained mode or fails negotiation before Seal; it must not reset
sequence. Exhaustion after commit freezes admission and requests finite drain.
Supporting wire wrap is a separate gate requiring authenticated extended-offset
mapping, serial-distance proofs below `2^31`, old-duplicate tests and middlebox
experiments. A large `u64` alone does not solve 32-bit wire ambiguity.

For an active lane, let `T` be the next actual-send offset, `A` the peer's latest
authenticated retirement frontier and `R` its advertised right edge. Data of
length `L` is admitted only when `T + L <= R - control_reserve` and
`T + L - A <= horizon_bytes`, with checked arithmetic. Controls use the same total
allowance and the reserved part of that horizon. Reports must be monotonic,
not acknowledge unsent bytes, and not retract an already committed right edge.
No raw ACK-only packet changes `A` or `R`. The advertised TCP window is bounded
by negotiated receive capacity and correctly rounded for the original scale.
Window scale is negotiated in SYN; it cannot be introduced after TLS.
[RFC 7323 §2.3](https://www.rfc-editor.org/rfc/rfc7323.html#section-2.3)

A valid later packet can advance the custom retirement frontier over missing
outer bytes. Already received older packets remain eligible only within both the
bounded byte-reorder horizon and the existing 128-packet authenticated replay
window. Missing/later rejected source copies are repaired by the existing upper
recovery engine. This deliberately differs from ordinary TCP; do not name this
frontier `tcp_acked_bytes` or feed it into smoltcp Reno. Numeric window checks do
not turn gap retirement into RFC-compliant receive semantics.

If no reverse report arrives, the sender can use its remaining finite horizon,
then stops. It does not fabricate a larger window. Window/control reports are
piggybacked when possible and coalesced by a finite time/byte threshold; they
never release native data. A report does not immediately trigger another report
solely because it exists: avoid ACK-of-ACK loops. Probe/window refresh and
transition/close retry share a finite control token bucket and the total wire
budget. Reserve queue capacity before polling recovery so rejected output stays
owned by its original source owner.

## Bounds, options, liveness and terminal state

Proposed first lab limits, all checked and digest-bound before authentication:

| Limit | Initial proposal |
| --- | --- |
| IP family and packet size | Native IPv4 raw adapter only; whole IP MTU 576..1500, also respect captured peer MSS |
| Queue capacity/work | At most 64 packets per lane per direction; one retained output packet; at most 32 ingress/egress operations per turn |
| Header/reorder horizon | At least four maximum segments, at most 1 MiB, below `2^31`; also capped by negotiated scaled window |
| Control reservation | Eight maximum control cells within the same horizon and total wire budget; minimum useful horizon must leave data capacity |
| Transition | One transaction; 30-second absolute timeout, 250 ms minimum retry spacing, at most 32 emitted transition copies; no deadline renewal from duplicates |
| Old-prefix response | One coalesced ACK per lane, at most 4/s, expires with the original transition deadline |
| Liveness | One authenticated nonce probe outstanding per lane, 5-second interval and 15-second reply deadline; duplicate/stale replies do not refresh it |
| Reordering | Existing 128-packet protected replay limit plus explicit byte bound; no allocation from peer-provided offsets |
| Key/sequence use | Existing datagram packet/byte usage ceilings plus smaller no-wire-wrap budget; exhaustion never resets nonce/counters |
| Close | 30-second absolute application-drain deadline; fixed bounded close-tail retention and retries, separately negotiated before use |

These are proposal bounds, not measured safe values for arbitrary paths. Exact
MTU accounting subtracts IPv4/TCP headers, negotiated TCP options, datagram
cover/common/tag, phase header and chosen recovery/FEC wrappers before native
fragmentation. No IP fragmentation, jumbo segment or oversized GSO assumption is
allowed. PMTU reduction after commit requires an explicit bounded reconfiguration
or terminal error; a late EMSGSIZE cannot silently drop the retained source.

First-profile bootstrap must negotiate no TCP timestamps and no ECN. The current
raw engine does not set a timestamp generator, but the future snapshot must
verify this rather than infer it. If timestamps/PAWS were negotiated, continuation
requires preserving their clocks/echo/acceptance state; reject handoff until that
separate option contract exists. Preserve original window scaling and peer MSS.
SACK-permitted may have been negotiated; the custom phase emits no invented SACK
blocks and ignores unauthenticated SACK for logical progress. Unsupported options
are a negotiation failure, not silently removed at the boundary.

Maintain separate monotonic counters for native admitted/confirmed records,
recovery sources/retries/repairs/feedback, sealed and physically sent packets,
actual IP bytes, bootstrap bytes genuinely TCP-acknowledged, custom retired bytes,
retired gaps, duplicate/replay/auth/format/tuple/window drops, window stalls,
transition copies, old-prefix responses and terminal outcomes. Counters cannot
wrap into a new identity. Queue sizes, high waters and actual I/O errno are safe
to report; keys, exporter bytes and native payloads are not.

The current recovery `OutboundBudget` is an allowance, not a congestion
controller. Removing smoltcp reliability also removes its normal Reno path.
Initially this profile is owned-lab-only with a predeclared aggregate pace/byte
cap. General network use remains blocked on the independent aggregate raw/UDP
congestion-control gate [FC-08](../flow-control.md#checklist); extra lanes and FEC
must not multiply that allowance. Authenticate actual probes/delivery feedback;
neither fabricated TCP retirement nor static configured capacity is an RTT or
congestion measurement.

Shutdown first freezes new native admission and proves existing recovery and
actual native delivery fences on both peers using bounded protected controls.
Only then may the explicit terminal substate emit TCP-shaped FIN at the actual
send frontier. Retain a bounded exact ciphertext/sequence cache for the final
close controls and retransmit those exact bytes when needed; do not allow new
payload after FIN or turn closing into general outer data ARQ. Bare FIN/ACK
observations never authorize native credit release, key changes or liveness.
The final control-cache format and simultaneous-close state machine require their
own review and tests before implementation. Require physical pending output to
empty and fixed final-ACK/linger completion before releasing the original socket;
otherwise report `CloseTimeout` with its actual unresolved fences.

Report `PacketPhaseDrained` only with both authenticated logical/native proofs
and the required terminal evidence. It is distinct from the existing maintained
`CloseReason::Clean`; skipped outer bytes cannot become a clean standard TCP
stream. Early peer reset, invalid late control, blocked native output, socket
failure or timeout is an error with retained-state counts. No reset is suppressed
or counted as successfully sent. The marked policy stays owned and unchanged
until descriptor/reservation release; no host firewall mutation is part of this
module. No ordinary Drop implementation sends FIN/RST as a side effect.

## NAT, TLS and fallback limits

RFC 5382 concerns TCP NAT mapping/refresh behavior; it explicitly excludes much
firewall and application inspection. Its idle-time recommendations do not
establish this custom phase's behavior on deployed equipment. Ordinary NAT can
change addresses/ports, sequence-normalizing ALGs can invalidate this design,
and connection tracking can reject the gap-retirement convention. Connection
migration, inbound NAT discovery and third-party network traversal are outside
this first fixed-peer capability. [RFC 5382 §§1, 5](https://www.rfc-editor.org/rfc/rfc5382.html)

TLS 1.3 authenticates records with its own directional record counters. Exported
keys do not let arbitrary reordered datagrams remain valid TLS records. After
Seal this profile leaves TLS record semantics; retained socket/sequence identity
is not retained HTTPS behavior. No-SNI and the existing certificate/member
verification stay in bootstrap. [RFC 8446 §5.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.3)

Capability negotiation must report `retained_tcp`, `raw_packet_v1_experimental`
or a precise unsupported reason. Missing raw permission uses an explicitly
compatible ordinary TCP or UDP profile only before connection/authentication;
ordinary TCP cannot expose ACK-independent packet semantics. Failed packet-phase
transition cannot silently resume the old TLS byte stream. No native retry,
window inflation, probe bypass or timeout increase is authorized by this design.

## Implementation and evidence checklist

All tasks below remain unchecked. Documentation/review is not implementation.

- [ ] [MOD-RAWPHASE-01] Review the custom gap-retirement semantics, retained default, exact configuration/profile digest and middlebox/HTTPS limitations.
- [ ] [MOD-RAWPHASE-02] Resolve the supported authoritative smoltcp snapshot/consume feasibility gate; review any narrow upstream change before dependency edits.
- [ ] [MOD-RAWPHASE-03] Specify and test one-owner bridge/TLS freeze with actual byte/ACK/output fences, including queued TLS post-handshake output and cancellation.
- [ ] [MOD-RAWPHASE-04] Implement bounded all-lane Prepare/Seal/Hello/Commit, exact complementary bootstrap fences, early-packet quarantine and no same-tuple uncertain rollback.
- [ ] [MOD-RAWPHASE-05] Implement failure-atomic protected phase validation using existing crypto/replay; modified outer header must not burn a legitimate packet's nonce.
- [ ] [MOD-RAWPHASE-06] Implement checked byte-offset/window accounting, identical WouldBlock retention, physical-send counters, near-wrap rejection and finite exhaustion/drain.
- [ ] [MOD-RAWPHASE-07] Compose existing ARQ/Cauchy-FEC and common MUX/QoS without new source identity, extra user credit or duplicate outer data ARQ.
- [ ] [MOD-RAWPHASE-08] Test dropped terminal bootstrap ACK, reordered old retransmission, crossing-boundary segment, simultaneous switch, paired-lane mismatch/loss, duplicate/conflicting commit and stuck peer deadlines.
- [ ] [MOD-RAWPHASE-09] Test data/control loss, reorder beyond replay/horizon, corruption, spoofed ACK/window/RST, exhausted control reserve, full native output and frozen sender without reverse reports.
- [ ] [MOD-RAWPHASE-10] Review and implement exact finite shutdown/close-tail state with no FIN/RST at handoff/drop; preserve failure outcomes and no false maintained clean-close result.
- [ ] [MOD-RAWPHASE-11] Independently verify single original tuple/SYN/sequence boundary, authentic byte fences, physical packet accounting, options and no plaintext payload with two-ended captures.
- [ ] [MOD-RAWPHASE-12] Qualify scoped clean/impaired TAP/TUN, NDP/ARP, namespace NAT/conntrack, port reuse, PMTU and abrupt-peer cases; preserve failed/unrun receipts and unchanged predeclared bounds.
- [ ] [MOD-RAWPHASE-13] Qualify real aggregate congestion/pacing and any 32-bit wrap/timestamp extensions before general-network capability exposure.
- [ ] [MOD-RAWPHASE-14] Run focused parser/state/ownership tests, strict lint/docs and coordinated source-stable aggregate; expose no CLI/native capability before the applicable gates pass.

Design inspection: current engine/driver/auth/datagram/recovery source and pinned
smoltcp public/private boundaries were read; the cited primary RFCs were checked.
No new implementation tests or packet-phase native experiments were run for this
proposal. Prior wave7 verification applies to the earlier implementation, not to
this unimplemented phase.
