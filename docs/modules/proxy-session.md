# Bounded TCP proxy session dispatcher

Status: pure dispatcher implemented and focused tested; native runtime, scheduling
and actual TLS integration remain separate gates.

## Contract

`session::Table` is a runtime-independent owner of a finite number of existing
`Opening` and `Leg` instances. One negotiated endpoint is the proxy originator;
the other accepts authorized Opens. Both endpoints still forward other traffic
through the ordinary transparent packet path. Bidirectional connection initiation
and simultaneous-open arbitration are not implied by this initial profile.

The caller authenticates, frames and orders all records before dispatch. It binds
the complete table configuration and role in the authenticated session digest,
authorizes routes before new local or remote admission, and places **all** relay,
transparent and TCP-control work through the same configured QoS/MUX budgets.
This table does not create a privileged data lane or perform authentication.

`Config` validates 1..64 lifetime owners, at most 4096 tuple/address rules, a
1..120000 ms reservation deadline and the existing finite maintained ring/packet
and relay byte/count dimensions. The configured sum of native rings, relay byte
retention, one record, both packet queues and one native handoff per owner must
fit a 256 MiB aggregate ceiling. Bounded flow/record metadata is additional; this
is a payload-capacity guard, not a measured total process-memory promise.

`ingest_native(packet, permit_new, now)` returns Transparent (caller retains the
original), Owned (table accepted/held it), or Backpressure (caller retries the
same original). Only a new permitted candidate SYN on the originator creates an
Opening. Duplicate initial SYNs during reservation cannot produce local ACKs.
`observe_transparent(packet, now)` must run before an incoming transparent packet
is written to TUN; it prevents a reverse-initiated/preexisting connection from
later being intercepted on the other side.

Tuple decisions are symmetric and last for the entire authenticated session.
There is no idle eviction, flow-ID reuse or migration of an existing transparent
connection. Finite tuple/address-policy storage and a finite **lifetime** flow
limit bound memory. If bypass-policy storage fills, admission locks out until a
new session: existing proxy flows continue and new connections stay transparent.
This deliberately conservative first implementation trades reconnect frequency
for a provable absence of midstream ownership changes. Closed proxy tuples remain
tombstones and are not reused in the same session.

Direct IPv4/IPv6 TCP packets are checksum-validated for tuple dispatch. Unsupported
IP options/fragments/extensions conservatively pin an address pair to transparent
ownership. Such an ambiguous packet cannot cross a pair with an existing proxy
owner: that is a conflict requiring session termination, rather than forwarding
part of an owned connection. Non-TCP direct UDP/ICMP packets remain transparent.
Unknown/protected TCP options and ECN/URG/NS flags are transparent before ownership
and terminate the particular owned flow afterward. Malformed/checksum-invalid
packets do not create a new decision. No IP/TCP header is rewritten.

## Reliable output and failure

Per-flow `pending_record` stays immutable until `confirm_record_sent` attests
ownership by the authenticated reliable carrier. The existing Open/Ready/Commit
barrier remains authoritative. A retained native slot likewise stays immutable
until `confirm_native_written` attests a complete native write; merely popping
a maintained packet is not delivery. Polling performs a caller-bounded number
of flow visits and bounded maintained-stack work per visit, fairly rotating the
starting flow. Selection among pending flow records belongs to the shared arbiter.

Open/Ready/Commit and Credit/Data/Fin keep their existing canonical formats.
`LTPX` uses the same exact 40-byte session/epoch/flow header, version 1, zero
reserved bytes, and one kind: Rejected(1), Cancelled(2), NativeFailure(3),
UnsupportedPacket(4), AdmissionExpired(5). It has no body. These are authenticated
terminal notifications, not clean stream completion. An unsent local Open can be
cancelled locally; after carrier ownership, cancellation is sent reliably. Remote
authorization/tuple-policy refusal produces a bounded Rejected entry. Every
remotely proposed ID must be the next monotonic ID and within the negotiated
lifetime limit; invalid or excessive IDs fail before allocation.

Terminal flow state retains any maintained reset/native output until actual write
confirmation. Later already-in-flight canonical records for that exact retired
scope are ignored, never used to revive the flow. Malformed and wrong-scope records
still fail. There is no transparent fallback after Open ownership or a local ACK.
An explicit clean retirement requires both Fin boundaries, actual native clean
close, acknowledged received bytes, empty maintained queues, no pending tunnel
record and no retained native slot. Peer TCP ACK still does not prove application
consumption. Runtime cancellation/transport EOF must terminate all remaining
owners; a clean table alone does not prove transport/session shutdown.

## Explicit TIME-WAIT policy and observed limits

The table config includes `TimeWaitResetPolicy`; an embedding runtime must bind
this selection alongside all other settings before authentication. All old raw
TCP/relay constructors retain `Maintained`. `IgnoreInTimeWait` is an explicit
optional mitigation following the F1 proposal in informational RFC 1337, which
differs from the RST transition still described in RFC 9293. It drops an already
validated RST only when the **current maintained state at packet processing** is
TIME-WAIT. A queued FIN immediately followed by RST is therefore handled correctly.
Each drop consumes a bounded poll step; no timer, sequence, acknowledgment or
close outcome is invented. The maintained TIME-WAIT timer remains unchanged, so
this is not the full hazard-avoidance claim requiring RFC 1337's MSL assumptions.
Selection is immutable after the first maintained poll. Established/FIN-WAIT
resets remain failures; expiry with unread receive bytes remains a failure.

Two concurrent IPv4/IPv6 connections each transferred 16,397/9,281 exact opaque
bytes in both directions, retained Open/native output under forced blocking, and
retired cleanly on a clean path and with loss during the first 80 native packets
plus continuing deterministic reorder/duplication. These runs explicitly selected
the optional policy on every maintained test endpoint.

The original continuous every-seventh-packet-loss trace remains separately tested:
with the unchanged default, an application-side post-EOF RST is reported at
26,350 ms, with 2,625 bytes still held by another relay direction. With the optional
mitigation, that same trace avoids the RST but still reaches its fixed 60,000 ms
bound with 1,601 bytes retained. Neither result is clean completion or a qualified
sustained-loss/performance claim. The bounded-outcome regressions preserve these
limitations rather than raising deadlines or silently dropping retained bytes.

References: [RFC 1337 section 3](https://www.rfc-editor.org/rfc/rfc1337#section-3),
[RFC 9293 segment handling](https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4).

## Checklist

- [x] [MOD-PROXY-SESSION-01] Implement validated bounded configuration, lifetime tuple/address policy, monotonic flow IDs and explicit originator/acceptor roles. Evidence: [pure table](../../crates/l2tunnel-tcp-proxy/src/session.rs), [configuration and sticky-policy tests](../../crates/l2tunnel-tcp-proxy/src/session/tests.rs), no idle eviction or in-session ID reuse.
- [x] [MOD-PROXY-SESSION-02] Integrate actual Opening/Leg owners, immutable native/carrier handoff, finite fair polling and authenticated terminal notification. Evidence: [table ownership](../../crates/l2tunnel-tcp-proxy/src/session.rs), per-flow retained output confirmation, bounded poll rotation and explicit LTPX terminal records; prior authenticated ordered delivery remains a caller precondition.
- [x] [MOD-PROXY-SESSION-03] Test concurrent real IPv4/IPv6 byte transfers, blocked admission/native/carrier work, clean retirement and no pre-Commit SYN-ACK. Evidence: [concurrent tests](../../crates/l2tunnel-tcp-proxy/src/session/tests.rs), exact 16,397/9,281 bytes per connection and clean/finite-loss deterministic tests; continuous periodic-loss outcomes remain explicitly unqualified above.
- [x] [MOD-PROXY-SESSION-04] Test sticky bypass, policy exhaustion, protected-option changes, rejection/cancellation, replay/order/scope/deadline and native-reset failures. Evidence: [session regressions](../../crates/l2tunnel-tcp-proxy/src/session/tests.rs), real maintained RST, ingress backpressure, late handoff expiry, terminal replay and no false clean retirement.
- [x] [MOD-PROXY-SESSION-05] Run strict focused checks, independent review and stable aggregate verification. Evidence: [source-stable wave 6](../../work/implementation-wave6/validation.json), 492 Rust cases and 36 Python tool tests; strict focused tests and review are described above.
- [ ] [MOD-PROXY-SESSION-06] Integrate actual authenticated runtime, shared QoS/MUX and measured credit targets, then qualify native TUN and explicit client selection.
- [ ] [MOD-PROXY-SESSION-07] Qualify the unchanged continuous periodic-loss trace through complete byte/native retirement without relaxing its fixed 60-second bound.


A locally allocated Opening that expires before any Open reaches reliable carrier
ownership leaves a lifetime flow-ID tombstone that its peer cannot know. The
initial runtime must terminate that session explicitly; subsequent Open IDs cannot
skip the peer's strict contiguous admission sequence. No skip/reuse message is
implemented. Quiescence may complete already allocated openings under their
original deadlines while preventing new owners. The public
`admission::inspect_open` accessor shares the authoritative bounded parser for
route authorization without reserving or acknowledging a TCP leg.
