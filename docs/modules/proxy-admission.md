# TCP proxy admission before local acknowledgment

Status: single-flow primitive and a separate [bounded session dispatcher](proxy-session.md)
are implemented and focused tested; actual authenticated/native runtime integration
remains pending. This extends the maintained IPv4/IPv6 relay leg and does
not select proxy ownership for transparent TUN traffic.

## Initial packet policy

`inspect_syn(packet, max_packet_bytes)` validates complete IP/TCP lengths and
checksums without mutation or allocation before deciding `Candidate(InitialSyn)`
or `Bypass(reason)`. Candidate owns at most 100 original bytes: a direct IPv4/IPv6
header plus a maximum 60-byte TCP header, with no SYN payload. It retains original
source/destination ports/addresses, ISN and DSCP. No packet rewriting occurs.

Only a plain initial SYN, standard MSS/window-scale/SACK-permitted/timestamp
offers and harmless NOP/end padding enter this first profile. Duplicate standard
options, unknown/protected options (including TCP-AO/MD5), Fast Open data, ECN/NS/
urgent flags, IP options/extensions/fragments and unsuitable addresses stay
transparent **from connection start**. Invalid lengths/checksums are explicit
errors. The future bounded flow dispatcher must keep bypassed tuples transparent;
this classifier alone does not track them. Both proxy legs negotiate their own
maintained-stack options; offered timestamps may be declined. This is not full
timestamp/ECN option preservation or support for urgent application data.
After ownership, the future dispatcher must fail the owned flow on unsupported
urgent/protected option changes; it cannot return an acknowledged flow to the
transparent path or silently use the maintained stack's ignored-URG behavior.

## Single-flow reservation transaction

`Opening::local(relay_config, native_config, InitialSyn, now, timeout)` allocates
the bounded server-side relay but does not ingest the held SYN or poll TCP.
Its immutable Open record carries the original SYN. Native config must preserve
the original destination as local and original source as peer. A caller starts
this only after session/member authentication and route/flow opt-in authorization.

`Opening::remote(relay_config, native_config, authenticated_open, now, timeout)`
validates scope and the same original SYN, reserves the client-side maintained
relay, and emits Ready. Its local address is the original source and peer is the
original destination. It does not emit a remote SYN yet. Allocation refusal is an
explicit error; the session dispatcher must send a bounded failure response.

When local receives Ready it stages Commit. Only
`confirm_record_sent()` for that exact Commit transfers reliable-carrier
ownership and injects the original SYN into the local maintained relay. Remote
receives authenticated Commit only after Ready has been handed to the carrier.
`take_leg()` then transfers the active relay out exactly once. Neither side polls
native TCP or emits a SYN/SYN-ACK before this remote reservation barrier. There
is no second TCP state machine; all later TCP behavior remains in `Leg`.

Open/Ready/Commit use an exact 40-byte `LTPA` header with version, kind, zero
reserved bits, session(16), epoch(u64), flow(u64), network byte order. Open adds
a u16 original-SYN length plus at most 100 original bytes; Ready/Commit have no
body. The authenticated reliable ordered carrier supplies direction, record
framing, replay protection and delivery. Wrong scope/kind/phase/truncation and
conflicting repeated input fail without applying a new state. Exact logical
duplicates are not retried here; the reliable carrier already owns retransmission.

One immutable admission output and one original SYN supplement the bounded relay
rings/queues. Caller-injected monotonic time has one fixed 1..120000 ms admission
deadline; polling or duplicates never extend it. Deadline failure releases no
local ACK and does not imply remote application acceptance. A caller must cancel
both reservations on failure; after Open submission there is no automatic
transparent fallback. Session-level rejection/cancel/reset delivery, aggregate
flow quotas, tuple dispatch and retained bypass decisions are later gates.

## Checklist

- [x] [MOD-PROXY-ADMIT-01] Implement bounded IPv4/IPv6 initial-SYN inspection and explicit preownership bypass/error reasons. Evidence: [strict inspector](../../crates/l2tunnel-tcp-proxy/src/admission.rs), [IPv4/IPv6 real-header tests](../../crates/l2tunnel-tcp-proxy/src/tests/admission.rs), maintained checksum/option decoders and no original packet rewrite.
- [x] [MOD-PROXY-ADMIT-02] Implement exact scoped Open/Ready/Commit and immutable output ownership around actual reserved maintained legs. Evidence: [Opening](../../crates/l2tunnel-tcp-proxy/src/admission.rs), inaccessible native I/O before the reservation/Commit barrier, fixed deadlines and exactly-once leg transfer.
- [x] [MOD-PROXY-ADMIT-03] Verify no native packet/ACK before remote reservation and actual Commit handoff, then transfer real application bytes through the resulting legs. Evidence: [reservation and four-owner transfer test](../../crates/l2tunnel-tcp-proxy/src/tests/admission.rs), IPv4/IPv6 8,193/6,151-byte bidirectional transfers with and without deterministic loss/reorder/duplicates; all maintained legs close cleanly.
- [x] [MOD-PROXY-ADMIT-04] Test truncation/checksum/tuple/options/protected flags, scope/order/replay/deadline and retained-carrier failures without false ownership. Evidence: [admission failure tests](../../crates/l2tunnel-tcp-proxy/src/tests/admission.rs), unchanged retained Open/Commit under blocking, no leg on premature handoff/expiry, wrong scope/kind/sequence and protected-option bypass.
- [x] [MOD-PROXY-ADMIT-05] Run strict focused checks and stable aggregate verification. Evidence: [source-stable wave 6](../../work/implementation-wave6/validation.json), 492 Rust cases and 36 Python tool tests; strict focused tests and review are described above.
- [ ] [MOD-PROXY-ADMIT-06] Add bounded session flow dispatch, authenticated rejection/cancel/reset, sticky transparent fallback and runtime/native qualification.

References: [TCP](https://www.rfc-editor.org/rfc/rfc9293.html),
[IPv6](https://www.rfc-editor.org/rfc/rfc8200.html), and the pinned smoltcp packet
and option decoders already used by the maintained relay.

Focused `cargo test -p l2tunnel-tcp-proxy --offline` passed 11 tests (three
admission tests plus eight original relay tests); strict all-target Clippy passed.
An independent read-only review found no material ownership/parser issue. These
tests inject caller-authenticated records; no genuine TLS session, dynamic flow
dispatcher, native TUN interception or production proxy selection is claimed.
