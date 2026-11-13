# Swift algorithm and current protected-UDP composition

Status: the pure Swift packing/recovery engine is implemented and protocol-tested.
The current explicit `--record-profile swift --carrier udp` composition is
implemented, with historical integration receipts from Linux TAP in owned
unprivileged network namespaces. It authenticates over TCP/TLS and sends data
over a separate UDP socket; it is not the target selected-carrier architecture.
It is not the default connection mode. Real devices, privileged host namespaces,
IPv6 underlay runs, Swift TUN qualification, Windows/Android, remote CI and
long-duration soak remain open.

The target is a reusable Swift data algorithm above the explicitly selected
carrier, using the [common secure session](secure-session.md) for inner
authentication, AEAD, replay protection and key lifecycle on every carrier,
including HTTPS. The fixed-peer session retains the selected carrier's socket
and five-tuple from handshake through data and management. A WireGuard-like
security model does not select a library, require WireGuard wire compatibility,
or make the current Swift-specific security protocol the common protocol.
The common implementation and bounded automatic recovery are planned; the
current CLI and wire formats below describe observed behavior.

- [x] [SW-01] Pure bounded engine: pack native packets across fixed-capacity source symbols, send each once, recover by receiver-requested retransmission with optional sliding-window GF(256) repairs, and deliver one exact ordered stream. Evidence: [engine](../../crates/l2tunnel-swift/src/lib.rs) with [loss, reordering, tail, flush, back-pressure and malformed-input tests](../../crates/l2tunnel-swift/src/tests.rs).
- [x] [SW-02] Stateless connection classification into ordering channels for Ethernet (one VLAN tag) and raw IPv4/IPv6, with fragments kept together and unknown input on channel zero. Evidence: [classifier and tests](../../crates/l2tunnel-swift/src/flow.rs).
- [x] [SW-03] Exact TCP/IPv4 header records on an ordered channel: delta fields, reconstructed length and checksums, compressor self-verification and literal fallback. Evidence: [codec and exactness, mutation and rejection tests](../../crates/l2tunnel-swift/src/header.rs).
- [x] [SW-04] Runtime: ChaCha20-Poly1305 datagrams keyed from the TLS exporter, packet-number replay window, IP-byte token-bucket pacing, readiness-driven device and socket I/O, aggregated feedback and bounded delivery batches. Evidence: [runtime with protected-engine, channel-independence, pacing, replay and two-endpoint loopback tests](../../crates/l2tunnel-runtime/src/swift.rs).
- [x] [SW-05] Shared client module and CLI selection with the complete policy bound into the authenticated session digest and rejected before credentials or sockets when invalid. Evidence: [client module](../../crates/l2tunnel-client-core/src/swift.rs), [CLI frontend](../../crates/l2tunnel-client-core/src/swift/cli.rs).
- [x] [SW-06] Unprivileged Linux TAP self-test under HTB and netem with verified payload, clean close, same-window wire accounting and layer-2 checks in both directions (ARP, full-MTU unfragmented ping, UDP from 1 to 1472 bytes). Evidence: [tool](../../tools/selftest.py), [helper tests](../../tools/test_selftest.py), [clean](../../work/swift-selftest41/clean.json), [delay](../../work/swift-selftest41/delay.json) and [1% loss](../../work/swift-selftest41/loss1.json) receipts.
- [x] [SW-07] Match the simulator at equal byte overhead within 2.5% on every self-test path. Evidence: [three reference runs](../../work/swift-selftest41/impaired-1.json), [kernel-default RTO run](../../work/swift-selftest41/impaired-kernel-rto.json), [simulator on the reference path](../../work/swift-simulator-reference38/output.log) and [on the control paths](../../work/swift-simulator-reference40/output.log).
- [x] [SW-12] Read-only `status` over the private local control socket, reporting phase and counters of the live session. Evidence: [response and tests](../../crates/l2tunnel-client-core/src/swift/cli.rs); every [self-test receipt](../../work/swift-selftest41/impaired-1.json) queries both endpoints with the real `status` command.
- [x] [SW-08] Route swift through the shared service API with disconnect and reconnect: the service owns the authenticated session, sockets and device as one backend; the CLI only parses and prints. Evidence: [service backend](../../crates/l2tunnel-client-core/src/service/owner.rs), [two-service lifecycle test over real loopback TLS and UDP](../../crates/l2tunnel-client-core/src/service/tests/swift.rs), [CLI adapter](../../crates/l2tunnel-client-core/src/swift/cli.rs), and the `lifecycle` block of the [self-test receipts](../../work/swift-selftest43/impaired.json), which disconnects and reconnects the live tunnel with the real commands.
- [ ] [SW-09] Qualify on real devices and privileged host namespaces, IPv6 underlay, TUN, long soak, CPU and memory.
- [x] [SW-10] Rekeying and sequence rollover without reconnecting: each direction's datagram key changes every 2^28 datagrams through an HKDF-SHA256 chain with no message, and source sequences are 64-bit inside the engine with their low 32 bits on the wire. Evidence: [key chain and ratchet test](../../crates/l2tunnel-runtime/src/swift.rs) covering many generations in both directions, a reordered straggler, forged and skipped generations and retirement; [boundary-crossing engine test](../../crates/l2tunnel-swift/src/tests.rs) under 15% loss with and without repairs. A production-cadence rekey (2^28 datagrams, hours at the reference rate) has not been observed in a live run.
- [ ] [SW-11] Negotiated epoch switching between swift and the other record profiles, retaining authenticated management, matching digests, drain barriers, bounded retries and old-epoch rejection. Cross-profile selection is currently startup-only. SW-13 does not narrow or complete this gate.
- [ ] [SW-13] Negotiated in-place change of the swift policy (budgets, channels, repair window and proportion, path MTU) on a live session: proposal and digest agreement on the retained authenticated stream, then a per-direction drain barrier, with datagram numbers and keys never reset. Implemented with focused tests ([control messages](../../crates/l2tunnel-swift/src/control.rs), [engine state machine, refusal and violation tests, two-runtime loopback test with two changes under traffic](../../crates/l2tunnel-runtime/src/swift.rs), [service and local `set-swift`](../../crates/l2tunnel-client-core/src/service/tests/swift.rs)); the original total deadline now covers silent proposal/barrier waits, receive flushing and terminal control writes, with injected-time and paused-runtime regressions. See the [checkpoint validation result and source identity](../../work/swift-policy-deadline-20261113/validation.json). The earlier [focused check](../../work/udp-framing-wording-20261113-final/focused-validation.json) passed, but its required aggregate check failed and [native receipts are mixed](#policy-change-receipts). Complete the remaining failure and native qualification gates before checking this item. Its Swift-specific policy change is not a substitute for SW-11.
- [ ] [SW-14] Compose the pure Swift algorithm over the explicitly selected carrier and common secure session, without an independent Swift connection/default or mandatory separate TCP/TLS bootstrap. Preserve packing, exact header records, channels, retransmission and optional repairs; prove handshake/data/control socket and five-tuple continuity, exact bytes, replay rejection, carrier overhead and unsupported-combination reporting. Implementation depends on the [common secure-session gates](secure-session.md).
- [ ] [SW-15] Move Swift policy changes and full SW-11 switching onto the common authenticated session-control service, independent of data profile and carrier. Retain digest agreement, per-direction drain, idempotent retries, original deadlines, delayed old feedback rejection and bounded control progress under saturated traffic. Preserve all other record profiles and Python parity requirements.
- [ ] [SW-16] Qualify fixed-peer bounded automatic recovery through the shared client/service API, enabled by default in the target design. Retain eligible logical-session delivery and mode-transaction state through temporary path loss and security-key refresh; distinguish peer state loss or explicit replacement sessions requiring authenticated reconciliation or reported loss. Bound liveness, proposal, barrier and retry waits and expose requested/effective recovery state and terminal failure. Test short loss, silent blackholes, restored paths, explicit disconnect and failed reauthentication without changing the host's network state.

## Current layering and target correction

The current client reuses the existing TLS/member authentication and directional
exporter secrets, and the shared service owns connect/disconnect/reconnect/status.
The pure `l2tunnel-swift` engine has no cryptography, socket or real clock.
The runtime now delegates protection, replay and its key chain to the explicit
`l2tunnel_security::swift_v2` compatibility owners. Their byte-exact legacy format
and TLS exporter roots remain unchanged; the new common packet format is a
separate API, not silently enabled on an existing Swift connection. See the
[packet-security extraction](packet-security.md). SW-13 still uses its private
TLS control codec rather than the common management transaction. AEAD and HKDF
continue to use maintained `ring` primitives.

The target correction preserves the algorithm and historical experiments while
converging authentication/security and management on common session services.
Carrier appearance and its handshake remain separate from Swift recovery.
The selected carrier must carry both session control and protected user data;
a separate protected UDP data flow after TCP/TLS bootstrap does not satisfy continuity.
Outer parseability, endpoint interoperability and measured ISP classification
remain separate acceptance claims. No current Swift result proves any of them.

## Why this design

`simulator/README.md` documents the 80/20 candidate as compact selective-repeat
ARQ with the reversible `tcp_delta` header profile over independent per-flow
ordering, not as a coded stream. At 15% independent loss every scheme needs at
least 17.6% extra datagrams; retransmitting exactly what was lost reaches that
bound, while proportional repairs sized for 15% cost about 20.5% and still leave
a residue. The engine therefore defaults to retransmission only and keeps
sliding-window repairs as an explicit option for latency-sensitive use.

Three measurements shaped the rest:

- One ordered stream for all connections let every loss delay every
  connection. Sixteen channels restored independent ordering.
- A partial symbol sent immediately costs a full datagram header for a few
  bytes. Partial symbols wait up to 1 ms for more native bytes.
- In-order delivery releases long runs at once. Recovered packets are written
  to the device in batches of 32 between socket reads, and the socket requests
  an 8 MiB receive buffer, which the kernel clamps to its configured maximum
  (416 KiB effective in the recorded runs). Before this the receiver itself
  dropped about 1.4% of datagrams.

## Current wire format

Every UDP payload is `[packet number u64][ciphertext][tag 16]`. The packet
number is the AEAD nonce, the replay identity and the repair coefficient seed.
Protection is always ChaCha20-Poly1305 AEAD; Swift has no MAC-only or unprotected
payload setting. Its authenticated packet-number replay window is 4096 packets.
The `KeyPurpose::Data` exporter secret of each direction on lane 0 starts a
chain: generation `g` protects packet numbers `g * 2^28` to `(g + 1) * 2^28 - 1`
with `HKDF-Expand(secret_g, "l2tunnel swift v2 datagram key")`, and
`secret_(g+1) = HKDF-Expand(secret_g, "l2tunnel swift v2 next secret")`, both
HKDF-SHA256. Because the generation is a function of the packet number, both
peers change keys at the same datagram without negotiating. A receiver derives
the next generation when a datagram first names it, adopts it only once a
datagram authenticates under it, keeps the previous generation while the
replay window still reaches into it, and holds no older secret. The interval
is part of the authenticated policy. The 64-bit packet number does not wrap.

Sequences are 64-bit in the engines; the wire carries their low 32 bits, which
each side expands relative to its own confirmed position. Every sequence a
peer may name lies within one flow window (4096) of that position, so the
expansion is unambiguous and a session continues across the 32-bit boundary.

The plaintext body starts with one byte holding the kind in bits 0–1 and the channel
in bits 2–7.

| Kind | Body after the leading byte |
| --- | --- |
| 0 source | low 32 bits of the sequence, 1 to `symbol_bytes` packed bytes |
| 1 repair | low 32 bits of the end sequence, covered count `u8`, GF(256) combination of `[length u16][payload]` vectors |
| 2 feedback | low 32 bits of base and of end, missing in newest window `u16`, request count `u8`, request offsets `u16` each; one block per channel, concatenated |

Packed bytes are records `[length u16][record]`. A record is tag `0` literal,
`1` literal that also sets a connection context, or `2` delta: a flag byte and
only the changed fields (identification, sequence, acknowledgement, control
word, timestamp value and echo) as modular varints. With a 1500-byte path MTU
the datagram body is 1448 bytes and a source symbol carries 1440.

## Lifecycle

The shared lifecycle service owns a swift session exactly as it owns the
managed TCP and base UDP backends: one accepted operation at a time, typed
completion, and release of the TLS stream, UDP socket and device before any
replacement work. A swift plan needs an attachment whose devices expose a
readiness descriptor. An acceptor's setup operation keeps its listener open
for up to 24 hours; each accepted TCP connection keeps the original handshake
timeout.

The private local control socket serves these commands through that service:

- `status` reports the lifecycle phase (`forwarding`, `disconnected`,
  `connecting`, `failed`), the committed policy `epoch`, the separate session
  `generation`, and the latest counters and effective policy.
- `disconnect` aborts the live session and leaves the daemon idle. It is a
  local abort, not a peer-confirmed drain; the peer sees its liveness stream
  close.
- `reconnect` replaces the live session, or connects again when idle, using
  the plan the daemon started with. The reply is sent once the new session is
  actually forwarding, or reports `failed`.
- `set-swift` requests a negotiated Swift policy change from the initiating
  endpoint; it does not select another record profile or carrier.

Every session derives fresh keys from its own TLS handshake and starts with
empty ordering state; packets in flight when that session ends are lost.
A temporary UDP outage does not by itself clear this state: recoverable socket
errors are treated as loss while the session and bounded retained sources stay
alive. Recovery can resume on path restoration. A fatal runtime error or closure
of the retained TLS stream ends the session. Current `--swift-restart` defaults
to `off`; `on` starts a new setup attempt after one second. This is a fresh
authenticated session, not continuation of the old packet-number or recovery
state. Without it a daemon exits when its session fails or its peer leaves,
and after a failed `reconnect`. Target default bounded automatic recovery is
tracked in SW-16 and the common secure-session ledger.

## Negotiated policy change

`set-swift` on the connecting endpoint's control socket changes any of the
forward and reverse budgets, channel count, repair window, repair proportion
and path MTU without a new handshake. Control messages are framed
`[length u16][kind u8][fields]` on the retained TLS stream, which is reliable
and ordered:

1. `Propose{epoch, policy}` from the coordinator (the connecting endpoint).
   The peer derives the complete configuration exactly as a fresh session with
   that policy would and answers `Accept{epoch, digest}`, or `Reject` when the
   policy is invalid, another change is in progress or the epoch is not the
   next one. The coordinator ends the session if the digest differs from its
   own derivation.
2. After agreement each endpoint stops admitting native packets, keeps
   sending until every source it sent is confirmed and its packing queue is
   empty, and sends `Barrier{epoch, first_number}` with its next datagram
   number.
3. The peer delivers everything it holds, replaces its receiving engines and
   header contexts, and answers `BarrierAck{epoch, feedback_from}` with its
   own next datagram number. Only then does the sender replace its sending
   engines, pacing and header contexts and resume. Sources and repairs
   numbered below `first_number`, and feedback numbered below
   `feedback_from`, belong to the drained epoch and are ignored.

The two directions cross their barriers independently; the local epoch is committed
when both have and the terminal control frames have finished writing. This does
not prove the peer observed the last acknowledgement. Focused tests exercise exact ordered delivery across this change;
that does not prove loss-free switching under every device or outage condition.
One original ten-second deadline covers the proposal, drain, receive flushing and
barrier phases, including pending terminal control writes. It begins when the
runtime proposes or first accepts the change; identical repeated proposals keep
their idempotent reply without extending the deadline. A message that does not fit the current state
ends the session. Only the coordinator proposes; the peer accepts any policy that
is valid for the session, so the connecting side controls both budgets. A new
session (reconnect or restart) starts again from the configured policy.

This control protocol assumes a retained reliable TLS stream. Each control write
is bounded by the earlier of its five-second write limit and the original
transaction deadline. A timeout ends the runtime with `TimedOut` and emits a
terminal snapshot; the pending requester receives `Closed`, exposed by the shared
service as `OutcomeUnknown`, never successful application or rollback. A direction
may already have changed behind its barrier, so the session ends rather than
unilaterally restoring the old state. These current-profile bounds do not select
the future common session's timer values. There is still no general Swift
heartbeat/dead-peer deadline outside a policy change. General common-control
retry, reconciliation and cross-profile switching remain required by SW-11,
SW-15 and SW-16; a successful local `set-swift` is not evidence for those gates.

## Bounds and failure behavior

Per channel: at most 4096 unconfirmed sources, at most `2 * window` pending
equations, one unfinished packet of receive stream beyond the flow bound, eight
header contexts. Across channels: one shared packing-queue budget of about 20 ms
of the send budget. A packet that does not fit is refused before compression so
the two header contexts cannot diverge.

Unauthenticated, replayed or mis-sized datagrams are counted and ignored.
Authenticated data that is structurally inconsistent ends the session with an
error. Socket errors that describe the path (full buffer, unbound peer,
firewall or connection-tracking drop, missing route) are treated as loss; the
loopback test first exposed this as a transient `EPERM`.

## Historical measured results

The following saved runs used unprivileged namespaces, `tools/selftest.py`, sixteen CUBIC flows, release
build, TAP devices bridged to the traffic hosts, shaper counting IP bytes,
tunnel budget 99% of the shaped rate:

| Path | Inner minimum RTO | Forward goodput | Simulator at equal overhead | Ratio |
| --- | --- | --- | --- | --- |
| 100/10 Mbit/s, 70 ms, 15% loss | 1000 ms | 79.74, 80.50, 79.91 Mbit/s | 80.72 Mbit/s | 98.8–99.7% |
| same | kernel default 200 ms | 79.23 Mbit/s | 79.04 Mbit/s | 100.2% |
| 100/10 Mbit/s, 70 ms, 1% loss | 1000 ms | 93.41 Mbit/s | 94.55 Mbit/s | 98.8% |
| 100/10 Mbit/s, 70 ms, no loss | 1000 ms | 93.69 Mbit/s | 94.61 Mbit/s | 99.0% |
| 100/10 Mbit/s, 2 ms, no loss | 1000 ms | 92.80 Mbit/s | 94.58 Mbit/s | 98.1% |

Each run measured 30 s after a 10 s warm-up; payload was verified, all sixteen
flows closed cleanly, the layer-2 checks passed in both directions and both
endpoints answered `status`. The simulator numbers are the mean of three
replications. An earlier set of the same runs is kept in
`work/swift-selftest39/`. The tunnel paces at 99% of the shaped rate while the
simulator uses all of it, which accounts for most of the remaining difference.

After the session moved into the shared lifecycle service, the reference path
measured 79.20 Mbit/s (98.1%) and the clean path 93.80 Mbit/s (99.2%), each
followed by a successful disconnect and reconnect of the live tunnel
(`work/swift-selftest43/`). Two runs taken while the test machine was heavily
loaded by unrelated work measured about 49 Mbit/s (`work/swift-selftest42/`);
the previous build measured 62–69 Mbit/s under the same load and both builds
reached 80.0 Mbit/s when it eased, so those runs show the harness's
sensitivity to scheduling, not a difference between builds.

With the key chain and 64-bit sequences the reference path measured 79.35
Mbit/s (98.3%), again with a successful disconnect and reconnect
(`work/swift-selftest44/`).

Retransmissions were 17.5–17.7% of sources on the 15% path. The simulator's
published candidate uses a 36-byte outer header and no authentication bytes and
reaches 82.3 Mbit/s; this tunnel's datagram carries 57 bytes of IPv4, UDP,
packet number, AEAD tag and source header, so the comparison above reruns the
same study function with `authentication_bytes=21`. Before this profile the
existing rolling profile measured 18.1 Mbit/s on the clean path in the same
harness.

Simultaneous reverse bulk traffic on the 15% path gave 58.2 and 8.1 Mbit/s: the
10 Mbit/s reverse budget is then shared between reverse data and forward
acknowledgements. That is a distinct workload, not the reference.

### Policy-change receipts

The later [under-load policy-change receipt](../../work/swift-selftest45/impaired-switch-under-load.json)
records a committed change, successful lifecycle checks, verified payload and
sixteen clean flow closes. It measured 63.188 Mbit/s against the 80.72 Mbit/s
reference, so `meets_reference` is false even though `integrity_passed` and
`passed` are true: the harness only requires the performance gate when
`--require-reference` is selected. Preserve the negative receipts as well:
[the initial run](../../work/swift-selftest45/impaired.json) failed lifecycle
checks; [the second](../../work/swift-selftest45/impaired-2.json) reached 79.614
Mbit/s but failed a full-MTU functional check; [the third](../../work/swift-selftest45/impaired-3.json)
failed a full-MTU check and measured 78.590 Mbit/s below the reference threshold.
All three report `integrity_passed: false` and `passed: false`. These finite
receipts do not identify their failures' cause, qualify SW-13 as complete, or
establish the current source or a different selected carrier's behavior.

The [saved aggregate check](../../work/udp-framing-wording-20261113-final/validation.json)
failed Clippy in `l2tunnel-runtime::swift` (`manual_is_multiple_of` in a test).
The [separate focused receipt](../../work/udp-framing-wording-20261113-final/focused-validation.json)
records 467 passing Rust test executions including doctests and passing rustdoc,
with the required aggregate check still failed. Neither is a fresh check of
the policy-deadline correction, a native lab run, remote CI or platform qualification.
The [policy-deadline checkpoint](../../work/swift-policy-deadline-20261113/validation.json)
records its local validation result and source identity; the historical receipts
above remain unchanged.
