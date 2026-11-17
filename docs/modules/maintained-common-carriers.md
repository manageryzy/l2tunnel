# Compact Common records on maintained TLS and QUIC

Status: the retained transport adapters, actual-owner authentication handoff and
Common runtime/service integration are implemented. The current compact cutover
has passing real TLS/QUIC Full capture evidence. The two TLS Half shutdown
failures now have passing focused continuations after cancellation ordering was
corrected. Current proxy shared-service and aggregate qualification are pending.
See the [current cutover ledger](compact-wire-cleanup.md)
for current results. The finite earlier Full/Half matrix, shared-service results,
QUIC retries and OpenVPN timeout continuations below retain their original source
scope. They are not a pristine aggregate pass or qualification of every current
composition.

The current Common format supports genuine TCP/TLS and genuine Quinn DATAGRAM
transports. It is distinct from the minimal QUIC/media appearance over UDP and
from the raw TCP-shaped phase after a real TLS handshake. Historical experiment
receipts retain their original source and configuration. Swift remains a
record transport algorithm inside the selected carrier.

## Original ownership and authentication

The selected path consumes the original authenticated connection. Full retains
one connection; Half retains the actual two authenticated and challenge-paired
connections in global First/Second order. First carries client-to-server bulk
data and Second carries server-to-client bulk data. Bounded bootstrap, feedback
and management output can use either original lane. No second data socket,
replacement identity or reconstructed connection is created at the handoff.

The request binding is acyclic. Before outer authentication, the maintained
request commits the carrier kind, duplex, exact framing limits, queue/timer
policy, conservative admission charges, complete Common catalog, both role
resources, selected data protection and transaction settings. Actual TLS/member
results are checked against that request. Genuine QUIC additionally binds its
complete selected lane profiles through its existing SessionConfig commitment.
The later Common envelope commits the fresh actual outer session evidence.

`retained_tls::Link` and `quic::common::Carrier` can be constructed only from
actual original authenticated owners. Copying `maintained::Authenticated` or
SessionInfo does not create that ownership. `establish::maintained::Outer`
consumes the actual maintained adapter and runs the existing initial-only
cookie/quarantine/Noise state machine. `member::maintained` runs the existing
Joining protocol and transfers the original root, owner, clock origin and
bounded bootstrap tails into the Common runtime. Every layer retains the
original setup deadline; this path adds no periodic key-exchange timer.

The selected design retains one inner Common Records protector and the
transport's mandatory outer TLS/QUIC protection. This is not a claim of one
encryption operation for the complete packet. Removing genuine TLS/QUIC AEAD
would require a different transport and security contract. Server trust remains
the configured certificate/root policy; the requested TLS server name does not
replace server identity authentication.

## Exact application framing and admission estimates

| Transport | Initial setup | Selected final records | Observable send boundary |
| --- | --- | --- | --- |
| Maintained TCP/TLS | Four-byte length, one-byte Bootstrap discriminator, existing covered setup body | Four-byte length, one-byte Final discriminator, exact Common Records bytes | `TlsStreamFlushed` |
| Genuine QUIC | Existing 48-byte L2QD session/capability/sequence envelope and covered setup body | Exact Common Carrier-layout Records bytes in DATAGRAM | `QuicDatagramAccepted` |

The TLS length includes the discriminator and body. Its five-byte framing is
exact application overhead. A Common data record adds 21 bytes with the default
ChaCha20-Poly1305 protection, 37 bytes with HMAC-SHA256, or nine bytes with an
explicit AES-CCM4 or ChaCha20/CRC32C selection. Strong feedback/control adds
21 bytes. Proxy records carrying credit or lifecycle controls use the strong
authenticated-data arm when ordinary data selects a short check, so their record
overhead is 21 bytes even with that short-check selection. Before algorithm,
packing, fragmentation or management-body fields, TLS data totals are therefore
26/42/14 bytes respectively, and strong feedback/control totals 26 bytes;
genuine QUIC data totals are 21/37/9 bytes and strong feedback/control totals
21 bytes. The short-check proxy exception raises these data totals to 26 bytes
for TLS and 21 bytes for QUIC. Mandatory TLS records, QUIC packet protection and
headers, IP/TCP/UDP headers, ACKs, congestion behavior and retransmissions are
additional transport costs. TLS and QUIC may split or coalesce application
records, so these totals are not physical packet sizes or throughput predictions.

The maintained Geometry separates final and bootstrap maxima and overheads.
`charge` is a configured admission estimate; it is never a measured physical
byte count. Genuine QUIC currently reserves its configured IP/UDP allowance plus
a conservative QUIC allowance. TLS similarly authenticates its explicit
allowance. A profile that cannot fit its complete selected catalog is refused;
constructors do not truncate an algorithm, shrink a repair window or silently
change the requested policy.

Bootstrap and Final framing are disjoint. Before final selection, final traffic
cannot reach the Common verifier. The retained bootstrap decoder remains
bounded by the original setup cap, and its messages remain subject to the
existing setup/tail state machines. There is no trial legacy/final parser.
Final packet-number/replay checks and data-versus-strong-feedback authority stay
with Common Records. An outer authenticated transport does not promote a
short-check data record into inner control or recovery authority.

## Bounded I/O and receipts

The TLS adapter has one persistent input per original lane and independent
bounded User/Control output slots. Partial prefixes, bodies, writes and flushes
survive cancellation of a poll. Bytes, submission identity and absolute
operation cap stay fixed after admission; progress cannot renew a timeout.
Frames cannot interleave on a stream. At frame boundaries, class scheduling
keeps queued User and Control work progressing. Invalid lengths/discriminators,
partial EOF, write failure and expiry are terminal for the retained owner.

The QUIC adapter retains a bounded copied DATAGRAM and move-only submission
ticket through Quinn acceptance. Selected small records use the selected
minimum-size queue accounting. Algorithm feedback and management use DATAGRAMs;
the original reliable stream is retained for paired setup and monitored for
EOF/errors, not used as a reliable recovery-feedback bypass.

The common wrapper preserves separate original User and Control tickets.
Completed flush/acceptance receipts remain observable even when the same poll
detects a terminal condition. A late successful acceptance is retained as a
fact and does not become an on-time success. The runtime uses the actual named
transport boundary for recovery custody; it does not invent an OS transmission
timestamp, TCP acknowledgment or peer delivery. Maintained accepted-record and
record-byte counters remain separate from socket/UDP physical counters.

The shared CLI/service status distinguishes configured QUIC receive/custody
queue bytes from the smaller outgoing FIFO bound. `quic_queues` is ordered by
the original First/Second lanes. Requested values come from complete Settings;
effective values come from queue geometry retained from the actual authenticated
QUIC owners. A proxy observation without Settings therefore reports unknown
requested queue geometry while retaining actual effective geometry. TLS and
unavailable observations use `null`, never a guessed value. These fields are
static bounds, not live occupancy, network flight, throughput or physical send
observations. Offline inspection has no effective queue or connection claim.
The Common outgoing bound is the lesser of the configured queue and two
maximum-record allowances; receive/custody policy is unchanged. Focused CLI and
actual Half QUIC service assertions pass with the affected TLS service and extent
checks in the
[status/extent receipt](../../work/aligned-extents-20261117/repair-status-extents-gate1.json).

The local TLS `TCP_NOTSENT_LOWAT` optimization is implemented and has finite
local Linux verification. Before an original authenticated TCP stream is split
into retained readers/writers, every Full/Half
lane requests `2 * (max_record_bytes + 5)` unsent bytes and reads the socket option
back. The current matrix's 1,430-byte maximum therefore requests 2,870 bytes.
Linux/Android use the maintained `socket2` API; installation or readback errors
fail setup under its original cap. Other platforms retain their existing TLS
behavior and report the option as unavailable. API availability does not qualify
an Android or other platform runtime.

`local_tls_send_queue` is separate from authenticated policy: it reports the
derived request, actual per-lane readbacks and `not_observed`, `unavailable` or
`installed`. No wire bytes or policy digests change. The value is a local
unsent-data threshold, not a hard FIFO capacity, current occupancy or TCP flight
limit; kernel buffering can overshoot it. Send-buffer sizes, unacknowledged
flight, admission charges and original deadlines remain unchanged. This cannot
move control ahead of bytes already accepted into TCP or preempt a partial TLS
record, and does not establish that the observed control expiry is fixed.

The threshold, actual Full/Half socket readback, authentication-binding
independence and requested/effective status tests pass in
[required checks3](../../work/aligned-extents-20261117/required-repair-checks3.log),
alongside the retained TLS custody/deadline tests. That aggregate run still
fails four other cases, including the measured TLS proxy handoff deadline;
it is not a full verification pass. The
[continuation](../../work/aligned-extents-20261117/required-repair-checks3-continuation1.json)
passes workspace rustdoc and the external Common CLI/service process probe.

The [release6 AlignedCompact TLS reverse run](../../work/aligned-extents-20261117/matrix-tls-repair6-reverse-attempt1/aligned-compact-tls/result.json)
passes all 16 TCP flow byte/hash/EOF checks with 243,264 unique application bytes
in the 10-second sample, or **0.1946112 Mbit/s**. Both actual Full sockets report
an installed 2,870-byte threshold. The unchanged network is 100/10 Mbit/s,
35 ms delay and 15% loss each way. Captures report zero capture drops; the
sample contains 300,478 reverse-direction and 84,516 opposite-direction WAN IP
bytes. These totals include control, ACKs and retransmissions and are not
encapsulation overhead. The
[release4 attempt](../../work/aligned-extents-20261117/matrix-tls-repair4-reverse-attempt1/aligned-compact-tls/result.json)
ended with client whole-message control expiry at 23.190915 seconds and had no
qualified rate. These independent loss realizations do not isolate LOWAT as the
cause of the changed outcome or measure peak kernel queue occupancy.

The release6 pass remains narrow: receiving the complete stream took another
33.31 seconds after the measurement window, leaving approximately 0.59 seconds
before the original probe cap. Server TLS EOF followed the client's explicit
disconnect, so this receipt qualifies the finite native TCP workload, not orderly
bilateral shutdown. It does not close throughput, latency, measured-proxy or
platform qualification gates.

Control-before-User polling is restored in maintained output and runtime receipt
selection. The existing bounded owner admits pending management ahead of a held
User after a full QUIC FIFO becomes available; neither an accepted DATAGRAM nor
network congestion flight is recalled. The
[focused priority receipt](../../work/aligned-extents-20261117/trace-priority-focused2.json)
passes that actual-owner case, original-arrival Compact feedback handling and
the bounded scalar trace cases. This does not make feedback reliable or change
its original deadline.

The maintained runtime yields to the executor after each bounded Common work
turn. Ready custom QUIC futures do not themselves guarantee cooperative
scheduling. The same-turn receipt and bounded-input promotion preserve both
directions before the next turn; the yield does not renew any operation cap.

Storage plans validate checked sizes before new framing buffers are allocated.
The enclosing Common admission charges the actual new adapter/cell/buffer
capacity once. Preexisting TLS/Quinn internals, allocator metadata and bounded
future allocations are not claimed as a complete static memory reservation;
the full resource-qualification requirement remains open.

## Reused Common behavior and capability limits

`run_common_on_maintained` installs the same Common Driver, Bank, authenticated
management and sole runtime loop used by the existing carriers. It adds neither
a second recovery engine nor a carrier-specific copy of the switching state
machine. Complete catalog membership, requested/effective configuration,
negotiated epochs, drain barriers, idempotent retries and liveness remain the
existing owners' responsibility.

Genuine QUIC DATAGRAM feedback is lossy and subject to Quinn congestion and
queue behavior. Maintained TLS feedback traverses reliable ordered TCP. The
latter does not reproduce a Python model whose feedback traverses an unreliable
reverse link. Both require their own matching performance configuration rather
than borrowing historical simulator or raw/UDP results.

The native Common runtime entry point requires the existing Unix `AsRawFd`
device/readiness boundary. Current verification is local Linux. Portable
protocol codecs remain independent of Tokio, OS handles and real clocks; these
maintained transport adapters belong to the runtime/transport crates. This batch
does not establish native Windows or Android support, privileged TAP/TUN/raw
operation, production native CLI behavior, throughput or ISP QoS classification.

Protocol parseability, endpoint interoperability and resistance to identification
remain separate claims. Genuine outer TLS/QUIC remains governed by its actual
protocol implementation, while the application payload is our private tunnel.
The private member exchange and payload do not establish interoperability with
arbitrary HTTPS or QUIC applications, nor do they establish undetectability or
preferential network treatment.

## Shared service, CLI and observations

`Profile::new_maintained_compact` validates the complete catalog and selected
geometry before I/O. `bind_maintained` derives the effective envelope only from
the actual authenticated original owners. The service factory retains the
existing attachment, readiness, local control and teardown lifecycle; its
runtime entry is `run_common_on_maintained`.

The strict CLI selection is `--carrier tcp|quic --record-profile common`, with
`--common-transaction-plan` containing explicit `compact_wire` and a separate
`--maintained-policy` version-1 JSON file. `--udp-cover` selects the initial inner
bootstrap appearance only. The maintained policy contains the explicit First
tuple, the required Second tuple for Half, final/bootstrap geometry and complete
TLS or QUIC bounds. Ambiguous wildcard endpoints, inconsistent Full/Half lanes,
unknown JSON fields and conflicting `--udp-bind`/`--udp-peer` inputs are refused
before startup. Genuine QUIC policy additionally binds its application ID,
DATAGRAM queue bound, reliable-control window and idle/I/O timeouts.
This selected binding currently requires IPv4 or unscoped IPv6 endpoints.
Nonzero IPv6 scope/flow attributes are refused because they are host-local
routing state, not a shared authenticated peer tuple. Scoped IPv6 needs a
separate local-routing representation before it can be supported here.

The client uses its own trust roots and authenticated server name. Maintained
TLS permits independent `--sni`; this genuine QUIC implementation does not expose
independent SNI and reports that capability as unavailable. Offline
`inspect-common-transaction-plan` reports validated requested policy without
authentication: effective envelope/configuration, outer binding and actual lane
observations remain absent. Native Common service uses the existing local API4
catalog and negotiated-switch controls shared by CLI and GUI consumers.

`maintained_carrier` status separates requested policy from effective policy
reported by the running Driver. It includes actual original lane sessions and
tuples, actual outer binding, `TlsStreamFlushed` or `QuicDatagramAccepted`, and
the mandatory outer AEAD qualification. `physical_wire_bytes_observed` remains
false. Copied requested tuples or completion of outer authentication alone do
not populate an effective running-owner claim.

Maintained proxy and measured-proxy CLI selections are implemented through the
shared Common client/service API and retain the original authenticated carrier
owners. Fresh full-service qualification and aggregate validation for the current
cutover remain pending; implementation alone does not close the existing proxy,
TCP-window ownership or mode-parity acceptance requirements.
The additive same-owner reuse profile has its existing Full/native-IP/
PerConnection catalog constraints and needs actual composition evidence.

## Repair-batch observations (2026-11-17)

Release4's owned Linux `swift-arq-quic` forward phase passes at
0.341728 Mbit/s with the original 100/10 Mbit/s links, 35 ms and 15% loss each
way, sixteen native TCP flows and ten-second measurement window. The
[exact case](../../work/aligned-extents-20261117/matrix-quic-repair4-forward-attempt1/swift-arq-quic/result.json)
qualifies this finite phase after Control priority restoration. It does not
qualify QUIC reverse/simultaneous phases, all algorithms or a throughput target.
The [combined report](../../work/aligned-extents-20261117/matrix-report-repairs4-complete1/report.md)
retains the failed baseline and each selected phase's source/binary provenance.

The release4 `aligned-compact-tls` reverse attempt still fails. Its client reports
`whole-message control error: Expired` at runtime elapsed 23.190915 seconds;
the server subsequently reports `UnexpectedEof`. Both scalar traces show positive
source0 feedback applied: the client after its first physical attempt, and the
server after one retry. This attempt does not reproduce or explain the earlier
source0 `RetryExhausted`. The
[trace analysis](../../work/aligned-extents-20261117/compact-arq-trace4-analysis.json)
records original acceptance, authenticated feedback and application timestamps.
Each trace retains at most 512 events and overflows before the terminal failure,
so it cannot attribute that later control expiry. The independent local time
origins are not a cross-peer clock synchronization proof.

Two failure/observation corrections have
[focused passing checks](../../work/aligned-extents-20261117/receipt-and-proxy-errors-focused1.json).
Proxy failures now retain both the Common runtime error and joined actor error
when both exist, preserving the selected primary error's kind and source without
claiming temporal order. Success, joins and handoff caps are unchanged; this is
diagnostic correctness, not a repair of measured-proxy `HandoffExpired`.
Accepted-emission metrics now commit only after receipt identity, scope, length
and charge correlate with the retained output, while still counting a genuine
late acceptance before reporting its original deadline failure. Prepared output
and mismatched receipts never become sent-byte observations. These finite passes
do not close the failed aggregate gate or the current proxy requirements.

The later
[required-check continuation](../../work/aligned-extents-20261117/required-repair-checks2-continuation1.json)
passes the measured TLS proxy and both Half QUIC four-family switching cases.
It still fails measured QUIC proxy handoff, Swift TLS reconnect (`AddrInUse`),
and the Full QUIC CCM/CRC terminal checks after their switching exercises pass.
Formatting, strict workspace Clippy and rustdoc pass, but the Rust aggregate
does not. Earlier failed attempts retain their scope and unresolved causes;
these latest passes do not establish a general timing or throughput repair.

## Source and validation boundaries

The principal implementation seams are:

- `l2tunnel-runtime/src/retained_tls.rs`: actual Full/Half TLS ownership,
  persistent framing, bounded storage and named flush receipts.
- `l2tunnel-quic/src/common.rs` and `common/send.rs`: selected actual QUIC
  DATAGRAM framing, bootstrap capability/replay and retained send tickets.
- `secure_udp/maintained.rs` and `maintained_io.rs`: authenticated requested
  policy, actual lane evidence and common maintained-owner custody.
- `secure_udp/establish_maintained.rs` and `member_maintained.rs`: reuse of the
  existing initial-only Noise/member protocols and original tail owners.
- `secure_udp/transport_maintained_contract.rs`,
  `transport_maintained_carrier.rs` and `transport_common_maintained.rs`: complete
  catalog admission and installation into the existing Common runtime.

The [focused retained-TLS receipt](../../work/maintained-compact-20261117/tls-adapter-results.json)
records seven passing lower-adapter cases and the preserved earlier compile
failure. These checks cover real authenticated Full/Half connections,
exact framing and receipts, partial I/O cancellation, original deadlines, parser
limits, EOF cleanup, class progress, storage accounting and foreign/stale tokens.
Private synthetic streams test framing failure paths only; they do not create
public authentication authority. Genuine QUIC adapter checks separately cover
its actual transport owners. These lower-adapter passes precede later integration
edits and cannot serve as a complete source-final runtime receipt.

The [runtime receipt](../../work/maintained-compact-20261117/runtime-results.json)
preserves the first eight-case matrix (five passes and three failures), the exact
failed Full/CCM trace, the unsuccessful cooperative-budget candidate and all four
passing QUIC continuations after per-turn yielding. The failed trace reported
zero Quinn loss/congestion events and loopback RTT of 143/171 ms. The matching
passing Full/CCM continuation reported about 3.7 ms on both peers with the original
500 ms Pong cap unchanged. This is local scheduling evidence, not an ISP/network
or throughput result. Eight retained-TLS adapter cases and two wrapper cases,
including the partial-prefix timer regression, passed separately.

The matrix exercises actual TLS and QUIC Full/Half owners, both selected data
suites, bidirectional Unix-device bytes in Swift, Aligned, Packed and Rolling,
four authenticated switches back to Swift, matching Pongs, original lane release
and named receipt accounting. All final feedback uses the selected carrier.
Service, CLI and proxy compositions require their own receipts. Failed attempts
remain visible beside corrected continuations. The required
`python3 tools/check.py` result is recorded by the batch owner separately.

The [shared-client receipt](../../work/maintained-compact-20261117/client-results.json)
preserves policy/parser/requested-binding checks, real service mainflow evidence
and the corrected idle-supervisor fixture teardown. The final workspace run
passes both real shared-service cases: TLS Full with independently configured
SNI and our own certificate trust, and genuine QUIC Half. Each verifies actual
requested/effective identity, original tuples, native bytes, matching Pongs,
Swift-to-Aligned switching, post-switch bytes, disconnect and owner release.
Offline CLI inspection remains requested-only. Same-owner reuse has focused
configuration/capability evidence, not a maintained runtime-reuse receipt.

The [batch validation receipt](../../work/maintained-compact-20261117/maintained-compact-scoped-validation.json)
binds the final source and required-check continuations. The original command
is `python3 tools/check.py` with the existing simulator environment on `PATH`
and `RUST_TEST_THREADS=4`. Initial Clippy and test-callsite corrections are
preserved; passed prerequisite checks are not repeated. Final formatting and
all-target/all-feature Clippy pass. Workspace tests report 2,532 passed,
two failed and two ignored. Both failures are existing OpenVPN shared-service
test cases, which pass exact sequential retries using that same binary
([follow-up receipt](../../work/maintained-compact-20261117/openvpn-followup.json)).
Their failure cause is unqualified; no pristine aggregate pass or baseline-failure
attribution is made. All eight new runtime cases and both new service cases pass
in the workspace invocation. The remaining-stage continuation passes the codec
no-default-features branch (112 tests), warnings-as-errors rustdoc, existing
external CLI probes, two tooling groups (131 and 225 tests) and the full Linux
simulator suite (1,658 tests). Existing external CLI probes exercise their
documented UDP service paths; they do not qualify production maintained
connect/serve or TAP/TUN startup. All commands and source hashes are retained in
the batch receipt; these scoped continuations do not erase the aggregate failures.

Full SW-11, all 47 Python-mode entries, RLNC/parity/rolling/packed/compact,
independent recovery, proxy and existing mode-parity deliverables remain in
scope at their original definitions. This carrier integration does not complete
or narrow those parent requirements.
