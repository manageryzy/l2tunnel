# Explicit TUN TCP proxy

Status: bounded relay primitive implemented and locally tested; native interception
and client selection remain planned. Transparent active TUN still preserves
endpoint TCP bytes. This optional profile terminates TCP at each tunnel end and
keeps application bytes, including application TLS, opaque. It is not selected by
the current CLI and does not change established transparent connections.

The [bounded session dispatcher](proxy-session.md) now composes actual reserved
IPv4/IPv6 legs with lifetime ownership rules and reliable terminal notices. Its
native/runtime/QoS integration remains pending, and its documented sustained-loss
test bound is not qualified by the passing primitive tests.

## Ownership and first slice

The pure `l2tunnel-tcp-proxy` crate first implements one bounded relay leg around
the maintained `l2tunnel-raw-tcp::TcpEngine`. Native complete IPv4/TCP packets enter
that engine; its real receive ring owns locally acknowledged bytes. Ordered
stream bytes cross an authenticated, reliable, ordered tunnel as scoped records.
The opposite relay inserts them into its maintained TCP send ring and retains
responsibility until the actual remote TCP ACK releases them. No application
consumption or durable receipt is inferred from a TCP ACK.

Two relays plus two independent application-side TCP endpoints form the first
deterministic integration test. It must transfer arbitrary bidirectional bytes
under native loss/reorder/duplicates, half-close correctly, expose actual local
zero-window pressure, and recover when the remote application drains. A retained
tunnel record cannot be discarded or replaced under carrier backpressure.

`Leg::new(Config, raw_tcp::Config, Role, Millis)` constructs the maintained TCP
owner after validating finite resource dimensions. `ingest_packet`, `poll` and
`pop_packet` inject time and native I/O. `receive_authenticated` accepts only
records delivered by a previously authenticated reliable ordered session.
`pending_record` borrows one immutable output; `confirm_record_sent` releases it
only after the carrier takes ownership. Native packet ownership similarly moves
to the caller until native send completes. No socket, runtime, clock, TLS object,
route or platform handle belongs in this crate.

`Config` binds a nonzero session/epoch/flow `Scope`, maximum record bytes, maximum
byte/record windows and initial target windows. `set_target` can raise/lower future
credit within those maxima; already advertised cumulative credit is irrevocable.
This primitive does not claim a measured target algorithm or dynamically resize
the maintained TCP receive ring. Integration must connect the existing measured
target/QoS machinery, and distinguish local advertised TCP window, tunnel credit,
and remote TCP send/congestion windows in status.

The first slice supports the exact-tuple, unfragmented IPv4/IPv6 TCP engine's
validated capabilities. Additive `Leg::new_ip(Config, TcpIpConfig, Role, Millis)`
selects a same-family tuple; the original IPv4 constructor remains unchanged.
IPv6 extensions, fragments, jumbograms and ambiguous scoped endpoints remain
unsupported. Original-SYN interception, options policy, remote-open coordination
and native TUN runtime are separate required slices. The next
[pre-acknowledgment admission design](proxy-admission.md) freezes those initial
packet and remote reservation boundaries before implementation.
There is no fallback midway through an owned TCP stream. TCP-AO/MD5, unsupported
IP/TCP options and simultaneous-open handling require admission policy before any
local ACK. A runtime must authenticate and reserve the remote leg before exposing
the local SYN-ACK; the primitive alone is not that admission protocol.

## Record and accounting contract

Each record has a canonical 40-byte header: `LTPR` magic(4), version(1), kind(1),
zero reserved(2), session(16), epoch(8), flow(8), all integers big endian. The
authenticated carrier supplies direction and framing. Kinds are Credit(1),
Data(2), Fin(3); each body begins with two u64 values. Credit carries cumulative
byte/record grants; Data carries zero-based record index and byte offset followed
by 1..max_record_bytes actual payload; Fin carries exact final byte/record counts.
Exact length, scope, reserved bits and checked arithmetic are validated before
mutation. Data must be contiguous and within both grants. There is no transparent
packet rewriting, synthetic Ethernet wrapper or special SYN/probe QoS lane.

Each received Data record retains an end offset until the maintained send ring
has actually acknowledged that end. Pending payload plus maintained send-ring
payload is bounded by the byte window; retained record boundaries are bounded by
the record window. Credit is renewed from acknowledged bytes/complete records,
not from merely calling `write`. A reset/timeout/abort must be checked before
interpreting a shrinking send queue as acknowledgment. One immutable output and
bounded native packet queues supplement these negotiated limits.
Maximum record size must fit the maintained send ring. Injection waits until the
complete next record fits, transfers it in full, and drops its temporary payload
allocation. This avoids retaining already copied prefixes across partial writes.
Fixed send/receive rings, bounded native queues and record metadata are separately
allocated resources; original-byte credit is not a total process-memory metric.

Remote Fin is accepted only at the exact contiguous receive boundary. It requests
the local TCP FIN after all accepted bytes enter that engine, whose maintained
retransmission/FIN handling remains authoritative. Local TCP EOF emits Fin only
after every original received byte has entered the ordered tunnel. Incoming data
after Fin, conflicting Fin, regressing credit, counter exhaustion, malformed
records and abnormal maintained termination fail explicitly. EOF of the tunnel
before completed ownership transfer must abort both local legs; resumption and
crash recovery are not implemented by retaining an in-memory ACK counter.

## Acceptance checklist

- [x] [MOD-PROXY-01] Implement canonical scoped record codec, transactional rejection and finite byte/count accounting around a maintained TCP leg. Evidence: [pure leg](../../crates/l2tunnel-tcp-proxy/src/lib.rs), [eight focused tests](../../crates/l2tunnel-tcp-proxy/src/tests.rs).
- [x] [MOD-PROXY-02] Test four independent TCP owners with arbitrary bidirectional bytes, loss/reordering/duplicates and exact half-close behavior. Evidence: [four-owner test](../../crates/l2tunnel-tcp-proxy/src/tests.rs), simultaneous bulk and request/EOF/reply with and without deterministic impairment; all four maintained owners reach clean Closed.
- [x] [MOD-PROXY-03] Verify actual packet advertised-window pressure/reopening, irrevocable grant reduction, remote ACK-based release and bounded blocked-carrier ownership. Evidence: [pressure and blocked-carrier tests](../../crates/l2tunnel-tcp-proxy/src/tests.rs), exact TCP window fields and original-byte/record ownership bounds checked each tick.
- [x] [MOD-PROXY-04] Test malformed/scope/offset/replay/credit/FIN/exhaustion and reset/timeout failures without false clean completion or credit. Evidence: [transactional rejection, independent count credit, timeout/reset tests](../../crates/l2tunnel-tcp-proxy/src/tests.rs), abnormal maintained termination checked before ACK accounting.
- [x] [MOD-PROXY-05] Run focused warning-denied checks and a stable aggregate workspace validation for the primitive. Evidence: [wave5 receipt](../../work/implementation-wave5/validation.json), 420 Rust cases and 28 Python tool cases, full strict checks with identical before/after source hashes; native proxy remains unqualified.
- [ ] [MOD-PROXY-06] Add authenticated remote Open/Ready/reject, bounded SYN retention, explicit preownership fallback and source/destination-preserving IPv4/IPv6 TUN runtime.
- [ ] [MOD-PROXY-07] Integrate measured aggressive few-flow targets, shared QoS/MUX and reliable transport ownership; qualify all three window domains separately.
- [ ] [MOD-PROXY-08] Expose explicit shared client/CLI selection and qualify Linux native IPv4/IPv6, FIN/RST, protected-option fallback and isolated netem receipts.

References: [TCP, RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html),
[performance-enhancing proxy tradeoffs, RFC 3135](https://www.rfc-editor.org/rfc/rfc3135.html),
and the pinned smoltcp 0.14.0 public socket API used by the existing TCP engine.

Local commands executed: `cargo test -p l2tunnel-tcp-proxy --offline` passed eight
tests; warning-denied targeted Clippy and rustdoc passed. Independent read-only
review found no material ownership/accounting blocker. The deterministic lab
uses a caller-authenticated-record precondition; it is not real TLS, native TUN,
a proxy admission handshake, or a sustained throughput/fairness result.
The four-owner transfer, native-window pressure and blocked-carrier tests now run
in both IPv4 and IPv6, including concurrent and request/EOF/reply traffic.

The first pressure assertion used a one-byte future credit target and sampled
before the remote native receive ring filled; that fixture was still making ACK
progress. The final test lowers 1024-byte grants to a 512-byte/one-record target,
waits for real native zero-window pressure, verifies a stable ACK plateau, and
then restores capacity. The timeout test likewise starts the maintained deadline
at actual native transmission, not at send-ring insertion. Neither correction
changed the implementation's acceptance of lost payload or abnormal closure.
