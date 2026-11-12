# UDP packet runtime

Status: implemented and real TCP/TLS/UDP loopback integration-tested with two
independent memory packet devices. Native OS qualification has a separate receipt.
The design was written before implementation. This adapter composes existing authenticated
UDP, selectable selective-repeat/Cauchy recovery, frame compression and fragmentation.
It is one ordered data channel with fixed None/Lz4 compression. It does not implement
TUN adaptive QoS, standalone UDP bootstrap, hot reload or protocol interoperability.

## Frozen embedding interface

`runtime::udp::Config::new(duplex, cover, protection, path_mtu, ipv6)` supplies
finite defaults. Public Copy fields are `duplex`, `cover`, `protection`,
`path_mtu`, `outer_overhead_bytes`, `arq`, `control_timeout`,
`heartbeat_interval`, `reassembly_timeout`, `recovery` and `wire_budget`.
Every constructor validates again.
Defaults are 120 seconds for the control lease, 1 second for heartbeats and 60
seconds for incomplete reassembly. Pair setup must finish within the first lane
lease; the constructor fails closed if a delayed second authentication exhausts it.
No background heartbeat is claimed before `run`.
`base_session_config(runtime, config)` binds all behavioral/resource settings;
`session_config(runtime, config, Lane::{First,Second})` adds the exact UDP profile;
`carrier_config(runtime, config, lane, peer)` constructs the matching carrier
bootstrap input. Both peers authenticate that final digest before establishing UDP.

`Link::full(carrier, runtime, config)` consumes one established full carrier.
`client_pair(first, second, runtime, config)` and `server_pair(...)` consume two
independently authenticated half carriers. First is global client-to-server lane
0; Second is global server-to-client lane 1. Constructors reject mismatched digest,
identity, role, lane or duplicate session IDs before device reads. A random 32-byte
TLS challenge on First is echoed on Second and acknowledged on both lanes. The
same TLS connections remain live for control. `run(device, link, runtime, config)`
checks the retained binding once more and owns all socket tasks until termination.

## Wire and bounded state

Data is native packet -> versioned FrameCodec record -> bounded fragments ->
selective-repeat source -> protected UDP datagram. MTU accounting includes actual
outer IP/UDP, custom cover, protection header/tag, ARQ header and fragment header.
Each retry calls the unique UDP sealer again, obtaining a fresh nonce while
retaining its logical ARQ source identity. No OS IP fragmentation is requested.
The fixed epoch is 1. Per-lane full session IDs/roles bind ARQ; fragments carry a
shortened context only inside that fully authenticated and validated envelope.

TLS control uses an 8-byte `L2UC`, version 1, kind, u16 big-endian length header.
Kinds: heartbeat 1/length 0; ACK 2/length 48 for selective repeat or 56 for
Cauchy, selected from authenticated configuration; cumulative actual
native delivery credit 3/length 8. Unknown kinds, lengths, role/context mismatch,
regressing credit or credit beyond admitted frames terminate the link. Device
EtherTypes never enter this control parser. UDP accepts only the selected engine's source/systematic/repair records; TLS accepts
only its feedback. ACKs are cumulative/bitmap engine output, not arbitrary user ACKs.

Each lane owns bounded ARQ windows, one pending outbound fragment batch, one
incomplete ordered reassembly, bounded complete native packets and one UDP writer
slot. The sender limits admitted native packets by actual peer device delivery,
including packets stalled on WouldBlock. This is fixed runtime admission credit,
not the planned adaptive TUN flow-control ledger. Native input uses the shared 65536-byte maximum-plus-one buffer contract while
still enforcing the configured native packet limit before encoding.
Reassembly timeout is terminal:
ACKed partial records are never silently forgotten while claiming reliability.

Long-lived readers retain partial TLS framing across timer events. Each TLS writer
retains its in-flight record and coalesces pending ACK/credit snapshots; periodic
heartbeats are a timer, never an accumulating queue. Control reads continue while
the device is blocked. The carrier's finite idle lease closes UDP if authenticated
TLS input stops. Task cancellation drops all child futures and unique key owners.
EOF with pending work fails explicitly; reconnect/resume is not implemented.

## Acceptance tasks

- [x] [MOD-UDP-RUNTIME-01] Canonical binding, constructor validation, real pair proof. Evidence: [constructors and digest](../../crates/l2tunnel-runtime/src/udp.rs), [binding and constructor tests](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-UDP-RUNTIME-02] Actual native packet bytes over real TCP/TLS/UDP, full and paired half, TAP/TUN contracts, both covers/protections, MTU fragmentation, exact delivery under deterministic loss/reorder. Evidence: [16-case loopback matrix](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-UDP-RUNTIME-03] WouldBlock credit bounds, malformed/authenticated dispatch separation, retained TLS closure, coalesced blocked writer, retry/reassembly terminal failure and native sentinel limit. Evidence: [focused failure tests](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-UDP-RUNTIME-04] Local fmt, tests, Clippy, rustdoc and aggregate checks. Evidence: [validation commands below](#local-validation), [aggregate runner](../../tools/check.py).
- [x] [MOD-UDP-RUNTIME-05] Privileged owned-namespace/native UDP qualification: 36 no-FEC profile cases and nine fixed-Lz4 cases. Evidence: [independent native UDP audit](../../work/native-udp-matrix-audit.json), [Lz4 receipt](../../work/native-udp-lz4/receipt.json).
- [ ] [MOD-UDP-RUNTIME-06] Additional FEC profiles, hot switching, rekey, standalone UDP
  bootstrap and adaptive QoS remain separate work.

The loopback matrix has deterministic every-seventh-datagram loss and
periodic reordering. It checks both directions byte-for-byte using a 576-byte
outer path MTU and 2500/3200-byte native packets. A blocked receiving device retains
exactly the configured two admitted packets while reverse traffic and TLS feedback
continue. This finite local test does not establish congestion fairness, Internet
reliability, Windows/Android device support or Python experiment parity.

## Local validation

Executed on local Linux: `cargo fmt -p l2tunnel-runtime`,
`cargo test -p l2tunnel-runtime --offline` (23 unit/integration tests, including
11 UDP tests), `cargo clippy -p l2tunnel-runtime --all-targets --offline -- -D warnings`,
`RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-runtime --no-deps --offline`,
and `python3 tools/check.py` all passed. Aggregate output for this implementation
wave was saved at `/tmp/l2tunnel-udp-runtime-check.log`; it is a temporary local
receipt, not a portable CI artifact. Remote CI, Windows/Android devices and
privileged native qualification are separate gates.

## Selectable Cauchy recovery and common emission allowance

Status: implemented and real TCP/TLS/UDP loopback integration-tested. This section
was designed before implementation. The no-FEC mode and `Config::new` remain default.

The public Copy configuration includes `recovery: RecoveryMode` and
`wire_budget: WireBudget`. `RecoveryMode` is `SelectiveRepeat` or
`Cauchy { sources: usize, repairs: usize, flush_after: Duration }`.
`Config::with_recovery(mode) -> io::Result<Config>` recalculates the bounded ARQ
source width and send/receive byte limits after subtracting every coding header.
No root/client code must guess these dimensions. Cauchy sources and repairs are
bounded to 1..=16 each and the source count cannot exceed the negotiated ARQ windows.
The existing `session_config`, `carrier_config`, pair constructors and `run` remain.

`WireBudget { interval: Duration, packets: usize, wire_bytes: usize }` is one
finite admission allowance shared by both directions/lanes of a local Link and
by UDP source/systematic/repair/retry records and TLS feedback/credit/heartbeats.
Defaults are 128 protocol records and `128 * path_mtu` accounted bytes per
1 millisecond. Three control frames per physical lane, each charged at the maximum
selected feedback length plus control framing, are reserved within that total.
The allowance refills only
on the monotonic runtime interval, never on each engine poll. A finite internal
control reservation is included inside the overall allowance; data cannot spend
that reservation. This fixed pacing allowance is not congestion control.

The Reliable engine is authoritative for envelopes and FEC. The runtime calls
`poll_data` and `poll_feedback` separately with the same underlying budget ledger,
and uses `inspect_peer` before transport-specific dispatch. Reliable feedback is
56 bytes (8-byte envelope plus the existing 48-byte ACK); no-FEC feedback remains
48 bytes, selected only from authenticated configuration. Data input may be a
source/systematic/repair record, and TLS feedback must classify as Feedback.
`RestoredCapacity` is recoverable pressure. Malformed coding, conflicting restored
sources, wrong role/context and exhausted retries terminate the link.

For Cauchy, maximum emitted plaintext is
`8 + 56 + sources + 2 + 44 + arq.max_source_bytes`; fragment bytes remain the ARQ
source payload. Original coded ARQ input must not exceed the FEC 4096-byte ceiling.
Derived decoder generations, symbols, matrix reservation, per-symbol work, expiry,
restored packet/byte limits and partial-block age are finite and all enter the
canonical authentication digest (`udp-runtime/v2`), together with the exact
emission allowance. The decoder lifetime is the initial RTO in milliseconds
(minimum one); generation count is `min(64, ceil(receive_window / sources) + 1)`;
source/repair/scratch reservations are derived from those bounded dimensions.
FEC expiry falls back to retained ARQ; native reassembly expiry remains terminal.
No repaired source consumes a new native admission credit. An intentionally
slow pacing budget can extend local queue age past the configured RTO; retry
exhaustion remains explicit, rather than silently resetting the timer.

The adapter charges external overhead rather than asking Reliable to assume that
UDP and retained TLS have the same framing cost. Reliable's internal external
overhead is zero and every returned record receives the correct adapter charge.
UDP charge includes complete protection and configured IP/UDP overhead. TLS control
uses a documented conservative allowance for its framing, two TLS records and two
maximum-header TCP packets. This accounting does not measure kernel segmentation,
ACK traffic or retransmissions and is not a claim of exact physical wire bytes.

Budget is charged before admission to a bounded writer. Previously admitted
in-flight/queued records may carry across a refill boundary; there are at most the
existing one in-flight and one queued data record per lane and coalesced control
snapshots. Superseded ACK reservations are not refunded. Credit and heartbeat
writes acquire their allowance from the same ledger, so control never has an
unaccounted bypass. Writer waits do not cancel/restart partial frames.

- [x] [MOD-UDP-FEC-01] Freeze recovery/budget helpers and bind exact derived configuration; reject over-MTU or unsupported settings before device reads. Evidence: [configuration and binding](../../crates/l2tunnel-runtime/src/udp.rs), [configuration tests](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-UDP-FEC-02] Compose authoritative Reliable split polling/inspection with per-lane framing, bounded ARQ fallback and unchanged logical native credit. Evidence: [Engine adapter and runtime](../../crates/l2tunnel-runtime/src/udp.rs).
- [x] [MOD-UDP-FEC-03] Enforce one finite common interval allowance with reserved internal control service, including TLS ACK/credit/heartbeats under blocked writers. Evidence: [shared Ledger and writer](../../crates/l2tunnel-runtime/src/udp.rs), [cross-lane, distinct-framing and low-quota tests](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-UDP-FEC-04] Test actual authenticated UDP loss repaired before first RTO, insufficient parity followed by real ARQ fallback, full/half TAP/TUN, bounded backpressure and exact maximum wire framing. Evidence: [18 UDP tests including 16-case Cauchy matrix](../../crates/l2tunnel-runtime/src/udp_tests.rs).
- [x] [MOD-UDP-FEC-05] Run local formatting/tests/Clippy/rustdoc and aggregate checks, with native receipts and remaining modes recorded separately. Evidence: [FEC validation below](#fec-validation), [aggregate runner](../../tools/check.py).

## Native qualification for this adapter

The integrator executed 36 no-FEC cases across both covers and both protection
suites, plus nine fixed-Lz4 cases. It separately executed 36 Cauchy cases. Each
nine-case profile includes TAP/TUN/native VXLAN, full and paired half clean paths,
and half-mode netem paths. Receipts include actual IPv4/IPv6 native probes,
byte-exact TCP payload verification, owned-namespace cleanup, UDP packet capture,
and a scoped UDP-only outage that leaves the retained TCP control connection
established and verifies restoration. The underlay used IPv4 and a 1200-byte path
MTU. See the [UDP audit](../../work/native-udp-matrix-audit.json),
[Lz4 receipt](../../work/native-udp-lz4/receipt.json) and
[Cauchy audit](../../work/native-fec-matrix-audit.json).

Integrity-profile captures contain genuine systematic and repair symbols in both
directions, validated against the exact LD/L2RF/FE framing and saved binary/capture
hashes. Captures do not verify secret MAC keys or prove which particular equation
caused reconstruction. The independent two-endpoint loopback test establishes the
separate repair-before-RTO and insufficient-rank-to-ARQ behavior. These finite
receipts establish packet delivery and MTU constraints, not coding efficiency,
congestion fairness or a cross-platform performance claim.

- [x] [MOD-UDP-FEC-06] Qualify native Cauchy data delivery, MTU, retained control during UDP outage, systematic/repair emission and cleanup in 36 owned-namespace cases. Evidence: [native FEC matrix audit](../../work/native-fec-matrix-audit.json).

## FEC validation

After the Cauchy adapter and shared allowance changes, executed on local Linux:
`cargo fmt -p l2tunnel-runtime`, `cargo test -p l2tunnel-runtime udp::tests --offline`
(18 UDP tests), `cargo clippy -p l2tunnel-runtime --all-targets --offline -- -D warnings`,
`RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-runtime --no-deps --offline`,
and `python3 tools/check.py` all passed. The aggregate local log is
`/tmp/l2tunnel-udp-fec-check.log`; the integrator's stable workspace snapshot is
separate evidence for the complete concurrent implementation wave.
