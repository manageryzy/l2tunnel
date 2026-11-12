# Implementation status and evidence

This page records finite implemented scope. The master checklist and module
checklists remain authoritative for unfinished requirements and mode parity.

## Current parallel checkpoint

The [source24 aggregate](../work/implementation-wave24/validation.json) passes
1144 Rust test executions including explicit feature variants, 201 Python tool
cases, and 1654 simulator cases with all 795 copied inputs stable. The test-review
repairs, pure bandwidth/RTT delivery controller, and opt-in runtime profiling are
committed separately. Its [exact release build](../work/native-build24/receipt.json)
completed four serial TAP/TUN clean/delay half-duplex profiling cases with exact
payload and owned cleanup. All four still fail the 80 Mbit/s forward target.
[Independent profiling](../work/throughput24-analysis/24p-final4/report.md) observes
the 64-record credit limit blocking admission despite no local queue-full events.
The source25 runtime integration separates local queues from the authenticated
BDP budget and has passed204 focused runtime tests plus shared-client policy
tests. Its aggregate and native throughput checks remain pending and are not
covered by source24's acceptance.

The [source23c aggregate](../work/implementation-wave23c/validation.json) passes
1055 Rust and 198 Python tool cases with all 658 inputs stable. Its exact release
build completed twelve matched native half-duplex cases: six system and three
measured-proxy transfers passed exact-byte/EOF measurement; the three 15%-loss
cases failed their original probe deadlines. All owned cleanup passed. Every
accepted forward rate fails the owner's 80 Mbit/s target. See the
[profiling ledger](modules/managed-profiling.md) for separate integrity and
performance evidence. Runtime profiling and bandwidth/RTT-based outstanding
credit are the current priority. The five new test-review repairs are tracked
in [review follow-ups](review-followups.md); their combined gate passed in source24.

The [source23b aggregate](../work/implementation-wave23b/validation.json) passes
1055 Rust and 195 Python cases with all 658 copied inputs stable. Proxy control
pacing and rolling/raw registration retirement are committed. Its
[release build](../work/native-build23b/receipt.json) matches the checked source.
The first eight native throughput attempts authenticated and connected their
application sockets, but stopped before measurement: this host's iproute2 6.1
prints plain text for `tc -j class`. All owned namespaces were cleaned up and
these attempts supply no accepted speed or window measurements. The
[independent audit](../work/throughput23-analysis/system-half-first-failed-v2/report.md)
preserves this tool-compatibility failure separately from protocol results.
The corrected harness also replaces the clean-lab measured-proxy timing policy
with one explicit WAN policy shared by every comparison path. Historical
pressure policies and their original receipts remain unchanged.

The [source22 aggregate](../work/implementation-wave22/validation.json) passed
1034 Rust and 183 Python cases with all 649 copied inputs stable. It includes
the base absolute handshake deadline and aligned/packed idle-flow retirement
repairs. Both fixes are committed; the subsequent source23b check above adds
proxy control pacing and rolling/raw flow retirement.
The owner's current priority is actual directional throughput and window traces
under matched delay/loss profiles; clean same-host transfers are only a baseline.

The first [source23 aggregate](../work/implementation-wave23/validation.json)
failed two client-control deadline fixtures: their 100 ms shutdown limit with
the default 256 control records/s no longer fits the validated pacing policy.
The original stable failed snapshot is retained. A derived correction keeps the
same 100 ms deadline and retry/failure assertions, selects an explicit matching
512 records/s test policy on both peers, and separately tests rejection of the
old infeasible combination. It does not change production defaults or renew
network deadlines. The throughput harness has independent kernel-loopback
accounting evidence; native performance remains pending the combined gate.

The [source21 aggregate](../work/implementation-wave21/validation.json) passed
1017 Rust and 183 Python cases with all 642 copied inputs stable. It integrates
the real TLS/HTTP2 carrier and final rolling protected-counter capture agreement.
These are committed module checkpoints, not native or performance qualifications.
The [native window investigation](modules/native-window-qualification.md) tracks
the owner's priority on actual TCP-window ownership and measured TAP/TUN speed.

The [source20 aggregate](../work/implementation-wave20/validation.json) passed
999 Rust and 183 Python cases, formatting, strict lint/docs, golden and CLI
checks with all 632 copied inputs stable. It includes the raw AEAD capture
harness, first rolling native harness and matching rust-analyzer toolchain
components. It excludes the subsequent rolling protected-counter agreement
correction, HTTPS integration and three [review fixes](review-followups.md).
No source20 native build or execution is qualified by this aggregate.

The [rolling-client/native-harness aggregate](../work/implementation-wave19/validation.json)
passed 999 Rust and 154 Python cases plus required formatting, strict lint/docs,
golden and CLI checks. All 629 copied inputs remained unchanged. It includes the
explicit rolling client, bounded pressure-only WAN capture allocation, corrected
raw capture/startup audit and deterministic oversized-RPC fixture correction.
The [exact native build](../work/native-build19/receipt.json) passed and matches
the complete checked source map. The raw finite native result is recorded below;
the corrected proxy pressure reruns failed growth acceptance, as recorded below.
Concurrent HTTPS and rolling native harness work is excluded from this snapshot.

The [wave18 frozen aggregate](../work/implementation-wave18/validation.json)
passed 987 Rust and 142 Python cases, formatting, strict workspace Clippy,
warning-denied rustdoc, golden vectors and CLI checks. All 620 source inputs
were unchanged during the run. The [exact native build](../work/native-build18/receipt.json)
matches that complete input map. This includes the raw opener/client and native
harness, rolling scheduler/runtime, causal raw fixture correction and directional
proxy-pressure correction. Subsequent HTTPS, rolling-client and pressure-capture
allocation work is excluded. The [wave16b aggregate](../work/implementation-wave16b/validation.json)
remains the earlier 593-input, 949 Rust/126 Python checkpoint.
The derived [wave17 aggregate](../work/implementation-wave17/validation.json)
kept all 608 inputs stable but failed the raw paired-lane review test's pending
message precondition (`pairing_review_tests.rs:299`), after 524 Rust and two
Python cases. Its original receipt is retained. It is not a passing aggregate.
The [derived pairing fixture](../work/raw-pairing-precondition18/validation.json)
now reproduces the early observation deterministically and waits for the original
driver's actual blocked send, keeping all original authority/deadline assertions.
Its 152 focused cases and strict lint pass. Wave18's aggregate and exact build
now pass; native acceptance remains separately gated.
The earlier [wave14b aggregate](../work/implementation-wave14b/validation.json)
remains the 562-input, 858 Rust/107 Python checkpoint for its historical native
builds; later results do not rewrite that evidence.

The [active workflow](development-workflow.md#current-composition-wave) now runs
raw packet native qualification, measured native pressure diagnosis and rolling
runtime integration in three independent source/build lanes. Aggregate/build/native
qualification uses a copied source checkpoint, releasing developers immediately
after copy verification. Clean native profiles use disjoint owned namespaces;
concurrent runs qualify finite connectivity/integrity, not performance.

The subsequent [rolling client checkpoint](../work/rolling-client19/validation.json)
passes 113 library and 19 example cases, including actual protected UDP and
genuine QUIC with both device layers and duplex modes. Strict policy parsing,
authentication binding, original setup expiry and cancellation are covered.
The [pressure capture allocation](../work/proxy-pressure-capture19/validation.json)
adds an explicit 32768-packet WAN allocation only for pressure profiles; native,
fixed and clean captures retain 8192, with unchanged payload/growth/window gates
and file/child/deadline limits. Both bundles passed the new copied source19
aggregate; they are not part of wave18 or new native qualifications.

The first copied wave14 failed because source identity collection excluded any
directory named `target`, including the real Rust module
`crates/l2tunnel-flow-control/src/target/tests.rs`. The correction includes that
source and adds two regression tests. [Snapshot lineage](../work/source-snapshot14b.json)
records the four-file derived correction; the original failed receipt is retained.
Historical source maps omitted this test file even when the original live-tree
checks executed it, so they do not establish its hash identity. No historical
receipt has been rewritten.

The [six clean packed native cases](../work/packed-clean-matrix14b/receipt.json)
passed for TAP/TUN/VXLAN in full and paired-half modes using that immutable build.
All six independent audits passed exact payloads, positive aggregation in both
directions, MTU/capture requirements and namespace cleanup. See the
[case evidence](modules/packed-native.md#clean-parallel-native-qualification).
Other carriers, impairment, performance and complete Python parity stay open.

The [rolling equation checkpoint](../work/rolling-recovery-checkpoint15/validation.json)
now passes 39 FEC unit and three two-owner integration cases. It reconstructs
actual bytes from independent received equations, retains fixed-support known
columns, bounds incremental work, and handles output pressure/deadlines. It has
no integrated repair scheduler or transport at that checkpoint. The subsequent
[pure scheduler checkpoint](../work/rolling-scheduler16/validation.json) passes
65 FEC cases, including bounded repair credit, idle tails, full-scope cumulative
feedback, lost final receipts and published-prefix pressure. The subsequent
[rolling runtime](modules/rolling-runtime.md) passes nine focused tests covering
16 actual authenticated UDP and four genuine QUIC scenarios, plus two shared
budget tests. It retains common MUX, bounded feedback/native ownership and original
deadlines. An observed Pipeline clock-domain mismatch and pre-native validation
ordering were corrected with regression evidence. Client activation, native
qualification and large-window deployment remain separate. The measured proxy
[shared client checkpoint](../work/proxy-measured-client/validation.json) passes
95 library and 19 example cases and invokes the actual measured runtime through
an explicit CLI profile. The subsequent wire codec adds nine focused cases.
These finite modules do not close the complete Python-family gates.

The [native original-packet opener](modules/raw-native-packet.md) passes 152
raw-I/O/raw-TCP cases with two privileged probes ignored. It returns the unchanged
descriptor and port reservation from the shared namespace/policy-validated
constructor. The [explicit shared raw client](modules/raw-packet-client.md)
passes 101 client and 19 example cases, selecting the actual authenticated packet
runtime with strict bounded settings, original setup deadlines and observable
capabilities. Its native qualification, congestion controller, clean drain and
hot reload are explicitly unavailable. These completed bundles entered wave17
and the passing derived wave18 aggregate; no native result follows from their
focused compilation or tests.

The [first four raw-packet native cases](../work/raw-native18-initial-audit.json)
all retain failed original receipts and passed owned cleanup. TAP/full and
TUN/full/half reached exact native transfer, confirmed fences and natural bounded
carrier-loss termination, then failed the capture auditor's hardcoded requested
horizon. Their actual effective horizon is 18560 bytes, bounded by the maintained
TCP window; the configured 32768 is a ceiling. TAP/half instead stopped at the
startup descriptor-count observation. The [corrected independent four-case
audit](../work/raw-native-matrix19-audit.json) now passes those three saved
executions plus the new source19 TAP/half execution. The auditor derives the
horizon from original captured TCP/SYN/Hello evidence; the startup fix samples
descriptors after actual Active status. Exact native bytes, original lane
continuity, natural bounded carrier-loss failure and all owned cleanup passed.
Original failed receipts remain unchanged. This finite clean integrity profile
does not qualify graceful close, congestion, AEAD or broader paths/platforms.

The source-stable wave15 aggregate failed in a paired OpenVPN-like UDP close;
its unchanged isolated rerun passed, leaving the original cause unattributed.
Wave15b with four test threads failed two QUIC cancellation/expiry socket-release
checks. Both original receipts remain preserved in the
[Git import provenance](checkpoints/2026-11-12.md). A successful observation build
does not erase these aggregate failures.

The completed derived-wave16 bundles include [raw packet runtime](modules/raw-runtime.md)
(158 focused raw/runtime cases, one privileged case ignored),
[QUIC ownership/deadline corrections](modules/quic-owner-cleanup.md)
(128 client/example/QUIC cases), and explicit original-deadline checks in
[OpenVPN-like close](modules/standalone-openvpn-runtime.md) (49 cases). The latter
fixes a deterministic late-ready completion bug; it does not attribute the older
paired close timeout. Root-owned source-stable aggregate validation is separate.

The default-concurrency [wave16 aggregate](../work/implementation-wave16/validation.json)
passed the previously failing QUIC/OpenVPN checks but stopped at the measured
stream fixture's `saw_echo` assertion, after exact payload transfer and before
drain. This was not a drain failure. A 500 ms public-status interval reproduces
the fixture's ordering mistake: native EOF can arrive in 210 ms before a coalesced
measurement snapshot. The corrected fixture keeps its measurement workload
active until both real samples are observed, within the unchanged five-second
transfer bound, then checks exact FIN/drain within its unchanged fifteen-second
bound. All 158 runtime cases and the complete wave16b aggregate now pass. The
original wave15/15b/16 failures remain preserved; a finite pass does not attribute
the older OpenVPN paired-close timeout or qualify a native pressure profile.

Both [measured native clean cases](modules/proxy-measured-native.md) and their
independent audits passed on the exact observation build. Both pressure cases
completed exact-byte transfers but failed measurement acceptance. Saved captures
show actual zero windows on all eight native legs; three reopen before the reader
release and fail the unchanged first-reopen condition. A real maintained-stack
regression now fixes the missing observation of unread native bytes stalled by
exhausted peer credit; 157 runtime and 36 harness tests pass, including pressure
clearing and ownership-safe failed-case socket cleanup. The subsequent exact-build
[full](../work/native-proxy-measured-full-pressure16b/receipt.json) and
[half](../work/native-proxy-measured-half-pressure16b/receipt.json) pressure runs
still failed acceptance: native payloads and owned cleanup passed, but growth was
suppressed. A directional audit found that the new pressure predicate duplicates
existing sender-credit demand, which must remain eligible for startup growth.
The [directional correction](modules/proxy-directional-pressure.md) separates that
source-side signal from downstream pressure using the maintained native peer's
actual advertised window and pending send bytes. Its 252 affected Rust cases,
435 vendor cases, two focused IPv6 vendor cases and strict checks pass; the
read-only observation uses a separately pinned incremental vendor patch and
preserves the original patch/archive. No corrected native rerun is claimed yet.
All eight independently audited first-reopen/ACK conditions passed in
these later captures; all four WAN captures reached their unchanged 8192-packet
bound, so complete carrier capture qualification is separately bound-exhausted.
See the [audit](../work/native-pressure16b-audit/REPORT.md). Native pressure,
adaptive window growth and QoS/fairness qualification remain open.

The exact source19 pressure reruns also remain failed: independent
[full](../work/native-pressure19-audit/full-audit.json) and
[half](../work/native-pressure19-audit/half-audit.json) readback shows all four
endpoint candidate peaks stayed at the initial 32768 bytes. Two-flow demand and
actual paused downstream pressure were observed, so growth is the missing
measurement gate. Exact application probes and all eight first-reopen/new-ACK
proofs passed. WAN captures now fit the explicitly bounded allocation (24158
packets per side in full, 25022 in half, below 32768), with zero kernel drops;
the earlier capture-cap exhaustion is resolved for these executions. Half's
structural capture audit passed; full separately lacks complete native
handshake/bidirectional-FIN evidence on one flow. Both cases stopped before
drain acceptance and completed owned cleanup. No pressure qualification or
unchanged rerun is inferred from the successful payloads.

## First native vertical slice

- Real maintained TCP/TLS 1.3, verified server identity/name without SNI, and
  exporter/transcript-bound Ed25519 allowlist authentication. Nine real loopback
  tests exercise wrong identity/configuration, malformed input, deadlines and
  cross-connection replay. See [authentication design](modules/auth.md).
- Persistent authenticated data streams, default paired half duplex and explicit
  full duplex; checked framing/sequence/session/layer, finite queues and device
  backpressure. See [runtime](modules/runtime.md) and [client core](modules/client-runtime.md).
- Linux TAP/TUN attachment with one reviewed ioctl boundary. Native IPv4 traffic
  crossed real TAP bridges and TUN devices in both directions, using 56- and
  1200-byte ICMP payloads. Four clean-link scenarios passed with exact packet counts. The first lossy
  receipt demonstrated connectivity, but its zero-loss acceptance was invalid:
  a substring check accepted 40%/50% loss, and ping with a deadline continued
  sending until its reply target. Those lossy cases require corrected reruns.
  [Native wave 1 receipt](../work/native-wave1/receipt.json) records the binary
  hash, every ping result, actual qdisc statistics and successful cleanup. Original receipts are retained
  unchanged; [the acceptance audit](../work/native-acceptance-audit.json) records this correction.
- [Corrected native wave 4](../work/native-wave4/receipt.json) supersedes the
  earlier lossy acceptance: all six TAP/TUN half/full and impaired cases passed
  with LZ4 enabled, 12 exact one-packet IPv4 probes and six IPv6 probes per case,
  plus 65,536 checksum-verified TCP payload bytes per case. The original failed
  receipts and acceptance audit remain intact. This is finite connectivity/data
  integrity evidence, not a performance claim.
- [Kernel VXLAN qualification](../work/vxlan-qualified/receipt.json) passed
  half/full clean and half-duplex impaired cases, with the same IPv4/IPv6/TCP
  checks. Both ends used Linux kernel VXLAN devices connected to the userspace
  VTEP and retained TCP/TLS tunnel. Native VXLAN MTU was 1400, VNI 42, and source
  vx0/eth0 checksum and segmentation offloads were disabled explicitly in owned
  namespaces. The receipt includes actual offload flags and qdisc statistics.
  Prior [failure capture](../work/vxlan-capture/receipt.json) showed partial TCP
  checksums reaching the remote kernel; byte-only UDP reception does not carry
  skb offload metadata. General offload/PMTU integration remains unfinished.

## Pure modules and scope limits

[Native UDP evidence](../work/native-udp-matrix-audit.json) now covers 36 passed
TAP/TUN/VXLAN cases: both custom covers, both confidentiality/integrity suites,
clean half/full and impaired half duplex. Every case includes exact IPv4/IPv6
probes, checksum-verified 65,536-byte TCP payloads, real UDP captures and a negative
path test that drops UDP while retaining TLS control, then restores connectivity.
An independent audit validated saved hashes and that every captured outer IPv4
packet fit path MTU 1200 without IP fragmentation. This profile retains TCP/TLS
for bootstrap, ARQ feedback and liveness; it is not standalone UDP or native FEC.
The initial native buffer-contract failure remains recorded separately.

[Native Cauchy qualification](../work/native-fec-matrix-audit.json) passed a
further 36 cases with systematic block FEC plus selective-repeat fallback.
The independent audit confirmed actual systematic and repair symbols in both
directions of integrity-mode captures. Real-socket tests separately prove lost
data is reconstructed before the initial RTO and that insufficient repair rank
falls back to ARQ. The runtime charges data, repair, retries and retained TLS
feedback/credit/heartbeats against one finite shared emission allowance; it is
fixed pacing/accounting rather than an Internet congestion controller.
[UDP LZ4](../work/native-udp-lz4/receipt.json) passed another nine native cases.

[Genuine standalone QUIC](../work/native-quic-matrix-audit.json) passed
36 TAP/TUN/VXLAN cases with maintained QUIC TLS/member authentication, Full/Half
lanes, None/LZ4 and selective-repeat/Cauchy recovery. Both owned endpoints blocked all underlay TCP before
authentication; deliberately attempted SYNs timed out and increased drop counters.
The actual QUIC connection carried retained authenticated control and DATAGRAM
data, and captures began before its handshake. Exact IPv4/IPv6/TCP payload checks,
UDP path interruption/restoration and namespace cleanup passed. No established
underlay TCP socket was present. This is separate from custom QUIC-like UDP;
opaque configured ALPN is observable and is not an HTTP/3 camouflage claim.
The independent audit verifies every captured outer IP packet fits MTU 1228,
with no IP fragmentation. The owned interfaces actually use that MTU and have
GSO/GRO disabled. Public QUIC Initial, Handshake, Retry and short headers were
observed, including coalesced packets; no 0-RTT header was present. The earlier
36 functional cases remain preserved but their captures include offload-merged
packets, so they are not physical MTU evidence. QUIC-protected contents were not
independently decrypted by this audit.
The [earlier stale-binary failure](../work/native-quic-arq/receipt.json) is retained;
it rejected the new CLI flag before authentication and cleaned up successfully.

Transparent active TUN now also traverses real retained TLS: [None](../work/native-active-plain/receipt.json)
and [LZ4](../work/native-active-lz4/receipt.json) each passed three native cases,
including impaired half duplex. This activates actual per-flow credit/release,
weighted DRR and CRC MUX while preserving endpoint TCP bytes. Targets use the
explicit fixed bootstrap floor in those historical receipts. The runtime now also
performs authenticated idle retirement; [three native churn cases](../work/native-active-churn-qualified/receipt.json)
passed twelve distinct TCP source-port flows through only two slots, each carrying
4096 checksum-verified bytes. Both duplex modes and impaired half duplex passed.

Optional measured adaptation is now integrated and explicitly selected with
`--adaptive on`. [None](../work/native-active-measured/receipt.json) and
[LZ4](../work/native-active-measured-lz4/receipt.json) passed another six native
TUN cases with the same two-slot churn plus IPv4/IPv6 and 64 KiB TCP checks.
The [None telemetry audit](../work/native-active-measured-audit.json) found actual
target growth above the configured floor with contemporaneous measured RTT,
native delivery rate and queued remote demand in all six endpoint/case traces.
The [LZ4 audit](../work/native-active-measured-lz4-audit.json) found it in five of
six traces; no growth was recorded on the clean full-duplex initiator trace.
All traces reported actual completed flow retirement. Repeated retained peak
snapshots are not separate growth events. These finite receipts do not measure
sustained throughput or weighted fairness; active managed switching remains open.

[Managed native qualification](../work/native-managed-logical/receipt.json)
passed all nine TAP/TUN/VXLAN cases: clean half/full and 70 ms RTT / 15% loss
half duplex for each layer. Every case passed IPv4/IPv6 probes and a paced
524,288-byte checksum-verified TCP transfer while the local API requested
Off→LZ4→Off. Both peers reported matching idle epochs 2 and 3. Cleanup passed.
Two earlier receipts remain preserved: [initial retry queue failure](../work/native-managed-switch/receipt.json)
and [first coalescing attempt](../work/native-managed-retry/receipt.json).
The final implementation coalesces logical requests while allowing each real
transmission a fresh replay sequence. It also flushes final delivery feedback
before completing a clean TLS half-close. This qualifies compression switching,
not live carrier/duplex/recovery/channel changes.

Credit ledgers and RTT-gated adaptive targets, weighted byte DRR, internal control
origin/replay admission, VXLAN framing/domain maps, frame compression, bounded
fragmentation/reassembly, actual systematic block FEC, selective-repeat ARQ,
protected datagrams and the packet scheduler pipeline have focused tests. The [facade integration test](../crates/l2tunnel/tests/pipeline.rs)
composes scheduling, MUX, wire and VXLAN while rejecting user-origin management
spoofing. These tests do not imply all those modules are already active in the
native runtime.

The native smoke does not measure sustained throughput, fair sharing, TCP proxy
window behavior, FEC efficiency, active-probe resistance, HTTPS/L2TP cover,
raw TCP interoperability or general third-party VPN interoperability. Local VXLAN attachment and protected
UDP underlay have distinct receipts. Windows/Android native tests and remote CI
have not run. Every Python mode retains its own uncompleted parity gate until
byte behavior and acceptance evidence exist.

The [explicit TCP proxy primitive](modules/tcp-proxy.md) now passes eight focused
tests around four independent maintained TCP owners. They cover simultaneous
opaque bidirectional bytes, request/EOF/reply, deterministic native packet
loss/reorder/duplicates, full clean close, actual zero-window/reopen, and bounded
byte/count credit renewed only from native ACK progress. This is a pure relay
test, not authenticated remote-open admission or native TUN proxy integration.

[TCP timestamp/delta header coding](modules/tcp-header-codec.md) matches 28 actual
Python byte/context vectors. [Aligned bodies](modules/aligned-body-codec.md) match
328 vectors for length elision, prediction, timestamp dictionary and generic short
records. Fragment scheduling, out-of-order early release and native integration
remain separate gates; these primitives do not complete entire catalog modes.

[Raw retained TCP/TLS](modules/raw-tcp.md) has four passing clean TAP/TUN full/half
native cases with coherent tuple/SYN/TLS captures and no kernel-established owner.
Its impaired matrix is not qualified: preserved IPv6/probe deadlines and a final
unacknowledged capture gap remain open. The current maintained reliable stream
does not implement the separately planned ACK-independent custom packet phase.
An additive [marked raw descriptor](modules/raw-reset-policy.md) now separates
maintained-stack packets from unmarked kernel resets under an exact owned
namespace policy. Its [actual-descriptor diagnostic](../work/raw-marked-descriptor-diagnostic/receipt.json)
observed the marked ACK and RST at both endpoints, rejected the unmarked RST with
EPERM and confirmed the exact drop counters and cleanup. This proves the policy
mechanism; it neither attributes earlier bare errors nor qualifies a complete
marked tunnel or graceful driver close. Subsequent
[marked tunnel qualification](../work/raw-native-marked-audit.json) passed clean
TAP/TUN in full/half duplex with exact native transfer and both maintained close
fences. The first impaired TAP/half case failed its eighth native probe; impaired
TUN remains unrun. Captures contain no RST and show delayed IPv6 neighbor traffic
through the ordered lane. This is distinct from the earlier unmarked EPERM drain
failure. [Raw packet-phase design](modules/raw-packet-phase.md) is an explicit
custom TCP-shaped datagram proposal, with an authoritative stack-handoff gate;
it is not an implemented fix or an HTTPS/middlebox compatibility claim.

## Integrated additions after wave 5

[Aligned runtime](modules/aligned-runtime.md) now composes Python-compatible
header/body/source symbols, bounded Cauchy/ARQ recovery and actual TLS-bootstrapped
UDP or genuine QUIC in injected-device tests. Full and paired half duplex,
TAP/TUN, loss/reorder and native backpressure have focused evidence. Native
client selection has also passed an [18-case native matrix](../work/native-aligned-matrix-audit.json):
TAP/TUN/VXLAN, clean full/half and 70 ms / 15% impaired half duplex, with both
protected custom UDP and genuine QUIC. Every case passed exact IPv4/IPv6 probes,
65,536-byte checksum-verified TCP, path interruption/restoration and owned cleanup.
Saved captures fit whole-IP MTU 1500 without truncation or fragmentation. These
receipts use Cauchy4+2, channels4 and no frame compression; they do not qualify
timed packing, unordered early-short recovery, graceful native shutdown or all
catalog modes.

[Standalone OpenVPN-like UDP](modules/standalone-openvpn-runtime.md) retains
actual TLS/member authentication over bounded reliable UDP control, protected
data, shared wire budgets and exporter-bound paired lanes. Its wave6 checkpoint
contained 24 focused tests. Later focused checks cover retained close-task
ownership, checked physical MTU derivation and a corrected closing-phase ACK-loss
test hook. The [device adapter](modules/openvpn-device.md) and [shared client](modules/openvpn-client.md)
now transfer real authenticated loopback traffic with injected packet devices,
explicit CLI selection and private Linux key-file provisioning. Their new
code is included in wave7; native UDP-only qualification remains unfinished. Carrier close is
not yet a distributed native-device quiescence proof.

[Proxy admission](modules/proxy-admission.md) and the [bounded IPv4/IPv6 session
table](modules/proxy-session.md) reserve actual remote TCP legs before local
SYN acknowledgment. Concurrent byte/half-close, sticky bypass, immutable handoff,
rejection/reset and finite-loss tests pass. Explicit optional TIME-WAIT reset
handling preserves the default maintained-stack behavior. Persistent periodic
loss still has a preserved fixed-bound incomplete trace. The [fixed-credit TUN
proxy runtime](modules/proxy-runtime.md) now has 15 focused tests over actual
authenticated full/paired TLS, maintained IPv4/IPv6 TCP endpoints, shared
transparent/proxy scheduling, exact byte/half-close, queued-output expiry and
finite drain fences. The complete runtime suite passed 105 focused regression
cases at this checkpoint and is included in wave7. Its client selection, native device
qualification and measured adaptive proxy-window controller remain unfinished.

[Timed packed sources](modules/packed-source.md) preserve actual Python bytes and
scheduling observations. Their separate [identity envelope](modules/packed-envelope.md)
binds full scope, recovery source, absolute unit and record identifiers, subject
to carrier authentication. [Batch admission](modules/packed-admission.md) adds
bounded ledger rollback for later-unit failure. These are focused pure primitives;
packed recovery ownership, context-dependent batch decoding and native integration
remain separate open work.

## Focused additions after wave 7

The [packed sender](modules/packed-sender.md) now composes exact aligned units,
timed packing and absolute identities while retaining recovery ownership outside
the codec. Six focused tests include fixed deadlines, immutable source pressure,
context/fragment byte round trips and distinct fresh/owned clock exhaustion. An
independent review found the latter ownership edge and its fix is covered by a
regression. [Semantic batch preflight](modules/packed-validation.md) validates
complete records in a bounded private receiver before live admission; four
focused tests preserve pending native bytes, decoder contexts and admission
ledgers on late failure. All74 codec tests and strict lint/docs passed. Actual
[packed recovery composition](modules/packed-recovery.md) subsequently passed nine
focused packed tests plus all eight ordinary aligned regressions, strict lint/docs
and independent ownership review. It uses the existing actual Cauchy/ARQ owner,
separate unit/source identities and complete semantic batch admission. Wave9
contains this composition; wave8 does not. The subsequent
[packed runtime](modules/packed-runtime.md) now passes nine focused tests and all
six ordinary aligned regressions, strict lint/docs and independent ownership
review. It adds distinct authenticated full/paired UDP and genuine QUIC bindings,
bounded common-MUX bursts and an original unsealed-packing deadline wake in the
same actor. Its injected timer tests are separate from its real carrier tests.
The [explicit packed client](modules/packed-client.md) subsequently passed 12
focused tests covering typed UDP/QUIC factories, TAP/TUN full/half delivery,
strict CLI selection, actual policy/auth rejection, original deadlines, caller
cancellation, four fixed ordinary binding regressions and missing second lanes
after real first-lane authentication.
Independent source review accepted its ownership and one-deadline composition.
Quinn can retain canceled endpoint sockets during its maintained protocol closing
period; exact tuple reuse was observed around three seconds after cancellation,
separately from the unchanged setup deadline. Wave11 contains the client/runtime
checkpoint; native packed qualification and catalog parity remain open. Wave9
contains neither this client nor the newer runtime checkpoint.

The separate [raw switchable driver](modules/raw-owner-handoff.md) now passes 18
mock handoff tests. It returns the original packet I/O and unique maintained
snapshot only after exact ciphertext/physical-send fences and the original
deadline pass. Review fixes cover time crossing during final consume and releasing
the shared gate before a rejected generic I/O bundle is destroyed. Real TLS
freeze, two-peer transition and packet-phase/native activation remain open.

The [proxy client](modules/proxy-client.md) provides explicit fixed-credit TUN
selection, immutable bounded route policy and private local status/drain RPC.
Request acceptance is separate from the actual runtime terminal report. Client
tests include real full/half TLS sessions with blocked native output and repeat
drain requests that cannot renew the original deadline. A startup race found in
client integration was fixed: user bytes require local Ready to be actually
flushed and all peer Ready messages received. The focused package checkpoints are
52 client tests and109 runtime tests. Subsequent
[native proxy qualification](../work/native-proxy-clean-audit.json) passed clean
TUN full and paired-half modes using one source-stable immutable binary. Each
case completed concurrent IPv4/IPv6 allowed TCP flows, denied-port and reverse
transparent flows, exact 65,537/32,771-byte bidirectional payloads and EOF, twelve
ICMP probes, and both native FIN directions without resets. Captures prove
independent sequence spaces for split flows and original SYN bytes for bypass.
Both peers reported two clean and zero stopped proxy owners, exact complementary
user/native fences, and closure of the original one/two TLS lanes. All captured
whole IP packets fit MTU1500 with no truncation or kernel capture drops; owned
cleanup passed. This qualifies fixed credit on clean Linux TUN, not measured
adaptive proxy windows, lossy native behavior or sustained fairness.

The [first native proxy attempt](../work/native-proxy-full-clean/tun-full-clean/receipt.json)
completed application/proxy closure but remained unsupported at capture audit:
unused IPv6 Hop-by-Hop MLD traffic on the IPv4-only underlay was outside the strict
parser. Later cases disabled IPv6 only on the four owned IPv4 underlay interfaces,
recorded original/effective values and retained native TUN IPv6. The earlier
receipt was not rewritten, parser acceptance was not weakened, and both later
cases used the exact original binary with separately recorded harness provenance.

The reviewed [smoltcp snapshot seam](modules/raw-stack-handoff.md) is now selected
as a local pinned source dependency. Its original 0BSD notice and 134-file
provenance are preserved; one additive file patch supplies a read-only observation.
The [integrity checker](../tools/check_smoltcp_source.py) verifies the reviewed
source/patch/license and lock selection, and aggregate hashing includes the
third-party tree. This is not a completed raw connection handoff or packet phase.

Standalone OpenVPN-like native qualification retains both the
[original failure](../work/native-openvpn-first-tun-half/receipt.json) and the
[unchanged two-second diagnostic failure](../work/native-openvpn-diagnostic-tun-half-2s/receipt.json).
The latter reports an actual carrier Timeout; its exact internal deadline cause
is still not distinguished. The adapter now preserves actual terminal errors
across source/task readiness, and new case receipts persist completed evidence
incrementally. A separately specified
[short-outage case](../work/native-openvpn-short-recovery-once/receipt.json) passed:
clean TUN/half, 264.245 ms guaranteed interruption, 282.677 ms conservative
operation interval, exact negative/restored probes, native65,536-byte hash,
IPv4/IPv6 traffic, captured MTU1200 and cleanup. This narrower observation does
not replace either two-second restoration failure or complete the native matrix.
The separately specified
[idle-loss case](../work/native-openvpn-idle-loss-once/receipt.json) passed its
expected-terminal contract: both daemons exited1 with actual Timeout observed
2.923/2.928 seconds after joint block installation; the joint block lasted4.028
seconds under the original five-second observation/removal deadline. This is
bounded terminal-loss behavior, not restored forwarding or clean native drain.

The later [clean native drain matrix](../work/openvpn-native-drain11-matrix.json)
and [independent audit](../work/openvpn-native-drain11-independent-audit.json)
passed four Linux TAP/TUN full/paired-half cases, each run once with the same
immutable wave11-derived daemon. Every case passed 18 exact native probes and
the 65,536-byte TCP hash, authenticated local drain, complementary peer fences,
and idempotent repeated local requests. Both original processes stayed identifiable
while all original UDP tuples were simultaneously rebound and their final private
RPC state was checked; both then exited zero in 8.11–8.16 seconds under the one
12-second observation deadline. Captures began before authentication, had zero
kernel drops and no outer IP packet larger than1200 bytes; namespace cleanup
passed. The five-second native drain and five-second local grace were unchanged.
This qualifies clean native drain only: the earlier outage/paired-close failures,
impaired drain, VXLAN and broad mode parity remain separate open work.

## Reproduction

The [owned raw pairing checkpoint](../work/raw-pairing-checkpoint/validation.json)
passes 107 raw-I/O tests (one privileged adapter test remains ignored) and
19 raw-TCP tests, plus package formatting, strict Clippy and rustdoc. It retains
the actual one/full or ordered two/half TLS/member owners, validates the complete
pair transcript and derives private purpose/direction/lane-separated keys from
the original exporters. The [root source review](../work/raw-pairing-root-review14/REPORT.md)
found and verified fixes for final bridge accounting after driver destruction
and elapsed-only false progress. Whole-workspace integration is still pending;
this checkpoint grants no Armed, Seal, freeze, physical handoff or native packet
phase authority.

The [second packed native attempt](../work/packed-native-tun-half13/receipt.json)
remains failed at capture acceptance after the exact IPv4/IPv6 probes, 65,536-byte
TCP hash, bidirectional small-packet burst and UDP interruption/restoration had
completed. The auditor incorrectly required one logical session across the two
distinct authenticated half-duplex lanes. The [independent diagnosis](../work/packed-scope-review13/REPORT.md)
traced each actual runtime recovery scope to its corresponding TLS/UDP lane.
The [focused correction](../work/packed-scope-fix13/validation.json) passed tests,
strict lint/docs and offline reinspection of the unchanged original captures.
Neither that reinspection nor successful namespace cleanup changes the native
failure into a pass; a fresh immutable build and native retry are still required.

The [Ethernet witness extension](modules/packed-ethernet-audit.md) now recognizes
complete raw Ethernet records under explicit finite classifier/length rules,
with 80 client and 19 auditor tests passed and an independent source review.
Its [focused check](../work/packed-ethernet-check13/validation.json) stopped at
strict Clippy because the concurrently developed measured proxy runtime still
contained unused internal integration code and two style lints. Current edits
therefore have no new whole-workspace green receipt. TAP/VXLAN packed native
qualification and the measured proxy actor remain separate open gates.

[Integrated wave13 checks](../work/implementation-wave13/validation.json) passed
805 Rust unit/integration/doctest cases and 105 Python tool tests, workspace
formatting, warning-denied Clippy/rustdoc, five Python golden checks and CLI
validation. All recorded inputs stayed unchanged, including the Python oracle
source and Cargo/editor configuration now included in the manifest. This adds the
pure measured proxy controller and corrected packed startup recovery marker.
The [immutable native bundle](../work/packed-native-build13/receipt.json) uses
exactly that checked source map. Measured runtime/native window activation, raw
pairing/freeze and the corrected packed native retry remain separate acceptance
steps; this aggregate does not establish them.

[Integrated wave12 checks](../work/implementation-wave12/validation.json) passed
787 Rust unit/integration/doctest cases and 105 Python tool tests, workspace
formatting, warning-denied Clippy/rustdoc, five Python golden checks and CLI
validation. All recorded inputs stayed unchanged. This adds the original-stream
TLS record adapter, exclusive authenticated TLS message owner, bounded proxy
measurement owner, packed native harness and structural-only capture auditor.
The [immutable native bundle](../work/packed-native-build12/receipt.json) was built
from exactly that checked source map. No native result, measured proxy runtime,
raw TLS freeze or packet-phase authority follows from this aggregate.

[Integrated wave11 checks](../work/implementation-wave11/validation.json) passed
702 Rust unit/integration/doctest cases and 85 Python tool tests, workspace
formatting, warning-denied Clippy/rustdoc, five Python golden checks and CLI
validation. All recorded source/document/vendor hashes stayed unchanged. This
snapshot includes packed runtime/client composition, the raw switchable driver,
the pure proxy allocator and measurement codec, standalone native-drain client,
and its 22-test additive native harness with corrected residual-resource evidence.
The subsequent raw record adapter and measurement owner are separate checkpoints.
The previously failing real paired-close test passed here; its wave10 failure
remains unresolved and must not be explained away by this later success. No
privileged native run or complete Python mode parity follows from this aggregate.

[Integrated wave10 checks](../work/implementation-wave10/validation.json) retained
a source-stable failure: the real OpenVPN paired IPv4-loss/IPv6-integrity transfer
test returned `IncompleteClose` (45 of 46 carrier tests passed). Formatting and
workspace Clippy had passed, but the Rust workspace test command stopped and the
remaining Python/docs/final checks did not execute. Its original log and hashes
are preserved. This is not an aggregate qualification for the newer packed
runtime, raw switchable driver, native-drain client or pure adaptive planner.
The paired-close failure is under investigation; no timeout was enlarged.

[Integrated wave9 checks](../work/implementation-wave9/validation.json) passed
627 Rust unit/integration/doctest cases and 63 Python tool tests, workspace
formatting, warning-denied Clippy/rustdoc, five Python golden checks and CLI
validation. All recorded source/document/vendor hashes stayed unchanged. This
snapshot adds packed recovery composition, the pinned maintained TCP snapshot
and pure tracked handoff owner, native proxy harness, and standalone UDP native
drain control/device composition. The latter includes paired cross-lane close
ordering, terminal-watch and original-deadline regressions. Real raw driver
handoff, packed runtime and standalone native-drain CLI/native qualification
remain separate open gates; native proxy evidence uses its own immutable build.

[Integrated wave8 checks](../work/implementation-wave8/validation.json) passed
587 Rust unit/integration/doctest cases and 46 Python tool tests, complete
workspace formatting, warning-denied Clippy/rustdoc, five Python golden checks
and CLI validation. No source or documentation changed during the run. This
adds the exact packed sender, semantic batch preflight, failure-atomic checked
datagram opening, proxy Ready-flush fix and client/local API, plus precise
standalone terminal propagation and incremental outage evidence. Native labs
remain separately identified; raw packet-phase and packed recovery designs are
not implementations merely because their documents are in this snapshot.

[Integrated wave7 checks](../work/implementation-wave7/validation.json) passed
549 Rust unit/integration/doctest cases and39 Python tool tests, all workspace
formatting, warning-denied Clippy/rustdoc, five actual-Python golden generators
and CLI validation. Source hashes remained identical throughout the check. It
includes the packed primitives, aligned client, OpenVPN device/client and close
ownership fixes, proxy runtime and marked raw adapter/helper. The ignored raw
descriptor test was executed separately in its owned diagnostic, not implicitly
by the ordinary suite. Native matrices and platform qualification remain separate.

[Integrated wave 6 checks](../work/implementation-wave6/validation.json) passed
492 Rust unit/integration/doctest cases and 36 Python tool tests, workspace
formatting, warning-denied Clippy/rustdoc and CLI validation. Source hashes
remained identical throughout the check. It includes aligned runtime, standalone
UDP carrier pairing, IPv4/IPv6 proxy admission/table, explicit retained TLS drain
and raw error instrumentation. These local checks do not qualify unfinished
native impaired cases, Windows/Android devices or the 47 catalog parity gates.


[Integrated wave 5 checks](../work/implementation-wave5/validation.json) passed
420 Rust unit/integration/doctest cases and 28 Python tool tests, complete workspace
formatting, warning-denied Clippy/rustdoc and CLI validation. Before/after source
hashes match. This snapshot adds the active policy transaction/client, bounded
TCP proxy leg, UDP admission/reliable control primitive, and Python header/body/
receiver byte fixtures. Native integration, standalone UDP TLS and complete mode
parity are separate gates; a tested primitive is not an implemented full profile.

[Integrated wave 4 checks](../work/implementation-wave4/validation.json) passed
352 Rust unit/integration/doctest cases and 18 Python harness tests, formatting,
warning-denied Clippy/rustdoc and CLI validation. Source hashes stayed identical
through the coordinated freeze. This includes measured active feedback/retirement,
genuine QUIC carrier/runtime/client, generic TLS I/O, raw stream close regressions,
generic management configuration and active policy validation. It does not imply
the later active hot-switch engine or raw native qualification already passed.

[Integrated wave 3 checks](../work/implementation-wave3/validation.json) passed
296 Rust unit/integration/doctest cases and 18 Python harness tests, workspace
formatting, warning-denied Clippy and rustdoc, and CLI validation. Before/after
source hashes match with no concurrent source changes. This includes active TUN,
serialized primitive retirement, systematic reliable/FEC composition, both UDP
runtime profiles and shared client selection. Native receipts remain separate;
no Windows/Android or remote CI execution is implied.

[Integrated wave 2 checks](../work/implementation-wave2/validation.json) passed
226 Rust unit/integration/doctest cases and 16 Python harness tests, formatting,
warning-denied workspace Clippy and rustdoc. The receipt's before/after source
hashes match exactly, so this was a stable source snapshot. It includes the
TCP-authenticated UDP carrier's loopback tests but no UDP native-device test.
No remote CI or Windows/Android execution is implied by this Linux result.

Run `python3 tools/check.py` for unprivileged workspace checks, or
`python3 tools/record_check.py --output /new/output/directory` to preserve the
output and before/after source identity. Run
`cargo build -p l2tunneld` and the explicit native harness command documented in
[README](../README.md) for new owned namespaces and fresh ephemeral lab identities.
The harness never modifies host routes, bridges or qdiscs and refuses preexisting
namespace names. Endpoint processes are stopped before ownership-checked cleanup.
