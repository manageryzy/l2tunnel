# Implementation status

The implementation is incomplete and has not qualified the owner's full native
performance and mode requirements, including the 80 Mbit/s acceptance target.
Work now follows the blocking behavior corrections at
[the top of the implementation checklist](implementation-checklist.md#blocking-behavior-corrections--execute-before-new-feature-work).
The checked module tasks are individual deliverables, not a product completion
percentage. All 47 complete Python mode gates remain open.

## Architecture target and current Swift composition

The target separates pure data algorithms, a [common inner secure session](modules/secure-session.md),
and the explicitly selected appearance carrier. The common fixed-peer security
model is WireGuard-like, with AEAD data on every carrier including HTTPS.
Maintained Noise, common protection, numbered Swift records and selected UDP
runtime/service components now have finite implementation evidence; the complete
cross-carrier contract and lifecycle remain unfinished. The selected carrier must retain the same socket and five-tuple
through its handshake, user data and authenticated management. Swift is a data
packing/recovery algorithm, not an independent connection mode or implicit default.
Bounded automatic recovery is required by default in the target design.
These targets do not remove RLNC, parity, rolling, packed, proxy, SW-11 or any
of the 47 Python mode gates. Retaining Swift's AEAD on every carrier does not
delete independently selected authenticated-cleartext requirements of other
profiles; their common protection contract remains an explicit design gate.

The historical explicit [Swift composition](modules/swift.md) authenticates
over TCP/TLS and sends data over a separate UDP socket. It reuses TLS/member
authentication, exporter secrets and the shared lifecycle service, preserving
its v2 AEAD/replay/key-chain wire through the common security library's explicit
compatibility owners. Its TLS policy wire remains profile-specific, while the
policy coordinator is now shared with the common UDP adapter. Data is always
ChaCha20-Poly1305, with a 4096-packet replay window and
automatic per-direction HKDF key generations every 2^28 datagrams. The pure
engine has no socket, real clock, key or device dependency. The retained
compatibility path and all saved receipts remain available.

The new explicit `quic-like` and `media-like` carriers select Swift separately
as a record profile. They share the original UDP socket through admission,
Noise, existing Ed25519 member proof, common ChaCha20-Poly1305 User/Control records,
full Swift packing/recovery and fixed authenticated control. CLI construction
uses the same immutable profile, deferred attachment, service owner and version2
local API as an embedding frontend. It does not supply dummy TLS credentials or
implicitly choose a carrier.

The additive [whole-message custody](modules/control-messages.md) and
[explicit control streams](modules/control-streams.md) are separately implemented
and protocol-tested. Genuine generic PREPARE envelopes survive bounded
fragmentation/recovery; both-cover original-socket fixtures preserve liveness
through a blocked transaction using one common security owner. This does not
enable a new selected runtime contract, complete a mode switch or qualify
retired-retry permits, lifecycle, other platforms or native performance.
The [required source-stable aggregate](../work/common-control-messages-20261113/aggregate-attempt-3/validation.json)
passes 1555 Rust cases including doctests, 295 Python tooling cases and 1658
simulator cases; preserved checklist-format failures are described in the module
ledgers. These are local Linux checks, not new native or non-Linux qualification.

The [source-stable focused integration receipt](../work/secure-udp-integrated-focused-20261113/attempt-3/validation.json)
passed 17 driver tests, 21 secure-UDP/client tests, retained service/local API
tests, strict Clippy and rustdoc. Actual paired UDP/service fixtures exercise
native Unix datagram packet devices, both appearances, IPv4/native bytes,
authenticated policy changes, requested/effective status, negative trust,
cancellation, late readiness and manual fresh-session reconnect. Driver fixtures
also cover independent Tokio runtimes, exact FIFO recovery after a measured
OS `WouldBlock`, permanent native stalls, replay/tamper, immutable challenge
deadlines and key generations. They do not qualify actual Linux TAP/TUN throughput,
full default retained-state recovery, fresh-DH rekey, generic management,
OpenVPN/HTTPS migration or full SW-11. The
[runtime](modules/secure-udp-runtime.md), [service](modules/secure-udp-service.md)
and [native lab](modules/secure-udp-native.md) ledgers preserve those boundaries.

Subsequent [immutable native baselines](modules/secure-udp-native.md#initial-immutable-native-baseline)
now execute the actual CLI on Linux TAP in fresh owned user/network/mount
namespaces. QUIC-like clean and70ms/no-loss cases passed at83.01/83.48Mbit/s.
At70ms/15% loss each way, QUIC-like38.91 and media-like39.76Mbit/s failed the
unchanged80Mbit/s target, while exact hashes/EOF, native probes, live policy
commits, fresh manual reconnect, complete captures and cleanup passed. These
four runs use their own immutable baseline binary; they do not qualify later
source changes or the complete matrix. The later [28-test runtime check](../work/secure-udp-deadline-focused-20261113/attempt-4/validation.json)
and strict Clippy cover authenticated Pong expiry, native event/completion
deadlines and ready retransmission/repair wakeups. Corrected-runtime native
attempts then failed a ping phase and a bulk-time runtime timeout, respectively;
neither supplies qualified throughput. The latest harness retains bounded live
failure observations. The required aggregate for these corrections passed as recorded below; native requalification remains open.

The owner-requested [counter-guided checkpoint](modules/secure-udp-native.md#counter-guided-performance-correction)
now observes scheduling, credit/refill discard, charged classes, native pressure
and current-channel Swift recovery through the shared client/service API.
The independently tested burst and bounded output-order corrections improve
impaired QUIC-like goodput from40.0928 to64.5727 to70.6236Mbit/s. Build7's
matched clean case is72.0171 and its media-like impaired case is78.2192. These
pass exact native integrity, control changes, manual reconnect, captures and
cleanup but fail80Mbit/s. Reported native-pressure
drops/output-full/write-WouldBlock are zero; remaining pacing/CPU causes are
unresolved and saturated native-read fairness is SUR-11. The exact preserved old
binary now measures71.4825 clean, so its historical83.0069 is not a current
environment baseline. A fresh overhead/timing sensitivity study gives78.75/78.60
for QUIC/media-like simulation; it is not kernel performance or full parity.

The requested [kernel profile](modules/secure-udp-native.md#requested-kernel-profiling)
identifies TAP/network execution and epoll/futex/scheduler call chains, with zero
lost samples. Simultaneous tunnel physical reads are zero and writes about172KB
per endpoint over16.6s despite substantial host I/O PSI; off-CPU wait causality
remains unproved. A separate reviewed correction removes CPU-count-sized worker
pools from one-shot local API helpers. Actual old/new CLI tests observe255-to-1
threads with byte-identical replies and one request; the daemon scheduler and
original65s private timeout remain unchanged. Build8 then measures77.3464Mbit/s
QUIC-like impaired and still fails80 with functional/capture/cleanup passed.

Historical `tools/selftest.py` runs (Linux TAP, unprivileged
namespaces, HTB and netem, sixteen verified CUBIC flows, 100/10 Mbit/s, 70 ms
RTT, 15% loss each way) measured 79.74, 80.50 and 79.91 Mbit/s forward
goodput against 80.72 Mbit/s from the Python simulator rerun at the tunnel's
real per-datagram overhead, and 79.23 against 79.04 with the kernel's default
minimum RTO. The 1% loss, delay-only and clean paths measured 93.41, 93.69 and
92.80 against 94.55, 94.61 and 94.58. [Receipts](../work/swift-selftest41/impaired-1.json)
and the simulator runs ([reference path](../work/swift-simulator-reference38/output.log),
[control paths](../work/swift-simulator-reference40/output.log)) are saved.
These are integration receipts in one local environment only: real devices,
privileged host namespaces, Swift TUN/IPv6 underlay, soak, Windows/Android and
the other profiles' blocking corrections remain open. The
self-test [disconnects and reconnects](../work/swift-selftest43/impaired.json)
the live tunnel through the shared service. Key-generation and 32-bit sequence
boundary behavior have focused tests; no production-cadence 2^28-datagram live
rekey was observed. The [later baseline receipt](../work/swift-selftest44/impaired.json)
records 79.35 Mbit/s with lifecycle checks. Temporary UDP path loss can retain
the live session/recovery state; an actual restart authenticates anew and clears
the old delivery state. Current automatic restart defaults to off, and the
retained TLS closure signal has no general Swift heartbeat/dead-peer deadline.

SW-13 adds negotiated internal Swift policy changes over a private retained-TLS
control codec, with focused parser/state/loopback/service tests and
[mixed native receipts](modules/swift.md#policy-change-receipts). The successful
under-load change measured 63.188 Mbit/s, below the reference acceptance, while
three other receipts retain functional or lifecycle failures. Full proposal and
barrier-response deadlines, common-control integration, complete cross-record
profile switching (SW-11), and peer-confirmed clean drain remain open. SW-13
does not narrow SW-11 or close any Python mode gate.

## Verification evidence

The [latest required aggregate](../work/secure-udp-performance-progress-20261113/attempt-3/validation.json)
passed with unchanged source maps:1526 Rust cases including doctests,295 Python
tooling cases and1658 simulator cases, plus formatting, strict workspace Clippy,
rustdoc and CLI checks. `RUST_TEST_THREADS=1` serializes the complete Rust suite;
no cases, assertions, original deadlines or performance thresholds were relaxed.
Native labs, kernel profiling, remote CI and Windows/Android execution retain
their separate scopes. Subsequent changes reconcile documentation evidence only.

The performance correction has an [expanded source-stable focused pass](../work/secure-udp-performance-focused-20261113/attempt-5/validation.json)
and50 passing [native-tooling tests](../work/secure-udp-native-tooling-focused-20261113/attempt-9/validation.json).
The [first aggregate attempt](../work/secure-udp-performance-progress-20261113/attempt-1/validation.json)
failed two existing elapsed-time assertions; both passed [unchanged isolated checks](../work/secure-udp-performance-focused-20261113/deadline-recheck-1/validation.json).
The [serial aggregate attempt](../work/secure-udp-performance-progress-20261113/attempt-2/validation.json)
then passed1526 Rust cases including doctests and executed295 Python tests, but
failed one existing100ms kernel-loopback measurement with zero received bytes,
before the simulator suite. Its [unchanged isolated recheck](../work/secure-udp-performance-progress-20261113/kernel-loopback-recheck-1.log)
passed all three kernel-loopback tests. Neither failed aggregate is relabeled;
no deadlines, test assertions or performance thresholds were relaxed.

The [preceding correction aggregate](../work/secure-udp-native-progress-20261113/attempt-1/validation.json)
passed 1498 Rust cases including doctests, 285 Python tooling cases and 1658 simulator
cases, with unchanged source maps, formatting, strict Clippy, rustdoc and CLI
checks. It executes the new-profile attachment rejection, 28 transport regressions
and 40 native-tooling tests. Native labs, remote CI and platform qualification
remain separate. The [prior runtime/service aggregate](../work/secure-udp-runtime-service-20261113/attempt-1/validation.json) retains its original 1487/271/1658 result and source identity.

The prior committed factory checkpoint, `e689674`, has a
[source-stable aggregate receipt](../work/shared-session-client-20261113/validation.json):
1437 Rust cases including doctests, 245 Python tooling cases and 1658 simulator
cases passed. Its [evidence reconciliation](../work/shared-session-client-20261113/postcheck-ledger-validation.json)
verified the final documentation and unchanged non-document inputs. The newer
runtime/service focused receipt above applies only to its recorded compiled
graph; the complete new aggregate above validates its later recorded inputs.
Actual native measurements remain separate.

The historical [UDP wording aggregate check](../work/udp-framing-wording-20261113-final/validation.json)
failed strict Clippy in a Swift runtime test (`manual_is_multiple_of`). Its
[focused follow-up](../work/udp-framing-wording-20261113-final/focused-validation.json)
records 467 passing Rust test executions including doctests and passing rustdoc,
but retains a failed required aggregate check. This review does not change that
failed result. Saved source maps apply to their recorded inputs; later passing
checkpoints do not rewrite historical failures.

The earlier [source30 aggregate check](../work/implementation-wave30/validation.json)
passed on code commit `10d4a0b`, including decoder commit `1c98510`:
1263 Rust test executions, 222 Python tool
executions and 1658 simulator cases. All recorded source inputs stayed unchanged;
formatting, strict Clippy and rustdoc passed. Two existing Rust descriptor tests
remain ignored because they require explicit owned namespaces. The simulator
suite had no skips. This local check includes real loopback carriers and injected
devices; privileged native tests, remote CI and Windows/Android qualification
remain separate.

This contains [sparse decoder transactions and the systematic fast path](modules/local-global-rlnc.md),
the [pure common control envelope](modules/management.md), and the actual
[managed TCP shared service](modules/client-runtime.md). The same rank-one
W8192/rows2048 witness reduced charged copies from 19,788,352 to 26,614 per job.
Clean width1462 originals now charge 2,922 copies and no GF operations, versus
14,038 copies and 9,669 GF operations before the fast path. Checked decoder
reservation for this geometry is 67,371,524 bytes, including fixed versions and
decision metadata. These are logical work/reservation measures, not CPU time,
RSS or throughput. General repair algebra, other packet copies and runtime
global-support expansion remain open. The common control codec does not yet
negotiate or dispatch on a live carrier.

The [service receipt](../work/service29/validation.json) includes real half-lane
setup cancellation, full/half reconnect after original owner release, exact
replacement bytes, compression apply and interrupted-apply uncertainty. Its
32-entry terminal history no longer grows allocation during teardown. Portable
local command types retain exact serde bytes and old exports; only Unix transport
is gated. Other profile lifecycles and Windows/Android qualification remain open.
The [source29 check](../work/implementation-wave29/validation.json) preserves the
preceding sparse-row and pure-control checkpoint.

The prior [source28 aggregate](../work/implementation-wave28/validation.json),
[base UDP/QUIC receipt](../work/base-delivery28/validation.json),
[client receipt and negative proofs](../work/base-delivery28/client-validation.json),
[raw receipt](../work/raw-delivery28/RECEIPT.md) and
[harness receipt](../work/base-delivery28/root-harness-receipt.json) bind the
scoped changes. Raw terminal snapshots retain the last complete accounting turn
and original fault, rather than combining partially updated counters. The actual
QUIC bind-classifier regression and original 200 ms setup deadline both reject
their old behavior; the original rolling early-return cause remains unconfirmed.

The [previous source27e check](../work/implementation-wave27e/validation.json)
and [causal OpenVPN close correction](../work/openvpn-close28/RECEIPT.md) remain
historical receipts. The positive close case drains actual impaired user/control
work before requiring clean shutdown; continuing final-ACK loss must still return
`IncompleteClose` at the original five-second bound. Production close bounds are
unchanged. Earlier dependency failure and exact cleanup repair are recorded below.

## Historical native measurements for TCP/TLS frame forwarding

The [source25 aggregate](../work/implementation-wave25/validation.json) and
[release receipt](../work/native-build25/receipt.json) bind the executable and
copied helpers used for these native measurements. Later source repairs
have not been qualified by those historical runs.

Four serial native TAP/TUN half-duplex cases passed exact payload, EOF, helper
provenance and owned cleanup. Every case failed forward 80 Mbit/s acceptance:

| Profile | Path | A to B Mbit/s | B to A Mbit/s |
| --- | --- | ---: | ---: |
| TAP system | Clean | 17.571 | 6.748 |
| TUN system | Clean | 9.066 | 7.692 |
| TAP system | 70 ms nominal RTT, no random loss | 11.191 | 6.642 |
| TUN system | 70 ms nominal RTT, no random loss | 10.473 | 6.821 |

These use the opt-in byte BDP policy on ordinary TCP/TLS frame forwarding, one
simultaneous bidirectional application flow, and 100/10 Mbit/s shared shaping.
They are not the Python compact-wire/MUX16/RLNC workload. The
[independent audit](../work/throughput24-analysis/25bdp-final4/report.md) finds no
forward delivery-credit blocking after the change; reverse WAN traffic fills
its 10 Mbit/s allowance. Queueing and traffic composition need correction and
measurement; two TLS writes alone have not been proved the throughput cause.

## Required behavior and actual reachability

| Requirement | Current executable evidence | Required correction or remaining gate |
| --- | --- | --- |
| Verified handshake, member identity, full/paired-half ownership | Real retained TLS and authenticated UDP/QUIC/raw slices | Broader carrier/path security, cover and resource gates remain in CONN-* |
| TAP/TUN and fixed-peer VXLAN | Finite native Linux connectivity/data-integrity matrices | Broad VTEP/MTU/offload/platform behavior and performance remain open |
| Local queue versus link flight budget | TCP/TLS frame BDP; focused rolling/aligned/packed and base UDP/QUIC/raw byte-credit integration | Source28 aggregate passed; new-profile native qualification remains open. Recovery still has an independent 64-source ceiling, so FIX-01 remains open |
| Python high-performance composition | Codec/recovery libraries and separate aligned/packed/rolling clients exist | No qualified matching native composition; FIX-02 through FIX-04 |
| TUN flow control and QoS | Transparent active-credit path and fixed TCP-proxy slices | Adaptive native-window growth and complete fairness/pressure gates still fail or remain unrun |
| Hot mode switching | Authenticated compression changes and finite active-TUN switches | Full codec/recovery/MUX switching matrix and control-under-load correctness remain open |
| Shared clients | Managed TCP, base UDP and Swift have a shared retained lifecycle owner; portable local schema is separate from Unix transport | Remaining profile lifecycle migration, full requested/effective capabilities, GUI and native Windows/Android remain open under FIX-12 |
| Carrier/recovery and stable control boundaries | Independent pure crates, fixed runtime compositions and a bounded common control codec; Swift has a separate private policy codec | Common secure-session integration, actual interchangeable recovery and negotiated stable control dispatch still require the SEC-*, FIX-10/FIX-11 and SW-* gates |
| Common authentication/security and carrier continuity | Current Swift reuses TLS/member auth but uses separate TCP/TLS control and protected UDP data; other existing slices retain their own documented owners | Common fixed-peer AEAD session across every selected carrier, same-socket handshake/data/control, bounded default recovery and independent appearance/QoS validation are planned; no security library has been chosen |

Use [the architecture](architecture.md), [project boundaries](implementation-plan.md),
[Python parity contracts](mode-parity.md) and the stable task IDs in the master
and module ledgers for exact scope. A supported library symbol is not evidence
that a client selects it or that a native acceptance test exercised it.

## Architecture corrections in progress

The blocking fixes remain in the master checklist. Tested changes include
independent native byte delivery budgets for rolling/aligned/packed and base
UDP/QUIC/raw, shared
immutable FEC history, bounded reusable rolling output buffers, one contiguous
TLS framing write, sparse equation-row publication, and explicit pressure/deadline witnesses. These do not prove
end-to-end zero copy or the native performance target.

The legacy retained-control parser now lives outside UDP, protected OpenVPN-like
datagrams have a separate internal owner, and existing-session command handling
is public in client-core. These are real extractions with unchanged wire
identities. A separately versioned, borrowed common-control codec now binds
session, primary/target lanes, active/draining epoch and configuration digest.
The public interchangeable recovery composition, actual negotiated control
service and complete client lifecycle API are still required by
FIX-10 through FIX-12. The current [base UDP/QUIC](modules/packet-delivery.md)
and [raw](modules/raw-runtime.md) changes replace local-queue admission limits
with authenticated original-byte/record budgets. Their actual-carrier tests use
a local queue of two and larger native flight; original send completion, receiver
pressure and deadlines remain explicit. They passed the source28
aggregate. The independently bounded recovery source window and
new native performance qualification remain part of FIX-01.

The [source-pinned framing assessment](../work/rolling-fast30/next-step.md)
identifies another blocking FIX-02 defect: at the audited MTU1500 geometry,
a 1500-byte TUN packet becomes two full 1500-byte outer IPv4 datagrams because
the short final source is also serialized at the full coded width. Removing that padding and
composing compact records are first-priority implementation work. This is static
byte accounting, not a new native measurement. FIX-03 also requires separating
wire-ingress queue storage from recovery support and qualifying full8192-support
recovery, repair CPU cost and feedback-induced Busy loss before lifting the
current128 runtime guard. The fast-path tests do not satisfy those gates.

The [audit inventory](../work/deep-audit26/checked-index.json) is navigation for
unreviewed evidence, not a completion percentage. Confirmed discrepancies require
behavioral fixes and regressions; descriptions and evidence links alone do not
close a gate.

## Evidence and reproduction

- Run `python3 tools/check.py` in the documented Python/Rust environment for the
  complete local nonprivileged check. Use `tools/record_check.py --output
  work/<fresh-output>` to retain its exact source map and output.
- Native tools default to dry run. Execute only an exact checked build in fresh
  owned namespaces; preserve original rate/delay/loss, payload and cleanup receipts.
- The [native/profile ledger](modules/managed-profiling.md) retains the measured
  legacy64-record baseline and subsequent BDP comparison.
- [Review follow-ups](review-followups.md) record confirmed historical correctness
  and test fixes. A later pass does not erase an earlier unattributed failure.
- The previous long chronological status is preserved in
  [the audit snapshot](../work/deep-audit26/status-before-cleanup.md) and Git history.
  Saved simulator and native experiment receipts are unchanged. Repeated wave
  narratives were removed from this current-status page.
- The [disk cleanup record](../work/disk-cleanup-20261112/summary.json) lists
  removed compiler caches and binary copies. It also mistakenly removed one
  required Python native extension; the [append-only repair receipt](../work/disk-cleanup-20261112/dependency-repair.json)
  records exact restoration and verification of all five installed native
  dependency files. The unsafe one-off cleanup script is retired. Source, Git
  history, saved experiment results and validation logs remain. Commit `34f6272`
  disables incremental development caches and requires one shared Cargo target.
