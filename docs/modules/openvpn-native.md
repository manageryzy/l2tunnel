# Standalone OpenVPN-like native qualification

Status: two unchanged two-second restoration cases failed; one separately
contracted short-recovery case and one expected-terminal idle-loss case passed.
All four namespace cleanups passed. Wider native qualification remains open. The shared client and
packet-device adapter passed the stable [wave-7 aggregate](../../work/implementation-wave7/validation.json).
This slice owns `tools/native_smoke.py`, its focused tests and this document.
The shared CLI is handed to the proxy-client owner; any necessary client fix
must be coordinated. Existing raw-native tools remain separately owned.

## First case and unchanged acceptance

Run only clean TUN, paired half duplex, ordinary frame records, one system FIFO
channel, AEAD data and compression off. Use a unique output directory and owned
namespace journal. Copy the tested daemon and harness into that directory before
launching either endpoint. Generate ephemeral member/TLS credentials and separate
private admission/cookie bundles through explicit keygen commands; never retain
or print private key material in receipts. The cookie bundle stays server-only.

Keep the carrier's three-second fresh-TLS inactivity policy, one-hour lease and
all existing harness probe predicates/deadlines unchanged. In particular retain
the two-second UDP blackhole probe, require exactly one packet sent and zero
received while blocked, require both endpoints still alive, then require exact
restored ping success after removing only the owned filter. If this interrupts
the carrier long enough to trigger its real inactivity/recovery/reassembly bound,
retain the failed receipt and stage. Do not retry until pass, extend the policy,
accept partial transfer or reclassify the failure as success.

Before authentication, block outer TCP on both owned underlay interfaces and
prove a real SYN times out with an incremented drop counter. Start packet captures
before UDP bootstrap. The standalone branch has no TCP listen/remote argument;
wait for actual fixed UDP socket bindings rather than a nonexistent TCP-listener
log. For paired mode require both bound ports before starting the initiator.

Set the actual endpoint/router underlay MTU to the declared whole-IP ceiling and
disable checksum/segmentation/receive aggregation offloads on those owned links.
Capture audit checks classic-PCAP structure, complete Ethernet/IPv4/UDP framing,
no outer fragments, exact fixed endpoint/port tuples, permitted standalone wire
discriminators, required bootstrap/control/data observations per lane and every
observed complete IP length within MTU. Captures are finite samples, not proofs
of arbitrary-loss delivery, cryptographic correctness or every emitted packet.
TLS/member success is established by the actual daemon factories and logs, not
by recognizing a header. No established underlay TCP socket may appear.

Native traffic keeps the existing exact IPv4/IPv6 ICMP count predicates and
native TCP SHA-256 payload check. Sampled native counters must show actual
transmits and fresh TLS progress at both endpoints; sampled retention fields
remain last-completed-iteration observations, not exact final inventories.
Process termination and namespace cleanup are bounded and recorded separately;
they are not clean distributed native shutdown receipts.

## Follow-up decision

Report the first case and exact stage before expanding the matrix. If the
unchanged two-second blackhole test fails, propose a separate expected-terminal
idle-loss case and an explicitly bounded recovery probe as distinct coverage.
Neither replaces or erases the first observation. Only after review, qualify
additional TAP/TUN/VXLAN, full/half, None/LZ4, AEAD/integrity and selected
70 ms/15% loss cases in independent output paths. This does not claim OpenVPN
interoperability, production middlebox acceptance, throughput, non-Linux native
support, active TUN flow control or complete simulator parity.

## First observed result

The immutable first run used clean TUN, paired half duplex, MTU 1200 and the
unchanged two-second UDP blackhole/three-second carrier inactivity policy. Its
[original receipt](../../work/native-openvpn-first-tun-half/receipt.json) is a
failure: after removing the owned blackhole, the restored single ping received
zero of one packet. The [stage journal](../../work/native-openvpn-first-tun-half/tun-half-clean-stage.json)
entered `udp_restoration_probe` at 4.4966 seconds. Both endpoint logs ended with
`native source stream ended`; namespace cleanup passed. No matrix expansion or
retry was performed. The [immutable build record](../../work/openvpn-native-build1/build.json)
identifies the exact tested daemon.

A separate [read-only diagnostic](../../work/native-openvpn-first-diagnostic.json)
retains capture hashes and finite framing checks: each endpoint capture contains
349 packets, complete bootstrap/control/protected-data observations on both UDP
lanes, and maximum whole-IP length 1200. These observations do not turn the failed
restoration into a passing native qualification. Sampled native counters show
delivery and TLS progress before termination, but are not final inventories.

The adapter version tested in this first run allowed source-channel closure to win a race with its
supervised reader error. The resulting generic error does not establish whether
inactivity, recovery exhaustion or another carrier error caused this run to end.
An inactivity explanation for that historical run remains an unproved inference.
The stage sequence also shows that earlier probe checks completed, but the harness
kept their successful outputs in memory until whole-case success. Consequently,
the failed receipt does **not** retain the earlier native TCP payload digest; the
receiver log contains only its readiness line. This evidence gap must be fixed
for future runs without modifying the original failed receipt.

Approved evidence follow-up: write a new per-case receipt before probes, then
atomically replace it after each completed probe, TCP sender stdout/hash, socket
proof and capture milestone. Bound each JSON receipt to 4 MiB, refuse to reuse an
existing initial path, and retain the prior complete JSON if replacement fails.
Final capture samples can be audited after processes stop on either success or
failure; this diagnostic must not change the original case outcome. This applies
only to future newly owned output directories.

The approved terminal follow-up now preserves the supervised reader error in the
existing one-slot source handoff and task result, with the same error kind and OS
code. Owner health reports observed lane terminal enums. Eight focused runtime
tests cover both readiness orders, EOF and bounded diagnostics. This cannot
retroactively recover the old run's reason. Before another native run, propose
separately named expected-terminal
long-blackhole and bounded short-outage recovery cases. Each case must retain its
own acceptance, actual elapsed outage and result. The original restoration failure
remains an independent observation, and neither follow-up is a substitute for
the open native matrix gate.

## Approved diagnostic replay

Run exactly one additional clean TUN/half case in
`work/native-openvpn-diagnostic-tun-half-2s`, using a newly copied immutable daemon
from `work/openvpn-native-build2`. This is an instrumentation replay, not a retry
until pass: the unchanged two-second negative ping must still be exactly 1/0,
both endpoints must still be running at the existing check, and the restored
single ping must still be exactly 1/1 with the original 30-second ping timeout.
The three-second carrier inactivity, all recovery bounds and cleanup predicates
remain unchanged. Preserve incremental probe/hash/socket/capture receipts and
the actual terminal class reported by the fixed adapter. Report the result
before any other native run. A generic `Timeout` proves a deadline outcome, not
specifically inactivity; `Closed`/EOF never proves a timeout. The first failed
receipt remains immutable and separate.

The diagnostic replay also failed at restored ping (0/1); cleanup passed. Both
endpoint logs reported `carrier Timeout; deadline cause not distinguished`.
The [diagnostic receipt](../../work/native-openvpn-diagnostic-tun-half-2s/receipt.json)
retains 12 exact IPv4 probes, six IPv6 probes and the completed 65,536-byte native
TCP SHA-256 result. Its stopped captures each contain 345 packets with maximum
whole-IP length 1200. This is positive finite payload evidence inside a failed
restoration case, not an overall native pass. Unlike the first run, the failure
is now known to be an actual carrier deadline outcome. Both original two-second
failure receipts remain unchanged.

## Separate outage contracts

The following design and focused tests were reviewed before one execution of
each profile. Both are explicitly selected standalone
OpenVPN-like, clean TUN/half cases with a distinct case-name suffix, new output
directory, immutable binary and unchanged three-second carrier policy. Other
carrier/layer/duplex/netem selections cannot silently use these probes.

`short-recovery` installs the owned UDP egress block on endpoint A. After confirmed
installation, run exactly one negative ping with `-c 1 -W 0.2`, require exit 1
and exactly 1/0 packets, and keep the block until at least 250 ms after confirmed
installation. Record the drop counter and remove only that filter. The
conservative outage interval, from installation-command start through removal-
command completion, must be no more than 500 ms. Endpoints must remain running
before and after removal. The restored probe retains `-c 1 -W 30` and must be
exactly 1/1. Exceeding the operational timing ceiling is a failed run, even when
payload later recovers; no automatic retry or deadline extension is permitted.

`idle-loss` installs the owned UDP egress block on both endpoints. The joint
outage starts when both installation commands have completed. Retain both blocks
for at least four seconds from that instant. A single immutable observation
deadline is five seconds from that same instant, including filter removal and
terminal observation. Both daemon processes must exit nonzero by that deadline
and report an actual carrier `Timeout` or `IncompleteClose` terminal; signal
termination is rejected. Both must be running before filter installation. Generic
EOF, `Closed`, `Failed`, cancellation or exit zero does not satisfy this predicate.
There is no restored-success probe or clean-native-close claim. The result is
expected-terminal coverage, not successful forwarding through an outage.

For both profiles journal each endpoint's installation/removal command start and
completion timestamps. Report the guaranteed joint blocked interval (latest
installation completion through earliest removal start) and the conservative
whole-operation interval (earliest installation start through latest removal
completion), rather than pretending userspace can timestamp the exact kernel
filter transition. Preserve the ordinary pre-outage payload checks, TCP-block
proof, UDP bindings, captures, physical MTU and bounded namespace cleanup. Every
overrun or unexpected outcome is retained as failure.

## Finite outcome checkpoint

These observations are adjacent because the narrower passing contracts do not
replace the original restoration failures. Every run used clean TUN/half, MTU
1200, AEAD and compression off. No TAP/full/VXLAN/netem matrix was attempted.

| Independent case | Retained outcome | Scope |
| --- | --- | --- |
| [Original two-second interruption](../../work/native-openvpn-first-tun-half/receipt.json) | Failed restored ping 0/1; cleanup passed | Generic source EOF hid the terminal cause; completed earlier TCP hash was not retained. |
| [Instrumented two-second replay](../../work/native-openvpn-diagnostic-tun-half-2s/receipt.json) | Failed restored ping 0/1; both actual carrier `Timeout`; cleanup passed | Incremental receipt retains 65,536-byte TCP SHA-256 and 12 IPv4 plus six IPv6 probes. Timeout does not identify the expired deadline. |
| [Short recovery, one execution](../../work/native-openvpn-short-recovery-once/receipt.json) | Passed exact blocked 1/0 and restored 1/1; cleanup passed | Guaranteed blocked interval 264.245 ms; conservative installation/removal interval 282.677 ms, within 500 ms. Endpoints remained alive. |
| [Symmetric idle-loss, one execution](../../work/native-openvpn-idle-loss-once/receipt.json) | Passed expected-terminal contract; both exit 1 with actual `Timeout`; cleanup passed | Guaranteed joint block 4.0280 s; whole operation 4.0766 s. Terminals observed 2.9229/2.9275 s after joint installation, before the fixed five-second deadline. No restored-success or clean-close claim. |

Both separately contracted cases retained complete two-lane bootstrap/control/data
capture samples with maximum whole-IP length 1200, actual TCP-block/socket proofs,
65,536-byte native TCP SHA-256 and 12 IPv4 plus six IPv6 positive probes before the
outage. They use the reviewed [immutable build 2](../../work/openvpn-native-build2/build.json).
Captures prove finite observed framing/MTU, not every packet or cryptographic
validity. No retry or acceptance widening was performed. The local checkpoint
also passed 18 Python harness tests, eight focused standalone adapter tests, all
109 runtime package tests, strict runtime Clippy and rustdoc. The coordinated
post-change [wave-8 aggregate](../../work/implementation-wave8/validation.json)
passed with stable source hashes: 587 Rust tests including doctests and 46 Python
tests. That aggregate is local unprivileged validation, separate from these labs.

- [x] [MOD-OVPNNATIVE-01] Freeze exact first-case scope, ownership, unchanged acceptance and evidence limits before harness changes. Evidence: [first-case contract](#first-case-and-unchanged-acceptance), [follow-up decision](#follow-up-decision).
- [x] [MOD-OVPNNATIVE-02] Add strict standalone harness selection, private provisioning, UDP readiness, pre-auth captures, physical MTU and TCP-block/socket evidence with focused parser tests. Evidence: [harness](../../tools/native_smoke.py), [13 focused tests including standalone selection and bounded PCAP parsing](../../tools/test_native_smoke.py).
- [x] [MOD-OVPNNATIVE-03] Run one immutable clean TUN/half case with the unchanged UDP-negative/restoration probe and retain exact result/stage/cleanup. Evidence: [failed first receipt with successful cleanup](../../work/native-openvpn-first-tun-half/receipt.json), [retained stage](../../work/native-openvpn-first-tun-half/tun-half-clean-stage.json), [separate read-only capture diagnostic](../../work/native-openvpn-first-diagnostic.json).
- [x] [MOD-OVPNNATIVE-04] Review first-case outcome before selecting further recovery/terminal-loss or native matrix coverage. Evidence: [preserved first observation](#first-observed-result), [separate frozen contracts](#separate-outage-contracts), [adjacent finite outcomes](#finite-outcome-checkpoint).
- [ ] [MOD-OVPNNATIVE-05] Record separately reviewed finite native matrix results and remaining gaps without broad production/parity claims.
- [x] [MOD-OVPNNATIVE-06] Refresh coordinated full workspace checks after final harness changes. Evidence: [stable wave 8, 587 Rust and 46 Python tests](../../work/implementation-wave8/validation.json).
- [x] [MOD-OVPNNATIVE-07] Persist bounded incremental probe/socket/capture evidence atomically and test failure retention without changing acceptance. Evidence: [exclusive atomic case receipts](../../tools/native_smoke.py), [15 focused tests including replacement failure, historical reuse and completed-hash retention](../../tools/test_native_smoke.py).
- [x] [MOD-OVPNNATIVE-08] Preserve actual carrier terminal errors across source/task readiness order with deterministic tests; do not infer inactivity from EOF. Evidence: [bounded one-slot error propagation (retired in Common cutover)](compact-wire-cleanup.md), [eight focused adapter tests (retired in Common cutover)](compact-wire-cleanup.md), [precise terminal contract](openvpn-device.md#termination-and-later-clientnative-gates).
- [x] [MOD-OVPNNATIVE-09] Implement separately named short-recovery and expected-terminal profiles with strict timing/terminal parser and failure-path tests before executing either. Evidence: [strict profile selection and outage execution](../../tools/native_smoke.py), [18 focused tests including injected-clock cleanup/deadline and terminal classification](../../tools/test_native_smoke.py), [frozen separate contracts](#separate-outage-contracts).
- [x] [MOD-OVPNNATIVE-10] After checkpoint review, run each approved separate profile once and retain finite outcomes without replacing the original restoration failures. Evidence: [single short-recovery receipt](../../work/native-openvpn-short-recovery-once/receipt.json), [single expected-terminal receipt](../../work/native-openvpn-idle-loss-once/receipt.json), [adjacent failure boundaries](#finite-outcome-checkpoint).
