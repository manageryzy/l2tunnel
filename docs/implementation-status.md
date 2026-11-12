# Implementation status

The implementation is incomplete and does not meet the owner's 80 Mbit/s native
performance requirement. Work now follows the blocking behavior corrections at
[the top of the implementation checklist](implementation-checklist.md#blocking-behavior-corrections--execute-before-new-feature-work).
The checked module tasks are individual deliverables, not a product completion
percentage. All 47 complete Python mode gates remain open.

## Current verification

The [source30 aggregate check](../work/implementation-wave30/validation.json)
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

## Latest native measurements

The [source25 aggregate](../work/implementation-wave25/validation.json) and
[release receipt](../work/native-build25/receipt.json) bind the executable and
copied helpers used for the latest native measurements. Later source repairs
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
| Shared clients | Managed TCP CLI and embedding frontend use one typed retained lifecycle; portable local schema is separate from Unix transport | Other profile lifecycle migration, richer local lifecycle commands, GUI and native Windows/Android remain open under FIX-12 |
| Carrier/recovery and stable control boundaries | Independent pure crates, fixed runtime compositions and a bounded common control codec | Actual OpenVPN-like recovery composition and negotiated stable control dispatch still require FIX-10/FIX-11 |

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
