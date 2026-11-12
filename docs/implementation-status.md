# Implementation status

The implementation is incomplete and does not meet the owner's 80 Mbit/s native
performance requirement. Work now follows the blocking behavior corrections at
[the top of the implementation checklist](implementation-checklist.md#blocking-behavior-corrections--execute-before-new-feature-work).
The checked module tasks are individual deliverables, not a product completion
percentage. All 47 complete Python mode gates remain open.

## Current verified checkpoint

Source25 is committed as `8f6bc63` and `7248d33`. Its
[aggregate check](../work/implementation-wave25/validation.json) passed 1159 Rust
test executions including feature variants, 202 Python tool tests and 1654
simulator cases. All 799 recorded source inputs stayed unchanged. The
[release receipt](../work/native-build25/receipt.json) binds the executable and
copied native helpers to that source. Remote CI and Windows/Android device tests
are not covered by this check.

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
| Local queue versus link flight budget | Source25 BDP is wired only into TCP/TLS frame mode | Rolling/aligned/packed/raw still require independent delivery credit; FIX-01 |
| Python high-performance composition | Codec/recovery libraries and separate aligned/packed/rolling clients exist | No qualified matching native composition; FIX-02 through FIX-04 |
| TUN flow control and QoS | Transparent active-credit path and fixed TCP-proxy slices | Adaptive native-window growth and complete fairness/pressure gates still fail or remain unrun |
| Hot mode switching | Authenticated compression changes and finite active-TUN switches | Full codec/recovery/MUX switching matrix and control-under-load correctness remain open |
| Shared clients | Runnable Linux shared CLI/local API profiles | Full deployable configuration, GUI, Windows and Android runtimes remain open |

Use [the architecture](architecture.md), [project boundaries](implementation-plan.md),
[Python parity contracts](mode-parity.md) and the stable task IDs in the master
and module ledgers for exact scope. A supported library symbol is not evidence
that a client selects it or that a native acceptance test exercised it.

## Unaccepted working changes and active repairs

Source26 working changes include independent rolling delivery credit, exact
full-flush byte accounting, separate local/unconfirmed gauges, one contiguous TLS
framing write, paced management service, strict complete-simulator checks, meaningful
authentication deadline witnesses and early packed-channel validation. Focused
checks exist, but no source26 aggregate/native performance acceptance is claimed.
The full behavior audit takes priority over further fallback micro-optimization.
Confirmed discrepancies become blocking implementation TODOs, followed by
regressions and real-path validation; changing descriptions alone cannot close them.

The audit inventory currently contains 643 checked leaf tasks out of 1042 before
its new repair tasks. Evidence links exist, but link existence is not deep review.
[Audit navigation](../work/deep-audit26/checked-index.json) explicitly retains
unreviewed entries. No audit-complete claim follows from that inventory.

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
