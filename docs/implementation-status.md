# Implementation status

The implementation is incomplete and does not meet the owner's 80 Mbit/s native
performance requirement. Work now follows the blocking behavior corrections at
[the top of the implementation checklist](implementation-checklist.md#blocking-behavior-corrections--execute-before-new-feature-work).
The checked module tasks are individual deliverables, not a product completion
percentage. All 47 complete Python mode gates remain open.

## Current verification

The current repair checkpoint is not aggregate-qualified. The
[source27d check](../work/implementation-wave27d/validation.json) stopped at an
OpenVPN-like paired impairment test returning `IncompleteClose` under its
original five-second deadline. Its fixture continues counter-based packet loss
through final control exchange, so clean close is not guaranteed within that
bound. The [independent review](../work/openvpn-paired-close27d-review/REPORT.md)
does not attribute the saved failure to a particular lost ACK. A causal fixture
correction and subsequent stable aggregate check are required.

The preceding [source27c check](../work/implementation-wave27c/validation.json)
passed 1205 Rust test executions and 216 Python tool test executions, then failed
simulator collection because disk cleanup had incorrectly removed an installed
cryptography extension. The exact dependency was restored and its RECORD hash
verified; the independent [full simulator rerun](../work/check-python-repair27/full-simulator.log)
passes all 1658 cases without skips. Component results do not turn the failed
aggregate into a pass. Remote CI and Windows/Android device tests remain separate.

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
| Local queue versus link flight budget | TCP/TLS frame BDP; focused rolling/aligned/packed byte-credit integration | Base UDP/QUIC and raw retain queue/flight coupling; aggregate/native qualification and FIX-01 remain open |
| Python high-performance composition | Codec/recovery libraries and separate aligned/packed/rolling clients exist | No qualified matching native composition; FIX-02 through FIX-04 |
| TUN flow control and QoS | Transparent active-credit path and fixed TCP-proxy slices | Adaptive native-window growth and complete fairness/pressure gates still fail or remain unrun |
| Hot mode switching | Authenticated compression changes and finite active-TUN switches | Full codec/recovery/MUX switching matrix and control-under-load correctness remain open |
| Shared clients | Runnable Linux shared CLI/local API profiles and reusable existing-session commands | Full service lifecycle remains private CLI orchestration; FIX-12, GUI and native Windows/Android remain open |
| Carrier/recovery and stable control boundaries | Independent pure protocol crates; multiple fixed runtime compositions | OpenVPN-like user recovery and data-mode-dependent control framing require FIX-10/FIX-11 |

Use [the architecture](architecture.md), [project boundaries](implementation-plan.md),
[Python parity contracts](mode-parity.md) and the stable task IDs in the master
and module ledgers for exact scope. A supported library symbol is not evidence
that a client selects it or that a native acceptance test exercised it.

## Architecture corrections in progress

The blocking fixes remain in the master checklist. Tested changes include
independent native byte delivery budgets for rolling/aligned/packed, shared
immutable FEC history, bounded reusable rolling output buffers, one contiguous
TLS framing write, and explicit pressure/deadline witnesses. These do not prove
end-to-end zero copy or the native performance target.

The legacy retained-control parser now lives outside UDP, protected OpenVPN-like
datagrams have a separate internal owner, and existing-session command handling
is public in client-core. These are real extractions with unchanged wire
identities; the public interchangeable recovery composition, negotiated stable
control envelope and complete client lifecycle API are still required by
FIX-10 through FIX-12. Base UDP/QUIC and raw delivery budget integration remains
part of FIX-01, including the independently bounded recovery source window.

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
