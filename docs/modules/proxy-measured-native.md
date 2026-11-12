# Measured native TUN acceptance harness

Status: the dry-run-first harness and its unprivileged validators/endpoints are
implemented. No privileged measured TUN case has been run by this change. A
passing harness test, target change or compile is not native advertised-window
qualification. The [focused receipt](../../work/proxy-measured-native-harness/validation.json)
and [client checkpoint](../../work/proxy-measured-client/validation.json) have
separate scopes. Runtime authority remains in
[the measured runtime contract](proxy-measured-runtime.md).

## Entry points and owned scope

```sh
python3 tools/proxy_measured_native_smoke.py --lab-id measured --output NEW_DIRECTORY
python3 tools/proxy_measured_native_smoke.py --lab-id measured --output NEW_DIRECTORY --profile pressure
```

Both commands default to a plan only. They validate the suffixed namespace IDs
and print the complete strict measured policy, clean topology, exact CLI flags,
workloads and original bounds. They create no output, keys, sockets or network
objects. `--only-case tun-full-clean|tun-half-clean` selects one clean case;
pressure requires both `--profile pressure` and its matching
`tun-full-pressure|tun-half-pressure` selection. Omitting `--only-case` runs full
and paired-half in separate owned namespaces for the selected profile.

An actual run additionally requires explicit `--apply`, Linux/root, an exclusive
new output directory, `--binary PATH`, and `--build-receipt PATH`. The receipt
must prove the original source-stable build and exact binary hash. Its source
map must also include the exact executed measured harness, fixed helper and
`netns_lab.py`. Copy all three beside the binary, verify them against that build,
and replace the launcher process with the copied harness before any namespace
mutation. The copied worker checks its directory device/inode, exclusive layout,
loaded module paths and helper hashes, rechecks them around each case and
rechecks the binary afterward. A later live helper substitution cannot qualify.
The launch-observed source map remains distinct from the original build map.
Source hashing includes real source directories named `target`; generated root
build directories are outside the scanned crate/application/vendor roots.

The new harness reuses the fixed harness's identity-checked namespace journal,
bounded command/process/capture helpers, strict exact-byte probes and existing
split/bypass/FIN/underlay audits. Historical fixed harness profile defaults and
saved receipts are unchanged. Only its source-provenance directory filter was
corrected, with a regression for `src/target/tests.rs`.

All TUN, address, qdisc, ECN, offload and IPv6-underlay adjustments occur inside
new journal-owned namespaces. No host route, qdisc, bridge, sysctl or existing
namespace is adopted. Cleanup stops only retained child objects and uses the
same ownership journal. Failed evidence and cleanup failures remain visible.
Private key material stays in a temporary mode-0700 directory; copied artifacts
and receipts contain hashes and public paths, never private keys.

## Actual selected policy and clean gate

The harness uses `--traffic proxy-measured --carrier tcp --layer tun --device tun0
--record-profile frame --compression off --max-packet 1600` and the selected
full/half duplex. `policy()` emits all required `measured-relay-v1` fields:
16 channels/owners, maintained TIME-WAIT, only A-to-B port 24451 proxy routes for
IPv4/IPv6, an initial aggregate target of 32768 bytes/32 records, a 2048-byte/
one-record floor, a 65536-byte/64-record per-flow cap, and a 1-MiB/1024-record
session/policy cap. Report/rate/probe/plan/status intervals are 10 ms; service
work counts are four, and all ownership/freshness timers are explicit. Both
peers authenticate this exact policy. Nothing infers measured selection from
extra JSON fields or modifies endpoint TCP congestion algorithms.

Each clean case retains the existing native baseline:

1. Capture both `tun0` and both `wan0` before generating traffic. Authenticate
   the original one/two TLS lanes and require identical measured digests,
   Forwarding, zero allocated owners and matching effective lane/profile state.
2. Prove bidirectional IPv4/IPv6 ICMP bypass. Run two concurrent owned TCP flows,
   one per family, with exact opaque 65537/32771-byte bidirectional payloads and
   FIN/EOF. Require two real owners and different split SYN/SYN-ACK sequence
   spaces, rather than treating transparent byte delivery as split proof.
3. Retain the denied-port and reverse-originator transparent transfers. Their
   original SYN identity must cross unchanged; owner counts remain two.
4. Retain actual measured ACK bins, fresh authenticated common-path echo service
   latency and admissions of Demand/EchoRequest/EchoReply. These are actual
   Controller snapshots; echo latency is not native RTT or cwnd.
5. Submit both drains promptly, observe actual terminal close reports, exact
   cross-peer user/native fences, two clean/zero stopped flows and closure of
   every original TLS lane. Require successful child exits and owned cleanup.

Clean capture evidence records both native legs' original SYN window and
option bytes, the negotiated scale and observed established windows. The SYN
window remains unscaled. The maintained native ring is preallocated at 65536
bytes; an initial SYN window is not evidence of progressive ring enlargement.
The clean profile does not require or claim a pressure-induced window change.

## Separate finite pressure gate

`--profile pressure` replaces only the two owned application transfers. Every
endpoint concurrently sends exactly 786433 deterministic opaque bytes, with
8192-byte requested application send/receive buffers, pauses its reader for two
seconds, then reads to exact EOF. Actual effective buffer sizes and bounded
send/read timing are recorded. Send completion must follow the read pause,
proving this finite workload did not simply fit in all buffers. All traffic uses
the same measured runtime, channels and native paths as the clean case.

For each family and each maintained native leg, require:

- The actual native advertiser's positive window, then zero during the correct
  downstream application's paused-reader interval.
- Its **first** positive window after that selected zero strictly after the
  downstream reader's release, followed by new original-byte ACK progress after
  release. A window that reopened before release and merely sends a later
  positive ACK is rejected. All proof packets precede the first native FIN.
- Exact original SYN/SYN-ACK scaling negotiation. Apply the advertiser's scale
  only when both native peers offered scaling; keep the SYN field unscaled.
- Complete capture/checksum/MTU/FIN/reset evidence and renewed exact payload
  completion. `a_native` uses the original server/listen reader release;
  `b_native` uses the original client/connect reader release.

Classic-PCAP microsecond/nanosecond timestamps are retained. Probe monotonic
nanoseconds are mapped to capture realtime with bracketed realtime reads at
start, reader release and end. Each bracket is at most 1 ms and the overall
offset envelope at most 5 ms. The zero lies strictly inside the conservative
pause interval; first reopen and new ACK lie strictly after the conservative
release upper bound, including capture timestamp quantization. Unstable clocks
or ambiguous ordering fail the evidence gate; no synthetic timestamp is used.

The pressure gate also requires actual demanding flows, qualified ACK/service
observations and an applied few-flow candidate above the explicit initial
32768-byte target on both peers. Two-demand and receiver/carrier-pressure
samples must be polled entirely inside the real overlapping reader pauses;
pressure must include an authoritative observation newer than the first such
sample, excluding frozen startup status. This is separate from the captured
native-window proof. A relay target, reservation or grant is never reported as
a native advertised window or native cwnd.

Both owned flows must have overlapping send intervals and exact bidirectional
completion within the original bounds. The current measured client has equal
DSCP weights and no weight editor. This is a finite two-flow demand/completion
gate. Weighted fairness, 4/16/64-flow tests, impairments, performance comparisons
and native RTT/cwnd measurements remain separate tasks.

## Bounds and evidence

Retain the fixed harness's original 300-second case, 30-second transfer,
5-second probe inactivity, 40-second startup, 120-second runtime drain,
127-second drain observation and five-second local-only post-result grace.
No request, later phase or reader release renews them. Each local RPC remains
at most two seconds/8192 bytes. Retain 8192 packets/32 MiB per capture,
4-MiB logs/atomic receipts and the separate 30-second namespace-cleanup bound.
The measured harness retains at most 512 status samples, polling at 20 ms while
workloads run and 100 ms during terminal observation; sample exhaustion is a
bounded outcome, not truncation followed by pass.

Outcomes distinguish passed, failed, bound_exhausted, unsupported and
 tool_failure in the case receipt. Preserve all failures, original timestamps,
helper/policy/binary/source hashes and cleanup status. No privileged run is
performed by ordinary `tools/check.py`; its new module only exercises validators,
dry-run/safe-ownership failure paths and ordinary kernel IPv4/IPv6 loopback
pressure endpoints.

- [x] [MOD-PROXY-MEASURED-NATIVE-01] Implement concrete dry-run-first clean/pressure plans, strict measured CLI/policy, immutable copied execution and same journal-owned setup/cleanup. Evidence: [harness](../../tools/proxy_measured_native_smoke.py) and the focused receipt; no privileged outcome is implied.
- [x] [MOD-PROXY-MEASURED-NATIVE-02] Implement strict aggregate/measurement, exact pressure probe, first-reopen causality, timestamp/scaling and safe ownership validators; pass finite unprivileged tests and independent review. Evidence: [focused tests](../../tools/test_proxy_measured_native_smoke.py) and [receipt](../../work/proxy-measured-native-harness/validation.json). Real TUN captures remain a separate gate.
- [ ] [MOD-PROXY-MEASURED-NATIVE-03] Freeze a source-stable qualified binary/helpers and pass one actual clean full-duplex case with exact IPv4/IPv6 split/bypass/FIN/native fences/TLS closure and cleanup.
- [ ] [MOD-PROXY-MEASURED-NATIVE-04] Pass the same actual clean paired-half case, preserving both original authenticated lanes and reverse service.
- [ ] [MOD-PROXY-MEASURED-NATIVE-05] After clean cases pass, independently audit full/half pressure captures, mapped first reopen/new ACK, measured few-flow growth, two-flow demand/completion and all final fences.
- [ ] [MOD-PROXY-MEASURED-NATIVE-06] Design and qualify separate weighted/many-flow fairness and impaired comparisons against unchanged fixed-credit baselines. Do not infer a speedup or broad native capability from this finite harness.
