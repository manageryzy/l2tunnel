# Owned rolling-frame native qualification

Status: implemented harness with scoped unprivileged tests; aggregate/native gates remain open.
No privileged run has occurred. The runtime/client finite local evidence is in
[rolling runtime](rolling-runtime.md) and [rolling client](rolling-client.md).

## Explicit finite matrix and ownership

New `tools/rolling_native_smoke.py` is dry-run by default. Explicit `--apply`
requires an immutable successful source-stable build receipt, exact daemon and
all loaded helper hashes. It copies daemon/helpers/receipt into a fresh exclusive
output and replaces the launcher with the copied worker before any namespace
mutation. The worker rechecks helper provenance, exact directory identity and
layout, and the daemon hash before/after each case. No shared helper is edited.

The first apply requires an exact `--only-case` (one original lab owner).
Cases explicitly select `udp|quic`, `tap|tun`, `full|half`, and `clean|loss`.
The complete strict policy is W32/local8/G16, maximum original1000, ratio1/2,
H8, job/handoff5000ms, debt20000ms, tail20ms, feedback5ms/4events, bounded
32MiB reservations, service4096/pass8 and four common MUX channels. This is a
small-window engineering profile. UDP uses only custom QUIC-like cover with
HMAC integrity; genuine QUIC uses maintained AEAD and no custom cover. Native
packet maximum1600, underlay MTU1500, compression off and system selection are
explicit. TAP system versus transparent TUN DRR remains visible in status.
The loss profile installs35ms/15% random loss on both owned WAN egress queues;
clean uses1ms/0%. These gates and exact payload/deadline bounds are fixed.

Reuse the existing journal/namespace identity owners, finite process/capture/
receipt helpers and independent native TCP byte/capture auditor. After shared owned topology creation, every additional network
mutation names a currently journal-owned namespace. No host route, bridge,
qdisc, sysctl or firewall changes are allowed. Existing namespaces are never
adopted or removed. Apply rollback and normal cleanup have read-only before/after
namespace observations so an unjournaled/replaced/residual name fails evidence.
Only private identity-checked local sockets may be removed after owned processes
are reaped. Original setup/case/stage deadlines and bounded logs, captures,
status samples and subprocess owners are retained across retries/failures.

## Actual acceptance and limits

Before authentication, genuine QUIC installs owned TCP egress blocking and
records failed TCP SYN/drop evidence. Protected UDP keeps its actual retained
TLS lanes; capture parsing distinguishes TLS control from fixed UDP data tuples.
Both peers must report exact authenticated rolling selection/digest and actual
Forwarding state. No native packet or completed ping infers the selected mode.
All user probes use the native device/common MUX. Require IPv4/IPv6 probes and
independent bidirectional kernel TCP payloads65537/32771 bytes for each family,
with exact hashes and EOF. Independently audit native IP packet bytes, complete
TCP streams and no unexpected native reset. This IP auditor does not claim
byte-exact arbitrary Ethernet/VLAN/padding metadata qualification. Finite captures must start before
authentication, report real readiness, have no truncation/kernel drops and stay
below packet/byte/MTU caps. UDP visible records must structurally show both source
and repair in each bulk direction/lane; this does not authenticate captured tags
or prove that a particular repair caused a native delivery. QUIC captures prove
outer path/size only, because authenticated datagrams are encrypted.

Protected UDP also drops only UDP egress for a fixed2s, requires blocked native
probes in both directions and actual filter drops on each peer, then restores the original filters and requires
native probes to recover. Conservative realtime/monotonic clock brackets and drift checks bound the
capture-time interval. Fresh captured TLS connection bytes and later peer ACK
progress in each direction/lane during the installed
outage distinguish retained control progress from UDP data recovery. Old
retransmissions alone cannot satisfy this causal control witness. Original
runtime debt/job deadlines are never renewed. Final cleanup explicitly cancels
original daemons; cancellation is never a clean-drain/native-credit receipt.
W8192, complete local/global Python family, alternate UDP cover/suite, throughput,
fairness, hot switching, protected clean close and non-Linux platforms stay open.

## Checklist

- [x] [MOD-ROLLINGNAT-01] Implement strict dry-run matrix/commands, exact selected status and immutable copied-helper execution; pass unprivileged regressions. Evidence: [18 new pure regressions](../../tools/test_rolling_native_smoke.py), [exact scoped receipt](../../work/rolling-native19/validation.json).
- [x] [MOD-ROLLINGNAT-02] Implement bounded owned native/capture/UDP-outage/QUIC-TCP-block orchestration and failure cleanup; pass unprivileged ownership and parser regressions. Evidence: [bounded orchestration](../../tools/rolling_native_smoke.py), [parser/provenance/cleanup regressions](../../tools/test_rolling_native_smoke.py).
- [ ] [MOD-ROLLINGNAT-03] Pass root's next stable aggregate before any native build/run.
- [x] [MOD-ROLLINGNAT-03A] Freeze exact scoped files and finite unprivileged evidence. Evidence: [source/helper hashes and 60-test receipt](../../work/rolling-native19/validation.json).
- [ ] [MOD-ROLLINGNAT-03B] Pass root aggregate with cross-capture identity agreement: equal session/scope, equal bytes at overlapping protected counters/record IDs and common protected source/repair packets and records in every bulk direction; opaque QUIC requires common captured datagrams without plaintext claims.
- [ ] [MOD-ROLLINGNAT-04] Execute/audit exact clean UDP and QUIC TAP/TUN full/half cases with fresh owned labs and immutable build.
- [ ] [MOD-ROLLINGNAT-05] Execute/audit fixed35ms/15% loss cases with unchanged exact payloads and deadlines.
- [ ] [MOD-ROLLINGNAT-06] Independently qualify alternate profiles, W8192 service and full Python-family behavior before broader claims.

## Scoped verification and execution boundary

The new harness has no privileged/native execution receipt. Its pure regression
suite covers all16 dry-run cases, exact peer commands, selected status/capability
rejection, literal visible-wire structures and malformed/truncated corpus,
PCAP extents/checksums/precision/MTU/caps, fresh TLS sequence/ACK outage causality,
clock drift, immutable helper substitution/loaded origin, verified-copy exec
before namespace apply, one shared process cleanup deadline, and partial-apply
residual namespace versus actual journal cleanup. Reused helper regressions run
in the same unprivileged group. The exact files and commands are pinned in the
[scoped receipt](../../work/rolling-native19/validation.json). Root must register
the new unittest in the next copied aggregate and use this tool's `source_hashes`
for a subsequent immutable native build; no existing helper/default is edited.

Original direct command allowance is10s; the unchanged shared topology/cleanup
helper also retains its existing15s per-command cap within the same original
case/cleanup deadline. Offload and underlay sysctl helper calls have a10s total
local allowance. Case150s, setup35s, transfer30s, data outage2s, final settle1s and
cleanup30s are fixed. Captures remain8192packets/32MiB each, local replies8192B,
logs/receipts4MiB and status snapshots64slots. Both daemon cancellation signals
are issued before waiting; forced cleanup cannot satisfy a protocol acceptance
stage or be reported as clean drain. Explicit capture/timeout exhaustion is
`bound_exhausted`; unsupported observation, tool failure and invalid evidence
remain separately reported.

## Pre-native ALPN correction

Independent first-run readback caught a concrete launcher error before any native
execution: the first literal decoded to17 bytes, while the unchanged client CLI
requires exactly16 bytes/32 hexadecimal digits. The corrected explicit lab ALPN is
`rolling-nativ-01` (16 bytes), encoded from a bytes constant. The command regression
checks exact32 hexadecimal digits and16 decoded bytes for every generated QUIC
peer/layer/duplex command. A separate pre-I/O invocation of the existing immutable
source19 daemon confirms the old literal is rejected by the actual CLI and the
corrected literal reaches the missing-credential boundary without socket/device
setup. The [superseding scoped receipt](../../work/rolling-native20/validation.json)
preserves this evidence; the original frozen19 files remain historical artifacts.
No CLI bound, loss, deadline, payload or runtime default changed. Root subsequently
added cross-capture session/scope, counter and record-byte agreement, with common
source and repair records in each bulk direction. Loss may leave noncommon packet
subsets; equal complete captures are not required. QUIC requires common opaque
datagram bytes in every lane/direction, without claiming plaintext or cryptographic
verification. Three new adversarial regressions reject individually valid but
different traces and preserve legitimate loss subsets; all 21 rolling harness
tests passed. Aggregate/native qualification remains separately gated above.

A further regression shifted all protected packet counters while preserving
identical inner record IDs and bytes. The source20 auditor incorrectly accepted
these disjoint traces. The corrected auditor requires at least one identical
protected source packet and one identical protected repair packet per bulk
direction, in addition to record agreement. The before/after regression is
preserved in `work/rolling-peer-agreement20/`; source20's passing aggregate
predates this correction and cannot qualify the final auditor.
