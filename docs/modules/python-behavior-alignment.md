# Python behavior alignment and named runtime compositions

Status: required implementation contract, based on the current source audit.
The named compositions below are not yet implemented and integration-tested as
complete Rust profiles. This contract supplements FIX-01/02/03/04/10/11/12/13,
all 47 P-* entries and full SW-11; it does not replace or narrow them.

## Separate reference configurations

For single-flow Packed C48, the application delivery order is part of the
comparison. The frozen forward flow uses one channel and holds full-size
data behind its predecessors. The early-delivery variant can hand a
decodable segment to TCP while a predecessor is missing. Its cumulative
NewReno sender reacts to the resulting duplicate ACKs. Linux uses native
SACK processing and may reject a late original under TCP timestamp
validation. The optional Python `tcp_data_paws` switch applies that
established-DATA check at the receiving TCP endpoint. Its effect depends
on which packets actually reach that endpoint, their order and their
timestamps. In the matched FIFO and early-delivery simulator runs it
rejected zero and 23 segments respectively.
[Matched receiver and native evidence](frame-channel-experiment.md#receive-service-and-inner-tcp-timestamp-validation).

Single-flow comparisons must also name the application credit rule and
latency origin. The optional paced application producer models socket-unsent
and unacknowledged bytes under one credit cap and records scheduled, written,
first TCP issue and completed-read times separately. Record the end-of-drain
unconfirmed count and the number of records absent from the latency cohort.
[Socket-credit comparisons](frame-channel-experiment.md#single-flow-socket-credit-and-the-two-directions-of-recovery).

The [source-bound configuration inventory](../../work/parallel-features-20261115/python-parity-staging/flow-layout/named-profiles-v0.json)
retains exact fields, seeds, result paths and hashes. The accompanying
[composition audit](../../work/parallel-features-20261115/python-parity-staging/flow-layout/contract-v0.md)
records the actual Python and Rust call paths. These are historical observations
and current source analysis, not new throughput measurements or owner defaults.

| Named reference | Recovery and ACK behavior | Required Rust composition |
| --- | --- | --- |
| `quic-overhead-1/2/3`, `compact-arq` sensitivity | Sixteen independent CompactTCP instances, each with its own directional recovery and codec state; shared physical links. Reverse inner TCP ACKs bypass compact recovery but still traverse the charged lossy link. Three stored runs average 78.7501557 Mbit/s. | Bounded actual per-connection owners, CompactARQ feedback/timing and explicit lossy ACK recovery bypass. Sixteen MUX channels are not sixteen independent connection owners. |
| C46/C47/C48, `Mux16 Select3 Pack0.5 ACK2 C5 Load64/72/76` | One shared PackedWire recovery owner per direction, sixteen connection-RR channels and learned reverse affinity. MuxTCP sends inner ACKs through the same MUX/recovery despite inherited `reliable_acks=False`. Offered loads are 64/72/76 Mbit/s. | Actual shared directional packed/RLNC composition, full global8192/local128/every16, copies3, 0.5 ms packing and 5 ms ACK coalescing; keep the three offered-load profiles distinct. |

The first reference uses block_sources8192, repair_ratio0, flush1 ms,
feedback5 ms/64 packets, tcp_delta, modeled outer36/authentication45 bytes,
25 s traffic/5 s warmup/20 s drain and no application rate cap. The second uses
repair_ratio0.205, feedback1 ms/64 packets, flush2 ms, independent short records
up to128 bytes, predictive records, payload-length elision, trimmed repair padding,
context-and-independent short copies and raw_ipv4_crc32 in the simulator.
Its inner ACK settings are every2, delayed ACK10 ms, coalescing5 ms, copies1 and
no aggregate-ACK batching; traffic/warmup/drain are90/5/30 s. Both use sixteen
CUBIC flows and a fixed aggregate4 MiB inner window. Exact configuration objects,
including all remaining fields, are authoritative in the linked inventory.

Record the scenario's100/10 Mbit/s,70 ms RTT and15% loss separately from a
70 ms delay **each way** experiment. Compare identical measurement windows and
ACK paths. Authentication byte cost is not executed cryptography. Neither a
source audit nor equal outer overhead explains the entire native performance gap.

## Recovery, wire and time contract

Use the selected Python implementation as the behavior oracle. Replace a wrong
Rust selected path instead of preserving its behavior as the target. Retain
historical receipts and explicitly versioned compatibility readers; a legacy
mode remains labeled legacy until its replacement is selected end to end.

CompactARQ requires a new transmission serial on every source attempt, a bounded
serial-to-send-time history, cumulative prefix and rotating receipt bitmap,
echoed transmission serial, receiver ACK delay and feedback serial. RTT samples
subtract the receiver delay. Preserve Python's SRTT/RTTVAR estimator, adaptive
RTO, three-later-receipts threshold, newer-echo/newer-feedback tests and RTT guard
for fast retransmission. Receipt arms two additional lossy feedback repeats.
Timeouts belong to the current attempt serial; stale timers do not retry a newer
attempt. The current Python `_timeout` recalculates `_rto()` and does **not** use
exponential timeout backoff. First-flight and bounded-gap variants retain their
own additional rules; they are not aliases for the base algorithm.

Python models packet fields and byte costs; it does not provide an existing
serialized CompactARQ byte codec. Derive deterministic behavioral event fixtures
from that implementation and define explicit Rust wire fixtures separately.
Do not claim byte parity with nonexistent Python serialization. Version and
authenticate the complete new policy/wire namespace; do not repurpose old padding,
local custody tokens or cryptographic packet numbers as transmission serials.
Public protocol code keeps injected time/I/O and independently bounded source,
history, bitmap, retry and work storage; no Tokio, OS or real-clock dependencies.

Python times from link serialization finish. Rust whole-carrier acceptance is
the closest existing observable boundary, and may precede kernel/NIC departure.
Retain the original acceptance timestamp through delayed callbacks. Expose queue,
acceptance and observation times distinctly; do not label this physical clock
difference exact simulation parity. Retransmits, repairs, copies and feedback all
consume their actual selected-carrier bytes and pacing budget.

## Runtime composition and TCP priority

Recovery feedback follows the selected carrier's ordinary lossy data path for
these lossy references. Reliable TCP/TLS or QUIC-stream feedback is a material
legacy difference. Authenticated management remains independently reliable and
bounded on the same selected carrier; changing recovery feedback must preserve
liveness, epoch negotiation, rekey capability and SW-11 drain/retry semantics.

The flow/recovery profile explicitly identifies native flows, MUX channels,
codec contexts, recovery owners and physical lanes. Per-flow and shared-directional
profiles need different actual owners and isolation tests. Reverse affinity is
learned from authenticated decoded record identity, with bounded capacity and
explicit simultaneous-open conflicts; do not modulo-remap an incompatible channel.

For the independent reference, an inner ACK bypasses **recovery only**. It retains
the common admission policy, authentication/replay, MUX and wire budget. Define
unreliable-record retirement separately from peer-confirmed native delivery so
loss neither strands epoch drain nor fabricates delivered counters. The shared
Packed reference retains ACK recovery and needs no such bypass.

Prioritize actual L3 IPv4/IPv6 TCP. RawIp packing alone is not tcp_delta header
compression. Preserve options, payloads, checksums and unsupported-packet fallback;
keep L2 contexts and other user traffic working. Transparent TUN cannot control
endpoint cwnd or manufacture endpoint ACK policy. Selected TCP proxy owns its
maintained TCP endpoints and may implement endpoint policy there. Keep local
storage, native flight credit and recovery debt as three independent domains.

ACK coalescing must operate on actual bounded unsent ACK custody. Preserve genuine
duplicate events, TCP option/ECN/window semantics and the original coalescing cap;
new arrivals cannot renew it. Delay10 ms and coalescing5 ms are different timers.
All emitted ACKs and probes use the same admission and channel budget as data.

Full packed acceptance requires actual global8192 support at meaningful symbol
width, local128 and global cadence16, old-hole recovery, bounded ingress independent
of recovery support, retained sources, actual short-source physical copies and
installed ACK coalescing in one selected client profile. Codec copy selection or
an eight-byte-symbol component witness cannot close that end-to-end requirement.

The named CompactWire source fixes1460-byte symbols and MTU1500. Current Rust
Packed metadata and actual cryptographic/carrier overhead cannot fit that same
symbol into one MTU1500 datagram. Preserve the coding width and network MTU:
complete alignment needs a versioned source/repair fragmentation and bounded
reassembly composition, with original identities/deadlines and each physical
fragment charged/authenticated. A changed-MTU experiment must have a distinct
configuration label. The maintained [fragment original-time core](fragment-original-time.md)
now has finite protocol evidence; [whole-group charging](rolling-fragment-output.md)
and [selected Engine/Bank/runtime fragmentation](common-record-fragmentation.md)
have finite implementation evidence. Their complete service/native/resource
qualification remains open. Full8192 also requires bounded authenticated ingress separate
from recovery support so multi-turn GF work does not discard every later arrival
as local Busy. Neither requirement is satisfied by the small-symbol component
witness; exact source findings remain in the
[source-bound integration audit](../../work/parallel-features-20261115/python-parity-staging/full-packed-common/contract-v0.md).

The current learned mapping is an explicit CompleteV2 mapping code3. It learns
from the actual authenticated decoded native channel into the same outbound
Pipeline, without advancing its local connection-RR cursor. Conflicts are explicit;
a bounded idle scan retires a binding and passive ACK history only after actual
Engine drain. Both directions require matching channel width/native layer and
learned selection. Legacy v1 configuration explicitly refuses this new mapping;
its original bytes/defaults are unchanged. The actual paired Packed Engine case
passes in [Cases21](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-21/validation.json); its combined ACK-history retirement correction passes
[Cases22](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-22/validation.json). This is not the complete independent recovery topology.
See [independent-owner prerequisite](connection-records.md) and
[actual ACK ingress](common-ack-ingress.md).

## Parallel implementation and acceptance ledger

The integrator owns common configuration, authenticated wire revisions, profile
dispatch, docs and batch validation. Independent lanes own CompactARQ recovery,
flow/affinity and ACK custody, and codec/rolling/copy execution. Agree shared APIs
before dependent implementation. Current TCP shared-service work can finish in
parallel; it is not Python parity evidence.

- [ ] [PBA-01] Bind each selected runtime comparison to the complete named Python configuration, source hashes, topology, ACK path, time/loss units, payload/window and measurement definition. Reject unsupported combinations before I/O; report requested/effective values through the shared client/service API.
- [ ] [PBA-02] Implement actual CompactARQ serial/history, RTT and receiver-delay sampling, rotating lossy feedback/repeats, adaptive timeout and guarded fast retry, including its first-flight/bounded-gap variants. Differential event traces cover loss, reorder, duplicates, silent tails, bounds and stale callbacks; actual selected runtime feedback uses the same carrier.
- [ ] [PBA-03] Install separately selected per-connection and shared-directional recovery topologies with bounded ownership and authenticated namespaces. Validate learned reverse affinity, conflicts, shared admission, isolation and explicit lossy-ACK retirement without false delivery or stranded drain.
- [ ] [PBA-04] Deliver the complete named Packed global8192/local128/every16 profile with real short copies, packing and ACK coalescing through actual authenticated client/runtime paths. Qualify meaningful symbol width, old holes beyond128, full/half local2 pressure, feedback loss, ring reuse, exact physical bytes and live management; component tests are prerequisites only. The [exact fragment output charge](rolling-fragment-output.md) is a finite prerequisite; it does not qualify selected Engine/runtime fragmentation or this full profile.
- [ ] [PBA-05] Integrate L3 TCP compression and safe ACK handling first, with exact IPv4/IPv6/TCP bytes/options/checksums and fallback. Preserve and optimize L2; keep transparent TUN and explicit proxy ownership claims distinct.
- [ ] [PBA-06] Run focused changed-behavior differential and runtime checks in bounded parallel groups, then the required full check at batch acceptance. Run matched native clean/delay/loss comparisons with per-direction payload, repair/retry/copy/feedback/authentication bytes, timing, CPU and queue counters. Preserve the full80 Mbit/s target, all47 modes, SW-11, RLNC/parity/rolling/packed/proxy and platform/resource gates.

None of these complete deliverables is checked by this design change. Keep
planned, protocol-tested, implemented, integration-tested and measured-native
evidence separate, and retain failed attempts with their exact source scope.

Implementation details remain separately qualified: [selected CompactARQ](compact-arq.md)
and [physical Rolling copies](rolling-source-copies.md). Their finite leaves do
not replace the complete PBA-01..06 definitions above.


## Historical source bindings and the confirmed-prefix comparison (2026-11-19)

All 15 source hashes in each of the four named references match Git revision
`502314fb86ec21b075e705492b7280ee19551791`. The historical reference digests
and measurement provenance remain pinned to those bytes. The current checkout
differs in two files. The selected CompactARQ study instantiates
`CompactARQTransport` directly and does not select the new C48 wire grammar in
`compact_wire.py`. Its TCP endpoint does inherit the changed recovery boundary
in `tcp.py`: a third duplicate ACK at the end of the previous loss window can
no longer start another window reduction at that same ACK number. Reproducing a
historical TCP trajectory therefore requires the pinned source. The preflight
accepts these two reviewed checkout hashes for the CompactARQ configuration
projection and records them separately from the historical source hashes. A
further change to any bound file requires review. Shared Packed C46, C47 and
C48 retain their individual reference digests and pending native bindings.

The following executable C48 simulation compares fixed support with trimming an
acknowledged prefix from global or tail repair rows. Both use the same regular
and near8 opportunities, confirmed prefix from received feedback, physical
compact repair payload and modeled direction costs. The first two arms use
per-channel FIFO delivery. The second pair releases independently decodable
records to the modeled TCP receiver across gaps. In both pairs, the modeled TCP
sender starts at 10 segments, offers 90 Mbit/s of 512-byte segments, and has a
4 MiB unconfirmed limit. Each run uses the same RNG seed
(`11891353551447149637`), 100/10 Mbit/s, 70 ms RTT and 15% independent loss in
each direction. Goodput covers seconds 2 through 12. P99 covers issued segments
through application delivery, including drain. Repair share is forward IP bytes
for repair, near8 and outer retransmission divided by all forward IP bytes
during the goodput window.

| Delivery | Global support | Goodput (Mbit/s) | P99 (ms) | Inner TCP retransmissions | Forward repair share | Segments never issued by 12 s |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| FIFO | Fixed | 77.464 | 482.82 | 0 | 17.224% | 45,767 |
| FIFO | Confirmed prefix | 78.195 | 465.66 | 0 | 17.165% | 45,108 |
| Immediate | Fixed | 0.331 | 177.55 | 28 | 30.328% | 262,629 |
| Immediate | Confirmed prefix | 0.326 | 177.55 | 27 | 30.860% | 262,637 |

All arms drained their issued TCP data and both outer directions within the
48-second drain budget. Under FIFO trimming skipped 2,368,315 source positions
across 412 emitted repair rows. Immediate delivery skipped 3,651 across nine
rows. The immediate runs issued only 1,043 and 1,035 of 263,672 scheduled
segments, respectively. Their P99 excludes all work the modeled sender had yet
to admit. This single seed measures model behavior. Native Linux TCP, GF
execution time and native scheduling require separate measurements.
[FIFO fixed](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/perf-prefix-model-fifo-fixed/evidence.json),
[FIFO confirmed prefix](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/perf-prefix-model-fifo-confirmed_prefix/evidence.json),
[immediate fixed](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/perf-prefix-model-immediate-fixed/evidence.json),
[immediate confirmed prefix](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/perf-prefix-model-immediate-confirmed_prefix/evidence.json).

## Current individual reference bindings

The current checkout's named CompactARQ projection also covers opt-in changes
to the Packed native-IP grammar and NewReno duplicate-ACK reentry model.
The named reference selects CompactARQ and its existing cumulative-ACK TCP endpoint
with the new ACK heuristic disabled. Its pinned historical source and run
configuration are separate from the reviewed live-file hashes. The fixed-anchor
wire and two-seed single-flow evidence belong to the distinct Packed studies.
In those studies, wire-only SACK and sender-side scoreboard processing are
separately selectable. Both pay for actual reverse SACK frames. The scoreboard
uses received ranges to select retransmissions and preserves the original
congestion recovery boundary when multiple segments have been retransmitted.
The optional `scoreboard-dsack` policy can restore the window after all
retries in that episode have returned duplicate receipts and the cumulative
ACK covers the recovery interval. It preserves ambiguous or unproven reductions.
In the matched two-seed comparison it improved goodput and application P99
over the scoreboard and increased inner retransmissions per delivered MiB.
The independently selectable earliest-gap request can advance an already
payable named mask when a single degree of freedom is missing across two
ordinary feedback turns. In the initial wire-only seed it produced identical
traffic. In the held-out wire-only seed it advanced the first native segment
past its TCP retransmission, improving goodput from 1.128 to 1.619 Mbit/s.
The scoreboard arms had worse delivery P99, so this remains a comparison
policy. [Directional costs and final debts](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/mixed-frontier-policy-comparison-v2.json).
[Current Packed comparison](frame-channel-experiment.md#native-ip-header-and-single-flow-model-comparison)
and [scoreboard results](frame-channel-experiment.md#inner-tcp-sack-evidence-and-repeated-congestion-recovery).

## Six-blocker correction batch (2026-11-18)

The benchmark exporter now has an explicit `--python-reference compact-arq-quic-overhead`
selection. It constructs sixteen independent CompactARQ Guarded owners with8192
sources per owner,5 ms/64-event feedback and authenticated lossy inner-ACK recovery
bypass. The ordinary Cauchy64-source and512-source independent diagnostic rows
retain their original identities and policies. The selected Compact recovery uses
its existing transmission serial, RTT/receiver-delay estimator, guarded fast retry
and adaptive non-exponential timeout; ordinary Cauchy is not renamed to this mode.

The named row pins the complete Python reference inventory and source hashes.
Offline daemon inspection projects the actual decoded descriptor; the harness
checks it against both the requested row and the pinned reference core before
creating a namespace. Exact comparison is refused while any declared difference
remains. Geometry, real cryptography/outer wire, kernel TCP/window behavior,
finite attempts/history, carrier-acceptance clock and the current native workload
window remain explicit differences. C46/C47/C48 remain separate full requirements.
A matching recovery projection does not qualify a matching full experiment.

The same batch feeds direct ARQ retries into uniquely mapped live Cauchy decoder
state and removes timer-wheel waits between runnable bounded Rolling/Research
work turns. The latter addresses the identified ingress-service delay using the
existing work grants, queue capacities and original deadlines. [Native receipts](../../work/aligned-extents-20261117/batch23-results.jsonl) show ordinary Cauchy passing forward at 0.9869568 Mbit/s. Both named Compact attempts validated the selection and exhausted the 10-second local status query during the workload. Rolling still expired. After bounded elimination/copy batching, the server received its repair at 6,998,906 us and admitted it at 11,989,497 us, leaving 9,409 us before the original decoder deadline. The server observed 113,829 Busy returns and 55,485 cooperative Work selections. Over a distinct 7.7005-second sample it consumed 7.15 seconds of user CPU and 0.10 seconds of kernel CPU. These are process totals, not a per-function profile. The queue service rate under load and management responsiveness remain unresolved. PBA-01..06 and full native acceptance remain open.
