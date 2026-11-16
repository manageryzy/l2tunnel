# Python behavior alignment and named runtime compositions

Status: required implementation contract, based on the current source audit.
The named compositions below are not yet implemented and integration-tested as
complete Rust profiles. This contract supplements FIX-01/02/03/04/10/11/12/13,
all 47 P-* entries and full SW-11; it does not replace or narrow them.

## Separate reference configurations

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
configuration label. Full8192 also requires bounded authenticated ingress separate
from recovery support so multi-turn GF work does not discard every later arrival
as local Busy. Neither requirement is satisfied by the small-symbol component
witness; exact source findings remain in the
[source-bound integration audit](../../work/parallel-features-20261115/python-parity-staging/full-packed-common/contract-v0.md).

## Parallel implementation and acceptance ledger

The integrator owns common configuration, authenticated wire revisions, profile
dispatch, docs and batch validation. Independent lanes own CompactARQ recovery,
flow/affinity and ACK custody, and codec/rolling/copy execution. Agree shared APIs
before dependent implementation. Current TCP shared-service work can finish in
parallel; it is not Python parity evidence.

- [ ] [PBA-01] Bind each selected runtime comparison to the complete named Python configuration, source hashes, topology, ACK path, time/loss units, payload/window and measurement definition. Reject unsupported combinations before I/O; report requested/effective values through the shared client/service API.
- [ ] [PBA-02] Implement actual CompactARQ serial/history, RTT and receiver-delay sampling, rotating lossy feedback/repeats, adaptive timeout and guarded fast retry, including its first-flight/bounded-gap variants. Differential event traces cover loss, reorder, duplicates, silent tails, bounds and stale callbacks; actual selected runtime feedback uses the same carrier.
- [ ] [PBA-03] Install separately selected per-connection and shared-directional recovery topologies with bounded ownership and authenticated namespaces. Validate learned reverse affinity, conflicts, shared admission, isolation and explicit lossy-ACK retirement without false delivery or stranded drain.
- [ ] [PBA-04] Deliver the complete named Packed global8192/local128/every16 profile with real short copies, packing and ACK coalescing through actual authenticated client/runtime paths. Qualify meaningful symbol width, old holes beyond128, full/half local2 pressure, feedback loss, ring reuse, exact physical bytes and live management; component tests are prerequisites only.
- [ ] [PBA-05] Integrate L3 TCP compression and safe ACK handling first, with exact IPv4/IPv6/TCP bytes/options/checksums and fallback. Preserve and optimize L2; keep transparent TUN and explicit proxy ownership claims distinct.
- [ ] [PBA-06] Run focused changed-behavior differential and runtime checks in bounded parallel groups, then the required full check at batch acceptance. Run matched native clean/delay/loss comparisons with per-direction payload, repair/retry/copy/feedback/authentication bytes, timing, CPU and queue counters. Preserve the full80 Mbit/s target, all47 modes, SW-11, RLNC/parity/rolling/packed/proxy and platform/resource gates.

None of these complete deliverables is checked by this design change. Keep
planned, protocol-tested, implemented, integration-tested and measured-native
evidence separate, and retain failed attempts with their exact source scope.

Implementation details remain separately qualified: [selected CompactARQ](compact-arq.md)
and [physical Rolling copies](rolling-source-copies.md). Their finite leaves do
not replace the complete PBA-01..06 definitions above.
