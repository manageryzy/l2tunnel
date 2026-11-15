# Python-to-Rust mode parity

Status: parity inventory, audited against the working Python sources and saved experiment receipts on 2026-11-11 UTC. All 47 complete catalog acceptance gates below remain open. The Rust workspace now contains tested protocol primitives and native Linux compositions, recorded in [implementation status](implementation-status.md); those finite results do not establish an entire Python family's behavioral and byte-level parity. Catalog status remains **planned** until its complete gate passes. An enum, configuration example, or trait is not an implemented transport.

The stable identifiers in [the mode catalog](../config/mode-catalog.toml) are a coverage checklist, not the final wire identifiers. Source paths below are relative to `simulator/`. A profile combines carrier, recovery, packetization, delivery, header codec, MUX, and ACK policies; every Cartesian combination is neither meaningful nor supported.

## Milestone vocabulary

| Milestone | Completion boundary |
| --- | --- |
| M0 | Workspace, public contracts, strict configuration, coding conventions, CI, and this inventory. |
| M1 | Authenticated session and carrier adapters, key lifecycle, bounded framing, and fail-closed capability negotiation. |
| M2 | Byte-exact L2/L3 records, classification, MUX, fragmentation, header contexts, and basic delivery. |
| M3 | ARQ and full-byte FEC implementations, feedback, timers, pacing, and bounded resource use. |
| M4 | ACK/packing optimizations and coordinated configuration epochs, with loss/reorder switch tests. |
| M5 | Linux/Windows/Android adapters, namespace/bridge/netem integration, baselines, and release gates. |
| M6 | Research algorithm ports with separately reported diagnostic and complete-protocol results. |

All deployable Python mode families are requirements, including unfavorable modes retained for comparison. Research algorithms remain tracked; analytical upper bounds and noncausal oracles are test tools and cannot be advertised as wire modes.

The target [common secure session](modules/secure-session.md) and explicitly
selected carrier are composition boundaries around these algorithms, not a
replacement inventory. Swift remains a reusable packing/recovery algorithm.
Its historical separate TCP/TLS-bootstrap path is distinct from the newer
same-socket common-UDP integration; neither qualifies another mode family.
RLNC, parity, rolling, packed, proxy and every catalog entry remain in scope.
Negotiated switching between Swift and the other record profiles retains the
full SW-11 gate; changing Swift's own policy under SW-13 is only an internal
policy operation and does not satisfy cross-profile parity or switching.

The additive [OpenVPN outer-wire carrier](modules/openvpn-wire-carrier.md) has
focused pure grammar/control and actual same-socket TLS/member/opaque-record
evidence. It does not install another recovery mode or satisfy any complete
catalog entry. Standard-dissector, Common Driver/service, full lifecycle and
native/platform/ISP acceptance stay separate from these finite carrier checks.
The explicit [streamed-control runtime checkpoint](modules/streamed-swift-control.md)
retains that same boundary: SwiftPolicyV1 and independent Liveness are actual
adapter functions; generic Management/DataFeedback and other record engines remain
open requirements. It changes none of the 47 catalog acceptance definitions.

The additive [generic Swift runtime](modules/generic-secure-udp.md) now passes
finite same-socket/native-device tests with canonical complete configurations
and two nonzero asymmetric Swift switches. Explicit shared Prepared/service/APIv3
selection now also has finite paired-owner and IPC status/switch evidence.
Explicit complete-plan CLI/inspection/APIv3 commands now pass a finite
[external-process/shared-service batch](modules/generic-transaction-cli.md).
Successful production CLI TAP/TUN startup, DataFeedback/other profile integration,
the complete generic IPC/failure/fault/resource matrix and full cross-profile
SW-11 remain open. Every complete catalog gate below retains its original
definition and remains open.

The preceding [actual reserved common Engine checkpoint](modules/common-engine-storage.md)
protocol-tests real Swift/Aligned/Packed owners over the same actual reserved
Pipeline/MUX/DRR. Paired pure tests and selected existing caller regressions do
not qualify full SW-11. The subsequent
[mixed Bank](modules/common-record-bank.md),
[shared native storage](modules/shared-native-storage.md),
[native event counts](modules/common-native-counts.md) and
[compact rolling records](modules/rolling-records.md) have finite protocol evidence.
Unpacked Aligned independent-short delivery is implemented across an older gap;
Packed/rolling early-short and their full matrices remain separate requirements.
Complete resources, rolling runtime installation and all47 catalog gates retain
their original definitions and remain open.

The [fourth pure rolling family](modules/rolling-common-records.md) now has complete
tag4 bytes, actual reserved Engine/Bank custody and real repair/feedback-loss
fixtures for both native interpretations and source-wire versions. Older readers
reject tag4; the three existing profile byte formats remain unchanged. Explicit
GF work and post-carrier confirmation still require selected runtime installation.
The [managed initial](modules/managed-initial-handoff.md) and
[physical send](modules/original-datagram-custody.md) prerequisites do not qualify
another whole carrier or recovery mode. All47 complete definitions remain open.

The [explicit Common runtime/service](modules/common-transaction-state.md) now
installs the real reserved Bank and passes finite authenticated original-UDP
Swift→Aligned→Packed→Swift with actual Unix packet-device writes, liveness and
typed complete-configuration operations. This is partial SW-11 implementation,
not full parity or a new carrier/default. The full loss/fault/resource/lifecycle,
rolling, native and platform matrices remain required. Portable Common IPC/CLI
is not installed; existing Swift-only APIv3 is not a complete Common schema.

The [source-bound performance workload audit](../work/secure-udp-performance-analysis-20261113/hash-geometry-attempt-1/diagnostic.json)
distinguishes the independent per-connection recovery used by the78.7502Mbit/s
compact simulator sensitivity from current Rust directional hash/channel ordering.
In that archived build8 test, sixteen TCP connections occupy nine forward and
ten reverse ACK channels; the simulator's reverse ACKs bypass compact recovery.
Neither that study nor the later SUR-11 runtime fairness correction qualifies
P-unified-duplex-mux, full mode parity, reverse affinity or connection-round-robin
admission. All47 complete catalog gates retain their stated scope and status.

## Recovery and scheduling

| Catalog ID | Existing Python implementation | Knobs and behavior that must survive the port | Rust milestone |
| --- | --- | --- | --- |
| `legacy-arq` | `src/l2tunnel_sim/model.py:Tunnel` | Selective symbol retransmission, timeout guard; `rto_factor`, `rto_min_ms`; per-batch exact IDs or `cumulative_feedback`; `feedback_batch`, `feedback_wait_ms`. | M3 |
| `legacy-block-fec` | `model.py:Tunnel.add_to_code/flush_code`; `coding.py:block_coefficients` | Systematic GF(256) Cauchy blocks; `block_size`, `block_repairs`, partial-block proportional rounding, `fec_wait_ms`, `repair_spacing_ms`; residual ARQ. Total Cauchy symbols at most 256. | M3 |
| `legacy-sliding-fec` | `model.py:Tunnel.flush_code/queue_repair` | Random linear sliding window; `long_window`, `repair_every`, `repairs_per_group`; optional integer-credit `interleave_repairs`, causal `feedback_repair`, residual ARQ. | M3 |
| `legacy-hybrid-fec` | `model.py:Tunnel.flush_code` | Short-window repairs with every `long_every` repair using `long_window`; `short_window`, plus sliding-mode timing and feedback knobs. | M3 |
| `compact-rlnc` | `compact.py:CompactTransport/coefficient/CompactConfig` | Elastic GF(256) window; `repair_ratio`, `block_sources`, `flush_ms`, `feedback_ms`, `feedback_packets`, `tail_repair_delay_ms`; cumulative confirmation, retained source window, feedback/tail repairs. | M3 |
| `compact-arq` | `compact_arq.py:CompactARQTransport/ARQFlight` | Selective repeat, cumulative prefix plus receipt bitmap, transmission serial/ACK echo, receiver delay subtraction, RTT estimation, guarded retries and timeout backoff. | M3 |
| `first-flight-arq` | `compact_lowlatency.py:FirstFlightARQTransport` | Fresh feedback acknowledging at least three later sources may expedite only the first retry; repeated retries keep the RTT guard. | M3 |
| `bounded-gap-arq` | `compact_lowlatency.py:BoundedGapARQTransport` | First-flight recovery plus rate-limited feedback for an advancing qualified gap; `gap_feedback_min_interval_ms`. Feedback consumes opposite-direction service. | M3 |
| `compact-block-fec` | `compact_block.py:CompactBlockTransport/CompactBlockConfig` | Bounded GF(256) generations, initial repair ratio, rank-deficit feedback and in-flight repair subtraction by transmission serial. `generation_sources`, `idle_flush_ms`, `maximum_block_ms`, `assumed_loss_rate`, `repair_margin`. | M3 |
| `local-global-rlnc` | `shared_records.py:SharedRecordTransport._repair` | Shared coding with `repair_window_sources` and `global_repair_every`; periodic global repair protects older debt. `compact_wire.py` specializes this to W128/G16 and an 8192-source bound. | M3 |
| `path-scheduling` | `model.py:Simulation.send`; `multiflow.py:MultiFlow` | Earliest estimated arrival over reserved FIFO paths, forward/reverse rates and RTT factors; application pacing; independent sessions sharing service. `flow_count` differs from ordering lanes and MUX channels. Preserve fixed-total and per-flow window policies. | M3 |

`coding.py:Decoder` performs coefficient/rank recovery. Bulk simulator repairs generally do **not** multiply and transmit actual payload bytes. `compact_wire.py` explicitly uses zero repair payload placeholders and a source ledger. The Rust FEC gate therefore requires real vector arithmetic and recovery from received bytes only, including nonzero/random payloads, partial symbols, lost contexts, and malformed coefficients. Passing the Python throughput experiment cannot satisfy this gate.

## Records, compression, wire framing, and MUX

| Catalog ID | Existing Python implementation | Required variants and bounds | Rust milestone |
| --- | --- | --- | --- |
| `legacy-fragment-packing` | `model.py:Tunnel.frame/Packer` | `fragments`, `source_batch`, `repair_batch`, reverse equivalents, `pack_wait_ms`, MTU-aware fragmentation; shared loss event for packed symbols; forward `streams` round-robin ordered lanes and `reverse_ordered`. | M2 |
| `compact-cross-frame` | `compact.py:CompactTransport` | Records span symbols and share datagrams; reliable context and ordered stream release; valid-length metadata and tail flush. | M2 |
| `full-l2` | `compact.py:CompactHeaderCodec.encode/decode`; `CompactConfig.header_profile` | `full_l2`, and raw kind-2 fallback for unsupported headers. Complete original Ethernet bytes must round-trip. | M2 |
| `tcp-header-codecs` | `compact.py:CompactHeaderCodec` | `tcp_timestamp` context + 23 dynamic bytes; `tcp_delta` masked modular varint deltas. Ethernet/IPv4/TCP with 12-byte timestamp option; validate regenerable checksums and lengths, otherwise full-frame fallback. Payload bytes remain opaque. | M2 |
| `independent-record-arq` | `compact_unordered.py:IndependentRecordARQ/IndependentRecordTCP` | Explicit record ID and fragment descriptors, independent completion, selectable ordered/unordered delivery. These are distinct from per-channel delta contexts. | M2 + M3 |
| `shared-context-mux` | `shared_compact.py:MultiplexedHeaderCodec/MultiplexedCompactTransport/SharedCompactMultiFlow` | Multiple flow contexts in a shared compact coding stream. Retain as an earlier reference mode. | M2 |
| `shared-records` | `shared_records.py:SharedRecordReceiver/SharedRecordTransport` | Channel + wrapping channel sequence + encoded length, valid-byte/anchor symbol header; independent ordered release per channel or global ordered delivery via `independent_delivery`. Half-range channel serial bounds apply. | M2 |
| `aligned-records` | `aligned_records.py:AlignedRecordTransport/AlignedRecordReceiver` | Channel records aligned to coding symbols, implicit zero extension and explicit record fragments; `elide_payload_length`, `packed_predictive_records`, `timestamp_pair_dictionary`; exceptional records keep ordinary codec path. | M2 |
| `independent-short-records` | `aligned_records.py:AlignedRecordReceiver.receive`; `AlignedRecordConfig.independent_short_frame_bytes` | Self-contained kind-2 short frames can release before older channel records without advancing the contiguous watermark past gaps. Preserve deduplication tombstones and original context. Selection is by generic size, not SYN-only privilege. | M4 |
| `compact-wire` | `compact_wire.py:encode_source/encode_repair/decode_packet/CompactWireTransport` | Executable typed source/repair/tail headers; simulated `udp` or `raw_ipv4_crc32` envelopes, `trim_repair_padding`, short-source copies and scope. Current wire requires MTU1500, one FIFO, zero jitter, 1460-byte symbols, W128/G16, window8192, zero authentication budget. | M2 + M3 |
| `packed-wire` | `packed_wire.py:PackedWireTransport/PackedAlignedReceiver/packed_units` | Pack actual aligned record units, including context/fragment units; bounded `pack_sources_max_delay_ms`; preserve decoding and per-channel admission constraints. | M4 |
| `unified-duplex-mux` | `mux.py:DuplexMux`; `mux_tcp.py:UnifiedMuxMultiFlow/MuxTCP` | Same ingress classifier/arbiter for bulk and probes in both directions; FIFO per channel and round-robin admission; configurable 1..256 channels for unpacked records, 1..255 for packed records (channel255 is the container marker), current publication cap16. Reject an incompatible count before creating flows. `mapping=crc32` or `connection_round_robin`; learned reverse affinity comes from decoded frames. | M2 |
| `payload-compression` | No general payload compressor in Python | Explicitly new work: disabled/pass-through baseline, bounded optional payload compression, expansion fallback, frame-length limits, no cross-peer unauthenticated dictionary state. Header compression above is the actual Python parity requirement. | M4 |

The current `DuplexMux` validates only complete unfragmented Ethernet/IPv4/TCP frames. It rejects other frames; it is not a complete TAP classifier. The Rust library must add documented fallback routing for ARP, IPv6, UDP, VLAN, fragmented IP, and unknown EtherTypes, and a separate TUN IP-packet contract. TCP tuple affinity uses normalized endpoints; IPv6, fragment affinity, simultaneous opposite-side opens, idle eviction, and collision behavior require explicit tests. Python connection-round-robin raises on conflicting simultaneous assignments; that is a known limitation, not a sufficient production arbitration protocol.

`raw_ipv4_crc32` is a byte-cost/framing simulator envelope. It is not raw TCP, TLS, L2TP, authentication, encryption, or a claim of passage through a middlebox. CRC32 protects accidental corruption, not hostile modification. Do not freeze the compact 15-bit source ID as the authenticated session format: session/epoch identity, replay limits, extended sequence space, direction-specific nonce domains, and stale datagrams must be specified first.

## ACK policies and reference transports

| Catalog ID | Existing Python implementation | Required behavior | Rust milestone |
| --- | --- | --- | --- |
| `inner-ack-controls` | `tcp.py:PlainTCP`; `compact_tcp.py:CompactTCP` | `ack_every`, `ack_delay_ms`; reliable reverse coded stream or native complete 66-byte lossy ACK records. This is inner workload behavior, not permission to disable kernel outer TCP ACKs. | M4 + M5 |
| `ack-coalescing` | `compact_ack.py:CoalescedACKTCP` | Supersede only unsent advancing cumulative ACKs; preserve each distinct duplicate ACK and selected timestamp echo; `ack_coalesce_ms`. Optional acknowledged-segment slow-start is a **workload controller** variant, not tunnel behavior. | M4 |
| `ack-copies` | `compact_ack.py:CoalescedACKTCP.transmit_ack` | 1..4 copies with `ack_copy_spacing_ms`, charged full records and deduplication IDs. Separately retain `short_source_copies` at transport level; do not count either as free recovery. | M4 |
| `aggregate-acks` | `aggregate_ack.py:ACKAggregator/encode_batch/decode_batch/AggregateACKTCP` | Cross-flow hold timer; `record_encoding=full`, `batch_delta`, or `batch_varint`. Datagrams independently contain full first-frame/context state; byte patches and event-ID varints select the smallest valid envelope; exact 66-byte frame reconstruction. | M4 |
| `reverse-fec` | `config.py:Strategy`; `model.py:Simulation.make_transports` | `reverse_fec`, reverse source/repair batching, reverse order policy. Reverse recovery and its feedback consume both directions' budgets. | M3 |
| `direct-tcp-baseline` | `tcp.py:PlainTCP`; `tcp_syn_baseline.py` | Direct CUBIC/Reno with NewReno cumulative recovery, delayed ACK and RTO knobs; compare against actual OS TCP in integration tests. Python lacks Linux SACK/RACK-TLP/PRR/HyStart++ fidelity. | M5, benchmark only |
| `quic-baseline` | `quic.py:QUIC`; `reliable_tunnel.py:RecordQUIC/ReliableTunnelMultiFlow` | Actual pinned aioquic transport with CUBIC/Reno; direct application or complete-L2 stream; separate TCP-over-QUIC shared ordered-stream reference. Preserve auxiliary probe-stream versus same-stream labels. | M5, comparison adapter |
| `kcp-baseline` | `kcp.py:KCPContext`; `reliable_tunnel.py:RecordKCP/ReliableTunnelMultiFlow` | Actual pinned upstream C KCP; ordered messages, `window`, `nodelay`, `interval`, `resend`, `nocwnd`, MTU. Current inner-TCP reference shares a queue with probes. | M5, comparison adapter |

For production TAP and transparent TUN, preserve endpoint TCP ACK/window behavior. Port ACK-generation/coalescing variants into explicitly owned TUN TCP-proxy or benchmark profiles; do not enable them by transparent header rewriting. Any supported optimization must validate frames and options and preserve meaningful duplicate ACKs. Outer carrier ACKs, inner TCP ACKs, and tunnel feedback are three different mechanisms and need separate configuration/counters.

## Research algorithms versus diagnostic-only studies

These have executable Python mathematics or finite coding simulations, often with `protocol_executions=0`. Track their causal algorithm ports in M6 behind explicit experimental capabilities; do not delete them from parity coverage or advertise their analytical rates as Rust throughput.

| Catalog ID | Python source and symbol | Implementable algorithm to track separately |
| --- | --- | --- |
| `research-age-support` | `studies/rtt_age_support.py:support/profiles` | Age-selected repair supports with local/global-window variants. |
| `research-age-coefficients` | `rtt_age_coefficients.py:repair_coefficient` | Age-band/lane coefficient taps and periodic dense refresh. |
| `research-mixed-degree` | `rtt_mixed_degree.py:sparse_support` | Sparse-degree repairs interleaved with dense repairs. |
| `research-recursive-parity` | `rtt_recursive_parity.py:source_taps/check_equation/expanded_coefficient` | Source-regular recursive parity, tap count/width and periodic reset. |
| `research-recursive-fallback` | `rtt_recursive_fallback.py:repair_mode/repair_coefficient` | Periodic charged fresh-prefix repair in recursive parity. |
| `research-rolling-accumulator` | `rtt_rolling_accumulator.py:repair_coefficient/repair_support` | Repeated-coefficient rolling supports. |
| `research-spatial-coupling` | `rtt_spatial_coupling.py:section_constraints/repair_slot` | Finite GF(256) spatially coupled parity pipeline. |
| `research-checkpoint-repair` | `rtt_checkpoint_repairs.py:support` | Delayed-prefix-feedback checkpoint repair. |
| `research-feedback-gate` | `rtt_feedback_gate.py:SenderGate/Snapshot` | Repair eligibility from causal feedback age, with charged slots. |
| `research-selective-fallback` | `rtt_selective_fallback.py:SelectiveSender/repair_equation` | Causal selective-feedback fallback on the fixed repair schedule. |
| `research-bitmap-fallback` | `rtt_bitmap_coded_fallback.py:BitmapSender/repair_equation` | Old-debt coded equations reconstructed from received receipt bitmaps. |
| `research-subpacket-convolutional` | `subpacket_convolutional.py:coefficient_bytes/parity_equation` | Systematic finite-memory subpacket convolutional code; time-varying and invariant coefficients. |
| `research-lrsc-staircase` | `lrsc_staircase.py:coefficients/parity_equation` | Finite GF(256) Cauchy staircase heuristic; not an established universal LRSC guarantee. |
| `research-partial-repair` | `partial_repair_screen.py:CoupledDecoder/HalfDecoder/repair_header` | Full-vector controls, coupled-half parity, and partial-half packetization. |
| `research-source-bridge` | `source_bridge_diagnostic.py:source_equation/source_header` | Causal D128 source-side precoding, separately tested from ordinary systematic sources. |

Keep these additional **diagnostic-only**, without wire-mode feature flags: `rtt_busy_period.py` (dense information-deficit and noncausal FIFO models), `rtt_deadline_converse.py` (necessary bounds for fixed slots/arrivals), `oracle_repair_diagnostic.py` (instantaneous-loss oracle), `latency_counterfactual.py` (optimistic fixed-trajectory clocks), `predictive_wire_budget.py` (fixed-cohort byte arithmetic), `repair_extent_audit.py` (saved-trace padding projection), and `rtt_budget_analysis*.py`/report scripts (derived analysis). Their causal controls and tested codec primitives belong to the corresponding real modes above. An oracle is never an implementation milestone.

## Source-verified evidence that informs the implementation

The authoritative candidate selection for this plan is the latest saved [small-packet and shared-baseline analysis](../work/results-20261110/tcp-latency/tcp-syn-small-packet-analysis/current-series-index.html), generated on 2026-11-11 at 15:25 UTC. Its [selection manifest](../work/results-20261110/tcp-latency/tcp-syn-small-packet-analysis/selection-manifest.json), [validation receipt](../work/results-20261110/tcp-latency/tcp-syn-small-packet-analysis/current-series-validation.json), [raw coverage](../work/results-20261110/tcp-latency/tcp-syn-small-packet-analysis/current-series-coverage.csv), [outside-plot coverage](../work/results-20261110/tcp-latency/tcp-syn-small-packet-analysis/outside-plot-coverage.csv), and [means](../work/results-20261110/tcp-latency/tcp-syn-small-packet-analysis/current-series-means.csv) retain both new candidates and earlier mechanisms. The earlier unified-MUX16 report is historical mechanism evidence; its 64-byte, 4 Mbps offered-load run is not the latest small-packet candidate.

This audit checked **309/309 saved observation SHA256s** (238 plotted plus 71 outside the plot), **490/490 frozen source-file instances across 14 study manifests**, and the latest selection-manifest hash; all matched. The 238 plotted observations comprise 159 primary and 79 supplementary rows, including 118 unified-MUX and 120 shared-transport baseline observations. All primary configuration groups have three seeds; supplementary groups may be incomplete or ineligible. Repeated campaigns retain separate identities and are not pooled as additional independent seeds. Hash verification establishes stored provenance; no simulation was rerun.

Shared link conditions are 100/10 Mbps forward/reverse IP service, 70 ms base RTT, 15% IID packet loss and MTU1500. Goodput and byte cost use the same recorded post-stability interval. Goodput pools payload bytes / interval durations across seeds; SYN P99 is the mean of each replication's P99. The SYN metric measures original inner SYN submission until matching inner SYN-ACK reception, including retry waits; it is not outer TLS handshake latency. Extra forward byte cost is `100 * (forward serialized IP service bytes / delivered application payload bytes - 1)` and includes fractional packet service at interval boundaries.

### Latest packed small-packet candidates

These are the qualified three-seed `A2 C5` candidates, all with completed/confirmed traffic and flushed probes in the stored observations. Their three displayed metrics were independently recomputed from the verified coverage rows and match the means CSV.

| Application payload bytes | Configured application cap Mbps | Measured application Mbps | Extra forward IP bytes / application bytes | Inner SYN P99 ms | Receipt ID |
| ---: | ---: | ---: | ---: | ---: | --- |
| 64 | 64 | 64.003 | 35.216% | 74.338 | `mean-ac4a93e32adc` |
| 256 | 72 | 71.998 | 26.560% | 74.623 | `mean-5edf141c3b3f` |
| 512 | 76 | 75.996 | 25.777% | 73.865 | `mean-a38ce655f0fb` |

The 64-byte rows come from `tcp-syn-small-packet-64-qualified` runs 2/4/6; the 256-byte rows from `tcp-syn-small-packet-qualified` runs 3/7/11; the 512-byte rows from runs 4/8/12. Each uses 90 seconds of traffic, a 5-second warmup parameter, 30 seconds of drain, 16 inner CUBIC flows and 16 shared MUX channels, connection-round-robin affinity, a fixed aggregate 4 MiB window, and a 1-second minimum inner TCP RTO.

Required candidate settings are `pack_sources_max_delay_ms=0.5`, `ack_every=2`, **`ack_coalesce_ms=5`**, and `ack_delay_ms=10`. The 5 ms setting is tunnel-side coalescing of already-generated advancing ACKs; it does not mean the inner TCP delayed-ACK timer is 5 ms. Coding uses `repair_ratio=0.205`, W128/G16, an 8192-source bound, and `feedback_ms=1`; records use delta/predictive header coding, payload-length elision, repair-padding trimming, independent full-frame records up to 128 bytes, and three copies only for contexts/independent short records (`short_source_copy_scope=context_and_independent`). The envelope remains simulated raw IPv4 with CRC32 and zero authentication overhead. `wire_format=compact_wire` dispatches through `mux_tcp.py:UnifiedMuxMultiFlow` to `PackedWireTransport` in both directions when the packing-delay option is positive.

The same latest report also preserves matched qualified ACK-policy controls: 64-byte `A64 C2` measures 63.980 Mbps / 35.256% / 74.552 ms; 256-byte `A16 C2` measures 71.986 Mbps / 26.589% / 77.029 ms; 512-byte `A8 C2` measures 76.001 Mbps / 25.780% / 74.063 ms. These modes remain in the inventory. Here `A` identifies the inner ACK segment threshold and `C` the coalescing interval in milliseconds. The `A2 C5` results support prioritizing source packing plus ordinary two-segment ACK generation and bounded coalescing for the first real implementation.

These are achieved **offered-load observations**, not measured capacity maxima. The 64-byte result is approximately 64 Mbps, not the historical 4 Mbps observation; the offered load and profile changed, so their ratio must not be described as an isolated 16-fold speedup from packing. The small-packet candidates record zero passes of the historical joint target because that target includes approximately 80 Mbps throughput; low latency and complete confirmation do not waive that throughput threshold. These byte-cost percentages also do not establish a 20% packet-overhead target.

### Historical mechanism evidence retained in the latest selection

The earlier [unified MUX16 campaign](../work/results-20261110/tcp-latency/tcp-syn-unified-mux16-analysis/current-series-index.html) established why the mode inventory includes both ordered and independent-short-record delivery. The latest analysis retains these 1448-byte-payload rows:

| Stored configuration | Seeds | Application Mbps | Extra forward IP bytes / application bytes | Inner SYN P99 ms | Receipt ID |
| --- | ---: | ---: | ---: | ---: | --- |
| Ordered round-robin MUX16, r20.5%, short copies4 | 3 | 80.296 | 23.656% | 194.680 | `mean-25eacd8fcbc9` |
| Independent short records128, MUX16 RR, r20.5%, copies4 | 3 | 80.284 | 23.502% | 78.352 | `mean-d9aeddc8e936` |
| Independent short records128, MUX16 RR, r20.5%, copies3 | 3 | 80.284 | 23.517% | 77.177 | `mean-a49742ed73b5` |
| CRC32 hash MUX16 screen, r21%, copies4 | 3 | 32.099 | 59.708% | 1129.866 | `mean-9d0cb8b35d2f` |

The first three use 90-second traffic, 5-second warmup parameter, 30-second drain and an 80.3 Mbps configured application cap; the hash screen uses 30/5/20 seconds and an 80.05 Mbps cap. They are not a controlled causal estimate of mapping alone; the independent rows also change delayed-ACK settings. The two independent r20.5 rows each have three recorded joint passes; the ordered and hash rows have zero. The older small-payload observations used explicit loads approximately 4/16/32/64/76 Mbps for 64/256/512/1024/1228 bytes; retain them as historical points, not current recommended loads or saturation measurements.

The implementation priority is therefore bounded shared MUX, independently decodable short frames, **0.5 ms source packing and configurable ACK coalescing**, while measuring queueing, reverse capacity and context head-of-line delay. Do not select one redundancy percentage as a universal optimum. Negative, incomplete, unsteady, and baseline observations remain part of the acceptance corpus; the latest 71 outside-plot cases must not be silently discarded.

All these results exclude codec/crypto CPU service and real kernel/TAP scheduling. Compact-wire profiles require zero authentication bytes; raw-IP/CRC byte savings must be recalculated for authenticated TCP/UDP records. Bulk FEC uses coefficient/rank simulation and ledger-recovered source bytes. Link queues, loss process, synthetic inner TCP, known-capacity pacing, stable-window admission and finite drain are material assumptions. None verifies raw TCP sequence continuity, TLS-based traffic classification, active-probe behavior, real congestion fairness, platform support or safe configuration switching. The shared TCP/QUIC/KCP observations preserve their actual record path, controller, queue-gate version, runtime and eligibility; they cannot substitute for kernel or real-device benchmarks.

## Completion criteria for parity

1. Freeze golden Python vectors for each byte codec, modular sequence rule, feedback envelope and causal scheduling decision; identify whether the reference is a full protocol run, byte codec, coding-only test, or analytical diagnostic.
2. Differential-test Rust using real arbitrary frame bytes, deterministic loss/reorder/duplicate traces, wraparound, backpressure, context loss, unsupported headers and parser truncation. Full-vector FEC must recover from received bytes without sender-ledger access.
3. Run every supported profile in both directions, with independent bidirectional payload as well as ACK-dominated reverse traffic. Test the default half-duplex policy separately from full duplex; Python's direction flags do not implement a half-duplex carrier scheduler.
4. For hot switching, test prepare/commit/barrier/epoch behavior through lost control messages, delayed old frames, changed channel mapping and compression state. Merely changing both endpoint configuration files is not a sufficient safety proof.
5. Preserve separate counts for inner frames/payload, source packets, FEC, retransmissions, control traffic, forward/reverse IP bytes, incomplete delivery and confirmation. Report ordinary TCP/QUIC/KCP reference results independently from tunnel algorithms.
6. Complete Linux bridge plus `tc qdisc netem` tests, platform device tests, malformed-input/fuzz gates, resource limits, and measured CPU/latency/throughput before changing any planned mode to implemented or production-ready.

## Additional real-implementation requirements

The 47 entries above inventory Python/reference requirements. TUN active credit,
actual TCP proxy windows, QoS, internal L2 management, VXLAN and OpenVPN-like/QUIC-like
UDP covers are additional requirements, tracked in the
[implementation checklist](implementation-checklist.md) and its detailed task lists.
They are not retroactive Python results and do not change these 47 inventory IDs.

The [common inner security and recovery target](modules/secure-session.md)
adds fixed-peer authentication, AEAD data for all carriers including HTTPS,
replay/rekey isolation, authenticated control and bounded automatic recovery.
Its WireGuard-like model has no selected implementation library yet.
Independent authenticated-cleartext requirements of existing generic UDP/raw
profiles remain tracked; keeping Swift encrypted does not remove them. Carrier
appearance work, including the minimal QUIC and RTP/media appearance targets,
does not establish protocol interoperability or measured ISP QoS treatment.
The real TCP/TLS bootstrap followed by raw TCP-shaped data in the original
sequence space remains an independent HTTPS-path requirement, with privilege,
kernel ACK/RST, firewall, platform and recovery gates. Neither a real HTTP
stream nor a new inner security library silently substitutes for that path.
All these additions require their own implementation and runtime evidence;
none closes or removes an existing P-* task.
