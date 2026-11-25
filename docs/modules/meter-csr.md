# Meter CSR and management query

Status: in progress. MCSR-01, MCSR-11 and MCSR-13 pass. The always-on collector,
Common CSR publisher, local API (`meters_read`/`meters_catalog` and CSR-derived
`metrics`), CLI (`l2tunnelctl meters`), Common in-band remote reads over `Liveness`
(`ProfileTag::MetersV1`, MCSR-09 partial), and the GUI Statistics CSR meters panel
(MCSR-12 partial) are implemented and contract-tested. Full meter-family coverage
(MCSR-04..07), a dedicated negotiated `Meters = 5` stream/capability bit (MCSR-08/09),
TCP-proxy remote reads (MCSR-10), histogram percentiles in the GUI (MCSR-12), and
real-pair overhead receipts (MCSR-14) remain open. This document does not change
the [buffer coverage inventory](buffer-observability.md) or its measurement
contract; it adds a live, queryable home for those meters and for further
meter families.

## Owner decisions (2026-11-24)

The owner settled these, one question each:

1. Meters are exposed both locally and to the remote peer, as a meter CSR
   (control/status register block) with one management API to query it.
2. Registers are addressed by named paths, for example
   `runtime.native_ingress.lane0.user.occupancy_bytes`, each holding a u64
   value.
3. Metering is always on. The CSR is read-only status; reading it never
   changes protocol behavior.
4. An authenticated peer may read every path of this side's CSR. Inner flows
   appear only as numeric flow IDs; flow labels (5-tuples, SOCKS5 targets)
   never cross the wire. The local API still shows labels.
5. Remote reads are request/reply over the in-band authenticated management
   channel: no traffic unless someone queries.
6. The CSR carries four families: buffers/backpressure (every BP-01..BP-24
   owner, including all gaps), recovery/protocol, carrier/transport and
   MUX/flow traffic.
7. Each wait/latency meter keeps the existing scalars plus a fixed log2
   histogram.
8. The CSR is the single source of truth. The existing local `metrics`
   action becomes a typed view computed from CSR paths.
9. This session implements every task, MCSR-01..14, including the runtime and
   protocol parts.
10. The runtime publishes a bounded meter table at the existing report
    interval through the same sink that carries `CommonSnapshot`. A read
    returns the latest table and its age.
11. Remote reads use a new negotiated control stream, `Meters = 5`, under
    whole-message custody. *(Implementation note: Common sessions currently
    carry remote reads over the existing authenticated `Liveness` stream using
    `ProfileTag::MetersV1` in `Control` scope with stream-bounded paging; a
    dedicated `Meters = 5` stream and capability bit remain tracked under
    MCSR-08/09.)*
12. Every live inner flow up to the runtime's flow-table bound gets CSR
    instances.
13. Paths are named after the owning Rust component, not ledger row codes.
    The BP row and meter family are catalog attributes.
14. `L2TUNNEL_BUFFER_METRICS` / `L2TUNNEL_WIRE_METRICS` stay as an
    end-of-session `.bmetrics` dump of the same CSR table.
15. Remote-read limits: 250 ms minimum interval per session, one read in
    flight, 16 KiB reply per page, 256 entries per page, 2 s deadline,
    96-byte prefix.
16. Always-on collector state uses sparse key slots: each owner reserves a
    fixed number of site/lane/class slots at construction, each with every
    wait cause and its histogram. A key beyond the slots counts as
    `slots_exhausted` and marks the owner invalid; it is never dropped
    silently.
17. Amends decision 10: the CSR has its own cadence. Snapshots keep their
    report interval (1 ms in some proxy profiles, where the measured
    controller uses them as control input). The table is rebuilt at most
    every 100 ms, never faster than the report interval, and the newest
    table rides along with each snapshot. Reads report the table's own
    sample time and age. Rebuilding on every 1 ms snapshot failed 2–3
    measured-proxy tests that pass without the rebuild.

## Starting point (observed 2026-11-24)

- The runtime collector (`crates/l2tunnel-runtime/src/buffer_metrics.rs`,
  `buffer_metrics/observer.rs`) is opt-in through `L2TUNNEL_BUFFER_METRICS` /
  `L2TUNNEL_WIRE_METRICS` and writes terminal `.bmetrics` files only. Nothing
  reads it while a session runs.
- 15 of the 30 `Site` variants have no production call site. BP-03, BP-11,
  BP-12 and BP-19 have no runtime collector; most other rows are partial (see
  the inventory).
- The collector's `Lane` is `Shared | First | Second`, not a lane index, so it
  cannot name more than two lanes.
- The live local `metrics` action (`crates/l2tunnel-client-core/src/local/metrics.rs`,
  `service/metrics_local.rs`) projects wire/device/rate/lane counters from the
  Common status. Its channel and flow tables are empty because the runtime does
  not report them, and only `CreditStatus` carries buffer-like live state.
- The management frame defines `STATUS = 8`, but no runtime sends it. Generic
  cross-profile control dispatch is still open
  ([SCM-07](control-messages.md), [SCS-07](control-streams.md)); only streamed
  Swift has runtime custody.

## Register model

### Paths

A path is a dot-joined sequence of segments matching `[a-z0-9_]+`. Bounds:
at most 10 segments and 128 bytes (a 20-digit flow ID with the longest wait
reason needs 103 bytes); a query prefix is at most 96 bytes. Its shape is
`crate.component[.instance...].meter[.qualifier...]`:

- `crate` is the owning crate's short name: the `l2tunnel-` prefix is
  dropped and `-` becomes `_` (`codec`, `tcp_proxy`, `flow_control`,
  `client_core`). The facade crate stays `l2tunnel`. `meta` holds CSR
  identity.
- `component` is the owning module or owner inside that crate.
- `instance` segments keep the three independent counts separate: `laneN`
  (authenticated carrier lane, or `shared` for a lane-shared owner such as
  the Common driver's aggregate counters), `chN` (MUX channel) and `flowN` (inner flow,
  numeric only). Direction is `tx`/`rx`; traffic class is `user`, `feedback`,
  `management` or `shared`.
- Prefix queries match whole segments only: `runtime.native_ingress` matches
  `runtime.native_ingress.lane0...` and does not match
  `runtime.native_ingress_x`.

Component roots and their inventory rows:

| Root | Row | Root | Row |
|---|---|---|---|
| `mux.channel`, `qos.scheduler`, `packet.flow_table`, `pipeline.queue` | BP-01 | `pipeline.ack_coalescing` | BP-02 |
| `l2tunnel.record_bank`, `runtime.native_window` | BP-03 | `codec.aligned_sender`, `codec.packed_sender` | BP-04 |
| `codec.aligned_receiver` | BP-05 | `reliable.outgoing`, `reliable.restored`, `reliable.decoder` | BP-06 |
| `recovery.arq`, `reliable.compact_arq` | BP-07 | `swift.sender`, `swift.receiver`, `swift.byte_queue` | BP-08 |
| `fec.decoder` | BP-09 | `fec.rolling`, `l2tunnel.rolling_records` | BP-10 |
| `fec.legacy_sliding`, `fec.research` | BP-11 | `runtime.common_fragments` | BP-12 |
| `l2tunnel.connection_records` | BP-13 | `runtime.native_ingress`, `runtime.user_slot` | BP-14 |
| `runtime.native_output` | BP-15 | `management.control_streams.<stream>` | BP-16 |
| `runtime.proxy`, `tcp_proxy.session` | BP-17 | `raw_tcp.engine`, `runtime.raw_carrier` | BP-18 |
| `openvpn.wire_carrier` | BP-19 | `runtime.retained_tls` | BP-20 |
| `quic.connection` | BP-21 | `runtime.maintained` | BP-22 |
| `client_core.local` | BP-23 | `<component>.static` | BP-24 |
| `flow_control.session_credit.tx`, `.rx` | credit | | |

Each runtime collector site has its own root under its component, per lane
and class: for example `runtime.retained_tls.write`, `runtime.raw_carrier.send`,
`runtime.native_output.device_write` and `flow_control.session_credit.window`.
The site-to-root map is `crates/l2tunnel-runtime/src/buffer_metrics/csr.rs`;
a test checks that every site path resolves in the catalog.
`meta.owner.<owner>` holds each collector's sample time, slot use,
`slots_exhausted`, invalid flag and blocked-time union.

Examples:

```
meta.version                                                 = 1
meta.sampled_us                                              = 5120034
runtime.native_ingress.lane0.user.occupancy_bytes            = 4096
runtime.native_ingress.lane0.user.high_water_bytes           = 65536
runtime.native_ingress.lane0.user.capacity_bytes             = 131072
runtime.native_ingress.lane0.user.refusals                   = 12
runtime.native_ingress.lane0.user.wait.buffer_capacity.completed_us = 8410
runtime.native_ingress.lane0.user.wait.buffer_capacity.hist.b03     = 5
mux.channel.ch3.wait.queue_full.max_us                       = 840
recovery.arq.ch0.tx.retransmits                              = 31
quic.connection.lane1.rtt_us                                 = 18250
mux.flow42.rx.bytes                                          = 1048576
```

### Values and kinds

Every register is a u64. A static catalog gives each path pattern a kind and
unit: `gauge`, `capacity`, `high_water`, `counter` or `duration_us`, plus
histogram buckets. Counters and durations only grow within one session
generation. A generation change restarts every series, so rates are the
difference between two reads with the same session generation, which every
reply carries.

An absent path means this profile does not report that meter. A catalog
entry can also mark a meter as `unavailable` with a reason (for example
provider-private Quinn queue occupancy), and such a meter is never reported
as zero. This replaces today's `unreported` list.

### Waits

Each independently identified wait cause (`wait.<reason>`) keeps the current
contract's scalars, `completed_us`, `open_us`, `censored_us`, `episodes` and
`max_us`, plus `hist.b00..b23`. Bucket `bI` counts completed episodes in
`[2^I, 2^(I+1))` µs; `b00` also counts durations under 1 µs, and `b23` counts
everything from 2^23 µs (about 8.4 s) up. Open and censored episodes stay out
of the histogram, which is why they keep their own scalars. Clients derive
p50/p99 from the buckets. Durations from overlapping causes or different
owners are never summed.

### Snapshots

One read returns, for each owner, values sampled at a single runtime instant.
It also returns the session generation, the service sampling time, the table
age, and each owner's runtime sample time (`meta.owner.<owner>.sampled_us`). Values from different owners can come from different
instants, and the reply says so; it is not a global atomic snapshot.

## Local management API

Two read-only actions are added beside `metrics`, following the versioning
rule in [local operations](local-operations.md):

| Action | Fields | Reply |
|---|---|---|
| `meters_read` | `side` (`local`/`remote`), `prefix`, optional `cursor`, `limit` (1..=256) | `meters{side, generation, sampled_ms, age_ms, entries[{path, value}], next?}`; codes `not_running`, `invalid_limit`, `invalid_prefix`, `invalid_cursor`, `busy`, `peer_timeout`, `peer_malformed`, `remote_unavailable` |
| `meters_catalog` | `prefix`, optional `cursor`, `limit` (1..=256) | `meter_catalog{version, entries[{pattern, kind, unit, state, reason?}], next?}` |

Replies stay within the existing local reply limit, so a large prefix pages
through `cursor`. `metrics` keeps its schema but is computed from CSR paths;
its `unreported` list then names the missing paths.

## In-band remote read

- Request: prefix, cursor, entry limit and reply byte cap. Reply: generation,
  owner sample times, entries and an optional next cursor. Shared path
  prefixes are delta-encoded so that named paths fit the reply cap.
- Carried as one authenticated management request/reply under the
  [whole-message control custody](control-messages.md) (bounded fragmentation,
  reliable delivery, original deadline), with the same MUX admission and
  channel budget as other traffic.
- At most one remote read is in flight per session, with a minimum interval
  between reads. Excess local requests get `busy`, never a queue.
- The answering side builds the reply from its own CSR, with flow IDs only and
  no labels. Non-Common backends report `remote_unavailable`, while an
  unresponsive or incompatible peer reports `peer_timeout` or `peer_malformed`
  (never empty or zero values; `peer_unsupported` is reserved for future
  negotiated capability signaling).
- Typed refusals and decode failures never panic and never change session
  state.

## Clients

- CLI: `l2tunnelctl meters read [--remote] PREFIX`, `meters catalog [PREFIX]`,
  and `meters watch [--remote] PREFIX` showing rates and histogram percentiles.
  `stats show|watch` is unchanged and reads the derived `metrics` view.
- GUI: the Statistics page ([DGUI-09](desktop-gui.md)) gains Buffers,
  Recovery, Carrier and Flows views with separate lane, channel and flow
  tables, local and remote columns, percentiles and bounded client history.
- `tools/fake_local_service.py` serves a simulated CSR, labelled FAKE, for
  GUI/CLI development.

## Ownership

This session implements all tasks (decision 9). Another session is editing
runtime, recovery, FEC, reliable and management files at the same time, so
changes there are minimal, made with the Edit tool, and formatted per file.

## Tasks

- [x] [MCSR-01] Pure `l2tunnel-meters` crate (tier 1, no Tokio, clocks or I/O): path grammar and validation, static catalog with kinds/units/unavailable reasons, bounded fallible table, wait interval scalars with log2 histogram, segment-boundary prefix match, cursor paging; focused tests for limits, clock regression, overflow and invalid paths. Evidence: [crate source and 20 focused tests](../../crates/l2tunnel-meters/src/lib.rs) (`cargo test -p l2tunnel-meters --locked`, 2026-11-24, local Linux).
- [ ] [MCSR-02] Always-on runtime collection: every owner reserves bounded meter state at construction and accounts for it in its resource plan, and disabled-allocation paths are removed; a snapshot fills an `l2tunnel-meters` table without I/O; `.bmetrics` export reads the same table. Measure the per-event cost against the current opt-in build. Progress: observers are always constructed, the collector uses sparse key slots with histograms ([collector](../../crates/l2tunnel-runtime/src/buffer_metrics.rs), [observer](../../crates/l2tunnel-runtime/src/buffer_metrics/observer.rs)), and the Common runtime publishes its CSR with each snapshot at the decision-17 cadence ([publisher](../../crates/l2tunnel-runtime/src/secure_udp/transport_meters.rs)). Open: the retained-TLS, maintained-QUIC and proxy-bridge observers are not yet in the published table; resource-plan accounting; `.bmetrics` still uses its own JSON writer over the same collector; per-event cost not measured (the only comparison so far is the measured-proxy A/B behind decision 17).
- [ ] [MCSR-03] Instance identity: replace the collector's `Shared/First/Second` lane with bounded lane indices; carry MUX channel and flow (with incarnation) identities through every collector so the three counts stay separate in paths. Progress: `Lane::Index(u16)` replaces the two-lane fold, and the retained-TLS and maintained-QUIC hooks no longer merge lanes 2+ into lane 1. Open: channel and flow identities.
- [ ] [MCSR-04] Buffer family: CSR paths for every BP-01..BP-24 owner, wiring all `Site` variants without call sites and the missing BP-03, BP-11, BP-12 and BP-19 collectors and every partial-row gap in the [inventory](buffer-observability.md), at the inventory's full scope.
- [x] [MCSR-05] Recovery/protocol family: per-channel ARQ retransmits, RTO firings, ACK/feedback counts, FEC/RLNC repairs sent and used, decode failures, replay rejects and records lost past their deadline, for every profile that has them. Evidence: [engine recovery snapshot](../../crates/l2tunnel/src/record_engine/buffer_diagnostics.rs) (`Engine::recovery_metrics` across Swift, Aligned, Packed, Rolling, and Research), [CSR publisher](../../crates/l2tunnel-runtime/src/secure_udp/transport_meters.rs) (`swift.sender.ch*`, `swift.receiver.ch*`, `recovery.arq.ch*`, `reliable.compact_arq.ch0`, `reliable.decoder.ch0`, `fec.decoder.ch0`, `fec.rolling.ch0`, `fec.research.ch0`), and [end-to-end catalog-validated test](../../crates/l2tunnel-client-core/src/service/tests/secure_udp_transaction.rs) (`csr_meters_populate_recovery_carrier_mux_channels_flows_and_rtt`).
- [ ] [MCSR-06] Carrier/transport family: per-lane RTT, QUIC congestion/loss, UDP socket drops and receive-buffer readback, TLS pending and receiver credit (moving `CreditStatus` content into paths). Progress: receiver credit (`flow_control.session_credit.tx/rx`), session RTT (`runtime.session.rtt_us` from credit `min_rtt`, Swift smoothed RTT, and authenticated liveness ping/pong RTT), UDP socket drops and receive-buffer requested/granted (`udp.socket.shared.*`), session rates/channels, aggregate wire counters (`runtime.wire.shared`), native output `would_block`, record bank slots, and device counters are published and verified (`csr_meters_populate_recovery_carrier_mux_channels_flows_and_rtt`). Open: per-lane Quinn QUIC congestion/loss and retained-TLS `pending_writes` CSR publication.
- [x] [MCSR-07] MUX/flow family: per-channel and per-flow packets/bytes per direction, admitted/refused and queue depth, filling the channel and flow tables of `metrics`. Evidence: [per-channel queue depth](../../crates/l2tunnel-mux/src/lib.rs) (`Mux::channel_queued_bytes`), [pipeline/engine accessors](../../crates/l2tunnel/src/record_engine/buffer_diagnostics.rs) (`Engine::channel_queued_bytes`, `Engine::lookup_flow_id`, `ProfileIdentity::channel_index`), [fixed-capacity allocation-free counter bank](../../crates/l2tunnel-runtime/src/secure_udp/transport_common.rs) (`MuxCounters`), [runtime hooks](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_io.rs), [CSR publisher](../../crates/l2tunnel-runtime/src/secure_udp/transport_meters.rs) (`mux.channel.ch*.{tx,rx}.*`, `mux.flow*.{tx,rx,state}`), and [end-to-end test](../../crates/l2tunnel-client-core/src/service/tests/secure_udp_transaction.rs) (`csr_meters_populate_recovery_carrier_mux_channels_flows_and_rtt` confirming `metrics.channels`, `metrics.flows`, and `metrics.rtt_micros` populate and clear `channel_counters`/`flow_counters`/`rtt` from `metrics.unreported`).
- [ ] [MCSR-08] In-band meter request/reply wire contract: codec with delta-encoded paths, bounds, capability negotiation, typed refusals, rate limit, flow-label exclusion; byte-exact tests and failure-path tests. Progress: the body codec, limits, refusals and rate gate pass byte-exact and failure tests ([wire](../../crates/l2tunnel-meters/src/wire.rs)). Open: capability negotiation through the stream configuration.
- [ ] [MCSR-09] Runtime in-band dispatch of meter reads under whole-message control custody with MUX admission, deadline and single-in-flight bound. Depends on generic control dispatch (SCM-07/SCS-07). Progress: implemented on Common sessions over the authenticated `Liveness` control stream (`ProfileTag::MetersV1`, `Control` scope, stream-bounded paging via `answer_bounded`, single-in-flight, 250 ms rate gate, 2 s deadline; [port](../../crates/l2tunnel-runtime/src/secure_udp/transport_remote_meters.rs), integration test `remote_meters_cross_the_real_session_with_paging_and_rate_gate`). Open: dedicated `Meters = 5` stream and negotiated capability bit if later split from `Liveness`.
- [ ] [MCSR-10] Local API `meters_read`/`meters_catalog` with paging and remote forwarding; `metrics` computed from the CSR; service tests for every refusal code. Progress: both actions, local paging, Common remote forwarding (`side: remote`), the `meters` capability, CSR-derived `metrics`, and service refusal tests (`invalid_limit`, `invalid_prefix`, `invalid_cursor`, `not_running`, `busy`, catalog paging) pass focused and two-peer loopback tests ([service](../../crates/l2tunnel-client-core/src/service/meters_local.rs), [metrics view](../../crates/l2tunnel-client-core/src/service/metrics_local.rs), [integration test](../../crates/l2tunnel-client-core/src/service/tests/secure_udp_transaction.rs)). Open: TCP-proxy remote forwarding.
- [x] [MCSR-11] CLI `meters read|catalog|watch` with rates and percentiles; tests against the fake service. Evidence: [CLI](../../crates/l2tunnel-client-core/src/cli_groups_meters.rs) with parse and watch-line tests, [fake-service CLI test](../../tools/test_fake_local_service.py) (`test_simulated_meter_reads_page_local_remote_and_catalog`, 2026-11-24, local Linux).
- [ ] [MCSR-12] GUI Statistics views (advances DGUI-09): local/remote, lane/channel/flow tables, percentiles, bounded history. Progress: Statistics page includes bounded charts, carrier/MUX/flow/device sections, and live CSR meters with Local/Remote toggle, prefix filter, auto-refresh, rate deltas, and log2 wait-histogram p50/p99 percentiles ([pages](../../crates/l2tunnel-desktop-ui/src/pages.rs)). Open: per-channel/flow tables once MCSR-07 populates them.
- [x] [MCSR-13] Fake service CSR, labelled FAKE, with CLI tests. Evidence: [SIMULATED CSR in the fake service](../../tools/fake_local_service.py) (`meters_table`, version `fake`), [CLI test](../../tools/test_fake_local_service.py).
- [ ] [MCSR-14] Integration: local and remote reads on the real loopback pair (`tools/local_real_pair.py`); always-on overhead comparison recorded as a receipt. Privileged labs only when the owner asks.

## Acceptance matrix

| Case | Expected |
|---|---|
| Read with no session running | `not_running`; no partial table |
| Profile lacks a meter | Path absent; catalog shows it, or `unavailable` with reason; never zero |
| Generation changes between two reads | Client restarts every rate series |
| Remote peer unavailable or without meter support | `remote_unavailable` / `peer_timeout` (or `peer_unsupported` once negotiated) |
| Second remote read while one is in flight | `busy`; first read unaffected |
| Remote read under saturated user traffic | Served within MUX admission and channel budget; user traffic keeps its admission policy |
| Remote reply over the byte cap | Paged with `next`; never truncated silently |
| Malformed or oversized remote request | Typed refusal; no panic, no session state change |
| Flow meters read remotely | Numeric flow IDs only; no labels or addresses on the wire |
| Wait open at session end | Counted in `censored_us`, never in the histogram |
| Overlapping wait causes | Reported per cause; never summed |
