//! Live meter CSR publication with each Common snapshot
//! (`docs/modules/meter-csr.md`, decisions 3 and 10).
//!
//! The table is assembled at the existing report interval from the snapshot
//! just built and the owner's always-on collector, then published as a
//! compact shared copy. Nothing here changes protocol state. A failure
//! leaves the snapshot without meters; it never fails the snapshot.

use std::sync::Arc;

use l2tunnel::record_engine::RecoveryMetrics;
use l2tunnel_meters::{Limits, Table, TableError, catalog};

use super::common::{ChannelMeterSnapshot, FlowMeterSnapshot};
use super::{CommonSnapshot, CreditSnapshot};

/// Shortest interval between CSR rebuilds (meter-csr decision 17).
pub(super) const REBUILD_INTERVAL_US: u64 = 100_000;
/// Registers outside the collector and per-channel/per-flow tables, with room to spare.
const FIXED_ENTRIES: usize = 192;
/// Registers per MUX channel (`tx` + `rx` directional registers).
const PER_CHANNEL_MUX: usize = 8;
/// Registers per inner flow (`tx` + `rx` + `state`).
const PER_FLOW_MUX: usize = 6;
/// Registers per Swift recovery channel (`swift.sender`, `swift.receiver`, `recovery.arq`).
const PER_RECOVERY_CHANNEL: usize = 24;
/// Registers per collector key outside its wait blocks: samples, three
/// gauges per unit and three refusal totals.
const PER_KEY: usize = 16;
/// Registers per observed wait cause: eight scalars and the histogram.
const PER_REASON: usize = 8 + l2tunnel_meters::wait::BUCKETS;
/// Average path bytes reserved per register; a miss retries with twice.
const AVERAGE_PATH: usize = 80;

fn put(table: &mut Table, path: &str, value: u64) -> Result<(), TableError> {
    table.put_str(path, value)
}

fn credit(table: &mut Table, value: &CreditSnapshot) -> Result<(), TableError> {
    let r = value.receiver;
    let rx = "flow_control.session_credit.rx";
    for (name, field) in [
        ("processed", r.processed),
        ("limit", r.limit),
        ("bytes_above", r.bytes_above),
        ("drain_rate", r.drain_bytes),
        ("drain_datagram_rate", r.drain_datagrams),
        ("allowance_bytes", r.allowance_bytes),
        ("issued", r.issued),
        ("frozen", u64::from(r.frozen)),
        ("rejected", value.rejected),
        ("sender_restarts", value.sender_restarts),
        ("unrecorded", value.unrecorded),
        ("allowance_readback", u64::from(value.allowance_readback)),
    ] {
        table.put(format_args!("{rx}.{name}"), field)?;
    }
    if let Some(requested) = value.requested_receive_buffer {
        table.put(format_args!("{rx}.rcvbuf_requested"), requested)?;
    }
    if let Some(readback) = value.receive_buffer_readback {
        table.put(format_args!("{rx}.rcvbuf_readback"), readback)?;
    }
    if let Some(s) = value.sender {
        let tx = "flow_control.session_credit.tx";
        for (name, field) in [
            ("limit", s.limit),
            ("window_datagrams", s.window),
            ("bytes_above", s.bytes_above),
            ("peer_processed", s.peer_processed),
            ("in_flight_bytes", s.inflight_bytes),
            ("in_flight_datagrams", s.inflight_datagrams),
            ("peer_drain_rate", s.peer_drain_bytes),
            ("pacing_rate", s.pacing_rate),
            ("accepted", s.accepted),
            ("stale", s.stale),
            ("credit_blocked", s.credit_blocked),
            ("pacing_blocked", s.pacing_blocked),
            ("declared_lost", s.declared_lost),
            ("range", s.range),
            ("range_blocked", s.range_blocked),
            ("range_probes", s.range_probes),
        ] {
            table.put(format_args!("{tx}.{name}"), field)?;
        }
        if let Some(rtt) = s.min_rtt {
            table.put(
                format_args!("{tx}.min_rtt_us"),
                u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX),
            )?;
        }
    }
    let tx = "flow_control.session_credit.tx";
    if let Some(requested) = value.requested_send_buffer {
        table.put(format_args!("{tx}.sndbuf_requested"), requested)?;
    }
    if let Some(readback) = value.send_buffer_readback {
        table.put(format_args!("{tx}.sndbuf_readback"), readback)?;
    }
    Ok(())
}

fn mux_channels(table: &mut Table, channels: &[ChannelMeterSnapshot]) -> Result<(), TableError> {
    for ch in channels {
        let base = format!("mux.channel.ch{}", ch.channel);
        for (name, field) in [
            ("tx.packets", ch.tx_packets),
            ("tx.bytes", ch.tx_bytes),
            ("tx.admitted", ch.tx_admitted),
            ("tx.refused", ch.tx_refused),
            ("tx.queued_bytes", ch.tx_queued_bytes),
            ("rx.packets", ch.rx_packets),
            ("rx.bytes", ch.rx_bytes),
        ] {
            table.put(format_args!("{base}.{name}"), field)?;
        }
    }
    Ok(())
}

fn mux_flows(table: &mut Table, flows: &[FlowMeterSnapshot]) -> Result<(), TableError> {
    for flow in flows {
        let base = format!("mux.flow{}", flow.flow);
        for (name, field) in [
            ("tx.packets", flow.tx_packets),
            ("tx.bytes", flow.tx_bytes),
            ("rx.packets", flow.rx_packets),
            ("rx.bytes", flow.rx_bytes),
            ("state", flow.state),
        ] {
            table.put(format_args!("{base}.{name}"), field)?;
        }
    }
    Ok(())
}

fn recovery(table: &mut Table, snapshot: &CommonSnapshot) -> Result<(), TableError> {
    match &snapshot.recovery_metrics {
        RecoveryMetrics::Swift { channels } => {
            for ch in channels {
                let idx = ch.channel;
                if let Some(send) = ch.send {
                    let s = send.stats;
                    let repairs = s.repairs.saturating_add(s.tail_repairs);
                    table.put(format_args!("swift.sender.ch{idx}.retries"), s.retransmits)?;
                    table.put(format_args!("swift.sender.ch{idx}.repairs_sent"), repairs)?;
                    table.put(
                        format_args!("swift.sender.ch{idx}.feedback"),
                        ch.receive.map_or(0, |r| r.feedback),
                    )?;
                    for (name, field) in [
                        ("records", s.sources),
                        ("retransmits", s.retransmits),
                        ("rto", 0),
                        ("acks", 0),
                        ("replay_rejects", 0),
                        ("deadline_losses", 0),
                    ] {
                        table.put(format_args!("recovery.arq.ch{idx}.tx.{name}"), field)?;
                    }
                }
                if let Some(rx) = ch.receive {
                    let repairs_sent = ch
                        .send
                        .map_or(0, |s| s.stats.repairs.saturating_add(s.stats.tail_repairs));
                    for (name, field) in [
                        ("repairs_sent", repairs_sent),
                        ("repairs_used", rx.useful_repairs),
                        ("decode_failures", rx.useless_repairs),
                        ("feedback", rx.feedback),
                        ("deadline_losses", 0),
                    ] {
                        table.put(format_args!("swift.receiver.ch{idx}.{name}"), field)?;
                    }
                    for (name, field) in [
                        ("records", rx.sources.saturating_add(rx.recovered)),
                        ("retransmits", 0),
                        ("rto", 0),
                        ("acks", rx.feedback),
                        ("replay_rejects", rx.duplicates),
                        ("deadline_losses", 0),
                    ] {
                        table.put(format_args!("recovery.arq.ch{idx}.rx.{name}"), field)?;
                    }
                }
            }
        }
        RecoveryMetrics::Reliable { arq, reliable } => {
            let rto = arq.retransmissions.saturating_sub(arq.fast_retransmissions);
            for (name, field) in [
                ("records", arq.transmissions),
                ("retransmits", arq.retransmissions),
                ("rto", rto),
                ("acks", arq.feedback_received),
                ("replay_rejects", 0),
                ("deadline_losses", reliable.expired_generations),
            ] {
                table.put(format_args!("reliable.compact_arq.ch0.tx.{name}"), field)?;
            }
            for (name, field) in [
                ("records", arq.received_unique),
                ("retransmits", 0),
                ("rto", 0),
                ("acks", arq.feedback_sent),
                ("replay_rejects", arq.duplicates),
                ("deadline_losses", reliable.expired_generations),
            ] {
                table.put(format_args!("reliable.compact_arq.ch0.rx.{name}"), field)?;
            }
            for (name, field) in [
                ("repairs_sent", reliable.repair_packets),
                ("repairs_used", reliable.repaired_unique_sources),
                ("decode_failures", reliable.skipped_fec_packets),
                ("feedback", reliable.feedback_packets),
                ("deadline_losses", reliable.expired_generations),
            ] {
                table.put(format_args!("reliable.decoder.ch0.{name}"), field)?;
            }
            table.put_str(
                "fec.decoder.ch0.repairs_used",
                reliable.repaired_unique_sources,
            )?;
            table.put_str(
                "fec.decoder.ch0.decode_failures",
                reliable.skipped_fec_packets,
            )?;
        }
        RecoveryMetrics::Rolling { .. } => {
            for (name, field) in [
                ("repairs_sent", 0),
                ("repairs_used", 0),
                ("decode_failures", 0),
                ("feedback", 0),
                ("deadline_losses", 0),
            ] {
                table.put(format_args!("fec.rolling.ch0.{name}"), field)?;
            }
        }
        RecoveryMetrics::Other => {}
    }
    if let Some(research) = &snapshot.research_receiver {
        for (name, field) in [
            ("repairs_sent", 0),
            ("repairs_used", research.covering_repairs),
            ("decode_failures", research.abandon.dropped_repairs),
            ("feedback", research.receipt_repeats),
            ("deadline_losses", research.abandon.abandoned),
        ] {
            table.put(format_args!("fec.research.ch0.{name}"), field)?;
        }
    }
    Ok(())
}

fn best_rtt_us(snapshot: &CommonSnapshot) -> Option<u64> {
    if let Some(rtt) = snapshot
        .credit
        .as_ref()
        .and_then(|c| c.sender)
        .and_then(|s| s.min_rtt)
    {
        return Some(u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX));
    }
    if let RecoveryMetrics::Swift { channels } = &snapshot.recovery_metrics
        && let Some(rtt) = channels
            .iter()
            .filter_map(|ch| ch.send.map(|s| s.stats.smoothed_rtt_micros))
            .find(|&rtt| rtt > 0)
    {
        return Some(rtt);
    }
    snapshot.liveness.last_rtt_micros
}

/// Write every register derived from the snapshot itself.
fn snapshot_registers(table: &mut Table, snapshot: &CommonSnapshot) -> Result<(), TableError> {
    put(table, "meta.version", catalog::VERSION)?;
    put(table, "meta.sampled_us", snapshot.elapsed_micros)?;
    put(table, "runtime.session.elapsed_us", snapshot.elapsed_micros)?;
    put(table, "runtime.session.send_rate", snapshot.send_rate)?;
    put(table, "runtime.session.receive_rate", snapshot.receive_rate)?;
    put(
        table,
        "runtime.session.send_channels",
        u64::from(snapshot.send_channels),
    )?;
    put(
        table,
        "runtime.session.receive_channels",
        u64::from(snapshot.receive_channels),
    )?;
    if let Some(rtt_us) = best_rtt_us(snapshot) {
        put(table, "runtime.session.rtt_us", rtt_us)?;
    }
    // The Common driver's counters aggregate every lane, so they are the
    // lane-shared instance rather than a claim about lane 0.
    let c = &snapshot.counters;
    let wire = "runtime.wire.shared";
    for (name, field) in [
        ("sent_packets", c.wire_packets),
        ("sent_bytes", c.wire_bytes),
        ("accepted_packets", c.socket_accepted_packets),
        ("accepted_bytes", c.socket_accepted_ip_bytes),
        ("send_drops", c.socket_drops),
        ("received_packets", c.received_packets),
        ("receive_errors", c.socket_receive_errors),
        ("rejected_packets", c.rejected_packets),
        ("replay_rejections", c.replay_rejections),
    ] {
        table.put(format_args!("{wire}.{name}"), field)?;
    }
    put(table, "udp.socket.shared.socket_drops", c.socket_drops)?;
    if let Some(value) = &snapshot.credit {
        if let Some(requested) = value.requested_receive_buffer {
            put(table, "udp.socket.shared.rcvbuf_requested", requested)?;
        }
        if let Some(granted) = value.receive_buffer_readback {
            put(table, "udp.socket.shared.rcvbuf_granted", granted)?;
        }
    }
    for (name, field) in [
        ("read_packets", c.native_read),
        ("written_packets", c.native_written),
        ("oversize", c.native_oversize),
        ("backpressure_drops", c.native_backpressure_drops),
        ("pending_packets", c.native_pending_packets as u64),
        ("pending_bytes", c.native_pending_bytes as u64),
    ] {
        table.put(format_args!("runtime.device.{name}"), field)?;
    }
    put(
        table,
        "runtime.native_output.would_block",
        snapshot.performance.native_write_would_block,
    )?;
    let draining = usize::from(snapshot.native_delivery[1].is_some()) as u64;
    put(table, "l2tunnel.record_bank.epoch_slots", 1 + draining)?;
    put(table, "l2tunnel.record_bank.draining_generations", draining)?;
    if let Some(frag_in) = &snapshot.fragment_ingress {
        let groups: usize = frag_in.pending.iter().sum();
        put(table, "runtime.common_fragments.groups", groups as u64)?;
    }
    if let Some(frag_st) = &snapshot.fragment_statistics {
        put(
            table,
            "runtime.common_fragments.reassembled",
            frag_st.groups_written,
        )?;
        put(
            table,
            "runtime.common_fragments.expired",
            snapshot
                .fragment_data_drops
                .saturating_add(snapshot.fragment_feedback_drops),
        )?;
    }
    if let Some(ack) = &snapshot.ack_ingress {
        put(
            table,
            "pipeline.ack_coalescing.shared.held",
            ack.statistics.flushed,
        )?;
        put(
            table,
            "pipeline.ack_coalescing.shared.replaced",
            ack.statistics.superseded,
        )?;
    }
    if let Some(value) = &snapshot.credit {
        credit(table, value)?;
    }
    mux_channels(table, &snapshot.channel_metrics)?;
    mux_flows(table, &snapshot.flow_metrics)?;
    recovery(table, snapshot)?;
    Ok(())
}

fn build(
    snapshot: &CommonSnapshot,
    observer: Option<&crate::buffer_metrics::Observer>,
    now: u64,
    path_scale: usize,
) -> Option<Table> {
    let (keys, reasons) = observer.map_or((0, 0), crate::buffer_metrics::Observer::csr_extent);
    let recovery_channels = match &snapshot.recovery_metrics {
        RecoveryMetrics::Swift { channels } => channels.len(),
        RecoveryMetrics::Reliable { .. } | RecoveryMetrics::Rolling { .. } => 1,
        RecoveryMetrics::Other => usize::from(snapshot.research_receiver.is_some()),
    };
    let entries = FIXED_ENTRIES
        .saturating_add(
            snapshot
                .channel_metrics
                .len()
                .saturating_mul(PER_CHANNEL_MUX),
        )
        .saturating_add(snapshot.flow_metrics.len().saturating_mul(PER_FLOW_MUX))
        .saturating_add(recovery_channels.saturating_mul(PER_RECOVERY_CHANNEL))
        .saturating_add(keys.saturating_mul(PER_KEY))
        .saturating_add(reasons.saturating_mul(PER_REASON));
    let mut table = Table::new(Limits::for_entries(
        entries,
        AVERAGE_PATH.saturating_mul(path_scale),
    ))
    .ok()?;
    snapshot_registers(&mut table, snapshot).ok()?;
    if let Some(observer) = observer {
        observer.write_csr(&mut table, now).ok()?;
    }
    table.seal().ok()?;
    Some(table)
}

/// The CSR to publish with one snapshot: the retained table while it is
/// younger than [`REBUILD_INTERVAL_US`], otherwise a fresh one sized from
/// the observed keys and causes. `None` when no table could be built; the
/// reason is not protocol-visible.
pub(super) fn publish(
    snapshot: &CommonSnapshot,
    observer: Option<&crate::buffer_metrics::Observer>,
    now: u64,
) -> Option<Arc<Table>> {
    if let Some(observer) = observer
        && let Some(table) = observer.published_since(now.saturating_sub(REBUILD_INTERVAL_US))
    {
        return Some(table);
    }
    let table =
        Arc::new(build(snapshot, observer, now, 1).or_else(|| build(snapshot, observer, now, 2))?);
    if let Some(observer) = observer {
        observer.retain_published(now, table.clone());
    }
    Some(table)
}

// The bounds must cover what the collector writes per key and per cause.
const _: () = assert!(PER_KEY >= 1 + 6 + 3);
const _: () = assert!(PER_REASON == 32);
const _: () = assert!(REBUILD_INTERVAL_US >= 1_000);
