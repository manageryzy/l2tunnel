//! Live meter CSR publication with each Common snapshot
//! (`docs/modules/meter-csr.md`, decisions 3 and 10).
//!
//! The table is assembled at the existing report interval from the snapshot
//! just built and the owner's always-on collector, then published as a
//! compact shared copy. Nothing here changes protocol state. A failure
//! leaves the snapshot without meters; it never fails the snapshot.

use std::sync::Arc;

use l2tunnel_meters::{Limits, Table, TableError, catalog};

use super::{CommonSnapshot, CreditSnapshot};

/// Shortest interval between CSR rebuilds (meter-csr decision 17).
pub(super) const REBUILD_INTERVAL_US: u64 = 100_000;
/// Registers outside the collector, with room to spare.
const FIXED_ENTRIES: usize = 128;
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
    if let Some(value) = &snapshot.credit {
        credit(table, value)?;
    }
    Ok(())
}

fn build(
    snapshot: &CommonSnapshot,
    observer: Option<&crate::buffer_metrics::Observer>,
    now: u64,
    path_scale: usize,
) -> Option<Table> {
    let (keys, reasons) = observer.map_or((0, 0), crate::buffer_metrics::Observer::csr_extent);
    let entries = FIXED_ENTRIES
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
