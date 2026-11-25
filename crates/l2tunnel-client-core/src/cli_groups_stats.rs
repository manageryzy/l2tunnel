//! `service info` and `stats show|watch` text output for the grouped CLI.
use crate::local::{Capability, Metrics, ServiceInfo};
use std::io::{self, Write};

fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| "—".into(), |value| value.to_string())
}

/// Human service information.
pub(super) fn write_info(out: &mut dyn Write, info: &ServiceInfo) -> io::Result<()> {
    writeln!(
        out,
        "version {} · role {} · local API {} · uptime {} s",
        info.version,
        match info.role {
            crate::local::Role::Client => "client",
            crate::local::Role::Server => "server",
            crate::local::Role::Unconfigured => "unconfigured",
        },
        info.api,
        info.uptime_ms / 1000
    )?;
    for Capability {
        feature,
        available,
        reason,
    } in &info.capabilities
    {
        match (available, reason) {
            (true, _) => writeln!(out, "  {feature:?}: available")?,
            (false, reason) => writeln!(
                out,
                "  {feature:?}: unavailable ({})",
                reason.as_deref().unwrap_or("no reason given")
            )?,
        }
    }
    Ok(())
}

/// Human counter snapshot; lanes, channels and flows stay separate.
pub(super) fn write_metrics(out: &mut dyn Write, metrics: &Metrics) -> io::Result<()> {
    writeln!(
        out,
        "generation {} · carrier {} · sampled at {} ms",
        metrics.generation, metrics.carrier, metrics.sampled_ms
    )?;
    if let Some(wire) = metrics.wire {
        writeln!(
            out,
            "wire: sent {} pkts / {} B, accepted {} pkts, received {} pkts, drops {}, \
             receive errors {}, rejected {}, replay {}",
            wire.sent_packets,
            wire.sent_bytes,
            wire.accepted_packets,
            wire.received_packets,
            wire.send_drops,
            wire.receive_errors,
            wire.rejected_packets,
            wire.replay_rejections
        )?;
    }
    if let Some(device) = metrics.device {
        writeln!(
            out,
            "device: read {} pkts, written {} pkts, pending {} pkts / {} B, oversize {}, \
             backpressure drops {}",
            device.read_packets,
            device.written_packets,
            device.pending_packets,
            device.pending_bytes,
            device.oversize,
            device.backpressure_drops
        )?;
    }
    writeln!(
        out,
        "channels: send {} · receive {} · selected rate send {} B/s, receive {} B/s",
        optional(metrics.send_channels.map(u64::from)),
        optional(metrics.receive_channels.map(u64::from)),
        optional(metrics.selected_send_rate),
        optional(metrics.selected_receive_rate)
    )?;
    for lane in &metrics.lanes {
        writeln!(
            out,
            "lane {} {} {} -> {} sent {} pkts received {} pkts",
            lane.lane,
            lane.carrier,
            lane.local,
            lane.remote,
            optional(lane.wire.map(|wire| wire.sent_packets)),
            optional(lane.wire.map(|wire| wire.received_packets))
        )?;
    }
    for channel in &metrics.channels {
        writeln!(
            out,
            "channel {} queued {} B admitted {} dropped {}",
            channel.channel, channel.queued_bytes, channel.admitted, channel.dropped
        )?;
    }
    for flow in &metrics.flows {
        writeln!(
            out,
            "flow {} {} sent {} B received {} B {}",
            flow.flow, flow.label, flow.sent_bytes, flow.received_bytes, flow.state
        )?;
    }
    if !metrics.unreported.is_empty() {
        writeln!(out, "not reported: {}", metrics.unreported.join(", "))?;
    }
    Ok(())
}

/// One `stats watch` line: rates since the previous sample of the same series.
pub(super) fn rate_line(previous: Option<&Metrics>, current: &Metrics) -> String {
    let Some(previous) = previous.filter(|previous| {
        previous.generation == current.generation && current.sampled_ms > previous.sampled_ms
    }) else {
        return format!(
            "generation {} · new series (rates from the next sample)",
            current.generation
        );
    };
    let seconds = (current.sampled_ms - previous.sampled_ms) as f64 / 1000.0;
    let rate = |old: Option<u64>, new: Option<u64>, scale: f64| match (old, new) {
        (Some(old), Some(new)) if new >= old => {
            format!("{:.0}", (new - old) as f64 * scale / seconds)
        }
        _ => "—".into(),
    };
    let wire = |metrics: &Metrics, pick: fn(&crate::local::WireCounters) -> u64| {
        metrics.wire.as_ref().map(pick)
    };
    let device = |metrics: &Metrics, pick: fn(&crate::local::DeviceCounters) -> u64| {
        metrics.device.as_ref().map(pick)
    };
    format!(
        "sent {} b/s · sent {} pkt/s · received {} pkt/s · device read {} pkt/s · device written {} pkt/s",
        rate(
            wire(previous, |wire| wire.sent_bytes),
            wire(current, |wire| wire.sent_bytes),
            8.0
        ),
        rate(
            wire(previous, |wire| wire.sent_packets),
            wire(current, |wire| wire.sent_packets),
            1.0
        ),
        rate(
            wire(previous, |wire| wire.received_packets),
            wire(current, |wire| wire.received_packets),
            1.0
        ),
        rate(
            device(previous, |device| device.read_packets),
            device(current, |device| device.read_packets),
            1.0
        ),
        rate(
            device(previous, |device| device.written_packets),
            device(current, |device| device.written_packets),
            1.0
        ),
    )
}
