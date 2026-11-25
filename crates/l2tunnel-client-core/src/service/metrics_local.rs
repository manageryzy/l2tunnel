//! Version-5 `metrics`: a typed view of the meter CSR (meter-csr decision 8).
//! Every number comes from a CSR path; lane endpoints come from the Common
//! status. Nothing is estimated: a missing path is listed as `unreported`.
use super::*;
use crate::local::{
    CHANNEL_LIMIT, ChannelMetrics, DeviceCounters, FLOW_LIMIT, FlowMetrics, LANE_LIMIT,
    LaneMetrics, Metrics, Role, WireCounters,
};
use crate::secure_udp::common_status::Status;
use l2tunnel_meters::Table;

const WIRE: [&str; 9] = [
    "sent_packets",
    "sent_bytes",
    "accepted_packets",
    "accepted_bytes",
    "send_drops",
    "received_packets",
    "receive_errors",
    "rejected_packets",
    "replay_rejections",
];

fn get(table: Option<&Table>, path: &str) -> Option<u64> {
    table?.get(path)
}

/// Wire counters of one `runtime.wire` instance, only when all are present.
fn wire(table: Option<&Table>, instance: &str) -> Option<WireCounters> {
    let mut values = [0_u64; WIRE.len()];
    for (value, name) in values.iter_mut().zip(WIRE) {
        *value = get(table, &format!("runtime.wire.{instance}.{name}"))?;
    }
    let [
        sent_packets,
        sent_bytes,
        accepted_packets,
        accepted_bytes,
        send_drops,
        received_packets,
        receive_errors,
        rejected_packets,
        replay_rejections,
    ] = values;
    Some(WireCounters {
        sent_packets,
        sent_bytes,
        accepted_packets,
        accepted_bytes,
        send_drops,
        received_packets,
        receive_errors,
        rejected_packets,
        replay_rejections,
    })
}

fn device(table: Option<&Table>) -> Option<DeviceCounters> {
    let read = |name: &str| get(table, &format!("runtime.device.{name}"));
    Some(DeviceCounters {
        read_packets: read("read_packets")?,
        written_packets: read("written_packets")?,
        oversize: read("oversize")?,
        backpressure_drops: read("backpressure_drops")?,
        pending_packets: read("pending_packets")?,
        pending_bytes: read("pending_bytes")?,
    })
}

/// Instances under `prefix` whose next segment is `tag` plus an index.
fn instances(table: Option<&Table>, prefix: &str, tag: &str) -> Vec<u64> {
    let mut found: Vec<u64> = Vec::new();
    let Some(table) = table else {
        return found;
    };
    for (path, _) in table.matching(prefix, None) {
        let rest = path[prefix.len()..].trim_start_matches('.');
        let segment = rest.split('.').next().unwrap_or("");
        if let Some(index) = l2tunnel_meters::path::instance(segment, tag)
            && found.last() != Some(&index)
            && !found.contains(&index)
        {
            found.push(index);
        }
    }
    found
}

fn channels(table: Option<&Table>) -> Vec<ChannelMetrics> {
    instances(table, "mux.channel", "ch")
        .into_iter()
        .filter_map(|index| {
            let base = format!("mux.channel.ch{index}.tx");
            Some(ChannelMetrics {
                channel: u16::try_from(index).ok()?,
                queued_bytes: get(table, &format!("{base}.queued_bytes"))?,
                admitted: get(table, &format!("{base}.admitted"))?,
                dropped: get(table, &format!("{base}.refused"))?,
            })
        })
        .take(CHANNEL_LIMIT)
        .collect()
}

fn flows(table: Option<&Table>) -> Vec<FlowMetrics> {
    let mut flows: Vec<FlowMetrics> = instances(table, "mux", "flow")
        .into_iter()
        .filter_map(|index| {
            let state = get(table, &format!("mux.flow{index}.state"))
                .and_then(|code| usize::try_from(code).ok())
                .and_then(|code| l2tunnel_meters::catalog::FLOW_STATES.get(code))
                .copied()
                .unwrap_or("unknown");
            Some(FlowMetrics {
                flow: index,
                label: format!("flow {index}"),
                sent_bytes: get(table, &format!("mux.flow{index}.tx.bytes"))?,
                received_bytes: get(table, &format!("mux.flow{index}.rx.bytes"))?,
                state: state.to_owned(),
            })
        })
        .collect();
    // The busiest first, as the schema promises.
    flows
        .sort_by_key(|flow| std::cmp::Reverse(flow.sent_bytes.saturating_add(flow.received_bytes)));
    flows.truncate(FLOW_LIMIT);
    flows
}

/// Lanes of the running session: each raw lane, otherwise the one carrier
/// connection between `local` and `peer`.
fn lanes(status: &Status, role: Role) -> Vec<LaneMetrics> {
    if let Some(raw) = &status.raw_carrier {
        let lanes: Vec<LaneMetrics> = raw
            .lanes
            .iter()
            .enumerate()
            .filter_map(|(index, lane)| {
                let lane = lane.as_ref()?;
                let (local, remote) = if role == Role::Server {
                    (&lane.server, &lane.client)
                } else {
                    (&lane.client, &lane.server)
                };
                Some(LaneMetrics {
                    lane: u16::try_from(index).ok()?,
                    carrier: raw.effective.clone(),
                    local: local.clone(),
                    remote: remote.clone(),
                    wire: None,
                })
            })
            .take(LANE_LIMIT)
            .collect();
        if !lanes.is_empty() {
            return lanes;
        }
    }
    let carrier = if let Some(original) = &status.original_carrier {
        original.effective.clone()
    } else if let Some(effective) = status
        .maintained_carrier
        .as_ref()
        .and_then(|carrier| carrier.effective.as_ref())
    {
        effective.carrier.clone()
    } else {
        status.carrier.clone()
    };
    vec![LaneMetrics {
        lane: 0,
        carrier,
        local: status.local.clone(),
        remote: status.peer.clone(),
        wire: None,
    }]
}

/// What metrics read: the CSR for numbers, the status for lane endpoints.
pub(super) struct Source<'a> {
    pub generation: u64,
    pub carrier: &'a str,
    pub table: Option<&'a Table>,
    pub lanes: Vec<LaneMetrics>,
}
impl<'a> Source<'a> {
    fn of(status: &'a Status, role: Role, table: Option<&'a Table>) -> Self {
        Self {
            generation: status.generation,
            carrier: &status.carrier,
            table,
            lanes: lanes(status, role),
        }
    }
}

/// Project one running session's registers.
pub(super) fn project(source: Source<'_>, sampled_ms: u64) -> Metrics {
    let table = source.table;
    let aggregate = wire(table, "shared");
    let mut lanes = source.lanes;
    for lane in &mut lanes {
        lane.wire = wire(table, &format!("lane{}", lane.lane));
    }
    let per_lane = lanes.iter().any(|lane| lane.wire.is_some());
    // A single carrier connection carries the whole wire aggregate.
    if !per_lane && let [lane] = lanes.as_mut_slice() {
        lane.wire = aggregate;
    }
    let rtt_micros = get(table, "runtime.session.rtt_us");
    let channels = channels(table);
    let flows = flows(table);
    let device = device(table);
    let mut unreported = Vec::new();
    if lanes.len() > 1 && !per_lane {
        unreported.push("lane_counters".to_owned());
    }
    for (missing, name) in [
        (rtt_micros.is_none(), "rtt"),
        (channels.is_empty(), "channel_counters"),
        (flows.is_empty(), "flow_counters"),
        (aggregate.is_none(), "wire"),
        (device.is_none(), "device"),
    ] {
        if missing {
            unreported.push(name.to_owned());
        }
    }
    let channel = |path: &str| get(table, path).and_then(|value| u16::try_from(value).ok());
    Metrics {
        generation: source.generation,
        sampled_ms,
        carrier: source.carrier.to_owned(),
        runtime_micros: get(table, "meta.sampled_us"),
        wire: aggregate,
        device,
        selected_send_rate: get(table, "runtime.session.send_rate"),
        selected_receive_rate: get(table, "runtime.session.receive_rate"),
        send_channels: channel("runtime.session.send_channels"),
        receive_channels: channel("runtime.session.receive_channels"),
        rtt_micros,
        lanes,
        channels,
        flows,
        unreported,
    }
}

impl Handle {
    /// Counters of the running Common session; `None` when none is running.
    pub fn metrics(&self) -> Option<Metrics> {
        let (snapshot, role) = {
            let state = self.0.lock();
            (
                Self::snapshot_locked(&state),
                state
                    .plan
                    .as_ref()
                    .map_or(Role::Unconfigured, Prepared::role),
            )
        };
        let sampled_ms = u64::try_from(self.0.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let observation = self.observation(&snapshot)?;
        let status = observation.common.as_ref()?;
        let table = self.live_meters().map(|(_, _, table)| table);
        (status.running && status.terminal.is_none())
            .then(|| project(Source::of(status, role, table.as_deref()), sampled_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane(index: u16) -> LaneMetrics {
        LaneMetrics {
            lane: index,
            carrier: "udp".into(),
            local: "127.0.0.1:1".into(),
            remote: "127.0.0.1:2".into(),
            wire: None,
        }
    }
    fn table(registers: &[(&str, u64)]) -> Result<Table, Box<dyn std::error::Error>> {
        let mut table = Table::new(l2tunnel_meters::Limits::for_entries(64, 64))?;
        for (path, value) in registers {
            table.put_str(path, *value)?;
        }
        table.seal()?;
        Ok(table)
    }
    fn source<'a>(table: Option<&'a Table>, lanes: Vec<LaneMetrics>) -> Source<'a> {
        Source {
            generation: 3,
            carrier: "quic-like",
            table,
            lanes,
        }
    }
    fn wire_registers(instance: &str) -> Vec<(String, u64)> {
        WIRE.iter()
            .enumerate()
            .map(|(index, name)| (format!("runtime.wire.{instance}.{name}"), index as u64 * 10))
            .collect()
    }

    #[test]
    fn one_lane_carries_the_aggregate_and_gaps_are_named() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut registers = wire_registers("shared");
        registers.push(("meta.sampled_us".into(), 9));
        registers.push(("runtime.session.send_rate".into(), 1_000));
        registers.push(("runtime.session.send_channels".into(), 2));
        let borrowed: Vec<(&str, u64)> = registers.iter().map(|(p, v)| (p.as_str(), *v)).collect();
        let table = table(&borrowed)?;
        let metrics = project(source(Some(&table), vec![lane(0)]), 42);
        assert_eq!((metrics.generation, metrics.sampled_ms), (3, 42));
        assert_eq!(metrics.runtime_micros, Some(9));
        assert_eq!(metrics.wire.map(|wire| wire.sent_bytes), Some(10));
        assert_eq!(metrics.lanes[0].wire, metrics.wire);
        assert_eq!(metrics.selected_send_rate, Some(1_000));
        assert_eq!(metrics.selected_receive_rate, None);
        assert_eq!(metrics.send_channels, Some(2));
        assert_eq!(metrics.device, None);
        assert_eq!(
            metrics.unreported,
            ["rtt", "channel_counters", "flow_counters", "device"]
        );
        Ok(())
    }

    #[test]
    fn several_lanes_never_split_the_aggregate() {
        let metrics = project(source(None, vec![lane(0), lane(1)]), 1);
        assert!(metrics.lanes.iter().all(|lane| lane.wire.is_none()));
        assert_eq!(metrics.unreported[0], "lane_counters");
        assert!(metrics.unreported.contains(&"wire".to_owned()));
    }

    #[test]
    fn per_lane_channels_and_flows_come_from_paths() -> Result<(), Box<dyn std::error::Error>> {
        let mut registers = wire_registers("lane1");
        for (path, value) in [
            ("mux.channel.ch0.tx.queued_bytes", 5),
            ("mux.channel.ch0.tx.admitted", 6),
            ("mux.channel.ch0.tx.refused", 7),
            ("mux.flow3.tx.bytes", 10),
            ("mux.flow3.rx.bytes", 1),
            ("mux.flow3.state", 1),
            ("mux.flow9.tx.bytes", 100),
            ("mux.flow9.rx.bytes", 0),
        ] {
            registers.push((path.into(), value));
        }
        let borrowed: Vec<(&str, u64)> = registers.iter().map(|(p, v)| (p.as_str(), *v)).collect();
        let table = table(&borrowed)?;
        let metrics = project(source(Some(&table), vec![lane(0), lane(1)]), 1);
        assert_eq!(metrics.lanes[0].wire, None);
        assert_eq!(metrics.lanes[1].wire.map(|wire| wire.sent_bytes), Some(10));
        assert!(!metrics.unreported.contains(&"lane_counters".to_owned()));
        assert_eq!(metrics.channels.len(), 1);
        assert_eq!(metrics.channels[0].dropped, 7);
        assert_eq!(metrics.flows.len(), 2);
        assert_eq!(metrics.flows[0].flow, 9, "busiest first");
        assert_eq!(metrics.flows[0].state, "unknown");
        assert_eq!(metrics.flows[1].state, "active");
        Ok(())
    }
}
