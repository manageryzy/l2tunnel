//! Opt-in coalesced base-native diagnostics, independent of managed schema3.
use super::{Duration, io};
use l2tunnel_flow_control::{Credit, delivery_window::Status};
use l2tunnel_runtime::udp::{LaneStatus, Observer, Reporter, Snapshot};
use serde::Serialize;
use std::future::Future;
use tokio::time::{Instant, MissedTickBehavior};

pub(super) enum Runtime {
    UdpFrame,
    QuicFrame,
}
impl Runtime {
    fn name(&self) -> &'static str {
        match self {
            Self::UdpFrame => "udp-frame",
            Self::QuicFrame => "quic-frame",
        }
    }
}
pub(super) struct Observation {
    latest: Observer,
    interval: Duration,
}
pub(super) fn channel(interval: Option<Duration>) -> (Option<Observation>, Option<Reporter>) {
    match interval {
        None => (None, None),
        Some(interval) => {
            let (latest, reporter) = l2tunnel_runtime::udp::observations();
            (Some(Observation { latest, interval }), Some(reporter))
        }
    }
}
/// Attach the existing printer to a latest-snapshot owner created elsewhere,
/// such as the shared service's live base UDP generation.
pub(super) fn attach(latest: Observer, interval: Option<Duration>) -> Option<Observation> {
    interval.map(|interval| Observation { latest, interval })
}
#[derive(Serialize)]
struct Counts {
    records: u64,
    bytes: u64,
}
impl From<Credit> for Counts {
    fn from(value: Credit) -> Self {
        Self {
            records: value.records,
            bytes: value.bytes,
        }
    }
}
#[derive(Serialize)]
struct Local {
    queue_limit_packets: usize,
    queued_packets: usize,
    device_blocked: bool,
}
#[derive(Serialize)]
struct Recovery {
    configured_source_bytes: usize,
    configured_send_records: usize,
    configured_send_bytes: usize,
    configured_receive_records: usize,
    configured_receive_bytes: usize,
    retained_send_records: usize,
    retained_send_bytes: usize,
    retained_receive_records: usize,
    retained_receive_bytes: usize,
    admission_blocked: bool,
}
#[derive(Serialize)]
struct Sample {
    first_flight_at_micros: u64,
    feedback_at_micros: u64,
    raw_micros: u64,
    smoothed_micros: u64,
}
#[derive(Serialize)]
struct Native {
    admitted: Counts,
    delivered_unique: Counts,
    delivered_prefix: Counts,
    first_flight_prefix: Counts,
    first_flight_total: Counts,
    reserved: Counts,
    target_bytes: u64,
    retained_records: usize,
    sample: Option<Sample>,
    sample_fresh: bool,
    next_first_flight_deadline_micros: Option<u64>,
    failed: bool,
    bank_records: usize,
    pending_bytes: u64,
    staged_bytes: usize,
    admission_blocked: bool,
}
impl Native {
    fn new(value: LaneStatus) -> Self {
        let Status {
            admitted,
            delivered,
            delivered_prefix,
            flushed,
            flushed_total,
            outstanding,
            target_bytes,
            retained_records,
            sample,
            sample_fresh,
            next_flush_deadline,
            failed,
        } = value.delivery;
        Self {
            admitted: admitted.into(),
            delivered_unique: delivered.into(),
            delivered_prefix: delivered_prefix.into(),
            first_flight_prefix: flushed.into(),
            first_flight_total: flushed_total.into(),
            reserved: outstanding.into(),
            target_bytes,
            retained_records,
            sample: sample.map(|s| Sample {
                first_flight_at_micros: s.flushed_at.0,
                feedback_at_micros: s.feedback_at.0,
                raw_micros: s.raw_micros,
                smoothed_micros: s.smoothed_micros,
            }),
            sample_fresh,
            next_first_flight_deadline_micros: next_flush_deadline.map(|t| t.0),
            failed,
            bank_records: value.bank_records,
            pending_bytes: value.native_pending_bytes,
            staged_bytes: value.staged_bytes,
            admission_blocked: value.delivery_blocked,
        }
    }
}
#[derive(Serialize)]
struct Lane {
    local: Local,
    recovery: Recovery,
    native: Native,
}
impl From<LaneStatus> for Lane {
    fn from(value: LaneStatus) -> Self {
        Self {
            local: Local {
                queue_limit_packets: value.local_queue_limit,
                queued_packets: value.local_queued,
                device_blocked: value.device_blocked,
            },
            recovery: Recovery {
                configured_source_bytes: value.recovery_limits.max_source_bytes,
                configured_send_records: value.recovery_limits.send_records,
                configured_send_bytes: value.recovery_limits.send_bytes,
                configured_receive_records: value.recovery_limits.receive_records,
                configured_receive_bytes: value.recovery_limits.receive_bytes,
                retained_send_records: value.recovery.send_records,
                retained_send_bytes: value.recovery.send_bytes,
                retained_receive_records: value.recovery.receive_records,
                retained_receive_bytes: value.recovery.receive_bytes,
                admission_blocked: value.recovery_blocked,
            },
            native: Native::new(value),
        }
    }
}
#[derive(Serialize)]
struct Report {
    event: &'static str,
    schema: u8,
    runtime: &'static str,
    observer_elapsed_micros: u64,
    terminal: bool,
    lanes: [Option<Lane>; 2],
}
fn report(snapshot: Snapshot, runtime: &Runtime, elapsed: Duration, terminal: bool) -> Report {
    Report {
        event: "datagram_profile",
        schema: 1,
        runtime: runtime.name(),
        observer_elapsed_micros: u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
        terminal,
        lanes: snapshot.lanes.map(|lane| lane.map(Lane::from)),
    }
}
fn print(
    snapshot: Snapshot,
    runtime: &Runtime,
    elapsed: Duration,
    terminal: bool,
) -> io::Result<()> {
    println!(
        "{}",
        serde_json::to_string(&report(snapshot, runtime, elapsed, terminal))
            .map_err(io::Error::other)?
    );
    Ok(())
}
pub(super) async fn observe(
    operation: impl Future<Output = io::Result<()>>,
    observation: Option<Observation>,
    runtime: Runtime,
) -> io::Result<()> {
    let Some(observation) = observation else {
        return operation.await;
    };
    let started = Instant::now();
    let mut timer = tokio::time::interval_at(started + observation.interval, observation.interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tokio::pin!(operation);
    loop {
        tokio::select! {
            result = &mut operation => {
                print(observation.latest.status(), &runtime, started.elapsed(), true)?;
                return result;
            }
            _ = timer.tick() => {
                print(observation.latest.status(), &runtime, started.elapsed(), false)?;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_flow_control::{delivery_window::Controller, target::Micros};
    #[test]
    fn formatter_keeps_native_bytes_recovery_retention_and_local_queue_distinct() -> io::Result<()>
    {
        let mut controller = Controller::new(crate::delivery_tests::policy().forward, Micros(0))
            .map_err(io::Error::other)?;
        controller
            .admit(1500, Micros(1))
            .map_err(io::Error::other)?;
        controller.admit(40, Micros(2)).map_err(io::Error::other)?;
        let lane = LaneStatus {
            delivery: controller.status(Micros(3)).map_err(io::Error::other)?,
            recovery: l2tunnel_recovery::Retained {
                send_records: 1,
                send_bytes: 91,
                receive_records: 2,
                receive_bytes: 124,
            },
            recovery_limits: l2tunnel_recovery::ArqConfig::default(),
            local_queue_limit: 2,
            local_queued: 1,
            bank_records: 3,
            native_pending_bytes: 1520,
            staged_bytes: 40,
            recovery_blocked: true,
            delivery_blocked: false,
            device_blocked: true,
        };
        let value = serde_json::to_value(report(
            Snapshot {
                lanes: [Some(lane), None],
            },
            &Runtime::UdpFrame,
            Duration::from_micros(77),
            true,
        ))
        .map_err(io::Error::other)?;
        assert_eq!(value["event"], "datagram_profile");
        assert_eq!(value["schema"], 1);
        assert_eq!(value["runtime"], "udp-frame");
        assert_eq!(value["terminal"], true);
        assert_eq!(value["observer_elapsed_micros"], 77);
        assert_eq!(value["lanes"][0]["local"]["queue_limit_packets"], 2);
        assert_eq!(value["lanes"][0]["recovery"]["retained_send_bytes"], 91);
        assert_eq!(value["lanes"][0]["recovery"]["configured_send_records"], 64);
        assert_eq!(value["lanes"][0]["native"]["reserved"]["bytes"], 1540);
        assert_eq!(value["lanes"][0]["native"]["reserved"]["records"], 2);
        assert!(value["lanes"][1].is_null());
        let quic = serde_json::to_value(report(
            Snapshot::default(),
            &Runtime::QuicFrame,
            Duration::ZERO,
            false,
        ))
        .map_err(io::Error::other)?;
        assert_eq!(quic["runtime"], "quic-frame");
        assert_eq!(quic["terminal"], false);
        assert!(channel(None).0.is_none());
        Ok(())
    }
}
