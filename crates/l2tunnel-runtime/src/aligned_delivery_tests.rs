use super::*;
use l2tunnel_flow_control::Credit;
use tokio::io::AsyncWriteExt;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn at(value: u64) -> Duration {
    Duration::from_micros(value)
}
fn policy() -> delivery_window::Config {
    delivery_window::Config {
        target_bandwidth_bps: 80_000_000,
        bootstrap_rtt_micros: 70_000,
        min_rtt_micros: 1,
        max_rtt_micros: 2_000_000,
        headroom_percent: 125,
        minimum_bytes: 1500,
        max_inflight_bytes: 4 * 1024 * 1024,
        max_records: 2,
        max_packet_bytes: 1500,
        metadata_limit_bytes: 1024 * 1024,
        sample_ttl_micros: 1_000_000,
        flush_timeout_micros: 2_000_000,
    }
}
fn identity(channel: u8, record: u64) -> protocol::RecordIdentity {
    protocol::RecordIdentity {
        channel: protocol::ChannelId(channel),
        record: aligned_receiver::RecordId(record),
    }
}
fn unit(identity: protocol::RecordIdentity, index: usize, count: usize) -> protocol::UnitWitness {
    protocol::UnitWitness {
        identity,
        index,
        count,
    }
}
#[test]
fn mixed_native_order_and_all_parts_release_exact_bytes_without_retry_timestamp_repair()
-> TestResult {
    let mut flight = Flight::new(policy(), 2, 8)?;
    let a = identity(1, 7);
    let b = identity(0, 9);
    flight.admit(a, 1500, at(0))?;
    flight.admit(b, 40, at(0))?;
    // One physical packed send contains only A's second fragment and all of B.
    flight.sent(&[unit(a, 1, 2), unit(b, 0, 1)], at(100), at(200))?;
    flight.delivered(b, at(300), at(400))?;
    let status = flight.controller.status(Micros(400))?;
    assert_eq!(
        status.outstanding,
        Credit {
            bytes: 1500,
            records: 1
        }
    );
    assert_eq!(status.flushed, Credit::default());
    assert_eq!(
        status.flushed_total,
        Credit {
            bytes: 40,
            records: 1
        }
    );
    assert_eq!(status.delivered_prefix, Credit::default());
    assert_eq!(status.sample.map(|s| s.raw_micros), Some(200));
    assert!(
        !flight.preview(1, at(500))?,
        "delivered hole must retain bounded ordinal span"
    );
    flight.delivered(a, at(600), at(700))?;
    let sample = flight.controller.status(Micros(700))?.sample;
    // Retrying part1 cannot renew the first successful actual send timestamp.
    flight.sent(&[unit(a, 1, 2)], at(1000), at(1100))?;
    // A's earlier physical send callback was observed after delivery. All parts
    // are now genuine, but neither the later retry nor callback creates a sample.
    flight.sent(&[unit(a, 0, 2)], at(50), at(1200))?;
    let done = flight.controller.status(Micros(1200))?;
    assert_eq!(done.flushed_total, done.admitted);
    assert_eq!(done.retained_records, 0);
    assert_eq!(done.sample, sample);
    flight.delivered(b, at(300), at(1300))?;
    assert_eq!(flight.controller.status(Micros(1300))?.sample, sample);
    assert!(
        flight
            .delivered(identity(0, 10), at(1400), at(1400))
            .is_err()
    );
    Ok(())
}
#[test]
fn partial_native_send_and_early_ack_cannot_erase_original_deadline() -> TestResult {
    let mut flight = Flight::new(policy(), 2, 8)?;
    let a = identity(1, 0);
    let b = identity(0, 0);
    flight.admit(a, 1500, at(100))?;
    flight.admit(b, 40, at(200))?;
    flight.sent(&[unit(a, 1, 2), unit(b, 0, 1)], at(300), at(400))?;
    flight.delivered(b, at(500), at(600))?;
    flight.delivered(a, at(700), at(800))?;
    assert_eq!(
        flight.controller.status(Micros(800))?.next_flush_deadline,
        Some(Micros(2_000_100))
    );
    assert!(
        flight
            .sent(&[unit(a, 0, 2)], at(250), at(2_000_100))
            .is_err()
    );
    let status = flight.controller.status(Micros(2_000_100))?;
    assert!(status.failed);
    assert_eq!(
        status.flushed_total,
        Credit {
            bytes: 40,
            records: 1
        }
    );
    assert_eq!(status.retained_records, 2);
    Ok(())
}
#[test]
fn metadata_and_original_unit_geometry_are_checked_before_new_authority() -> TestResult {
    let origin = Instant::now();
    let before = origin
        .checked_sub(Duration::from_micros(1))
        .ok_or("test origin")?;
    assert!(
        since(origin, before).is_err(),
        "event timestamps must never saturate to origin"
    );
    let mut cfg = policy();
    cfg.metadata_limit_bytes = metadata(cfg, 2, 8)? - 1;
    assert!(Flight::new(cfg, 2, 8).is_err());
    let mut flight = Flight::new(policy(), 2, 8)?;
    let a = identity(0, 1);
    flight.admit(a, 40, at(100))?;
    assert!(flight.admit(a, 40, at(100)).is_err());
    // A separate context serial, wrong channel or future body creates no
    // native authority even when the authenticated peer supplies the identity.
    for rejected in [
        identity(0, 0),
        identity(1, 1),
        identity(0, 2),
        identity(255, 1),
    ] {
        assert!(flight.delivered(rejected, at(150), at(200)).is_err());
    }
    assert_eq!(
        flight.controller.status(Micros(200))?.delivered,
        Credit::default()
    );
    assert!(flight.sent(&[unit(a, 0, 1)], at(99), at(200)).is_err());
    assert!(flight.sent(&[unit(a, 0, 1)], at(201), at(200)).is_err());
    assert!(flight.sent(&[unit(a, 2, 2)], at(150), at(200)).is_err());
    assert_eq!(
        flight.controller.status(Micros(200))?.flushed_total,
        Credit::default()
    );
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn native_control_uses_strict_shared_parser_and_original_receipt_before_queue_wait()
-> TestResult {
    let (mut writer, reader) = tokio::io::duplex(256);
    let (events, mut rx) = mpsc::channel(1);
    events
        .send((0, udp::NativeControlEvent::Ack(vec![]), Instant::now()))
        .await?;
    let task = tokio::spawn(udp::read_native_control_bound_timed(
        reader,
        1,
        events,
        Duration::from_secs(2),
        56,
        *b"L2A2",
    ));
    let origin = Instant::now();
    tokio::time::advance(Duration::from_millis(10)).await;
    writer
        .write_all(b"L2A2\x01\x03\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00\x11")
        .await?;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(90)).await;
    rx.recv().await.ok_or("occupied event")?;
    let (lane, event, actual) = rx.recv().await.ok_or("native receipt")?;
    assert_eq!(lane, 1);
    assert_eq!(actual.duration_since(origin), Duration::from_millis(10));
    assert!(matches!(
        event,
        udp::NativeControlEvent::Delivered {
            channel: 3,
            record: 17
        }
    ));
    task.abort();
    let _ = task.await;
    // The scalar eight-byte grammar remains invalid under explicit v2 selection.
    let (mut writer, reader) = tokio::io::duplex(256);
    let (events, _rx) = mpsc::channel(1);
    let task = tokio::spawn(udp::read_native_control_bound_timed(
        reader,
        0,
        events,
        Duration::from_secs(2),
        56,
        *b"L2A2",
    ));
    writer.write_all(b"L2A2\x01\x03\x00\x08").await?;
    assert_eq!(
        task.await?.err().ok_or("scalar must reject")?.kind(),
        io::ErrorKind::InvalidData
    );
    Ok(())
}

struct Sender {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    fail: bool,
}
impl DatagramSend for Sender {
    async fn send(&mut self, _: &[u8]) -> io::Result<()> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}
#[tokio::test(start_paused = true)]
async fn actual_send_reserves_bounded_observer_before_io_and_retains_original_time() -> TestResult {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let (packets, input) = mpsc::channel(1);
    let (events, mut rx) = mpsc::channel(1);
    let witness = unit(identity(0, 0), 0, 1);
    let origin = Instant::now();
    events
        .send(Sent {
            lane: 7,
            units: vec![],
            at: origin,
        })
        .await?;
    packets
        .send(Outbound {
            bytes: vec![1],
            units: vec![witness],
        })
        .await?;
    let task = tokio::spawn(write_datagrams(
        Sender {
            calls: calls.clone(),
            fail: false,
        },
        input,
        1,
        events,
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(10)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "full event queue must backpressure before carrier send"
    );
    rx.recv().await.ok_or("old event")?;
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(90)).await;
    let event = rx.recv().await.ok_or("actual send")?;
    assert_eq!(event.lane, 1);
    assert_eq!(event.at.duration_since(origin), Duration::from_millis(10));
    assert_eq!(event.units, vec![witness]);
    task.abort();
    let _ = task.await;
    Ok(())
}
#[tokio::test]
async fn failed_actual_send_never_publishes_native_first_flight() -> TestResult {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let (packets, input) = mpsc::channel(1);
    let (events, mut rx) = mpsc::channel(1);
    packets
        .send(Outbound {
            bytes: vec![1],
            units: vec![unit(identity(0, 0), 0, 1)],
        })
        .await?;
    let result = write_datagrams(
        Sender {
            calls: calls.clone(),
            fail: true,
        },
        input,
        0,
        events,
    )
    .await;
    assert_eq!(
        result.err().ok_or("send failure")?.kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(rx.try_recv().is_err());
    Ok(())
}
