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
    const BOUNDARY: crate::datagram::SendBoundary =
        crate::datagram::SendBoundary::OsDatagramAccepted;
    async fn send(&mut self, bytes: &[u8]) -> io::Result<crate::datagram::DatagramSent> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(crate::datagram::DatagramSent {
                actual_at: tokio::time::Instant::now(),
                payload_bytes: bytes.len(),
                boundary: crate::datagram::SendBoundary::OsDatagramAccepted,
            })
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
            output: None,
        })
        .await?;
    packets
        .send(Outbound {
            bytes: vec![1],
            units: vec![witness],
            output: None,
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
            output: None,
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

fn physical_config(
    duplex: Duplex,
    queue_packets: usize,
) -> Result<(Config, DatagramPolicy), Box<dyn std::error::Error>> {
    let runtime = RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1500,
        compression: Compression::None,
        queue_packets,
        poll_interval: Duration::from_millis(1),
    };
    let transport = udp::Config::new(
        duplex,
        l2tunnel_datagram::CoverProfile::QuicLike,
        l2tunnel_datagram::Protection::ChaCha20Poly1305,
        576,
        false,
    )?
    .with_recovery(udp::RecoveryMode::Cauchy {
        sources: 3,
        repairs: 2,
        flush_after: Duration::from_millis(2),
    })?;
    let delivery = crate::managed::DeliveryConfig {
        forward: policy(),
        reverse: policy(),
    };
    Ok((
        Config::for_udp(runtime, transport, 1, delivery)?,
        transport.policy()?,
    ))
}

#[tokio::test(start_paused = true)]
async fn actual_peer_ack_waits_for_its_source_send_callback_without_blocking_native_receipts()
-> TestResult {
    let (config, wire_policy) = physical_config(Duplex::Full, 2)?;
    let context = RecoveryContext {
        session: 42,
        epoch: 1,
        role: EndpointRole::Initiator,
    };
    let mut endpoint = Selection::Aligned(config).endpoint(context)?;
    let mut peer = Selection::Aligned(config).endpoint(RecoveryContext {
        role: EndpointRole::Responder,
        ..context
    })?;
    let origin = Instant::now();
    endpoint.enqueue_identified(protocol::ChannelId(0), &[0x45; 40], Duration::ZERO)?;
    let mut bytes = vec![0; wire_policy.payload_bytes];
    let mut allowance = l2tunnel_reliable::OutboundBudget {
        packets: 1,
        wire_bytes: 65_535,
    };
    // The first real poll collects the partial FEC block; it is eligible only
    // after that block's original configured flush, not at initial admission.
    assert!(
        endpoint
            .poll_data(origin.elapsed(), &mut bytes, &mut allowance)?
            .is_none()
    );
    tokio::time::advance(config.protocol.recovery.flush_after).await;
    let length = endpoint
        .poll_data(origin.elapsed(), &mut bytes, &mut allowance)?
        .ok_or("actual source after original flush")?;
    let output = endpoint.pending_output().ok_or("actual output token")?;
    assert!(matches!(
        output.kind,
        l2tunnel_reliable::RecordKind::Source | l2tunnel_reliable::RecordKind::Systematic
    ));
    let (packets, input) = mpsc::channel(1);
    let (events, mut sent) = mpsc::channel(1);
    packets
        .send(Outbound {
            bytes: bytes[..length].to_vec(),
            units: vec![],
            output: Some(output),
        })
        .await?;
    let task = tokio::spawn(write_datagrams(
        Sender {
            calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            fail: false,
        },
        input,
        0,
        events,
    ));
    // The actual carrier accepted this source, but its callback has not yet
    // reached the actor. A genuine peer can already send its recovery receipt.
    tokio::task::yield_now().await;
    peer.receive_authenticated(&bytes[..length], origin.elapsed())?;
    tokio::time::advance(Duration::from_millis(10)).await;
    let now = origin.elapsed();
    let mut allowance = l2tunnel_reliable::OutboundBudget {
        packets: 1,
        wire_bytes: 65_535,
    };
    let length = peer
        .poll_feedback(now, &mut bytes, &mut allowance)?
        .ok_or("actual peer ACK")?;
    let event = udp::NativeControlEvent::Ack(bytes[..length].to_vec());
    let (feedback, _changes) = watch::channel(Feedback::default());
    let (native_feedback, _native) = mpsc::channel(1);
    let mut state = State {
        endpoint,
        outbound: None,
        feedback,
        native_feedback,
        receives: false,
        flight: None,
        incoming: policy(),
        next_channel: 0,
        feedback_first: true,
    };
    let before = state.endpoint.status().recovery.arq.send_records;
    assert!(state.waits_for_source_send(&event));
    assert!(
        !state.waits_for_source_send(&udp::NativeControlEvent::Delivered {
            channel: 0,
            record: 0
        })
    );
    let completion = sent.try_recv()?;
    assert_eq!(completion.output, Some(output));
    assert_eq!(
        completion.at.duration_since(origin),
        config.protocol.recovery.flush_after
    );
    state.sent(completion, origin, now)?;
    assert!(!state.waits_for_source_send(&event));
    state.control(event, now, now)?;
    assert_eq!(
        state.endpoint.status().recovery.arq.send_records,
        before - 1
    );
    assert_eq!(state.endpoint.status().failure, None);
    task.abort();
    let _ = task.await;
    Ok(())
}

struct BlockedSender(std::sync::Arc<tokio::sync::Notify>);
impl DatagramSend for BlockedSender {
    const BOUNDARY: crate::datagram::SendBoundary =
        crate::datagram::SendBoundary::OsDatagramAccepted;
    async fn send(&mut self, _bytes: &[u8]) -> io::Result<crate::datagram::DatagramSent> {
        self.0.notify_one();
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn half_queue_one_blocked_source_cannot_reserve_feedback_and_heartbeat_completion()
-> TestResult {
    blocked_source_control(Duplex::Half).await
}

#[tokio::test(start_paused = true)]
async fn full_queue_one_same_endpoint_feedback_flushes_while_actual_data_send_is_blocked()
-> TestResult {
    blocked_source_control(Duplex::Full).await
}

async fn blocked_source_control(duplex: Duplex) -> TestResult {
    use tokio::io::AsyncReadExt;
    let (config, mut wire_policy) = physical_config(duplex, 1)?;
    wire_policy.control_magic = *b"L2A2";
    let origin = Instant::now();
    let context = RecoveryContext {
        session: 42,
        epoch: 1,
        role: EndpointRole::Initiator,
    };
    let mut sending = Selection::Aligned(config).endpoint(context)?;
    let incoming_session = if duplex == Duplex::Full { 42 } else { 43 };
    let mut receiving = if duplex == Duplex::Half {
        Some(Selection::Aligned(config).endpoint(RecoveryContext {
            session: incoming_session,
            ..context
        })?)
    } else {
        None
    };
    let mut remote = Selection::Aligned(config).endpoint(RecoveryContext {
        session: incoming_session,
        role: EndpointRole::Responder,
        ..context
    })?;
    let mut bytes = vec![0; wire_policy.payload_bytes];
    let mut allowance = l2tunnel_reliable::OutboundBudget {
        packets: 1,
        wire_bytes: 65_535,
    };
    sending.enqueue_identified(protocol::ChannelId(0), &[0x45; 40], origin.elapsed())?;
    assert!(
        sending
            .poll_data(origin.elapsed(), &mut bytes, &mut allowance)?
            .is_none()
    );
    tokio::time::advance(config.protocol.recovery.flush_after).await;
    let length = sending
        .poll_data(origin.elapsed(), &mut bytes, &mut allowance)?
        .ok_or("blocked source")?;
    let source = sending.pending_output().ok_or("blocked source token")?;
    let capacity = completion_capacity(if duplex == Duplex::Full { 1 } else { 2 }, duplex, true)?;
    assert_eq!(capacity, if duplex == Duplex::Full { 2 } else { 3 });
    let (events, mut completions) = mpsc::channel(capacity);
    let (packets, input) = mpsc::channel(1);
    packets
        .send(Outbound {
            bytes: bytes[..length].to_vec(),
            units: vec![],
            output: Some(source),
        })
        .await?;
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let data_task = tokio::spawn(write_datagrams(
        BlockedSender(entered.clone()),
        input,
        0,
        events.clone(),
    ));
    timeout(wire_policy.control_timeout, entered.notified()).await?;
    assert_eq!(
        events.capacity(),
        capacity - 1,
        "actual blocked data owns one permit"
    );

    // Full duplex uses the SAME real endpoint; half duplex uses its opposite
    // receive lane. Both must ACK actual ingress while data remains blocked.
    remote.enqueue_identified(protocol::ChannelId(0), &[0x46; 40], origin.elapsed())?;
    let mut allowance = l2tunnel_reliable::OutboundBudget {
        packets: 1,
        wire_bytes: 65_535,
    };
    assert!(
        remote
            .poll_data(origin.elapsed(), &mut bytes, &mut allowance)?
            .is_none()
    );
    tokio::time::advance(config.protocol.recovery.flush_after).await;
    let length = remote
        .poll_data(origin.elapsed(), &mut bytes, &mut allowance)?
        .ok_or("incoming source")?;
    let incoming = remote.pending_output().ok_or("incoming source token")?;
    remote.confirm_output_at(origin.elapsed(), origin.elapsed(), incoming)?;
    let receiving = receiving.as_mut().unwrap_or(&mut sending);
    receiving.receive_authenticated(&bytes[..length], origin.elapsed())?;
    tokio::time::advance(config.protocol.recovery.arq.ack_delay).await;
    let mut allowance = l2tunnel_reliable::OutboundBudget {
        packets: 1,
        wire_bytes: 65_535,
    };
    if duplex == Duplex::Full {
        let before = allowance;
        assert!(
            receiving
                .poll_feedback(origin.elapsed(), &mut bytes, &mut allowance)?
                .is_none(),
            "legacy single-slot polling exposes the real full-duplex coupling"
        );
        assert_eq!(allowance, before);
    }
    let length = receiving
        .poll_feedback_independent(origin.elapsed(), &mut bytes, &mut allowance)?
        .ok_or("independent feedback")?;
    let feedback = receiving
        .pending_feedback_output()
        .ok_or("independent feedback token")?;
    assert_eq!(
        receiving.pending_data_output(),
        if duplex == Duplex::Full {
            Some(source)
        } else {
            None
        }
    );
    let ack = bytes[..length].to_vec();
    let (changes, receiver) = watch::channel(Feedback {
        ack: Some(FeedbackOutput {
            bytes: ack.clone(),
            output: feedback,
        }),
    });
    let (_native, native) = mpsc::channel(1);
    let (writer, mut reader) = tokio::io::duplex(256);
    let lane = usize::from(duplex == Duplex::Half);
    let control_task = tokio::spawn(write_control(
        writer,
        receiver,
        native,
        wire_policy,
        udp::SharedBudget::from_policy(wire_policy, origin),
        lane,
        events.clone(),
    ));
    timeout(wire_policy.control_timeout, async {
        let mut header = [0; 8];
        reader.read_exact(&mut header).await?;
        assert_eq!(&header[..6], b"L2A2\x01\x02");
        assert_eq!(
            usize::from(u16::from_be_bytes([header[6], header[7]])),
            ack.len()
        );
        let mut actual = vec![0; ack.len()];
        reader.read_exact(&mut actual).await?;
        assert_eq!(actual, ack);
        reader.read_exact(&mut header).await?;
        assert_eq!(&header, b"L2A2\x01\x01\0\0");
        Ok::<_, io::Error>(())
    })
    .await??;
    let completed = completions.try_recv()?;
    assert_eq!(completed.lane, lane);
    assert_eq!(completed.output, Some(feedback));
    assert!(completed.units.is_empty());
    receiving.confirm_output_at(origin.elapsed(), since(origin, completed.at)?, feedback)?;
    assert_eq!(receiving.pending_feedback_output(), None);
    assert_eq!(
        receiving.pending_output(),
        if duplex == Duplex::Full {
            Some(source)
        } else {
            None
        }
    );
    assert_eq!(sending.pending_output(), Some(source));
    assert!(
        completions.try_recv().is_err(),
        "blocked data has no physical receipt"
    );
    assert!(!data_task.is_finished());
    drop(changes);
    data_task.abort();
    control_task.abort();
    let _ = data_task.await;
    let _ = control_task.await;
    Ok(())
}
