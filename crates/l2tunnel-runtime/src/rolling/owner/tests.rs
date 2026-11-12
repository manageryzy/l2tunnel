use super::*;
use std::cell::Cell;

fn config() -> io::Result<(RuntimeConfig, Config, DatagramPolicy)> {
    let runtime = RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: crate::Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    };
    let transport = udp::Config::new(
        Duplex::Full,
        l2tunnel_datagram::CoverProfile::OpenVpnLike,
        l2tunnel_datagram::Protection::HmacSha256,
        576,
        false,
    )?;
    Ok((
        runtime,
        Config::for_udp(
            runtime,
            transport,
            4,
            crate::rolling::config::test_delivery(runtime),
        )?,
        transport.policy()?,
    ))
}
fn state() -> io::Result<(State, Pipeline)> {
    let (runtime, config, policy) = config()?;
    let (feedback, _) = watch::channel(udp::Feedback::default());
    Ok((
        State::new(
            LaneContext {
                session: [6; 16],
                index: 0,
                initiator: false,
            },
            runtime,
            policy,
            config,
            feedback,
            None,
        )?,
        Pipeline::new(config.pipeline).map_err(io::Error::other)?,
    ))
}
fn packet(tcp: bool) -> Vec<u8> {
    let mut bytes = vec![0; 28];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&28_u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = if tcp { 6 } else { 17 };
    bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
    bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
    bytes[20..22].copy_from_slice(&1000_u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&2000_u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&8_u16.to_be_bytes());
    bytes
}
struct Device<'a> {
    calls: usize,
    clock: &'a Cell<u64>,
    advance: bool,
    blocked: bool,
}
impl PacketDevice for Device<'_> {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, _: &[u8]) -> io::Result<()> {
        self.calls += 1;
        if self.advance {
            self.clock.set(6);
        }
        if self.blocked {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            Ok(())
        }
    }
}
#[test]
fn malformed_inner_or_conflicting_channel_cannot_have_native_side_effect() -> io::Result<()> {
    for malformed in [true, false] {
        let (mut state, mut pipeline) = state()?;
        let bytes = packet(malformed);
        let channel = if malformed {
            0
        } else {
            let metadata = pipeline
                .enqueue(bytes.clone(), Duration::ZERO)
                .map_err(io::Error::other)?;
            (metadata.binding.channel + 1) % 4
        };
        state.native_pending_bytes += bytes.len() as u64;
        state.native.push_back(Native {
            bytes,
            channel,
            deadline: protocol::Tick(5),
            prepared: false,
        });
        let clock = Cell::new(0);
        let mut device = Device {
            calls: 0,
            clock: &clock,
            advance: false,
            blocked: false,
        };
        assert!(
            state
                .deliver(&mut device, &mut pipeline, || Ok(protocol::Tick(
                    clock.get()
                )))
                .is_err()
        );
        assert_eq!(device.calls, 0);
        assert_eq!(state.delivered, 0);
        assert_eq!(state.feedback.borrow().credit, 0);
        assert_eq!(state.native.len(), 1);
    }
    Ok(())
}
#[test]
fn prepared_wouldblock_retains_bytes_deadline_and_late_success_never_publishes_credit()
-> io::Result<()> {
    let (mut state, mut pipeline) = state()?;
    let bytes = packet(false);
    let key = pipeline.classify(&bytes).map_err(io::Error::other)?.key;
    state.native_pending_bytes += bytes.len() as u64;
    state.native.push_back(Native {
        bytes: bytes.clone(),
        channel: 0,
        deadline: protocol::Tick(5),
        prepared: false,
    });
    let clock = Cell::new(0);
    let mut device = Device {
        calls: 0,
        clock: &clock,
        advance: false,
        blocked: true,
    };
    state.deliver(&mut device, &mut pipeline, || {
        Ok(protocol::Tick(clock.get()))
    })?;
    let binding = pipeline
        .flow(&key)
        .ok_or_else(|| invalid("prepared flow"))?;
    clock.set(2);
    state.deliver(&mut device, &mut pipeline, || {
        Ok(protocol::Tick(clock.get()))
    })?;
    assert_eq!(pipeline.flow(&key), Some(binding));
    assert_eq!(
        state.native.front().map(|v| v.bytes.as_slice()),
        Some(bytes.as_slice())
    );
    assert_eq!(
        state.native.front().map(|v| v.deadline),
        Some(protocol::Tick(5))
    );
    device.blocked = false;
    device.advance = true;
    assert_eq!(
        state
            .deliver(&mut device, &mut pipeline, || Ok(protocol::Tick(
                clock.get()
            )))
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(state.delivered, 0);
    assert_eq!(state.feedback.borrow().credit, 0);
    assert_eq!(state.native.len(), 1);
    Ok(())
}

#[test]
fn rolling_reverse_capacity_retains_original_native_without_credit() -> io::Result<()> {
    let (mut state, _) = state()?;
    let mut cache = config()?.1.pipeline;
    cache.flows.idle_timeout = Duration::from_millis(1);
    let mut pipeline = Pipeline::new(cache).map_err(io::Error::other)?;
    for port in 10000..11024u16 {
        let mut bytes = packet(false);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        pipeline
            .enqueue(bytes, Duration::ZERO)
            .map_err(io::Error::other)?;
        pipeline.dequeue().map_err(io::Error::other)?;
    }
    let bytes = packet(false);
    let mut expected = Pipeline::new(config()?.1.pipeline).map_err(io::Error::other)?;
    let channel = expected
        .enqueue(bytes.clone(), Duration::ZERO)
        .map_err(io::Error::other)?
        .binding
        .channel;
    state.native_pending_bytes += bytes.len() as u64;
    state.native.push_back(Native {
        bytes: bytes.clone(),
        channel,
        deadline: protocol::Tick(5),
        prepared: false,
    });
    let clock = Cell::new(1);
    let mut device = Device {
        calls: 0,
        clock: &clock,
        advance: false,
        blocked: false,
    };
    state.deliver(&mut device, &mut pipeline, || {
        Ok(protocol::Tick(clock.get()))
    })?;
    assert_eq!(device.calls, 0);
    assert_eq!(
        state.native.front().map(|v| v.bytes.as_slice()),
        Some(bytes.as_slice())
    );
    assert_eq!(state.feedback.borrow().credit, 0);
    let mut cursor = None;
    pump::retire_registration(&mut pipeline, None, &mut cursor, Duration::from_millis(1))?;
    clock.set(2);
    state.deliver(&mut device, &mut pipeline, || {
        Ok(protocol::Tick(clock.get()))
    })?;
    assert_eq!(device.calls, 1);
    assert!(state.native.is_empty());
    assert_eq!(state.feedback.borrow().credit, 1);
    for offset in 0..1100u16 {
        let now = u64::from(offset) + 3;
        pump::retire_registration(&mut pipeline, None, &mut cursor, Duration::from_millis(now))?;
        let mut bytes = packet(false);
        bytes[20..22].copy_from_slice(&(20000 + offset).to_be_bytes());
        let mut expected = Pipeline::new(cache).map_err(io::Error::other)?;
        let channel = expected
            .enqueue(bytes.clone(), Duration::ZERO)
            .map_err(io::Error::other)?
            .binding
            .channel;
        state.native_pending_bytes += bytes.len() as u64;
        state.native.push_back(Native {
            bytes: bytes.clone(),
            channel,
            deadline: protocol::Tick(now + 5),
            prepared: false,
        });
        clock.set(now);
        state.deliver(&mut device, &mut pipeline, || {
            Ok(protocol::Tick(clock.get()))
        })?;
        assert!(state.native.is_empty());
    }
    assert_eq!(device.calls, 1101);
    assert_eq!(state.feedback.borrow().credit, 1101);
    Ok(())
}

#[test]
fn rolling_prepared_native_survives_retirement_and_original_expiry() -> io::Result<()> {
    let (mut state, _) = state()?;
    let mut cache = config()?.1.pipeline;
    cache.flows.idle_timeout = Duration::from_millis(1);
    let mut pipeline = Pipeline::new(cache).map_err(io::Error::other)?;
    let bytes = packet(false);
    let metadata = pipeline
        .enqueue(bytes.clone(), Duration::ZERO)
        .map_err(io::Error::other)?;
    pipeline.dequeue().map_err(io::Error::other)?;
    let now = 0;
    state.native_pending_bytes += bytes.len() as u64;
    state.native.push_back(Native {
        bytes: bytes.clone(),
        channel: metadata.binding.channel,
        deadline: protocol::Tick(now + 5),
        prepared: false,
    });
    let clock = Cell::new(now);
    let mut device = Device {
        calls: 0,
        clock: &clock,
        advance: false,
        blocked: true,
    };
    state.deliver(&mut device, &mut pipeline, || {
        Ok(protocol::Tick(clock.get()))
    })?;
    let deadline = state
        .native
        .front()
        .ok_or_else(|| invalid("held"))?
        .deadline;
    let mut cursor = None;
    for _ in 0..2 {
        pump::retire_registration(
            &mut pipeline,
            None,
            &mut cursor,
            Duration::from_millis(now + 1),
        )?;
    }
    assert_eq!(pipeline.registered_flows(), 0);
    assert_eq!(
        state.native.front().map(|v| v.bytes.as_slice()),
        Some(bytes.as_slice())
    );
    assert_eq!(state.native.front().map(|v| v.deadline), Some(deadline));
    // Cache retirement never renews the original handoff timer or grants credit.
    clock.set(now + 5);
    assert_eq!(
        state
            .deliver(&mut device, &mut pipeline, || Ok(protocol::Tick(
                clock.get()
            )))
            .err()
            .map(|v| v.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(state.delivered, 0);
    assert_eq!(state.feedback.borrow().credit, 0);
    Ok(())
}

#[test]
fn native_flight_uses_actual_byte_budget_not_local64_record_queue() -> io::Result<()> {
    let (mut rt, _, transport_policy) = config()?;
    rt.queue_packets = 64;
    let transport = udp::Config::new(
        Duplex::Full,
        l2tunnel_datagram::CoverProfile::OpenVpnLike,
        l2tunnel_datagram::Protection::HmacSha256,
        576,
        false,
    )?;
    let mut cfg = Config::for_udp(rt, transport, 4, crate::rolling::config::test_delivery(rt))?;
    cfg.delivery.forward.max_records = 128;
    cfg.delivery.reverse.max_records = 128;
    cfg.scheduler.recovery.window = 128;
    cfg.scheduler.recovery.max_rows = 128;
    cfg.scheduler.recovery.repair_history = 256;
    cfg.scheduler.repair_numerator = 0;
    cfg.validate(rt, transport_policy)?;
    let (feedback, _) = watch::channel(udp::Feedback::default());
    let mut state = State::new(
        LaneContext {
            session: [9; 16],
            index: 0,
            initiator: true,
        },
        rt,
        transport_policy,
        cfg,
        feedback,
        None,
    )?;
    let mut pipeline = Pipeline::new(cfg.pipeline).map_err(io::Error::other)?;
    let mut actual_bytes = 0_u64;
    for ordinal in 1..=65 {
        let length = [28_usize, 60, 128][((ordinal - 1) % 3) as usize];
        let mut bytes = packet(false);
        bytes.resize(length, 0);
        bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        bytes[24..26].copy_from_slice(&((length - 20) as u16).to_be_bytes());
        actual_bytes += length as u64;
        pipeline
            .enqueue(bytes.clone(), Duration::ZERO)
            .map_err(io::Error::other)?;
        let selected = pipeline
            .dequeue()
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("selected packet"))?;
        assert!(state.admit(&selected, Micros(ordinal))?);
        state.submit(protocol::Tick(0))?;
        let sender = state.sender.as_mut().ok_or_else(|| invalid("sender"))?;
        let id = sender
            .pending_output()
            .ok_or_else(|| invalid("systematic"))?
            .id();
        sender
            .confirm_output(id, protocol::Tick(0))
            .map_err(io::Error::other)?;
        assert_eq!(state.completion(id), Some(ordinal));
        state.queued(id);
    }
    let flight = state
        .flight
        .as_ref()
        .ok_or_else(|| invalid("delivery owner"))?;
    let status = flight.status(Micros(65)).map_err(io::Error::other)?;
    assert_eq!(status.outstanding.records, 65);
    assert_eq!(actual_bytes, 4_624);
    assert_eq!(status.outstanding.bytes, actual_bytes);
    assert_eq!(status.flushed.bytes, 0);
    assert_eq!(
        status.flushed.records, 0,
        "scheduler queue handoff is not datagram success"
    );
    assert_eq!(status.sample, None);
    assert_eq!(rt.queue_packets, 64);
    state.first_flight(65, Micros(70), Micros(100))?;
    let flushed = state
        .flight
        .as_ref()
        .ok_or_else(|| invalid("delivery owner"))?
        .status(Micros(100))
        .map_err(io::Error::other)?
        .flushed;
    assert_eq!(flushed.records, 65);
    assert_eq!(flushed.bytes, actual_bytes);
    state.control(
        udp::ControlEvent::Credit(65),
        protocol::Tick(1),
        Micros(70_070),
        Micros(70_100),
    )?;
    let status = state
        .flight
        .as_ref()
        .ok_or_else(|| invalid("delivery owner"))?
        .status(Micros(70_100))
        .map_err(io::Error::other)?;
    assert_eq!(status.outstanding.bytes, 0);
    assert_eq!(status.flushed, flushed);
    assert_eq!(status.sample.map(|s| s.raw_micros), Some(70_000));
    Ok(())
}

#[test]
fn only_final_native_fragment_source_marks_full_first_flight() -> io::Result<()> {
    let (rt, mut cfg, policy) = config()?;
    cfg.scheduler.repair_numerator = 0;
    let (feedback, _) = watch::channel(udp::Feedback::default());
    let mut state = State::new(
        LaneContext {
            session: [8; 16],
            index: 0,
            initiator: true,
        },
        rt,
        policy,
        cfg,
        feedback,
        None,
    )?;
    let mut bytes = packet(false);
    bytes.resize(1200, 0x37);
    bytes[2..4].copy_from_slice(&1200u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&1180u16.to_be_bytes());
    let mut pipeline = Pipeline::new(cfg.pipeline).map_err(io::Error::other)?;
    pipeline
        .enqueue(bytes, Duration::ZERO)
        .map_err(io::Error::other)?;
    let selected = pipeline
        .dequeue()
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("selected"))?;
    assert!(state.admit(&selected, Micros(0))?);
    let total = state.fragments.len();
    assert!(total > 1);
    for index in 0..total {
        state.submit(protocol::Tick(0))?;
        let sender = state.sender.as_mut().ok_or_else(|| invalid("sender"))?;
        let id = sender
            .pending_output()
            .ok_or_else(|| invalid("systematic"))?
            .id();
        sender
            .confirm_output(id, protocol::Tick(0))
            .map_err(io::Error::other)?;
        assert_eq!(
            state.completion(id),
            if index + 1 == total { Some(1) } else { None }
        );
        state.queued(id);
        assert_eq!(
            state
                .flight
                .as_ref()
                .ok_or_else(|| invalid("flight"))?
                .status(Micros(0))
                .map_err(io::Error::other)?
                .flushed
                .records,
            0
        );
    }
    state.first_flight(1, Micros(100), Micros(200))?;
    assert_eq!(
        state
            .flight
            .as_ref()
            .ok_or_else(|| invalid("flight"))?
            .status(Micros(200))
            .map_err(io::Error::other)?
            .flushed
            .records,
        1
    );
    Ok(())
}

#[test]
fn original_native_first_flight_deadline_is_not_renewed_by_late_success() -> io::Result<()> {
    let (rt, mut cfg, policy) = config()?;
    cfg.delivery.forward.flush_timeout_micros = 1000;
    let (feedback, _) = watch::channel(udp::Feedback::default());
    let mut state = State::new(
        LaneContext {
            session: [7; 16],
            index: 0,
            initiator: true,
        },
        rt,
        policy,
        cfg,
        feedback,
        None,
    )?;
    let mut pipeline = Pipeline::new(cfg.pipeline).map_err(io::Error::other)?;
    pipeline
        .enqueue(packet(false), Duration::ZERO)
        .map_err(io::Error::other)?;
    let selected = pipeline
        .dequeue()
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("selected"))?;
    assert!(state.admit(&selected, Micros(10))?);
    state.service_at(protocol::Tick(1), cfg, Micros(1009))?;
    assert!(state.first_flight(1, Micros(20), Micros(1010)).is_err());
    assert!(state.first_flight(1, Micros(20), Micros(1011)).is_err());
    let status = state
        .flight
        .as_ref()
        .ok_or_else(|| invalid("flight"))?
        .status(Micros(1011))
        .map_err(io::Error::other)?;
    assert!(status.failed);
    assert_eq!(status.next_flush_deadline, Some(Micros(1010)));
    assert_eq!(status.flushed.records, 0);
    assert_eq!(status.sample, None);
    Ok(())
}
