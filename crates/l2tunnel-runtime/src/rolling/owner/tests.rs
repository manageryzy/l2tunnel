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
        Config::for_udp(runtime, transport, 4)?,
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
