//! Explicit streamed backend on actual runtime/device and original-UDP owners.
//!
//! Deterministic fault cases exercise production Driver methods after actual
//! socket handoff. They do not claim a privileged TAP/netem lab or generic
//! cross-profile transaction support.

use super::*;
use crate::secure_udp::control as backend;
use mg::{control_streams as streams, messages};

fn streamed(mut value: Config) -> Config {
    let mut delivery = value.control;
    delivery.wire_overhead += streams::HEADER_BYTES;
    let settings = messages::Settings {
        delivery,
        path_mtu: value.path_mtu,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131_072,
        max_fragments: 32,
        max_reassembly_bytes: 16_384,
        max_incomplete_messages: 2,
        message_lifetime: value.lifetime.lease,
        work_per_call: 8,
    };
    value.streams = Some(backend::Settings {
        streams: [settings; 3],
    });
    value
}

fn frame(number: u8, bytes: usize) -> Vec<u8> {
    let mut packet = vec![0; bytes];
    packet[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    packet[6..12].copy_from_slice(&[7, 8, 9, 10, 11, 12]);
    packet[12..14].copy_from_slice(&[0x88, 0xb5]);
    for (index, byte) in packet[14..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(number);
    }
    if packet.len() >= 16 {
        let length = packet.len();
        packet[length - 2..].fill(0);
    }
    packet
}

fn exchange(pair: &Pair, start: u8) -> Result {
    for (index, bytes) in [14, 42, 100, 256, 512].into_iter().enumerate() {
        let packet = frame(start.wrapping_add(index as u8), bytes);
        assert_eq!(pair.client.send(&packet)?, packet.len());
        let mut input = [0; 513];
        let length = pair.server.recv(&mut input)?;
        assert_eq!(&input[..length], packet);
        let packet = frame(start.wrapping_add(index as u8).wrapping_add(91), bytes);
        assert_eq!(pair.server.send(&packet)?, packet.len());
        let length = pair.client.recv(&mut input)?;
        assert_eq!(&input[..length], packet);
    }
    Ok(())
}

#[test]
fn explicit_streams_and_legacy_keep_exact_native_bytes_and_policy_on_both_covers() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for selected in [false, true] {
            let original = config(appearance);
            assert!(original.streams.is_none());
            let selected_config = if selected {
                streamed(original)
            } else {
                original
            };
            if selected {
                assert_ne!(
                    selected_config.canonical_digest()?,
                    original.canonical_digest()?
                );
            }
            selected_config.validate()?;
            let pair = Pair::start(appearance, selected_config, selected_config)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            assert_eq!(
                runtime.block_on(pair.participant.switch(policy_value())),
                Err(SwitchError::NotCoordinator)
            );
            exchange(&pair, 0)?;
            let epoch = runtime
                .block_on(async {
                    tokio::time::timeout(Duration::from_secs(2), pair.handle.switch(policy_value()))
                        .await
                })?
                .map_err(|error| io::Error::other(format!("streamed policy switch: {error:?}")))?;
            assert_eq!(epoch, 1);
            exchange(&pair, 31)?;
            // Each direction sends enough protected records for the configured
            // eight-record key generations and an actual matching liveness round.
            for number in 0..24 {
                let packet = frame(number, 256);
                assert_eq!(pair.client.send(&packet)?, packet.len());
                let mut output = [0; 513];
                let length = pair.server.recv(&mut output)?;
                assert_eq!(&output[..length], packet);
                assert_eq!(pair.server.send(&packet)?, packet.len());
                let length = pair.client.recv(&mut output)?;
                assert_eq!(&output[..length], packet);
            }
            thread::sleep(Duration::from_millis(40));
            let addresses = pair.addresses;
            let stopped = pair.stop()?;
            assert_eq!(stopped.len(), 2);
            for endpoint in stopped {
                assert_eq!(endpoint.reason, StopReason::Cancelled);
                let snapshot = endpoint.snapshot;
                assert!(!snapshot.running);
                assert_eq!(snapshot.committed.epoch, policy::Epoch(1));
                assert_eq!(snapshot.send.records.channels, 3);
                assert_eq!(snapshot.receive.records.channels, 3);
                assert!(snapshot.pending.is_none());
                assert!(snapshot.liveness.last_pong_micros.is_some());
                assert!(
                    snapshot
                        .counters
                        .user_generation
                        .is_some_and(|value| value.0 > 0)
                );
                assert!(
                    snapshot
                        .counters
                        .control_generation
                        .is_some_and(|value| value.0 > 0)
                );
                assert_eq!(snapshot.counters.native_read, 34);
                assert_eq!(snapshot.counters.native_written, 34);
                assert_eq!(snapshot.performance.native_write_batch_packets, 34);
                assert_eq!(
                    snapshot.performance.bootstrap_ip_bytes
                        + snapshot.performance.control_ip_bytes
                        + snapshot.performance.user_ip_bytes
                        + snapshot.performance.feedback_ip_bytes,
                    snapshot.counters.wire_bytes
                );
                assert_eq!(
                    snapshot.performance.bootstrap_packets
                        + snapshot.performance.control_packets
                        + snapshot.performance.user_packets
                        + snapshot.performance.feedback_packets,
                    snapshot.counters.wire_packets
                );
                assert_eq!(
                    snapshot.counters.wire_bytes,
                    snapshot.counters.socket_accepted_ip_bytes
                );
                assert_eq!(snapshot.info.authenticated.configuration, [3; 32]);
                let local = (snapshot.info.local_addr, snapshot.info.peer_addr);
                assert_eq!(
                    local,
                    if snapshot.info.role == security::Role::Initiator {
                        addresses
                    } else {
                        (addresses.1, addresses.0)
                    }
                );
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Side {
    A,
    B,
}

#[derive(Debug)]
enum Traffic {
    Source {
        stream: streams::Stream,
        id: u64,
        kind: u8,
        payload: Vec<u8>,
    },
    Ack {
        stream: streams::Stream,
        prefix: u64,
    },
    User,
}

#[derive(Debug)]
struct Attempt {
    side: Side,
    number: u64,
    wire_bytes: usize,
    traffic: Traffic,
    dropped: bool,
}

struct Endpoint {
    socket: tokio::net::UdpSocket,
    driver: Driver,
    original: (SocketAddr, SocketAddr),
}

struct FaultFixture {
    endpoints: [Endpoint; 2],
    start: u64,
    attempts: Vec<Attempt>,
}

impl FaultFixture {
    async fn new(appearance: cover::Appearance) -> Result<Self> {
        let mut configured = config(appearance);
        // This explicit finite test profile fits130 real round trips inside the
        // original policy cap. It changes no CLI defaults or production timeout.
        configured.policy.transaction_micros = 10_000_000;
        configured.lifetime.lease = Duration::from_secs(60);
        configured.lifetime.ping_interval = Duration::from_millis(20);
        configured.lifetime.pong_timeout = Duration::from_millis(500);
        configured.control.recovery.max_retries = 64;
        configured.work.send_batch = 1;
        configured.report_interval = None;
        let configured = streamed(configured);
        let (a, b) = parts_pair(appearance).await?;
        let setup_end = a.deadline.max(b.deadline);
        let origin = Instant::now();
        let (a_socket, mut a) =
            Driver::new(a, security::ConfigDigest([3; 32]), configured, origin)?;
        let (b_socket, mut b) =
            Driver::new(b, security::ConfigDigest([3; 32]), configured, origin)?;
        for driver in [&mut a, &mut b] {
            driver.bucket.tokens = 0;
            assert!(driver.tail(setup_end)?.is_none());
            assert!(driver.bootstrap.deadline().is_none());
            assert!(driver.joining.deadline().is_none());
        }
        for socket in [&a_socket, &b_socket] {
            let mut input = [0; 1501];
            let mut empty = false;
            for _ in 0..128 {
                match socket.try_recv(&mut input) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        empty = true;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            assert!(empty, "stream fault fixture retained setup input");
        }
        let start = add(clock(origin, setup_end)?, Duration::from_millis(20))?.max(1_000_000);
        Ok(Self {
            endpoints: [
                Endpoint {
                    original: (a_socket.local_addr()?, a_socket.peer_addr()?),
                    socket: a_socket,
                    driver: a,
                },
                Endpoint {
                    original: (b_socket.local_addr()?, b_socket.peer_addr()?),
                    socket: b_socket,
                    driver: b,
                },
            ],
            start,
            attempts: Vec::new(),
        })
    }

    fn request(&mut self) -> Result<oneshot::Receiver<std::result::Result<u64, SwitchError>>> {
        let (reply, receiver) = oneshot::channel();
        let endpoint = &mut self.endpoints[0];
        endpoint.driver.request(
            self.start,
            policy_value(),
            reply,
            &resolve(endpoint.driver.config),
        )?;
        Ok(receiver)
    }

    fn describe(driver: &Driver, is_control: bool, wire_bytes: usize) -> Result<(u64, Traffic)> {
        if !is_control {
            return Ok((
                driver
                    .counters
                    .user_number
                    .ok_or("missing User identity")?
                    .0,
                Traffic::User,
            ));
        }
        let number = driver
            .counters
            .control_number
            .ok_or("missing Control identity")?
            .0;
        let length = wire_bytes
            .checked_sub(driver.config.control.wire_overhead)
            .ok_or("stream control accounting underflow")?;
        let wrapped = streams::Frame::decode(
            &driver.control_wire[..length],
            streams::Limits {
                max_packet_bytes: driver.config.control.recovery.max_source_bytes
                    + recovery::DATA_HEADER_BYTES,
            },
        )?;
        let binding = streams::delivery_binding(
            delivery::Binding {
                session: mg::SessionId(driver.info.binding.session.0),
                lane: mg::LaneId(LANE),
                local_role: driver.role(),
                control_epoch: driver.config.control_epoch.0,
            },
            wrapped.stream,
        )?;
        let context = recovery::RecoveryContext {
            session: u128::from_be_bytes(driver.info.binding.session.0),
            epoch: binding.control_epoch,
            role: if driver.info.role == security::Role::Initiator {
                recovery::EndpointRole::Responder
            } else {
                recovery::EndpointRole::Initiator
            },
        };
        let traffic = match recovery::inspect_packet(
            wrapped.packet,
            context,
            driver.config.control.recovery.max_source_bytes,
        )? {
            recovery::PacketView::Data { source, payload } => Traffic::Source {
                stream: wrapped.stream,
                id: source.0,
                kind: *payload.first().ok_or("empty whole-message source")?,
                payload: payload.to_vec(),
            },
            recovery::PacketView::Ack { prefix, .. } => Traffic::Ack {
                stream: wrapped.stream,
                prefix,
            },
        };
        Ok((number, traffic))
    }

    async fn turn(
        &mut self,
        side: Side,
        at: u64,
        fault: &mut impl FnMut(&Attempt) -> bool,
    ) -> Result<bool> {
        let (left, right) = self.endpoints.split_at_mut(1);
        let (from, to) = if side == Side::A {
            (&mut left[0], &mut right[0])
        } else {
            (&mut right[0], &mut left[0])
        };
        from.driver.progress(at)?;
        from.driver.submit_control(at)?;
        let before = from.driver.counters;
        from.driver
            .send(&from.socket, at, from.driver.origin + duration(at))?;
        let packets = from.driver.counters.wire_packets - before.wire_packets;
        if packets == 0 {
            return Ok(false);
        }
        assert_eq!(packets, 1);
        assert_eq!(
            from.driver.counters.socket_accepted_packets - before.socket_accepted_packets,
            1
        );
        let wire_bytes = usize::try_from(from.driver.counters.wire_bytes - before.wire_bytes)?;
        assert_eq!(
            from.driver.counters.socket_accepted_ip_bytes - before.socket_accepted_ip_bytes,
            wire_bytes as u64
        );
        let is_control = from.driver.counters.control_number != before.control_number;
        let (number, traffic) = Self::describe(&from.driver, is_control, wire_bytes)?;
        let mut wire = [0; 1501];
        let length =
            tokio::time::timeout(Duration::from_secs(1), to.socket.recv(&mut wire)).await??;
        assert_eq!(length + from.driver.ip, wire_bytes);
        assert_eq!(&wire[..length], &from.driver.wire[..length]);
        let mut attempt = Attempt {
            side,
            number,
            wire_bytes,
            traffic,
            dropped: false,
        };
        attempt.dropped = fault(&attempt);
        if !attempt.dropped {
            assert!(to.driver.check_expiry(at)?);
            to.driver.receive(
                &wire[..length],
                at,
                to.driver.origin + duration(at),
                &resolve(to.driver.config),
            )?;
            to.driver.collect_native(at)?;
        }
        assert!(
            self.attempts.len() < 40_000,
            "bounded stream trace exhausted"
        );
        self.attempts.push(attempt);
        Ok(true)
    }

    async fn pump(&mut self, at: u64, fault: &mut impl FnMut(&Attempt) -> bool) -> Result {
        for _ in 0..64 {
            let a = self.turn(Side::A, at, fault).await?;
            let b = self.turn(Side::B, at, fault).await?;
            if !a && !b {
                return Ok(());
            }
        }
        Err("stream fixture exceeded per-time work bound".into())
    }

    fn accounting(&self, now: u64) -> Result {
        for (side, endpoint) in [Side::A, Side::B].into_iter().zip(&self.endpoints) {
            assert_eq!(
                (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                endpoint.original
            );
            let counters = endpoint.driver.counters;
            assert_eq!(counters.wire_bytes, counters.socket_accepted_ip_bytes);
            assert_eq!(counters.wire_packets, counters.socket_accepted_packets);
            assert_eq!(
                self.attempts
                    .iter()
                    .filter(|attempt| attempt.side == side)
                    .map(|attempt| attempt.wire_bytes as u64)
                    .sum::<u64>(),
                counters.wire_bytes
            );
            let numbers: Vec<_> = self
                .attempts
                .iter()
                .filter(|attempt| attempt.side == side && !matches!(attempt.traffic, Traffic::User))
                .map(|attempt| attempt.number)
                .collect();
            assert!(
                numbers.windows(2).all(|pair| pair[0] < pair[1]),
                "stream reset/reused shared Control nonce"
            );
            let metrics = endpoint.driver.snapshot(now, true).performance;
            assert_eq!(
                metrics.bootstrap_ip_bytes
                    + metrics.control_ip_bytes
                    + metrics.user_ip_bytes
                    + metrics.feedback_ip_bytes,
                counters.wire_bytes
            );
        }
        Ok(())
    }

    async fn finish(
        &mut self,
        response: &mut oneshot::Receiver<std::result::Result<u64, SwitchError>>,
        start: u64,
    ) -> Result<u64> {
        let mut applied = false;
        for step in 0..3_000 {
            let at = start + step * 1_000;
            self.pump(at, &mut |_| false).await?;
            if !applied {
                match response.try_recv() {
                    Ok(Ok(epoch)) => {
                        assert_eq!(epoch, 1);
                        applied = true;
                    }
                    Ok(Err(error)) => {
                        return Err(format!("stream policy request failed: {error:?}").into());
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if applied
                && self.endpoints.iter().all(|endpoint| {
                    endpoint.driver.coordinator.pending().is_none()
                        && endpoint.driver.policy_source.is_none()
                })
            {
                for endpoint in &self.endpoints {
                    assert_eq!(
                        endpoint.driver.coordinator.committed().epoch,
                        policy::Epoch(1)
                    );
                    assert_eq!(endpoint.driver.send.records.channels, 3);
                    assert_eq!(endpoint.driver.receive.records.channels, 3);
                    assert!(endpoint.driver.target.is_none());
                    assert!(endpoint.driver.records.additional_data().is_none());
                }
                return Ok(at);
            }
        }
        Err("released streamed policy did not settle under its original cap".into())
    }
}

#[tokio::test]
async fn blocked_transaction_data_keeps_130_actual_liveness_rounds_independent_on_both_covers()
-> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = FaultFixture::new(appearance).await?;
        let mut response = fixture.request()?;
        let deadline = fixture.endpoints[0]
            .driver
            .coordinator
            .deadline()
            .ok_or("missing policy deadline")?;
        let mut last_pong = [None; 2];
        let mut completed = [0u64; 2];
        let mut released = None;
        for step in 0..4_000 {
            let at = fixture.start + step * 1_000;
            fixture
                .pump(at, &mut |attempt| {
                    attempt.side == Side::A
                        && matches!(
                            attempt.traffic,
                            Traffic::Source {
                                stream: streams::Stream::Transaction,
                                ..
                            }
                        )
                })
                .await?;
            for index in 0..2 {
                let driver = &fixture.endpoints[index].driver;
                if driver.live.last_pong_micros != last_pong[index] {
                    assert!(driver.live.last_pong_micros.is_some());
                    completed[index] += 1;
                    last_pong[index] = driver.live.last_pong_micros;
                }
            }
            let coordinator = &fixture.endpoints[0].driver;
            assert_eq!(coordinator.coordinator.deadline(), Some(deadline));
            assert_eq!(coordinator.coordinator.committed().epoch, policy::Epoch(0));
            assert!(coordinator.policy_source.is_some());
            assert!(
                fixture.endpoints[1].driver.coordinator.pending().is_none(),
                "blocked production Transaction source unexpectedly dispatched"
            );
            assert!(matches!(
                response.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            if completed.iter().all(|rounds| *rounds >= 130) {
                released = Some(at + 1_000);
                break;
            }
        }
        let released = released.ok_or("independent runtime liveness did not complete130 rounds")?;
        assert!(released < deadline.0);
        assert!(fixture.attempts.iter().any(|attempt| attempt.dropped
            && matches!(
                attempt.traffic,
                Traffic::Source {
                    stream: streams::Stream::Transaction,
                    id: 0,
                    kind: messages::FRAGMENT_KIND,
                    ..
                }
            )));
        for side in [Side::A, Side::B] {
            let attempts: Vec<_> = fixture
                .attempts
                .iter()
                .filter(|attempt| {
                    attempt.side == side
                        && matches!(
                            attempt.traffic,
                            Traffic::Source {
                                stream: streams::Stream::Liveness,
                                ..
                            }
                        )
                })
                .collect();
            assert!(attempts.len() > 128);
            assert!(attempts.iter().all(|attempt| !attempt.dropped));
        }
        let last = fixture.finish(&mut response, released).await?;
        assert!(last < deadline.0);
        fixture.accounting(last)?;
    }
    Ok(())
}

#[tokio::test]
async fn source_ack_without_whole_acceptance_keeps_the_exact_swift_output_token() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = FaultFixture::new(appearance).await?;
        let mut response = fixture.request()?;
        let original = fixture.endpoints[0]
            .driver
            .coordinator
            .outbound()
            .ok_or("missing Propose token")?;
        let deadline = fixture.endpoints[0]
            .driver
            .coordinator
            .deadline()
            .ok_or("missing policy deadline")?;
        let mut stopped = None;
        for step in 0..200 {
            let at = fixture.start + step * 1_000;
            fixture
                .pump(at, &mut |attempt| {
                    attempt.side == Side::B
                        && matches!(
                            attempt.traffic,
                            Traffic::Source {
                                stream: streams::Stream::Transaction,
                                kind: messages::ACCEPTED_KIND,
                                ..
                            }
                        )
                })
                .await?;
            let acked = fixture.attempts.iter().any(|attempt| attempt.side == Side::B && !attempt.dropped
                && matches!(attempt.traffic, Traffic::Ack { stream: streams::Stream::Transaction, prefix } if prefix >= 1));
            let receipts_lost = fixture
                .attempts
                .iter()
                .filter(|attempt| {
                    attempt.dropped
                        && matches!(
                            attempt.traffic,
                            Traffic::Source {
                                stream: streams::Stream::Transaction,
                                kind: messages::ACCEPTED_KIND,
                                ..
                            }
                        )
                })
                .count();
            if acked && receipts_lost >= 2 {
                let driver = &mut fixture.endpoints[0].driver;
                let pending = driver
                    .policy_source
                    .as_ref()
                    .ok_or("source ACK released policy token")?;
                assert_eq!(pending.id, original.id);
                let token = pending.source;
                assert!(!driver.control.confirmed(token, duration(at))?);
                assert_eq!(driver.coordinator.outbound(), Some(original));
                assert_eq!(driver.coordinator.deadline(), Some(deadline));
                assert_eq!(driver.coordinator.committed().epoch, policy::Epoch(0));
                assert!(matches!(
                    response.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
                stopped = Some(at + 1_000);
                break;
            }
        }
        let resumed =
            stopped.ok_or("fixture did not observe actual ACK without whole acceptance")?;
        // An actually lost complete-message receipt is retransmitted byte for
        // byte with the same source ID, but a fresh shared Control identity.
        let receipts: Vec<_> = fixture
            .attempts
            .iter()
            .filter_map(|attempt| match &attempt.traffic {
                Traffic::Source {
                    stream: streams::Stream::Transaction,
                    id,
                    kind: messages::ACCEPTED_KIND,
                    payload,
                } if attempt.side == Side::B && attempt.dropped => Some((id, payload)),
                _ => None,
            })
            .collect();
        assert!(receipts.len() >= 2);
        assert!(receipts.windows(2).all(|pair| pair[0] == pair[1]));
        let last = fixture.finish(&mut response, resumed).await?;
        assert!(last < deadline.0);
        fixture.accounting(last)?;
    }
    Ok(())
}
#[path = "transport_stream_crossing_tests.rs"]
mod crossing;
#[path = "transport_stream_custody_tests.rs"]
mod custody;
