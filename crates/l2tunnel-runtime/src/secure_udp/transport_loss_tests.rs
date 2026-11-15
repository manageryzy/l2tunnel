//! Deterministic control-loss schedules over real roots and original UDP sockets.
//!
//! Injected protocol time is independent of the bounded wait for an actual local
//! UDP handoff. Faults discard complete production emissions after socket receipt;
//! they do not fabricate authenticated input, ACKs, retry state or control frames.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Side {
    A,
    B,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Ping(u64),
    Pong(u64),
}
#[derive(Debug)]
enum Traffic {
    Source {
        id: u64,
        command: Command,
        logical: u64,
        payload: Vec<u8>,
    },
    Ack {
        prefix: u64,
        bitmap: u64,
    },
    User,
}
#[derive(Debug)]
struct Attempt {
    side: Side,
    at: u64,
    number: u64,
    wire_bytes: usize,
    traffic: Traffic,
    dropped: bool,
}
struct Endpoint {
    socket: tokio::net::UdpSocket,
    driver: owner::StateCell<Driver>,
}
struct LossFixture {
    endpoints: [Endpoint; 2],
    start: u64,
    attempts: Vec<Attempt>,
}

#[inline(never)]
fn fixture_driver(
    parts: member::Parts,
    config: Config,
    origin: Instant,
) -> Result<(tokio::net::UdpSocket, owner::StateCell<Driver>)> {
    let (socket, driver) = Driver::new(parts, security::ConfigDigest([3; 32]), config, origin)?;
    // Keep the actual owner once without retaining large inline construction
    // temporaries in the asynchronous fixture and each awaiting test future.
    Ok((socket, owner::StateCell::new(driver)?))
}

impl LossFixture {
    async fn new(kind: cover::Appearance) -> Result<Self> {
        let mut config = config(kind);
        config.send.records.channels = 1;
        config.send.records.codec.repair_numerator = 0;
        config.send.records.codec.flush_micros = 1_000;
        config.receive.records = config.send.records;
        // These are the actual CLI control retry and liveness settings. The
        // fixture changes neither the five-second bound nor the retry schedule.
        config.control.recovery = recovery::ArqConfig {
            max_source_bytes: 256,
            send_records: 32,
            receive_records: 32,
            send_bytes: 8192,
            receive_bytes: 8192,
            ..recovery::ArqConfig::default()
        };
        config.control.interval = Duration::from_millis(10);
        config.control.packets_per_interval = 4;
        let reserve = config.control.recovery.max_source_bytes
            + recovery::DATA_HEADER_BYTES
            + recovery::ACK_PACKET_BYTES
            + 2 * config.control.wire_overhead;
        config.control.bytes_per_interval = 2 * reserve;
        config.lifetime.lease = Duration::from_secs(60);
        config.lifetime.ping_interval = Duration::from_secs(1);
        config.lifetime.pong_timeout = Duration::from_secs(5);
        config.native.stall_timeout = Duration::from_secs(10);
        config.report_interval = None;
        // One production emission per turn makes every injected fault explicit.
        config.work.send_batch = 1;
        let (a, b) = parts_pair(kind).await?;
        let end = a.deadline.max(b.deadline);
        let origin = Instant::now();
        let (a_socket, mut a) = fixture_driver(a, config, origin)?;
        let (b_socket, mut b) = fixture_driver(b, config, origin)?;
        for driver in [&mut a, &mut b] {
            driver.bucket.tokens = 0;
            assert!(driver.tail(end)?.is_none());
            assert!(driver.bootstrap.deadline().is_none());
            assert!(driver.joining.deadline().is_none());
        }
        for socket in [&a_socket, &b_socket] {
            let mut input = vec![0; 1501];
            let mut drained = false;
            for _ in 0..128 {
                match socket.try_recv(&mut input) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        drained = true;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            assert!(drained, "fixture left unbounded setup input");
        }
        let start = add(clock(origin, end)?, Duration::from_millis(20))?.max(1_000_000);
        Ok(Self {
            endpoints: [
                Endpoint {
                    socket: a_socket,
                    driver: a,
                },
                Endpoint {
                    socket: b_socket,
                    driver: b,
                },
            ],
            start,
            attempts: Vec::new(),
        })
    }

    fn driver(&self, side: Side) -> &Driver {
        &self.endpoints[usize::from(side == Side::B)].driver
    }
    fn driver_mut(&mut self, side: Side) -> &mut Driver {
        &mut self.endpoints[usize::from(side == Side::B)].driver
    }
    fn describe(driver: &Driver, control: bool, wire_bytes: usize) -> Result<(u64, Traffic)> {
        if !control {
            let number = driver
                .counters
                .user_number
                .ok_or_else(|| protocol("missing User number"))?;
            return Ok((number.0, Traffic::User));
        }
        let number = driver
            .counters
            .control_number
            .ok_or_else(|| protocol("missing Control number"))?;
        let length = wire_bytes
            .checked_sub(driver.config.control.wire_overhead)
            .ok_or_else(|| protocol("control accounting underflow"))?;
        let context = recovery::RecoveryContext {
            session: u128::from_be_bytes(driver.info.binding.session.0),
            epoch: driver.config.control_epoch.0,
            role: match driver.info.role {
                security::Role::Initiator => recovery::EndpointRole::Responder,
                security::Role::Responder => recovery::EndpointRole::Initiator,
            },
        };
        let view = recovery::inspect_packet(
            &driver.buffers.control_wire[..length],
            context,
            driver.config.control.recovery.max_source_bytes,
        )?;
        let traffic = match view {
            recovery::PacketView::Data { source, payload } => {
                let envelope = control::Envelope::decode(payload, driver.envelope_limits())?;
                let command = match envelope.body {
                    control::Body::Ping { nonce } => Command::Ping(nonce),
                    control::Body::Pong { nonce } => Command::Pong(nonce),
                    _ => return Err(protocol("unexpected fixture control command").into()),
                };
                Traffic::Source {
                    id: source.0,
                    command,
                    logical: envelope.binding.packet.0,
                    payload: payload.to_vec(),
                }
            }
            recovery::PacketView::Ack { prefix, bitmap } => Traffic::Ack { prefix, bitmap },
        };
        Ok((number.0, traffic))
    }

    async fn turn(
        &mut self,
        side: Side,
        at: u64,
        fault: &mut impl FnMut(&Attempt) -> bool,
    ) -> Result<Option<usize>> {
        let (left, right) = self.endpoints.split_at_mut(1);
        let (from, to) = if side == Side::A {
            (&mut left[0], &mut right[0])
        } else {
            (&mut right[0], &mut left[0])
        };
        from.driver.progress(at)?;
        from.driver.submit_control(at)?;
        let before = from.driver.counters;
        let sent_at = from.driver.origin + duration(at);
        from.driver.send(&from.socket, at, sent_at)?;
        let packets = from.driver.counters.wire_packets - before.wire_packets;
        if packets == 0 {
            assert_eq!(from.driver.counters.control_number, before.control_number);
            assert_eq!(from.driver.counters.user_number, before.user_number);
            return Ok(None);
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
        let mut wire = vec![0; to.driver.cover.limits().max_packet_bytes + 1];
        let length =
            tokio::time::timeout(Duration::from_secs(1), to.socket.recv(&mut wire)).await??;
        assert_eq!(length + from.driver.ip, wire_bytes);
        assert_eq!(&wire[..length], &from.driver.buffers.wire[..length]);
        let mut attempt = Attempt {
            side,
            at,
            number,
            wire_bytes,
            traffic,
            dropped: false,
        };
        attempt.dropped = fault(&attempt);
        if !attempt.dropped {
            assert!(to.driver.check_expiry(at)?);
            let received_at = to.driver.origin + duration(at);
            let resolver = resolve(to.driver.config);
            to.driver
                .receive(&wire[..length], at, received_at, &resolver)?;
            to.driver.collect_native(at)?;
        }
        let index = self.attempts.len();
        self.attempts.push(attempt);
        Ok(Some(index))
    }

    async fn pump(&mut self, at: u64, fault: &mut impl FnMut(&Attempt) -> bool) -> Result {
        for _ in 0..64 {
            let a = self.turn(Side::A, at, fault).await?;
            let b = self.turn(Side::B, at, fault).await?;
            if a.is_none() && b.is_none() {
                return Ok(());
            }
        }
        Err(protocol("control fault fixture work bound exhausted").into())
    }

    fn sources(&self, side: Side, id: u64) -> Vec<&Attempt> {
        self.attempts
            .iter()
            .filter(|attempt| {
                attempt.side == side
                    && matches!(attempt.traffic, Traffic::Source { id: source, .. } if source == id)
            })
            .collect()
    }
    fn assert_same_sources(&self, side: Side, id: u64) -> Result {
        let attempts = self.sources(side, id);
        assert!(!attempts.is_empty());
        let first = &attempts[0].traffic;
        for pair in attempts.windows(2) {
            assert!(
                pair[1].number > pair[0].number,
                "retry reused a security number"
            );
        }
        for attempt in &attempts {
            match (first, &attempt.traffic) {
                (
                    Traffic::Source {
                        command: a,
                        logical: x,
                        payload: p,
                        ..
                    },
                    Traffic::Source {
                        command: b,
                        logical: y,
                        payload: q,
                        ..
                    },
                ) => {
                    assert_eq!(a, b);
                    assert_eq!(x, y);
                    assert_eq!(p, q);
                    assert_eq!(
                        attempt.wire_bytes,
                        44 + p.len() + self.driver(side).config.control.wire_overhead
                    );
                }
                _ => return Err(protocol("source fixture changed record class").into()),
            }
        }
        Ok(())
    }
    async fn fresh_user(&mut self, side: Side, at: u64) -> Result {
        let before = self
            .driver(side)
            .owner
            .legacy()?
            .engine
            .stats()
            .sender
            .sources;
        assert_eq!(
            self.driver_mut(side)
                .owner
                .legacy_mut()?
                .engine
                .offer(at - 1_000, &ethernet(7))?,
            records::Admission::Accepted
        );
        for _ in 0..8 {
            self.turn(side, at, &mut |_| false).await?;
            if self
                .driver(side)
                .owner
                .legacy()?
                .engine
                .stats()
                .sender
                .sources
                > before
            {
                return Ok(());
            }
        }
        Err(protocol("fresh User emission was not admitted").into())
    }
}

#[tokio::test]
async fn loss_of_the_first_ping_or_pong_recovers_without_renewing_the_challenge() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for ping in [true, false] {
            let mut fixture = LossFixture::new(kind).await?;
            let start = fixture.start;
            let mut dropped = false;
            let mut fault = |attempt: &Attempt| {
                let selected = if ping {
                    attempt.side == Side::A
                        && matches!(
                            attempt.traffic,
                            Traffic::Source {
                                command: Command::Ping(1),
                                ..
                            }
                        )
                } else {
                    attempt.side == Side::B
                        && matches!(
                            attempt.traffic,
                            Traffic::Source {
                                command: Command::Pong(1),
                                ..
                            }
                        )
                };
                if selected && !dropped {
                    dropped = true;
                    true
                } else {
                    false
                }
            };
            fixture.pump(start, &mut fault).await?;
            assert!(fixture.driver(Side::A).challenge.is_some());
            assert_eq!(
                fixture
                    .driver(Side::A)
                    .challenge
                    .as_ref()
                    .map(|value| value.deadline),
                Some(start + 5_000_000)
            );
            fixture.pump(start + 5_000, &mut fault).await?;
            fixture.pump(start + 199_999, &mut fault).await?;
            assert!(fixture.driver(Side::A).challenge.is_some());
            fixture.pump(start + 200_000, &mut fault).await?;
            fixture.pump(start + 205_000, &mut fault).await?;
            assert!(dropped);
            for side in [Side::A, Side::B] {
                assert!(fixture.driver(side).challenge.is_none());
                assert!(fixture.driver(side).control.drained());
                assert_eq!(fixture.driver(side).terminal, None);
                assert_eq!(
                    fixture.driver(side).live.last_pong_micros,
                    Some(start + 200_000)
                );
            }
            fixture.assert_same_sources(if ping { Side::A } else { Side::B }, 0)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn out_of_order_pong_custody_cannot_pass_the_missing_ping_or_clear_liveness() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = LossFixture::new(kind).await?;
        let start = fixture.start;
        let mut copies = 0;
        let mut fault = |attempt: &Attempt| {
            if attempt.side == Side::A && matches!(attempt.traffic, Traffic::Source { id: 0, .. }) {
                copies += 1;
                copies == 1
            } else {
                false
            }
        };
        fixture.pump(start, &mut fault).await?;
        let b = fixture.driver(Side::B);
        assert_eq!(b.control.retained().receive_records, 1);
        assert_eq!(b.control.retained().receive_bytes, 88);
        assert_eq!(b.envelope_rx, 1);
        assert_eq!(b.remote_ping, 0);
        assert_eq!(
            b.challenge.as_ref().map(|challenge| challenge.nonce),
            Some(1)
        );
        fixture.pump(start + 5_000, &mut fault).await?;
        assert!(
            fixture
                .attempts
                .iter()
                .any(|attempt| attempt.side == Side::B
                    && matches!(
                        attempt.traffic,
                        Traffic::Ack {
                            prefix: 0,
                            bitmap: 2
                        }
                    ))
        );
        assert!(
            !fixture
                .driver_mut(Side::A)
                .control
                .legacy_mut()
                .ok_or("missing legacy control")?
                .source_confirmed(0, duration(start + 5_000))?
        );
        assert!(
            fixture
                .driver_mut(Side::A)
                .control
                .legacy_mut()
                .ok_or("missing legacy control")?
                .source_confirmed(1, duration(start + 5_000))?
        );
        assert!(fixture.driver(Side::B).challenge.is_some());
        fixture.pump(start + 200_000, &mut fault).await?;
        assert_eq!(
            fixture.driver(Side::B).control.retained().receive_records,
            0
        );
        assert_eq!(fixture.driver(Side::B).envelope_rx, 3);
        assert_eq!(fixture.driver(Side::B).remote_ping, 1);
        assert!(fixture.driver(Side::A).challenge.is_none());
        assert!(fixture.driver(Side::B).challenge.is_none());
        fixture.assert_same_sources(Side::A, 0)?;
    }
    Ok(())
}

#[tokio::test]
async fn four_lost_copies_recover_at_three_seconds_but_five_reach_the_original_timeout() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for lost in [4, 5] {
            let mut fixture = LossFixture::new(kind).await?;
            let start = fixture.start;
            let mut copies = 0;
            let mut fault = |attempt: &Attempt| {
                if attempt.side == Side::A
                    && matches!(
                        attempt.traffic,
                        Traffic::Source {
                            id: 0,
                            command: Command::Ping(1),
                            ..
                        }
                    )
                {
                    copies += 1;
                    copies <= lost
                } else {
                    false
                }
            };
            for offset in [
                0, 5_000, 199_999, 200_000, 205_000, 599_999, 600_000, 605_000, 1_399_999,
                1_400_000, 1_405_000, 2_999_999,
            ] {
                fixture.pump(start + offset, &mut fault).await?;
            }
            assert_eq!(fixture.sources(Side::A, 0).len(), 4);
            for side in [Side::A, Side::B] {
                assert_eq!(
                    fixture
                        .driver(side)
                        .challenge
                        .as_ref()
                        .map(|challenge| challenge.deadline),
                    Some(start + 5_000_000)
                );
            }
            fixture.pump(start + 3_000_000, &mut fault).await?;
            assert_eq!(
                fixture
                    .sources(Side::A, 0)
                    .iter()
                    .map(|attempt| attempt.at - start)
                    .collect::<Vec<_>>(),
                vec![0, 200_000, 600_000, 1_400_000, 3_000_000]
            );
            fixture.assert_same_sources(Side::A, 0)?;
            if lost == 4 {
                fixture.pump(start + 3_005_000, &mut fault).await?;
                for side in [Side::A, Side::B] {
                    assert!(fixture.driver(side).challenge.is_none());
                    assert_eq!(
                        fixture.driver(side).live.last_pong_micros,
                        Some(start + 3_000_000)
                    );
                    assert!(fixture.driver(side).control.drained());
                }
            } else {
                assert_eq!(
                    fixture.driver(Side::A).control.deadline(),
                    duration(start + 6_000_000)
                );
                for side in [Side::A, Side::B] {
                    fixture.fresh_user(side, start + 4_999_000).await?;
                }
                for side in [Side::A, Side::B] {
                    let driver = fixture.driver_mut(side);
                    assert_eq!(driver.live.last_verified_micros, Some(start + 4_999_000));
                    assert_eq!(
                        driver
                            .challenge
                            .as_ref()
                            .map(|challenge| challenge.deadline),
                        Some(start + 5_000_000)
                    );
                    assert!(driver.check_expiry(start + 4_999_999)?);
                    assert_eq!(
                        driver
                            .check_expiry(start + 5_000_000)
                            .err()
                            .map(|error| error.kind()),
                        Some(io::ErrorKind::TimedOut)
                    );
                    assert_eq!(driver.terminal, Some(StopReason::PeerTimeout));
                    assert!(driver.challenge.is_some());
                }
                assert_eq!(fixture.sources(Side::A, 0).len(), 5);
                assert!(
                    fixture
                        .sources(Side::A, 0)
                        .iter()
                        .all(|attempt| attempt.dropped)
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn lost_ack_retries_preserve_exact_control_and_never_repeat_ping_effects() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = LossFixture::new(kind).await?;
        let start = fixture.start;
        let mut dropped = false;
        let mut fault = |attempt: &Attempt| {
            if !dropped && attempt.side == Side::B && matches!(attempt.traffic, Traffic::Ack { .. })
            {
                dropped = true;
                true
            } else {
                false
            }
        };
        fixture.pump(start, &mut fault).await?;
        fixture.pump(start + 5_000, &mut fault).await?;
        let receive_number = fixture.driver(Side::B).envelope_rx;
        let send_number = fixture.driver(Side::B).control.legacy_next_sequence();
        let pong = fixture.driver(Side::B).live.last_pong_micros;
        assert!(fixture.driver(Side::A).challenge.is_none());
        assert_eq!(fixture.driver(Side::A).control.retained().send_records, 2);
        fixture.pump(start + 200_000, &mut fault).await?;
        assert_eq!(fixture.driver(Side::B).envelope_rx, receive_number);
        assert_eq!(
            fixture.driver(Side::B).control.legacy_next_sequence(),
            send_number
        );
        assert_eq!(fixture.driver(Side::B).remote_ping, 1);
        assert!(fixture.driver(Side::B).pong.is_none());
        assert_eq!(fixture.driver(Side::B).live.last_pong_micros, pong);
        fixture.pump(start + 205_000, &mut fault).await?;
        assert!(dropped);
        for side in [Side::A, Side::B] {
            assert!(fixture.driver(side).control.drained());
            assert!(fixture.driver(side).challenge.is_none());
        }
        for id in [0, 1] {
            assert_eq!(fixture.sources(Side::A, id).len(), 2);
            fixture.assert_same_sources(Side::A, id)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn refilling_shared_credit_preserves_control_attempts_and_reserve_under_queued_user_load()
-> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = LossFixture::new(kind).await?;
        let start = fixture.start;
        let a = fixture.driver_mut(Side::A);
        for number in 0..64 {
            assert_eq!(
                a.owner
                    .legacy_mut()?
                    .engine
                    .offer(start - 1_000, &ethernet(number))?,
                records::Admission::Accepted
            );
        }
        assert!(a.owner.legacy()?.engine.data_ready(start));
        a.bucket.tokens = 0;
        a.bucket.last = start;
        let mut fault = |_: &Attempt| true;
        assert!(fixture.turn(Side::A, start, &mut fault).await?.is_none());
        let reserve = fixture.driver(Side::A).reserve;
        let ready = fixture.driver(Side::A).bucket.ready_at(reserve)?;
        assert_eq!(fixture.driver(Side::A).control.retained().send_records, 1);
        assert!(
            fixture
                .turn(Side::A, ready - 1, &mut fault)
                .await?
                .is_none()
        );
        assert_eq!(
            fixture
                .driver(Side::A)
                .records
                .next_number(Class::Control)
                .0,
            0
        );
        assert_eq!(
            fixture.driver(Side::A).records.next_number(Class::User).0,
            0
        );
        let first = fixture
            .turn(Side::A, ready, &mut fault)
            .await?
            .ok_or_else(|| protocol("reserved control was not emitted"))?;
        assert!(matches!(
            fixture.attempts[first].traffic,
            Traffic::Source {
                id: 0,
                command: Command::Ping(1),
                ..
            }
        ));
        assert_eq!(fixture.attempts[first].at, ready);
        assert_eq!(
            fixture.attempts[first].wire_bytes,
            44 + 88 + fixture.driver(Side::A).config.control.wire_overhead
        );
        let a = fixture.driver(Side::A);
        let maximum = a
            .send
            .records
            .codec
            .datagram_bytes
            .max(a.receive.records.codec.datagram_bytes);
        let user_ready = a
            .bucket
            .ready_at(a.records.capacity(maximum)?.packet_bytes + a.ip + a.reserve)?;
        assert!(
            fixture
                .turn(Side::A, user_ready - 1, &mut fault)
                .await?
                .is_none()
        );
        let user = fixture
            .turn(Side::A, user_ready, &mut fault)
            .await?
            .ok_or_else(|| protocol("queued User was not emitted"))?;
        assert!(matches!(fixture.attempts[user].traffic, Traffic::User));
        assert!(fixture.driver(Side::A).bucket.allowance() >= reserve);
        assert_eq!(
            fixture
                .driver(Side::A)
                .owner
                .legacy()?
                .engine
                .stats()
                .sender
                .sources,
            1
        );
        let retry = fixture
            .turn(Side::A, ready + 200_000, &mut fault)
            .await?
            .ok_or_else(|| protocol("due control retry was starved by User load"))?;
        assert!(matches!(
            fixture.attempts[retry].traffic,
            Traffic::Source {
                id: 0,
                command: Command::Ping(1),
                ..
            }
        ));
        assert_eq!(fixture.sources(Side::A, 0).len(), 2);
        fixture.assert_same_sources(Side::A, 0)?;
        assert_eq!(fixture.driver(Side::A).counters.socket_drops, 0);
    }
    Ok(())
}
