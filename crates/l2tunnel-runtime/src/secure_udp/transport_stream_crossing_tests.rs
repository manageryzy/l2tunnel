//! Deterministic Driver-method crossing on real roots and original UDP sockets.
//!
//! Emissions are captured after actual socket handoff and delayed byte-exactly.
//! The work-one case pauses one real verified Pong at the production receive
//! prefix, before semantic presentation, to retain ready independent liveness.
//! This is not a full run-loop, native-device or privileged impairment fixture.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Logical {
    Profile {
        message: u64,
        command: swift::control::Message,
        scope: control::Scope,
    },
    Pong {
        nonce: u64,
    },
    Other,
}

fn logical(traffic: &Traffic) -> Result<Logical> {
    let Traffic::Source {
        kind: messages::FRAGMENT_KIND,
        payload,
        ..
    } = traffic
    else {
        return Ok(Logical::Other);
    };
    // The actual Swift envelope fits one unchanged LX fragment at this source
    // cap. Diagnose its exact wire bytes; this parser grants no authority.
    assert_eq!(&payload[1..5], b"LX\x01\x00");
    assert_eq!(u16::from_be_bytes(payload[33..35].try_into()?), 0);
    assert_eq!(u16::from_be_bytes(payload[35..37].try_into()?), 1);
    let bytes = &payload[1 + l2tunnel_codec::FRAGMENT_HEADER_BYTES..];
    assert_eq!(
        u32::from_be_bytes(payload[29..33].try_into()?) as usize,
        bytes.len()
    );
    assert_eq!(
        u16::from_be_bytes(payload[39..41].try_into()?) as usize,
        bytes.len()
    );
    let envelope = control::Envelope::decode(
        bytes,
        control::Limits {
            max_frame_bytes: 4096,
            max_management_bytes: mg::HEADER_LEN,
            max_feedback_bytes: 1,
        },
    )?;
    match envelope.body {
        control::Body::ProfileControl {
            tag: control::ProfileTag::SwiftPolicyV1,
            bytes,
        } => {
            let (command, used) =
                swift::control::Message::decode(bytes)?.ok_or("incomplete policy")?;
            assert_eq!(used, bytes.len());
            Ok(Logical::Profile {
                message: u64::from_be_bytes(payload[21..29].try_into()?),
                command,
                scope: envelope.binding.scope,
            })
        }
        control::Body::Pong { nonce } => Ok(Logical::Pong { nonce }),
        _ => Ok(Logical::Other),
    }
}

fn receipt(traffic: &Traffic) -> Result<Option<(u64, u64)>> {
    match traffic {
        Traffic::Source {
            stream: streams::Stream::Transaction,
            id,
            kind: messages::ACCEPTED_KIND,
            payload,
        } => {
            assert_eq!(payload.len(), 45);
            Ok(Some((*id, u64::from_be_bytes(payload[1..9].try_into()?))))
        }
        _ => Ok(None),
    }
}

fn second_policy() -> swift::control::Policy {
    swift::control::Policy {
        channels: 4,
        window: 16,
        repair_permille: 200,
        ..policy_value()
    }
}

fn crossing_resolver(configured: Config) -> Resolver {
    Box::new(move |requested| {
        let digest = if *requested == policy_value() {
            91
        } else if *requested == second_policy() {
            92
        } else {
            return None;
        };
        let mut direction = configured.send;
        direction.records.channels = usize::from(requested.channels);
        direction.records.codec.window = usize::from(requested.window);
        direction.records.codec.repair_numerator = u32::from(requested.repair_permille);
        direction.records.codec.repair_denominator = 1000;
        Some(policy::Resolved {
            send: direction,
            receive: direction,
            digest: policy::Digest([digest; 32]),
        })
    })
}

struct Flight {
    attempt: usize,
    wire: Vec<u8>,
}

struct Crossing {
    fixture: FaultFixture,
    final_message: Option<(u64, u64)>,
    receipts: Vec<Flight>,
    acknowledgments: Vec<Flight>,
    held_pong: Option<Flight>,
    capture_pong: bool,
    block_final: bool,
    next_proposal: bool,
    hold_next_proposal: bool,
    held_proposal: Option<Flight>,
    prepare_tiny_window: bool,
}

impl Crossing {
    async fn new(kind: cover::Appearance, work: usize) -> Result<owner::StateCell<Self>> {
        Self::with_receive_window(kind, work, 32, false).await
    }

    async fn with_receive_window(
        kind: cover::Appearance,
        work: usize,
        receive_records: usize,
        quiet_liveness: bool,
    ) -> Result<owner::StateCell<Self>> {
        let mut configured = config(kind);
        configured.policy.transaction_micros = 10_000_000;
        configured.lifetime.lease = Duration::from_secs(60);
        if quiet_liveness {
            configured.lifetime.ping_interval = Duration::from_secs(10);
        }
        configured.control.recovery.max_retries = 64;
        configured.control.recovery.receive_records = receive_records;
        configured.security.packets_per_key = 1024;
        configured.work.send_batch = 1;
        configured.report_interval = None;
        let mut configured = streamed(configured);
        for settings in &mut configured
            .streams
            .as_mut()
            .ok_or("missing streams")?
            .streams
        {
            settings.work_per_call = work;
        }
        let (a, b) = parts_pair(kind).await?;
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
            assert!(empty, "crossing setup input did not drain");
        }
        let start = add(clock(origin, setup_end)?, Duration::from_millis(20))?.max(1_000_000);
        // Return only the existing fallible cell header from setup. Keeping
        // this actual pair inline in its caller duplicates both Driver layouts
        // in async return/await storage during the real authentication phase.
        Ok(owner::StateCell::new(Self {
            fixture: FaultFixture {
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
            },
            final_message: None,
            receipts: Vec::new(),
            acknowledgments: Vec::new(),
            held_pong: None,
            capture_pong: false,
            block_final: true,
            next_proposal: false,
            hold_next_proposal: false,
            held_proposal: None,
            prepare_tiny_window: receive_records == 1,
        })?)
    }

    fn request(
        &mut self,
        now: u64,
        value: swift::control::Policy,
    ) -> Result<oneshot::Receiver<std::result::Result<u64, SwitchError>>> {
        let (reply, receiver) = oneshot::channel();
        let driver = &mut self.fixture.endpoints[0].driver;
        driver.request(now, value, reply, &crossing_resolver(driver.config))?;
        Ok(receiver)
    }

    async fn emit(&mut self, side: Side, now: u64) -> Result<Option<Flight>> {
        let (left, right) = self.fixture.endpoints.split_at_mut(1);
        let (from, to) = if side == Side::A {
            (&mut left[0], &mut right[0])
        } else {
            (&mut right[0], &mut left[0])
        };
        from.driver.progress(now)?;
        if self.prepare_tiny_window {
            // Match the real outer-loop service during setup. With a genuine
            // one-record receive window, ARQ work can expose a complete message
            // without another ingress; the final-custody cut disables this
            // preparation before asserting the explicit no-ingress turn.
            from.driver
                .service_control(now, &crossing_resolver(from.driver.config))?;
        }
        from.driver.submit_control(now)?;
        let before = from.driver.counters;
        from.driver
            .send(&from.socket, now, from.driver.origin + duration(now))?;
        let packets = from.driver.counters.wire_packets - before.wire_packets;
        if packets == 0 {
            return Ok(None);
        }
        assert_eq!(packets, 1);
        assert_eq!(
            from.driver.counters.socket_accepted_packets - before.socket_accepted_packets,
            1
        );
        let charge = usize::try_from(from.driver.counters.wire_bytes - before.wire_bytes)?;
        let is_control = from.driver.counters.control_number != before.control_number;
        let (number, traffic) = FaultFixture::describe(&from.driver, is_control, charge)?;
        let mut wire = vec![0; 1501];
        let length =
            tokio::time::timeout(Duration::from_secs(1), to.socket.recv(&mut wire)).await??;
        assert_eq!(length + from.driver.ip, charge);
        assert_eq!(&wire[..length], &from.driver.buffers.wire[..length]);
        wire.truncate(length);
        assert!(self.fixture.attempts.len() < 40_000);
        let attempt = self.fixture.attempts.len();
        self.fixture.attempts.push(Attempt {
            side,
            number,
            wire_bytes: charge,
            traffic,
            dropped: true,
        });
        Ok(Some(Flight { attempt, wire }))
    }

    fn deliver(&mut self, flight: Flight, now: u64) -> Result {
        let index = if self.fixture.attempts[flight.attempt].side == Side::A {
            1
        } else {
            0
        };
        let endpoint = &mut self.fixture.endpoints[index];
        if self.prepare_tiny_window {
            // Setup of the genuine one-record ARQ window performs bounded work
            // before another source arrives. Zero allowance cannot emit an
            // attempt or reserve a common packet number. The final-ingress test
            // disables this preparation before the event under test.
            for _ in 0..6 {
                assert!(
                    endpoint
                        .driver
                        .control
                        .poll(duration(now), 0, &mut endpoint.driver.buffers.control_wire)?
                        .is_none()
                );
                endpoint
                    .driver
                    .service_control(now, &crossing_resolver(endpoint.driver.config))?;
            }
        }
        assert!(endpoint.driver.check_expiry(now)?);
        endpoint.driver.receive(
            &flight.wire,
            now,
            endpoint.driver.origin + duration(now),
            &crossing_resolver(endpoint.driver.config),
        )?;
        endpoint.driver.collect_native(now)?;
        self.fixture.attempts[flight.attempt].dropped = false;
        Ok(())
    }

    async fn turn(&mut self, side: Side, now: u64) -> Result<bool> {
        let Some(flight) = self.emit(side, now).await? else {
            return Ok(false);
        };
        let attempt = &self.fixture.attempts[flight.attempt];
        let view = logical(&attempt.traffic)?;
        if side == Side::B
            && let Logical::Profile {
                message,
                command: swift::control::Message::BarrierAck { epoch: 1, .. },
                ..
            } = view
        {
            let Traffic::Source { id, .. } = attempt.traffic else {
                return Err("final policy did not use a real source".into());
            };
            match self.final_message {
                Some(original) => assert_eq!(original, (message, id)),
                None => self.final_message = Some((message, id)),
            }
        }
        if self.block_final && side == Side::A && self.final_message.is_some() {
            if receipt(&attempt.traffic)?.is_some_and(|(_, message)| {
                Some(message) == self.final_message.map(|value| value.0)
            }) {
                assert!(self.receipts.len() < 128);
                self.receipts.push(flight);
                return Ok(true);
            }
            if matches!(
                attempt.traffic,
                Traffic::Ack {
                    stream: streams::Stream::Transaction,
                    ..
                }
            ) {
                assert!(self.acknowledgments.len() < 128);
                self.acknowledgments.push(flight);
                return Ok(true);
            }
        }
        if side == Side::A
            && let Logical::Profile {
                command: swift::control::Message::Propose { epoch: 2, .. },
                scope,
                ..
            } = view
        {
            let Traffic::Source { id, .. } = attempt.traffic else {
                return Err("new policy did not use a real source".into());
            };
            let receipt_flight = self
                .receipts
                .first()
                .ok_or("new policy preceded retained final receipt")?;
            let (receipt_id, _) = receipt(&self.fixture.attempts[receipt_flight.attempt].traffic)?
                .ok_or("missing final receipt identity")?;
            assert_eq!(
                id,
                receipt_id + 1,
                "new command must sit directly behind the withheld semantic receipt"
            );
            assert_eq!(scope.epoch, core::Epoch(2));
            assert_eq!(scope.digest, core::ConfigDigest([91; 32]));
            self.next_proposal = true;
            if self.hold_next_proposal {
                assert!(self.held_proposal.is_none());
                self.held_proposal = Some(flight);
                return Ok(true);
            }
        }
        if self.capture_pong
            && side == Side::A
            && matches!(view, Logical::Pong { nonce } if self.fixture.endpoints[1].driver.challenge
                .as_ref().is_some_and(|challenge| challenge.submitted && challenge.nonce == nonce))
        {
            assert!(self.held_pong.is_none());
            self.held_pong = Some(flight);
            self.capture_pong = false;
            return Ok(true);
        }
        if self.prepare_tiny_window
            && self.held_pong.is_some()
            && side == Side::A
            && matches!(
                attempt.traffic,
                Traffic::Source {
                    stream: streams::Stream::Liveness,
                    ..
                } | Traffic::Ack {
                    stream: streams::Stream::Liveness,
                    ..
                }
            )
        {
            // Preserve the first matching Pong and its real pending challenge.
            // Further genuine Liveness attempts remain fault-dropped until the
            // exact held flight is verified at the final-custody cut.
            return Ok(true);
        }
        self.deliver(flight, now)?;
        Ok(true)
    }

    async fn pump(&mut self, now: u64, stop_on_pong: bool) -> Result {
        for _ in 0..64 {
            let a = self.turn(Side::A, now).await?;
            if stop_on_pong && self.held_pong.is_some() {
                return Ok(());
            }
            let b = self.turn(Side::B, now).await?;
            if !a && !b {
                return Ok(());
            }
        }
        Err("crossing per-time work exhausted".into())
    }

    fn pause_verified_pong(&mut self, flight: Flight, now: u64) -> Result<u64> {
        let attempt = &self.fixture.attempts[flight.attempt];
        assert_eq!(attempt.side, Side::A);
        let Logical::Pong { nonce } = logical(&attempt.traffic)? else {
            return Err("paused input is not Pong".into());
        };
        let driver = &mut self.fixture.endpoints[1].driver;
        let challenge = driver
            .challenge
            .as_ref()
            .ok_or("Pong has no actual challenge")?;
        assert_eq!(challenge.nonce, nonce);
        assert!(challenge.submitted && now < challenge.deadline);
        assert!(driver.check_expiry(now)?);
        // Pause exactly after the production Class::Control ingress prefix.
        // Do not call receive again: that would replay the same authenticated
        // datagram instead of resuming semantic presentation from held custody.
        driver.counters.received_packets = driver.counters.received_packets.saturating_add(1);
        let decoded = driver.cover.decode(&flight.wire)?;
        assert!(
            !driver
                .bootstrap
                .receive(decoded, driver.origin + duration(now))?
        );
        assert!(
            !driver
                .joining
                .receive(decoded, driver.origin + duration(now))?
        );
        let opened = driver.records.open(
            &flight.wire,
            &mut driver.buffers.open,
            &mut driver.buffers.plain,
        )?;
        assert_eq!(opened.class, Class::Control);
        assert_eq!(opened.number.0, attempt.number);
        assert_eq!(opened.scope, driver.records.control_scope());
        driver.live.last_verified_micros = Some(now);
        driver.control.receive(
            mg::Ingress::AuthenticatedManagement {
                session: mg::SessionId(driver.info.binding.session.0),
                lane: mg::LaneId(LANE),
                sender: driver.remote(),
            },
            &driver.buffers.plain[..opened.bytes],
            duration(now),
        )?;
        self.fixture.attempts[flight.attempt].dropped = false;
        Ok(nonce)
    }
}

async fn crossing(kind: cover::Appearance, work: usize, alignment: usize) -> Result {
    let mut storage = Crossing::new(kind, work).await?;
    let case = &mut *storage;
    let start = case.fixture.start;
    let mut first = case.request(start, policy_value())?;
    let first_deadline = case.fixture.endpoints[0]
        .driver
        .owner
        .legacy()?
        .coordinator
        .deadline()
        .ok_or("first cap")?;
    let mut applied_at = None;
    let mut prepared_at = None;
    for step in 0..2_000 {
        let now = start + step * 1_000;
        case.pump(now, false).await?;
        if applied_at.is_none() {
            match first.try_recv() {
                Ok(Ok(epoch)) => {
                    assert_eq!(epoch, 1);
                    applied_at = Some(now);
                }
                Ok(Err(error)) => return Err(format!("first policy failed: {error:?}").into()),
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let final_ack = case.final_message.is_some_and(|(_, source)| {
            case.acknowledgments.iter().any(|flight| {
                matches!(case.fixture.attempts[flight.attempt].traffic,
                Traffic::Ack { stream: streams::Stream::Transaction, prefix } if prefix > source)
            })
        });
        if applied_at.is_some() && !case.receipts.is_empty() && final_ack {
            prepared_at = Some(now);
            break;
        }
    }
    let first_applied = applied_at.ok_or("first policy never completed locally")?;
    let prepared_at =
        prepared_at.ok_or("completed first policy did not emit its retained receipts")?;
    assert!(first_applied < first_deadline.0);
    assert!(!case.receipts.is_empty() && !case.acknowledgments.is_empty());
    let first_scope = record::Scope {
        epoch: security::Epoch(2),
        configuration: security::ConfigDigest([91; 32]),
    };
    assert_eq!(
        case.fixture.endpoints[0].driver.records.active_data(),
        first_scope
    );
    let old_cap = case.fixture.endpoints[1]
        .driver
        .policy_cap
        .ok_or("follower lost first custody cap")?;
    assert!(case.fixture.endpoints[1].driver.policy_source.is_some());
    assert_eq!(
        case.fixture.endpoints[1]
            .driver
            .owner
            .legacy()?
            .coordinator
            .committed()
            .epoch,
        policy::Epoch(0)
    );

    let second_start = prepared_at + 1_000;
    let mut second = case.request(second_start, second_policy())?;
    let second_deadline = case.fixture.endpoints[0]
        .driver
        .owner
        .legacy()?
        .coordinator
        .deadline()
        .ok_or("second cap")?;
    case.capture_pong = true;
    let mut crossing_at = None;
    for step in 0..500 {
        let now = second_start + step * 1_000;
        case.pump(now, true).await?;
        if case.held_pong.is_some() && case.next_proposal {
            crossing_at = Some(now);
            break;
        }
    }
    let now = crossing_at.ok_or("new proposal and independent matching Pong were not captured")?;
    assert!(now < old_cap && now < second_deadline.0);
    assert_eq!(case.fixture.endpoints[1].driver.policy_cap, Some(old_cap));
    assert_eq!(case.fixture.endpoints[1].driver.target, Some(first_scope));
    assert_ne!(
        case.fixture.endpoints[1].driver.records.active_data(),
        first_scope
    );
    assert!(matches!(
        second.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let acknowledgement = case
        .acknowledgments
        .pop()
        .ok_or("missing actual source ACK")?;
    let (_, final_source) = case.final_message.ok_or("missing final output identity")?;
    assert!(
        matches!(case.fixture.attempts[acknowledgement.attempt].traffic,
        Traffic::Ack { stream: streams::Stream::Transaction, prefix } if prefix > final_source)
    );
    case.deliver(acknowledgement, now)?;
    let pong = case.held_pong.take().ok_or("missing captured Pong")?;
    let pong_nonce = if work == 1 {
        let nonce = case.pause_verified_pong(pong, now)?;
        // Complete only bounded transport work, without dispatching the pending
        // matching Pong. Different alignments exercise all work-one phase slots.
        for _ in 0..6 + alignment {
            case.fixture.endpoints[1].driver.progress(now)?;
        }
        assert_eq!(
            case.fixture.endpoints[1].driver.live.outstanding,
            Some(nonce)
        );
        Some(nonce)
    } else {
        case.deliver(pong, now)?;
        None
    };
    let previous_receipt = case
        .receipts
        .pop()
        .ok_or("missing actual whole Accepted receipt")?;
    assert!(case.next_proposal);
    // Receipt N follows the already received new-origin fragment N+1. Its real
    // source ACK and complete acceptance must settle old policy before the next
    // envelope can acquire scope admission; a staged reader is not authority.
    case.deliver(previous_receipt, now)?;
    case.block_final = false;
    let mut completed = None;
    for step in 0..3_000 {
        let at = now + step * 1_000;
        case.pump(at, false).await?;
        if let Some(nonce) = pong_nonce {
            assert_ne!(
                case.fixture.endpoints[1].driver.live.outstanding,
                Some(nonce),
                "held matching Pong did not progress during crossing"
            );
        }
        match second.try_recv() {
            Ok(Ok(epoch)) => {
                assert_eq!(epoch, 2);
                completed = Some(at);
            }
            Ok(Err(error)) => return Err(format!("second policy failed: {error:?}").into()),
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(oneshot::error::TryRecvError::Closed) if completed.is_some() => {}
            Err(error) => return Err(error.into()),
        }
        if completed.is_some()
            && case
                .fixture
                .endpoints
                .iter()
                .try_fold(true, |settled, endpoint| {
                    Ok::<_, io::Error>(
                        settled
                            && endpoint
                                .driver
                                .owner
                                .legacy()?
                                .coordinator
                                .committed()
                                .epoch
                                == policy::Epoch(2)
                            && endpoint
                                .driver
                                .owner
                                .legacy()?
                                .coordinator
                                .pending()
                                .is_none()
                            && endpoint.driver.policy_source.is_none()
                            && endpoint.driver.target.is_none(),
                    )
                })?
        {
            assert!(at < second_deadline.0);
            let final_scope = record::Scope {
                epoch: security::Epoch(3),
                configuration: security::ConfigDigest([92; 32]),
            };
            for endpoint in &case.fixture.endpoints {
                assert_eq!(endpoint.driver.records.active_data(), final_scope);
                assert!(endpoint.driver.records.additional_data().is_none());
                assert_eq!(endpoint.driver.source_scope, final_scope);
                assert_eq!(endpoint.driver.feedback_scope, final_scope);
                assert_eq!(endpoint.driver.send.records.channels, 4);
                assert_eq!(endpoint.driver.receive.records.channels, 4);
                assert!(endpoint.driver.policy_cap.is_none());
                assert!(endpoint.driver.live.last_pong_micros.is_some());
                assert!(endpoint.driver.terminal.is_none());
            }
            case.fixture.accounting(at)?;
            return Ok(());
        }
    }
    Err("back-to-back policies failed to settle within their original caps".into())
}

#[tokio::test]
async fn whole_receipt_reordered_behind_next_origin_settles_before_gate_on_both_covers() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        crossing(kind, 8, 0).await?;
        for alignment in 0..3 {
            crossing(kind, 1, alignment).await?;
        }
    }
    Ok(())
}

async fn no_ingress_after_final_custody(kind: cover::Appearance, alignment: usize) -> Result<bool> {
    let mut storage = Crossing::with_receive_window(kind, 1, 1, false).await?;
    let case = &mut *storage;
    case.capture_pong = true;
    let start = case.fixture.start;
    let mut first = case.request(start, policy_value())?;
    let mut applied = false;
    let mut prepared = None;
    for step in 0..2_000 {
        let now = start + step * 1_000;
        case.pump(now, false).await?;
        if !applied {
            match first.try_recv() {
                Ok(Ok(epoch)) => {
                    assert_eq!(epoch, 1);
                    applied = true;
                }
                Ok(Err(error)) => return Err(format!("tiny-window first policy: {error:?}").into()),
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let acknowledged_final = case.final_message.is_some_and(|(_, source)| {
            case.acknowledgments.iter().any(|flight| {
                matches!(
                case.fixture.attempts[flight.attempt].traffic,
                Traffic::Ack { stream: streams::Stream::Transaction, prefix } if prefix > source)
            })
        });
        if applied && !case.receipts.is_empty() && acknowledged_final && case.held_pong.is_some() {
            prepared = Some(now);
            break;
        }
    }
    let a = &case.fixture.endpoints[0].driver;
    let b = &case.fixture.endpoints[1].driver;
    let a_legacy = a.owner.legacy()?;
    let b_legacy = b.owner.legacy()?;
    let prepared = prepared.ok_or_else(|| {
        format!(
            "tiny-window first custody was not retained: applied={applied}, final={:?}, receipts={}, acks={}, a_committed={:?}, b_committed={:?}, a_pending={:?}, b_pending={:?}, a_control={:?}, b_control={:?}",
            case.final_message,
            case.receipts.len(),
            case.acknowledgments.len(),
            a_legacy.coordinator.committed(),
            b_legacy.coordinator.committed(),
            a_legacy.coordinator.pending(),
            b_legacy.coordinator.pending(),
            a.control.retained(),
            b.control.retained(),
        )
    })?;
    let next_at = prepared + 1_000;
    let mut second = case.request(next_at, second_policy())?;
    case.hold_next_proposal = true;
    let mut captured_at = None;
    'capture: for step in 0..500 {
        let now = next_at + step * 1_000;
        for _ in 0..64 {
            let a = case.turn(Side::A, now).await?;
            if case.held_proposal.is_some() {
                captured_at = Some(now);
                break 'capture;
            }
            let b = case.turn(Side::B, now).await?;
            if !a && !b {
                break;
            }
        }
    }
    let now = captured_at.ok_or("tiny-window next proposal was not emitted")?;
    let old_cap = case.fixture.endpoints[1]
        .driver
        .policy_cap
        .ok_or("missing old cap")?;
    let old_scope = case.fixture.endpoints[1].driver.records.active_data();
    let first_scope = record::Scope {
        epoch: security::Epoch(2),
        configuration: security::ConfigDigest([91; 32]),
    };
    assert_ne!(old_scope, first_scope);
    assert_eq!(
        case.fixture.endpoints[1]
            .driver
            .config
            .control
            .recovery
            .receive_records,
        1
    );
    let proposal = case
        .held_proposal
        .take()
        .ok_or("missing exact proposal wire")?;
    let Logical::Profile {
        message,
        command: swift::control::Message::Propose { epoch: 2, .. },
        ..
    } = logical(&case.fixture.attempts[proposal.attempt].traffic)?
    else {
        return Err("captured command is not the second proposal".into());
    };

    // Window one cannot accept source N+1 before N. Deliver the real whole
    // receipt first while withholding the independent ACK for the old final
    // output. The new-origin message can now reassemble legally and remain
    // deferred, without granting a staged reader management authority.
    let accepted = case.receipts.pop().ok_or("missing final whole receipt")?;
    case.deliver(accepted, now)?;
    case.deliver(proposal, now)?;
    {
        let driver = &mut case.fixture.endpoints[1].driver;
        for _ in 0..6 + alignment {
            driver.progress(now)?;
        }
        assert_eq!(driver.policy_cap, Some(old_cap));
        assert_eq!(driver.target, Some(first_scope));
        assert_eq!(driver.records.active_data(), old_scope);
        assert!(driver.control.ready_for_dispatch(None)?);
        assert!(
            !driver
                .control
                .ready_for_dispatch(driver.target.map(envelope_scope))?
        );
    }

    let acknowledgment = case
        .acknowledgments
        .pop()
        .ok_or("missing final source ACK")?;
    let (_, final_source) = case.final_message.ok_or("missing final source")?;
    assert!(
        matches!(case.fixture.attempts[acknowledgment.attempt].traffic,
        Traffic::Ack { stream: streams::Stream::Transaction, prefix } if prefix > final_source)
    );
    let pong = case.held_pong.take().ok_or("missing real matching Pong")?;
    case.prepare_tiny_window = false;
    let nonce = case.pause_verified_pong(pong, now)?;
    for _ in 0..6 + alignment {
        case.fixture.endpoints[1].driver.progress(now)?;
    }
    assert_eq!(
        case.fixture.endpoints[1].driver.live.outstanding,
        Some(nonce)
    );
    // This is the final UDP ingress delivered to B. The former code could use
    // its sole semantic-loop slot for the real matching Pong after settling
    // the old target, leaving the complete next command without a trigger.
    case.deliver(acknowledgment, now)?;
    let driver = &mut case.fixture.endpoints[1].driver;
    let ingress = driver.counters.received_packets;
    assert_ne!(driver.live.outstanding, Some(nonce));
    assert_eq!(driver.live.last_pong_micros, Some(now));
    let waited = driver.owner.legacy()?.coordinator.pending().is_none();
    if waited {
        assert_eq!(
            driver.owner.legacy()?.coordinator.committed().epoch,
            policy::Epoch(1)
        );
        assert!(driver.target.is_none());
        assert_eq!(driver.records.active_data(), first_scope);
        assert!(driver.control.ready_for_dispatch(None)?);
        assert!(driver.control_work);
    }
    // One bounded outer-loop service must make progress without a new network
    // packet. Repeated empty turns must neither redispatch nor renew this lease.
    driver.service_control(now, &crossing_resolver(driver.config))?;
    let pending = driver
        .owner
        .legacy()?
        .coordinator
        .pending()
        .ok_or("ready command stalled without further ingress")?;
    assert_eq!(pending.epoch, policy::Epoch(2));
    assert_eq!(pending.policy, second_policy());
    let cap = driver
        .policy_cap
        .ok_or("new operation has no original cap")?;
    for _ in 0..8 {
        driver.service_control(now, &crossing_resolver(driver.config))?;
        assert_eq!(driver.counters.received_packets, ingress);
        assert_eq!(driver.policy_cap, Some(cap));
        assert_eq!(
            driver
                .owner
                .legacy()?
                .coordinator
                .outstanding()
                .filter(|output| matches!(
                    output.message,
                    swift::control::Message::Accept { epoch: 2, .. }
                ))
                .count(),
            1
        );
    }

    let mut receipt_sources = std::collections::BTreeSet::new();
    let mut last = now;
    for step in 0..64 {
        let at = now + step * 1_000;
        let driver = &mut case.fixture.endpoints[1].driver;
        driver.service_control(at, &crossing_resolver(driver.config))?;
        assert_eq!(driver.counters.received_packets, ingress);
        if let Some(flight) = case.emit(Side::B, at).await?
            && let Some((source, accepted_message)) =
                receipt(&case.fixture.attempts[flight.attempt].traffic)?
            && accepted_message == message
        {
            receipt_sources.insert(source);
        }
        assert!(matches!(
            second.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        last = at;
    }
    assert_eq!(
        receipt_sources.len(),
        1,
        "semantic acceptance was absent or queued more than once"
    );
    let driver = &case.fixture.endpoints[1].driver;
    assert_eq!(driver.counters.received_packets, ingress);
    assert_eq!(driver.policy_cap, Some(cap));
    assert_eq!(
        driver
            .owner
            .legacy()?
            .coordinator
            .pending()
            .ok_or("unconfirmed second policy vanished")?
            .epoch,
        policy::Epoch(2)
    );
    assert!(driver.terminal.is_none());
    case.fixture.accounting(last)?;
    Ok(waited)
}

#[tokio::test]
async fn ready_next_policy_is_serviced_once_without_another_udp_ingress() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut observed_deferred = false;
        for alignment in 0..3 {
            observed_deferred |= no_ingress_after_final_custody(kind, alignment).await?;
        }
        assert!(
            observed_deferred,
            "fixture never exhausted the sole semantic slot at final custody"
        );
    }
    Ok(())
}
