//! Deterministic faults after actual protected original-UDP handoff.
//!
//! Sender plaintext is diagnostic only. A dropped packet never opens through
//! the actual destination Records. Native counts come from real device writes.

use super::*;
use l2tunnel_codec::{FragmentContext, Reassembler, ReassemblyConfig, ReassemblyStatus};
use mg::{control_streams as streams, session_control as sc};

const TRACE_LIMIT: usize = 20_000;
const HOLD_LIMIT: usize = 128;
const TURN_LIMIT: usize = 3000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route {
    Deliver,
    Drop,
    Hold(u8),
}

#[derive(Clone, Debug)]
enum Traffic {
    User {
        feedback: bool,
        repair: bool,
    },
    Source {
        stream: streams::Stream,
        id: u64,
        payload: Vec<u8>,
    },
    Ack {
        stream: streams::Stream,
    },
}

#[derive(Clone, Debug)]
struct Flight {
    from: usize,
    number: security::PacketNumber,
    wire_bytes: usize,
    wire: Vec<u8>,
    traffic: Traffic,
    phases: [transaction::Phase; 2],
}

impl Flight {
    fn transaction_ack(&self) -> bool {
        matches!(
            self.traffic,
            Traffic::Ack {
                stream: streams::Stream::Transaction,
                ..
            }
        )
    }
    fn transaction_fragment(&self) -> bool {
        matches!(&self.traffic, Traffic::Source { stream: streams::Stream::Transaction, payload, .. }
            if payload.first() == Some(&messages::FRAGMENT_KIND))
    }
}

struct ObservedMessage {
    from: usize,
    message: u64,
    kind: mg::MessageKind,
    bytes: Vec<u8>,
}

struct Attempt {
    flight: Flight,
    route: Route,
}

struct Preview {
    target: usize,
    bytes: Vec<u8>,
    preparation: bool,
}

struct FaultFixture {
    inner: Fixture,
    held: Vec<(u8, Flight)>,
    attempts: Vec<Attempt>,
    assemblers: [Option<Reassembler>; 2],
    messages: Vec<ObservedMessage>,
    previews: Vec<Preview>,
    turns: usize,
}

fn state(driver: &Driver) -> Result<&transactions::State> {
    match &driver.owner {
        owner::DataOwner::Generic(state) => Ok(state),
        owner::DataOwner::Legacy(_) => Err("fault fixture selected legacy State".into()),
        owner::DataOwner::Common(_) => Err("fault fixture selected Common State".into()),
    }
}

fn fault_contracts(kind: cover::Appearance, pressure: bool) -> Result<[TransactionContract; 2]> {
    let original = contracts(kind)?;
    let make = |prior: &TransactionContract| -> Result<TransactionContract> {
        let mut config = prior.config();
        config.work.send_batch = 1;
        // Commit and Retire each occupy two real LX sources. Keeping both
        // plus the genuine CommitAck Accepted receipt requires five slots.
        let records = if pressure { 5 } else { 32 };
        config.control.recovery.send_records = records;
        config.control.recovery.receive_records = records;
        config.control.recovery.send_bytes = records * config.control.recovery.max_source_bytes;
        config.control.recovery.receive_bytes = records * config.control.recovery.max_source_bytes;
        let streams = config
            .streams
            .as_mut()
            .ok_or("fault fixture missing streams")?;
        for entry in &mut streams.streams {
            entry.delivery = delivery::Settings {
                wire_overhead: config.control.wire_overhead + streams::HEADER_BYTES,
                ..config.control
            };
        }
        Ok(TransactionContract::new(
            prior.expected_configuration(),
            prior.role(),
            config,
            prior.cover(),
            prior.ipv6(),
            prior.envelope(),
            prior.catalog().clone(),
            prior.settings(),
        )?)
    };
    Ok([make(&original[0])?, make(&original[1])?])
}

fn sender_stats(driver: &Driver) -> Result<swift::SenderStats> {
    let mut total = swift::SenderStats::default();
    for epoch in driver.transaction_epochs().into_iter().flatten() {
        total.add(&driver.owner.engine(epoch)?.stats().sender);
    }
    Ok(total)
}

fn large_channel_packet(channel: usize, width: usize, marker: u8) -> Result<Vec<u8>> {
    let mut bytes = channel_packet(channel, width, marker)?;
    bytes.resize(512, marker);
    let ip = &mut bytes[14..];
    ip[2..4].copy_from_slice(&498_u16.to_be_bytes());
    ip[10..12].fill(0);
    ip[24..26].copy_from_slice(&478_u16.to_be_bytes());
    let sum: u32 = ip[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    assert_eq!(swift::flow::classify_ethernet(&bytes, width), channel);
    Ok(bytes)
}

impl FaultFixture {
    fn diagnostic(&self) -> Result<String> {
        let mut values = Vec::with_capacity(2);
        for endpoint in &self.inner.endpoints {
            let driver = &endpoint.driver;
            let actual = state(driver)?;
            values.push(format!(
                "phase={:?}, operation={:?}, custody={:?}, recovery={:?}, dispatched={}, outcome={}, sender={:?}",
                actual.peer().phase(), actual.peer().operation(), actual.output_custody_for_test(),
                driver.control.retained(), driver.control.has_dispatched(),
                driver.generic.as_ref().is_some_and(|runtime| runtime.outcome.is_some()),
                sender_stats(driver)?,
            ));
        }
        Ok(format!(
            "now={} turns={} sides={values:?} messages={:?}",
            self.inner.now,
            self.turns,
            self.messages
                .iter()
                .map(|message| (message.from, message.message, message.kind))
                .collect::<Vec<_>>()
        ) + &format!(
            " previews={} recent_transaction={:?}",
            self.previews.len(),
            self.attempts
                .iter()
                .rev()
                .filter_map(|attempt| {
                    match &attempt.flight.traffic {
                        Traffic::Source {
                            stream: streams::Stream::Transaction,
                            id,
                            payload,
                        } => Some((
                            attempt.flight.from,
                            *id,
                            payload.first().copied(),
                            payload.len(),
                            attempt.route,
                        )),
                        _ => None,
                    }
                })
                .take(12)
                .collect::<Vec<_>>()
        ))
    }
    async fn new(kind: cover::Appearance, pressure: bool) -> Result<Self> {
        Ok(Self {
            inner: Fixture::from_contracts(kind, fault_contracts(kind, pressure)?).await?,
            held: Vec::new(),
            attempts: Vec::new(),
            assemblers: [None, None],
            messages: Vec::new(),
            previews: Vec::new(),
            turns: 0,
        })
    }

    fn describe(
        driver: &Driver,
        before: Counters,
        cost: usize,
        feedback: bool,
        repair: bool,
    ) -> Result<(security::PacketNumber, Traffic)> {
        if driver.counters.control_number == before.control_number {
            let number = driver
                .counters
                .user_number
                .ok_or("missing actual User number")?;
            return Ok((number, Traffic::User { feedback, repair }));
        }
        let number = driver
            .counters
            .control_number
            .ok_or("missing actual Control number")?;
        let length = cost
            .checked_sub(driver.config.control.wire_overhead)
            .ok_or("control cost underflow")?;
        let wrapped = streams::Frame::decode(
            driver
                .buffers
                .control_wire
                .get(..length)
                .ok_or("control capture extent")?,
            streams::Limits {
                max_packet_bytes: driver.config.control.recovery.max_source_bytes
                    + recovery::DATA_HEADER_BYTES,
            },
        )?;
        let derived = streams::delivery_binding(
            delivery::Binding {
                session: mg::SessionId(driver.info.binding.session.0),
                lane: mg::LaneId(LANE),
                local_role: driver.role(),
                control_epoch: driver.config.control_epoch.0,
            },
            wrapped.stream,
        )?;
        let packet = recovery::inspect_packet(
            wrapped.packet,
            recovery::RecoveryContext {
                session: u128::from_be_bytes(driver.info.binding.session.0),
                epoch: derived.control_epoch,
                role: if driver.info.role == security::Role::Initiator {
                    recovery::EndpointRole::Responder
                } else {
                    recovery::EndpointRole::Initiator
                },
            },
            driver.config.control.recovery.max_source_bytes,
        )?;
        let traffic = match packet {
            recovery::PacketView::Data { source, payload } => Traffic::Source {
                stream: wrapped.stream,
                id: source.0,
                payload: payload.to_vec(),
            },
            recovery::PacketView::Ack { .. } => Traffic::Ack {
                stream: wrapped.stream,
            },
        };
        Ok((number, traffic))
    }

    fn observe_message(&mut self, flight: &Flight) -> Result {
        let Traffic::Source {
            stream: streams::Stream::Transaction,
            payload,
            ..
        } = &flight.traffic
        else {
            return Ok(());
        };
        if payload.first() != Some(&messages::FRAGMENT_KIND) {
            return Ok(());
        }
        let fragment = payload.get(1..).ok_or("empty LX source")?;
        if self.assemblers[flight.from].is_none() {
            let session = u64::from_be_bytes(fragment.get(4..12).ok_or("LX session")?.try_into()?);
            let epoch = u64::from_be_bytes(fragment.get(12..20).ok_or("LX epoch")?.try_into()?);
            self.assemblers[flight.from] = Some(Reassembler::new(
                FragmentContext {
                    session: l2tunnel_codec::SessionId(session),
                    epoch: core::Epoch(epoch),
                },
                ReassemblyConfig {
                    max_message_bytes: 4096,
                    max_messages: 4,
                    max_fragment_payload_bytes: 151,
                    max_fragments_per_message: 32,
                    max_total_fragments: 128,
                    max_reserved_bytes: 16_384,
                    max_lifetime_ticks: 5_000_000,
                    replay_window: 64,
                },
            )?);
        }
        let mut output = [0; 4096];
        let assembler = self.assemblers[flight.from]
            .as_mut()
            .ok_or("diagnostic assembler absent")?;
        if let ReassemblyStatus::Complete { message, length } =
            assembler.accept(fragment, self.inner.now, &mut output)?
        {
            let envelope = sc::Envelope::decode(
                &output[..length],
                sc::Limits {
                    max_frame_bytes: 4096,
                    max_management_bytes: 4096 - sc::HEADER_BYTES,
                    max_feedback_bytes: 1,
                },
            )?;
            let sc::Body::Management(bytes) = envelope.body else {
                return Err("nonmanagement Transaction emission".into());
            };
            let kind = mg::Frame::decode(bytes, mg::Limits::default())?.header.kind;
            assert!(
                self.messages.len() < 64,
                "diagnostic message ledger exhausted"
            );
            self.messages.push(ObservedMessage {
                from: flight.from,
                message: message.0,
                kind,
                bytes: output[..length].to_vec(),
            });
        }
        Ok(())
    }

    async fn turn(&mut self, mut route: impl FnMut(&Flight) -> Route) -> Result {
        assert!(self.turns < TURN_LIMIT, "fault fixture turn limit");
        self.turns += 1;
        self.inner.now = self
            .inner
            .now
            .checked_add(1000)
            .ok_or("fault fixture clock overflow")?;
        let now = self.inner.now;
        for side in 0..2 {
            let emitted = {
                let endpoint = &mut self.inner.endpoints[side];
                assert!(endpoint.driver.check_expiry(now)?);
                endpoint.driver.admit_transaction(|| Ok(duration(now)))?;
                endpoint.driver.collect_native(now)?;
                endpoint.driver.progress_transaction(now)?;
                endpoint.driver.report_transaction_completion(
                    || Ok(now),
                    |driver, at| {
                        driver.snapshot_transaction(at, true)?;
                        Ok(())
                    },
                )?;
                endpoint.driver.service_selected_control(now, None)?;
                endpoint.driver.submit_control(now)?;
                let before = endpoint.driver.counters;
                let sender_before = sender_stats(&endpoint.driver)?;
                let feedback_before = endpoint.driver.performance.counters.feedback_packets;
                endpoint.driver.send(
                    &endpoint.socket,
                    now,
                    endpoint.driver.origin + duration(now),
                )?;
                let packets = endpoint.driver.counters.wire_packets - before.wire_packets;
                assert!(packets <= 1);
                assert_eq!(
                    packets,
                    endpoint.driver.counters.socket_accepted_packets
                        - before.socket_accepted_packets
                );
                assert_eq!(endpoint.driver.counters.socket_drops, 0);
                if packets == 0 {
                    None
                } else {
                    let cost =
                        usize::try_from(endpoint.driver.counters.wire_bytes - before.wire_bytes)?;
                    assert_eq!(
                        cost as u64,
                        endpoint.driver.counters.socket_accepted_ip_bytes
                            - before.socket_accepted_ip_bytes
                    );
                    let (number, traffic) = Self::describe(
                        &endpoint.driver,
                        before,
                        cost,
                        endpoint.driver.performance.counters.feedback_packets != feedback_before,
                        {
                            let after = sender_stats(&endpoint.driver)?;
                            after.repairs > sender_before.repairs
                                || after.tail_repairs > sender_before.tail_repairs
                        },
                    )?;
                    Some((number, traffic, cost))
                }
            };
            let Some((number, traffic, cost)) = emitted else {
                continue;
            };
            let mut wire = [0; 1501];
            let target = &self.inner.endpoints[1 - side];
            let length =
                tokio::time::timeout(Duration::from_secs(1), target.socket.recv(&mut wire))
                    .await??;
            let sender = &self.inner.endpoints[side];
            assert_eq!(length + sender.driver.ip, cost);
            assert_eq!(&wire[..length], &sender.driver.buffers.wire[..length]);
            let phases = [
                state(&self.inner.endpoints[0].driver)?.peer().phase(),
                state(&self.inner.endpoints[1].driver)?.peer().phase(),
            ];
            let flight = Flight {
                from: side,
                number,
                wire_bytes: cost,
                wire: wire[..length].to_vec(),
                traffic,
                phases,
            };
            self.observe_message(&flight)?;
            let selected = route(&flight);
            match selected {
                Route::Deliver => self.deliver(&flight)?,
                Route::Drop => {}
                Route::Hold(tag) => {
                    assert!(self.held.len() < HOLD_LIMIT, "held flight limit");
                    self.held.push((tag, flight.clone()));
                }
            }
            assert!(
                self.attempts.len() < TRACE_LIMIT,
                "actual attempt ledger exhausted"
            );
            self.attempts.push(Attempt {
                flight,
                route: selected,
            });
        }
        for endpoint in &mut self.inner.endpoints {
            endpoint.driver.collect_native(now)?;
            for _ in 0..endpoint.driver.config.work.native_write_batch {
                if endpoint.driver.native.is_empty() {
                    break;
                }
                let mut ready = tokio::time::timeout(
                    Duration::from_secs(1),
                    endpoint.device.ready_mut(Interest::WRITABLE),
                )
                .await??;
                if !endpoint.driver.write_native(&mut ready, || Ok(now))? {
                    break;
                }
            }
            endpoint.driver.progress_transaction(now)?;
            assert_eq!(
                (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                endpoint.original
            );
        }
        Ok(())
    }

    fn deliver(&mut self, flight: &Flight) -> Result {
        let now = self.inner.now;
        let target = &mut self.inner.endpoints[1 - flight.from];
        let before = target.driver.counters.socket_accepted_packets;
        target.driver.receive_selected(
            &flight.wire,
            now,
            target.driver.origin + duration(now),
            None,
        )?;
        assert_eq!(target.driver.counters.socket_accepted_packets, before);
        // A real side0 ingress can become complete immediately before side1's
        // production admit prefix consumes it in this same turn. Observe the
        // immutable joint preview here, never mutate/ACK/dispatch on its behalf.
        let preview = if target.driver.info.role == security::Role::Responder
            && target
                .driver
                .generic
                .as_ref()
                .is_some_and(|runtime| runtime.outcome.is_some())
            && state(&target.driver)?.peer().phase() == transaction::Phase::Idle
            && let Some(operation) = state(&target.driver)?.peer().operation()
        {
            target
                .driver
                .control
                .preview_transaction(
                    state(&target.driver)?.peer(),
                    duration(now),
                    operation.expires(),
                )?
                .map(|view| Preview {
                    target: 1 - flight.from,
                    bytes: view.envelope().to_vec(),
                    preparation: view.preparation().is_some(),
                })
        } else {
            None
        };
        if let Some(preview) = preview {
            assert!(
                self.previews.len() < 64,
                "bounded cached preview ledger exhausted"
            );
            self.previews.push(preview);
        }
        Ok(())
    }

    fn release(&mut self, tag: u8, reverse: bool) -> Result<usize> {
        let mut selected = Vec::new();
        let mut retained = Vec::new();
        for (held_tag, flight) in self.held.drain(..) {
            if held_tag == tag {
                selected.push(flight);
            } else {
                retained.push((held_tag, flight));
            }
        }
        self.held = retained;
        if reverse {
            selected.reverse();
        }
        let count = selected.len();
        for flight in selected {
            self.deliver(&flight)?;
        }
        Ok(count)
    }

    fn replay(&mut self, captured: &Flight) -> Result {
        self.deliver(captured)
    }

    fn start_switch(
        &mut self,
    ) -> Result<(
        C,
        oneshot::Receiver<std::result::Result<core::Epoch, SwitchError>>,
    )> {
        let driver = &mut self.inner.endpoints[0].driver;
        let contract = &driver
            .generic
            .as_ref()
            .ok_or("missing generic contract")?
            .contract;
        let descriptor = contract
            .catalog()
            .descriptors()
            .iter()
            .copied()
            .find(|value| *value != contract.catalog().initial())
            .ok_or("missing supported target")?;
        let target = C::new(contract.envelope(), descriptor)?;
        let (reply, result) = oneshot::channel();
        driver.request_transaction(self.inner.now, target, reply)?;
        Ok((target, result))
    }

    async fn settle(
        &mut self,
        reply: &mut oneshot::Receiver<std::result::Result<core::Epoch, SwitchError>>,
    ) -> Result<core::Epoch> {
        let mut answer = None;
        for _ in 0..1200 {
            self.turn(|_| Route::Deliver).await?;
            if answer.is_none() {
                match reply.try_recv() {
                    Ok(value) => {
                        answer = Some(value.map_err(|error| {
                            io::Error::other(format!("fault switch: {error:?}"))
                        })?)
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if answer.is_some()
                && self.inner.endpoints.iter().all(|endpoint| {
                    state(&endpoint.driver).is_ok_and(|state| {
                        state.peer().operation().is_none() && state.can_admit_data()
                    }) && endpoint.driver.records.additional_data().is_none()
                })
            {
                return answer.ok_or_else(|| "settled switch lost answer".into());
            }
        }
        Err("genuine final proofs did not settle in bounded turns".into())
    }

    fn accounting(&self) -> Result {
        for side in 0..2 {
            let driver = &self.inner.endpoints[side].driver;
            let rows: Vec<_> = self
                .attempts
                .iter()
                .filter(|attempt| attempt.flight.from == side)
                .collect();
            let captured_bytes: u64 = rows.iter().map(|row| row.flight.wire_bytes as u64).sum();
            let mut sources = std::collections::BTreeMap::new();
            for row in &rows {
                if let Traffic::Source {
                    stream,
                    id,
                    payload,
                } = &row.flight.traffic
                    && let Some(previous) = sources.insert((*stream as u8, *id), payload.as_slice())
                {
                    assert_eq!(
                        previous,
                        payload.as_slice(),
                        "retained ARQ source payload changed on retransmission"
                    );
                }
            }
            // Clean initial exchange was driven by the existing fixture, so the
            // captured suffix is bounded by, not equated with, lifetime totals.
            assert!(captured_bytes <= driver.counters.wire_bytes);
            for control in [false, true] {
                let numbers: Vec<_> = rows
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.flight.traffic,
                            Traffic::Source { .. } | Traffic::Ack { .. }
                        ) == control
                    })
                    .map(|row| row.flight.number.0)
                    .collect();
                assert!(numbers.windows(2).all(|pair| pair[0] < pair[1]));
            }
            assert_eq!(
                driver.counters.wire_packets,
                driver.counters.socket_accepted_packets
            );
            assert_eq!(
                driver.counters.wire_bytes,
                driver.counters.socket_accepted_ip_bytes
            );
            assert_eq!(
                (
                    self.inner.endpoints[side].socket.local_addr()?,
                    self.inner.endpoints[side].socket.peer_addr()?
                ),
                self.inner.endpoints[side].original
            );
        }
        Ok(())
    }
}

#[test]
fn actual_cached_final_retry_preserves_two_unconfirmed_outputs_on_both_covers() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let mut fixture = FaultFixture::new(kind, false).await?;
                fixture.inner.exchange_all_channels(13).await?;
                let (_, mut reply) = fixture.start_switch()?;
                let mut reached = false;
                for _ in 0..700 {
                    fixture
                        .turn(|flight| {
                            if flight.from == 0
                                && flight.transaction_ack()
                                && matches!(
                                    flight.phases[1],
                                    transaction::Phase::FollowerCommitted
                                        | transaction::Phase::Idle
                                )
                            {
                                Route::Drop
                            } else if flight.from == 1
                                && flight.transaction_fragment()
                                && flight.phases[1] == transaction::Phase::Idle
                            {
                                Route::Hold(1)
                            } else {
                                Route::Deliver
                            }
                        })
                        .await?;
                    let server = &fixture.inner.endpoints[1].driver;
                    let custody = state(server)?.output_custody_for_test();
                    if server
                        .generic
                        .as_ref()
                        .is_some_and(|runtime| runtime.outcome.is_some())
                        && state(server)?.peer().phase() == transaction::Phase::Idle
                        && state(&fixture.inner.endpoints[0].driver)?.peer().phase()
                            == transaction::Phase::AwaitRetireAck
                        && custody[..2]
                            .iter()
                            .all(|entry| entry.is_some_and(|(_, _, confirmed, _)| !confirmed))
                        && custody[2].is_none()
                        && fixture.messages.iter().any(|message| {
                            message.from == 1 && message.kind == mg::MessageKind::Retire
                        })
                    {
                        reached = true;
                        break;
                    }
                }
                assert!(
                    reached,
                    "actual cached-final two-output pressure not reached: {}",
                    fixture.diagnostic()?
                );
                let server = &fixture.inner.endpoints[1].driver;
                let operation = state(server)?
                    .peer()
                    .operation()
                    .ok_or("server lost unconfirmed final operation")?;
                let custody = state(server)?.output_custody_for_test();
                let final_message = fixture
                    .messages
                    .iter()
                    .find(|message| message.from == 1 && message.kind == mg::MessageKind::Retire)
                    .ok_or("missing actual final envelope observation")?;
                let final_id = final_message.message;
                let final_bytes = final_message.bytes.clone();
                let final_submission = sc::Envelope::decode(
                    &final_bytes,
                    sc::Limits {
                        max_frame_bytes: 4096,
                        max_management_bytes: 4096 - sc::HEADER_BYTES,
                        max_feedback_bytes: 1,
                    },
                )?
                .binding
                .packet
                .0;
                assert!(
                    custody
                        .iter()
                        .flatten()
                        .any(|(submission, _, _, final_reply)| *final_reply
                            && submission.0 == final_submission)
                );
                let usage = state(server)?.usage();
                assert!(state(server)?.engine(operation.origin().epoch).is_err());
                assert_eq!(reply.try_recv(), Err(oneshot::error::TryRecvError::Empty));
                for _ in 0..20 {
                    fixture
                        .turn(|flight| {
                            if (flight.from == 0 && flight.transaction_ack())
                                || (flight.from == 1
                                    && flight.transaction_fragment()
                                    && flight.phases[1] == transaction::Phase::Idle)
                            {
                                Route::Drop
                            } else {
                                Route::Deliver
                            }
                        })
                        .await?;
                }
                // Sender-observed LX bytes identify a diagnostic cohort only;
                // they do not grant receiver authority or consume replay state.
                let mut first: std::collections::BTreeMap<u64, (security::PacketNumber, &[u8])> =
                    std::collections::BTreeMap::new();
                let mut ordinary_final_retry = false;
                for attempt in &fixture.attempts {
                    if attempt.flight.from != 1 {
                        continue;
                    }
                    let Traffic::Source {
                        stream: streams::Stream::Transaction,
                        id,
                        payload,
                    } = &attempt.flight.traffic
                    else {
                        continue;
                    };
                    if payload.first() != Some(&messages::FRAGMENT_KIND) {
                        continue;
                    }
                    // Kind byte plus LX message offset20..28. The diagnostic
                    // Reassembler already validated the captured fragment.
                    let message = payload
                        .get(21..29)
                        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                        .map(u64::from_be_bytes);
                    if message != Some(final_id) {
                        continue;
                    }
                    if let Some((number, original)) = first.get(id) {
                        assert_eq!(*original, payload.as_slice());
                        assert!(attempt.flight.number > *number);
                        assert_eq!(attempt.route, Route::Drop);
                        ordinary_final_retry = true;
                    } else {
                        assert_eq!(attempt.route, Route::Hold(1));
                        assert!(first.len() < 32, "bounded final fragment observation");
                        first.insert(*id, (attempt.flight.number, payload));
                    }
                }
                assert!(
                    ordinary_final_retry,
                    "no actual final-RETIRE ARQ retransmission observed: {}",
                    fixture.diagnostic()?
                );
                let server = &fixture.inner.endpoints[1].driver;
                assert_eq!(state(server)?.peer().operation(), Some(operation));
                assert_eq!(state(server)?.output_custody_for_test(), custody);
                assert_eq!(state(server)?.usage(), usage);
                assert!(state(server)?.engine(operation.origin().epoch).is_err());
                assert_eq!(reply.try_recv(), Err(oneshot::error::TryRecvError::Empty));
                // This is the separately labeled genuine Peer-poll seam, not a
                // claim that State bypasses its maintained FrozenOutput suppression.
                let now = duration(fixture.inner.now);
                let driver = &mut fixture.inner.endpoints[0].driver;
                let owner::DataOwner::Generic(actual) = &mut driver.owner else {
                    return Err("missing client State".into());
                };
                let command = actual.independent_final_retry_for_test(now)?;
                let mut retry = driver
                    .control
                    .freeze_transaction(actual.peer(), &command, now)?;
                let retry_bytes = retry.envelope().to_vec();
                assert!(matches!(
                    driver.control.submit_frozen(&mut retry, now)?,
                    control_owner::Attempt::Complete(_)
                ));
                let mut previewed = false;
                for _ in 0..300 {
                    fixture
                        .turn(|flight| {
                            if (flight.from == 0 && flight.transaction_ack())
                                || (flight.from == 1
                                    && flight.transaction_fragment()
                                    && flight.phases[1] == transaction::Phase::Idle)
                            {
                                Route::Drop
                            } else {
                                Route::Deliver
                            }
                        })
                        .await?;
                    if let Some(view) = fixture
                        .previews
                        .iter()
                        .find(|view| view.target == 1 && view.bytes == retry_bytes)
                    {
                        assert!(!view.preparation);
                        previewed = true;
                        break;
                    }
                }
                assert!(
                    previewed,
                    "fresh actual logical RETIRE retry never reached joint preview: {}",
                    fixture.diagnostic()?
                );
                for _ in 0..3 {
                    fixture
                        .turn(|flight| {
                            if (flight.from == 0 && flight.transaction_ack())
                                || (flight.from == 1
                                    && flight.transaction_fragment()
                                    && flight.phases[1] == transaction::Phase::Idle)
                            {
                                Route::Drop
                            } else {
                                Route::Deliver
                            }
                        })
                        .await?;
                }
                let server = &fixture.inner.endpoints[1].driver;
                assert_eq!(state(server)?.peer().operation(), Some(operation));
                assert_eq!(state(server)?.output_custody_for_test(), custody);
                assert_eq!(state(server)?.usage(), usage);
                assert!(
                    fixture
                        .messages
                        .iter()
                        .filter(
                            |message| message.from == 1 && message.kind == mg::MessageKind::Retire
                        )
                        .all(|message| message.message == final_id && message.bytes == final_bytes)
                );
                assert!(state(server)?.engine(operation.origin().epoch).is_err());
                assert_eq!(reply.try_recv(), Err(oneshot::error::TryRecvError::Empty));
                assert!(fixture.release(1, true)? >= 2);
                assert_eq!(fixture.settle(&mut reply).await?, operation.ticket().epoch);
                let token = retry.token().ok_or("independent retry lost real token")?;
                let mut confirmed = false;
                for _ in 0..300 {
                    fixture.turn(|_| Route::Deliver).await?;
                    if fixture.inner.endpoints[0].driver.control.with_confirmed(
                        token,
                        duration(fixture.inner.now),
                        |_| Ok(()),
                    )? == control_owner::Attempt::Complete(())
                    {
                        fixture.inner.endpoints[0]
                            .driver
                            .control
                            .retire(token, duration(fixture.inner.now))?;
                        confirmed = true;
                        break;
                    }
                }
                assert!(
                    confirmed,
                    "independent actual retry custody did not confirm"
                );
                fixture.inner.exchange_all_channels(55).await?;
                let initial = fixture.inner.endpoints[0]
                    .driver
                    .generic
                    .as_ref()
                    .ok_or("missing contract")?
                    .contract
                    .initial();
                fixture.inner.switch(initial).await?;
                fixture.accounting()?;
            }
            Ok(())
        }))
}

#[test]
fn actual_old_user_loss_and_prepare_fragment_reorder_recover_before_physical_switch() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let mut fixture = FaultFixture::new(kind, false).await?;
                let old_epoch = state(&fixture.inner.endpoints[0].driver)?.epoch();
                let mut expected: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
                for side in 0..2 {
                    let width = fixture.inner.endpoints[side].driver.send.records.channels;
                    for channel in 0..width {
                        // Several full native packets create later real symbols
                        // on the lost source's own channel. A sole short source
                        // gives the receiver no gap until a tail repair rescues it.
                        for ordinal in 0..4 {
                            let packet = large_channel_packet(
                                channel, width, 81 + channel as u8 + ordinal * 16,
                            )?;
                            fixture.inner.admit(side, &packet).await?;
                            expected[1 - side].push(packet);
                        }
                    }
                }
                let (_, mut reply) = fixture.start_switch()?;
                let mut transaction_fragments = 0;
                let mut dropped_user = false;
                let mut dropped_fragment = false;
                let mut released = false;
                let mut retransmits = 0;
                let mut suppress_repairs = true;
                let mut repair_drops = 0;
                for _ in 0..300 {
                    fixture
                        .turn(|flight| {
                            if suppress_repairs
                                && matches!(flight.traffic, Traffic::User { repair: true, .. })
                            {
                                repair_drops += 1;
                                return Route::Drop;
                            }
                            if !dropped_user
                                && matches!(flight.traffic, Traffic::User { feedback: false, repair: false })
                            {
                                dropped_user = true;
                                return Route::Drop;
                            }
                            if flight.from == 0 && flight.transaction_fragment() {
                                transaction_fragments += 1;
                                if transaction_fragments == 1 {
                                    return Route::Hold(3);
                                }
                                if transaction_fragments == 2 {
                                    dropped_fragment = true;
                                    return Route::Drop;
                                }
                            }
                            Route::Deliver
                        })
                        .await?;
                    for endpoint in &fixture.inner.endpoints {
                        if let Ok(engine) = endpoint.driver.owner.engine(old_epoch) {
                            retransmits = retransmits.max(engine.stats().sender.retransmits);
                        }
                    }
                    if retransmits > 0 {
                        suppress_repairs = false;
                    }
                    if !released && transaction_fragments >= 4 {
                        assert_eq!(fixture.release(3, false)?, 1);
                        released = true;
                    }
                    if released && dropped_user && retransmits > 0 {
                        break;
                    }
                }
                assert!(
                    dropped_user && dropped_fragment && released && retransmits > 0,
                    "actual loss/reorder/retransmission preconditions were not reached: source_drop={dropped_user} fragment_drop={dropped_fragment} fragments={transaction_fragments} released={released} retransmits={retransmits} repair_drops={repair_drops}; {}",
                    fixture.diagnostic()?
                );
                assert!(
                    fixture.messages.iter().any(
                        |message| message.from == 0 && message.kind == mg::MessageKind::Prepare
                    )
                );
                let epoch = fixture.settle(&mut reply).await?;
                assert_eq!(epoch.0, old_epoch.0 + 1);
                for (side, wanted) in expected.iter_mut().enumerate() {
                    let mut actual = Vec::new();
                    let mut output = [0; 513];
                    for _ in 0..16 {
                        match fixture.inner.endpoints[side].host.recv(&mut output) {
                            Ok(bytes) => actual.push(output[..bytes].to_vec()),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) => return Err(error.into()),
                        }
                    }
                    actual.sort();
                    wanted.sort();
                    assert_eq!(&actual, wanted);
                    assert_eq!(
                        fixture.inner.endpoints[side].driver.counters.native_written,
                        wanted.len() as u64
                    );
                }
                // Replaying an actually delivered old ciphertext after retirement
                // cannot recreate its native delivery. Scope rejection may precede
                // replay checking, so only the surviving semantic facts are asserted.
                let old = fixture
                    .attempts
                    .iter()
                    .find(|attempt| {
                        attempt.route == Route::Deliver
                            && matches!(attempt.flight.traffic, Traffic::User { .. })
                    })
                    .ok_or("missing delivered old User")?
                    .flight
                    .clone();
                let target = 1 - old.from;
                let writes = fixture.inner.endpoints[target]
                    .driver
                    .counters
                    .native_written;
                fixture.replay(&old)?;
                assert_eq!(
                    fixture.inner.endpoints[target]
                        .driver
                        .counters
                        .native_written,
                    writes
                );
                assert!(
                    fixture.inner.endpoints[target]
                        .driver
                        .records
                        .additional_data()
                        .is_none()
                );
                fixture.inner.exchange_all_channels(99).await?;
                let initial = fixture.inner.endpoints[0]
                    .driver
                    .generic
                    .as_ref()
                    .ok_or("missing contract")?
                    .contract
                    .initial();
                fixture.inner.switch(initial).await?;
                fixture.accounting()?;
            }
            Ok(())
        }))
}
