use super::*;
use crate::{
    EndpointId, Ingress, LaneId, Role, SessionId, session_control as control,
    transaction::{self as tx, Configuration},
};
use l2tunnel_core::{Duplex, Epoch, Mapping, ModeConfig};
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn identity(role: Role) -> tx::Identity {
    tx::Identity {
        session: SessionId([0x3D; 16]),
        role,
        local: EndpointId(if role == Role::Client { 11 } else { 22 }),
        remote: EndpointId(if role == Role::Client { 22 } else { 11 }),
        lane: LaneId(7),
    }
}

fn ingress(sender: Role) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: identity(sender).session,
        lane: LaneId(7),
        sender,
    }
}

fn envelope_limits() -> control::Limits {
    control::Limits {
        max_frame_bytes: 4096,
        max_management_bytes: 4096 - control::HEADER_BYTES,
        max_feedback_bytes: 256,
    }
}

struct Prepared<C: Configuration> {
    bytes: Vec<u8>,
    coordinator: tx::Peer<C>,
    follower: tx::Peer<C>,
    initial: C,
}

fn prepare<C: Configuration>(initial: C, next: C) -> TestResult<Prepared<C>> {
    let settings = tx::Settings {
        retry_ms: 20,
        phase_timeout_ms: 2000,
        reconcile_timeout_ms: 4000,
    };
    let supported = [initial.clone(), next.clone()];
    let mut coordinator = tx::Peer::new(
        identity(Role::Client),
        Epoch(1),
        initial.clone(),
        &supported,
        settings,
        tx::Tick(0),
    )?;
    let follower = tx::Peer::new(
        identity(Role::Server),
        Epoch(1),
        initial.clone(),
        &supported,
        settings,
        tx::Tick(0),
    )?;
    assert!(matches!(
        coordinator.propose(next, tx::Tick(0))?.event,
        Some(tx::Event::Stage { .. })
    ));
    let fence: Vec<u64> = (0..initial.channels())
        .map(|channel| u64::from(channel) * 3)
        .collect();
    let management = coordinator
        .staged(tx::Fence::new(&fence)?, tx::Tick(0))?
        .outbound
        .ok_or(tx::Error::Unexpected)?;
    let envelope = control::Envelope {
        binding: control::Binding {
            session: identity(Role::Client).session,
            lane: LaneId(7),
            sender: Role::Client,
            packet: crate::PacketNumber(1),
            scope: control::Scope {
                epoch: Epoch(1),
                digest: tx::configuration_digest(&initial)?,
            },
        },
        body: control::Body::Management(&management),
    };
    let mut bytes = vec![0; envelope.encoded_len(envelope_limits())?];
    envelope.encode(&mut bytes, envelope_limits())?;
    Ok(Prepared {
        bytes,
        coordinator,
        follower,
        initial,
    })
}

fn ordinary_prepare() -> TestResult<Prepared<ModeConfig>> {
    let initial = ModeConfig::default();
    let next = ModeConfig {
        mapping: Mapping::Crc32,
        ..initial.clone()
    };
    prepare(initial, next)
}

/// Every canonical byte carries one validated per-channel weight; none is padding.
#[derive(Clone, Debug, Eq, PartialEq)]
struct MaximumPolicy([u16; 256]);

impl Configuration for MaximumPolicy {
    const ENCODED_LEN: usize = 512;
    const DIGEST_DOMAIN: &'static [u8] = b"test/whole-control/256-weights/v1\0";

    fn validate(&self) -> Result<(), tx::Error> {
        if self.0.iter().any(|weight| !(1..=1024).contains(weight)) {
            return Err(tx::Error::Configuration("channel weight"));
        }
        Ok(())
    }

    fn encode_into(&self, output: &mut [u8]) -> Result<(), tx::Error> {
        if output.len() != Self::ENCODED_LEN {
            return Err(tx::Error::Malformed);
        }
        for (bytes, weight) in output.chunks_exact_mut(2).zip(self.0) {
            bytes.copy_from_slice(&weight.to_be_bytes());
        }
        Ok(())
    }

    fn decode(input: &[u8]) -> Result<Self, tx::Error> {
        if input.len() != Self::ENCODED_LEN {
            return Err(tx::Error::Malformed);
        }
        let mut weights = [0; 256];
        for (weight, bytes) in weights.iter_mut().zip(input.chunks_exact(2)) {
            *weight = u16::from_be_bytes([bytes[0], bytes[1]]);
        }
        let result = Self(weights);
        result.validate()?;
        Ok(result)
    }

    fn channels(&self) -> u16 {
        256
    }

    fn duplex(&self) -> Duplex {
        Duplex::Half
    }
}

fn maximum_prepare() -> TestResult<Prepared<MaximumPolicy>> {
    let initial = MaximumPolicy([1; 256]);
    let mut next = initial.clone();
    next.0[255] = 1024;
    prepare(initial, next)
}

fn settings() -> Settings {
    Settings {
        delivery: crate::delivery::Settings {
            recovery: l2tunnel_recovery::ArqConfig {
                max_source_bytes: 256,
                send_bytes: 768,
                receive_bytes: 768,
                send_records: 3,
                receive_records: 3,
                initial_rto: Duration::from_millis(10),
                maximum_rto: Duration::from_millis(40),
                ack_delay: Duration::ZERO,
                max_retries: 16,
            },
            interval: Duration::from_millis(5),
            packets_per_interval: 4,
            bytes_per_interval: 1024,
            wire_overhead: 64,
        },
        path_mtu: 512,
        max_message_bytes: 4096,
        max_outbound_messages: 3,
        max_outbound_bytes: 3 * 4096,
        max_fragments: 32,
        max_reassembly_bytes: 2 * 4096,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(1),
        work_per_call: 4,
    }
}

fn binding(role: Role) -> crate::delivery::Binding {
    crate::delivery::Binding {
        session: identity(role).session,
        lane: LaneId(7),
        local_role: role,
        control_epoch: 2,
    }
}

fn inspect(sender: usize, packet: &[u8]) -> TestResult<l2tunnel_recovery::PacketView<'_>> {
    Ok(l2tunnel_recovery::inspect_packet(
        packet,
        l2tunnel_recovery::RecoveryContext {
            session: u128::from_be_bytes(identity(Role::Client).session.0),
            epoch: 2,
            role: if sender == 0 {
                l2tunnel_recovery::EndpointRole::Responder
            } else {
                l2tunnel_recovery::EndpointRole::Initiator
            },
        },
        256,
    )?)
}

#[derive(Default)]
struct Faults {
    enabled: bool,
    first_fragment_dropped: bool,
    middle_fragment_dropped: bool,
    final_source: Option<u64>,
    final_fragment_dropped: bool,
    recovery_ack_dropped: bool,
    whole_receipt_dropped: bool,
    duplicates_scheduled: usize,
    repeated_sources: usize,
    attempts: std::collections::BTreeMap<(usize, u64), Vec<u8>>,
}

struct Network {
    peers: [Owner; 2],
    settings: Settings,
    time: u64,
    packets: Vec<(u64, usize, Vec<u8>)>,
    charged: [u64; 2],
    faults: Faults,
}

impl Network {
    fn new(settings: Settings, faults: bool) -> TestResult<Self> {
        Ok(Self {
            peers: [
                Owner::new(
                    settings,
                    binding(Role::Client),
                    Duration::ZERO,
                    Duration::from_secs(2),
                )?,
                Owner::new(
                    settings,
                    binding(Role::Server),
                    Duration::ZERO,
                    Duration::from_secs(2),
                )?,
            ],
            settings,
            time: 0,
            packets: Vec::new(),
            charged: [0; 2],
            faults: Faults {
                enabled: faults,
                ..Faults::default()
            },
        })
    }

    fn now(&self) -> Duration {
        Duration::from_millis(self.time)
    }

    fn step(&mut self) -> TestResult {
        let now = self.now();
        let arriving = std::mem::take(&mut self.packets);
        for (at, target, bytes) in arriving {
            if at > self.time {
                self.packets.push((at, target, bytes));
            } else {
                let sender = if target == 1 {
                    Role::Client
                } else {
                    Role::Server
                };
                self.peers[target].receive(ingress(sender), &bytes, now)?;
            }
        }
        for side in 0..2 {
            self.peers[side].tick(now)?;
            let mut allowance = 1024;
            for turn in 0..32 {
                let mut output = [0; 512];
                let Some(emission) = self.peers[side].poll(now, allowance, &mut output)? else {
                    break;
                };
                assert!(turn < 31, "one finite interval produced unbounded work");
                assert_eq!(
                    emission.wire_bytes,
                    emission.bytes + self.settings.delivery.wire_overhead
                );
                assert!(emission.wire_bytes <= self.settings.path_mtu);
                assert!(emission.wire_bytes <= allowance);
                allowance -= emission.wire_bytes;
                self.charged[side] += emission.wire_bytes as u64;
                let bytes = output[..emission.bytes].to_vec();
                let mut discard = false;
                match inspect(side, &bytes)? {
                    l2tunnel_recovery::PacketView::Data { source, payload } => {
                        if let Some(previous) = self.faults.attempts.get(&(side, source.0)) {
                            assert_eq!(payload, previous, "retry changed retained source bytes");
                            self.faults.repeated_sources += 1;
                        } else {
                            self.faults
                                .attempts
                                .insert((side, source.0), payload.to_vec());
                        }
                        if self.faults.enabled && side == 0 && payload.first() == Some(&1) {
                            if source.0 == 0 && !self.faults.first_fragment_dropped {
                                self.faults.first_fragment_dropped = true;
                                discard = true;
                            }
                            if source.0 == 6 && !self.faults.middle_fragment_dropped {
                                self.faults.middle_fragment_dropped = true;
                                discard = true;
                            }
                            if Some(source.0) == self.faults.final_source
                                && !self.faults.final_fragment_dropped
                            {
                                self.faults.final_fragment_dropped = true;
                                discard = true;
                            }
                        }
                        if self.faults.enabled
                            && side == 1
                            && payload.first() == Some(&2)
                            && !self.faults.whole_receipt_dropped
                        {
                            self.faults.whole_receipt_dropped = true;
                            discard = true;
                        }
                    }
                    l2tunnel_recovery::PacketView::Ack { .. } => {
                        if self.faults.enabled && side == 1 && !self.faults.recovery_ack_dropped {
                            self.faults.recovery_ack_dropped = true;
                            discard = true;
                        }
                    }
                }
                if !discard {
                    let delay = if self.time.is_multiple_of(2) { 3 } else { 1 };
                    self.packets
                        .push((self.time + delay, 1 - side, bytes.clone()));
                    if self.faults.enabled {
                        self.packets.push((self.time + 4, 1 - side, bytes));
                        self.faults.duplicates_scheduled += 1;
                    }
                }
            }
            let retained = self.peers[side].retained();
            assert!(retained.recovery.send_records <= 3);
            assert!(retained.recovery.receive_records <= 3);
            assert!(retained.recovery.send_bytes <= 768);
            assert!(retained.recovery.receive_bytes <= 768);
            assert!(retained.outbound_messages <= self.settings.max_outbound_messages);
            assert!(
                retained.outbound_bytes + retained.outbound_fragment_bytes
                    <= self.settings.max_outbound_bytes
            );
            assert!(retained.incomplete_messages <= self.settings.max_incomplete_messages);
            assert!(retained.reassembly_bytes <= self.settings.max_reassembly_bytes);
            assert_eq!(
                retained.source_scratch_bytes,
                self.settings.delivery.recovery.max_source_bytes
            );
        }
        assert!(
            self.packets.len() <= 64,
            "fault fixture exceeded its own queue bound"
        );
        self.time += 1;
        Ok(())
    }

    fn await_pending(&mut self, side: usize) -> TestResult {
        for _ in 0..600 {
            if self.peers[side].pending().is_some() {
                return Ok(());
            }
            self.step()?;
        }
        Err(std::io::Error::other("whole message did not arrive before fixture bound").into())
    }

    fn await_confirmed(&mut self, side: usize, ticket: Ticket) -> TestResult {
        for _ in 0..600 {
            let now = self.now();
            if self.peers[side].confirmed(ticket, now)? {
                return Ok(());
            }
            self.step()?;
        }
        Err(std::io::Error::other("whole receipt did not arrive before fixture bound").into())
    }
}

fn transfer_prepare<C: Configuration + std::fmt::Debug>(mut prepared: Prepared<C>) -> TestResult {
    let expected = prepared.bytes.clone();
    let mut network = Network::new(settings(), true)?;
    let chunk_bytes =
        network.settings.delivery.recovery.max_source_bytes - FRAGMENT_HEADER_BYTES - 1;
    network.faults.final_source = Some((expected.len().div_ceil(chunk_bytes) - 1) as u64);
    let ticket = network.peers[0].submit(
        SubmissionId(1),
        &expected,
        Duration::ZERO,
        Duration::from_millis(900),
    )?;
    network.await_pending(1)?;
    let delivery = network.peers[1].pending().ok_or(Error::Protocol)?;
    assert_eq!(delivery.bytes(), expected);
    assert_eq!(delivery.ticket().length(), expected.len());
    let accepted = delivery.ticket();
    let envelope = control::Envelope::decode(delivery.bytes(), envelope_limits())?;
    let control::Body::Management(management) = envelope.body else {
        return Err(Error::Protocol.into());
    };
    let effects =
        prepared
            .follower
            .receive(ingress(Role::Client), management, tx::Tick(network.time))?;
    assert!(matches!(effects.event, Some(tx::Event::Stage { .. })));
    assert_eq!(prepared.follower.active_config(), &prepared.initial);
    assert_eq!(prepared.coordinator.active_config(), &prepared.initial);
    assert_eq!(prepared.follower.phase(), tx::Phase::FollowerStaging);
    let now = network.now();
    assert!(!network.peers[0].confirmed(ticket, now)?);
    let now = network.now();
    network.peers[1].accept(accepted, now)?;
    network.await_confirmed(0, ticket)?;
    assert_eq!(prepared.follower.active_config(), &prepared.initial);
    assert_eq!(prepared.coordinator.active_config(), &prepared.initial);
    assert_eq!(prepared.follower.phase(), tx::Phase::FollowerStaging);
    assert!(network.peers[1].pending().is_none());
    assert!(network.faults.first_fragment_dropped);
    assert!(network.faults.final_fragment_dropped);
    assert!(network.faults.recovery_ack_dropped);
    assert!(network.faults.whole_receipt_dropped);
    assert!(network.faults.duplicates_scheduled > 0);
    assert!(network.faults.repeated_sources > 0);
    if expected.len() == 2762 {
        assert!(network.faults.middle_fragment_dropped);
        assert!(
            network
                .faults
                .attempts
                .keys()
                .filter(|(side, _)| *side == 0)
                .count()
                > 2
        );
    }
    for side in 0..2 {
        assert_eq!(
            network.peers[side].statistics().emitted_wire_bytes,
            network.charged[side]
        );
    }
    let now = network.now();
    network.peers[0].retire(ticket, now)?;
    assert_eq!(network.peers[0].retained().outbound_messages, 0);
    for _ in 0..100 {
        network.step()?;
        if network.packets.is_empty()
            && network
                .peers
                .iter()
                .all(|peer| peer.retained().recovery.send_records == 0)
        {
            break;
        }
    }
    assert!(network.packets.is_empty());
    assert!(
        network
            .peers
            .iter()
            .all(|peer| peer.retained().recovery.send_records == 0)
    );
    assert!(network.peers[1].pending().is_none());
    Ok(())
}

#[test]
fn ordinary_prepare_is_exact_once_through_fragment_and_receipt_faults() -> TestResult {
    let prepared = ordinary_prepare()?;
    assert_eq!(prepared.bytes.len(), 354);
    transfer_prepare(prepared)
}

#[test]
fn largest_canonical_prepare_streams_through_a_three_source_window() -> TestResult {
    let prepared = maximum_prepare()?;
    assert_eq!(prepared.bytes.len(), 2762);
    transfer_prepare(prepared)
}

#[test]
fn fragment_acks_do_not_confirm_a_complete_message_held_for_acceptance() -> TestResult {
    let bytes = ordinary_prepare()?.bytes;
    let mut network = Network::new(settings(), false)?;
    let ticket = network.peers[0].submit(
        SubmissionId(1),
        &bytes,
        Duration::ZERO,
        Duration::from_millis(900),
    )?;
    network.await_pending(1)?;
    for _ in 0..100 {
        network.step()?;
        if network.peers[0].retained().recovery.send_records == 0 {
            break;
        }
    }
    assert_eq!(network.peers[0].retained().recovery.send_records, 0);
    let now = network.now();
    assert!(!network.peers[0].confirmed(ticket, now)?);
    assert_eq!(network.peers[1].retained().held_bytes, bytes.len());
    for _ in 0..20 {
        let pending = network.peers[1].pending().ok_or(Error::Protocol)?;
        assert_eq!(pending.bytes(), bytes);
        network.step()?;
    }
    let delivered = network.peers[1].pending().ok_or(Error::Protocol)?.ticket();
    let now = network.now();
    network.peers[1].accept(delivered, now)?;
    network.await_confirmed(0, ticket)?;
    assert!(network.peers[1].pending().is_none());
    Ok(())
}

#[test]
fn bounded_multiple_submissions_preserve_held_bytes_and_do_not_consume_refused_ids() -> TestResult {
    let bytes = ordinary_prepare()?.bytes;
    let mut config = settings();
    config.max_message_bytes = 512;
    config.max_reassembly_bytes = 1024;
    config.max_outbound_messages = 2;
    config.max_outbound_bytes = 1000;
    config.work_per_call = 1;
    let mut network = Network::new(config, false)?;
    let deadline = Duration::from_millis(900);
    let first = network.peers[0].submit(SubmissionId(1), &bytes, Duration::ZERO, deadline)?;
    let before = network.peers[0].retained();
    assert_eq!(
        network.peers[0].submit(SubmissionId(2), &bytes, Duration::ZERO, deadline),
        Err(Error::Backpressure)
    );
    assert_eq!(network.peers[0].retained(), before);
    assert_eq!(
        network.peers[0].submit(SubmissionId(1), &bytes, Duration::ZERO, deadline)?,
        first
    );
    let mut changed = bytes.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert_eq!(
        network.peers[0].submit(SubmissionId(1), &changed, Duration::ZERO, deadline),
        Err(Error::ChangedSubmission)
    );
    assert_eq!(
        network.peers[0].submit(
            SubmissionId(1),
            &bytes,
            Duration::ZERO,
            deadline + Duration::from_nanos(1)
        ),
        Err(Error::ChangedSubmission)
    );
    let tail = b"second message\0\0";
    let second = network.peers[0].submit(SubmissionId(2), tail, Duration::ZERO, deadline)?;
    assert_eq!(second.message(), first.message() + 1);
    assert_eq!(second.submission(), SubmissionId(2));
    assert_eq!(
        network.peers[0].submit(SubmissionId(3), b"third", Duration::ZERO, deadline),
        Err(Error::Backpressure)
    );
    network.await_pending(1)?;
    let first_received = network.peers[1].pending().ok_or(Error::Protocol)?.ticket();
    for _ in 0..30 {
        let held = network.peers[1].pending().ok_or(Error::Protocol)?;
        assert_eq!(held.ticket(), first_received);
        assert_eq!(held.bytes(), bytes);
        network.step()?;
    }
    let now = network.now();
    assert_eq!(
        network.peers[0].retire(first, now),
        Err(Error::NotConfirmed)
    );
    network.peers[1].accept(first_received, now)?;
    network.await_pending(1)?;
    let held = network.peers[1].pending().ok_or(Error::Protocol)?;
    assert_eq!(held.bytes(), tail);
    let second_received = held.ticket();
    let now = network.now();
    network.peers[1].accept(second_received, now)?;
    network.await_confirmed(0, first)?;
    network.await_confirmed(0, second)?;
    let now = network.now();
    network.peers[0].retire(first, now)?;
    assert_eq!(
        network.peers[0].submit(SubmissionId(1), &bytes, now, deadline),
        Err(Error::SubmissionOrder)
    );
    let third = network.peers[0].submit(SubmissionId(3), b"third", now, deadline)?;
    assert_eq!(third.message(), second.message() + 1);
    Ok(())
}

fn first_sources(config: Settings, bytes: &[u8]) -> TestResult<Vec<Vec<u8>>> {
    let mut sender = Owner::new(
        config,
        binding(Role::Client),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    sender.submit(
        SubmissionId(1),
        bytes,
        Duration::ZERO,
        config.message_lifetime,
    )?;
    let mut packets = Vec::new();
    let mut allowance = 4096;
    for _ in 0..32 {
        let mut output = [0; 512];
        let Some(emission) = sender.poll(Duration::ZERO, allowance, &mut output)? else {
            if packets.len() >= 2 {
                break;
            }
            sender.tick(Duration::ZERO)?;
            continue;
        };
        allowance -= emission.wire_bytes;
        assert!(matches!(
            inspect(0, &output[..emission.bytes])?,
            l2tunnel_recovery::PacketView::Data { .. }
        ));
        packets.push(output[..emission.bytes].to_vec());
    }
    assert_eq!(
        packets.len(),
        2,
        "ordinary PREPARE must span two real sources"
    );
    Ok(packets)
}

#[test]
fn exact_receiver_deadline_keeps_nanosecond_precision_and_rejects_late_final_fragment() -> TestResult
{
    let bytes = ordinary_prepare()?.bytes;
    let mut config = settings();
    config.message_lifetime = Duration::from_millis(100);
    let packets = first_sources(config, &bytes)?;
    // The receiver uses an independent local time origin, not sender timestamps.
    let start = Duration::from_millis(500);
    let deadline = start + config.message_lifetime;
    for arrival in [
        deadline - Duration::from_nanos(1),
        deadline,
        deadline + Duration::from_nanos(1),
    ] {
        let mut receiver =
            Owner::new(config, binding(Role::Server), start, Duration::from_secs(2))?;
        receiver.receive(ingress(Role::Client), &packets[0], start)?;
        receiver.tick(start)?;
        assert!(receiver.pending().is_none());
        let before = receiver.retained();
        assert_eq!(before.incomplete_messages, 1);
        assert!(receiver.deadline() <= deadline);
        if arrival < deadline {
            receiver.receive(ingress(Role::Client), &packets[1], arrival)?;
            receiver.tick(arrival)?;
            let held = receiver.pending().ok_or(Error::Protocol)?;
            assert_eq!(held.bytes(), bytes);
            assert_eq!(held.deadline(), deadline);
            let ticket = held.ticket();
            receiver.accept(ticket, arrival)?;
            // Once accepted, the message deadline no longer cancels its receipt.
            receiver.tick(deadline)?;
        } else {
            assert_eq!(
                receiver.receive(ingress(Role::Client), &packets[1], arrival),
                Err(Error::Expired)
            );
            assert!(receiver.pending().is_none());
            assert_eq!(
                receiver.tick(arrival + Duration::from_millis(1)),
                Err(Error::Expired)
            );
            assert_eq!(receiver.tick(start), Err(Error::Expired));
        }
    }
    Ok(())
}

#[test]
fn held_and_outbound_deadlines_are_original_and_sticky_across_retries() -> TestResult {
    let bytes = ordinary_prepare()?.bytes;
    let config = settings();
    let mut sender = Owner::new(
        config,
        binding(Role::Client),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    let deadline = Duration::from_millis(40);
    let ticket = sender.submit(SubmissionId(1), &bytes, Duration::ZERO, deadline)?;
    let before = deadline - Duration::from_nanos(1);
    assert_eq!(
        sender.submit(SubmissionId(1), &bytes, before, deadline)?,
        ticket
    );
    assert!(!sender.confirmed(ticket, before)?);
    assert_eq!(sender.tick(deadline), Err(Error::Expired));
    assert_eq!(sender.confirmed(ticket, deadline), Err(Error::Expired));
    assert_eq!(sender.retire(ticket, deadline), Err(Error::Expired));
    assert_eq!(
        sender.submit(
            SubmissionId(2),
            b"new",
            deadline,
            deadline + Duration::from_millis(20)
        ),
        Err(Error::Expired)
    );
    let mut output = [0xA5; 512];
    assert_eq!(
        sender.poll(deadline, usize::MAX, &mut output),
        Err(Error::Expired)
    );
    assert_eq!(output, [0xA5; 512]);

    let packets = first_sources(config, &bytes)?;
    let mut receiver = Owner::new(
        config,
        binding(Role::Server),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    for packet in &packets {
        receiver.receive(ingress(Role::Client), packet, Duration::ZERO)?;
    }
    receiver.tick(Duration::ZERO)?;
    let held = receiver.pending().ok_or(Error::Protocol)?;
    let held_ticket = held.ticket();
    let original = held.deadline();
    let late = original - Duration::from_nanos(1);
    receiver.receive(ingress(Role::Client), &packets[0], late)?;
    assert_eq!(
        receiver.pending().ok_or(Error::Protocol)?.deadline(),
        original
    );
    assert_eq!(receiver.accept(held_ticket, original), Err(Error::Expired));
    assert_eq!(
        receiver.accept(held_ticket, original + Duration::from_millis(1)),
        Err(Error::Expired)
    );
    Ok(())
}

#[test]
fn refused_output_and_shared_allowance_do_not_start_retries() -> TestResult {
    let bytes = ordinary_prepare()?.bytes;
    let mut config = settings();
    config.delivery.recovery.max_retries = 0;
    let mut sender = Owner::new(
        config,
        binding(Role::Client),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    sender.submit(
        SubmissionId(1),
        &bytes,
        Duration::ZERO,
        Duration::from_millis(900),
    )?;
    let retained = sender.retained();
    let mut short = vec![0xA5; sender.max_packet_bytes() - 1];
    assert_eq!(
        sender.poll(Duration::ZERO, usize::MAX, &mut short),
        Err(Error::Delivery(crate::delivery::Error::OutputTooSmall))
    );
    assert!(short.iter().all(|byte| *byte == 0xA5));
    assert_eq!(sender.retained(), retained);
    let mut output = [0xA5; 512];
    for now in [
        Duration::ZERO,
        Duration::from_millis(100),
        Duration::from_millis(300),
    ] {
        assert!(sender.poll(now, 0, &mut output)?.is_none());
        assert_eq!(sender.statistics().emitted_packets, 0);
    }
    // More than seven configured RTOs passed without handoff; this is still attempt1.
    let emission = sender
        .poll(Duration::from_millis(301), 1024, &mut output)?
        .ok_or(Error::Protocol)?;
    assert!(matches!(
        inspect(0, &output[..emission.bytes])?,
        l2tunnel_recovery::PacketView::Data {
            source: l2tunnel_recovery::SourceId(0),
            ..
        }
    ));
    assert_eq!(sender.statistics().emitted_packets, 1);
    Ok(())
}

#[test]
fn full_authenticated_context_is_required_before_any_fragment_custody() -> TestResult {
    let bytes = ordinary_prepare()?.bytes;
    let config = settings();
    let packets = first_sources(config, &bytes)?;
    let mut receiver = Owner::new(
        config,
        binding(Role::Server),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    let original = receiver.retained();
    let mut different_session = identity(Role::Client).session;
    different_session.0[15] ^= 1;
    for (origin, expected) in [
        (Ingress::UserTraffic, crate::delivery::Error::Origin),
        (
            Ingress::AuthenticatedManagement {
                session: different_session,
                lane: LaneId(7),
                sender: Role::Client,
            },
            crate::delivery::Error::Binding,
        ),
        (
            Ingress::AuthenticatedManagement {
                session: identity(Role::Client).session,
                lane: LaneId(8),
                sender: Role::Client,
            },
            crate::delivery::Error::Binding,
        ),
        (ingress(Role::Server), crate::delivery::Error::Binding),
    ] {
        assert_eq!(
            receiver.receive(origin, &packets[0], Duration::ZERO),
            Err(Error::Delivery(expected))
        );
        assert_eq!(receiver.retained(), original);
        assert!(receiver.pending().is_none());
    }
    for packet in &packets {
        receiver.receive(ingress(Role::Client), packet, Duration::ZERO)?;
    }
    receiver.tick(Duration::ZERO)?;
    assert_eq!(receiver.pending().ok_or(Error::Protocol)?.bytes(), bytes);
    Ok(())
}

#[test]
fn invalid_new_deadlines_are_recoverable_but_observed_time_reversal_is_sticky() -> TestResult {
    let mut sender = Owner::new(
        settings(),
        binding(Role::Client),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    let now = Duration::from_millis(10);
    for deadline in [now, now + Duration::from_secs(1) + Duration::from_nanos(1)] {
        assert_eq!(
            sender.submit(SubmissionId(1), b"original\0", now, deadline),
            Err(Error::Expired)
        );
        assert_eq!(sender.retained().outbound_messages, 0);
    }
    let ticket = sender.submit(
        SubmissionId(1),
        b"original\0",
        now,
        Duration::from_millis(500),
    )?;
    assert_eq!(ticket.message(), 1);
    assert_eq!(
        sender.tick(now - Duration::from_nanos(1)),
        Err(Error::NonMonotonicTime)
    );
    assert_eq!(sender.confirmed(ticket, now), Err(Error::NonMonotonicTime));
    let mut output = [0xA5; 512];
    assert_eq!(
        sender.poll(now, usize::MAX, &mut output),
        Err(Error::NonMonotonicTime)
    );
    assert_eq!(output, [0xA5; 512]);
    Ok(())
}

#[test]
fn absolute_deadline_overflow_is_recoverable_and_relative_tick_overflow_is_terminal() -> TestResult
{
    let origin = Duration::MAX - Duration::from_secs(2);
    let mut owner = Owner::new(settings(), binding(Role::Client), origin, Duration::MAX)?;
    let now = Duration::MAX - Duration::from_millis(500);
    assert_eq!(
        owner.submit(
            SubmissionId(1),
            b"bounded",
            now,
            Duration::MAX - Duration::from_nanos(1)
        ),
        Err(Error::TimeOverflow)
    );
    assert_eq!(owner.retained().outbound_messages, 0);
    owner.tick(now)?;

    let mut owner = Owner::new(
        settings(),
        binding(Role::Client),
        Duration::ZERO,
        Duration::MAX,
    )?;
    let beyond = Duration::from_nanos(u64::MAX) + Duration::from_nanos(1);
    assert_eq!(owner.tick(beyond), Err(Error::TimeOverflow));
    assert_eq!(owner.tick(Duration::ZERO), Err(Error::TimeOverflow));
    Ok(())
}

#[test]
fn bounded_local_work_stops_requesting_immediate_wakes_when_only_receipt_is_missing() -> TestResult
{
    let mut config = settings();
    config.work_per_call = 1;
    let mut network = Network::new(config, false)?;
    let bytes = ordinary_prepare()?.bytes;
    let ticket = network.peers[0].submit(
        SubmissionId(1),
        &bytes,
        Duration::ZERO,
        Duration::from_millis(900),
    )?;
    network.await_pending(1)?;
    for _ in 0..100 {
        network.step()?;
        if network.peers[0].retained().recovery.send_records == 0 && network.packets.is_empty() {
            break;
        }
    }
    let now = network.now();
    assert_eq!(network.peers[0].retained().recovery.send_records, 0);
    assert!(!network.peers[0].confirmed(ticket, now)?);
    let mut future = false;
    for _ in 0..64 {
        network.peers[0].tick(now)?;
        if network.peers[0].deadline() > now {
            future = true;
            break;
        }
    }
    assert!(
        future,
        "bounded scans must settle while waiting for semantic receipt"
    );
    assert!(network.peers[0].deadline() <= Duration::from_millis(900));
    Ok(())
}

fn opposite(role: Role) -> Role {
    match role {
        Role::Client => Role::Server,
        Role::Server => Role::Client,
    }
}

fn emitted_sources(owner: &mut Owner, now: Duration, count: usize) -> TestResult<Vec<Vec<u8>>> {
    let mut packets = Vec::new();
    let mut allowance = 4096;
    for _ in 0..32 {
        let mut output = [0; 512];
        if let Some(emission) = owner.poll(now, allowance, &mut output)? {
            allowance -= emission.wire_bytes;
            packets.push(output[..emission.bytes].to_vec());
            if packets.len() == count {
                break;
            }
        } else {
            owner.tick(now)?;
        }
    }
    assert_eq!(packets.len(), count);
    Ok(packets)
}

fn holding_in(receiver_binding: crate::delivery::Binding) -> TestResult<(Owner, Ticket)> {
    let mut sender_binding = receiver_binding;
    sender_binding.local_role = opposite(receiver_binding.local_role);
    let config = settings();
    let mut sender = Owner::new(
        config,
        sender_binding,
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    let mut receiver = Owner::new(
        config,
        receiver_binding,
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    sender.submit(
        SubmissionId(1),
        b"same exact bytes\0",
        Duration::ZERO,
        Duration::from_millis(900),
    )?;
    for packet in emitted_sources(&mut sender, Duration::ZERO, 1)? {
        receiver.receive(
            Ingress::AuthenticatedManagement {
                session: sender_binding.session,
                lane: sender_binding.lane,
                sender: sender_binding.local_role,
            },
            &packet,
            Duration::ZERO,
        )?;
    }
    receiver.tick(Duration::ZERO)?;
    let ticket = receiver.pending().ok_or(Error::Protocol)?.ticket();
    Ok((receiver, ticket))
}

#[test]
fn opaque_tickets_cannot_transfer_custody_across_full_session_lane_role_or_stream() -> TestResult {
    let original = binding(Role::Server);
    let (_, stale) = holding_in(original)?;
    let mut changed_session = original;
    changed_session.session.0[15] ^= 1;
    let variants = [
        changed_session,
        crate::delivery::Binding {
            lane: LaneId(8),
            ..original
        },
        crate::delivery::Binding {
            local_role: Role::Client,
            ..original
        },
        crate::delivery::Binding {
            control_epoch: 3,
            ..original
        },
    ];
    for context in variants {
        let (mut receiver, valid) = holding_in(context)?;
        assert_eq!(valid.message(), stale.message());
        assert_eq!(valid.length(), stale.length());
        assert_eq!(valid.digest(), stale.digest());
        let before = receiver.retained();
        let deadline = receiver.pending().ok_or(Error::Protocol)?.deadline();
        assert_eq!(
            receiver.accept(stale, Duration::ZERO),
            Err(Error::UnknownTicket)
        );
        assert_eq!(receiver.retained(), before);
        let held = receiver.pending().ok_or(Error::Protocol)?;
        assert_eq!(held.ticket(), valid);
        assert_eq!(held.bytes(), b"same exact bytes\0");
        assert_eq!(held.deadline(), deadline);
        receiver.accept(valid, Duration::ZERO)?;
        assert!(receiver.pending().is_none());
    }
    Ok(())
}

#[test]
fn accept_backpressure_preserves_complete_custody_until_a_real_receipt_frees_capacity() -> TestResult
{
    let config = settings();
    let mut left = Owner::new(
        config,
        binding(Role::Client),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    let mut right = Owner::new(
        config,
        binding(Role::Server),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    let deadline = Duration::from_millis(900);
    right.submit(
        SubmissionId(1),
        &ordinary_prepare()?.bytes,
        Duration::ZERO,
        deadline,
    )?;
    let right_sources = emitted_sources(&mut right, Duration::ZERO, 2)?;
    assert_eq!(right.retained().recovery.send_records, 2);
    left.submit(SubmissionId(1), b"first", Duration::ZERO, deadline)?;
    left.submit(SubmissionId(2), b"second\0", Duration::ZERO, deadline)?;
    for packet in emitted_sources(&mut left, Duration::ZERO, 2)? {
        right.receive(ingress(Role::Client), &packet, Duration::ZERO)?;
    }
    right.tick(Duration::ZERO)?;
    let first = right.pending().ok_or(Error::Protocol)?;
    assert_eq!(first.bytes(), b"first");
    let first_ticket = first.ticket();
    right.accept(first_ticket, Duration::ZERO)?;
    assert_eq!(right.retained().recovery.send_records, 3);
    for _ in 0..8 {
        right.tick(Duration::ZERO)?;
    }
    let second = right.pending().ok_or(Error::Protocol)?;
    assert_eq!(second.bytes(), b"second\0");
    let ticket = second.ticket();
    let original = second.deadline();
    let retained = right.retained();
    assert_eq!(
        right.accept(ticket, Duration::ZERO),
        Err(Error::Backpressure)
    );
    assert_eq!(right.retained(), retained);
    let held = right.pending().ok_or(Error::Protocol)?;
    assert_eq!(held.ticket(), ticket);
    assert_eq!(held.bytes(), b"second\0");
    assert_eq!(held.deadline(), original);

    // Free a real source by transporting an authenticated ARQ ACK, not a test setter.
    left.receive(ingress(Role::Server), &right_sources[0], Duration::ZERO)?;
    let mut acknowledged = false;
    for _ in 0..16 {
        let mut packet = [0; 512];
        if let Some(emission) = left.poll(Duration::ZERO, 4096, &mut packet)?
            && matches!(
                inspect(0, &packet[..emission.bytes])?,
                l2tunnel_recovery::PacketView::Ack { .. }
            )
        {
            right.receive(
                ingress(Role::Client),
                &packet[..emission.bytes],
                Duration::ZERO,
            )?;
            acknowledged = true;
            break;
        }
    }
    assert!(acknowledged);
    right.accept(ticket, Duration::ZERO)?;
    assert!(right.pending().is_none());
    Ok(())
}

#[test]
fn construction_enforces_complete_wire_and_independent_completion_reservations() -> TestResult {
    let mut config = settings();
    config.path_mtu = 44 + 256 + config.delivery.wire_overhead;
    let exact = Owner::new(
        config,
        binding(Role::Client),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    assert_eq!(
        exact.max_packet_bytes() + config.delivery.wire_overhead,
        config.path_mtu
    );
    config.path_mtu -= 1;
    assert!(matches!(
        Owner::new(
            config,
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(2)
        ),
        Err(Error::Settings)
    ));
    config = settings();
    config.max_reassembly_bytes = 2 * config.max_message_bytes - 1;
    assert!(matches!(
        Owner::new(
            config,
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(2)
        ),
        Err(Error::Settings)
    ));
    config = settings();
    config.delivery.recovery.send_records = 1;
    assert!(matches!(
        Owner::new(
            config,
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(2)
        ),
        Err(Error::Settings)
    ));
    Ok(())
}

#[test]
fn readonly_time_check_never_observes_future_or_poisoned_invalid_time() -> TestResult {
    let origin = Duration::from_millis(10);
    let mut owner = Owner::new(
        settings(),
        binding(Role::Client),
        origin,
        Duration::from_secs(2),
    )?;
    let before = (
        owner.last_now,
        owner.failed,
        owner.phase,
        owner.idle_actions,
        owner.retained(),
    );
    assert_eq!(
        owner.check_time(origin - Duration::from_nanos(1)),
        Err(Error::NonMonotonicTime)
    );
    assert_eq!(
        owner.check_time(Duration::from_secs(u64::MAX)),
        Err(Error::TimeOverflow)
    );
    assert_eq!(owner.check_time(Duration::from_secs(1)), Ok(()));
    assert_eq!(
        (
            owner.last_now,
            owner.failed,
            owner.phase,
            owner.idle_actions,
            owner.retained()
        ),
        before
    );
    // A future successful preview must not make this actual original time stale.
    owner.tick(origin)?;
    assert_eq!(owner.last_now, origin);
    assert_eq!(owner.failed, None);
    Ok(())
}

#[test]
fn readonly_time_check_preserves_actual_sticky_failure_before_other_errors() -> TestResult {
    let origin = Duration::from_millis(10);
    let mut owner = Owner::new(
        settings(),
        binding(Role::Client),
        origin,
        Duration::from_secs(2),
    )?;
    assert_eq!(
        owner.tick(origin - Duration::from_nanos(1)),
        Err(Error::NonMonotonicTime)
    );
    let before = (owner.last_now, owner.failed, owner.retained());
    for now in [Duration::ZERO, origin, Duration::from_secs(u64::MAX)] {
        assert_eq!(owner.check_time(now), Err(Error::NonMonotonicTime));
        assert_eq!((owner.last_now, owner.failed, owner.retained()), before);
    }
    let mut expired = Owner::new(
        settings(),
        binding(Role::Client),
        Duration::ZERO,
        Duration::from_millis(20),
    )?;
    assert_eq!(expired.tick(Duration::from_millis(20)), Err(Error::Expired));
    assert_eq!(expired.check_time(Duration::ZERO), Err(Error::Expired));
    assert_eq!(
        expired.check_time(Duration::from_secs(u64::MAX)),
        Err(Error::Expired)
    );
    Ok(())
}

#[test]
fn readonly_time_check_uses_real_outbound_held_partial_and_session_caps() -> TestResult {
    let config = settings();
    let bytes = ordinary_prepare()?.bytes;
    let deadline = Duration::from_millis(700);
    let mut sender = Owner::new(
        config,
        binding(Role::Client),
        Duration::ZERO,
        Duration::from_secs(2),
    )?;
    sender.submit(SubmissionId(1), &bytes, Duration::ZERO, deadline)?;
    let before = (sender.last_now, sender.failed, sender.retained());
    assert_eq!(sender.expiry(), deadline);
    assert_eq!(
        sender.check_time(deadline - Duration::from_nanos(1)),
        Ok(())
    );
    assert_eq!(sender.check_time(deadline), Err(Error::Expired));
    assert_eq!((sender.last_now, sender.failed, sender.retained()), before);
    assert_eq!(sender.check_time(Duration::ZERO), Ok(()));

    let packets = first_sources(config, &bytes)?;
    for complete in [false, true] {
        let mut receiver = Owner::new(
            config,
            binding(Role::Server),
            Duration::ZERO,
            Duration::from_secs(2),
        )?;
        for packet in packets
            .iter()
            .take(if complete { packets.len() } else { 1 })
        {
            receiver.receive(ingress(Role::Client), packet, Duration::ZERO)?;
        }
        receiver.tick(Duration::ZERO)?;
        if complete {
            assert_eq!(receiver.pending().ok_or(Error::Protocol)?.bytes(), bytes);
        } else {
            assert!(receiver.pending().is_none());
            assert_eq!(receiver.retained().incomplete_messages, 1);
        }
        let original = receiver.expiry();
        let before = (
            receiver.last_now,
            receiver.failed,
            receiver.retained(),
            receiver
                .pending()
                .map(|item| (item.ticket(), item.deadline())),
        );
        assert_eq!(
            receiver.check_time(original - Duration::from_nanos(1)),
            Ok(())
        );
        assert_eq!(receiver.check_time(original), Err(Error::Expired));
        assert_eq!(
            receiver.check_time(original + Duration::from_nanos(1)),
            Err(Error::Expired)
        );
        assert_eq!(
            (
                receiver.last_now,
                receiver.failed,
                receiver.retained(),
                receiver
                    .pending()
                    .map(|item| (item.ticket(), item.deadline()))
            ),
            before
        );
        assert_eq!(receiver.check_time(Duration::ZERO), Ok(()));
    }
    let owner = Owner::new(config, binding(Role::Client), Duration::ZERO, deadline)?;
    assert_eq!(owner.check_time(deadline - Duration::from_nanos(1)), Ok(()));
    assert_eq!(owner.check_time(deadline), Err(Error::Expired));
    assert_eq!(owner.failed, None);
    assert_eq!(
        owner.expiry_snapshot(deadline).candidate,
        Some(ExpiryCandidate {
            deadline,
            kind: ExpiryKind::Session,
        })
    );
    Ok(())
}

#[test]
fn readonly_time_check_excludes_only_actual_confirmed_outbound_expiry() -> TestResult {
    let bytes = ordinary_prepare()?.bytes;
    let mut network = Network::new(settings(), false)?;
    let deadline = Duration::from_millis(700);
    let ticket = network.peers[0].submit(SubmissionId(1), &bytes, Duration::ZERO, deadline)?;
    network.await_pending(1)?;
    let incoming = network.peers[1].pending().ok_or(Error::Protocol)?.ticket();
    let now = network.now();
    network.peers[1].accept(incoming, now)?;
    network.await_confirmed(0, ticket)?;
    assert_eq!(network.peers[0].retained().outbound_messages, 1);
    let before = (
        network.peers[0].last_now,
        network.peers[0].failed,
        network.peers[0].retained(),
    );
    assert_eq!(network.peers[0].check_time(deadline), Ok(()));
    assert_eq!(network.peers[0].expiry_snapshot(deadline).candidate, None);
    assert_eq!(
        (
            network.peers[0].last_now,
            network.peers[0].failed,
            network.peers[0].retained()
        ),
        before
    );
    Ok(())
}
