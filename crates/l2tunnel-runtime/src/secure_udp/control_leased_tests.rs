//! Actual two-Peer and whole-message-owner tests for the explicit leased bridge.

use super::*;
use l2tunnel_core::{ConfigDigest, Epoch, ModeConfig};
use l2tunnel_management::transaction as tx;

#[path = "control_v2_tests.rs"]
mod v2_tests;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const CAP: tx::Tick = tx::Tick(4_000);

fn base() -> delivery::Settings {
    delivery::Settings {
        recovery: recovery::ArqConfig {
            max_source_bytes: 192,
            send_bytes: 768,
            receive_bytes: 768,
            send_records: 4,
            receive_records: 4,
            initial_rto: Duration::from_millis(10),
            maximum_rto: Duration::from_millis(100),
            ack_delay: Duration::ZERO,
            max_retries: 64,
        },
        interval: Duration::from_millis(10),
        packets_per_interval: 2,
        bytes_per_interval: 2048,
        wire_overhead: 76,
    }
}

fn settings() -> Settings {
    let message = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: 84,
            ..base()
        },
        path_mtu: 1500,
        max_message_bytes: 2048,
        max_outbound_messages: 3,
        max_outbound_bytes: 8192,
        max_fragments: 16,
        max_reassembly_bytes: 4096,
        max_incomplete_messages: 1,
        message_lifetime: Duration::from_secs(2),
        work_per_call: 4,
    };
    Settings {
        streams: [message; 3],
    }
}

fn modes() -> [ModeConfig; 2] {
    [
        ModeConfig {
            channels: 2,
            ..ModeConfig::default()
        },
        ModeConfig {
            channels: 3,
            ..ModeConfig::default()
        },
    ]
}

fn binding(role: mg::Role) -> delivery::Binding {
    delivery::Binding {
        session: mg::SessionId([0x61; 16]),
        lane: mg::LaneId(0),
        local_role: role,
        control_epoch: 1,
    }
}

fn verified(role: mg::Role) -> mg::Ingress {
    mg::Ingress::AuthenticatedManagement {
        session: binding(role).session,
        lane: binding(role).lane,
        sender: role,
    }
}

fn control_scope() -> sc::Scope {
    sc::Scope {
        epoch: Epoch(1),
        digest: ConfigDigest([0x91; 32]),
    }
}

fn data_scope(epoch: u64, config: &ModeConfig) -> Result<sc::Scope> {
    Ok(sc::Scope {
        epoch: Epoch(epoch),
        digest: tx::configuration_digest(config)?,
    })
}

struct Lab {
    owners: [Owner; 2],
    peers: [tx::Peer; 2],
    now: Duration,
    emitted: Vec<WireFrame>,
}

struct WireFrame {
    side: usize,
    stream: streams::Stream,
    at: Duration,
    refill_start: Duration,
    wire_bytes: usize,
}

#[derive(Clone, Copy)]
enum TestStorage {
    Legacy,
    Arq,
    Complete,
}

impl Lab {
    fn new() -> Result<Self> {
        Self::with_settings(settings())
    }

    fn with_settings(selected: Settings) -> Result<Self> {
        Self::with_construction(selected, TestStorage::Legacy)
    }

    fn reserved(selected: Settings) -> Result<Self> {
        Self::with_construction(selected, TestStorage::Arq)
    }

    fn with_construction(selected: Settings, storage: TestStorage) -> Result<Self> {
        let catalog = modes();
        let make = |role| -> Result<(Owner, tx::Peer)> {
            let owner = if matches!(storage, TestStorage::Complete) {
                let plans = selected.message_storage_plans(
                    binding(role),
                    Duration::ZERO,
                    Duration::from_secs(10),
                )?;
                Owner::new_leased_reserved_messages(
                    base(),
                    selected,
                    binding(role),
                    control_scope(),
                    data_scope(1, &catalog[0])?,
                    Duration::ZERO,
                    Duration::from_secs(10),
                    plans.map(|plan| messages::storage::Limits {
                        capacity_bytes: plan.capacity_bytes(),
                    }),
                )?
            } else if matches!(storage, TestStorage::Arq) {
                let mut limits = [recovery::storage::Limits { capacity_bytes: 0 }; 3];
                for (limit, settings) in limits.iter_mut().zip(selected.streams) {
                    limit.capacity_bytes =
                        recovery::storage::Plan::for_arq(settings.delivery.recovery)?
                            .capacity_bytes();
                }
                Owner::new_leased_reserved_arq(
                    base(),
                    selected,
                    binding(role),
                    control_scope(),
                    data_scope(1, &catalog[0])?,
                    Duration::ZERO,
                    Duration::from_secs(10),
                    limits,
                )?
            } else {
                Owner::new_leased(
                    base(),
                    selected,
                    binding(role),
                    control_scope(),
                    data_scope(1, &catalog[0])?,
                    Duration::ZERO,
                    Duration::from_secs(10),
                )?
            };
            let identity = tx::Identity {
                session: binding(role).session,
                role,
                lane: binding(role).lane,
                local: mg::EndpointId(if role == mg::Role::Client { 11 } else { 22 }),
                remote: mg::EndpointId(if role == mg::Role::Client { 22 } else { 11 }),
            };
            let peer = tx::Peer::new_leased(
                identity,
                Epoch(1),
                catalog[0].clone(),
                &catalog,
                tx::Settings {
                    retry_ms: 10,
                    phase_timeout_ms: 3_000,
                    reconcile_timeout_ms: 4_000,
                },
                tx::LeaseSettings {
                    session_expires: tx::Tick(10_000),
                    max_operation_ms: 5_000,
                    transaction_epoch: owner.transaction_binding()?.control_epoch,
                },
                tx::Tick(0),
            )?;
            Ok((owner, peer))
        };
        let (client_owner, client) = make(mg::Role::Client)?;
        let (server_owner, server) = make(mg::Role::Server)?;
        Ok(Self {
            owners: [client_owner, server_owner],
            peers: [client, server],
            now: Duration::ZERO,
            emitted: Vec::new(),
        })
    }

    fn tick(&self) -> Result<tx::Tick> {
        Ok(tx::Tick(u64::try_from(self.now.as_millis())?))
    }

    fn pump(&mut self) -> Result {
        self.pump_filtered(false)
    }

    fn pump_filtered(&mut self, drop_server_transaction_data: bool) -> Result {
        self.now += Duration::from_millis(1);
        for side in 0..2 {
            let (left, right) = self.owners.split_at_mut(1);
            let (source, target, role) = if side == 0 {
                (&mut left[0], &mut right[0], mg::Role::Client)
            } else {
                (&mut right[0], &mut left[0], mg::Role::Server)
            };
            let mut allowance = 4096;
            let mut packet = [0; 512];
            while let Some(emission) = source.poll(self.now, allowance, &mut packet)? {
                allowance -= emission.wire_bytes;
                let limits = streams::Limits {
                    max_packet_bytes: 236,
                };
                let selected_v2 = matches!(&source.backend,
                    Backend::Streamed(streamed) if streamed.lifecycle.is_some());
                let frame = if selected_v2 {
                    let actual = streams::v2::Frame::decode(&packet[..emission.bytes], limits)?;
                    streams::Frame {
                        stream: actual.stream,
                        packet: actual.packet,
                    }
                } else {
                    streams::Frame::decode(&packet[..emission.bytes], limits)?
                };
                let Backend::Streamed(streamed) = &source.backend else {
                    return Err("leased pump requires streamed owner".into());
                };
                self.emitted.push(WireFrame {
                    side,
                    stream: frame.stream,
                    at: self.now,
                    refill_start: streamed
                        .refill
                        .checked_sub(streamed.quota.interval)
                        .ok_or("invalid actual quota refill")?,
                    wire_bytes: emission.wire_bytes,
                });
                let drop = side == 1
                    && drop_server_transaction_data
                    && frame.stream == streams::Stream::Transaction
                    && matches!(
                        recovery::inspect_packet(
                            frame.packet,
                            recovery::RecoveryContext {
                                session: u128::from_be_bytes(binding(role).session.0),
                                epoch: source.transaction_binding()?.control_epoch,
                                role: recovery::EndpointRole::Initiator,
                            },
                            192
                        )?,
                        recovery::PacketView::Data { .. }
                    );
                if !drop {
                    target.receive(verified(role), &packet[..emission.bytes], self.now)?;
                }
            }
        }
        Ok(())
    }

    fn prepare(&mut self) -> Result<Vec<u8>> {
        assert!(matches!(
            self.peers[0]
                .propose_until(modes()[1].clone(), self.tick()?, CAP)?
                .event,
            Some(tx::Event::Stage { .. })
        ));
        self.peers[0]
            .staged(tx::Fence::new(&[0, 0])?, self.tick()?)?
            .outbound
            .ok_or_else(|| "missing actual PREPARE".into())
    }

    fn send(&mut self, side: usize, command: &[u8]) -> Result<FrozenOutput> {
        let mut frozen =
            self.owners[side].freeze_transaction(&self.peers[side], command, self.now)?;
        assert!(matches!(
            self.owners[side].submit_frozen(&mut frozen, self.now)?,
            Attempt::Complete(_)
        ));
        Ok(frozen)
    }

    fn dispatched(&mut self, target: usize) -> Result<PendingEffect<ModeConfig>> {
        let mut slot = None;
        for _ in 0..300 {
            self.pump()?;
            if self.owners[target].dispatch_transaction(
                &mut self.peers[target],
                self.now,
                CAP,
                &mut slot,
            )? == DispatchProgress::Dispatched
            {
                return slot.ok_or_else(|| "dispatched without retained effects".into());
            }
        }
        Err("bounded transaction delivery did not dispatch".into())
    }

    fn accept(
        &mut self,
        target: usize,
        effect: &PendingEffect<ModeConfig>,
        terminal: bool,
    ) -> Result {
        let tick = self.tick()?;
        let peer = &mut self.peers[target];
        let accepted = self.owners[target].with_accepted(effect.incoming(), self.now, |proof| {
            if terminal {
                peer.complete_accepted(proof, effect.envelope(), tick)
                    .map_err(protocol)?;
            }
            Ok(())
        })?;
        assert_eq!(accepted, Attempt::Complete(()));
        Ok(())
    }

    fn confirm(
        &mut self,
        side: usize,
        frozen: &FrozenOutput,
        terminal: bool,
        retire: bool,
    ) -> Result {
        let token = frozen.token().ok_or("missing real outgoing token")?;
        for _ in 0..300 {
            self.pump()?;
            let tick = self.tick()?;
            let peer = &mut self.peers[side];
            if self.owners[side].with_confirmed(token, self.now, |proof| {
                if terminal {
                    peer.complete_confirmed(proof, frozen.envelope(), tick)
                        .map_err(protocol)?;
                }
                Ok(())
            })? == Attempt::Complete(())
            {
                if retire {
                    self.owners[side].retire(token, self.now)?;
                }
                return Ok(());
            }
        }
        Err("bounded whole-message confirmation did not complete".into())
    }

    fn exchange(&mut self, side: usize, command: &[u8]) -> Result<PendingEffect<ModeConfig>> {
        let frozen = self.send(side, command)?;
        let effect = self.dispatched(1 - side)?;
        self.accept(1 - side, &effect, false)?;
        self.confirm(side, &frozen, false, true)?;
        Ok(effect)
    }

    fn assert_shared_wire_quota(&self) {
        let mut windows = std::collections::BTreeMap::new();
        for frame in &self.emitted {
            let selected_v2 = matches!(&self.owners[frame.side].backend,
                Backend::Streamed(streamed) if streamed.lifecycle.is_some());
            let all: &[streams::Stream] = if selected_v2 {
                &streams::v2::ALL
            } else {
                &streams::Stream::ALL
            };
            assert!(all.contains(&frame.stream));
            assert!(frame.at >= frame.refill_start);
            assert!(frame.at < frame.refill_start + base().interval);
            let totals = windows
                .entry((frame.side, frame.refill_start))
                .or_insert((0, 0));
            totals.0 += 1;
            totals.1 += frame.wire_bytes;
            assert!(totals.0 <= base().packets_per_interval);
            assert!(totals.1 <= base().bytes_per_interval);
        }
        assert!(
            self.emitted
                .iter()
                .any(|frame| frame.stream == streams::Stream::Transaction)
        );
        assert!(
            self.emitted
                .iter()
                .any(|frame| frame.stream == streams::Stream::Liveness)
        );
    }

    /// Both messages must reach semantic acceptance, real confirmation and retirement.
    fn ping_pong(&mut self, nonce: u64, drop_server_transaction_data: bool) -> Result {
        let ping = self.owners[0]
            .submit(
                control_scope(),
                sc::Body::Ping { nonce },
                self.now,
                CAP_DURATION,
                false,
            )?
            .ok_or("reserved Ping admission")?;
        let mut pong = None;
        let mut received_pong = false;
        let mut ping_confirmed = false;
        let mut pong_confirmed = false;
        for _ in 0..100 {
            self.pump_filtered(drop_server_transaction_data)?;
            let mut scratch = [0; 2048];
            if pong.is_none()
                && let Some(incoming) = self.owners[1].next(self.now, &mut scratch)?
            {
                assert_eq!(incoming.stream, Some(streams::Stream::Liveness));
                let envelope =
                    sc::Envelope::decode(&scratch[..incoming.bytes], envelope_limits(2048)?)?;
                assert_eq!(envelope.binding.scope, control_scope());
                assert_eq!(envelope.body, sc::Body::Ping { nonce });
                self.owners[1].accepted(incoming, self.now)?;
                pong = Some(
                    self.owners[1]
                        .submit(
                            control_scope(),
                            sc::Body::Pong { nonce },
                            self.now,
                            CAP_DURATION,
                            false,
                        )?
                        .ok_or("reserved Pong admission")?,
                );
            }
            if !received_pong && let Some(incoming) = self.owners[0].next(self.now, &mut scratch)? {
                assert_eq!(incoming.stream, Some(streams::Stream::Liveness));
                let envelope =
                    sc::Envelope::decode(&scratch[..incoming.bytes], envelope_limits(2048)?)?;
                assert_eq!(envelope.binding.scope, control_scope());
                assert_eq!(envelope.body, sc::Body::Pong { nonce });
                self.owners[0].accepted(incoming, self.now)?;
                received_pong = true;
            }
            if !ping_confirmed && self.owners[0].confirmed(ping, self.now)? {
                self.owners[0].retire(ping, self.now)?;
                ping_confirmed = true;
            }
            if let Some(pong) = pong
                && !pong_confirmed
                && self.owners[1].confirmed(pong, self.now)?
            {
                self.owners[1].retire(pong, self.now)?;
                pong_confirmed = true;
            }
            if received_pong && ping_confirmed && pong_confirmed {
                return Ok(());
            }
        }
        Err("bounded reserved Ping/Pong did not confirm and retire".into())
    }
}

#[test]
fn joint_dispatch_waits_for_effect_capacity_and_does_not_commit_invalid_cap() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let _frozen = lab.send(0, &prepare)?;
    for _ in 0..50 {
        lab.pump()?;
    }
    let mut slot = None;
    let highest = match &lab.owners[1].backend {
        Backend::Streamed(s) => s.gate.highest_packet(streams::Stream::Transaction),
        Backend::Legacy(_) => return Err("wrong backend".into()),
    };
    assert!(
        lab.owners[1]
            .dispatch_transaction(&mut lab.peers[1], lab.now, tx::Tick(0), &mut slot)
            .is_err()
    );
    assert!(slot.is_none());
    assert_eq!(lab.peers[1].phase(), tx::Phase::Idle);
    let Backend::Streamed(s) = &lab.owners[1].backend else {
        return Err("wrong backend".into());
    };
    assert_eq!(s.gate.highest_packet(streams::Stream::Transaction), highest);
    assert_eq!(
        lab.owners[1].dispatch_transaction(&mut lab.peers[1], lab.now, CAP, &mut slot)?,
        DispatchProgress::Dispatched
    );
    let bytes = slot.as_ref().ok_or("missing effects")?.envelope().to_vec();
    assert_eq!(lab.peers[1].phase(), tx::Phase::FollowerStaging);
    assert_eq!(
        lab.owners[1].dispatch_transaction(&mut lab.peers[1], lab.now, CAP, &mut slot)?,
        DispatchProgress::Blocked
    );
    assert_eq!(slot.as_ref().ok_or("lost effects")?.envelope(), bytes);
    let retained = slot.take().ok_or("lost effects")?;
    assert_eq!(
        lab.owners[1].dispatch_transaction(&mut lab.peers[1], lab.now, CAP, &mut slot)?,
        DispatchProgress::Blocked
    );
    assert!(
        lab.owners[1]
            .accepted(retained.incoming(), lab.now)
            .is_err()
    );
    lab.accept(1, &retained, false)?;
    Ok(())
}

#[test]
fn source_acks_cannot_supply_complete_confirmation_before_actual_acceptance() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let frozen = lab.send(0, &prepare)?;
    let effect = lab.dispatched(1)?;
    for _ in 0..30 {
        lab.pump()?;
    }
    assert_eq!(lab.owners[0].retained().send_records, 0);
    let Backend::Streamed(streamed) = &lab.owners[0].backend else {
        return Err("expected actual streamed owner".into());
    };
    let snapshot = streamed.owners[0].buffer_snapshot();
    assert_eq!(snapshot.retained.recovery.send_records, 0);
    assert_eq!(snapshot.awaiting_accepted, 1);
    assert_eq!(snapshot.confirmed_metadata, 0);
    assert_eq!(snapshot.retained.outbound_messages, 1);
    assert!(!snapshot.counter_overflow);
    let mut called = false;
    assert_eq!(
        lab.owners[0].with_confirmed(frozen.token().ok_or("missing token")?, lab.now, |_| {
            called = true;
            Ok(())
        })?,
        Attempt::Blocked
    );
    assert!(!called);
    assert!(lab.owners[1].has_dispatched());
    lab.accept(1, &effect, false)?;
    lab.confirm(0, &frozen, false, true)?;
    Ok(())
}

#[test]
fn receipt_pressure_retains_one_dispatch_until_real_source_ack_frees_capacity() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let frozen = lab.send(0, &prepare)?;
    let first_effect = lab.dispatched(1)?;
    // Occupy the actual Transaction recovery owner, rather than replacing its
    // capacity or confirmation state with a test flag. The receiver need not
    // semantically accept this auxiliary message to ACK its recovery sources.
    let Backend::Streamed(streamed) = &mut lab.owners[1].backend else {
        return Err("wrong backend".into());
    };
    let owner = &mut streamed.owners[index(streams::Stream::Transaction)];
    owner.submit(
        messages::SubmissionId(999),
        &[0x73; 600],
        lab.now,
        lab.now + Duration::from_secs(2),
    )?;
    for _ in 0..8 {
        owner.tick(lab.now)?;
    }
    assert_eq!(owner.retained().recovery.send_records, 3);
    lab.accept(1, &first_effect, false)?;
    let _ready = lab.peers[1].staged(tx::Fence::new(&[0, 0])?, lab.tick()?)?;
    for _ in 0..10 {
        lab.pump_filtered(true)?;
    }
    let retry = lab.peers[0]
        .poll(lab.tick()?)?
        .outbound
        .ok_or("missing actual PREPARE retry")?;
    let _retry_frozen = lab.send(0, &retry)?;
    let mut slot = None;
    for _ in 0..100 {
        lab.pump_filtered(true)?;
        if lab.owners[1].dispatch_transaction(&mut lab.peers[1], lab.now, CAP, &mut slot)?
            == DispatchProgress::Dispatched
        {
            break;
        }
    }
    let effect = slot
        .take()
        .ok_or("missing duplicate logical request dispatch")?;
    let original = effect.envelope().to_vec();
    let Backend::Streamed(streamed) = &lab.owners[1].backend else {
        return Err("wrong backend".into());
    };
    assert_eq!(
        streamed.owners[index(streams::Stream::Transaction)]
            .retained()
            .recovery
            .send_records,
        4
    );
    let mut called = false;
    assert_eq!(
        lab.owners[1].with_accepted(effect.incoming(), lab.now, |_| {
            called = true;
            Ok(())
        })?,
        Attempt::Blocked
    );
    assert!(!called);
    assert!(lab.owners[1].has_dispatched());
    assert_eq!(effect.envelope(), original);
    let mut slot = None;
    assert_eq!(
        lab.owners[1].dispatch_transaction(&mut lab.peers[1], lab.now, CAP, &mut slot)?,
        DispatchProgress::Blocked
    );
    let mut accepted = false;
    for _ in 0..100 {
        lab.pump()?;
        if lab.owners[1].with_accepted(effect.incoming(), lab.now, |_| Ok(()))?
            == Attempt::Complete(())
        {
            accepted = true;
            break;
        }
    }
    assert!(accepted);
    assert_eq!(effect.envelope(), original);
    assert!(!lab.owners[1].has_dispatched());
    lab.confirm(0, &frozen, false, true)?;
    Ok(())
}

#[test]
fn liveness_does_not_overwrite_retained_transaction_bytes_or_force_acceptance() -> Result {
    let mut selected = settings();
    for stream in &mut selected.streams {
        stream.message_lifetime = Duration::from_secs(5);
    }
    let mut lab = Lab::with_settings(selected)?;
    let prepare = lab.prepare()?;
    let frozen = lab.send(0, &prepare)?;
    let effect = lab.dispatched(1)?;
    let original = effect.envelope().to_vec();
    for nonce in 1..=130 {
        let mut received = false;
        let token = lab.owners[0].submit(
            control_scope(),
            sc::Body::Ping { nonce },
            lab.now,
            CAP_DURATION,
            true,
        )?;
        assert!(token.is_some());
        for _ in 0..50 {
            lab.pump()?;
            let mut scratch = [0; 2048];
            if let Some(incoming) = lab.owners[1].next(lab.now, &mut scratch)? {
                let envelope =
                    sc::Envelope::decode(&scratch[..incoming.bytes], envelope_limits(2048)?)?;
                assert_eq!(envelope.body, sc::Body::Ping { nonce });
                lab.owners[1].accepted(incoming, lab.now)?;
                received = true;
            }
            let retired = match &lab.owners[0].backend {
                Backend::Streamed(s) => s.outgoing[index(streams::Stream::Liveness)].is_empty(),
                Backend::Legacy(_) => false,
            };
            if received && retired {
                break;
            }
        }
        assert!(received);
        assert_eq!(effect.envelope(), original);
        assert!(lab.owners[1].has_dispatched());
        assert_eq!(
            lab.owners[0].with_confirmed(
                frozen.token().ok_or("missing token")?,
                lab.now,
                |_| Ok(())
            )?,
            Attempt::Blocked
        );
    }
    lab.accept(1, &effect, false)?;
    lab.confirm(0, &frozen, false, true)?;
    Ok(())
}

const CAP_DURATION: Duration = Duration::from_millis(CAP.0);

fn reserved_pressure_lab(complete: bool) -> Result<Lab> {
    let mut selected = settings();
    for stream in &mut selected.streams {
        stream.message_lifetime = Duration::from_secs(5);
    }
    let lab = if complete {
        Lab::with_construction(selected, TestStorage::Complete)?
    } else {
        Lab::reserved(selected)?
    };
    for owner in &lab.owners {
        if complete {
            let plans = selected.message_storage_plans(
                owner.binding,
                Duration::ZERO,
                Duration::from_secs(10),
            )?;
            for (usage, plan) in owner
                .message_storage_usage()
                .ok_or("missing complete control storage")?
                .into_iter()
                .zip(plans)
            {
                assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
                assert_eq!(usage.limit_bytes, usage.capacity_bytes);
                assert_eq!(
                    usage.reassembly.capacity_bytes,
                    plan.reassembly_plan().capacity_bytes()
                );
                assert_eq!(usage.arq.capacity_bytes, plan.arq_plan().capacity_bytes());
            }
            assert_eq!(
                owner.wrapper_capacity_bytes()?,
                selected.wrapper_capacity_bytes(base())?
            );
        } else {
            assert!(owner.message_storage_usage().is_none());
        }
        let usage = owner
            .arq_storage_usage()
            .ok_or("missing actual reserved stream owners")?;
        for (actual, settings) in usage.into_iter().zip(selected.streams) {
            assert_eq!(
                actual.capacity_bytes,
                recovery::storage::Plan::for_arq(settings.delivery.recovery)?.capacity_bytes()
            );
            assert_eq!(actual.limit_bytes, actual.capacity_bytes);
        }
    }
    Ok(lab)
}

type PoolUsage = (
    [[recovery::storage::Usage; 3]; 2],
    [Option<[messages::storage::Usage; 3]>; 2],
);
fn actual_pool_usage(lab: &Lab) -> Result<PoolUsage> {
    Ok((
        [
            lab.owners[0]
                .arq_storage_usage()
                .ok_or("missing client pools")?,
            lab.owners[1]
                .arq_storage_usage()
                .ok_or("missing server pools")?,
        ],
        lab.owners
            .each_ref()
            .map(|owner| owner.message_storage_usage()),
    ))
}

fn assert_original_held_effect(
    lab: &Lab,
    effect: &PendingEffect<ModeConfig>,
    bytes: &[u8],
    original_message_deadline: Duration,
) -> Result {
    assert_eq!(effect.envelope(), bytes);
    assert_eq!(effect.operation().expires(), CAP);
    for peer in &lab.peers {
        assert_eq!(
            peer.operation()
                .ok_or("lost original Peer operation")?
                .expires(),
            CAP
        );
    }
    let Backend::Streamed(streamed) = &lab.owners[1].backend else {
        return Err("wrong reserved backend".into());
    };
    let held = streamed.held[index(streams::Stream::Transaction)]
        .ok_or("lost actual retained Transaction effect")?;
    assert_eq!(held.incoming, effect.incoming());
    assert_eq!(held.deadline, original_message_deadline);
    assert!(held.dispatched && held.leased);
    Ok(())
}

fn held_effect_deadline(lab: &Lab) -> Result<Duration> {
    let Backend::Streamed(streamed) = &lab.owners[1].backend else {
        return Err("wrong reserved backend".into());
    };
    Ok(streamed.held[index(streams::Stream::Transaction)]
        .ok_or("missing actual held Transaction")?
        .deadline)
}

#[test]
fn reserved_held_transaction_allows_sixteen_confirmed_ping_pong_pairs_with_shared_quota() -> Result
{
    for complete in [false, true] {
        let mut lab = reserved_pressure_lab(complete)?;
        let usage = actual_pool_usage(&lab)?;
        let prepare = lab.prepare()?;
        let frozen = lab.send(0, &prepare)?;
        let deadline = frozen.deadline();
        let effect = lab.dispatched(1)?;
        let exact = effect.envelope().to_vec();
        let held_deadline = held_effect_deadline(&lab)?;
        let phases = [lab.peers[0].phase(), lab.peers[1].phase()];
        for nonce in 1..=16 {
            lab.ping_pong(nonce, false)?;
            assert_original_held_effect(&lab, &effect, &exact, held_deadline)?;
            assert_eq!(frozen.deadline(), deadline);
            assert_eq!([lab.peers[0].phase(), lab.peers[1].phase()], phases);
            assert_eq!(actual_pool_usage(&lab)?, usage);
            let mut called = false;
            assert_eq!(
                lab.owners[0].with_confirmed(
                    frozen.token().ok_or("missing original token")?,
                    lab.now,
                    |_| {
                        called = true;
                        Ok(())
                    },
                )?,
                Attempt::Blocked
            );
            assert!(!called);
        }
        assert!(lab.now < Duration::from_secs(2));
        lab.assert_shared_wire_quota();
        lab.accept(1, &effect, false)?;
        lab.confirm(0, &frozen, false, true)?;
        assert!(!lab.owners[1].has_dispatched());
        assert_eq!(actual_pool_usage(&lab)?, usage);
        lab.assert_shared_wire_quota();
    }
    Ok(())
}

#[test]
fn reserved_saturated_transaction_preserves_effect_while_sixteen_ping_pong_pairs_settle() -> Result
{
    for complete in [false, true] {
        let mut lab = reserved_pressure_lab(complete)?;
        let usage = actual_pool_usage(&lab)?;
        let prepare = lab.prepare()?;
        let frozen = lab.send(0, &prepare)?;
        let first = lab.dispatched(1)?;
        let Backend::Streamed(streamed) = &mut lab.owners[1].backend else {
            return Err("wrong reserved backend".into());
        };
        let transaction = &mut streamed.owners[index(streams::Stream::Transaction)];
        transaction.submit(
            messages::SubmissionId(999),
            &[0x73; 600],
            lab.now,
            lab.now + Duration::from_secs(2),
        )?;
        for _ in 0..8 {
            transaction.tick(lab.now)?;
        }
        assert_eq!(transaction.retained().recovery.send_records, 3);
        lab.accept(1, &first, false)?;
        let _ready = lab.peers[1].staged(tx::Fence::new(&[0, 0])?, lab.tick()?)?;
        for _ in 0..10 {
            lab.pump_filtered(true)?;
        }
        let retry = lab.peers[0]
            .poll(lab.tick()?)?
            .outbound
            .ok_or("missing real PREPARE retry")?;
        let repeated = lab.send(0, &retry)?;
        let mut slot = None;
        for _ in 0..100 {
            lab.pump_filtered(true)?;
            if lab.owners[1].dispatch_transaction(&mut lab.peers[1], lab.now, CAP, &mut slot)?
                == DispatchProgress::Dispatched
            {
                break;
            }
        }
        let effect = slot.ok_or("saturated Transaction did not dispatch actual retry")?;
        let exact = effect.envelope().to_vec();
        let held_deadline = held_effect_deadline(&lab)?;
        let phases = [lab.peers[0].phase(), lab.peers[1].phase()];
        for nonce in 1..=16 {
            let Backend::Streamed(streamed) = &lab.owners[1].backend else {
                return Err("wrong reserved backend".into());
            };
            assert_eq!(
                streamed.owners[index(streams::Stream::Transaction)]
                    .retained()
                    .recovery
                    .send_records,
                base().recovery.send_records
            );
            let mut called = false;
            assert_eq!(
                lab.owners[1].with_accepted(effect.incoming(), lab.now, |_| {
                    called = true;
                    Ok(())
                })?,
                Attempt::Blocked
            );
            assert!(!called);
            lab.ping_pong(nonce, true)?;
            assert_original_held_effect(&lab, &effect, &exact, held_deadline)?;
            assert_eq!([lab.peers[0].phase(), lab.peers[1].phase()], phases);
            assert_eq!(frozen.deadline(), CAP_DURATION);
            assert_eq!(repeated.deadline(), CAP_DURATION);
            assert_eq!(actual_pool_usage(&lab)?, usage);
            let Backend::Streamed(streamed) = &lab.owners[1].backend else {
                return Err("wrong reserved backend".into());
            };
            assert_eq!(
                streamed.owners[index(streams::Stream::Transaction)]
                    .retained()
                    .recovery
                    .send_records,
                base().recovery.send_records
            );
        }
        assert!(lab.now < Duration::from_secs(2));
        lab.assert_shared_wire_quota();
        let mut settled = false;
        for _ in 0..100 {
            lab.pump()?;
            if lab.owners[1].with_accepted(effect.incoming(), lab.now, |_| Ok(()))?
                == Attempt::Complete(())
            {
                settled = true;
                break;
            }
        }
        assert!(settled);
        assert_eq!(effect.envelope(), exact);
        assert!(!lab.owners[1].has_dispatched());
        lab.confirm(0, &frozen, false, true)?;
        lab.confirm(0, &repeated, false, true)?;
        assert_eq!(actual_pool_usage(&lab)?, usage);
        lab.assert_shared_wire_quota();
    }
    Ok(())
}

#[test]
fn reserved_liveness_never_renews_original_held_operation_cap() -> Result {
    for complete in [false, true] {
        let mut lab = reserved_pressure_lab(complete)?;
        let usage = actual_pool_usage(&lab)?;
        let prepare = lab.prepare()?;
        let frozen = lab.send(0, &prepare)?;
        let effect = lab.dispatched(1)?;
        let exact = effect.envelope().to_vec();
        let held_deadline = held_effect_deadline(&lab)?;
        for nonce in 1..=16 {
            lab.ping_pong(nonce, false)?;
        }
        assert_original_held_effect(&lab, &effect, &exact, held_deadline)?;
        assert_eq!(frozen.deadline(), CAP_DURATION);
        assert_eq!(lab.owners[0].expiry(), CAP_DURATION);
        lab.assert_shared_wire_quota();
        lab.now = CAP_DURATION;
        let mut called = false;
        assert!(
            lab.owners[0]
                .with_confirmed(
                    frozen.token().ok_or("missing original token")?,
                    lab.now,
                    |_| {
                        called = true;
                        Ok(())
                    }
                )
                .is_err()
        );
        assert!(!called);
        for peer in &mut lab.peers {
            assert_eq!(peer.poll(CAP), Err(tx::Error::LeaseExpired));
            assert_eq!(peer.phase(), tx::Phase::Failed);
        }
        assert_eq!(effect.envelope(), exact);
        assert_eq!(effect.operation().expires(), CAP);
        assert_eq!(held_effect_deadline(&lab)?, held_deadline);
        assert!(lab.owners[1].has_dispatched());
        assert_eq!(actual_pool_usage(&lab)?, usage);
    }
    Ok(())
}

#[test]
fn frozen_retry_is_exact_and_confirmed_intermediate_does_not_renew_message_deadline() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let mut frozen = lab.send(0, &prepare)?;
    let effect = lab.dispatched(1)?;
    lab.accept(1, &effect, false)?;
    lab.confirm(0, &frozen, false, false)?;
    let original = frozen.envelope().to_vec();
    let deadline = frozen.deadline();
    let retry = lab.peers[0]
        .poll(lab.tick()?)?
        .outbound
        .ok_or("missing actual logical retry")?;
    assert_ne!(retry, prepare);
    assert!(frozen.logical_matches(&lab.peers[0], &retry)?);
    lab.now = deadline + Duration::from_millis(1);
    assert_eq!(lab.owners[0].pending_deadline(), None);
    assert_eq!(
        lab.owners[0].submit_frozen(&mut frozen, lab.now)?,
        Attempt::Complete(frozen.token().ok_or("lost token")?)
    );
    assert_eq!(frozen.envelope(), original);
    assert_eq!(frozen.deadline(), deadline);
    assert_eq!(
        lab.peers[0]
            .operation()
            .ok_or("lost original operation")?
            .expires(),
        CAP
    );
    Ok(())
}

#[test]
fn refused_next_logical_output_keeps_candidate_bytes_id_and_original_cap() -> Result {
    let mut selected = settings();
    selected.streams[0].max_outbound_messages = 1;
    let mut lab = Lab::with_settings(selected)?;
    lab.owners[0].enable_buffer_metrics();
    let prepare = lab.prepare()?;
    let first = lab.send(0, &prepare)?;
    let staged = lab.dispatched(1)?;
    lab.accept(1, &staged, false)?;
    lab.confirm(0, &first, false, false)?;
    let ready = lab.peers[1]
        .staged(tx::Fence::new(&[0, 0])?, lab.tick()?)?
        .outbound
        .ok_or("missing READY")?;
    let _drain = lab.exchange(1, &ready)?;
    let fence = tx::Fence::new(&[0, 0])?;
    let barrier = lab.peers[0]
        .confirm_drained(&fence, &fence, lab.tick()?)?
        .outbound
        .ok_or("missing BARRIER")?;
    let mut frozen = lab.owners[0].freeze_transaction(&lab.peers[0], &barrier, lab.now)?;
    let exact = frozen.envelope().to_vec();
    let id = frozen.submission();
    let deadline = frozen.deadline();
    assert_eq!(id.0, 2);
    let first_refusal = lab.now;
    for _ in 0..20 {
        assert_eq!(
            lab.owners[0].submit_frozen(&mut frozen, lab.now)?,
            Attempt::Blocked
        );
        assert_eq!(frozen.envelope(), exact);
        assert_eq!(frozen.submission(), id);
        assert_eq!(frozen.deadline(), deadline);
        assert_eq!(frozen.operation().expires(), CAP);
        lab.pump()?;
    }
    assert!(
        lab.owners[0]
            .freeze_transaction(&lab.peers[0], &barrier, lab.now)
            .is_err()
    );
    let before = management_report(&lab.owners[0], lab.now)?;
    assert_eq!(before["streams"][0]["stream"], "Transaction");
    assert_eq!(
        before["frozen_submission_wait"]["wrapper_entry_refusals"],
        20
    );
    assert_eq!(before["frozen_submission_wait"]["completed_episodes"], 0);
    assert_eq!(
        before["frozen_submission_wait"]["first_refusal_us"],
        u64::try_from(first_refusal.as_micros())?
    );
    assert_eq!(
        before["frozen_submission_wait"]["pending"]["submission"],
        id.0
    );
    lab.owners[0].retire(first.token().ok_or("missing first token")?, lab.now)?;
    assert!(matches!(
        lab.owners[0].submit_frozen(&mut frozen, lab.now)?,
        Attempt::Complete(_)
    ));
    assert_eq!(frozen.submission(), id);
    assert_eq!(frozen.envelope(), exact);
    let after = management_report(&lab.owners[0], lab.now)?;
    assert_eq!(after["frozen_submission_wait"]["completed_episodes"], 1);
    assert_eq!(after["frozen_submission_wait"]["censored_episodes"], 0);
    assert!(after["frozen_submission_wait"]["pending"].is_null());
    assert_eq!(
        after["frozen_submission_wait"]["completed_us"],
        u64::try_from((lab.now - first_refusal).as_micros())?
    );
    assert_eq!(
        after["frozen_submission_wait"]["last_resolved"]["identity"]["original_deadline_us"],
        u64::try_from(deadline.as_micros())?
    );
    assert_eq!(
        after["frozen_submission_wait"]["last_resolved"]["outcome"],
        "Admitted"
    );
    assert_eq!(after["binding"]["control_epoch"], 1);
    assert_eq!(
        after["streams"].as_array().ok_or("missing streams")?.len(),
        3
    );
    assert_eq!(after["invalid_occupancy"], false);
    Ok(())
}

#[test]
fn unadmitted_reservation_expires_without_transmission_or_fresh_identity() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let mut frozen = lab.owners[0].freeze_transaction(&lab.peers[0], &prepare, lab.now)?;
    let original = frozen.envelope().to_vec();
    assert_eq!(lab.owners[0].pending_deadline(), Some(frozen.deadline()));
    assert_eq!(lab.owners[0].expiry(), frozen.deadline());
    assert!(lab.owners[0].deadline() <= frozen.deadline());
    assert_eq!(lab.owners[0].retained(), recovery::Retained::default());
    lab.now = frozen.deadline();
    assert_eq!(
        lab.owners[0]
            .submit_frozen(&mut frozen, lab.now)
            .err()
            .ok_or("expired output admitted")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(frozen.submission().0, 1);
    assert_eq!(frozen.envelope(), original);
    assert!(frozen.token().is_none());
    Ok(())
}

#[test]
fn reservation_cancellation_requires_actual_same_operation_supersession() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let mut frozen = lab.owners[0].freeze_transaction(&lab.peers[0], &prepare, lab.now)?;
    assert!(
        lab.owners[0]
            .cancel_frozen(&lab.peers[0], &mut frozen, lab.now)
            .is_err()
    );
    assert_eq!(lab.owners[0].pending_deadline(), Some(frozen.deadline()));
    // Only the real Peer can supersede its logical command. Feed genuine
    // encoded peer output directly here to isolate cancellation from transport.
    lab.peers[1].receive_until(verified(mg::Role::Client), &prepare, tx::Tick(0), CAP)?;
    let ready = lab.peers[1]
        .staged(tx::Fence::new(&[0, 0])?, tx::Tick(0))?
        .outbound
        .ok_or("missing READY")?;
    lab.peers[0].receive_until(verified(mg::Role::Server), &ready, tx::Tick(0), CAP)?;
    assert_eq!(lab.peers[0].operation(), Some(frozen.operation()));
    lab.owners[0].cancel_frozen(&lab.peers[0], &mut frozen, lab.now)?;
    assert_eq!(lab.owners[0].pending_deadline(), None);
    assert!(lab.owners[0].submit_frozen(&mut frozen, lab.now).is_err());
    let fence = tx::Fence::new(&[0, 0])?;
    let barrier = lab.peers[0]
        .confirm_drained(&fence, &fence, tx::Tick(0))?
        .outbound
        .ok_or("missing BARRIER")?;
    let next = lab.owners[0].freeze_transaction(&lab.peers[0], &barrier, lab.now)?;
    assert_eq!(next.submission().0, frozen.submission().0);
    assert_eq!(next.operation().expires(), CAP);
    Ok(())
}

#[test]
fn explicit_contract_rejects_another_peer_binding_and_liveness_confirmation() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    assert!(
        lab.owners[1]
            .freeze_transaction(&lab.peers[0], &prepare, lab.now)
            .is_err()
    );
    let live = lab.owners[0]
        .submit(
            control_scope(),
            sc::Body::Ping { nonce: 71 },
            lab.now,
            CAP_DURATION,
            false,
        )?
        .ok_or("missing liveness token")?;
    assert!(
        lab.owners[0]
            .with_confirmed(live, lab.now, |_| Ok(()))
            .is_err()
    );
    let frozen = lab.owners[0].freeze_transaction(&lab.peers[0], &prepare, lab.now)?;
    let envelope = sc::Envelope::decode(frozen.envelope(), envelope_limits(2048)?)?;
    assert_eq!(envelope.binding.scope, data_scope(1, &modes()[0])?);
    assert_eq!(envelope.body, sc::Body::Management(prepare.as_slice()));
    let legacy = Owner::new(
        base(),
        Some(settings()),
        binding(mg::Role::Client),
        control_scope(),
        data_scope(1, &modes()[0])?,
        lab.now,
        Duration::from_secs(10),
    )?;
    assert!(legacy.transaction_binding().is_err());
    Ok(())
}

#[test]
fn callback_failure_is_terminal_after_real_acceptance_and_cannot_dispatch_twice() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let _frozen = lab.send(0, &prepare)?;
    let effect = lab.dispatched(1)?;
    let result: io::Result<Attempt<()>> =
        lab.owners[1].with_accepted(effect.incoming(), lab.now, |_proof| {
            Err(io::Error::other("injected semantic completion failure"))
        });
    assert!(result.is_err());
    let mut output = [0; 512];
    assert!(lab.owners[1].poll(lab.now, 4096, &mut output).is_err());
    assert!(
        lab.owners[1]
            .with_accepted(effect.incoming(), lab.now, |_| Ok(()))
            .is_err()
    );
    assert!(lab.owners[1].has_dispatched());
    Ok(())
}

#[test]
fn real_final_proofs_release_both_peers_after_data_scope_retirement() -> Result {
    let mut lab = Lab::new()?;
    let old = data_scope(1, &modes()[0])?;
    let next = data_scope(2, &modes()[1])?;
    let prepare = lab.prepare()?;
    let stage = lab.exchange(0, &prepare)?;
    assert!(matches!(
        stage.effects().event,
        Some(tx::Event::Stage { .. })
    ));
    let fence = tx::Fence::new(&[0, 0])?;
    let ready = lab.peers[1]
        .staged(fence.clone(), lab.tick()?)?
        .outbound
        .ok_or("missing READY")?;
    let drain = lab.exchange(1, &ready)?;
    assert!(matches!(
        drain.effects().event,
        Some(tx::Event::Drain { .. })
    ));
    let barrier = lab.peers[0]
        .confirm_drained(&fence, &fence, lab.tick()?)?
        .outbound
        .ok_or("missing BARRIER")?;
    let no_reply = lab.exchange(0, &barrier)?;
    assert!(no_reply.effects().outbound.is_none());
    let acknowledgement = lab.peers[1]
        .confirm_drained(&fence, &fence, lab.tick()?)?
        .outbound
        .ok_or("missing BARRIER reply")?;
    let mut commit = lab.exchange(1, &acknowledgement)?;
    let mut commit_ack = lab.exchange(0, &commit.take_outbound().ok_or("missing COMMIT")?)?;
    assert!(matches!(
        commit_ack.effects().event,
        Some(tx::Event::Committed(_))
    ));
    lab.owners[1].advance_scope(next)?;
    assert!(
        lab.owners[1]
            .retire_leased_draining(&lab.peers[1], old, lab.now)
            .is_err()
    );
    let mut retire = lab.exchange(1, &commit_ack.take_outbound().ok_or("missing COMMIT ACK")?)?;
    assert!(matches!(
        retire.effects().event,
        Some(tx::Event::Committed(_))
    ));
    lab.owners[0].advance_scope(next)?;
    let retire_request = retire.take_outbound().ok_or("missing RETIRE")?;
    let mut retired = lab.exchange(0, &retire_request)?;
    assert!(matches!(
        retired.effects().event,
        Some(tx::Event::Retired(Epoch(1)))
    ));
    lab.owners[1].retire_leased_draining(&lab.peers[1], old, lab.now)?;
    assert!(lab.peers[1].operation().is_some());
    assert!(lab.peers[1].cached_retry_authority(lab.tick()?)?.is_some());
    let final_reply = retired
        .take_outbound()
        .ok_or("missing exact RETIRE reply")?;
    for _ in 0..10 {
        lab.pump()?;
    }
    let retry = lab.peers[0]
        .poll(lab.tick()?)?
        .outbound
        .ok_or("missing real RETIRE retry")?;
    let cached = lab.exchange(0, &retry)?;
    assert!(cached.effects().event.is_none());
    let repeated = cached
        .effects()
        .outbound
        .as_ref()
        .ok_or("missing exact cached reply")?;
    let first = mg::Frame::decode(&final_reply, mg::Limits::default())?;
    let repeated = mg::Frame::decode(repeated, mg::Limits::default())?;
    assert!(first.header.same_request(repeated.header));
    assert_eq!(first.body, repeated.body);
    let frozen = lab.send(1, &final_reply)?;
    assert!(frozen.context().is_final_reply());
    let accepted = lab.dispatched(0)?;
    assert_eq!(accepted.operation().expires(), CAP);
    assert!(matches!(
        accepted.effects().event,
        Some(tx::Event::Retired(Epoch(1)))
    ));
    lab.owners[0].retire_leased_draining(&lab.peers[0], old, lab.now)?;
    assert!(lab.peers[0].operation().is_some());
    lab.accept(0, &accepted, true)?;
    assert!(lab.peers[0].operation().is_none());
    assert!(lab.peers[1].operation().is_some());
    lab.confirm(1, &frozen, true, true)?;
    assert!(lab.peers[1].operation().is_none());
    assert_eq!(lab.peers[0].active_epoch(), Epoch(2));
    assert_eq!(lab.peers[1].active_epoch(), Epoch(2));
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct PreviewState {
    owner_now: Duration,
    owner_failed: bool,
    next: [u64; 4],
    highest: [Option<mg::PacketNumber>; 3],
    retained: [messages::Retained; 3],
    held: [Option<Incoming>; 4],
    pending: Option<(messages::Ticket, Duration, Vec<u8>, usize)>,
    phase: tx::Phase,
    operation: Option<tx::Operation>,
    active: ModeConfig,
    epoch: Epoch,
    requests: usize,
    replies: usize,
    phase_deadline: Option<tx::Tick>,
}

fn preview_state(lab: &Lab, side: usize) -> Result<PreviewState> {
    let owner = &lab.owners[side];
    let Backend::Streamed(streamed) = &owner.backend else {
        return Err("wrong preview backend".into());
    };
    let peer = &lab.peers[side];
    Ok(PreviewState {
        owner_now: owner.now,
        owner_failed: owner.failed,
        next: streamed.next,
        highest: streams::Stream::ALL.map(|stream| streamed.gate.highest_packet(stream)),
        retained: std::array::from_fn(|i| streamed.owners[i].retained()),
        held: streamed.held.map(|held| held.map(|held| held.incoming)),
        pending: streamed.owners[index(streams::Stream::Transaction)]
            .pending()
            .map(|delivery| {
                (
                    delivery.ticket(),
                    delivery.deadline(),
                    delivery.bytes().to_vec(),
                    delivery.bytes().as_ptr() as usize,
                )
            }),
        phase: peer.phase(),
        operation: peer.operation(),
        active: peer.active_config().clone(),
        epoch: peer.active_epoch(),
        requests: peer.retained_requests(),
        replies: peer.retained_replies(),
        phase_deadline: peer.phase_deadline(),
    })
}

fn await_preview_pending(lab: &mut Lab, side: usize) -> Result {
    for _ in 0..300 {
        let Backend::Streamed(streamed) = &lab.owners[side].backend else {
            return Err("wrong preview backend".into());
        };
        if streamed.owners[index(streams::Stream::Transaction)]
            .pending()
            .is_some()
        {
            return Ok(());
        }
        lab.pump()?;
    }
    Err("bounded actual Transaction message did not become pending".into())
}

#[test]
fn borrowed_preview_returns_exact_pending_bytes_without_ids_time_or_sequence_mutation() -> Result {
    let mut lab = Lab::new()?;
    assert!(
        lab.owners[1]
            .preview_transaction(&lab.peers[1], lab.now, CAP)?
            .is_none()
    );
    let prepare = lab.prepare()?;
    let frozen = lab.send(0, &prepare)?;
    await_preview_pending(&mut lab, 1)?;
    let before = preview_state(&lab, 1)?;
    let (ticket, deadline, bytes, address) =
        before.pending.as_ref().ok_or("missing actual bytes")?;
    let mut intended = None;
    for now in [
        lab.now,
        lab.now + Duration::from_millis(100),
        *deadline - Duration::from_nanos(1),
    ] {
        let view = lab.owners[1]
            .preview_transaction(&lab.peers[1], now, CAP)?
            .ok_or("missing borrowed view")?;
        assert_eq!(view.envelope(), bytes);
        assert_eq!(view.envelope(), frozen.envelope());
        assert_eq!(view.envelope().as_ptr() as usize, *address);
        assert_eq!(view.deadline(), *deadline);
        let incoming = view.incoming();
        assert_eq!(incoming.bytes, bytes.len());
        assert_eq!(incoming.stream, Some(streams::Stream::Transaction));
        assert_eq!(incoming.token.binding, binding(mg::Role::Server));
        assert_eq!(
            incoming.token.kind,
            TokenKind::Streamed {
                stream: streams::Stream::Transaction,
                ticket: *ticket
            }
        );
        let preparation = view
            .preparation()
            .ok_or("missing real first-PREPARE intent")?;
        assert_eq!(preparation.config(), &modes()[1]);
        assert_eq!(preparation.identity().role, mg::Role::Server);
        assert_eq!(preparation.origin(), data_scope(1, &modes()[0])?);
        assert_eq!(preparation.expires(), CAP);
        intended = view.into_preparation();
        assert_eq!(preview_state(&lab, 1)?, before);
    }
    let intended = intended.ok_or("lost owned preparation")?;
    let mut effect = None;
    assert_eq!(
        lab.owners[1].dispatch_transaction(&mut lab.peers[1], lab.now, CAP, &mut effect)?,
        DispatchProgress::Dispatched
    );
    let effect = effect.ok_or("actual dispatch lost effects")?;
    assert_eq!(
        effect.incoming().token.kind,
        TokenKind::Streamed {
            stream: streams::Stream::Transaction,
            ticket: *ticket
        }
    );
    assert!(
        matches!(effect.effects().event.as_ref(), Some(tx::Event::Stage { ticket, config })
        if *ticket == intended.ticket() && config == intended.config())
    );
    let held = preview_state(&lab, 1)?;
    assert!(
        lab.owners[1]
            .preview_transaction(&lab.peers[1], lab.now, CAP)?
            .is_none()
    );
    assert_eq!(preview_state(&lab, 1)?, held);
    lab.accept(1, &effect, false)?;
    Ok(())
}

#[test]
fn borrowed_preview_cap_time_and_original_message_expiry_refusals_do_not_consume_pending() -> Result
{
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let _frozen = lab.send(0, &prepare)?;
    await_preview_pending(&mut lab, 1)?;
    let before = preview_state(&lab, 1)?;
    let deadline = before.pending.as_ref().ok_or("missing actual message")?.1;
    for (now, cap) in [
        (lab.now, tx::Tick(0)),
        (lab.now - Duration::from_nanos(1), CAP),
        (deadline, CAP),
        (deadline + Duration::from_nanos(1), CAP),
        (Duration::from_secs(10), CAP),
    ] {
        assert!(
            lab.owners[1]
                .preview_transaction(&lab.peers[1], now, cap)
                .is_err()
        );
        assert_eq!(preview_state(&lab, 1)?, before);
    }
    let intent = lab.owners[1]
        .preview_transaction(&lab.peers[1], lab.now, CAP)?
        .ok_or("lost valid original view")?
        .into_preparation()
        .ok_or("lost intent")?;
    assert_eq!(intent.expires(), CAP);
    let mut effect = None;
    // Actual dispatch checks the caller's original cap again after any allocation.
    assert!(
        lab.owners[1]
            .dispatch_transaction(&mut lab.peers[1], lab.now, tx::Tick(0), &mut effect)
            .is_err()
    );
    assert!(effect.is_none());
    assert_eq!(preview_state(&lab, 1)?, before);
    assert_eq!(
        lab.owners[1].dispatch_transaction(&mut lab.peers[1], lab.now, CAP, &mut effect)?,
        DispatchProgress::Dispatched
    );
    Ok(())
}

#[test]
fn borrowed_preview_checks_actual_time_and_sticky_failure_in_every_stream() -> Result {
    for stream in streams::Stream::ALL {
        let mut lab = Lab::new()?;
        let prepare = lab.prepare()?;
        let _frozen = lab.send(0, &prepare)?;
        await_preview_pending(&mut lab, 1)?;
        let now = lab.now;
        let Backend::Streamed(streamed) = &mut lab.owners[1].backend else {
            return Err("wrong preview backend".into());
        };
        let actual = &mut streamed.owners[index(stream)];
        actual.tick(now + Duration::from_millis(10))?;
        assert_eq!(
            actual.tick(now + Duration::from_millis(5)),
            Err(messages::Error::NonMonotonicTime)
        );
        let before = preview_state(&lab, 1)?;
        // The underlying failed attempt is newer than wrapper now; expiry alone
        // would miss its sticky failure at this intermediate time.
        assert!(
            lab.owners[1]
                .preview_transaction(&lab.peers[1], now + Duration::from_millis(1), CAP)
                .is_err()
        );
        assert_eq!(preview_state(&lab, 1)?, before);
    }
    Ok(())
}

#[test]
fn borrowed_preview_rejects_unselected_control_and_actual_callback_failure() -> Result {
    let mut lab = Lab::new()?;
    for selected in [None, Some(settings())] {
        let owner = Owner::new(
            base(),
            selected,
            binding(mg::Role::Server),
            control_scope(),
            data_scope(1, &modes()[0])?,
            Duration::ZERO,
            Duration::from_secs(10),
        )?;
        assert!(
            owner
                .preview_transaction(&lab.peers[1], Duration::ZERO, CAP)
                .is_err()
        );
    }
    let prepare = lab.prepare()?;
    let _frozen = lab.send(0, &prepare)?;
    let effect = lab.dispatched(1)?;
    let failed: io::Result<Attempt<()>> =
        lab.owners[1].with_accepted(effect.incoming(), lab.now, |_| {
            Err(io::Error::other("injected actual callback failure"))
        });
    assert!(failed.is_err());
    let before = preview_state(&lab, 1)?;
    assert!(
        lab.owners[1]
            .preview_transaction(&lab.peers[1], lab.now, CAP)
            .is_err()
    );
    assert_eq!(preview_state(&lab, 1)?, before);
    Ok(())
}

#[test]
fn borrowed_preview_rejects_actual_invalid_joint_envelopes_without_consuming_owner_bytes() -> Result
{
    for case in 0..5 {
        let mut lab = Lab::new()?;
        let prepare = lab.prepare()?;
        let frozen = lab.owners[0].freeze_transaction(&lab.peers[0], &prepare, lab.now)?;
        let valid = sc::Envelope::decode(frozen.envelope(), envelope_limits(2048)?)?;
        let mut outer = valid.binding;
        let mut command = prepare.clone();
        match case {
            0 => {}
            1 => outer.scope.digest = ConfigDigest([0x11; 32]),
            2 => {}
            3 => {}
            _ => {
                let frame = mg::Frame::decode(&prepare, mg::Limits::default())?;
                let mut header = frame.header;
                header.destination = mg::EndpointId(99);
                command.resize(mg::HEADER_LEN + frame.body.len(), 0);
                mg::Frame {
                    header,
                    body: frame.body,
                }
                .encode(&mut command, mg::Limits::default())?;
            }
        }
        let body = if case == 3 {
            sc::Body::ProfileControl {
                tag: sc::ProfileTag::SwiftPolicyV1,
                bytes: &[1],
            }
        } else {
            sc::Body::Management(&command)
        };
        let envelope = sc::Envelope {
            binding: outer,
            body,
        };
        let mut encoded = vec![0; envelope.encoded_len(envelope_limits(2048)?)?];
        envelope.encode(&mut encoded, envelope_limits(2048)?)?;
        // These intentionally invalid application bytes still pass through the
        // actual whole-message fragmentation/reassembly and custody path.
        if case == 0 {
            encoded[6] = mg::Role::Server as u8;
        }
        if case == 2 {
            encoded[32..40].fill(0);
        }
        let Backend::Streamed(streamed) = &mut lab.owners[0].backend else {
            return Err("wrong actual sender backend".into());
        };
        streamed.owners[index(streams::Stream::Transaction)].submit(
            messages::SubmissionId(999),
            &encoded,
            lab.now,
            Duration::from_secs(2),
        )?;
        await_preview_pending(&mut lab, 1)?;
        let before = preview_state(&lab, 1)?;
        assert_eq!(
            before
                .pending
                .as_ref()
                .ok_or("missing actual invalid message")?
                .2,
            encoded
        );
        for _ in 0..2 {
            assert!(
                lab.owners[1]
                    .preview_transaction(&lab.peers[1], lab.now, CAP)
                    .is_err(),
                "invalid joint case {case}"
            );
            assert_eq!(preview_state(&lab, 1)?, before);
        }
        assert_eq!(lab.peers[1].phase(), tx::Phase::Idle);
        assert_eq!(lab.peers[1].operation(), None);
    }
    Ok(())
}

#[test]
fn borrowed_preview_of_real_logical_retry_has_no_second_preparation() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let first = lab.send(0, &prepare)?;
    let effect = lab.dispatched(1)?;
    lab.accept(1, &effect, false)?;
    lab.confirm(0, &first, false, true)?;
    let _ready = lab.peers[1].staged(tx::Fence::new(&[0, 0])?, lab.tick()?)?;
    let retry = lab.peers[0]
        .poll(lab.tick()?)?
        .outbound
        .ok_or("missing actual logical retry")?;
    let retry_frozen = lab.send(0, &retry)?;
    await_preview_pending(&mut lab, 1)?;
    let before = preview_state(&lab, 1)?;
    let view = lab.owners[1]
        .preview_transaction(&lab.peers[1], lab.now, CAP)?
        .ok_or("missing retry view")?;
    assert_eq!(view.envelope(), retry_frozen.envelope());
    assert!(view.preparation().is_none());
    assert!(view.into_preparation().is_none());
    assert_eq!(preview_state(&lab, 1)?, before);
    let mut slot = None;
    assert_eq!(
        lab.owners[1].dispatch_transaction(&mut lab.peers[1], lab.now, CAP, &mut slot)?,
        DispatchProgress::Dispatched
    );
    assert!(
        slot.as_ref()
            .ok_or("missing retry effects")?
            .effects()
            .event
            .is_none()
    );
    Ok(())
}

fn await_ready_stream(lab: &mut Lab, side: usize, stream: streams::Stream) -> Result {
    for _ in 0..300 {
        let Backend::Streamed(streamed) = &lab.owners[side].backend else {
            return Err("wrong readiness backend".into());
        };
        if streamed.owners[index(stream)].pending().is_some() {
            return Ok(());
        }
        lab.pump()?;
    }
    Err("bounded actual stream message did not become pending".into())
}

#[test]
fn nontransaction_hint_excludes_real_pending_transaction_without_mutation() -> Result {
    let mut lab = Lab::new()?;
    assert!(!lab.owners[1].ready_nontransaction()?);
    let prepare = lab.prepare()?;
    let frozen = lab.send(0, &prepare)?;
    await_preview_pending(&mut lab, 1)?;
    let before = preview_state(&lab, 1)?;
    for _ in 0..3 {
        assert!(lab.owners[1].ready_for_dispatch(None)?);
        assert!(!lab.owners[1].ready_nontransaction()?);
        assert_eq!(preview_state(&lab, 1)?, before);
    }
    let mut output = [0; 2048];
    assert!(lab.owners[1].next(lab.now, &mut output)?.is_none());
    let view = lab.owners[1]
        .preview_transaction(&lab.peers[1], lab.now, CAP)?
        .ok_or("readiness consumed actual Transaction custody")?;
    assert_eq!(view.envelope(), frozen.envelope());
    let legacy = Owner::new(
        base(),
        None,
        binding(mg::Role::Server),
        control_scope(),
        data_scope(1, &modes()[0])?,
        Duration::ZERO,
        Duration::from_secs(10),
    )?;
    assert!(!legacy.ready_nontransaction()?);
    Ok(())
}

#[test]
fn nontransaction_hint_finds_real_liveness_and_excludes_its_held_message() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let frozen = lab.send(0, &prepare)?;
    await_preview_pending(&mut lab, 1)?;
    let _ping = lab.owners[0]
        .submit(
            control_scope(),
            sc::Body::Ping { nonce: 71 },
            lab.now,
            CAP_DURATION,
            true,
        )?
        .ok_or("missing actual Ping submission")?;
    await_ready_stream(&mut lab, 1, streams::Stream::Liveness)?;
    let before = preview_state(&lab, 1)?;
    for _ in 0..3 {
        assert!(lab.owners[1].ready_nontransaction()?);
        assert_eq!(preview_state(&lab, 1)?, before);
    }
    let mut output = [0; 2048];
    let incoming = lab.owners[1]
        .next(lab.now, &mut output)?
        .ok_or("nontransaction readiness lost actual Ping")?;
    assert_eq!(incoming.stream, Some(streams::Stream::Liveness));
    assert_eq!(
        sc::Envelope::decode(&output[..incoming.bytes], envelope_limits(2048)?)?.body,
        sc::Body::Ping { nonce: 71 }
    );
    let held = preview_state(&lab, 1)?;
    assert!(lab.owners[1].ready_for_dispatch(None)?);
    assert!(!lab.owners[1].ready_nontransaction()?);
    assert_eq!(preview_state(&lab, 1)?, held);
    lab.owners[1].accepted(incoming, lab.now)?;
    assert!(!lab.owners[1].ready_nontransaction()?);
    let view = lab.owners[1]
        .preview_transaction(&lab.peers[1], lab.now, CAP)?
        .ok_or("Liveness readiness consumed actual Transaction")?;
    assert_eq!(view.envelope(), frozen.envelope());
    Ok(())
}

#[test]
fn nontransaction_hint_leaves_malformed_transaction_to_joint_preview() -> Result {
    let mut lab = Lab::new()?;
    let prepare = lab.prepare()?;
    let frozen = lab.owners[0].freeze_transaction(&lab.peers[0], &prepare, lab.now)?;
    let mut invalid = frozen.envelope().to_vec();
    invalid[4] = 0xff;
    let Backend::Streamed(streamed) = &mut lab.owners[0].backend else {
        return Err("wrong actual sender backend".into());
    };
    streamed.owners[index(streams::Stream::Transaction)].submit(
        messages::SubmissionId(999),
        &invalid,
        lab.now,
        Duration::from_secs(2),
    )?;
    await_preview_pending(&mut lab, 1)?;
    let before = preview_state(&lab, 1)?;
    assert!(lab.owners[1].ready_for_dispatch(None).is_err());
    assert!(!lab.owners[1].ready_nontransaction()?);
    assert!(
        lab.owners[1]
            .preview_transaction(&lab.peers[1], lab.now, CAP)
            .is_err()
    );
    assert_eq!(preview_state(&lab, 1)?, before);
    let _ping = lab.owners[0]
        .submit(
            control_scope(),
            sc::Body::Pong { nonce: 72 },
            lab.now,
            CAP_DURATION,
            true,
        )?
        .ok_or("missing actual Pong submission")?;
    await_ready_stream(&mut lab, 1, streams::Stream::Liveness)?;
    let before = preview_state(&lab, 1)?;
    assert!(lab.owners[1].ready_nontransaction()?);
    assert_eq!(preview_state(&lab, 1)?, before);
    Ok(())
}

#[test]
fn nontransaction_hint_does_not_authorize_unsupported_or_substituted_data_feedback() -> Result {
    for substituted in [false, true] {
        let mut lab = Lab::new()?;
        let body = if substituted {
            sc::Body::Ping { nonce: 73 }
        } else {
            sc::Body::RecoveryFeedback {
                lane: mg::LaneId(0),
                tag: sc::RecoveryTag::SelectiveRepeatV1,
                bytes: &[1],
            }
        };
        let envelope = sc::Envelope {
            binding: envelope_binding(binding(mg::Role::Client), 1, data_scope(1, &modes()[0])?),
            body,
        };
        let mut encoded = vec![0; envelope.encoded_len(envelope_limits(2048)?)?];
        envelope.encode(&mut encoded, envelope_limits(2048)?)?;
        let Backend::Streamed(streamed) = &mut lab.owners[0].backend else {
            return Err("wrong actual sender backend".into());
        };
        streamed.owners[index(streams::Stream::DataFeedback)].submit(
            messages::SubmissionId(1),
            &encoded,
            lab.now,
            Duration::from_secs(2),
        )?;
        await_ready_stream(&mut lab, 1, streams::Stream::DataFeedback)?;
        let before = preview_state(&lab, 1)?;
        for _ in 0..2 {
            assert!(lab.owners[1].ready_nontransaction().is_err());
            assert_eq!(preview_state(&lab, 1)?, before);
        }
        let mut output = [0; 2048];
        assert!(lab.owners[1].next(lab.now, &mut output).is_err());
    }
    Ok(())
}

// These reports observe actual MessageOwner and transaction output state. They
// do not replace ARQ/semantic custody with fabricated metric queue values.
fn management_report(owner: &Owner, at: Duration) -> Result<serde_json::Value> {
    let mut report = buffers::Report::new()?;
    let charged = report.heap_bytes();
    report.sample(owner, u64::try_from(at.as_micros())?);
    assert_eq!(report.heap_bytes(), charged);
    let mut output = Vec::new();
    report.write(&mut output)?;
    Ok(serde_json::from_slice(&output)?)
}

fn refused_management_prepare() -> Result<(Lab, FrozenOutput, Vec<u8>)> {
    let mut selected = settings();
    selected.streams[0].max_outbound_messages = 1;
    let mut lab = Lab::with_settings(selected)?;
    lab.owners[0].enable_buffer_metrics();
    // A genuine ordinary profile-control admission occupies the bounded
    // Transaction wrapper until its own actual semantic receipt/retirement.
    assert!(
        lab.owners[0]
            .submit(
                data_scope(1, &modes()[0])?,
                sc::Body::ProfileControl {
                    tag: sc::ProfileTag::SlotReuseV1,
                    bytes: &[0x42]
                },
                lab.now,
                CAP_DURATION,
                false
            )?
            .is_some()
    );
    let prepare = lab.prepare()?;
    let mut frozen = lab.owners[0].freeze_transaction(&lab.peers[0], &prepare, lab.now)?;
    lab.now = Duration::from_millis(1);
    assert_eq!(
        lab.owners[0].submit_frozen(&mut frozen, lab.now)?,
        Attempt::Blocked
    );
    lab.now = Duration::from_millis(3);
    assert_eq!(
        lab.owners[0].submit_frozen(&mut frozen, lab.now)?,
        Attempt::Blocked
    );
    Ok((lab, frozen, prepare))
}

#[test]
fn management_frozen_wait_censors_cancellation_expiry_and_metric_stop_separately() -> Result {
    for outcome in ["Cancelled", "OwnerFailure", "MetricStop"] {
        let (mut lab, mut frozen, prepare) = refused_management_prepare()?;
        let deadline = frozen.deadline();
        let exact = frozen.envelope().to_vec();
        lab.now = Duration::from_millis(5);
        match outcome {
            "Cancelled" => {
                let tick = lab.tick()?;
                lab.peers[1].receive_until(verified(mg::Role::Client), &prepare, tick, CAP)?;
                let ready = lab.peers[1]
                    .staged(tx::Fence::new(&[0, 0])?, tick)?
                    .outbound
                    .ok_or("missing genuine READY supersession")?;
                lab.peers[0].receive_until(verified(mg::Role::Server), &ready, tick, CAP)?;
                lab.owners[0].cancel_frozen(&lab.peers[0], &mut frozen, lab.now)?;
            }
            "OwnerFailure" => {
                lab.now = deadline;
                assert_eq!(
                    lab.owners[0]
                        .submit_frozen(&mut frozen, lab.now)
                        .err()
                        .ok_or("expired reservation admitted")?
                        .kind(),
                    io::ErrorKind::TimedOut
                );
            }
            _ => lab.owners[0].finish_buffer_metrics(lab.now),
        }
        assert_eq!(frozen.deadline(), deadline);
        assert_eq!(frozen.envelope(), exact);
        let report = management_report(&lab.owners[0], lab.now)?;
        let wait = &report["frozen_submission_wait"];
        assert_eq!(wait["completed_episodes"], 0);
        assert_eq!(wait["censored_episodes"], 1);
        assert_eq!(wait["wrapper_entry_refusals"], 2);
        assert_eq!(
            wait["censored_us"],
            u64::try_from((lab.now - Duration::from_millis(1)).as_micros())?
        );
        assert_eq!(wait["last_resolved"]["outcome"], outcome);
        assert!(wait["pending"].is_null());
        assert_eq!(
            wait["last_resolved"]["identity"]["original_deadline_us"],
            u64::try_from(deadline.as_micros())?
        );
        // Cleanup/another stop must not extend an already closed interval.
        lab.owners[0].finish_buffer_metrics(lab.now + Duration::from_millis(1));
        let terminal = management_report(&lab.owners[0], lab.now + Duration::from_millis(1))?;
        assert_eq!(
            terminal["frozen_submission_wait"]["censored_us"],
            wait["censored_us"]
        );
        assert_eq!(
            terminal["frozen_submission_wait"]["last_resolved"],
            wait["last_resolved"]
        );
    }
    Ok(())
}

#[test]
fn management_ordinary_reused_submission_id_is_count_only() -> Result {
    let mut selected = settings();
    selected.streams[1].max_outbound_messages = 1;
    let mut lab = Lab::with_settings(selected)?;
    lab.owners[0].enable_buffer_metrics();
    for nonce in 1..=3 {
        let admitted = lab.owners[0].submit(
            control_scope(),
            sc::Body::Ping { nonce },
            lab.now,
            CAP_DURATION,
            false,
        )?;
        assert_eq!(admitted.is_some(), nonce == 1);
        lab.now += Duration::from_millis(1);
    }
    let report = management_report(&lab.owners[0], lab.now)?;
    assert_eq!(report["streams"][1]["stream"], "Liveness");
    assert_eq!(report["streams"][1]["ordinary_submit_refusals"], 2);
    assert!(report["streams"][1]["ordinary_submit_duration_us"].is_null());
    assert_eq!(report["frozen_submission_wait"]["completed_episodes"], 0);
    assert_eq!(report["frozen_submission_wait"]["censored_episodes"], 0);
    assert!(report["frozen_submission_wait"]["pending"].is_null());
    Ok(())
}
