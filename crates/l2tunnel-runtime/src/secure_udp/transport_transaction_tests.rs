//! Actual Bank/Owner/two-Peer custody. Empty-engine fences are real pure facts;
//! these tests do not claim a native device or protected socket was exercised.

use super::*;
use l2tunnel::swift_configuration::Descriptor;
use l2tunnel_recovery as recovery;
use l2tunnel_swift::policy;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SESSION: Duration = Duration::from_secs(10);
const EXTERNAL: usize = 137;

fn identity(role: mg::Role) -> tx::Identity {
    tx::Identity {
        session: mg::SessionId([0x62; 16]),
        role,
        lane: mg::LaneId(7),
        local: mg::EndpointId(if role == mg::Role::Client { 1 } else { 2 }),
        remote: mg::EndpointId(if role == mg::Role::Client { 2 } else { 1 }),
    }
}
fn binding(role: mg::Role) -> delivery::Binding {
    delivery::Binding {
        session: identity(role).session,
        lane: identity(role).lane,
        local_role: role,
        control_epoch: 1,
    }
}
fn verified(role: mg::Role) -> mg::Ingress {
    mg::Ingress::AuthenticatedManagement {
        session: identity(role).session,
        lane: identity(role).lane,
        sender: role,
    }
}
fn direction(channels: usize) -> policy::Direction {
    policy::Direction {
        records: records::Config {
            codec: l2tunnel_swift::Config {
                datagram_bytes: 256,
                window: 2,
                repair_numerator: 0,
                repair_denominator: 1,
                flow_sources: 6,
                queue_bytes: 2048,
                max_packet: 129,
                flush_micros: 0,
                feedback_micros: 10,
                tail_micros: 1000,
                min_rto_micros: 100,
                max_rto_micros: 10_000,
            },
            channels,
            layer: records::Layer::Ip,
            max_native: 128,
        },
        bytes_per_second: 100_000,
    }
}
fn catalog() -> Result<Catalog> {
    let initial = Descriptor::new(1500, direction(2), direction(3))?;
    let target = Descriptor::new(1500, direction(4), direction(1))?;
    Ok(Catalog::new(initial, &[initial, target])?)
}
fn values() -> Result<[C; 2]> {
    let catalog = catalog()?;
    let envelope = EnvelopeDigest::new([0x71; 32]);
    Ok([
        C::new(envelope, catalog.initial())?,
        C::new(envelope, Descriptor::new(1500, direction(4), direction(1))?)?,
    ])
}
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
            max_retries: 128,
        },
        interval: Duration::from_millis(10),
        packets_per_interval: 2,
        bytes_per_interval: 2048,
        wire_overhead: 76,
    }
}
fn selected() -> control_owner::Settings {
    let message = mg::messages::Settings {
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
        message_lifetime: Duration::from_secs(4),
        work_per_call: 4,
    };
    control_owner::Settings {
        streams: [message; 3],
    }
}
fn control_scope() -> sc::Scope {
    sc::Scope {
        epoch: Epoch(1),
        digest: l2tunnel_core::ConfigDigest([0x91; 32]),
    }
}
fn bank(role: mg::Role, short: usize) -> Result<Bank> {
    let values = values()?;
    let remote = if role == mg::Role::Client {
        mg::Role::Server
    } else {
        mg::Role::Client
    };
    let maximum = values
        .iter()
        .map(|value| {
            storage::Plan::for_engine(
                value.descriptor().direction(role).records,
                value.descriptor().direction(remote).records,
            )
            .map(|plan| plan.capacity_bytes())
        })
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or("no real plan")?;
    let limit = std::mem::size_of::<storage::Set>() + EXTERNAL + 2 * maximum - short;
    Ok(Bank::new(
        identity(role),
        Epoch(10),
        values[0],
        storage::Limits {
            capacity_bytes: limit,
        },
        EXTERNAL,
    )?)
}
fn state(role: mg::Role, bank: Bank, protocol: tx::Settings, session: Duration) -> Result<State> {
    let retained_bytes = bank.usage().limit_bytes;
    Ok(State::new(
        identity(role),
        Epoch(10),
        values()?[0].envelope(),
        catalog()?,
        TransactionSettings {
            protocol,
            max_operation_ms: 5000,
            retained_bytes,
        },
        control_streams::delivery_binding(binding(role), control_streams::Stream::Transaction)?,
        Duration::ZERO,
        session,
        bank,
    )?)
}
fn owner(
    role: mg::Role,
    selected: control_owner::Settings,
    session: Duration,
) -> Result<control_owner::Owner> {
    let streamed = selected.streams[0].delivery;
    let base = delivery::Settings {
        wire_overhead: streamed
            .wire_overhead
            .checked_sub(control_streams::HEADER_BYTES)
            .ok_or("missing stream wrapper overhead")?,
        ..streamed
    };
    Ok(control_owner::Owner::new_leased(
        base,
        selected,
        binding(role),
        control_scope(),
        sc::Scope {
            epoch: Epoch(10),
            digest: tx::configuration_digest(&values()?[0])?,
        },
        Duration::ZERO,
        session,
    )?)
}
fn fence(width: usize) -> Result<tx::Fence> {
    Ok(tx::Fence::new(&vec![0; width])?)
}
fn protocol() -> tx::Settings {
    tx::Settings {
        retry_ms: 10,
        phase_timeout_ms: 500,
        reconcile_timeout_ms: 1000,
    }
}
fn pressure_selected() -> control_owner::Settings {
    let mut selected = selected();
    // Retain actual source ACK debt without preventing the multi-fragment
    // PREPARE or its later semantic replies from reaching the other Peer.
    for stream in &mut selected.streams {
        let arq = &mut stream.delivery.recovery;
        arq.send_records = 32;
        arq.receive_records = 32;
        arq.send_bytes = 32 * 192;
        arq.receive_bytes = 32 * 192;
    }
    selected
}

struct Lab {
    states: [State; 2],
    owners: [control_owner::Owner; 2],
    held: [Option<Action>; 2],
    now: Duration,
    drop_server_acks: bool,
    dropped_acks: usize,
    drop_client_acks: bool,
    drop_server_final_data: bool,
}
impl Lab {
    fn new() -> Result<Self> {
        Self::with(protocol(), selected(), SESSION)
    }
    fn with(
        protocol: tx::Settings,
        selected: control_owner::Settings,
        session: Duration,
    ) -> Result<Self> {
        Ok(Self {
            states: [
                state(
                    mg::Role::Client,
                    bank(mg::Role::Client, 0)?,
                    protocol,
                    session,
                )?,
                state(
                    mg::Role::Server,
                    bank(mg::Role::Server, 0)?,
                    protocol,
                    session,
                )?,
            ],
            owners: [
                owner(mg::Role::Client, selected, session)?,
                owner(mg::Role::Server, selected, session)?,
            ],
            held: [None, None],
            now: Duration::ZERO,
            drop_server_acks: false,
            dropped_acks: 0,
            drop_client_acks: false,
            drop_server_final_data: false,
        })
    }
    fn propose(&mut self) -> Result {
        assert_eq!(
            self.states[0].propose(&mut self.owners[0], values()?[1], tx::Tick(5000), || Ok(
                self.now
            ))?,
            Progress::Advanced
        );
        Ok(())
    }
    fn wire(&mut self) -> Result {
        for side in 0..2 {
            let role = if side == 0 {
                mg::Role::Client
            } else {
                mg::Role::Server
            };
            let mut allowance = 4096;
            let mut packet = [0; 512];
            for _ in 0..8 {
                let Some(emission) = self.owners[side].poll(self.now, allowance, &mut packet)?
                else {
                    break;
                };
                allowance -= emission.wire_bytes;
                let frame = control_streams::Frame::decode(
                    &packet[..emission.bytes],
                    control_streams::Limits {
                        max_packet_bytes: 236,
                    },
                )?;
                let epoch =
                    control_streams::delivery_binding(binding(role), frame.stream)?.control_epoch;
                let view = recovery::inspect_packet(
                    frame.packet,
                    recovery::RecoveryContext {
                        session: u128::from_be_bytes(identity(role).session.0),
                        epoch,
                        role: if side == 0 {
                            recovery::EndpointRole::Responder
                        } else {
                            recovery::EndpointRole::Initiator
                        },
                    },
                    192,
                )?;
                if side == 1
                    && self.drop_server_acks
                    && frame.stream == control_streams::Stream::Transaction
                    && matches!(view, recovery::PacketView::Ack { .. })
                {
                    self.dropped_acks += 1;
                    continue;
                }
                if side == 0
                    && self.drop_client_acks
                    && frame.stream == control_streams::Stream::Transaction
                    && matches!(view, recovery::PacketView::Ack { .. })
                {
                    continue;
                }
                if side == 1
                    && self.drop_server_final_data
                    && self.states[1].peer.phase() == tx::Phase::Idle
                    && frame.stream == control_streams::Stream::Transaction
                    && matches!(view, recovery::PacketView::Data { .. })
                {
                    continue;
                }
                self.owners[1 - side].receive(
                    verified(role),
                    &packet[..emission.bytes],
                    self.now,
                )?;
            }
        }
        Ok(())
    }
    fn step(&mut self, dispatch: [bool; 2]) -> Result {
        self.now += Duration::from_millis(1);
        for (side, dispatch) in dispatch.into_iter().enumerate() {
            self.states[side].service(&mut self.owners[side], self.now)?;
            if dispatch {
                self.states[side].dispatch(&mut self.owners[side], || Ok(self.now))?;
            }
            self.states[side].service(&mut self.owners[side], self.now)?;
        }
        self.wire()
    }
    fn gather(&mut self) {
        for side in 0..2 {
            if self.held[side].is_none() {
                self.held[side] = self.states[side].take_action();
            }
        }
    }
    fn complete(&mut self, side: usize) -> Result<Progress> {
        let mut action = self.held[side].take().ok_or("no held actual action")?;
        let event = action.event().clone();
        let result = match event {
            tx::Event::Stage { .. } => {
                let width = usize::from(
                    self.states[side].peer().sender_channels(
                        identity(if side == 0 {
                            mg::Role::Client
                        } else {
                            mg::Role::Server
                        })
                        .role,
                    ),
                );
                self.states[side].complete_action(
                    &mut self.owners[side],
                    &mut action,
                    Completion::Staged {
                        admitted: &fence(width)?,
                    },
                    self.now,
                )
            }
            tx::Event::Drain { local, peer } => {
                let old = self.states[side].engine(action.operation().origin().epoch)?;
                assert!(old.send_drained() && old.receive_drained());
                self.states[side].complete_action(
                    &mut self.owners[side],
                    &mut action,
                    Completion::Drained {
                        sent: &local,
                        delivered: &peer,
                    },
                    self.now,
                )
            }
            _ => self.states[side].complete_action(
                &mut self.owners[side],
                &mut action,
                Completion::Applied,
                self.now,
            ),
        }?;
        if result == Progress::Blocked {
            self.held[side] = Some(action);
        }
        Ok(result)
    }
    fn drive(&mut self) -> Result {
        self.gather();
        for side in 0..2 {
            if self.held[side].is_some() {
                self.complete(side)?;
            }
        }
        Ok(())
    }
    fn pending_kind(&self, side: usize) -> Result<Option<mg::MessageKind>> {
        let cap = self.states[side]
            .pending_admission
            .map(|p| p.cap)
            .or_else(|| {
                self.states[side]
                    .peer
                    .operation()
                    .map(tx::Operation::expires)
            })
            .unwrap_or(tx::Tick(5000));
        self.owners[side]
            .preview_transaction(&self.states[side].peer, self.now, cap)?
            .map(|view| management_kind(view.envelope()))
            .transpose()
            .map_err(Into::into)
    }
}

#[test]
fn actual_asymmetric_banks_and_whole_message_proofs_complete_both_peers() -> Result {
    let mut lab = Lab::new()?;
    assert_eq!(lab.states[0].epoch(), Epoch(10));
    assert!(lab.states.iter().all(State::can_admit_data));
    lab.propose()?;
    let reserved = lab.states[0].usage();
    assert!(lab.states[0].engine(Epoch(11)).is_err());
    let mut outcomes = [None, None];
    let mut complete = false;
    for _ in 0..2000 {
        lab.step([true, true])?;
        lab.drive()?;
        for (side, stored) in outcomes.iter_mut().enumerate() {
            if let Some(outcome) = lab.states[side].take_outcome() {
                assert!(stored.is_none());
                *stored = Some(outcome);
            }
        }
        if lab.states.iter().all(|state| {
            state.operation.is_none()
                && state.peer.operation().is_none()
                && state.outputs.iter().all(Option::is_none)
                && state.work.is_none()
        }) && outcomes.iter().all(Option::is_some)
        {
            complete = true;
            break;
        }
    }
    assert!(
        complete,
        "finite actual two-peer transaction did not settle custody"
    );
    for (side, outcome) in outcomes.iter().enumerate() {
        assert_eq!(lab.states[side].epoch(), Epoch(11));
        assert_eq!(lab.states[side].current(), &values()?[1]);
        assert!(lab.states[side].engine(Epoch(10)).is_err());
        assert!(lab.states[side].engine(Epoch(11)).is_ok());
        assert!(lab.states[side].can_admit_data());
        assert!(matches!(
            *outcome,
            Some(Outcome::Retired {
                epoch: Epoch(10),
                ..
            })
        ));
        assert_eq!(lab.states[side].usage().building_bytes, 0);
    }
    assert!(lab.states[0].usage().engine_bytes < reserved.engine_bytes);
    Ok(())
}

#[test]
fn actual_allocation_resample_expiry_cancels_only_virgin_without_peer_identity_burn() -> Result {
    let mut lab = Lab::new()?;
    let before = lab.states[0].usage();
    let mut samples = [Duration::ZERO, Duration::from_millis(5000)].into_iter();
    assert!(
        lab.states[0]
            .propose(&mut lab.owners[0], values()?[1], tx::Tick(5000), || samples
                .next()
                .ok_or_else(|| io::Error::other("extra clock sample")))
            .is_err()
    );
    assert_eq!(lab.states[0].usage().engine_bytes, before.engine_bytes);
    assert!(lab.states[0].prepared.is_none());
    assert_eq!(lab.states[0].peer.phase(), tx::Phase::Idle);
    assert!(lab.states[0].peer.operation().is_none());
    assert!(lab.states[0].engine(Epoch(10)).is_ok());
    assert!(lab.states[0].engine(Epoch(11)).is_err());
    assert_eq!(
        lab.states[0].propose(&mut lab.owners[0], values()?[1], tx::Tick(10000), || Ok(
            Duration::from_millis(5000)
        ))?,
        Progress::Advanced
    );
    assert_eq!(
        lab.states[0]
            .peer
            .operation()
            .ok_or("missing actual operation")?
            .ticket()
            .attempt,
        1
    );
    Ok(())
}

#[test]
fn actual_duplicate_prepare_while_stage_issued_preserves_original_prepared_guard() -> Result {
    let mut lab = Lab::new()?;
    lab.propose()?;
    for _ in 0..300 {
        lab.step([true, true])?;
        lab.gather();
        if lab.held[0]
            .as_ref()
            .is_some_and(|action| matches!(action.event(), tx::Event::Stage { .. }))
        {
            lab.complete(0)?;
        }
        if lab.held[1]
            .as_ref()
            .is_some_and(|action| matches!(action.event(), tx::Event::Stage { .. }))
        {
            break;
        }
    }
    assert!(
        lab.held[1]
            .as_ref()
            .is_some_and(|action| matches!(action.event(), tx::Event::Stage { .. }))
    );
    let original = lab.states[1]
        .prepared
        .as_ref()
        .ok_or("Stage missing actual virgin guard")?
        .ticket();
    let usage = lab.states[1].usage();
    lab.now += Duration::from_millis(20);
    // This actual Peer emits a remote logical retry. A separate real FrozenOutput
    // deliberately bypasses the sender State coalescer to exercise receiver input.
    let command = lab.states[0]
        .peer
        .poll(tick(lab.now)?)?
        .outbound
        .ok_or("missing actual PREPARE retry")?;
    let mut retry = lab.owners[0].freeze_transaction(&lab.states[0].peer, &command, lab.now)?;
    assert!(matches!(
        lab.owners[0].submit_frozen(&mut retry, lab.now)?,
        control_owner::Attempt::Complete(_)
    ));
    for _ in 0..100 {
        lab.now += Duration::from_millis(1);
        lab.wire()?;
        if lab.pending_kind(1)?.is_some() {
            break;
        }
    }
    assert_eq!(lab.pending_kind(1)?, Some(mg::MessageKind::Prepare));
    assert_eq!(
        lab.states[1].dispatch(&mut lab.owners[1], || Ok(lab.now))?,
        Progress::Advanced
    );
    assert_eq!(
        lab.states[1]
            .prepared
            .as_ref()
            .ok_or("retry discarded original Prepared")?
            .ticket(),
        original
    );
    assert_eq!(lab.states[1].usage().engine_bytes, usage.engine_bytes);
    lab.states[1].service(&mut lab.owners[1], lab.now)?;
    assert_eq!(lab.complete(1)?, Progress::Advanced);
    assert!(lab.states[1].prepared.is_none());
    assert!(lab.states[1].engine(Epoch(11)).is_ok());
    Ok(())
}

#[test]
fn actual_staging_timeout_interrupts_work_and_releases_only_virgin_target() -> Result {
    let mut lab = Lab::new()?;
    let initial = lab.states[0].usage();
    lab.propose()?;
    lab.states[0].service(&mut lab.owners[0], Duration::ZERO)?;
    let mut action = lab.states[0].take_action().ok_or("missing actual Stage")?;
    assert!(lab.states[0].take_action().is_none());
    lab.now = Duration::from_millis(500);
    assert_eq!(
        lab.states[0].complete_action(
            &mut lab.owners[0],
            &mut action,
            Completion::Staged {
                admitted: &fence(2)?
            },
            lab.now
        )?,
        Progress::Blocked
    );
    assert!(matches!(
        lab.states[0].interruption(&action),
        Some(tx::Event::Aborted(_))
    ));
    assert!(lab.states[0].prepared.is_some());
    assert_eq!(
        lab.states[0].complete_action(
            &mut lab.owners[0],
            &mut action,
            Completion::Cancelled,
            lab.now
        )?,
        Progress::Advanced
    );
    assert!(lab.states[0].prepared.is_none());
    assert_eq!(lab.states[0].usage().engine_bytes, initial.engine_bytes);
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    let mut aborted = lab.states[0]
        .take_action()
        .ok_or("actual Aborted event was overwritten")?;
    assert!(matches!(aborted.event(), tx::Event::Aborted(_)));
    lab.states[0].complete_action(
        &mut lab.owners[0],
        &mut aborted,
        Completion::Applied,
        lab.now,
    )?;
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    assert!(matches!(
        lab.states[0].take_outcome(),
        Some(Outcome::Aborted { attempt: 1, .. })
    ));
    assert!(lab.states[0].can_admit_data());
    assert!(
        lab.states[0]
            .complete_action(
                &mut lab.owners[0],
                &mut action,
                Completion::Cancelled,
                lab.now
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn applied_commit_completes_under_actual_uncertain_effect_without_rollback() -> Result {
    let mut lab = Lab::new()?;
    lab.propose()?;
    let mut found = false;
    for _ in 0..1000 {
        lab.step([true, true])?;
        lab.gather();
        for side in 0..2 {
            let hold = side == 0
                && lab.held[side]
                    .as_ref()
                    .is_some_and(|action| matches!(action.event(), tx::Event::Committed(_)));
            if lab.held[side].is_some() && !hold {
                lab.complete(side)?;
            }
        }
        if lab.held[0]
            .as_ref()
            .is_some_and(|action| matches!(action.event(), tx::Event::Committed(_)))
        {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "actual CommitAck did not produce guarded Committed work"
    );
    assert_eq!(lab.states[0].epoch(), Epoch(10));
    assert_eq!(lab.states[0].peer.active_epoch(), Epoch(11));
    lab.now = duration(
        lab.states[0]
            .peer
            .phase_deadline()
            .ok_or("no actual phase deadline")?,
    );
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    assert_eq!(lab.states[0].peer.phase(), tx::Phase::Uncertain);
    assert!(matches!(
        lab.states[0]
            .effect
            .as_ref()
            .and_then(|effect| effect.effects.event.as_ref()),
        Some(tx::Event::Uncertain(_))
    ));
    assert_eq!(lab.complete(0)?, Progress::Advanced);
    assert_eq!(lab.states[0].epoch(), Epoch(11));
    assert!(lab.states[0].engine(Epoch(10)).is_ok());
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    let mut uncertain = lab.states[0]
        .take_action()
        .ok_or("actual Uncertain event lost during Applied")?;
    assert!(matches!(uncertain.event(), tx::Event::Uncertain(_)));
    assert!(
        lab.states[0]
            .complete_action(
                &mut lab.owners[0],
                &mut uncertain,
                Completion::Cancelled,
                lab.now
            )
            .is_err()
    );
    lab.states[0].complete_action(
        &mut lab.owners[0],
        &mut uncertain,
        Completion::Applied,
        lab.now,
    )?;
    assert_eq!(lab.states[0].epoch(), Epoch(11));
    assert!(lab.states[0].engine(Epoch(10)).is_ok());
    assert!(!lab.states[0].can_admit_data());
    assert!(lab.states[0].take_outcome().is_none());
    Ok(())
}

#[test]
fn commit_ack_waits_before_joint_gate_when_two_actual_outputs_unconfirmed() -> Result {
    let mut lab = Lab::with(protocol(), pressure_selected(), SESSION)?;
    lab.propose()?;
    let mut blocked = false;
    for _ in 0..1000 {
        // Leave Client pending envelopes un-dispatched for exact preflight inspection.
        lab.step([false, true])?;
        lab.gather();
        for side in 0..2 {
            if lab.held[side].is_some() {
                if side == 0
                    && lab.held[side]
                        .as_ref()
                        .is_some_and(|action| matches!(action.event(), tx::Event::Drain { .. }))
                {
                    lab.drop_server_acks = true;
                }
                lab.complete(side)?;
            }
        }
        if lab.pending_kind(0)? == Some(mg::MessageKind::CommitAck) {
            assert_eq!(lab.states[0].outputs.iter().flatten().count(), 2);
            assert!(
                lab.states[0]
                    .outputs
                    .iter()
                    .flatten()
                    .all(|output| !output.confirmed)
            );
            let phase = lab.states[0].peer.phase();
            let operation = lab.states[0].peer.operation();
            let incoming = lab.owners[0]
                .preview_transaction(
                    &lab.states[0].peer,
                    lab.now,
                    operation.ok_or("lost operation")?.expires(),
                )?
                .ok_or("lost real CommitAck")?
                .incoming();
            assert_eq!(
                lab.states[0].dispatch(&mut lab.owners[0], || Ok(lab.now))?,
                Progress::Blocked
            );
            assert_eq!(lab.states[0].peer.phase(), phase);
            assert_eq!(lab.states[0].peer.operation(), operation);
            assert_eq!(
                lab.owners[0]
                    .preview_transaction(
                        &lab.states[0].peer,
                        lab.now,
                        operation.ok_or("lost operation")?.expires()
                    )?
                    .ok_or("CommitAck consumed under pressure")?
                    .incoming(),
                incoming
            );
            assert!(lab.states[0].outputs[2].is_none());
            blocked = true;
            break;
        }
        lab.states[0].dispatch(&mut lab.owners[0], || Ok(lab.now))?;
    }
    assert!(blocked && lab.dropped_acks > 0);
    lab.drop_server_acks = false;
    let mut resumed = false;
    for _ in 0..300 {
        lab.step([true, true])?;
        if lab.states[0].peer.active_epoch() == Epoch(11) {
            resumed = true;
            break;
        }
    }
    assert!(
        resumed,
        "actual source confirmation did not release normal semantic capacity"
    );
    assert!(lab.states[0].outputs[2].is_none());
    Ok(())
}

#[test]
fn two_actual_unconfirmed_outputs_keep_emergency_phase_abort_capacity() -> Result {
    let mut lab = Lab::with(protocol(), pressure_selected(), SESSION)?;
    lab.drop_server_acks = true;
    lab.propose()?;
    let mut awaiting = false;
    for _ in 0..1000 {
        lab.step([true, true])?;
        lab.gather();
        for side in 0..2 {
            if side == 0
                && lab.held[side]
                    .as_ref()
                    .is_some_and(|action| matches!(action.event(), tx::Event::Drain { .. }))
            {
                lab.drop_server_acks = true;
            }
            let hold = side == 1
                && lab.held[side]
                    .as_ref()
                    .is_some_and(|action| matches!(action.event(), tx::Event::Drain { .. }));
            if lab.held[side].is_some() && !hold {
                lab.complete(side)?;
            }
        }
        if lab.states[0].peer.phase() == tx::Phase::AwaitBarrier
            && lab.states[0].outputs.iter().flatten().count() == 2
        {
            awaiting = true;
            break;
        }
    }
    assert!(
        awaiting,
        "fixture did not retain PREPARE and BARRIER simultaneously"
    );
    assert!(
        lab.states[0]
            .outputs
            .iter()
            .flatten()
            .all(|output| !output.confirmed)
    );
    let original = lab.states[0].operation.ok_or("missing original cap")?;
    lab.now = duration(
        lab.states[0]
            .peer
            .phase_deadline()
            .ok_or("missing actual phase cap")?,
    );
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    assert_eq!(lab.states[0].peer.phase(), tx::Phase::Aborting);
    assert_eq!(lab.states[0].operation, Some(original));
    assert_eq!(lab.states[0].outputs.iter().flatten().count(), 3);
    assert_eq!(
        mg::Frame::decode(
            lab.states[0].outputs[2]
                .as_ref()
                .ok_or("emergency slot missing")?
                .frozen
                .command(),
            mg::Limits::default()
        )?
        .header
        .kind,
        mg::MessageKind::Reject
    );
    assert!(
        lab.states[0]
            .next_deadline()
            .is_some_and(|deadline| deadline > lab.now)
    );
    Ok(())
}

#[test]
fn confirmed_logical_marker_survives_fulfilled_deadline_and_liveness_progress() -> Result {
    let mut selected = selected();
    for stream in &mut selected.streams {
        stream.message_lifetime = Duration::from_secs(2);
    }
    let mut lab = Lab::with(
        tx::Settings {
            retry_ms: 10,
            phase_timeout_ms: 8000,
            reconcile_timeout_ms: 9000,
        },
        selected,
        Duration::from_secs(20),
    )?;
    lab.propose()?;
    for _ in 0..300 {
        lab.step([true, true])?;
        lab.gather();
        if lab.held[0].is_some() {
            lab.complete(0)?;
        }
        if lab.held[1].is_some()
            && lab.states[0]
                .outputs
                .iter()
                .flatten()
                .any(|output| output.confirmed)
        {
            break;
        }
    }
    assert!(
        lab.held[1]
            .as_ref()
            .is_some_and(|action| matches!(action.event(), tx::Event::Stage { .. }))
    );
    let output = lab.states[0]
        .outputs
        .iter()
        .flatten()
        .find(|output| output.confirmed)
        .ok_or("no actual confirmed PREPARE")?;
    let bytes = output.frozen.envelope().to_vec();
    let submission = output.frozen.submission();
    let deadline = output.frozen.deadline();
    for nonce in 1..=130u64 {
        assert!(
            lab.owners[0]
                .submit(
                    control_scope(),
                    sc::Body::Ping { nonce },
                    lab.now,
                    Duration::from_secs(5),
                    true
                )?
                .is_some()
        );
        let mut ping = false;
        let mut pong = false;
        for _ in 0..100 {
            lab.step([true, true])?;
            for side in 0..2 {
                let mut scratch = [0; 2048];
                if let Some(incoming) = lab.owners[side].next(lab.now, &mut scratch)? {
                    let envelope = sc::Envelope::decode(
                        &scratch[..incoming.bytes],
                        sc::Limits {
                            max_frame_bytes: 2048,
                            max_management_bytes: 1968,
                            max_feedback_bytes: 1,
                        },
                    )?;
                    match envelope.body {
                        sc::Body::Ping { nonce: actual } if side == 1 && actual == nonce => {
                            ping = true;
                            assert!(
                                lab.owners[1]
                                    .submit(
                                        control_scope(),
                                        sc::Body::Pong { nonce },
                                        lab.now,
                                        Duration::from_secs(5),
                                        true
                                    )?
                                    .is_some()
                            );
                        }
                        sc::Body::Pong { nonce: actual } if side == 0 && actual == nonce => {
                            pong = true;
                        }
                        _ => return Err("unexpected actual Liveness message".into()),
                    }
                    lab.owners[side].accepted(incoming, lab.now)?;
                }
            }
            if ping && pong {
                break;
            }
        }
        assert!(
            ping && pong,
            "independent actual liveness round did not complete"
        );
    }
    for _ in 0..50 {
        lab.step([true, true])?;
    }
    lab.now = lab.now.max(deadline + Duration::from_millis(1));
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    let output = lab.states[0]
        .outputs
        .iter()
        .flatten()
        .next()
        .ok_or("fulfilled logical marker disappeared")?;
    assert_eq!(output.frozen.envelope(), bytes);
    assert_eq!(output.frozen.submission(), submission);
    assert_eq!(output.frozen.deadline(), deadline);
    assert!(output.confirmed);
    assert_eq!(lab.states[0].outputs.iter().flatten().count(), 1);
    assert!(
        lab.states[0]
            .next_deadline()
            .is_some_and(|next| next > lab.now)
    );
    Ok(())
}

#[test]
fn actual_action_rejects_foreign_completion_and_wrong_fence_before_bank_publish() -> Result {
    let mut first = Lab::new()?;
    let mut other = Lab::new()?;
    first.propose()?;
    other.propose()?;
    first.states[0].service(&mut first.owners[0], Duration::ZERO)?;
    other.states[0].service(&mut other.owners[0], Duration::ZERO)?;
    let mut action = first.states[0]
        .take_action()
        .ok_or("missing first actual Stage")?;
    let retained = first.states[0].usage();
    assert!(
        other.states[0]
            .complete_action(
                &mut other.owners[0],
                &mut action,
                Completion::Staged {
                    admitted: &fence(2)?
                },
                Duration::ZERO
            )
            .is_err()
    );
    assert!(
        first.states[0]
            .complete_action(
                &mut first.owners[0],
                &mut action,
                Completion::Staged {
                    admitted: &fence(3)?
                },
                Duration::ZERO
            )
            .is_err()
    );
    assert!(!action.finished);
    assert_eq!(first.states[0].usage().engine_bytes, retained.engine_bytes);
    assert!(first.states[0].engine(Epoch(11)).is_err());
    assert_eq!(
        first.states[0].complete_action(
            &mut first.owners[0],
            &mut action,
            Completion::Staged {
                admitted: &fence(2)?
            },
            Duration::ZERO
        )?,
        Progress::Advanced
    );
    assert!(first.states[0].engine(Epoch(11)).is_ok());
    assert!(
        first.states[0]
            .complete_action(
                &mut first.owners[0],
                &mut action,
                Completion::Staged {
                    admitted: &fence(2)?
                },
                Duration::ZERO
            )
            .is_err()
    );
    Ok(())
}

fn ip_frame(port: u16, tag: u8) -> Vec<u8> {
    let mut packet = vec![0; 32];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&32_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&u16::from(tag).to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
    let sum: u32 = packet[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet[20..22].copy_from_slice(&port.to_be_bytes());
    packet[22..24].copy_from_slice(&24_500_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&12_u16.to_be_bytes());
    packet[28..32].fill(tag);
    packet
}
fn channel_packet(channel: usize, channels: usize, tag: u8) -> Result<Vec<u8>> {
    let port = (40_000..40_256_u16)
        .find(|port| l2tunnel_swift::flow::classify_ip(&ip_frame(*port, tag), channels) == channel)
        .ok_or("no actual flow for fixture channel")?;
    Ok(ip_frame(port, tag))
}
fn engine_fence(state: &State, epoch: Epoch, direction: records::Direction) -> Result<tx::Fence> {
    let engine = state.engine(epoch)?;
    let width = match direction {
        records::Direction::Send => engine.send_config().channels,
        records::Direction::Receive => engine.receive_config().channels,
    };
    let counts = (0..width)
        .map(|index| {
            let channel = records::ChannelId::new(index).ok_or("invalid actual channel")?;
            Ok(engine
                .boundary(direction, channel)
                .ok_or("missing actual boundary")?
                .count
                .0)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(tx::Fence::new(&counts)?)
}
type NativeExpectations = [Vec<(records::NativeIdentity, Vec<u8>)>; 2];
fn seed_native(
    lab: &mut Lab,
    epoch: Epoch,
    count: u8,
    now: u64,
    next: &mut [u64; 2],
) -> Result<NativeExpectations> {
    let mut expected: NativeExpectations = [Vec::new(), Vec::new()];
    let mut flights: [Vec<(records::RecordNumber, Vec<u8>)>; 2] = [Vec::new(), Vec::new()];
    // Build both outgoing flights before delivering either direction. Thus the
    // seeded bodies are source data rather than feedback for the other flight.
    for side in 0..2 {
        let width = lab.states[side].engine(epoch)?.send_config().channels;
        for channel in 0..width {
            for tag in 1..=count {
                let packet = channel_packet(channel, width, tag)?;
                let records::IdentifiedAdmission::Accepted(identity) = lab.states[side]
                    .entry(epoch)?
                    .offer_identified(now, &packet)?
                else {
                    return Err("actual native source admission refused".into());
                };
                assert_eq!(identity.channel.index(), channel);
                assert_eq!(identity.record, records::NativeRecordId(u64::from(tag - 1)));
                expected[side].push((identity, packet));
            }
        }
        let mut exhausted = false;
        for _ in 0..32 {
            let number = records::RecordNumber(next[side]);
            let body = lab.states[side]
                .entry(epoch)?
                .poll(now, number, true)?
                .map(<[u8]>::to_vec);
            let Some(body) = body else {
                exhausted = true;
                break;
            };
            assert_eq!(
                body[0] & l2tunnel_swift::KIND_MASK,
                l2tunnel_swift::KIND_SOURCE
            );
            next[side] = next[side]
                .checked_add(1)
                .ok_or("caller record number exhausted")?;
            flights[side].push((number, body));
        }
        assert!(exhausted, "finite native source poll bound exhausted");
        assert!(!flights[side].is_empty());
        assert!(!lab.states[side].engine(epoch)?.send_drained());
    }
    for (side, flight) in flights.iter_mut().enumerate() {
        for (number, body) in flight {
            lab.states[1 - side]
                .entry(epoch)?
                .accept(now + 1, *number, body)?;
        }
    }
    for state in &lab.states {
        assert!(!state.engine(epoch)?.send_drained());
        assert!(!state.engine(epoch)?.receive_drained());
    }
    Ok(expected)
}
fn extract_and_confirm(
    lab: &mut Lab,
    epoch: Epoch,
    expected: &NativeExpectations,
    now: u64,
    next: &mut [u64; 2],
) -> Result {
    for side in 0..2 {
        let mut received = Vec::new();
        let mut exhausted = false;
        for _ in 0..32 {
            let packet = lab.states[side]
                .entry(epoch)?
                .pop_identified()?
                .map(|packet| (packet.identity, packet.bytes.to_vec()));
            let Some(packet) = packet else {
                exhausted = true;
                break;
            };
            assert!(!received.iter().any(|(identity, _)| identity == &packet.0));
            assert!(
                expected[1 - side]
                    .iter()
                    .any(|expected| expected == &packet)
            );
            received.push(packet);
        }
        assert!(
            exhausted,
            "actual native extraction never observed terminal None"
        );
        assert_eq!(received.len(), expected[1 - side].len());
        let fence = engine_fence(&lab.states[side], epoch, records::Direction::Receive)?;
        assert!(lab.states[side].entry(epoch)?.pop_identified()?.is_none());
        assert_eq!(
            engine_fence(&lab.states[side], epoch, records::Direction::Receive)?,
            fence
        );
        assert!(lab.states[side].engine(epoch)?.receive_drained());
        assert!(!lab.states[side].engine(epoch)?.send_drained());
    }
    let mut feedback: [Vec<(records::RecordNumber, Vec<u8>)>; 2] = [Vec::new(), Vec::new()];
    for side in 0..2 {
        let mut exhausted = false;
        for _ in 0..16 {
            let number = records::RecordNumber(next[side]);
            let body = lab.states[side]
                .entry(epoch)?
                .poll(now, number, false)?
                .map(<[u8]>::to_vec);
            let Some(body) = body else {
                exhausted = true;
                break;
            };
            assert_eq!(
                body[0] & l2tunnel_swift::KIND_MASK,
                l2tunnel_swift::KIND_FEEDBACK
            );
            next[side] = next[side]
                .checked_add(1)
                .ok_or("caller record number exhausted")?;
            feedback[side].push((number, body));
        }
        assert!(exhausted, "finite actual feedback bound exhausted");
        assert!(!feedback[side].is_empty());
    }
    for (side, flight) in feedback.iter_mut().enumerate() {
        for (number, body) in flight {
            lab.states[1 - side]
                .entry(epoch)?
                .accept(now, *number, body)?;
        }
    }
    for side in 0..2 {
        assert!(lab.states[side].engine(epoch)?.send_drained());
        assert!(lab.states[side].engine(epoch)?.receive_drained());
        assert_eq!(
            engine_fence(&lab.states[side], epoch, records::Direction::Send)?,
            engine_fence(&lab.states[1 - side], epoch, records::Direction::Receive)?
        );
    }
    Ok(())
}

#[test]
fn actual_nonzero_asymmetric_fences_hold_custody_and_reset_only_native_generation() -> Result {
    let mut lab = Lab::new()?;
    let mut next = [1_u64 << 42, 1_u64 << 48];
    let old = seed_native(&mut lab, Epoch(10), 2, 0, &mut next)?;
    let admitted = [
        engine_fence(&lab.states[0], Epoch(10), records::Direction::Send)?,
        engine_fence(&lab.states[1], Epoch(10), records::Direction::Send)?,
    ];
    assert_eq!(admitted[0].counts(), &[2, 2]);
    assert_eq!(admitted[1].counts(), &[2, 2, 2]);
    lab.now = Duration::from_millis(1);
    lab.propose()?;
    let mut draining = false;
    for _ in 0..300 {
        lab.step([true, true])?;
        lab.gather();
        for (side, admitted) in admitted.iter().enumerate() {
            if lab.held[side]
                .as_ref()
                .is_some_and(|action| matches!(action.event(), tx::Event::Stage { .. }))
            {
                let mut action = lab.held[side].take().ok_or("missing actual Stage")?;
                assert_eq!(
                    lab.states[side].complete_action(
                        &mut lab.owners[side],
                        &mut action,
                        Completion::Staged { admitted },
                        lab.now
                    )?,
                    Progress::Advanced
                );
            }
        }
        if lab.held.iter().all(|action| {
            action
                .as_ref()
                .is_some_and(|action| matches!(action.event(), tx::Event::Drain { .. }))
        }) {
            draining = true;
            break;
        }
    }
    assert!(
        draining,
        "nonzero transaction did not reach independent drain work"
    );
    for side in 0..2 {
        let action = lab.held[side].as_ref().ok_or("lost actual Drain")?;
        let tx::Event::Drain { local, peer } = action.event() else {
            return Err("not actual Drain".into());
        };
        assert_eq!(local, &admitted[side]);
        assert_eq!(peer, &admitted[1 - side]);
        assert_ne!(
            &engine_fence(&lab.states[side], Epoch(10), records::Direction::Receive)?,
            peer
        );
        assert!(!lab.states[side].engine(Epoch(10))?.send_drained());
        assert!(!lab.states[side].engine(Epoch(10))?.receive_drained());
        assert!(lab.states[side].engine(Epoch(11)).is_ok());
        assert_eq!(lab.states[side].epoch(), Epoch(10));
    }
    for _ in 0..5 {
        lab.step([true, true])?;
    }
    assert!(
        lab.states
            .iter()
            .all(|state| state.engine(Epoch(10)).is_ok() && state.epoch() == Epoch(10))
    );
    let native_now = u64::try_from(lab.now.as_micros())? + 100;
    extract_and_confirm(&mut lab, Epoch(10), &old, native_now, &mut next)?;
    for side in 0..2 {
        let sent = engine_fence(&lab.states[side], Epoch(10), records::Direction::Send)?;
        let delivered = engine_fence(&lab.states[side], Epoch(10), records::Direction::Receive)?;
        let mut action = lab.held[side]
            .take()
            .ok_or("lost drain after actual debt settled")?;
        assert_eq!(
            lab.states[side].complete_action(
                &mut lab.owners[side],
                &mut action,
                Completion::Drained {
                    sent: &sent,
                    delivered: &delivered
                },
                lab.now
            )?,
            Progress::Advanced
        );
    }
    let mut retired = [false; 2];
    let mut settled = false;
    for _ in 0..1000 {
        lab.step([true, true])?;
        lab.drive()?;
        for (side, retired) in retired.iter_mut().enumerate() {
            if let Some(outcome) = lab.states[side].take_outcome() {
                assert!(matches!(
                    outcome,
                    Outcome::Retired {
                        epoch: Epoch(10),
                        ..
                    }
                ));
                *retired = true;
            }
        }
        if retired.into_iter().all(|done| done)
            && lab.states.iter().all(|state| state.operation.is_none())
        {
            settled = true;
            break;
        }
    }
    assert!(
        settled,
        "actual nonzero final message proofs did not settle"
    );
    for side in 0..2 {
        assert!(lab.states[side].engine(Epoch(10)).is_err());
        assert_eq!(lab.states[side].epoch(), Epoch(11));
        let engine = lab.states[side].engine(Epoch(11))?;
        assert_eq!(engine.send_config().channels, if side == 0 { 4 } else { 1 });
        assert_eq!(
            engine.receive_config().channels,
            if side == 0 { 1 } else { 4 }
        );
        assert!(
            engine_fence(&lab.states[side], Epoch(11), records::Direction::Send)?
                .counts()
                .iter()
                .all(|count| *count == 0)
        );
        assert!(
            engine_fence(&lab.states[side], Epoch(11), records::Direction::Receive)?
                .counts()
                .iter()
                .all(|count| *count == 0)
        );
    }
    let continuation = next;
    let native_now = u64::try_from(lab.now.as_micros())? + 200;
    let new = seed_native(&mut lab, Epoch(11), 1, native_now, &mut next)?;
    assert!(
        new.iter()
            .flatten()
            .all(|(identity, _)| identity.record == records::NativeRecordId(0))
    );
    assert!(next[0] > continuation[0] && next[1] > continuation[1]);
    extract_and_confirm(&mut lab, Epoch(11), &new, native_now + 100, &mut next)?;
    assert!(next[0] > (1_u64 << 42) && next[1] > (1_u64 << 48));
    Ok(())
}

#[test]
fn caller_local_cap_survives_actual_blocked_request_and_is_not_recomputed() -> Result {
    let mut lab = Lab::new()?;
    lab.propose()?;
    let queued_cap = tx::Tick(1);
    assert_eq!(
        lab.states[0].propose(&mut lab.owners[0], values()?[0], queued_cap, || Ok(lab.now))?,
        Progress::Blocked
    );
    let mut settled = false;
    for _ in 0..1000 {
        lab.step([true, true])?;
        lab.drive()?;
        for side in 0..2 {
            lab.states[side].take_outcome();
        }
        if lab.states.iter().all(|state| state.operation.is_none()) {
            settled = true;
            break;
        }
    }
    assert!(settled && lab.now > duration(queued_cap));
    let before = lab.states[0].usage();
    assert!(
        lab.states[0]
            .propose(&mut lab.owners[0], values()?[0], queued_cap, || Ok(lab.now))
            .is_err()
    );
    assert_eq!(lab.states[0].usage(), before);
    assert!(lab.states[0].peer.operation().is_none());
    assert!(lab.states[0].prepared.is_none());
    let new_request_cap = tx::Tick(tick(lab.now)?.0 + 5000);
    assert_eq!(
        lab.states[0].propose(&mut lab.owners[0], values()?[0], new_request_cap, || Ok(
            lab.now
        ))?,
        Progress::Advanced
    );
    let operation = lab.states[0]
        .peer
        .operation()
        .ok_or("missing actual second request")?;
    assert_eq!(operation.expires(), new_request_cap);
    assert_eq!(operation.ticket().attempt, 2);
    Ok(())
}

#[test]
fn current_frozen_custody_owns_retries_without_burning_inner_packet_numbers() -> Result {
    let mut lab = Lab::new()?;
    lab.propose()?;
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    lab.gather();
    assert_eq!(lab.complete(0)?, Progress::Advanced);
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    let output = lab.states[0]
        .outputs
        .iter()
        .flatten()
        .next()
        .ok_or("missing first frozen output")?;
    let first = mg::Frame::decode(output.frozen.command(), mg::Limits::default())?
        .header
        .packet;
    let envelope = output.frozen.envelope().to_vec();
    let submission = output.frozen.submission();
    let token = output
        .frozen
        .token()
        .ok_or("first output not really admitted")?;
    for millis in 1..=200 {
        lab.now = Duration::from_millis(millis);
        lab.states[0].service(&mut lab.owners[0], lab.now)?;
    }
    let output = lab.states[0]
        .outputs
        .iter()
        .flatten()
        .next()
        .ok_or("current output was discarded")?;
    assert_eq!(output.frozen.envelope(), envelope);
    assert_eq!(output.frozen.submission(), submission);
    assert_eq!(output.frozen.token(), Some(token));
    assert_eq!(lab.states[0].outputs.iter().flatten().count(), 1);
    // A real explicit Peer poll now emits the immediate next inner packet.
    // If ordinary State service had minted/coalesced retries, this ID would skip.
    let retry = lab.states[0]
        .peer
        .poll(tick(lab.now)?)?
        .outbound
        .ok_or("missing genuine due retry")?;
    assert_eq!(
        mg::Frame::decode(&retry, mg::Limits::default())?
            .header
            .packet
            .0,
        first.0 + 1
    );
    Ok(())
}

#[test]
fn real_confirmed_callback_failure_keeps_frozen_custody_and_marks_state_terminal() -> Result {
    let mut lab = Lab::new()?;
    lab.propose()?;
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    lab.gather();
    lab.complete(0)?;
    lab.states[0].service(&mut lab.owners[0], lab.now)?;
    let output = lab.states[0]
        .outputs
        .iter()
        .flatten()
        .next()
        .ok_or("missing actual PREPARE custody")?;
    let token = output
        .frozen
        .token()
        .ok_or("output was not actually admitted")?;
    let bytes = output.frozen.envelope().to_vec();
    let mut callback_ran = false;
    for _ in 0..300 {
        lab.now += Duration::from_millis(1);
        // Deliberately leave Client State unserviced so the actual Owner proof
        // becomes available before State observes confirmation of this marker.
        lab.states[1].service(&mut lab.owners[1], lab.now)?;
        lab.states[1].dispatch(&mut lab.owners[1], || Ok(lab.now))?;
        lab.states[1].service(&mut lab.owners[1], lab.now)?;
        lab.wire()?;
        let result = lab.owners[0].with_confirmed(token, lab.now, |_actual_proof| {
            callback_ran = true;
            Err::<(), _>(io::Error::other("deliberate real-proof callback failure"))
        });
        if callback_ran {
            assert!(result.is_err());
            break;
        }
        assert_eq!(result?, control_owner::Attempt::Blocked);
    }
    assert!(
        callback_ran,
        "no actual whole-message Confirmed proof became available"
    );
    assert!(
        !lab.states[0]
            .outputs
            .iter()
            .flatten()
            .next()
            .ok_or("lost unobserved marker")?
            .confirmed
    );
    assert!(lab.states[0].service(&mut lab.owners[0], lab.now).is_err());
    assert!(lab.states[0].failed);
    assert!(!lab.states[0].can_admit_data());
    assert!(lab.states[0].next_deadline().is_none());
    let retained = lab.states[0]
        .outputs
        .iter()
        .flatten()
        .next()
        .ok_or("terminal error discarded custody")?;
    assert_eq!(retained.frozen.envelope(), bytes);
    assert_eq!(retained.frozen.token(), Some(token));
    assert!(!retained.confirmed);
    assert!(
        lab.owners[0]
            .with_confirmed(token, lab.now, |_| Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn exact_cached_final_request_coalesces_under_two_real_unconfirmed_outputs() -> Result {
    let mut lab = Lab::with(protocol(), pressure_selected(), SESSION)?;
    lab.propose()?;
    let mut retired = false;
    for _ in 0..1000 {
        lab.step([true, true])?;
        lab.gather();
        for side in 0..2 {
            if side == 1
                && lab.held[side]
                    .as_ref()
                    .is_some_and(|action| matches!(action.event(), tx::Event::Committed(_)))
            {
                // Preserve the server COMMIT_ACK's actual source debt, while
                // withholding its later final reply from the still-waiting client.
                lab.drop_client_acks = true;
                lab.drop_server_final_data = true;
            }
            if lab.held[side].is_some() {
                lab.complete(side)?;
            }
        }
        if matches!(
            lab.states[1].take_outcome(),
            Some(Outcome::Retired {
                epoch: Epoch(10),
                ..
            })
        ) {
            retired = true;
            break;
        }
    }
    assert!(retired, "actual server physical retirement did not occur");
    assert_eq!(lab.states[1].peer.phase(), tx::Phase::Idle);
    assert_eq!(lab.states[0].peer.phase(), tx::Phase::AwaitRetireAck);
    let operation = lab.states[1]
        .peer
        .operation()
        .ok_or("final cache released without actual confirmation")?;
    assert_eq!(lab.states[1].outputs.iter().flatten().count(), 2);
    assert!(
        lab.states[1]
            .outputs
            .iter()
            .flatten()
            .all(|output| !output.confirmed)
    );
    assert!(!lab.states[1].normal_output_room()?);
    assert!(lab.states[1].engine(Epoch(10)).is_err());
    let before = lab.states[1].usage();
    let current = lab.states[1]
        .outputs
        .iter()
        .flatten()
        .find(|output| output.frozen.context().is_final_reply())
        .ok_or("missing actual cached final FrozenOutput")?;
    let bytes = current.frozen.envelope().to_vec();
    let submission = current.frozen.submission();
    let deadline = current.frozen.deadline();
    lab.now += Duration::from_millis(20);
    let command = lab.states[0]
        .peer
        .poll(tick(lab.now)?)?
        .outbound
        .ok_or("missing real independently re-encoded RETIRE retry")?;
    let mut retry = lab.owners[0].freeze_transaction(&lab.states[0].peer, &command, lab.now)?;
    assert!(matches!(
        lab.owners[0].submit_frozen(&mut retry, lab.now)?,
        control_owner::Attempt::Complete(_)
    ));
    let mut pending = false;
    for _ in 0..200 {
        lab.now += Duration::from_millis(1);
        lab.wire()?;
        if lab.pending_kind(1)? == Some(mg::MessageKind::Retire) {
            pending = true;
            break;
        }
    }
    assert!(
        pending,
        "actual independently encoded final request was not retained"
    );
    let view = lab.owners[1]
        .preview_transaction(&lab.states[1].peer, lab.now, operation.expires())?
        .ok_or("missing actual cached preview")?;
    assert!(view.preparation().is_none());
    let authority = lab.states[1]
        .peer
        .cached_retry_authority(tick(lab.now)?)?
        .ok_or("missing actual cached authority")?;
    assert_eq!(authority.operation(), operation);
    assert_eq!(authority.reply_kind(), mg::MessageKind::Retire);
    assert_eq!(
        lab.states[1].dispatch(&mut lab.owners[1], || Ok(lab.now))?,
        Progress::Advanced
    );
    lab.states[1].service(&mut lab.owners[1], lab.now)?;
    assert_eq!(lab.states[1].peer.operation(), Some(operation));
    assert_eq!(lab.states[1].usage(), before);
    assert!(lab.states[1].prepared.is_none());
    assert!(lab.states[1].take_action().is_none());
    assert!(lab.states[1].take_outcome().is_none());
    assert_eq!(lab.states[1].outputs.iter().flatten().count(), 2);
    assert!(lab.states[1].outputs[2].is_none());
    let current = lab.states[1]
        .outputs
        .iter()
        .flatten()
        .find(|output| output.frozen.context().is_final_reply())
        .ok_or("cached retry discarded final custody")?;
    assert_eq!(current.frozen.envelope(), bytes);
    assert_eq!(current.frozen.submission(), submission);
    assert_eq!(current.frozen.deadline(), deadline);
    lab.drop_client_acks = false;
    lab.drop_server_final_data = false;
    let mut settled = false;
    for _ in 0..1000 {
        lab.step([true, true])?;
        lab.drive()?;
        if lab
            .states
            .iter()
            .all(|state| state.peer.operation().is_none())
        {
            settled = true;
            break;
        }
    }
    assert!(
        settled,
        "genuine final proofs did not complete after cached retry pressure cleared"
    );
    let token = retry.token().ok_or("independent retry lost actual token")?;
    let mut confirmed = false;
    for _ in 0..300 {
        lab.step([true, true])?;
        if lab.owners[0].with_confirmed(token, lab.now, |_| Ok(()))?
            == control_owner::Attempt::Complete(())
        {
            lab.owners[0].retire(token, lab.now)?;
            confirmed = true;
            break;
        }
    }
    assert!(
        confirmed,
        "independent fixture retry retained unconfirmed custody"
    );
    assert_eq!(lab.states[1].epoch(), Epoch(11));
    assert!(lab.states[1].engine(Epoch(10)).is_err());
    Ok(())
}
