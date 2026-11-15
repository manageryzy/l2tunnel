//! One actual generic State, actual common Banks and complete reserved Control.
//! Empty record owners give genuine zero fences; no encrypted/native-I/O claim.
use super::super::common_engines::{Bank as CommonBank, tests as fixture};
use super::*;
use l2tunnel::record_configuration as common;
use l2tunnel_management::messages;
use l2tunnel_recovery as recovery;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SESSION: Duration = Duration::from_secs(10);
const CAP: tx::Tick = tx::Tick(5000);

fn role(side: usize) -> mg::Role {
    if side == 0 {
        mg::Role::Client
    } else {
        mg::Role::Server
    }
}
fn binding(side: usize) -> delivery::Binding {
    let id = fixture::identity(role(side));
    delivery::Binding {
        session: id.session,
        lane: id.lane,
        local_role: id.role,
        control_epoch: 1,
    }
}
fn control_scope() -> sc::Scope {
    sc::Scope {
        epoch: Epoch(1),
        digest: l2tunnel_core::ConfigDigest([0x91; 32]),
    }
}
fn catalog() -> Result<common::Catalog> {
    let values = fixture::values()?;
    let descriptors = values.map(|value| *value.descriptor());
    Ok(common::Catalog::new(descriptors[0], &descriptors)?)
}
fn protocol() -> tx::Settings {
    tx::Settings {
        retry_ms: 10,
        phase_timeout_ms: 2000,
        reconcile_timeout_ms: 3000,
    }
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
    let message = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: 84,
            ..base()
        },
        path_mtu: 1500,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 16384,
        max_fragments: 32,
        max_reassembly_bytes: 8192,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(4),
        work_per_call: 8,
    };
    control_owner::Settings {
        streams: [message; 3],
    }
}
fn sequence_bank(side: usize) -> Result<CommonBank> {
    let role = role(side);
    let values = fixture::values()?;
    let initial = fixture::initial_plan(role)?;
    let mut heaps = [0; 3];
    for (index, value) in values.into_iter().enumerate() {
        heaps[index] = l2tunnel::record_engine::storage::Plan::for_engine(
            value,
            l2tunnel::record_engine::Context {
                epoch: 11,
                ..initial.context()
            },
            fixture::geometry(),
            fixture::native(),
        )?
        .heap_bytes();
    }
    let inventory = l2tunnel::record_bank::storage::Plan::for_bank(initial, fixture::EXTERNAL)?;
    let fixed = inventory
        .capacity_bytes()
        .checked_sub(initial.heap_bytes())
        .ok_or("fixture fixed budget underflow")?;
    // Every exercised switch retains the actual current heap while preparing
    // its target; later Aligned/Packed coexistence cannot use the Swift heap.
    let retained = [(0, 1), (1, 2), (2, 0)].into_iter().try_fold(
        0,
        |maximum, (current, target)| -> Result<usize> {
            let pair = heaps[current]
                .checked_add(heaps[target])
                .ok_or("fixture coexisting budget overflow")?;
            Ok(maximum.max(pair))
        },
    )?;
    let limit = fixed
        .checked_add(retained)
        .ok_or("fixture complete budget overflow")?;
    let bank = CommonBank::new(
        fixture::identity(role),
        Epoch(10),
        values[0],
        fixture::geometry(),
        fixture::native(),
        l2tunnel::record_bank::storage::Limits {
            capacity_bytes: limit,
        },
        fixture::EXTERNAL,
    )?;
    let usage = bank.usage();
    assert_eq!(usage.limit_bytes, limit);
    assert_eq!(usage.capacity_bytes, inventory.capacity_bytes());
    assert_eq!(usage.engine_bytes, heaps[0]);
    assert_eq!(
        usage.fixed_bytes.checked_add(usage.external_bytes),
        Some(fixed)
    );
    Ok(bank)
}
fn state(side: usize, bank: CommonBank) -> Result<CommonState> {
    let retained_bytes = bank.usage().limit_bytes;
    Ok(CommonState::new(
        fixture::identity(role(side)),
        Epoch(10),
        fixture::values()?[0].envelope(),
        catalog()?,
        TransactionSettings {
            protocol: protocol(),
            max_operation_ms: 5000,
            retained_bytes,
        },
        control_streams::delivery_binding(binding(side), control_streams::Stream::Transaction)?,
        Duration::ZERO,
        SESSION,
        bank,
    )?)
}
fn owner(side: usize) -> Result<control_owner::Owner> {
    let selected = selected();
    let mut limits = [messages::storage::Limits { capacity_bytes: 0 }; 3];
    for (index, stream) in control_streams::Stream::ALL.into_iter().enumerate() {
        limits[index].capacity_bytes = messages::storage::Plan::for_owner(
            selected.streams[index],
            control_streams::delivery_binding(binding(side), stream)?,
            Duration::ZERO,
            SESSION,
        )?
        .capacity_bytes();
    }
    Ok(control_owner::Owner::new_leased_reserved_messages(
        base(),
        selected,
        binding(side),
        control_scope(),
        sc::Scope {
            epoch: Epoch(10),
            digest: tx::configuration_digest(&fixture::values()?[0])?,
        },
        Duration::ZERO,
        SESSION,
        limits,
    )?)
}

struct Lab {
    states: [CommonState; 2],
    owners: [control_owner::Owner; 2],
    held: [Option<CommonAction>; 2],
    now: Duration,
    prepares: usize,
}
impl Lab {
    fn new() -> Result<Self> {
        Ok(Self {
            states: [state(0, sequence_bank(0)?)?, state(1, sequence_bank(1)?)?],
            owners: [owner(0)?, owner(1)?],
            held: [None, None],
            now: Duration::ZERO,
            prepares: 0,
        })
    }
    fn wire(&mut self) -> Result {
        for side in 0..2 {
            let mut allowance = 4096;
            let mut packet = [0; 512];
            for _ in 0..8 {
                let Some(emission) = self.owners[side].poll(self.now, allowance, &mut packet)?
                else {
                    break;
                };
                allowance -= emission.wire_bytes;
                self.owners[1 - side].receive(
                    mg::Ingress::AuthenticatedManagement {
                        session: binding(side).session,
                        lane: binding(side).lane,
                        sender: role(side),
                    },
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
                let cap = self.states[side]
                    .peer()
                    .operation()
                    .map(tx::Operation::expires)
                    .unwrap_or(CAP);
                if let Some(view) = self.owners[side].preview_transaction(
                    self.states[side].peer(),
                    self.now,
                    cap,
                )? {
                    let envelope = sc::Envelope::decode(
                        view.envelope(),
                        sc::Limits {
                            max_frame_bytes: 4096,
                            max_management_bytes: 4096 - sc::HEADER_BYTES,
                            max_feedback_bytes: 1,
                        },
                    )?;
                    let sc::Body::Management(command) = envelope.body else {
                        return Err("not actual Management".into());
                    };
                    let frame = mg::Frame::decode(
                        command,
                        tx::configuration_limits::<common::Configuration>()?,
                    )?;
                    if frame.header.kind == mg::MessageKind::Prepare {
                        let encoded = frame
                            .body
                            .get(8..8 + common::CONFIGURATION_BYTES)
                            .ok_or("incomplete common canonical request")?;
                        let value = common::Configuration::decode(encoded)?;
                        assert_eq!(
                            frame.header.ticket.digest,
                            tx::configuration_digest(&value)?
                        );
                        if let Some(expected) = view.preparation() {
                            let mut canonical = [0; common::CONFIGURATION_BYTES];
                            expected.config().encode_into(&mut canonical)?;
                            assert_eq!(encoded, canonical.as_slice());
                            assert_eq!(&value, expected.config());
                            self.prepares += 1;
                        }
                    }
                }
                self.states[side].dispatch(&mut self.owners[side], || Ok(self.now))?;
            }
            self.states[side].service(&mut self.owners[side], self.now)?;
        }
        self.wire()
    }
    fn drive(&mut self) -> Result {
        for side in 0..2 {
            if self.held[side].is_none() {
                self.held[side] = self.states[side].take_action();
            }
            let Some(mut action) = self.held[side].take() else {
                continue;
            };
            let completion = match action.event().clone() {
                tx::Event::Stage { .. } => {
                    let old = self.states[side].engine(action.operation().origin().epoch)?;
                    assert!(old.drained()?);
                    assert_eq!(
                        old.statistics(),
                        l2tunnel::record_engine::Statistics::default()
                    );
                    // No record ingress/admission occurs in this pure control fixture.
                    // These exact old-width zeros therefore describe actual empty owners.
                    let width = self.states[side].peer().sender_channels(role(side));
                    let fence = tx::Fence::new(&vec![0; usize::from(width)])?;
                    self.states[side].complete_action(
                        &mut self.owners[side],
                        &mut action,
                        Completion::Staged { admitted: &fence },
                        self.now,
                    )?
                }
                tx::Event::Drain { local, peer } => {
                    let old = self.states[side].engine(action.operation().origin().epoch)?;
                    assert!(old.drained()?);
                    assert!(local.counts().iter().all(|count| *count == 0));
                    assert!(peer.counts().iter().all(|count| *count == 0));
                    assert!(old.pending_native().is_none());
                    self.states[side].complete_action(
                        &mut self.owners[side],
                        &mut action,
                        Completion::Drained {
                            sent: &local,
                            delivered: &peer,
                        },
                        self.now,
                    )?
                }
                _ => self.states[side].complete_action(
                    &mut self.owners[side],
                    &mut action,
                    Completion::Applied,
                    self.now,
                )?,
            };
            if completion == Progress::Blocked {
                self.held[side] = Some(action);
            }
        }
        Ok(())
    }
    fn propose(&mut self, value: common::Configuration) -> Result {
        let cap = tx::Tick(u64::try_from(self.now.as_millis())? + 5000);
        assert_eq!(
            self.states[0].propose(&mut self.owners[0], value, cap, || Ok(self.now))?,
            Progress::Advanced
        );
        Ok(())
    }
    fn settle(&mut self) -> Result<[Outcome; 2]> {
        let mut outcomes = [None, None];
        for _ in 0..2000 {
            self.step([true, true])?;
            self.drive()?;
            for (side, stored) in outcomes.iter_mut().enumerate() {
                if let Some(outcome) = self.states[side].take_outcome() {
                    assert!(stored.is_none());
                    *stored = Some(outcome);
                }
            }
            if outcomes.iter().all(Option::is_some)
                && self.held.iter().all(Option::is_none)
                && self.states.iter().all(|state| {
                    state.operation.is_none()
                        && state.peer().operation().is_none()
                        && state.outputs.iter().all(Option::is_none)
                        && state.work.is_none()
                })
            {
                return Ok([
                    outcomes[0].ok_or("left outcome")?,
                    outcomes[1].ok_or("right outcome")?,
                ]);
            }
        }
        Err("finite common State transaction did not settle actual custody".into())
    }
}

#[test]
fn one_real_state_switches_empty_reserved_swift_aligned_packed_and_back() -> Result {
    let mut lab = Lab::new()?;
    let values = fixture::values()?;
    for (index, value) in [values[1], values[2], values[0]].into_iter().enumerate() {
        let old = Epoch(10 + u64::try_from(index)?);
        let target = Epoch(old.0 + 1);
        lab.propose(value)?;
        assert!(
            lab.states[0].engine(target).is_err(),
            "virgin target became packet-visible"
        );
        let outcomes = lab.settle()?;
        for (side, outcome) in outcomes.into_iter().enumerate() {
            assert!(matches!(outcome, Outcome::Retired { epoch, .. } if epoch == old));
            assert_eq!(lab.states[side].current(), &value);
            assert_eq!(lab.states[side].epoch(), target);
            assert_eq!(lab.states[side].peer().active_config(), &value);
            assert_eq!(lab.states[side].peer().phase(), tx::Phase::Idle);
            assert!(lab.states[side].engine(old).is_err());
            assert_eq!(lab.states[side].engine(target)?.configuration(), &value);
            assert!(lab.states[side].can_admit_data());
            assert_eq!(lab.states[side].usage().building_bytes, 0);
        }
    }
    assert_eq!(lab.prepares, 3);
    for state in &lab.states {
        assert_eq!(state.usage().peak_bytes, state.usage().limit_bytes);
    }
    Ok(())
}

#[test]
fn common_catalog_refusal_and_post_allocation_cap_leave_original_owners() -> Result {
    let mut lab = Lab::new()?;
    let values = fixture::values()?;
    let before = lab.states[0].usage();
    let original = lab.states[0].engine(Epoch(10))? as *const l2tunnel::record_engine::Engine;
    let wrong_anchor = common::Configuration::new(
        common::EnvelopeDigest::new([0x3a; 32]),
        *values[1].descriptor(),
    )?;
    assert!(
        lab.states[0]
            .propose(&mut lab.owners[0], wrong_anchor, CAP, || Ok(Duration::ZERO))
            .is_err()
    );
    assert_eq!(lab.states[0].usage(), before);
    let descriptor = values[1].descriptor();
    let unlisted = common::Configuration::new(
        values[1].envelope(),
        common::Descriptor::new(
            1499,
            descriptor.duplex(),
            *descriptor.direction(mg::Role::Client).common(),
            *descriptor.direction(mg::Role::Server).common(),
            *descriptor.profile(),
        )?,
    )?;
    assert!(
        lab.states[0]
            .propose(&mut lab.owners[0], unlisted, CAP, || Ok(Duration::ZERO))
            .is_err()
    );
    assert_eq!(lab.states[0].usage(), before);
    let mut samples = [Duration::ZERO, Duration::from_millis(CAP.0)].into_iter();
    assert!(
        lab.states[0]
            .propose(&mut lab.owners[0], values[1], CAP, || samples
                .next()
                .ok_or_else(|| io::Error::other("extra sample")))
            .is_err()
    );
    assert_eq!(lab.states[0].usage().engine_bytes, before.engine_bytes);
    assert_eq!(lab.states[0].usage().capacity_bytes, before.capacity_bytes);
    assert_eq!(
        lab.states[0].engine(Epoch(10))? as *const l2tunnel::record_engine::Engine,
        original
    );
    assert!(lab.states[0].prepared.is_none());
    assert!(lab.states[0].peer().operation().is_none());
    assert_eq!(lab.states[0].peer().phase(), tx::Phase::Idle);
    Ok(())
}

fn pending_prepare(lab: &Lab) -> Result<Option<(control_owner::Incoming, Duration, Vec<u8>)>> {
    Ok(lab.owners[1]
        .preview_transaction(lab.states[1].peer(), lab.now, CAP)?
        .map(|view| (view.incoming(), view.deadline(), view.envelope().to_vec())))
}

#[test]
fn held_complete_common_prepare_keeps_exact_custody_while_liveness_confirms() -> Result {
    let mut lab = Lab::new()?;
    lab.propose(fixture::values()?[1])?;
    let mut pending = None;
    for _ in 0..500 {
        lab.step([true, false])?;
        lab.drive()?;
        if let Some(view) = pending_prepare(&lab)? {
            pending = Some(view);
            break;
        }
    }
    let original = pending.ok_or("complete real common PREPARE never arrived")?;
    assert_eq!(
        management_kind_for::<common::Configuration>(&original.2)?,
        mg::MessageKind::Prepare
    );
    let operation_cap = lab.states[0].operation_deadline();
    for nonce in 1..=16 {
        let ping = lab.owners[0]
            .submit(
                control_scope(),
                sc::Body::Ping { nonce },
                lab.now,
                Duration::from_millis(CAP.0),
                false,
            )?
            .ok_or("Ping admission unexpectedly blocked")?;
        let mut pong = None;
        let mut received = false;
        let mut complete = false;
        for _ in 0..128 {
            lab.step([true, false])?;
            lab.drive()?;
            for side in 0..2 {
                let mut bytes = [0; 4096];
                let Some(incoming) = lab.owners[side].next(lab.now, &mut bytes)? else {
                    continue;
                };
                assert_eq!(incoming.stream, Some(control_streams::Stream::Liveness));
                let envelope = sc::Envelope::decode(
                    &bytes[..incoming.bytes],
                    sc::Limits {
                        max_frame_bytes: 4096,
                        max_management_bytes: 4016,
                        max_feedback_bytes: 1,
                    },
                )?;
                match (side, envelope.body) {
                    (1, sc::Body::Ping { nonce: value }) if value == nonce => {
                        pong = Some(
                            lab.owners[1]
                                .submit(
                                    control_scope(),
                                    sc::Body::Pong { nonce },
                                    lab.now,
                                    Duration::from_millis(CAP.0),
                                    false,
                                )?
                                .ok_or("Pong admission unexpectedly blocked")?,
                        );
                    }
                    (0, sc::Body::Pong { nonce: value }) if value == nonce => {
                        received = true;
                    }
                    _ => return Err("Liveness body or direction changed".into()),
                }
                lab.owners[side].accepted(incoming, lab.now)?;
            }
            if let Some(pong) = pong
                && received
                && lab.owners[0].confirmed(ping, lab.now)?
                && lab.owners[1].confirmed(pong, lab.now)?
            {
                lab.owners[0].retire(ping, lab.now)?;
                lab.owners[1].retire(pong, lab.now)?;
                complete = true;
                break;
            }
        }
        assert!(complete, "whole Ping/Pong custody did not confirm");
        assert_eq!(pending_prepare(&lab)?.as_ref(), Some(&original));
        assert_eq!(lab.states[0].operation_deadline(), operation_cap);
        assert!(lab.states[1].peer().operation().is_none());
    }
    lab.settle()?;
    assert_eq!(lab.states[0].current(), &fixture::values()?[1]);
    assert_eq!(lab.states[1].current(), &fixture::values()?[1]);
    Ok(())
}
