use super::*;
use crate::storage::{self, Limits, Plan};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn config() -> ArqConfig {
    ArqConfig {
        max_source_bytes: 16,
        send_bytes: 64,
        receive_bytes: 64,
        send_records: 4,
        receive_records: 4,
        initial_rto: ms(10),
        maximum_rto: ms(80),
        ack_delay: Duration::ZERO,
        max_retries: 8,
    }
}
fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x314159,
        epoch: 9,
        role,
    }
}
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn make(config: ArqConfig, role: EndpointRole, reserved: bool) -> Result<SelectiveRepeat> {
    Ok(if reserved {
        SelectiveRepeat::new_reserved(
            config,
            context(role),
            Limits {
                capacity_bytes: Plan::for_arq(config)?.capacity_bytes(),
            },
        )?
    } else {
        SelectiveRepeat::new(config, context(role))?
    })
}
fn inventory(engine: &SelectiveRepeat) -> Result<Vec<(usize, usize)>> {
    let Sent::Reserved(sent) = &engine.0.sent else {
        return Err("reserved send backing".into());
    };
    let Received::Reserved(received) = &engine.0.received else {
        return Err("reserved receive backing".into());
    };
    let mut values = vec![
        (sent.as_ptr() as usize, sent.capacity()),
        (received.as_ptr() as usize, received.capacity()),
    ];
    values.extend(sent.iter().map(|slot| {
        (
            slot.flight.payload.as_ptr() as usize,
            slot.flight.payload.capacity(),
        )
    }));
    values.extend(
        received
            .iter()
            .map(|slot| (slot.payload.as_ptr() as usize, slot.payload.capacity())),
    );
    Ok(values)
}

#[test]
fn exact_plan_one_short_invalid_layout_and_legacy_observation() -> Result {
    let config = config();
    let plan = Plan::for_arq(config)?;
    assert_eq!(plan.config(), config);
    assert_eq!(
        plan.capacity_bytes(),
        storage::array_bytes::<SendSlot>(4)? + storage::array_bytes::<ReceiveSlot>(4)? + 8 * 16
    );
    assert!(
        matches!(SelectiveRepeat::new_reserved(config, context(EndpointRole::Initiator),
        Limits { capacity_bytes: plan.capacity_bytes() - 1 }),
        Err(storage::Error::Limit { required, limit })
        if required == plan.capacity_bytes() && limit + 1 == required)
    );
    let owner = make(config, EndpointRole::Initiator, true)?;
    assert_eq!(
        owner.storage_usage(),
        Some(storage::Usage {
            capacity_bytes: plan.capacity_bytes(),
            limit_bytes: plan.capacity_bytes(),
            allocations: 10,
        })
    );
    assert_eq!(
        make(config, EndpointRole::Initiator, false)?.storage_usage(),
        None
    );
    assert_eq!(
        storage::array_bytes::<u64>(usize::MAX),
        Err(storage::Error::Layout)
    );
    for invalid in [
        ArqConfig {
            max_source_bytes: 0,
            ..config
        },
        ArqConfig {
            send_records: 65,
            ..config
        },
        ArqConfig {
            receive_records: 0,
            ..config
        },
        ArqConfig {
            send_bytes: 15,
            ..config
        },
        ArqConfig {
            initial_rto: Duration::ZERO,
            ..config
        },
    ] {
        assert_eq!(
            Plan::for_arq(invalid),
            Err(storage::Error::Recovery(RecoveryError::InvalidConfig))
        );
    }
    Ok(())
}

#[test]
fn every_real_constructor_reservation_can_fail_without_publishing_an_engine() -> Result {
    let config = config();
    let plan = Plan::for_arq(config)?;
    for point in 1..=2 + config.send_records + config.receive_records {
        let mut allocation = storage::Allocation::failing(plan.capacity_bytes(), point);
        assert!(matches!(
            Engine::new_reserved(config, context(EndpointRole::Initiator), &mut allocation),
            Err(storage::Error::Allocation)
        ));
        assert_eq!(allocation.attempts(), point);
        assert_eq!(allocation.usage().allocations, point - 1);
        // A fresh actual owner can immediately provision the same full inventory.
        let owner = make(config, EndpointRole::Initiator, true)?;
        assert_eq!(
            owner.storage_usage().map(|usage| usage.capacity_bytes),
            Some(plan.capacity_bytes())
        );
    }
    Ok(())
}

#[test]
fn every_partial_constructor_inventory_is_owned_then_actually_dropped() -> Result {
    use storage::ConstructionEventKind as Kind;
    let config = config();
    let plan = Plan::for_arq(config)?;
    let reservations = 2 + config.send_records + config.receive_records;
    for point in 1..=reservations {
        let trace = std::rc::Rc::new(std::cell::RefCell::new(
            storage::ConstructionTrace::default(),
        ));
        let mut allocation =
            storage::Allocation::traced(plan.capacity_bytes(), Some(point), trace.clone());
        assert!(matches!(
            Engine::new_reserved(config, context(EndpointRole::Initiator), &mut allocation),
            Err(storage::Error::Allocation)
        ));
        assert_eq!(allocation.attempts(), point);
        assert_eq!(allocation.usage().allocations, point - 1);
        let events: Vec<_> = trace.borrow().events().collect();
        assert!(!trace.borrow().overflow);
        assert_eq!(events.len(), 3 * (point - 1));
        for reservation in 1..point {
            let matching: Vec<_> = events
                .iter()
                .filter(|event| event.reservation == reservation)
                .collect();
            assert_eq!(matching.len(), 3);
            assert_eq!(matching[0].kind, Kind::Reserved);
            assert_eq!(matching[1].kind, Kind::Owned);
            assert_eq!(matching[2].kind, Kind::Released);
            assert!(matching[0].pointer != 0 && matching[0].bytes != 0);
            for event in &matching[1..] {
                assert_eq!(event.pointer, matching[0].pointer);
                assert_eq!(event.capacity, matching[0].capacity);
                assert_eq!(event.bytes, matching[0].bytes);
            }
        }
        assert!(events.iter().all(|event| event.reservation < point));
        let released: Vec<_> = events
            .iter()
            .filter(|event| event.kind == Kind::Released)
            .map(|event| event.reservation)
            .collect();
        // Payloads are really dropped before their enclosing metadata Vecs.
        let expected: Vec<_> = (3..point)
            .chain((1..point).filter(|reservation| *reservation <= 2))
            .collect();
        assert_eq!(released, expected);
        // A simultaneous independent constructor cannot read or alter this
        // local trace; no process-global allocator/failpoint state is used.
        let other = make(config, EndpointRole::Responder, true)?;
        assert_eq!(
            other.storage_usage().map(|usage| usage.allocations),
            Some(reservations)
        );
        assert_eq!(trace.borrow().events().collect::<Vec<_>>(), events);
    }
    Ok(())
}

#[test]
fn successful_constructor_transfers_the_traced_inventory_without_early_release() -> Result {
    use storage::ConstructionEventKind as Kind;
    let config = config();
    let plan = Plan::for_arq(config)?;
    let trace = std::rc::Rc::new(std::cell::RefCell::new(
        storage::ConstructionTrace::default(),
    ));
    let mut allocation = storage::Allocation::traced(plan.capacity_bytes(), None, trace.clone());
    let owner = SelectiveRepeat(Engine::new_reserved(
        config,
        context(EndpointRole::Initiator),
        &mut allocation,
    )?);
    let events: Vec<_> = trace.borrow().events().collect();
    assert!(!trace.borrow().overflow);
    let actual = inventory(&owner)?;
    assert_eq!(events.len(), 3 * actual.len());
    for (index, (pointer, capacity)) in actual.into_iter().enumerate() {
        let matching: Vec<_> = events
            .iter()
            .filter(|event| event.reservation == index + 1)
            .collect();
        assert_eq!(matching.len(), 3);
        assert_eq!(matching[0].kind, Kind::Reserved);
        assert_eq!(matching[1].kind, Kind::Owned);
        assert_eq!(matching[2].kind, Kind::Published);
        for event in matching {
            assert_eq!(event.pointer, pointer);
            assert_eq!(event.capacity, capacity);
        }
    }
    assert_eq!(
        allocation.usage(),
        owner.storage_usage().ok_or("missing usage")?
    );
    // The trace describes constructor custody only, not an allocator hook or
    // the later Engine destructor. Its transfer evidence remains immutable.
    drop(owner);
    assert_eq!(trace.borrow().events().collect::<Vec<_>>(), events);
    Ok(())
}

#[test]
fn full_window_reuse_keeps_every_pointer_and_capacity_above_64_cycles() -> Result {
    let mut left = make(config(), EndpointRole::Initiator, true)?;
    let mut right = make(config(), EndpointRole::Responder, true)?;
    let left_inventory = inventory(&left)?;
    let right_inventory = inventory(&right)?;
    let usage = left.storage_usage();
    let mut packet = [0; 128];
    let mut output = [0; 16];
    for round in 0..130_u64 {
        let now = ms(round * 2);
        for slot in 0..4 {
            let payload = [round as u8, slot];
            let payload = if slot == 0 {
                &[][..]
            } else {
                payload.as_slice()
            };
            assert_eq!(left.submit(payload, now)?, round * 4 + u64::from(slot));
        }
        for slot in 0..4 {
            let size = left
                .poll_source(now, &mut packet)?
                .ok_or(RecoveryError::MalformedPacket)?;
            right.receive(&packet[..size], now)?;
            let item = right
                .poll_delivered(&mut output)?
                .ok_or(RecoveryError::MalformedPacket)?;
            assert_eq!(item, (round * 4 + slot, if slot == 0 { 0 } else { 2 }));
        }
        let size = right
            .poll_feedback(now, &mut packet)?
            .ok_or(RecoveryError::MalformedPacket)?;
        left.receive(&packet[..size], now)?;
        assert!(left.drained());
        assert!(right.drained());
        assert_eq!(left.storage_usage(), usage);
        assert_eq!(inventory(&left)?, left_inventory);
        assert_eq!(inventory(&right)?, right_inventory);
    }
    assert_eq!(left.statistics().submitted, 520);
    Ok(())
}

fn complete_receive_windows(role: EndpointRole) -> Result {
    let remote = if role == EndpointRole::Initiator {
        EndpointRole::Responder
    } else {
        EndpointRole::Initiator
    };
    let mut sender = make(config(), role, true)?;
    let mut receiver = make(config(), remote, true)?;
    let sender_inventory = inventory(&sender)?;
    let receiver_inventory = inventory(&receiver)?;
    let usage = [sender.storage_usage(), receiver.storage_usage()];
    let mut packet = [0; 128];
    let mut output = [0; 16];
    for round in 0..130_u64 {
        let now = ms(round * 2);
        let payloads = [
            Vec::new(),
            vec![round as u8, 1],
            vec![round as u8, 2],
            vec![round as u8, 3],
        ];
        for (index, payload) in payloads.iter().enumerate() {
            assert_eq!(sender.submit(payload, now)?, round * 4 + index as u64);
        }
        let mut packets = Vec::new();
        for _ in 0..4 {
            let bytes = sender
                .poll_source(now, &mut packet)?
                .ok_or("missing source")?;
            packets.push(packet[..bytes].to_vec());
        }
        for index in [3, 1, 0, 2] {
            receiver.receive(&packets[index], now)?;
        }
        assert_eq!(receiver.retained().receive_records, 4);
        assert_eq!(receiver.retained().receive_bytes, 6);
        assert_eq!(receiver.0.receive_prefix, round * 4 + 4);
        assert_eq!(receiver.0.deliver_next, round * 4);
        let mut received_ids: Vec<_> = receiver.0.received.keys().copied().collect();
        received_ids.sort();
        assert_eq!(
            received_ids,
            (round * 4..round * 4 + 4).map(SourceId).collect::<Vec<_>>()
        );
        assert_eq!(inventory(&receiver)?, receiver_inventory);
        let bytes = receiver
            .poll_feedback(now, &mut packet)?
            .ok_or("missing ACK")?;
        sender.receive(&packet[..bytes], now)?;
        assert!(sender.drained());
        for source in round * 4..round * 4 + 4 {
            assert!(sender.source_confirmed(SourceId(source))?);
        }
        // Receiving ACKs is not application delivery: all acknowledged bytes,
        // including the zero-length occupied slot, remain at the receiver.
        assert!(!receiver.drained());
        assert_eq!(receiver.retained().receive_records, 4);
        assert_eq!(receiver.retained().receive_bytes, 6);
        for (index, payload) in payloads.iter().enumerate() {
            assert_eq!(
                receiver.poll_delivered(&mut output)?,
                Some((round * 4 + index as u64, payload.len()))
            );
            assert_eq!(&output[..payload.len()], payload);
        }
        assert_eq!(receiver.poll_delivered(&mut output)?, None);
        assert!(receiver.drained());
        assert_eq!([sender.storage_usage(), receiver.storage_usage()], usage);
        assert_eq!(inventory(&sender)?, sender_inventory);
        assert_eq!(inventory(&receiver)?, receiver_inventory);
    }
    assert_eq!(sender.statistics().submitted, 520);
    assert_eq!(receiver.statistics().delivered, 520);
    Ok(())
}

#[test]
fn complete_receive_pool_recycles_130_reordered_windows_in_each_direction() -> Result {
    complete_receive_windows(EndpointRole::Initiator)?;
    complete_receive_windows(EndpointRole::Responder)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateSnapshot {
    sent: Vec<FlightState>,
    received: Vec<(SourceId, Vec<u8>)>,
    next_source: u64,
    receive_prefix: u64,
    deliver_next: u64,
    send_bytes: usize,
    receive_bytes: usize,
    ack_at: Option<Duration>,
    prefer_data: bool,
    last_now: Duration,
    failure: Option<RecoveryError>,
    statistics: Statistics,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FlightState {
    source: SourceId,
    payload: Vec<u8>,
    attempts: u32,
    retry_at: Option<Duration>,
    rto: Duration,
}

fn state_snapshot(owner: &SelectiveRepeat) -> StateSnapshot {
    let engine = &owner.0;
    let mut sent: Vec<_> = engine
        .sent
        .iter()
        .map(|(source, flight)| FlightState {
            source: *source,
            payload: flight.payload.clone(),
            attempts: flight.attempts,
            retry_at: flight.retry_at,
            rto: flight.rto,
        })
        .collect();
    sent.sort_by_key(|entry| entry.source);
    let mut received: Vec<_> = match &engine.received {
        Received::Legacy(values) => values
            .iter()
            .map(|(source, payload)| (*source, payload.clone()))
            .collect(),
        Received::Reserved(slots) | Received::Indexed(slots) => slots
            .iter()
            .filter_map(|slot| slot.source.map(|source| (source, slot.payload.clone())))
            .collect(),
    };
    received.sort_by_key(|entry| entry.0);
    StateSnapshot {
        sent,
        received,
        next_source: engine.next_source,
        receive_prefix: engine.receive_prefix,
        deliver_next: engine.deliver_next,
        send_bytes: engine.send_bytes,
        receive_bytes: engine.receive_bytes,
        ack_at: engine.ack_at,
        prefer_data: engine.prefer_data,
        last_now: engine.last_now,
        failure: engine.failure,
        statistics: engine.statistics,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct BytePressureTrace {
    rejected: RecoveryError,
    after_refusal: StateSnapshot,
    after_retry: StateSnapshot,
    ack: Vec<u8>,
    delivered: Vec<(u64, Vec<u8>)>,
    statistics: [Statistics; 2],
}

fn receive_byte_pressure(reserved: bool) -> Result<BytePressureTrace> {
    let config = ArqConfig {
        receive_bytes: 16,
        ..config()
    };
    let mut sender = make(config, EndpointRole::Initiator, reserved)?;
    let mut receiver = make(config, EndpointRole::Responder, reserved)?;
    let original_inventory = reserved.then(|| inventory(&receiver)).transpose()?;
    let usage = receiver.storage_usage();
    let payloads = [vec![0x11; 8], vec![0x22; 8], vec![0x33]];
    let mut packets = Vec::new();
    let mut packet = [0; 128];
    for payload in &payloads {
        sender.submit(payload, ms(0))?;
    }
    for _ in &payloads {
        let size = sender
            .poll_source(ms(0), &mut packet)?
            .ok_or("missing source")?;
        packets.push(packet[..size].to_vec());
    }
    receiver.receive(&packets[0], ms(0))?;
    receiver.receive(&packets[1], ms(0))?;
    assert_eq!(receiver.retained().receive_bytes, 16);
    assert_eq!(receiver.retained().receive_records, 2);
    assert!(receiver.retained().receive_records < config.receive_records);
    assert!(2 - receiver.0.deliver_next < config.receive_records as u64);
    assert!(payloads[2].len() <= config.max_source_bytes);
    let before = state_snapshot(&receiver);
    let rejected = receiver
        .receive(&packets[2], ms(5))
        .err()
        .ok_or("receive byte pressure missing")?;
    assert_eq!(rejected, RecoveryError::Capacity(BufferSide::Receive));
    assert_eq!(state_snapshot(&receiver), before);
    assert_eq!(receiver.storage_usage(), usage);
    if let Some(expected) = &original_inventory {
        assert_eq!(&inventory(&receiver)?, expected);
    }
    let mut output = [0; 16];
    let mut delivered = Vec::new();
    let (source, bytes) = receiver
        .poll_delivered(&mut output)?
        .ok_or("first delivery")?;
    delivered.push((source, output[..bytes].to_vec()));
    assert_eq!(delivered[0], (0, payloads[0].clone()));
    // Rejected5ms input did not consume the receive clock or byte charge.
    receiver.receive(&packets[2], ms(1))?;
    assert_eq!(receiver.retained().receive_bytes, 9);
    let after_retry = state_snapshot(&receiver);
    let size = receiver
        .poll_feedback(ms(1), &mut packet)?
        .ok_or("missing ACK")?;
    let ack = packet[..size].to_vec();
    sender.receive(&ack, ms(1))?;
    assert!(sender.drained());
    while let Some((source, bytes)) = receiver.poll_delivered(&mut output)? {
        delivered.push((source, output[..bytes].to_vec()));
    }
    assert_eq!(
        delivered,
        payloads
            .into_iter()
            .enumerate()
            .map(|(index, payload)| (index as u64, payload))
            .collect::<Vec<_>>()
    );
    assert!(receiver.drained());
    assert_eq!(receiver.storage_usage(), usage);
    if let Some(expected) = original_inventory {
        assert_eq!(inventory(&receiver)?, expected);
    }
    Ok(BytePressureTrace {
        rejected,
        after_refusal: before,
        after_retry,
        ack,
        delivered,
        statistics: [sender.statistics(), receiver.statistics()],
    })
}

#[test]
fn receive_byte_pressure_with_free_slots_is_atomic_and_matches_legacy() -> Result {
    assert_eq!(receive_byte_pressure(false)?, receive_byte_pressure(true)?);
    Ok(())
}

fn refusal(
    owner: &mut SelectiveRepeat,
    packet: &[u8],
    now: Duration,
    expected: RecoveryError,
) -> Result<RecoveryError> {
    let before = state_snapshot(owner);
    let usage = owner.storage_usage();
    let before_inventory = usage.map(|_| inventory(owner)).transpose()?;
    let observed = owner
        .receive(packet, now)
        .err()
        .ok_or("expected receive refusal")?;
    assert_eq!(observed, expected);
    assert_eq!(state_snapshot(owner), before);
    assert_eq!(owner.storage_usage(), usage);
    if let Some(expected) = before_inventory {
        assert_eq!(inventory(owner)?, expected);
    }
    Ok(observed)
}

#[derive(Debug, Eq, PartialEq)]
struct RefusalTrace {
    errors: Vec<RecoveryError>,
    packets: Vec<Vec<u8>>,
    after_invalid_ack: StateSnapshot,
    after_valid_ack: StateSnapshot,
    final_state: [StateSnapshot; 2],
    delivered: Vec<(u64, Vec<u8>)>,
}

fn malformed_profile_and_ack_scenario(reserved: bool) -> Result<RefusalTrace> {
    let mut sender = make(config(), EndpointRole::Initiator, reserved)?;
    let mut receiver = make(config(), EndpointRole::Responder, reserved)?;
    let mut errors = Vec::new();
    let mut packets = Vec::new();
    for payload in [b"one", b"two", b"end"] {
        sender.submit(payload, ms(0))?;
    }
    let mut packet = [0; 128];
    // The third source is genuinely admitted but has not transmitted; the
    // mixed ACK below also names a real already-transmitted source.
    for _ in 0..2 {
        let size = sender
            .poll_source(ms(0), &mut packet)?
            .ok_or("missing source")?;
        packets.push(packet[..size].to_vec());
    }
    let original = packets[0].clone();
    for length in 0..original.len() {
        errors.push(refusal(
            &mut receiver,
            &original[..length],
            ms(5),
            RecoveryError::MalformedPacket,
        )?);
    }
    let variants = [
        (0, 0, RecoveryError::MalformedPacket),
        (4, 2, RecoveryError::MalformedPacket),
        (5, Profile::CarrierOnly.code(), RecoveryError::WrongProfile),
        (5, 0, RecoveryError::WrongProfile),
        (5, 0xff, RecoveryError::WrongProfile),
        (6, 0xff, RecoveryError::MalformedPacket),
        (
            7,
            EndpointRole::Responder.code(),
            RecoveryError::WrongContext,
        ),
        (7, 2, RecoveryError::WrongContext),
        (8, original[8] ^ 1, RecoveryError::WrongContext),
        (24, original[24] ^ 1, RecoveryError::WrongContext),
    ];
    for (offset, value, error) in variants {
        let mut changed = original.clone();
        changed[offset] = value;
        errors.push(refusal(&mut receiver, &changed, ms(5), error)?);
    }
    let mut trailing = original.clone();
    trailing.push(0);
    errors.push(refusal(
        &mut receiver,
        &trailing,
        ms(5),
        RecoveryError::MalformedPacket,
    )?);
    let mut bad_length = original.clone();
    bad_length[40..44].copy_from_slice(&4_u32.to_be_bytes());
    errors.push(refusal(
        &mut receiver,
        &bad_length,
        ms(5),
        RecoveryError::MalformedPacket,
    )?);
    bad_length[40..44].copy_from_slice(&17_u32.to_be_bytes());
    errors.push(refusal(
        &mut receiver,
        &bad_length,
        ms(5),
        RecoveryError::SourceTooLarge,
    )?);
    let mut exhausted = original.clone();
    exhausted[32..40].copy_from_slice(&u64::MAX.to_be_bytes());
    errors.push(refusal(
        &mut receiver,
        &exhausted,
        ms(5),
        RecoveryError::CounterExhausted,
    )?);
    // These canonical packets remain admissible at0ms: none of the refused
    // 5ms inputs consumed the receiver clock, slots, ACK state or statistics.
    receiver.receive(&original, ms(0))?;
    let size = receiver
        .poll_feedback(ms(0), &mut packet)?
        .ok_or("missing real ACK")?;
    let ack = packet[..size].to_vec();
    assert_eq!(
        inspect_packet(&ack, context(EndpointRole::Initiator), 16)?,
        PacketView::Ack {
            prefix: 1,
            bitmap: 0
        }
    );
    for length in 0..ack.len() {
        errors.push(refusal(
            &mut sender,
            &ack[..length],
            ms(5),
            RecoveryError::MalformedPacket,
        )?);
    }
    let mut trailing_ack = ack.clone();
    trailing_ack.push(0);
    errors.push(refusal(
        &mut sender,
        &trailing_ack,
        ms(5),
        RecoveryError::MalformedPacket,
    )?);
    let mut reflected = ack.clone();
    reflected[7] = EndpointRole::Initiator.code();
    errors.push(refusal(
        &mut sender,
        &reflected,
        ms(5),
        RecoveryError::WrongContext,
    )?);
    let mut wrong_profile = ack.clone();
    wrong_profile[5] = Profile::CarrierOnly.code();
    errors.push(refusal(
        &mut sender,
        &wrong_profile,
        ms(5),
        RecoveryError::WrongProfile,
    )?);
    let mut malformed_ack = ack.clone();
    malformed_ack[40..48].copy_from_slice(&1_u64.to_be_bytes());
    errors.push(refusal(
        &mut sender,
        &malformed_ack,
        ms(5),
        RecoveryError::MalformedPacket,
    )?);
    let mut unallocated = ack.clone();
    unallocated[32..40].copy_from_slice(&4_u64.to_be_bytes());
    errors.push(refusal(
        &mut sender,
        &unallocated,
        ms(5),
        RecoveryError::UnsentAcknowledgement,
    )?);
    let mut selective_unallocated = ack.clone();
    selective_unallocated[40..48].copy_from_slice(&4_u64.to_be_bytes());
    errors.push(refusal(
        &mut sender,
        &selective_unallocated,
        ms(5),
        RecoveryError::UnsentAcknowledgement,
    )?);
    let mut mixed = ack.clone();
    mixed[40..48].copy_from_slice(&2_u64.to_be_bytes());
    errors.push(refusal(
        &mut sender,
        &mixed,
        ms(5),
        RecoveryError::UnsentAcknowledgement,
    )?);
    let after_invalid_ack = state_snapshot(&sender);
    assert_eq!(sender.retained().send_records, 3);
    assert!(!sender.source_confirmed(SourceId(0))?);
    assert!(!sender.source_confirmed(SourceId(2))?);
    sender.receive(&ack, ms(1))?;
    let after_valid_ack = state_snapshot(&sender);
    assert!(sender.source_confirmed(SourceId(0))?);
    assert_eq!(sender.retained().send_records, 2);
    packets.push(ack);
    let size = sender
        .poll_source(ms(1), &mut packet)?
        .ok_or("missing untransmitted source")?;
    packets.push(packet[..size].to_vec());
    assert!(matches!(
        inspect_packet(&packet[..size], context(EndpointRole::Responder), 16)?,
        PacketView::Data {
            source: SourceId(2),
            ..
        }
    ));
    receiver.receive(&packets[1], ms(1))?;
    receiver.receive(&packet[..size], ms(1))?;
    let size = receiver
        .poll_feedback(ms(1), &mut packet)?
        .ok_or("missing complete ACK")?;
    packets.push(packet[..size].to_vec());
    sender.receive(&packet[..size], ms(1))?;
    assert!(sender.drained());
    let mut output = [0; 16];
    let mut delivered = Vec::new();
    while let Some((source, size)) = receiver.poll_delivered(&mut output)? {
        delivered.push((source, output[..size].to_vec()));
    }
    assert_eq!(
        delivered,
        vec![
            (0, b"one".to_vec()),
            (1, b"two".to_vec()),
            (2, b"end".to_vec())
        ]
    );
    assert!(receiver.drained());
    Ok(RefusalTrace {
        errors,
        packets,
        after_invalid_ack,
        after_valid_ack,
        final_state: [state_snapshot(&sender), state_snapshot(&receiver)],
        delivered,
    })
}

#[test]
fn malformed_context_profile_and_mixed_ack_refusals_match_legacy_atomically() -> Result {
    assert_eq!(
        malformed_profile_and_ack_scenario(false)?,
        malformed_profile_and_ack_scenario(true)?
    );
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct Trace {
    packets: Vec<Vec<u8>>,
    errors: Vec<RecoveryError>,
    delivered: Vec<(u64, Vec<u8>)>,
    statistics: [Statistics; 2],
    retained: [Retained; 2],
    deadlines: [Option<Duration>; 2],
}
fn scenario(reserved: bool) -> Result<Trace> {
    let mut left = make(config(), EndpointRole::Initiator, reserved)?;
    let mut right = make(config(), EndpointRole::Responder, reserved)?;
    let mut trace = Trace {
        packets: Vec::new(),
        errors: Vec::new(),
        delivered: Vec::new(),
        statistics: [Statistics::default(); 2],
        retained: [Retained::default(); 2],
        deadlines: [None; 2],
    };
    let mut packet = [0; 128];
    let mut original = Vec::new();
    for source in 0..4_u8 {
        let payload = [source; 8];
        left.submit(if source == 0 { &[] } else { &payload }, ms(0))?;
    }
    for _ in 0..4 {
        let size = left
            .poll_source(ms(0), &mut packet)?
            .ok_or(RecoveryError::MalformedPacket)?;
        original.push(packet[..size].to_vec());
        trace.packets.push(packet[..size].to_vec());
    }
    for source in [3, 1, 1] {
        right.receive(&original[source], ms(0))?;
    }
    let mut conflict = original[1].clone();
    conflict[DATA_HEADER_BYTES] ^= 1;
    trace.errors.push(
        right
            .receive(&conflict, ms(0))
            .err()
            .ok_or("retained conflict")?,
    );
    let mut reflection = original[1].clone();
    reflection[7] = EndpointRole::Responder.code();
    trace.errors.push(
        right
            .receive(&reflection, ms(0))
            .err()
            .ok_or("reflection")?,
    );
    let size = right
        .poll_feedback(ms(0), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    trace.packets.push(packet[..size].to_vec());
    left.receive(&packet[..size], ms(0))?;
    trace.errors.push(
        left.submit(b"hole", ms(0))
            .err()
            .ok_or("send span survives selective holes")?,
    );
    assert_eq!(left.poll_source(ms(5), &mut packet)?, None);
    trace.errors.push(
        left.poll_source(ms(4), &mut packet)
            .err()
            .ok_or("clock regression")?,
    );
    let mut retries = Vec::new();
    for _ in 0..2 {
        let size = left
            .poll_source(ms(10), &mut packet)?
            .ok_or(RecoveryError::MalformedPacket)?;
        retries.push(packet[..size].to_vec());
        trace.packets.push(packet[..size].to_vec());
    }
    assert_eq!(u64::from_be_bytes(retries[0][32..40].try_into()?), 0);
    assert_eq!(u64::from_be_bytes(retries[1][32..40].try_into()?), 2);
    for retry in retries.iter().rev() {
        right.receive(retry, ms(10))?;
    }
    let size = right
        .poll_feedback(ms(10), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    trace.packets.push(packet[..size].to_vec());
    left.receive(&packet[..size], ms(10))?;
    assert_eq!(left.submit(b"new", ms(10))?, 4);
    let size = left
        .poll_source(ms(10), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    let new = packet[..size].to_vec();
    trace.errors.push(
        right
            .receive(&new, ms(10))
            .err()
            .ok_or("undelivered receive window")?,
    );
    let mut output = [0; 16];
    while let Some((source, size)) = right.poll_delivered(&mut output)? {
        trace.delivered.push((source, output[..size].to_vec()));
    }
    right.receive(&new, ms(10))?;
    right.receive(&original[1], ms(10))?;
    let size = right
        .poll_feedback(ms(10), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    trace.packets.push(packet[..size].to_vec());
    left.receive(&packet[..size], ms(10))?;
    left.submit(b"end", ms(10))?;
    packet[32..40].copy_from_slice(&6_u64.to_be_bytes());
    trace.errors.push(
        left.receive(&packet[..size], ms(10))
            .err()
            .ok_or("untransmitted ACK")?,
    );
    let mut short = [0xa5; 1];
    trace.errors.push(
        left.poll_source(ms(10), &mut short)
            .err()
            .ok_or("short output")?,
    );
    assert_eq!(short, [0xa5]);
    trace.statistics = [left.statistics(), right.statistics()];
    trace.retained = [left.retained(), right.retained()];
    trace.deadlines = [left.deadline(), right.deadline()];
    Ok(trace)
}

#[test]
fn loss_selective_holes_reorder_duplicates_pressure_and_timers_match_legacy() -> Result {
    assert_eq!(scenario(false)?, scenario(true)?);
    Ok(())
}

#[test]
fn due_retry_uses_deadline_before_source_or_physical_slot_order() -> Result {
    let mut owner = make(config(), EndpointRole::Initiator, true)?;
    let mut packet = [0; 128];
    owner.submit(b"first", ms(0))?;
    owner.submit(b"second", ms(0))?;
    owner.poll_source(ms(0), &mut packet)?;
    owner.poll_source(ms(0), &mut packet)?;
    owner
        .0
        .sent
        .get_mut(&SourceId(0))
        .ok_or(RecoveryError::MalformedPacket)?
        .retry_at = Some(ms(20));
    owner
        .0
        .sent
        .get_mut(&SourceId(1))
        .ok_or(RecoveryError::MalformedPacket)?
        .retry_at = Some(ms(10));
    let size = owner
        .poll_source(ms(20), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    assert!(matches!(
        inspect_packet(&packet[..size], context(EndpointRole::Responder), 16)?,
        PacketView::Data {
            source: SourceId(1),
            ..
        }
    ));
    Ok(())
}

#[test]
fn byte_pressure_and_invalid_ack_leave_actual_slots_unchanged() -> Result {
    let config = ArqConfig {
        send_bytes: 16,
        receive_bytes: 16,
        ..config()
    };
    let mut owner = make(config, EndpointRole::Initiator, true)?;
    owner.submit(&[1; 16], ms(0))?;
    let before = inventory(&owner)?;
    let stats = owner.statistics();
    assert_eq!(
        owner.submit(&[2], ms(0)),
        Err(RecoveryError::Capacity(BufferSide::Send))
    );
    assert_eq!(owner.next_source_id()?, SourceId(1));
    assert_eq!(owner.statistics(), stats);
    let mut ack = [0; ACK_PACKET_BYTES];
    write_common(
        &mut ack,
        context(EndpointRole::Responder),
        Profile::Selective,
        2,
    );
    ack[32..40].copy_from_slice(&1_u64.to_be_bytes());
    assert_eq!(
        owner.receive(&ack, ms(0)),
        Err(RecoveryError::UnsentAcknowledgement)
    );
    assert_eq!(owner.retained().send_bytes, 16);
    assert_eq!(inventory(&owner)?, before);
    Ok(())
}

#[test]
fn high_nonwrapping_source_ids_and_empty_delivery_use_full_identity() -> Result {
    let mut left = make(config(), EndpointRole::Initiator, true)?;
    let mut right = make(config(), EndpointRole::Responder, true)?;
    left.0.next_source = u64::MAX - 2;
    right.0.receive_prefix = u64::MAX - 2;
    right.0.deliver_next = u64::MAX - 2;
    let mut packet = [0; 128];
    for source in u64::MAX - 2..u64::MAX {
        assert_eq!(left.submit(&[], ms(0))?, source);
        let size = left
            .poll_source(ms(0), &mut packet)?
            .ok_or(RecoveryError::MalformedPacket)?;
        right.receive(&packet[..size], ms(0))?;
        assert_eq!(right.poll_delivered(&mut [])?, Some((source, 0)));
    }
    assert_eq!(
        left.submit(&[], ms(0)),
        Err(RecoveryError::CounterExhausted)
    );
    assert_eq!(left.next_source_id(), Err(RecoveryError::CounterExhausted));
    let size = right
        .poll_feedback(ms(0), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    left.receive(&packet[..size], ms(0))?;
    assert!(left.source_confirmed(SourceId(u64::MAX - 1))?);
    assert!(!left.source_confirmed(SourceId(u64::MAX))?);
    Ok(())
}

#[test]
fn original_zero_retry_failure_and_time_overflow_precede_mutation() -> Result {
    for reserved in [false, true] {
        let config = ArqConfig {
            max_retries: 0,
            ..config()
        };
        let mut owner = make(config, EndpointRole::Initiator, reserved)?;
        owner.submit(b"x", ms(0))?;
        let mut packet = [0; 128];
        owner.poll_source(ms(0), &mut packet)?;
        let expected = RecoveryError::RetryExhausted {
            source: SourceId(0),
        };
        assert_eq!(owner.poll_source(ms(10), &mut []), Err(expected));
        assert_eq!(owner.failure(), Some(expected));
        assert_eq!(owner.poll_source(ms(0), &mut packet), Err(expected));
        assert_eq!(owner.retained().send_records, 1);
        let mut owner = make(config, EndpointRole::Initiator, reserved)?;
        owner.submit(b"x", ms(0))?;
        let before = owner.statistics();
        let mut packet = [0xa5; 128];
        assert_eq!(
            owner.poll_source(Duration::MAX, &mut packet),
            Err(RecoveryError::TimeOverflow)
        );
        assert_eq!(packet, [0xa5; 128]);
        assert_eq!(owner.statistics(), before);
        assert_eq!(owner.deadline(), Some(ms(0)));
    }
    Ok(())
}
