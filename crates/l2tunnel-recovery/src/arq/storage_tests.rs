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
