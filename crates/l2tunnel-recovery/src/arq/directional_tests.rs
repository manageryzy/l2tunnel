use super::*;
use crate::storage::{self, DuplexPlan, Limits};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn policies() -> (ArqConfig, ArqConfig) {
    let send = ArqConfig {
        max_source_bytes: 16,
        send_bytes: 32,
        receive_bytes: 48,
        send_records: 2,
        receive_records: 3,
        initial_rto: ms(10),
        maximum_rto: ms(80),
        ack_delay: ms(2),
        max_retries: 3,
    };
    let receive = ArqConfig {
        max_source_bytes: 64,
        send_bytes: 192,
        receive_bytes: 256,
        send_records: 3,
        receive_records: 4,
        initial_rto: ms(30),
        maximum_rto: ms(120),
        ack_delay: ms(7),
        max_retries: 2,
    };
    (send, receive)
}
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x8765,
        epoch: 19,
        role,
    }
}
fn owner(
    send: ArqConfig,
    receive: ArqConfig,
    role: EndpointRole,
    reserved: bool,
) -> Result<SelectiveRepeat> {
    Ok(if reserved {
        SelectiveRepeat::new_duplex_reserved(
            send,
            receive,
            context(role),
            Limits {
                capacity_bytes: DuplexPlan::for_arq(send, receive)?.capacity_bytes(),
            },
        )?
    } else {
        SelectiveRepeat::new_duplex(send, receive, context(role))?
    })
}

#[test]
fn asymmetric_reserved_inventory_is_actual_and_one_short_refuses() -> Result {
    let (send, receive) = policies();
    let plan = DuplexPlan::for_arq(send, receive)?;
    assert_eq!(plan.send_config(), send);
    assert_eq!(plan.receive_config(), receive);
    assert_eq!(
        plan.capacity_bytes(),
        storage::array_bytes::<SendSlot>(2)?
            + storage::array_bytes::<ReceiveSlot>(4)?
            + 2 * 16
            + 4 * 64
    );
    assert!(matches!(SelectiveRepeat::new_duplex_reserved(send, receive,
        context(EndpointRole::Initiator), Limits { capacity_bytes: plan.capacity_bytes() - 1 }),
        Err(storage::Error::Limit { required, limit })
        if required == plan.capacity_bytes() && limit + 1 == required));
    let engine = owner(send, receive, EndpointRole::Initiator, true)?;
    assert_eq!(
        engine.storage_usage(),
        Some(storage::Usage {
            limit_bytes: plan.capacity_bytes(),
            capacity_bytes: plan.capacity_bytes(),
            allocations: 8,
        })
    );
    let Sent::Reserved(sent, _) = &engine.0.sent else {
        return Err("send backing".into());
    };
    let Received::Reserved(received, _) = &engine.0.received else {
        return Err("receive backing".into());
    };
    assert_eq!(sent.capacity(), 2);
    assert!(sent.iter().all(|slot| slot.flight.payload.capacity() == 16));
    assert_eq!(received.capacity(), 4);
    assert!(received.iter().all(|slot| slot.payload.capacity() == 64));
    assert_eq!(engine.send_max_packet_bytes(), 60);
    assert_eq!(engine.receive_max_packet_bytes(), 108);
    assert_eq!(engine.max_packet_bytes(), 108);
    assert_eq!(
        storage::Plan::for_arq(send)?.capacity_bytes(),
        DuplexPlan::for_arq(send, send)?.capacity_bytes()
    );
    let mut invalid = receive;
    invalid.max_source_bytes = 0;
    let mut allocation = storage::Allocation::failing(plan.capacity_bytes(), 1);
    assert!(matches!(
        Engine::new_duplex_reserved(
            send,
            invalid,
            context(EndpointRole::Initiator),
            &mut allocation
        ),
        Err(storage::Error::Recovery(RecoveryError::InvalidConfig))
    ));
    assert_eq!(allocation.attempts(), 0);
    Ok(())
}

#[test]
fn asymmetric_loss_retries_and_feedback_follow_their_data_direction() -> Result {
    let (a, b) = policies();
    for reserved in [false, true] {
        let mut left = owner(a, b, EndpointRole::Initiator, reserved)?;
        let mut right = owner(b, a, EndpointRole::Responder, reserved)?;
        let forward = [0x1a; 16];
        let reverse = [0xb2; 64];
        assert_eq!(
            left.submit(&[0; 17], ms(0)),
            Err(RecoveryError::SourceTooLarge)
        );
        assert_eq!(left.submit(&forward, ms(0))?, 0);
        assert_eq!(right.submit(&reverse, ms(0))?, 0);
        let mut packet = [0; 108];
        assert_eq!(left.poll_source(ms(0), &mut packet)?, Some(60)); // lost
        let length = right.poll_source(ms(0), &mut packet)?.ok_or("reverse")?;
        left.receive(&packet[..length], ms(0))?;
        assert_eq!(left.poll_feedback(ms(6), &mut packet)?, None);
        let length = left
            .poll_feedback(ms(7), &mut packet)?
            .ok_or("reverse receipt")?;
        right.receive(&packet[..length], ms(7))?;
        assert_eq!(right.retained().send_records, 0);
        assert_eq!(left.poll_source(ms(9), &mut packet)?, None);
        let length = left.poll_source(ms(10), &mut packet)?.ok_or("retry")?;
        right.receive(&packet[..length], ms(10))?;
        assert_eq!(right.poll_feedback(ms(11), &mut packet)?, None);
        let length = right
            .poll_feedback(ms(12), &mut packet)?
            .ok_or("forward receipt")?;
        left.receive(&packet[..length], ms(12))?;
        let mut payload = [0; 64];
        assert_eq!(left.poll_delivered(&mut payload)?, Some((0, 64)));
        assert_eq!(payload, reverse);
        assert_eq!(right.poll_delivered(&mut payload)?, Some((0, 16)));
        assert_eq!(&payload[..16], &forward);
        assert_eq!(left.statistics().retransmissions, 1);
        assert_eq!(right.statistics().retransmissions, 0);
        assert!(left.drained() && right.drained());
    }
    Ok(())
}

#[test]
fn receive_cap_does_not_inherit_the_larger_local_send_cap() -> Result {
    let (small, large) = policies();
    let mut left = owner(large, small, EndpointRole::Initiator, true)?;
    let mut incompatible_peer = owner(large, large, EndpointRole::Responder, false)?;
    incompatible_peer.submit(&[0x55; 32], ms(0))?;
    let mut packet = [0; 108];
    let length = incompatible_peer
        .poll_source(ms(0), &mut packet)?
        .ok_or("source")?;
    assert_eq!(
        left.receive(&packet[..length], ms(0)),
        Err(RecoveryError::SourceTooLarge)
    );
    assert_eq!(left.retained(), Retained::default());
    assert_eq!(left.statistics(), Statistics::default());
    assert_eq!(left.deadline(), None);
    Ok(())
}

#[test]
fn receive_byte_pressure_retries_exact_sources_without_acknowledging_refusal() -> Result {
    let (small, mut large) = policies();
    large.receive_bytes = large.max_source_bytes;
    for reserved in [false, true] {
        let mut local = owner(small, large, EndpointRole::Initiator, reserved)?;
        let mut peer = owner(large, small, EndpointRole::Responder, reserved)?;
        peer.submit(&[0x31; 64], ms(0))?;
        peer.submit(&[0x42; 64], ms(0))?;
        let mut packet = [0; 108];
        let n = peer.poll_source(ms(0), &mut packet)?.ok_or("first")?;
        local.receive(&packet[..n], ms(0))?;
        let n = peer.poll_source(ms(0), &mut packet)?.ok_or("second")?;
        let refused = packet[..n].to_vec();
        assert_eq!(
            local.receive(&refused, ms(0)),
            Err(RecoveryError::Capacity(BufferSide::Receive))
        );
        assert_eq!(local.retained().receive_records, 1);
        assert_eq!(local.retained().receive_bytes, 64);
        let n = local
            .poll_feedback(ms(7), &mut packet)?
            .ok_or("bounded receipt")?;
        assert_eq!(
            inspect_packet(&packet[..n], context(EndpointRole::Responder), 16)?,
            PacketView::Ack {
                prefix: 1,
                bitmap: 0
            }
        );
        peer.receive(&packet[..n], ms(7))?;
        assert_eq!(peer.retained().send_records, 1);
        assert_eq!(local.poll_delivered(&mut packet)?, Some((0, 64)));
        assert_eq!(&packet[..64], &[0x31; 64]);
        local.receive(&refused, ms(7))?;
        assert_eq!(local.poll_delivered(&mut packet)?, Some((1, 64)));
        assert_eq!(&packet[..64], &[0x42; 64]);
    }
    Ok(())
}

#[test]
fn every_asymmetric_partial_reservation_is_really_dropped() -> Result {
    use storage::ConstructionEventKind as Kind;
    let (send, receive) = policies();
    let plan = DuplexPlan::for_arq(send, receive)?;
    let reservations = 2 + send.send_records + receive.receive_records;
    for point in 1..=reservations {
        let trace = std::rc::Rc::new(std::cell::RefCell::new(
            storage::ConstructionTrace::default(),
        ));
        let mut allocation =
            storage::Allocation::traced(plan.capacity_bytes(), Some(point), trace.clone());
        assert!(matches!(
            Engine::new_duplex_reserved(
                send,
                receive,
                context(EndpointRole::Initiator),
                &mut allocation
            ),
            Err(storage::Error::Allocation)
        ));
        assert_eq!(allocation.attempts(), point);
        let events: Vec<_> = trace.borrow().events().collect();
        assert!(!trace.borrow().overflow);
        assert_eq!(events.len(), 3 * (point - 1));
        for reservation in 1..point {
            let events: Vec<_> = events
                .iter()
                .filter(|event| event.reservation == reservation)
                .collect();
            assert_eq!(
                events.iter().map(|event| event.kind).collect::<Vec<_>>(),
                [Kind::Reserved, Kind::Owned, Kind::Released]
            );
            assert!(events.iter().all(|event| event.pointer == events[0].pointer
                && event.capacity == events[0].capacity
                && event.bytes == events[0].bytes));
        }
        assert_eq!(
            owner(send, receive, EndpointRole::Initiator, true)?
                .storage_usage()
                .map(|usage| usage.allocations),
            Some(reservations)
        );
    }
    Ok(())
}

#[test]
fn equal_direction_legacy_duplex_reserved_event_traces_match() -> Result {
    let (config, _) = policies();
    let mut engines = [
        SelectiveRepeat::new(config, context(EndpointRole::Initiator))?,
        SelectiveRepeat::new_duplex(config, config, context(EndpointRole::Initiator))?,
        owner(config, config, EndpointRole::Initiator, true)?,
    ];
    for engine in &mut engines {
        engine.submit(b"first", ms(0))?;
        engine.submit(b"second", ms(0))?;
    }
    for now in [0, 0, 9, 10, 10, 30, 30, 70, 70, 150] {
        let outcomes: Vec<_> = engines
            .iter_mut()
            .map(|engine| {
                let mut bytes = [0xa5; 60];
                let result = engine.poll(ms(now), &mut bytes);
                (
                    result,
                    bytes,
                    engine.retained(),
                    engine.deadline(),
                    engine.statistics(),
                    engine.failure(),
                )
            })
            .collect();
        assert_eq!(outcomes[0], outcomes[1]);
        assert_eq!(outcomes[0], outcomes[2]);
    }
    Ok(())
}

#[test]
fn carrier_only_uses_independent_directional_source_bounds_without_receipts() -> Result {
    let (a, b) = policies();
    let mut left = CarrierOnly::new_duplex(a, b, context(EndpointRole::Initiator))?;
    let mut right = CarrierOnly::new_duplex(b, a, context(EndpointRole::Responder))?;
    left.submit(&[1; 16], ms(0))?;
    right.submit(&[2; 64], ms(0))?;
    let mut bytes = [0; 108];
    let n = left.poll(ms(0), &mut bytes)?.ok_or("forward")?;
    right.receive(&bytes[..n], ms(0))?;
    let n = right.poll(ms(0), &mut bytes)?.ok_or("reverse")?;
    left.receive(&bytes[..n], ms(0))?;
    assert_eq!(left.poll_delivered(&mut bytes)?, Some((0, 64)));
    assert_eq!(right.poll_delivered(&mut bytes)?, Some((0, 16)));
    assert!(left.drained() && right.drained());
    Ok(())
}
