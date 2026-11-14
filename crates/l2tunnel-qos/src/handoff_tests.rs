use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn scheduler() -> Result<Scheduler, Box<dyn std::error::Error>> {
    let config = SchedulerConfig {
        base_quantum_bytes: 64,
        max_classes: 2,
        max_flows: 4,
        max_packet_bytes: 512,
        max_queued_bytes: 8192,
        max_queued_packets: 32,
        per_flow_bytes: 4096,
        per_flow_packets: 16,
    };
    let mut scheduler = Scheduler::new(
        config,
        &[ClassConfig {
            id: ClassId::new(7),
            weight: 1,
        }],
    )?;
    for (id, weight) in [(1, 1), (2, 2), (3, 3)] {
        scheduler.register_flow(FlowConfig {
            id: FlowId::new(id),
            class: ClassId::new(7),
            weight,
        })?;
    }
    Ok(scheduler)
}

#[test]
fn selected_refusal_keeps_real_payload_and_deficit_until_one_successful_service() -> TestResult {
    let mut scheduler = scheduler()?;
    scheduler.enqueue(FlowId::new(1), vec![7; 100])?;
    scheduler.enqueue(FlowId::new(1), vec![8; 100])?;
    let head = scheduler.peek_eligible(|_, _| true)?.ok_or("head")?;
    let pointer = scheduler.flows[&head.flow]
        .packets
        .front()
        .ok_or("packet")?
        .as_ptr();
    let deficit = scheduler.flows[&head.flow].deficit;
    let active = scheduler.active.clone();
    for _ in 0..3 {
        assert_eq!(
            scheduler.offer_selected(|actual, bytes| {
                assert_eq!(actual, head);
                assert_eq!(bytes, &[7; 100]);
                assert_eq!(bytes.as_ptr(), pointer);
                Ok::<Option<()>, &str>(None)
            }),
            Ok(None)
        );
        assert_eq!(
            scheduler.offer_selected(|_, _| Err::<Option<()>, _>("full")),
            Err(OfferError::Downstream("full"))
        );
        assert_eq!(scheduler.selected, Some(head));
        assert_eq!(scheduler.flows[&head.flow].deficit, deficit);
        assert_eq!(scheduler.active, active);
        assert_eq!(
            (scheduler.queued_bytes(), scheduler.queued_packets()),
            (200, 2)
        );
    }
    let (packet, token) = scheduler
        .offer_selected(|_, _| Ok::<_, &str>(Some(31)))
        .map_err(|_| "offer")?
        .ok_or("packet")?;
    assert_eq!(packet.payload.as_ptr(), pointer);
    assert_eq!(
        (packet.flow, packet.class, token),
        (head.flow, head.class, 31)
    );
    assert_eq!(scheduler.flows[&head.flow].deficit, deficit - 100);
    assert_eq!(
        (scheduler.queued_bytes(), scheduler.queued_packets()),
        (100, 1)
    );
    assert_eq!(scheduler.selected, None);
    assert_eq!(
        scheduler.offer_selected(|_, _| -> Result<Option<()>, &str> { Err("selection required") }),
        Ok(None)
    );
    assert_eq!(scheduler.dequeue()?.ok_or("second")?.payload, [8; 100]);
    assert_eq!(scheduler.active_flows(), 0);
    Ok(())
}

#[test]
fn actual_blocked_heads_and_weighted_order_match_legacy_after_refused_offers() -> TestResult {
    let mut offered = scheduler()?;
    let mut legacy = scheduler()?;
    for scheduler in [&mut offered, &mut legacy] {
        for round in 0..4 {
            for (id, length) in [(1, 85), (2, 130), (3, 40)] {
                scheduler.enqueue(FlowId::new(id), vec![id as u8 * 10 + round; length])?;
            }
        }
    }
    for step in 0..12 {
        let expected = legacy
            .dequeue_eligible(|id, _| step != 0 || id != FlowId::new(1))?
            .ok_or("packet")?;
        let head = offered
            .peek_eligible(|id, _| step != 0 || id != FlowId::new(1))?
            .ok_or("head")?;
        assert_eq!(head.flow, expected.flow);
        let deficit = offered.flows[&head.flow].deficit;
        assert_eq!(
            offered.offer_selected(|_, _| Ok::<Option<()>, &str>(None)),
            Ok(None)
        );
        assert_eq!(
            offered.offer_selected(|_, _| Err::<Option<()>, _>("busy")),
            Err(OfferError::Downstream("busy"))
        );
        assert_eq!(offered.flows[&head.flow].deficit, deficit);
        let (actual, ()) = offered
            .offer_selected(|_, _| Ok::<_, &str>(Some(())))
            .map_err(|_| "offer")?
            .ok_or("packet")?;
        assert_eq!(actual, expected);
        assert_eq!(
            (offered.queued_bytes(), offered.queued_packets()),
            (legacy.queued_bytes(), legacy.queued_packets())
        );
    }
    assert_eq!(offered.dequeue()?, None);
    assert_eq!(legacy.dequeue()?, None);
    Ok(())
}

#[test]
fn selected_invariant_and_arithmetic_failures_precede_downstream_admission() -> TestResult {
    let mut scheduler = scheduler()?;
    scheduler.enqueue(FlowId::new(1), vec![3; 100])?;
    let head = scheduler.peek_eligible(|_, _| true)?.ok_or("head")?;
    let pointer = scheduler.flows[&head.flow]
        .packets
        .front()
        .ok_or("packet")?
        .as_ptr();
    scheduler.queued_bytes = 0;
    assert_eq!(
        scheduler.offer_selected(|_, _| -> Result<Option<()>, &str> { Err("arithmetic callback") }),
        Err(OfferError::Schedule(ScheduleError::Arithmetic))
    );
    assert_eq!(
        scheduler.flows[&head.flow]
            .packets
            .front()
            .ok_or("retained")?
            .as_ptr(),
        pointer
    );
    assert_eq!(scheduler.selected, Some(head));
    scheduler.queued_bytes = 100;
    scheduler.flows.get_mut(&head.flow).ok_or("flow")?.bytes = 101;
    assert_eq!(
        scheduler
            .offer_selected(|_, _| -> Result<Option<()>, &str> { Err("last-packet callback") }),
        Err(OfferError::Schedule(ScheduleError::Invariant))
    );
    scheduler.flows.get_mut(&head.flow).ok_or("flow")?.bytes = 100;
    scheduler.queued_packets = 2;
    assert_eq!(
        scheduler.offer_selected(|_, _| -> Result<Option<()>, &str> {
            Err("residual-accounting callback")
        }),
        Err(OfferError::Schedule(ScheduleError::Invariant))
    );
    scheduler.queued_packets = 1;
    scheduler.selected = Some(PacketHead {
        class: ClassId::new(8),
        ..head
    });
    assert_eq!(
        scheduler.offer_selected(|_, _| -> Result<Option<()>, &str> { Err("invariant callback") }),
        Err(OfferError::Schedule(ScheduleError::Invariant))
    );
    scheduler.selected = Some(head);
    let (packet, ()) = scheduler
        .offer_selected(|_, _| Ok::<_, &str>(Some(())))
        .map_err(|_| "offer")?
        .ok_or("packet")?;
    assert_eq!(packet.payload.as_ptr(), pointer);
    assert_eq!(
        (
            scheduler.queued_bytes(),
            scheduler.queued_packets(),
            scheduler.active_flows()
        ),
        (0, 0, 0)
    );
    Ok(())
}
