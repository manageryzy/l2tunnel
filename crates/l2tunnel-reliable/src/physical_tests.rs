use super::*;

pub(super) fn owner(
    config: ReliableConfig,
    role: EndpointRole,
    reserved: bool,
) -> Result<Reliable, Box<dyn std::error::Error>> {
    if reserved {
        let plan = storage::Plan::for_duplex(config, config)?;
        Ok(Reliable::new_duplex_reserved(
            config,
            config,
            context(role),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?)
    } else {
        Ok(Reliable::new(config, context(role))?)
    }
}
fn allowance() -> OutboundBudget {
    OutboundBudget {
        packets: 8,
        wire_bytes: 1_000_000,
    }
}

#[test]
fn partial_fec_and_held_output_do_not_start_rto_or_recharge_before_whole_send() -> TestResult {
    for reserved in [false, true] {
        let mut sender = owner(config(), EndpointRole::Initiator, reserved)?;
        sender.enable_physical_send_confirmation()?;
        let usage = sender.storage_usage();
        sender.submit(b"partial actual FEC source", time(0))?;
        let mut output = vec![0xa5; sender.max_packet_bytes()];
        let mut budget = allowance();
        assert_eq!(sender.poll_data(time(0), &mut output, &mut budget)?, None);
        assert_eq!(sender.arq.deadline(), None);
        assert_eq!(sender.storage().building_packets, 1);
        assert_eq!(sender.pending_output(), None);
        let mut blocked = OutboundBudget::default();
        assert_eq!(
            sender.poll_data(time(150), &mut output, &mut blocked)?,
            None
        );
        assert_eq!(sender.arq_statistics().retransmissions, 0);
        assert_eq!(sender.arq.deadline(), None);
        let before = budget;
        let length = sender
            .poll_data(time(150), &mut output, &mut budget)?
            .ok_or("actual systematic")?;
        let pending = sender.pending_output().ok_or("physical witness")?;
        assert_eq!(pending.kind, RecordKind::Systematic);
        assert_eq!(pending.bytes, length);
        assert_eq!(pending.wire_bytes, length + config().outer_overhead_bytes);
        assert_eq!(budget.packets, before.packets - 1);
        assert_eq!(budget.wire_bytes, before.wire_bytes - pending.wire_bytes);
        let bytes = output.clone();
        let charged = budget;
        assert_eq!(
            sender.poll_feedback(time(350), &mut output, &mut budget)?,
            None
        );
        assert_eq!(output, bytes);
        assert_eq!(budget, charged);
        assert_eq!(sender.pending_output(), Some(pending));
        assert_eq!(sender.deadline(), None);
        sender.confirm_output_at(time(400), time(350), pending)?;
        assert_eq!(sender.arq.deadline(), Some(time(450)));
        assert_eq!(
            sender.confirm_output(Duration::MAX, pending),
            Err(Error::OutputToken)
        );
        assert_eq!(sender.failure(), None);
        for _ in 0..4 {
            if sender
                .poll_data(time(400), &mut output, &mut budget)?
                .is_none()
            {
                break;
            }
            let repair = sender.pending_output().ok_or("repair custody")?;
            assert_eq!(repair.kind, RecordKind::Repair);
            sender.confirm_output(time(400), repair)?;
        }
        assert_eq!(sender.deadline(), Some(time(450)));
        assert_eq!(sender.poll_data(time(449), &mut output, &mut budget)?, None);
        assert!(
            sender
                .poll_data(time(450), &mut output, &mut budget)?
                .is_some()
        );
        assert_eq!(
            sender.pending_output().ok_or("retry custody")?.kind,
            RecordKind::Source
        );
        assert_eq!(sender.arq_statistics().retransmissions, 1);
        assert_eq!(sender.storage_usage(), usage);

        let mut legacy = owner(config(), EndpointRole::Initiator, reserved)?;
        legacy.submit(b"partial actual FEC source", time(0))?;
        assert_eq!(
            legacy.poll_data(time(0), &mut output, &mut allowance())?,
            None
        );
        assert_eq!(legacy.arq.deadline(), Some(time(100)));
        assert_eq!(legacy.pending_output(), None);
    }
    Ok(())
}

#[test]
fn acknowledged_held_retry_keeps_real_slot_until_exact_physical_confirmation() -> TestResult {
    let config = ReliableConfig {
        repair_symbols: 0,
        ..config()
    };
    let mut sender = owner(config, EndpointRole::Initiator, true)?;
    let mut receiver = owner(config, EndpointRole::Responder, true)?;
    sender.enable_physical_send_confirmation()?;
    receiver.enable_physical_send_confirmation()?;
    sender.submit(b"retained retry original", time(0))?;
    let mut output = vec![0; sender.max_packet_bytes()];
    let mut budget = allowance();
    let length = sender
        .poll_data(time(0), &mut output, &mut budget)?
        .ok_or("first direct")?;
    let original = output[..length].to_vec();
    let first = sender.pending_output().ok_or("first witness")?;
    sender.confirm_output(time(0), first)?;
    receiver.receive(&original, time(0))?;
    let mut feedback = vec![0; receiver.max_packet_bytes()];
    let feedback_length = receiver
        .poll_feedback(time(1), &mut feedback, &mut allowance())?
        .ok_or("actual peer ACK")?;
    let ack = receiver.pending_output().ok_or("feedback custody")?;
    assert_eq!(ack.kind, RecordKind::Feedback);
    receiver.confirm_output(time(1), ack)?;
    let retry_length = sender
        .poll_data(time(100), &mut output, &mut budget)?
        .ok_or("held actual retry")?;
    assert_eq!(&output[..retry_length], original);
    let retry = sender.pending_output().ok_or("retry witness")?;
    assert_ne!(retry, first);

    let mut foreign = owner(config, EndpointRole::Initiator, true)?;
    foreign.enable_physical_send_confirmation()?;
    foreign.submit(b"retained retry original", time(0))?;
    let mut foreign_output = vec![0; foreign.max_packet_bytes()];
    assert!(
        foreign
            .poll_data(time(0), &mut foreign_output, &mut allowance())?
            .is_some()
    );
    assert_eq!(
        sender.confirm_output(
            Duration::MAX,
            foreign.pending_output().ok_or("foreign witness")?
        ),
        Err(Error::OutputToken)
    );
    assert_eq!(sender.pending_output(), Some(retry));
    assert_eq!(sender.failure(), None);
    sender.receive(&feedback[..feedback_length], time(101))?;
    assert_eq!(sender.storage().arq.send_records, 1);
    assert_eq!(sender.pending_output(), Some(retry));
    assert_eq!(sender.arq.deadline(), None);
    let saved = output.clone();
    let charged = budget;
    assert_eq!(sender.poll_data(time(199), &mut output, &mut budget)?, None);
    assert_eq!(output, saved);
    assert_eq!(budget, charged);
    sender.confirm_output(time(200), retry)?;
    assert_eq!(sender.storage().arq.send_records, 0);
    assert!(sender.drained());
    assert_eq!(sender.poll_data(time(400), &mut output, &mut budget)?, None);
    assert_eq!(sender.arq_statistics().retransmissions, 1);
    assert_eq!(
        sender.confirm_output(Duration::MAX, retry),
        Err(Error::OutputToken)
    );
    assert_eq!(sender.failure(), None);
    Ok(())
}
