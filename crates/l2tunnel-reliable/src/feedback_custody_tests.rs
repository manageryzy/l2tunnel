//! Real full-duplex feedback against a physically held source, not a second ARQ.
use super::*;

#[test]
fn independent_feedback_keeps_both_exact_physical_tokens_and_actual_requested_storage() -> TestResult
{
    for reserved in [false, true] {
        let policy = config();
        let make = |role| -> Result<Reliable, Box<dyn std::error::Error>> {
            Ok(if reserved {
                let plan = storage::Plan::for_duplex(policy, policy)?;
                Reliable::new_duplex_reserved(
                    policy,
                    policy,
                    context(role),
                    storage::Limits {
                        capacity_bytes: plan.capacity_bytes(),
                    },
                )?
            } else {
                Reliable::new(policy, context(role))?
            })
        };
        let mut a = make(EndpointRole::Initiator)?;
        let mut b = make(EndpointRole::Responder)?;
        a.enable_physical_send_confirmation()?;
        b.enable_physical_send_confirmation()?;
        let usage = a.storage_usage();
        for payload in [b"first\0\xff".as_slice(), b"next", b"tail"] {
            a.submit(payload, time(0))?;
            b.submit(payload, time(0))?;
        }
        let mut data = vec![0xa5; a.send_max_packet_bytes()];
        let mut remote = vec![0xa5; b.send_max_packet_bytes()];
        let mut data_budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1_000_000,
        };
        let length = a
            .poll_data(time(0), &mut data, &mut data_budget)?
            .ok_or("held actual systematic")?;
        let main = a.pending_output().ok_or("held data token")?;
        assert_eq!(main.kind, RecordKind::Systematic);
        let original = data[..length].to_vec();
        let charged_data = data_budget;
        let mut remote_budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1_000_000,
        };
        let remote_len = b
            .poll_data(time(0), &mut remote, &mut remote_budget)?
            .ok_or("opposite actual systematic")?;
        let foreign = b.pending_output().ok_or("opposite token")?;
        b.confirm_output_at(time(0), time(0), foreign)?;
        a.receive(&remote[..remote_len], time(0))?;

        let mut feedback = vec![0x7a; a.send_max_packet_bytes()];
        let untouched = feedback.clone();
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1_000_000,
        };
        let allowance = budget;
        assert!(
            a.poll_feedback(time(1), &mut feedback, &mut budget)?
                .is_none(),
            "unchanged legacy polling exposes the actual single-slot coupling"
        );
        assert_eq!(feedback, untouched);
        assert_eq!(budget, allowance);
        assert!(matches!(
            a.poll_feedback_independent(time(1), &mut [0; 1], &mut budget),
            Err(Error::OutputTooSmall { .. })
        ));
        assert_eq!(budget, allowance);
        assert_eq!(a.pending_output(), Some(main));
        assert_eq!(a.pending_feedback_output(), None);

        let feedback_len = a
            .poll_feedback_independent(time(1), &mut feedback, &mut budget)?
            .ok_or("independent actual feedback")?;
        let ack = a
            .pending_feedback_output()
            .ok_or("independent feedback token")?;
        assert_eq!(ack.kind, RecordKind::Feedback);
        assert_eq!(
            a.inspect_output(&feedback[..feedback_len])?,
            RecordKind::Feedback
        );
        assert_eq!(allowance.packets - budget.packets, 1);
        assert_eq!(
            allowance.wire_bytes - budget.wire_bytes,
            feedback_len + policy.outer_overhead_bytes
        );
        assert_eq!(data[..length], original);
        assert_eq!(data_budget, charged_data);
        assert_eq!(a.pending_output(), Some(main));
        assert!(!a.drained());
        assert_eq!(a.storage_usage(), usage);
        let mut retry = vec![0x55; feedback.len()];
        let retry_before = retry.clone();
        let budget_before = budget;
        assert!(
            a.poll_feedback_independent(time(2), &mut retry, &mut budget)?
                .is_none()
        );
        assert_eq!(retry, retry_before);
        assert_eq!(budget, budget_before);
        // Foreign-token refusal happens before the deliberately regressed time.
        assert_eq!(
            a.confirm_output_at(time(0), time(0), foreign),
            Err(Error::OutputToken)
        );
        assert_eq!(a.pending_output(), Some(main));
        assert_eq!(a.pending_feedback_output(), Some(ack));

        if reserved {
            // Exercise the opposite callback ordering on actual reserved backing.
            a.confirm_output_at(time(2), time(1), main)?;
            assert_eq!(a.pending_output(), Some(ack));
            assert_eq!(a.arq.deadline(), Some(time(101)));
            let mut next_data = vec![0x31; a.send_max_packet_bytes()];
            let mut next_budget = OutboundBudget {
                packets: 1,
                wire_bytes: 1_000_000,
            };
            let before_next = next_budget;
            assert!(
                a.poll_data(time(2), &mut next_data, &mut next_budget)?
                    .is_none(),
                "legacy combined data polling remains coupled to held feedback"
            );
            let next_length = a
                .poll_data_independent(time(2), &mut next_data, &mut next_budget)?
                .ok_or("next actual systematic despite independent feedback")?;
            let next = a.pending_data_output().ok_or("next main-lane token")?;
            assert_eq!(next.kind, RecordKind::Systematic);
            assert_eq!(a.pending_feedback_output(), Some(ack));
            assert_eq!(before_next.packets - next_budget.packets, 1);
            assert_eq!(
                before_next.wire_bytes - next_budget.wire_bytes,
                next_length + policy.outer_overhead_bytes
            );
            assert_eq!(data[..length], original);
            a.confirm_output_at(time(2), time(2), next)?;
            assert_eq!(a.pending_data_output(), None);
            assert_eq!(a.pending_feedback_output(), Some(ack));

            a.confirm_output_at(time(3), time(1), ack)?;
            assert_eq!(
                a.arq.deadline(),
                Some(time(101)),
                "feedback cannot rearm a source RTO"
            );
        } else {
            a.confirm_output_at(time(2), time(1), ack)?;
            assert_eq!(a.pending_feedback_output(), None);
            assert_eq!(a.pending_output(), Some(main));
            assert_eq!(
                a.confirm_output_at(time(0), time(0), ack),
                Err(Error::OutputToken)
            );
            a.confirm_output_at(time(4), time(3), main)?;
            assert_eq!(a.arq.deadline(), Some(time(103)));
        }
        assert_eq!(a.pending_output(), None);
        assert_eq!(a.pending_feedback_output(), None);
        assert!(
            !a.drained(),
            "logical source/repair debt was not acknowledged by a local send"
        );
        assert_eq!(a.storage_usage(), usage);
        assert_eq!(a.arq_statistics().retransmissions, 0);
        assert_eq!(data[..length], original);
        b.receive(&feedback[..feedback_len], time(4))?;
        assert_eq!(b.storage().arq.send_records, 2);
        b.receive(&original, time(4))?;
        let mut actual = [0; 64];
        let (id, n) = b
            .poll_delivered(&mut actual)?
            .ok_or("real original source")?;
        assert_eq!(id, 0);
        assert_eq!(&actual[..n], b"first\0\xff");
    }
    Ok(())
}

#[test]
fn only_independent_feedback_custody_prevents_otherwise_complete_receive_drain() -> TestResult {
    let (mut sender, mut receiver) = endpoints()?;
    sender.enable_physical_send_confirmation()?;
    receiver.enable_physical_send_confirmation()?;
    let input = sources();
    submit_all(&mut sender, &input)?;
    let mut bytes = vec![0; sender.send_max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 3,
        wire_bytes: 1_000_000,
    };
    for _ in 0..3 {
        let n = sender
            .poll_data(time(0), &mut bytes, &mut budget)?
            .ok_or("actual systematic")?;
        let token = sender.pending_output().ok_or("actual source token")?;
        sender.confirm_output_at(time(0), time(0), token)?;
        receiver.receive(&bytes[..n], time(0))?;
    }
    assert_eq!(deliveries(&mut receiver)?, indexed(&input));
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1_000_000,
    };
    receiver
        .poll_feedback_independent(time(1), &mut bytes, &mut budget)?
        .ok_or("final receive ACK")?;
    let token = receiver
        .pending_feedback_output()
        .ok_or("held final feedback")?;
    assert!(receiver.arq.drained());
    assert_eq!(receiver.storage().restored_packets, 0);
    assert_eq!(receiver.storage().outbound_packets, 0);
    assert!(
        !receiver.drained(),
        "the actual feedback handoff is still outstanding"
    );
    receiver.confirm_output_at(time(2), time(1), token)?;
    assert!(receiver.drained());
    Ok(())
}
