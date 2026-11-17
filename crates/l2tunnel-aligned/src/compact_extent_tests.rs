//! Actual selected Aligned source lengths through recovery and native custody.
use super::*;

fn raw_config() -> Config {
    let mut config = config(256);
    config.native_policy = NativePolicy::RawIp;
    config.receiver.body.elide_payload_length = false;
    config.receiver.body.predictive = false;
    config.receiver.body.timestamp_pair_dictionary = false;
    config.recovery.repair_symbols = 0;
    config
}

fn witness_slot() -> [UnitWitness; 1] {
    [UnitWitness {
        identity: RecordIdentity {
            channel: ChannelId(0),
            record: RecordId(0),
        },
        index: 0,
        count: 1,
    }]
}

#[test]
fn short_aligned_direct_arq_keeps_exact_extent_across_physical_retry_and_fragments() -> TestResult {
    for (native_bytes, lengths) in [(100, vec![109]), (600, vec![259, 259, 118])] {
        let config = raw_config();
        let plan = storage::Plan::for_duplex(config, config)?;
        let make = |role| {
            Endpoint::new_reserved(
                config,
                context(role),
                storage::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )
        };
        let (mut left, mut right) = (
            make(EndpointRole::Initiator)?,
            make(EndpointRole::Responder)?,
        );
        left.enable_physical_send_confirmation()?;
        left.enable_compact_wire_with_overheads(49, 61)?;
        right.enable_compact_wire_with_overheads(49, 61)?;
        let usage = left.storage_usage().ok_or("reserved storage")?;
        assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
        let mut frame = vec![0x37; native_bytes];
        frame[native_bytes - 7..].fill(0);
        let identity = left.enqueue_identified(ChannelId(0), &frame, ms(0))?;
        let retained_bytes: usize = lengths.iter().map(|length| length - 2).sum();
        assert_eq!(left.status().recovery.arq.send_bytes, retained_bytes);
        let mut original = Vec::new();
        for (index, expected) in lengths.iter().copied().enumerate() {
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: expected + 49,
            };
            let packet = emit(&mut left, 0, false, &mut budget)?.ok_or("original source")?;
            assert_eq!(packet.len(), expected);
            assert_eq!(
                budget,
                OutboundBudget {
                    packets: 0,
                    wire_bytes: 0
                }
            );
            let token = left.pending_data_output().ok_or("physical custody")?;
            assert_eq!((token.bytes, token.wire_bytes), (expected, expected + 49));
            let mut units = witness_slot();
            assert_eq!(left.outgoing_units(&packet, &mut units)?, 1);
            assert_eq!(units[0].identity, identity);
            assert_eq!(units[0].index, index);
            assert_eq!(units[0].count, lengths.len());
            let mut blocked = allowance(&left);
            let before = blocked;
            assert!(emit(&mut left, 0, false, &mut blocked)?.is_none());
            assert_eq!(blocked, before);
            assert_eq!(left.pending_data_output(), Some(token));
            left.confirm_output(ms(0), token)?;
            if index != 0 {
                right.receive_authenticated(&packet, ms(1))?;
            }
            original.push(packet);
        }
        assert!(deliveries(&mut right, 1)?.is_empty());
        for (index, expected) in original.iter().enumerate() {
            let mut budget = allowance(&left);
            let packet = emit(&mut left, 100, false, &mut budget)?.ok_or("actual retry")?;
            assert_eq!(&packet, expected);
            let mut units = witness_slot();
            assert_eq!(left.outgoing_units(&packet, &mut units)?, 1);
            assert_eq!(units[0].identity, identity);
            assert_eq!(units[0].index, index);
            let token = left.pending_data_output().ok_or("retry custody")?;
            left.confirm_output(ms(100), token)?;
            right.receive_authenticated(&packet, ms(100))?;
        }
        assert_eq!(deliveries(&mut right, 100)?, [(0, frame)]);
        let mut budget = allowance(&right);
        let before = budget.wire_bytes;
        let feedback = emit(&mut right, 101, true, &mut budget)?.ok_or("actual feedback")?;
        assert_eq!(before - budget.wire_bytes, feedback.len() + 61);
        left.receive_authenticated(&feedback, ms(101))?;
        assert!(left.drained() && right.drained());
        assert_eq!(left.status().recovery.arq.send_bytes, 0);
        assert_eq!(left.storage_usage(), Some(usage));
    }
    Ok(())
}

#[test]
fn short_aligned_endpoint_rejects_truncated_or_padded_raw_unit_before_native_delivery() -> TestResult
{
    for truncate in [true, false] {
        let (mut left, mut right) = peers(raw_config())?;
        left.enable_compact_wire(61)?;
        right.enable_compact_wire(61)?;
        let mut frame = vec![0x37; 100];
        frame[93..].fill(0);
        left.enqueue_admitted_raw(ChannelId(0), &frame, ms(0))?;
        let mut packet = emissions(&mut left, 0)?.remove(0);
        if truncate {
            packet.pop();
        } else {
            packet.push(0);
        }
        assert!(matches!(
            right.receive_authenticated(&packet, ms(1)),
            Err(Error::Envelope(_))
        ));
        assert!(right.pending().is_none());
        assert_eq!(right.status().receiver.retained_records, 0);
    }
    Ok(())
}
