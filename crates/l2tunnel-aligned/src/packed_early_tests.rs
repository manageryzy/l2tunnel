//! Actual Packed recovery holes and the existing reserved native-delivery ledger.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn config(short: usize) -> packed::Config {
    let mut base = tests::config(128);
    base.native_policy = NativePolicy::RawIp;
    base.receiver.body.elide_payload_length = false;
    base.receiver.body.predictive = false;
    base.receiver.body.timestamp_pair_dictionary = false;
    base.receiver.body.independent_short_frame_bytes = short;
    let original = 56 + 8 * 4 + 128;
    base.recovery.arq.max_source_bytes = original;
    base.recovery.arq.send_bytes = 8 * original;
    base.recovery.arq.receive_bytes = 8 * original;
    base.recovery.fec.block.max_source_bytes = 44 + original;
    base.recovery.fec.block.max_packet_bytes = 56 + 3 + 2 + 44 + original;
    base.recovery.max_restored_bytes = 16 * (44 + original);
    base.max_recovery_packet_bytes = 8 + base.recovery.fec.block.max_packet_bytes;
    base.receiver.lookahead_records = 4;
    base.receiver.lookahead_bytes = 4 * 65535;
    base.receiver.lookahead_fragments = 4 * base.receiver.max_fragments_per_record;
    packed::Config {
        base,
        hold_micros: 500,
        max_units: 4,
        work_limit: 4,
    }
}
fn receiver(
    config: packed::Config,
    reserved: bool,
) -> Result<packed::Endpoint, Box<dyn std::error::Error>> {
    Ok(if reserved {
        let plan = storage::Plan::for_packed_duplex(config, config)?;
        packed::Endpoint::new_reserved(
            config,
            tests::context(EndpointRole::Responder),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?
    } else {
        packed::Endpoint::new(config, tests::context(EndpointRole::Responder))?
    })
}
fn packets(config: packed::Config) -> Result<[Vec<u8>; 2], Box<dyn std::error::Error>> {
    let mut sender = packed::Endpoint::new(config, tests::context(EndpointRole::Initiator))?;
    let first = sender.enqueue_identified(ChannelId(0), &[11; 70], ms(0))?;
    sender.flush(ms(0))?;
    let second = sender.enqueue_identified(ChannelId(0), b"tiny", ms(0))?;
    sender.flush(ms(0))?;
    let mut allowance = OutboundBudget {
        packets: 16,
        wire_bytes: 16 * (sender.max_packet_bytes() + 28),
    };
    // The first actual recovery poll collects fresh ARQ sources and starts its
    // original partial-block timer. Packed flush alone starts no FEC timer.
    let mut initial = vec![0; sender.max_packet_bytes()];
    assert!(
        sender
            .poll_data(ms(0), &mut initial, &mut allowance)?
            .is_none()
    );
    let mut selected: [Option<Vec<u8>>; 2] = [None, None];
    let mut witnesses = [receiver::UnitWitness {
        identity: first,
        index: 0,
        count: 1,
    }; 4];
    for _ in 0..16 {
        let mut bytes = vec![0; sender.max_packet_bytes()];
        let Some(length) = sender.poll_data(ms(5), &mut bytes, &mut allowance)? else {
            break;
        };
        bytes.truncate(length);
        let count = sender.outgoing_units(&bytes, &mut witnesses)?;
        for (slot, identity) in [first, second].into_iter().enumerate() {
            if witnesses[..count]
                .iter()
                .any(|unit| unit.identity == identity)
            {
                assert!(selected[slot].is_none());
                selected[slot] = Some(bytes.clone());
            }
        }
    }
    let [first, second] = selected;
    Ok([
        first.ok_or("missing first actual systematic")?,
        second.ok_or("missing later actual systematic")?,
    ])
}

#[test]
fn packed_short_crosses_actual_recovery_gap_then_contiguous_source_handoff_deduplicates()
-> TestResult {
    for reserved in [false, true] {
        for enabled in [false, true] {
            let config = config(if enabled { 32 } else { 0 });
            let [first, second] = packets(config)?;
            let mut receive = receiver(config, reserved)?;
            receive.receive_authenticated(&second, ms(6))?;
            assert_eq!(
                receive.status().receiver.source_floor,
                Some(receiver::SourceId(0))
            );
            assert_eq!(
                receive.prepare(ChannelId(0), ms(6), 8)?,
                if enabled {
                    Prepared::Ready
                } else {
                    Prepared::Idle
                }
            );
            if enabled {
                let pending = receive.pending().ok_or("actual early native")?;
                assert!(pending.early);
                assert_eq!(pending.bytes, b"tiny");
                let deadline = receive.pending_deadline();
                assert_eq!(deadline, Some(ms(5006)));
                assert_eq!(receive.prepare(ChannelId(1), ms(8), 8)?, Prepared::Ready);
                assert_eq!(receive.pending().ok_or("held early native")?.bytes, b"tiny");
                assert_eq!(receive.pending_deadline(), deadline);
                receive.commit_delivery(ms(8))?;
                assert_eq!(receive.status().receiver.early_tombstones, 1);
                assert_eq!(
                    receive.status().receiver.source_floor,
                    Some(receiver::SourceId(0))
                );
            }
            receive.receive_authenticated(&first, ms(9))?;
            assert_eq!(receive.prepare(ChannelId(0), ms(9), 8)?, Prepared::Ready);
            assert!(!receive.pending().ok_or("older frame")?.early);
            assert_eq!(receive.pending().ok_or("older bytes")?.bytes, &[11; 70]);
            receive.commit_delivery(ms(9))?;
            if !enabled {
                assert_eq!(receive.prepare(ChannelId(0), ms(9), 8)?, Prepared::Ready);
                assert_eq!(
                    receive.pending().ok_or("ordinary later frame")?.bytes,
                    b"tiny"
                );
                assert!(!receive.pending().ok_or("ordinary metadata")?.early);
                receive.commit_delivery(ms(9))?;
            }
            assert_eq!(receive.prepare(ChannelId(0), ms(10), 8)?, Prepared::Idle);
            assert_eq!(
                receive.status().receiver.source_floor,
                Some(receiver::SourceId(2))
            );
            assert_eq!(receive.status().receiver.early_tombstones, 0);
            receive.receive_authenticated(&second, ms(11))?;
            assert_eq!(receive.prepare(ChannelId(0), ms(11), 8)?, Prepared::Idle);
            assert!(receive.pending().is_none());
        }
    }
    Ok(())
}

#[test]
fn packed_early_pending_keeps_original_record_expiry_under_native_pressure() -> TestResult {
    let config = config(32);
    let [first, second] = packets(config)?;
    let mut receive = receiver(config, true)?;
    receive.receive_authenticated(&second, ms(6))?;
    assert_eq!(receive.prepare(ChannelId(0), ms(6), 1)?, Prepared::Ready);
    assert_eq!(receive.pending_deadline(), Some(ms(5006)));
    // Resolve the separate recovery debt while the actual early native output
    // remains held, so the receiver's original record cap is discriminating.
    receive.receive_authenticated(&first, ms(7))?;
    assert!(receive.pending().ok_or("held early native")?.early);
    assert_eq!(receive.prepare(ChannelId(0), ms(5005), 1)?, Prepared::Ready);
    assert_eq!(receive.pending_deadline(), Some(ms(5006)));
    assert_eq!(
        receive.commit_delivery(ms(5006)),
        Err(Error::Receiver(receiver::Error::Expired))
    );
    assert!(receive.pending().is_none());
    assert!(!receive.drained());
    Ok(())
}
