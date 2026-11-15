use super::*;

fn policy(window: usize) -> Policy {
    Policy {
        recovery: Config {
            window,
            local_window: window.min(128),
            global_every: 16,
            max_payload: 8,
            max_rows: 4,
            repair_history: 32,
            handoff_sources: window,
            job_ticks: 100_000,
            debt_ticks: 1_000_000,
            handoff_ticks: 500_000,
            memory_bytes: 64 << 20,
        },
        repair_numerator: 0,
        repair_denominator: 1,
        tail_ticks: 20,
        feedback_ticks: 10,
        feedback_packets: 1,
        memory_bytes: 64 << 20,
        source_wire: wire::SourceWire::Exact,
    }
}

fn scope() -> Scope {
    Scope {
        session: [0x37; 16],
        epoch: 7,
        stream: 11,
        direction: 0,
    }
}

fn work(units: usize) -> WorkBudget {
    WorkBudget {
        field: units,
        copies: units,
        metadata: units,
    }
}

fn step(receiver: &mut Receiver, now: Tick, budget: WorkBudget) -> Result<ReceiverStep, Error> {
    let step = receiver.step(now, budget)?;
    assert!(step.work.field <= budget.field);
    assert!(step.work.copies <= budget.copies);
    assert!(step.work.metadata <= budget.metadata);
    Ok(step)
}

fn source(receiver: &mut Receiver, id: u32, bytes: &[u8], now: Tick) -> Result<Begin, Error> {
    let mut packet = [0; wire::HEADER_BYTES + 10];
    let length = wire::encode_source_with(
        receiver.policy.recovery,
        receiver.policy.source_wire,
        scope(),
        SourceId(id),
        bytes,
        &mut packet,
    )?;
    receiver.receive_wire(&packet[..length], now)
}

fn finish_decode(receiver: &mut Receiver, now: Tick) -> Result<WorkUsed, Error> {
    let mut total = WorkUsed::default();
    for _ in 0..10_000 {
        let value = step(receiver, now, work(MAX_STEP_WORK))?;
        total.field += value.work.field;
        total.copies += value.work.copies;
        total.metadata += value.work.metadata;
        if !receiver.status().decoder.pending_job {
            return Ok(total);
        }
    }
    Err(Error::WorkLimit)
}

fn finish_feedback(receiver: &mut Receiver, now: Tick, units: usize) -> Result<Feedback, Error> {
    for _ in 0..10_000 {
        if let Some(value) = receiver.pending_feedback() {
            return Ok(value);
        }
        step(receiver, now, work(units))?;
    }
    Err(Error::WorkLimit)
}

#[test]
fn tiny_serialization_admits_ingress_and_handoff_without_losing_later_feedback() -> Result<(), Error>
{
    let mut receiver = Receiver::new(policy(8), scope(), Tick(0))?;
    source(&mut receiver, 0, &[0x81, 0, 0x42, 0], Tick(0))?;
    for _ in 0..1_000 {
        step(&mut receiver, Tick(0), work(1))?;
        if receiver.scan.is_some() {
            break;
        }
    }
    let first = receiver.scan.as_ref().ok_or(Error::Identity)?.value;
    assert_eq!((first.prefix, first.observed_end, first.deficit), (1, 1, 0));
    assert!(receiver.pending_feedback().is_none());
    assert_eq!(
        source(&mut receiver, 1, &[0x19, 0, 0xe3], Tick(3))?,
        Begin::Staged
    );
    receiver.confirm_handoff(SourceId(0), Tick(3))?;
    for _ in 0..1_000 {
        step(&mut receiver, Tick(3), work(1))?;
        if !receiver.status().decoder.pending_job {
            break;
        }
    }
    assert!(!receiver.status().decoder.pending_job);
    assert_eq!(receiver.status().decoder.decoded_prefix, 2);
    assert_eq!(receiver.status().feedback_events, 1);
    assert_eq!(receiver.status().feedback_due, Some(Tick(13)));
    assert_eq!(finish_feedback(&mut receiver, Tick(4), 1)?, first);
    let mut expected = [0; 64];
    expected[..4].copy_from_slice(b"L2RF");
    expected[4] = 1;
    expected[5] = 3;
    expected[8..24].copy_from_slice(&[0x37; 16]);
    expected[31] = 7;
    expected[35] = 11;
    expected[47] = 1;
    expected[51] = 1;
    expected[55] = 1;
    assert_eq!(receiver.pending_feedback_wire(), Some(expected.as_slice()));
    receiver.confirm_feedback(first.id, Tick(4))?;
    assert_eq!(receiver.status().feedback_due, Some(Tick(13)));
    step(
        &mut receiver,
        Tick(4),
        WorkBudget {
            metadata: 1,
            ..WorkBudget::default()
        },
    )?;
    receiver.confirm_handoff(SourceId(1), Tick(4))?;
    let next = finish_feedback(&mut receiver, Tick(4), 1)?;
    assert_eq!(next.id, FeedbackId(2));
    assert_eq!((next.prefix, next.observed_end, next.deficit), (2, 2, 0));
    Ok(())
}

#[test]
fn feedback_cost_is_constant_at_global8192_and_new_ingress_never_renews_output_expiry()
-> Result<(), Error> {
    for window in [128, 8_192] {
        let mut selected = policy(window);
        selected.recovery.job_ticks = 100;
        let mut receiver = Receiver::new(selected, scope(), Tick(0))?;
        let end = window as u32;
        source(&mut receiver, end - 1, &[0x93, 0, 0x21, 0], Tick(0))?;
        let zero = step(&mut receiver, Tick(0), WorkBudget::default())?;
        assert_eq!(zero.work, WorkUsed::default());
        assert!(receiver.scan.is_none());
        // Rank-zero original decode plus the whole 64-byte feedback fits the
        // same cap at both sizes; the previous known-column scan did not.
        let result = step(&mut receiver, Tick(0), work(128))?;
        assert!(result.work.metadata <= 100);
        assert!(result.feedback_ready);
        let frozen = receiver.pending_feedback().ok_or(Error::Identity)?;
        assert_eq!(
            (frozen.prefix, frozen.observed_end, frozen.deficit),
            (0, end, end - 1)
        );
        assert_eq!(receiver.deadline(), Some(Tick(100)));
        assert_eq!(
            source(&mut receiver, end - 2, &[0xd1, 0, 0x38], Tick(50))?,
            Begin::Staged
        );
        assert_eq!(receiver.pending_feedback(), Some(frozen));
        assert_eq!(receiver.deadline(), Some(Tick(100)));
        step(&mut receiver, Tick(99), WorkBudget::default())?;
        assert_eq!(receiver.step(Tick(100), work(1)), Err(Error::Expired));
        assert_eq!(receiver.status().terminal, Some(Error::Expired));
        assert_eq!(receiver.step(Tick(100), work(1)), Err(Error::Terminal));
    }
    Ok(())
}

#[test]
fn full8192_every16_global_repair_recovers_old_hole_and_reuses_actual_rings()
-> Result<(), Box<dyn std::error::Error>> {
    let mut selected = policy(8_192);
    selected.feedback_packets = 65_536;
    let config = selected.recovery;
    let mut encoder = Encoder::new(config, scope(), Tick(0))?;
    let mut receiver = Receiver::new(selected, scope(), Tick(0))?;
    let tx_usage = encoder.storage_usage()?;
    let rx_usage = receiver.storage_usage()?;
    let global = config.support(8_192, RepairId(16), false)?;
    let hole = (0..128_u32)
        .find(|id| crate::field::compact_coefficient(global.seed, *id) != 0)
        .ok_or(Error::Identity)?;
    for id in 0..8_192_u32 {
        let bytes = payload(id);
        assert_eq!(encoder.admit_source(&bytes, Tick(0))?, SourceId(id));
        if id != hole {
            source(&mut receiver, id, &bytes, Tick(0))?;
            finish_decode(&mut receiver, Tick(0))?;
        }
    }
    assert_eq!(
        encoder.admit_source(&payload(8_192), Tick(0)),
        Err(Error::Capacity)
    );
    assert_eq!(encoder.status().confirmed_prefix, 0);
    assert_eq!(receiver.status().decoder.decoded_prefix, hole);
    assert_eq!(receiver.status().decoder.known_sources, 8_191);
    assert_eq!(receiver.status().decoder.rank, 0);
    step(
        &mut receiver,
        Tick(10),
        WorkBudget {
            metadata: 1,
            ..WorkBudget::default()
        },
    )?;
    assert!(receiver.status().feedback_building);
    let old_receipt = receiver.scan.as_ref().ok_or(Error::Identity)?.value;
    assert_eq!(
        (
            old_receipt.prefix,
            old_receipt.observed_end,
            old_receipt.deficit
        ),
        (hole, 8_192, 1)
    );
    let mut global_send_work = 0;
    let mut global_receive_work = 0;
    for serial in 1..=16_u64 {
        assert_eq!(encoder.begin_repair(false, Tick(10))?, RepairId(serial));
        for _ in 0..10_000 {
            if encoder.pending_repair().is_some() {
                break;
            }
            let used = encoder.step(Tick(10), work(MAX_STEP_WORK))?;
            assert!(
                used.field <= MAX_STEP_WORK
                    && used.copies <= MAX_STEP_WORK
                    && used.metadata <= MAX_STEP_WORK
            );
            if serial == 16 {
                global_send_work += used.field;
            }
        }
        let repair = encoder.pending_repair().ok_or(Error::WorkLimit)?;
        assert_eq!(repair.support.end, 8_192);
        assert_eq!(repair.support.start, if serial == 16 { 0 } else { 8_064 });
        let mut packet = [0; wire::HEADER_BYTES + 10];
        let length = wire::encode_repair_with(config, selected.source_wire, repair, &mut packet)?;
        assert_eq!(
            receiver.receive_wire(&packet[..length], Tick(10))?,
            Begin::Staged
        );
        encoder.confirm_repair(RepairId(serial), Tick(10))?;
        let used = finish_decode(&mut receiver, Tick(10))?;
        if serial == 16 {
            global_receive_work += used.field;
        } else {
            assert_eq!(receiver.status().decoder.decoded_prefix, hole);
            assert_eq!(receiver.status().decoder.rank, 0);
        }
    }
    assert!(global_send_work > MAX_STEP_WORK);
    assert!(global_receive_work > MAX_STEP_WORK);
    assert_eq!(receiver.status().decoder.decoded_prefix, 8_192);
    assert_eq!(receiver.status().decoder.rank, 0);
    for id in 0..8_192_u32 {
        assert_eq!(
            receiver.pending_source(),
            Some((SourceId(id), payload(id).as_slice()))
        );
        receiver.confirm_handoff(SourceId(id), Tick(10))?;
    }
    assert_eq!(receiver.pending_feedback(), Some(old_receipt));
    assert_eq!(receiver.status().feedback_due, Some(Tick(20)));
    receiver.confirm_feedback(old_receipt.id, Tick(20))?;
    let current = finish_feedback(&mut receiver, Tick(20), 1)?;
    assert_eq!(
        (current.prefix, current.observed_end, current.deficit),
        (8_192, 8_192, 0)
    );
    encoder.confirm_prefix(current.prefix, Tick(20))?;
    receiver.confirm_feedback(current.id, Tick(20))?;

    // Two more complete windows reuse both actual decoder identity banks and
    // the encoder's retained-source slots; no source/repair bytes are fabricated.
    for batch in 1..=2_u32 {
        let now = Tick(u64::from(batch) * 10 + 10);
        let first = batch * 8_192;
        for id in first..first + 8_192 {
            let bytes = payload(id);
            assert_eq!(encoder.admit_source(&bytes, now)?, SourceId(id));
            source(&mut receiver, id, &bytes, now)?;
            finish_decode(&mut receiver, now)?;
            assert_eq!(
                receiver.pending_source(),
                Some((SourceId(id), bytes.as_slice()))
            );
            receiver.confirm_handoff(SourceId(id), now)?;
        }
        let due = Tick(now.0 + 10);
        let receipt = finish_feedback(&mut receiver, due, 1)?;
        assert_eq!(receipt.prefix, first + 8_192);
        assert_eq!(receipt.observed_end, receipt.prefix);
        assert_eq!(receipt.deficit, 0);
        encoder.confirm_prefix(receipt.prefix, due)?;
        receiver.confirm_feedback(receipt.id, due)?;
        assert_eq!(encoder.storage_usage()?, tx_usage);
        assert_eq!(receiver.storage_usage()?, rx_usage);
    }
    assert_eq!(encoder.status().next_source, 24_576);
    assert_eq!(encoder.status().confirmed_prefix, 24_576);
    assert_eq!(receiver.status().decoder.handoff_prefix, 24_576);
    assert_eq!(
        source(&mut receiver, 0, &payload(0), Tick(40))?,
        Begin::Stale
    );
    Ok(())
}

fn payload(id: u32) -> [u8; 8] {
    let bytes = id.to_be_bytes();
    [0x95, bytes[0], bytes[1], 0, bytes[2], bytes[3], 0xa7, 0]
}
