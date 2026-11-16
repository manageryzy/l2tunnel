use super::*;
use crate::legacy_sliding::{Begin, DecodeStep, FeedbackId, Receiver, Term};

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Coefficients(u8);
impl crate::legacy_sliding::CoefficientSource for Coefficients {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        for byte in bytes {
            self.0 = self.0.wrapping_add(1).max(1);
            *byte = self.0;
        }
        Ok(())
    }
}
const ORACLE: &str = include_str!("../../tests/fixtures/legacy-admission-packing.txt");
struct Captured(usize);
impl crate::legacy_sliding::CoefficientSource for Captured {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        // Actual Random(7349) draws captured by the unchanged Python oracle.
        let bytes = [0x2b, 0xc3, 0x35, 0xc3, 0x69, 0x5e, 0x4f, 0xb4];
        let end = self.0.checked_add(output.len()).ok_or(Error::Exhausted)?;
        output.copy_from_slice(bytes.get(self.0..end).ok_or(Error::Exhausted)?);
        self.0 = end;
        Ok(())
    }
}
fn oracle_snapshot(sender: &BatchSender, at: u64) -> TestResult {
    let prefix = format!("z {at} ");
    let row = ORACLE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or(Error::Identity)?;
    let expected = row
        .split_ascii_whitespace()
        .map(str::parse)
        .collect::<Result<Vec<u64>, _>>()?;
    let status = sender.status();
    assert_eq!(
        expected,
        [
            u64::from(status.fec_count),
            u64::from(status.repair_credit),
            status.fec_generation,
            status.periodic_repairs
        ]
    );
    Ok(())
}
fn config() -> Config {
    Config {
        recovery: rolling::Config {
            window: 16,
            local_window: 2,
            global_every: 16,
            max_payload: 11,
            max_rows: 16,
            repair_history: 32,
            handoff_sources: 16,
            job_ticks: 1000,
            debt_ticks: 10000,
            handoff_ticks: 5000,
            memory_bytes: 1 << 20,
        },
        mode: crate::legacy_sliding::Mode::Sliding,
        long_window: 5,
        short_window: 2,
        long_every: 3,
        repair_every: 5,
        repairs_per_group: 2,
        interleave_repairs: true,
        feedback_repair: true,
        cumulative_feedback: false,
        feedback_batch: 16,
        fec_wait_ticks: 10,
        repair_spacing_ticks: 1,
        feedback_wait_ticks: 2,
        rto_min_ticks: 100,
        rto_factor_numerator: 5,
        rto_factor_denominator: 2,
        repair_queue: 16,
        max_attempts: 16,
        feedback_payload_budget: 512,
        max_record_bytes: 512,
        memory_bytes: 1 << 20,
    }
}
fn scope() -> Scope {
    Scope {
        session: [0x73; 16],
        epoch: 3,
        stream: 4,
        direction: 1,
    }
}
fn packing(config: Config) -> Result<Packing, Error> {
    let mut packing = Packing {
        source_batch: 2,
        repair_batch: 2,
        pack_wait_ticks: 5,
        analytical_mtu: 600,
        max_packet_bytes: 65_535,
        packet_slots: 8,
        memory_bytes: 1 << 20,
    };
    packing.max_packet_bytes = packing.required_packet_bytes(config)?;
    Ok(packing)
}
fn make_sender(config: Config, packing: Packing) -> Result<BatchSender, storage::Error> {
    let plan = Plan::new(config, packing)?;
    BatchSender::new_reserved(
        config,
        packing,
        scope(),
        Tick(0),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )
}
fn work() -> WorkBudget {
    WorkBudget {
        field: 1,
        copies: 1,
        metadata: 1,
    }
}
fn receive(
    receiver: &mut Receiver,
    config: Config,
    packing: Packing,
    bytes: &[u8],
    now: Tick,
) -> Result<(), Error> {
    let view = batch_wire::inspect(config, packing, bytes)?;
    assert_eq!(view.scope(), scope());
    for record in view.records() {
        assert_eq!(receiver.receive_wire(record, now)?, Begin::Staged);
        finish(receiver, now)?;
    }
    Ok(())
}
fn finish(receiver: &mut Receiver, now: Tick) -> Result<(), Error> {
    for _ in 0..100_000 {
        let step = receiver.step(now, work())?;
        assert!(step.work.field <= 1 && step.work.copies <= 1 && step.work.metadata <= 1);
        if matches!(step.decode, DecodeStep::Capacity(_)) {
            return Err(Error::Capacity);
        }
        if !receiver.status().decoder.pending_job && !receiver.status().scanning {
            return Ok(());
        }
    }
    Err(Error::WorkLimit)
}

#[test]
fn actual_batches_keep_admission_credit_and_frozen_cohorts_through_loss_and_held_receipt()
-> TestResult {
    let config = config();
    let packing = packing(config)?;
    let plan = Plan::new(config, packing)?;
    assert!(
        BatchSender::new_reserved(
            config,
            packing,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        )
        .is_err()
    );
    let mut sender = make_sender(config, packing)?;
    let usage = sender.storage_usage()?;
    assert_eq!(
        (usage.capacity_bytes, usage.allocations),
        (plan.capacity_bytes(), plan.allocations())
    );
    let mut random = Captured(0);
    sender.admit_source(&[0, 0], Tick(0), Tick(0), &mut random)?;
    oracle_snapshot(&sender, 0)?;
    assert!(sender.pending_output().is_none());
    sender.admit_source(&[1, 0], Tick(1), Tick(1), &mut random)?;
    oracle_snapshot(&sender, 1)?;
    let first = sender.pending_output().ok_or(Error::Busy)?;
    assert_eq!((first.kind, first.records), (Kind::Source, 2));
    let first_id = first.id;
    let first_bytes = first.bytes.to_vec();
    let first_charge = first.charge(28)?;
    for id in 2..5 {
        sender.admit_source(&[id as u8, 0], Tick(id), Tick(id), &mut random)?;
        oracle_snapshot(&sender, id)?;
    }
    assert_eq!(
        (
            sender.status().periodic_repairs,
            sender.status().repair_credit
        ),
        (2, 0)
    );
    // The repair packer reserves both original due events (3 and 5) in one
    // packet even though real GF work is deliberately deferred until tick 10.
    for _ in 0..256 {
        let used = sender.step(Tick(10), work(), &mut random)?;
        assert!(used.field <= 1 && used.copies <= 1 && used.metadata <= 1);
    }
    sender.step(Tick(20), WorkBudget::default(), &mut random)?;
    oracle_snapshot(&sender, 20)?;
    let repeated = sender.pending_output().ok_or(Error::Busy)?;
    assert_eq!(
        (repeated.id, repeated.bytes, repeated.charge(28)?),
        (first_id, first_bytes.as_slice(), first_charge)
    );
    assert_eq!(sender.status().sent_sources, 0);
    assert_eq!(sender.status().unsent_sources, 5);
    let received = [SourceId(0)];
    let early = Feedback {
        scope: scope(),
        id: FeedbackId(1),
        prefix: None,
        ids: &received,
    };
    assert_eq!(
        sender.receive_feedback(early, Tick(350), &mut random),
        Err(Error::Busy)
    );
    assert_eq!(sender.status().feedback, None);
    // The whole first packet is physically sent, then lost as one unit.
    sender.confirm_output(first_id, Tick(350), Tick(351), 1000)?;
    assert_eq!(sender.last_receipt().ok_or(Error::Identity)?.records, 2);
    assert_eq!(
        sender.receive_feedback_at(early, Tick(349), Tick(351), &mut random),
        Err(Error::TimeRegression)
    );
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    let mut packets = 1usize;
    let mut network = first_charge;
    let mut protocol = first_bytes.len();
    let mut repair_rows = Vec::new();
    let mut repair_coefficients = Vec::new();
    let timing = ORACLE
        .lines()
        .filter(|line| line.starts_with("t "))
        .map(|line| line.split_ascii_whitespace().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    assert_eq!(timing.len(), 4);
    while let Some(output) = sender.pending_output() {
        let id = output.id;
        let kind = output.kind;
        let count = output.records;
        assert_eq!(
            sender.selected().ok_or(Error::Busy)?.1.ready,
            Some(Tick(timing[packets][1].parse()?))
        );
        let bytes = output.bytes.to_vec();
        let charge = output.charge(28)?;
        if kind == Kind::Repair {
            assert_eq!(count, 2);
            for record in batch_wire::inspect(config, packing, &bytes)?.records() {
                let mut terms = [Term {
                    source: SourceId(0),
                    coefficient: 0,
                }; 255];
                let mut ids = [SourceId(0); 255];
                let wire::View::Repair(repair) =
                    wire::inspect(config, record, &mut terms, &mut ids)?
                else {
                    return Err(Error::Format.into());
                };
                repair_rows.push(
                    repair
                        .terms
                        .iter()
                        .map(|term| term.source)
                        .collect::<Vec<_>>(),
                );
                repair_coefficients.push(
                    repair
                        .terms
                        .iter()
                        .map(|term| format!("{:02x}", term.coefficient))
                        .collect::<String>(),
                );
            }
        }
        let accepted = timing[packets][5].parse::<u64>()?;
        sender.confirm_output(id, Tick(accepted), Tick(accepted + 1), 1000)?;
        receive(&mut receiver, config, packing, &bytes, Tick(1700))?;
        packets += 1;
        network += charge;
        protocol += bytes.len();
    }
    assert_eq!(
        repair_rows,
        [
            vec![SourceId(0), SourceId(1), SourceId(2)],
            vec![
                SourceId(0),
                SourceId(1),
                SourceId(2),
                SourceId(3),
                SourceId(4)
            ]
        ]
    );
    let expected_coefficients = ORACLE
        .lines()
        .filter(|line| line.starts_with("q "))
        .map(|line| line.split_ascii_whitespace().last().ok_or(Error::Format))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(repair_coefficients, expected_coefficients);
    assert_eq!(packets, 4);
    assert_eq!(network, protocol + 28 * packets);
    assert_eq!(sender.status().repair_credit, 0);
    assert_eq!(
        (
            sender.status().physical_source_attempts,
            sender.status().physical_repairs
        ),
        (5, 2)
    );
    assert_eq!(receiver.status().receipt_prefix, 5);
    for id in 0..5 {
        assert_eq!(
            receiver.pending_source(),
            Some((SourceId(id), [id as u8, 0].as_slice()))
        );
        receiver.confirm_handoff(SourceId(id), Tick(1700))?;
    }
    finish(&mut receiver, Tick(1702))?;
    let feedback = receiver.pending_feedback().ok_or(Error::Identity)?;
    assert_eq!(
        feedback.ids,
        [
            SourceId(0),
            SourceId(1),
            SourceId(2),
            SourceId(3),
            SourceId(4)
        ]
    );
    sender.receive_feedback(feedback, Tick(1702), &mut random)?;
    receiver.confirm_feedback(feedback.id, Tick(1702))?;
    assert!(sender.is_drained());
    assert_eq!(sender.storage_usage()?, usage);
    Ok(())
}

#[test]
fn first_item_timer_exact_wire_bounds_and_original_acceptance_rto_survive_waits() -> TestResult {
    let mut config = config();
    config.interleave_repairs = false;
    config.repair_every = 20;
    config.fec_wait_ticks = 1000;
    let mut packing = packing(config)?;
    packing.source_batch = 3;
    packing.max_packet_bytes = packing.required_packet_bytes(config)?;
    let mut short = packing;
    short.max_packet_bytes -= 1;
    assert_eq!(short.validate(config), Err(Error::Configuration));
    let mut sender = make_sender(config, packing)?;
    let mut random = Coefficients(0);
    sender.admit_source(&[0], Tick(0), Tick(0), &mut random)?;
    sender.admit_source(&[1, 0], Tick(4), Tick(4), &mut random)?;
    assert_eq!(sender.next_wakeup(), Some(Tick(5)));
    sender.step(Tick(5), WorkBudget::default(), &mut random)?;
    let output = sender.pending_output().ok_or(Error::Busy)?;
    let id = output.id;
    let bytes = output.bytes.to_vec();
    assert_eq!(output.deadline, Tick(1000));
    assert_eq!(output.records, 2);
    assert_eq!(
        output.charge(48)?,
        8 + 2 * (2 + wire::HEADER_BYTES) + 3 + 48
    );
    assert_eq!(batch_wire::inspect(config, packing, &bytes)?.count(), 2);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(batch_wire::inspect(config, packing, &trailing).is_err());
    let mut wrong_class = bytes.clone();
    wrong_class[5] = Kind::Repair.code();
    assert!(batch_wire::inspect(config, packing, &wrong_class).is_err());
    sender.admit_source(&[2], Tick(6), Tick(6), &mut random)?;
    sender.step(Tick(11), WorkBudget::default(), &mut random)?;
    assert_eq!(sender.pending_output().ok_or(Error::Busy)?.bytes, bytes);
    sender.confirm_output(id, Tick(10), Tick(12), 100)?;
    assert_eq!(sender.next_wakeup(), Some(Tick(260)));
    assert_eq!(
        sender.confirm_output(id, Tick(10), Tick(12), 100),
        Err(Error::Identity)
    );
    let mut foreign = make_sender(config, packing)?;
    foreign.admit_source(&[7], Tick(0), Tick(0), &mut random)?;
    foreign.step(Tick(5), WorkBudget::default(), &mut random)?;
    let foreign_id = foreign.pending_output().ok_or(Error::Busy)?.id;
    assert_eq!(
        sender.confirm_output(foreign_id, Tick(12), Tick(12), 100),
        Err(Error::Identity)
    );
    assert_eq!(sender.last_receipt().ok_or(Error::Identity)?.id, id);
    Ok(())
}

#[test]
fn late_whole_packet_fact_is_retained_without_reissue_or_new_credit() -> TestResult {
    let mut config = config();
    config.recovery.job_ticks = 20;
    config.fec_wait_ticks = 10;
    let packing = packing(config)?;
    let mut sender = make_sender(config, packing)?;
    let mut random = Coefficients(0);
    sender.admit_source(&[9, 0], Tick(0), Tick(0), &mut random)?;
    sender.admit_source(&[10, 0], Tick(1), Tick(1), &mut random)?;
    let output = sender.pending_output().ok_or(Error::Busy)?;
    let id = output.id;
    let bytes = output.bytes.len();
    assert_eq!(output.records, 2);
    assert_eq!(sender.deadline(), Some(Tick(20)));
    assert_eq!(
        sender.confirm_output(id, Tick(19), Tick(20), 100),
        Err(Error::Expired)
    );
    assert_eq!(
        sender.last_receipt(),
        Some(Receipt {
            id,
            records: 2,
            bytes,
            accepted: Tick(19),
            observed: Tick(20),
            failure: Some(Error::Expired)
        })
    );
    assert_eq!(
        (
            sender.status().physical_source_attempts,
            sender.status().unsent_sources,
            sender.status().sent_sources
        ),
        (2, 0, 2)
    );
    assert_eq!(sender.terminal(), Some(Error::Expired));
    assert!(sender.pending_output().is_none());
    assert!(!sender.is_drained());
    assert_eq!(sender.status().repair_credit, 4);
    assert_eq!(
        sender.confirm_output(id, Tick(19), Tick(20), 100),
        Err(Error::Terminal)
    );

    // One late repair packet must likewise consume every represented job,
    // including later items after the first observation discovers expiry.
    config.repair_every = 1;
    config.repairs_per_group = 2;
    let mut packing = packing;
    packing.source_batch = 1;
    let mut repairs = make_sender(config, packing)?;
    repairs.admit_source(&[11, 0], Tick(0), Tick(0), &mut random)?;
    let source_id = repairs.pending_output().ok_or(Error::Busy)?.id;
    repairs.confirm_output(source_id, Tick(0), Tick(0), 100)?;
    for _ in 0..256 {
        let used = repairs.step(Tick(3), work(), &mut random)?;
        assert!(used.field <= 1 && used.copies <= 1 && used.metadata <= 1);
    }
    let output = repairs.pending_output().ok_or(Error::Busy)?;
    assert_eq!((output.kind, output.records), (Kind::Repair, 2));
    let id = output.id;
    assert_eq!(repairs.status().queued_repairs, 2);
    assert_eq!(
        repairs.confirm_output(id, Tick(19), Tick(20), 100),
        Err(Error::Expired)
    );
    assert_eq!(
        (
            repairs.status().physical_repairs,
            repairs.status().queued_repairs
        ),
        (2, 0)
    );
    assert_eq!(repairs.last_receipt().ok_or(Error::Identity)?.records, 2);
    assert_eq!(repairs.terminal(), Some(Error::Expired));
    assert!(repairs.pending_output().is_none());
    Ok(())
}

#[test]
fn acknowledged_held_retry_pins_its_flight_until_exact_physical_receipt() -> TestResult {
    let mut config = config();
    config.recovery.window = 2;
    config.recovery.max_rows = 2;
    config.recovery.handoff_sources = 2;
    config.long_window = 1;
    config.short_window = 1;
    config.repair_every = 255;
    config.repairs_per_group = 1;
    config.interleave_repairs = false;
    config.fec_wait_ticks = 1000;
    let mut packing = packing(config)?;
    packing.source_batch = 1;
    let mut sender = make_sender(config, packing)?;
    let usage = sender.storage_usage()?;
    let mut random = Coefficients(0);
    sender.admit_source(&[0], Tick(0), Tick(0), &mut random)?;
    let first = sender.pending_output().ok_or(Error::Busy)?.id;
    sender.confirm_output(first, Tick(0), Tick(0), 0)?;
    sender.step(Tick(100), work(), &mut random)?;
    let held = sender.pending_output().ok_or(Error::Busy)?;
    assert_eq!(held.kind, Kind::Retry);
    let id = held.id;
    let bytes = held.bytes.to_vec();
    let cap = held.deadline;
    let feedback = Feedback {
        scope: scope(),
        id: FeedbackId(1),
        prefix: None,
        ids: &[SourceId(0)],
    };
    sender.receive_feedback(feedback, Tick(101), &mut random)?;
    assert_eq!(sender.status().pending_sources, 0);
    assert_eq!(
        sender.admit_source(&[1], Tick(101), Tick(101), &mut random)?,
        SourceId(1)
    );
    let before = sender.status();
    assert_eq!(
        sender.admit_source(&[2], Tick(101), Tick(101), &mut random),
        Err(Error::Capacity)
    );
    assert_eq!(
        sender.status().encoder.next_source,
        before.encoder.next_source
    );
    assert_eq!(
        sender.status().physical_source_attempts,
        before.physical_source_attempts
    );
    let repeated = sender.pending_output().ok_or(Error::Busy)?;
    assert_eq!(
        (repeated.id, repeated.bytes, repeated.deadline),
        (id, bytes.as_slice(), cap)
    );
    sender.confirm_output(id, Tick(101), Tick(102), 0)?;
    assert_eq!(sender.status().physical_source_attempts, 2);
    assert_eq!(
        sender.admit_source(&[2], Tick(102), Tick(102), &mut random)?,
        SourceId(2)
    );
    assert_eq!(sender.storage_usage()?, usage);
    Ok(())
}
