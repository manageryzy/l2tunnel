//! Independent owners exchange complete received data/feedback bytes only.
use l2tunnel_fec::rolling::{
    self, Begin, Config, Error, RepairId, Scope, SourceId, Tick, WorkBudget,
    scheduler::{
        self, Feedback, FeedbackDisposition, FeedbackId, Output, OutputId, Policy, Receiver, Sender,
    },
};
use std::collections::VecDeque;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn scope() -> Scope {
    Scope {
        session: [0x39; 16],
        epoch: 7,
        stream: 0x10203,
        direction: 1,
    }
}
fn policy() -> Policy {
    Policy {
        recovery: Config {
            window: 8,
            local_window: 3,
            global_every: 2,
            max_payload: 32,
            max_rows: 8,
            repair_history: 31,
            handoff_sources: 2,
            job_ticks: 1000,
            debt_ticks: 10000,
            handoff_ticks: 2000,
            memory_bytes: 1 << 20,
        },
        repair_numerator: 1,
        repair_denominator: 3,
        tail_ticks: 10,
        feedback_ticks: 3,
        feedback_packets: 4,
        memory_bytes: 1 << 20,
        source_wire: rolling::wire::SourceWire::Padded,
    }
}
fn work(n: usize) -> WorkBudget {
    WorkBudget {
        field: n,
        copies: n,
        metadata: n,
    }
}
fn original(id: u32) -> Vec<u8> {
    let n = id as usize % 32 + 1;
    (0..n)
        .map(|i| {
            if id.is_multiple_of(4) || i + 2 >= n {
                0
            } else {
                (id as u8).wrapping_mul(73) ^ (i as u8).wrapping_mul(19)
            }
        })
        .collect()
}
fn packet(sender: &Sender) -> Result<(OutputId, Vec<u8>)> {
    let id = sender.pending_output().ok_or("output absent")?.id();
    let mut bytes = vec![0; rolling::wire::HEADER_BYTES + policy().recovery.width()?];
    let length = sender.encode_pending(&mut bytes)?;
    // The charged length is exactly what the selected source format emits.
    assert_eq!(sender.pending_wire_len()?, Some(length));
    bytes.truncate(length);
    Ok((id, bytes))
}
fn drive_sender(sender: &mut Sender, now: Tick, n: usize) -> Result {
    for _ in 0..100_000 {
        let used = sender.step(now, work(n))?;
        assert!(used.field <= n && used.copies <= n && used.metadata <= n);
        if sender.pending_output().is_some() || !sender.status().encoder.pending_repair {
            return Ok(());
        }
    }
    Err("sender finite work bound exhausted".into())
}
fn drive_receiver(receiver: &mut Receiver, now: Tick, n: usize) -> Result {
    for _ in 0..100_000 {
        let result = receiver.step(now, work(n))?;
        assert!(result.work.field <= n && result.work.copies <= n && result.work.metadata <= n);
        assert!(!matches!(result.decode, rolling::DecodeStep::Capacity(_)));
        let status = receiver.status();
        if !status.decoder.pending_job
            && !status.feedback_building
            && result.work == WorkBudget::default()
        {
            return Ok(());
        }
    }
    Err("receiver finite work bound exhausted".into())
}
fn source_wire(id: SourceId, original: &[u8]) -> Result<Vec<u8>> {
    let p = policy();
    let mut bytes = vec![0; rolling::wire::HEADER_BYTES + p.recovery.width()?];
    rolling::wire::encode_source(p.recovery, scope(), id, original, &mut bytes)?;
    Ok(bytes)
}

#[test]
fn full_wire_two_owners_recover_eight_windows_with_data_repair_and_feedback_loss() -> Result {
    use rolling::wire::SourceWire;
    for (units, source_wire) in [
        (1, SourceWire::Padded),
        (17, SourceWire::Padded),
        (65_536, SourceWire::Padded),
        (1, SourceWire::Exact),
        (17, SourceWire::Exact),
        (65_536, SourceWire::Exact),
    ] {
        let p = Policy {
            source_wire,
            ..policy()
        };
        let full = rolling::wire::HEADER_BYTES + p.recovery.width()?;
        let mut short_sources = 0;
        let mut sender = Sender::new(p, scope(), Tick(0))?;
        let mut receiver = Receiver::new(p, scope(), Tick(0))?;
        let mut admitted = 0;
        let mut delivered = 0;
        let mut forward = VecDeque::new();
        let mut reverse = VecDeque::new();
        let mut dropped = [0; 3];
        let mut tails = 0;
        let mut old_feedback: Option<Vec<u8>> = None;
        for round in 0..2000_u64 {
            let now = Tick(round);
            if admitted < 64 {
                match sender.admit_source(&original(admitted), now) {
                    Ok(id) => {
                        assert_eq!(id.0, admitted);
                        admitted += 1;
                    }
                    Err(Error::Busy | Error::Capacity) => (),
                    Err(e) => return Err(e.into()),
                }
            }
            drive_sender(&mut sender, now, units)?;
            if let Some(output) = sender.pending_output() {
                let (id, bytes) = packet(&sender)?;
                // WouldBlock: no confirmation and no new output identity/bytes.
                if round % 13 != 2 {
                    let lose = match output {
                        Output::Source { id, original, .. } => {
                            // Padded records are always full width. Exact ones
                            // carry only the header, length and original bytes.
                            assert_eq!(
                                bytes.len(),
                                match source_wire {
                                    SourceWire::Padded => full,
                                    SourceWire::Exact =>
                                        rolling::wire::HEADER_BYTES + 2 + original.len(),
                                }
                            );
                            short_sources += usize::from(bytes.len() < full);
                            let lose = id.0 % 5 == 0 || id.0 % 7 == 3;
                            dropped[0] += usize::from(lose);
                            lose
                        }
                        Output::Repair(r) => {
                            assert_eq!(bytes.len(), full, "repairs are never trimmed");
                            tails += usize::from(r.support.tail);
                            let lose = r.id.0 % 4 == 1;
                            dropped[1] += usize::from(lose);
                            lose
                        }
                    };
                    sender.confirm_output(id, now)?;
                    if !lose {
                        forward.push_back(bytes);
                    }
                } else {
                    sender.step(now, WorkBudget::default())?;
                    assert_eq!(packet(&sender)?.1, bytes);
                    assert_eq!(packet(&sender)?.0, id);
                }
            }
            // Every other turn delays one packet; reverse pop introduces reorder.
            if (forward.len() > 1 || round % 2 == 0)
                && let Some(bytes) = if round % 3 == 0 {
                    forward.pop_back()
                } else {
                    forward.pop_front()
                }
            {
                match receiver.receive_wire(&bytes, now)? {
                    Begin::Staged => drive_receiver(&mut receiver, now, units)?,
                    Begin::Duplicate | Begin::Stale => (),
                }
            }
            drive_receiver(&mut receiver, now, units)?;
            if round % 5 != 1 {
                while let Some((id, bytes)) = receiver.pending_source() {
                    assert_eq!(id.0, delivered);
                    assert_eq!(bytes, original(delivered));
                    receiver.confirm_handoff(id, now)?;
                    delivered += 1;
                }
            }
            if let Some(value) = receiver.pending_feedback() {
                let bytes = receiver
                    .pending_feedback_wire()
                    .ok_or("feedback bytes")?
                    .to_vec();
                if round % 11 != 3 {
                    receiver.confirm_feedback(value.id, now)?;
                    if value.id.0 % 3 == 1 {
                        dropped[2] += 1;
                    } else {
                        reverse.push_back(bytes);
                    }
                } else {
                    receiver.step(now, WorkBudget::default())?;
                    assert_eq!(receiver.pending_feedback_wire(), Some(bytes.as_slice()));
                }
            }
            if (reverse.len() > 1 || round % 3 == 0)
                && let Some(bytes) = reverse.pop_back()
            {
                sender.receive_feedback_wire(&bytes, now)?;
                // Real old bytes may arrive after a later receipt.
                if let Some(old) = old_feedback.take() {
                    sender.receive_feedback_wire(&old, now)?;
                }
                old_feedback = Some(bytes);
            }
            assert!(forward.len() <= 4 && reverse.len() <= 4);
            assert!(receiver.status().decoder.known_sources <= 2 * p.recovery.window);
            if delivered == 64 && sender.status().encoder.confirmed_prefix == 64 {
                assert!(dropped.iter().all(|count| *count > 0));
                assert!(tails > 0);
                assert_eq!(short_sources > 0, source_wire == SourceWire::Exact);
                assert_eq!(sender.deadline(), None);
                break;
            }
        }
        assert_eq!(
            (
                admitted,
                delivered,
                sender.status().encoder.confirmed_prefix
            ),
            (64, 64, 64)
        );
    }
    Ok(())
}

#[test]
fn source_handoff_earns_exact_credit_and_freezes_output_until_matching_confirmation() -> Result {
    let mut p = policy();
    p.repair_numerator = 2;
    let mut sender = Sender::new(p, scope(), Tick(0))?;
    for source in 0..3 {
        let now = Tick(source as u64);
        let id = sender.admit_source(&original(source), now)?;
        let before = sender.status();
        let (_, bytes) = packet(&sender)?;
        sender.step(now, work(1))?;
        assert_eq!(sender.status().repair_credit, before.repair_credit);
        assert_eq!(
            sender.confirm_output(OutputId::Source(SourceId(source + 1)), now),
            Err(Error::Identity)
        );
        let mut small = vec![0x9e; bytes.len() - 1];
        let saved = small.clone();
        assert_eq!(
            sender.encode_pending(&mut small),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(small, saved);
        assert_eq!(packet(&sender)?.1, bytes);
        sender.confirm_output(OutputId::Source(id), now)?;
        if source != 0 {
            assert_eq!(sender.admit_source(b"held", now), Err(Error::Busy));
            drive_sender(&mut sender, now, 1)?;
            let repair = match sender.pending_output().ok_or("repair")? {
                Output::Repair(r) => r,
                _ => return Err("source".into()),
            };
            assert_eq!(repair.id, RepairId(source as u64));
            assert!(!repair.support.tail);
            assert_eq!(repair.support.start, 0);
            assert_eq!(repair.support.end, source + 1);
            let (id, bytes) = packet(&sender)?;
            sender.step(now, work(1))?;
            assert_eq!(packet(&sender)?.1, bytes);
            sender.confirm_output(id, now)?;
        }
    }
    assert_eq!(sender.status().repair_credit, 0);
    Ok(())
}

#[test]
fn tail_burst_uses_actual_deficit_and_duplicate_receipts_cannot_renew_triggers() -> Result {
    let mut p = policy();
    p.repair_numerator = 0;
    let mut sender = Sender::new(p, scope(), Tick(0))?;
    for id in 0..3 {
        let source = sender.admit_source(&original(id), Tick(id as u64))?;
        sender.confirm_output(OutputId::Source(source), Tick(id as u64))?;
    }
    let feedback = Feedback {
        scope: scope(),
        id: FeedbackId(3),
        prefix: 0,
        observed_end: 3,
        deficit: 3,
    };
    assert_eq!(
        sender.receive_feedback(feedback, Tick(3))?,
        FeedbackDisposition::Applied
    );
    let due = sender.status().tail_due;
    let end = sender.deadline();
    assert_eq!(
        sender.receive_feedback(feedback, Tick(4))?,
        FeedbackDisposition::Duplicate
    );
    assert_eq!(
        sender.receive_feedback(
            Feedback {
                id: FeedbackId(2),
                ..feedback
            },
            Tick(5)
        )?,
        FeedbackDisposition::Stale
    );
    assert_eq!(
        sender.receive_feedback(
            Feedback {
                deficit: 2,
                ..feedback
            },
            Tick(5)
        ),
        Err(Error::Conflict)
    );
    assert_eq!((sender.status().tail_due, sender.deadline()), (due, end));
    assert_eq!(due, Some(Tick(12)));
    sender.step(Tick(12), WorkBudget::default())?;
    assert!(!sender.status().encoder.pending_repair);
    for n in 0..3 {
        drive_sender(&mut sender, Tick(12), 1)?;
        let r = match sender.pending_output().ok_or("tail")? {
            Output::Repair(r) => r,
            _ => return Err("source".into()),
        };
        assert!(r.support.tail);
        assert_eq!((r.support.start, r.support.end), (0, 3));
        assert_eq!(r.id, RepairId(n + 1));
        sender.confirm_output(OutputId::Repair(r.id), Tick(12))?;
    }
    assert_eq!(sender.status().tail_remaining, 0);
    assert_eq!(sender.status().tail_due, Some(Tick(22)));
    assert_eq!(sender.deadline(), end);
    Ok(())
}

#[test]
fn lost_final_receipt_is_reissued_after_a_stale_tail_without_sender_ledger_access() -> Result {
    let mut p = policy();
    p.repair_numerator = 0;
    p.feedback_packets = 1;
    let mut sender = Sender::new(p, scope(), Tick(0))?;
    let mut receiver = Receiver::new(p, scope(), Tick(0))?;
    let id = sender.admit_source(b"original\0\0", Tick(0))?;
    let (_, bytes) = packet(&sender)?;
    sender.confirm_output(OutputId::Source(id), Tick(0))?;
    receiver.receive_wire(&bytes, Tick(0))?;
    drive_receiver(&mut receiver, Tick(0), 1)?;
    assert_eq!(
        receiver.pending_source().ok_or("source")?.1,
        b"original\0\0"
    );
    receiver.confirm_handoff(id, Tick(0))?;
    let lost = receiver.pending_feedback().ok_or("first receipt")?;
    assert_eq!(lost.prefix, 1);
    receiver.confirm_feedback(lost.id, Tick(0))?; // Actual reverse handoff, then network loss.
    assert_eq!(sender.status().encoder.confirmed_prefix, 0);
    drive_sender(&mut sender, Tick(10), 1)?;
    let (tail, bytes) = packet(&sender)?;
    sender.confirm_output(tail, Tick(10))?;
    assert_eq!(receiver.receive_wire(&bytes, Tick(10))?, Begin::Stale);
    drive_receiver(&mut receiver, Tick(10), 1)?;
    let fresh = receiver.pending_feedback().ok_or("repeated receipt")?;
    assert_eq!(fresh.id, FeedbackId(2));
    assert_eq!(fresh.prefix, 1);
    sender.receive_feedback_wire(receiver.pending_feedback_wire().ok_or("wire")?, Tick(10))?;
    receiver.confirm_feedback(fresh.id, Tick(10))?;
    assert_eq!(sender.status().encoder.confirmed_prefix, 1);
    assert_eq!(sender.deadline(), None);
    assert_eq!(sender.status().tail_due, None);
    Ok(())
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    text.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

#[test]
fn independent_python_feedback_literal_and_structural_malformed_corpus() -> Result {
    let p = policy();
    let literal = unhex(include_str!("fixtures/rolling-scheduler-feedback.hex"))?;
    let value = Feedback {
        scope: scope(),
        id: FeedbackId(0x0102030405060708),
        prefix: 2,
        observed_end: 7,
        deficit: 3,
    };
    assert_eq!(scheduler::decode_feedback(p.recovery, &literal)?, value);
    let mut encoded = vec![0xee; 70];
    assert_eq!(
        scheduler::encode_feedback(p.recovery, value, &mut encoded)?,
        64
    );
    assert_eq!(&encoded[..64], literal);
    assert_eq!(&encoded[64..], &[0xee; 6]);
    for size in 0..64 {
        assert!(scheduler::decode_feedback(p.recovery, &literal[..size]).is_err());
    }
    let mut too_long = literal.clone();
    too_long.push(0);
    assert_eq!(
        scheduler::decode_feedback(p.recovery, &too_long),
        Err(Error::Length)
    );
    for offset in [0, 4, 5, 6, 7, 37, 38, 39, 60, 61, 62, 63] {
        let mut changed = literal.clone();
        changed[offset] ^= 0x80;
        assert_eq!(
            scheduler::decode_feedback(p.recovery, &changed),
            Err(Error::Format)
        );
    }
    for bad in [
        Feedback {
            id: FeedbackId(0),
            ..value
        },
        Feedback {
            id: FeedbackId(u64::MAX),
            ..value
        },
        Feedback { prefix: 8, ..value },
        Feedback {
            observed_end: 11,
            ..value
        },
        Feedback {
            deficit: 6,
            ..value
        },
    ] {
        let mut out = vec![0x72; 64];
        let saved = out.clone();
        assert_eq!(
            scheduler::encode_feedback(p.recovery, bad, &mut out),
            Err(Error::Identity)
        );
        assert_eq!(out, saved);
    }
    let mut short = vec![0x3c; 63];
    assert_eq!(
        scheduler::encode_feedback(p.recovery, value, &mut short),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(short, vec![0x3c; 63]);
    Ok(())
}

#[test]
fn deficit_uses_committed_known_columns_and_independent_equation_rank() -> Result {
    let mut p = policy();
    p.feedback_packets = 1;
    let mut receiver = Receiver::new(p, scope(), Tick(0))?;
    receiver.receive_wire(&source_wire(SourceId(3), b"d")?, Tick(0))?;
    drive_receiver(&mut receiver, Tick(0), 1)?;
    let first = receiver.pending_feedback().ok_or("source feedback")?;
    assert_eq!((first.prefix, first.observed_end, first.deficit), (0, 4, 3));
    receiver.confirm_feedback(first.id, Tick(0))?;
    let literal = unhex(include_str!("fixtures/rolling-scheduler-repair.hex"))?;
    receiver.receive_wire(&literal, Tick(1))?;
    drive_receiver(&mut receiver, Tick(1), 1)?;
    assert_eq!(receiver.status().decoder.rank, 1);
    let second = receiver.pending_feedback().ok_or("rank feedback")?;
    assert_eq!(
        (second.prefix, second.observed_end, second.deficit),
        (0, 4, 2)
    );
    Ok(())
}

#[test]
fn feedback_first_event_trigger_scan_work_and_held_bytes_have_original_deadlines() -> Result {
    let mut p = policy();
    p.feedback_packets = 3;
    p.recovery.job_ticks = 20;
    p.recovery.debt_ticks = 100;
    p.recovery.handoff_ticks = 80;
    let mut receiver = Receiver::new(p, scope(), Tick(0))?;
    receiver.receive_wire(&source_wire(SourceId(0), b"one")?, Tick(0))?;
    drive_receiver(&mut receiver, Tick(0), 1)?;
    assert_eq!(receiver.status().feedback_due, Some(Tick(3)));
    assert!(!receiver.status().feedback_ready);
    receiver.receive_wire(&source_wire(SourceId(1), b"two")?, Tick(2))?;
    drive_receiver(&mut receiver, Tick(2), 1)?;
    assert_eq!(receiver.status().feedback_due, Some(Tick(3)));
    let no_work = receiver.step(Tick(3), WorkBudget::default())?;
    assert_eq!(no_work.work, WorkBudget::default());
    assert!(!receiver.status().feedback_building);
    receiver.step(Tick(3), work(1))?;
    assert!(receiver.status().feedback_building);
    assert_eq!(
        receiver.receive_wire(&source_wire(SourceId(2), b"busy")?, Tick(3)),
        Err(Error::Busy)
    );
    assert_eq!(
        receiver.confirm_handoff(SourceId(0), Tick(3)),
        Err(Error::Busy)
    );
    drive_receiver(&mut receiver, Tick(3), 1)?;
    let value = receiver.pending_feedback().ok_or("held feedback")?;
    let held = receiver
        .pending_feedback_wire()
        .ok_or("held bytes")?
        .to_vec();
    assert_eq!(receiver.deadline(), Some(Tick(23)));
    // Independent input may progress behind a complete immutable feedback output.
    receiver.confirm_handoff(SourceId(0), Tick(4))?;
    receiver.receive_wire(&source_wire(SourceId(2), b"three")?, Tick(4))?;
    drive_receiver(&mut receiver, Tick(4), 1)?;
    assert_eq!(receiver.pending_feedback_wire(), Some(held.as_slice()));
    assert_eq!(receiver.pending_feedback(), Some(value));
    assert_eq!(receiver.deadline(), Some(Tick(23)));
    assert_eq!(
        receiver.confirm_feedback(FeedbackId(value.id.0 + 1), Tick(5)),
        Err(Error::Identity)
    );
    assert_eq!(receiver.step(Tick(23), work(1)), Err(Error::Expired));
    assert_eq!(receiver.status().terminal, Some(Error::Expired));
    assert_eq!(receiver.step(Tick(24), work(1)), Err(Error::Terminal));
    Ok(())
}

#[test]
fn feedback_domain_future_extent_and_regression_never_retire_unsent_sources() -> Result {
    let mut sender = Sender::new(policy(), scope(), Tick(0))?;
    sender.admit_source(b"pending", Tick(0))?;
    let mut feedback = Feedback {
        scope: scope(),
        id: FeedbackId(1),
        prefix: 1,
        observed_end: 1,
        deficit: 0,
    };
    assert_eq!(
        sender.receive_feedback(feedback, Tick(0)),
        Err(Error::Identity)
    );
    assert_eq!(sender.status().encoder.confirmed_prefix, 0);
    sender.confirm_output(OutputId::Source(SourceId(0)), Tick(0))?;
    for change in 0..4 {
        let mut wrong = feedback;
        match change {
            0 => wrong.scope.session[0] ^= 1,
            1 => wrong.scope.epoch += 1,
            2 => wrong.scope.stream += 1,
            _ => wrong.scope.direction ^= 1,
        }
        assert_eq!(sender.receive_feedback(wrong, Tick(0)), Err(Error::Scope));
    }
    sender.receive_feedback(feedback, Tick(0))?;
    feedback.id = FeedbackId(2);
    feedback.prefix = 0;
    feedback.deficit = 1;
    assert_eq!(
        sender.receive_feedback(feedback, Tick(0))?,
        FeedbackDisposition::Stale
    );
    assert_eq!(sender.status().encoder.confirmed_prefix, 1);
    assert_eq!(sender.status().feedback, Some(FeedbackId(1)));
    Ok(())
}

#[test]
fn original_sender_debt_and_blocked_output_expire_without_timer_renewal() -> Result {
    let mut p = policy();
    p.recovery.job_ticks = 20;
    p.recovery.debt_ticks = 100;
    let mut sender = Sender::new(p, scope(), Tick(0))?;
    sender.admit_source(b"blocked", Tick(0))?;
    let (_, bytes) = packet(&sender)?;
    assert_eq!(sender.deadline(), Some(Tick(20)));
    sender.step(Tick(19), WorkBudget::default())?;
    assert_eq!(packet(&sender)?.1, bytes);
    assert_eq!(sender.deadline(), Some(Tick(20)));
    assert_eq!(
        sender.confirm_output(OutputId::Source(SourceId(0)), Tick(20)),
        Err(Error::Expired)
    );
    assert_eq!(sender.status().sent_sources, 0);
    assert_eq!(sender.status().repair_credit, 0);
    let mut sender = Sender::new(p, scope(), Tick(0))?;
    sender.admit_source(b"debt", Tick(0))?;
    sender.confirm_output(OutputId::Source(SourceId(0)), Tick(0))?;
    for now in (10..100).step_by(10) {
        drive_sender(&mut sender, Tick(now), 1)?;
        let id = sender.pending_output().ok_or("tail")?.id();
        sender.confirm_output(id, Tick(now))?;
        assert_eq!(sender.deadline(), Some(Tick(100)));
    }
    assert_eq!(sender.step(Tick(100), work(1)), Err(Error::Expired));
    Ok(())
}

#[test]
fn total_reservations_work_caps_and_time_regression_are_explicit() -> Result {
    let p = policy();
    let a = Sender::memory_bound(p)?;
    let b = Receiver::memory_bound(p)?;
    assert!(
        Sender::new(
            Policy {
                memory_bytes: a,
                ..p
            },
            scope(),
            Tick(0)
        )
        .is_ok()
    );
    assert!(
        Receiver::new(
            Policy {
                memory_bytes: b,
                ..p
            },
            scope(),
            Tick(0)
        )
        .is_ok()
    );
    assert!(matches!(
        Sender::new(
            Policy {
                memory_bytes: a - 1,
                ..p
            },
            scope(),
            Tick(0)
        ),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        Receiver::new(
            Policy {
                memory_bytes: b - 1,
                ..p
            },
            scope(),
            Tick(0)
        ),
        Err(Error::Capacity)
    ));
    for bad in [
        Policy {
            repair_denominator: 0,
            ..p
        },
        Policy {
            repair_numerator: 4,
            ..p
        },
        Policy { tail_ticks: 0, ..p },
        Policy {
            feedback_packets: 0,
            ..p
        },
        Policy {
            feedback_ticks: u64::MAX,
            ..p
        },
    ] {
        assert_eq!(bad.validate(), Err(Error::Configuration));
    }
    let mut sender = Sender::new(p, scope(), Tick(2))?;
    let mut receiver = Receiver::new(p, scope(), Tick(2))?;
    let over = WorkBudget {
        metadata: 65537,
        ..WorkBudget::default()
    };
    assert_eq!(sender.step(Tick(2), over), Err(Error::WorkLimit));
    assert_eq!(receiver.step(Tick(2), over), Err(Error::WorkLimit));
    assert_eq!(sender.step(Tick(1), work(1)), Err(Error::TimeRegression));
    assert_eq!(receiver.step(Tick(1), work(1)), Err(Error::TimeRegression));
    assert_eq!(sender.status().terminal, Some(Error::TimeRegression));
    assert_eq!(receiver.status().terminal, Some(Error::TimeRegression));
    Ok(())
}

#[test]
fn published_prefix_feedback_excludes_retained_history_and_known_future_debt() -> Result {
    let mut p = policy();
    p.recovery.handoff_sources = 1;
    p.feedback_packets = 16;
    let mut receiver = Receiver::new(p, scope(), Tick(0))?;
    for id in (0..4).rev() {
        receiver.receive_wire(&source_wire(SourceId(id), &original(id))?, Tick(0))?;
        drive_receiver(&mut receiver, Tick(0), 1)?;
    }
    assert_eq!(receiver.status().decoder.decoded_prefix, 1);
    drive_receiver(&mut receiver, Tick(3), 1)?;
    let receipt = receiver.pending_feedback().ok_or("published receipt")?;
    assert_eq!(
        (receipt.prefix, receipt.observed_end, receipt.deficit),
        (1, 4, 0)
    );
    receiver.confirm_feedback(receipt.id, Tick(3))?;
    for id in 0..3 {
        receiver.confirm_handoff(SourceId(id), Tick(3))?;
    }
    drive_receiver(&mut receiver, Tick(6), 1)?;
    let receipt = receiver.pending_feedback().ok_or("history receipt")?;
    assert_eq!(
        (receipt.prefix, receipt.observed_end, receipt.deficit),
        (4, 4, 0)
    );
    assert_eq!(receiver.status().decoder.known_sources, 4);
    Ok(())
}

#[test]
fn receipt_during_a_pending_tail_preserves_issued_bytes_and_original_job_expiry() -> Result {
    let mut p = policy();
    p.repair_numerator = 0;
    p.recovery.job_ticks = 20;
    let mut sender = Sender::new(p, scope(), Tick(0))?;
    let id = sender.admit_source(b"pending-tail", Tick(0))?;
    sender.confirm_output(OutputId::Source(id), Tick(0))?;
    drive_sender(&mut sender, Tick(10), 1)?;
    let (id, bytes) = packet(&sender)?;
    assert_eq!(sender.deadline(), Some(Tick(30)));
    sender.receive_feedback(
        Feedback {
            scope: scope(),
            id: FeedbackId(1),
            prefix: 1,
            observed_end: 1,
            deficit: 0,
        },
        Tick(11),
    )?;
    assert_eq!(packet(&sender)?.0, id);
    assert_eq!(packet(&sender)?.1, bytes);
    assert_eq!(sender.deadline(), Some(Tick(30)));
    sender.confirm_output(id, Tick(12))?;
    assert_eq!(sender.status().tail_due, None);
    assert_eq!(sender.deadline(), None);
    sender.step(Tick(22), work(1))?;
    assert!(sender.pending_output().is_none());
    Ok(())
}

#[test]
fn primitive_borrowed_repair_confirmation_is_identity_checked_and_does_not_copy() -> Result {
    let p = policy();
    let mut encoder = rolling::Encoder::new(p.recovery, scope(), Tick(0))?;
    encoder.admit_source(b"actual bytes", Tick(0))?;
    let first = encoder.begin_repair(true, Tick(0))?;
    while encoder.pending_repair().is_none() {
        encoder.step(Tick(0), work(17))?;
    }
    let bytes = encoder.pending_repair().ok_or("repair")?.bytes.to_vec();
    assert_eq!(
        encoder.confirm_repair(RepairId(first.0 + 1), Tick(0)),
        Err(Error::Identity)
    );
    assert_eq!(encoder.pending_repair().ok_or("retained")?.bytes, bytes);
    encoder.confirm_repair(first, Tick(0))?;
    assert!(encoder.pending_repair().is_none());
    assert_eq!(encoder.begin_repair(true, Tick(0))?, RepairId(first.0 + 1));
    Ok(())
}
