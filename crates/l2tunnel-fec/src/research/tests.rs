#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use std::collections::VecDeque;

fn scope() -> Scope {
    Scope {
        session: [37; 16],
        epoch: 9,
        stream: 2,
        direction: 1,
    }
}
fn config(profile: Profile) -> Config {
    let window = profile.minimum_window().unwrap().max(256);
    Config {
        profile,
        feedback_ticks: 50,
        memory_bytes: rolling::MAX_MEMORY,
        recovery: rolling::Config {
            window,
            local_window: 128,
            global_every: 16,
            max_payload: 23,
            max_rows: 16,
            repair_history: 128,
            handoff_sources: window,
            job_ticks: 100_000,
            debt_ticks: 1_000_000,
            handoff_ticks: 100_000,
            memory_bytes: rolling::MAX_MEMORY,
        },
    }
}
fn budget() -> WorkBudget {
    WorkBudget {
        field: 65536,
        copies: 65536,
        metadata: 65536,
    }
}
fn payload(id: u32) -> Vec<u8> {
    (0..1 + id as usize % 23)
        .map(|at| {
            if at % 7 == 0 {
                0
            } else {
                id.wrapping_mul(29).wrapping_add(at as u32 * 71) as u8
            }
        })
        .collect()
}
fn service(receiver: &mut Receiver, now: Tick, delivered: &mut Vec<Vec<u8>>) -> Vec<Feedback> {
    let mut feedbacks = Vec::new();
    for _ in 0..10_000 {
        let step = receiver.step(now, budget()).unwrap();
        assert!(
            step.work.field <= 65536 && step.work.copies <= 65536 && step.work.metadata <= 65536
        );
        assert!(
            !matches!(step.decode, DecodeStep::Capacity(_)),
            "finite fixture exceeded configured rows"
        );
        while let Some((id, bytes)) = receiver.pending_source() {
            assert_eq!(id.0 as usize, delivered.len());
            delivered.push(bytes.to_vec());
            receiver.confirm_handoff(id, now).unwrap();
        }
        if let Some(f) = receiver.pending_feedback() {
            let mut bytes = [0; wire::HEADER_BYTES];
            assert_eq!(
                receiver.encode_feedback(&mut bytes).unwrap(),
                wire::HEADER_BYTES
            );
            assert!(
                matches!(wire::inspect(receiver.config_for_test(),&bytes),Ok(wire::View::Feedback(value)) if value==f)
            );
            receiver.confirm_feedback(f.id, now).unwrap();
            feedbacks.push(f);
        }
        if !receiver.status().decoder.pending_job && receiver.status().feedback_event.is_none() {
            return feedbacks;
        }
    }
    panic!("bounded service fixture failed to quiesce");
}

#[test]
fn research_real_payload_loss_reorder_reset_fallback_and_ack_history() {
    research_loss_fixture(false);
}
#[test]
fn selected_compact_research_actual_loss_reorder_reset_fallback_and_ack_history() {
    research_loss_fixture(true);
}
fn research_loss_fixture(selected: bool) {
    for profile in [
        Profile::Recursive {
            taps: 3,
            width: 8,
            reset: 256,
            fresh_interval: 0,
        },
        Profile::Recursive {
            taps: 4,
            width: 8,
            reset: 256,
            fresh_interval: 8,
        },
        Profile::Accumulator {
            lanes: 7,
            window: 128,
        },
    ] {
        let config = config(profile);
        let receive_record = |receiver: &mut Receiver, bytes: &[u8], now: Tick| {
            if selected {
                receiver.receive_view_at(
                    wire::compact::inspect(config, scope(), bytes)?,
                    now,
                    now,
                    Tick(u64::MAX),
                )
            } else {
                receiver.receive_wire(bytes, now)
            }
        };
        let receive_feedback = |sender: &mut Sender, feedback: Feedback, now: Tick| {
            if selected {
                let mut bytes = [0; wire::compact::MAXIMUM_FEEDBACK_BYTES];
                let length = wire::compact::encode_feedback(feedback, &mut bytes)?;
                let wire::View::Feedback(parsed) =
                    wire::compact::inspect(config, scope(), &bytes[..length])?
                else {
                    return Err(Error::Format);
                };
                sender.receive_feedback(parsed, now)
            } else {
                sender.receive_feedback(feedback, now)
            }
        };
        let sender_plan = storage::Plan::for_sender(config).unwrap();
        let receiver_plan = storage::Plan::for_receiver(config).unwrap();
        let mut sender = Sender::new_reserved(
            config,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: sender_plan.capacity_bytes(),
            },
        )
        .unwrap();
        let mut receiver = Receiver::new_reserved(
            config,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: receiver_plan.capacity_bytes(),
            },
        )
        .unwrap();
        let sender_usage = sender.storage_usage().unwrap();
        let receiver_usage = receiver.storage_usage().unwrap();
        let mut delivered = Vec::new();
        let mut feedback = VecDeque::new();
        let mut delayed: Option<Vec<u8>> = None;
        let mut last_packet = Vec::new();
        let mut repairs = 0;
        let mut source_bytes = 0;
        let mut repair_bytes = 0;
        let mut expected_repair_bytes = 0;
        for id in 0..1600u32 {
            let now = Tick(100 + u64::from(id) * 10);
            while feedback.front().is_some_and(|(due, _)| *due <= now) {
                let (_, value) = feedback.pop_front().unwrap();
                receive_feedback(&mut sender, value, now).unwrap();
            }
            sender.admit_source(&payload(id), now, now).unwrap();
            loop {
                for _ in 0..10_000 {
                    if sender.pending_output().is_some() {
                        break;
                    }
                    let used = sender.step(now, budget()).unwrap();
                    assert!(used.field <= 65536 && used.copies <= 65536 && used.metadata <= 65536);
                }
                let output = sender.pending_output().expect("finite encoder work");
                let identity = output.id();
                let length = if selected {
                    wire::compact::data_len(output).unwrap()
                } else {
                    output.encoded_len()
                };
                if let Output::Repair(repair) = output {
                    let extent = 2
                        + (repair.equation.support.start..repair.equation.support.end)
                            .map(|id| payload(id).len())
                            .max()
                            .unwrap();
                    assert_eq!(repair.equation.bytes.len(), extent);
                    expected_repair_bytes += wire::HEADER_BYTES + extent;
                }
                let mut bytes = vec![0; length];
                if selected {
                    assert_eq!(
                        wire::compact::encode_data(output, &mut bytes).unwrap(),
                        length
                    );
                } else {
                    assert_eq!(output.charge(53).unwrap(), bytes.len() + 53);
                    assert_eq!(sender.encode_pending(&mut bytes).unwrap(), bytes.len());
                }
                let lost = match identity {
                    OutputId::Source(s) => {
                        source_bytes += bytes.len();
                        matches!(s.0, 0 | 17 | 600 | 1225 | 1240)
                    }
                    OutputId::Repair(r) => {
                        repairs += 1;
                        repair_bytes += bytes.len();
                        r.0 == 2 || r.0 == 256
                    }
                };
                sender.confirm_output(identity, now).unwrap();
                if !lost {
                    if identity == OutputId::Source(SourceId(10)) {
                        delayed = Some(bytes);
                    } else {
                        receive_record(&mut receiver, &bytes, now).unwrap();
                        for f in service(&mut receiver, now, &mut delivered) {
                            feedback.push_back((Tick(now.0 + 70), f));
                        }
                        if id.is_multiple_of(97) {
                            assert!(matches!(
                                receive_record(&mut receiver, &bytes, now).unwrap(),
                                Begin::Duplicate | Begin::Stale
                            ));
                            for f in service(&mut receiver, now, &mut delivered) {
                                feedback.push_back((Tick(now.0 + 70), f));
                            }
                        }
                        if let Some(old) = delayed.take() {
                            receive_record(&mut receiver, &old, now).unwrap();
                            for f in service(&mut receiver, now, &mut delivered) {
                                feedback.push_back((Tick(now.0 + 70), f));
                            }
                        }
                        last_packet = bytes;
                    }
                }
                if !sender.status().repair_pending {
                    break;
                }
            }
        }
        assert_eq!(repairs, 1600 * 26 / 125);
        assert_eq!(sender.status().sent_repairs, repairs);
        assert_eq!(
            delivered,
            (0..1600).map(payload).collect::<Vec<_>>(),
            "profile {profile:?}"
        );
        if selected {
            assert!(repair_bytes < repairs as usize * (wire::HEADER_BYTES + 25));
            assert_eq!(
                source_bytes,
                (0..1600)
                    .map(|id| 1 + rolling::wire::compact::len(u64::from(id)) + payload(id).len())
                    .sum::<usize>()
            );
        } else {
            assert_eq!(repair_bytes, expected_repair_bytes);
            assert!(repair_bytes < repairs as usize * (wire::HEADER_BYTES + 25));
            assert_eq!(
                source_bytes,
                (0..1600)
                    .map(|id| wire::HEADER_BYTES + payload(id).len())
                    .sum::<usize>()
            );
        }
        let now = Tick(20000);
        receive_record(&mut receiver, &last_packet, now).unwrap();
        let final_feedback = service(&mut receiver, now, &mut delivered);
        while let Some((_, value)) = feedback.pop_front() {
            receive_feedback(&mut sender, value, now).unwrap();
        }
        for f in final_feedback {
            receive_feedback(&mut sender, f, now).unwrap();
        }
        assert_eq!(sender.status().encoder.confirmed_prefix, 1600);
        assert_eq!(sender.storage_usage().unwrap(), sender_usage);
        assert_eq!(receiver.storage_usage().unwrap(), receiver_usage);
    }
}

#[test]
fn research_wire_limits_and_failure_atomic_serialization() {
    let c = config(Profile::Accumulator {
        lanes: 7,
        window: 128,
    });
    let mut sender = Sender::new(c, scope(), Tick(0)).unwrap();
    sender.admit_source(&[1, 0, 250], Tick(0), Tick(0)).unwrap();
    let mut packet = vec![0; wire::HEADER_BYTES + 3];
    sender.encode_pending(&mut packet).unwrap();
    for end in 0..=wire::HEADER_BYTES {
        assert!(wire::inspect(c, &packet[..end]).is_err());
    }
    let mut short = vec![0xa5; packet.len() - 1];
    assert_eq!(
        sender.encode_pending(&mut short),
        Err(Error::OutputTooSmall)
    );
    assert!(short.iter().all(|b| *b == 0xa5));
    for at in [0, 4, 6, 7, 37, 38, 39, 62, 63, 64, 72, 76] {
        let mut invalid = packet.clone();
        invalid[at] ^= 1;
        assert!(wire::inspect(c, &invalid).is_err(), "offset {at}");
    }
    let mut receiver = Receiver::new(c, scope(), Tick(0)).unwrap();
    let before = receiver.status().decoder;
    let mut wrong = packet.clone();
    wrong[8] ^= 1;
    assert_eq!(receiver.receive_wire(&wrong, Tick(0)), Err(Error::Scope));
    assert_eq!(receiver.status().decoder, before);
    let mut invalid = packet.clone();
    invalid.extend([0; 30]);
    assert!(receiver.receive_wire(&invalid, Tick(0)).is_err());
    assert_eq!(receiver.status().decoder, before);
}

#[test]
fn research_receiver_packet_trigger_feedback_and_original_queue_deadline() {
    let mut c = config(Profile::Accumulator {
        lanes: 1,
        window: 128,
    });
    c.recovery.job_ticks = 100;
    c.feedback_ticks = 5;
    let mut r = Receiver::new(c, scope(), Tick(0)).unwrap();
    let mut bytes = vec![0; wire::HEADER_BYTES + 1];
    wire::encode_source(c, scope(), SourceId(0), &[7], &mut bytes).unwrap();
    r.receive_wire_at(&bytes, Tick(1), Tick(90), Tick(101))
        .unwrap();
    assert_eq!(r.deadline(), Some(Tick(101)));
    assert_eq!(r.step(Tick(101), budget()), Err(Error::Expired));
    let mut r = Receiver::new(c, scope(), Tick(0)).unwrap();
    let mut output = Vec::new();
    r.receive_wire(&bytes, Tick(0)).unwrap();
    let first = service(&mut r, Tick(0), &mut output);
    assert_eq!(first.len(), 1);
    r.receive_wire(&bytes, Tick(1)).unwrap();
    assert!(service(&mut r, Tick(1), &mut output).is_empty());
    assert!(
        service(&mut r, Tick(6), &mut output).is_empty(),
        "idle time must not generate reports"
    );
    r.receive_wire(&bytes, Tick(6)).unwrap();
    assert!(r.pending_feedback().is_none());
    r.step(Tick(6), WorkBudget::default()).unwrap();
    assert!(r.pending_feedback().is_none());
    r.step(Tick(6), budget()).unwrap();
    let snapshot = r.pending_feedback().unwrap();
    wire::encode_source(c, scope(), SourceId(1), &[9], &mut bytes).unwrap();
    r.receive_wire(&bytes, Tick(12)).unwrap();
    r.step(Tick(12), budget()).unwrap();
    assert_eq!(r.pending_feedback(), Some(snapshot));
    assert_eq!(r.status().feedback_event, Some(Tick(12)));
    r.confirm_feedback(snapshot.id, Tick(13)).unwrap();
    r.step(Tick(13), budget()).unwrap();
    assert_eq!(r.pending_feedback().unwrap().prefix, 2);
    assert_eq!(r.deadline(), Some(Tick(112)));
}

#[test]
fn research_exact_storage_bounds_and_configuration_refusal() {
    let c = config(Profile::Recursive {
        taps: 4,
        width: 8,
        reset: 256,
        fresh_interval: 16,
    });
    let s = storage::Plan::for_sender(c).unwrap();
    let r = storage::Plan::for_receiver(c).unwrap();
    assert!(matches!(
        Sender::new_reserved(
            c,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: s.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Capacity)
    ));
    assert!(matches!(
        Receiver::new_reserved(
            c,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: r.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Capacity)
    ));
    assert!(
        Sender::new_reserved(
            c,
            scope(),
            Tick(u64::MAX),
            storage::Limits {
                capacity_bytes: usize::MAX
            }
        )
        .is_err()
    );
    let mut invalid = c;
    invalid.recovery.window -= 1;
    assert_eq!(invalid.validate(), Err(Error::Configuration));
}

#[test]
fn previous_full_width_research_wire_version_is_refused() {
    let c = config(Profile::Accumulator {
        lanes: 7,
        window: 128,
    });
    let mut bytes = [0; 100];
    let length = wire::encode_source(c, scope(), SourceId(0), &[1, 0], &mut bytes).unwrap();
    bytes[4] = 1;
    assert!(matches!(
        wire::inspect(c, &bytes[..length]),
        Err(Error::Format)
    ));
}
