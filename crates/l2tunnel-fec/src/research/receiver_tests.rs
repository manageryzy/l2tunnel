use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(profile: Profile) -> Result<Config, Error> {
    let window = profile.minimum_window()?.max(8);
    Ok(Config {
        recovery: rolling::Config {
            window,
            local_window: window,
            global_every: 16,
            max_payload: 8,
            max_rows: 4,
            repair_history: 8,
            handoff_sources: window,
            job_ticks: 100,
            debt_ticks: 1_000,
            handoff_ticks: 500,
            memory_bytes: rolling::MAX_MEMORY,
        },
        profile,
        feedback_ticks: 5,
        memory_bytes: rolling::MAX_MEMORY,
    })
}
fn scope() -> Scope {
    Scope {
        session: [41; 16],
        epoch: 2,
        stream: 7,
        direction: 1,
    }
}
fn budget() -> WorkBudget {
    WorkBudget {
        field: 65_536,
        copies: 65_536,
        metadata: 65_536,
    }
}
fn source(config: Config, id: u32, bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = vec![0; wire::HEADER_BYTES + bytes.len()];
    wire::encode_source(config, scope(), SourceId(id), bytes, &mut output)?;
    Ok(output)
}
fn finish(receiver: &mut Receiver, now: Tick) -> Result<(), Error> {
    for _ in 0..1_000 {
        receiver.step(now, budget())?;
        if !receiver.status().decoder.pending_job {
            return Ok(());
        }
    }
    Err(Error::WorkLimit)
}

#[test]
fn research_receiver_conflict_immediately_hides_pending_feedback() -> TestResult {
    let config = config(Profile::Accumulator {
        lanes: 2,
        window: 8,
    })?;
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    receiver.receive_wire(&source(config, 0, &[7, 0])?, Tick(0))?;
    finish(&mut receiver, Tick(0))?;
    assert!(receiver.pending_feedback().is_some());
    assert_eq!(
        receiver.receive_wire(&source(config, 0, &[8, 0])?, Tick(1)),
        Err(Error::Conflict)
    );
    assert_eq!(receiver.status().terminal, Some(Error::Conflict));
    assert!(receiver.pending_feedback().is_none());
    let mut output = [0xa5; wire::HEADER_BYTES];
    assert_eq!(receiver.encode_feedback(&mut output), Err(Error::Busy));
    assert_eq!(output, [0xa5; wire::HEADER_BYTES]);
    assert_eq!(receiver.step(Tick(1), budget()), Err(Error::Terminal));
    Ok(())
}

#[test]
fn research_receiver_feedback_keeps_original_arrival_and_cap_after_commit() -> TestResult {
    let config = config(Profile::Accumulator {
        lanes: 2,
        window: 8,
    })?;
    for cap in [Tick(10), Tick(u64::MAX)] {
        let mut receiver = Receiver::new(config, scope(), Tick(0))?;
        receiver.receive_wire_at(&source(config, 0, &[7])?, Tick(0), Tick(5), cap)?;
        finish(&mut receiver, Tick(6))?;
        receiver.confirm_handoff(SourceId(0), Tick(6))?;
        let expected = cap.min(Tick(100));
        assert!(receiver.pending_feedback().is_some());
        assert_eq!(receiver.deadline(), Some(expected));
        assert_eq!(
            receiver.step(expected, WorkBudget::default()),
            Err(Error::Expired)
        );
        assert!(receiver.pending_feedback().is_none());
    }
    Ok(())
}

#[test]
fn research_receiver_cap_survives_feedback_until_upper_handoff_and_releases_when_idle() -> TestResult
{
    let config = config(Profile::Accumulator {
        lanes: 2,
        window: 8,
    })?;
    let packet = source(config, 0, &[7])?;
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    receiver.receive_wire_at(&packet, Tick(0), Tick(5), Tick(10))?;
    finish(&mut receiver, Tick(6))?;
    let feedback = receiver.pending_feedback().ok_or(Error::Busy)?;
    receiver.confirm_feedback(feedback.id, Tick(7))?;
    assert_eq!(receiver.deadline(), Some(Tick(10)));
    assert_eq!(
        receiver.confirm_handoff(SourceId(0), Tick(10)),
        Err(Error::Expired)
    );

    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    receiver.receive_wire_at(&packet, Tick(0), Tick(5), Tick(10))?;
    finish(&mut receiver, Tick(6))?;
    let feedback = receiver.pending_feedback().ok_or(Error::Busy)?;
    receiver.confirm_feedback(feedback.id, Tick(7))?;
    receiver.confirm_handoff(SourceId(0), Tick(8))?;
    assert_eq!(receiver.deadline(), None);
    assert_eq!(receiver.retained_cap, None);
    receiver.receive_wire_at(&source(config, 1, &[9])?, Tick(11), Tick(11), Tick(30))?;
    finish(&mut receiver, Tick(11))?;
    assert_eq!(receiver.deadline(), Some(Tick(30)));
    Ok(())
}

#[test]
fn research_receiver_changed_confirmed_prefix_conflicts_even_when_support_is_identical()
-> TestResult {
    let config = config(Profile::Recursive {
        taps: 3,
        width: 8,
        reset: 256,
        fresh_interval: 0,
    })?;
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    for source in 0..5 {
        sender.admit_source(&[source as u8, 0, 255], Tick(0), Tick(0))?;
        let id = sender.pending_output().ok_or(Error::Busy)?.id();
        sender.confirm_output(id, Tick(0))?;
    }
    for _ in 0..1_000 {
        sender.step(Tick(0), budget())?;
        if sender.pending_output().is_some() {
            break;
        }
    }
    let mut packet = vec![0; sender.pending_wire_len().ok_or(Error::Busy)?];
    sender.encode_pending(&mut packet)?;
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    receiver.receive_wire(&packet, Tick(0))?;
    finish(&mut receiver, Tick(0))?;
    assert_eq!(receiver.receive_wire(&packet, Tick(1))?, Begin::Duplicate);
    // Recursive support ignores the sender receipt; changing this field remains
    // structurally canonical but is not an exact replay of the retained record.
    packet[76..80].copy_from_slice(&1u32.to_be_bytes());
    assert!(wire::inspect(config, &packet).is_ok());
    assert_eq!(
        receiver.receive_wire(&packet, Tick(2)),
        Err(Error::Conflict)
    );
    assert_eq!(receiver.status().terminal, Some(Error::Conflict));
    assert!(receiver.pending_feedback().is_none());
    Ok(())
}
