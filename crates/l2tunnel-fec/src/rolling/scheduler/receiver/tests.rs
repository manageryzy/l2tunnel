use super::*;

#[test]
fn feedback_identity_exhaustion_is_terminal_without_reusing_a_wire_identity() -> Result<(), Error> {
    let policy = Policy {
        recovery: Config {
            window: 1,
            local_window: 1,
            global_every: 1,
            max_payload: 1,
            max_rows: 1,
            repair_history: 1,
            handoff_sources: 1,
            job_ticks: 10,
            debt_ticks: 100,
            handoff_ticks: 20,
            memory_bytes: 1 << 20,
        },
        repair_numerator: 0,
        repair_denominator: 1,
        tail_ticks: 5,
        feedback_ticks: 2,
        feedback_packets: 1,
        memory_bytes: 1 << 20,
    };
    let scope = Scope {
        session: [1; 16],
        epoch: 1,
        stream: 1,
        direction: 0,
    };
    let mut receiver = Receiver::new(policy, scope, Tick(0))?;
    receiver.next_feedback = u64::MAX - 1;
    let mut source = [0; 67];
    wire::encode_source(policy.recovery, scope, SourceId(0), b"x", &mut source)?;
    receiver.receive_wire(&source, Tick(0))?;
    receiver.step(
        Tick(0),
        WorkBudget {
            field: 65536,
            copies: 65536,
            metadata: 65536,
        },
    )?;
    assert_eq!(
        receiver.pending_feedback().map(|f| f.id),
        Some(FeedbackId(u64::MAX - 1))
    );
    receiver.confirm_feedback(FeedbackId(u64::MAX - 1), Tick(0))?;
    assert_eq!(receiver.receive_wire(&source, Tick(0))?, Begin::Duplicate);
    assert_eq!(
        receiver.step(
            Tick(0),
            WorkBudget {
                metadata: 1,
                ..WorkBudget::default()
            }
        ),
        Err(Error::Exhausted)
    );
    assert_eq!(receiver.status().terminal, Some(Error::Exhausted));
    assert!(!receiver.status().feedback_building);
    assert!(receiver.pending_feedback_wire().is_none());
    assert_eq!(receiver.status().decoder.decoded_prefix, 1);
    Ok(())
}
