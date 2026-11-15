use super::*;

#[test]
fn future_original_view_exposes_only_committed_bytes_without_handoff() -> Result<(), Error> {
    let config = Config {
        window: 8,
        local_window: 4,
        global_every: 2,
        max_payload: 8,
        max_rows: 8,
        repair_history: 8,
        handoff_sources: 2,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 1 << 20,
    };
    let scope = Scope {
        session: [7; 16],
        epoch: 3,
        stream: 9,
        direction: 0,
    };
    let mut decoder = Decoder::new(config, scope, Tick(0))?;
    let original = [5, 0, 3, 0];
    decoder.begin_source(scope, SourceId(1), &original, Tick(0))?;
    for _ in 0..10_000 {
        assert_eq!(decoder.decoded_source(SourceId(1))?, None);
        let work = WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        };
        if matches!(decoder.step(Tick(0), work)?, DecodeStep::Accepted { .. }) {
            break;
        }
    }
    assert!(!decoder.status().pending_job);
    let before = decoder.status();
    assert_eq!(before.decoded_prefix, 0);
    assert_eq!(before.handoff_prefix, 0);
    assert_eq!(decoder.pending_source(), None);
    assert_eq!(decoder.decoded_source(SourceId(0))?, None);
    assert_eq!(
        decoder.decoded_source(SourceId(1))?,
        Some(original.as_slice())
    );
    assert_eq!(decoder.decoded_source(SourceId(17))?, None);
    assert_eq!(decoder.status(), before);

    let mut encoder = Encoder::new(config, scope, Tick(0))?;
    encoder.admit_source(&[8, 0], Tick(0))?;
    encoder.admit_source(&original, Tick(0))?;
    encoder.begin_repair(true, Tick(0))?;
    for _ in 0..10_000 {
        if encoder.pending_repair().is_some() {
            break;
        }
        encoder.step(
            Tick(0),
            WorkBudget {
                field: 1,
                copies: 1,
                metadata: 1,
            },
        )?;
    }
    decoder.begin_repair(encoder.pending_repair().ok_or(Error::Identity)?, Tick(0))?;
    for _ in 0..10_000 {
        assert_eq!(decoder.decoded_source(SourceId(0))?, None);
        assert_eq!(
            decoder.decoded_source(SourceId(1))?,
            Some(original.as_slice())
        );
        if matches!(
            decoder.step(
                Tick(0),
                WorkBudget {
                    field: 1,
                    copies: 1,
                    metadata: 1
                }
            )?,
            DecodeStep::Accepted { .. }
        ) {
            break;
        }
    }
    assert_eq!(decoder.decoded_source(SourceId(0))?, Some(&[8, 0][..]));
    decoder.confirm_handoff(SourceId(0), Tick(0))?;
    assert_eq!(decoder.decoded_source(SourceId(0))?, None);
    assert_eq!(
        decoder.decoded_source(SourceId(1))?,
        Some(original.as_slice())
    );
    decoder.confirm_handoff(SourceId(1), Tick(0))?;
    assert_eq!(decoder.decoded_source(SourceId(1))?, None);
    Ok(())
}
