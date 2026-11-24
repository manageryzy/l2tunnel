//! RRP-05: abandoning the oldest unrecoverable hole.
use super::*;

type TestResult = Result<(), Error>;

const BUDGET: WorkBudget = WorkBudget {
    field: 64,
    copies: 64,
    metadata: 64,
};

fn config() -> Config {
    Config {
        window: 8,
        local_window: 3,
        global_every: 2,
        max_payload: 8,
        max_rows: 8,
        repair_history: 8,
        handoff_sources: 8,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 1 << 20,
    }
}

fn scope() -> Scope {
    Scope {
        session: [7; 16],
        epoch: 3,
        stream: 9,
        direction: 0,
    }
}

fn original(id: u32) -> [u8; 3] {
    [id as u8 + 1, 0xa5, id as u8]
}

fn settle(decoder: &mut Decoder) -> TestResult {
    for _ in 0..10_000 {
        if let DecodeStep::Idle(_) = decoder.step(Tick(0), BUDGET)? {
            return Ok(());
        }
    }
    Err(Error::WorkLimit)
}

fn source(decoder: &mut Decoder, id: u32) -> Result<Begin, Error> {
    let begin = decoder.begin_source(scope(), SourceId(id), &original(id), Tick(0))?;
    settle(decoder)?;
    Ok(begin)
}

/// Build the next tail (global) or regular repair and feed it to the decoder.
fn repair(
    encoder: &mut Encoder,
    decoder: &mut Decoder,
    tail: bool,
) -> Result<(Begin, Support), Error> {
    let id = encoder.begin_repair(tail, Tick(0))?;
    for _ in 0..10_000 {
        if encoder.pending_repair().is_some() {
            break;
        }
        encoder.step(Tick(0), BUDGET)?;
    }
    let pending = encoder.pending_repair().ok_or(Error::Identity)?;
    let support = pending.support;
    let begin = decoder.begin_repair(pending, Tick(0))?;
    encoder.confirm_repair(id, Tick(0))?;
    settle(decoder)?;
    Ok((begin, support))
}

fn encoder(sources: u32) -> Result<Encoder, Error> {
    let mut encoder = Encoder::new(config(), scope(), Tick(0))?;
    for id in 0..sources {
        encoder.admit_source(&original(id), Tick(0))?;
    }
    Ok(encoder)
}

fn hand_off(decoder: &mut Decoder) -> Result<Vec<u32>, Error> {
    let mut handed = Vec::new();
    while let Some((id, bytes)) = decoder.pending_source() {
        assert_eq!(bytes, original(id.0));
        handed.push(id.0);
        decoder.confirm_handoff(id, Tick(0))?;
    }
    Ok(handed)
}

#[test]
fn free_column_is_passed_over_and_a_late_original_is_stale() -> TestResult {
    let mut decoder = Decoder::new_sliding(config(), scope(), Tick(0))?;
    source(&mut decoder, 1)?;
    source(&mut decoder, 2)?;
    assert_eq!(decoder.status().decoded_prefix, 0);
    assert_eq!(decoder.pending_source(), None);

    assert_eq!(decoder.abandon_prefix(Tick(0))?, Some(SourceId(0)));
    let status = decoder.status();
    assert_eq!(status.decoded_prefix, 3);
    assert_eq!(status.handoff_prefix, 1);
    assert_eq!(decoder.feedback_state()?, (3, 3, 0));
    assert_eq!(decoder.decoded_source(SourceId(0))?, None);
    assert!(decoder.is_abandoned(0)?);
    assert_eq!(hand_off(&mut decoder)?, [1, 2]);

    // Nothing more to abandon.
    assert_eq!(decoder.abandon_prefix(Tick(0))?, None);
    // The lost original arrives late: stale, never a conflict or terminal.
    assert_eq!(source(&mut decoder, 0)?, Begin::Stale);
    assert_eq!(
        decoder.abandon_status(),
        AbandonStatus {
            abandoned: 1,
            dropped_repairs: 0,
            late_originals: 1,
            dropped_rows: 0,
        }
    );
    assert_eq!(decoder.status().terminal, None);
    Ok(())
}

#[test]
fn pivot_row_is_dropped_and_later_repairs_still_recover_other_sources() -> TestResult {
    let mut encoder = encoder(4)?;
    let mut decoder = Decoder::new_sliding(config(), scope(), Tick(0))?;
    // Sources 0 and 1 are lost; 2 and 3 arrive.
    source(&mut decoder, 2)?;
    source(&mut decoder, 3)?;
    // One global repair over [0, 4): one equation, two unknowns.
    let (_, support) = repair(&mut encoder, &mut decoder, true)?;
    assert_eq!((support.start, support.end), (0, 4));
    assert_eq!(decoder.status().rank, 1);

    assert_eq!(decoder.abandon_prefix(Tick(0))?, Some(SourceId(0)));
    let status = decoder.status();
    assert_eq!(status.rank, 0);
    assert_eq!(status.decoded_prefix, 1);
    assert_eq!(status.handoff_prefix, 1);
    assert_eq!(decoder.feedback_state()?, (1, 4, 1));

    // A later repair that still includes source 0 is dropped whole.
    let (begin, support) = repair(&mut encoder, &mut decoder, true)?;
    assert_eq!(support.start, 0);
    assert_eq!(begin, Begin::Staged);
    assert_eq!(decoder.status().rank, 0);
    assert_eq!(decoder.status().decoded_prefix, 1);
    assert_eq!(decoder.abandon_status().dropped_repairs, 1);

    // Repair 3 is local, over [1, 4): it recovers source 1.
    let (_, support) = repair(&mut encoder, &mut decoder, false)?;
    assert_eq!((support.start, support.end), (1, 4));
    assert_eq!(decoder.status().decoded_prefix, 4);
    assert_eq!(hand_off(&mut decoder)?, [1, 2, 3]);
    assert_eq!(
        decoder.abandon_status(),
        AbandonStatus {
            abandoned: 1,
            dropped_repairs: 1,
            late_originals: 0,
            dropped_rows: 1,
        }
    );
    Ok(())
}

#[test]
fn abandonment_waits_for_a_staged_job_and_respects_handoff() -> TestResult {
    let mut decoder = Decoder::new_sliding(config(), scope(), Tick(0))?;
    // No hole yet.
    assert_eq!(decoder.abandon_prefix(Tick(0))?, None);
    source(&mut decoder, 0)?;
    // Source 1 is lost; 2 is staged but not stepped.
    decoder.begin_source(scope(), SourceId(2), &original(2), Tick(0))?;
    assert_eq!(decoder.abandon_prefix(Tick(0)), Err(Error::Busy));
    assert_eq!(decoder.status().terminal, None);
    settle(&mut decoder)?;

    // The upper owner has not taken source 0 yet: the hole at 1 is abandoned,
    // and handoff skips it only once source 0 is confirmed.
    assert_eq!(decoder.abandon_prefix(Tick(0))?, Some(SourceId(1)));
    assert_eq!(decoder.status().decoded_prefix, 3);
    assert_eq!(decoder.status().handoff_prefix, 0);
    assert_eq!(hand_off(&mut decoder)?, [0, 2]);
    assert_eq!(decoder.status().handoff_prefix, 3);
    Ok(())
}

#[test]
fn abandoned_slots_are_evicted_and_reused_by_later_sources() -> TestResult {
    let config = config();
    let mut decoder = Decoder::new_sliding(config, scope(), Tick(0))?;
    let total = 6 * config.window as u32;
    for id in 0..total {
        // Every third source is lost.
        if id % 3 == 0 {
            continue;
        }
        source(&mut decoder, id)?;
        if decoder.status().decoded_prefix < id {
            assert_eq!(decoder.abandon_prefix(Tick(0))?, Some(SourceId(id - 1)));
        }
        let handed = hand_off(&mut decoder)?;
        assert!(handed.iter().all(|id| id % 3 != 0));
    }
    let status = decoder.status();
    assert_eq!(status.decoded_prefix, total);
    assert_eq!(status.handoff_prefix, total);
    assert_eq!(decoder.abandon_status().abandoned, u64::from(total / 3));
    let (prefix, observed, deficit) = decoder.feedback_state()?;
    assert_eq!((prefix, observed, deficit), (total, total, 0));
    assert!(status.known_sources <= 2 * config.window);
    Ok(())
}
