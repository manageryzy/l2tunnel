use super::*;

fn config() -> Config {
    Config {
        window: 8,
        local_window: 4,
        global_every: 1,
        max_payload: 8,
        max_rows: 1,
        repair_history: 8,
        handoff_sources: 1,
        job_ticks: 100,
        debt_ticks: 1_000,
        handoff_ticks: 500,
        memory_bytes: 1 << 20,
    }
}

fn scope() -> Scope {
    Scope {
        session: [0x6b; 16],
        epoch: 2,
        stream: 5,
        direction: 1,
    }
}

fn budget() -> WorkBudget {
    WorkBudget {
        field: 1,
        copies: 1,
        metadata: 1,
    }
}

// This independent oracle reads the actual committed identity cells, including
// while a different ticket owns partially changed rows or header metadata.
fn check_snapshot(decoder: &Decoder) -> Result<(u32, u32, u32), Error> {
    let mut unknown = 0_u32;
    for id in decoder.live.prefix..decoder.live.observed {
        if decoder.live_known(id as usize % (2 * decoder.config.window))? != Some(id) {
            unknown += 1;
        }
    }
    let expected = (
        decoder.live.prefix,
        decoder.live.observed,
        unknown.saturating_sub(decoder.live.rank as u32),
    );
    assert_eq!(decoder.feedback_state()?, expected);
    Ok(expected)
}

fn finish(decoder: &mut Decoder) -> Result<DecodeStep, Error> {
    for _ in 0..100_000 {
        check_snapshot(decoder)?;
        let step = decoder.step(Tick(0), budget())?;
        check_snapshot(decoder)?;
        if !matches!(step, DecodeStep::Pending(_)) {
            return Ok(step);
        }
    }
    Err(Error::WorkLimit)
}

fn repair(encoder: &mut Encoder) -> Result<(RepairId, Support, Vec<u8>), Error> {
    encoder.begin_repair(true, Tick(0))?;
    for _ in 0..100_000 {
        if let Some(value) = encoder.pending_repair() {
            let packet = (value.id, value.support, value.bytes.to_vec());
            encoder.confirm_repair(value.id, Tick(0))?;
            return Ok(packet);
        }
        encoder.step(Tick(0), budget())?;
    }
    Err(Error::WorkLimit)
}

fn stage(decoder: &mut Decoder, packet: &(RepairId, Support, Vec<u8>)) -> Result<(), Error> {
    assert_eq!(
        decoder.begin_repair(
            Repair {
                scope: scope(),
                id: packet.0,
                support: packet.1,
                bytes: &packet.2,
            },
            Tick(0),
        )?,
        Begin::Staged
    );
    Ok(())
}

#[test]
fn committed_snapshot_matches_columns_through_lagging_eviction_and_ring_reuse() -> Result<(), Error>
{
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    let mut saw_lagging_eviction = false;
    for batch in 0..12_u32 {
        let first = batch * 4;
        for id in (first..first + 4).rev() {
            decoder.begin_source(scope(), SourceId(id), &id.to_be_bytes(), Tick(0))?;
            assert!(matches!(finish(&mut decoder)?, DecodeStep::Accepted { .. }));
        }
        for id in first..first + 4 {
            assert_eq!(
                decoder.pending_source(),
                Some((SourceId(id), id.to_be_bytes().as_slice()))
            );
            decoder.confirm_handoff(SourceId(id), Tick(0))?;
            saw_lagging_eviction |= decoder.live.evicted_before
                < decoder.live.prefix.saturating_sub(config().window as u32);
            check_snapshot(&decoder)?;
        }
        assert_eq!(decoder.feedback_state()?, (first + 4, first + 4, 0));
    }
    assert!(saw_lagging_eviction);
    Ok(())
}

#[test]
fn committed_snapshot_ignores_gf_shadow_capacity_abort_and_expiry() -> Result<(), Error> {
    let mut encoder = Encoder::new(config(), scope(), Tick(0))?;
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    for bytes in [&[11, 12][..], &[21, 22], &[31, 32]] {
        encoder.admit_source(bytes, Tick(0))?;
    }
    let first = repair(&mut encoder)?;
    let second = repair(&mut encoder)?;
    stage(&mut decoder, &first)?;
    let mut saw_unpublished_rank = false;
    for _ in 0..100_000 {
        check_snapshot(&decoder)?;
        let result = decoder.step(Tick(0), budget())?;
        saw_unpublished_rank |= decoder.shadow.rank != decoder.live.rank;
        check_snapshot(&decoder)?;
        if !matches!(result, DecodeStep::Pending(_)) {
            assert!(matches!(result, DecodeStep::Accepted { .. }));
            break;
        }
    }
    assert!(saw_unpublished_rank);
    assert!(!decoder.status().pending_job);
    assert_eq!(decoder.status().rank, 1);
    let committed = check_snapshot(&decoder)?;
    stage(&mut decoder, &second)?;
    assert!(matches!(finish(&mut decoder)?, DecodeStep::Capacity(_)));
    assert_eq!(check_snapshot(&decoder)?, committed);
    assert!(!decoder.status().pending_job);

    decoder.begin_source(scope(), SourceId(2), &[31, 32], Tick(0))?;
    for _ in 0..100_000 {
        if matches!(
            decoder.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::Store { index: 1.., .. }
        ) {
            break;
        }
        assert!(matches!(
            decoder.step(Tick(0), budget())?,
            DecodeStep::Pending(_)
        ));
        assert_eq!(check_snapshot(&decoder)?, committed);
    }
    assert!(matches!(
        decoder.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Store { index: 1.., .. }
    ));
    assert_eq!(check_snapshot(&decoder)?, committed);
    assert_eq!(
        decoder.step(Tick(config().job_ticks), budget()),
        Err(Error::Expired)
    );
    assert_eq!(check_snapshot(&decoder)?, committed);
    Ok(())
}

#[test]
fn snapshot_rejects_inconsistent_committed_arithmetic() -> Result<(), Error> {
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    for live in [
        Header {
            prefix: 1,
            ..Header::default()
        },
        Header {
            evicted_before: 1,
            ..Header::default()
        },
        Header {
            known_count: 1,
            ..Header::default()
        },
        Header {
            prefix: 2,
            observed: 1,
            known_count: 2,
            ..Header::default()
        },
    ] {
        decoder.live = live;
        assert_eq!(decoder.feedback_state(), Err(Error::Identity));
    }
    Ok(())
}
