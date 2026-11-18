//! Codec caps follow original bytes across real recovery admission, not a busy cohort.
use super::*;

fn stage_config() -> Config {
    let mut config = config(true, rolling::wire::SourceWire::Exact);
    config.forward.packing.max_units = 1;
    config.forward.codec_stage_micros = 1000;
    config
}

// Consume only actual prepared output. Stop with the requested source retained
// by recovery so a subsequent sealed source experiences real admission pressure.
fn admit_next<P: RecoveryPolicy>(owner: &mut Endpoint<P>, now: Tick, target: u32) -> TestResult {
    let mut bytes = [0; rolling::wire::MAX_RECORD_BYTES];
    let mut witnesses = [witness(); 4];
    for number in 1..=64 {
        owner.step(now, work())?;
        let next = P::send_state(&owner.sender).encoder.next_source;
        assert!(next <= target);
        if next == target {
            return Ok(());
        }
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 10000,
        };
        if let Some(output) =
            owner.prepare_output(now, number, true, &mut bytes, &mut budget, &mut witnesses)?
        {
            owner.confirm_output(now, output)?;
        }
    }
    Err("bounded recovery source progress did not complete".into())
}

fn continuous<P: RecoveryPolicy>(config: Config<P>) -> TestResult {
    let mut owner = observed(config, Role::Client)?;
    owner.enable_compact_wire(53)?;
    let usage = owner.storage_usage();
    let cap = config.forward.codec_stage_micros;
    owner
        .enqueue_admitted_identified(Tick(1), 0, &packet(true, 1, 48))?
        .ok_or("first frame")?;
    owner.flush(Tick(1))?;
    assert_eq!(P::send_state(&owner.sender).encoder.next_source, 1);
    assert_eq!(owner.stage_deadline, None);

    owner
        .enqueue_admitted_identified(Tick(400), 0, &packet(true, 2, 48))?
        .ok_or("sealed second frame")?;
    owner.flush(Tick(400))?;
    owner
        .enqueue_admitted_identified(Tick(800), 0, &packet(true, 3, 48))?
        .ok_or("third frame behind second source")?;
    assert!(owner.packing.status().staged_frame);
    assert_eq!(owner.stage_deadline, Some(Tick(400 + cap)));
    admit_next(&mut owner, Tick(900), 2)?;
    assert!(!owner.packing.is_idle());
    assert_eq!(owner.packing.oldest_admission_micros(), Some(800));
    assert_eq!(owner.stage_deadline, Some(Tick(800 + cap)));

    owner
        .enqueue_admitted_identified(Tick(1200), 0, &packet(true, 4, 48))?
        .ok_or("continuous fourth frame")?;
    // The second frame's former codec deadline is inclusive but no longer
    // belongs to codec-held bytes. The third frame keeps its original cap.
    admit_next(&mut owner, Tick(1400), 3)?;
    assert!(!owner.packing.is_idle());
    assert_eq!(owner.packing.oldest_admission_micros(), Some(1200));
    assert_eq!(owner.stage_deadline, Some(Tick(1200 + cap)));
    owner
        .enqueue_admitted_identified(Tick(1600), 0, &packet(true, 5, 48))?
        .ok_or("continuous fifth frame")?;
    owner.advance(Tick(1800))?;
    assert_eq!(owner.stage_deadline, Some(Tick(2200)));
    assert_eq!(owner.storage_usage(), usage);

    // Real old custody still expires at its original cap despite newer input.
    owner.advance(Tick(2199))?;
    assert_eq!(owner.advance(Tick(2200)), Err(Error::Expired));
    let failure = owner
        .expiry_snapshot()
        .local_failure
        .ok_or("codec expiry")?;
    assert_eq!(failure.owner, expiry::LocalOwner::CodecStage);
    assert_eq!(failure.deadline, Tick(2200));
    assert_eq!(failure.observed, Tick(2200));
    Ok(())
}

#[test]
fn continuous_refill_retires_only_transferred_codec_deadlines() -> TestResult {
    let config = stage_config();
    continuous(config)?;
    continuous(research_config(config))
}

fn fragment_tail<P: RecoveryPolicy>(config: Config<P>) -> TestResult {
    let mut owner = observed(config, Role::Client)?;
    owner.enable_compact_wire(53)?;
    owner
        .enqueue_admitted_identified(Tick(1), 0, &packet(true, 7, 800))?
        .ok_or("fragmented native frame")?;
    owner.flush(Tick(1))?;
    assert_eq!(P::send_state(&owner.sender).encoder.next_source, 1);
    assert!(owner.packing.status().staged_frame);
    assert_eq!(owner.stage_deadline, Some(Tick(1001)));
    admit_next(&mut owner, Tick(500), 2)?;
    assert_eq!(owner.packing.oldest_admission_micros(), Some(1));
    assert_eq!(owner.stage_deadline, Some(Tick(1001)));
    assert!(
        owner
            .enqueue_admitted_identified(Tick(700), 0, &packet(true, 8, 48))?
            .is_none()
    );
    owner.advance(Tick(1000))?;
    assert_eq!(owner.advance(Tick(1001)), Err(Error::Expired));
    let failure = owner
        .expiry_snapshot()
        .local_failure
        .ok_or("fragment expiry")?;
    assert_eq!(failure.owner, expiry::LocalOwner::CodecStage);
    assert_eq!(failure.deadline, Tick(1001));
    Ok(())
}

#[test]
fn fragmented_old_frame_and_refused_refill_preserve_original_codec_cap() -> TestResult {
    let config = stage_config();
    fragment_tail(config)?;
    fragment_tail(research_config(config))
}
