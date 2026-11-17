//! Actual Swift preparation, authentication input and delayed carrier ownership.
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn prepared(
    engine: &mut Engine,
    now: u64,
    number: u64,
    allow: bool,
) -> TestResult<(PreparedOutput, Vec<u8>)> {
    let maximum = engine.send_config().codec.datagram_bytes;
    let emission = engine
        .prepare_emission_with_limits(now, RecordNumber(number), allow, maximum, maximum)?
        .ok_or("actual prepared output")?;
    let bytes = emission.body().to_vec();
    Ok((engine.pending_output().ok_or("retained witness")?, bytes))
}
fn offer(engine: &mut Engine, now: u64, counter: u32) -> TestResult<Vec<u8>> {
    let native = packet(40_000, counter, 20);
    engine.offer_on_channel_identified(now, ChannelId::new(0).ok_or("channel")?, &native)?;
    Ok(native)
}
fn feedback(base: u32, end: u32, requests: &[u16]) -> Vec<u8> {
    let mut body = vec![crate::KIND_FEEDBACK];
    body.extend_from_slice(&base.to_be_bytes());
    body.extend_from_slice(&end.to_be_bytes());
    body.extend_from_slice(&(requests.len() as u16).to_be_bytes());
    body.push(requests.len() as u8);
    for offset in requests {
        body.extend_from_slice(&offset.to_be_bytes());
    }
    body
}
fn reserved(config: Config) -> TestResult<crate::storage::Owned> {
    let plan = crate::storage::Plan::for_engine(config, config)?;
    Ok(crate::storage::Owned::new(
        plan,
        crate::storage::Limits {
            capacity_bytes: plan.capacity_bytes() + std::mem::size_of::<crate::storage::Owned>(),
        },
    )?)
}
#[test]
fn prepared_source_and_retry_use_actual_acceptance_and_suppress_pending_attempts() -> TestResult {
    let mut owned = reserved(config(1))?;
    let original = owned.usage();
    let native = packet(40_000, 0, 20);
    owned.entry().offer(10, &native)?;
    let bytes = {
        let mut entry = owned.entry();
        entry
            .prepare_emission_with_limits(10, RecordNumber(1), true, 256, 256)?
            .ok_or("first source")?
            .body()
            .to_vec()
    };
    let first = owned.engine().pending_output().ok_or("first witness")?;
    assert!(owned.engine().data_deadline().is_none());
    assert!(!owned.engine().data_ready(10_000));
    assert!(bytes.len() < 256, "short source stays short");
    assert_eq!(owned.engine().senders[0].stats().smoothed_rtt_micros, 0);
    owned.entry().confirm_output_at(10_001, 10_000, first)?;
    owned
        .entry()
        .accept(20_000, RecordNumber(10), &mut feedback(0, 1, &[0]))?;
    assert_eq!(
        owned.engine().senders[0].stats().smoothed_rtt_micros,
        10_000
    );
    assert_eq!(
        owned.engine().senders[0].observation().retransmit_pending,
        1
    );
    let retry_bytes = owned
        .entry()
        .prepare_emission_with_limits(20_000, RecordNumber(2), true, 256, 256)?
        .ok_or("requested retry")?
        .body()
        .to_vec();
    let retry = owned.engine().pending_output().ok_or("retry witness")?;
    assert_eq!(retry_bytes, bytes);
    owned
        .entry()
        .accept(40_000, RecordNumber(11), &mut feedback(0, 1, &[0]))?;
    assert_eq!(
        owned.engine().senders[0].observation().retransmit_pending,
        0
    );
    let repeated = owned
        .entry()
        .prepare_emission_with_limits(40_001, RecordNumber(999), false, 0, 0)?
        .ok_or("same pending record")?
        .body()
        .to_vec();
    assert_eq!(repeated, retry_bytes);
    assert_eq!(owned.engine().pending_output(), Some(retry));
    owned.entry().confirm_output_at(50_001, 50_000, retry)?;
    owned
        .entry()
        .accept(59_999, RecordNumber(12), &mut feedback(0, 1, &[0]))?;
    assert_eq!(
        owned.engine().senders[0].observation().retransmit_pending,
        0
    );
    owned
        .entry()
        .accept(60_000, RecordNumber(13), &mut feedback(0, 1, &[0]))?;
    assert_eq!(
        owned.engine().senders[0].observation().retransmit_pending,
        1
    );
    assert_eq!(owned.usage(), original);
    Ok(())
}
#[test]
fn older_copy_ack_cannot_consume_pending_retry_or_enable_epoch_drain() -> TestResult {
    let mut engine = Engine::new(config(1))?;
    offer(&mut engine, 10, 0)?;
    let (first, _) = prepared(&mut engine, 10, 1, true)?;
    assert_eq!(
        engine.confirm_output_at(99, 100, first),
        Err(Error::OutputTime)
    );
    assert_eq!(engine.pending_output(), Some(first));
    engine.confirm_output_at(100, 100, first)?;
    engine.accept(200, RecordNumber(10), &mut feedback(0, 1, &[0]))?;
    let (retry, _) = prepared(&mut engine, 200, 2, true)?;
    engine.accept(300, RecordNumber(11), &mut feedback(1, 1, &[]))?;
    assert_eq!(engine.unconfirmed(), 0);
    assert!(!engine.send_drained());
    assert_eq!(
        engine.replace_send(config(1), RecordNumber(12)),
        Err(Error::NotDrained)
    );
    assert_eq!(engine.pending_output(), Some(retry));
    engine.confirm_output_at(400, 250, retry)?;
    assert!(engine.send_drained());
    assert_eq!(engine.unconfirmed(), 0);
    assert!(engine.data_deadline().is_none());
    assert_eq!(
        engine.confirm_output_at(400, 250, retry),
        Err(Error::OutputToken)
    );
    Ok(())
}
#[test]
fn earned_and_tail_repairs_keep_exact_seed_bytes_and_recover_lost_short_source() -> TestResult {
    for numerator in [0, 1] {
        let mut c = config(1);
        c.codec.repair_numerator = numerator;
        c.codec.repair_denominator = 1;
        let mut sender = Engine::new(c)?;
        let mut reference = Engine::new(c)?;
        let mut receiver = Engine::new(c)?;
        let native = offer(&mut sender, 10, 0)?;
        offer(&mut reference, 10, 0)?;
        let (source, source_bytes) = prepared(&mut sender, 10, 1, true)?;
        assert_eq!(body(&mut reference, 1000, 1, true)?, source_bytes);
        sender.confirm_output_at(1000, 1000, source)?;
        let due = if numerator == 0 { 2000 } else { 1001 };
        let (repair, wire) = prepared(&mut sender, due, 2, true)?;
        assert_eq!(repair.kind(), EmissionKind::Repair);
        assert_eq!(body(&mut reference, due, 2, true)?, wire);
        assert_eq!(prepared(&mut sender, 6000, 999, false)?.0, repair);
        // The source was deliberately lost; one actual GF equation restores it.
        receiver.accept(6000, RecordNumber(2), &mut wire.clone())?;
        assert_eq!(receiver.pop()?.ok_or("GF-restored short native")?, native);
        sender.confirm_output_at(6000, 5000, repair)?;
        if numerator == 0 {
            assert_eq!(sender.senders[0].deadline(), Some(15_000));
        }
    }
    Ok(())
}
#[test]
fn delayed_tail_acceptance_cannot_overwrite_newer_feedback_probe_state() -> TestResult {
    let mut sender = Engine::new(config(1))?;
    offer(&mut sender, 10, 0)?;
    let (first, _) = prepared(&mut sender, 10, 1, true)?;
    sender.confirm_output_at(1000, 1000, first)?;
    let (tail, _) = prepared(&mut sender, 2000, 2, true)?;
    sender.accept(5500, RecordNumber(20), &mut feedback(0, 1, &[]))?;
    let newer = sender.senders[0].deadline();
    assert_eq!(newer, Some(15_500));
    sender.confirm_output_at(6000, 5000, tail)?;
    assert_eq!(sender.senders[0].deadline(), newer);
    Ok(())
}
#[test]
fn frozen_feedback_commits_only_its_report_and_preserves_new_dirty_event() -> TestResult {
    let mut sender = Engine::new(config(1))?;
    let mut receiver = Engine::new(config(1))?;
    offer(&mut sender, 0, 0)?;
    let _lost = body(&mut sender, 0, 1, true)?;
    offer(&mut sender, 10, 1)?;
    receiver.accept(20, RecordNumber(2), &mut body(&mut sender, 10, 2, true)?)?;
    let (report, original) = prepared(&mut receiver, 100, 10, false)?;
    assert!(!receiver.feedback_ready(200));
    assert!(receiver.feedback_deadline().is_none());
    assert!(receiver.feedback_opportunity().is_none());
    assert_eq!(u32::from_be_bytes(original[5..9].try_into()?), 2);
    assert_eq!(original[11], 0);
    offer(&mut sender, 110, 2)?;
    receiver.accept(150, RecordNumber(3), &mut body(&mut sender, 110, 3, true)?)?;
    assert_eq!(prepared(&mut receiver, 200, 11, false)?.1, original);
    receiver.confirm_output_at(200, 120, report)?;
    let (next, bytes) = prepared(&mut receiver, 220, 11, false)?;
    assert_eq!(u32::from_be_bytes(bytes[5..9].try_into()?), 3);
    assert_eq!(
        bytes[11], 0,
        "later source was not in the frozen reported_end"
    );
    receiver.confirm_output_at(220, 220, next)?;
    Ok(())
}
