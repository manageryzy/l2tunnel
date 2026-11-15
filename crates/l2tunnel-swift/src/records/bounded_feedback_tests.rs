//! Complete existing feedback blocks under an explicit selected-owner allowance.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn config(channels: usize) -> Config {
    Config {
        channels,
        layer: Layer::Ethernet,
        max_native: 512,
        codec: crate::Config {
            datagram_bytes: 256,
            window: 2,
            repair_numerator: 0,
            repair_denominator: 1,
            flow_sources: 8,
            queue_bytes: 4096,
            max_packet: 513,
            flush_micros: 0,
            feedback_micros: 100,
            tail_micros: 1000,
            min_rto_micros: 1000,
            max_rto_micros: 10000,
        },
    }
}
fn packet(value: u8) -> Vec<u8> {
    let mut bytes = vec![value; 46];
    bytes[..12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    bytes[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    bytes
}
fn drained(channels: usize) -> Result<Engine, Box<dyn std::error::Error>> {
    drained_with_datagram(channels, 256)
}
fn drained_with_datagram(
    channels: usize,
    datagram_bytes: usize,
) -> Result<Engine, Box<dyn std::error::Error>> {
    let mut configuration = config(channels);
    configuration.codec.datagram_bytes = datagram_bytes;
    let mut sender = Engine::new(configuration)?;
    let mut receiver = Engine::new(configuration)?;
    for channel in 0..channels {
        assert!(matches!(
            sender.offer_on_channel_identified(
                0,
                ChannelId::new(channel).ok_or("channel")?,
                &packet(channel as u8)
            )?,
            IdentifiedAdmission::Accepted(_)
        ));
    }
    for number in 0..channels {
        let source = sender
            .poll_emission(0, RecordNumber(number as u64), true)?
            .ok_or("source")?;
        assert_eq!(source.kind(), EmissionKind::Source);
        let mut body = source.body().to_vec();
        receiver.accept(1, RecordNumber(number as u64), &mut body)?;
    }
    for _ in 0..channels {
        assert!(receiver.pop()?.is_some());
    }
    assert!(receiver.pop()?.is_none());
    assert!(receiver.send_drained() && receiver.receive_drained());
    Ok(receiver)
}
fn literal(channel: u8, requests: &[u16]) -> Vec<u8> {
    let mut body = vec![tagged(crate::KIND_FEEDBACK, usize::from(channel))];
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.push(requests.len() as u8);
    for request in requests {
        body.extend_from_slice(&request.to_be_bytes());
    }
    body
}
#[test]
fn legacy_feedback_keeps_worst_case_channel_packing_and_literal_bytes() -> TestResult {
    // One actual 12-byte block plus the next worst-case 140-byte reservation
    // exceeds this real datagram ceiling; the unchanged legacy packer defers it.
    let mut engine = drained_with_datagram(2, 144)?;
    let first = engine
        .poll_emission(1000, RecordNumber(5), false)?
        .ok_or("first feedback")?;
    assert_eq!(first.kind(), EmissionKind::Feedback);
    assert_eq!(first.body(), literal(0, &[]));
    let second = engine
        .poll_emission(1000, RecordNumber(6), false)?
        .ok_or("second feedback")?;
    assert_eq!(second.body(), literal(1, &[]));
    assert_eq!(engine.stats().receiver.feedback, 2);
    Ok(())
}
#[test]
fn too_small_feedback_credit_preserves_debt_and_exact_retry_bytes() -> TestResult {
    let mut engine = drained(1)?;
    let statistics = engine.stats();
    let observation = engine.channel_stats(0);
    let opportunity = engine.feedback_opportunity();
    let scheduling = (engine.feedback_at, engine.feedback_turn);
    assert_eq!(opportunity, Some((100, crate::FEEDBACK_HEADER)));
    assert!(
        engine
            .poll_emission_bounded(1000, RecordNumber(5), false, 11)?
            .is_none()
    );
    assert_eq!(engine.stats(), statistics);
    assert_eq!(engine.channel_stats(0), observation);
    assert_eq!(engine.feedback_opportunity(), opportunity);
    assert_eq!((engine.feedback_at, engine.feedback_turn), scheduling);
    let feedback = engine
        .poll_emission_bounded(1000, RecordNumber(5), false, 12)?
        .ok_or("complete 12-byte feedback")?;
    assert_eq!(feedback.kind(), EmissionKind::Feedback);
    assert_eq!(feedback.body(), literal(0, &[]));
    assert_eq!(engine.stats().receiver.feedback, 1);
    Ok(())
}
#[test]
fn bounded_feedback_serves_whole_channels_and_never_consumes_underfunded_data() -> TestResult {
    let mut engine = drained(3)?;
    let before_capacity = (engine.body.capacity(), engine.block.capacity());
    let first = engine
        .poll_emission_bounded(1000, RecordNumber(5), false, 24)?
        .ok_or("two channel blocks")?;
    let mut expected = literal(0, &[]);
    expected.extend_from_slice(&literal(1, &[]));
    assert_eq!(first.body(), expected);
    assert_eq!(engine.feedback_turn, 2);
    let second = engine
        .poll_emission_bounded(1000, RecordNumber(6), false, 12)?
        .ok_or("last channel block")?;
    assert_eq!(second.body(), literal(2, &[]));
    assert_eq!(engine.stats().receiver.feedback, 3);
    assert_eq!(
        (engine.body.capacity(), engine.block.capacity()),
        before_capacity
    );
    let mut data = Engine::new(config(1))?;
    assert!(matches!(
        data.offer_on_channel_identified(0, ChannelId::new(0).ok_or("channel")?, &packet(91))?,
        IdentifiedAdmission::Accepted(_)
    ));
    let before = data.channel_stats(0);
    let statistics = data.stats();
    assert!(
        data.poll_emission_bounded(0, RecordNumber(9), true, 255)?
            .is_none()
    );
    assert_eq!(data.channel_stats(0), before);
    assert_eq!(data.stats(), statistics);
    assert_eq!(
        data.poll_emission_bounded(0, RecordNumber(9), true, 256)?
            .ok_or("full source allowance")?
            .kind(),
        EmissionKind::Source
    );
    Ok(())
}
#[test]
fn a_missing_source_feedback_block_is_never_truncated_to_fit() -> TestResult {
    let mut sender = Engine::new(config(1))?;
    let mut receiver = Engine::new(config(1))?;
    for value in 0..2 {
        sender.offer_on_channel_identified(
            0,
            ChannelId::new(0).ok_or("channel")?,
            &packet(value),
        )?;
        let source = sender
            .poll_emission(0, RecordNumber(u64::from(value)), true)?
            .ok_or("source")?;
        if value == 1 {
            let mut body = source.body().to_vec();
            receiver.accept(1, RecordNumber(1), &mut body)?;
        }
    }
    // First feedback records the actual end. The next unchanged-end feedback
    // requests missing source zero through the original authoritative algorithm.
    receiver
        .poll_emission_bounded(1000, RecordNumber(5), false, 256)?
        .ok_or("initial gap feedback")?;
    let before = receiver.stats();
    let opportunity = receiver.feedback_opportunity();
    assert_eq!(opportunity, Some((1100, 14)));
    assert!(
        receiver
            .poll_emission_bounded(1100, RecordNumber(6), false, 13)?
            .is_none()
    );
    assert_eq!(receiver.stats(), before);
    assert_eq!(receiver.feedback_opportunity(), opportunity);
    let feedback = receiver
        .poll_emission_bounded(1100, RecordNumber(6), false, 14)?
        .ok_or("complete gap request")?;
    assert_eq!(feedback.body().len(), 14);
    assert_eq!(feedback.body()[crate::FEEDBACK_HEADER - 1], 1);
    assert_eq!(
        &feedback.body()[crate::FEEDBACK_HEADER..],
        &0u16.to_be_bytes()
    );
    Ok(())
}
