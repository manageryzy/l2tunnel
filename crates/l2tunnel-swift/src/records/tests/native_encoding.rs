use super::*;

fn observed(
    value: ObservedAdmission,
) -> Result<(NativeIdentity, NativeEncodingObservation), Error> {
    match value {
        ObservedAdmission::Accepted { identity, encoding } => Ok((identity, encoding)),
        _ => Err(Error::Admission),
    }
}

#[test]
fn native_observation_preserves_literal_expansion_delta_and_meaningful_zeros() -> Result<(), Error>
{
    let mut engine = Engine::new(config(1))?;
    let channel = ChannelId::new(0).ok_or(Error::Configuration)?;
    let literal = [1, 2, 0, 0];
    let (first, raw) = observed(engine.offer_on_channel_observed(0, channel, &literal)?)?;
    assert_eq!(first.record, NativeRecordId(0));
    assert_eq!(raw.kind, header::EncodingKind::Literal);
    assert_eq!(
        (
            raw.original_native_bytes,
            raw.encoded_body_bytes,
            raw.framing_bytes
        ),
        (4, 5, 2)
    );
    assert_eq!((raw.codec_net_gain_bytes(), raw.net_gain_bytes()), (-1, -3));
    assert_eq!(raw.context_bytes, 0);
    let original = packet(1234, 0, 8);
    let (_, context) = observed(engine.offer_on_channel_observed(0, channel, &original)?)?;
    assert_eq!(context.kind, header::EncodingKind::LiteralContext);
    assert_eq!(
        (context.original_native_bytes, context.encoded_body_bytes),
        (48, 49)
    );
    assert_eq!((context.context_bytes, context.framing_bytes), (0, 2));
    assert_eq!(context.net_gain_bytes(), -3);
    let next = packet(1234, 1, 8);
    let (_, delta) = observed(engine.offer_on_channel_observed(0, channel, &next)?)?;
    assert_eq!(delta.kind, header::EncodingKind::Delta);
    assert_eq!(
        (delta.original_native_bytes, delta.encoded_body_bytes),
        (48, 10)
    );
    assert_eq!(
        (delta.codec_net_gain_bytes(), delta.net_gain_bytes()),
        (38, 36)
    );
    assert_eq!(
        engine.offer_observed(0, &[])?,
        ObservedAdmission::PacketSize
    );
    assert_eq!(engine.stats().native_read, 3);
    let mut peer = Engine::new(config(1))?;
    for number in 0..8 {
        if let Some(bytes) = engine.poll(0, RecordNumber(number), true)? {
            peer.accept(0, RecordNumber(number), &mut bytes.to_vec())?;
        }
    }
    for expected in [&literal[..], &original, &next] {
        assert_eq!(peer.pop()?.ok_or(Error::Admission)?, expected);
    }
    assert!(peer.pop()?.is_none());
    assert_eq!(
        peer.channel_buffer_snapshot(channel)
            .receive
            .ok_or(Error::Admission)?
            .stream_bytes,
        0
    );
    assert_eq!(engine.stats().native_read, 3);
    assert_eq!(engine.stats().sender.packets, 3);
    Ok(())
}

#[test]
fn native_observation_refusal_does_not_allocate_identity_or_advance_context() -> Result<(), Error> {
    let mut settings = config(1);
    settings.codec.queue_bytes = settings.codec.max_packet + crate::FRAME_PREFIX;
    let mut engine = Engine::new(settings)?;
    let channel = ChannelId::new(0).ok_or(Error::Configuration)?;
    let first = packet(1234, 0, 8);
    let next = packet(1234, 1, 8);
    observed(engine.offer_on_channel_observed(0, channel, &first)?)?;
    let retained = engine.channel_buffer_snapshot(channel);
    let send = retained.send.ok_or(Error::Admission)?;
    assert_eq!(send.packing_bytes, 51);
    assert_eq!(
        engine.packing_buffer_snapshot(),
        (51, settings.codec.queue_bytes)
    );
    assert_eq!(
        engine.offer_on_channel_observed(0, channel, &next)?,
        ObservedAdmission::Full
    );
    assert_eq!(engine.stats().native_read, 1);
    assert_eq!(engine.channel_buffer_snapshot(channel), retained);
    assert!(engine.poll(0, RecordNumber(0), true)?.is_some());
    let emitted = engine
        .channel_buffer_snapshot(channel)
        .send
        .ok_or(Error::Admission)?;
    assert_eq!(emitted.packing_bytes, 0);
    assert_eq!(emitted.source_records, 1);
    assert_eq!(emitted.source_bytes, 51);
    let (identity, encoding) = observed(engine.offer_on_channel_observed(0, channel, &next)?)?;
    assert_eq!(identity.record, NativeRecordId(1));
    assert_eq!(encoding.kind, header::EncodingKind::Delta);
    assert_eq!(encoding.encoded_body_bytes, 10);
    engine.admitted[0] = u64::MAX;
    assert_eq!(
        engine.offer_on_channel_observed(0, channel, &next)?,
        ObservedAdmission::Full
    );
    assert!(engine.poll(0, RecordNumber(1), true)?.is_some());
    assert_eq!(
        engine.offer_on_channel_observed(0, channel, &next),
        Err(Error::CounterExhausted)
    );
    assert_eq!(engine.stats().native_read, 2);
    Ok(())
}
