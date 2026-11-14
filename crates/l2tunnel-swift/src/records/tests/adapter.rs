//! Actual-owner admission and emission regressions for the common MUX adapter.

use super::native_identity::snapshot;
use super::*;

fn channel(index: usize) -> Result<ChannelId, Error> {
    ChannelId::new(index).ok_or(Error::Configuration)
}

#[test]
fn caller_channel_controls_real_identity_and_independent_header_contexts() -> Result<(), Error> {
    for layer in [Layer::Ip, Layer::Ethernet] {
        let mut c = config(2);
        c.layer = layer;
        let mut sender = Engine::new(c)?;
        let mut receiver = Engine::new(c)?;
        let mut natives = Vec::new();
        for ordinal in 0..3 {
            let ip = packet(40_000, ordinal, 16);
            let native = if layer == Layer::Ethernet {
                let mut frame = vec![0x11; 12];
                frame.extend_from_slice(&[0x08, 0x00]);
                frame.extend_from_slice(&ip);
                frame
            } else {
                ip
            };
            let classified = match layer {
                Layer::Ip => crate::flow::classify_ip(&native, 2),
                Layer::Ethernet => crate::flow::classify_ethernet(&native, 2),
            };
            // The same flow is deliberately installed in both real channels;
            // each compressor/decompressor must maintain its own first header.
            for index in [1 - classified, classified] {
                assert_eq!(
                    sender.offer_on_channel_identified(0, channel(index)?, &native)?,
                    IdentifiedAdmission::Accepted(NativeIdentity {
                        channel: channel(index)?,
                        record: NativeRecordId(u64::from(ordinal)),
                    }),
                );
            }
            natives.push(native);
        }
        let mut number = 1_u64 << 40;
        while let Some(emission) = sender.poll_emission(0, RecordNumber(number), true)? {
            assert_eq!(emission.kind(), EmissionKind::Source);
            let mut wire = emission.body().to_vec();
            receiver.accept(0, RecordNumber(number), &mut wire)?;
            number += 1;
        }
        for (ordinal, native) in natives.iter().enumerate() {
            for index in 0..2 {
                let popped = receiver.pop_identified()?.ok_or(Error::Admission)?;
                assert_eq!(popped.identity.channel, channel(index)?);
                assert_eq!(popped.identity.record, NativeRecordId(ordinal as u64));
                assert_eq!(popped.bytes, native);
            }
        }
        assert!(receiver.pop_identified()?.is_none());
        assert!(sender.stats().header_bytes_saved > 0);
    }
    Ok(())
}

#[test]
fn explicit_channel_refusals_preserve_shared_budget_and_counter_atomicity() -> Result<(), Error> {
    let mut c = config(2);
    c.max_native = 96;
    c.codec.max_packet = 97;
    c.codec.queue_bytes = 99;
    let mut observed = Engine::new(c)?;
    let mut reference = Engine::new(c)?;
    let before = snapshot(&observed)?;
    assert_eq!(
        observed.offer_on_channel_identified(55, channel(2)?, &[]),
        Err(Error::Configuration),
    );
    assert_eq!(snapshot(&observed)?, before);
    let first = packet(40_000, 0, 56);
    assert_eq!(
        observed.offer_on_channel_identified(0, channel(0)?, &first)?,
        reference.offer_on_channel_identified(0, channel(0)?, &first)?
    );
    assert_eq!(
        observed.offer_on_channel_identified(0, channel(1)?, &first)?,
        IdentifiedAdmission::Full
    );
    assert_eq!(
        observed.offer_on_channel_identified(0, channel(1)?, &[])?,
        IdentifiedAdmission::PacketSize
    );
    assert_eq!(observed.stats().native_dropped, 2);
    assert_eq!(observed.admitted, reference.admitted);
    assert_eq!(
        body(&mut observed, 0, 1, true)?,
        body(&mut reference, 0, 1, true)?
    );
    // An unreachable counter endpoint is the sole private state setup.
    observed.admitted[1] = u64::MAX;
    let before = snapshot(&observed)?;
    assert_eq!(
        observed.offer_on_channel_identified(0, channel(1)?, &first),
        Err(Error::CounterExhausted)
    );
    assert_eq!(snapshot(&observed)?, before);
    observed.admitted[1] = 0;
    assert_eq!(
        observed.offer_on_channel_identified(0, channel(1)?, &first)?,
        reference.offer_on_channel_identified(0, channel(1)?, &first)?
    );
    assert_eq!(
        body(&mut observed, 0, 2, true)?,
        body(&mut reference, 0, 2, true)?
    );
    Ok(())
}

#[test]
fn asymmetric_send_width_refuses_receive_only_channel_without_mutation() -> Result<(), Error> {
    let mut engine = Engine::new(config(3))?;
    engine.replace_send(config(1), RecordNumber(0))?;
    assert!(
        engine
            .channel_stats(2)
            .is_some_and(|stats| stats.receive.is_some())
    );
    let before = snapshot(&engine)?;
    assert_eq!(
        engine.offer_on_channel_identified(7, channel(2)?, &packet(1, 0, 8)),
        Err(Error::Configuration)
    );
    assert_eq!(snapshot(&engine)?, before);
    Ok(())
}

#[test]
fn typed_emissions_preserve_full_number_repair_and_feedback_priority() -> Result<(), Error> {
    let mut c = config(1);
    c.codec.repair_numerator = 1;
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let native = [0xaa, 0, 0xbb];
    sender.offer_on_channel_identified(0, channel(0)?, &native)?;
    let source = sender
        .poll_emission(0, RecordNumber(1), true)?
        .ok_or(Error::Admission)?;
    assert_eq!(source.kind(), EmissionKind::Source);
    assert_eq!(source.body(), [0, 0, 0, 0, 0, 0, 4, 0, 0xaa, 0, 0xbb]);
    let seed = 0x1_0000_0007;
    let repair = sender
        .poll_emission(0, RecordNumber(seed), true)?
        .ok_or(Error::Admission)?;
    assert_eq!(repair.kind(), EmissionKind::Repair);
    assert_eq!(
        repair.body(),
        [1, 0, 0, 0, 1, 1, 0, 31, 0, 225, 0, 11, 0, 215]
    );
    receiver.accept(1, RecordNumber(seed), &mut repair.body().to_vec())?;
    assert_eq!(receiver.pop()?, Some(native.as_slice()));
    receiver.offer_on_channel_identified(1, channel(0)?, &native)?;
    let feedback = receiver
        .poll_emission(100, RecordNumber(seed + 1), false)?
        .ok_or(Error::Admission)?;
    assert_eq!(feedback.kind(), EmissionKind::Feedback);
    assert_eq!(feedback.body(), [2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);
    sender.accept(101, RecordNumber(seed + 1), &mut feedback.body().to_vec())?;
    assert!(sender.send_drained());
    assert!(
        receiver
            .poll_emission(100, RecordNumber(seed + 2), false)?
            .is_none()
    );
    assert_eq!(
        receiver
            .poll_emission(100, RecordNumber(seed + 3), true)?
            .ok_or(Error::Admission)?
            .kind(),
        EmissionKind::Source
    );
    Ok(())
}
