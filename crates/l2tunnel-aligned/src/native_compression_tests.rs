//! Actual selected compact owners preserve compression across loss and reordering.
use super::*;

fn configured(
    reverse: bool,
    packed: bool,
    native: NativePolicy,
) -> TestResult<packed::CompactConfig> {
    let mut config = policy(reverse, packed)?;
    config.base.native_policy = native;
    config.base.receiver.body.elide_payload_length = false;
    config.base.receiver.body.predictive = false;
    config.base.receiver.body.timestamp_pair_dictionary = false;
    config.base.receiver.body.independent_short_frame_bytes = 0;
    Ok(config)
}

#[test]
fn current_native_compression_aligned_and_packed_survive_loss_reorder_and_feedback() -> TestResult {
    for native in [
        NativePolicy::RawEthernet,
        NativePolicy::RawIp,
        NativePolicy::Lz4Ethernet,
        NativePolicy::Lz4Ip,
    ] {
        for packed in [false, true] {
            let forward = configured(false, packed, native)?;
            let reverse = configured(true, packed, native)?;
            let mut a = Body::construct(
                forward,
                reverse,
                EndpointRole::Initiator,
                packed,
                usize::MAX,
            )?;
            let mut b = Body::construct(
                reverse,
                forward,
                EndpointRole::Responder,
                packed,
                usize::MAX,
            )?;
            body!(&mut a, enable_compact_wire(41))?;
            body!(&mut b, enable_compact_wire(97))?;
            // Deliberately opaque packet bytes include meaningful terminal zeros.
            // Native layer admission belongs to the outer Common Pipeline.
            let frames = [
                vec![0; 700],
                (0..193).map(|i| (i * 73) as u8).chain([0; 4]).collect(),
            ];
            let mut admitted = 0;
            let mut received = Vec::new();
            let mut delayed = None;
            let mut dropped = false;
            let mut never_drop = true;
            for tick in 0..1000 {
                let now = Duration::from_millis(tick);
                if admitted < frames.len() {
                    match body!(
                        &mut a,
                        enqueue_admitted(ChannelId(0), &frames[admitted], now)
                    ) {
                        Ok(()) => admitted += 1,
                        Err(Error::Busy) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                let mut output = vec![0; a.maximum()];
                let mut budget = OutboundBudget {
                    packets: 1,
                    wire_bytes: 100_000,
                };
                if let Some(length) = a.poll(now, false, &mut output, &mut budget)? {
                    let token = a.token(false).ok_or("actual compact token")?;
                    a.confirm(now, token)?;
                    output.truncate(length);
                    if !dropped {
                        dropped = true;
                    } else if delayed.is_none() && tick < 10 {
                        delayed = Some(output);
                    } else {
                        b.receive(now, &output)?;
                        if let Some(old) = delayed.take() {
                            b.receive(now, &old)?;
                        }
                    }
                }
                if tick == 10
                    && let Some(old) = delayed.take()
                {
                    b.receive(now, &old)?;
                }
                transfer(&mut b, &mut a, now, true, &mut never_drop, false)?;
                b.collect(now, &mut received)?;
                if received.len() == frames.len() && a.drained() && b.drained() {
                    break;
                }
            }
            assert!(dropped && a.statistics().retry_packets > 0);
            assert_eq!(received, frames);
            assert!(a.drained() && b.drained());
        }
    }
    Ok(())
}

#[test]
fn current_native_compression_policy_is_canonical_and_strict_before_allocation() -> TestResult {
    let mut digests = Vec::new();
    for native in [
        NativePolicy::RawEthernet,
        NativePolicy::RawIp,
        NativePolicy::Lz4Ethernet,
        NativePolicy::Lz4Ip,
    ] {
        let mut config = configured(false, true, native)?;
        let mut encoded = [0; packed::COMPACT_CONFIG_BYTES];
        config.encode_into(&mut encoded)?;
        assert_eq!(packed::CompactConfig::decode(&encoded)?, config);
        assert_eq!(encoded[0], native.wire());
        digests.push(encoded);
        assert!(native.accepts_unit(&[0, 0, 0, 2, 0, 1, 0]));
        assert_eq!(
            native.accepts_unit(&[0, 0, 0, 10, 0, 1, 0, 9, 0]),
            native.uses_lz4()
        );
        assert!(!native.accepts_unit(&[0, 0, 0, 8, 0, 40]));
        assert!(!native.accepts_unit(&[0, 0, 0, 4, 0, 100, 0, 0, 8]));
        config.base.receiver.body.predictive = true;
        assert!(config.validate().is_err());
    }
    for (index, a) in digests.iter().enumerate() {
        for b in &digests[index + 1..] {
            assert_ne!(a, b);
        }
    }
    assert!(!NativePolicy::EthernetHeaders.accepts_unit(&[0, 0, 0, 10]));
    assert!(!NativePolicy::IpHeaders.accepts_unit(&[0, 0, 0, 10]));
    Ok(())
}
