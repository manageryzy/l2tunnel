//! Actual native packets, authenticated record IDs and the existing Packed unit grammar.
use super::*;

fn sender(symbol: usize, first: u64) -> Result<tx::Sender> {
    Ok(tx::Sender::new_ip(
        scope(),
        tx::Config {
            body: body_config(symbol),
            channels: 2,
            first_record: rx::RecordId(first),
        },
    )?)
}

fn drain(sender: &mut tx::Sender, symbol: usize) -> Result<Vec<(u64, Vec<u8>)>> {
    let mut records: Vec<(u64, Vec<u8>)> = Vec::new();
    while sender.is_pending() {
        let unit = sender.pending_unit()?;
        packed::validate_unit(unit.bytes, symbol)?;
        let part = &unit.bytes[3..];
        if part[0] == 4 {
            let offset = usize::from(u16::from_be_bytes([part[3], part[4]]));
            if offset == 0 {
                records.push((unit.record.0, Vec::new()));
            }
            let (id, bytes) = records.last_mut().ok_or("missing first fragment")?;
            assert_eq!((*id, bytes.len()), (unit.record.0, offset));
            bytes.extend_from_slice(&part[5..]);
        } else {
            records.push((unit.record.0, part.to_vec()));
        }
        sender.commit_unit()?;
    }
    Ok(records)
}

#[test]
fn fixed_anchor_sender_decodes_each_wrapped_body_using_only_its_exact_full_context() -> Result {
    let symbol = 96;
    let mut sender = sender(symbol, 65_532)?;
    let ch = rx::ChannelId(0);
    let mut anchor = None;
    for step in 0..19u32 {
        let ipv6 = step >= 10;
        let data = vec![step as u8; if step.is_multiple_of(3) { 145 } else { 21 }];
        let ip = packet(
            ipv6,
            &[],
            &options(10 + step * 18, 20),
            &data,
            100 + step * 21,
            step as u16,
        );
        let (id, obs) = sender.stage_fixed_anchor_headers_observed(ch, &ip)?;
        let next = sender.next_record(ch)?;
        assert_eq!(
            sender.stage_fixed_anchor_headers_observed(ch, &ip),
            Err(tx::Error::Busy)
        );
        assert_eq!(sender.next_record(ch)?, next);
        let records = drain(&mut sender, symbol)?;
        if let [(serial, context), _] = &records[..] {
            assert_eq!(context[0], 8);
            assert_eq!(context.len(), obs.context_bytes);
            anchor = Some((*serial, context.clone()));
        }
        let (serial, context) = anchor.as_ref().ok_or("missing anchor")?;
        let (_, wrapped) = records.last().ok_or("missing body")?;
        let (distance, _) = body::fixed_anchor_parts(wrapped)?;
        assert_eq!(id.record.0 - serial, u64::from(distance));
        assert_eq!(wrapped.len(), obs.encoded_body_bytes);
        if step == 10 {
            assert_eq!(distance, 1);
        } // New IP version needs a new full context.
        let mut restored = vec![0; 4096];
        for pad in [body::Padding::Exact, body::Padding::ZeroExtended] {
            if pad == body::Padding::ZeroExtended && wrapped.len() > symbol - 3 {
                continue;
            }
            let mut dec = body::Decoder::new_ip(body_config(symbol))?;
            dec.decode_body(context, body::Padding::Exact, &mut [])?;
            let mut encoded = wrapped.clone();
            if pad == body::Padding::ZeroExtended {
                encoded.resize(symbol - 3, 0);
            }
            assert_eq!(
                dec.decode_fixed_anchor_body(&encoded, pad, &mut restored)?,
                body::Decoded::Frame {
                    consumed: wrapped.len(),
                    written: ip.len(),
                    kind: obs.kind
                }
            );
            assert_eq!(restored[..ip.len()], ip);
        }
    }
    Ok(())
}

#[test]
fn fixed_anchor_sender_expires_through_raw_fallback_and_rejects_malformed_without_committing()
-> Result {
    let mut sender = sender(256, 0)?;
    let ch = rx::ChannelId(0);
    let ip = packet(false, &[], &[], &[42; 64], 17, 5);
    sender.stage_fixed_anchor_headers_observed(ch, &ip)?;
    drain(&mut sender, 256)?;
    for _ in 0..8 {
        let (_, obs) = sender.stage_fixed_anchor_headers_observed(ch, &[1, 2, 3])?;
        assert_eq!(obs.kind, body::BodyKind::Raw);
        assert_eq!(drain(&mut sender, 256)?[0].1[0], 2);
    }
    let expected = sender.next_record(ch)?;
    assert!(
        sender
            .stage_fixed_anchor_headers_observed(ch, &[0; 4097])
            .is_err()
    );
    assert_eq!(sender.next_record(ch)?, expected);
    let (native, obs) = sender.stage_fixed_anchor_headers_observed(ch, &ip)?;
    let new = drain(&mut sender, 256)?;
    assert!(obs.context_bytes > 0);
    assert_eq!(Some(rx::RecordId(new[0].0)), expected);
    assert_eq!(Some(native.record.0), new[0].0.checked_add(1));
    assert_eq!(body::fixed_anchor_parts(&new[1].1)?.0, 1);
    for body in [
        &[11, 0, 6, 0][..],
        &[11, 9, 6, 0],
        &[11, 1, 2, 0, 0],
        &[11, 1, 11, 1, 6, 0],
        &[11, 1],
        &[11, 1, 9, 0],
        &[11, 1, 6, 2, 128],
    ] {
        let mut unit = vec![0; 3];
        unit.extend_from_slice(body);
        assert!(packed::validate_unit(&unit, 256).is_err());
    }
    Ok(())
}

#[test]
fn fixed_anchor_sender_exact_plan_isolated_channels_and_exhaustion() -> Result {
    let config = tx::Config {
        body: body_config(96),
        channels: 2,
        first_record: rx::RecordId(u64::MAX - 2),
    };
    let plan = heap::SenderPlan::for_ip_config(config)?;
    let limits = heap::Limits {
        capacity_bytes: plan.capacity_bytes(),
    };
    let mut sender = tx::Sender::new_reserved_ip(scope(), config, limits)?;
    let usage = sender.storage_usage();
    let ip = packet(false, &[], &[], &[0; 32], 100, 0);
    for channel in [rx::ChannelId(1), rx::ChannelId(0)] {
        let (identity, _) = sender.stage_fixed_anchor_headers_observed(channel, &ip)?;
        assert_eq!(identity.record.0, u64::MAX - 1);
        let first = drain(&mut sender, 96)?;
        assert_eq!(first[0].1[0], 8);
        assert_eq!(body::fixed_anchor_parts(&first[1].1)?.0, 1);
        let ipv6 = packet(true, &[], &[], &[0; 32], 100, 0);
        assert_eq!(
            sender.stage_fixed_anchor_headers_observed(channel, &ipv6),
            Err(tx::Error::Exhausted)
        );
        assert!(!sender.is_pending());
        let (last, _) = sender.stage_fixed_anchor_headers_observed(channel, &ip)?;
        assert_eq!(last.record.0, u64::MAX);
        assert_eq!(
            body::fixed_anchor_parts(&drain(&mut sender, 96)?[0].1)?.0,
            2
        );
        assert_eq!(sender.next_record(channel)?, None);
    }
    assert_eq!(sender.storage_usage(), usage);
    let mut ethernet = tx::Sender::new(scope(), config)?;
    assert_eq!(
        ethernet.stage_fixed_anchor_headers_observed(rx::ChannelId(0), &ip),
        Err(tx::Error::Body(body::Error::Configuration))
    );
    assert_eq!(
        ethernet.next_record(rx::ChannelId(0))?,
        Some(config.first_record)
    );
    Ok(())
}
