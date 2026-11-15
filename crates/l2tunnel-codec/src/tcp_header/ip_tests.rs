//! Exact native bytes and real selected codec ownership; not runtime/native proof.
use super::*;
use crate::{
    aligned_body as body, aligned_receiver as rx, aligned_sender as tx, aligned_storage as heap,
    packed, packed_envelope, packed_sender as packing,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const FIRST: &str = "45000037ffff4000400626bf0a0000010a00000201bb1388fffffffe000000098018ffff5c5b00000101080affffffff000000070102f0";
const FIRST_RECORD: &str = "08003445000037ffff4000400626bf0a0000010a00000201bb1388fffffffe000000098018ffff5c5b00000101080affffffff00000007090003000102f0";
const NEXT: &str = "4500003600004000400626c00a0000010a00000201bb138800000001000000098018ffff4c5e00000101080a000000000000000700ff";
fn hex(text: &str) -> Result<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|at| Ok(u8::from_str_radix(&text[at..at + 2], 16)?))
        .collect()
}
fn decode(decoder: &mut IpHeaderDecoder, records: &[u8]) -> Result<Vec<u8>> {
    let mut offset = 0;
    let mut native = vec![0; 4096];
    let mut result = None;
    while offset < records.len() {
        match decoder.decode_next(&records[offset..], &mut native)? {
            Decoded::Context { consumed } => offset += consumed,
            Decoded::Frame {
                consumed, written, ..
            } => {
                offset += consumed;
                assert!(result.is_none());
                result = Some(native[..written].to_vec());
            }
        }
    }
    result.ok_or_else(|| "no original packet".into())
}
#[test]
fn literal_native_ip_context_delta_legacy_refusal_and_atomic_failures() -> Result {
    let packet = hex(FIRST)?;
    let expected = hex(FIRST_RECORD)?;
    let mut encoded = vec![0; 4125];
    let mut encoder = IpHeaderEncoder::new(4096)?;
    let mut decoder = IpHeaderDecoder::new(4096)?;
    let length = encoder.encode(&packet, &mut encoded)?;
    assert_eq!(&encoded[..length], expected);
    assert_eq!(decode(&mut decoder, &expected)?, packet);
    assert_eq!(
        HeaderDecoder::new(4096)?.decode_next(&expected, &mut [0; 4096]),
        Err(Error::InvalidRecord)
    );
    let delta = hex("0900024301030100ff")?;
    assert_eq!(
        IpHeaderDecoder::new(4096)?.decode_next(&delta, &mut [0; 4096]),
        Err(Error::MissingContext)
    );
    let length = encoder.encode(&hex(NEXT)?, &mut encoded)?;
    assert_eq!(&encoded[..length], delta);
    assert_eq!(decode(&mut decoder, &delta)?, hex(NEXT)?);
    // Split complete context/body records; a context alone is a valid parser result.
    for record in [&expected[..55], &expected[55..]] {
        for end in 0..record.len() {
            let mut trial = IpHeaderDecoder::new(4096)?;
            if record[0] != 8 {
                trial.decode_next(&expected[..55], &mut [])?;
            }
            let old = trial.context;
            let mut out = [0xa5; 4096];
            assert!(trial.decode_next(&record[..end], &mut out).is_err());
            assert_eq!(trial.context, old);
            assert_eq!(out, [0xa5; 4096]);
        }
    }
    let mut trial = IpHeaderDecoder::new(4096)?;
    trial.decode_next(&expected[..55], &mut [])?;
    let old = trial.context;
    let mut out = [0xa5; 54];
    assert_eq!(
        trial.decode_next(&expected[55..], &mut out),
        Err(Error::OutputTooSmall { needed: 55 })
    );
    assert_eq!(trial.context, old);
    assert_eq!(out, [0xa5; 54]);
    let mut trial = IpHeaderEncoder::new(4096)?;
    let mut small = vec![0xa5; expected.len() - 1];
    assert!(trial.encode(&packet, &mut small).is_err());
    assert!(!trial.has_context());
    assert!(small.iter().all(|byte| *byte == 0xa5));
    Ok(())
}
// Independent fixture checksum calculation; no encoder or restoration helper is used.
fn internet(parts: &[&[u8]]) -> u16 {
    let all = parts
        .iter()
        .flat_map(|part| part.iter().copied())
        .collect::<Vec<_>>();
    let mut sum = 0u64;
    for pair in all.chunks(2) {
        sum += u64::from(u16::from_be_bytes([
            pair[0],
            pair.get(1).copied().unwrap_or(0),
        ]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn packet(
    ipv6: bool,
    ip_options: &[u8],
    tcp_options: &[u8],
    payload: &[u8],
    seq: u32,
    id: u16,
) -> Vec<u8> {
    assert!(ip_options.len().is_multiple_of(4) && tcp_options.len().is_multiple_of(4));
    let ip = if ipv6 { 40 } else { 20 + ip_options.len() };
    let tcp = 20 + tcp_options.len();
    let mut bytes = vec![0; ip + tcp + payload.len()];
    if ipv6 {
        bytes[0] = 0x60;
        bytes[1] = 0x13;
        bytes[4..6].copy_from_slice(&((tcp + payload.len()) as u16).to_be_bytes());
        bytes[6] = 6;
        bytes[7] = 37;
        bytes[8] = 0xfd;
        bytes[23] = 1;
        bytes[24] = 0xfd;
        bytes[39] = 2;
    } else {
        bytes[0] = 0x40 | ((ip / 4) as u8);
        bytes[2..4].copy_from_slice(&((ip + tcp + payload.len()) as u16).to_be_bytes());
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[6] = 0x40;
        bytes[8] = 37;
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
        bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
        bytes[20..ip].copy_from_slice(ip_options);
        let value = internet(&[&bytes[..ip]]);
        bytes[10..12].copy_from_slice(&value.to_be_bytes());
    }
    bytes[ip..ip + 4].copy_from_slice(&[0x01, 0xbb, 0x13, 0x88]);
    bytes[ip + 4..ip + 8].copy_from_slice(&seq.to_be_bytes());
    bytes[ip + 8..ip + 12].copy_from_slice(&900u32.to_be_bytes());
    bytes[ip + 12] = ((tcp / 4) as u8) << 4;
    bytes[ip + 13] = 0x18;
    bytes[ip + 14..ip + 16].copy_from_slice(&4096u16.to_be_bytes());
    bytes[ip + 20..ip + tcp].copy_from_slice(tcp_options);
    bytes[ip + tcp..].copy_from_slice(payload);
    let length = (tcp + payload.len()) as u32;
    let checksum = if ipv6 {
        let mut pseudo = [0; 40];
        pseudo[..32].copy_from_slice(&bytes[8..40]);
        pseudo[32..36].copy_from_slice(&length.to_be_bytes());
        pseudo[39] = 6;
        internet(&[&pseudo, &bytes[ip..]])
    } else {
        let mut pseudo = [0; 12];
        pseudo[..8].copy_from_slice(&bytes[12..20]);
        pseudo[9] = 6;
        pseudo[10..].copy_from_slice(&(length as u16).to_be_bytes());
        internet(&[&pseudo, &bytes[ip..]])
    };
    bytes[ip + 16..ip + 18].copy_from_slice(&checksum.to_be_bytes());
    bytes
}
fn options(timestamp: u32, echo: u32) -> Vec<u8> {
    let mut result = vec![1, 1, 8, 10];
    result.extend_from_slice(&timestamp.to_be_bytes());
    result.extend_from_slice(&echo.to_be_bytes());
    result
}
fn body_config(symbol: usize) -> body::Config {
    body::Config {
        max_frame_bytes: 4096,
        symbol_bytes: symbol,
        elide_payload_length: true,
        predictive: true,
        timestamp_pair_dictionary: true,
        independent_short_frame_bytes: 0,
    }
}
#[test]
fn native_ipv6_prediction_has_no_ipid_options_are_exact_and_unsupported_bytes_fall_back() -> Result
{
    let first = packet(true, &[], &options(10, 20), &[0, 0xff, 7, 0], 100, 0);
    let second = packet(true, &[], &options(28, 37), &[3, 0, 0xff, 9], 104, 0);
    let mut encoder = body::Encoder::new_ip(body_config(256))?;
    let mut decoder = body::Decoder::new_ip(body_config(256))?;
    let mut bytes = vec![0; 4125];
    let mut out = vec![0; 4096];
    let encoded = encoder.encode(&first, &mut bytes)?;
    assert_eq!(bytes[0], 8);
    assert_eq!(encoded.context_len, 75);
    assert_eq!(bytes[encoded.context_len], 6);
    decoder.decode_body(
        &bytes[..encoded.context_len],
        body::Padding::Exact,
        &mut out,
    )?;
    decoder.decode_body(
        &bytes[encoded.context_len..encoded.written()],
        body::Padding::Exact,
        &mut out,
    )?;
    assert_eq!(&out[..first.len()], first);
    let encoded = encoder.encode(&second, &mut bytes)?;
    assert_eq!(encoded.context_len, 0);
    assert_eq!(&bytes[..encoded.written()], &[0x15, 3, 0, 0xff, 9]);
    decoder.decode_body(&bytes[..encoded.written()], body::Padding::Exact, &mut out)?;
    assert_eq!(&out[..second.len()], second);
    let changed_options = packet(
        true,
        &[],
        &[2, 4, 5, 180, 1, 1, 4, 2, 1, 1, 1, 1],
        &[1, 2, 0, 0xff],
        108,
        0,
    );
    let encoded = encoder.encode(&changed_options, &mut bytes)?;
    assert_eq!(bytes[0], 8);
    assert!(encoded.context_len > 0);
    decoder.decode_body(
        &bytes[..encoded.context_len],
        body::Padding::Exact,
        &mut out,
    )?;
    decoder.decode_body(
        &bytes[encoded.context_len..encoded.written()],
        body::Padding::Exact,
        &mut out,
    )?;
    assert_eq!(&out[..changed_options.len()], changed_options);
    // A native IPv6 context cannot accept an invented IPv4 ID mask bit.
    let mut raw_encoder = IpHeaderEncoder::new(4096)?;
    let length = raw_encoder.encode(&first, &mut bytes)?;
    let mut raw_decoder = IpHeaderDecoder::new(4096)?;
    let _ = decode(&mut raw_decoder, &bytes[..length])?;
    let saved = raw_decoder.context;
    let mut untouched = [0xa5; 4096];
    assert_eq!(
        raw_decoder.decode_next(&[9, 0, 0, 1, 1], &mut untouched),
        Err(Error::InvalidRecord)
    );
    assert_eq!(raw_decoder.context, saved);
    assert_eq!(untouched, [0xa5; 4096]);
    // Full IHL60/TCP60 context remains bounded and all option bytes are retained.
    let maximum = packet(false, &[1; 40], &[1; 40], &[9, 0, 0xff], 7, 65535);
    let mut headers = IpHeaderEncoder::new(4096)?;
    let length = headers.encode(&maximum, &mut bytes)?;
    assert_eq!(&bytes[..3], &[8, 0, 120]);
    assert_eq!(
        decode(&mut IpHeaderDecoder::new(4096)?, &bytes[..length])?,
        maximum
    );
    let mut unit = vec![0, 0, 0];
    unit.extend_from_slice(&bytes[..123]);
    assert_eq!(
        crate::source_copy::Policy {
            max_unit_bytes: 128,
            copies: 3,
            scope: crate::source_copy::Scope::ContextAndIndependent
        }
        .copies_for_unit(&unit, 256)?,
        3
    );
    let changed = packet(false, &[1; 40], &[1; 40], &[9, 0, 0xff], 10, 0);
    let length = headers.encode(&changed, &mut bytes)?;
    assert_eq!(bytes[0], 9);
    assert!(length < changed.len());
    let mut bad_checksum = first.clone();
    bad_checksum[56] ^= 1;
    let mut fragment = hex(FIRST)?;
    fragment[6] |= 0x20;
    let mut extension = first.clone();
    extension[6] = 0;
    let mut jumbo = first.clone();
    jumbo[4..6].fill(0);
    let mut bad_options = first.clone();
    bad_options[63] = 0;
    for original in [
        bad_checksum,
        fragment,
        extension,
        jumbo,
        bad_options,
        vec![0x45],
        vec![0, 1, 2, 3],
    ] {
        let mut encoder = IpHeaderEncoder::new(4096)?;
        let length = encoder.encode(&original, &mut bytes)?;
        assert_eq!(bytes[0], 2);
        assert_eq!(&bytes[3..length], original);
        assert!(!encoder.has_context());
    }
    Ok(())
}
fn scope() -> rx::Scope {
    rx::Scope {
        session: [7; 16],
        epoch: l2tunnel_core::Epoch(3),
        direction: rx::Direction::InitiatorToResponder,
    }
}
fn limits() -> rx::Limits {
    rx::Limits {
        body: body_config(64),
        channels: 2,
        first_record: rx::RecordId(0),
        first_source: rx::SourceId(0),
        record_window: 64,
        source_window: 128,
        lookahead_records: 8,
        lookahead_bytes: 32768,
        lookahead_fragments: 256,
        max_fragments_per_record: 128,
        lifetime_ticks: 1000,
    }
}
fn take(
    receiver: &mut rx::Receiver,
    channel: rx::ChannelId,
    identity: rx::RecordIdentity,
    expected: &[u8],
) -> Result {
    for _ in 0..8 {
        if receiver.prepare(channel, rx::Tick(1), 1)? == rx::Prepared::Ready {
            break;
        }
    }
    let pending = receiver.pending().ok_or("actual prepared native packet")?;
    assert_eq!(pending.bytes, expected);
    assert_eq!(pending.record, identity.record);
    assert_eq!(pending.channel, identity.channel);
    receiver.commit_delivery(rx::Tick(1))?;
    Ok(())
}
#[test]
fn reserved_aligned_and_packed_ip_owners_preserve_literal_bytes_ids_fragments_and_exact_capacity()
-> Result {
    let limits = limits();
    let sender_config = tx::Config {
        body: limits.body,
        channels: limits.channels,
        first_record: limits.first_record,
    };
    let plan = heap::SenderPlan::for_ip_config(sender_config)?;
    assert!(plan.ip_headers());
    assert!(
        matches!(tx::Sender::new_reserved_ip(scope(),sender_config,heap::Limits {capacity_bytes:plan.capacity_bytes()-1}),Err(heap::Error::Limit {required,limit}) if required==plan.capacity_bytes()&&limit+1==required)
    );
    let receive_plan = heap::ReceiverPlan::for_ip_limits(limits)?;
    let packets = [
        packet(false, &[1; 40], &[1; 40], &[0, 0xff, 1], 10, 1),
        packet(true, &[], &options(20, 30), &[8, 7, 0, 0xff], 100, 0),
        vec![0x45, 0, 0, 0],
    ];
    let mut functional = tx::Sender::new_ip(scope(), sender_config)?;
    let mut reserved = tx::Sender::new_reserved_ip(
        scope(),
        sender_config,
        heap::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let mut receiver = rx::Receiver::new_reserved_ip(
        scope(),
        limits,
        heap::Limits {
            capacity_bytes: receive_plan.capacity_bytes(),
        },
    )?;
    let before = receiver.storage_usage();
    let mut source = 0;
    for (index, original) in packets.iter().enumerate() {
        let channel = rx::ChannelId((index % 2) as u8);
        let identity = functional.stage_identified(channel, original)?;
        assert_eq!(reserved.stage_identified(channel, original)?, identity);
        while functional.is_pending() {
            let a = functional.pending_unit()?;
            let b = reserved.pending_unit()?;
            assert_eq!(a.bytes, b.bytes);
            assert_eq!(a.record, b.record);
            let record = a.record;
            let mut symbol = a.bytes.to_vec();
            symbol.resize(64, 0);
            receiver.admit_authenticated(
                rx::SymbolIdentity {
                    scope: scope(),
                    source: rx::SourceId(source),
                    record,
                },
                &symbol,
                rx::Tick(1),
            )?;
            functional.commit_unit()?;
            reserved.commit_unit()?;
            source += 1;
        }
        assert!(!reserved.is_pending());
        take(&mut receiver, channel, identity, original)?;
    }
    assert_eq!(receiver.storage_usage(), before);
    assert_eq!(
        reserved
            .storage_usage()
            .ok_or("sender actual usage")?
            .capacity_bytes,
        plan.capacity_bytes()
    );
    let config = packing::Config {
        sender: sender_config,
        packing: packed::Config {
            symbol_bytes: 64,
            hold_micros: 500,
        },
        max_units: 4,
        first_unit: rx::SourceId(0),
        work_limit: 1,
    };
    let plan = heap::PackedSenderPlan::for_ip_config(config)?;
    assert!(plan.ip_headers());
    let mut functional = packing::Sender::new_ip(scope(), config)?;
    let mut reserved = packing::Sender::new_reserved_ip(
        scope(),
        config,
        heap::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let mut receiver = rx::Receiver::new_reserved_ip(
        scope(),
        limits,
        heap::Limits {
            capacity_bytes: receive_plan.capacity_bytes(),
        },
    )?;
    let before = receiver.storage_usage();
    let mut now = 1;
    let mut source = 0;
    let mut output = vec![0; config.envelope().max_source_bytes()?];
    let mut comparison = output.clone();
    for (index, original) in packets.iter().enumerate() {
        let channel = rx::ChannelId((index % 2) as u8);
        let identity = functional.stage_identified(channel, original, now)?;
        assert_eq!(reserved.stage_identified(channel, original, now)?, identity);
        for _ in 0..256 {
            now += 1;
            functional.flush(now)?;
            reserved.flush(now)?;
            assert_eq!(functional.status(), reserved.status());
            if functional.status().packing.sealed {
                let a = functional.write_pending(rx::SourceId(source), &mut output)?;
                let b = reserved.write_pending(rx::SourceId(source), &mut comparison)?;
                assert_eq!(&output[..a], &comparison[..b]);
                let view = packed_envelope::decode(config.envelope(), scope(), &output[..a])?;
                for unit in view.units()? {
                    let mut symbol = unit.bytes.to_vec();
                    symbol.resize(64, 0);
                    receiver.admit_authenticated(unit.identity, &symbol, rx::Tick(1))?;
                }
                assert_eq!(
                    reserved.write_pending(rx::SourceId(source), &mut comparison)?,
                    a
                );
                assert_eq!(&output[..a], &comparison[..a]);
                functional.commit_source()?;
                reserved.commit_source()?;
                source += 1;
            }
            if functional.is_idle() {
                break;
            }
        }
        assert!(functional.is_idle() && reserved.is_idle());
        take(&mut receiver, channel, identity, original)?;
    }
    assert_eq!(receiver.storage_usage(), before);
    assert_eq!(
        reserved
            .storage_usage()
            .ok_or("packed actual usage")?
            .capacity_bytes,
        plan.capacity_bytes()
    );
    Ok(())
}
