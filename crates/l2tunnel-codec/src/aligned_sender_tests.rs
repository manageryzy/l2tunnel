use super::*;
use crate::aligned_receiver::Direction;
use l2tunnel_core::Epoch;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn scope() -> Scope {
    Scope {
        session: [7; 16],
        epoch: Epoch(9),
        direction: Direction::InitiatorToResponder,
    }
}
fn config(symbol_bytes: usize, short: usize, first: u64) -> Config {
    Config {
        body: aligned_body::Config {
            max_frame_bytes: 4096,
            symbol_bytes,
            elide_payload_length: true,
            predictive: true,
            timestamp_pair_dictionary: true,
            independent_short_frame_bytes: short,
        },
        channels: 2,
        first_record: RecordId(first),
    }
}
fn hex(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !input.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    (0..input.len())
        .step_by(2)
        .map(|offset| Ok(u8::from_str_radix(&input[offset..offset + 2], 16)?))
        .collect()
}
#[test]
fn native_observation_counts_complete_fragment_framing_once_after_success() -> TestResult {
    let mut sender = Sender::new(scope(), config(32, 0, 7))?;
    let empty = sender.buffer_snapshot();
    assert_eq!(empty.stage.items, 0);
    assert_eq!(empty.stage.item_capacity, 1);
    let mut native = [0; 70];
    native[..3].copy_from_slice(&[1, 2, 3]);
    let (identity, observation) = sender.stage_raw_observed(ChannelId(0), &native)?;
    assert_eq!(identity.record, RecordId(7));
    assert_eq!(observation.original_native_bytes, 70);
    assert_eq!(observation.context_bytes, 0);
    assert_eq!(observation.encoded_body_bytes, 73);
    assert_eq!(observation.framing_bytes, 32);
    assert_eq!(observation.kind, aligned_body::BodyKind::Raw);
    assert_eq!(observation.codec_net_gain_bytes(), -3);
    assert_eq!(observation.net_gain_bytes(), -35);
    let retained = sender.buffer_snapshot();
    assert_eq!(retained.stage.items, 1);
    assert_eq!(retained.stage.bytes, 73);
    assert_eq!(retained.remaining_bytes, 73);
    assert_eq!(
        sender.stage_raw_observed(ChannelId(0), &native),
        Err(Error::Busy)
    );
    assert_eq!(
        Error::Busy.buffer_refusal(),
        Some(crate::diagnostics::StageBlock::RetainedFrame)
    );
    assert_eq!(sender.buffer_snapshot(), retained);
    let mut body = Vec::new();
    let mut wire_bytes = 0;
    let mut units = 0;
    while sender.is_pending() {
        let unit = sender.pending_unit()?;
        assert_eq!(unit.record, identity.record);
        assert_eq!(unit.bytes[3], 4);
        body.extend_from_slice(&unit.bytes[8..]);
        wire_bytes += unit.bytes.len();
        units += 1;
        let remaining = sender.buffer_snapshot().remaining_bytes;
        sender.commit_unit()?;
        assert!(sender.buffer_snapshot().remaining_bytes < remaining);
    }
    assert_eq!(units, 4);
    assert_eq!(wire_bytes, 105);
    assert_eq!(&body[..3], &[2, 0, 70]);
    assert_eq!(&body[3..], native);
    assert_eq!(sender.buffer_snapshot(), empty);
    assert!(sender.stage_raw_observed(ChannelId(2), &native).is_err());
    let (next, again) = sender.stage_raw_observed(ChannelId(0), &native)?;
    assert_eq!(next.record, RecordId(8));
    assert_eq!(again, observation);
    Ok(())
}
#[test]
fn every_actual_python_sender_symbol_matches_context_fragment_padding_and_wrap() -> TestResult {
    let mut name = "";
    let mut sender = Sender::new(scope(), config(1460, 0, 0))?;
    let mut symbols = 0usize;
    for line in include_str!("../tests/data/aligned-sender-goldens.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split('\t').collect();
        if name != fields[0] {
            name = fields[0];
            sender = Sender::new(
                scope(),
                config(fields[2].parse()?, fields[3].parse()?, fields[4].parse()?),
            )?;
        }
        sender.stage(ChannelId(fields[5].parse()?), &hex(fields[6])?)?;
        let records: Vec<_> = fields[7].split(';').collect();
        for (index, record) in records.iter().enumerate() {
            let parts: Vec<_> = record.split(':').collect();
            let source = SourceId(parts[0].parse()?);
            let absolute = RecordId(parts[1].parse()?);
            let expected = hex(parts[2])?;
            let unit = sender.pending_unit()?;
            assert_eq!(unit.channel, ChannelId(fields[5].parse()?));
            assert_eq!(unit.record, absolute);
            assert_eq!(unit.bytes, &expected[..unit.bytes.len()]);
            assert!(expected[unit.bytes.len()..].iter().all(|byte| *byte == 0));
            crate::packed::validate_unit(unit.bytes, expected.len())?;
            let next_record = records
                .get(index + 1)
                .and_then(|value| value.split(':').nth(1))
                .map(str::parse::<u64>)
                .transpose()?;
            assert_eq!(unit.completes_record, next_record != Some(absolute.0));
            assert_eq!(unit.completes_frame, index + 1 == records.len());
            let meaningful = unit.bytes.to_vec();
            assert_eq!(sender.pending_unit()?.bytes, meaningful);
            let mut output = vec![0xa5; aligned_envelope::HEADER_BYTES + expected.len()];
            let length = sender.write_pending(source, &mut output)?;
            let view = aligned_envelope::decode(scope(), expected.len(), 2, &output[..length])?;
            assert_eq!(
                view.identity,
                SymbolIdentity {
                    scope: scope(),
                    source,
                    record: absolute
                }
            );
            assert_eq!(
                view.symbol, expected,
                "{} step {} source {}",
                name, fields[1], source.0
            );
            let mut compact = vec![0xa5; expected.len() + 10];
            let compact_length = sender.write_pending_compact(&mut compact)?;
            let compact_view = aligned_envelope::decode_compact(
                scope(),
                source,
                expected.len(),
                2,
                &compact[..compact_length],
            )?;
            assert_eq!(compact_view.identity, view.identity);
            assert_eq!(compact_view.symbol, meaningful);
            assert_eq!(
                compact_length,
                crate::source_identity::varint_len(absolute.0) + meaningful.len()
            );
            let held = compact.clone();
            assert_eq!(sender.write_pending_compact(&mut compact)?, compact_length);
            assert_eq!(compact, held);
            let original = output.clone();
            assert_eq!(sender.write_pending(source, &mut output)?, length);
            assert_eq!(output, original);
            if symbols.is_multiple_of(2) {
                sender.commit_unit()?;
            } else {
                sender.commit_source()?;
            }
            symbols += 1;
        }
        assert!(!sender.is_pending());
    }
    assert_eq!(symbols, 2588);
    Ok(())
}
#[test]
fn stage_and_output_failures_preserve_context_ids_and_pending_bytes() -> TestResult {
    let mut sender = Sender::new(scope(), config(20, 0, 0))?;
    sender.stage(ChannelId(0), b"abcdefghijklmnopqrstuvwxyz")?;
    let mut output = vec![0; 68];
    sender.write_pending(SourceId(3), &mut output)?;
    let original = output.clone();
    let next = sender.next_record(ChannelId(0))?;
    assert_eq!(sender.stage(ChannelId(0), b"different"), Err(Error::Busy));
    let mut short = [0xa5; 16];
    assert!(matches!(
        sender.write_pending(SourceId(3), &mut short),
        Err(Error::Envelope(
            aligned_envelope::Error::OutputTooSmall { .. }
        ))
    ));
    assert_eq!(short, [0xa5; 16]);
    sender.write_pending(SourceId(3), &mut output)?;
    assert_eq!(output, original);
    assert_eq!(sender.next_record(ChannelId(0))?, next);
    while sender.is_pending() {
        sender.commit_source()?;
    }
    assert_eq!(
        sender.stage(ChannelId(9), b"bad"),
        Err(Error::Configuration)
    );
    assert!(sender.stage(ChannelId(0), &vec![0; 4097]).is_err());
    assert_eq!(sender.next_record(ChannelId(0))?, next);
    sender.stage(ChannelId(0), b"valid")?;
    sender.write_pending(SourceId(4), &mut output)?;
    assert_eq!(
        aligned_envelope::decode(scope(), 20, 2, &output)?
            .identity
            .record,
        RecordId(1)
    );
    Ok(())
}
#[test]
fn envelope_rejects_all_truncations_lengths_scopes_channels_and_serials() -> TestResult {
    let mut sender = Sender::new(scope(), config(72, 0, 65536))?;
    sender.stage(ChannelId(1), b"body")?;
    let mut output = vec![0; 120];
    sender.write_pending(SourceId(42), &mut output)?;
    for length in 0..output.len() {
        assert!(aligned_envelope::decode(scope(), 72, 2, &output[..length]).is_err());
    }
    let mut trailing = output.clone();
    trailing.push(0);
    assert!(aligned_envelope::decode(scope(), 72, 2, &trailing).is_err());
    for offset in [0, 1, 2, 3, 4, 5, 6, 7, 8, 23, 24, 31, 47, 48, 49, 50] {
        let mut malformed = output.clone();
        malformed[offset] ^= 0x80;
        assert!(
            aligned_envelope::decode(scope(), 72, 2, &malformed).is_err(),
            "offset {offset}"
        );
    }
    let mut wrong = scope();
    wrong.direction = Direction::ResponderToInitiator;
    assert_eq!(
        aligned_envelope::decode(wrong, 72, 2, &output),
        Err(aligned_envelope::Error::Scope)
    );
    // Full absolute source/record words are preserved, not guessed from low16.
    output[32..40].copy_from_slice(&u64::MAX.to_be_bytes());
    output[40..48].copy_from_slice(&(65536u64 * 2).to_be_bytes());
    let view = aligned_envelope::decode(scope(), 72, 2, &output)?;
    assert_eq!(view.identity.source, SourceId(u64::MAX));
    assert_eq!(view.identity.record, RecordId(131072));
    Ok(())
}
#[test]
fn record_exhaustion_is_transactional_and_channels_are_independent() -> TestResult {
    let mut sender = Sender::new(scope(), config(1460, 0, u64::MAX))?;
    let row = include_str!("../tests/data/aligned-sender-goldens.tsv")
        .lines()
        .find(|line| line.starts_with("wrap\t0\t"))
        .ok_or("golden")?;
    let native = hex(row.split('\t').nth(6).ok_or("native field")?)?;
    assert_eq!(sender.stage(ChannelId(0), &native), Err(Error::Exhausted));
    assert_eq!(sender.next_record(ChannelId(0))?, Some(RecordId(u64::MAX)));
    assert!(!sender.is_pending());
    sender.stage(ChannelId(0), b"last")?;
    assert_eq!(sender.next_record(ChannelId(0))?, None);
    sender.commit_source()?;
    assert_eq!(sender.stage(ChannelId(0), b"again"), Err(Error::Exhausted));
    sender.stage(ChannelId(1), b"independent")?;
    Ok(())
}

#[test]
fn explicit_raw_staging_preserves_header_context_and_u16_body_boundary() -> TestResult {
    let fixture = include_str!("../tests/data/aligned-sender-goldens.tsv");
    let frames: Vec<_> = fixture
        .lines()
        .filter(|line| line.starts_with("symbol128\t0\t") || line.starts_with("symbol128\t1\t"))
        .map(|line| hex(line.split('\t').nth(6).ok_or("frame")?))
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;
    let config = config(128, 0, 0);
    let mut actual = aligned_body::Encoder::new(config.body)?;
    let mut reference = aligned_body::Encoder::new(config.body)?;
    let mut bytes = vec![0; actual.max_encoded_len()];
    actual.encode(&frames[0], &mut bytes)?;
    reference.encode(&frames[0], &mut bytes)?;
    let raw = actual.encode_raw(&frames[1], &mut bytes)?;
    assert_eq!(raw.context_len, 0);
    assert_eq!(raw.kind, aligned_body::BodyKind::Raw);
    assert_eq!(&bytes[3..raw.written()], &frames[1]);
    let encoded = actual.encode(&frames[1], &mut bytes)?;
    let mut expected = vec![0; reference.max_encoded_len()];
    assert_eq!(reference.encode(&frames[1], &mut expected)?, encoded);
    assert_eq!(&bytes[..encoded.written()], &expected[..encoded.written()]);
    let mut sender = Sender::new(scope(), config)?;
    sender.stage_raw(ChannelId(1), &frames[0])?;
    let mut packet = vec![0; 176];
    sender.write_pending(SourceId(0), &mut packet)?;
    assert_eq!(packet[51], 4); // Raw130+3 body is fragmented at symbol128.
    assert_eq!(&packet[56..59], &[2, 0, 130]);
    let mut largest = config.body;
    largest.max_frame_bytes = 65535;
    let mut encoder = aligned_body::Encoder::new(largest)?;
    let mut output = vec![0xa5; encoder.max_encoded_len()];
    assert_eq!(
        encoder.encode_raw(&vec![1; 65533], &mut output),
        Err(aligned_body::Error::RecordTooLarge)
    );
    assert!(output.iter().all(|byte| *byte == 0xa5));
    assert_eq!(
        encoder.encode_raw(&vec![1; 65532], &mut output)?.body_len,
        65535
    );
    Ok(())
}

#[test]
fn exact_units_pack_zero_tails_and_preserve_local_backpressure() -> TestResult {
    use crate::{aligned_receiver as receiver, packed, packed_envelope as envelope};
    let policy = config(64, 0, 0);
    let mut sender = Sender::new(scope(), policy)?;
    assert_eq!(sender.commit_unit(), Err(Error::NoPending));
    assert!(matches!(sender.pending_unit(), Err(Error::NoPending)));
    let mut packer = packed::Packer::new(packed::Config {
        symbol_bytes: 64,
        hold_micros: 500,
    })?;
    let original = [
        (ChannelId(0), [1, 2, 0, 0, 0, 0]),
        (ChannelId(1), [3, 4, 0, 0, 0, 0]),
        (ChannelId(0), [5, 6, 0, 0, 0, 0]),
    ];
    let mut records = Vec::new();
    for (channel, frame) in &original {
        sender.stage_raw(*channel, frame)?;
        let unit = sender.pending_unit()?;
        assert_eq!(unit.bytes.len(), 12);
        assert_eq!(&unit.bytes[6..], frame);
        assert!(unit.completes_record && unit.completes_frame);
        records.push(unit.record);
        assert_eq!(packer.push(unit.bytes, 1, 0)?, packed::Push::Accepted);
        sender.commit_unit()?;
        assert!(!sender.is_pending());
    }
    packer.tick(500)?;
    let source = packer.pending().ok_or("unsealed source")?;
    assert_eq!(source.units, 3);
    let held = source.payload.to_vec();
    sender.stage_raw(ChannelId(1), b"next")?;
    let next = sender.pending_unit()?.bytes.to_vec();
    assert_eq!(packer.push(&next, 1, 501)?, packed::Push::Backpressure);
    assert_eq!(sender.pending_unit()?.bytes, next);
    assert_eq!(packer.pending().ok_or("lost source")?.payload, held);

    let geometry = envelope::Config {
        symbol_bytes: 64,
        channels: 2,
        max_units: 4,
    };
    let identity = envelope::Identity {
        scope: scope(),
        source: SourceId(42),
        first_unit: SourceId(0),
    };
    let mut encoded = vec![0; geometry.max_source_bytes()?];
    let length = envelope::encode(geometry, identity, &records, &held, &mut encoded)?;
    let view = envelope::decode(geometry, scope(), &encoded[..length])?;
    assert_eq!(view.identity(), identity);
    let units = view
        .units()?
        .map(|unit| {
            let mut padded = unit.bytes.to_vec();
            padded.resize(64, 0);
            (unit.identity, padded)
        })
        .collect::<Vec<_>>();
    let authenticated = units
        .iter()
        .map(|(identity, bytes)| receiver::AuthenticatedSymbol {
            identity: *identity,
            bytes,
        })
        .collect::<Vec<_>>();
    let mut receiver = receiver::Receiver::new(
        scope(),
        receiver::Limits {
            body: policy.body,
            channels: 2,
            first_record: RecordId(0),
            first_source: SourceId(0),
            record_window: 8,
            source_window: 16,
            lookahead_records: 8,
            lookahead_bytes: 4096,
            lookahead_fragments: 64,
            max_fragments_per_record: 64,
            lifetime_ticks: 100,
        },
    )?;
    assert_eq!(
        receiver.admit_batch_authenticated(&authenticated, receiver::Tick(1))?,
        vec![receiver::Admission::Accepted; 3]
    );
    for (channel, frame) in original {
        assert_eq!(
            receiver.prepare(channel, receiver::Tick(1), 1)?,
            receiver::Prepared::Ready
        );
        assert_eq!(
            receiver.pending().ok_or("missing decoded native")?.bytes,
            frame
        );
        receiver.commit_delivery(receiver::Tick(1))?;
    }
    // This is a pure codec composition. No recovery owner accepted the source,
    // so the packer's actual recovery handoff is deliberately not committed.
    assert_eq!(packer.pending().ok_or("source still owned")?.payload, held);
    Ok(())
}
