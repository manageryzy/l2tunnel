use super::*;
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

#[test]
fn checksum_preserves_words_across_empty_parts_odd_splits_and_block_boundaries() {
    let bytes: Vec<u8> = (0..196_619u32).map(|i| 255 - (i % 19) as u8).collect();
    for len in [0, 1, 20, 51, 1448, 65_535, 65_536, 65_537, bytes.len()] {
        let packet = &bytes[..len];
        let sum = packet
            .iter()
            .enumerate()
            .map(|(i, byte)| u64::from(*byte) << if i % 2 == 0 { 8 } else { 0 })
            .sum::<u64>();
        let expected = if sum == 0 {
            0xffff
        } else {
            0xfffe - ((sum - 1) % 65_535) as u16
        };
        for stride in [1, 7, 1448, 65_535, 65_536, 65_537] {
            let parts: Vec<_> = packet
                .chunks(stride)
                .flat_map(|part| [part, &[][..]])
                .collect();
            assert_eq!(checksum(&parts), expected, "length {len}, stride {stride}");
        }
    }
}

struct Vector {
    profile: HeaderProfile,
    name: &'static str,
    reset: bool,
    frame: Vec<u8>,
    record: Vec<u8>,
    encoder: Option<[u8; 66]>,
    decoder: Option<[u8; 66]>,
}
fn hex(text: &str) -> Result<Vec<u8>, TestError> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex fixture".into());
    }
    text.as_bytes()
        .chunks(2)
        .map(|bytes| Ok(u8::from_str_radix(std::str::from_utf8(bytes)?, 16)?))
        .collect()
}
fn context(text: &str) -> Result<Option<[u8; 66]>, TestError> {
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            hex(text)?
                .try_into()
                .map_err(|_| "context fixture length")?,
        ))
    }
}
fn vectors() -> Result<Vec<Vector>, TestError> {
    include_str!("../tests/data/tcp-header-goldens.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 7 {
                return Err("fixture column count".into());
            }
            let profile = match fields[0] {
                "tcp_timestamp" => HeaderProfile::TcpTimestamp,
                "tcp_delta" => HeaderProfile::TcpDelta,
                _ => return Err("fixture profile".into()),
            };
            Ok(Vector {
                profile,
                name: fields[1],
                reset: fields[2] == "1",
                frame: hex(fields[3])?,
                record: hex(fields[4])?,
                encoder: context(fields[5])?,
                decoder: context(fields[6])?,
            })
        })
        .collect()
}
fn seed(profile: HeaderProfile) -> Result<Vector, TestError> {
    vectors()?
        .into_iter()
        .find(|v| v.profile == profile && v.name == "initial")
        .ok_or_else(|| "missing initial fixture".into())
}
fn decode_frame(decoder: &mut HeaderDecoder, bytes: &[u8]) -> Result<Vec<u8>, TestError> {
    let mut out = vec![0; MAX_FRAME_BYTES];
    let mut offset = 0;
    let mut frame = None;
    while offset < bytes.len() {
        match decoder.decode_next(&bytes[offset..], &mut out)? {
            Decoded::Context { consumed } => offset += consumed,
            Decoded::Frame {
                consumed, written, ..
            } => {
                if frame.is_some() {
                    return Err("multiple frames".into());
                }
                frame = Some(out[..written].to_vec());
                offset += consumed;
            }
        }
    }
    frame.ok_or_else(|| "missing native frame".into())
}

#[test]
fn all_actual_python_records_and_context_transitions_are_byte_exact() -> TestResult {
    let vectors = vectors()?;
    assert_eq!(vectors.len(), 28);
    for profile in [HeaderProfile::TcpTimestamp, HeaderProfile::TcpDelta] {
        let mut encoder = HeaderEncoder::new(profile, MAX_FRAME_BYTES)?;
        let mut decoder = HeaderDecoder::new(MAX_FRAME_BYTES)?;
        for vector in vectors.iter().filter(|v| v.profile == profile) {
            if vector.reset {
                encoder.reset();
                decoder.reset();
            }
            let mut output = vec![0; encoder.max_encoded_len()];
            let length = encoder.encode(&vector.frame, &mut output)?;
            assert_eq!(&output[..length], vector.record, "{}", vector.name);
            assert_eq!(
                encoder.context, vector.encoder,
                "{} encoder state",
                vector.name
            );
            assert_eq!(
                decode_frame(&mut decoder, &vector.record)?,
                vector.frame,
                "{}",
                vector.name
            );
            assert_eq!(
                decoder.context, vector.decoder,
                "{} decoder state",
                vector.name
            );
        }
    }
    Ok(())
}

#[test]
fn every_truncated_fixture_record_and_short_output_preserves_prior_state() -> TestResult {
    for profile in [HeaderProfile::TcpTimestamp, HeaderProfile::TcpDelta] {
        let mut encoder = HeaderEncoder::new(profile, MAX_FRAME_BYTES)?;
        let mut decoder = HeaderDecoder::new(MAX_FRAME_BYTES)?;
        for vector in vectors()?.into_iter().filter(|v| v.profile == profile) {
            if vector.reset {
                encoder.reset();
                decoder.reset();
            }
            let before = encoder.context;
            for capacity in 0..vector.record.len() {
                let mut out = vec![0xcc; capacity];
                assert!(matches!(
                    encoder.encode(&vector.frame, &mut out),
                    Err(Error::OutputTooSmall { .. })
                ));
                assert_eq!(encoder.context, before);
                assert!(out.iter().all(|b| *b == 0xcc));
            }
            let mut output = vec![0; encoder.max_encoded_len()];
            encoder.encode(&vector.frame, &mut output)?;
            let mut offset = 0;
            while offset < vector.record.len() {
                let prior = decoder.context;
                let bytes = &vector.record[offset..];
                let mut full = HeaderDecoder {
                    maximum: MAX_FRAME_BYTES,
                    context: prior,
                };
                let event = full.decode_next(bytes, &mut output)?;
                let consumed = match event {
                    Decoded::Context { consumed } | Decoded::Frame { consumed, .. } => consumed,
                };
                for end in 0..consumed {
                    let mut trial = HeaderDecoder {
                        maximum: MAX_FRAME_BYTES,
                        context: prior,
                    };
                    assert!(trial.decode_next(&bytes[..end], &mut output).is_err());
                    assert_eq!(trial.context, prior);
                }
                if let Decoded::Frame { written, .. } = event {
                    for capacity in 0..written {
                        let mut trial = HeaderDecoder {
                            maximum: MAX_FRAME_BYTES,
                            context: prior,
                        };
                        let mut small = vec![0xcc; capacity];
                        assert!(matches!(
                            trial.decode_next(bytes, &mut small),
                            Err(Error::OutputTooSmall { .. })
                        ));
                        assert_eq!(trial.context, prior);
                        assert!(small.iter().all(|b| *b == 0xcc));
                    }
                }
                decoder.decode_next(bytes, &mut output)?;
                offset += consumed;
            }
        }
    }
    Ok(())
}

#[test]
fn reset_rejects_dynamic_records_and_raw_fallback_preserves_context() -> TestResult {
    for profile in [HeaderProfile::TcpTimestamp, HeaderProfile::TcpDelta] {
        let vector = seed(profile)?;
        let mut decoder = HeaderDecoder::new(MAX_FRAME_BYTES)?;
        let mut output = vec![0; MAX_FRAME_BYTES];
        assert_eq!(
            decoder.decode_next(&vector.record[69..], &mut output),
            Err(Error::MissingContext)
        );
        assert_eq!(
            decoder.decode_next(&vector.record[..69], &mut []),
            Ok(Decoded::Context { consumed: 69 })
        );
        assert!(decoder.has_context());
        let previous = decoder.context;
        decoder.decode_next(&[2, 0, 1, 0x45], &mut output)?;
        assert_eq!(decoder.context, previous);
        decoder.reset();
        assert!(!decoder.has_context());
        assert_eq!(
            decoder.decode_next(&vector.record[69..], &mut output),
            Err(Error::MissingContext)
        );
        let mut encoder = HeaderEncoder::new(profile, MAX_FRAME_BYTES)?;
        encoder.encode(&vector.frame, &mut output)?;
        assert!(encoder.has_context());
        encoder.reset();
        assert!(!encoder.has_context());
        let count = encoder.encode(&vector.frame, &mut output)?;
        assert_eq!(&output[..count], vector.record);
    }
    Ok(())
}

#[test]
fn malformed_context_record_and_varints_fail_without_context_mutation() -> TestResult {
    let vector = seed(HeaderProfile::TcpDelta)?;
    let mut decoder = HeaderDecoder::new(MAX_FRAME_BYTES)?;
    let mut output = vec![0; MAX_FRAME_BYTES];
    decoder.decode_next(&vector.record[..69], &mut output)?;
    let before = decoder.context;
    for bytes in [
        vec![0, 0, 65],
        vec![9, 0, 0],
        vec![3, 0, 0, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        vec![1, 255, 255],
        vec![3, 255, 255],
    ] {
        assert!(decoder.decode_next(&bytes, &mut output).is_err());
        assert_eq!(decoder.context, before);
    }
    for offset in [3 + 12, 3 + 14, 3 + 23, 3 + 24, 3 + 46, 3 + 54] {
        let mut bad = vector.record[..69].to_vec();
        bad[offset] ^= if offset == 3 + 46 { 0x10 } else { 1 };
        assert_eq!(
            decoder.decode_next(&bad, &mut output),
            Err(Error::InvalidRecord)
        );
        assert_eq!(decoder.context, before);
    }
    let five = [3, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0x7f];
    assert!(matches!(
        decoder.decode_next(&five, &mut output)?,
        Decoded::Frame {
            kind: RecordKind::Delta,
            written: 66,
            ..
        }
    ));
    // Python accepts a 35-bit delta, then reduces modulo the 16-bit IP ID width.
    assert_eq!(u16::from_be_bytes([output[18], output[19]]), 65534);
    let before = decoder.context;
    let six = [3, 0, 0, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0];
    assert_eq!(
        decoder.decode_next(&six, &mut output),
        Err(Error::DeltaOverflow)
    );
    assert_eq!(decoder.context, before);
    Ok(())
}

#[test]
fn maximum_native_lengths_and_opaque_unsupported_bytes_remain_bounded() -> TestResult {
    for maximum in [0, MAX_FRAME_BYTES + 1, usize::MAX] {
        assert!(matches!(
            HeaderEncoder::new(HeaderProfile::TcpDelta, maximum),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            HeaderDecoder::new(maximum),
            Err(Error::Configuration)
        ));
    }
    let vector = seed(HeaderProfile::TcpTimestamp)?;
    for profile in [HeaderProfile::TcpTimestamp, HeaderProfile::TcpDelta] {
        let mut encoder = HeaderEncoder::new(profile, MAX_FRAME_BYTES)?;
        let mut decoder = HeaderDecoder::new(MAX_FRAME_BYTES)?;
        let mut encoded = vec![0; encoder.max_encoded_len()];
        let original: [u8; 66] = vector.frame[..66].try_into()?;
        let payload: Vec<u8> = (0..MAX_FRAME_BYTES - 66).map(|n| n as u8).collect();
        let header = restore_header(&original, &dynamic(&original), &payload)?;
        let mut frame = header.to_vec();
        frame.extend_from_slice(&payload);
        let count = encoder.encode(&frame, &mut encoded)?;
        assert!(count <= encoder.max_encoded_len());
        assert_eq!(decode_frame(&mut decoder, &encoded[..count])?, frame);
        let raw = vec![0xff; MAX_FRAME_BYTES];
        let count = encoder.encode(&raw, &mut encoded)?;
        assert_eq!(count, MAX_FRAME_BYTES + 3);
        assert_eq!(decode_frame(&mut decoder, &encoded[..count])?, raw);
        let before = encoder.context;
        assert_eq!(
            encoder.encode(&vec![0; MAX_FRAME_BYTES + 1], &mut encoded),
            Err(Error::FrameTooLarge)
        );
        assert_eq!(encoder.context, before);
    }
    let mut bounded = HeaderDecoder::new(65)?;
    assert!(bounded.decode_next(&vector.record, &mut [0; 65]).is_err());
    Ok(())
}

#[test]
fn valid_stale_delta_is_not_detectable_without_outer_epoch_context() -> TestResult {
    let vector = seed(HeaderProfile::TcpDelta)?;
    let mut first = HeaderDecoder::new(MAX_FRAME_BYTES)?;
    let mut second = HeaderDecoder::new(MAX_FRAME_BYTES)?;
    let mut out = vec![0; MAX_FRAME_BYTES];
    first.decode_next(&vector.record[..69], &mut out)?;
    let other = vectors()?
        .into_iter()
        .find(|v| v.profile == HeaderProfile::TcpDelta && v.name == "new_static_context")
        .ok_or("changed context fixture")?;
    second.decode_next(&other.record[..69], &mut out)?;
    let a = decode_frame(&mut first, &vector.record[69..])?;
    let b = decode_frame(&mut second, &vector.record[69..])?;
    assert_ne!(a, b);
    assert_eq!(a, vector.frame);
    second.reset();
    assert_eq!(
        second.decode_next(&vector.record[69..], &mut out),
        Err(Error::MissingContext)
    );
    Ok(())
}

#[test]
fn deterministic_hostile_inputs_never_exceed_output_or_commit_on_error() -> TestResult {
    let vector = seed(HeaderProfile::TcpDelta)?;
    let mut seed = 0x1357_9bdf_u32;
    for length in 0..256 {
        for initialized in [false, true] {
            let mut decoder = HeaderDecoder::new(512)?;
            let mut out = vec![0xcc; 512];
            if initialized {
                decoder.decode_next(&vector.record[..69], &mut out)?;
            }
            let previous = decoder.context;
            let mut bytes = vec![0; length];
            for byte in &mut bytes {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                *byte = (seed >> 24) as u8;
            }
            match decoder.decode_next(&bytes, &mut out) {
                Ok(Decoded::Frame {
                    consumed, written, ..
                }) => {
                    assert!(consumed <= bytes.len());
                    assert!(written <= out.len());
                }
                Ok(Decoded::Context { consumed }) => assert!(consumed <= bytes.len()),
                Err(_) => assert_eq!(decoder.context, previous),
            }
        }
    }
    Ok(())
}
