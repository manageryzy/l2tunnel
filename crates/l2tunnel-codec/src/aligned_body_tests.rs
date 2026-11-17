use super::*;
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
struct Vector {
    trace: &'static str,
    case: usize,
    config: Config,
    frame: Vec<u8>,
    context: Vec<u8>,
    body: Vec<u8>,
    encoder: Option<[u8; 66]>,
    decoder: Option<[u8; 66]>,
}
fn hex(text: &str) -> Result<Vec<u8>, TestError> {
    if !text.len().is_multiple_of(2) {
        return Err("odd fixture hex".into());
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
fn context(text: &str) -> Result<Option<[u8; 66]>, TestError> {
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            hex(text)?.try_into().map_err(|_| "fixture context size")?,
        ))
    }
}
fn vectors() -> Result<Vec<Vector>, TestError> {
    include_str!("../tests/data/aligned-body-goldens.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 12 {
                return Err("fixture columns".into());
            }
            Ok(Vector {
                trace: fields[0],
                case: fields[1].parse()?,
                config: Config {
                    max_frame_bytes: 65535,
                    symbol_bytes: fields[2].parse()?,
                    elide_payload_length: fields[3] == "1",
                    predictive: fields[4] == "1",
                    timestamp_pair_dictionary: fields[5] == "1",
                    independent_short_frame_bytes: fields[6].parse()?,
                },
                frame: hex(fields[7])?,
                context: hex(fields[8])?,
                body: hex(fields[9])?,
                encoder: context(fields[10])?,
                decoder: context(fields[11])?,
            })
        })
        .collect()
}
fn config() -> Config {
    Config {
        max_frame_bytes: 65535,
        symbol_bytes: 1460,
        elide_payload_length: true,
        predictive: true,
        timestamp_pair_dictionary: true,
        independent_short_frame_bytes: 0,
    }
}
fn vector(trace: &str, case: usize) -> Result<Vector, TestError> {
    vectors()?
        .into_iter()
        .find(|v| v.trace == trace && v.case == case)
        .ok_or_else(|| "missing vector".into())
}
fn decode(decoder: &mut Decoder, body: &[u8], native: Option<&[u8]>) -> TestResult {
    let before = decoder.header.clone();
    let mut output = vec![0xcc; decoder.config.max_frame_bytes];
    let event = decoder.decode_body(body, Padding::Exact, &mut output)?;
    match (event, native) {
        (Decoded::Context { consumed }, None) => {
            assert_eq!(consumed, body.len());
            assert!(output.iter().all(|b| *b == 0xcc));
        }
        (
            Decoded::Frame {
                consumed, written, ..
            },
            Some(frame),
        ) => {
            assert_eq!(consumed, body.len());
            assert_eq!(&output[..written], frame);
        }
        _ => return Err("wrong decode event".into()),
    }
    if body.len() <= decoder.config.symbol_bytes - 3 {
        let expected = decoder.header.context().copied();
        decoder.header = before;
        let mut padded = body.to_vec();
        padded.resize(decoder.config.symbol_bytes - 3, 0);
        let padded_event = decoder.decode_body(&padded, Padding::ZeroExtended, &mut output)?;
        assert_eq!(event, padded_event);
        assert_eq!(decoder.header.context().copied(), expected);
        if let Some(frame) = native {
            assert_eq!(&output[..frame.len()], frame);
        }
    }
    Ok(())
}
#[test]
fn actual_python_bodies_all_masks_pairs_and_contexts_match_exactly() -> TestResult {
    let vectors = vectors()?;
    assert_eq!(vectors.len(), 328);
    let mut encoder = Encoder::new(config())?;
    let mut decoder = Decoder::new(config())?;
    for vector in vectors {
        if vector.case == 0 {
            encoder = Encoder::new(vector.config)?;
            decoder = Decoder::new(vector.config)?;
        }
        let mut bytes = vec![0xcc; encoder.max_encoded_len()];
        let encoded = encoder.encode(&vector.frame, &mut bytes)?;
        let observation = encoded.observation();
        assert_eq!(observation.original_native_bytes, vector.frame.len());
        assert_eq!(observation.context_bytes, vector.context.len());
        assert_eq!(observation.encoded_body_bytes, vector.body.len());
        assert_eq!(observation.framing_bytes, 0);
        assert_eq!(
            observation.codec_net_gain_bytes(),
            vector.frame.len() as i128 - vector.context.len() as i128 - vector.body.len() as i128
        );
        assert_eq!(
            &bytes[..encoded.context_len],
            vector.context,
            "{} {} context",
            vector.trace,
            vector.case
        );
        assert_eq!(
            &bytes[encoded.context_len..encoded.written()],
            vector.body,
            "{} {} body",
            vector.trace,
            vector.case
        );
        assert_eq!(
            encoder.header.context().copied(),
            vector.encoder,
            "{} {} encoder state",
            vector.trace,
            vector.case
        );
        if !vector.context.is_empty() {
            decode(&mut decoder, &vector.context, None)?;
        }
        decode(&mut decoder, &vector.body, Some(&vector.frame))?;
        assert_eq!(
            decoder.header.context().copied(),
            vector.decoder,
            "{} {} decoder state",
            vector.trace,
            vector.case
        );
    }
    Ok(())
}
#[test]
fn every_fixture_truncation_and_short_output_rolls_back_context_and_output() -> TestResult {
    let mut encoder = Encoder::new(config())?;
    let mut decoder = Decoder::new(config())?;
    let mut scratch = vec![0; encoder.max_encoded_len()];
    for vector in vectors()? {
        if vector.case == 0 {
            encoder = Encoder::new(vector.config)?;
            decoder = Decoder::new(vector.config)?;
        }
        let before = encoder.header.context().copied();
        let needed = vector.context.len() + vector.body.len();
        for size in [0, needed - 1] {
            let mut output = vec![0xcc; size];
            assert!(matches!(
                encoder.encode(&vector.frame, &mut output),
                Err(Error::OutputTooSmall { .. })
            ));
            assert_eq!(encoder.header.context().copied(), before);
            assert!(output.iter().all(|b| *b == 0xcc));
        }
        encoder.encode(&vector.frame, &mut scratch)?;
        for (record, is_context) in [(&vector.context, true), (&vector.body, false)] {
            if record.is_empty() {
                continue;
            }
            let before = decoder.header.context().copied();
            let mut output = vec![0xcc; vector.frame.len()];
            for cut in 0..record.len() {
                assert!(
                    decoder
                        .decode_body(&record[..cut], Padding::Exact, &mut output)
                        .is_err(),
                    "{} {} cut {}",
                    vector.trace,
                    vector.case,
                    cut
                );
                assert_eq!(decoder.header.context().copied(), before);
                assert!(output.iter().all(|b| *b == 0xcc));
            }
            if !is_context && !vector.frame.is_empty() {
                let mut short = vec![0xcc; vector.frame.len() - 1];
                assert!(matches!(
                    decoder.decode_body(record, Padding::Exact, &mut short),
                    Err(Error::OutputTooSmall { .. })
                ));
                assert_eq!(decoder.header.context().copied(), before);
                assert!(short.iter().all(|b| *b == 0xcc));
            }
            decoder.decode_body(record, Padding::Exact, &mut output)?;
        }
    }
    Ok(())
}
#[test]
fn padding_validation_is_transactional_and_separate_from_header_elision() -> TestResult {
    let first = vector("pair_64_0", 0)?;
    let second = vector("pair_64_0", 1)?;
    let mut decoder = Decoder::new(config())?;
    let mut output = vec![0xcc; 65535];
    let mut bad_context = first.context.clone();
    bad_context.push(0);
    assert_eq!(
        decoder.decode_body(&bad_context, Padding::Exact, &mut output),
        Err(Error::Padding)
    );
    assert!(!decoder.has_context());
    decode(&mut decoder, &first.context, None)?;
    decode(&mut decoder, &first.body, Some(&first.frame))?;
    let before = decoder.header.context().copied();
    for body in [&second.body, &first.context] {
        let mut padded = body.clone();
        padded.resize(1457, 0);
        padded[1456] = 1;
        assert_eq!(
            decoder.decode_body(&padded, Padding::ZeroExtended, &mut output),
            Err(Error::Padding)
        );
        assert_eq!(decoder.header.context().copied(), before);
        assert!(output.iter().all(|b| *b == 0xcc));
        assert_eq!(
            decoder.decode_body(body, Padding::ZeroExtended, &mut output),
            Err(Error::Padding)
        );
        let mut exact = body.clone();
        exact.push(0);
        assert_eq!(
            decoder.decode_body(&exact, Padding::Exact, &mut output),
            Err(Error::Padding)
        );
    }
    decode(&mut decoder, &second.body, Some(&second.frame))?;
    Ok(())
}
#[test]
fn reset_and_generic_short_fallback_preserve_required_context_boundaries() -> TestResult {
    let rows = vectors()?;
    let short: Vec<_> = rows.iter().filter(|v| v.trace == "short").collect();
    let mut encoder = Encoder::new(short[0].config)?;
    let mut decoder = Decoder::new(short[0].config)?;
    let mut bytes = vec![0; encoder.max_encoded_len()];
    for row in short {
        let before = encoder.header.context().copied();
        let encoded = encoder.encode(&row.frame, &mut bytes)?;
        if row.frame.len() <= 128 {
            assert_eq!(encoded.kind, BodyKind::Raw);
            assert_eq!(encoded.context_len, 0);
            assert_eq!(encoder.header.context().copied(), before);
        }
        if encoded.context_len != 0 {
            decode(&mut decoder, &bytes[..encoded.context_len], None)?;
        }
        decode(
            &mut decoder,
            &bytes[encoded.context_len..encoded.written()],
            Some(&row.frame),
        )?;
    }
    encoder.reset();
    decoder.reset();
    let second = vector("pair_64_0", 1)?;
    let mut output = vec![0xcc; 1024];
    assert_eq!(
        decoder.decode_body(&second.body, Padding::Exact, &mut output),
        Err(Error::Header(tcp_header::Error::MissingContext))
    );
    assert!(!encoder.has_context() && !decoder.has_context());
    assert!(output.iter().all(|b| *b == 0xcc));
    Ok(())
}
#[test]
fn finite_maxima_explicit_fragment_fallback_and_small_native_large_symbol_work() -> TestResult {
    for invalid in [
        Config {
            max_frame_bytes: 0,
            ..config()
        },
        Config {
            max_frame_bytes: 65536,
            ..config()
        },
        Config {
            symbol_bytes: 8,
            ..config()
        },
        Config {
            symbol_bytes: 65536,
            ..config()
        },
        Config {
            predictive: false,
            ..config()
        },
        Config {
            independent_short_frame_bytes: 1455,
            ..config()
        },
    ] {
        assert!(Encoder::new(invalid).is_err());
        assert!(Decoder::new(invalid).is_err());
    }
    let mut encoder = Encoder::new(config())?;
    let mut out = vec![0xcc; encoder.max_encoded_len()];
    let raw = vec![0xaa; 65532];
    let encoded = encoder.encode(&raw, &mut out)?;
    assert_eq!(encoded.body_len, 65535);
    assert_eq!(encoded.kind, BodyKind::Raw);
    let mut decoder = Decoder::new(config())?;
    decode(&mut decoder, &out[..encoded.written()], Some(&raw))?;
    out.fill(0xcc);
    assert_eq!(
        encoder.encode(&vec![0xaa; 65533], &mut out),
        Err(Error::RecordTooLarge)
    );
    assert!(!encoder.has_context());
    assert!(out.iter().all(|b| *b == 0xcc));
    for case in 0..2 {
        let row = vector("capacity_4000", case)?;
        let encoded = encoder.encode(&row.frame, &mut out)?;
        assert_eq!(encoded.kind, BodyKind::Delta);
        assert!(encoded.body_len > 1457);
    }
    let bounded = Config {
        max_frame_bytes: 130,
        symbol_bytes: 65535,
        ..config()
    };
    let mut decoder = Decoder::new(bounded)?;
    for case in 0..2 {
        let row = vector("pair_64_0", case)?;
        if !row.context.is_empty() {
            decode(&mut decoder, &row.context, None)?;
        }
        decode(&mut decoder, &row.body, Some(&row.frame))?;
    }
    assert_eq!(
        decoder.expanded.len() + decoder.native.len(),
        2 * bounded.max_frame_bytes + 44
    );
    Ok(())
}
#[test]
fn malformed_context_varints_and_hostile_bodies_do_not_commit_or_panic() -> TestResult {
    let first = vector("pair_64_0", 0)?;
    let mut decoder = Decoder::new(config())?;
    let mut output = vec![0xcc; 65535];
    let mut context = first.context.clone();
    context[3 + 24] ^= 1;
    assert!(
        decoder
            .decode_body(&context, Padding::Exact, &mut output)
            .is_err()
    );
    assert!(!decoder.has_context());
    decode(&mut decoder, &first.context, None)?;
    let before = decoder.header.context().copied();
    for bytes in [
        vec![4, 0, 0],
        vec![6, 0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        vec![255, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
    ] {
        assert!(
            decoder
                .decode_body(&bytes, Padding::Exact, &mut output)
                .is_err()
        );
        assert_eq!(decoder.header.context().copied(), before);
        assert!(output.iter().all(|b| *b == 0xcc));
    }
    let mut state = 0x12345678u32;
    for size in 0..512 {
        let mut body = vec![0; size];
        for byte in &mut body {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        let mut candidate = Decoder::new(config())?;
        candidate.header = decoder.header.clone();
        let before = candidate.header.context().copied();
        output.fill(0xcc);
        if candidate
            .decode_body(&body, Padding::Exact, &mut output)
            .is_err()
        {
            assert_eq!(candidate.header.context().copied(), before);
            assert!(output.iter().all(|b| *b == 0xcc));
        }
    }
    Ok(())
}
