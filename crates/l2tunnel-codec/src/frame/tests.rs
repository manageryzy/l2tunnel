use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn codec(
    layer: FrameLayer,
    compression: Compression,
    maximum: usize,
) -> Result<FrameCodec, CodecError> {
    FrameCodec::new(CodecConfig {
        layer,
        max_frame_bytes: maximum,
        compression,
    })
}

#[test]
fn exact_raw_header_and_all_small_lengths_round_trip() -> TestResult {
    let raw = codec(FrameLayer::Ethernet, Compression::None, 1024)?;
    assert_eq!(
        raw.encode_vec(&[1, 2])?,
        vec![b'L', b'F', 1, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 1, 2]
    );
    for layer in [FrameLayer::Ethernet, FrameLayer::Ip] {
        let mut raw = codec(layer, Compression::None, 1024)?;
        for length in 1..=1024 {
            let original: Vec<_> = (0..length).map(|i| ((i * 31) % 251) as u8).collect();
            let record = raw.encode_vec(&original)?;
            assert_eq!(record.len(), FRAME_HEADER_BYTES + length);
            assert_eq!(raw.decode_vec(&record)?, original);
            let mut output = vec![0xa5; length + 4];
            assert_eq!(raw.decode(&record, &mut output)?, length);
            assert_eq!(output.get(..length), Some(original.as_slice()));
            assert_eq!(output.get(length..), Some([0xa5; 4].as_slice()));
        }
        raw.reset();
    }
    Ok(())
}

#[test]
fn maximum_frame_boundary_and_local_configuration_limits() -> TestResult {
    assert!(matches!(
        codec(FrameLayer::Ip, Compression::None, 0),
        Err(CodecError::InvalidConfig)
    ));
    assert!(matches!(
        codec(FrameLayer::Ip, Compression::None, MAX_FRAME_BYTES + 1),
        Err(CodecError::InvalidConfig)
    ));
    let mut raw = codec(FrameLayer::Ip, Compression::None, MAX_FRAME_BYTES)?;
    let frame = vec![0x79; MAX_FRAME_BYTES];
    let encoded = raw.encode_vec(&frame)?;
    assert_eq!(encoded.len(), raw.max_encoded_len());
    assert_eq!(raw.decode_vec(&encoded)?, frame);
    let mut destination = [0xa5; 16];
    assert_eq!(
        raw.encode(&[], &mut destination),
        Err(CodecError::EmptyFrame)
    );
    assert_eq!(destination, [0xa5; 16]);
    let small = codec(FrameLayer::Ip, Compression::None, 1)?;
    assert_eq!(small.encode_vec(&[1, 2]), Err(CodecError::FrameTooLarge));
    Ok(())
}

#[test]
fn encode_decode_destinations_are_atomic_on_capacity_failure() -> TestResult {
    let mut raw = codec(FrameLayer::Ethernet, Compression::None, 64)?;
    let frame = vec![3; 32];
    let record = raw.encode_vec(&frame)?;
    let mut output = [0xa5; 31];
    assert_eq!(
        raw.decode(&record, &mut output),
        Err(CodecError::OutputTooSmall)
    );
    assert_eq!(output, [0xa5; 31]);
    assert_eq!(
        raw.encode(&frame, &mut output),
        Err(CodecError::OutputTooSmall)
    );
    assert_eq!(output, [0xa5; 31]);
    Ok(())
}

#[test]
fn every_truncation_and_header_corruption_is_rejected_atomically() -> TestResult {
    let mut raw = codec(FrameLayer::Ethernet, Compression::None, 256)?;
    let record = raw.encode_vec(&[7; 64])?;
    for length in 0..record.len() {
        let mut output = [0xa5; 256];
        assert!(raw.decode(&record[..length], &mut output).is_err());
        assert_eq!(output, [0xa5; 256]);
    }
    for (offset, value) in [
        (0, 0),
        (2, 2),
        (3, 0),
        (3, 2),
        (4, 2),
        (5, 1),
        (6, 1),
        (7, 1),
    ] {
        let mut invalid = record.clone();
        invalid[offset] = value;
        let mut output = [0xa5; 256];
        assert!(raw.decode(&invalid, &mut output).is_err());
        assert_eq!(output, [0xa5; 256]);
    }
    for offset in [8, 12] {
        for declared in [0_u32, 63, 65, u32::MAX] {
            let mut invalid = record.clone();
            invalid[offset..offset + 4].copy_from_slice(&declared.to_be_bytes());
            let mut output = [0xa5; 256];
            assert!(raw.decode(&invalid, &mut output).is_err());
            assert_eq!(output, [0xa5; 256]);
        }
    }
    let mut trailing = record;
    trailing.push(0);
    assert_eq!(raw.decode_vec(&trailing), Err(CodecError::InvalidLength));
    Ok(())
}

#[cfg(feature = "lz4")]
#[test]
fn compression_is_selected_only_if_smaller_and_has_no_dictionary() -> TestResult {
    let compress = codec(FrameLayer::Ip, Compression::Lz4IfSmaller, 16384)?;
    let raw = codec(FrameLayer::Ip, Compression::None, 16384)?;
    let repeated = vec![0x81; 8192];
    let record = compress.encode_vec(&repeated)?;
    assert_eq!(record[4], 1);
    assert!(record.len() < repeated.len() + FRAME_HEADER_BYTES);
    assert_eq!(raw.decode_vec(&record)?, repeated);
    assert_eq!(compress.encode_vec(&[7])?[4], 0);
    let mut seed = 0x3197_42a1_u32;
    let random: Vec<_> = (0..2048)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect();
    let record = compress.encode_vec(&random)?;
    assert_eq!(record[4], 0);
    assert_eq!(compress.decode_vec(&record)?, random);
    // Independently encoded blocks need no preceding record for correct decoding.
    let fresh = codec(FrameLayer::Ip, Compression::None, 16384)?;
    assert_eq!(
        fresh.decode_vec(&compress.encode_vec(&repeated)?)?,
        repeated
    );
    Ok(())
}

#[cfg(feature = "lz4")]
#[test]
fn malformed_lz4_expansion_and_wrong_exact_length_leave_output_unchanged() -> TestResult {
    let mut codec = codec(FrameLayer::Ip, Compression::Lz4IfSmaller, 16384)?;
    let record = codec.encode_vec(&vec![7; 8192])?;
    assert_eq!(record[4], 1);
    for declared in [128_u32, 8191, 8193, 16384] {
        let mut invalid = record.clone();
        invalid[8..12].copy_from_slice(&declared.to_be_bytes());
        let mut output = vec![0xa5; 16384];
        assert_eq!(
            codec.decode(&invalid, &mut output),
            Err(CodecError::MalformedCompression)
        );
        assert!(output.iter().all(|value| *value == 0xa5));
    }
    for body_length in 1..record.len() - FRAME_HEADER_BYTES {
        let mut truncated = record[..FRAME_HEADER_BYTES + body_length].to_vec();
        truncated[12..16].copy_from_slice(&u32::try_from(body_length)?.to_be_bytes());
        let mut output = vec![0xa5; 8192];
        assert_eq!(
            codec.decode(&truncated, &mut output),
            Err(CodecError::MalformedCompression)
        );
        assert!(output.iter().all(|value| *value == 0xa5));
    }
    Ok(())
}

#[cfg(not(feature = "lz4"))]
#[test]
fn no_feature_build_rejects_lz4_explicitly() -> TestResult {
    assert!(matches!(
        codec(FrameLayer::Ip, Compression::Lz4IfSmaller, 64),
        Err(CodecError::CompressionUnavailable)
    ));
    let raw = codec(FrameLayer::Ip, Compression::None, 64)?;
    let mut compressed = raw.encode_vec(&[1; 10])?;
    compressed[4] = 1;
    compressed[12..16].copy_from_slice(&1_u32.to_be_bytes());
    compressed.truncate(FRAME_HEADER_BYTES + 1);
    assert_eq!(
        raw.decode_vec(&compressed),
        Err(CodecError::CompressionUnavailable)
    );
    Ok(())
}

#[test]
fn original_length_preflight_reuses_strict_framing_without_decoding_allocations() -> TestResult {
    for layer in [FrameLayer::Ethernet, FrameLayer::Ip] {
        for compression in [Compression::None, Compression::Lz4IfSmaller] {
            if compression == Compression::Lz4IfSmaller && !cfg!(feature = "lz4") {
                continue;
            }
            let codec = codec(layer, compression, 1500)?;
            let record = codec.encode_vec(&vec![7; 1500])?;
            assert_eq!(codec.decoded_len(&record)?, 1500);
            assert_eq!(codec.decode_vec(&record)?.len(), 1500);
            for end in 0..FRAME_HEADER_BYTES {
                assert!(codec.decoded_len(&record[..end]).is_err());
            }
            let mut bad = record.clone();
            bad.push(0);
            assert!(codec.decoded_len(&bad).is_err());
            let mut bad = record.clone();
            bad[8..12].copy_from_slice(&1501u32.to_be_bytes());
            assert!(codec.decoded_len(&bad).is_err());
            let mut bad = record;
            bad[5] = 1;
            assert!(codec.decoded_len(&bad).is_err());
        }
    }
    Ok(())
}
