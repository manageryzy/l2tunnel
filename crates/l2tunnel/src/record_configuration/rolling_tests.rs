//! Literal tag4 slots and complete parser relations; legacy vectors stay separate.
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn tag4_preserves_fixed_v2_shape_and_literal_complete_directional_words() -> TestResult {
    let config =
        crate::record_engine::rolling_tests::fixture(false, fec::rolling::wire::SourceWire::Exact)?;
    let mut bytes = [0; CONFIGURATION_BYTES];
    config.encode_into(&mut bytes)?;
    assert_eq!(CONFIGURATION_BYTES, 1304);
    assert_eq!(DESCRIPTOR_BYTES, 1272);
    assert_eq!(&bytes[..8], b"L2RC\x02\x04\x02\0");
    let forward: [u64; 44] = [
        1, 1024, 192, 1, 1, 1, 64, 3, 7, 13, 32, 32, 4, 262140, 64, 8, 5_000_000, 192, 503, 4, 13,
        4, 1_000_000, 16, 4, 2, 512, 16, 64, 2, 1_000_000, 10_000_000, 2_000_000, 16_777_216, 1, 2,
        1000, 100, 2, 16_777_216, 2, 17, 50_000, 17,
    ];
    let mut reverse = forward;
    for (index, value) in [
        (2, 224),
        (7, 2),
        (8, 19),
        (9, 91),
        (17, 224),
        (18, 701),
        (20, 91),
        (41, 73),
    ] {
        reverse[index] = value;
    }
    for (offset, expected) in [
        (HEADER_BYTES + 32 + COMMON_DIRECTION_BYTES, forward),
        (
            HEADER_BYTES + 32 + DIRECTION_BYTES + COMMON_DIRECTION_BYTES,
            reverse,
        ),
    ] {
        for (index, value) in expected.into_iter().enumerate() {
            assert_eq!(
                &bytes[offset + index * 8..offset + (index + 1) * 8],
                &value.to_be_bytes()
            );
        }
        assert_eq!(
            &bytes[offset + rolling::ACTIVE_BYTES..offset + PROFILE_SLOT_BYTES],
            &[0; 4]
        );
    }
    assert_eq!(Configuration::decode(&bytes)?, config);
    let mut descriptor = [0; DESCRIPTOR_BYTES];
    config.descriptor().encode_into(&mut descriptor)?;
    assert_eq!(Descriptor::decode(&descriptor)?, *config.descriptor());
    let mut expected_digest = digest::Context::new(&digest::SHA256);
    expected_digest.update(b"l2tunnel/record-transaction-config/v2\0");
    expected_digest.update(&bytes);
    assert_eq!(
        config.digest()?.0.as_slice(),
        expected_digest.finish().as_ref()
    );
    assert_eq!(
        <Configuration as transaction::Configuration>::ENCODED_LEN,
        1304
    );
    Ok(())
}

#[test]
fn tag4_padding_shared_bindings_narrow_fields_and_aliases_refuse_without_output_mutation()
-> TestResult {
    let config = crate::record_engine::rolling_tests::fixture(
        false,
        fec::rolling::wire::SourceWire::Padded,
    )?;
    let mut bytes = [0; CONFIGURATION_BYTES];
    config.encode_into(&mut bytes)?;
    let a = HEADER_BYTES + 32 + COMMON_DIRECTION_BYTES;
    let b = a + DIRECTION_BYTES;
    for (offset, value) in [
        (a + rolling::ACTIVE_BYTES, 1),
        (b + rolling::ACTIVE_BYTES + 3, 1),
    ] {
        let mut bad = bytes;
        bad[offset] = value;
        assert_eq!(Configuration::decode(&bad), Err(Error::Padding));
    }
    for (offset, value) in [(b + 42 * 8, 50_001u64), (b + 43 * 8, 18)] {
        let mut bad = bytes;
        bad[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        assert_eq!(Configuration::decode(&bad), Err(Error::Relation));
    }
    for (word, value) in [
        (3, 2u64),
        (7, u64::MAX),
        (40, 3),
        (43, u64::from(u32::MAX) + 1),
    ] {
        let mut bad = bytes;
        bad[a + word * 8..a + (word + 1) * 8].copy_from_slice(&value.to_be_bytes());
        assert!(Configuration::decode(&bad).is_err());
    }
    let Profile::Rolling { mut config, stream } = *config.descriptor().profile() else {
        return Err("wrong real family".into());
    };
    config.forward.packing.sender.first_record.0 += 1;
    assert!(config.validate().is_err());
    let mut output = [0x93; CONFIGURATION_BYTES];
    assert!(
        rolling::encode(
            config.forward,
            17,
            50_000,
            stream,
            &mut output[..PROFILE_SLOT_BYTES]
        )
        .is_err()
    );
    assert_eq!(output, [0x93; CONFIGURATION_BYTES]);
    Ok(())
}
