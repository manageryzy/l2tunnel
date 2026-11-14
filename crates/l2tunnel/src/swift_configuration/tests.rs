use super::*;
use transaction::Configuration as Canonical;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn forward() -> policy::Direction {
    policy::Direction {
        records: records::Config {
            channels: 3,
            layer: records::Layer::Ethernet,
            max_native: 1500,
            codec: l2tunnel_swift::Config {
                datagram_bytes: 1424,
                window: 7,
                repair_numerator: 1,
                repair_denominator: 3,
                flow_sources: 9,
                queue_bytes: 65_537,
                max_packet: 1501,
                flush_micros: 123,
                feedback_micros: 5001,
                tail_micros: 10_001,
                min_rto_micros: 20_001,
                max_rto_micros: 900_001,
            },
        },
        bytes_per_second: 2_000_001,
    }
}
fn reverse() -> policy::Direction {
    policy::Direction {
        records: records::Config {
            channels: 2,
            layer: records::Layer::Ethernet,
            max_native: 1500,
            codec: l2tunnel_swift::Config {
                datagram_bytes: 1200,
                window: 5,
                repair_numerator: 2,
                repair_denominator: 7,
                flow_sources: 11,
                queue_bytes: 32_769,
                max_packet: 1501,
                flush_micros: 17,
                feedback_micros: 3007,
                tail_micros: 11_003,
                min_rto_micros: 30_001,
                max_rto_micros: 700_003,
            },
        },
        bytes_per_second: 1_000_002,
    }
}
fn descriptor(path: usize) -> std::result::Result<Descriptor, Error> {
    Descriptor::new(path, forward(), reverse())
}
fn configuration() -> std::result::Result<Configuration, Error> {
    Configuration::new(EnvelopeDigest::new([0xa5; 32]), descriptor(1500)?)
}
fn wire(
    value: &Configuration,
) -> std::result::Result<[u8; CONFIGURATION_BYTES], transaction::Error> {
    let mut bytes = [0; CONFIGURATION_BYTES];
    value.encode_into(&mut bytes)?;
    Ok(bytes)
}
fn decoded(bytes: &[u8]) -> std::result::Result<Configuration, transaction::Error> {
    <Configuration as Canonical>::decode(bytes)
}
fn word(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

/// Positional wire vector independent of the production field visitor. Values
/// deliberately differ by direction and retain non-kilobit rates/fractions.
fn literal_wire() -> Vec<u8> {
    let mut bytes = b"L2TC\x01\x01\x01\x00".to_vec();
    bytes.extend_from_slice(&[0xa5; 32]);
    for number in [
        1500_u64, 3, 1, 1500, 2_000_001, 1424, 7, 1, 3, 9, 65_537, 1501, 123, 5001, 10_001, 20_001,
        900_001, 2, 1, 1500, 1_000_002, 1200, 5, 2, 7, 11, 32_769, 1501, 17, 3007, 11_003, 30_001,
        700_003,
    ] {
        bytes.extend_from_slice(&number.to_be_bytes());
    }
    bytes
}

#[test]
fn independent_complete_wire_and_digest_vectors_are_exact() -> Result {
    let value = configuration()?;
    let expected = literal_wire();
    assert_eq!(expected.len(), 304);
    assert_eq!(wire(&value)?.as_slice(), expected);
    assert_eq!(decoded(&expected)?, value);
    // Independently calculated from the literal bytes using standard SHA256,
    // including the exact domain and trailing NUL; no project codec was used.
    assert_eq!(
        transaction::configuration_digest(&value)?.0,
        [
            0xd6, 0x50, 0xa7, 0x17, 0x1a, 0xc7, 0xe3, 0x45, 0x89, 0x35, 0x5f, 0x41, 0x38, 0xc4,
            0xe3, 0x34, 0x23, 0xbb, 0x87, 0x62, 0x36, 0x60, 0x35, 0x7b, 0xe0, 0x64, 0x9e, 0xb6,
            0x63, 0x76, 0x7e, 0x1b,
        ]
    );
    Ok(())
}

#[test]
fn global_roles_preserve_both_complete_asymmetric_directions() -> Result {
    let value = configuration()?;
    let native = value.descriptor();
    assert_eq!(native.path_mtu(), 1500);
    assert_eq!(native.forward(), forward());
    assert_eq!(native.reverse(), reverse());
    assert_eq!(native.direction(Role::Client), forward());
    assert_eq!(native.direction(Role::Server), reverse());
    assert_eq!(value.channels(), 3);
    assert_eq!(value.sender_channels(Role::Client), 3);
    assert_eq!(value.sender_channels(Role::Server), 2);
    assert_eq!(value.duplex(), Duplex::Full);
    let restored = decoded(&wire(&value)?)?;
    assert_eq!(restored.sender_channels(Role::Client), 3);
    assert_eq!(restored.sender_channels(Role::Server), 2);
    assert_eq!(restored.descriptor().direction(Role::Server), reverse());
    Ok(())
}

#[test]
fn every_directional_wire_field_is_validated_and_bound() -> Result {
    let value = configuration()?;
    let original = wire(&value)?;
    let digest = transaction::configuration_digest(&value)?;
    for direction in 0..2 {
        for field in 0..16 {
            let offset = 48 + direction * 128 + field * 8;
            let mut mutated = original;
            let old = read_number(&mutated[offset..offset + 8])?;
            word(&mut mutated, offset, old + 1);
            let actual = decoded(&mutated);
            if matches!(field, 1 | 2 | 10) {
                // A single physical layer/max/encoded-max change breaks the
                // complete immutable native-format relationship.
                assert!(actual.is_err(), "direction {direction}, field {field}");
            } else {
                let actual = actual?;
                assert_eq!(wire(&actual)?, mutated);
                assert_ne!(
                    transaction::configuration_digest(&actual)?,
                    digest,
                    "direction {direction}, field {field}"
                );
            }
        }
    }
    let mut changed = original;
    word(&mut changed, 40, 1501);
    assert_ne!(
        transaction::configuration_digest(&decoded(&changed)?)?,
        digest
    );
    for (index, _) in original.iter().enumerate().take(40).skip(8) {
        let mut changed = original;
        changed[index] ^= 1;
        assert_ne!(
            transaction::configuration_digest(&decoded(&changed)?)?,
            digest
        );
    }
    Ok(())
}

#[test]
fn joint_native_format_changes_remain_explicit_in_the_digest() -> Result {
    let value = configuration()?;
    let mut original = wire(&value)?;
    for offset in [48, 176] {
        word(&mut original, offset + 8, 2);
        word(&mut original, offset + 16, 1499);
        word(&mut original, offset + 80, 1500);
    }
    let changed = decoded(&original)?;
    assert_eq!(
        changed.descriptor().forward().records.layer,
        records::Layer::Ip
    );
    assert_eq!(changed.descriptor().reverse().records.max_native, 1499);
    assert_ne!(
        transaction::configuration_digest(&changed)?,
        transaction::configuration_digest(&value)?
    );
    // A real session still rejects a changed native format at its envelope
    // preflight; this pure codec does not grant that runtime change.
    Ok(())
}

#[test]
fn malformed_lengths_prefixes_and_output_capacity_are_atomic() -> Result {
    let value = configuration()?;
    let expected = wire(&value)?;
    for length in 0..CONFIGURATION_BYTES {
        assert_eq!(
            decoded(&expected[..length]),
            Err(transaction::Error::Malformed)
        );
    }
    let mut extended = expected.to_vec();
    extended.push(0);
    assert_eq!(decoded(&extended), Err(transaction::Error::Malformed));
    for (offset, _) in expected.iter().enumerate().take(8) {
        let mut bytes = expected;
        bytes[offset] ^= 1;
        assert_eq!(decoded(&bytes), Err(transaction::Error::Malformed));
    }
    let mut short = [0xa7; CONFIGURATION_BYTES - 1];
    let mut long = [0xa7; CONFIGURATION_BYTES + 1];
    assert_eq!(
        value.encode_into(&mut short),
        Err(transaction::Error::Malformed)
    );
    assert_eq!(
        value.encode_into(&mut long),
        Err(transaction::Error::Malformed)
    );
    assert_eq!(short, [0xa7; CONFIGURATION_BYTES - 1]);
    assert_eq!(long, [0xa7; CONFIGURATION_BYTES + 1]);
    Ok(())
}

#[test]
fn scalar_and_conversion_failures_never_truncate_into_valid_values() -> Result {
    let original = wire(&configuration()?)?;
    // Each value would become a plausible small scalar if a decoder cast down
    // to32 bits before validation. Both directions must reject it unchanged.
    for direction in 0..2 {
        for (field, low) in [
            (0, 3),
            (2, 1500),
            (4, 1424),
            (5, 7),
            (6, 1),
            (7, 3),
            (8, 9),
            (9, 65_537),
            (10, 1501),
        ] {
            let mut bytes = original;
            word(
                &mut bytes,
                48 + direction * 128 + field * 8,
                (1_u64 << 32) + low,
            );
            assert_eq!(decoded(&bytes), Err(transaction::Error::Malformed));
        }
        for (field, invalid) in [
            (0, 0),
            (0, 65),
            (1, 0),
            (1, 3),
            (3, 7999),
            (3, 1_250_000_001),
            (4, 63),
            (4, 65_001),
            (5, 0),
            (5, 256),
            (6, 65_537),
            (7, 0),
            (7, 65_537),
            (8, 4),
            (8, 65_536),
            (9, 1502),
            (9, (1 << 30) + 1),
            (10, 0),
            (11, 1_000_001),
            (12, 0),
            (13, 0),
            (14, 0),
            (15, 60_000_001),
        ] {
            let mut bytes = original;
            word(&mut bytes, 48 + direction * 128 + field * 8, invalid);
            assert_eq!(
                decoded(&bytes),
                Err(transaction::Error::Malformed),
                "direction {direction}, field {field}"
            );
        }
    }
    for mtu in [0, 255, 65_536, u64::MAX] {
        let mut bytes = original;
        word(&mut bytes, 40, mtu);
        assert_eq!(decoded(&bytes), Err(transaction::Error::Malformed));
    }
    Ok(())
}

#[test]
fn exact_rates_and_fractions_are_never_rounded_or_normalized() -> Result {
    let exact = configuration()?;
    assert_eq!(exact.descriptor().forward().bytes_per_second, 2_000_001);
    assert_eq!(exact.descriptor().reverse().bytes_per_second, 1_000_002);
    assert_eq!(
        exact
            .descriptor()
            .forward()
            .records
            .codec
            .repair_denominator,
        3
    );
    let mut fraction = forward();
    fraction.records.codec.repair_numerator = 333;
    fraction.records.codec.repair_denominator = 1000;
    let approximate = Configuration::new(
        exact.envelope(),
        Descriptor::new(1500, fraction, reverse())?,
    )?;
    assert_ne!(
        transaction::configuration_digest(&exact)?,
        transaction::configuration_digest(&approximate)?
    );
    fraction.records.codec.repair_numerator = 2;
    fraction.records.codec.repair_denominator = 6;
    let equivalent_ratio = Configuration::new(
        exact.envelope(),
        Descriptor::new(1500, fraction, reverse())?,
    )?;
    assert_ne!(wire(&exact)?, wire(&equivalent_ratio)?);
    assert_ne!(
        transaction::configuration_digest(&exact)?,
        transaction::configuration_digest(&equivalent_ratio)?
    );
    Ok(())
}

#[test]
fn constructor_bounds_and_large_exact_values_round_trip() -> Result {
    assert_eq!(descriptor(255), Err(Error::PathMtu));
    assert_eq!(descriptor(65_536), Err(Error::PathMtu));
    let mut high = forward();
    high.bytes_per_second = 1_250_000_000;
    high.records.channels = 64;
    high.records.max_native = 65_534;
    high.records.codec.max_packet = 65_535;
    high.records.codec.datagram_bytes = 65_000;
    high.records.codec.window = 255;
    high.records.codec.repair_numerator = 65_536;
    high.records.codec.repair_denominator = 65_536;
    high.records.codec.flow_sources = 65_535;
    high.records.codec.queue_bytes = 1 << 30;
    high.records.codec.flush_micros = 1_000_000;
    high.records.codec.feedback_micros = u64::MAX;
    high.records.codec.tail_micros = u64::MAX;
    high.records.codec.min_rto_micros = 60_000_000;
    high.records.codec.max_rto_micros = 60_000_000;
    // Mirrors the existing pure scalar bounds only; large timers/resources do
    // not claim carrier geometry, prepared-budget or live timer feasibility.
    let value = Configuration::new(
        EnvelopeDigest::new([0; 32]),
        Descriptor::new(65_535, high, high)?,
    )?;
    assert_eq!(decoded(&wire(&value)?)?, value);
    let mut different = reverse();
    different.records.layer = records::Layer::Ip;
    assert_eq!(
        Descriptor::new(1500, forward(), different),
        Err(Error::NativeFormat)
    );
    let mut empty = forward();
    empty.records.max_native = 0;
    empty.records.codec.max_packet = 1;
    assert_eq!(Descriptor::new(256, empty, empty), Err(Error::NativeFormat));
    Ok(())
}

#[test]
fn catalog_has_independent_literal_root_and_order() -> Result {
    let initial = descriptor(1600)?;
    let first = descriptor(1500)?;
    let catalog = Catalog::new(initial, &[initial, first])?;
    assert_eq!(catalog.initial(), initial);
    assert_eq!(catalog.descriptors(), &[first, initial]);
    assert_eq!(
        catalog.root(),
        Catalog::new(initial, &[first, initial])?.root()
    );
    assert_eq!(
        *catalog.root().as_bytes(),
        [
            0x9e, 0x8d, 0x8c, 0xbf, 0xf2, 0x59, 0x19, 0xa7, 0xa4, 0x40, 0xfc, 0x4e, 0xbb, 0x49,
            0x51, 0xfc, 0xc6, 0xbc, 0xc2, 0xe8, 0xd7, 0xed, 0xef, 0xba, 0xe3, 0x68, 0x80, 0x02,
            0x9d, 0x6d, 0xf3, 0xfd,
        ]
    );
    Ok(())
}

#[test]
fn catalog_rejects_empty_oversized_duplicate_or_unlisted_initial() -> Result {
    let first = descriptor(1500)?;
    assert_eq!(Catalog::new(first, &[]), Err(Error::CatalogSize));
    assert_eq!(Catalog::new(first, &[first; 65]), Err(Error::CatalogSize));
    assert_eq!(Catalog::new(first, &[first, first]), Err(Error::Duplicate));
    assert_eq!(
        Catalog::new(descriptor(1600)?, &[first]),
        Err(Error::Unlisted)
    );
    let supported = (1500..1564)
        .map(descriptor)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let catalog = Catalog::new(first, &supported)?;
    assert_eq!(catalog.descriptors().len(), MAX_CATALOG_ENTRIES);
    assert_eq!(
        catalog.configurations(EnvelopeDigest::new([0; 32])).len(),
        64
    );
    Ok(())
}

#[test]
fn same_mtu_catalog_entries_are_sorted_by_the_full_both_direction_bytes() -> Result {
    let initial = descriptor(1500)?;
    let mut changed_forward = forward();
    changed_forward.records.codec.feedback_micros += 1;
    let forward_changed = Descriptor::new(1500, changed_forward, reverse())?;
    let mut changed_reverse = reverse();
    changed_reverse.records.codec.queue_bytes += 1;
    let reverse_changed = Descriptor::new(1500, forward(), changed_reverse)?;
    let catalog = Catalog::new(initial, &[forward_changed, reverse_changed, initial])?;
    assert_eq!(
        catalog.descriptors(),
        &[initial, reverse_changed, forward_changed]
    );
    assert_ne!(
        catalog.root(),
        Catalog::new(initial, &[initial, forward_changed])?.root()
    );
    assert_ne!(
        catalog.root(),
        Catalog::new(initial, &[initial, reverse_changed])?.root()
    );
    Ok(())
}

#[test]
fn anchor_free_catalog_binds_complete_configurations_without_hash_recursion() -> Result {
    let initial = descriptor(1500)?;
    let catalog = Catalog::new(initial, &[descriptor(1600)?, initial])?;
    let root = catalog.root();
    let first = catalog.configurations(EnvelopeDigest::new([1; 32]));
    let second = catalog.configurations(EnvelopeDigest::new([2; 32]));
    for ((a, b), descriptor) in first.iter().zip(&second).zip(catalog.descriptors()) {
        assert_eq!(a.descriptor(), *descriptor);
        assert_eq!(b.descriptor(), *descriptor);
        assert_eq!(a.envelope().as_bytes(), &[1; 32]);
        assert_eq!(b.envelope().as_bytes(), &[2; 32]);
        assert_ne!(
            transaction::configuration_digest(a)?,
            transaction::configuration_digest(b)?
        );
        assert_eq!(decoded(&wire(a)?)?, *a);
        assert_eq!(decoded(&wire(b)?)?, *b);
    }
    assert_eq!(catalog.root(), root);
    // These assertions prove only pure catalog/value separation. Neither label
    // authenticates an envelope, provisions a peer nor installs a data scope.
    Ok(())
}
