//! Literal tag4 slots and complete parser relations; legacy vectors stay separate.
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn current_repair_grammar_roundtrips_selected_formats_and_rejects_unknown_versions() -> TestResult {
    for format in [
        fec::rolling::wire::SourceWire::Padded,
        fec::rolling::wire::SourceWire::Exact,
        fec::rolling::wire::SourceWire::TargetedExact,
    ] {
        let config = crate::record_engine::rolling_tests::fixture(false, format)?;
        let mut bytes = [0; CONFIGURATION_BYTES];
        config.encode_into(&mut bytes)?;
        assert_eq!(Configuration::decode(&bytes)?, config);
        for offset in [
            HEADER_BYTES + 32 + COMMON_DIRECTION_BYTES + 40 * 8,
            HEADER_BYTES + 32 + DIRECTION_BYTES + COMMON_DIRECTION_BYTES + 40 * 8,
        ] {
            assert_eq!(
                &bytes[offset..offset + 8],
                &u64::from(format.policy_id()).to_be_bytes()
            );
            for old in [1u64, 2, 255, u64::MAX] {
                let mut stale = bytes;
                stale[offset..offset + 8].copy_from_slice(&old.to_be_bytes());
                assert_eq!(Configuration::decode(&stale), Err(Error::Prefix));
            }
            let mut ethernet_ack_compression = bytes;
            let selector = fec::rolling::wire::SourceWire::TargetedExactAckLz4.policy_id();
            ethernet_ack_compression[offset..offset + 8]
                .copy_from_slice(&u64::from(selector).to_be_bytes());
            assert_eq!(
                Configuration::decode(&ethernet_ack_compression),
                Err(Error::Profile)
            );
        }
    }
    Ok(())
}

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
        1000, 100, 2, 16_777_216, 4, 17, 50_000, 17,
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
    expected_digest.update(b"l2tunnel/record-transaction-config/v5\0");
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
        (40, 2),
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

#[test]
fn tag5_binds_both_copy_policies_and_rejects_noncanonical_fields() -> TestResult {
    use crate::codec::source_copy::{Policy, Scope};
    let old =
        crate::record_engine::rolling_tests::fixture(true, fec::rolling::wire::SourceWire::Exact)?;
    let Profile::Rolling { config, stream } = *old.descriptor().profile() else {
        return Err("missing Rolling fixture".into());
    };
    let policies = rolling_records::CopyPolicies {
        forward: Policy {
            max_unit_bytes: 128,
            copies: 3,
            scope: Scope::ContextAndIndependent,
        },
        reverse: Policy {
            max_unit_bytes: 64,
            copies: 2,
            scope: Scope::AllShort,
        },
    };
    let select = |copies| -> TestResult<Configuration> {
        let descriptor = old.descriptor();
        Ok(Configuration::new(
            old.envelope(),
            Descriptor::new(
                descriptor.path_mtu(),
                descriptor.duplex(),
                *descriptor.direction(Role::Client).common(),
                *descriptor.direction(Role::Server).common(),
                Profile::RollingCopies {
                    config,
                    stream,
                    copies,
                },
            )?,
        )?)
    };
    let selected = select(policies)?;
    let mut old_bytes = [0; CONFIGURATION_BYTES];
    let mut bytes = old_bytes;
    old.encode_into(&mut old_bytes)?;
    selected.encode_into(&mut bytes)?;
    assert_eq!(bytes[5], 5);
    let a = HEADER_BYTES + 32 + COMMON_DIRECTION_BYTES + rolling::ACTIVE_BYTES;
    let b = a + DIRECTION_BYTES;
    assert_eq!(&bytes[a..a + 4], &[0, 128, 3, 2]);
    assert_eq!(&bytes[b..b + 4], &[0, 64, 2, 1]);
    assert_eq!(Configuration::decode(&bytes)?, selected);
    assert_ne!(selected.digest()?, old.digest()?);
    let one = select(rolling_records::CopyPolicies::ONE)?;
    assert_ne!(one.digest()?, old.digest()?);
    let mut normalized = bytes;
    normalized[5] = 4;
    normalized[a..a + 4].fill(0);
    normalized[b..b + 4].fill(0);
    assert_eq!(normalized, old_bytes);
    for (offset, value) in [
        (a, 1),
        (a + 2, 0),
        (a + 2, 5),
        (b + 2, 5),
        (a + 3, 0),
        (b + 3, 3),
    ] {
        let mut bad = bytes;
        bad[offset] = value;
        assert!(Configuration::decode(&bad).is_err());
    }
    for changed in [
        rolling_records::CopyPolicies {
            forward: Policy {
                copies: 2,
                ..policies.forward
            },
            ..policies
        },
        rolling_records::CopyPolicies {
            reverse: Policy {
                max_unit_bytes: 63,
                ..policies.reverse
            },
            ..policies
        },
        rolling_records::CopyPolicies {
            reverse: Policy {
                scope: Scope::ContextAndIndependent,
                ..policies.reverse
            },
            ..policies
        },
    ] {
        assert_ne!(select(changed)?.digest()?, selected.digest()?);
    }
    Ok(())
}

#[test]
fn near8_is_one_authenticated_forward_word_and_needs_its_own_catalog_entry() -> TestResult {
    use fec::rolling::wire::SourceWire::{Exact, TargetedExact, TargetedNear8};
    let old = crate::record_engine::rolling_tests::fixture(false, TargetedExact)?;
    let Profile::Rolling { config, stream } = *old.descriptor().profile() else {
        return Err("missing rolling fixture".into());
    };
    let descriptor = old.descriptor();
    let select = |forward, reverse, with_copies| {
        let mut config = config;
        config.forward.scheduler.source_wire = forward;
        config.reverse.scheduler.source_wire = reverse;
        let profile = if with_copies {
            Profile::RollingCopies {
                config,
                stream,
                copies: rolling_records::CopyPolicies::ONE,
            }
        } else {
            Profile::Rolling { config, stream }
        };
        Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            *descriptor.direction(Role::Client).common(),
            *descriptor.direction(Role::Server).common(),
            profile,
        )
    };
    let baseline = select(TargetedExact, TargetedExact, true)?;
    let proposed = select(TargetedNear8, TargetedExact, true)?;
    let offset = HEADER_BYTES + COMMON_DIRECTION_BYTES + 40 * 8;
    let mut bytes = [0; DESCRIPTOR_BYTES];
    let mut old_bytes = bytes;
    baseline.encode_into(&mut old_bytes)?;
    proposed.encode_into(&mut bytes)?;
    assert_eq!(&bytes[offset..offset + 8], &6u64.to_be_bytes());
    assert_eq!(
        &bytes[offset + DIRECTION_BYTES..offset + DIRECTION_BYTES + 8],
        &5u64.to_be_bytes()
    );
    assert_eq!(Descriptor::decode(&bytes)?, proposed);
    bytes[offset..offset + 8].copy_from_slice(&5u64.to_be_bytes());
    assert_eq!(bytes, old_bytes);
    assert_ne!(
        Configuration::new(old.envelope(), baseline)?.digest()?,
        Configuration::new(old.envelope(), proposed)?.digest()?
    );
    let old_catalog = Catalog::new(baseline, &[baseline])?;
    let near_catalog = Catalog::new(proposed, &[proposed])?;
    assert_ne!(old_catalog.root(), near_catalog.root());
    assert!(matches!(
        Catalog::new(proposed, &[baseline]),
        Err(Error::Unlisted)
    ));
    assert!(select(TargetedExact, TargetedNear8, true).is_err());
    assert!(select(TargetedNear8, TargetedNear8, true).is_err());
    assert!(select(TargetedNear8, Exact, true).is_err());
    assert!(select(TargetedNear8, TargetedExact, false).is_err());
    let mut reverse_only = old_bytes;
    reverse_only[offset + DIRECTION_BYTES..offset + DIRECTION_BYTES + 8]
        .copy_from_slice(&6u64.to_be_bytes());
    assert!(Descriptor::decode(&reverse_only).is_err());
    Ok(())
}

#[test]
fn near8_variants_negotiate_distinct_directional_configuration_digests() -> TestResult {
    use fec::rolling::wire::SourceWire::{
        TargetedExact, TargetedNear8, TargetedNear8ConfirmedPrefix, TargetedNear8Hold35,
    };
    let old = crate::record_engine::rolling_tests::fixture(true, TargetedExact)?;
    let d = old.descriptor();
    let Profile::Rolling { mut config, stream } = *d.profile() else {
        return Err("missing rolling fixture".into());
    };
    let select = |config| {
        Descriptor::new(
            d.path_mtu(),
            d.duplex(),
            *d.direction(Role::Client).common(),
            *d.direction(Role::Server).common(),
            Profile::RollingCopies {
                config,
                stream,
                copies: rolling_records::CopyPolicies::ONE,
            },
        )
    };
    config.forward.scheduler.source_wire = TargetedNear8;
    let immediate = select(config)?;
    config.forward.scheduler.source_wire = TargetedNear8Hold35;
    let held = select(config)?;
    let mut bytes = [0; DESCRIPTOR_BYTES];
    held.encode_into(&mut bytes)?;
    assert_eq!(Descriptor::decode(&bytes)?, held);
    assert_eq!(TargetedNear8Hold35.version(), TargetedNear8.version());
    assert_ne!(
        Configuration::new(old.envelope(), immediate)?.digest()?,
        Configuration::new(old.envelope(), held)?.digest()?
    );
    assert!(matches!(
        Catalog::new(held, &[immediate]),
        Err(Error::Unlisted)
    ));
    config.forward.scheduler.source_wire = TargetedNear8ConfirmedPrefix;
    let prefix = select(config)?;
    prefix.encode_into(&mut bytes)?;
    assert_eq!(Descriptor::decode(&bytes)?, prefix);
    assert_ne!(
        Configuration::new(old.envelope(), immediate)?.digest()?,
        Configuration::new(old.envelope(), prefix)?.digest()?
    );
    assert!(matches!(
        Catalog::new(prefix, &[held, immediate]),
        Err(Error::Unlisted)
    ));
    for reverse in [TargetedNear8Hold35, TargetedNear8ConfirmedPrefix] {
        config.reverse.scheduler.source_wire = reverse;
        assert!(select(config).is_err());
    }
    Ok(())
}

#[test]
fn delivery_policy_selects_tags_11_and_12_and_round_trips_canonically() -> TestResult {
    use fec::rolling::wire::SourceWire::{Exact, TargetedExact, TargetedNear8Hold35};
    use rolling_records::{EffectiveRelease, GuardMode, NativeRelease, ReturnGuard};
    let old = crate::record_engine::rolling_tests::fixture(true, TargetedExact)?;
    let d = old.descriptor();
    let Profile::Rolling { config, stream } = *d.profile() else {
        return Err("missing rolling fixture".into());
    };
    assert!(config.forward.delivery_default() && config.reverse.delivery_default());
    assert_eq!(
        config.forward.effective_release(),
        EffectiveRelease::FlowOrdered
    );
    assert_eq!(config.forward.effective_guard_per_mille(), Some(100));
    let build = |config, copies: Option<rolling_records::CopyPolicies>| {
        Descriptor::new(
            d.path_mtu(),
            d.duplex(),
            *d.direction(Role::Client).common(),
            *d.direction(Role::Server).common(),
            match copies {
                None => Profile::Rolling { config, stream },
                Some(copies) => Profile::RollingCopies {
                    config,
                    stream,
                    copies,
                },
            },
        )
    };
    let word = |direction: usize| {
        HEADER_BYTES + direction * DIRECTION_BYTES + COMMON_DIRECTION_BYTES + 43 * 8
    };
    // All-default values keep tag 4 and a zero upper stream half.
    let mut default_bytes = [0; DESCRIPTOR_BYTES];
    build(config, None)?.encode_into(&mut default_bytes)?;
    assert_eq!(default_bytes[5], 4);
    for direction in [0, 1] {
        assert_eq!(default_bytes[word(direction)..word(direction) + 4], [0; 4]);
    }
    let mut mislabeled = default_bytes;
    mislabeled[5] = 11;
    assert_eq!(Descriptor::decode(&mislabeled), Err(Error::Prefix));

    let mut explicit = config;
    explicit.forward.native_release = NativeRelease::Independent;
    explicit.reverse.return_guard = ReturnGuard::on(250);
    let one = build(explicit, None)?;
    let mut bytes = [0; DESCRIPTOR_BYTES];
    one.encode_into(&mut bytes)?;
    assert_eq!(bytes[5], 11);
    assert_eq!(bytes[word(0)..word(0) + 4], [1, 0, 0, 0]);
    assert_eq!(bytes[word(1)..word(1) + 4], [0, 2, 0, 250]);
    assert_eq!(Descriptor::decode(&bytes)?, one);
    let mut as_tag4 = bytes;
    as_tag4[5] = 4;
    assert_eq!(Descriptor::decode(&as_tag4), Err(Error::Prefix));
    for (offset, value, error) in [
        (word(0), 3, Error::Prefix),      // unknown release
        (word(1) + 1, 3, Error::Prefix),  // unknown guard mode
        (word(1) + 1, 1, Error::Profile), // Off with a nonzero ratio
    ] {
        let mut changed = bytes;
        changed[offset] = value;
        assert_eq!(Descriptor::decode(&changed), Err(error));
    }
    let two = build(explicit, Some(rolling_records::CopyPolicies::ONE))?;
    two.encode_into(&mut bytes)?;
    assert_eq!(bytes[5], 12);
    assert_eq!(Descriptor::decode(&bytes)?, two);

    // An explicit value that resolves like the default is still bound separately.
    let mut same = config;
    same.forward.native_release = NativeRelease::FlowOrdered;
    assert_eq!(
        same.forward.effective_release(),
        config.forward.effective_release()
    );
    assert_ne!(same.digest()?, config.digest()?);
    assert_ne!(explicit.digest()?, config.digest()?);
    assert_ne!(
        Configuration::new(old.envelope(), one)?.digest()?,
        Configuration::new(old.envelope(), build(config, None)?)?.digest()?
    );

    for guard in [
        ReturnGuard::on(0),
        ReturnGuard::on(1001),
        ReturnGuard {
            mode: GuardMode::Off,
            per_mille: 5,
        },
    ] {
        let mut invalid = config;
        invalid.forward.return_guard = guard;
        assert!(build(invalid, None).is_err());
    }
    // Explicit values need a targeted IP direction without the bounded hold.
    let plain = crate::record_engine::rolling_tests::fixture(true, Exact)?;
    let Profile::Rolling { config: plain, .. } = *plain.descriptor().profile() else {
        return Err("missing rolling fixture".into());
    };
    assert_eq!(plain.forward.effective_release(), EffectiveRelease::Channel);
    assert_eq!(plain.forward.effective_guard_per_mille(), None);
    let mut untargeted = plain;
    untargeted.forward.native_release = NativeRelease::FlowOrdered;
    assert!(untargeted.validate().is_err());
    let mut unguarded = plain;
    unguarded.forward.return_guard = ReturnGuard::OFF;
    assert!(unguarded.validate().is_err());
    let mut held = config;
    held.forward.scheduler.source_wire = TargetedNear8Hold35;
    assert_eq!(
        held.forward.effective_release(),
        EffectiveRelease::BoundedHold
    );
    held.forward.native_release = NativeRelease::FlowOrdered;
    assert!(build(held, Some(rolling_records::CopyPolicies::ONE)).is_err());
    Ok(())
}
