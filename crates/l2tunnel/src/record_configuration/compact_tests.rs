//! Complete requested policy is canonical; actual capability remains checked.
use super::*;
use l2tunnel_codec::source_copy;
use l2tunnel_recovery::{CompactArqConfig, CompactBounds, CompactRecovery, CompactTiming};
use l2tunnel_reliable::CompactReliableConfig;

fn policy(reverse: bool, packed: bool) -> Result<aligned::packed::CompactConfig> {
    let old = aligned_policy(reverse, packed);
    let arq = old.recovery.arq;
    let recovery = CompactReliableConfig::new(
        CompactArqConfig::new(
            CompactBounds {
                max_source_bytes: arq.max_source_bytes,
                send_bytes: arq.send_bytes,
                receive_bytes: arq.receive_bytes,
                send_records: arq.send_records,
                receive_records: arq.receive_records,
            },
            CompactTiming {
                nominal_rtt: Duration::from_nanos(if reverse { 90_000_013 } else { 70_000_011 }),
                feedback_interval: Duration::from_nanos(if reverse {
                    3_000_019
                } else {
                    5_000_017
                }),
                feedback_packets: if reverse { 63 } else { 64 },
            },
            if reverse { 79 } else { 77 },
            if reverse { 47 } else { 43 },
            if reverse { 7 } else { 8 },
            if reverse {
                CompactRecovery::BoundedGap {
                    min_interval: Duration::from_nanos(1_000_021),
                }
            } else {
                CompactRecovery::Guarded
            },
        )?,
        old.recovery.outer_overhead_bytes,
    )?;
    Ok(aligned::packed::CompactConfig {
        base: aligned::CompactConfig {
            native_policy: old.native_policy,
            receiver: old.receiver,
            recovery,
            max_recovery_packet_bytes: 1024,
            copies: source_copy::Policy::ONE,
        },
        hold_micros: if reverse { 901 } else { 201 },
        max_units: if reverse { 4 } else { 3 },
        work_limit: if reverse { 3 } else { 2 },
    })
}

fn value(
    forward: aligned::packed::CompactConfig,
    reverse: aligned::packed::CompactConfig,
    packed: bool,
) -> Result<Configuration> {
    let profile = if packed {
        Profile::PackedCompact { forward, reverse }
    } else {
        Profile::AlignedCompact {
            forward: forward.base,
            reverse: reverse.base,
        }
    };
    Ok(Configuration::new(
        EnvelopeDigest::new([0x6c; 32]),
        Descriptor::new(
            1500,
            Duplex::Full,
            common(
                false,
                false,
                forward.base.receiver.channels,
                forward.base.receiver.body.max_frame_bytes,
            )?,
            common(
                true,
                true,
                reverse.base.receiver.channels,
                reverse.base.receiver.body.max_frame_bytes,
            )?,
            profile,
        )?,
    )?)
}

#[test]
fn complete_compact_tags_preserve_both_directional_policies_strict_padding_and_explicit_copy_refusal()
-> Result {
    for packed in [false, true] {
        let forward = policy(false, packed)?;
        let reverse = policy(true, packed)?;
        let original = value(forward, reverse, packed)?;
        let bytes = encoded(&original)?;
        assert_eq!(bytes.len(), 1304);
        assert_eq!(&bytes[..4], b"L2RC");
        assert_eq!(bytes[4], 2);
        assert_eq!(bytes[5], if packed { 7 } else { 6 });
        assert_eq!(Configuration::decode(&bytes)?, original);
        assert_eq!(
            original.descriptor().sender_channels(Role::Client),
            forward.base.receiver.channels
        );
        assert_eq!(
            original.descriptor().sender_channels(Role::Server),
            reverse.base.receiver.channels
        );
        assert_eq!(
            transaction::configuration_digest(&original)?,
            original.digest()?
        );
        let used = if packed {
            aligned::packed::COMPACT_CONFIG_BYTES
        } else {
            aligned::COMPACT_CONFIG_BYTES
        };
        assert_eq!(used, if packed { 273 } else { 249 });
        for (base, direction) in [(320, forward), (948, reverse)] {
            let mut active = vec![0; used];
            if packed {
                direction.encode_into(&mut active)?;
                assert_eq!(aligned::packed::CompactConfig::decode(&active)?, direction);
            } else {
                direction.base.encode_into(&mut active)?;
                assert_eq!(aligned::CompactConfig::decode(&active)?, direction.base);
            }
            assert_eq!(&bytes[base..base + used], active);
            for offset in base + used..base + PROFILE_SLOT_BYTES {
                let mut malformed = bytes;
                malformed[offset] = 1;
                assert_eq!(Configuration::decode(&malformed), Err(Error::Padding));
            }
            for length in [0, used - 1, used + 1] {
                let malformed = vec![0; length];
                if packed {
                    assert!(aligned::packed::CompactConfig::decode(&malformed).is_err());
                } else {
                    assert!(aligned::CompactConfig::decode(&malformed).is_err());
                }
            }
        }
        // Fields absent from legacy R0/FEC policy remain actual digest inputs.
        let mut changed = forward;
        changed.base.recovery = CompactReliableConfig::new(
            CompactArqConfig::new(
                forward.base.recovery.arq().bounds(),
                forward.base.recovery.arq().timing(),
                forward.base.recovery.arq().maximum_feedback_bytes(),
                forward.base.recovery.arq().history_entries() + 1,
                forward.base.recovery.arq().maximum_attempts(),
                forward.base.recovery.arq().recovery(),
            )?,
            forward.base.recovery.outer_overhead_bytes(),
        )?;
        let changed = value(changed, reverse, packed)?;
        assert_ne!(encoded(&changed)?, bytes);
        assert_ne!(changed.digest()?, original.digest()?);
        // No selected Compact bytes are reinterpreted as an old family slot.
        let mut legacy_tag = bytes;
        legacy_tag[5] = if packed { 3 } else { 2 };
        assert!(Configuration::decode(&legacy_tag).is_err());
        if !packed {
            let mut requested = forward;
            requested.base.copies = source_copy::Policy {
                max_unit_bytes: 128,
                copies: 3,
                scope: source_copy::Scope::ContextAndIndependent,
            };
            let represented = value(requested, reverse, false)?;
            assert_eq!(Configuration::decode(&encoded(&represented)?)?, represented);
            assert_ne!(represented.digest()?, original.digest()?);
            assert!(matches!(
                aligned::compact_storage::Plan::for_duplex(requested.base, reverse.base),
                Err(aligned::storage::Error::Endpoint(
                    aligned::Error::UnsupportedCopies
                ))
            ));
            assert!(matches!(
                aligned::Endpoint::new_compact_duplex_reserved(
                    requested.base,
                    reverse.base,
                    l2tunnel_recovery::RecoveryContext {
                        session: 7,
                        epoch: 9,
                        role: l2tunnel_recovery::EndpointRole::Initiator
                    },
                    aligned::storage::Limits { capacity_bytes: 0 },
                ),
                Err(aligned::storage::Error::Endpoint(
                    aligned::Error::UnsupportedCopies
                ))
            ));
        }
    }
    Ok(())
}
