use super::*;
use crate::{aligned_storage, source_copy};

fn selected(
    config: Config,
    policy: source_copy::Policy,
    reserved: bool,
) -> Result<Sender, Box<dyn std::error::Error>> {
    if reserved {
        let plan = aligned_storage::PackedSenderPlan::for_config(config)?;
        Ok(Sender::new_reserved_with_copies(
            scope(),
            config,
            aligned_storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
            policy,
        )?)
    } else {
        Ok(Sender::new_with_copies(scope(), config, policy)?)
    }
}

fn actual_frame() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let row = include_str!("../tests/data/aligned-sender-goldens.tsv")
        .lines()
        .find(|line| line.starts_with("symbol128\t0\t"))
        .ok_or("maintained actual frame")?;
    hex(row.split('\t').nth(6).ok_or("native field")?)
}

#[test]
fn actual_context_copy_boundary_retains_body_source_and_output_until_handoff() -> TestResult {
    let config = config(1460);
    let policy = source_copy::Policy {
        max_unit_bytes: 100,
        copies: 3,
        scope: source_copy::Scope::ContextAndIndependent,
    };
    let frame = actual_frame()?;
    for reserved in [false, true] {
        let mut sender = selected(config, policy, reserved)?;
        let usage = sender.storage_usage();
        sender.stage_identified(ChannelId(0), &frame, 10)?;
        assert_eq!(sender.copy_policy(), policy);
        assert_eq!(sender.pending_copies()?, 3);
        assert_eq!(
            sender.packing.pending().ok_or("context source")?.reason,
            packed::SealReason::CopyPolicy
        );
        assert_eq!(sender.status().next_unit, Some(SourceId(1)));
        assert!(sender.status().staged_frame);
        let saved = sender.status();
        let source = (1u64 << 60) + 9;
        let mut output = vec![0xa5; config.envelope().max_source_bytes()?];
        let length = sender.write_pending(SourceId(source), &mut output)?;
        let original = output.clone();
        let mut short = [0xa5; 8];
        assert!(matches!(
            sender.write_pending(SourceId(source), &mut short),
            Err(Error::Envelope(envelope::Error::OutputTooSmall { .. }))
        ));
        assert_eq!(short, [0xa5; 8]);
        sender.poll(900)?;
        assert_eq!(sender.status(), saved);
        assert_eq!(sender.pending_copies()?, 3);
        assert_eq!(sender.write_pending(SourceId(source), &mut output)?, length);
        assert_eq!(output, original);
        let context = envelope::decode(config.envelope(), scope(), &output[..length])?;
        assert_eq!(context.len(), 1);
        assert_eq!(context.identity().first_unit, SourceId(0));
        let unit = context.units()?.next().ok_or("actual context")?;
        assert_eq!(unit.identity.record, RecordId(0));
        assert_eq!(unit.bytes[3], 0);
        assert_eq!(unit.bytes.len(), 72);
        let context_source = output[..length].to_vec();
        sender.commit_source()?;
        assert!(sender.status().staged_frame);
        assert_eq!(sender.pending_copies(), Err(Error::NoPending));
        sender.flush(901)?;
        assert_eq!(sender.pending_copies()?, 1);
        let body_source = copy_to_test_owner(&mut sender, config, source + 1)?;
        let body = envelope::decode(config.envelope(), scope(), &body_source)?;
        assert_eq!(body.identity().first_unit, SourceId(1));
        assert_eq!(
            body.units()?.next().ok_or("actual body")?.identity.record,
            RecordId(1)
        );
        assert!(sender.is_idle());
        assert_eq!(sender.storage_usage(), usage);

        let mut receiver = receiver(config)?;
        receive(config, &mut receiver, source, &context_source)?;
        receive(config, &mut receiver, source + 1, &body_source)?;
        assert_eq!(
            receiver.prepare(ChannelId(0), receiver::Tick(1), 8)?,
            receiver::Prepared::Ready
        );
        assert_eq!(
            receiver
                .pending()
                .ok_or("actual reconstructed native")?
                .bytes,
            frame
        );
        receiver.commit_delivery(receiver::Tick(1))?;
        assert_eq!(
            receiver.prepare(ChannelId(0), receiver::Tick(1), 8)?,
            receiver::Prepared::Idle
        );
    }
    Ok(())
}

#[test]
fn generic_counts_apply_before_packing_and_default_bytes_and_fragment_policy_are_preserved()
-> TestResult {
    let config = config(64);
    let policy = source_copy::Policy {
        max_unit_bytes: 12,
        copies: 4,
        scope: source_copy::Scope::AllShort,
    };
    for reserved in [false, true] {
        let mut repeated = selected(config, policy, reserved)?;
        let mut explicit_one = selected(config, source_copy::Policy::ONE, reserved)?;
        let mut original = if reserved {
            let plan = aligned_storage::PackedSenderPlan::for_config(config)?;
            Sender::new_reserved(
                scope(),
                config,
                aligned_storage::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )?
        } else {
            Sender::new(scope(), config)?
        };
        for sender in [&mut repeated, &mut explicit_one, &mut original] {
            sender.stage_raw(ChannelId(0), &[1, 2, 0, 0], 10)?;
            sender.stage_raw(ChannelId(1), &[3, 4, 0, 0], 20)?;
            sender.flush(20)?;
        }
        assert_eq!(repeated.pending_copies()?, 4);
        assert_eq!(explicit_one.pending_copies()?, 1);
        assert_eq!(original.pending_copies()?, 1);
        let mut bytes = vec![0; config.envelope().max_source_bytes()?];
        let length = repeated.write_pending(SourceId(73), &mut bytes)?;
        let view = envelope::decode(config.envelope(), scope(), &bytes[..length])?;
        assert_eq!(view.len(), 2);
        assert!(view.payload().len() > policy.max_unit_bytes);
        for sender in [&mut explicit_one, &mut original] {
            let mut comparison = vec![0; bytes.len()];
            assert_eq!(sender.write_pending(SourceId(73), &mut comparison)?, length);
            assert_eq!(comparison, bytes);
            assert_eq!(sender.storage_usage(), repeated.storage_usage());
        }
        let bad = source_copy::Policy {
            copies: 5,
            ..policy
        };
        assert!(selected(config, bad, reserved).is_err());
        assert!(matches!(
            Sender::new_reserved_with_copies(
                scope(),
                config,
                aligned_storage::Limits { capacity_bytes: 0 },
                bad
            ),
            Err(aligned_storage::Error::PackedSender(Error::Copies(
                source_copy::Error::Configuration
            )))
        ));
    }

    let mut fragments = aligned::Sender::new(scope(), config.sender)?;
    fragments.stage_raw(ChannelId(0), &[0x51; 200])?;
    let all = source_copy::Policy {
        max_unit_bytes: 64,
        copies: 4,
        scope: source_copy::Scope::AllShort,
    };
    let selective = source_copy::Policy {
        scope: source_copy::Scope::ContextAndIndependent,
        ..all
    };
    let mut count = 0;
    while fragments.is_pending() {
        let before = fragments.pending_unit()?.bytes.to_vec();
        assert_eq!(before[3], 4);
        assert_eq!(fragments.pending_copies(all)?, 4);
        assert_eq!(fragments.pending_copies(selective)?, 1);
        assert_eq!(fragments.pending_unit()?.bytes, before);
        fragments.commit_unit()?;
        count += 1;
    }
    assert!(count > 1);
    Ok(())
}
