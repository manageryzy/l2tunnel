use super::*;
use crate::record_configuration as configuration;
use crate::{fec::rolling, management::Role};
use l2tunnel_codec::aligned_receiver as receiver;
use l2tunnel_reliable::OutboundBudget;
use std::time::Duration;

#[test]
fn actual_rolling_carrier_tokens_bind_bank_before_time_and_never_ack_on_poll()
-> Result<(), Box<dyn std::error::Error>> {
    let config =
        crate::record_engine::rolling_tests::fixture(false, rolling::wire::SourceWire::Exact)?;
    let plan = engine::storage::Plan::for_engine(
        config,
        engine::Context {
            session: 0x1234_5678_9012_3456,
            epoch: 7,
            role: Role::Client,
        },
        engine::Geometry {
            forward_overhead_bytes: 17,
            reverse_overhead_bytes: 73,
        },
        engine::NativeLimits {
            stall_micros: 50_000,
        },
    )?;
    let mut bank = tests::bank(plan, 0)?;
    let mut foreign = tests::bank(plan, 0)?;
    let id = bank.initial();
    let other = foreign.initial();
    let original_usage = bank.usage();
    let work = rolling::WorkBudget {
        field: 65_536,
        copies: 65_536,
        metadata: 65_536,
    };
    let mut output = [0; 1500];
    let mut witnesses = [receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }; 4];
    let packet = tests::packet(0x5b);
    for (owner, generation) in [(&mut bank, id), (&mut foreign, other)] {
        let mut entry = owner.entry(generation)?;
        entry.enqueue_borrowed(engine::Tick(0), &packet)?;
        entry
            .admit_borrowed(engine::Tick(0))?
            .ok_or("actual rolling admission")?;
        assert!(entry.step(engine::Tick(1000), work)?.is_some());
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1500,
        };
        let emitted = entry
            .poll(
                engine::Tick(1000),
                (1u64 << 59) + 7,
                true,
                &mut output,
                &mut budget,
                &mut witnesses,
            )?
            .ok_or("actual rolling emission")?;
        assert_eq!(
            entry
                .pending_carrier_output()
                .ok_or("actual rolling token")?
                .emission(),
            emitted
        );
        assert_eq!(budget.packets, 0);
    }
    let foreign_token = foreign
        .entry(other)?
        .pending_carrier_output()
        .ok_or("foreign token")?;
    assert_eq!(
        bank.entry(id)?
            .confirm_carrier_output(engine::Tick(u64::MAX), foreign_token),
        Err(Error::Stale)
    );
    bank.entry(id)?.tick(engine::Tick(1000))?;
    let mut entry = bank.entry(id)?;
    let token = entry.pending_carrier_output().ok_or("original token")?;
    let duplicate = entry.pending_carrier_output().ok_or("retained token")?;
    assert_eq!(token.generation(), id);
    let mut untouched = [0x87; 1500];
    let mut budget = OutboundBudget {
        packets: 0,
        wire_bytes: 0,
    };
    assert_eq!(
        entry.poll(
            engine::Tick(1000),
            u64::MAX,
            false,
            &mut untouched,
            &mut budget,
            &mut witnesses
        )?,
        Some(token.emission())
    );
    assert_eq!(untouched, [0x87; 1500]);
    assert_eq!(
        budget,
        OutboundBudget {
            packets: 0,
            wire_bytes: 0
        }
    );
    entry.confirm_carrier_output(engine::Tick(1000), token)?;
    assert!(entry.pending_carrier_output().is_none());
    assert_eq!(
        entry.confirm_carrier_output(engine::Tick(1000), duplicate),
        Err(Error::Engine(engine::Error::Token))
    );
    assert_eq!(bank.usage(), original_usage);
    assert!(matches!(bank.retire(id), Err(Error::NotDrained)));
    Ok(())
}

#[test]
fn actual_aligned_and_packed_carrier_tokens_hold_source_and_arm_retry_at_acceptance()
-> tests::TestResult {
    for family in [tests::Family::Aligned, tests::Family::Packed] {
        let original = tests::config(family)?;
        let descriptor = original.descriptor();
        let mut profile = *descriptor.profile();
        let recovery = match &mut profile {
            configuration::Profile::Aligned { forward, reverse } => {
                forward.recovery.arq.initial_rto = Duration::from_millis(10);
                reverse.recovery.arq.initial_rto = Duration::from_millis(10);
                forward.recovery
            }
            configuration::Profile::Packed { forward, reverse } => {
                forward.base.recovery.arq.initial_rto = Duration::from_millis(10);
                reverse.base.recovery.arq.initial_rto = Duration::from_millis(10);
                forward.base.recovery
            }
            _ => return Err("positive-repair custody fixture".into()),
        };
        // Only shorten this fixture's RTO. Its real FEC lifetime remains 50ms.
        assert_eq!(recovery.fec.max_lifetime_ticks, 50);
        assert_eq!(recovery.repair_symbols, 1);
        let configuration = configuration::Configuration::new(
            original.envelope(),
            configuration::Descriptor::new(
                descriptor.path_mtu(),
                descriptor.duplex(),
                *descriptor.direction(Role::Client).common(),
                *descriptor.direction(Role::Server).common(),
                profile,
            )?,
        )?;
        let make_plan = |epoch| {
            engine::storage::Plan::for_engine(
                configuration,
                engine::Context {
                    session: 0x1234_5678_9012_3456,
                    epoch,
                    role: Role::Client,
                },
                engine::Geometry {
                    forward_overhead_bytes: 17,
                    reverse_overhead_bytes: 73,
                },
                engine::NativeLimits {
                    stall_micros: 50_000,
                },
            )
        };
        let initial = make_plan(7)?;
        let target = make_plan(8)?;
        let mut bank = tests::bank(initial, target.heap_bytes())?;
        let id = bank.initial();
        let mut prepared = bank.prepare(target)?;
        let different_generation = bank.publish(&mut prepared)?;
        let mut foreign = tests::bank(initial, 0)?;
        let foreign_id = foreign.initial();
        let original_usage = bank.usage();
        let packet = tests::packet(0x5b);
        let witness = receiver::UnitWitness {
            identity: receiver::RecordIdentity {
                channel: receiver::ChannelId(0),
                record: receiver::RecordId(0),
            },
            index: 0,
            count: 1,
        };
        let mut output = [0; 1500];
        let mut witnesses = [witness; 4];
        let mut original_body = None;
        for (index, (owner, generation)) in [(&mut bank, id), (&mut foreign, foreign_id)]
            .into_iter()
            .enumerate()
        {
            let mut entry = owner.entry(generation)?;
            entry.enqueue_borrowed(engine::Tick(0), &packet)?;
            entry
                .admit_borrowed(engine::Tick(0))?
                .ok_or("actual admission")?;
            let mut actual = None;
            for millis in 0..=10 {
                let mut budget = OutboundBudget {
                    packets: 1,
                    wire_bytes: 1500,
                };
                if let Some(emission) = entry.poll(
                    engine::Tick(millis * 1000),
                    71,
                    true,
                    &mut output,
                    &mut budget,
                    &mut witnesses,
                )? {
                    assert_eq!(
                        emission.kind,
                        engine::EmissionKind::Source(engine::SourceForm::SystematicFec)
                    );
                    assert_eq!(budget.packets, 0);
                    assert_eq!(budget.wire_bytes, 1500 - emission.wire_bytes);
                    if index == 0 {
                        original_body = Some(output[..emission.bytes].to_vec());
                    }
                    actual = Some(emission);
                    break;
                }
                assert_eq!(
                    budget,
                    OutboundBudget {
                        packets: 1,
                        wire_bytes: 1500
                    }
                );
            }
            assert!(
                actual.is_some(),
                "bounded original positive-FEC emission: {family:?}"
            );
        }
        let first = bank
            .entry(id)?
            .pending_carrier_output()
            .ok_or("held source")?
            .emission();
        let first_body = original_body.ok_or("original retained source bytes")?;
        let parsed = l2tunnel_reliable::inspect_structural(
            &first_body,
            l2tunnel_recovery::EndpointRole::Initiator,
            recovery.maximum_packet_bytes()?,
            recovery.arq.max_source_bytes,
            recovery.fec.block,
        )?;
        let (source, bytes) = parsed.source.ok_or("actual systematic original source")?;
        let source_bytes = bytes.to_vec();
        assert_eq!(parsed.sender.epoch, 7);
        let foreign_token = foreign
            .entry(foreign_id)?
            .pending_carrier_output()
            .ok_or("foreign source")?;
        assert_eq!(
            bank.entry(id)?.confirm_carrier_output_at(
                engine::Tick(u64::MAX),
                engine::Tick(u64::MAX),
                foreign_token
            ),
            Err(Error::Stale)
        );
        let wrong_generation = bank
            .entry(id)?
            .pending_carrier_output()
            .ok_or("generation source")?;
        assert_eq!(
            bank.entry(different_generation)?.confirm_carrier_output_at(
                engine::Tick(u64::MAX),
                engine::Tick(u64::MAX),
                wrong_generation
            ),
            Err(Error::Stale)
        );

        let before = bank.engine(id)?.statistics();
        let original_context = engine::Context {
            session: 0x1234_5678_9012_3456,
            epoch: 7,
            role: Role::Client,
        };
        let mut entry = bank.entry(id)?;
        // No whole send occurred, even though more than one RTO has elapsed.
        entry.tick(engine::Tick(19_999))?;
        let token = entry
            .pending_carrier_output()
            .ok_or("original pending source")?;
        let repeated = entry
            .pending_carrier_output()
            .ok_or("duplicate observation")?;
        assert_eq!(token.emission(), first);
        assert_eq!(token.context(), original_context);
        let mut untouched = [0x87; 1500];
        let mut untouched_witnesses = [witness; 4];
        let mut empty = OutboundBudget {
            packets: 0,
            wire_bytes: 0,
        };
        assert_eq!(
            entry.poll(
                engine::Tick(19_999),
                u64::MAX,
                false,
                &mut untouched,
                &mut empty,
                &mut untouched_witnesses
            )?,
            Some(first)
        );
        assert_eq!(untouched, [0x87; 1500]);
        assert_eq!(untouched_witnesses, [witness; 4]);
        assert_eq!(
            empty,
            OutboundBudget {
                packets: 0,
                wire_bytes: 0
            }
        );
        // The carrier accepted at 20ms; its completion was observed at 25ms.
        entry.confirm_carrier_output_at(engine::Tick(25_000), engine::Tick(20_000), token)?;
        assert!(entry.pending_carrier_output().is_none());
        assert_eq!(
            entry.confirm_carrier_output_at(
                engine::Tick(u64::MAX),
                engine::Tick(u64::MAX),
                repeated
            ),
            Err(Error::Engine(engine::Error::Token))
        );
        entry.tick(engine::Tick(25_000))?;
        assert_eq!(bank.engine(id)?.statistics(), before);
        assert_eq!(bank.usage(), original_usage);

        // Send all already queued systematics/repair, then lose them after send.
        // This is physical acceptance, not simulated WouldBlock or a peer ACK.
        let mut number = 72;
        let mut saw_repair = false;
        let mut drained_output = false;
        for _ in 0..64 {
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: 1500,
            };
            let mut entry = bank.entry(id)?;
            let Some(emission) = entry.poll(
                engine::Tick(25_000),
                number,
                true,
                &mut output,
                &mut budget,
                &mut witnesses,
            )?
            else {
                drained_output = true;
                break;
            };
            saw_repair |= emission.kind == engine::EmissionKind::Repair;
            let token = entry
                .pending_carrier_output()
                .ok_or("queued output custody")?;
            assert_eq!(token.emission(), emission);
            entry.confirm_carrier_output(engine::Tick(25_000), token)?;
            number += 1;
        }
        assert!(
            drained_output && saw_repair,
            "actual positive-FEC backlog: {family:?}"
        );
        assert_eq!(bank.engine(id)?.deadline()?, Some(engine::Tick(30_000)));
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1500,
        };
        assert!(
            bank.entry(id)?
                .poll(
                    engine::Tick(29_999),
                    number,
                    true,
                    &mut output,
                    &mut budget,
                    &mut witnesses
                )?
                .is_none()
        );
        assert_eq!(
            budget,
            OutboundBudget {
                packets: 1,
                wire_bytes: 1500
            }
        );
        let retry = bank
            .entry(id)?
            .poll(
                engine::Tick(30_000),
                number,
                true,
                &mut output,
                &mut budget,
                &mut witnesses,
            )?
            .ok_or("retry at actual acceptance plus RTO")?;
        assert_eq!(
            retry.kind,
            engine::EmissionKind::Source(engine::SourceForm::DirectArq)
        );
        let parsed = l2tunnel_reliable::inspect_structural(
            &output[..retry.bytes],
            l2tunnel_recovery::EndpointRole::Initiator,
            recovery.maximum_packet_bytes()?,
            recovery.arq.max_source_bytes,
            recovery.fec.block,
        )?;
        assert_eq!(parsed.source, Some((source, source_bytes.as_slice())));
        let token = bank
            .entry(id)?
            .pending_carrier_output()
            .ok_or("retry custody")?;
        bank.entry(id)?
            .confirm_carrier_output(engine::Tick(30_000), token)?;
        assert_eq!(bank.engine(id)?.configuration(), &configuration);
        assert_eq!(bank.usage(), original_usage);
        assert!(matches!(bank.retire(id), Err(Error::NotDrained)));
    }
    Ok(())
}
