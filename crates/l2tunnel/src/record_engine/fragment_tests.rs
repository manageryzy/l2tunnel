//! Real selected Engine/Bank/codec custody with trusted simulated whole writes.
//! Authentication/replay is a caller prerequisite; no handshake/runtime is fabricated.
use super::*;
use crate::{codec, fec::rolling, record_bank};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture() -> TestResult<configuration::Configuration> {
    let original = rolling_tests::fixture(true, rolling::wire::SourceWire::Padded)?;
    let descriptor = original.descriptor();
    let configuration::Profile::Rolling { mut config, stream } = *descriptor.profile() else {
        return Err("actual rolling fixture".into());
    };
    for direction in [&mut config.forward, &mut config.reverse] {
        direction.receiver.body.symbol_bytes = 1460;
        direction.receiver.body.max_frame_bytes = 1500;
        direction.packing.sender.body = direction.receiver.body;
        direction.packing.packing.symbol_bytes = 1460;
        direction.packing.max_units = 1;
        direction.scheduler.recovery.max_payload = 1524;
    }
    let common = |role| -> TestResult<configuration::CommonDirection> {
        let actual = descriptor.direction(role).common();
        let mut pipeline = actual.pipeline();
        pipeline.parse.max_packet_bytes = 1500;
        Ok(configuration::CommonDirection::new(
            actual.traffic(),
            pipeline,
            actual.bytes_per_second(),
            actual.burst_bytes(),
            actual.native_window(),
        )?)
    };
    Ok(configuration::Configuration::new(
        original.envelope(),
        configuration::Descriptor::new(
            1500,
            descriptor.duplex(),
            common(Role::Client)?,
            common(Role::Server)?,
            configuration::Profile::Rolling { config, stream },
        )?,
    )?)
}
fn context(role: Role) -> Context {
    Context {
        session: 0xfeed_beef_8899_aabb_1234_5678_9012_3456,
        epoch: 7,
        role,
    }
}
fn policy() -> FragmentPolicy {
    let direction = |outer, label| {
        let framing = codec::FragmentConfig {
            path_mtu: 1500,
            outer_overhead_bytes: outer,
            max_message_bytes: 1590,
            max_fragments: 2,
        };
        let receive = |bytes| codec::ReassemblyConfig {
            max_message_bytes: bytes,
            max_messages: 2,
            max_fragment_payload_bytes: 1460,
            max_fragments_per_message: 2,
            max_total_fragments: 4,
            max_reserved_bytes: 2 * bytes,
            max_lifetime_ticks: 100000,
            replay_window: 64,
        };
        FragmentDirection {
            framing,
            labels: [
                codec::SessionId(label),
                codec::SessionId(label + 1),
                codec::SessionId(label + 2),
            ],
            first_message: codec::MessageId(1),
            reassembly: ReassemblyPolicies {
                systematic: receive(1590),
                repair: receive(1590),
                feedback: receive(64),
            },
        }
    };
    FragmentPolicy {
        forward: direction(17, 0x11),
        reverse: direction(73, 0x22),
    }
}
fn plan(c: configuration::Configuration, role: Role) -> TestResult<storage::Plan> {
    Ok(storage::Plan::for_engine_with_fragmentation(
        c,
        context(role),
        tests::geometry(),
        NativeLimits {
            stall_micros: 50000,
        },
        None,
        None,
        Some(policy()),
    )?)
}
fn build(c: configuration::Configuration, role: Role) -> TestResult<Engine> {
    let plan = plan(c, role)?;
    Ok(Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}
fn work() -> rolling::WorkBudget {
    rolling::WorkBudget {
        field: 65536,
        copies: 65536,
        metadata: 65536,
    }
}
fn witnesses() -> [receiver::UnitWitness; 4] {
    [receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }; 4]
}
fn admit(engine: &mut Engine, bytes: &[u8]) -> TestResult<ProfileIdentity> {
    engine.enqueue_borrowed(Tick(0), bytes)?;
    for _ in 0..64 {
        if let Some(admitted) = engine.admit_borrowed(Tick(0))? {
            return Ok(admitted.permit);
        }
    }
    Err("bounded real common admission".into())
}
fn transfer(
    sender: &mut Engine,
    peer: &mut Engine,
    now: Tick,
    cap: Tick,
) -> TestResult<Option<(FragmentGroup, FragmentAdmission)>> {
    sender.step(now, work())?;
    let mut units = witnesses();
    let mut budget = OutboundBudget {
        packets: 2,
        wire_bytes: 1704,
    };
    let Some(group) =
        sender.reserve_fragment_group_until(now, 9, true, cap, &mut budget, &mut units)?
    else {
        return Ok(None);
    };
    assert_eq!(
        (group.logical_bytes, group.packets, group.wire_bytes),
        (1590, 2, 1704)
    );
    assert_eq!(budget, OutboundBudget::default());
    assert_eq!(sender.pending_carrier_output(), None);
    let mut old_output = [0xa5; 2000];
    assert_eq!(
        sender.poll(now, 99, true, &mut old_output, &mut budget, &mut units),
        Err(Error::FragmentPolicy)
    );
    assert!(old_output.iter().all(|b| *b == 0xa5));
    let mut final_admission = None;
    for index in 0..group.packets {
        let observed = Tick(now.0 + u64::try_from(index)?);
        let mut output = [0; 1500];
        // An interleaved control allocation may have consumed arbitrary numbers
        // since reserve; the first real number need not be prospective 9.
        let number = 100 + now.0 * 10 + u64::try_from(index)? * 7;
        let emitted = sender
            .poll_reserved_fragment(observed, number, &mut output)?
            .ok_or("actual physical fragment")?;
        assert_eq!(emitted.index, index);
        assert_eq!(emitted.emission.security_number, number);
        assert!(emitted.emission.wire_bytes <= 1500);
        assert_eq!(emitted.emission.bytes + 17, emitted.emission.wire_bytes);
        let token = sender
            .pending_fragment_output()
            .ok_or("exact physical token")?;
        assert_eq!(token.context(), context(Role::Client));
        let duplicate = sender
            .pending_fragment_output()
            .ok_or("retained physical witness")?;
        let mut untouched = [0xa5; 1500];
        assert_eq!(
            sender.poll_reserved_fragment(observed, 999, &mut untouched)?,
            Some(emitted)
        );
        assert!(untouched.iter().all(|b| *b == 0xa5));
        let kind = peer.inspect_fragment_kind(&output[..emitted.emission.bytes])?;
        assert_eq!(kind, emitted.emission.kind);
        let accepted = peer.accept_fragment_authenticated_until(
            now,
            observed,
            cap,
            number,
            &output[..emitted.emission.bytes],
        )?;
        if index == 0 {
            assert_eq!(accepted, FragmentAdmission::Pending);
        } else {
            final_admission = Some(accepted);
        }
        let receipt = sender.confirm_fragment_at(observed, observed, token)?;
        if index + 1 < group.packets {
            assert_eq!(receipt, FragmentReceipt::More);
            assert_eq!(sender.pending_fragment_group(), Some(group));
        } else {
            assert_eq!(receipt, FragmentReceipt::GroupComplete(group));
        }
        let stats = sender.fragment_statistics();
        assert_eq!(
            sender.confirm_fragment_at(Tick(0), Tick(0), duplicate),
            Err(Error::Token)
        );
        assert_eq!(sender.fragment_statistics(), stats);
    }
    assert_eq!(sender.pending_fragment_group(), None);
    Ok(Some((
        group,
        final_admission.ok_or("complete actual body")?,
    )))
}

#[test]
fn actual_selected_1460_symbol_1500_mtu_reserves_once_and_reconstructs_native() -> TestResult {
    let c = fixture()?;
    assert!(matches!(
        storage::Plan::for_engine(
            c,
            context(Role::Client),
            tests::geometry(),
            NativeLimits {
                stall_micros: 50000
            }
        ),
        Err(storage::Error::Engine(Error::Geometry))
    ));
    let complete = plan(c, Role::Client)?;
    assert!(matches!(
        Engine::new_reserved(
            complete,
            storage::Limits {
                capacity_bytes: complete.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    let mut sender = build(c, Role::Client)?;
    let mut receiver = build(c, Role::Server)?;
    let usage = sender.storage_usage().ok_or("actual usage")?;
    assert!(usage.fragment_bytes > 2 * 1590);
    assert_eq!(
        usage.fixed_bytes
            + usage.pipeline_bytes
            + usage.record_bytes
            + usage.ingress_bytes
            + usage.fragment_bytes,
        usage.capacity_bytes
    );
    let original = tests::packet(true, 4401, 1460, 0x73);
    let identity = admit(&mut sender, &original)?;
    let mut groups = 0;
    let mut delivered = false;
    let mut completed_at = Tick(0);
    for step in 1..=32u64 {
        let now = Tick(step * 1000);
        sender.step(now, work())?;
        if groups == 0 {
            let mut output = [0xa5; 2000];
            let mut units = witnesses();
            for mut short in [
                OutboundBudget {
                    packets: 1,
                    wire_bytes: 1704,
                },
                OutboundBudget {
                    packets: 2,
                    wire_bytes: 1703,
                },
            ] {
                let saved = short;
                assert_eq!(
                    sender.reserve_fragment_group(now, 9, true, &mut short, &mut units)?,
                    None
                );
                assert_eq!(short, saved);
                assert_eq!(sender.pending_fragment_group(), None);
            }
            assert_eq!(
                sender.poll(
                    now,
                    9,
                    true,
                    &mut output,
                    &mut OutboundBudget::default(),
                    &mut units
                ),
                Err(Error::FragmentPolicy)
            );
            assert!(output.iter().all(|b| *b == 0xa5));
        }
        if let Some((_, accepted)) = transfer(&mut sender, &mut receiver, now, Tick(100000))? {
            assert_eq!(accepted, FragmentAdmission::Accepted);
            groups += 1;
        }
        let observed = Tick(now.0 + 2);
        for _ in 0..8 {
            receiver.step(observed, work())?;
        }
        let mut output = [0; 1500];
        for _ in 0..8 {
            if let NativePreparation::Ready(packet) =
                receiver.prepare_native(observed, 32, Tick(100000), &mut output)?
            {
                assert_eq!(packet.identity(), identity);
                assert_eq!(&output[..packet.bytes()], original);
                receiver.commit_native(observed, packet.token())?;
                delivered = true;
                completed_at = observed;
            }
        }
        if delivered {
            break;
        }
    }
    assert!(delivered);
    assert_eq!(groups, 2);
    assert_eq!(receiver.statistics().committed, 1);
    assert_eq!(
        sender
            .fragment_statistics()
            .ok_or("physical stats")?
            .packets_written,
        4
    );
    assert_eq!(
        sender
            .fragment_statistics()
            .ok_or("physical stats")?
            .groups_written,
        2
    );
    assert_eq!(sender.storage_usage(), Some(usage));
    // Reverse feedback is an actual scheduler snapshot, classified from the
    // authenticated LX bytes even though Records exposes only Class::User.
    let at = Tick(completed_at.0 + 101);
    for _ in 0..8 {
        receiver.step(at, work())?;
    }
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 177,
    };
    let feedback = receiver
        .reserve_fragment_group(at, 0, false, &mut budget, &mut witnesses())?
        .ok_or("actual reverse feedback group")?;
    assert_eq!(
        (feedback.kind, feedback.packets, feedback.wire_bytes),
        (EmissionKind::Feedback, 1, 177)
    );
    assert_eq!(budget, OutboundBudget::default());
    let mut bytes = [0; 1500];
    let emitted = receiver
        .poll_reserved_fragment(at, 900, &mut bytes)?
        .ok_or("actual reverse feedback fragment")?;
    assert_eq!(
        sender.inspect_fragment_kind(&bytes[..emitted.emission.bytes])?,
        EmissionKind::Feedback
    );
    assert_eq!(
        sender.accept_fragment_authenticated_until(
            at,
            at,
            Tick(100000),
            900,
            &bytes[..emitted.emission.bytes]
        )?,
        FragmentAdmission::Accepted
    );
    let token = receiver
        .pending_fragment_output()
        .ok_or("real reverse physical witness")?;
    assert_eq!(
        receiver.confirm_fragment_at(at, at, token)?,
        FragmentReceipt::GroupComplete(feedback)
    );
    let mut duplicate_labels = policy();
    duplicate_labels.forward.labels[1] = duplicate_labels.forward.labels[0];
    assert!(matches!(
        storage::Plan::for_engine_with_fragmentation(
            c,
            context(Role::Client),
            tests::geometry(),
            NativeLimits {
                stall_micros: 50000
            },
            None,
            None,
            Some(duplicate_labels)
        ),
        Err(storage::Error::Engine(Error::FragmentPolicy))
    ));
    let mut directional = policy();
    directional.reverse.labels = directional.forward.labels;
    assert!(
        storage::Plan::for_engine_with_fragmentation(
            c,
            context(Role::Client),
            tests::geometry(),
            NativeLimits {
                stall_micros: 50000
            },
            None,
            None,
            Some(directional)
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn completed_original_body_survives_real_decoder_busy_and_expires_at_original_cap() -> TestResult {
    let c = fixture()?;
    let mut sender = build(c, Role::Client)?;
    let mut receiver = build(c, Role::Server)?;
    let original = tests::packet(true, 4402, 1460, 0x74);
    admit(&mut sender, &original)?;
    let mut groups = 0;
    let mut held = None;
    for step in 1..=16u64 {
        let now = Tick(step * 1000);
        if let Some((_, admission)) = transfer(&mut sender, &mut receiver, now, Tick(20000))? {
            groups += 1;
            if admission == FragmentAdmission::Held {
                held = Some(receiver.fragment_ingress_snapshot().ok_or("held body")?);
                break;
            }
            assert_eq!(admission, FragmentAdmission::Accepted);
        }
        // Deliberately do not service receiving GF work: the first real decoder
        // job retains ownership while the next whole body must survive Busy.
    }
    assert_eq!(groups, 2);
    let held = held.ok_or("actual decoder Busy completion")?;
    assert!(held.held_received[0].is_some());
    assert_eq!(held.held_caps[0], Some(Tick(20000)));
    assert_eq!(held.held_received[1..], [None, None]);
    assert_eq!(receiver.retry_fragment_inputs(Tick(19000))?, 0);
    assert_eq!(receiver.fragment_ingress_snapshot(), Some(held));
    assert!(!receiver.drained()?);
    assert_eq!(
        receiver.retry_fragment_inputs(Tick(20000)),
        Err(Error::Expired)
    );
    assert_eq!(receiver.fragment_ingress_snapshot(), Some(held));
    assert_eq!(receiver.statistics().committed, 0);
    Ok(())
}

#[test]
fn actual_bank_fragment_receipt_refuses_foreign_generation_before_time_and_waits_for_last()
-> TestResult {
    let c = fixture()?;
    let selected = plan(c, Role::Client)?;
    let bank_plan = record_bank::storage::Plan::for_bank(selected, 0)?;
    let mut bank = record_bank::Bank::new(
        bank_plan,
        record_bank::storage::Limits {
            capacity_bytes: bank_plan.capacity_bytes(),
        },
    )?;
    let mut foreign = record_bank::Bank::new(
        bank_plan,
        record_bank::storage::Limits {
            capacity_bytes: bank_plan.capacity_bytes(),
        },
    )?;
    let id = bank.initial();
    let other = foreign.initial();
    let initial_usage = bank.usage();
    let mut entry = bank.entry(id)?;
    entry.enqueue_borrowed(Tick(0), &tests::packet(true, 4403, 64, 0x75))?;
    let mut admitted = false;
    for _ in 0..64 {
        if entry.admit_borrowed(Tick(0))?.is_some() {
            admitted = true;
            break;
        }
    }
    assert!(admitted);
    entry.step(Tick(1000), work())?;
    let mut budget = OutboundBudget {
        packets: 2,
        wire_bytes: 1704,
    };
    let group = entry
        .reserve_fragment_group(Tick(1000), 1, true, &mut budget, &mut witnesses())?
        .ok_or("actual Bank group")?;
    assert_eq!(budget, OutboundBudget::default());
    for index in 0..group.packets {
        let now = Tick(1000 + u64::try_from(index)?);
        let mut output = [0; 1500];
        entry
            .poll_reserved_fragment(now, 9 + u64::try_from(index)?, &mut output)?
            .ok_or("actual Bank fragment")?;
        let wrong = entry.pending_fragment_output().ok_or("Bank witness")?;
        assert_eq!(wrong.generation(), id);
        assert_eq!(
            foreign
                .entry(other)?
                .confirm_fragment_at(Tick(u64::MAX), Tick(u64::MAX), wrong),
            Err(record_bank::Error::Stale)
        );
        let actual = entry
            .pending_fragment_output()
            .ok_or("same actual custody")?;
        let result = entry.confirm_fragment_at(now, now, actual)?;
        assert_eq!(
            result,
            if index + 1 == group.packets {
                FragmentReceipt::GroupComplete(group)
            } else {
                FragmentReceipt::More
            }
        );
    }
    assert!(entry.pending_fragment_group().is_none());
    assert_eq!(
        entry
            .fragment_statistics()
            .ok_or("physical stats")?
            .groups_written,
        1
    );
    assert_eq!(bank.usage(), initial_usage);
    assert!(matches!(
        bank.retire(id),
        Err(record_bank::Error::NotDrained)
    ));
    Ok(())
}

#[test]
fn compact_fragment_asymmetric_strong_feedback_keeps_exact_group_and_native_custody() -> TestResult
{
    let c = fixture()?;
    let build_selected = |role, feedback| -> TestResult<Engine> {
        let plan = storage::Plan::for_engine_with_compact_wire_and_fragmentation(
            c,
            context(role),
            tests::geometry(),
            NativeLimits {
                stall_micros: 50000,
            },
            None,
            None,
            Some(policy()),
            feedback,
        )?;
        Ok(Engine::new_reserved(
            plan,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?)
    };
    let mut a = build_selected(Role::Client, 29)?;
    let mut b = build_selected(Role::Server, 85)?;
    let original = tests::packet(true, 4401, 1460, 0x73);
    let identity = admit(&mut a, &original)?;
    let mut delivered = false;
    let mut feedback_seen = false;
    let mut number = 0;
    for step in 1..=32u64 {
        let now = Tick(step * 1000);
        for reverse in [false, true] {
            let (sender, peer, data_overhead, feedback_overhead) = if reverse {
                (&mut b, &mut a, 73, 85)
            } else {
                (&mut a, &mut b, 17, 29)
            };
            sender.step(now, work())?;
            let mut budget = OutboundBudget {
                packets: 8,
                wire_bytes: 100_000,
            };
            let before = budget;
            let Some(group) = sender.reserve_fragment_group_until(
                now,
                number,
                true,
                Tick(100000),
                &mut budget,
                &mut witnesses(),
            )?
            else {
                continue;
            };
            assert_eq!(before.packets - budget.packets, group.packets);
            assert_eq!(before.wire_bytes - budget.wire_bytes, group.wire_bytes);
            let overhead = if group.kind == EmissionKind::Feedback {
                feedback_seen = true;
                feedback_overhead
            } else {
                data_overhead
            };
            let mut physical = 0;
            for _ in 0..group.packets {
                number += 1;
                let mut output = [0; 1500];
                let emitted = sender
                    .poll_reserved_fragment(now, number, &mut output)?
                    .ok_or("selected fragment")?;
                assert_eq!(
                    emitted.emission.bytes + overhead,
                    emitted.emission.wire_bytes
                );
                physical += emitted.emission.wire_bytes;
                let bytes = &output[..emitted.emission.bytes];
                assert_eq!(peer.inspect_fragment_kind(bytes)?, group.kind);
                let before_receive = peer.fragment_ingress_snapshot();
                assert!(
                    peer.inspect_fragment_kind(&bytes[..bytes.len() - 1])
                        .is_err()
                );
                assert_eq!(peer.fragment_ingress_snapshot(), before_receive);
                peer.accept_fragment_authenticated_until(now, now, Tick(100000), number, bytes)?;
                let token = sender
                    .pending_fragment_output()
                    .ok_or("selected physical token")?;
                sender.confirm_fragment_at(now, now, token)?;
            }
            assert_eq!(physical, group.wire_bytes);
        }
        for _ in 0..8 {
            b.step(now, work())?;
            let mut output = [0; 1500];
            if let NativePreparation::Ready(packet) =
                b.prepare_native(now, 32, Tick(100000), &mut output)?
            {
                assert_eq!(packet.identity(), identity);
                assert_eq!(&output[..packet.bytes()], original);
                b.commit_native(now, packet.token())?;
                delivered = true;
            }
        }
        if delivered && feedback_seen {
            break;
        }
    }
    assert!(delivered && feedback_seen);
    Ok(())
}
