//! Actual selected Engine/reassembly/research owners. Carrier authentication is
//! the caller prerequisite here; no public metadata grants that authority.
use super::*;
use crate::codec;

fn fragment_policy() -> FragmentPolicy {
    let direction = |outer, label| {
        let limits = |bytes| codec::ReassemblyConfig {
            max_message_bytes: bytes,
            max_messages: 2,
            max_fragment_payload_bytes: 1443,
            max_fragments_per_message: 2,
            max_total_fragments: 4,
            max_reserved_bytes: 2 * bytes,
            max_lifetime_ticks: 100_000,
            replay_window: 64,
        };
        FragmentDirection {
            framing: codec::FragmentConfig {
                path_mtu: 1500,
                outer_overhead_bytes: outer,
                max_message_bytes: 1024,
                max_fragments: 2,
            },
            reassembly: ReassemblyPolicies {
                systematic: limits(1024),
                repair: limits(1024),
                feedback: limits(80),
            },
            labels: [
                codec::SessionId(label),
                codec::SessionId(label + 1),
                codec::SessionId(label + 2),
            ],
            first_message: codec::MessageId(1),
        }
    };
    FragmentPolicy {
        forward: direction(17, 11),
        reverse: direction(73, 21),
    }
}

#[test]
fn selected_fragment_feedback_before_and_after_whole_send_in_one_tick_freezes_actual_prefix()
-> TestResult {
    for early in [true, false] {
        let c = configuration(policies()[2])?;
        let policy = fragment_policy();
        let plan = storage::Plan::for_engine_with_fragmentation(
            c,
            context(Role::Client),
            geometry(),
            NativeLimits {
                stall_micros: 50_000,
            },
            None,
            None,
            Some(policy),
        )?;
        let mut sender = Engine::new_reserved(
            plan,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        let mut peer = build(c, Role::Server)?;
        let usage = sender.storage_usage();
        sender.enqueue_borrowed(Tick(0), &packet(false, 2401, 1024, 0x61))?;
        let mut held = None;
        let mut sources = 0;
        for turn in 0..1000u64 {
            let now = Tick(turn * 100);
            sender.admit_borrowed(now)?;
            sender.step(now, work())?;
            let Some(group) = sender.reserve_fragment_group_until(
                now,
                turn + 1,
                true,
                Tick(1_000_000),
                &mut OutboundBudget {
                    packets: 2,
                    wire_bytes: 3000,
                },
                &mut witnesses(),
            )?
            else {
                continue;
            };
            assert!(matches!(group.kind, EmissionKind::Source(_)));
            assert_eq!(group.packets, 1);
            let mut body = [0; 1500];
            let physical = sender
                .poll_reserved_fragment(now, turn + 1, &mut body)?
                .ok_or("actual fragment")?;
            let token = sender
                .pending_fragment_output()
                .ok_or("actual physical witness")?;
            if sources == 4 {
                held = Some((now, group, token));
                break;
            }
            sender.confirm_fragment_at(now, now, token)?;
            if sources == 0 {
                peer.accept_authenticated(
                    now,
                    physical.emission.security_number,
                    physical.emission.kind,
                    &mut body[codec::FRAGMENT_HEADER_BYTES..physical.emission.bytes],
                )?;
                peer.step(now, work())?;
            }
            sources += 1;
        }
        let (prepared, group, token) = held.ok_or("fifth actual source")?;
        let duplicate = sender
            .pending_fragment_output()
            .ok_or("retained actual witness")?;
        let received = Tick(prepared.0 + 1);
        let observed = Tick(prepared.0 + 3);
        peer.step(received, work())?;
        let mut body = [0; 1500];
        let feedback = peer
            .poll(
                received,
                1 << 54,
                false,
                &mut body,
                &mut OutboundBudget {
                    packets: 1,
                    wire_bytes: 1500,
                },
                &mut witnesses(),
            )?
            .ok_or("real peer feedback")?;
        assert_eq!(feedback.kind, EmissionKind::Feedback);
        peer.confirm_carrier_output(
            received,
            peer.pending_carrier_output().ok_or("feedback witness")?,
        )?;
        let mut fragmenter = codec::Fragmenter::new(
            codec::FragmentContext {
                session: policy.reverse.labels[2],
                epoch: crate::core::Epoch(context(Role::Client).epoch),
            },
            policy.reverse.framing,
            policy.reverse.first_message,
        )?;
        let fragments = fragmenter.fragment(&body[..feedback.bytes])?;
        let order = |offset| codec::CausalTime::from_nanos(u128::from(received.0) * 1000 + offset);
        for fragment in &fragments.fragments {
            assert_eq!(
                sender.accept_fragment_authenticated_ordered_until(
                    received,
                    observed,
                    Tick(100_000),
                    feedback.security_number,
                    order(if early { 100 } else { 900 }),
                    fragment
                )?,
                FragmentAdmission::Held
            );
        }
        assert_eq!(sender.pending_fragment_group(), Some(group));
        assert_eq!(
            sender
                .research_status()
                .ok_or("actual sender")?
                .0
                .sent_sources,
            4
        );
        assert_eq!(
            sender
                .research_status()
                .ok_or("actual sender")?
                .0
                .encoder
                .confirmed_prefix,
            0
        );
        assert_eq!(
            sender.confirm_fragment_ordered_at(observed, received, order(500), token)?,
            FragmentReceipt::GroupComplete(group)
        );
        assert_eq!(
            sender.confirm_fragment_ordered_at(Tick(0), Tick(0), order(0), duplicate),
            Err(Error::Token)
        );
        let state = sender.research_status().ok_or("actual completed sender")?.0;
        assert_eq!((state.sent_sources, state.encoder.confirmed_prefix), (5, 1));
        assert!(state.terminal.is_none());
        sender.step(observed, work())?;
        let repair = sender
            .reserve_fragment_group_until(
                observed,
                1000,
                true,
                Tick(1_000_000),
                &mut OutboundBudget {
                    packets: 2,
                    wire_bytes: 3000,
                },
                &mut witnesses(),
            )?
            .ok_or("actual earned repair")?;
        assert_eq!(repair.kind, EmissionKind::Repair);
        let physical = sender
            .poll_reserved_fragment(observed, 1000, &mut body)?
            .ok_or("repair fragment")?;
        let configuration::Profile::Research { config, .. } = *c.descriptor().profile() else {
            return Err("actual policy".into());
        };
        let research::wire::View::Repair(repair) = research::wire::inspect(
            config.forward.scheduler,
            &body[codec::FRAGMENT_HEADER_BYTES..physical.emission.bytes],
        )?
        else {
            return Err("actual repair bytes".into());
        };
        assert_eq!(repair.confirmed, if early { 1 } else { 0 });
        assert_eq!(sender.storage_usage(), usage);
    }
    Ok(())
}

#[test]
fn selected_ingress_retains_two_real_feedbacks_across_one_physical_receipt() -> TestResult {
    let c = configuration(policies()[2])?;
    let plan = storage::Plan::for_engine_with_options(
        c,
        context(Role::Client),
        geometry(),
        NativeLimits {
            stall_micros: 50_000,
        },
        None,
        Some(rolling_records::IngressLimits {
            slots: 2,
            capacity_bytes: 1 << 20,
        }),
    )?;
    let mut sender = Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let mut peer = build(c, Role::Server)?;
    let usage = sender.storage_usage();
    sender.enqueue_borrowed(Tick(0), &packet(false, 2401, 1024, 0x61))?;
    let mut feedbacks = Vec::new();
    let mut held = None;
    let mut sources = 0;
    for turn in 0..1000u64 {
        let now = Tick(turn * 100);
        sender.admit_borrowed(now)?;
        sender.step(now, work())?;
        let mut body = [0; 1500];
        let Some(emission) = sender.poll(
            now,
            turn + 1,
            true,
            &mut body,
            &mut OutboundBudget {
                packets: 1,
                wire_bytes: 1500,
            },
            &mut witnesses(),
        )?
        else {
            continue;
        };
        assert!(matches!(emission.kind, EmissionKind::Source(_)));
        let token = sender
            .pending_carrier_output()
            .ok_or("actual source token")?;
        if sources == 4 {
            held = Some((now, emission, token));
            break;
        }
        sender.confirm_carrier_output(now, token)?;
        if sources < 2 {
            peer.accept_authenticated(
                now,
                emission.security_number,
                emission.kind,
                &mut body[..emission.bytes],
            )?;
            let mut actual = None;
            for _ in 0..256 {
                peer.step(now, work())?;
                let mut bytes = [0; 1500];
                if let Some(feedback) = peer.poll(
                    now,
                    (1 << 54) + sources,
                    false,
                    &mut bytes,
                    &mut OutboundBudget {
                        packets: 1,
                        wire_bytes: 1500,
                    },
                    &mut witnesses(),
                )? {
                    assert_eq!(feedback.kind, EmissionKind::Feedback);
                    peer.confirm_carrier_output(
                        now,
                        peer.pending_carrier_output()
                            .ok_or("actual feedback token")?,
                    )?;
                    actual = Some((feedback, bytes[..feedback.bytes].to_vec()));
                    break;
                }
            }
            feedbacks.push(actual.ok_or("actual independent peer feedback")?);
        }
        sources += 1;
    }
    let (prepared, emission, token) = held.ok_or("fifth actual source")?;
    assert_eq!(feedbacks.len(), 2);
    let received = Tick(prepared.0 + 1);
    let observed = Tick(prepared.0 + 3);
    let order = |offset| codec::CausalTime::from_nanos(u128::from(received.0) * 1000 + offset);
    for (index, (feedback, bytes)) in feedbacks.iter().enumerate() {
        assert!(sender.retain_research_feedback_authenticated_until(
            received,
            observed,
            Tick(100_000),
            feedback.security_number,
            Some(order(if index == 0 { 100 } else { 900 })),
            bytes,
        )?);
    }
    let queued = sender.rolling_ingress_status().ok_or("selected queue")?;
    assert_eq!(queued.packets, 2);
    assert_eq!(queued.oldest_received, Some(received));
    assert_eq!(queued.deadline, Some(Tick(100_000)));
    assert_eq!(
        sender
            .pending_carrier_output()
            .ok_or("unchanged token")?
            .emission(),
        emission
    );
    assert_eq!(
        sender
            .research_status()
            .ok_or("actual sender")?
            .0
            .sent_sources,
        4
    );
    assert_eq!(
        sender
            .research_status()
            .ok_or("actual sender")?
            .0
            .encoder
            .confirmed_prefix,
        0
    );
    assert_eq!(
        sender.retain_research_feedback_authenticated_until(
            received,
            observed,
            Tick(100_000),
            u64::MAX,
            Some(order(950)),
            &feedbacks[1].1,
        ),
        Err(Error::Rolling(rolling_records::Error::Busy))
    );
    assert_eq!(
        sender.rolling_ingress_status(),
        Some(rolling_records::IngressStatus {
            full_refusals: [0, 0, 1],
            ..queued
        })
    );
    sender.confirm_carrier_output_ordered_at(observed, received, order(500), token)?;
    let actual = sender.research_status().ok_or("completed actual sender")?.0;
    assert_eq!(
        (actual.sent_sources, actual.encoder.confirmed_prefix),
        (5, 2)
    );
    assert!(actual.terminal.is_none());
    assert_eq!(
        sender
            .rolling_ingress_status()
            .ok_or("empty queue")?
            .packets,
        0
    );
    sender.step(observed, work())?;
    let mut bytes = [0; 1500];
    let repair = sender
        .poll(
            observed,
            u64::MAX - 1,
            true,
            &mut bytes,
            &mut OutboundBudget {
                packets: 1,
                wire_bytes: 1500,
            },
            &mut witnesses(),
        )?
        .ok_or("actual frozen repair")?;
    let configuration::Profile::Research { config, .. } = *c.descriptor().profile() else {
        return Err("actual policy".into());
    };
    let research::wire::View::Repair(repair) =
        research::wire::inspect(config.forward.scheduler, &bytes[..repair.bytes])?
    else {
        return Err("actual repair bytes".into());
    };
    assert_eq!(repair.confirmed, 1);
    assert_eq!(sender.storage_usage(), usage);
    Ok(())
}
