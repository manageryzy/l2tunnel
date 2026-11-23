use super::*;

fn configured() -> (Config, CopyPolicies) {
    let mut cfg = config(true, rolling::wire::SourceWire::TargetedExact);
    cfg.reverse.native_policy = NativePolicy::IpHeaders;
    cfg.reverse.scheduler.source_wire = rolling::wire::SourceWire::TargetedExactAckLz4;
    let copies = CopyPolicies {
        reverse: codec::source_copy::Policy {
            copies: 3,
            max_unit_bytes: 128,
            scope: codec::source_copy::Scope::ContextAndIndependent,
        },
        ..CopyPolicies::ONE
    };
    (cfg, copies)
}

fn reserved(cfg: Config, role: Role, copies: CopyPolicies) -> TestResult<Endpoint> {
    let plan = storage::Plan::for_endpoint_with_options(
        cfg,
        context(role),
        17,
        Tick(0),
        copies,
        Some(IngressLimits {
            slots: 4,
            capacity_bytes: 65536,
        }),
    )?;
    let mut endpoint = Endpoint::new_reserved_with_copies(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    endpoint.enable_compact_wire(73)?;
    endpoint.enable_queue_aware_repair_budget(1500)?;
    Ok(endpoint)
}

fn ack(edge: u32) -> Vec<u8> {
    let mut b = packet(true, 0, 52);
    b[28..32].copy_from_slice(&edge.to_be_bytes());
    b[32] = 0x80;
    b[40..52].copy_from_slice(&[1, 1, 5, 10, 0, 0, 32, 0, 0, 0, 40, 0]);
    b
}

#[test]
fn ack_lz4_three_lost_copies_named_retry_and_actual_budget() -> TestResult {
    let (cfg, copies) = configured();
    let mut sender = reserved(cfg, Role::Server, copies)?;
    let mut receiver = reserved(cfg, Role::Client, copies)?;
    let mut originals = Vec::new();
    let mut first_wire = Vec::new();
    let mut pn = 1;
    let mut witness_buffer = [witness(); 4];
    for source in 0..2u32 {
        for index in 0..2 {
            let frame = ack(101 + source * 2 + index);
            sender
                .enqueue_admitted_identified(Tick(0), 0, &frame)?
                .ok_or("stage ACK")?;
            originals.push(frame);
        }
        sender.flush(Tick(0))?;
        sender.step(Tick(0), work())?;
        for ordinal in 1..=3 {
            sender.step(Tick(0), work())?;
            let cost = sender.ready_data_wire_bytes()?.ok_or("ready source cost")?;
            let mut refused = OutboundBudget {
                packets: 1,
                wire_bytes: cost - 1,
            };
            let mut output = [0; 512];
            assert!(
                sender
                    .prepare_output(
                        Tick(0),
                        pn,
                        true,
                        &mut output,
                        &mut refused,
                        &mut witness_buffer
                    )?
                    .is_none()
            );
            assert_eq!(refused.wire_bytes, cost - 1);
            let mut exact = OutboundBudget {
                packets: 1,
                wire_bytes: cost,
            };
            let token = sender
                .prepare_output(
                    Tick(0),
                    pn,
                    true,
                    &mut output,
                    &mut exact,
                    &mut witness_buffer,
                )?
                .ok_or("exact compressed budget")?;
            assert_eq!(
                (token.witnesses, token.wire_bytes, exact.wire_bytes),
                (2, cost, 0)
            );
            assert_eq!(
                token.source_copy().ok_or("physical copy")?.ordinal(),
                ordinal
            );
            let packet = &output[..token.bytes];
            assert_eq!(packet[..3], [1, source as u8, 0]);
            let plain = usize::from(u16::from_be_bytes([packet[3], packet[4]]));
            assert!(cost < 2 + plain + cfg.geometry.reverse_overhead_bytes);
            let extent = sender.inspect_output_extent(packet)?;
            assert_eq!(extent.recovery.bytes, packet.len());
            assert_eq!(extent.codec.ok_or("packed extent")?.bytes, packet.len() - 2);
            assert_eq!(sender.outgoing_units(packet, &mut witness_buffer)?, 2);
            if source == 0 {
                if ordinal == 1 {
                    first_wire = packet.to_vec()
                }
                assert_eq!(packet, first_wire);
            } else {
                receiver.accept_authenticated(Tick(0), token.kind, packet)?;
            }
            sender.confirm_output(Tick(0), token)?;
            pn += 1;
        }
    }
    for _ in 0..8 {
        receiver.step(Tick(0), work())?;
    }
    let now = Tick(3_000);
    let mut feedback_pn = 100;
    let mut named = false;
    for _ in 0..64 {
        receiver.step(now, work())?;
        let Some((_, d)) = emit(&mut receiver, now, &mut feedback_pn, false)? else {
            continue;
        };
        named |= d.bytes.first() == Some(&5);
        sender.accept_authenticated(now, d.kind, &d.bytes)?;
        if named {
            break;
        }
    }
    assert!(named);
    sender.step(now, work())?;
    let (token, d) = emit(&mut sender, now, &mut pn, true)?.ok_or("named source retry")?;
    assert!(token.has_requested_credit());
    assert_eq!(d.bytes, first_wire);
    let mut malformed = d.bytes.clone();
    malformed[3..5].copy_from_slice(&u16::MAX.to_be_bytes());
    let prior = receiver.receiver_status();
    assert!(
        receiver
            .accept_authenticated(now, d.kind, &malformed)
            .is_err()
    );
    assert_eq!(receiver.receiver_status(), prior);
    receiver.accept_authenticated(now, d.kind, &d.bytes)?;
    let mut delivered = Vec::new();
    for _ in 0..64 {
        receiver.step(now, work())?;
        let mut output = [0; 1024];
        if let NativePreparation::Ready(native) =
            receiver.prepare_native(now, 32, Tick(10_000), &mut output)?
        {
            delivered.push(output[..native.bytes()].to_vec());
            receiver.commit_native(now, native.token())?;
        }
    }
    delivered.sort();
    originals.sort();
    assert_eq!(delivered, originals);
    assert_eq!(receiver.receiver_status().decoder.decoded_prefix, 2);
    Ok(())
}

#[test]
fn ack_lz4_ordinary_equation_matches_plain_and_restores_lost_source() -> TestResult {
    let (cfg, copies) = configured();
    let mut reference = cfg;
    reference.reverse.scheduler.source_wire = rolling::wire::SourceWire::TargetedExact;
    let mut plain = reserved(reference, Role::Server, copies)?;
    let mut compressed = reserved(cfg, Role::Server, copies)?;
    let mut receiver = reserved(cfg, Role::Client, copies)?;
    let mut plain_pn = 0;
    let mut compressed_pn = 0;
    let mut originals = Vec::new();
    for index in 0..2 {
        let now = Tick(index);
        let group = [ack(2000 + 2 * index as u32), ack(2001 + 2 * index as u32)];
        for sender in [&mut plain, &mut compressed] {
            for frame in &group {
                sender
                    .enqueue_admitted_identified(now, 0, frame)?
                    .ok_or("stage ACK")?;
            }
            sender.flush(now)?;
        }
        originals.extend(group);
        for _ in 0..3 {
            plain.step(now, work())?;
            compressed.step(now, work())?;
            let (_, baseline) =
                emit(&mut plain, now, &mut plain_pn, true)?.ok_or("plain source")?;
            let (_, tested) =
                emit(&mut compressed, now, &mut compressed_pn, true)?.ok_or("compressed source")?;
            assert_eq!(tested.kind, baseline.kind);
            assert!(tested.bytes.len() < baseline.bytes.len());
            if index == 1 {
                receiver.accept_authenticated(now, tested.kind, &tested.bytes)?;
            }
        }
    }
    let now = Tick(2);
    let mut repaired = false;
    for _ in 0..32 {
        plain.step(now, work())?;
        compressed.step(now, work())?;
        let observed = emit(&mut compressed, now, &mut compressed_pn, true)?;
        let control = emit(&mut plain, now, &mut plain_pn, true)?;
        assert_eq!(observed.is_some(), control.is_some());
        if let (Some((token, eq)), Some((baseline, raw))) = (observed, control) {
            assert_eq!(eq.kind, record_engine::EmissionKind::Repair);
            assert_eq!(eq.bytes[0], 2);
            assert_eq!(eq.bytes, raw.bytes);
            assert_eq!(token.wire_bytes, baseline.wire_bytes);
            receiver.accept_authenticated(now, eq.kind, &eq.bytes)?;
            repaired = true;
            break;
        }
    }
    assert!(repaired);
    let mut delivered = Vec::new();
    for _ in 0..64 {
        receiver.step(now, work())?;
        let mut output = [0; 1024];
        if let NativePreparation::Ready(native) =
            receiver.prepare_native(now, 32, Tick(10_000), &mut output)?
        {
            delivered.push(output[..native.bytes()].to_vec());
            receiver.commit_native(now, native.token())?;
        }
    }
    originals.sort();
    delivered.sort();
    assert_eq!(delivered, originals);
    Ok(())
}

/// Send `sources` ACK sources of two units each; return (first copies,
/// extra copies, regular repairs) emitted, with every output fed to `peer`.
fn send_acks(
    sender: &mut Endpoint,
    peer: &mut Endpoint,
    now: Tick,
    sources: u32,
    pn: &mut u64,
) -> TestResult<(usize, usize, usize)> {
    let (mut first, mut extra, mut repairs) = (0, 0, 0);
    for source in 0..sources {
        for index in 0..2 {
            sender
                .enqueue_admitted_identified(now, 0, &ack(201 + source * 2 + index))?
                .ok_or("stage ACK")?;
        }
        sender.flush(now)?;
        for _ in 0..16 {
            sender.step(now, work())?;
            let Some((token, d)) = emit(sender, now, pn, true)? else {
                continue;
            };
            match (token.id, token.source_copy()) {
                (OutputId::Data(scheduler::OutputId::Source(_)), Some(c)) if c.ordinal() > 1 => {
                    extra += 1
                }
                (OutputId::Data(scheduler::OutputId::Source(_)), _) => first += 1,
                (OutputId::Data(scheduler::OutputId::Repair(_)), _) => repairs += 1,
                _ => {}
            }
            peer.accept_authenticated(now, d.kind, &d.bytes)?;
            for _ in 0..8 {
                peer.step(now, work())?;
            }
        }
    }
    Ok((first, extra, repairs))
}

#[test]
fn return_guard_sheds_ack_copies_and_regular_repairs_only_while_engaged() -> TestResult {
    let (cfg, copies) = configured();
    assert_eq!(
        cfg.reverse.effective_guard_per_mille(),
        Some(ReturnGuard::DEFAULT_PER_MILLE)
    );
    let mut off_cfg = cfg;
    off_cfg.reverse.return_guard = ReturnGuard::OFF;
    let mut results = Vec::new();
    for (config, engage) in [(cfg, false), (off_cfg, true), (cfg, true)] {
        let mut sender = reserved(config, Role::Server, copies)?;
        let mut receiver = reserved(config, Role::Client, copies)?;
        let mut pn = 1;
        if engage {
            // Budget 100 KB at the default ratio, above the 16 KiB floor, already
            // used by never-shed output: any extra must be refused while engaged.
            sender.observe_delivered_for_test(Tick(0), 1_000_000);
            sender.observe_required_for_test(Tick(0), 100_000);
        }
        let counts = send_acks(&mut sender, &mut receiver, Tick(1), 8, &mut pn)?;
        results.push((counts, sender.return_guard_status()));
    }
    // Default guard without delivered peer traffic is disengaged: every copy and repair leaves.
    let ((first, extra, repairs), idle) = results[0];
    assert!(!idle.engaged);
    assert_eq!((first, extra), (8, 16));
    assert!(repairs > 0);
    assert_eq!(idle.shed_copy_sources + idle.shed_repairs, 0);
    // An explicit off guard measures but sends the same outputs.
    let (off_counts, off) = results[1];
    assert_eq!(off_counts, (first, extra, repairs));
    assert_eq!(off.effective_per_mille, None);
    assert_eq!(off.shed_copy_sources + off.shed_repairs, 0);
    assert_eq!(off.window_delivered_bytes, 1_000_000);
    assert!(!off.engaged);
    // Engaged default guard: first copies only, regular repairs displaced.
    let ((g_first, g_extra, g_repairs), guarded) = results[2];
    assert!(guarded.engaged);
    assert_eq!((g_first, g_extra, g_repairs), (8, 0, 0));
    assert_eq!(guarded.shed_copy_sources, 8);
    assert!(guarded.shed_repairs >= repairs as u64);
    assert_eq!(guarded.window_extra_bytes, 0);
    assert!(guarded.window_first_bytes > 0);
    Ok(())
}

#[test]
fn return_guard_counts_committed_native_bytes_from_the_peer() -> TestResult {
    let (cfg, copies) = configured();
    let mut sender = reserved(cfg, Role::Server, copies)?;
    let mut receiver = reserved(cfg, Role::Client, copies)?;
    let mut pn = 1;
    send_acks(&mut sender, &mut receiver, Tick(1), 4, &mut pn)?;
    let mut delivered = 0;
    for _ in 0..64 {
        receiver.step(Tick(2), work())?;
        let mut output = [0; 1024];
        if let NativePreparation::Ready(native) =
            receiver.prepare_native(Tick(2), 32, Tick(10_000), &mut output)?
        {
            delivered += native.bytes();
            receiver.commit_native(Tick(2), native.token())?;
        }
    }
    assert_eq!(delivered, 8 * ack(0).len());
    assert_eq!(
        receiver.return_guard_status().window_delivered_bytes,
        delivered as u64
    );
    Ok(())
}
