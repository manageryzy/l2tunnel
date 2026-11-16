//! Real reserved decoder input custody; no socket/native-platform qualification.
use super::*;

fn queued(config: Config, slots: usize) -> TestResult<(Endpoint, storage::Usage)> {
    let maximum = config.forward.maximum_packet_bytes()?;
    let mut ingress = IngressLimits {
        slots,
        capacity_bytes: usize::MAX,
    };
    ingress.capacity_bytes = ingress.required_capacity(maximum)?;
    let short = IngressLimits {
        capacity_bytes: ingress.capacity_bytes - 1,
        ..ingress
    };
    assert!(matches!(
        short.required_capacity(maximum),
        Err(Error::Ingress(crate::native_storage::Error::Limit { .. }))
    ));
    let old = storage::Plan::for_endpoint(config, context(Role::Server), 17, Tick(0))?;
    let plan = storage::Plan::for_endpoint_with_options(
        config,
        context(Role::Server),
        17,
        Tick(0),
        CopyPolicies::ONE,
        Some(ingress),
    )?;
    assert_eq!(
        plan.capacity_bytes(),
        old.capacity_bytes() + ingress.capacity_bytes
    );
    let endpoint = Endpoint::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let usage = endpoint
        .storage_usage()
        .ok_or("actual queue/decoder heap")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    Ok((endpoint, usage))
}

#[test]
fn actual_queue_retains_busy_input_exact_bytes_and_original_age_until_decoder_ownership()
-> TestResult {
    let config = short_config(64, rolling::wire::SourceWire::Exact);
    let (old_wire, short_wire, old_id, short_id, old, short) = originals(config)?;
    let (mut receiver, usage) = queued(config, 2)?;
    receiver.accept_authenticated_until(
        Tick(6),
        Tick(6),
        Tick(9_000_000),
        Some(71),
        short_wire.kind,
        &short_wire.bytes,
    )?;
    receiver.accept_authenticated_until(
        Tick(7),
        Tick(7),
        Tick(8_000_000),
        Some(72),
        old_wire.kind,
        &old_wire.bytes,
    )?;
    let full = receiver.ingress_status().ok_or("actual ingress")?;
    assert_eq!(full.packets, 2);
    assert_eq!(full.bytes, short_wire.bytes.len() + old_wire.bytes.len());
    assert_eq!(full.oldest_received, Some(Tick(6)));
    assert_eq!(full.oldest_records_number, Some(71));
    assert_eq!(full.deadline, Some(Tick(1_000_006)));
    assert!(!receiver.drained());
    assert_eq!(
        receiver.accept_authenticated_until(
            Tick(7),
            Tick(7),
            Tick(8_000_000),
            Some(73),
            short_wire.kind,
            &short_wire.bytes
        ),
        Err(Error::Busy)
    );
    assert_eq!(receiver.ingress_status(), Some(full));
    let one = receiver.step(
        Tick(9),
        rolling::WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        },
    )?;
    assert!(
        one.receive.work.field <= 1
            && one.receive.work.copies <= 1
            && one.receive.work.metadata <= 1
    );
    let held = receiver.ingress_status().ok_or("retained input")?;
    assert_eq!(held.packets, 1);
    assert_eq!(held.bytes, old_wire.bytes.len());
    assert_eq!(held.oldest_received, Some(Tick(7)));
    assert_eq!(held.oldest_records_number, Some(72));
    assert!(receiver.receiver_status().decoder.pending_job);
    service_until(&mut receiver, Tick(9), |owner| {
        owner
            .ingress_status()
            .is_some_and(|state| state.packets == 0)
            && owner.receiver_status().decoder.handoff_prefix == 2
    })?;
    let mut output = [0; 1024];
    for (identity, bytes) in [(old_id, old), (short_id, short)] {
        let native = ready(&mut receiver, Tick(9), &mut output)?;
        assert_eq!(native.identity(), identity);
        assert_eq!(&output[..native.bytes()], bytes);
        receiver.commit_native(Tick(9), native.token())?;
    }
    assert_eq!(receiver.statistics().committed, 2);
    assert_eq!(receiver.storage_usage(), Some(usage));
    assert_eq!(
        receiver
            .ingress_status()
            .ok_or("empty actual ingress")?
            .bytes,
        0
    );
    Ok(())
}

#[test]
fn queued_and_started_input_preserve_original_caller_cap_without_timer_renewal() -> TestResult {
    let config = short_config(64, rolling::wire::SourceWire::Exact);
    let (_, wire, _, _, _, _) = originals(config)?;
    for start in [false, true] {
        let (mut receiver, usage) = queued(config, 1)?;
        receiver.accept_authenticated_until(
            Tick(6),
            Tick(6),
            Tick(11),
            Some(91),
            wire.kind,
            &wire.bytes,
        )?;
        assert_eq!(
            receiver.ingress_status().ok_or("actual input")?.deadline,
            Some(Tick(11))
        );
        if start {
            receiver.step(
                Tick(9),
                rolling::WorkBudget {
                    field: 1,
                    copies: 1,
                    metadata: 1,
                },
            )?;
            assert_eq!(receiver.ingress_status().ok_or("actual input")?.packets, 0);
            assert!(receiver.receiver_status().decoder.pending_job);
            assert_eq!(receiver.deadline(), Some(Tick(11)));
        }
        assert!(receiver.tick(Tick(11)).is_err());
        assert!(receiver.failure().is_some());
        assert!(receiver.tick(Tick(10)).is_err());
        assert!(!receiver.drained());
        assert_eq!(receiver.storage_usage(), Some(usage));
    }
    Ok(())
}
