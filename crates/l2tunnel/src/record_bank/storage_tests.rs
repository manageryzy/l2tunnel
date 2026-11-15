use super::tests::{FAMILIES, Family, TestResult, bank, packet, plan};
use super::*;
use l2tunnel_management::Role;

#[test]
fn actual_two_slot_layout_counts_inline_headers_once_and_measures_nested_heaps() -> TestResult {
    for family in FAMILIES {
        let first = plan(family, Role::Client, 7)?;
        let inventory = storage::Plan::for_bank(first, 137)?;
        let required = size_of::<Bank>() + 137 + first.heap_bytes();
        assert_eq!(inventory.capacity_bytes(), required);
        assert_eq!(inventory.initial().configuration(), first.configuration());
        assert_eq!(inventory.external_bytes(), 137);
        assert!(
            matches!(Bank::new(inventory, storage::Limits { capacity_bytes: required - 1 }), Err(Error::Limit { required: actual, limit }) if actual == required && limit + 1 == required)
        );
        for extra in [0, 1] {
            let bank = Bank::new(
                inventory,
                storage::Limits {
                    capacity_bytes: required + extra,
                },
            )?;
            let nested = bank
                .engine(bank.initial())?
                .storage_usage()
                .ok_or("actual reserved owner")?;
            let usage = bank.usage();
            assert_eq!(usage.fixed_bytes, size_of::<Bank>());
            assert!(usage.fixed_bytes >= 2 * size_of::<engine::Engine>());
            assert_eq!(
                usage.engine_bytes,
                nested.pipeline_bytes + nested.record_bytes
            );
            assert_eq!(usage.engine_bytes, first.heap_bytes());
            assert_eq!(usage.capacity_bytes, required);
            assert_eq!(usage.limit_bytes, required + extra);
            assert_eq!(usage.allocations, nested.allocations);
            assert_eq!((usage.building_bytes, usage.peak_bytes), (0, required));
        }
    }
    assert!(matches!(
        storage::Plan::for_bank(plan(Family::Swift, Role::Client, 7)?, usize::MAX),
        Err(Error::Layout)
    ));
    Ok(())
}

#[test]
fn one_short_second_slot_never_enters_constructor_and_exact_plus_one_admits() -> TestResult {
    let initial = plan(Family::Swift, Role::Client, 7)?;
    let target = plan(Family::Packed, Role::Client, 8)?;
    let inventory = storage::Plan::for_bank(initial, 137)?;
    let complete = inventory.capacity_bytes() + target.heap_bytes();
    let mut refused = Bank::new(
        inventory,
        storage::Limits {
            capacity_bytes: complete - 1,
        },
    )?;
    let before = refused.usage();
    let mut entered = false;
    assert!(
        matches!(refused.prepare_with(target, |_, _, _| { entered = true; Err(engine::storage::Error::Invariant) }), Err(Error::Limit { required, limit }) if required == complete && limit == complete - 1)
    );
    assert!(!entered);
    assert_eq!(refused.usage(), before);
    assert_eq!(refused.next_generation, Some(2));
    for extra in [0, 1] {
        let mut bank = Bank::new(
            inventory,
            storage::Limits {
                capacity_bytes: complete + extra,
            },
        )?;
        let mut prepared = bank.prepare(target)?;
        let target_usage = bank
            .prepared_engine(&prepared)?
            .storage_usage()
            .ok_or("actual target")?;
        let initial_usage = bank
            .engine(bank.initial())?
            .storage_usage()
            .ok_or("actual initial")?;
        assert_eq!(
            bank.usage().engine_bytes,
            initial.heap_bytes() + target.heap_bytes()
        );
        assert_eq!(bank.usage().capacity_bytes, complete);
        assert_eq!(bank.usage().peak_bytes, complete);
        assert_eq!(
            bank.usage().allocations,
            initial_usage.allocations + target_usage.allocations
        );
        bank.cancel(&mut prepared)?;
        assert_eq!(bank.usage().capacity_bytes, inventory.capacity_bytes());
        assert_eq!(bank.usage().peak_bytes, complete);
    }
    Ok(())
}

#[test]
fn actual_target_drop_keeps_attempted_peak_and_preserves_live_old_owner_and_generation()
-> TestResult {
    let initial = plan(Family::Swift, Role::Client, 7)?;
    let target = plan(Family::Aligned, Role::Client, 8)?;
    let mut bank = bank(initial, target.heap_bytes())?;
    let current = bank.initial();
    let metadata = bank
        .entry(current)?
        .enqueue_borrowed(engine::Tick(0), &packet(0x72))?;
    let original = bank.engine(current)? as *const engine::Engine;
    let old_queue = bank.engine(current)?.queue_usage();
    let old_stats = bank.engine(current)?.statistics();
    let before = bank.usage();
    let expected_peak = before.capacity_bytes + target.heap_bytes();
    let mut dropped = false;
    let result = bank.prepare_with(target, |plan, limits, charge| {
        assert_eq!(charge.building_bytes, plan.heap_bytes());
        assert_eq!(charge.engine_bytes, before.engine_bytes);
        assert_eq!(charge.capacity_bytes, expected_peak);
        assert_eq!(charge.peak_bytes, expected_peak);
        // This is a local post-construction refusal, not nested allocator exhaustion.
        let actual = engine::Engine::new_reserved(plan, limits)?;
        assert_eq!(
            actual.storage_usage().map(|usage| usage.capacity_bytes),
            Some(plan.capacity_bytes())
        );
        drop(actual);
        dropped = true;
        Err(engine::storage::Error::Invariant)
    });
    assert!(matches!(
        result,
        Err(Error::Storage(engine::storage::Error::Invariant))
    ));
    assert!(dropped);
    assert_eq!(bank.next_generation, Some(2));
    assert_eq!(bank.usage().engine_bytes, before.engine_bytes);
    assert_eq!(bank.usage().allocations, before.allocations);
    assert_eq!(
        (bank.usage().capacity_bytes, bank.usage().building_bytes),
        (before.capacity_bytes, 0)
    );
    assert_eq!(bank.usage().peak_bytes, expected_peak);
    assert_eq!(bank.engine(current)? as *const engine::Engine, original);
    assert_eq!(bank.engine(current)?.queue_usage(), old_queue);
    assert_eq!(bank.engine(current)?.statistics(), old_stats);
    let mut prepared = bank.prepare(target)?;
    assert_eq!(prepared.id.generation, 2);
    let published = bank.publish(&mut prepared)?;
    assert_eq!(
        bank.engine(published)?.configuration(),
        target.configuration()
    );
    let admitted = bank
        .entry(current)?
        .admit_borrowed(engine::Tick(0))?
        .ok_or("old owner still progresses")?;
    assert_eq!(admitted.metadata, metadata);
    assert_eq!(
        bank.engine(current)?.statistics().admitted,
        old_stats.admitted + 1
    );
    Ok(())
}

#[test]
fn nonwrapping_instance_and_final_generation_exhaustion_preserve_retained_owners() -> TestResult {
    let instances = AtomicU64::new(u64::MAX - 1);
    assert_eq!(allocate_instance(&instances), Ok(u64::MAX - 1));
    assert_eq!(allocate_instance(&instances), Err(Error::Exhausted));
    assert_eq!(instances.load(Ordering::Relaxed), u64::MAX);
    let initial = plan(Family::Swift, Role::Client, 7)?;
    let target = plan(Family::Packed, Role::Client, 8)?;
    let mut bank = bank(initial, target.heap_bytes())?;
    bank.next_generation = Some(u64::MAX);
    let mut prepared = bank.prepare(target)?;
    assert_eq!(prepared.id.generation, u64::MAX);
    assert_eq!(bank.next_generation, None);
    let last = bank.publish(&mut prepared)?;
    bank.retire(last)?;
    let before = bank.usage();
    let mut entered = false;
    assert!(matches!(
        bank.prepare_with(target, |_, _, _| {
            entered = true;
            Err(engine::storage::Error::Invariant)
        }),
        Err(Error::Exhausted)
    ));
    assert!(!entered);
    assert_eq!(bank.usage(), before);
    assert!(matches!(bank.engine(last), Err(Error::Stale)));
    assert_eq!(
        bank.engine(bank.initial())?.configuration(),
        initial.configuration()
    );
    Ok(())
}
