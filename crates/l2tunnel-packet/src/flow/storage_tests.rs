use super::*;
use crate::{Domain, Tuple};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(mapping: Mapping) -> FlowTableConfig {
    FlowTableConfig {
        capacity: 4,
        channels: 256,
        mapping,
        idle_timeout: Duration::from_millis(5),
    }
}
fn key(number: u16) -> FlowKey {
    FlowKey {
        domain: Domain::default(),
        tuple: Tuple::Ethernet(number, [0; 6], [1; 6]),
    }
}
fn backing(table: &FlowTable) -> Result<(usize, *const Cell), &'static str> {
    match &table.entries {
        Entries::Reserved(entries) => Ok((entries.capacity(), entries.as_ptr())),
        _ => Err("expected actual reserved entries"),
    }
}
fn reserved(config: FlowTableConfig) -> Result<FlowTable, storage::Error> {
    let plan = storage::Plan::for_config(config)?;
    FlowTable::with_plan(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )
}

#[test]
fn complete_plan_admission_measures_actual_capacity_before_publication() -> TestResult {
    let plan = storage::Plan::for_config(config(Mapping::Crc32))?;
    let required = plan.capacity_bytes();
    assert_eq!(required, 4 * std::mem::size_of::<Cell>());
    let mut allocation = storage::Allocation::failing(1);
    let refused = FlowTable::with_allocation(
        plan,
        storage::Limits {
            capacity_bytes: required - 1,
        },
        &mut allocation,
    );
    assert!(
        matches!(refused, Err(storage::Error::Limit { required: r, limit }) if r == required && limit == required - 1)
    );
    assert_eq!(allocation.attempts, 0);
    assert!(matches!(
        FlowTable::with_allocation(
            plan,
            storage::Limits {
                capacity_bytes: required
            },
            &mut allocation
        ),
        Err(storage::Error::Allocation)
    ));
    assert_eq!(allocation.attempts, 1);
    for extra in [0, 1] {
        let table = FlowTable::with_plan(
            plan,
            storage::Limits {
                capacity_bytes: required + extra,
            },
        )?;
        let (capacity, _) = backing(&table)?;
        assert_eq!(capacity, plan.config().capacity);
        assert_eq!(
            table.storage_usage(),
            Some(storage::Usage {
                limit_bytes: required + extra,
                capacity_bytes: capacity * std::mem::size_of::<Cell>(),
                allocations: 1
            })
        );
        assert!(table.is_empty());
    }
    assert_eq!(FlowTable::new(plan.config())?.storage_usage(), None);
    Ok(())
}

#[test]
fn scalar_maxima_and_layout_validation_preserve_full_original_domain() -> TestResult {
    let maximum = storage::Plan::for_config(FlowTableConfig {
        capacity: 65536,
        ..config(Mapping::ConnectionRoundRobin)
    })?;
    assert_eq!(maximum.config().capacity, 65536);
    assert_eq!(maximum.config().channels, 256);
    assert_eq!(
        maximum.capacity_bytes(),
        65536 * std::mem::size_of::<Cell>()
    );
    for invalid in [
        FlowTableConfig {
            capacity: 0,
            ..maximum.config()
        },
        FlowTableConfig {
            capacity: 65537,
            ..maximum.config()
        },
        FlowTableConfig {
            channels: 257,
            ..maximum.config()
        },
        FlowTableConfig {
            idle_timeout: Duration::ZERO,
            ..maximum.config()
        },
    ] {
        assert_eq!(
            storage::Plan::for_config(invalid),
            Err(storage::Error::Flow(FlowError::InvalidConfig))
        );
        assert!(matches!(
            FlowTable::new_reserved(invalid, storage::Limits { capacity_bytes: 0 }),
            Err(storage::Error::Flow(FlowError::InvalidConfig))
        ));
    }
    assert_eq!(
        storage::array_bytes::<Cell>(usize::MAX),
        Err(storage::Error::Layout)
    );
    Ok(())
}

#[test]
fn real_reserved_and_legacy_tables_preserve_mapping_retirement_and_reuse() -> TestResult {
    for mapping in [Mapping::Crc32, Mapping::ConnectionRoundRobin] {
        let mut fixed = reserved(config(mapping))?;
        let mut legacy = FlowTable::new(config(mapping))?;
        let original = backing(&fixed)?;
        for round in 0..32u64 {
            let now = Duration::from_millis(round * 10);
            for number in [3, 1, 4, 2] {
                assert_eq!(
                    fixed.assign(key(number), now),
                    legacy.assign(key(number), now)
                );
            }
            assert_eq!(fixed.assign(key(9), now), Err(FlowError::Capacity));
            assert_eq!(legacy.assign(key(9), now), Err(FlowError::Capacity));
            let existing = fixed.lookup(&key(3)).ok_or("existing")?;
            assert_eq!(
                fixed.learn(key(3), existing.channel, now),
                legacy.learn(key(3), existing.channel, now)
            );
            let conflicting = (existing.channel + 1) % 256;
            assert_eq!(
                fixed.learn(key(3), conflicting, now),
                legacy.learn(key(3), conflicting, now)
            );
            assert_eq!(fixed.oldest_idle(now), legacy.oldest_idle(now));
            let expiry = now + Duration::from_millis(5);
            // Canonical key order, rather than insertion order, breaks equal-age ties.
            assert_eq!(fixed.oldest_idle(expiry)?.map(|(key, _)| key), Some(key(1)));
            for number in [4, 2, 1, 3] {
                assert_eq!(
                    fixed.retire_idle(&key(number), expiry),
                    legacy.retire_idle(&key(number), expiry)
                );
            }
            assert!(fixed.is_empty());
            assert_eq!(backing(&fixed)?, original);
            assert_eq!(fixed.next_id, legacy.next_id);
            assert_eq!(fixed.next_channel, legacy.next_channel);
        }
    }
    Ok(())
}

#[test]
fn dropped_transactions_and_last_identity_keep_error_order_and_epoch_continuation() -> TestResult {
    let cfg = FlowTableConfig {
        capacity: 1,
        ..config(Mapping::ConnectionRoundRobin)
    };
    let mut fixed = reserved(cfg)?;
    let original = backing(&fixed)?;
    {
        let prepared = fixed.prepare_assign(key(1), Duration::from_secs(50))?;
        assert_eq!(
            prepared.binding(),
            Binding {
                id: FlowId(1),
                channel: 0
            }
        );
    }
    {
        let prepared = fixed.prepare_learn(key(1), 255, Duration::from_secs(60))?;
        assert_eq!(prepared.binding().channel, 255);
    }
    assert!(fixed.is_empty());
    assert_eq!(fixed.last_now, Duration::ZERO);
    assert_eq!((fixed.next_id, fixed.next_channel), (Some(1), 0));
    fixed.next_id = Some(u64::MAX);
    let final_binding = fixed.assign(key(1), Duration::from_secs(2))?;
    assert_eq!(final_binding.id, FlowId(u64::MAX));
    assert_eq!(
        fixed.assign(key(2), Duration::from_secs(1)),
        Err(FlowError::TimeRegression)
    );
    assert_eq!(
        fixed.learn(key(2), 256, Duration::from_secs(2)),
        Err(FlowError::InvalidChannel)
    );
    assert_eq!(
        fixed.assign(key(2), Duration::from_secs(2)),
        Err(FlowError::Capacity)
    );
    assert_eq!(fixed.assign(key(1), Duration::from_secs(2))?, final_binding);
    assert_eq!(fixed.remove_drained(&key(1)), Some(final_binding));
    assert_eq!(
        fixed.assign(key(2), Duration::from_secs(2)),
        Err(FlowError::IdExhausted)
    );
    assert_eq!(backing(&fixed)?, original);
    let mut continued = reserved(cfg)?;
    continued.continue_ids_from(&fixed)?;
    assert_eq!(
        continued.assign(key(2), Duration::ZERO),
        Err(FlowError::TimeRegression)
    );
    assert_eq!(
        continued.assign(key(2), Duration::from_secs(2)),
        Err(FlowError::IdExhausted)
    );
    Ok(())
}
