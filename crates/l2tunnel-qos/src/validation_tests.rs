use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> SchedulerConfig {
    SchedulerConfig {
        base_quantum_bytes: 64,
        max_classes: 4,
        max_flows: 2,
        max_packet_bytes: 1500,
        max_queued_bytes: 8000,
        max_queued_packets: 4,
        per_flow_bytes: 2000,
        per_flow_packets: 2,
    }
}

fn class(id: u16, weight: u32) -> ClassConfig {
    ClassConfig {
        id: ClassId::new(id),
        weight,
    }
}

fn expect_error(config: SchedulerConfig, classes: &[ClassConfig], expected: ConfigError) {
    assert_eq!(config.validate(classes), Err(expected));
    assert!(matches!(Scheduler::new(config, classes), Err(error) if error == expected));
}

#[test]
fn scalar_scheduler_errors_keep_constructor_precedence() {
    let original = config();
    let mut value = original;
    value.base_quantum_bytes = 0;
    value.max_packet_bytes = original.per_flow_bytes + 1;
    expect_error(value, &[], ConfigError::ZeroLimit);
    value.base_quantum_bytes = original.base_quantum_bytes;
    expect_error(value, &[], ConfigError::InconsistentBounds);
    expect_error(original, &[], ConfigError::NoClasses);

    value = original;
    value.max_classes = 1;
    expect_error(
        value,
        &[class(0, 0), class(0, 0)],
        ConfigError::TooManyClasses,
    );
    expect_error(
        original,
        &[class(0, 1), class(0, 0)],
        ConfigError::ZeroWeight,
    );
    expect_error(
        original,
        &[class(0, 1), class(0, 1)],
        ConfigError::DuplicateClass,
    );
}

#[test]
fn class_bitmap_covers_word_boundaries_and_maximum_class_id() -> TestResult {
    let classes = [class(0, 1), class(63, 2), class(64, 3), class(u16::MAX, 4)];
    config().validate(&classes)?;
    let mut scheduler = Scheduler::new(config(), &classes)?;
    for (id, class_id) in [(1, 0), (2, u16::MAX)] {
        scheduler.register_flow(FlowConfig {
            id: FlowId::new(id),
            class: ClassId::new(class_id),
            weight: 1,
        })?;
    }
    for repeated in [0, 63, 64, u16::MAX] {
        expect_error(
            config(),
            &[class(repeated, 1), class(repeated, 1)],
            ConfigError::DuplicateClass,
        );
    }
    Ok(())
}

#[test]
fn shared_flow_quantum_keeps_live_duplicate_capacity_and_weight_order() -> TestResult {
    let limits = SchedulerConfig {
        base_quantum_bytes: u32::MAX,
        max_flows: 1,
        ..config()
    };
    assert_eq!(limits.flow_quantum(None, 0), Err(FlowError::ZeroWeight));
    assert_eq!(limits.flow_quantum(None, 1), Err(FlowError::UnknownClass));
    assert_eq!(
        limits.flow_quantum(Some(2), u32::MAX),
        Err(FlowError::Arithmetic)
    );
    assert_eq!(limits.flow_quantum(Some(2), 1)?, u64::from(u32::MAX) * 2);
    let mut scheduler = Scheduler::new(limits, &[class(0, 2)])?;
    let flow = FlowConfig {
        id: FlowId::new(1),
        class: ClassId::new(0),
        weight: 1,
    };
    scheduler.register_flow(flow)?;
    let invalid = FlowConfig {
        id: flow.id,
        class: ClassId::new(1),
        weight: 0,
    };
    assert_eq!(scheduler.register_flow(invalid), Err(FlowError::Duplicate));
    let invalid = FlowConfig {
        id: FlowId::new(2),
        ..invalid
    };
    assert_eq!(scheduler.register_flow(invalid), Err(FlowError::Capacity));
    scheduler.remove_flow(flow.id)?;
    assert_eq!(scheduler.register_flow(invalid), Err(FlowError::ZeroWeight));
    assert_eq!(
        scheduler.register_flow(FlowConfig {
            weight: 1,
            ..invalid
        }),
        Err(FlowError::UnknownClass)
    );
    assert_eq!(
        scheduler.register_flow(FlowConfig {
            class: flow.class,
            weight: u32::MAX,
            ..invalid
        }),
        Err(FlowError::Arithmetic)
    );
    scheduler.register_flow(flow)?;
    scheduler.enqueue(flow.id, vec![7])?;
    assert_eq!(scheduler.set_flow_weight(flow.id, 0), Err(FlowError::Busy));
    assert_eq!(
        scheduler.dequeue()?.ok_or("missing actual packet")?.payload,
        vec![7]
    );
    assert_eq!(
        scheduler.set_flow_weight(flow.id, 0),
        Err(FlowError::ZeroWeight)
    );
    Ok(())
}

#[test]
fn exact_maximum_deficit_and_duplicate_arithmetic_use_original_checked_helper() -> TestResult {
    let quantum = u64::from(u32::MAX) * u64::from(u32::MAX);
    let Ok(maximum_packet) = usize::try_from(u64::MAX - quantum + 1) else {
        return Ok(());
    };
    let limits = SchedulerConfig {
        base_quantum_bytes: u32::MAX,
        max_packet_bytes: maximum_packet,
        per_flow_bytes: maximum_packet,
        max_queued_bytes: maximum_packet,
        ..config()
    };
    limits.validate(&[class(0, u32::MAX)])?;
    assert_eq!(limits.flow_quantum(Some(u32::MAX), 1)?, quantum);
    let mut scheduler = Scheduler::new(limits, &[class(0, u32::MAX)])?;
    scheduler.register_flow(FlowConfig {
        id: FlowId::new(1),
        class: ClassId::new(0),
        weight: 1,
    })?;
    let invalid = SchedulerConfig {
        max_packet_bytes: maximum_packet + 1,
        per_flow_bytes: maximum_packet + 1,
        max_queued_bytes: maximum_packet + 1,
        ..limits
    };
    expect_error(
        invalid,
        &[class(0, 1), class(0, u32::MAX)],
        ConfigError::Arithmetic,
    );
    assert_eq!(
        invalid.flow_quantum(Some(u32::MAX), 1),
        Err(FlowError::Arithmetic)
    );
    Ok(())
}
