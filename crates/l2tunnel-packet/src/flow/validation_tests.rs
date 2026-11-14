use super::*;
use crate::{Domain, Tuple};

fn config() -> FlowTableConfig {
    FlowTableConfig {
        capacity: 1,
        channels: 1,
        mapping: Mapping::ConnectionRoundRobin,
        idle_timeout: Duration::from_nanos(1),
    }
}

#[test]
fn scalar_validation_rejects_exact_flow_bounds_before_construction() {
    let valid = config();
    let invalid = [
        FlowTableConfig {
            capacity: 0,
            ..valid
        },
        FlowTableConfig {
            capacity: 65_537,
            ..valid
        },
        FlowTableConfig {
            channels: 0,
            ..valid
        },
        FlowTableConfig {
            channels: 257,
            ..valid
        },
        FlowTableConfig {
            idle_timeout: Duration::ZERO,
            ..valid
        },
    ];
    for value in invalid {
        assert_eq!(value.validate(), Err(FlowError::InvalidConfig));
        assert!(matches!(
            FlowTable::new(value),
            Err(FlowError::InvalidConfig)
        ));
    }
}

#[test]
fn scalar_validation_preserves_extreme_policy_and_fresh_actual_identity() -> Result<(), FlowError> {
    let key = FlowKey {
        domain: Domain::default(),
        tuple: Tuple::Ethernet(0x88b5, [1; 6], [2; 6]),
    };
    for value in [
        config(),
        FlowTableConfig {
            capacity: 65_536,
            channels: 256,
            idle_timeout: Duration::from_secs(u64::MAX),
            ..config()
        },
    ] {
        value.validate()?;
        let mut table = FlowTable::new(value)?;
        assert!(table.is_empty());
        assert_eq!(
            table.preview_assign(key, Duration::ZERO)?,
            Binding {
                id: FlowId(1),
                channel: 0,
            }
        );
        assert_eq!(table.assign(key, Duration::ZERO)?.id, FlowId(1));
        assert_eq!(table.len(), 1);
    }
    Ok(())
}
