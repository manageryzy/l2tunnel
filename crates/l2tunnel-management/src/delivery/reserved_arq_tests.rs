use super::*;
use l2tunnel_recovery::storage::{Limits, Plan};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn settings() -> Settings {
    Settings {
        recovery: ArqConfig {
            max_source_bytes: 128,
            send_bytes: 512,
            receive_bytes: 512,
            send_records: 4,
            receive_records: 4,
            initial_rto: Duration::from_millis(10),
            maximum_rto: Duration::from_millis(80),
            ack_delay: Duration::ZERO,
            max_retries: 8,
        },
        interval: Duration::from_millis(10),
        packets_per_interval: 4,
        bytes_per_interval: 1024,
        wire_overhead: 64,
    }
}
fn binding(role: Role) -> Binding {
    Binding {
        session: SessionId([0x79; 16]),
        lane: LaneId(7),
        local_role: role,
        control_epoch: 3,
    }
}
fn ingress(role: Role) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: binding(role).session,
        lane: LaneId(7),
        sender: role,
    }
}

#[test]
fn pure_validation_and_reserved_service_preserve_original_error_precedence() -> Result {
    let mut settings = settings();
    settings.recovery.initial_rto = Duration::ZERO;
    settings.wire_overhead = usize::MAX;
    let expected = Error::Recovery(RecoveryError::InvalidConfig);
    assert_eq!(
        settings.validate(
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(1)
        ),
        Err(expected)
    );
    assert!(
        matches!(Service::new(settings, binding(Role::Client), Duration::ZERO, Duration::from_secs(1)),
        Err(error) if error == expected)
    );
    assert!(
        matches!(Service::new_reserved_arq(settings, binding(Role::Client), Duration::ZERO,
        Duration::from_secs(1), Limits { capacity_bytes: 0 }),
        Err(ReservedArqError::Service(error)) if error == expected)
    );
    settings.interval = Duration::ZERO;
    assert_eq!(
        settings.validate(
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(1)
        ),
        Err(Error::Settings)
    );
    Ok(())
}

#[test]
fn reserved_service_owns_actual_sources_receipts_quota_and_original_expiry() -> Result {
    let settings = settings();
    let heap = Plan::for_arq(settings.recovery)?.capacity_bytes();
    assert!(matches!(
        Service::new_reserved_arq(
            settings,
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(1),
            Limits {
                capacity_bytes: heap - 1
            }
        ),
        Err(ReservedArqError::Storage(_))
    ));
    let make = |role| {
        Service::new_reserved_arq(
            settings,
            binding(role),
            Duration::ZERO,
            Duration::from_secs(1),
            Limits {
                capacity_bytes: heap,
            },
        )
    };
    let mut left = make(Role::Client)?;
    let mut right = make(Role::Server)?;
    let usage = left.arq_storage_usage();
    assert_eq!(usage.map(|usage| usage.capacity_bytes), Some(heap));
    let source = left.submit(b"owned source bytes", Duration::ZERO)?;
    let mut packet = [0; 256];
    assert_eq!(left.poll(Duration::ZERO, 0, &mut packet)?, None);
    assert!(!left.source_confirmed(source, Duration::ZERO)?);
    let emission = left
        .poll(Duration::ZERO, usize::MAX, &mut packet)?
        .ok_or(Error::Settings)?;
    assert_eq!(emission.wire_bytes, emission.bytes + settings.wire_overhead);
    right.receive(
        ingress(Role::Client),
        &packet[..emission.bytes],
        Duration::ZERO,
    )?;
    assert!(!left.source_confirmed(source, Duration::ZERO)?);
    let mut output = [0; 128];
    let (_, size) = right
        .deliver(&mut output, Duration::ZERO)?
        .ok_or(Error::Settings)?;
    assert_eq!(&output[..size], b"owned source bytes");
    let ack = right
        .poll(Duration::ZERO, usize::MAX, &mut packet)?
        .ok_or(Error::Settings)?;
    left.receive(ingress(Role::Server), &packet[..ack.bytes], Duration::ZERO)?;
    assert!(left.source_confirmed(source, Duration::ZERO)?);
    assert!(left.drained());
    assert_eq!(left.arq_storage_usage(), usage);
    assert_eq!(
        left.submit(b"late", Duration::from_secs(1)),
        Err(Error::Expired)
    );
    assert_eq!(
        Service::new(
            settings,
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(1)
        )?
        .arq_storage_usage(),
        None
    );
    Ok(())
}
