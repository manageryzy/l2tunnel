//! Actual selected control construction and liveness over reserved ARQ owners.

use super::*;
use l2tunnel_core::{ConfigDigest, Epoch};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn base() -> delivery::Settings {
    delivery::Settings {
        recovery: recovery::ArqConfig {
            max_source_bytes: 192,
            send_bytes: 768,
            receive_bytes: 768,
            send_records: 4,
            receive_records: 4,
            initial_rto: Duration::from_millis(10),
            maximum_rto: Duration::from_millis(100),
            ack_delay: Duration::ZERO,
            max_retries: 32,
        },
        interval: Duration::from_millis(10),
        packets_per_interval: 2,
        bytes_per_interval: 2048,
        wire_overhead: 76,
    }
}
fn selected() -> Settings {
    Settings {
        streams: [messages::Settings {
            delivery: delivery::Settings {
                wire_overhead: 84,
                ..base()
            },
            path_mtu: 1500,
            max_message_bytes: 2048,
            max_outbound_messages: 3,
            max_outbound_bytes: 8192,
            max_fragments: 16,
            max_reassembly_bytes: 4096,
            max_incomplete_messages: 1,
            message_lifetime: Duration::from_secs(2),
            work_per_call: 4,
        }; 3],
    }
}
fn binding(role: mg::Role) -> delivery::Binding {
    delivery::Binding {
        session: mg::SessionId([0x29; 16]),
        lane: mg::LaneId(0),
        local_role: role,
        control_epoch: 3,
    }
}
fn scope(epoch: u64, byte: u8) -> sc::Scope {
    sc::Scope {
        epoch: Epoch(epoch),
        digest: ConfigDigest([byte; 32]),
    }
}
fn limits() -> Result<[recovery::storage::Limits; 3]> {
    let bytes = recovery::storage::Plan::for_arq(base().recovery)?.capacity_bytes();
    Ok([recovery::storage::Limits {
        capacity_bytes: bytes,
    }; 3])
}
fn make(role: mg::Role) -> Result<Owner> {
    Ok(Owner::new_leased_reserved_arq(
        base(),
        selected(),
        binding(role),
        scope(3, 0x31),
        scope(1, 0x71),
        Duration::ZERO,
        Duration::from_secs(5),
        limits()?,
    )?)
}

#[test]
fn actual_three_stream_usage_matches_plans_and_legacy_is_not_reported_reserved() -> Result {
    let owner = make(mg::Role::Client)?;
    let usage = owner
        .arq_storage_usage()
        .ok_or_else(|| invalid("missing actual pools"))?;
    for (observed, settings) in usage.into_iter().zip(selected().streams) {
        assert_eq!(
            observed.capacity_bytes,
            recovery::storage::Plan::for_arq(settings.delivery.recovery)?.capacity_bytes()
        );
        assert_eq!(observed.allocations, 10);
    }
    let legacy = Owner::new_leased(
        base(),
        selected(),
        binding(mg::Role::Client),
        scope(3, 0x31),
        scope(1, 0x71),
        Duration::ZERO,
        Duration::from_secs(5),
    )?;
    assert_eq!(legacy.arq_storage_usage(), None);
    let mut invalid_limits = limits()?;
    invalid_limits[2].capacity_bytes -= 1;
    assert!(
        Owner::new_leased_reserved_arq(
            base(),
            selected(),
            binding(mg::Role::Client),
            scope(3, 0x31),
            scope(1, 0x71),
            Duration::ZERO,
            Duration::from_secs(5),
            invalid_limits
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn reserved_control_uses_actual_liveness_binding_shared_quota_and_confirmation() -> Result {
    let mut owners = [make(mg::Role::Client)?, make(mg::Role::Server)?];
    let before = owners[0].arq_storage_usage();
    let token = owners[0]
        .submit(
            scope(3, 0x31),
            sc::Body::Ping { nonce: 0x9876 },
            Duration::ZERO,
            Duration::from_secs(1),
            false,
        )?
        .ok_or_else(|| invalid("liveness admission"))?;
    let mut packet = [0; 512];
    assert_eq!(owners[0].poll(Duration::ZERO, 0, &mut packet)?, None);
    let mut accepted = false;
    let mut confirmed = false;
    let mut envelope = [0; 2048];
    for tick in 0..500 {
        let now = Duration::from_millis(tick);
        for side in 0..2 {
            let sender = if side == 0 {
                mg::Role::Client
            } else {
                mg::Role::Server
            };
            for _ in 0..2 {
                let Some(emission) = owners[side].poll(now, usize::MAX, &mut packet)? else {
                    break;
                };
                let verified = mg::Ingress::AuthenticatedManagement {
                    session: binding(sender).session,
                    lane: binding(sender).lane,
                    sender,
                };
                owners[1 - side].receive(verified, &packet[..emission.bytes], now)?;
            }
        }
        if !accepted && let Some(incoming) = owners[1].next(now, &mut envelope)? {
            let decoded =
                sc::Envelope::decode(&envelope[..incoming.bytes], envelope_limits(2048)?)?;
            assert!(matches!(decoded.body, sc::Body::Ping { nonce: 0x9876 }));
            assert_eq!(decoded.binding.scope, scope(3, 0x31));
            owners[1].accepted(incoming, now)?;
            accepted = true;
        }
        if owners[0].confirmed(token, now)? {
            owners[0].retire(token, now)?;
            confirmed = true;
            break;
        }
    }
    assert!(accepted && confirmed);
    assert_eq!(owners[0].arq_storage_usage(), before);
    Ok(())
}
