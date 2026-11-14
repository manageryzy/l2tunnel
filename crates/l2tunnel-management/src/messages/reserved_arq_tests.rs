use super::*;
use crate::{LaneId, SessionId};
use l2tunnel_recovery::{
    EndpointRole, PacketView, RecoveryContext, inspect_packet,
    storage::{Limits, Plan},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn settings() -> Settings {
    Settings {
        delivery: delivery::Settings {
            recovery: l2tunnel_recovery::ArqConfig {
                max_source_bytes: 128,
                send_bytes: 384,
                receive_bytes: 384,
                send_records: 3,
                receive_records: 3,
                initial_rto: Duration::from_millis(10),
                maximum_rto: Duration::from_millis(40),
                ack_delay: Duration::ZERO,
                max_retries: 32,
            },
            interval: Duration::from_millis(5),
            packets_per_interval: 4,
            bytes_per_interval: 1024,
            wire_overhead: 64,
        },
        path_mtu: 512,
        max_message_bytes: 1024,
        max_outbound_messages: 3,
        max_outbound_bytes: 4096,
        max_fragments: 16,
        max_reassembly_bytes: 2048,
        max_incomplete_messages: 1,
        message_lifetime: Duration::from_secs(1),
        work_per_call: 4,
    }
}
fn binding(role: Role) -> delivery::Binding {
    delivery::Binding {
        session: SessionId([0x81; 16]),
        lane: LaneId(2),
        local_role: role,
        control_epoch: 7,
    }
}
fn verified(sender: Role) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: binding(sender).session,
        lane: LaneId(2),
        sender,
    }
}

#[test]
fn pure_message_validation_preserves_nested_errors_before_storage_limit() -> Result {
    let mut settings = settings();
    settings.delivery.recovery.initial_rto = Duration::ZERO;
    let expected = Error::Delivery(delivery::Error::Recovery(RecoveryError::InvalidConfig));
    assert_eq!(
        settings.validate(
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(2)
        ),
        Err(expected)
    );
    assert!(
        matches!(Owner::new_reserved_arq(settings, binding(Role::Client), Duration::ZERO,
        Duration::from_secs(2), Limits { capacity_bytes: 0 }),
        Err(ReservedArqError::Message(error)) if error == expected)
    );
    settings.max_message_bytes = 0;
    assert_eq!(
        settings.validate(
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(2)
        ),
        Err(Error::Settings)
    );
    Ok(())
}

#[test]
fn actual_fragment_source_copies_and_45_byte_receipt_produce_real_confirmation_after_loss() -> Result
{
    let settings = settings();
    let heap = Plan::for_arq(settings.delivery.recovery)?.capacity_bytes();
    let make = |role| {
        Owner::new_reserved_arq(
            settings,
            binding(role),
            Duration::ZERO,
            Duration::from_secs(2),
            Limits {
                capacity_bytes: heap,
            },
        )
    };
    let mut peers = [make(Role::Client)?, make(Role::Server)?];
    let usage = peers[0].arq_storage_usage();
    let original: Vec<u8> = (0..700).map(|n| (n % 251) as u8).collect();
    let deadline = Duration::from_millis(900);
    let ticket = peers[0].submit(SubmissionId(1), &original, Duration::ZERO, deadline)?;
    let mut dropped_source = false;
    let mut dropped_acceptance = false;
    let mut accepted = false;
    let mut confirmed_at = None;
    let mut packet = [0; 256];
    for tick in 0..800 {
        let now = Duration::from_millis(tick);
        for side in 0..2 {
            let sender = if side == 0 {
                Role::Client
            } else {
                Role::Server
            };
            for _ in 0..4 {
                let Some(emission) = peers[side].poll(now, usize::MAX, &mut packet)? else {
                    break;
                };
                let context = RecoveryContext {
                    session: u128::from_be_bytes(binding(sender).session.0),
                    epoch: 7,
                    role: if side == 0 {
                        EndpointRole::Responder
                    } else {
                        EndpointRole::Initiator
                    },
                };
                if let PacketView::Data { payload, .. } =
                    inspect_packet(&packet[..emission.bytes], context, 128)?
                {
                    if side == 0 && !dropped_source {
                        dropped_source = true;
                        continue;
                    }
                    if side == 1
                        && !dropped_acceptance
                        && payload.len() == ACCEPTED_BYTES
                        && payload.first() == Some(&ACCEPTED_KIND)
                    {
                        dropped_acceptance = true;
                        continue;
                    }
                }
                peers[1 - side].receive(verified(sender), &packet[..emission.bytes], now)?;
            }
        }
        if !accepted && let Some(held) = peers[1].pending() {
            assert_eq!(held.bytes(), original);
            let incoming = held.ticket();
            let proof = peers[1].accept_with_receipt(incoming, now)?;
            assert_eq!(proof.ticket(), incoming);
            accepted = true;
        }
        if let Some(proof) = peers[0].confirmation(ticket, now)? {
            assert_eq!(proof.ticket(), ticket);
            confirmed_at = Some(now);
            break;
        }
    }
    assert!(accepted && dropped_source && dropped_acceptance);
    let now = confirmed_at.ok_or(Error::Expired)?;
    assert_eq!(peers[0].arq_storage_usage(), usage);
    assert_eq!(
        peers[0].submit(SubmissionId(1), &original, now, deadline)?,
        ticket
    );
    peers[0].retire(ticket, now)?;
    assert_eq!(
        peers[0].submit(SubmissionId(1), &original, now, deadline),
        Err(Error::SubmissionOrder)
    );
    assert_eq!(
        Owner::new(
            settings,
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(2)
        )?
        .arq_storage_usage(),
        None
    );
    Ok(())
}

#[test]
fn reserved_message_rejection_does_not_change_original_deadline() -> Result {
    let settings = settings();
    let heap = Plan::for_arq(settings.delivery.recovery)?.capacity_bytes();
    let mut owner = Owner::new_reserved_arq(
        settings,
        binding(Role::Client),
        Duration::ZERO,
        Duration::from_secs(2),
        Limits {
            capacity_bytes: heap,
        },
    )?;
    let deadline = Duration::from_millis(50);
    owner.submit(SubmissionId(1), b"original", Duration::ZERO, deadline)?;
    assert_eq!(
        owner.submit(
            SubmissionId(1),
            b"original",
            Duration::from_millis(1),
            Duration::from_millis(51)
        ),
        Err(Error::ChangedSubmission)
    );
    assert_eq!(owner.tick(deadline), Err(Error::Expired));
    Ok(())
}
