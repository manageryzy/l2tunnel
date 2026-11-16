//! Actual final Records + selected Reliable composition; fixture roots are not
//! Noise/member admission or installation in the Aligned/Common runtime loop.
use super::*;
use l2tunnel::secure_record::compact::{AUTHENTICATED_OVERHEAD, DATA_OVERHEAD, Kind, Selection};
use l2tunnel_recovery::{
    CompactArqConfig, CompactBounds, CompactPacketKind, CompactPacketView, CompactRecovery,
    CompactTiming, EndpointRole, RecoveryContext, SourceId, inspect_compact_body,
};
use l2tunnel_reliable::{CompactOverheads, CompactReliableConfig, OutboundBudget, Reliable};

fn policy(size: usize, mode: CompactRecovery) -> Result<CompactArqConfig> {
    Ok(CompactArqConfig::new(
        CompactBounds {
            max_source_bytes: size,
            send_bytes: size * 8,
            receive_bytes: size * 8,
            send_records: 8,
            receive_records: 8,
        },
        CompactTiming {
            nominal_rtt: Duration::from_millis(70),
            feedback_interval: Duration::from_millis(5),
            feedback_packets: 64,
        },
        77,
        32,
        8,
        mode,
    )?)
}

#[test]
fn compact_arq_direct_final_records_preserve_duplex_loss_retry_feedback_and_physical_charge()
-> Result<()> {
    let (a_cover, b_cover) = covers(cover::Appearance::QuicLike)?;
    let selection = Selection {
        protection: security::compact::Protection::Aes128Ccm4,
        limits: security::compact::Selection {
            max_forward_packets: 4096,
            max_failed_checks: 128,
        },
    };
    let mut records = [
        Records::new_compact(
            root(security::Role::Initiator)?,
            security::LaneId(7),
            limits(),
            a_cover,
            control(),
            data(),
            selection,
        )?,
        Records::new_compact(
            root(security::Role::Responder)?,
            security::LaneId(7),
            limits(),
            b_cover,
            control(),
            data(),
            selection,
        )?,
    ];
    let policies = [
        policy(64, CompactRecovery::Guarded)?,
        policy(96, CompactRecovery::FirstFlight)?,
    ];
    let context = |role| RecoveryContext {
        session: u128::from_be_bytes([3; 16]),
        epoch: data().epoch.0,
        role,
    };
    let mut owners = [
        Reliable::new_compact_duplex(
            CompactReliableConfig::new(policies[0], 9)?,
            CompactReliableConfig::new(policies[1], 9)?,
            context(EndpointRole::Initiator),
        )?,
        Reliable::new_compact_duplex(
            CompactReliableConfig::new(policies[1], 9)?,
            CompactReliableConfig::new(policies[0], 9)?,
            context(EndpointRole::Responder),
        )?,
    ];
    let native: [&[u8]; 2] = [b"forward\0native\xff", b"reverse\xffnative\0"];
    owners[0].submit(native[0], Duration::ZERO)?;
    owners[1].submit(native[1], Duration::ZERO)?;
    let sockets = [
        UdpSocket::bind("127.0.0.1:0")?,
        UdpSocket::bind("127.0.0.1:0")?,
    ];
    sockets[0].connect(sockets[1].local_addr()?)?;
    sockets[1].connect(sockets[0].local_addr()?)?;
    for socket in &sockets {
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    }
    let overheads = CompactOverheads {
        data: DATA_OVERHEAD,
        feedback: AUTHENTICATED_OVERHEAD,
    };
    let mut dropped_data = [false; 2];
    let mut first_packet = [None::<Vec<u8>>, None];
    let mut dropped_feedback = false;
    let mut tampered_feedback = false;
    let mut retried = [false; 2];
    let mut delivered = [0; 2];
    let mut wire_totals = [0usize; 2];
    let mut workspace = [0; 1024];
    let mut packet = [0; 1024];
    let mut received = [0; 1024];
    let mut clear = [0; 1024];
    for tick in 0..1000 {
        let now = Duration::from_millis(tick);
        for sender in 0..2 {
            let peer = 1 - sender;
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: 1024,
            };
            let mut source = None;
            let mut branch = CompactPacketKind::Feedback;
            let emission = owners[sender].poll_compact_with(
                now,
                &mut budget,
                overheads,
                |view: CompactPacketView<'_>| {
                    branch = view.kind();
                    if let CompactPacketView::Data {
                        source: identity,
                        serial,
                        payload,
                    } = view
                    {
                        assert_eq!(identity, SourceId(0));
                        assert_eq!(payload, native[sender]);
                        source = Some(serial);
                    }
                    records[sender]
                        .seal_compact_arq_in(
                            data(),
                            outer(tick as u32),
                            view,
                            &mut workspace,
                            &mut packet,
                        )
                        .map(Some)
                },
            )?;
            let Some(emission) = emission else { continue };
            let sealed = emission.value;
            let feedback = branch == CompactPacketKind::Feedback;
            assert_eq!(sealed.bytes, emission.prepared.wire_bytes);
            assert_eq!(
                sealed.bytes,
                emission.prepared.bytes
                    + if feedback {
                        AUTHENTICATED_OVERHEAD
                    } else {
                        DATA_OVERHEAD
                    }
            );
            assert_eq!(budget.packets, 0);
            assert_eq!(budget.wire_bytes, 1024 - sealed.bytes);
            wire_totals[sender] += sealed.bytes;
            if let Some(serial) = source {
                assert_eq!(emission.prepared.bytes, native[sender].len() + 2);
                if serial == 1 {
                    assert_eq!(sealed.number.0, 0);
                    first_packet[sender] = Some(packet[..sealed.bytes].to_vec());
                } else {
                    assert_eq!(serial, 2);
                    assert_eq!(sealed.number.0, 1);
                    assert_ne!(
                        first_packet[sender].as_deref(),
                        Some(&packet[..sealed.bytes])
                    );
                    retried[sender] = true;
                }
            }
            // The same returned witness is retained through whole UDP acceptance;
            // intentional loss below is after actual physical handoff, not WB.
            assert_eq!(sockets[sender].send(&packet[..sealed.bytes])?, sealed.bytes);
            owners[sender].confirm_output(now, emission.prepared)?;
            let size = sockets[peer].recv(&mut received)?;
            assert_eq!(&received[..size], &packet[..sealed.bytes]);
            if !feedback && !dropped_data[sender] {
                dropped_data[sender] = true;
                continue;
            }
            if feedback && sender == 1 && !dropped_feedback {
                dropped_feedback = true;
                continue;
            }
            if feedback && !tampered_feedback {
                let mut forged = received;
                forged[size - 1] ^= 1;
                assert!(
                    records[peer]
                        .open(&forged[..size], &mut workspace, &mut clear)
                        .is_err()
                );
                tampered_feedback = true;
            }
            let opened = records[peer].open(&received[..size], &mut workspace, &mut clear)?;
            assert_eq!(opened.class, Class::User);
            assert_eq!(opened.scope, data());
            assert_eq!(opened.feedback, feedback);
            assert!(opened.authenticated);
            let kind = if opened.feedback {
                CompactPacketKind::Feedback
            } else {
                CompactPacketKind::Data
            };
            let policy = if opened.feedback {
                policies[peer]
            } else {
                policies[sender]
            };
            let view = inspect_compact_body(kind, &clear[..opened.bytes], policy)?;
            owners[peer].receive_compact_view_at(view, now, now)?;
            assert_eq!(
                records[peer].open(&received[..size], &mut workspace, &mut clear),
                Err(Error::Security(security::Error::Replay))
            );
        }
        for receiver in 0..2 {
            if let Some((source, size)) = owners[receiver].poll_delivered(&mut clear)? {
                assert_eq!(source, 0);
                assert_eq!(&clear[..size], native[1 - receiver]);
                delivered[receiver] += 1;
            }
        }
        if delivered == [1, 1] && owners.iter().all(Reliable::drained) {
            break;
        }
    }
    assert_eq!(delivered, [1, 1]);
    assert_eq!(dropped_data, [true, true]);
    assert_eq!(retried, [true, true]);
    assert!(dropped_feedback && tampered_feedback);
    for (index, owner) in owners.iter_mut().enumerate() {
        assert!(owner.drained());
        assert_eq!(owner.arq_statistics().retransmissions, 1);
        assert_eq!(
            owner.statistics().emitted_wire_bytes,
            wire_totals[index] as u64
        );
        assert_eq!(owner.poll_delivered(&mut clear)?, None);
    }
    let body = b"independent fixed management";
    let cap = records[0].capacity_for(Kind::Control, body.len())?;
    let control = records[0].seal(
        Class::Control,
        outer(999),
        body,
        &mut workspace,
        &mut packet,
    )?;
    assert_eq!(control.bytes, cap.packet_bytes);
    assert_eq!(control.bytes, body.len() + AUTHENTICATED_OVERHEAD);
    let opened = records[1].open(&packet[..control.bytes], &mut workspace, &mut clear)?;
    assert_eq!(opened.class, Class::Control);
    assert!(opened.authenticated && !opened.feedback);
    assert_eq!(&clear[..opened.bytes], body);
    Ok(())
}
