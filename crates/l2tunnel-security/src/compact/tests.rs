use super::*;
use crate::{ConfigDigest, Epoch, Role, SessionBinding, SessionId};

pub(super) fn root(role: Role) -> Result<SessionRoot, Error> {
    SessionRoot::from_split_keys(
        Zeroizing::new([1; 32]),
        Zeroizing::new([2; 32]),
        SessionBinding {
            session: SessionId([7; 16]),
            transcript: [8; 32],
        },
        role,
    )
}
pub(super) fn limits() -> Limits {
    Limits {
        max_body_bytes: 1500,
        packets_per_key: 8192,
        max_body_bytes_per_key: 1 << 30,
    }
}
pub(super) fn selection() -> Selection {
    Selection {
        max_forward_packets: 8192,
        max_failed_checks: 64,
    }
}
pub(super) fn metadata() -> Metadata<'static> {
    Metadata {
        epoch: Epoch(42),
        configuration: ConfigDigest([9; 32]),
        extra: &[0x31],
    }
}
fn suites() -> [Protection; 3] {
    [
        Protection::Aes128Ccm4,
        Protection::ChaCha20Crc32c,
        Protection::ChaCha20Poly1305,
    ]
}

#[test]
fn selected_suites_bind_exact_context_and_reject_mutation_without_replay_commit()
-> Result<(), Error> {
    for suite in suites() {
        let mut sending = root(Role::Initiator)?;
        let mut receiving = root(Role::Responder)?;
        let mut sender =
            sending.compact_sender(Purpose::Data, LaneId(3), limits(), suite, selection())?;
        let mut receiver =
            receiving.compact_receiver(Purpose::Data, LaneId(3), limits(), suite, selection())?;
        let body: Vec<_> = (0..900).map(|index| (index * 37) as u8).collect();
        let mut packet = vec![0; 1600];
        let sealed = sender.seal(metadata(), &body, &mut packet)?;
        packet.truncate(sealed.bytes);
        assert_eq!(&packet[..4], &[0; 4]);
        assert_eq!(sealed.number, PacketNumber(0));
        assert_eq!(packet.len(), body.len() + suite.overhead_bytes());
        assert_ne!(&packet[4..4 + body.len()], body.as_slice());
        let mut output = [0xAA; 1600];
        for wrong in [
            Metadata {
                epoch: Epoch(43),
                ..metadata()
            },
            Metadata {
                configuration: ConfigDigest([8; 32]),
                ..metadata()
            },
            Metadata {
                extra: &[0x32],
                ..metadata()
            },
        ] {
            assert_eq!(
                receiver.open(wrong, &packet, &mut output),
                Err(Error::Authentication)
            );
            assert_eq!(receiver.highest_number(), None);
            assert_eq!(receiver.generation(), KeyGeneration(0));
            assert!(
                output[..body.len() + suite.tag_bytes()]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
        for index in [4, packet.len() - 1] {
            packet[index] ^= 1;
            assert_eq!(
                receiver.open(metadata(), &packet, &mut output),
                Err(Error::Authentication)
            );
            assert_eq!(receiver.highest_number(), None);
            packet[index] ^= 1;
        }
        let opened = receiver.open(metadata(), &packet, &mut output)?;
        assert_eq!(&output[..opened.bytes], body.as_slice());
        assert_eq!(receiver.failed_checks(), 5);
        assert_eq!(
            receiver.open(metadata(), &packet, &mut output),
            Err(Error::Replay)
        );
        assert_eq!(receiver.failed_checks(), 5);
        let empty = sender.seal(metadata(), &[], &mut packet)?;
        assert_eq!(&packet[..4], &[0, 0, 0, 1]);
        assert_eq!(
            receiver
                .open(metadata(), &packet[..empty.bytes], &mut output)?
                .bytes,
            0
        );
    }
    Ok(())
}

#[test]
fn compact_domains_refuse_weak_control_and_conflicting_legacy_owners_before_reservation()
-> Result<(), Error> {
    for suite in [Protection::Aes128Ccm4, Protection::ChaCha20Crc32c] {
        for purpose in [Purpose::Management, Purpose::Recovery, Purpose::Joining] {
            let mut sending = root(Role::Initiator)?;
            assert_eq!(
                sending
                    .compact_sender(purpose, LaneId(1), limits(), suite, selection())
                    .err(),
                Some(Error::ContextMismatch)
            );
            let mut sender = sending.compact_sender(
                purpose,
                LaneId(1),
                limits(),
                Protection::ChaCha20Poly1305,
                selection(),
            )?;
            let mut receiving = root(Role::Responder)?;
            let mut receiver = receiving.compact_receiver(
                purpose,
                LaneId(1),
                limits(),
                Protection::ChaCha20Poly1305,
                selection(),
            )?;
            let mut packet = [0; 64];
            let sealed = sender.seal(metadata(), b"retiring ACK", &mut packet)?;
            assert_eq!(sealed.bytes, 12 + 4 + 16);
            let mut output = [0; 64];
            assert_eq!(
                receiver
                    .open(metadata(), &packet[..sealed.bytes], &mut output)?
                    .bytes,
                12
            );
        }
        let mut sending = root(Role::Initiator)?;
        let invalid = Selection {
            max_forward_packets: 0,
            ..selection()
        };
        assert_eq!(
            sending
                .compact_sender(Purpose::Data, LaneId(0), limits(), suite, invalid)
                .err(),
            Some(Error::InvalidLimits)
        );
        let _owner =
            sending.compact_sender(Purpose::Data, LaneId(0), limits(), suite, selection())?;
        assert_eq!(
            sending
                .sender(
                    Purpose::Data,
                    LaneId(0),
                    limits(),
                    crate::Protection::ChaCha20Poly1305
                )
                .err(),
            Some(Error::DomainInUse)
        );
        assert_eq!(
            sending
                .compact_sender(Purpose::Data, LaneId(0), limits(), suite, selection())
                .err(),
            Some(Error::DomainInUse)
        );
        let mut wrong_root = root(Role::Initiator)?;
        let _legacy = wrong_root.sender(
            Purpose::Data,
            LaneId(0),
            limits(),
            crate::Protection::ChaCha20Poly1305,
        )?;
        assert_eq!(
            wrong_root
                .compact_sender(Purpose::Data, LaneId(0), limits(), suite, selection())
                .err(),
            Some(Error::DomainInUse)
        );
    }
    Ok(())
}

#[test]
fn original_failure_gap_byte_and_nonce_caps_refuse_without_silent_reset() -> Result<(), Error> {
    for suite in suites() {
        let mut sending = root(Role::Initiator)?;
        let mut receiving = root(Role::Responder)?;
        let selected = Selection {
            max_forward_packets: 1,
            max_failed_checks: 2,
        };
        let mut sender =
            sending.compact_sender(Purpose::Data, LaneId(0), limits(), suite, selected)?;
        let mut receiver =
            receiving.compact_receiver(Purpose::Data, LaneId(0), limits(), suite, selected)?;
        let mut packets = Vec::new();
        let mut bytes = [0xAA; 128];
        assert_eq!(
            sender.seal(metadata(), &[1], &mut bytes[..1]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(sender.next_number(), PacketNumber(0));
        assert_eq!(bytes, [0xAA; 128]);
        for _ in 0..4 {
            let sealed = sender.seal(metadata(), b"actual body", &mut bytes)?;
            packets.push(bytes[..sealed.bytes].to_vec());
        }
        let mut output = [0xAA; 128];
        assert_eq!(
            receiver.open(metadata(), &packets[3], &mut output),
            Err(Error::Generation)
        );
        assert_eq!(receiver.failed_checks(), 0);
        assert_eq!(receiver.highest_number(), None);
        for index in [0usize, 1] {
            let end = packets[index].len() - 1;
            packets[index][end] ^= 1;
            assert_eq!(
                receiver.open(metadata(), &packets[index], &mut output),
                Err(Error::Authentication)
            );
            packets[index][end] ^= 1;
            if index == 0 {
                assert_eq!(
                    receiver.open(metadata(), &packets[0], &mut output)?.number,
                    PacketNumber(0)
                );
                assert_eq!(receiver.failed_checks(), 1);
            }
        }
        assert_eq!(receiver.failed_checks(), 2);
        assert_eq!(
            receiver.open(metadata(), &packets[1], &mut output),
            Err(Error::KeyUsageExhausted)
        );
        assert_eq!(receiver.highest_number(), Some(PacketNumber(0)));
        let mut sending = root(Role::Initiator)?;
        let capped = Limits {
            max_body_bytes: 32,
            packets_per_key: 4,
            max_body_bytes_per_key: 32,
        };
        let mut sender =
            sending.compact_sender(Purpose::Data, LaneId(0), capped, suite, selection())?;
        sender.seal(metadata(), &[1; 32], &mut bytes)?;
        bytes.fill(0xAA);
        assert_eq!(
            sender.seal(metadata(), &[1], &mut bytes),
            Err(Error::KeyUsageExhausted)
        );
        assert_eq!(sender.next_number(), PacketNumber(1));
        assert_eq!(bytes, [0xAA; 128]);
        sender.next = u64::MAX;
        assert_eq!(
            sender.seal(metadata(), &[1], &mut bytes),
            Err(Error::CounterExhausted)
        );
        assert_eq!(bytes, [0xAA; 128]);
    }
    Ok(())
}

#[test]
fn actual_key_rollover_preserves_reordered_previous_packets_and_separates_suites()
-> Result<(), Error> {
    let mut first_wires = Vec::new();
    for suite in suites() {
        let configured = Limits {
            packets_per_key: 2,
            ..limits()
        };
        let mut sending = root(Role::Initiator)?;
        let mut receiving = root(Role::Responder)?;
        let mut sender =
            sending.compact_sender(Purpose::Data, LaneId(0), configured, suite, selection())?;
        let mut receiver =
            receiving.compact_receiver(Purpose::Data, LaneId(0), configured, suite, selection())?;
        let mut packets = Vec::new();
        for _ in 0..4 {
            let mut bytes = [0; 64];
            let sealed = sender.seal(metadata(), b"same body", &mut bytes)?;
            packets.push(bytes[..sealed.bytes].to_vec());
        }
        first_wires.push(packets[0].clone());
        let mut output = [0; 64];
        for index in [0, 2, 1, 3] {
            let opened = receiver.open(metadata(), &packets[index], &mut output)?;
            assert_eq!(opened.number, PacketNumber(index as u64));
            assert_eq!(&output[..opened.bytes], b"same body");
        }
        assert_eq!(sender.generation(), KeyGeneration(1));
        assert_eq!(receiver.generation(), KeyGeneration(1));
        assert_eq!(receiver.previous_generation(), Some(KeyGeneration(0)));
    }
    assert_ne!(first_wires[0], first_wires[1]);
    assert_ne!(first_wires[0], first_wires[2]);
    Ok(())
}
