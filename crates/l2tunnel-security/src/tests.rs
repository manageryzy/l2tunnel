use super::*;
use zeroize::Zeroizing;

fn binding() -> SessionBinding {
    SessionBinding {
        session: SessionId([7; 16]),
        transcript: [8; 32],
    }
}
fn root(role: Role, binding: SessionBinding) -> Result<SessionRoot, Error> {
    SessionRoot::from_split_keys(
        Zeroizing::new([1; 32]),
        Zeroizing::new([2; 32]),
        binding,
        role,
    )
}
fn limits() -> Limits {
    Limits {
        max_body_bytes: 1500,
        packets_per_key: 8192,
        max_body_bytes_per_key: 1 << 30,
    }
}
fn metadata() -> Metadata<'static> {
    Metadata {
        epoch: Epoch(42),
        configuration: ConfigDigest([9; 32]),
        extra: b"carrier header",
    }
}

#[test]
fn common_suites_authenticate_arbitrary_bodies_metadata_and_all_domains() -> Result<(), Error> {
    for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
        let mut sending = root(Role::Initiator, binding())?;
        let mut receiving = root(Role::Responder, binding())?;
        let mut sender = sending.sender(Purpose::Data, LaneId(3), limits(), protection)?;
        let mut receiver = receiving.receiver(Purpose::Data, LaneId(3), limits(), protection)?;
        let body: Vec<_> = (0..900).map(|index| (index * 37) as u8).collect();
        let mut packet = vec![0; body.len() + sender.overhead()];
        let sealed = sender.seal(metadata(), &body, &mut packet)?;
        assert_eq!(sealed.number, PacketNumber(0));
        assert_eq!(sealed.bytes, packet.len());
        assert_eq!(&packet[..2], &[VERSION, protection as u8]);
        if protection == Protection::HmacSha256 {
            assert_eq!(&packet[10..10 + body.len()], &body);
        } else {
            assert_ne!(&packet[10..10 + body.len()], &body);
        }
        let mut output = vec![0xAA; body.len() + 32];
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
                extra: b"different carrier",
                ..metadata()
            },
        ] {
            assert_eq!(
                receiver.open(wrong, &packet, &mut output),
                Err(Error::Authentication)
            );
            assert_eq!(receiver.highest_number(), None);
            assert_eq!(receiver.generation(), KeyGeneration(0));
            if protection == Protection::ChaCha20Poly1305 {
                assert!(output[..body.len() + 16].iter().all(|byte| *byte == 0));
            }
        }
        for (role, scope, lane, context) in [
            (Role::Responder, Purpose::Management, LaneId(3), binding()),
            (Role::Responder, Purpose::Data, LaneId(4), binding()),
            (Role::Initiator, Purpose::Data, LaneId(3), binding()),
            (
                Role::Responder,
                Purpose::Data,
                LaneId(3),
                SessionBinding {
                    session: SessionId([6; 16]),
                    ..binding()
                },
            ),
            (
                Role::Responder,
                Purpose::Data,
                LaneId(3),
                SessionBinding {
                    transcript: [6; 32],
                    ..binding()
                },
            ),
        ] {
            let mut wrong_root = root(role, context)?;
            let mut wrong = wrong_root.receiver(scope, lane, limits(), protection)?;
            assert_eq!(
                wrong.open(metadata(), &packet, &mut output),
                Err(Error::Authentication)
            );
            assert_eq!(wrong.highest_number(), None);
        }
        let opened = receiver.open(metadata(), &packet, &mut output)?;
        assert_eq!(opened.bytes, body.len());
        assert_eq!(&output[..opened.bytes], &body);
        assert_eq!(
            receiver.open(metadata(), &packet, &mut output),
            Err(Error::Replay)
        );
        // Empty generic records are authenticated, not unauthenticated keepalives.
        let empty = sender.seal(metadata(), &[], &mut packet)?;
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
fn duplicate_domain_ownership_and_domain_capacity_are_bounded() -> Result<(), Error> {
    let mut root = root(Role::Initiator, binding())?;
    let protection = Protection::ChaCha20Poly1305;
    let _sender = root.sender(Purpose::Data, LaneId(0), limits(), protection)?;
    assert_eq!(
        root.sender(Purpose::Data, LaneId(0), limits(), protection)
            .err(),
        Some(Error::DomainInUse)
    );
    assert_eq!(
        root.sender(Purpose::Data, LaneId(0), limits(), Protection::HmacSha256)
            .err(),
        Some(Error::DomainInUse)
    );
    // The opposite direction owns a different replay/counter domain.
    let _receiver = root.receiver(Purpose::Data, LaneId(0), limits(), protection)?;
    assert_eq!(
        root.receiver(Purpose::Data, LaneId(0), limits(), protection)
            .err(),
        Some(Error::DomainInUse)
    );
    for lane in 1..(MAX_DOMAINS - 1) as u32 {
        let _owner = root.sender(Purpose::Data, LaneId(lane), limits(), protection)?;
    }
    assert_eq!(
        root.sender(Purpose::Joining, LaneId(99), limits(), protection)
            .err(),
        Some(Error::DomainCapacity)
    );
    Ok(())
}

#[test]
fn malformed_lengths_metadata_buffers_and_suite_bits_do_not_commit_state() -> Result<(), Error> {
    for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
        let mut sending = root(Role::Initiator, binding())?;
        let mut receiving = root(Role::Responder, binding())?;
        let mut sender = sending.sender(Purpose::Data, LaneId(0), limits(), protection)?;
        let mut receiver = receiving.receiver(Purpose::Data, LaneId(0), limits(), protection)?;
        let mut packet = vec![0; 1600];
        assert_eq!(
            sender.seal(metadata(), &[1; 1501], &mut packet),
            Err(Error::TooLarge)
        );
        assert_eq!(
            sender.seal(metadata(), &[1; 100], &mut packet[..1]),
            Err(Error::OutputTooSmall)
        );
        let extra = [0; MAX_METADATA_BYTES + 1];
        assert_eq!(
            sender.seal(
                Metadata {
                    extra: &extra,
                    ..metadata()
                },
                &[1],
                &mut packet
            ),
            Err(Error::TooLarge)
        );
        assert_eq!(sender.next_number(), PacketNumber(0));
        let sealed = sender.seal(metadata(), &[1; 100], &mut packet)?;
        packet.truncate(sealed.bytes);
        let mut output = [0; 200];
        for length in 0..sender.overhead() {
            assert_eq!(
                receiver.open(metadata(), &packet[..length], &mut output),
                Err(Error::Malformed)
            );
        }
        for index in [0, 1] {
            packet[index] ^= 3;
            assert_eq!(
                receiver.open(metadata(), &packet, &mut output),
                Err(Error::ContextMismatch)
            );
            packet[index] ^= 3;
        }
        assert_eq!(
            receiver.open(metadata(), &packet, &mut output[..1]),
            Err(Error::OutputTooSmall)
        );
        packet[12] ^= 1;
        assert_eq!(
            receiver.open(metadata(), &packet, &mut output),
            Err(Error::Authentication)
        );
        assert_eq!(receiver.highest_number(), None);
        packet[12] ^= 1;
        assert_eq!(receiver.open(metadata(), &packet, &mut output)?.bytes, 100);
    }
    Ok(())
}

#[test]
fn common_body_byte_limits_are_independent_of_packet_intervals() -> Result<(), Error> {
    for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
        let small = Limits {
            max_body_bytes: 32,
            packets_per_key: 10,
            max_body_bytes_per_key: 64,
        };
        let mut sending = root(Role::Initiator, binding())?;
        let mut receiving = root(Role::Responder, binding())?;
        let mut sender = sending.sender(Purpose::Data, LaneId(0), small, protection)?;
        let mut receiver = receiving.receiver(Purpose::Data, LaneId(0), small, protection)?;
        let mut packet = [0; 100];
        let mut output = [0; 100];
        for _ in 0..2 {
            let sealed = sender.seal(metadata(), &[7; 32], &mut packet)?;
            receiver.open(metadata(), &packet[..sealed.bytes], &mut output)?;
        }
        assert_eq!(
            sender.seal(metadata(), &[7], &mut packet),
            Err(Error::KeyUsageExhausted)
        );
        assert_eq!(sender.next_number(), PacketNumber(2));
        // An authenticated peer with a larger local budget cannot increase ours.
        let mut peer = root(Role::Initiator, binding())?;
        let mut peer = peer.sender(Purpose::Data, LaneId(0), limits(), protection)?;
        for _ in 0..3 {
            let sealed = peer.seal(metadata(), &[7; 32], &mut packet)?;
            if sealed.number == PacketNumber(2) {
                assert_eq!(
                    receiver.open(metadata(), &packet[..sealed.bytes], &mut output),
                    Err(Error::KeyUsageExhausted)
                );
            }
        }
        assert_eq!(receiver.highest_number(), Some(PacketNumber(1)));
    }
    Ok(())
}

#[test]
fn swift_compatibility_ratchets_with_reordering_and_rejects_forged_skips() -> Result<(), Error> {
    let mut sender = swift_v2::Sender::new(&[9; 32], 100, 8)?;
    let mut receiver = swift_v2::Receiver::new(&[9; 32], 100, 8)?;
    let mut packet = [0; 124];
    let mut output = [0; 116];
    let mut held = Vec::new();
    for number in 0..400u64 {
        let sealed = sender.seal(&number.to_be_bytes(), &mut packet)?;
        assert_eq!(sealed.bytes, 8 + swift_v2::OVERHEAD_BYTES);
        if number == 23 {
            held.extend_from_slice(&packet[..sealed.bytes]);
            continue;
        }
        let opened = receiver.open(&packet[..sealed.bytes], &mut output)?;
        assert_eq!(opened.number, PacketNumber(number));
        assert_eq!(&output[..opened.bytes], &number.to_be_bytes());
        if number == 26 {
            assert_eq!(receiver.open(&held, &mut output)?.number, PacketNumber(23));
        }
    }
    let current = receiver.generation();
    for jump in [1, 2, 9] {
        let mut forged = [0; 40];
        forged[..8].copy_from_slice(&((current.0 + jump) * 8).to_be_bytes());
        let error = receiver.open(&forged, &mut output).err();
        assert_eq!(
            error,
            Some(if jump == 1 {
                Error::Authentication
            } else {
                Error::Generation
            })
        );
        assert_eq!(receiver.generation(), current);
    }
    assert_eq!(receiver.highest_number(), Some(PacketNumber(399)));
    Ok(())
}

#[test]
fn previous_keys_retire_at_the_replay_boundary_and_old_packets_stay_rejected() -> Result<(), Error>
{
    let mut sender = swift_v2::Sender::new(&[9; 32], 1, 8192)?;
    let mut receiver = swift_v2::Receiver::new(&[9; 32], 1, 8192)?;
    let mut packet = [0; 25];
    let mut output = [0; 17];
    let mut held = [0; 25];
    for number in 0..=8192 + REPLAY_PACKETS {
        let sealed = sender.seal(&[7], &mut packet)?;
        if number == 8191 {
            held.copy_from_slice(&packet);
            continue;
        }
        receiver.open(&packet[..sealed.bytes], &mut output)?;
        if number == 8192 + REPLAY_PACKETS - 1 {
            assert_eq!(receiver.previous_generation(), Some(KeyGeneration(0)));
        }
    }
    assert_eq!(receiver.previous_generation(), None);
    assert_eq!(receiver.open(&held, &mut output), Err(Error::Replay));
    Ok(())
}

#[test]
fn invalid_limits_and_maximum_body_are_checked_before_packet_work() -> Result<(), Error> {
    for invalid in [
        Limits {
            max_body_bytes: 0,
            ..limits()
        },
        Limits {
            max_body_bytes: MAX_BODY_BYTES + 1,
            ..limits()
        },
        Limits {
            packets_per_key: 0,
            ..limits()
        },
        Limits {
            packets_per_key: MAX_PACKETS_PER_KEY + 1,
            ..limits()
        },
        Limits {
            max_body_bytes_per_key: MAX_BODY_BYTES_PER_KEY + 1,
            ..limits()
        },
    ] {
        let mut root = root(Role::Initiator, binding())?;
        assert_eq!(
            root.sender(
                Purpose::Data,
                LaneId(0),
                invalid,
                Protection::ChaCha20Poly1305
            )
            .err(),
            Some(Error::InvalidLimits)
        );
        assert!(
            root.sender(
                Purpose::Data,
                LaneId(0),
                limits(),
                Protection::ChaCha20Poly1305
            )
            .is_ok()
        );
    }
    for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
        let large = Limits {
            max_body_bytes: MAX_BODY_BYTES,
            ..limits()
        };
        let mut sending = root(Role::Initiator, binding())?;
        let mut receiving = root(Role::Responder, binding())?;
        let mut sender = sending.sender(Purpose::Data, LaneId(0), large, protection)?;
        let mut receiver = receiving.receiver(Purpose::Data, LaneId(0), large, protection)?;
        let body = vec![0xAD; MAX_BODY_BYTES];
        let mut packet = vec![0; body.len() + sender.overhead()];
        let mut output = vec![0; body.len() + 32];
        let sealed = sender.seal(metadata(), &body, &mut packet)?;
        assert!(sealed.bytes < 65_507);
        let opened = receiver.open(metadata(), &packet, &mut output)?;
        assert_eq!(&output[..opened.bytes], &body);
    }
    Ok(())
}
