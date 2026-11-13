use super::*;
use crate::{EndpointId, Ingress, MessageKind, RequestId};
use l2tunnel_session::Ticket;
type R<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn limits() -> Limits {
    Limits {
        max_frame_bytes: 1024,
        max_management_bytes: 512,
        max_feedback_bytes: 128,
    }
}
fn scope(epoch: u64) -> Scope {
    Scope {
        epoch: Epoch(epoch),
        digest: ConfigDigest([0x22; 32]),
    }
}
fn policy(epoch: u64, recovery: RecoveryTag) -> ScopePolicy {
    ScopePolicy {
        scope: scope(epoch),
        recovery,
        max_feedback_bytes: 16,
        receipts: ReceiptPolicy::Record { channels: 4 },
    }
}
fn binding(packet: u64, epoch: u64) -> Binding {
    Binding {
        session: SessionId([0x11; 16]),
        lane: LaneId(11),
        sender: Role::Client,
        packet: PacketNumber(packet),
        scope: scope(epoch),
    }
}
fn ingress(lane: u32) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: SessionId([0x11; 16]),
        lane: LaneId(lane),
        sender: Role::Client,
    }
}
fn gate() -> R<Gate> {
    Ok(Gate::new(
        PeerBinding {
            session: SessionId([0x11; 16]),
            remote_role: Role::Client,
            control_lane: LaneId(11),
            data_lanes: [Some(LaneId(11)), Some(LaneId(12))],
        },
        limits(),
        policy(7, RecoveryTag::RollingV1),
    )?)
}
fn encoded(envelope: Envelope<'_>) -> R<Vec<u8>> {
    let mut bytes = vec![0; envelope.encoded_len(limits())?];
    envelope.encode(&mut bytes, limits())?;
    Ok(bytes)
}
fn feedback(packet: u64, epoch: u64, tag: RecoveryTag, lane: u32) -> R<Vec<u8>> {
    encoded(Envelope {
        binding: binding(packet, epoch),
        body: Body::RecoveryFeedback {
            lane: LaneId(lane),
            tag,
            bytes: &[0xaa, 0xbb, 0xcc],
        },
    })
}
fn from_hex(text: &str) -> R<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|at| Ok(u8::from_str_radix(&text[at..at + 2], 16)?))
        .collect()
}

#[test]
fn exact_golden_wire_and_borrowed_roundtrip() -> R {
    for (body, golden) in [
        (
            Body::Ping {
                nonce: 0x0102030405060708,
            },
            PING_HEX,
        ),
        (
            Body::RecoveryFeedback {
                lane: LaneId(12),
                tag: RecoveryTag::RollingV1,
                bytes: &[0xaa, 0xbb, 0xcc],
            },
            FEEDBACK_HEX,
        ),
        (
            Body::NativeReceipt {
                lane: LaneId(12),
                receipt: NativeReceipt::Record {
                    channel: 3,
                    record: 9,
                },
            },
            NATIVE_HEX,
        ),
    ] {
        let envelope = Envelope {
            binding: binding(1, 7),
            body,
        };
        let bytes = encoded(envelope)?;
        assert_eq!(bytes, from_hex(golden)?);
        assert_eq!(Envelope::decode(&bytes, limits())?, envelope);
    }
    Ok(())
}
#[test]
fn exact_limits_unknown_tags_reserved_and_failure_atomic_output() -> R {
    let valid = feedback(1, 7, RecoveryTag::RollingV1, 12)?;
    for end in 0..HEADER_BYTES {
        assert!(Envelope::decode(&valid[..end], limits()).is_err());
    }
    for (at, value) in [(4, 2), (5, 0), (6, 0), (7, 1), (8, 1), (86, 1), (84, 0xff)] {
        let mut bad = valid.clone();
        bad[at] = value;
        assert!(Envelope::decode(&bad, limits()).is_err(), "offset={at}");
    }
    let mut bad = valid.clone();
    bad.push(0);
    assert!(Envelope::decode(&bad, limits()).is_err());
    let limit = Limits {
        max_feedback_bytes: 2,
        ..limits()
    };
    assert!(Envelope::decode(&valid, limit).is_err());
    let envelope = Envelope {
        binding: binding(1, 7),
        body: Body::RecoveryFeedback {
            lane: LaneId(12),
            tag: RecoveryTag::RollingV1,
            bytes: &[7; 129],
        },
    };
    let mut output = [0x55; 1024];
    assert!(envelope.encode(&mut output, limits()).is_err());
    assert_eq!(output, [0x55; 1024]);
    let exact = Envelope {
        binding: binding(1, 7),
        body: Body::RecoveryFeedback {
            lane: LaneId(12),
            tag: RecoveryTag::RollingV1,
            bytes: &[7; 128],
        },
    };
    assert_eq!(encoded(exact)?.len(), HEADER_BYTES + 8 + 128);
    Ok(())
}
#[test]
fn primary_binding_target_lanes_replay_sequence_and_errors_do_not_advance() -> R {
    let mut gate = gate()?;
    let first = feedback(1, 7, RecoveryTag::RollingV1, 12)?;
    for origin in [Ingress::UserTraffic, Ingress::Unauthenticated, ingress(12)] {
        assert!(gate.admit(origin, &first).is_err());
    }
    assert_eq!(gate.highest_packet(), None);
    assert_eq!(gate.admit(ingress(11), &first)?.slot, ScopeSlot::Active);
    for bytes in [
        feedback(2, 8, RecoveryTag::RollingV1, 12)?,
        feedback(2, 7, RecoveryTag::ReliableV1, 12)?,
        feedback(2, 7, RecoveryTag::RollingV1, 13)?,
        feedback(3, 7, RecoveryTag::RollingV1, 12)?,
    ] {
        assert!(gate.admit(ingress(11), &bytes).is_err());
        assert_eq!(gate.highest_packet(), Some(PacketNumber(1)));
    }
    assert!(gate.admit(ingress(11), &first).is_err());
    let second = feedback(2, 7, RecoveryTag::RollingV1, 11)?;
    gate.admit(ingress(11), &second)?;
    assert_eq!(gate.highest_packet(), Some(PacketNumber(2)));
    Ok(())
}
#[test]
fn only_active_plus_one_draining_scope_and_no_counter_reset() -> R {
    let mut gate = gate()?;
    gate.admit(ingress(11), &feedback(1, 7, RecoveryTag::RollingV1, 12)?)?;
    gate.advance_scope(policy(8, RecoveryTag::ReliableV1))?;
    assert!(
        gate.advance_scope(policy(9, RecoveryTag::SelectiveRepeatV1))
            .is_err()
    );
    assert_eq!(
        gate.admit(ingress(11), &feedback(2, 7, RecoveryTag::RollingV1, 12)?)?
            .slot,
        ScopeSlot::Draining
    );
    assert_eq!(
        gate.admit(ingress(11), &feedback(3, 8, RecoveryTag::ReliableV1, 12)?)?
            .slot,
        ScopeSlot::Active
    );
    assert!(gate.retire_draining(scope(6)).is_err());
    gate.retire_draining(scope(7))?;
    assert!(
        gate.admit(ingress(11), &feedback(4, 7, RecoveryTag::RollingV1, 12)?)
            .is_err()
    );
    assert_eq!(gate.highest_packet(), Some(PacketNumber(3)));
    gate.admit(ingress(11), &feedback(4, 8, RecoveryTag::ReliableV1, 12)?)?;
    gate.advance_scope(policy(9, RecoveryTag::SelectiveRepeatV1))?;
    assert_eq!(gate.highest_packet(), Some(PacketNumber(4)));
    Ok(())
}
#[test]
fn native_grammar_channels_and_nested_legacy_management_binding() -> R {
    let mut gate = gate()?;
    for receipt in [
        NativeReceipt::Cumulative { records: 1 },
        NativeReceipt::Record {
            channel: 4,
            record: 1,
        },
    ] {
        let bytes = encoded(Envelope {
            binding: binding(1, 7),
            body: Body::NativeReceipt {
                lane: LaneId(12),
                receipt,
            },
        })?;
        assert!(gate.admit(ingress(11), &bytes).is_err());
    }
    let inner = crate::Frame {
        header: crate::Header {
            kind: MessageKind::Prepare,
            sender: Role::Client,
            lane: LaneId(11),
            session: SessionId([0x11; 16]),
            packet: PacketNumber(4),
            request: RequestId(5),
            source_epoch: Epoch(7),
            ticket: Ticket {
                epoch: Epoch(8),
                attempt: 1,
                digest: ConfigDigest([0x33; 32]),
            },
            source: EndpointId(1),
            destination: EndpointId(2),
        },
        body: &[0x44, 0x55],
    };
    let mut legacy = vec![0; crate::HEADER_LEN + 2];
    inner.encode(&mut legacy, crate::Limits::default())?;
    let envelope = Envelope {
        binding: binding(1, 7),
        body: Body::Management(&legacy),
    };
    let bytes = encoded(envelope)?;
    assert_eq!(&bytes[HEADER_BYTES..], legacy);
    gate.admit(ingress(11), &bytes)?;
    let mut wrong = envelope;
    wrong.binding.scope = scope(8);
    assert!(wrong.encode(&mut [0; 1024], limits()).is_err());
    Ok(())
}
#[test]
fn serialized_packet_numbers_never_wrap_or_reset() -> R {
    let mut sequence = PacketNumbers::default();
    assert_eq!(sequence.assign()?, PacketNumber(1));
    assert_eq!(sequence.assign()?, PacketNumber(2));
    let mut exhausted = PacketNumbers {
        next: Some(u64::MAX),
    };
    assert_eq!(exhausted.assign()?, PacketNumber(u64::MAX));
    assert!(exhausted.assign().is_err());
    assert!(exhausted.assign().is_err());
    Ok(())
}

#[test]
fn decoder_borrows_exact_payload_and_short_output_is_atomic() -> R {
    let wire = feedback(1, 7, RecoveryTag::RollingV1, 12)?;
    let frame = Envelope::decode(&wire, limits())?;
    let Body::RecoveryFeedback { bytes, .. } = frame.body else {
        return Err("feedback variant".into());
    };
    assert_eq!(bytes.as_ptr(), wire[HEADER_BYTES + 8..].as_ptr());
    let mut short = [0x55; 8];
    assert!(frame.encode(&mut short, limits()).is_err());
    assert_eq!(short, [0x55; 8]);
    let mut gate = gate()?;
    let mut wrong = wire.clone();
    wrong[48] ^= 1;
    assert!(gate.admit(ingress(11), &wrong).is_err());
    assert_eq!(gate.highest_packet(), None);
    gate.admit(ingress(11), &wire)?;
    Ok(())
}
#[test]
fn receiver_sequence_exhaustion_does_not_reset_or_advance() -> R {
    let mut gate = gate()?;
    gate.replay = crate::ReplayWindow {
        highest: Some(PacketNumber(u64::MAX - 1)),
        seen: u128::MAX,
    };
    let wire = feedback(u64::MAX, 7, RecoveryTag::RollingV1, 12)?;
    gate.admit(ingress(11), &wire)?;
    assert_eq!(gate.highest_packet(), Some(PacketNumber(u64::MAX)));
    assert!(gate.admit(ingress(11), &wire).is_err());
    assert_eq!(gate.highest_packet(), Some(PacketNumber(u64::MAX)));
    Ok(())
}

const PING_HEX: &str = "4c32534301040100000000580000000b111111111111111111111111111111110000000000000001000000000000000722222222222222222222222222222222222222222222222222222222222222220102030405060708";

const FEEDBACK_HEX: &str = "4c325343010201000000005b0000000b111111111111111111111111111111110000000000000001000000000000000722222222222222222222222222222222222222222222222222222222222222220000000c00030000aabbcc";

const NATIVE_HEX: &str = "4c32534301030100000000600000000b111111111111111111111111111111110000000000000001000000000000000722222222222222222222222222222222222222222222222222222222222222220000000c020000030000000000000009";

#[test]
fn profile_control_has_exact_additive_wire_and_borrowed_payload() -> R {
    // Existing Swift Reject(epoch=1, Invalid), including its length prefix.
    let command = [0, 10, 3, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    let frame = Envelope {
        binding: binding(1, 7),
        body: Body::ProfileControl {
            tag: ProfileTag::SwiftPolicyV1,
            bytes: &command,
        },
    };
    let packet = encoded(frame)?;
    let golden = concat!(
        "4c32534301060100000000600000000b",
        "11111111111111111111111111111111",
        "00000000000000010000000000000007",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "00010000000a03000000000000000101"
    );
    assert_eq!(packet, from_hex(golden)?);
    let decoded = Envelope::decode(&packet, limits())?;
    assert_eq!(decoded, frame);
    let Body::ProfileControl { bytes, .. } = decoded.body else {
        return Err("wrong decoded profile body".into());
    };
    assert_eq!(bytes.as_ptr(), packet[HEADER_BYTES + 4..].as_ptr());
    let mut output = [0xa5; 128];
    let written = frame.encode(&mut output, limits())?;
    assert_eq!(&output[..written], packet);
    assert!(output[written..].iter().all(|byte| *byte == 0xa5));
    Ok(())
}

#[test]
fn profile_control_refusals_preserve_output_and_admission_replay() -> R {
    let command = [0, 10, 3, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    let frame = Envelope {
        binding: binding(1, 7),
        body: Body::ProfileControl {
            tag: ProfileTag::SwiftPolicyV1,
            bytes: &command,
        },
    };
    let packet = encoded(frame)?;
    let mut admission = gate()?;
    for end in 0..packet.len() {
        assert!(Envelope::decode(&packet[..end], limits()).is_err());
    }
    for (at, byte) in [(80, 1), (81, 2), (82, 1), (83, 1), (5, 7)] {
        let mut bad = packet.clone();
        bad[at] = byte;
        assert!(admission.admit(ingress(11), &bad).is_err());
        assert_eq!(admission.highest_packet(), None);
    }
    for bytes in [Vec::new(), vec![0x42; MAX_PROFILE_CONTROL_BYTES + 1]] {
        let bad = Envelope {
            body: Body::ProfileControl {
                tag: ProfileTag::SwiftPolicyV1,
                bytes: &bytes,
            },
            ..frame
        };
        let mut output = [0xa5; 256];
        assert_eq!(bad.encode(&mut output, limits()), Err(Error::Length));
        assert_eq!(output, [0xa5; 256]);
    }
    let mut short = vec![0xa5; packet.len() - 1];
    assert_eq!(frame.encode(&mut short, limits()), Err(Error::Output));
    assert!(short.iter().all(|byte| *byte == 0xa5));
    assert!(admission.admit(Ingress::UserTraffic, &packet).is_err());
    assert_eq!(admission.highest_packet(), None);
    let accepted = admission.admit(ingress(11), &packet)?;
    assert_eq!(accepted.envelope.body, frame.body);
    assert_eq!(admission.highest_packet(), Some(PacketNumber(1)));
    assert!(admission.admit(ingress(11), &packet).is_err());
    assert_eq!(admission.highest_packet(), Some(PacketNumber(1)));
    Ok(())
}
