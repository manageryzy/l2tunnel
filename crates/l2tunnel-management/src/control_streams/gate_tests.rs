use super::*;
use crate::session_control::{Binding, ProfileTag};
use crate::{EndpointId, Frame, Header, LaneId, MessageKind, RequestId, Role, SessionId};
use l2tunnel_core::{ConfigDigest, Epoch};
use l2tunnel_session::Ticket;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn scope(epoch: u64) -> Scope {
    Scope {
        epoch: Epoch(epoch),
        digest: ConfigDigest([epoch as u8; 32]),
    }
}
fn settings() -> GateSettings {
    GateSettings {
        binding: PeerBinding {
            session: SessionId([0x11; 16]),
            remote_role: Role::Client,
            control_lane: LaneId(11),
            data_lanes: [Some(LaneId(11)), Some(LaneId(12))],
        },
        control: scope(1),
        active: DataPolicy {
            scope: scope(10),
            recovery: None,
            receipts: ReceiptPolicy::Cumulative,
        },
        limits: Limits {
            max_frame_bytes: 1024,
            max_management_bytes: 512,
            max_feedback_bytes: 128,
        },
    }
}
fn verified() -> Ingress {
    Ingress::AuthenticatedManagement {
        session: settings().binding.session,
        lane: LaneId(11),
        sender: Role::Client,
    }
}
fn encode(packet: u64, scope: Scope, body: Body<'_>) -> Result<Vec<u8>> {
    let envelope = Envelope {
        binding: Binding {
            session: settings().binding.session,
            lane: LaneId(11),
            sender: Role::Client,
            packet: PacketNumber(packet),
            scope,
        },
        body,
    };
    let mut output = vec![0; envelope.encoded_len(settings().limits)?];
    envelope.encode(&mut output, settings().limits)?;
    Ok(output)
}
fn management(origin: Scope) -> Result<Vec<u8>> {
    let frame = Frame {
        header: Header {
            kind: MessageKind::Prepare,
            sender: Role::Client,
            lane: LaneId(11),
            session: settings().binding.session,
            packet: PacketNumber(1),
            request: RequestId(1),
            source_epoch: origin.epoch,
            ticket: Ticket {
                attempt: 1,
                epoch: Epoch(origin.epoch.0 + 1),
                digest: ConfigDigest([0x77; 32]),
            },
            source: EndpointId(1),
            destination: EndpointId(2),
        },
        body: &[],
    };
    let mut bytes = vec![0; crate::HEADER_LEN];
    frame.encode(&mut bytes, crate::Limits::default())?;
    Ok(bytes)
}
fn state(gate: &Gate) -> ([Option<PacketNumber>; 3], DataPolicy, Option<DataPolicy>) {
    (
        Stream::ALL.map(|stream| gate.highest_packet(stream)),
        gate.active,
        gate.draining,
    )
}
fn rejected(gate: &mut Gate, stream: Stream, input: &[u8], expected: Error) {
    let before = state(gate);
    assert_eq!(gate.admit(verified(), stream, input).err(), Some(expected));
    assert_eq!(state(gate), before);
}

#[test]
fn fixed_liveness_survives_more_than_replay_window_before_transaction_one() -> Result {
    let mut gate = Gate::new(settings())?;
    for packet in 1..=257 {
        let bytes = encode(packet, scope(1), Body::Ping { nonce: packet })?;
        assert_eq!(
            gate.admit(verified(), Stream::Liveness, &bytes)?.body,
            Body::Ping { nonce: packet }
        );
    }
    assert_eq!(gate.highest_packet(Stream::Transaction), None);
    assert_eq!(gate.highest_packet(Stream::DataFeedback), None);
    let inner = management(scope(10))?;
    let bytes = encode(1, scope(10), Body::Management(&inner))?;
    let admitted = gate.admit(verified(), Stream::Transaction, &bytes)?;
    assert_eq!(admitted.body, Body::Management(&inner));
    assert_eq!(
        gate.highest_packet(Stream::Transaction),
        Some(PacketNumber(1))
    );
    assert_eq!(
        gate.highest_packet(Stream::Liveness),
        Some(PacketNumber(257))
    );
    Ok(())
}

#[test]
fn full_authenticated_binding_is_checked_before_parsing_or_mutation() -> Result {
    let mut gate = Gate::new(settings())?;
    let bytes = encode(1, scope(1), Body::Pong { nonce: 7 })?;
    let mut other_session = settings().binding.session;
    other_session.0[15] ^= 1;
    for origin in [
        Ingress::UserTraffic,
        Ingress::Unauthenticated,
        Ingress::AuthenticatedManagement {
            session: other_session,
            lane: LaneId(11),
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: settings().binding.session,
            lane: LaneId(12),
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: settings().binding.session,
            lane: LaneId(11),
            sender: Role::Server,
        },
    ] {
        let before = state(&gate);
        assert!(gate.admit(origin, Stream::Liveness, &[]).is_err());
        assert_eq!(state(&gate), before);
        assert!(gate.admit(origin, Stream::Liveness, &bytes).is_err());
        assert_eq!(state(&gate), before);
    }
    for at in [31, 15, 6] {
        let mut wrong = bytes.clone();
        wrong[at] ^= 1;
        let before = state(&gate);
        assert!(gate.admit(verified(), Stream::Liveness, &wrong).is_err());
        assert_eq!(state(&gate), before);
    }
    gate.admit(verified(), Stream::Liveness, &bytes)?;
    Ok(())
}

#[test]
fn malformed_and_cross_stream_bodies_leave_every_sequence_available() -> Result {
    let mut gate = Gate::new(settings())?;
    let ping = encode(1, scope(1), Body::Ping { nonce: 1 })?;
    for end in 0..ping.len() {
        let before = state(&gate);
        assert!(
            gate.admit(verified(), Stream::Liveness, &ping[..end])
                .is_err()
        );
        assert_eq!(state(&gate), before);
    }
    let mut trailing = ping.clone();
    trailing.push(0);
    rejected(&mut gate, Stream::Liveness, &trailing, Error::Length);
    for stream in [Stream::Transaction, Stream::DataFeedback] {
        rejected(&mut gate, stream, &ping, Error::Kind);
    }
    let profile = encode(
        1,
        scope(10),
        Body::ProfileControl {
            tag: ProfileTag::SwiftPolicyV1,
            bytes: &[1],
        },
    )?;
    for stream in [Stream::Liveness, Stream::DataFeedback] {
        rejected(&mut gate, stream, &profile, Error::Kind);
    }
    let native = encode(
        1,
        scope(10),
        Body::NativeReceipt {
            lane: LaneId(12),
            receipt: NativeReceipt::Cumulative { records: 1 },
        },
    )?;
    for stream in [Stream::Liveness, Stream::Transaction] {
        rejected(&mut gate, stream, &native, Error::Kind);
    }
    gate.admit(verified(), Stream::Liveness, &ping)?;
    gate.admit(verified(), Stream::Transaction, &profile)?;
    gate.admit(verified(), Stream::DataFeedback, &native)?;
    Ok(())
}

#[test]
fn gaps_duplicates_zero_and_exhaustion_do_not_reset_or_wrap_streams() -> Result {
    let mut gate = Gate::new(settings())?;
    let second = encode(2, scope(1), Body::Ping { nonce: 2 })?;
    rejected(&mut gate, Stream::Liveness, &second, Error::Sequence);
    let first = encode(1, scope(1), Body::Ping { nonce: 1 })?;
    let mut zero = first.clone();
    zero[32..40].fill(0);
    rejected(&mut gate, Stream::Liveness, &zero, Error::Binding);
    gate.admit(verified(), Stream::Liveness, &first)?;
    rejected(
        &mut gate,
        Stream::Liveness,
        &first,
        Error::Legacy(crate::Error::PacketReplay),
    );
    gate.admit(verified(), Stream::Liveness, &second)?;
    gate.replay[Stream::Liveness.index()] = ReplayWindow {
        highest: Some(PacketNumber(u64::MAX - 1)),
        seen: 1,
    };
    let last = encode(u64::MAX, scope(1), Body::Ping { nonce: 3 })?;
    gate.admit(verified(), Stream::Liveness, &last)?;
    rejected(&mut gate, Stream::Liveness, &last, Error::Exhausted);
    let inner = management(scope(10))?;
    let transaction = encode(1, scope(10), Body::Management(&inner))?;
    gate.admit(verified(), Stream::Transaction, &transaction)?;
    Ok(())
}

#[test]
fn fixed_scope_and_sequences_survive_bounded_data_advance_and_exact_retirement() -> Result {
    let mut gate = Gate::new(settings())?;
    let profile = |packet, origin| {
        encode(
            packet,
            origin,
            Body::ProfileControl {
                tag: ProfileTag::SwiftPolicyV1,
                bytes: &[1],
            },
        )
    };
    gate.admit(verified(), Stream::Transaction, &profile(1, scope(10))?)?;
    let next = DataPolicy {
        scope: scope(11),
        ..settings().active
    };
    gate.advance_scope(next)?;
    assert_eq!(
        gate.highest_packet(Stream::Transaction),
        Some(PacketNumber(1))
    );
    let before = state(&gate);
    assert_eq!(
        gate.advance_scope(DataPolicy {
            scope: scope(12),
            ..next
        }),
        Err(Error::Capacity)
    );
    assert_eq!(state(&gate), before);
    let mut wrong = scope(10);
    wrong.digest.0[31] ^= 1;
    assert_eq!(gate.retire_draining(wrong), Err(Error::Scope));
    assert_eq!(state(&gate), before);
    rejected(
        &mut gate,
        Stream::Transaction,
        &profile(2, scope(12))?,
        Error::Scope,
    );
    rejected(
        &mut gate,
        Stream::Transaction,
        &profile(2, wrong)?,
        Error::Scope,
    );
    gate.admit(verified(), Stream::Transaction, &profile(2, scope(10))?)?;
    gate.admit(verified(), Stream::Transaction, &profile(3, scope(11))?)?;
    gate.retire_draining(scope(10))?;
    rejected(
        &mut gate,
        Stream::Transaction,
        &profile(4, scope(10))?,
        Error::Scope,
    );
    gate.admit(verified(), Stream::Transaction, &profile(4, scope(11))?)?;
    for epoch in 12..=14 {
        gate.advance_scope(DataPolicy {
            scope: scope(epoch),
            ..next
        })?;
        gate.retire_draining(scope(epoch - 1))?;
    }
    let ping = encode(1, scope(1), Body::Ping { nonce: 9 })?;
    gate.admit(verified(), Stream::Liveness, &ping)?;
    rejected(
        &mut gate,
        Stream::Liveness,
        &encode(2, scope(14), Body::Pong { nonce: 9 })?,
        Error::Scope,
    );
    let before = state(&gate);
    assert_eq!(
        gate.advance_scope(DataPolicy {
            scope: scope(14),
            ..next
        }),
        Err(Error::Scope)
    );
    assert_eq!(state(&gate), before);
    Ok(())
}

#[test]
fn feedback_none_and_actual_grammar_lane_size_and_receipt_policy_are_enforced() -> Result {
    let mut gate = Gate::new(settings())?;
    let feedback =
        |origin, tag, lane, bytes| encode(1, origin, Body::RecoveryFeedback { lane, tag, bytes });
    let rolling = feedback(scope(10), RecoveryTag::RollingV1, LaneId(12), &[1])?;
    rejected(
        &mut gate,
        Stream::DataFeedback,
        &rolling,
        Error::FeedbackTag,
    );
    let native = encode(
        1,
        scope(10),
        Body::NativeReceipt {
            lane: LaneId(12),
            receipt: NativeReceipt::Cumulative { records: 3 },
        },
    )?;
    gate.admit(verified(), Stream::DataFeedback, &native)?;
    let mut configured = settings();
    configured.active.recovery = Some((RecoveryTag::RollingV1, 16));
    configured.active.receipts = ReceiptPolicy::Record { channels: 4 };
    let mut gate = Gate::new(configured)?;
    for bytes in [
        feedback(scope(10), RecoveryTag::ReliableV1, LaneId(12), &[1])?,
        feedback(scope(10), RecoveryTag::RollingV1, LaneId(99), &[1])?,
        feedback(scope(10), RecoveryTag::RollingV1, LaneId(12), &[1; 17])?,
    ] {
        rejected(&mut gate, Stream::DataFeedback, &bytes, Error::FeedbackTag);
    }
    for receipt in [
        NativeReceipt::Cumulative { records: 3 },
        NativeReceipt::Record {
            channel: 4,
            record: 3,
        },
    ] {
        let bytes = encode(
            1,
            scope(10),
            Body::NativeReceipt {
                lane: LaneId(12),
                receipt,
            },
        )?;
        rejected(&mut gate, Stream::DataFeedback, &bytes, Error::Receipt);
    }
    rejected(&mut gate, Stream::Liveness, &rolling, Error::Kind);
    gate.admit(verified(), Stream::DataFeedback, &rolling)?;
    gate.advance_scope(DataPolicy {
        scope: scope(11),
        recovery: Some((RecoveryTag::ReliableV1, 8)),
        receipts: ReceiptPolicy::Cumulative,
    })?;
    let retained = encode(
        2,
        scope(10),
        Body::RecoveryFeedback {
            lane: LaneId(12),
            tag: RecoveryTag::RollingV1,
            bytes: &[1],
        },
    )?;
    gate.admit(verified(), Stream::DataFeedback, &retained)?;
    let wrong_new = encode(
        3,
        scope(11),
        Body::RecoveryFeedback {
            lane: LaneId(12),
            tag: RecoveryTag::RollingV1,
            bytes: &[1],
        },
    )?;
    rejected(
        &mut gate,
        Stream::DataFeedback,
        &wrong_new,
        Error::FeedbackTag,
    );
    let next = encode(
        3,
        scope(11),
        Body::RecoveryFeedback {
            lane: LaneId(12),
            tag: RecoveryTag::ReliableV1,
            bytes: &[1],
        },
    )?;
    gate.admit(verified(), Stream::DataFeedback, &next)?;
    gate.retire_draining(scope(10))?;
    let retired = encode(
        4,
        scope(10),
        Body::RecoveryFeedback {
            lane: LaneId(12),
            tag: RecoveryTag::RollingV1,
            bytes: &[1],
        },
    )?;
    rejected(&mut gate, Stream::DataFeedback, &retired, Error::Scope);
    Ok(())
}

#[test]
fn construction_and_invalid_policy_advance_are_bounded_and_atomic() -> Result {
    for bad in [
        DataPolicy {
            scope: scope(0),
            ..settings().active
        },
        DataPolicy {
            recovery: Some((RecoveryTag::RollingV1, 0)),
            ..settings().active
        },
        DataPolicy {
            recovery: Some((RecoveryTag::RollingV1, 129)),
            ..settings().active
        },
        DataPolicy {
            receipts: ReceiptPolicy::Record { channels: 0 },
            ..settings().active
        },
        DataPolicy {
            receipts: ReceiptPolicy::Record { channels: 257 },
            ..settings().active
        },
    ] {
        let configured = GateSettings {
            active: bad,
            ..settings()
        };
        assert_eq!(Gate::new(configured).err(), Some(Error::Limits));
        let mut gate = Gate::new(settings())?;
        let before = state(&gate);
        assert_eq!(gate.advance_scope(bad), Err(Error::Limits));
        assert_eq!(state(&gate), before);
    }
    let mut duplicate = settings();
    duplicate.binding.data_lanes[1] = duplicate.binding.data_lanes[0];
    assert_eq!(Gate::new(duplicate).err(), Some(Error::Binding));
    let mut wrong_primary = settings();
    wrong_primary.binding.control_lane = LaneId(99);
    assert_eq!(Gate::new(wrong_primary).err(), Some(Error::Binding));
    let mut zero_session = settings();
    zero_session.binding.session = SessionId([0; 16]);
    assert_eq!(Gate::new(zero_session).err(), Some(Error::Binding));
    let mut zero_control = settings();
    zero_control.control = scope(0);
    assert_eq!(Gate::new(zero_control).err(), Some(Error::Limits));
    Ok(())
}
