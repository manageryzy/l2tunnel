use super::*;
use crate::{Ingress, LaneId, PacketNumber, Role, SessionId, session_control as sc};
use l2tunnel_core::{ConfigDigest, Epoch};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn binding() -> delivery::Binding {
    delivery::Binding {
        session: SessionId([7; 16]),
        lane: LaneId(2),
        local_role: Role::Client,
        control_epoch: 3,
    }
}
fn scope(epoch: u64, byte: u8) -> sc::Scope {
    sc::Scope {
        epoch: Epoch(epoch),
        digest: ConfigDigest([byte; 32]),
    }
}
fn verified() -> Ingress {
    Ingress::AuthenticatedManagement {
        session: binding().session,
        lane: binding().lane,
        sender: Role::Client,
    }
}
fn limits() -> sc::Limits {
    sc::Limits {
        max_frame_bytes: 65_536,
        max_management_bytes: 4096,
        max_feedback_bytes: 128,
    }
}
fn envelope(body: sc::Body<'_>, target: sc::Scope, packet: u64) -> Result<Vec<u8>> {
    let value = sc::Envelope {
        binding: sc::Binding {
            session: binding().session,
            lane: binding().lane,
            sender: Role::Client,
            packet: PacketNumber(packet),
            scope: target,
        },
        body,
    };
    let mut bytes = vec![0; value.encoded_len(limits())?];
    value.encode(&mut bytes, limits())?;
    Ok(bytes)
}
fn gate_settings() -> super::super::gate::GateSettings {
    super::super::gate::GateSettings {
        binding: sc::PeerBinding {
            session: binding().session,
            remote_role: Role::Client,
            control_lane: binding().lane,
            data_lanes: [Some(binding().lane), None],
        },
        control: scope(9, 9),
        active: super::super::gate::DataPolicy {
            scope: scope(1, 1),
            recovery: None,
            receipts: sc::ReceiptPolicy::Cumulative,
        },
        limits: limits(),
    }
}

#[test]
fn explicit_versions_keep_v1_bytes_and_reject_cross_version_or_unselected_lifecycle() -> Result {
    let limits = Limits {
        max_packet_bytes: 256,
    };
    let packet = [0x5a; 64];
    for stream in ALL {
        let mut wire = [0xa5; 80];
        let length = Frame {
            stream,
            packet: &packet,
        }
        .encode(&mut wire, limits)?;
        assert_eq!(&wire[..8], &[b'L', b'2', b'C', b'F', 2, stream as u8, 0, 0]);
        assert_eq!(&wire[8..length], &packet);
        assert_eq!(Frame::decode(&wire[..length], limits)?.stream, stream);
        assert_eq!(
            super::super::Frame::decode(&wire[..length], limits),
            Err(Error::Version)
        );
        assert!(wire[length..].iter().all(|byte| *byte == 0xa5));
        if stream != Stream::Lifecycle {
            let mut old = [0; 80];
            let old_length = super::super::Frame {
                stream,
                packet: &packet,
            }
            .encode(&mut old, limits)?;
            assert_eq!(&old[..8], &[b'L', b'2', b'C', b'F', 1, stream as u8, 0, 0]);
            assert_eq!(
                Frame::decode(&old[..old_length], limits),
                Err(Error::Version)
            );
        }
    }
    let mut output = [0xa5; 80];
    assert_eq!(
        super::super::Frame {
            stream: Stream::Lifecycle,
            packet: &packet
        }
        .encode(&mut output, limits),
        Err(Error::Stream)
    );
    assert_eq!(output, [0xa5; 80]);
    assert_eq!(
        super::super::delivery_binding(binding(), Stream::Lifecycle),
        Err(Error::Stream)
    );
    for stream in ALL {
        assert_eq!(
            delivery_binding(binding(), stream)?.control_epoch,
            12 + stream as u64
        );
    }
    for epoch in [0, u64::MAX / 4, u64::MAX] {
        let bad = delivery::Binding {
            control_epoch: epoch,
            ..binding()
        };
        if epoch == u64::MAX / 4 {
            assert!(delivery_binding(bad, Stream::Lifecycle).is_err());
        } else {
            assert!(delivery_binding(bad, Stream::Transaction).is_err());
        }
    }
    let mut malformed = [0; 72];
    Frame {
        stream: Stream::Lifecycle,
        packet: &packet,
    }
    .encode(&mut malformed, limits)?;
    for (at, value, expected) in [
        (4, 1, Error::Version),
        (5, 0, Error::Stream),
        (5, 5, Error::Stream),
        (6, 1, Error::Reserved),
        (7, 1, Error::Reserved),
    ] {
        let mut bad = malformed;
        bad[at] = value;
        assert_eq!(Frame::decode(&bad, limits), Err(expected));
    }
    Ok(())
}

#[test]
fn lifecycle_full_bound_is_distinct_from_unchanged_swift43_and_parser_grants_no_authority() -> Result
{
    let payload = vec![0x2b; sc::MAX_LIFECYCLE_BYTES - LIFECYCLE_HEADER_BYTES];
    let value = Lifecycle {
        kind: LifecycleKind::NoiseFlight,
        bytes: &payload,
    };
    let mut body = vec![0; sc::MAX_LIFECYCLE_BYTES];
    assert_eq!(
        value.encode(&mut body, sc::MAX_LIFECYCLE_BYTES)?,
        body.len()
    );
    assert_eq!(Lifecycle::decode(&body, body.len())?, value);
    let wire = envelope(
        sc::Body::ProfileControl {
            tag: sc::ProfileTag::SessionRefreshV1,
            bytes: &body,
        },
        scope(9, 9),
        1,
    )?;
    assert_eq!(wire.len(), 65_536);
    assert!(matches!(
        sc::Envelope::decode(&wire, limits())?.body,
        sc::Body::ProfileControl {
            tag: sc::ProfileTag::SessionRefreshV1,
            ..
        }
    ));
    assert!(
        envelope(
            sc::Body::ProfileControl {
                tag: sc::ProfileTag::SwiftPolicyV1,
                bytes: &[0; 44]
            },
            scope(1, 1),
            1
        )
        .is_err()
    );
    assert!(
        envelope(
            sc::Body::ProfileControl {
                tag: sc::ProfileTag::SwiftPolicyV1,
                bytes: &[0; 43]
            },
            scope(1, 1),
            1
        )
        .is_ok()
    );
    let mut short = [0xa5; 8];
    assert_eq!(
        Lifecycle {
            kind: LifecycleKind::Request,
            bytes: b"x"
        }
        .encode(&mut short, 9),
        Err(Error::Output)
    );
    assert_eq!(short, [0xa5; 8]);
    assert!(Lifecycle::decode(&body, body.len() - 1).is_err());
    for (at, byte) in [(0, 0), (4, 2), (5, 0), (6, 1), (7, 1)] {
        let mut bad = body[..16].to_vec();
        bad[at] = byte;
        assert!(Lifecycle::decode(&bad, 128).is_err());
    }
    assert!(Lifecycle::decode(b"L2RL\x01\x01\0\0", 128).is_err());
    Ok(())
}

#[test]
fn lifecycle_gate_is_v2_fixed_control_bound_and_independent_of_transaction_scopes() -> Result {
    use super::super::gate::{DataPolicy, Gate};
    let mut body = [0; 32];
    let length = Lifecycle {
        kind: LifecycleKind::Request,
        bytes: b"opaque actual material",
    }
    .encode(&mut body, 32)?;
    let profile = sc::Body::ProfileControl {
        tag: sc::ProfileTag::SessionRefreshV1,
        bytes: &body[..length],
    };
    let wire = envelope(profile, scope(9, 9), 1)?;
    let mut old = Gate::new_transaction_bound(gate_settings())?;
    assert_eq!(
        old.admit(verified(), Stream::Lifecycle, &wire).err(),
        Some(sc::Error::Kind)
    );
    assert_eq!(
        old.admit(verified(), Stream::Transaction, &wire).err(),
        Some(sc::Error::Kind)
    );
    assert_eq!(old.highest_packet(Stream::Lifecycle), None);
    let mut gate = Gate::new_v2_transaction_bound(gate_settings())?;
    for target in [scope(1, 1), scope(9, 8), scope(10, 9)] {
        assert_eq!(
            gate.admit(
                verified(),
                Stream::Lifecycle,
                &envelope(profile, target, 1)?
            )
            .err(),
            Some(sc::Error::Scope)
        );
        assert_eq!(gate.highest_packet(Stream::Lifecycle), None);
    }
    for stream in [Stream::Transaction, Stream::Liveness, Stream::DataFeedback] {
        assert_eq!(
            gate.admit(verified(), stream, &wire).err(),
            Some(sc::Error::Kind)
        );
    }
    for ingress in [
        Ingress::AuthenticatedManagement {
            session: SessionId([8; 16]),
            lane: binding().lane,
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: binding().session,
            lane: LaneId(3),
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: binding().session,
            lane: binding().lane,
            sender: Role::Server,
        },
    ] {
        assert_eq!(
            gate.admit(ingress, Stream::Lifecycle, b"short").err(),
            Some(sc::Error::Binding)
        );
    }
    gate.admit(verified(), Stream::Lifecycle, &wire)?;
    assert_eq!(
        gate.highest_packet(Stream::Lifecycle),
        Some(PacketNumber(1))
    );
    let ping = envelope(sc::Body::Ping { nonce: 7 }, scope(9, 9), 1)?;
    gate.admit(verified(), Stream::Liveness, &ping)?;
    gate.advance_scope(DataPolicy {
        scope: scope(2, 2),
        recovery: None,
        receipts: sc::ReceiptPolicy::Cumulative,
    })?;
    gate.retire_draining(scope(1, 1))?;
    gate.admit(
        verified(),
        Stream::Lifecycle,
        &envelope(profile, scope(9, 9), 2)?,
    )?;
    assert_eq!(
        gate.highest_packet(Stream::Lifecycle),
        Some(PacketNumber(2))
    );
    assert_eq!(gate.highest_packet(Stream::Transaction), None);
    assert_eq!(gate.highest_packet(Stream::Liveness), Some(PacketNumber(1)));
    Ok(())
}
