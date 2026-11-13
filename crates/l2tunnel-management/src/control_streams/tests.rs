use super::*;
use crate::{LaneId, Role, SessionId};

#[test]
fn exact_wrapper_preserves_every_inner_byte_and_output_tail() -> Result<(), Error> {
    let limits = Limits {
        max_packet_bytes: 256,
    };
    let packet: Vec<_> = (0..64).collect();
    for stream in Stream::ALL {
        let frame = Frame {
            stream,
            packet: &packet,
        };
        let mut output = [0xa5; 80];
        let bytes = frame.encode(&mut output, limits)?;
        assert_eq!(bytes, HEADER_BYTES + packet.len());
        assert_eq!(
            &output[..8],
            &[b'L', b'2', b'C', b'F', 1, stream as u8, 0, 0]
        );
        assert_eq!(&output[8..bytes], &packet);
        assert!(output[bytes..].iter().all(|byte| *byte == 0xa5));
        assert_eq!(Frame::decode(&output[..bytes], limits)?, frame);
    }
    Ok(())
}

#[test]
fn malformed_wrapper_and_output_refusal_are_atomic() -> Result<(), Error> {
    let limits = Limits {
        max_packet_bytes: 64,
    };
    let packet = [17; 64];
    let frame = Frame {
        stream: Stream::Transaction,
        packet: &packet,
    };
    let mut wire = [0; 72];
    frame.encode(&mut wire, limits)?;
    for length in 0..HEADER_BYTES + DATA_HEADER_BYTES {
        assert_eq!(Frame::decode(&wire[..length], limits), Err(Error::Length));
    }
    for (at, value, error) in [
        (0, 0, Error::Version),
        (4, 2, Error::Version),
        (5, 0, Error::Stream),
        (5, 4, Error::Stream),
        (6, 1, Error::Reserved),
        (7, 1, Error::Reserved),
    ] {
        let mut bad = wire;
        bad[at] = value;
        assert_eq!(Frame::decode(&bad, limits), Err(error));
    }
    let mut too_small = [0xa5; 71];
    assert_eq!(frame.encode(&mut too_small, limits), Err(Error::Output));
    assert_eq!(too_small, [0xa5; 71]);
    let bad_limits = Limits {
        max_packet_bytes: ACK_PACKET_BYTES - 1,
    };
    assert_eq!(frame.encode(&mut wire, bad_limits), Err(Error::Limits));
    let before = wire;
    assert_eq!(
        Frame {
            stream: Stream::Liveness,
            packet: &[7; 65],
        }
        .encode(&mut wire, limits),
        Err(Error::Length)
    );
    assert_eq!(wire, before);
    Ok(())
}

#[test]
fn distinct_fixed_contexts_never_alias_or_wrap() -> Result<(), Error> {
    let base = delivery::Binding {
        session: SessionId([1; 16]),
        lane: LaneId(7),
        local_role: Role::Client,
        control_epoch: 1,
    };
    let contexts = Stream::ALL
        .map(|stream| delivery_binding(base, stream))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        contexts
            .iter()
            .map(|binding| binding.control_epoch)
            .collect::<Vec<_>>(),
        vec![4, 5, 6]
    );
    for context in contexts {
        assert_eq!(context.session, base.session);
        assert_eq!(context.lane, base.lane);
        assert_eq!(context.local_role, base.local_role);
    }
    for epoch in [0, u64::MAX] {
        assert_eq!(
            delivery_binding(
                delivery::Binding {
                    control_epoch: epoch,
                    ..base
                },
                Stream::Liveness
            ),
            Err(Error::Context)
        );
    }
    Ok(())
}
