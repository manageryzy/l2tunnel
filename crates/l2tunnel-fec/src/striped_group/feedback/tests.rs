use super::*;
use crate::{ChannelId, Direction, Epoch, SessionId};

const CONTEXT: FecContext = FecContext {
    session: SessionId([1; 16]),
    epoch: Epoch(3),
    direction: Direction::ClientToServer,
    channel: ChannelId(7),
};

#[test]
fn compact_feedback_roundtrips_the_full_domain_and_inclusive_max() -> Result<(), Error> {
    let small = Feedback::new(
        CONTEXT,
        FeedbackId(1),
        Some(GenerationId(0)),
        Some(Missing::new(GenerationId(2), 5)?),
    )?;
    let wide = Feedback::new(
        CONTEXT,
        FeedbackId(u64::MAX),
        Some(GenerationId(u64::MAX - 130)),
        Some(Missing::new(GenerationId(u64::MAX - 63), 1 << 63 | 1)?),
    )?;
    let final_id = Feedback::new(CONTEXT, FeedbackId(2), Some(GenerationId(u64::MAX)), None)?;
    let mut buf = [0xaa; MAX_WIRE_BYTES + 1];
    for (msg, length) in [(small, 5), (wide, MAX_WIRE_BYTES), (final_id, 12)] {
        buf.fill(0xaa);
        assert_eq!(msg.wire_len(), length);
        assert_eq!(
            msg.encode(&mut buf[..length - 1]),
            Err(Error::OutputTooSmall { required: length })
        );
        assert!(buf.iter().all(|&v| v == 0xaa));
        assert_eq!(msg.encode(&mut buf)?, length);
        assert_eq!(buf[length], 0xaa);
        assert_eq!(Feedback::decode(CONTEXT, &buf[..length])?, msg);
        if msg == small {
            assert_eq!(&buf[..length], &[0x13, 1, 0, 2, 5]);
        }
        for end in 0..length {
            assert!(Feedback::decode(CONTEXT, &buf[..end]).is_err());
        }
    }
    assert!(
        wide.missing()
            .into_iter()
            .flat_map(Missing::ids)
            .eq([GenerationId(u64::MAX - 63), GenerationId(u64::MAX)])
    );
    let singleton = Missing::new(GenerationId(u64::MAX), 1)?;
    assert!(singleton.ids().eq([GenerationId(u64::MAX)]));
    Ok(())
}

#[test]
fn invalid_masks_and_noncanonical_fields_cannot_be_admitted() {
    for bytes in [
        &[0x10, 1][..],      // No coverage and no request.
        &[0x14, 1, 0],       // Reserved flag.
        &[0x21, 1, 0],       // Unknown version.
        &[0x11, 0, 0],       // Reserved logical ID.
        &[0x11, 0x81, 0, 0], // Overlong serial.
        &[0x11, 1, 0, 0],    // Trailing bytes.
        &[0x12, 1, 2, 0],    // Empty mask.
        &[0x12, 1, 2, 2],    // First bit is absent.
        &[0x13, 1, 7, 7, 1], // Source is already cumulatively covered.
        &[0x11, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2],
    ] {
        assert_eq!(Feedback::decode(CONTEXT, bytes), Err(Error::Malformed));
    }
    let overflow = &[0x12, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1, 3];
    assert_eq!(Feedback::decode(CONTEXT, overflow), Err(Error::Arithmetic));
    assert_eq!(
        Missing::new(GenerationId(u64::MAX - 62), 1 << 63 | 1),
        Err(Error::Arithmetic)
    );
    assert_eq!(
        Feedback::decode(CONTEXT, &[0; MAX_WIRE_BYTES + 1]),
        Err(Error::Malformed)
    );
}

#[test]
fn independent_replay_window_accepts_reordering_and_scopes_before_commit() -> Result<(), Error> {
    let ack =
        |context, serial| Feedback::new(context, FeedbackId(serial), Some(GenerationId(9)), None);
    let mut window = ReplayWindow::new(CONTEXT);
    assert!(window.accept(ack(CONTEXT, 2)?)?);
    assert!(window.accept(ack(CONTEXT, 1)?)?);
    assert!(!window.accept(ack(CONTEXT, 1)?)?);
    for context in [
        FecContext {
            direction: Direction::ServerToClient,
            ..CONTEXT
        },
        FecContext {
            session: SessionId([2; 16]),
            ..CONTEXT
        },
        FecContext {
            channel: ChannelId(1),
            ..CONTEXT
        },
        FecContext {
            epoch: Epoch(4),
            ..CONTEXT
        },
    ] {
        assert_eq!(
            window.accept(ack(context, u64::MAX)?),
            Err(Error::ContextMismatch)
        );
    }
    assert!(window.accept(ack(CONTEXT, 3)?)?);
    assert!(window.accept(ack(CONTEXT, u64::MAX)?)?);
    assert!(window.accept(ack(CONTEXT, u64::MAX - 63)?)?);
    assert!(!window.accept(ack(CONTEXT, u64::MAX - 64)?)?);
    assert!(!window.accept(ack(CONTEXT, u64::MAX)?)?);
    Ok(())
}
