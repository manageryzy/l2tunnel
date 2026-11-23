//! Established Common records on one UDP socket per peer. The receiver discards
//! specified ciphertexts before authentication to reproduce physical erasures.
use super::*;
use l2tunnel::fec::{
    self, GenerationId,
    mixed_datagram::Profile,
    striped_group::{
        ReceiveWindow, TransmitWindow,
        feedback::{Feedback, FeedbackId, Missing, ReplayWindow},
    },
};

fn transfer(from: &UdpSocket, to: &UdpSocket, packet: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(from.send(packet)?, packet.len());
    let mut input = [0; 1500];
    let used = to.recv(&mut input)?;
    Ok(input[..used].to_vec())
}

fn open(receiver: &mut Records, packet: &[u8], feedback: bool) -> Result<Vec<u8>> {
    let mut plain = [0; 1024];
    let meta = receiver.open_compact_with_carrier(packet, &[], &mut [0; 1500], &mut plain)?;
    assert_eq!(meta.scope, data());
    assert_eq!(meta.class, Class::User);
    assert!(meta.strongly_authenticated);
    assert_eq!(meta.feedback, feedback);
    Ok(plain[..meta.bytes].to_vec())
}

#[test]
fn mixed_members_and_named_retries_share_udp_and_retire_only_after_delivery() -> Result<()> {
    let [mut a, mut b] = peers(Protection::ChaCha20Poly1305)?;
    let left = UdpSocket::bind("127.0.0.1:0")?;
    let right = UdpSocket::bind("127.0.0.1:0")?;
    left.connect(right.local_addr()?)?;
    right.connect(left.local_addr()?)?;
    for socket in [&left, &right] {
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    }
    let context = fec::FecContext {
        session: fec::SessionId([3; 16]),
        epoch: fec::Epoch(data().epoch.0),
        channel: fec::ChannelId(1),
        direction: fec::Direction::ClientToServer,
    };
    let profile = Profile {
        data_cells: 3,
        parity_cells: 1,
        max_wire_bytes: 256,
        max_body_bytes: 256,
    };
    let key = |offset: u8| GenerationId((u64::MAX - 7) + u64::from(offset));
    let mut tx = TransmitWindow::new(profile, context, key(0), 10, 0, 8)?;
    let mut rx = ReceiveWindow::new(profile, context, key(0), 8, 4096)?;
    let mut feedback_replay = ReplayWindow::new(context);
    let mut raw = [0; 256];
    let mut scratch = [0; 256];
    let mut erased = Vec::new();
    for group in [0_u8, 4] {
        for id in group..group + 4 {
            tx.submit(u64::from(group), &[id; 48])?;
        }
        for ordinal in 0..4 {
            let (member, n) = tx
                .prepare_fresh(u64::from(group), &mut raw)?
                .ok_or("missing fresh member")?;
            assert_eq!(member.ordinal(), ordinal);
            let sealed = seal(&mut a, Kind::Data, data(), &[], &raw[..n])?;
            let packet = transfer(&left, &right, &sealed)?;
            tx.confirm_fresh(member)?;
            if group == 0 && ordinal == 0 {
                erased = packet;
            } else if !(group == 0 && ordinal == 1 || group == 4 && ordinal == 3) {
                let body = open(&mut b, &packet, false)?;
                rx.accept_authenticated(context, &body, &mut scratch)?;
            }
        }
    }
    assert!(!rx.can_recover(key(0)));
    assert_eq!(rx.recover_missing(key(4))?, 1);
    for id in 2_u8..8 {
        assert_eq!(rx.pending_original(key(id))?, Some([id; 48].as_slice()));
        assert!(rx.commit_original(key(id))?);
    }
    assert_eq!(rx.confirmed_through(), None);
    let mut missing = [GenerationId(0); 8];
    let count = rx.missing_ids(key(0), 8, &mut missing)?;
    assert_eq!(&missing[..count], &[key(0), key(1)]);
    let request = Feedback::new(
        context,
        FeedbackId(u64::MAX - 1),
        None,
        Some(Missing::new(missing[0], 1)?),
    )?;
    let n = request.encode(&mut raw)?;
    assert_eq!(n, request.wire_len());
    let packet = transfer(
        &right,
        &left,
        &seal(&mut b, Kind::Feedback, data(), &[], &raw[..n])?,
    )?;
    let received = open(&mut a, &packet, true)?;
    let request = Feedback::decode(context, &received)?;
    assert!(feedback_replay.accept(request)?);
    // The same logical request can legitimately arrive with fresh carrier authentication.
    let packet = transfer(
        &right,
        &left,
        &seal(&mut b, Kind::Feedback, data(), &[], &raw[..n])?,
    )?;
    let duplicate = Feedback::decode(context, &open(&mut a, &packet, true)?)?;
    assert!(!feedback_replay.accept(duplicate)?);
    let named = request.missing().ok_or("expected named retry")?;
    let n = tx.write_named(request.context(), named.first(), &mut raw)?;
    let packet = transfer(
        &left,
        &right,
        &seal(&mut a, Kind::Data, data(), &[], &raw[..n])?,
    )?;
    assert_ne!(packet, erased);
    let body = open(&mut b, &packet, false)?;
    assert_eq!(body, raw[..n]);
    rx.accept_authenticated(context, &body, &mut scratch)?;
    assert_eq!(
        b.open_compact_with_carrier(&packet, &[], &mut [0; 1500], &mut raw),
        Err(Error::Security(security::Error::Replay))
    );
    assert_eq!(rx.recover_missing(key(0))?, 1);
    for id in [0_u8, 1] {
        assert_eq!(rx.pending_original(key(id))?, Some([id; 48].as_slice()));
        rx.commit_original(key(id))?;
    }
    assert_eq!(rx.confirmed_through(), Some(GenerationId(u64::MAX)));
    let receipt = Feedback::new(context, FeedbackId(u64::MAX), rx.confirmed_through(), None)?;
    let n = receipt.encode(&mut raw)?;
    let packet = transfer(
        &right,
        &left,
        &seal(&mut b, Kind::Feedback, data(), &[], &raw[..n])?,
    )?;
    let received = open(&mut a, &packet, true)?;
    let receipt = Feedback::decode(context, &received)?;
    assert!(feedback_replay.accept(receipt)?);
    let last = receipt.confirmed_through().ok_or("expected final prefix")?;
    assert!(tx.confirm_through(receipt.context(), last)?);
    assert_eq!((rx.expanded_bytes(), tx.retained()), (0, 0));
    Ok(())
}
