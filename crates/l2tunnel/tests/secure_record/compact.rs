//! Final compact record behavior, independent of runtime/native qualification.
use super::*;
use l2tunnel::secure_record::compact::{Kind, Selection};
use security::compact::Protection;

fn selection(protection: Protection) -> Selection {
    Selection {
        protection,
        limits: security::compact::Selection {
            max_forward_packets: 4096,
            max_failed_checks: 128,
        },
    }
}
fn compact_peers(appearance: cover::Appearance, protection: Protection) -> Result<[Records; 2]> {
    let (a, b) = covers(appearance)?;
    Ok([
        Records::new_compact(
            root(security::Role::Initiator)?,
            security::LaneId(7),
            limits(),
            a,
            control(),
            data(),
            selection(protection),
        )?,
        Records::new_compact(
            root(security::Role::Responder)?,
            security::LaneId(7),
            limits(),
            b,
            control(),
            data(),
            selection(protection),
        )?,
    ])
}
fn compact_seal(records: &mut Records, kind: Kind, scope: Scope, body: &[u8]) -> Result<Vec<u8>> {
    let cap = records.capacity_for(kind, body.len())?;
    let mut scratch = vec![0; cap.seal_workspace_bytes];
    let mut wire = vec![0; cap.packet_bytes];
    let sealed = match kind {
        Kind::Data => records.seal_user_in(scope, outer(0), body, &mut scratch, &mut wire)?,
        Kind::Feedback => {
            records.seal_feedback_in(scope, outer(0), body, &mut scratch, &mut wire)?
        }
        Kind::Control => records.seal(Class::Control, outer(0), body, &mut scratch, &mut wire)?,
    };
    assert_eq!(wire.len(), sealed.bytes);
    Ok(wire)
}

#[test]
fn compact_both_profiles_covers_directions_and_authority_have_exact_wire_sizes() -> Result<()> {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for protection in [Protection::Aes128Ccm4, Protection::ChaCha20Crc32c] {
            let [mut a, mut b] = compact_peers(appearance, protection)?;
            for index in 0..20 {
                for reverse in [false, true] {
                    let (sender, receiver) = if reverse {
                        (&mut b, &mut a)
                    } else {
                        (&mut a, &mut b)
                    };
                    for kind in [Kind::Data, Kind::Feedback, Kind::Control] {
                        let body = [0x5a, 0xf3, index, 0, 0xff];
                        let scope = if kind == Kind::Control {
                            control()
                        } else {
                            data()
                        };
                        let packet = compact_seal(sender, kind, scope, &body)?;
                        assert_eq!(
                            packet.len(),
                            body.len() + if kind == Kind::Data { 9 } else { 21 }
                        );
                        let (opened, plain) = open(receiver, &packet)?;
                        assert_eq!(plain, body);
                        assert_eq!(opened.number.0, u64::from(index));
                        assert_eq!(opened.generation.0, u64::from(index) / 8);
                        assert_eq!(opened.scope, scope);
                        assert_eq!(opened.feedback, kind == Kind::Feedback);
                        assert_eq!(
                            opened.authenticated,
                            kind != Kind::Data || protection == Protection::Aes128Ccm4
                        );
                        assert_eq!(
                            receiver.open(&packet, &mut [0; 1600], &mut [0; 1024]),
                            Err(Error::Security(security::Error::Replay))
                        );
                    }
                }
            }
            assert_eq!(a.next_number(Class::User).0, 20);
            assert_eq!(a.next_feedback_number()?.0, 20);
        }
    }
    Ok(())
}

#[test]
fn compact_short_outputs_and_tampered_routes_do_not_consume_valid_retry() -> Result<()> {
    for protection in [Protection::Aes128Ccm4, Protection::ChaCha20Crc32c] {
        let [mut a, mut b] = compact_peers(cover::Appearance::QuicLike, protection)?;
        let body = b"nonzero compact data";
        let cap = a.capacity_for(Kind::Data, body.len())?;
        let mut short = vec![0x7a; cap.packet_bytes - 1];
        let mut scratch = vec![0x6b; cap.seal_workspace_bytes];
        assert_eq!(
            a.seal(Class::User, outer(0), body, &mut scratch, &mut short),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(short, vec![0x7a; cap.packet_bytes - 1]);
        assert_eq!(a.next_number(Class::User).0, 0);
        let packet = compact_seal(&mut a, Kind::Data, data(), body)?;
        assert_eq!(&packet[..5], &[0, 0, 0, 0, 0]);
        let mut out = vec![0x5a; body.len() - 1];
        assert_eq!(
            b.open(&packet, &mut [0; 1600], &mut out),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(out, vec![0x5a; body.len() - 1]);
        let mut wrong = packet.clone();
        wrong[0] = 0xc0;
        assert_eq!(
            b.open(&wrong, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Malformed)
        );
        wrong[0] = 1;
        assert_eq!(
            b.open(&wrong, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Scope)
        );
        wrong.copy_from_slice(&packet);
        *wrong.last_mut().ok_or("missing check")? ^= 1;
        assert!(b.open(&wrong, &mut [0; 1600], &mut [0; 1024]).is_err());
        assert_eq!(open(&mut b, &packet)?.1, body);
        let feedback = compact_seal(&mut a, Kind::Feedback, data(), b"retire")?;
        let mut forged = feedback.clone();
        forged[5] ^= 1;
        assert!(b.open(&forged, &mut [0; 1600], &mut [0; 1024]).is_err());
        let (opened, bytes) = open(&mut b, &feedback)?;
        assert!(opened.feedback && opened.authenticated);
        assert_eq!(bytes, b"retire");
    }
    Ok(())
}

#[test]
fn compact_reader_slots_follow_scopes_across_wrap_and_preserve_counter_domains() -> Result<()> {
    let [mut a, mut b] = compact_peers(cover::Appearance::MediaLike, Protection::Aes128Ccm4)?;
    let mut old_packet = None;
    for turn in 0..66u8 {
        let old = a.active_data();
        // Epochs may have equal low six bits; selectors are registered slots.
        let next = scope(old.epoch.0 + 64, turn);
        a.stage_data(next)?;
        b.stage_data(next)?;
        a.stage_data(next)?;
        let staged = compact_seal(&mut a, Kind::Data, next, &[turn, 0x7d])?;
        assert_eq!(open(&mut b, &staged)?.0.scope, next);
        let pending_old = compact_seal(&mut a, Kind::Feedback, old, &[turn])?;
        a.activate_data(next)?;
        b.activate_data(next)?;
        assert_eq!(open(&mut b, &pending_old)?.0.scope, old);
        let packet = compact_seal(&mut a, Kind::Data, next, &[turn, 0x55])?;
        assert_eq!(open(&mut b, &packet)?.1, [turn, 0x55]);
        if turn == 0 {
            old_packet = Some(packet);
        }
        a.retire_data(old)?;
        b.retire_data(old)?;
    }
    assert_eq!(a.next_number(Class::User).0, 132);
    assert_eq!(a.next_feedback_number()?.0, 66);
    assert!(
        b.open(
            &old_packet.ok_or("missing old packet")?,
            &mut [0; 1600],
            &mut [0; 1024]
        )
        .is_err()
    );
    let control_packet = compact_seal(&mut a, Kind::Control, control(), b"still alive")?;
    let (opened, bytes) = open(&mut b, &control_packet)?;
    assert_eq!(opened.number.0, 0);
    assert_eq!(bytes, b"still alive");
    Ok(())
}
