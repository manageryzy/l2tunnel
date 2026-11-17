//! Carrier route separation and single Records protection of external metadata.
use super::*;
use l2tunnel::secure_record::compact::{Kind, Layout, Selection};
use security::compact::Protection;

fn peers(protection: Protection) -> Result<[Records; 2]> {
    let (a, b) = covers(cover::Appearance::QuicLike)?;
    let make = |role, cover| -> Result<Records> {
        Ok(Records::new_compact_with_layout(
            root(role)?,
            security::LaneId(7),
            limits(),
            cover,
            control(),
            data(),
            Selection {
                protection,
                limits: security::compact::Selection {
                    max_forward_packets: 4096,
                    max_failed_checks: 128,
                },
            },
            Layout::Carrier,
        )?)
    };
    Ok([
        make(security::Role::Initiator, a)?,
        make(security::Role::Responder, b)?,
    ])
}

fn seal(
    sender: &mut Records,
    kind: Kind,
    scope: Scope,
    aad: &[u8],
    body: &[u8],
) -> Result<Vec<u8>> {
    let capacity = sender.capacity_for(kind, body.len())?;
    let mut workspace = vec![0; capacity.seal_workspace_bytes];
    let mut output = vec![0; capacity.packet_bytes];
    let sealed = sender.seal_compact_with_carrier(
        kind,
        scope,
        outer(0),
        body,
        aad,
        &mut workspace,
        &mut output,
    )?;
    assert_eq!(sealed.bytes, output.len());
    Ok(output)
}

#[test]
fn compact_carrier_all_routes_and_external_metadata_are_bound_without_extra_wire_bytes()
-> Result<()> {
    for protection in [Protection::Aes128Ccm4, Protection::ChaCha20Crc32c] {
        let [mut a, mut b] = peers(protection)?;
        let aad = [0x52; 49];
        for (kind, route, scope) in [
            (Kind::Data, 0x80, data()),
            (Kind::Feedback, 0xc0, data()),
            (Kind::AuthenticatedData, 2, data()),
            (Kind::Control, 0, control()),
            (Kind::CarrierControl, 1, control()),
        ] {
            let packet = seal(&mut a, kind, scope, &aad, b"exact-payload")?;
            assert_eq!(packet[0], route);
            assert_eq!(Layout::Carrier.kind(route)?, kind);
            assert_eq!(
                packet.len(),
                b"exact-payload".len() + if kind == Kind::Data { 9 } else { 21 }
            );
            let mut workspace = [0; 1600];
            let mut plaintext = [0; 1024];
            for index in [0, 31, 32, 33, 34, 35, 39, 43, 45, 47, 48] {
                let mut altered = aad;
                altered[index] ^= 1;
                assert!(
                    b.open_compact_with_carrier(&packet, &altered, &mut workspace, &mut plaintext)
                        .is_err()
                );
            }
            assert!(
                b.open_compact_with_carrier(&packet, &[], &mut workspace, &mut plaintext)
                    .is_err()
            );
            let opened =
                b.open_compact_with_carrier(&packet, &aad, &mut workspace, &mut plaintext)?;
            assert_eq!(&plaintext[..opened.bytes], b"exact-payload");
            assert_eq!(
                opened.authenticated,
                kind != Kind::Data || protection == Protection::Aes128Ccm4
            );
            assert_eq!(
                b.open_compact_with_carrier(&packet, &aad, &mut workspace, &mut plaintext),
                Err(Error::Security(security::Error::Replay))
            );
        }
        // Management and raw carrier controls share exactly one strong counter.
        assert_eq!(a.next_number(Class::Control).0, 2);
        assert_eq!(a.next_number(Class::User).0, 1);
        assert_eq!(a.next_feedback_number().0, 2);
    }
    Ok(())
}

#[test]
fn compact_carrier_route_relabeling_cannot_cross_management_authority_or_reader_slots() -> Result<()>
{
    let [mut a, mut b] = peers(Protection::Aes128Ccm4)?;
    let aad = b"original raw metadata";
    let control_packet = seal(&mut a, Kind::Control, control(), aad, b"control")?;
    let mut changed = control_packet.clone();
    changed[0] = 1;
    assert!(
        b.open_compact_with_carrier(&changed, aad, &mut [0; 1600], &mut [0; 1024])
            .is_err()
    );
    b.open_compact_with_carrier(&control_packet, aad, &mut [0; 1600], &mut [0; 1024])?;
    for index in 1..=65u8 {
        let old = a.active_data();
        let next = scope(old.epoch.0 + 1, index);
        a.stage_data(next)?;
        b.stage_data(next)?;
        let packet = seal(&mut a, Kind::Data, next, aad, &[index])?;
        assert_eq!(packet[0], 0x80 | (index & 63));
        b.open_compact_with_carrier(&packet, aad, &mut [0; 1600], &mut [0; 1024])?;
        let strong = seal(&mut a, Kind::AuthenticatedData, next, aad, &[index])?;
        let slot = index & 63;
        assert_eq!(strong[0], if slot < 22 { 2 + slot } else { 58 + slot });
        assert!(
            !(24..=79).contains(&strong[0]),
            "all carrier bootstrap prefixes remain disjoint"
        );
        b.open_compact_with_carrier(&strong, aad, &mut [0; 1600], &mut [0; 1024])?;
        a.activate_data(next)?;
        b.activate_data(next)?;
        a.retire_data(old)?;
        b.retire_data(old)?;
    }
    for byte in (24..80).chain(122..128) {
        assert!(Layout::Carrier.kind(byte).is_err());
    }
    assert_eq!(Layout::Carrier.kind(23)?, Kind::AuthenticatedData);
    assert_eq!(Layout::Carrier.kind(80)?, Kind::AuthenticatedData);
    assert_eq!(Layout::Carrier.kind(121)?, Kind::AuthenticatedData);
    Ok(())
}
