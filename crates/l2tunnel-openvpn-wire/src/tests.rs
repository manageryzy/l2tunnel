use super::*;

#[test]
fn actual_reset_ack_and_tls_layout_vectors_preserve_full_ids() -> Result<(), Error> {
    let client = SessionId([1, 2, 3, 4, 5, 6, 7, 8]);
    let server = SessionId([11, 12, 13, 14, 15, 16, 17, 18]);
    let mut out = [0xa5; 128];
    let length = encode_control(
        Opcode::HardResetClientV2,
        0,
        client,
        &[],
        None,
        Some(0),
        &[],
        &mut out,
    )?;
    assert_eq!(
        &out[..length],
        &[0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0]
    );
    assert_eq!(length, 14);
    let length = encode_control(
        Opcode::HardResetServerV2,
        0,
        server,
        &[0],
        Some(client),
        Some(0),
        &[],
        &mut out,
    )?;
    assert_eq!(
        &out[..length],
        &[
            0x40, 11, 12, 13, 14, 15, 16, 17, 18, 1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0
        ]
    );
    assert_eq!(length, 26);
    let length = encode_control(
        Opcode::Ack,
        0,
        client,
        &[0],
        Some(server),
        None,
        &[],
        &mut out,
    )?;
    assert_eq!(length, 22);
    assert_eq!(
        &out[..length],
        &[
            0x28, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 0, 0, 0, 11, 12, 13, 14, 15, 16, 17, 18
        ]
    );
    let tls = [0x16, 3, 3, 0, 3, 0x80, 0, 0];
    let ids = [0x8000_0000, u32::MAX];
    let length = encode_control(
        Opcode::Control,
        7,
        server,
        &ids,
        Some(client),
        Some(u32::MAX),
        &tls,
        &mut out,
    )?;
    let Packet::Control(parsed) = decode(&out[..length])? else {
        return Err(Error::Layout);
    };
    assert_eq!(out[0], 0x27);
    assert_eq!(parsed.acks.iter().collect::<Vec<_>>(), ids);
    assert_eq!(parsed.remote, Some(client));
    assert_eq!(parsed.packet_id, Some(u32::MAX));
    assert_eq!(parsed.payload, tls);
    assert_eq!(out[length], 0xa5);
    Ok(())
}

#[test]
fn conditional_control_headers_and_output_refusals_are_bounded() -> Result<(), Error> {
    let mut packet = [0; 128];
    let length = encode_control(
        Opcode::Control,
        0,
        SessionId([1; 8]),
        &[0, 2],
        Some(SessionId([2; 8])),
        Some(3),
        b"\x16\x03\x03",
        &mut packet,
    )?;
    // Every missing required conditional field, including all four packet-ID
    // octets, is refused. TLS fragment syntax itself belongs to the TLS owner.
    for cut in 0..31 {
        assert!(decode(&packet[..cut]).is_err(), "cut {cut}");
    }
    assert!(decode(&packet[..length]).is_ok());
    let mut out = [0xa5; 128];
    for (acks, remote, id, opcode, body) in [
        (&[1][..], None, Some(1), Opcode::Control, &b"x"[..]),
        (
            &[][..],
            Some(SessionId([2; 8])),
            Some(1),
            Opcode::Control,
            &b"x"[..],
        ),
        (
            &[1][..],
            Some(SessionId([2; 8])),
            Some(1),
            Opcode::Ack,
            &[][..],
        ),
        (&[][..], None, None, Opcode::Ack, &[][..]),
        (&[][..], None, Some(1), Opcode::HardResetClientV2, &b"x"[..]),
    ] {
        assert_eq!(
            encode_control(
                opcode,
                0,
                SessionId([1; 8]),
                acks,
                remote,
                id,
                body,
                &mut out
            ),
            Err(Error::Layout)
        );
        assert_eq!(out, [0xa5; 128]);
    }
    assert_eq!(
        encode_control(
            Opcode::Control,
            0,
            SessionId([1; 8]),
            &[],
            None,
            Some(1),
            b"x",
            &mut out[..14]
        ),
        Err(Error::Output)
    );
    assert_eq!(
        encode_control(
            Opcode::Control,
            8,
            SessionId([1; 8]),
            &[],
            None,
            Some(1),
            b"x",
            &mut out
        ),
        Err(Error::Bounds)
    );
    assert_eq!(out, [0xa5; 128]);
    Ok(())
}

#[test]
fn data_v1_and_v2_are_only_standard_headers_plus_exact_opaque_bytes() -> Result<(), Error> {
    let payload = b"\0\xffnot-L2AR\0\0";
    let mut out = [0xa5; 128];
    for (peer, header) in [
        (None, &[0x30][..]),
        (Some(0x80_00ff), &[0x48, 0x80, 0, 0xff][..]),
    ] {
        let length = encode_data(0, peer, payload, &mut out)?;
        assert_eq!(&out[..header.len()], header);
        assert_eq!(&out[header.len()..length], payload);
        assert_eq!(
            decode(&out[..length])?,
            Packet::Data {
                key_id: 0,
                peer_id: peer,
                payload
            }
        );
    }
    let before = out;
    assert_eq!(
        encode_data(0, Some(0x100_0000), payload, &mut out),
        Err(Error::Bounds)
    );
    assert_eq!(
        encode_data(0, None, payload, &mut out[..1]),
        Err(Error::Output)
    );
    assert_eq!(encode_data(0, None, &[], &mut out), Err(Error::Layout));
    assert_eq!(out, before);
    assert!(decode(&[0x48, 0, 0]).is_err());
    Ok(())
}
