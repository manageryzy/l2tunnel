use super::*;

fn header() -> Header {
    Header {
        kind: MessageKind::Prepare,
        sender: Role::Client,
        lane: LaneId(3),
        session: SessionId([7; 16]),
        packet: PacketNumber(1),
        request: RequestId(1),
        source_epoch: Epoch(4),
        ticket: Ticket {
            epoch: Epoch(5),
            attempt: 9,
            digest: ConfigDigest([11; 32]),
        },
        source: EndpointId(12),
        destination: EndpointId(13),
    }
}

fn bytes(header: Header, body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = vec![0; HEADER_LEN + body.len()];
    Frame { header, body }.encode(&mut output, Limits::default())?;
    Ok(output)
}

fn binding() -> SessionBinding {
    let h = header();
    SessionBinding {
        session: h.session,
        remote_role: h.sender,
        remote_endpoint: h.source,
        local_endpoint: h.destination,
    }
}

fn ingress(lane: LaneId) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: header().session,
        lane,
        sender: header().sender,
    }
}

#[test]
fn golden_frame_and_nonzero_payload_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let literal = concat!(
        "4c324d43010302000000007401020304",
        "000102030405060708090a0b0c0d0e0f",
        "01020304050607081112131415161718",
        "21222324252627283132333435363738",
        "4142434445464748",
        "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f",
        "7172737481828384deadbeef"
    );
    let golden: Result<Vec<_>, _> = (0..literal.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&literal[i..i + 2], 16))
        .collect();
    let golden = golden?;
    let decoded = Frame::decode(&golden, Limits::default())?;
    assert_eq!(decoded.header.kind, MessageKind::Barrier);
    assert_eq!(decoded.header.sender, Role::Server);
    assert_eq!(decoded.header.lane, LaneId(0x01020304));
    assert_eq!(decoded.header.packet, PacketNumber(0x0102030405060708));
    assert_eq!(decoded.header.request, RequestId(0x1112131415161718));
    assert_eq!(decoded.header.source_epoch, Epoch(0x2122232425262728));
    assert_eq!(decoded.header.ticket.epoch, Epoch(0x3132333435363738));
    assert_eq!(decoded.header.ticket.attempt, 0x4142434445464748);
    assert_eq!(decoded.header.source, EndpointId(0x71727374));
    assert_eq!(decoded.header.destination, EndpointId(0x81828384));
    assert_eq!(decoded.body, &[0xde, 0xad, 0xbe, 0xef]);
    let mut output = vec![0xaa; golden.len() + 3];
    assert_eq!(
        decoded.encode(&mut output, Limits::default())?,
        golden.len()
    );
    assert_eq!(&output[..golden.len()], golden.as_slice());
    assert_eq!(&output[golden.len()..], &[0xaa; 3]);
    for size in [0, 1, 128, 16_384 - HEADER_LEN] {
        let body: Vec<_> = (0_u8..=255).cycle().take(size).collect();
        let encoded = bytes(header(), &body)?;
        assert_eq!(Frame::decode(&encoded, Limits::default())?.body, body);
    }
    Ok(())
}

#[test]
fn malformed_and_bounded_codec_inputs_fail_without_output_mutation() -> Result<(), Error> {
    let good = bytes(header(), &[1, 2, 3])?;
    for len in 0..HEADER_LEN {
        assert_eq!(
            Frame::decode(&good[..len], Limits::default()),
            Err(Error::Truncated)
        );
    }
    for (offset, value, error) in [
        (0, 0, Error::WrongDiscriminator),
        (4, 2, Error::UnsupportedVersion),
        (5, 0, Error::UnknownKind),
        (6, 0, Error::UnknownRole),
        (7, 1, Error::ReservedBits),
        (8, 255, Error::LengthMismatch),
    ] {
        let mut bad = good.clone();
        bad[offset] = value;
        assert_eq!(Frame::decode(&bad, Limits::default()), Err(error));
    }
    assert_eq!(
        Frame::decode(&good[..HEADER_LEN], Limits::default()),
        Err(Error::LengthMismatch)
    );
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        Frame::decode(&trailing, Limits::default()),
        Err(Error::LengthMismatch)
    );
    let small = Limits {
        max_frame_bytes: HEADER_LEN,
        ..Limits::default()
    };
    assert_eq!(Frame::decode(&good, small), Err(Error::FrameTooLarge));
    let frame = Frame {
        header: header(),
        body: &[1, 2, 3],
    };
    let mut output = [0xbb; HEADER_LEN];
    assert_eq!(
        frame.encode(&mut output, Limits::default()),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(output, [0xbb; HEADER_LEN]);
    assert_eq!(frame.encode(&mut output, small), Err(Error::FrameTooLarge));
    assert_eq!(output, [0xbb; HEADER_LEN]);
    for limits in [
        Limits {
            max_frame_bytes: HEADER_LEN - 1,
            ..Limits::default()
        },
        Limits {
            max_frame_bytes: 65_537,
            ..Limits::default()
        },
        Limits {
            max_requests: 0,
            ..Limits::default()
        },
        Limits {
            max_requests: 1_025,
            ..Limits::default()
        },
        Limits {
            max_retained_bytes: HEADER_LEN - 1,
            ..Limits::default()
        },
        Limits {
            max_retained_bytes: usize::MAX,
            ..Limits::default()
        },
    ] {
        assert_eq!(Frame::decode(&good, limits), Err(Error::InvalidLimits));
        assert!(matches!(
            AdmissionGate::new(binding(), limits),
            Err(Error::InvalidLimits)
        ));
    }
    Ok(())
}

#[test]
fn user_spoofs_and_binding_mismatches_cannot_mutate_admission() -> Result<(), Error> {
    let mut gate = AdmissionGate::new(binding(), Limits::default())?;
    let good = bytes(header(), &[1])?;
    for origin in [Ingress::UserTraffic, Ingress::Unauthenticated] {
        assert_eq!(gate.admit(origin, &good), Err(Error::UntrustedOrigin));
        assert_eq!(gate.admit(origin, &[]), Err(Error::UntrustedOrigin));
    }
    for offset in [6, 12, 16, 104, 108] {
        let mut wrong = good.clone();
        wrong[offset] = if offset == 6 { 2 } else { 255 };
        assert_eq!(
            gate.admit(ingress(header().lane), &wrong),
            Err(Error::BindingMismatch)
        );
    }
    for origin in [
        ingress(LaneId(99)),
        Ingress::AuthenticatedManagement {
            session: SessionId([0; 16]),
            lane: header().lane,
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: header().session,
            lane: header().lane,
            sender: Role::Server,
        },
    ] {
        assert_eq!(gate.admit(origin, &good), Err(Error::BindingMismatch));
    }
    assert_eq!(gate.retained_requests(), 0);
    assert_eq!(gate.highest_packet(), None);
    assert_eq!(
        gate.admit(ingress(header().lane), &good)?.admission,
        Admission::NewRequest
    );
    Ok(())
}

#[test]
fn request_retries_are_distinct_from_packet_replay_and_conflicting_content() -> Result<(), Error> {
    let mut gate = AdmissionGate::new(binding(), Limits::default())?;
    let first = bytes(header(), &[1, 2])?;
    assert_eq!(
        gate.admit(ingress(header().lane), &first)?.admission,
        Admission::NewRequest
    );
    assert_eq!(
        gate.admit(ingress(header().lane), &first),
        Err(Error::PacketReplay)
    );
    let retried = Header {
        packet: PacketNumber(2),
        lane: LaneId(8),
        ..header()
    };
    let retry = bytes(retried, &[1, 2])?;
    assert_eq!(
        gate.admit(ingress(retried.lane), &retry)?.admission,
        Admission::RepeatedRequest
    );
    let next = Header {
        packet: PacketNumber(3),
        ..header()
    };
    let mut conflicts = vec![bytes(next, &[1, 3])?];
    for altered in [
        Header {
            kind: MessageKind::Commit,
            ..next
        },
        Header {
            source_epoch: Epoch(3),
            ..next
        },
        Header {
            ticket: Ticket {
                attempt: 10,
                ..next.ticket
            },
            ..next
        },
        Header {
            ticket: Ticket {
                epoch: Epoch(6),
                ..next.ticket
            },
            ..next
        },
        Header {
            ticket: Ticket {
                digest: ConfigDigest([0; 32]),
                ..next.ticket
            },
            ..next
        },
    ] {
        conflicts.push(bytes(altered, &[1, 2])?);
    }
    for conflict in conflicts {
        assert_eq!(
            gate.admit(ingress(next.lane), &conflict),
            Err(Error::RequestConflict)
        );
        assert_eq!(gate.highest_packet(), Some(PacketNumber(2)));
    }
    let retry = bytes(next, &[1, 2])?;
    assert_eq!(
        gate.admit(ingress(next.lane), &retry)?.admission,
        Admission::RepeatedRequest
    );
    assert_eq!(gate.retained_requests(), 1);
    assert_eq!(gate.retained_bytes(), HEADER_LEN + 2);
    Ok(())
}

#[test]
fn replay_window_edges_reordering_jumps_and_exhaustion_do_not_wrap() -> Result<(), Error> {
    let mut gate = AdmissionGate::new(binding(), Limits::default())?;
    for (packet, result) in [
        (128, Ok(Admission::NewRequest)),
        (1, Ok(Admission::RepeatedRequest)),
        (0, Err(Error::PacketTooOld)),
        (127, Ok(Admission::RepeatedRequest)),
        (1, Err(Error::PacketReplay)),
        (256, Ok(Admission::RepeatedRequest)),
        (128, Err(Error::PacketTooOld)),
        (u64::MAX, Ok(Admission::RepeatedRequest)),
        (u64::MAX - 127, Ok(Admission::RepeatedRequest)),
        (u64::MAX - 128, Err(Error::PacketTooOld)),
        (u64::MAX, Err(Error::PacketReplay)),
        (0, Err(Error::PacketTooOld)),
    ] {
        let encoded = bytes(
            Header {
                packet: PacketNumber(packet),
                ..header()
            },
            &[],
        )?;
        assert_eq!(
            gate.admit(ingress(header().lane), &encoded)
                .map(|r| r.admission),
            result
        );
    }
    Ok(())
}

#[test]
fn full_ledger_allows_exact_retry_and_failed_admission_does_not_consume_packet() -> Result<(), Error>
{
    for limits in [
        Limits {
            max_requests: 1,
            ..Limits::default()
        },
        Limits {
            max_retained_bytes: HEADER_LEN + 2,
            ..Limits::default()
        },
    ] {
        let mut gate = AdmissionGate::new(binding(), limits)?;
        let first = bytes(header(), &[1, 2])?;
        gate.admit(ingress(header().lane), &first)?;
        let new_header = Header {
            request: RequestId(2),
            packet: PacketNumber(200),
            ..header()
        };
        let new_request = bytes(new_header, &[])?;
        assert_eq!(
            gate.admit(ingress(new_header.lane), &new_request),
            Err(Error::Capacity)
        );
        assert_eq!(gate.highest_packet(), Some(PacketNumber(1)));
        let retry_header = Header {
            packet: new_header.packet,
            ..header()
        };
        let retry = bytes(retry_header, &[1, 2])?;
        assert_eq!(
            gate.admit(ingress(retry_header.lane), &retry)?.admission,
            Admission::RepeatedRequest
        );
        assert_eq!(gate.retained_requests(), 1);
        assert_eq!(gate.retained_bytes(), HEADER_LEN + 2);
    }
    Ok(())
}
