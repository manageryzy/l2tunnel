use super::*;
use std::{vec, vec::Vec};

const A_ID: ConnectionId = ConnectionId([0x11; 8]);
const B_ID: ConnectionId = ConnectionId([0x22; 8]);
const A_SSRC: Ssrc = Ssrc(0x1122_3344);
const B_SSRC: Ssrc = Ssrc(0x5566_7788);

fn peers(appearance: Appearance, limits: Limits) -> Result<(Config, Config), Error> {
    let a = Config::new(
        appearance,
        ConnectionIds {
            local: A_ID,
            peer: B_ID,
        },
        MediaConfig {
            local_ssrc: A_SSRC,
            peer_ssrc: B_SSRC,
            payload_type: 96,
        },
        limits,
    )?;
    let b = Config::new(
        appearance,
        ConnectionIds {
            local: B_ID,
            peer: A_ID,
        },
        MediaConfig {
            local_ssrc: B_SSRC,
            peer_ssrc: A_SSRC,
            payload_type: 96,
        },
        limits,
    )?;
    Ok((a, b))
}

fn fixture(appearance: Appearance) -> Result<(Config, Config), Error> {
    peers(
        appearance,
        Limits {
            max_packet_bytes: 1280,
            max_protected_bytes: 1200,
        },
    )
}

fn meta(phase: Phase) -> PacketMeta {
    PacketMeta {
        phase,
        packet_number: PacketNumber(0x1234_5678),
        media_timestamp: MediaTimestamp(0x90ab_cdef),
    }
}

fn encoded(config: Config, phase: Phase, body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = vec![0xa5; config.limits().max_packet_bytes];
    let length = config.encode(meta(phase), body, &mut output)?;
    output.truncate(length);
    Ok(output)
}

#[test]
fn retained_outgoing_validation_keeps_direction_and_exact_grammar() -> Result<(), Error> {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let (a, b) = fixture(appearance)?;
        for phase in [Phase::Handshake, Phase::Established] {
            for (sender, peer) in [(a, b), (b, a)] {
                let mut packet = encoded(sender, phase, &[0x31, 0, 0xa4])?;
                assert_eq!(sender.decode_outgoing(&packet)?, peer.decode(&packet)?);
                assert_eq!(sender.decode(&packet), Err(Error::IdentifierMismatch));
                assert_eq!(
                    peer.decode_outgoing(&packet),
                    Err(Error::IdentifierMismatch)
                );
                let identifier = match (appearance, phase) {
                    (Appearance::QuicLike, Phase::Handshake) => 6,
                    (Appearance::QuicLike, Phase::Established) => 1,
                    (Appearance::MediaLike, _) => 8,
                };
                packet[identifier] ^= 1;
                assert_eq!(
                    sender.decode_outgoing(&packet),
                    Err(Error::IdentifierMismatch)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn exact_quic_initial_wire_and_borrowed_zero_tail() -> Result<(), Error> {
    let (a, b) = fixture(Appearance::QuicLike)?;
    let body = [0xa5, 0, 0];
    let packet = encoded(a, Phase::Handshake, &body)?;
    let expected = [
        0xc3, 0, 0, 0, 1, 8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 8, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0, 7, 0x12, 0x34, 0x56, 0x78, 0xa5, 0, 0,
    ];
    assert_eq!(packet, expected);
    let decoded = b.decode(&packet)?;
    assert_eq!(decoded.protected, body);
    assert_eq!(decoded.protected.as_ptr(), packet[29..].as_ptr());
    assert_eq!(decoded.phase, Phase::Handshake);
    assert_eq!(
        decoded.sequence,
        OuterSequence::Quic(meta(Phase::Handshake).packet_number)
    );
    assert_eq!(decoded.media_timestamp, None);
    Ok(())
}

#[test]
fn exact_quic_established_wire() -> Result<(), Error> {
    let (a, b) = fixture(Appearance::QuicLike)?;
    let body = [0, 0x90, 0];
    let packet = encoded(a, Phase::Established, &body)?;
    assert_eq!(
        packet,
        [
            0x43, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x12, 0x34, 0x56, 0x78, 0, 0x90,
            0,
        ]
    );
    assert_eq!(b.decode(&packet)?.protected, body);
    assert_eq!(a.overhead(Phase::Established, body.len())?, 13);
    Ok(())
}

#[test]
fn exact_media_wire_and_private_body_length() -> Result<(), Error> {
    let (a, b) = fixture(Appearance::MediaLike)?;
    for phase in [Phase::Handshake, Phase::Established] {
        let packet = encoded(a, phase, &[0xa5, 0, 0])?;
        let marker = if phase == Phase::Handshake {
            0xe0
        } else {
            0x60
        };
        assert_eq!(
            packet,
            [
                0x80, marker, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0, 3,
                0xa5, 0, 0,
            ]
        );
        let decoded = b.decode(&packet)?;
        assert_eq!(decoded.phase, phase);
        assert_eq!(decoded.sequence, OuterSequence::Media(0x5678));
        assert_eq!(decoded.media_timestamp, Some(MediaTimestamp(0x90ab_cdef)));
        assert_eq!(decoded.protected, &[0xa5, 0, 0]);
        assert_eq!(
            decoded.protected.as_ptr(),
            packet[MEDIA_OVERHEAD..].as_ptr()
        );
    }
    Ok(())
}

#[test]
fn both_appearances_directions_and_phases_preserve_arbitrary_bytes() -> Result<(), Error> {
    let bodies = [
        vec![0],
        vec![0; 1200],
        vec![0xff, 0, 0x80, 0, 0],
        (0..1033).map(|n| (n % 256) as u8).collect(),
    ];
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let (a, b) = fixture(appearance)?;
        assert_eq!(a.appearance(), appearance);
        for (sender, receiver) in [(a, b), (b, a)] {
            for phase in [Phase::Handshake, Phase::Established] {
                for body in &bodies {
                    let packet = encoded(sender, phase, body)?;
                    assert_eq!(
                        packet.len(),
                        sender.overhead(phase, body.len())? + body.len()
                    );
                    let decoded = receiver.decode(&packet)?;
                    assert_eq!(decoded.phase, phase);
                    assert_eq!(decoded.protected, body);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn canonical_quic_varint_thresholds_and_exact_overhead() -> Result<(), Error> {
    let (a, b) = peers(
        Appearance::QuicLike,
        Limits {
            max_packet_bytes: 20_032,
            max_protected_bytes: 20_000,
        },
    )?;
    for (length, header, encoded_length) in [
        (1, 29, &[5_u8][..]),
        (59, 29, &[63][..]),
        (60, 30, &[0x40, 0x40][..]),
        (16_379, 30, &[0x7f, 0xff][..]),
        (16_380, 32, &[0x80, 0, 0x40, 0][..]),
        (20_000, 32, &[0x80, 0, 0x4e, 0x24][..]),
    ] {
        let body = vec![0; length];
        let packet = encoded(a, Phase::Handshake, &body)?;
        assert_eq!(a.overhead(Phase::Handshake, length)?, header);
        assert_eq!(&packet[24..24 + encoded_length.len()], encoded_length);
        assert_eq!(b.decode(&packet)?.protected, body);
    }
    Ok(())
}

#[test]
fn largest_supported_packets_fit_exactly() -> Result<(), Error> {
    for (appearance, overhead) in [(Appearance::QuicLike, 32), (Appearance::MediaLike, 14)] {
        let length = MAX_PACKET_BYTES - overhead;
        let (a, b) = peers(
            appearance,
            Limits {
                max_packet_bytes: MAX_PACKET_BYTES,
                max_protected_bytes: length,
            },
        )?;
        let body = vec![0; length];
        let packet = encoded(a, Phase::Handshake, &body)?;
        assert_eq!(packet.len(), MAX_PACKET_BYTES);
        assert_eq!(b.decode(&packet)?.protected, body);
    }
    Ok(())
}

#[test]
fn smallest_configured_packet_and_outer_number_extremes_round_trip() -> Result<(), Error> {
    for (appearance, overhead) in [(Appearance::QuicLike, 29), (Appearance::MediaLike, 14)] {
        let (a, b) = peers(
            appearance,
            Limits {
                max_packet_bytes: overhead + 1,
                max_protected_bytes: 1,
            },
        )?;
        for phase in [Phase::Handshake, Phase::Established] {
            for number in [0, u32::MAX] {
                let mut output = [0; 30];
                let length = a.encode(
                    PacketMeta {
                        packet_number: PacketNumber(number),
                        ..meta(phase)
                    },
                    &[0],
                    &mut output,
                )?;
                let decoded = b.decode(&output[..length])?;
                assert_eq!(decoded.protected, &[0]);
                let expected = match appearance {
                    Appearance::QuicLike => OuterSequence::Quic(PacketNumber(number)),
                    Appearance::MediaLike => OuterSequence::Media(number as u16),
                };
                assert_eq!(decoded.sequence, expected);
            }
        }
    }
    Ok(())
}

#[test]
fn every_length_delimited_packet_prefix_and_trailing_byte_is_rejected() -> Result<(), Error> {
    for (appearance, phase) in [
        (Appearance::QuicLike, Phase::Handshake),
        (Appearance::MediaLike, Phase::Handshake),
        (Appearance::MediaLike, Phase::Established),
    ] {
        let (a, b) = fixture(appearance)?;
        for body in [&[0_u8][..], &[1, 0, 2, 0][..], &[0_u8; 1200][..]] {
            let mut packet = encoded(a, phase, body)?;
            for end in 0..packet.len() {
                assert!(b.decode(&packet[..end]).is_err(), "accepted prefix {end}");
            }
            packet.push(0);
            assert_eq!(b.decode(&packet), Err(Error::Malformed));
        }
    }
    Ok(())
}

#[test]
fn short_quic_header_truncation_and_inner_authentication_boundary() -> Result<(), Error> {
    let (a, b) = fixture(Appearance::QuicLike)?;
    let mut packet = encoded(a, Phase::Established, &[1, 2, 0, 0])?;
    for end in 0..=QUIC_ESTABLISHED_OVERHEAD {
        assert!(b.decode(&packet[..end]).is_err());
    }
    // Short QUIC headers have no declared payload length. This is structurally
    // another packet; only the independently authenticated body can reject it.
    packet.pop();
    assert_eq!(b.decode(&packet)?.protected, &[1, 2, 0]);
    packet.push(0x70);
    assert_eq!(b.decode(&packet)?.protected, &[1, 2, 0, 0x70]);
    Ok(())
}

#[test]
fn wrong_directional_ids_and_media_sources_are_rejected() -> Result<(), Error> {
    for phase in [Phase::Handshake, Phase::Established] {
        let (a, b) = fixture(Appearance::QuicLike)?;
        let packet = encoded(a, phase, &[1])?;
        assert_eq!(a.decode(&packet), Err(Error::IdentifierMismatch));
        let indices = if phase == Phase::Handshake {
            &[6, 15][..]
        } else {
            &[1][..]
        };
        for &index in indices {
            let mut forged = packet.clone();
            forged[index] ^= 1;
            assert_eq!(b.decode(&forged), Err(Error::IdentifierMismatch));
        }
    }
    let (a, b) = fixture(Appearance::MediaLike)?;
    let mut packet = encoded(a, Phase::Established, &[1])?;
    assert_eq!(a.decode(&packet), Err(Error::IdentifierMismatch));
    packet[8] ^= 1;
    assert_eq!(b.decode(&packet), Err(Error::IdentifierMismatch));
    Ok(())
}

#[test]
fn quic_flags_version_id_widths_and_tokens_are_strict() -> Result<(), Error> {
    let (a, b) = fixture(Appearance::QuicLike)?;
    let initial = encoded(a, Phase::Handshake, &[1, 0])?;
    for (offset, value) in [
        (0, 0xc0),
        (0, 0xc2),
        (0, 0xe3),
        (0, 0x83),
        (1, 1),
        (4, 2),
        (5, 7),
        (14, 9),
        (23, 1),
    ] {
        let mut forged = initial.clone();
        forged[offset] = value;
        assert_eq!(b.decode(&forged), Err(Error::Malformed));
    }
    let short = encoded(a, Phase::Established, &[1])?;
    for first in [0, 0x40, 0x42, 0x47, 0x63, 0x7f] {
        let mut forged = short.clone();
        forged[0] = first;
        assert_eq!(b.decode(&forged), Err(Error::Malformed));
    }
    Ok(())
}

#[test]
fn noncanonical_quic_lengths_and_declared_payload_mismatches_are_rejected() -> Result<(), Error> {
    let (a, b) = fixture(Appearance::QuicLike)?;
    let packet = encoded(a, Phase::Handshake, &[1, 0])?;
    for replacement in [
        &[0x40, 6][..],
        &[0x80, 0, 0, 6][..],
        &[0xc0, 0, 0, 0, 0, 0, 0, 6][..],
    ] {
        let mut forged = packet[..24].to_vec();
        forged.extend_from_slice(replacement);
        forged.extend_from_slice(&packet[25..]);
        assert_eq!(b.decode(&forged), Err(Error::Malformed));
    }
    for value in [0, 4, 5, 7, 63] {
        let mut forged = packet.clone();
        forged[24] = value;
        assert_eq!(b.decode(&forged), Err(Error::Malformed));
    }
    let mut missing_varint = packet[..24].to_vec();
    missing_varint.push(0x40);
    assert_eq!(b.decode(&missing_varint), Err(Error::Truncated));
    Ok(())
}

#[test]
fn media_version_extensions_padding_payload_type_and_lengths_are_strict() -> Result<(), Error> {
    let (a, b) = fixture(Appearance::MediaLike)?;
    let packet = encoded(a, Phase::Established, &[1, 0])?;
    for (offset, value) in [
        (0, 0x40),
        (0, 0xc0),
        (0, 0xa0),
        (0, 0x90),
        (0, 0x81),
        (1, 97),
        (12, 1),
        (13, 0),
        (13, 1),
        (13, 3),
    ] {
        let mut forged = packet.clone();
        forged[offset] = value;
        assert_eq!(b.decode(&forged), Err(Error::Malformed));
    }
    Ok(())
}

#[test]
fn empty_received_bodies_and_cross_appearance_packets_are_rejected() -> Result<(), Error> {
    let (quic_a, quic_b) = fixture(Appearance::QuicLike)?;
    let (media_a, media_b) = fixture(Appearance::MediaLike)?;
    let quic_packet = encoded(quic_a, Phase::Handshake, &[0])?;
    let media_packet = encoded(media_a, Phase::Handshake, &[0])?;
    assert_eq!(quic_b.decode(&media_packet), Err(Error::Malformed));
    assert_eq!(media_b.decode(&quic_packet), Err(Error::Malformed));

    let mut initial_empty = quic_packet[..29].to_vec();
    initial_empty[24] = 4;
    assert_eq!(quic_b.decode(&initial_empty), Err(Error::Malformed));

    let short = encoded(quic_a, Phase::Established, &[0])?;
    assert_eq!(
        quic_b.decode(&short[..QUIC_ESTABLISHED_OVERHEAD]),
        Err(Error::EmptyPayload)
    );

    let mut media_empty = media_packet[..MEDIA_OVERHEAD].to_vec();
    media_empty[12..14].fill(0);
    assert_eq!(media_b.decode(&media_empty), Err(Error::EmptyPayload));
    Ok(())
}

#[test]
fn supplied_media_sequence_and_timestamp_wrap_are_not_inferred() -> Result<(), Error> {
    let (a, b) = fixture(Appearance::MediaLike)?;
    let mut output = [0; 1280];
    for (number, timestamp) in [(65_535, u32::MAX), (65_536, 0), (u32::MAX, 9)] {
        let length = a.encode(
            PacketMeta {
                phase: Phase::Established,
                packet_number: PacketNumber(number),
                media_timestamp: MediaTimestamp(timestamp),
            },
            &[0],
            &mut output,
        )?;
        let decoded = b.decode(&output[..length])?;
        assert_eq!(decoded.sequence, OuterSequence::Media(number as u16));
        assert_eq!(decoded.media_timestamp, Some(MediaTimestamp(timestamp)));
    }
    Ok(())
}

#[test]
fn configuration_rejects_zero_overflow_and_inconsistent_bounds() -> Result<(), Error> {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        for limits in [
            Limits {
                max_packet_bytes: 1280,
                max_protected_bytes: 0,
            },
            Limits {
                max_packet_bytes: 1280,
                max_protected_bytes: usize::from(u16::MAX) + 1,
            },
            Limits {
                max_packet_bytes: MAX_PACKET_BYTES + 1,
                max_protected_bytes: 100,
            },
            Limits {
                max_packet_bytes: 100,
                max_protected_bytes: 100,
            },
            Limits {
                max_packet_bytes: 0,
                max_protected_bytes: 1,
            },
        ] {
            assert_eq!(peers(appearance, limits), Err(Error::Configuration));
        }
        let (a, _) = fixture(appearance)?;
        let invalid_pt = MediaConfig {
            payload_type: 128,
            ..a.media
        };
        assert_eq!(
            Config::new(appearance, a.ids, invalid_pt, a.limits),
            Err(Error::Configuration)
        );
        assert_eq!(a.overhead(Phase::Handshake, 0), Err(Error::EmptyPayload));
        assert_eq!(
            a.overhead(Phase::Handshake, 1201),
            Err(Error::PayloadTooLarge)
        );
    }
    Ok(())
}

#[test]
fn zero_identifiers_and_ssrcs_are_structural_not_identity_claims() -> Result<(), Error> {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let config = Config::new(
            appearance,
            ConnectionIds {
                local: ConnectionId([0; 8]),
                peer: ConnectionId([0; 8]),
            },
            MediaConfig {
                local_ssrc: Ssrc(0),
                peer_ssrc: Ssrc(0),
                payload_type: 0,
            },
            Limits {
                max_packet_bytes: 1280,
                max_protected_bytes: 1200,
            },
        )?;
        let packet = encoded(config, Phase::Handshake, &[0])?;
        assert_eq!(config.decode(&packet)?.protected, &[0]);
    }
    Ok(())
}

#[test]
fn failed_encoding_never_changes_caller_storage() -> Result<(), Error> {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let (a, _) = fixture(appearance)?;
        for phase in [Phase::Handshake, Phase::Established] {
            let mut output = [0x6b; 1280];
            let snapshot = output;
            assert_eq!(
                a.encode(meta(phase), &[], &mut output),
                Err(Error::EmptyPayload)
            );
            assert_eq!(output, snapshot);
            assert_eq!(
                a.encode(meta(phase), &[0; 1201], &mut output),
                Err(Error::PayloadTooLarge)
            );
            assert_eq!(output, snapshot);
            let needed = a.overhead(phase, 4)? + 4;
            assert_eq!(
                a.encode(meta(phase), &[1, 2, 0, 0], &mut output[..needed - 1]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!(output, snapshot);
            let length = a.encode(meta(phase), &[1, 2, 0, 0], &mut output[..needed])?;
            assert_eq!(length, needed);
            assert!(output[needed..].iter().all(|byte| *byte == 0x6b));
        }
    }
    Ok(())
}

#[test]
fn receive_limits_apply_to_complete_packets_and_protected_bodies() -> Result<(), Error> {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let (a, b) = fixture(appearance)?;
        assert_eq!(b.decode(&[0; 1281]), Err(Error::PacketTooLarge));
        let mut packet = encoded(a, Phase::Established, &[0; 1200])?;
        packet.push(0);
        if appearance == Appearance::MediaLike {
            packet[12..14].copy_from_slice(&1201_u16.to_be_bytes());
        }
        assert_eq!(b.decode(&packet), Err(Error::PayloadTooLarge));
    }
    Ok(())
}

#[test]
fn accepted_outer_metadata_is_not_a_replay_or_authentication_decision() -> Result<(), Error> {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let (a, b) = fixture(appearance)?;
        let mut packet = encoded(a, Phase::Established, &[1, 0, 0])?;
        let first_sequence = {
            let first = b.decode(&packet)?;
            assert_eq!(b.decode(&packet)?, first); // This codec deliberately has no replay state.
            first.sequence
        };
        let number_at = if appearance == Appearance::QuicLike {
            9
        } else {
            2
        };
        packet[number_at] ^= 1;
        let changed = b.decode(&packet)?;
        assert_ne!(changed.sequence, first_sequence);
        assert_eq!(changed.protected, &[1, 0, 0]);
    }
    Ok(())
}

#[test]
fn bounded_parser_noise_is_rejected_without_panics() -> Result<(), Error> {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let (_, receiver) = fixture(appearance)?;
        let mut input = [0; 160];
        for first in 0..=u8::MAX {
            input.fill(first);
            for end in 0..=input.len() {
                assert!(receiver.decode(&input[..end]).is_err());
            }
        }
    }
    Ok(())
}
