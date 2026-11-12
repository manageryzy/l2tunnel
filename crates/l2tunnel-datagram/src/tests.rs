use super::*;
use std::net::UdpSocket;
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SECRET: [u8; 32] = [0x11; 32];
const PAYLOAD: [u8; 5] = [0, 1, 2, 254, 255];

fn config(cover: CoverProfile, protection: Protection) -> DatagramConfig {
    DatagramConfig {
        context: KeyContext {
            session: SessionId([0x22; 16]),
            direction: Direction::ClientToServer,
            lane: LaneId(0x0102_0304),
            generation: KeyGeneration(7),
        },
        cover,
        protection,
        path_mtu: 1500,
        outer_overhead_bytes: 28,
        max_payload_bytes: 1200,
        max_packets_per_key: 1000,
        max_payload_bytes_per_key: 1_000_000,
    }
}

fn configurations() -> [DatagramConfig; 4] {
    [
        config(CoverProfile::OpenVpnLike, Protection::ChaCha20Poly1305),
        config(CoverProfile::OpenVpnLike, Protection::HmacSha256),
        config(CoverProfile::QuicLike, Protection::ChaCha20Poly1305),
        config(CoverProfile::QuicLike, Protection::HmacSha256),
    ]
}

fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn structural_inspection_is_bounded_borrowed_and_never_authentication() -> TestResult {
    fn inspect(cfg: DatagramConfig, bytes: &[u8]) -> Result<StructuralDatagram<'_>, Error> {
        inspect_structural(
            cfg.cover,
            cfg.protection,
            cfg.path_mtu - cfg.outer_overhead_bytes,
            cfg.max_payload_bytes,
            bytes,
        )
    }
    for cfg in configurations() {
        let mut sealer = PacketSealer::new(cfg, &SECRET)?;
        let mut packet = sealer.seal_vec(&PAYLOAD)?.bytes;
        let view = inspect(cfg, &packet)?;
        assert_eq!(view.context, cfg.context);
        assert_eq!(view.number, PacketNumber(0));
        assert_eq!(view.body.len(), PAYLOAD.len());
        assert_eq!(view.tag.len(), cfg.protection.tag_bytes());
        if cfg.protection == Protection::HmacSha256 {
            assert_eq!(view.body, PAYLOAD);
        }
        for end in 0..packet.len() {
            assert!(inspect(cfg, &packet[..end]).is_err());
        }
        let last = packet.len() - 1;
        packet[last] ^= 1;
        assert!(inspect(cfg, &packet).is_ok()); // Deliberately no tag verification.
        let mut opener = PacketOpener::new(cfg, &SECRET)?;
        assert_eq!(
            opener.open(&packet, &mut [0; 5]),
            Err(Error::Authentication)
        );
        assert_eq!(opener.highest_packet(), None);
        packet.push(0);
        assert!(inspect(cfg, &packet).is_err());
        packet.pop();
        packet[cfg.cover.prefix_bytes() + 6] = 1;
        assert!(inspect(cfg, &packet).is_err());
        assert!(
            inspect_structural(cfg.cover, cfg.protection, 1, cfg.max_payload_bytes, &packet)
                .is_err()
        );
    }
    Ok(())
}

fn rejection_unchanged(
    opener: &mut PacketOpener,
    bytes: &[u8],
) -> Result<Error, Box<dyn std::error::Error>> {
    let previous_usage = opener.usage();
    let previous_highest = opener.highest_packet();
    let mut output = [0xa5; 1200];
    let error = opener
        .open(bytes, &mut output)
        .err()
        .ok_or("expected rejection")?;
    assert_eq!(output, [0xa5; 1200]);
    assert_eq!(opener.usage(), previous_usage);
    assert_eq!(opener.highest_packet(), previous_highest);
    Ok(error)
}

#[test]
fn independent_python_golden_vectors() -> TestResult {
    // Public deterministic fixtures from tests/generate_vectors.py, independently
    // using Python cryptography HKDF/ChaCha20Poly1305 and standard-library HMAC.
    let vectors = [
        "480203044c4401010101000022222222222222222222222222222222010203040000000700000000000000000005000055400532355f0904deb8176088bab34327a87c5c1f",
        "480203044c44010102010000222222222222222222222222222222220102030400000007000000000000000000050000000102feffe201eff6a7847878e7db575bfb853fa74bcf5bd523079a75feb59cb8ec408dc2",
        "4022222222222222224c44010201010000222222222222222222222222222222220102030400000007000000000000000000050000e8d4d3f7589c3f01f38affc16d74ac4a6aad2bb7ad",
        "4022222222222222224c44010202010000222222222222222222222222222222220102030400000007000000000000000000050000000102feff611bc12ef33e194eb691132481f67a95dd29ea5396bb38e621b41b05d0601401",
    ];
    for (configuration, expected) in configurations().into_iter().zip(vectors) {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        let sealed = sealer.seal_vec(&PAYLOAD)?;
        assert_eq!(hexadecimal(&sealed.bytes), expected);
        let mut output = [0; 5];
        assert_eq!(opener.open(&sealed.bytes, &mut output)?.payload_len, 5);
        assert_eq!(output, PAYLOAD);
    }
    Ok(())
}

#[test]
fn all_profiles_roundtrip_every_configured_payload_length() -> TestResult {
    for mut configuration in configurations() {
        configuration.max_packets_per_key = 1200;
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        for length in 1..=configuration.max_payload_bytes {
            let payload: Vec<_> = (0_u8..=255).cycle().take(length).collect();
            let mut wire = vec![0xa5; sealer.max_datagram_bytes() + 1];
            let sealed = sealer.seal_into(&payload, &mut wire)?;
            assert_eq!(sealed.packet.0, (length - 1) as u64);
            assert_eq!(sealed.wire_len, length + configuration.wire_overhead());
            assert_eq!(
                &wire[sealed.wire_len..],
                vec![0xa5; wire.len() - sealed.wire_len]
            );
            let mut output = vec![0xa5; configuration.max_payload_bytes + 1];
            let opened = opener.open(&wire[..sealed.wire_len], &mut output)?;
            assert_eq!(opened.packet, sealed.packet);
            assert_eq!(&output[..opened.payload_len], payload);
            assert_eq!(
                &output[opened.payload_len..],
                vec![0xa5; output.len() - opened.payload_len]
            );
        }
        assert_eq!(sealer.usage(), opener.usage());
        assert_eq!(sealer.usage().packets, 1200);
        assert_eq!(sealer.usage().payload_bytes, 720_600);
    }
    Ok(())
}

#[test]
fn maximum_udp_payload_and_mtu_exact_boundaries() -> TestResult {
    for mut configuration in configurations() {
        configuration.path_mtu = MAX_DATAGRAM_BYTES + 28;
        configuration.max_payload_bytes = MAX_DATAGRAM_BYTES - configuration.wire_overhead();
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        let payload = vec![0x66; configuration.max_payload_bytes];
        let sealed = sealer.seal_vec(&payload)?;
        assert_eq!(sealed.bytes.len(), MAX_DATAGRAM_BYTES);
        assert_eq!(opener.max_datagram_bytes(), MAX_DATAGRAM_BYTES);
        let mut output = vec![0; payload.len()];
        opener.open(&sealed.bytes, &mut output)?;
        assert_eq!(output, payload);
        configuration.path_mtu -= 1;
        assert!(matches!(
            PacketSealer::new(configuration, &SECRET),
            Err(Error::InvalidConfig)
        ));
        configuration.path_mtu = usize::MAX;
        configuration.max_payload_bytes += 1;
        assert!(matches!(
            PacketSealer::new(configuration, &SECRET),
            Err(Error::InvalidConfig)
        ));
    }
    Ok(())
}

#[test]
fn invalid_configuration_is_rejected_before_key_creation() {
    let original = configurations()[0];
    let mut invalid = Vec::new();
    for limit in [0, usize::from(u16::MAX) + 1, usize::MAX] {
        invalid.push(DatagramConfig {
            max_payload_bytes: limit,
            ..original
        });
    }
    for limit in [0, MAX_PACKETS_PER_KEY + 1, u64::MAX] {
        invalid.push(DatagramConfig {
            max_packets_per_key: limit,
            ..original
        });
    }
    for limit in [0, 1199, MAX_PAYLOAD_BYTES_PER_KEY + 1, u64::MAX] {
        invalid.push(DatagramConfig {
            max_payload_bytes_per_key: limit,
            ..original
        });
    }
    invalid.push(DatagramConfig {
        path_mtu: 27,
        ..original
    });
    invalid.push(DatagramConfig {
        path_mtu: original.wire_overhead() + 1200 + 27,
        ..original
    });
    invalid.push(DatagramConfig {
        outer_overhead_bytes: usize::MAX,
        ..original
    });
    for configuration in invalid {
        assert!(matches!(
            PacketSealer::new(configuration, &SECRET),
            Err(Error::InvalidConfig)
        ));
        assert!(matches!(
            PacketOpener::new(configuration, &SECRET),
            Err(Error::InvalidConfig)
        ));
    }
}

#[test]
fn local_send_rejection_preserves_output_usage_and_nonce() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let mut output = [0xa5; 1500];
        assert_eq!(sealer.seal_into(&[], &mut output), Err(Error::EmptyPayload));
        assert_eq!(
            sealer.seal_into(&[0; 1201], &mut output),
            Err(Error::PayloadTooLarge)
        );
        assert_eq!(
            sealer.seal_into(&PAYLOAD, &mut output[..4]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(output, [0xa5; 1500]);
        assert_eq!(sealer.usage(), Usage::default());
        assert_eq!(sealer.seal_vec(&PAYLOAD)?.packet, PacketNumber(0));
    }
    Ok(())
}

#[test]
fn every_truncation_and_appended_byte_rejected_without_state() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let sealed = sealer.seal_vec(&PAYLOAD)?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        for length in 0..sealed.bytes.len() {
            rejection_unchanged(&mut opener, &sealed.bytes[..length])?;
        }
        let mut appended = sealed.bytes.clone();
        appended.push(0);
        assert_eq!(
            rejection_unchanged(&mut opener, &appended)?,
            Error::Malformed
        );
        let oversized = vec![0; opener.max_datagram_bytes() + 1];
        rejection_unchanged(&mut opener, &oversized)?;
        opener.open(&sealed.bytes, &mut [0; 5])?;
    }
    Ok(())
}

#[test]
fn every_header_payload_and_tag_byte_is_authenticated() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let sealed = sealer.seal_vec(&PAYLOAD)?;
        for offset in 0..sealed.bytes.len() {
            let mut modified = sealed.bytes.clone();
            modified[offset] ^= 1;
            let mut opener = PacketOpener::new(configuration, &SECRET)?;
            rejection_unchanged(&mut opener, &modified)?;
            opener.open(&sealed.bytes, &mut [0; 5])?;
        }
    }
    Ok(())
}

#[test]
fn domain_separation_binds_every_context_component() -> TestResult {
    for original in configurations() {
        let original_key = derive_key(original, &SECRET)?;
        let mut variants = Vec::new();
        let mut configuration = original;
        configuration.context.direction = Direction::ServerToClient;
        variants.push(configuration);
        configuration = original;
        configuration.context.session.0[15] ^= 1;
        variants.push(configuration);
        configuration = original;
        configuration.context.lane.0 ^= 1;
        variants.push(configuration);
        configuration = original;
        configuration.context.generation.0 += 1;
        variants.push(configuration);
        configuration = original;
        configuration.cover = match original.cover {
            CoverProfile::OpenVpnLike => CoverProfile::QuicLike,
            CoverProfile::QuicLike => CoverProfile::OpenVpnLike,
        };
        variants.push(configuration);
        configuration = original;
        configuration.protection = match original.protection {
            Protection::ChaCha20Poly1305 => Protection::HmacSha256,
            Protection::HmacSha256 => Protection::ChaCha20Poly1305,
        };
        variants.push(configuration);
        let mut sealer = PacketSealer::new(original, &SECRET)?;
        let sealed = sealer.seal_vec(&PAYLOAD)?;
        for variant in variants {
            assert_ne!(&original_key[..], &derive_key(variant, &SECRET)?[..]);
            let mut opener = PacketOpener::new(variant, &SECRET)?;
            rejection_unchanged(&mut opener, &sealed.bytes)?;
        }
        assert_ne!(&original_key[..], &derive_key(original, &[0x12; 32])?[..]);
        let mut wrong_key = PacketOpener::new(original, &[0x12; 32])?;
        assert_eq!(
            rejection_unchanged(&mut wrong_key, &sealed.bytes)?,
            Error::Authentication
        );
    }
    Ok(())
}

#[test]
fn authenticated_cleartext_and_aead_have_distinct_payload_handling() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let sealed = sealer.seal_vec(&PAYLOAD)?;
        let header = configuration.validate()?.header;
        let body = &sealed.bytes[header..header + PAYLOAD.len()];
        match configuration.protection {
            Protection::HmacSha256 => assert_eq!(body, PAYLOAD),
            Protection::ChaCha20Poly1305 => assert_ne!(body, PAYLOAD),
        }
    }
    Ok(())
}

#[test]
fn reordering_duplicate_and_exact_replay_window_boundary() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let packets: Vec<_> = (0..=130)
            .map(|_| sealer.seal_vec(&PAYLOAD))
            .collect::<Result<_, _>>()?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        for number in [2, 0, 1] {
            assert_eq!(
                opener.open(&packets[number].bytes, &mut [0; 5])?.packet.0,
                number as u64
            );
        }
        assert_eq!(
            rejection_unchanged(&mut opener, &packets[1].bytes)?,
            Error::Replay
        );
        opener.open(&packets[130].bytes, &mut [0; 5])?;
        opener.open(&packets[3].bytes, &mut [0; 5])?;
        assert_eq!(
            rejection_unchanged(&mut opener, &packets[2].bytes)?,
            Error::Replay
        );
        assert_eq!(
            rejection_unchanged(&mut opener, &packets[0].bytes)?,
            Error::Replay
        );
        assert_eq!(opener.highest_packet(), Some(PacketNumber(130)));
        assert_eq!(opener.usage().packets, 5);
    }
    Ok(())
}

#[test]
fn forged_high_counter_cannot_move_existing_replay_window() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let first = sealer.seal_vec(&PAYLOAD)?;
        let second = sealer.seal_vec(&PAYLOAD)?;
        let third = sealer.seal_vec(&PAYLOAD)?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        opener.open(&first.bytes, &mut [0; 5])?;
        let mut forged = second.bytes.clone();
        let offset = configuration.cover.prefix_bytes() + 32;
        forged[offset..offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            rejection_unchanged(&mut opener, &forged)?,
            Error::Authentication
        );
        opener.open(&third.bytes, &mut [0; 5])?;
        opener.open(&second.bytes, &mut [0; 5])?;
        assert_eq!(
            rejection_unchanged(&mut opener, &first.bytes)?,
            Error::Replay
        );
    }
    Ok(())
}

#[test]
fn destination_failure_does_not_consume_authenticated_packet() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let sealed = sealer.seal_vec(&PAYLOAD)?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        let mut short = [0xa5; 4];
        assert_eq!(
            opener.open(&sealed.bytes, &mut short),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(short, [0xa5; 4]);
        assert_eq!(opener.highest_packet(), None);
        assert_eq!(opener.usage(), Usage::default());
        opener.open(&sealed.bytes, &mut [0; 5])?;
    }
    Ok(())
}

#[test]
fn authenticated_invalid_format_does_not_commit_replay() -> TestResult {
    for configuration in configurations() {
        // Internal fixture construction deliberately bypasses the production
        // sealer to model a peer that authenticates an illegal reserved field.
        let key = TrafficKey::new(configuration, &SECRET)?;
        let mut header = encode_header(configuration, PacketNumber(0), PAYLOAD.len())?;
        header[configuration.cover.prefix_bytes() + 6] = 1;
        let invalid = key.seal(PacketNumber(0), header, &PAYLOAD)?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        assert_eq!(
            rejection_unchanged(&mut opener, &invalid)?,
            Error::Malformed
        );
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        opener.open(&sealer.seal_vec(&PAYLOAD)?.bytes, &mut [0; 5])?;
    }
    Ok(())
}

#[test]
fn counter_exhaustion_is_checked_without_wrap() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        // Private test access exercises exhaustion; the public API cannot reset
        // counters or set an initial value and normal key-use caps expire sooner.
        sealer.next = Some(PacketNumber(u64::MAX));
        let final_packet = sealer.seal_vec(&PAYLOAD)?;
        assert_eq!(final_packet.packet, PacketNumber(u64::MAX));
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        opener.open(&final_packet.bytes, &mut [0; 5])?;
        let usage = sealer.usage();
        let mut output = [0xa5; 100];
        assert_eq!(
            sealer.seal_into(&PAYLOAD, &mut output),
            Err(Error::CounterExhausted)
        );
        assert_eq!(sealer.usage(), usage);
        assert_eq!(output, [0xa5; 100]);
        assert_eq!(
            rejection_unchanged(&mut opener, &final_packet.bytes)?,
            Error::Replay
        );
    }
    Ok(())
}

#[test]
fn packet_and_byte_key_limits_are_failure_atomic() -> TestResult {
    for mut configuration in configurations() {
        configuration.max_payload_bytes = 5;
        for byte_limit in [false, true] {
            let sender_config = configuration;
            let mut limited = configuration;
            if byte_limit {
                limited.max_payload_bytes_per_key = 10;
            } else {
                limited.max_packets_per_key = 2;
            }
            let mut limited_sealer = PacketSealer::new(limited, &SECRET)?;
            limited_sealer.seal_vec(&PAYLOAD)?;
            limited_sealer.seal_vec(&PAYLOAD)?;
            let mut output = [0xa5; 100];
            assert_eq!(
                limited_sealer.seal_into(&PAYLOAD, &mut output),
                Err(Error::KeyUsageExhausted)
            );
            assert_eq!(output, [0xa5; 100]);
            assert_eq!(
                limited_sealer.usage(),
                Usage {
                    packets: 2,
                    payload_bytes: 10
                }
            );
            let mut sealer = PacketSealer::new(sender_config, &SECRET)?;
            let mut opener = PacketOpener::new(limited, &SECRET)?;
            for _ in 0..2 {
                opener.open(&sealer.seal_vec(&PAYLOAD)?.bytes, &mut [0; 5])?;
            }
            assert_eq!(
                rejection_unchanged(&mut opener, &sealer.seal_vec(&PAYLOAD)?.bytes)?,
                Error::KeyUsageExhausted
            );
        }
    }
    Ok(())
}

#[test]
fn real_udp_loopback_both_directions_all_protection_and_cover_profiles() -> TestResult {
    let a = UdpSocket::bind("127.0.0.1:0")?;
    let b = UdpSocket::bind("127.0.0.1:0")?;
    a.set_read_timeout(Some(Duration::from_secs(2)))?;
    b.set_read_timeout(Some(Duration::from_secs(2)))?;
    for configuration in configurations() {
        for (sender, receiver, direction) in [
            (&a, &b, Direction::ClientToServer),
            (&b, &a, Direction::ServerToClient),
        ] {
            let mut configuration = configuration;
            configuration.context.direction = direction;
            let mut sealer = PacketSealer::new(configuration, &SECRET)?;
            let mut opener = PacketOpener::new(configuration, &SECRET)?;
            for length in [1, 5, configuration.max_payload_bytes] {
                let payload: Vec<_> = (0_u8..=255).cycle().take(length).collect();
                let packet = sealer.seal_vec(&payload)?;
                assert_eq!(
                    sender.send_to(&packet.bytes, receiver.local_addr()?)?,
                    packet.bytes.len()
                );
                let mut wire = vec![0; opener.max_datagram_bytes() + 1];
                let (received, from) = receiver.recv_from(&mut wire)?;
                assert_eq!(from, sender.local_addr()?);
                assert_eq!(received, packet.bytes.len());
                let mut output = vec![0xa5; configuration.max_payload_bytes];
                let opened = opener.open(&wire[..received], &mut output)?;
                assert_eq!(&output[..opened.payload_len], payload);
                assert_eq!(
                    rejection_unchanged(&mut opener, &wire[..received])?,
                    Error::Replay
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checked_rejection_preserves_output_replay_usage_and_retries_same_packet() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let sealed = sealer.seal_vec(&PAYLOAD)?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        let mut output = [0xa5; 32];
        let mut calls = 0;
        assert_eq!(
            opener.open_checked(&sealed.bytes, &mut output, |opened, bytes| {
                calls += 1;
                assert_eq!(opened.packet, sealed.packet);
                assert_eq!(opened.payload_len, PAYLOAD.len());
                assert_eq!(bytes, PAYLOAD);
                Err(Error::ContextMismatch)
            }),
            Err(CheckedOpenError::Rejected(Error::ContextMismatch))
        );
        assert_eq!(calls, 1);
        assert_eq!(output, [0xa5; 32]);
        assert_eq!(opener.usage(), Usage::default());
        assert_eq!(opener.highest_packet(), None);
        assert_eq!(opener.replay.seen, 0);
        let opened = opener.open_checked(&sealed.bytes, &mut output, |_, bytes| {
            calls += 1;
            assert_eq!(bytes, PAYLOAD);
            Ok::<(), Error>(())
        })?;
        assert_eq!(calls, 2);
        assert_eq!(opened.packet, sealed.packet);
        assert_eq!(&output[..PAYLOAD.len()], PAYLOAD);
        assert_eq!(&output[PAYLOAD.len()..], &[0xa5; 27]);
        assert_eq!(opener.usage().packets, 1);
        assert_eq!(opener.usage().payload_bytes, PAYLOAD.len() as u64);
        assert_eq!(opener.highest_packet(), Some(sealed.packet));
        assert_eq!(
            opener.open_checked(&sealed.bytes, &mut output, |_, _| {
                calls += 1;
                Ok::<(), Error>(())
            }),
            Err(CheckedOpenError::Datagram(Error::Replay))
        );
        assert_eq!(calls, 2);
    }
    Ok(())
}

#[test]
fn checked_authenticated_high_counter_rejection_cannot_evict_unseen_packets() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let first = sealer.seal_vec(&PAYLOAD)?;
        let second = sealer.seal_vec(&PAYLOAD)?;
        // A real authenticated high counter, not a forged unprotected header.
        sealer.next = Some(PacketNumber(256));
        let high = sealer.seal_vec(&[7; 1200])?;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        opener.open(&first.bytes, &mut [0; 5])?;
        let usage = opener.usage();
        let seen = opener.replay.seen;
        let mut output = [0xa5; 1200];
        assert_eq!(
            opener.open_checked(&high.bytes, &mut output, |opened, bytes| {
                assert_eq!(opened.packet, PacketNumber(256));
                assert_eq!(bytes, &[7; 1200]);
                Err(Error::ContextMismatch)
            }),
            Err(CheckedOpenError::Rejected(Error::ContextMismatch))
        );
        assert_eq!(output, [0xa5; 1200]);
        assert_eq!(opener.usage(), usage);
        assert_eq!(opener.highest_packet(), Some(PacketNumber(0)));
        assert_eq!(opener.replay.seen, seen);
        opener.open(&second.bytes, &mut [0; 5])?;
        opener.open_checked(&high.bytes, &mut output, |_, _| Ok::<(), Error>(()))?;
        assert_eq!(opener.highest_packet(), Some(PacketNumber(256)));
        assert_eq!(output, [7; 1200]);
    }
    Ok(())
}

#[test]
fn checked_callback_never_runs_for_invalid_input_or_short_destination() -> TestResult {
    for configuration in configurations() {
        let mut sealer = PacketSealer::new(configuration, &SECRET)?;
        let sealed = sealer.seal_vec(&PAYLOAD)?;
        let mut forged = sealed.bytes.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let mut wrong_context = sealed.bytes.clone();
        wrong_context[configuration.cover.prefix_bytes() + 8] ^= 1;
        let mut opener = PacketOpener::new(configuration, &SECRET)?;
        let cases = [
            (&[][..], 32, Error::Malformed),
            (
                &sealed.bytes[..sealed.bytes.len() - 1],
                32,
                Error::Malformed,
            ),
            (&forged[..], 32, Error::Authentication),
            (&wrong_context[..], 32, Error::ContextMismatch),
            (&sealed.bytes[..], 4, Error::OutputTooSmall),
        ];
        let mut calls = 0;
        for (packet, capacity, expected) in cases {
            let mut output = [0xa5; 32];
            assert_eq!(
                opener.open_checked(packet, &mut output[..capacity], |_, _| {
                    calls += 1;
                    Ok::<(), Error>(())
                }),
                Err(CheckedOpenError::Datagram(expected))
            );
            assert_eq!(calls, 0);
            assert_eq!(output, [0xa5; 32]);
            assert_eq!(opener.highest_packet(), None);
            assert_eq!(opener.usage(), Usage::default());
        }
        opener.open_checked(&sealed.bytes, &mut [0; 5], |_, _| {
            calls += 1;
            Ok::<(), Error>(())
        })?;
        assert_eq!(calls, 1);
    }
    Ok(())
}

#[test]
fn checked_rejection_does_not_spend_either_receive_key_budget() -> TestResult {
    for mut configuration in configurations() {
        configuration.max_payload_bytes = PAYLOAD.len();
        for byte_limit in [false, true] {
            let mut limited = configuration;
            if byte_limit {
                limited.max_payload_bytes_per_key = PAYLOAD.len() as u64;
            } else {
                limited.max_packets_per_key = 1;
            }
            let mut sealer = PacketSealer::new(configuration, &SECRET)?;
            let first = sealer.seal_vec(&PAYLOAD)?;
            let second = sealer.seal_vec(&PAYLOAD)?;
            let mut opener = PacketOpener::new(limited, &SECRET)?;
            let mut calls = 0;
            let mut output = [0xa5; 5];
            assert_eq!(
                opener.open_checked(&first.bytes, &mut output, |_, _| {
                    calls += 1;
                    Err(Error::ContextMismatch)
                }),
                Err(CheckedOpenError::Rejected(Error::ContextMismatch))
            );
            assert_eq!(output, [0xa5; 5]);
            assert_eq!(opener.usage(), Usage::default());
            opener.open_checked(&first.bytes, &mut output, |_, _| {
                calls += 1;
                Ok::<(), Error>(())
            })?;
            let usage = opener.usage();
            let seen = opener.replay.seen;
            output.fill(0xa5);
            assert_eq!(
                opener.open_checked(&second.bytes, &mut output, |_, _| {
                    calls += 1;
                    Ok::<(), Error>(())
                }),
                Err(CheckedOpenError::Datagram(Error::KeyUsageExhausted))
            );
            assert_eq!(calls, 2);
            assert_eq!(output, [0xa5; 5]);
            assert_eq!(opener.usage(), usage);
            assert_eq!(opener.highest_packet(), Some(PacketNumber(0)));
            assert_eq!(opener.replay.seen, seen);
        }
    }
    Ok(())
}
