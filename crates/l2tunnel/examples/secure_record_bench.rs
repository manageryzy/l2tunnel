//! Finite CPU benchmark of library records, without sockets or device claims.
use l2tunnel::{
    cover,
    secure_record::{Class, Records, Scope},
    security,
};
use std::{error::Error, hint::black_box, time::Instant};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn Error>> {
    let iterations: u32 = std::env::args()
        .nth(1)
        .map_or(Ok(100_000), |value| value.parse())?;
    if !(1..=1_000_000).contains(&iterations) {
        return Err("iterations must be within 1..=1000000".into());
    }
    println!(
        "{{\"scope\":\"local CPU seal-cover-parse-open round trips; no network or native devices\",\"cases\":["
    );
    let mut first = true;
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for protection in [
            security::Protection::ChaCha20Poly1305,
            security::Protection::HmacSha256,
        ] {
            for body_bytes in [64, 512, 1340] {
                let binding = security::SessionBinding {
                    session: security::SessionId([1; 16]),
                    transcript: [2; 32],
                };
                let make_root = |role| {
                    security::SessionRoot::from_split_keys(
                        Zeroizing::new([3; 32]),
                        Zeroizing::new([4; 32]),
                        binding,
                        role,
                    )
                };
                let make_cover = |local, peer| {
                    cover::Config::new(
                        appearance,
                        cover::ConnectionIds {
                            local: cover::ConnectionId([local; 8]),
                            peer: cover::ConnectionId([peer; 8]),
                        },
                        cover::MediaConfig {
                            local_ssrc: cover::Ssrc(u32::from(local)),
                            peer_ssrc: cover::Ssrc(u32::from(peer)),
                            payload_type: 96,
                        },
                        cover::Limits {
                            max_packet_bytes: 1472,
                            max_protected_bytes: 1430,
                        },
                    )
                };
                let control = Scope {
                    epoch: security::Epoch(1),
                    configuration: security::ConfigDigest([5; 32]),
                };
                let data = Scope {
                    epoch: security::Epoch(2),
                    configuration: security::ConfigDigest([6; 32]),
                };
                let limits = security::Limits {
                    max_body_bytes: 1340,
                    packets_per_key: security::MAX_PACKETS_PER_KEY,
                    max_body_bytes_per_key: security::MAX_BODY_BYTES_PER_KEY,
                };
                let mut sender = Records::new(
                    make_root(security::Role::Initiator)?,
                    security::LaneId(0),
                    limits,
                    protection,
                    make_cover(1, 2)?,
                    control,
                    data,
                )?;
                let mut receiver = Records::new(
                    make_root(security::Role::Responder)?,
                    security::LaneId(0),
                    limits,
                    protection,
                    make_cover(2, 1)?,
                    control,
                    data,
                )?;
                let mut body = vec![0xA5; body_bytes];
                let mut workspace = [0; 2048];
                let mut opened_workspace = [0; 2048];
                let mut wire = [0; 2048];
                let mut plain = [0; 2048];
                let packet_bytes = sender.capacity(body_bytes)?.packet_bytes;
                let started = Instant::now();
                for number in 0..iterations {
                    body[..4].copy_from_slice(&number.to_be_bytes());
                    let sealed = sender.seal(
                        Class::User,
                        cover::PacketMeta {
                            phase: cover::Phase::Established,
                            packet_number: cover::PacketNumber(number),
                            media_timestamp: cover::MediaTimestamp(number.wrapping_mul(960)),
                        },
                        black_box(&body),
                        &mut workspace,
                        &mut wire,
                    )?;
                    let opened = receiver.open(
                        black_box(&wire[..sealed.bytes]),
                        &mut opened_workspace,
                        &mut plain,
                    )?;
                    if opened.bytes != body.len() || plain[..opened.bytes] != body {
                        return Err("benchmark round-trip mismatch".into());
                    }
                    black_box(&plain[..opened.bytes]);
                }
                let elapsed_ns = started.elapsed().as_nanos().max(1);
                let payload_bytes = u64::from(iterations) * body_bytes as u64;
                let separator = if first { "" } else { "," };
                first = false;
                let appearance = match appearance {
                    cover::Appearance::QuicLike => "quic_like",
                    cover::Appearance::MediaLike => "media_like",
                };
                let protection = match protection {
                    security::Protection::ChaCha20Poly1305 => "chacha20_poly1305",
                    security::Protection::HmacSha256 => "hmac_sha256",
                };
                println!(
                    "{separator}{{\"appearance\":\"{appearance}\",\"protection\":\"{protection}\",\"body_bytes\":{body_bytes},\"iterations\":{iterations},\"elapsed_ns\":{elapsed_ns},\"payload_bytes\":{payload_bytes},\"packet_bytes\":{packet_bytes},\"modeled_ipv4_wire_bytes\":{},\"ns_per_round_trip\":{:.3},\"payload_round_trip_gbit_per_second\":{:.6}}}",
                    u64::from(iterations) * (packet_bytes as u64 + 28),
                    elapsed_ns as f64 / f64::from(iterations),
                    payload_bytes as f64 * 8.0 / elapsed_ns as f64
                );
            }
        }
    }
    println!("]}}");
    Ok(())
}
