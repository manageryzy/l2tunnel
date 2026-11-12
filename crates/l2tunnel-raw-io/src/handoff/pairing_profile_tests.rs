use super::test_support::*;
use super::*;
use l2tunnel_auth::{MemberPublicKey, ServerIdentity};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn independent_python_common_transcript_and_offer_vectors() -> R {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("pairing/profile_vectors.json"))?;
    for v in vectors.as_array().ok_or("vectors")? {
        let count = usize::try_from(v["lanes"].as_u64().ok_or("count")?)?;
        let (inputs, peer, _) = inputs(count == 2);
        let p = profile::validate(&inputs, config())?;
        assert_eq!(
            hex(&profile::encoding(config(), raw(true, 0), count)?),
            v["preimage"]
        );
        assert_eq!(hex(&p.digest.0), v["digest"]);
        for i in 0..count {
            assert_eq!(hex(&p.bases[i].digest.0), v["lane_bases"][i]);
        }
        let lanes = std::array::from_fn(|i| {
            (i < count).then_some(SessionInfo {
                session_id: [0x64 + i as u8; 16],
                peer_member: None,
                member: MemberPublicKey([0x42; 32]),
                server: ServerIdentity([0x53; 32]),
                config: SessionConfig {
                    layer: config().session.layer,
                    digest: ConfigDigest([0x75 + i as u8; 32]),
                },
            })
        });
        let transcript = profile::transcript_bytes(&p, [0x31; 32], lanes)?;
        assert_eq!(hex(&transcript), v["transcript"]);
        let mut digest_input = b"l2tunnel/raw-owned-pair-transcript/v1\0".to_vec();
        digest_input.extend_from_slice(&transcript);
        assert_eq!(hex(&profile::hash(&digest_input)), v["transcript_digest"]);
        assert_eq!(hex(&encode(1, 0, &transcript)), v["offer"]);
        drop((inputs, peer));
    }
    Ok(())
}
#[test]
fn every_canonical_runtime_field_changes_digest_and_local_tuple_does_not() -> R {
    let base = profile::encoding(config(), raw(true, 0), 2)?;
    let cfg = config();
    let raw_cfg = raw(true, 0);
    for i in 0..18 {
        let mut c = cfg;
        let mut r = raw_cfg;
        match i {
            0 => c.session.layer = l2tunnel_device::PacketLayer::Ethernet,
            1 => c.session.digest.0[0] ^= 1,
            2 => r.mtu += 1,
            3 => r.send_bytes += 1,
            4 => r.receive_bytes += 1,
            5 => r.packet_slots += 1,
            6 => r.ack_delay_millis += 1,
            7 => r.keepalive_millis += 1,
            8 => r.idle_timeout_millis += 1,
            9 => c.driver.work_limit += 1,
            10 => c.driver.max_handoff_duration -= Duration::from_micros(1),
            11 => c.timeout += Duration::from_micros(1),
            12 => c.messages.max_payload -= 1,
            13 => c.messages.messages_per_direction -= 1,
            14 => c.messages.bytes_per_direction -= 1,
            15 => {
                c.messages.records.incoming.wire_bytes -= 1;
                c.messages.records.outgoing.wire_bytes -= 1;
            }
            16 => {
                c.messages.records.incoming.records -= 1;
                c.messages.records.outgoing.records -= 1;
            }
            17 => c.messages.records.max_payload -= 1,
            _ => return Err("fixture index".into()),
        }
        assert_ne!(
            profile::hash(&profile::encoding(c, r, 2)?),
            profile::hash(&base),
            "field {i}"
        );
    }
    assert_ne!(profile::encoding(cfg, raw_cfg, 1)?, base);
    let mut local = raw_cfg;
    std::mem::swap(&mut local.local, &mut local.peer);
    local.random_seed += 1;
    assert_eq!(profile::encoding(cfg, local, 2)?, base);
    let mut c = cfg;
    c.driver.max_handoff_duration += Duration::from_nanos(1);
    assert!(profile::encoding(c, raw_cfg, 2).is_err());
    Ok(())
}
#[test]
fn resource_formula_exact_ceiling_overflow_and_fixed_metadata_caps() -> R {
    let r = raw(true, 0);
    for l in 1..=2 {
        let charge = profile::payload_charge(r, l)?;
        let expected = (l as u64)
            * (4096 + 4096 + 2 * 8 * 576 + 5 * 576 + 65_536 + 2 * 4104 + 6 * 32)
            + 236
            + 2 * 244;
        assert_eq!(charge.retained_payload, expected);
        assert_eq!(
            charge.peak_payload,
            expected + (l as u64) * (2 * 576 + 6 * 32) + 64 + 244
        );
    }
    // Resource arithmetic is independently bounded; full config validation
    // additionally enforces each engine's smaller ring geometry.
    let mut edge = r;
    let overhead = profile::payload_charge(r, 1)?.retained_payload - r.send_bytes as u64;
    edge.send_bytes = usize::try_from(profile::RETAINED - overhead)?;
    assert_eq!(
        profile::payload_charge(edge, 1)?.retained_payload,
        profile::RETAINED
    );
    edge.send_bytes += 1;
    assert!(matches!(
        profile::payload_charge(edge, 1),
        Err(PairError::Capacity)
    ));
    edge.mtu = usize::MAX;
    edge.packet_slots = usize::MAX;
    assert!(matches!(
        profile::payload_charge(edge, 2),
        Err(PairError::Capacity)
    ));
    struct Huge {
        _bytes: [u8; 1_048_576],
    }
    impl PacketIo for Huge {
        fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
            Ok(None)
        }
        fn send(&mut self, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(metadata::<PacketLink>(2, r)? < profile::METADATA);
    assert!(matches!(metadata::<Huge>(2, r), Err(PairError::Capacity)));
    let fixed =
        l2tunnel_raw_tcp::handoff::TrackedEngine::fixed_metadata_bytes().ok_or("metadata")?;
    assert!(fixed > size_of::<l2tunnel_raw_tcp::TcpEngine>());
    Ok(())
}
#[tokio::test]
async fn minimum_pair_slots_charge_real_messages_and_exhaust_without_new_credit() -> R {
    let (c, s, m, allowed) = fixture()?;
    let (ai, bi, probes) = inputs(false);
    let mut cfg = config();
    cfg.messages.max_payload = 244;
    cfg.messages.messages_per_direction = 3;
    cfg.messages.bytes_per_direction = 756;
    let mut a = begin_pair_client(ai, &c, "tunnel.test", &m, cfg)?;
    let mut b = begin_pair_server(bi, &s, &allowed, cfg)?;
    let (mut ar, mut br) = (None, None);
    std::future::poll_fn(|cx| {
        for (setup, owner) in [(&mut a, &mut ar), (&mut b, &mut br)] {
            if let Some(p) = owner {
                if let Poll::Ready(Err(e)) = PairedRaw::poll_progress(p, cx) {
                    return Poll::Ready(Err(e));
                }
            } else if let Poll::Ready(result) = Pin::new(setup).poll(cx) {
                *owner = Some(result?);
            }
        }
        if ar.is_some() && br.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    let (mut a, mut b) = (ar.ok_or("client")?, br.ok_or("server")?);
    let bs = b.status().messages[0].ok_or("status")?;
    assert_eq!(bs.outgoing.completed_messages, 2);
    assert_eq!(bs.outgoing.plaintext_bytes, 504);
    transfer(&mut b, &mut a, PairLane::First, &[0x8a; 244]).await?;
    a.consume_message(PairLane::First)?;
    let before = b.status().messages[0].ok_or("status")?.outgoing;
    assert!(b.stage_message(PairLane::First, b"exhausted").is_err());
    assert_eq!(b.status().messages[0].ok_or("status")?.outgoing, before);
    // Local admission rejection is recoverable, but cannot refund or reset the
    // already spent lifetime reservations.
    assert!(b.status().fault.is_none());
    assert!(b.stage_message(PairLane::First, b"again").is_err());
    assert_eq!(b.status().messages[0].ok_or("status")?.outgoing, before);
    drop((a, b));
    for p in probes {
        assert_eq!(p.dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    Ok(())
}
