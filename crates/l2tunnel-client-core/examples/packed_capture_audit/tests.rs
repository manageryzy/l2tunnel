use super::*;
use config::{Configuration, Derived};
use l2tunnel_codec::{
    aligned_body,
    aligned_receiver::{Direction, RecordId, Scope, SourceId},
    packed, packed_envelope,
};
use l2tunnel_core::Epoch;
use l2tunnel_datagram as datagram;
use l2tunnel_recovery::{EndpointRole, RecoveryContext};
use l2tunnel_reliable::{OutboundBudget, RecordKind, Reliable};
use serde_json::{Value, json};
use std::{ops::Deref, time::Duration};

#[path = "tests/ethernet.rs"]
mod ethernet;

struct Fixture {
    derived: Derived,
    sessions: [[u8; 16]; 2],
}
impl Deref for Fixture {
    type Target = Derived;
    fn deref(&self) -> &Self::Target {
        &self.derived
    }
}

fn settings() -> Value {
    json!({"version":2,"layer":"tun","duplex":"half","carrier":"udp",
    "path_mtu":1200,"max_packet":1600,"channels":4,"hold_micros":1000,
    "max_units":4,"work_limit":16,"fec_sources":4,"fec_repairs":2,
    "fec_flush_ms":5,"cover":"quic-like","protection":"integrity",
    "delivery": {
        "forward_bandwidth_bps":100_000_000,"reverse_bandwidth_bps":10_000_000,
        "bootstrap_rtt_micros":70_000,"min_rtt_micros":1000,"max_rtt_micros":2_000_000,
        "headroom_percent":125,"minimum_bytes":3200,"max_inflight_bytes":4_194_304,
        "max_records":8192,"metadata_limit_bytes":2_097_152,
        "sample_ttl_micros":4_000_000,"flush_timeout_micros":10_000_000
    }})
}
fn configure(value: &Value) -> Result<(Configuration, Fixture)> {
    let config = Configuration::parse(&serde_json::to_vec(value)?)?;
    let derived = config.derive()?;
    let sessions = if config.duplex == config::DuplexChoice::Half {
        [[7; 16], [8; 16]]
    } else {
        [[7; 16], [7; 16]]
    };
    Ok((config, Fixture { derived, sessions }))
}
fn scope(derived: &Fixture, direction: u8) -> Scope {
    Scope {
        session: derived.sessions[usize::from(direction)],
        epoch: Epoch(1),
        direction: if direction == 0 {
            Direction::InitiatorToResponder
        } else {
            Direction::ResponderToInitiator
        },
    }
}
fn ip(seed: u8) -> Vec<u8> {
    let mut bytes = vec![0; 36];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&36u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
    bytes[16..20].copy_from_slice(&[192, 0, 2, 2]);
    bytes[20..22].copy_from_slice(&1000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&1001u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&16u16.to_be_bytes());
    bytes[28..].fill(seed);
    bytes
}
fn raw_unit(derived: &Fixture, channel: u8, record: u64, packet: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = aligned_body::Encoder::new(derived.packed.protocol.base.receiver.body)?;
    let mut body = vec![0; encoder.max_encoded_len()];
    let written = encoder.encode_raw(packet, &mut body)?;
    assert_eq!(written.context_len, 0);
    let mut unit = vec![channel];
    unit.extend_from_slice(&(record as u16).to_be_bytes());
    unit.extend_from_slice(&body[..written.body_len]);
    Ok(unit)
}
fn source(
    derived: &Fixture,
    direction: u8,
    id: u64,
    first: u64,
    units: &[Vec<u8>],
    records: &[u64],
) -> Result<Vec<u8>> {
    let geometry = derived.packed.protocol.envelope();
    let mut packer = packed::Packer::new(packed::Config {
        symbol_bytes: geometry.symbol_bytes,
        hold_micros: 1000,
    })?;
    for unit in units {
        assert_eq!(packer.push(unit, 1, 0)?, packed::Push::Accepted);
    }
    packer.flush();
    let pending = packer.pending().ok_or("missing packed source")?;
    let records: Vec<_> = records.iter().copied().map(RecordId).collect();
    let mut output = vec![0; geometry.max_source_bytes()?];
    let size = packed_envelope::encode(
        geometry,
        packed_envelope::Identity {
            scope: scope(derived, direction),
            source: SourceId(id),
            first_unit: SourceId(first),
        },
        &records,
        pending.payload,
        &mut output,
    )?;
    output.truncate(size);
    Ok(output)
}
fn recovery_packets(
    derived: &Fixture,
    direction: u8,
    payloads: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>> {
    let config = derived.packed.protocol.base.recovery;
    let mut sender = Reliable::new(
        config,
        RecoveryContext {
            session: u128::from_be_bytes(derived.sessions[usize::from(direction)]),
            epoch: 1,
            role: if direction == 0 {
                EndpointRole::Initiator
            } else {
                EndpointRole::Responder
            },
        },
    )?;
    for (id, bytes) in payloads.iter().enumerate() {
        assert_eq!(sender.submit(bytes, Duration::ZERO)?, id as u64);
    }
    let mut output = vec![0; sender.max_packet_bytes()];
    let mut packets = Vec::new();
    for now in [
        config.flush_after,
        config.arq.initial_rto + config.flush_after,
    ] {
        let mut budget = OutboundBudget {
            packets: 128,
            wire_bytes: 128 * (sender.max_packet_bytes() + config.outer_overhead_bytes),
        };
        let mut complete = false;
        for _ in 0..128 {
            let Some(size) = sender.poll_data(now, &mut output, &mut budget)? else {
                complete = true;
                break;
            };
            packets.push(output[..size].to_vec());
        }
        assert!(complete, "bounded fixture emission exhausted");
    }
    Ok(packets)
}
fn kind(derived: &Fixture, direction: u8, packet: &[u8]) -> Result<RecordKind> {
    let base = derived.packed.protocol.base;
    Ok(l2tunnel_reliable::inspect_structural(
        packet,
        if direction == 0 {
            EndpointRole::Initiator
        } else {
            EndpointRole::Responder
        },
        base.max_recovery_packet_bytes,
        base.recovery.arq.max_source_bytes,
        base.recovery.fec.block,
    )?
    .kind)
}
fn seal(
    config: &Configuration,
    derived: &Fixture,
    direction: u8,
    packets: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let profile = datagram::DatagramConfig {
        context: datagram::KeyContext {
            session: datagram::SessionId(derived.sessions[usize::from(direction)]),
            direction: if direction == 0 {
                datagram::Direction::ClientToServer
            } else {
                datagram::Direction::ServerToClient
            },
            lane: datagram::LaneId(if config.duplex == config::DuplexChoice::Full {
                0
            } else {
                u32::from(direction)
            }),
            generation: datagram::KeyGeneration(0),
        },
        cover: config.cover()?,
        protection: datagram::Protection::HmacSha256,
        path_mtu: derived.geometry.udp_payload_ceiling,
        outer_overhead_bytes: 0,
        max_payload_bytes: derived.geometry.recovery_packet_ceiling,
        max_packets_per_key: 4096,
        max_payload_bytes_per_key: 8 * 1024 * 1024,
    };
    let mut sealer = datagram::PacketSealer::new(profile, &[3; 32])?;
    let mut input = Vec::new();
    for packet in packets {
        let sealed = sealer.seal_vec(packet)?;
        input.extend_from_slice(&u16::try_from(sealed.bytes.len())?.to_be_bytes());
        input.extend_from_slice(&[direction, 0]);
        input.extend_from_slice(&sealed.bytes);
    }
    Ok(input)
}
fn two_packets(derived: &Fixture, direction: u8) -> Result<Vec<u8>> {
    source(
        derived,
        direction,
        0,
        0,
        &[
            raw_unit(derived, 0, 0, &ip(1))?,
            raw_unit(derived, 1, 1, &ip(2))?,
        ],
        &[0, 1],
    )
}
fn direct(derived: &Fixture, direction: u8, source: Vec<u8>) -> Result<Vec<u8>> {
    recovery_packets(derived, direction, &[source])?
        .into_iter()
        .find(|packet| {
            kind(derived, direction, packet).is_ok_and(|kind| kind == RecordKind::Source)
        })
        .ok_or_else(|| "fixture did not emit a direct ARQ retry".into())
}

#[test]
fn exact_required_configuration_and_authoritative_geometry() -> Result<()> {
    let value = settings();
    let (_, derived) = configure(&value)?;
    let geometry = serde_json::to_value(&derived.geometry)?;
    assert_eq!(
        geometry.as_object().ok_or("geometry is not object")?.len(),
        15
    );
    assert_eq!(geometry["underlay_ip_version"], 4);
    assert_eq!(geometry["outer_overhead_bytes"], 28);
    assert_eq!(geometry["udp_payload_ceiling"], 1172);
    assert_eq!(geometry["packed_header_bytes"], 56);
    assert_eq!(geometry["record_id_bytes"], 32);
    assert_eq!(
        geometry["symbol_bytes"].as_u64().ok_or("symbol")? + 88,
        geometry["recovery_source_bytes"].as_u64().ok_or("source")?
    );
    assert_eq!(geometry["native_queue_packets"], 64);
    assert_eq!(geometry["native_queue_bytes"], 102400);
    for field in value.as_object().ok_or("settings")?.keys() {
        let mut missing = value.clone();
        missing.as_object_mut().ok_or("settings")?.remove(field);
        assert!(configure(&missing).is_err(), "missing {field}");
    }
    let mut unknown = value.clone();
    unknown["unexpected"] = json!(1);
    assert!(configure(&unknown).is_err());
    let original = serde_json::to_string(&value)?;
    let duplicate = format!("{{\"version\":1,{}", &original[1..]);
    assert!(Configuration::parse(duplicate.as_bytes()).is_err());
    assert!(Configuration::parse(&vec![b' '; CONFIG_LIMIT + 1]).is_err());
    for (field, bad) in [
        ("version", json!(1)),
        ("max_packet", json!(1599)),
        ("path_mtu", json!(575)),
        ("channels", json!(256)),
        ("channels", json!(0)),
        ("hold_micros", json!(0)),
        ("hold_micros", json!(1001)),
        ("max_units", json!(0)),
        ("work_limit", json!(256)),
        ("fec_sources", json!(17)),
        ("fec_repairs", json!(0)),
        ("fec_flush_ms", json!(u64::MAX)),
        ("cover", Value::Null),
        ("protection", Value::Null),
    ] {
        let mut changed = value.clone();
        changed[field] = bad;
        assert!(configure(&changed).is_err(), "accepted invalid {field}");
    }
    Ok(())
}

#[test]
fn configuration_only_accepts_aead_and_real_quic_but_audit_rejects_both() -> Result<()> {
    let mut value = settings();
    value["protection"] = json!("aead");
    let (config, derived) = configure(&value)?;
    assert!(audit::inspect(&config, &derived, &[]).is_err());
    value["carrier"] = json!("quic");
    value["path_mtu"] = json!(1228);
    assert!(configure(&value).is_err());
    value["cover"] = Value::Null;
    value["protection"] = Value::Null;
    let (config, derived) = configure(&value)?;
    assert!(audit::inspect(&config, &derived, &[]).is_err());
    assert_eq!(
        serde_json::to_value(&derived.geometry)?["udp_payload_ceiling"],
        1200
    );
    Ok(())
}

#[test]
fn maintained_encoders_prove_both_covers_duplex_directions_copies_and_aggregation() -> Result<()> {
    for cover in ["quic-like", "openvpn-like"] {
        for duplex in ["half", "full"] {
            let mut value = settings();
            value["cover"] = json!(cover);
            value["duplex"] = json!(duplex);
            let (config, derived) = configure(&value)?;
            let mut input = Vec::new();
            for direction in 0..2 {
                let packets =
                    recovery_packets(&derived, direction, &[two_packets(&derived, direction)?])?;
                assert!(packets.iter().any(|packet| {
                    kind(&derived, direction, packet)
                        .is_ok_and(|kind| kind == RecordKind::Systematic)
                }));
                assert!(packets.iter().any(|packet| {
                    kind(&derived, direction, packet).is_ok_and(|kind| kind == RecordKind::Repair)
                }));
                input.extend(seal(&config, &derived, direction, &packets)?);
            }
            let result = audit::inspect(&config, &derived, &input)?;
            assert_eq!(result["scope"], "structural-only");
            for direction in 0..2 {
                let row = &result["directions"][direction];
                assert_eq!(row.as_object().ok_or("counter row")?.len(), 9);
                assert_eq!(row["direction"], direction);
                assert_eq!(row["sources"], 1);
                assert_eq!(row["multi_unit_sources"], 1);
                assert_eq!(row["complete_packet_aggregation_sources"], 1);
                assert_eq!(row["max_units"], 2);
                assert_eq!(row["systematic_copies"], 1);
                assert_eq!(row["direct_copies"], 1);
                // A one-source partial block has one useful independent repair.
                assert_eq!(row["repair_packets"], 1);
                assert_eq!(row["duplicate_sources"], 1);
            }
        }
    }
    Ok(())
}

#[test]
fn physical_session_relationships_match_full_and_half_runtime_owners() -> Result<()> {
    for duplex in ["half", "full"] {
        let mut value = settings();
        value["duplex"] = json!(duplex);
        let (config, mut derived) = configure(&value)?;
        // Keep each packet internally consistent while violating only the
        // relation between the two real physical lane owners.
        derived.sessions[1] = if duplex == "half" { [7; 16] } else { [8; 16] };
        let mut input = Vec::new();
        for direction in 0..2 {
            let packets =
                recovery_packets(&derived, direction, &[two_packets(&derived, direction)?])?;
            input.extend(seal(&config, &derived, direction, &packets)?);
        }
        let error = audit::inspect(&config, &derived, &input)
            .err()
            .ok_or("invalid physical session relation accepted")?;
        assert!(error.to_string().contains(if duplex == "half" {
            "half physical lanes share one session"
        } else {
            "full physical lane session differs by direction"
        }));
    }
    Ok(())
}

#[test]
fn recovery_and_physical_sessions_cannot_be_substituted_independently() -> Result<()> {
    let (config, mut derived) = configure(&settings())?;
    for direction in 0..2 {
        let original = derived.sessions[usize::from(direction)];
        let packets = recovery_packets(&derived, direction, &[two_packets(&derived, direction)?])?;
        derived.sessions[usize::from(direction)] = [9; 16];
        let error = audit::inspect(
            &config,
            &derived,
            &seal(&config, &derived, direction, &packets)?,
        )
        .err()
        .ok_or("logical/physical session mismatch accepted")?;
        assert!(
            error
                .to_string()
                .contains("logical recovery session differs from physical lane")
        );
        derived.sessions[usize::from(direction)] = original;
    }
    Ok(())
}

#[test]
fn coherent_new_session_cannot_replace_an_observed_lane() -> Result<()> {
    let (config, mut derived) = configure(&settings())?;
    for direction in 0..2 {
        let original = derived.sessions[usize::from(direction)];
        let packets = recovery_packets(&derived, direction, &[two_packets(&derived, direction)?])?;
        let mut input = seal(&config, &derived, direction, &packets)?;
        derived.sessions[usize::from(direction)] = [9; 16];
        let changed = recovery_packets(&derived, direction, &[two_packets(&derived, direction)?])?;
        input.extend(seal(&config, &derived, direction, &changed)?);
        let error = audit::inspect(&config, &derived, &input)
            .err()
            .ok_or("coherent lane replacement accepted")?;
        assert!(error.to_string().contains("physical lane context changed"));
        derived.sessions[usize::from(direction)] = original;
    }
    Ok(())
}

#[test]
fn bounded_input_rejects_every_truncation_excess_count_and_direction() -> Result<()> {
    let (config, derived) = configure(&settings())?;
    let packet = direct(&derived, 0, two_packets(&derived, 0)?)?;
    let input = seal(&config, &derived, 0, &[packet])?;
    for end in 1..input.len() {
        assert!(
            audit::inspect(&config, &derived, &input[..end]).is_err(),
            "truncation {end}"
        );
    }
    let mut excess = input.clone();
    excess.push(0);
    assert!(audit::inspect(&config, &derived, &excess).is_err());
    for (offset, byte) in [(2, 2), (2, 1), (3, 1)] {
        let mut changed = input.clone();
        changed[offset] = byte;
        assert!(audit::inspect(&config, &derived, &changed).is_err());
    }
    let mut wrong_length = input.clone();
    wrong_length[..2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(audit::inspect(&config, &derived, &wrong_length).is_err());
    let bounded = input.repeat(RECORD_LIMIT);
    assert_eq!(
        audit::inspect(&config, &derived, &bounded)?["directions"][0]["duplicate_sources"],
        RECORD_LIMIT - 1
    );
    assert!(audit::inspect(&config, &derived, &input.repeat(RECORD_LIMIT + 1)).is_err());
    assert!(audit::inspect(&config, &derived, &vec![0; INPUT_LIMIT + 1]).is_err());
    assert_eq!(
        audit::inspect(&config, &derived, &[])?["directions"][0]["sources"],
        0
    );
    Ok(())
}

#[test]
fn strict_layer_scope_source_and_unit_range_consistency() -> Result<()> {
    let (config, derived) = configure(&settings())?;
    let source0 = two_packets(&derived, 0)?;
    let packet0 = direct(&derived, 0, source0.clone())?;
    let first = seal(&config, &derived, 0, std::slice::from_ref(&packet0))?;
    // Actual UDP runtime binds logical recovery to its physical TLS lane session.
    assert!(audit::inspect(&config, &derived, &first).is_ok());
    for (offset, value) in [(5, 1), (12, 9), (28, 2), (36, 1), (52, 1)] {
        let mut invalid = source0.clone();
        invalid[offset] = value;
        let packet = direct(&derived, 0, invalid)?;
        assert!(
            audit::inspect(&config, &derived, &seal(&config, &derived, 0, &[packet])?).is_err()
        );
    }
    for offset in [8 + 8, 8 + 24] {
        // Existing reliable prefix followed by actual ARQ session/epoch.
        let mut changed = packet0.clone();
        changed[offset] ^= 1;
        assert!(
            audit::inspect(&config, &derived, &seal(&config, &derived, 0, &[changed])?).is_err()
        );
    }
    let altered = source(
        &derived,
        0,
        0,
        0,
        &[
            raw_unit(&derived, 0, 0, &ip(8))?,
            raw_unit(&derived, 1, 1, &ip(9))?,
        ],
        &[0, 1],
    )?;
    let mut conflict = first.clone();
    conflict.extend(seal(
        &config,
        &derived,
        0,
        &[direct(&derived, 0, altered)?],
    )?);
    assert!(audit::inspect(&config, &derived, &conflict).is_err());
    let overlapping = source(
        &derived,
        0,
        1,
        1,
        &[raw_unit(&derived, 2, 2, &ip(4))?],
        &[2],
    )?;
    let packets = recovery_packets(&derived, 0, &[source0, overlapping])?;
    assert!(audit::inspect(&config, &derived, &seal(&config, &derived, 0, &packets)?).is_err());
    Ok(())
}

#[test]
fn context_fragment_and_duplicate_record_are_not_complete_aggregation() -> Result<()> {
    let (config, derived) = configure(&settings())?;
    let duplicates = source(
        &derived,
        0,
        0,
        0,
        &[
            raw_unit(&derived, 0, 0, &ip(1))?,
            raw_unit(&derived, 0, 0, &ip(1))?,
        ],
        &[0, 0],
    )?;
    let mut context = vec![0; 72];
    context[0] = 1;
    context[2] = 1; // Exact69-byte explicit kind0 context framing only.
    context[5] = 66;
    let fragment = vec![2, 0, 2, 4, 0, 4, 0, 0, 2, 0, 1, 9];
    packed::validate_unit(&fragment, derived.packed.protocol.envelope().symbol_bytes)?;
    let other = source(&derived, 0, 0, 0, &[context, fragment], &[1, 2])?;
    for payload in [duplicates, other] {
        let packet = direct(&derived, 0, payload)?;
        let result = audit::inspect(&config, &derived, &seal(&config, &derived, 0, &[packet])?)?;
        assert_eq!(result["directions"][0]["multi_unit_sources"], 1);
        assert_eq!(
            result["directions"][0]["complete_packet_aggregation_sources"],
            0
        );
    }
    Ok(())
}

#[test]
fn raw_ip_declared_length_and_systematic_length_are_exact() -> Result<()> {
    let (config, derived) = configure(&settings())?;
    for packet in [vec![0; 36], {
        let mut packet = ip(1);
        packet.push(0);
        packet
    }] {
        let payload = source(
            &derived,
            0,
            0,
            0,
            &[raw_unit(&derived, 0, 0, &packet)?],
            &[0],
        )?;
        assert!(
            audit::inspect(
                &config,
                &derived,
                &seal(&config, &derived, 0, &[direct(&derived, 0, payload)?])?
            )
            .is_err()
        );
    }
    let packets = recovery_packets(&derived, 0, &[two_packets(&derived, 0)?])?;
    let systematic = packets
        .iter()
        .find(|packet| kind(&derived, 0, packet).is_ok_and(|kind| kind == RecordKind::Systematic))
        .ok_or("systematic")?;
    let base = derived.packed.protocol.base;
    let view = l2tunnel_reliable::inspect_structural(
        systematic,
        EndpointRole::Initiator,
        base.max_recovery_packet_bytes,
        base.recovery.arq.max_source_bytes,
        base.recovery.fec.block,
    )?;
    let symbol = view.fec.ok_or("FEC view")?;
    assert_eq!(symbol.kind, l2tunnel_fec::SymbolKind::Systematic);
    let length_offset =
        l2tunnel_reliable::ENVELOPE_BYTES + l2tunnel_fec::HEADER_BYTES + symbol.coefficients.len();
    let mut invalid = systematic.clone();
    invalid[length_offset..length_offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(audit::inspect(&config, &derived, &seal(&config, &derived, 0, &[invalid])?).is_err());
    let mut capture = seal(&config, &derived, 0, std::slice::from_ref(systematic))?;
    let last = capture.len() - 1;
    capture[last] ^= 1;
    assert!(
        audit::inspect(&config, &derived, &capture).is_ok(),
        "structural audit must not pretend to verify HMAC"
    );
    Ok(())
}

#[test]
fn fec_generation_and_symbol_proofs_reject_cross_packet_conflicts() -> Result<()> {
    use l2tunnel_fec as fec;
    let (config, derived) = configure(&settings())?;
    let mut sources = Vec::new();
    for id in 0..3 {
        sources.push(source(
            &derived,
            0,
            id,
            id,
            &[raw_unit(&derived, id as u8, id, &ip(id as u8))?],
            &[id],
        )?);
    }
    sources.push(source(
        &derived,
        0,
        3,
        3,
        &[
            raw_unit(&derived, 0, 3, &ip(3))?,
            raw_unit(&derived, 1, 4, &ip(4))?,
        ],
        &[3, 4],
    )?);
    let packets = recovery_packets(&derived, 0, &sources)?;
    let prefix = packets
        .iter()
        .find(|packet| kind(&derived, 0, packet).is_ok_and(|kind| kind == RecordKind::Systematic))
        .ok_or("systematic fixture")?[..8]
        .to_vec();
    let direct: Vec<_> = packets
        .iter()
        .filter(|packet| kind(&derived, 0, packet).is_ok_and(|kind| kind == RecordKind::Source))
        .collect();
    assert_eq!(direct.len(), 4);
    let block = |indices: &[usize]| -> Result<fec::BlockEncoder> {
        let inputs: Vec<_> = indices.iter().map(|index| &direct[*index][8..]).collect();
        Ok(fec::BlockEncoder::new(
            fec::FecContext {
                session: fec::SessionId([7; 16]),
                epoch: fec::Epoch(1),
                direction: fec::Direction::ClientToServer,
                channel: fec::ChannelId(0),
            },
            fec::GenerationId(0),
            derived.packed.protocol.base.recovery.fec.block,
            &inputs,
        )?)
    };
    let wrap = |symbol: fec::EncodedSymbol| {
        let mut packet = prefix.clone();
        packet.extend(symbol.bytes);
        packet
    };
    let a = block(&[0, 1])?;
    let b = block(&[1, 2])?;
    let a0 = wrap(a.systematic(fec::SourceId(0))?);
    let a1 = wrap(a.systematic(fec::SourceId(1))?);
    assert!(
        audit::inspect(
            &config,
            &derived,
            &seal(&config, &derived, 0, &[a0.clone(), a1.clone()])?
        )
        .is_ok()
    );
    let cases = [
        (
            vec![a0.clone(), wrap(b.systematic(fec::SourceId(0))?)],
            "base ARQ source",
        ),
        (
            vec![a0.clone(), wrap(b.systematic(fec::SourceId(1))?)],
            "base ARQ source",
        ),
        (
            vec![
                a0.clone(),
                wrap(block(&[0, 3])?.systematic(fec::SourceId(1))?),
            ],
            "dimensions",
        ),
        (
            vec![wrap(block(&[0])?.systematic(fec::SourceId(0))?), a1],
            "dimensions",
        ),
        (
            vec![wrap(block(&[1, 0])?.systematic(fec::SourceId(1))?)],
            "precedes",
        ),
    ];
    for (packets, expected) in cases {
        let error = audit::inspect(&config, &derived, &seal(&config, &derived, 0, &packets)?)
            .err()
            .ok_or("conflict accepted")?;
        assert!(error.to_string().contains(expected), "{error}");
    }
    let repair = wrap(block(&[0, 1])?.repair(&[1, 2])?);
    let changed = wrap(block(&[0, 1])?.repair(&[2, 3])?);
    let error = audit::inspect(
        &config,
        &derived,
        &seal(&config, &derived, 0, &[repair.clone(), changed])?,
    )
    .err()
    .ok_or("repair conflict accepted")?;
    assert!(
        error
            .to_string()
            .contains("conflicting copies of one FEC symbol")
    );
    let observed = audit::inspect(
        &config,
        &derived,
        &seal(&config, &derived, 0, &[repair.clone(), repair])?,
    )?;
    assert_eq!(observed["directions"][0]["repair_packets"], 2);
    assert_eq!(observed["directions"][0]["sources"], 0);
    // Equal symbol/base/dimensions with altered actual ARQ bytes is also a conflict.
    let mut changed_source = direct[0][8..].to_vec();
    let last = changed_source.len() - 1;
    changed_source[last] ^= 1;
    let altered = fec::BlockEncoder::new(
        fec::FecContext {
            session: fec::SessionId([7; 16]),
            epoch: fec::Epoch(1),
            direction: fec::Direction::ClientToServer,
            channel: fec::ChannelId(0),
        },
        fec::GenerationId(0),
        derived.packed.protocol.base.recovery.fec.block,
        &[&changed_source, &direct[1][8..]],
    )?;
    let error = audit::inspect(
        &config,
        &derived,
        &seal(
            &config,
            &derived,
            0,
            &[a0, wrap(altered.systematic(fec::SourceId(0))?)],
        )?,
    )
    .err()
    .ok_or("systematic conflict accepted")?;
    assert!(
        error
            .to_string()
            .contains("conflicting copies of one FEC symbol")
    );
    Ok(())
}

#[test]
fn command_surface_is_exact_and_bounded() -> Result<()> {
    assert!(execute(&[]).is_err());
    assert!(
        execute(&[
            "audit".into(),
            "--input".into(),
            "a".into(),
            "--config".into(),
            "b".into()
        ])
        .is_err()
    );
    assert!(
        execute(&[
            "validate".into(),
            "--config".into(),
            "a".into(),
            "--input".into(),
            "b".into()
        ])
        .is_err()
    );
    let help = execute(&["--help".into()])?;
    assert!(help["limitations"].as_str().ok_or("help")?.contains("TUN"));
    let file =
        std::env::temp_dir().join(format!("l2tunnel-packed-audit-{}.json", std::process::id()));
    std::fs::write(&file, serde_json::to_vec(&settings())?)?;
    let result = execute(&[
        "validate".into(),
        "--config".into(),
        file.to_string_lossy().into_owned(),
    ]);
    std::fs::remove_file(&file)?;
    assert_eq!(result?["scope"], "configuration-only");
    assert!(read_bounded(Path::new("/tmp"), CONFIG_LIMIT).is_err());
    Ok(())
}
