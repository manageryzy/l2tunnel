use super::{
    Result,
    config::{Configuration, Derived, DuplexChoice, Layer},
};
use l2tunnel_codec::{
    aligned_body::{BodyKind, Decoded, Decoder, Padding},
    aligned_receiver::{Direction, Scope},
    packed_envelope,
};
use l2tunnel_core::Epoch;
use l2tunnel_datagram::{self as datagram, KeyContext};
use l2tunnel_recovery::EndpointRole;
use l2tunnel_reliable::{self as reliable, RecordKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default, Serialize)]
struct Counters {
    direction: u8,
    sources: usize,
    multi_unit_sources: usize,
    complete_packet_aggregation_sources: usize,
    max_units: usize,
    direct_copies: usize,
    systematic_copies: usize,
    repair_packets: usize,
    duplicate_sources: usize,
}

pub(super) fn inspect(
    config: &Configuration,
    derived: &Derived,
    input: &[u8],
) -> Result<serde_json::Value> {
    config.audit_profile()?;
    if input.len() > super::INPUT_LIMIT {
        return Err("capture byte limit exceeded".into());
    }
    let mut counters = [
        Counters::default(),
        Counters {
            direction: 1,
            ..Counters::default()
        },
    ];
    let mut physical: [Option<KeyContext>; 2] = [None, None];
    let mut logical = [None, None];
    // Keys and proofs borrow one input buffer capped at 8 MiB; at most4096 entries.
    let mut sources = BTreeMap::new();
    let mut ranges: [BTreeMap<u64, u64>; 2] = Default::default();
    let mut fec_symbols = BTreeMap::new();
    let mut fec_generations = BTreeMap::new();
    let mut offset = 0;
    let mut records = 0;
    while offset < input.len() {
        if records == super::RECORD_LIMIT {
            return Err("capture record limit exceeded".into());
        }
        records += 1;
        let header = input
            .get(offset..offset + 4)
            .ok_or("truncated input record header")?;
        let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
        let dir = usize::from(header[2]);
        if dir > 1 || header[3] != 0 {
            return Err("invalid input direction or reserved byte".into());
        }
        offset += 4;
        let packet = input
            .get(offset..offset + length)
            .ok_or("truncated input datagram")?;
        offset += length;
        let outer = datagram::inspect_structural(
            config.cover()?,
            datagram::Protection::HmacSha256,
            derived.geometry.udp_payload_ceiling,
            derived.geometry.recovery_packet_ceiling,
            packet,
        )?;
        let expected_direction = if dir == 0 {
            datagram::Direction::ClientToServer
        } else {
            datagram::Direction::ServerToClient
        };
        let expected_lane = if config.duplex == DuplexChoice::Half {
            dir as u32
        } else {
            0
        };
        if outer.context.direction != expected_direction
            || outer.context.lane.0 != expected_lane
            || outer.context.generation.0 != 0
            || outer.context.session.0 == [0; 16]
        {
            return Err(
                "physical direction/lane/generation/session differs from runtime profile".into(),
            );
        }
        if physical[dir].is_some_and(|prior| prior != outer.context) {
            return Err("physical lane context changed".into());
        }
        physical[dir] = Some(outer.context);
        if config.duplex == DuplexChoice::Full
            && physical[1 - dir].is_some_and(|other| other.session != outer.context.session)
        {
            return Err("full physical lane session differs by direction".into());
        }
        if config.duplex == DuplexChoice::Half
            && physical[1 - dir].is_some_and(|other| other.session == outer.context.session)
        {
            return Err("half physical lanes share one session".into());
        }
        let base = derived.packed.protocol.base;
        let inner = reliable::inspect_structural(
            outer.body,
            if dir == 0 {
                EndpointRole::Initiator
            } else {
                EndpointRole::Responder
            },
            base.max_recovery_packet_bytes,
            base.recovery.arq.max_source_bytes,
            base.recovery.fec.block,
        )?;
        if inner.sender.session == 0 || inner.sender.epoch != 1 {
            return Err("logical scope differs from fixed runtime epoch".into());
        }
        // This fixed UDP runtime constructs both owners from the same actual
        // TLS lane. Paired half duplex has two distinct lane sessions; full
        // duplex uses one session in both directions.
        if inner.sender.session.to_be_bytes() != outer.context.session.0 {
            return Err("logical recovery session differs from physical lane".into());
        }
        let scope_key = (inner.sender.session, inner.sender.epoch);
        if logical[dir].is_some_and(|prior| prior != scope_key) {
            return Err("logical recovery scope changed".into());
        }
        logical[dir] = Some(scope_key);
        if let Some(symbol) = inner.fec {
            let generation_key = (scope_key, dir, symbol.generation.0);
            let base = inner
                .source
                .map(|(source, _)| {
                    source
                        .0
                        .checked_sub(u64::from(symbol.symbol.0))
                        .ok_or("systematic ARQ source precedes its symbol index")
                })
                .transpose()?;
            let geometry = fec_generations.entry(generation_key).or_insert((
                symbol.source_count,
                symbol.coded_bytes,
                base,
            ));
            if geometry.0 != symbol.source_count || geometry.1 != symbol.coded_bytes {
                return Err("FEC generation dimensions changed".into());
            }
            if let Some(base) = base {
                if geometry.2.is_some_and(|prior| prior != base) {
                    return Err("systematic generation base ARQ source changed".into());
                }
                geometry.2 = Some(base);
            }
            let key = (generation_key, symbol.symbol.0);
            if fec_symbols.get(&key).is_some_and(|prior| *prior != symbol) {
                return Err("conflicting copies of one FEC symbol".into());
            }
            // Every proof borrows the already bounded input; both maps have at
            // most one new entry per input record, including repair-only records.
            fec_symbols.insert(key, symbol);
        }
        let row = &mut counters[dir];
        match inner.kind {
            RecordKind::Source => row.direct_copies += 1,
            RecordKind::Systematic => row.systematic_copies += 1,
            RecordKind::Repair => row.repair_packets += 1,
            RecordKind::Feedback => {
                return Err("feedback is not a UDP data record in this runtime".into());
            }
        }
        let Some((source, payload)) = inner.source else {
            continue;
        };
        let scope = Scope {
            session: inner.sender.session.to_be_bytes(),
            epoch: Epoch(inner.sender.epoch),
            direction: if dir == 0 {
                Direction::InitiatorToResponder
            } else {
                Direction::ResponderToInitiator
            },
        };
        let view = packed_envelope::decode(derived.packed.protocol.envelope(), scope, payload)?;
        if view.identity().source.0 != source.0 {
            return Err("ARQ and packed recovery source IDs disagree".into());
        }
        let key = (scope_key, dir, source.0);
        if let Some(prior) = sources.get(&key) {
            if *prior != payload {
                return Err("conflicting copies of one recovery source".into());
            }
            row.duplicate_sources += 1;
            continue;
        }
        let start = view.identity().first_unit.0;
        let end = start
            .checked_add(view.len() as u64 - 1)
            .ok_or("unit range overflow")?;
        if ranges[dir]
            .range(..=end)
            .next_back()
            .is_some_and(|(_, prior_end)| *prior_end >= start)
        {
            return Err("distinct recovery sources overlap the absolute unit range".into());
        }
        ranges[dir].insert(start, end);
        sources.insert(key, payload);
        row.sources += 1;
        row.max_units = row.max_units.max(view.len());
        row.multi_unit_sources += usize::from(view.len() >= 2);
        let mut complete = BTreeSet::new();
        for unit in view.units()? {
            // Framing and exact explicit length have already passed the codec.
            if unit.bytes[3] != 2 {
                continue;
            }
            let mut output = [0u8; 1600];
            let mut decoder = Decoder::new(base.receiver.body)?;
            let Decoded::Frame {
                written,
                kind: BodyKind::Raw,
                ..
            } = decoder.decode_body(&unit.bytes[3..], Padding::Exact, &mut output)?
            else {
                return Err("kind2 did not decode as a complete raw record".into());
            };
            if config.layer == Layer::Tun {
                let ip = &output[..written];
                l2tunnel_packet::classify(
                    l2tunnel_device::PacketLayer::Ip,
                    ip,
                    l2tunnel_packet::ParseLimits {
                        max_packet_bytes: 1600,
                        ..Default::default()
                    },
                )?;
                let exact = match ip[0] >> 4 {
                    4 => usize::from(u16::from_be_bytes([ip[2], ip[3]])) == ip.len(),
                    6 => 40 + usize::from(u16::from_be_bytes([ip[4], ip[5]])) == ip.len(),
                    _ => false,
                };
                if !exact {
                    return Err("raw IP unit has trailing or incomplete IP bytes".into());
                }
                complete.insert((unit.bytes[0], unit.identity.record.0));
            } else if super::ethernet::complete(&output[..written])? {
                complete.insert((unit.bytes[0], unit.identity.record.0));
            }
        }
        row.complete_packet_aggregation_sources += usize::from(complete.len() >= 2);
    }
    Ok(
        serde_json::json!({"version":1,"status":"passed","scope":"structural-only","directions":counters}),
    )
}
