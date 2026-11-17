use super::*;
use transaction::Configuration as Canonical;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn swift_policy(reverse: bool) -> records::Config {
    records::Config {
        channels: if reverse { 2 } else { 3 },
        layer: records::Layer::Ethernet,
        max_native: 1500,
        codec: swift::Config {
            datagram_bytes: if reverse { 1200 } else { 1424 },
            window: if reverse { 5 } else { 7 },
            repair_numerator: if reverse { 2 } else { 1 },
            repair_denominator: if reverse { 7 } else { 3 },
            flow_sources: if reverse { 11 } else { 9 },
            queue_bytes: if reverse { 32769 } else { 65537 },
            max_packet: 1501,
            flush_micros: if reverse { 17 } else { 123 },
            feedback_micros: if reverse { 3007 } else { 5001 },
            tail_micros: if reverse { 11003 } else { 10001 },
            min_rto_micros: if reverse { 30001 } else { 20001 },
            max_rto_micros: if reverse { 700003 } else { 900001 },
        },
    }
}
fn aligned_policy(reverse: bool, packed: bool) -> aligned::Config {
    let symbol = if reverse { 256 } else { 128 };
    let units = if reverse { 4 } else { 3 };
    let original = if packed {
        56 + 8 * units + symbol
    } else {
        48 + symbol
    };
    let source = 44 + original;
    let count = if reverse { 2 } else { 3 };
    let packet = 56 + count + 2 + source;
    let send_records = if reverse { 6 } else { 8 };
    let receive_records = if reverse { 7 } else { 8 };
    let restored = if reverse { 17 } else { 16 };
    aligned::Config {
        native_policy: if reverse {
            aligned::NativePolicy::RawIp
        } else {
            aligned::NativePolicy::EthernetHeaders
        },
        receiver: aligned_receiver::Limits {
            body: aligned_body::Config {
                max_frame_bytes: if reverse { 1600 } else { 1500 },
                symbol_bytes: symbol,
                independent_short_frame_bytes: if reverse { 23 } else { 17 },
                elide_payload_length: !reverse,
                predictive: !reverse,
                timestamp_pair_dictionary: !reverse,
            },
            channels: if reverse { 4 } else { 3 },
            first_record: aligned_receiver::RecordId(if reverse { 19 } else { 7 }),
            first_source: aligned_receiver::SourceId(0),
            record_window: if reverse { 31 } else { 32 },
            source_window: if reverse { 33 } else { 32 },
            lookahead_records: if reverse { 9 } else { 8 },
            lookahead_bytes: if packed {
                units * 65535
            } else if reverse {
                16384
            } else {
                8192
            },
            lookahead_fragments: if packed {
                units * 65535usize.div_ceil(symbol - 8)
            } else if reverse {
                4096
            } else {
                8192
            },
            max_fragments_per_record: 65535usize.div_ceil(symbol - 8),
            lifetime_ticks: if reverse { 6000 } else { 5000 },
        },
        recovery: ReliableConfig {
            arq: ArqConfig {
                max_source_bytes: original,
                send_bytes: send_records * original + if reverse { 5 } else { 1 },
                receive_bytes: receive_records * original + if reverse { 7 } else { 3 },
                send_records,
                receive_records,
                initial_rto: Duration::from_nanos(if reverse { 150000011 } else { 100000001 }),
                maximum_rto: Duration::from_nanos(if reverse { 450000013 } else { 400000003 }),
                ack_delay: Duration::from_nanos(if reverse { 7000017 } else { 1000007 }),
                max_retries: if reverse { 1 } else { 2 },
            },
            fec: fec::DecoderConfig {
                block: fec::BlockConfig {
                    max_sources: count,
                    max_source_bytes: source,
                    max_packet_bytes: packet,
                    max_work_per_symbol: if reverse { 1000003 } else { 1000001 },
                },
                max_generations: if reverse { 5 } else { 4 },
                max_symbols_per_generation: if reverse { 4 } else { 5 },
                max_reserved_bytes: if reverse { 1000009 } else { 1000007 },
                max_lifetime_ticks: if reverse { 59 } else { 53 },
                generation_window: if reverse { 37 } else { 32 },
            },
            repair_symbols: if reverse { 1 } else { 2 },
            flush_after: Duration::from_nanos(if reverse { 9000019 } else { 5000009 }),
            max_restored_packets: restored,
            max_restored_bytes: restored * source + if reverse { 13 } else { 11 },
            outer_overhead_bytes: if reverse { 73 } else { 17 },
        },
        max_recovery_packet_bytes: 8 + packet + if reverse { 9 } else { 7 },
    }
}
fn common(reverse: bool, raw: bool, channels: u16, native: usize) -> Result<CommonDirection> {
    let qos = pipeline::TunQosConfig {
        base_quantum_bytes: 1201,
        max_weight: 3,
        per_flow: pipeline::QueueLimits {
            bytes: 32771,
            packets: 17,
        },
    };
    let pipeline = pipeline::PipelineConfig {
        profile: if raw {
            pipeline::Profile::TunDrr(qos)
        } else {
            pipeline::Profile::TapSystem
        },
        flows: pipeline::FlowTableConfig {
            capacity: if reverse { 43 } else { 41 },
            channels,
            mapping: if reverse {
                Mapping::ConnectionRoundRobin
            } else {
                Mapping::Crc32
            },
            idle_timeout: Duration::new(if reverse { 3 } else { 1 }, if reverse { 4 } else { 2 }),
        },
        parse: pipeline::ParseLimits {
            max_packet_bytes: native,
            max_vlan_tags: if reverse { 2 } else { 3 },
            max_ipv6_extensions: if reverse { 5 } else { 7 },
            max_ipv6_extension_bytes: if reverse { 160 } else { 192 },
        },
        queue: pipeline::QueueLimits {
            bytes: if reverse { 65539 } else { 65537 },
            packets: if reverse { 131 } else { 129 },
        },
    };
    let window = if reverse {
        NativeWindow::Delivery(delivery_window::Config {
            target_bandwidth_bps: 4000000,
            bootstrap_rtt_micros: 70000,
            min_rtt_micros: 100,
            max_rtt_micros: 200000,
            headroom_percent: 125,
            minimum_bytes: native as u64,
            max_inflight_bytes: 100000,
            max_records: 17,
            max_packet_bytes: native as u64,
            metadata_limit_bytes: 10000,
            sample_ttl_micros: 4000000,
            flush_timeout_micros: 2000000,
        })
    } else {
        NativeWindow::Disabled
    };
    Ok(CommonDirection::new(
        if raw {
            traffic::TrafficPolicy::tun_tcp_proxy()
        } else {
            traffic::TrafficPolicy::tap()
        },
        pipeline,
        if reverse { 1000002 } else { 2000001 },
        if reverse { 8195 } else { 8193 },
        window,
    )?)
}
fn fixture(name: &str) -> Result<Configuration> {
    let (profile, channels, native, raw) = match name {
        "swift" => (
            Profile::Swift {
                forward: swift_policy(false),
                reverse: swift_policy(true),
            },
            2,
            1500,
            false,
        ),
        "aligned" => (
            Profile::Aligned {
                forward: aligned_policy(false, false),
                reverse: aligned_policy(true, false),
            },
            4,
            1600,
            true,
        ),
        "packed" => (
            Profile::Packed {
                forward: aligned::packed::Config {
                    base: aligned_policy(false, true),
                    hold_micros: 201,
                    max_units: 3,
                    work_limit: 2,
                },
                reverse: aligned::packed::Config {
                    base: aligned_policy(true, true),
                    hold_micros: 901,
                    max_units: 4,
                    work_limit: 3,
                },
            },
            4,
            1600,
            true,
        ),
        _ => return Err("fixture family".into()),
    };
    Ok(Configuration::new(
        EnvelopeDigest::new([0xa5; 32]),
        Descriptor::new(
            1500,
            Duplex::Full,
            common(false, false, 3, 1500)?,
            common(true, raw, channels, native)?,
            profile,
        )?,
    )?)
}
fn hex(value: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut chunks = value.as_bytes().chunks_exact(2);
    for bytes in &mut chunks {
        result.push(u8::from_str_radix(std::str::from_utf8(bytes)?, 16)?);
    }
    if !chunks.remainder().is_empty() {
        return Err("odd vector hex".into());
    }
    Ok(result)
}
fn encoded(value: &Configuration) -> Result<[u8; CONFIGURATION_BYTES]> {
    let mut bytes = [0; CONFIGURATION_BYTES];
    value.encode_into(&mut bytes)?;
    Ok(bytes)
}
fn word(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn literal_complete_bytes_and_independent_sha256_cover_all_actual_families() -> Result {
    for line in include_str!("vectors.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let mut fields = line.split('\t');
        let name = fields.next().ok_or("name")?;
        let bytes = hex(fields.next().ok_or("wire")?)?;
        let digest = hex(fields.next().ok_or("digest")?)?;
        assert_eq!(fields.next(), None);
        let value = fixture(name)?;
        assert_eq!(bytes.len(), 1304);
        assert_eq!(encoded(&value)?.as_slice(), bytes);
        assert_eq!(Configuration::decode(&bytes)?, value);
        assert_eq!(value.digest()?.0.as_slice(), digest);
        assert_eq!(transaction::configuration_digest(&value)?, value.digest()?);
        assert_eq!(
            <Configuration as Canonical>::ENCODING,
            transaction::ConfigurationEncoding::CompleteV2
        );
    }
    Ok(())
}

#[test]
fn current_transaction_refuses_previous_systematic_extent_domain() -> Result {
    use l2tunnel_core::Epoch;
    use l2tunnel_management::{EndpointId, Frame, Ingress, LaneId, SessionId};
    use transaction::{Fence, Identity, Peer, Settings, Tick};

    let initial = fixture("aligned")?;
    let mut next = initial;
    next.descriptor.forward.bytes_per_second += 1;
    let supported = [initial, next];
    let make = |role| {
        Peer::new_directional(
            Identity {
                session: SessionId([7; 16]),
                role,
                local: EndpointId(if role == Role::Client { 1 } else { 2 }),
                remote: EndpointId(if role == Role::Client { 2 } else { 1 }),
                lane: LaneId(3),
            },
            Epoch(1),
            initial,
            &supported,
            Settings::default(),
            Tick(0),
        )
    };
    let mut client = make(Role::Client)?;
    client.propose(next, Tick(0))?;
    let fence = Fence::new(&vec![0; usize::from(initial.sender_channels(Role::Client))])?;
    let prepare = client.staged(fence, Tick(1))?.outbound.ok_or("prepare")?;
    let limits = transaction::configuration_limits::<Configuration>()?;
    let mut previous = Frame::decode(&prepare, limits)?;
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(b"l2tunnel/record-transaction-config/v4\0");
    context.update(&encoded(&next)?);
    previous
        .header
        .ticket
        .digest
        .0
        .copy_from_slice(context.finish().as_ref());
    assert_ne!(previous.header.ticket.digest, next.digest()?);
    let mut old_prepare = vec![0; prepare.len()];
    assert_eq!(previous.encode(&mut old_prepare, limits)?, prepare.len());
    let ingress = Ingress::AuthenticatedManagement {
        session: SessionId([7; 16]),
        lane: LaneId(3),
        sender: Role::Client,
    };
    // The same canonical policy bytes are valid; the old authenticated ticket
    // digest cannot authorize the new systematic extent grammar.
    assert!(matches!(
        make(Role::Server)?.receive(ingress, &old_prepare, Tick(2)),
        Err(transaction::Error::Unexpected)
    ));
    assert!(matches!(
        make(Role::Server)?
            .receive(ingress, &prepare, Tick(2))?
            .event,
        Some(transaction::Event::Stage { .. })
    ));
    Ok(())
}

#[test]
fn every_wire_byte_is_preserved_or_refused_instead_of_silently_defaulted() -> Result {
    for name in ["swift", "aligned", "packed"] {
        let original = fixture(name)?;
        let bytes = encoded(&original)?;
        for index in 0..CONFIGURATION_BYTES {
            let mut changed = bytes;
            changed[index] ^= 1;
            if let Ok(decoded) = Configuration::decode(&changed) {
                assert_ne!(decoded, original, "{name} byte {index}");
                assert_eq!(encoded(&decoded)?, changed);
                assert_ne!(decoded.digest()?, original.digest()?);
            }
        }
    }
    Ok(())
}

#[test]
fn inactive_profile_qos_and_window_padding_are_strict_in_both_directions() -> Result {
    for (name, used) in [("swift", 120), ("aligned", 332)] {
        let original = encoded(&fixture(name)?)?;
        for base in [320, 948] {
            for index in base + used..base + 356 {
                let mut changed = original;
                changed[index] = 1;
                assert_eq!(Configuration::decode(&changed), Err(Error::Padding));
            }
        }
    }
    let original = encoded(&fixture("swift")?)?;
    for base in [48, 676] {
        for index in base + 9 * 8..base + 13 * 8 {
            let mut changed = original;
            changed[index] = 1;
            assert_eq!(Configuration::decode(&changed), Err(Error::Padding));
        }
    }
    for index in 48 + 22 * 8..48 + 34 * 8 {
        let mut changed = original;
        changed[index] = 1;
        assert_eq!(Configuration::decode(&changed), Err(Error::Padding));
    }
    Ok(())
}

#[test]
fn exact_lengths_tags_booleans_durations_and_narrow_integers_fail_closed() -> Result {
    let original = encoded(&fixture("aligned")?)?;
    for n in 0..CONFIGURATION_BYTES {
        assert_eq!(Configuration::decode(&original[..n]), Err(Error::Length));
    }
    let mut extra = original.to_vec();
    extra.push(0);
    assert_eq!(Configuration::decode(&extra), Err(Error::Length));
    for (offset, byte) in [(0, 0), (4, 1), (5, 0), (5, 10), (6, 0), (6, 3), (7, 1)] {
        let mut changed = original;
        changed[offset] = byte;
        assert_eq!(Configuration::decode(&changed), Err(Error::Prefix));
    }
    for index in [320 + 25, 320 + 26, 320 + 27] {
        let mut changed = original;
        changed[index] = 2;
        assert_eq!(Configuration::decode(&changed), Err(Error::Scalar));
    }
    for offset in [
        48 + 8 * 8,
        676 + 8 * 8,
        320 + 156,
        320 + 172,
        320 + 188,
        320 + 292,
    ] {
        let mut changed = original;
        word(&mut changed, offset, 1_000_000_000);
        assert_eq!(Configuration::decode(&changed), Err(Error::Scalar));
    }
    for offset in [48 + 6 * 8, 48 + 14 * 8, 320 + 28, 320 + 196] {
        let mut changed = original;
        word(&mut changed, offset, u64::MAX);
        assert_eq!(Configuration::decode(&changed), Err(Error::Integer));
    }
    let mut changed = encoded(&fixture("swift")?)?;
    word(&mut changed, 320 + 5 * 8, u64::from(u32::MAX) + 1);
    assert_eq!(Configuration::decode(&changed), Err(Error::Integer));
    Ok(())
}

#[test]
fn global_role_projection_and_profile_width_boundaries_preserve_complete_values() -> Result {
    for name in ["swift", "aligned", "packed"] {
        let config = fixture(name)?;
        let descriptor = config.descriptor();
        let client = descriptor.local(Role::Client);
        let server = descriptor.local(Role::Server);
        assert_eq!(client.send(), server.receive());
        assert_eq!(client.receive(), server.send());
        assert_eq!(client.send().channels(), 3);
        assert_eq!(
            client.receive().channels(),
            if name == "swift" { 2 } else { 4 }
        );
        assert_eq!(client.send().common().bytes_per_second(), 2000001);
        assert_eq!(client.receive().common().bytes_per_second(), 1000002);
        assert_eq!(
            descriptor.sender_channels(Role::Server),
            client.receive().channels()
        );
    }
    for (name, maximum) in [("swift", 64), ("aligned", 256), ("packed", 255)] {
        let original = encoded(&fixture(name)?)?;
        for channels in [1, maximum] {
            let mut changed = original;
            word(&mut changed, 48 + 6 * 8, channels);
            word(
                &mut changed,
                if name == "swift" { 320 } else { 320 + 28 },
                channels,
            );
            assert_eq!(
                Configuration::decode(&changed)?
                    .descriptor()
                    .sender_channels(Role::Client),
                channels as u16
            );
        }
        for channels in [0, maximum + 1] {
            let mut changed = original;
            word(&mut changed, 48 + 6 * 8, channels);
            word(
                &mut changed,
                if name == "swift" { 320 } else { 320 + 28 },
                channels,
            );
            assert!(Configuration::decode(&changed).is_err());
        }
    }
    Ok(())
}

#[test]
fn incompatible_complete_relations_refuse_without_mutating_output() -> Result {
    let original = fixture("swift")?;
    let bytes = encoded(&original)?;
    for (offset, value) in [(48 + 6 * 8, 4), (48 + 13 * 8, 1499), (676 + 30 * 8, 1499)] {
        let mut changed = bytes;
        word(&mut changed, offset, value);
        assert_eq!(Configuration::decode(&changed), Err(Error::Relation));
    }
    let mut bad = original;
    bad.descriptor.forward.bytes_per_second = 0;
    let mut output = [0xa5; CONFIGURATION_BYTES];
    assert_eq!(bad.encode_into(&mut output), Err(Error::Rate));
    assert_eq!(output, [0xa5; CONFIGURATION_BYTES]);
    let mut short = [0xa5; CONFIGURATION_BYTES - 1];
    assert_eq!(original.encode_into(&mut short), Err(Error::Length));
    assert_eq!(short, [0xa5; CONFIGURATION_BYTES - 1]);
    Ok(())
}

#[test]
fn catalogs_are_exact_sorted_anchor_free_bounded_and_initial_is_not_reordered() -> Result {
    let swift = *fixture("swift")?.descriptor();
    let aligned = *fixture("aligned")?.descriptor();
    let packed = *fixture("packed")?.descriptor();
    let catalog = Catalog::new(aligned, &[packed, swift, aligned])?;
    assert_eq!(catalog.descriptors(), [swift, aligned, packed]);
    assert_eq!(catalog.initial(), aligned);
    let expected = hex(include_str!("catalog-root.hex").trim())?;
    assert_eq!(catalog.root().as_bytes().as_slice(), expected);
    assert_eq!(
        Catalog::new(aligned, &[aligned, aligned]),
        Err(Error::Duplicate)
    );
    assert_eq!(
        Catalog::new(aligned, &[swift, packed]),
        Err(Error::Unlisted)
    );
    assert_eq!(Catalog::new(swift, &[]), Err(Error::CatalogSize));
    let mut many = Vec::new();
    for i in 0..65 {
        let mut member = swift;
        member.path_mtu += i;
        many.push(member);
    }
    assert_eq!(Catalog::new(swift, &many[..64])?.descriptors().len(), 64);
    assert_eq!(Catalog::new(swift, &many), Err(Error::CatalogSize));
    let a = catalog.configurations(EnvelopeDigest::new([1; 32]))?;
    let b = catalog.configurations(EnvelopeDigest::new([2; 32]))?;
    assert_eq!(a.len(), 3);
    for (a, b) in a.iter().zip(&b) {
        assert_eq!(a.descriptor(), b.descriptor());
        assert_ne!(a.digest()?, b.digest()?);
    }
    Ok(())
}

#[test]
fn represented_traffic_policy_is_not_a_claim_of_active_proxy_or_receipt_integration() -> Result {
    let original = fixture("aligned")?;
    let common = original.descriptor().local(Role::Server).send().common();
    assert_eq!(common.traffic().tcp, traffic::TcpControl::SplitTcpProxy);
    assert!(matches!(common.native_window(), NativeWindow::Delivery(_)));
    let mut requested = original;
    requested.descriptor.reverse.traffic.tcp = traffic::TcpControl::TunnelCredits;
    assert_eq!(Configuration::decode(&encoded(&requested)?)?, requested);
    assert_ne!(requested.digest()?, original.digest()?);
    // This pure value never constructs Active, terminates TCP or admits an engine.
    Ok(())
}

#[test]
fn common_rate_is_positive_exact_u64_without_legacy_resolver_clamping() -> Result {
    for name in ["swift", "aligned", "packed"] {
        let original = fixture(name)?;
        for rate in [1, 7999, 1250000001, u64::MAX] {
            let mut requested = original;
            requested.descriptor.forward.bytes_per_second = rate;
            let decoded = Configuration::decode(&encoded(&requested)?)?;
            assert_eq!(
                decoded
                    .descriptor()
                    .direction(Role::Client)
                    .common()
                    .bytes_per_second(),
                rate
            );
            assert_eq!(decoded, requested);
        }
        let mut invalid = original;
        invalid.descriptor.forward.bytes_per_second = 0;
        assert_eq!(invalid.validate(), Err(Error::Rate));
    }
    Ok(())
}

#[test]
fn existing_swift_v1_domain_wire_and_digest_remain_available() -> Result {
    use crate::swift_configuration as legacy;
    let records = |reverse| swift::policy::Direction {
        records: swift_policy(reverse),
        bytes_per_second: if reverse { 1000002 } else { 2000001 },
    };
    let descriptor = legacy::Descriptor::new(1500, records(false), records(true))?;
    let value = legacy::Configuration::new(legacy::EnvelopeDigest::new([0xa5; 32]), descriptor)?;
    let mut bytes = [0; legacy::CONFIGURATION_BYTES];
    value.encode_into(&mut bytes)?;
    assert_eq!(bytes.len(), 304);
    assert_eq!(&bytes[..8], b"L2TC\x01\x01\x01\x00");
    assert_eq!(
        <legacy::Configuration as Canonical>::ENCODING,
        transaction::ConfigurationEncoding::LegacyV1
    );
    assert_eq!(
        transaction::configuration_digest(&value)?.0.as_slice(),
        hex(concat!(
            "d650a7171ac7e34589355f4138c4e334",
            "23bb87623660357be0649eb663767e1b"
        ))?
    );
    assert!(Configuration::decode(&bytes).is_err());
    assert!(<legacy::Configuration as Canonical>::decode(&encoded(&fixture("swift")?)?).is_err());
    Ok(())
}

#[path = "compact_tests.rs"]
mod compact;
