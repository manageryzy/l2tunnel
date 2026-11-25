//! Explicit compact selection reaches the maintained Profile, never a parser-only flag.
use super::*;

#[test]
fn compact_plan_is_mandatory_with_strict_optional_protection_selection() -> io::Result<()> {
    let base = document(2)?;
    assert!(decode(&base)?.compact_wire.is_none());
    let selected = json!({"version":3,"data_protection":"aes-ccm-4",
        "max_forward_packets":8192,"max_failed_checks":64});
    for wrong in [
        Value::Null,
        json!({}),
        json!({"version":3,"data_protection":"unknown-protection",
        "max_forward_packets":8192,"max_failed_checks":64}),
    ] {
        let mut value = base.clone();
        value["compact_wire"] = wrong;
        assert!(decode(&value).is_err());
    }
    for protection in ["chacha20-poly1305", "hmac-sha256"] {
        let mut value = base.clone();
        value["compact_wire"] = selected.clone();
        value["compact_wire"]["data_protection"] = json!(protection);
        assert!(decode(&value)?.compact_wire.is_some());
    }
    for field in [
        "version",
        "data_protection",
        "max_forward_packets",
        "max_failed_checks",
    ] {
        let mut value = base.clone();
        value["compact_wire"] = selected.clone();
        value["compact_wire"]
            .as_object_mut()
            .ok_or_else(|| invalid("compact object"))?
            .remove(field);
        assert!(decode(&value).is_err(), "accepted missing {field}");
    }
    for (field, wrong) in [
        ("version", json!(2)),
        ("max_forward_packets", json!(0)),
        ("max_forward_packets", json!(2147483648u64)),
        ("max_failed_checks", json!(0)),
        ("unselected_default", json!(true)),
    ] {
        let mut value = base.clone();
        value["compact_wire"] = selected.clone();
        value["compact_wire"][field] = wrong;
        assert!(decode(&value).is_err(), "accepted invalid {field}");
    }
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(Zeroizing::new([21; 32])).public_key(),
        responder: hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key(),
    };
    let connection = ConnectionConfig {
        layer: l2tunnel_device::PacketLayer::Ip,
        duplex: l2tunnel_core::Duplex::Full,
        max_packet: 1500,
        compression: crate::Compression::None,
        handshake_timeout: Duration::from_secs(3),
    };
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let common = crate::cli::secure_udp_frontend::Common {
            appearance,
            role: Role::Initiator,
            local: "127.0.0.1:41921".parse().map_err(io::Error::other)?,
            peer: "127.0.0.1:41922".parse().map_err(io::Error::other)?,
            maximum_mtu: 2000,
            profile: hs::Profile::Ik,
        };
        let settings = common.raw(
            1500,
            connection.handshake_timeout,
            peers,
            l2tunnel_identity::MemberPublicKey([7; 32]),
        )?;
        let (overhead, body) = common.final_geometry()?;
        let legacy = decode(&base)?.build(connection, settings, peers, body, overhead)?;
        let lines = crate::cli::secure_udp_frontend::common_cli_output::inspection(
            &legacy,
            Role::Initiator,
        )?;
        assert_eq!(
            legacy.compact_wire().protection,
            l2tunnel_security::compact::Protection::ChaCha20Poly1305
        );
        assert_eq!(
            lines[0]["compact_wire"]["requested"]["data_protection"],
            "chacha20-poly1305"
        );
        assert_eq!(legacy.compact_wire().limits.max_failed_checks, u32::MAX);
        // A forward limit below 4 x the credit ceiling (2,048) is clamped and
        // reported, not refused.
        for (forward, ceiling) in [(8192_u32, 2048_u64), (4096, 1024)] {
            let mut value = base.clone();
            value["compact_wire"] = selected.clone();
            value["compact_wire"]["max_forward_packets"] = json!(forward);
            let profile = decode(&value)?.build(connection, settings, peers, body, overhead)?;
            let lines = crate::cli::secure_udp_frontend::common_cli_output::inspection(
                &profile,
                Role::Initiator,
            )?;
            let credit = &lines[0]["credit"];
            assert_eq!(credit["record_receive_range"], forward, "{credit}");
            assert_eq!(credit["requested_datagrams"][1], 2048, "{credit}");
            assert_eq!(credit["effective_datagrams"][1], ceiling, "{credit}");
            assert_eq!(credit["warning"].is_null(), forward == 8192, "{credit}");
        }
        let mut h0 = Vec::new();
        for protection in ["aes-ccm-4", "chacha20-crc32c"] {
            let mut value = base.clone();
            value["compact_wire"] = selected.clone();
            value["compact_wire"]["data_protection"] = json!(protection);
            let plan = decode(&value)?;
            let profile = plan.build(connection, settings, peers, body, overhead)?;
            assert_ne!(profile.configuration()?, legacy.configuration()?);
            h0.push(profile.configuration()?);
            assert_eq!(profile.catalog().descriptors(), plan.catalog.descriptors());
            for role in [Role::Initiator, Role::Responder] {
                let contract = profile.runtime_contract(role)?;
                assert_eq!(contract.expected_configuration(), profile.configuration()?);
                assert_eq!(
                    profile.establish_config(role)?.binding.configuration,
                    profile.configuration()?.0
                );
                assert_eq!(
                    contract.resources().control.wire_overhead,
                    28 + l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD
                );
                assert_eq!(contract.compact_wire(), profile.compact_wire());
                let lines =
                    crate::cli::secure_udp_frontend::common_cli_output::inspection(&profile, role)?;
                assert_eq!(
                    lines[0]["compact_wire"]["requested"]["data_protection"],
                    protection
                );
                assert!(lines[0]["compact_wire"]["effective"].is_null());
                assert_eq!(lines[0]["compact_wire"]["appearance"], "initial-only");
                assert_eq!(lines[0]["catalog_members"], 2);
            }
            value["outer_carrier"] = outer_policy(&value);
            let carrier_plan = decode(&value)?;
            carrier_plan.validate_carrier(true)?;
            assert!(carrier_plan.validate_carrier(false).is_err());
            let mut carrier_settings = settings;
            let (carrier_overhead, carrier_body) =
                common.carrier_geometry(&mut carrier_settings, carrier_plan.outer_capacity()?)?;
            let carrier_profile = carrier_plan.build(
                connection,
                carrier_settings,
                peers,
                carrier_body,
                carrier_overhead,
            )?;
            let outer = carrier_plan.outer_config(&carrier_profile)?;
            assert_eq!(
                outer.base.digest.0,
                carrier_profile.requested_configuration()?.0
            );
            assert_eq!(
                outer.outer_overhead_bytes, 29,
                "bootstrap still uses DataV1"
            );
            assert_eq!(
                carrier_profile
                    .requested_resources(Role::Initiator)
                    .control
                    .wire_overhead,
                49
            );
            let lines = crate::cli::secure_udp_frontend::common_cli_output::carrier_inspection(
                &carrier_profile,
                Role::Initiator,
                outer,
            )?;
            assert_eq!(lines[0]["carrier"], "openvpn-like");
            assert_eq!(
                lines[0]["compact_wire"]["requested"]["data_protection"],
                protection
            );
            assert!(lines[0]["compact_wire"]["effective"].is_null());
            assert!(lines[0]["effective_configuration"].is_null());
            assert_eq!(lines[0]["authenticated"], false);
        }
        assert_ne!(h0[0], h0[1]);
    }
    Ok(())
}

#[test]
fn compact_wire_proxy_cli_binds_complete_policy_and_retirement_before_authentication()
-> io::Result<()> {
    use l2tunnel::{pipeline, record_configuration as common};
    use l2tunnel_core::{Duplex, traffic::TcpControl};
    let old = descriptor(1_250_001)?;
    let direction = old.direction(l2tunnel_management::Role::Client).common();
    let mut pipeline = direction.pipeline();
    pipeline.flows.channels = 1;
    pipeline.flows.mapping = pipeline::Mapping::Crc32;
    let direction = common::CommonDirection::new(
        l2tunnel_core::traffic::TrafficPolicy {
            tcp: TcpControl::SplitTcpProxy,
            ..direction.traffic()
        },
        pipeline,
        direction.bytes_per_second(),
        direction.burst_bytes(),
        direction.native_window(),
    )
    .map_err(io::Error::other)?;
    let mut forward = native_fixtures::aligned(
        l2tunnel_device::PacketLayer::Ip,
        1500,
        28 + l2tunnel::secure_record::compact::DATA_OVERHEAD,
        false,
    );
    forward.receiver.channels = 1;
    forward.receiver.body.independent_short_frame_bytes = 0;
    forward.recovery.repair_symbols = 0;
    let reverse = forward;
    let descriptor = common::Descriptor::new(
        old.path_mtu(),
        Duplex::Full,
        direction,
        direction,
        common::Profile::Aligned { forward, reverse },
    )
    .map_err(io::Error::other)?;
    let mut document = document(1)?;
    document["catalog"] = json!([hex(descriptor)?]);
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(Zeroizing::new([21; 32])).public_key(),
        responder: hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key(),
    };
    let connection = ConnectionConfig {
        layer: l2tunnel_device::PacketLayer::Ip,
        duplex: Duplex::Full,
        max_packet: 1280,
        compression: crate::Compression::None,
        handshake_timeout: Duration::from_secs(3),
    };
    let frontend = crate::cli::secure_udp_frontend::Common {
        appearance: l2tunnel_cover::Appearance::QuicLike,
        role: Role::Initiator,
        local: "127.0.0.1:41921".parse().map_err(io::Error::other)?,
        peer: "127.0.0.1:41922".parse().map_err(io::Error::other)?,
        maximum_mtu: 2000,
        profile: hs::Profile::Ik,
    };
    let settings = frontend.raw(
        1280,
        connection.handshake_timeout,
        peers,
        l2tunnel_identity::MemberPublicKey([7; 32]),
    )?;
    let (overhead, maximum) = frontend.final_geometry()?;
    let mut proxy_settings =
        crate::proxy::Settings::new(crate::proxy::RoutePolicy::new(Vec::new())?);
    proxy_settings.channels = 1;
    let mut proxy = crate::proxy::runtime_config(connection, &proxy_settings)?;
    proxy.relay.max_record_bytes = 512;
    let packet = l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy::new(1500);
    let raw_selection = crate::raw_packet::common::Settings::from_json(
        &serde_json::to_vec(&json!({
            "version":1,"profile":"raw-common-carrier-v1",
            "forward":{"local":frontend.local,"peer":frontend.peer},"reverse":null,
            "packet":{"mtu":packet.mtu,"protection":"aead",
                "queue_packets":packet.queue_packets,"horizon_bytes":packet.horizon_bytes,
                "minimum_transfer_bytes":packet.minimum_transfer_bytes,
                "bytes_per_second":packet.bytes_per_second,"packets_per_second":packet.packets_per_second,
                "burst_bytes":packet.burst_bytes,"burst_packets":packet.burst_packets,
                "max_key_packets":packet.max_key_packets,"max_key_bytes":packet.max_key_bytes}
        }))
        .map_err(io::Error::other)?,
    )?;
    let mut digests = Vec::new();
    for protection in ["aes-ccm-4", "chacha20-crc32c"] {
        document["compact_wire"] = json!({"version":3,"data_protection":protection,
            "max_forward_packets":8192,"max_failed_checks":64});
        let plan = decode(&document)?;
        assert!(
            plan.build(connection, settings, peers, maximum, overhead)
                .is_err(),
            "proxy ownership must not become transparent native ownership"
        );
        for retained in [false, true] {
            let profile = plan.build_proxy(
                connection,
                settings,
                peers,
                maximum,
                overhead,
                proxy.clone(),
                retained,
            )?;
            assert_eq!(profile.proxy_retirement(), retained);
            assert_eq!(
                profile.compact_wire().protection,
                if protection == "aes-ccm-4" {
                    l2tunnel_security::compact::Protection::Aes128Ccm4
                } else {
                    l2tunnel_security::compact::Protection::ChaCha20Crc32c
                }
            );
            let binding = l2tunnel_runtime::proxy::session_config(&proxy)?.digest;
            for role in [Role::Initiator, Role::Responder] {
                let contract = profile.runtime_contract(role)?;
                assert_eq!(contract.proxy_binding(), Some(binding));
                assert_eq!(contract.proxy_retirement(), retained);
                assert_eq!(contract.expected_configuration(), profile.configuration()?);
            }
            digests.push(profile.configuration()?);
        }
        // The raw bootstrap uses the catalog's carrier MTU, independently of
        // the smaller native TCP MTU used by the proxy attachment.
        let mut raw_settings = frontend.raw(
            plan.initial().path_mtu(),
            connection.handshake_timeout,
            peers,
            l2tunnel_identity::MemberPublicKey([7; 32]),
        )?;
        let final_geometry = packet.final_record_geometry().map_err(io::Error::other)?;
        let (raw_overhead, _) = frontend.raw_geometry(
            &mut raw_settings,
            packet.record_geometry().map_err(io::Error::other)?,
            final_geometry,
        )?;
        let raw_profile = plan.build_selected_on(
            connection,
            raw_settings,
            peers,
            plan.protected_body_capacity(final_geometry.max_record_bytes)?,
            raw_overhead,
            Some(packet),
            Some((proxy.clone(), true)),
            None,
            None,
        )?;
        let lines = crate::cli::secure_udp_frontend::common_cli_output::raw_inspection(
            &raw_profile,
            Role::Initiator,
            &raw_selection,
        )?;
        assert!(raw_profile.raw_binding().is_none());
        assert_eq!(
            lines[0]["requested_final_framing"]["data_overhead_bytes"],
            61
        );
        assert_eq!(
            lines[0]["requested_final_framing"]["control_feedback_overhead_bytes"],
            61
        );
        assert!(lines[0]["effective_final_framing"].is_null());
        assert!(lines[0]["compact_wire"]["effective"].is_null());
        assert_eq!(lines[0]["authenticated"], false);
    }
    for (i, digest) in digests.iter().enumerate() {
        assert!(!digests[..i].contains(digest));
    }
    Ok(())
}
