//! Explicit compact selection reaches the maintained Profile, never a parser-only flag.
use super::*;

#[test]
fn compact_plan_is_strict_optional_and_legacy_inspection_stays_absent() -> io::Result<()> {
    let base = document(2)?;
    assert!(decode(&base)?.compact_wire.is_none());
    let selected = json!({"version":3,"data_protection":"aes-ccm-4",
        "max_forward_packets":8192,"max_failed_checks":64});
    for wrong in [
        Value::Null,
        json!({}),
        json!({"version":3,"data_protection":"chacha20-poly1305",
        "max_forward_packets":8192,"max_failed_checks":64}),
    ] {
        let mut value = base.clone();
        value["compact_wire"] = wrong;
        assert!(decode(&value).is_err());
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
        let (overhead, body) = common.geometry()?;
        let legacy = decode(&base)?.build(connection, settings, peers, body, overhead)?;
        let lines = crate::cli::secure_udp_frontend::common_cli_output::inspection(
            &legacy,
            Role::Initiator,
        )?;
        assert!(legacy.compact_wire().is_none());
        assert!(lines[0].get("compact_wire").is_none());
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
            assert!(decode(&value).is_err());
        }
        assert_ne!(h0[0], h0[1]);
    }
    Ok(())
}
