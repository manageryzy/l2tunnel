//! Finite parser and actual Profile construction; no socket/device startup.
use super::*;
use crate::secure_udp::common_status::tests::descriptor;
use l2tunnel_handshake as hs;
use l2tunnel_security::Role;
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[path = "common_cli_native_fixtures.rs"]
mod native_fixtures;
fn hex(descriptor: Descriptor) -> io::Result<String> {
    let mut bytes = [0; DESCRIPTOR_BYTES];
    descriptor
        .encode_into(&mut bytes)
        .map_err(io::Error::other)?;
    Ok(bytes.iter().map(|value| format!("{value:02x}")).collect())
}
fn document(count: usize) -> io::Result<Value> {
    let old = super::super::transaction_cli::test_plan_value();
    let mut catalog = Vec::new();
    for i in 0..count {
        catalog.push(hex(descriptor(1_250_001 + i as u64)?)?);
    }
    Ok(
        json!({"version":1,"backend":"common_records_v2","initial_index":0,"catalog":catalog,
        "transaction":old["transaction"],"runtime":old["runtime"],"rolling_work":null}),
    )
}
fn decode(value: &Value) -> io::Result<Plan> {
    Plan::decode(&serde_json::to_vec(value).map_err(io::Error::other)?)
}
fn outer_policy(value: &Value) -> Value {
    json!({"version":1,"backend":"openvpn_wire_common","max_record_bytes":1471,
        "control_arq":value["runtime"]["control"]["recovery"],
        "handshake_timeout_micros":3_000_000,"lifetime_micros":60_000_000,
        "packet_slots":8,"stream_bytes":65536,"poll_interval_micros":1000,"work_limit":16,
        "wire_budget":{"interval_micros":1000,"packets":128,"ip_bytes":131072,
            "reserved_control_packets":8,"reserved_control_bytes":8192,"maximum_control_packets":64}})
}
#[test]
fn complete_outer_policy_is_explicit_strict_and_exclusive_with_bare_plans() -> io::Result<()> {
    let mut value = document(1)?;
    let bare = decode(&value)?;
    bare.validate_carrier(false)?;
    assert!(bare.validate_carrier(true).is_err());
    value["outer_carrier"] = outer_policy(&value);
    decode(&value)?.validate_carrier(true)?;
    assert!(decode(&value)?.validate_carrier(false).is_err());
    for field in [
        "version",
        "backend",
        "max_record_bytes",
        "control_arq",
        "handshake_timeout_micros",
        "lifetime_micros",
        "packet_slots",
        "stream_bytes",
        "poll_interval_micros",
        "work_limit",
        "wire_budget",
    ] {
        let mut missing = value.clone();
        missing["outer_carrier"]
            .as_object_mut()
            .ok_or_else(|| invalid("outer object"))?
            .remove(field);
        assert!(decode(&missing).is_err(), "accepted missing {field}");
    }
    let mut unknown = value.clone();
    unknown["outer_carrier"]["hidden_default"] = json!(1);
    assert!(decode(&unknown).is_err());
    for (field, replacement) in [("version", json!(2)), ("backend", json!("protected"))] {
        let mut changed = value.clone();
        changed["outer_carrier"][field] = replacement;
        assert!(decode(&changed)?.validate_carrier(true).is_err());
    }
    Ok(())
}
#[test]
fn carrier_plan_inspection_derives_exact_cover_capacity_and_keeps_requested_full64()
-> io::Result<()> {
    let mut value = document(64)?;
    value["outer_carrier"] = outer_policy(&value);
    if let Some(path) = std::env::var_os("L2TUNNEL_CARRIER_INSPECTION_FIXTURE") {
        // Optional public fixture export; ordinary test runs have no file effects.
        let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
        if bytes.len() > 256 * 1024 {
            return Err(invalid(
                "carrier inspection fixture exceeds plan file bound",
            ));
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        std::io::Write::write_all(&mut file, &bytes)?;
        file.sync_all()?;
    }
    let plan = decode(&value)?;
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
        for role in [Role::Initiator, Role::Responder] {
            let common = super::super::Common {
                appearance,
                role,
                local: if role == Role::Initiator {
                    "127.0.0.1:41921"
                } else {
                    "127.0.0.1:41922"
                }
                .parse()
                .map_err(io::Error::other)?,
                peer: if role == Role::Initiator {
                    "127.0.0.1:41922"
                } else {
                    "127.0.0.1:41921"
                }
                .parse()
                .map_err(io::Error::other)?,
                maximum_mtu: 2000,
                profile: hs::Profile::Ik,
            };
            let mut settings = common.raw(
                1500,
                connection.handshake_timeout,
                peers,
                l2tunnel_identity::MemberPublicKey([7; 32]),
            )?;
            let (overhead, body) =
                common.carrier_geometry(&mut settings, plan.outer_capacity()?)?;
            assert_eq!(settings.cover.max_packet_bytes, 1471);
            let protected = if appearance == l2tunnel_cover::Appearance::QuicLike {
                1441
            } else {
                1457
            };
            assert_eq!(settings.cover.max_protected_bytes, protected);
            assert_eq!(
                body,
                protected - 9 - l2tunnel_security::COMMON_PREFIX_BYTES - 16
            );
            let profile = plan.build(connection, settings, peers, body, overhead)?;
            assert_eq!(profile.catalog().descriptors(), plan.catalog.descriptors());
            let outer = plan.outer_config(&profile)?;
            assert_eq!(outer.base.digest.0, profile.requested_configuration()?.0);
            assert_eq!(outer.base.layer, connection.layer);
            assert_eq!(outer.path_mtu, 1500);
            assert_eq!(outer.outer_overhead_bytes, 29);
            assert_eq!(outer.max_record_bytes, settings.cover.max_packet_bytes);
            assert_eq!(
                outer.control_arq,
                plan.outer_carrier
                    .as_ref()
                    .ok_or_else(|| invalid("outer absent"))?
                    .control_arq
                    .build()
            );
            let lines = super::super::common_cli_output::carrier_inspection(&profile, role, outer)?;
            assert_eq!(lines.len(), 17);
            assert_eq!(lines[0]["carrier"], "openvpn-like");
            assert_eq!(lines[0]["configuration_scope"], "requested_base_E0");
            assert_eq!(lines[0]["authenticated_outer_binding_required"], true);
            assert!(lines[0]["effective_configuration"].is_null());
            assert!(lines[0]["effective_envelope"].is_null());
            assert!(lines[0].get("initial").is_none());
            let mut count = 0;
            for line in lines.iter().skip(1) {
                assert_eq!(line["configuration_scope"], "requested_base_E0");
                count += line["configurations"]
                    .as_array()
                    .ok_or_else(|| invalid("configurations"))?
                    .len();
            }
            assert_eq!(count, 64);
            let mut invalid = outer;
            invalid.max_record_bytes += 1;
            assert!(invalid.validate().is_err());
        }
    }
    Ok(())
}
#[test]
fn complete_plan_bounds_full64_and_rejects_noncanonical_or_missing_fields() -> io::Result<()> {
    let full = document(64)?;
    assert_eq!(decode(&full)?.catalog.descriptors().len(), 64);
    for changed in [
        {
            let mut value = full.clone();
            value["catalog"] = json!([]);
            value
        },
        {
            let mut value = full.clone();
            let extra = value["catalog"][0].clone();
            value["catalog"]
                .as_array_mut()
                .ok_or_else(|| invalid("array"))?
                .push(extra);
            value
        },
        {
            let mut value = full.clone();
            value["catalog"][0] = json!(
                value["catalog"][0]
                    .as_str()
                    .ok_or_else(|| invalid("string"))?
                    .to_uppercase()
            );
            value
        },
        {
            let mut value = full.clone();
            value
                .as_object_mut()
                .ok_or_else(|| invalid("object"))?
                .remove("rolling_work");
            value
        },
        {
            let mut value = full.clone();
            value["runtime"]["typo"] = json!(1);
            value
        },
    ] {
        assert!(decode(&changed).is_err());
    }
    Ok(())
}
#[test]
fn actual_common_profile_inspection_keeps64_full_members_in_bounded_pages() -> io::Result<()> {
    let plan = decode(&document(64)?)?;
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
    for role in [Role::Initiator, Role::Responder] {
        let common = super::super::Common {
            appearance: l2tunnel_cover::Appearance::QuicLike,
            role,
            local: if role == Role::Initiator {
                "127.0.0.1:41921"
            } else {
                "127.0.0.1:41922"
            }
            .parse()
            .map_err(io::Error::other)?,
            peer: if role == Role::Initiator {
                "127.0.0.1:41922"
            } else {
                "127.0.0.1:41921"
            }
            .parse()
            .map_err(io::Error::other)?,
            maximum_mtu: 2000,
            profile: hs::Profile::Ik,
        };
        let (overhead, body) = common.geometry()?;
        let settings = common.raw(
            1500,
            connection.handshake_timeout,
            peers,
            l2tunnel_identity::MemberPublicKey([7; 32]),
        )?;
        let profile = plan.build(connection, settings, peers, body, overhead)?;
        let lines = super::super::common_cli_output::inspection(&profile, role)?;
        assert_eq!(lines.len(), 17);
        assert_eq!(lines[0]["catalog_members"], 64);
        let mut all = Vec::new();
        for line in lines.iter().skip(1) {
            let values = line["configurations"]
                .as_array()
                .ok_or_else(|| invalid("configurations"))?;
            assert_eq!(values.len(), 4);
            all.extend(values.iter().cloned());
            assert!(
                serde_json::to_vec(line).map_err(io::Error::other)?.len()
                    < super::super::transaction_cli_output::MAX_VALUE_BYTES
            );
        }
        let expected = profile
            .catalog()
            .configurations(profile.envelope())
            .map_err(io::Error::other)?;
        assert_eq!(all.len(), 64);
        for (actual, expected) in all.into_iter().zip(expected) {
            let actual: crate::secure_udp::common_status::CanonicalConfiguration =
                serde_json::from_value(actual).map_err(io::Error::other)?;
            assert_eq!(actual.configuration()?, expected);
        }
    }
    Ok(())
}
