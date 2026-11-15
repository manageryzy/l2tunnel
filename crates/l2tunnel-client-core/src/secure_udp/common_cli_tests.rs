//! Finite parser and actual Profile construction; no socket/device startup.
use super::*;
use crate::secure_udp::common_status::tests::descriptor;
use l2tunnel_handshake as hs;
use l2tunnel_security::Role;
use serde_json::{Value, json};
use zeroize::Zeroizing;
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
