//! Strict explicit selection and actual paired Profile resource/H0 binding.
use super::*;
fn selected() -> Value {
    json!({"initiator":{"selection":"benchmark","interval_micros":5000,"max_hold_micros":20000,"max_flows":4,"max_ack_bytes":130},"responder":null})
}
fn profile(value: &Value) -> io::Result<secure_udp::common_transaction_profile::Profile> {
    let plan = decode(value)?;
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
    let common = super::super::super::Common {
        appearance: l2tunnel_cover::Appearance::QuicLike,
        role: Role::Initiator,
        local: "127.0.0.1:41921".parse().map_err(io::Error::other)?,
        peer: "127.0.0.1:41922".parse().map_err(io::Error::other)?,
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
    plan.build(connection, settings, peers, body, overhead)
}
#[test]
fn optional_ack_policy_is_strict_and_binds_both_actual_role_resources_without_changing_descriptors()
-> io::Result<()> {
    let old = document(1)?;
    let original = profile(&old)?;
    assert_eq!(original.ack_coalescing(), [None, None]);
    let old_lines = super::super::super::common_cli_output::inspection(&original, Role::Initiator)?;
    assert!(old_lines[0].get("ack_coalescing").is_none());
    let mut selected_value = old.clone();
    selected_value["ack_coalescing"] = selected();
    let current = profile(&selected_value)?;
    assert_eq!(
        current.catalog().descriptors(),
        original.catalog().descriptors()
    );
    assert_ne!(current.envelope(), original.envelope());
    assert_ne!(current.configuration()?, original.configuration()?);
    let requested = current.ack_coalescing();
    assert!(requested[0].is_some());
    assert_eq!(requested[1], None);
    assert_eq!(
        current
            .runtime_contract(Role::Initiator)?
            .resources()
            .ack_coalescing,
        requested[0]
    );
    assert_eq!(
        current
            .runtime_contract(Role::Responder)?
            .resources()
            .ack_coalescing,
        None
    );
    let lines = super::super::super::common_cli_output::inspection(&current, Role::Initiator)?;
    assert_eq!(lines[0]["ack_coalescing"]["requested"], selected());
    assert!(lines[0]["ack_coalescing"]["effective"].is_null());
    assert_eq!(lines[0]["authenticated"], false);
    let mut changed = selected_value.clone();
    changed["ack_coalescing"]["responder"] = selected()["initiator"].clone();
    assert_ne!(
        profile(&changed)?.configuration()?,
        current.configuration()?
    );
    let paired = profile(&changed)?.envelope();
    changed["ack_coalescing"]["responder"]["interval_micros"] = json!(4000);
    assert_ne!(profile(&changed)?.envelope(), paired);
    for invalid_value in [
        Value::Null,
        json!({}),
        json!({"initiator":null,"responder":null}),
        json!({"initiator":selected()["initiator"],"responder":null,"unknown":1}),
    ] {
        let mut invalid = old.clone();
        invalid["ack_coalescing"] = invalid_value;
        assert!(profile(&invalid).is_err());
    }
    for (field, value) in [
        ("selection", json!("owned_tcp")),
        ("selection", json!("transparent")),
        ("max_hold_micros", json!(0)),
        ("max_flows", json!(9)),
        ("max_ack_bytes", json!(1501)),
        ("unknown", json!(1)),
    ] {
        let mut invalid = selected_value.clone();
        invalid["ack_coalescing"]["initiator"][field] = value;
        assert!(profile(&invalid).is_err(), "accepted unsupported {field}");
    }
    for field in [
        "selection",
        "interval_micros",
        "max_hold_micros",
        "max_flows",
        "max_ack_bytes",
    ] {
        let mut invalid = selected_value.clone();
        invalid["ack_coalescing"]["initiator"]
            .as_object_mut()
            .ok_or_else(|| io::Error::other("policy object"))?
            .remove(field);
        assert!(profile(&invalid).is_err(), "accepted missing {field}");
    }
    assert_eq!(profile(&old)?.configuration()?, original.configuration()?);
    Ok(())
}

#[test]
fn optional_rolling_ingress_is_strict_paired_and_bound_without_changing_descriptor_bytes()
-> io::Result<()> {
    let old = document(1)?;
    let original = profile(&old)?;
    assert_eq!(original.rolling_ingress(), [None, None]);
    let lines = super::super::super::common_cli_output::inspection(&original, Role::Initiator)?;
    assert!(lines[0].get("rolling_ingress").is_none());
    let selected = json!({"initiator":{"slots":2,"capacity_bytes":100000},"responder":null});
    let mut value = old.clone();
    value["rolling_ingress"] = selected.clone();
    let current = profile(&value)?;
    assert_eq!(
        current.catalog().descriptors(),
        original.catalog().descriptors()
    );
    assert_ne!(current.envelope(), original.envelope());
    assert_ne!(current.configuration()?, original.configuration()?);
    let requested = current.rolling_ingress();
    assert!(requested[0].is_some());
    assert_eq!(requested[1], None);
    assert_eq!(
        current
            .runtime_contract(Role::Initiator)?
            .resources()
            .rolling_ingress,
        requested[0]
    );
    assert_eq!(
        current
            .runtime_contract(Role::Responder)?
            .resources()
            .rolling_ingress,
        None
    );
    let lines = super::super::super::common_cli_output::inspection(&current, Role::Initiator)?;
    assert_eq!(lines[0]["rolling_ingress"]["requested"], selected);
    assert!(lines[0]["rolling_ingress"]["effective"].is_null());
    assert_eq!(lines[0]["authenticated"], false);
    let mut changed = value.clone();
    changed["rolling_ingress"]["responder"] = selected["initiator"].clone();
    let paired = profile(&changed)?.configuration()?;
    assert_ne!(paired, current.configuration()?);
    changed["rolling_ingress"]["responder"]["slots"] = json!(3);
    assert_ne!(profile(&changed)?.configuration()?, paired);
    for invalid_value in [
        Value::Null,
        json!({}),
        json!({"initiator":null,"responder":null}),
        json!({"initiator":selected["initiator"],"responder":null,"unknown":1}),
    ] {
        let mut invalid = old.clone();
        invalid["rolling_ingress"] = invalid_value;
        assert!(profile(&invalid).is_err());
    }
    for field in ["slots", "capacity_bytes"] {
        let mut missing = value.clone();
        missing["rolling_ingress"]["initiator"]
            .as_object_mut()
            .ok_or_else(|| io::Error::other("limits object"))?
            .remove(field);
        assert!(profile(&missing).is_err());
        for bad in [json!(0), json!(-1), json!(1.5)] {
            let mut invalid = value.clone();
            invalid["rolling_ingress"]["initiator"][field] = bad;
            assert!(profile(&invalid).is_err());
        }
    }
    assert_eq!(profile(&old)?.configuration()?, original.configuration()?);
    Ok(())
}

#[test]
fn raw_ack_ingress_requires_explicit_paired_limits_and_binds_actual_profile() -> io::Result<()> {
    let old = document(1)?;
    let original = profile(&old)?;
    assert_eq!(original.connection_ingress(), [None, None]);
    let mut value = old.clone();
    value["connection_ingress"] =
        json!({"initiator":{"slots":2,"capacity_bytes":100000},"responder":null});
    let current = profile(&value)?;
    assert_eq!(
        current.catalog().descriptors(),
        original.catalog().descriptors()
    );
    assert_ne!(current.configuration()?, original.configuration()?);
    assert_eq!(
        current
            .runtime_contract(Role::Initiator)?
            .resources()
            .connection_ingress,
        current.connection_ingress()[0]
    );
    assert_eq!(
        current
            .runtime_contract(Role::Responder)?
            .resources()
            .connection_ingress,
        None
    );
    let lines = super::super::super::common_cli_output::inspection(&current, Role::Initiator)?;
    assert_eq!(
        lines[0]["connection_ingress"]["requested"],
        value["connection_ingress"]
    );
    assert!(lines[0]["connection_ingress"]["effective"].is_null());
    assert!(lines[0]["connection_ingress"]["observation"].is_null());
    assert_eq!(lines[0]["authenticated"], false);
    let mut paired = value.clone();
    paired["connection_ingress"]["responder"] = json!({"slots":3,"capacity_bytes":100000});
    assert_ne!(profile(&paired)?.configuration()?, current.configuration()?);
    for invalid_value in [
        Value::Null,
        json!({"initiator":null,"responder":null}),
        json!({"initiator":{"slots":2,"capacity_bytes":100000}}),
        json!({"initiator":{"slots":0,"capacity_bytes":100000},"responder":null}),
        json!({"initiator":{"slots":2,"capacity_bytes":1},"responder":null}),
        json!({"initiator":{"slots":2,"capacity_bytes":100000,"extra":1},"responder":null}),
    ] {
        let mut invalid_value_plan = old.clone();
        invalid_value_plan["connection_ingress"] = invalid_value;
        assert!(profile(&invalid_value_plan).is_err());
    }
    assert_eq!(profile(&old)?.configuration()?, original.configuration()?);
    Ok(())
}
