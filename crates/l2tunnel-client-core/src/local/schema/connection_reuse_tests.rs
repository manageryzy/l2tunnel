use super::*;

fn key(port: u16) -> io::Result<FlowKey> {
    let mut bytes = [0; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..20].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    bytes[20..22].copy_from_slice(&port.to_be_bytes());
    bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    l2tunnel::packet::classify(
        l2tunnel::packet::PacketLayer::Ip,
        &bytes,
        l2tunnel::packet::ParseLimits::default(),
    )
    .map(|value| value.key)
    .map_err(io::Error::other)
}
#[test]
fn reuse_flow_keys_and_action_are_strict_bounded_and_explicit_v4() -> io::Result<()> {
    let a = key(1200)?;
    let b = key(1201)?;
    let request = ConnectionReuseRequest::new(15, a, b)?;
    let text = request.old_key.to_string();
    assert!(text.len() <= 124);
    assert_eq!(CanonicalFlowKey::parse(&text)?.key(), a);
    assert!(ConnectionReuseRequest::new(0, a, a).is_err());
    for bad in [
        String::new(),
        text.to_uppercase(),
        format!("{text}00"),
        "ab".repeat(63),
        text[..text.len() - 1].to_owned(),
    ] {
        assert!(CanonicalFlowKey::parse(&bad).is_err());
    }
    let action = Action::ReuseConnection {
        request,
        request_key: u64::MAX,
    };
    let wire = serde_json::to_string(&Request {
        version: COMMON_VERSION,
        action: action.clone(),
    })
    .map_err(io::Error::other)?;
    assert!(wire.len() < 1024);
    assert_eq!(
        serde_json::from_str::<Request>(&wire)
            .map_err(io::Error::other)?
            .action,
        action
    );
    for version in [VERSION, 2, 3] {
        let old = serde_json::to_string(&Request {
            version,
            action: action.clone(),
        })
        .map_err(io::Error::other)?;
        assert!(serde_json::from_str::<Request>(&old).is_err());
    }
    let mut unknown = serde_json::from_str::<serde_json::Value>(&wire).map_err(io::Error::other)?;
    unknown["action"]["request"]["authenticated"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Request>(unknown).is_err());
    assert_eq!(
        serde_json::to_string(&Request {
            version: VERSION,
            action: Action::Status {}
        })
        .map_err(io::Error::other)?,
        r#"{"version":1,"action":{"command":"status"}}"#
    );
    Ok(())
}
