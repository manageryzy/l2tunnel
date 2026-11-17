use super::*;
use l2tunnel_core::Duplex;
type Failure = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), Failure>;
fn connection(duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    }
}
#[test]
fn required_policy_fields_and_authoritative_defaults() -> io::Result<()> {
    let settings = Settings::from_json(
        br#"{"version":1,"channels":16,"time_wait_reset":"maintained","routes":[]}"#,
    )?;
    assert_eq!(settings, Settings::new(RoutePolicy::new(Vec::new())?));
    assert!(Settings::from_json(br#"{"version":1,"routes":[]}"#).is_err());
    Ok(())
}

#[test]
fn strict_policy_rejects_unknown_missing_duplicate_and_excessive_fields() -> TestResult {
    let base = serde_json::json!({"version":1,"channels":16,"time_wait_reset":"maintained","routes":[{"source":"10.0.0.0/24","destination":"10.1.0.0/24","ports":{"first":443,"last":443}}]});
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("channels", serde_json::json!(0)),
        ("channels", serde_json::json!(257)),
        ("time_wait_reset", serde_json::json!("automatic")),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut changed = base.clone();
        changed[field] = value;
        assert!(Settings::from_json(&serde_json::to_vec(&changed)?).is_err());
    }
    for text in [
        "10.0.0.1/24",
        "10.0.0.0/33",
        "10.0.0.0",
        "10.0.0.0/24 ",
        "localhost/24",
        "[::]/0",
        "::%1/0",
        "::/129",
    ] {
        let mut changed = base.clone();
        changed["routes"][0]["source"] = serde_json::json!(text);
        assert!(Settings::from_json(&serde_json::to_vec(&changed)?).is_err());
    }
    for (key, value) in [("first", 0), ("last", 442), ("last", 65536)] {
        let mut changed = base.clone();
        changed["routes"][0]["ports"][key] = serde_json::json!(value);
        assert!(Settings::from_json(&serde_json::to_vec(&changed)?).is_err());
    }
    let mut mixed = base.clone();
    mixed["routes"][0]["destination"] = serde_json::json!("fd00::/64");
    assert!(Settings::from_json(&serde_json::to_vec(&mixed)?).is_err());
    let mut unknown = base.clone();
    unknown["routes"][0]["ports"]["extra"] = serde_json::json!(0);
    assert!(Settings::from_json(&serde_json::to_vec(&unknown)?).is_err());
    let repeated = vec![base["routes"][0].clone(); 257];
    let mut large = base.clone();
    large["routes"] = serde_json::json!(repeated);
    assert!(Settings::from_json(&serde_json::to_vec(&large)?).is_err());
    large["routes"] = serde_json::json!(vec![base["routes"][0].clone(); 256]);
    assert_eq!(
        Settings::from_json(&serde_json::to_vec(&large)?)?
            .routes
            .rules()
            .len(),
        1
    );
    assert!(Settings::from_json(&vec![b' '; MAX_POLICY_BYTES + 1]).is_err());
    assert!(Settings::from_json(br#"{"version":1,"version":1,"channels":16,"time_wait_reset":"maintained","routes":[]}"#).is_err());
    Ok(())
}
#[test]
fn canonical_fixed_binding_and_incompatible_profiles() -> TestResult {
    let a=Settings::from_json(br#"{"version":1,"channels":4,"time_wait_reset":"maintained","routes":[{"source":"fd00::/64","destination":"fd01::/64","ports":{"first":1,"last":443}},{"source":"10.0.0.0/24","destination":"10.1.0.0/24","ports":{"first":443,"last":443}}]}"#)?;
    let mut b = a.clone();
    let mut rules = b.routes.rules().to_vec();
    rules.reverse();
    rules.push(rules[0]);
    b.routes = RoutePolicy::new(rules)?;
    let base = connection(Duplex::Half);
    let binding = runtime::session_config(&runtime_config(base, &a)?)?;
    assert_eq!(
        binding,
        runtime::session_config(&runtime_config(base, &b)?)?
    );
    assert_ne!(binding, base.session()?);
    for changed in [
        ConnectionConfig {
            layer: PacketLayer::Ethernet,
            ..base
        },
        ConnectionConfig {
            compression: Compression::Lz4IfSmaller,
            ..base
        },
        ConnectionConfig {
            handshake_timeout: Duration::ZERO,
            ..base
        },
        ConnectionConfig {
            handshake_timeout: Duration::from_secs(121),
            ..base
        },
        ConnectionConfig {
            max_packet: 1279,
            ..base
        },
    ] {
        assert!(runtime_config(changed, &a).is_err());
    }
    b.channels = 5;
    assert_ne!(
        binding,
        runtime::session_config(&runtime_config(base, &b)?)?
    );
    b = a.clone();
    b.time_wait_reset_policy = TimeWaitResetPolicy::IgnoreInTimeWait;
    assert_ne!(
        binding,
        runtime::session_config(&runtime_config(base, &b)?)?
    );
    b.channels = 257;
    assert!(runtime_config(base, &b).is_err());
    Ok(())
}

#[test]
fn maximum_mixed_ipv6_literal_has_canonical_policy_identity() -> TestResult {
    let text = "2001:db8:ffff:ffff:ffff:ffff:192.168.255.255/128";
    assert_eq!(text.len(), 48);
    // The maximum textual IPv6 address has six four-digit hex groups.
    let longest = "2001:ffff:ffff:ffff:ffff:ffff:192.168.255.255/128";
    assert_eq!(longest.len(), 49);
    let policy = serde_json::json!({"version":1,"channels":16,"time_wait_reset":"maintained","routes":[{"source":longest,"destination":longest,"ports":{"first":443,"last":443}}]});
    let settings = Settings::from_json(&serde_json::to_vec(&policy)?)?;
    let address: IpAddr = longest.split_once('/').ok_or("CIDR")?.0.parse()?;
    let canonical = format!("{address}/128");
    let mut other = policy;
    other["routes"][0]["source"] = serde_json::json!(canonical);
    other["routes"][0]["destination"] = serde_json::json!(canonical);
    let normalized = Settings::from_json(&serde_json::to_vec(&other)?)?;
    assert_eq!(settings, normalized);
    let cfg = connection(Duplex::Full);
    assert_eq!(
        runtime::session_config(&runtime_config(cfg, &settings)?)?,
        runtime::session_config(&runtime_config(cfg, &normalized)?)?
    );
    assert!(prefix(&format!("{}0", longest)).is_err());
    Ok(())
}
