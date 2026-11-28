//! New naming option validation only; actual TLS behavior is tested in auth.

use super::*;

fn values() -> BTreeMap<String, String> {
    [
        ("--sni", "cover.example"),
        ("--server-name", "own-server.test"),
        ("--ca", "/missing/tls-roots.der"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect()
}

#[test]
fn explicit_sni_selects_only_actual_wired_tls_readers_and_client_roles() -> io::Result<()> {
    let named = values();
    preflight("connect", &named)?;
    for traffic in ["system", "active", "proxy", "proxy-measured"] {
        let mut selected = named.clone();
        selected.insert("--carrier".into(), "tcp".into());
        selected.insert("--traffic".into(), traffic.into());
        preflight("connect", &selected)?;
    }
    let mut raw = named.clone();
    raw.insert("--carrier".into(), "raw-packet".into());
    preflight("connect", &raw)?;
    let mut carrier = named.clone();
    carrier.insert("--carrier".into(), "openvpn-like".into());
    carrier.insert("--record-profile".into(), "common".into());
    carrier.insert(
        "--common-transaction-plan".into(),
        "/missing/plan.json".into(),
    );
    preflight("connect", &carrier)?;
    carrier.insert("--role".into(), "connect".into());
    preflight("inspect-common-transaction-plan", &carrier)?;
    carrier.insert("--role".into(), "serve".into());
    assert!(preflight("inspect-common-transaction-plan", &carrier).is_err());
    for command in [
        "serve",
        "keygen",
        "status",
        "inspect-swift-transaction-plan",
    ] {
        assert!(preflight(command, &named).is_err());
    }
    for unsupported in ["udp", "quic", "quic-like", "media-like", "openvpn-like"] {
        let mut selected = named.clone();
        selected.insert("--carrier".into(), unsupported.into());
        assert!(preflight("connect", &selected).is_err());
    }
    let mut unwired = named;
    unwired.insert("--record-profile".into(), "rolling".into());
    assert!(preflight("connect", &unwired).is_err());
    Ok(())
}

#[test]
fn invalid_sni_and_role_refusals_precede_credential_or_runtime_side_effects() -> io::Result<()> {
    for invalid in [
        "",
        "127.0.0.1",
        "::1",
        "bad name.test",
        "a..test",
        "a\0.test",
    ] {
        let mut options = values();
        options.insert("--sni".into(), invalid.into());
        let error = preflight("connect", &options)
            .err()
            .ok_or_else(|| input("accepted invalid SNI"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        #[cfg(target_os = "linux")]
        {
            // The deliberately missing CA must never be opened: malformed SNI
            // wins with InvalidInput rather than that file's NotFound result.
            let error = client(&options)
                .err()
                .ok_or_else(|| input("constructed invalid TLS"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }
    let mut absent = values();
    absent.remove("--server-name");
    assert!(preflight("connect", &absent).is_err());
    Ok(())
}

#[test]
fn naming_observation_is_requested_only_and_omission_has_no_new_output() -> io::Result<()> {
    let named = values();
    preflight("connect", &named)?;
    assert_eq!(
        requested(&named)?,
        Some(serde_json::json!({
            "event":"tls_name_policy","schema":1,
            "requested":{"sni":"cover.example","verification_name":"own-server.test"},
            "effective":null,"authenticated":false
        })),
    );
    let mut old = named;
    old.remove("--sni");
    assert_eq!(policy(&old)?, auth::ClientSni::Disabled);
    assert!(requested(&old)?.is_none());
    preflight("serve", &old)?;
    preflight("keygen", &old)?;
    #[cfg(target_os = "linux")]
    {
        let certificate = rcgen::generate_simple_self_signed(vec!["own-server.test".to_owned()])
            .map_err(io::Error::other)?;
        let roots = [certificate.cert.der().to_vec()];
        let actual = from_roots(&old, &roots)?;
        assert_eq!(actual.sni(), &auth::ClientSni::Disabled);
        let mut options = old;
        options.insert("--sni".into(), "cover.example".into());
        let actual = from_roots(&options, &roots)?;
        assert_eq!(
            actual.sni(),
            &auth::ClientSni::Named("cover.example".into())
        );
        assert_eq!(options["--server-name"], "own-server.test");
    }
    Ok(())
}

#[test]
fn server_pin_preflight_validates_hex_carrier_and_client_role() -> io::Result<()> {
    let valid_pin = "a".repeat(64);
    let mut tcp = BTreeMap::new();
    tcp.insert("--server-pin".into(), valid_pin.clone());
    tcp.insert("--server-name".into(), "own-server.test".into());
    tcp.insert("--ca".into(), "/missing/tls-roots.der".into());
    preflight("connect", &tcp)?;
    assert!(preflight("serve", &tcp).is_err());

    // Maintained QUIC accepts --server-pin (unlike --sni).
    let mut quic = tcp.clone();
    quic.insert("--carrier".into(), "quic".into());
    quic.insert("--record-profile".into(), "common".into());
    quic.insert("--maintained-policy".into(), "/missing/policy.json".into());
    preflight("connect", &quic)?;

    // Non-TLS UDP covers reject --server-pin.
    let mut udp = tcp.clone();
    udp.insert("--carrier".into(), "quic-like".into());
    udp.insert("--record-profile".into(), "common".into());
    assert!(preflight("connect", &udp).is_err());

    // Malformed pin is rejected before opening CA file.
    let mut bad = tcp;
    bad.insert("--server-pin".into(), "not-64-hex".into());
    assert_eq!(
        preflight("connect", &bad).err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    Ok(())
}
