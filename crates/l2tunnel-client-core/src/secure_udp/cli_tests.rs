use super::*;

fn options_for(command: &str, carrier: &str) -> BTreeMap<String, String> {
    let mut options: BTreeMap<_, _> = [
        ("--carrier", carrier),
        ("--record-profile", "swift"),
        ("--duplex", "full"),
        ("--compression", "off"),
        ("--layer", "tun"),
        ("--device", "no-device-opened"),
        (
            "--udp-bind",
            if command == "connect" {
                "127.0.0.1:42101"
            } else {
                "127.0.0.1:42102"
            },
        ),
        (
            "--udp-peer",
            if command == "connect" {
                "127.0.0.1:42102"
            } else {
                "127.0.0.1:42101"
            },
        ),
        ("--noise-profile", "ik"),
        ("--noise-private-key-file", "absent-private"),
        ("--noise-peer-key-file", "absent-pin"),
        ("--session-admission-key-file", "absent-admission"),
        ("--swift-forward-kbit", "10000"),
        ("--swift-reverse-kbit", "5000"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    if command == "connect" {
        options.insert("--identity".into(), "absent-member".into());
    } else {
        options.insert("--allow-key".into(), "absent-member-public".into());
        options.insert("--session-cookie-key-file".into(), "absent-cookie".into());
    }
    options
}

#[test]
fn explicit_carrier_selection_is_pure_and_global_views_match() -> io::Result<()> {
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(zeroize::Zeroizing::new([11; 32])).public_key(),
        responder: hs::LocalSecret::new(zeroize::Zeroizing::new([22; 32])).public_key(),
    };
    for carrier in ["quic-like", "media-like"] {
        let client = options_for("connect", carrier);
        let server = options_for("serve", carrier);
        let client_config = configuration(&client)?;
        let server_config = configuration(&server)?;
        let client = selection("connect", &client, client_config)?
            .ok_or_else(|| input("missing selection"))?;
        let server = selection("serve", &server, server_config)?
            .ok_or_else(|| input("missing selection"))?;
        let a = client.build(
            client_config,
            peers,
            l2tunnel_identity::MemberPublicKey([7; 32]),
        )?;
        let b = server.build(
            server_config,
            peers,
            l2tunnel_identity::MemberPublicKey([7; 32]),
        )?;
        assert_eq!(a.configuration(peers)?, b.configuration(peers)?);
        assert_eq!(a.settings().cover, b.settings().cover);
        assert_eq!(a.runtime(security::Role::Initiator).path_mtu, 1500);
        let header = if carrier == "quic-like" { 13 } else { 14 };
        assert_eq!(
            a.runtime(security::Role::Initiator).security.max_body_bytes + 9 + 26 + header + 28,
            9000
        );
        assert_eq!(
            a.settings().cover.max_packet_bytes + 28,
            if carrier == "quic-like" { 9017 } else { 9000 }
        );
    }
    Ok(())
}

#[test]
fn short_setup_deadline_bounds_derived_cookie_and_retry_without_extending_it() -> io::Result<()> {
    let options = options_for("connect", "quic-like");
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(zeroize::Zeroizing::new([11; 32])).public_key(),
        responder: hs::LocalSecret::new(zeroize::Zeroizing::new([22; 32])).public_key(),
    };
    for deadline in [Duration::from_millis(300), Duration::from_millis(50)] {
        let mut connection = configuration(&options)?;
        connection.handshake_timeout = deadline;
        let profile = selection("connect", &options, connection)?
            .ok_or_else(|| input("missing explicit carrier"))?
            .build(
                connection,
                peers,
                l2tunnel_identity::MemberPublicKey([7; 32]),
            )?;
        let gate = profile.settings().gate;
        assert_eq!(profile.connection().handshake_timeout, deadline);
        assert_eq!(gate.handshake_timeout, deadline);
        assert_eq!(gate.cookie_ttl, deadline);
        assert_eq!(gate.maximum_rto, deadline);
        assert_eq!(gate.initial_rto, Duration::from_millis(100).min(deadline));
        profile.configuration(peers)?;
    }
    Ok(())
}

#[test]
fn invalid_or_legacy_combinations_fail_before_any_credential_file_read() -> io::Result<()> {
    let valid = options_for("connect", "quic-like");
    let mutations: [(&str, &str); 12] = [
        ("--carrier", "udp"),
        ("--record-profile", "system"),
        ("--duplex", "half"),
        ("--compression", "lz4"),
        ("--udp-peer", "127.0.0.1:0"),
        ("--noise-profile", "ikpsk2"),
        ("--noise-psk-file", "absent-psk"),
        ("--path-mtu", "100"),
        ("--max-path-mtu", "1000"),
        ("--swift-channels", "65"),
        ("--swift-forward-kbit", "63"),
        ("--ca", "absent-tls-root"),
    ];
    for (key, value) in mutations {
        let mut options = valid.clone();
        options.insert(key.into(), value.into());
        let config = configuration(&options)?;
        assert!(
            selection("connect", &options, config).is_err(),
            "accepted {key}={value}"
        );
    }
    let mut options = valid.clone();
    options.insert("--noise-profile".into(), "ikpsk2".into());
    options.insert("--noise-psk-file".into(), "absent-psk".into());
    assert!(selection("connect", &options, configuration(&options)?)?.is_some());
    assert!(selection("serve", &valid, configuration(&valid)?).is_err());
    Ok(())
}

#[test]
fn legacy_carriers_and_missing_selector_do_not_become_secure_udp() -> io::Result<()> {
    for carrier in ["tcp", "udp", "quic", "openvpn-like"] {
        let options = [("--carrier".into(), carrier.into())].into_iter().collect();
        let config = ConnectionConfig {
            layer: PacketLayer::Ip,
            duplex: Duplex::Full,
            max_packet: 1600,
            compression: Compression::None,
            handshake_timeout: Duration::from_secs(3),
        };
        assert!(selection("connect", &options, config)?.is_none());
    }
    Ok(())
}
