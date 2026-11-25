use super::*;

fn options_for(command: &str, carrier: &str) -> BTreeMap<String, String> {
    let mut options: BTreeMap<_, _> = [
        ("--carrier", carrier),
        ("--record-profile", "common"),
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
        ("--max-packet", "1500"),
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
    let file = transaction_integration_tests::PlanFile::new(
        &transaction_integration_tests::common_value()?,
    )?;
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(zeroize::Zeroizing::new([11; 32])).public_key(),
        responder: hs::LocalSecret::new(zeroize::Zeroizing::new([22; 32])).public_key(),
    };
    for carrier in ["quic-like", "media-like"] {
        let mut profiles = Vec::new();
        for role in ["connect", "serve"] {
            let mut options = options_for(role, carrier);
            options.insert(
                "--common-transaction-plan".into(),
                file.0.to_string_lossy().into_owned(),
            );
            let config = configuration(&options)?;
            let selected =
                selection(role, &options, config)?.ok_or_else(|| input("missing selection"))?;
            let Built::Records(profile) =
                selected.build(config, peers, l2tunnel_identity::MemberPublicKey([7; 32]))?
            else {
                return Err(input("native profile became proxy"));
            };
            assert_eq!(
                profile
                    .runtime_contract(security::Role::Initiator)?
                    .geometry()
                    .forward_overhead_bytes,
                49
            );
            assert_eq!(
                profile
                    .requested_resources(security::Role::Initiator)
                    .security
                    .max_body_bytes,
                9000 - 28 - 21
            );
            profiles.push(profile);
        }
        assert_eq!(profiles[0].configuration()?, profiles[1].configuration()?);
        assert_eq!(profiles[0].settings().cover, profiles[1].settings().cover);
    }
    Ok(())
}
#[test]
fn short_setup_deadline_bounds_derived_cookie_and_retry_without_extending_it() -> io::Result<()> {
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(zeroize::Zeroizing::new([11; 32])).public_key(),
        responder: hs::LocalSecret::new(zeroize::Zeroizing::new([22; 32])).public_key(),
    };
    let common = Common {
        appearance: l2tunnel_cover::Appearance::QuicLike,
        role: security::Role::Initiator,
        local: "127.0.0.1:42101".parse().map_err(io::Error::other)?,
        peer: "127.0.0.1:42102".parse().map_err(io::Error::other)?,
        maximum_mtu: 9000,
        profile: hs::Profile::Ik,
    };
    for deadline in [Duration::from_millis(300), Duration::from_millis(50)] {
        let settings = common.raw(
            1500,
            deadline,
            peers,
            l2tunnel_identity::MemberPublicKey([7; 32]),
        )?;
        let gate = settings.gate;
        assert_eq!(gate.handshake_timeout, deadline);
        assert_eq!(gate.cookie_ttl, deadline);
        assert_eq!(gate.maximum_rto, deadline);
        assert_eq!(gate.initial_rto, Duration::from_millis(100).min(deadline));
    }
    Ok(())
}

#[test]
fn invalid_or_legacy_combinations_fail_before_any_credential_file_read() -> io::Result<()> {
    let file = transaction_integration_tests::PlanFile::new(
        &transaction_integration_tests::common_value()?,
    )?;
    let mut valid = options_for("connect", "quic-like");
    valid.insert(
        "--common-transaction-plan".into(),
        file.0.to_string_lossy().into_owned(),
    );
    let mutations: [(&str, &str); 11] = [
        ("--carrier", "udp"),
        ("--record-profile", "system"),
        ("--duplex", "half"),
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
    let mut compressed = valid.clone();
    compressed.insert("--compression".into(), "lz4".into());
    let compressed_config = configuration(&compressed)?;
    assert_eq!(
        compressed_config.compression,
        crate::Compression::Lz4IfSmaller
    );
    assert!(selection("connect", &compressed, compressed_config)?.is_some());
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

#[test]
fn explicit_common_carrier_rejects_missing_cover_and_standalone_or_role_flags_before_plan_io()
-> io::Result<()> {
    for command in ["connect", "serve"] {
        let mut base = options_for(command, "openvpn-like");
        for key in ["--swift-forward-kbit", "--swift-reverse-kbit"] {
            base.remove(key);
        }
        base.insert("--record-profile".into(), "common".into());
        base.insert(
            "--common-transaction-plan".into(),
            "/no-plan-opened-by-this-negative-case".into(),
        );
        base.insert("--udp-cover".into(), "quic-like".into());
        if command == "connect" {
            base.insert("--ca".into(), "absent-ca".into());
            base.insert("--server-name".into(), "controlled.example".into());
        } else {
            base.insert("--cert".into(), "absent-cert".into());
            base.insert("--key".into(), "absent-tls-key".into());
        }
        for (key, value) in [
            ("--udp-cover", Some("openvpn-like")),
            ("--udp-cover", None),
            ("--common-transaction-plan", None),
            ("--admission-key-file", Some("unused-raw64")),
            ("--cookie-key-file", Some("unused-raw64-cookie")),
            ("--udp-protection", Some("integrity")),
            ("--openvpn-close-profile", Some("native-drain")),
            ("--openvpn-stats-ms", Some("1000")),
            ("--openvpn-lease-secs", Some("60")),
            (
                if command == "connect" {
                    "--cert"
                } else {
                    "--ca"
                },
                Some("wrong-role-tls"),
            ),
        ] {
            let mut changed = base.clone();
            if let Some(value) = value {
                changed.insert(key.into(), value.into());
            } else {
                changed.remove(key);
            }
            let error = selection(command, &changed, configuration(&changed)?)
                .err()
                .ok_or_else(|| input(format!("accepted invalid carrier input {key}")))?;
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidInput,
                "{command} {key}: {error}"
            );
        }
    }
    Ok(())
}

#[test]
fn vxlan_cli_attachment_enforces_tap_layer_bounds_and_loop_rejection_before_io() -> io::Result<()> {
    let file = transaction_integration_tests::PlanFile::new(
        &transaction_integration_tests::common_value()?,
    )?;
    for command in ["connect", "serve"] {
        let mut base = options_for(command, "quic-like");
        base.insert(
            "--common-transaction-plan".into(),
            file.0.to_string_lossy().into_owned(),
        );
        base.remove("--device");
        base.insert("--layer".into(), "tap".into());
        base.insert("--vxlan-bind".into(), "127.0.0.1:47891".into());
        base.insert("--vxlan-peer".into(), "127.0.0.1:47892".into());
        base.insert("--vni".into(), "1001".into());

        // Valid explicit TAP + VXLAN VTEP attachment passes selection before any I/O.
        let cfg = configuration(&base)?;
        assert_eq!(cfg.layer, PacketLayer::Ethernet);
        assert!(selection(command, &base, cfg)?.is_some());

        // Invalid combinations must fail with InvalidInput before opening sockets/files.
        let bad_cases: Vec<(&str, Option<&str>)> = vec![
            // VX-01: VTEP mode is incompatible with L3 TUN.
            ("--layer", Some("tun")),
            // VX-01: mutually exclusive with --device.
            ("--device", Some("tap0")),
            // Partial VXLAN flags rejected.
            ("--vni", None),
            ("--vxlan-peer", None),
            ("--vxlan-bind", None),
            // Out-of-range 24-bit VNI rejected.
            ("--vni", Some("16777216")),
            // Cross-family bind/peer rejected.
            ("--vxlan-peer", Some("[::1]:47892")),
            // Zero port / multicast / broadcast rejected.
            ("--vxlan-peer", Some("127.0.0.1:0")),
            ("--vxlan-peer", Some("224.0.0.1:4789")),
            ("--vxlan-peer", Some("255.255.255.255:4789")),
            // VX-05: self-loop bind == peer rejected.
            ("--vxlan-peer", Some("127.0.0.1:47891")),
            // VX-05: collision with outer tunnel carrier socket rejected.
            ("--vxlan-bind", Some("127.0.0.1:42101")),
            ("--vxlan-peer", Some("127.0.0.1:42102")),
        ];
        for (key, value) in bad_cases {
            let mut mutated = base.clone();
            if let Some(val) = value {
                mutated.insert(key.into(), val.into());
            } else {
                mutated.remove(key);
            }
            let cfg = configuration(&mutated)?;
            let err = selection(command, &mutated, cfg)
                .err()
                .ok_or_else(|| input(format!("accepted invalid VXLAN input {command} {key}")))?;
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidInput,
                "{command} {key}: {err}"
            );
        }
    }
    Ok(())
}

#[path = "raw_cli_tests.rs"]
mod raw_common;

#[path = "maintained_cli_selection_tests.rs"]
mod maintained_common;
