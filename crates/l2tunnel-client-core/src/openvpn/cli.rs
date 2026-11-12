//! Strict standalone selection; inherited CLI helpers remain authoritative.
use super::*;
pub(super) const OPTIONS: &[&str] = &[
    "--admission-key-file",
    "--cookie-key-file",
    "--openvpn-lease-secs",
    "--openvpn-stats-ms",
    "--openvpn-close-profile",
    "--openvpn-drain-timeout-ms",
];
pub(super) const HELP: &str = "Standalone custom OpenVPN-like: --carrier openvpn-like --udp-bind IP:PORT --udp-peer IP:PORT, plus half-duplex reverse UDP endpoints. No --remote/--listen or TCP socket. Both roles require --admission-key-file RAW64; serve additionally requires --cookie-key-file RAW64. The cookie bundle is server-only. --udp-protection aead|integrity, --path-mtu, --openvpn-lease-secs (default3600, max86400), --openvpn-stats-ms (default0) apply. One system FIFO channel and frame records only; no FEC/active/aligned/reload. Provision explicitly: openvpn-keygen --admission NEW_RAW64 --cookie NEW_RAW64. Full mode reserves the unused reverse key slot; it creates one authenticated lane. Opt in with --openvpn-close-profile native-drain (default legacy) and --openvpn-drain-timeout-ms 1..120000 (default5000); only this profile accepts --control-socket for status and drain-openvpn. Acceptance is not closure; terminal status remains locally available for five seconds after original network owners finish. No OpenVPN interoperability claim.";
pub(super) fn settings(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    command: &str,
) -> io::Result<Option<super::super::openvpn::Settings>> {
    if options.get("--carrier").map(String::as_str) != Some("openvpn-like") {
        if OPTIONS.iter().any(|key| options.contains_key(*key)) {
            return Err(input("standalone options require --carrier openvpn-like"));
        }
        return Ok(None);
    }
    if [
        "--listen",
        "--remote",
        "--udp-cover",
        "--quic-application-id",
        "--fec",
        "--fec-sources",
        "--fec-repairs",
        "--fec-flush-ms",
        "--aligned-channels",
    ]
    .iter()
    .chain(ACTIVE_OPTIONS[1..].iter())
    .any(|key| options.contains_key(*key))
        || options
            .get("--traffic")
            .is_some_and(|value| value != "system")
        || options
            .get("--record-profile")
            .is_some_and(|value| value != "frame")
    {
        return Err(input(
            "standalone UDP requires fixed UDP endpoints, system/frame profile and no TCP/FEC/active/reload options",
        ));
    }
    let drain = drain_timeout(options)?;
    if drain.is_none() && options.contains_key("--control-socket") {
        return Err(input(
            "legacy standalone profile does not support local control",
        ));
    }
    required(options, "--admission-key-file")?;
    match command {
        "serve" => {
            required(options, "--cookie-key-file")?;
        }
        "connect" if !options.contains_key("--cookie-key-file") => {}
        _ => {
            return Err(input(
                "cookie key file is required only on standalone serve",
            ));
        }
    }
    let address = |key| {
        required(options, key)?
            .parse::<SocketAddr>()
            .map_err(|_| input("standalone endpoint requires IP:PORT"))
    };
    let forward = super::super::udp::Endpoints {
        local: address("--udp-bind")?,
        peer: address("--udp-peer")?,
    };
    let reverse = match (
        options.contains_key("--udp-reverse-bind"),
        options.contains_key("--udp-reverse-peer"),
    ) {
        (false, false) => None,
        (true, true) => Some(super::super::udp::Endpoints {
            local: address("--udp-reverse-bind")?,
            peer: address("--udp-reverse-peer")?,
        }),
        _ => {
            return Err(input(
                "both standalone reverse endpoints are required together",
            ));
        }
    };
    let protection = match options
        .get("--udp-protection")
        .map(String::as_str)
        .unwrap_or("aead")
    {
        "aead" => l2tunnel_openvpn::Protection::ChaCha20Poly1305,
        "integrity" => l2tunnel_openvpn::Protection::HmacSha256,
        _ => return Err(input("standalone protection must be aead or integrity")),
    };
    let stats: u64 = number(options, "--openvpn-stats-ms", 0)?;
    if stats != 0 && !(100..=60_000).contains(&stats) {
        return Err(input("standalone stats must be 0 or 100..60000 ms"));
    }
    let value = super::super::openvpn::Settings {
        forward,
        reverse,
        protection,
        path_mtu: number(
            options,
            "--path-mtu",
            if forward.local.is_ipv4() { 1200 } else { 1280 },
        )?,
        authenticated_lease: Duration::from_secs(number(options, "--openvpn-lease-secs", 3600)?),
    };
    if let Some(drain_timeout) = drain {
        super::super::openvpn::drain::runtime_config(
            config,
            super::super::openvpn::drain::Settings {
                transport: value,
                drain_timeout,
            },
        )?;
    } else {
        super::super::openvpn::runtime_config(config, value)?;
    }
    Ok(Some(value))
}
fn drain_timeout(options: &BTreeMap<String, String>) -> io::Result<Option<Duration>> {
    match options
        .get("--openvpn-close-profile")
        .map(String::as_str)
        .unwrap_or("legacy")
    {
        "legacy" if !options.contains_key("--openvpn-drain-timeout-ms") => Ok(None),
        "native-drain" => {
            let ms: u64 = number(options, "--openvpn-drain-timeout-ms", 5000)?;
            if !(1..=120000).contains(&ms) {
                return Err(input("native drain timeout must be 1..120000 ms"));
            }
            Ok(Some(Duration::from_millis(ms)))
        }
        _ => Err(input(
            "close profile must be legacy or native-drain; timeout requires native-drain",
        )),
    }
}
#[cfg(target_os = "linux")]
#[path = "drain_cli.rs"]
mod native;
#[cfg(target_os = "linux")]
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    settings: super::super::openvpn::Settings,
) -> io::Result<()> {
    if let Some(drain_timeout) = drain_timeout(options)? {
        return native::execute(
            command,
            options,
            config,
            super::super::openvpn::drain::Settings {
                transport: settings,
                drain_timeout,
            },
        )
        .await;
    }
    use super::super::openvpn as client;
    let specification = DeviceSpec::parse(options, config)?;
    let admission = client::keys::read(Path::new(required(options, "--admission-key-file")?))?;
    let (link, native) = match command {
        "connect" => {
            let tls =
                ClientTls::from_der_roots(&[bounded_file(required(options, "--ca")?, 65536)?])
                    .map_err(auth_error)?;
            let member =
                MemberKey::from_pkcs8(&bounded_file(required(options, "--identity")?, 4096)?)
                    .map_err(auth_error)?;
            client::connect(
                &tls,
                required(options, "--server-name")?,
                &member,
                admission,
                config,
                settings,
            )
            .await?
        }
        "serve" => {
            let cookie = client::keys::read(Path::new(required(options, "--cookie-key-file")?))?;
            let tls = ServerTls::from_der(
                &[bounded_file(required(options, "--cert")?, 65536)?],
                &bounded_file(required(options, "--key")?, 65536)?,
            )
            .map_err(auth_error)?;
            let public: [u8; 32] = bounded_file(required(options, "--allow-key")?, 32)?
                .try_into()
                .map_err(|_| input("allow-key must contain exactly32 raw bytes"))?;
            let members = MemberAllowlist::new(&[MemberPublicKey(public)]).map_err(auth_error)?;
            client::accept(&tls, &members, admission, cookie, config, settings).await?
        }
        _ => return Err(input("unsupported standalone command")),
    };
    let device = specification.open(config)?;
    println!(
        "Authenticated {:?} {:?}; carrier standalone OpenVPN-like UDP only; system FIFO; frame records; {:?}; forwarding packet device",
        config.layer, config.duplex, settings.protection
    );
    let observer = link.observer();
    let run = l2tunnel_runtime::openvpn::run(device, link, native);
    let stats: u64 = number(options, "--openvpn-stats-ms", 0)?;
    if stats == 0 {
        return run.await;
    }
    let diagnostics = async {
        let mut timer = tokio::time::interval(Duration::from_millis(stats));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            let s = observer.snapshot()?;
            println!(
                "{}",
                serde_json::json!({"kind":"openvpn_native_stats","snapshot":"last_completed_iteration","native_ingress":s.native_ingress,"sources_admitted":s.sources_admitted,"sources_received":s.sources_received,"native_delivered":s.native_delivered,"outbound_fragments":s.outbound_fragments,"outbound_bytes":s.outbound_bytes,"reassembly_messages":s.reassembly_messages,"reassembly_bytes":s.reassembly_bytes,"native_queue_packets":s.native_queue_packets,"native_queue_bytes":s.native_queue_bytes,"tls_messages":s.tls_messages,"stopped":s.stopped})
            );
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    tokio::select! {result=run=>result,result=diagnostics=>result}
}
pub(super) fn generate(options: &BTreeMap<String, String>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        super::super::openvpn::keys::generate(
            Path::new(required(options, "--admission")?),
            Path::new(required(options, "--cookie")?),
        )?;
        println!(
            "Created private admission and server-only cookie bundles; distribute only admission to its member."
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "standalone key-file provisioning is qualified on Linux only",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn values() -> BTreeMap<String, String> {
        [
            ("--carrier", "openvpn-like"),
            ("--layer", "tun"),
            ("--duplex", "full"),
            ("--udp-bind", "127.0.0.1:24440"),
            ("--udp-peer", "127.0.0.1:24441"),
            ("--admission-key-file", "admission.raw"),
        ]
        .map(|(a, b)| (a.into(), b.into()))
        .into()
    }
    #[test]
    fn standalone_selection_is_explicit_and_rejects_ignored_options() -> io::Result<()> {
        let original = values();
        let config = configuration(&original)?;
        assert!(settings(&original, config, "connect")?.is_some());
        for (key, value) in [
            ("--listen", "127.0.0.1:24440"),
            ("--remote", "127.0.0.1:24441"),
            ("--cookie-key-file", "cookie.raw"),
            ("--udp-cover", "openvpn-like"),
            ("--fec", "none"),
            ("--record-profile", "aligned"),
            ("--traffic", "active"),
            ("--control-socket", "local"),
            ("--quic-application-id", "01"),
            ("--mux-channels", "1"),
            ("--openvpn-stats-ms", "1"),
        ] {
            let mut changed = original.clone();
            changed.insert(key.into(), value.into());
            assert!(settings(&changed, config, "connect").is_err(), "{key}");
        }
        for carrier in ["tcp", "udp", "quic"] {
            let mut changed = original.clone();
            changed.insert("--carrier".into(), carrier.into());
            assert!(settings(&changed, config, "connect").is_err());
        }
        assert!(settings(&original, config, "serve").is_err());
        let mut server = original;
        server.insert("--cookie-key-file".into(), "cookie.raw".into());
        assert!(settings(&server, config, "serve")?.is_some());
        Ok(())
    }
    #[test]
    fn native_drain_selection_is_explicit_bounded_and_legacy_stays_default() -> io::Result<()> {
        let original = values();
        let config = configuration(&original)?;
        assert_eq!(drain_timeout(&original)?, None);
        let mut explicit = original.clone();
        explicit.insert("--openvpn-close-profile".into(), "legacy".into());
        assert_eq!(
            settings(&original, config, "connect")?,
            settings(&explicit, config, "connect")?
        );
        let mut native = original.clone();
        native.insert("--openvpn-close-profile".into(), "native-drain".into());
        native.insert("--control-socket".into(), "/unused/private/api.sock".into());
        assert!(settings(&native, config, "connect")?.is_some());
        assert_eq!(drain_timeout(&native)?, Some(Duration::from_secs(5)));
        for (key, value) in [
            ("--openvpn-close-profile", "silent"),
            ("--openvpn-drain-timeout-ms", "0"),
            ("--openvpn-drain-timeout-ms", "120001"),
            ("--traffic", "active"),
            ("--record-profile", "aligned"),
            ("--fec", "none"),
            ("--remote", "127.0.0.1:2"),
        ] {
            let mut bad = native.clone();
            bad.insert(key.into(), value.into());
            assert!(settings(&bad, config, "connect").is_err(), "{key}");
        }
        for value in ["1", "120000"] {
            native.insert("--openvpn-drain-timeout-ms".into(), value.into());
            assert!(settings(&native, config, "connect")?.is_some());
        }
        explicit.insert("--openvpn-drain-timeout-ms".into(), "5000".into());
        assert!(settings(&explicit, config, "connect").is_err());
        for carrier in ["tcp", "udp", "quic"] {
            let mut bad = native.clone();
            bad.insert("--carrier".into(), carrier.into());
            assert!(settings(&bad, config, "connect").is_err());
        }
        Ok(())
    }
}
