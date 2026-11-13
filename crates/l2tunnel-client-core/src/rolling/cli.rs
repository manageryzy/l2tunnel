//! Explicit startup-only rolling selection; all transport owners come from the shared API.
use super::*;
use crate::rolling as client;
pub(super) const OPTIONS: &[&str] = &["--rolling-policy"];
pub(super) const HELP: &str = "Rolling frames: --record-profile rolling --rolling-policy JSON_FILE with explicit --carrier udp|quic, TAP/TUN and system traffic. Complete strict version1 policy is authenticated before forwarding. No --fec, active/proxy/packed/aligned/raw/VXLAN composition, hot reload or clean drain. Optional --control-socket supports status only. Small-window integration is not native, W8192 or full Python-family qualification.";
pub(super) fn selection(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<&str>> {
    if options.get("--record-profile").map(String::as_str) != Some("rolling") {
        if options.contains_key("--rolling-policy") {
            return Err(input(
                "rolling policy requires explicit --record-profile rolling",
            ));
        }
        return Ok(None);
    }
    if !matches!(
        options.get("--carrier").map(String::as_str),
        Some("udp" | "quic")
    ) || options.get("--traffic").is_some_and(|v| v != "system")
        || [
            "--fec",
            "--fec-sources",
            "--fec-repairs",
            "--fec-flush-ms",
            "--aligned-channels",
            "--proxy-policy",
            "--raw-policy",
            "--raw-mark",
            "--vxlan-bind",
            "--vxlan-peer",
            "--vni",
        ]
        .iter()
        .chain(&ACTIVE_OPTIONS[1..])
        .chain(standalone::OPTIONS)
        .chain(packed_frontend::OPTIONS)
        .any(|key| options.contains_key(*key))
    {
        return Err(input(
            "rolling requires explicit UDP/QUIC, native TAP/TUN and system traffic without other recovery/profile tuning",
        ));
    }
    config.session()?;
    Ok(Some(required(options, "--rolling-policy")?))
}
#[cfg(target_os = "linux")]
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    path: &str,
) -> io::Result<()> {
    let settings = client::Settings::from_json(&bounded_file(path, client::MAX_POLICY_BYTES)?)?;
    // Only this explicit profile permits a read-only status service on datagrams.
    let mut transport_options = options.clone();
    transport_options.remove("--control-socket");
    let udp = udp_settings(&transport_options, config)?;
    let quic = quic_settings(&transport_options, config)?;
    if let Some(transport) = udp {
        client::udp_config(config, transport, &settings)?;
    }
    if let Some(transport) = quic {
        client::quic_config(config, transport, &settings)?;
    }
    let device = DeviceSpec::parse(options, config)?;
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    let session = match command {
        "connect" => {
            let address = required(options, "--remote")?
                .parse()
                .map_err(|_| input("remote requires IP:PORT"))?;
            let roots = vec![bounded_file(required(options, "--ca")?, 65536)?];
            let member =
                MemberKey::from_pkcs8(&bounded_file(required(options, "--identity")?, 4096)?)
                    .map_err(auth_error)?;
            let name = required(options, "--server-name")?;
            if let Some(transport) = quic {
                client::connect_quic(&roots, name, &member, config, transport, &settings).await?
            } else {
                let tls = ClientTls::from_der_roots(&roots).map_err(auth_error)?;
                client::connect_udp(
                    address,
                    &tls,
                    name,
                    &member,
                    config,
                    udp.ok_or_else(|| input("rolling UDP selection absent"))?,
                    &settings,
                )
                .await?
            }
        }
        "serve" => {
            let address: SocketAddr = required(options, "--listen")?
                .parse()
                .map_err(|_| input("listen requires IP:PORT"))?;
            let chain = vec![bounded_file(required(options, "--cert")?, 65536)?];
            let key = bounded_file(required(options, "--key")?, 65536)?;
            let public: [u8; 32] = bounded_file(required(options, "--allow-key")?, 32)?
                .try_into()
                .map_err(|_| input("allow-key requires exactly32 bytes"))?;
            let allow = MemberAllowlist::new(&[MemberPublicKey(public)]).map_err(auth_error)?;
            if let Some(transport) = quic {
                let listener =
                    client::QuicListener::bind(&chain, &key, config, transport, &settings)?;
                listener.accept(&allow).await?
            } else {
                let tls = ServerTls::from_der(&chain, &key).map_err(auth_error)?;
                let listener = TcpListener::bind(address).await?;
                client::accept_udp(
                    &listener,
                    &tls,
                    &allow,
                    config,
                    udp.ok_or_else(|| input("rolling UDP selection absent"))?,
                    &settings,
                )
                .await?
            }
        }
        _ => return Err(input("unsupported rolling command")),
    };
    let observer = session.observer();
    let finished = observer.clone();
    let device = device.open(config)?;
    println!(
        "{}",
        serde_json::to_string(
            &serde_json::json!({"event":"rolling_authenticated","state":observer.snapshot()})
        )
        .map_err(io::Error::other)?
    );
    let result = serve(session.run(device), observer, api, config.compression).await;
    println!(
        "{}",
        serde_json::to_string(
            &serde_json::json!({"event":"rolling_terminal","state":finished.snapshot()})
        )
        .map_err(io::Error::other)?
    );
    result
}
#[cfg(unix)]
pub(crate) fn response(
    observer: &client::Observer,
    request: crate::local::Request,
    compression: Compression,
) -> crate::local::Response {
    use crate::local::{self, Action, Response, Snapshot};
    let rolling = observer.snapshot();
    let ok = matches!(request.action, Action::Status {});
    Response {
        version: local::VERSION,
        ok,
        code: if ok { "ok" } else { "unsupported" }.into(),
        state: Some(Snapshot {
            epoch: rolling.epoch,
            phase: format!("{:?}", rolling.phase).to_lowercase(),
            compression: match compression {
                Compression::None => local::Compression::Off,
                Compression::Lz4IfSmaller => local::Compression::Lz4,
            },
            active: None,
            proxy: None,
            openvpn_drain: None,
            raw_packet: None,
            rolling: Some(rolling),
            #[cfg(unix)]
            swift: None,
            #[cfg(unix)]
            secure_udp: None,
        }),
    }
}
#[cfg(unix)]
pub(crate) async fn serve(
    run: impl std::future::Future<Output = io::Result<()>>,
    observer: client::Observer,
    api: Option<crate::local::Server>,
    compression: Compression,
) -> io::Result<()> {
    if let Some(api) = api {
        let service =
            api.serve(move |request| std::future::ready(response(&observer, request, compression)));
        tokio::pin!(service);
        tokio::select! {result=run=>result,result=&mut service=>Err(result.err().unwrap_or_else(||io::Error::other("rolling status service stopped")))}
    } else {
        run.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options() -> BTreeMap<String, String> {
        [
            ("--layer", "tun"),
            ("--carrier", "udp"),
            ("--record-profile", "rolling"),
            ("--rolling-policy", "missing.json"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
    }
    #[test]
    fn rolling_cli_requires_exact_explicit_selection_and_leaves_defaults() -> io::Result<()> {
        let valid = options();
        let config = configuration(&valid)?;
        assert_eq!(selection(&valid, config)?, Some("missing.json"));
        for (key, value) in [
            ("--carrier", "tcp"),
            ("--carrier", "raw-packet"),
            ("--carrier", "openvpn-like"),
            ("--traffic", "proxy-measured"),
            ("--traffic", "active"),
            ("--fec", "none"),
            ("--fec", "cauchy"),
            ("--fec-sources", "4"),
            ("--packed-channels", "4"),
            ("--aligned-channels", "4"),
            ("--adaptive", "on"),
            ("--proxy-policy", "missing.json"),
            ("--vxlan-bind", "127.0.0.1:1"),
            ("--raw-mark", "7"),
        ] {
            let mut bad = valid.clone();
            bad.insert(key.into(), value.into());
            assert!(selection(&bad, config).is_err(), "{key}");
        }
        let mut bad = valid.clone();
        bad.remove("--carrier");
        assert!(selection(&bad, config).is_err());
        let mut bad = valid.clone();
        bad.remove("--record-profile");
        assert!(selection(&bad, config).is_err());
        let mut legacy = bad;
        legacy.remove("--rolling-policy");
        assert!(selection(&legacy, config)?.is_none());
        let mut quic = valid;
        quic.insert("--carrier".into(), "quic".into());
        quic.insert("--control-socket".into(), "/unused/status".into());
        assert!(selection(&quic, config)?.is_some());
        Ok(())
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rolling_incompatible_profile_fails_before_policy_file_or_credentials() -> io::Result<()>
    {
        let mut bad = options();
        bad.insert("--fec".into(), "none".into());
        let error = super::super::execute("connect", &bad)
            .await
            .err()
            .ok_or_else(|| input("accepted incompatible profile"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("rolling"));
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn rolling_local_status_is_bounded_and_other_actions_cannot_mutate() -> io::Result<()> {
        let c = configuration(&options())?;
        let p = l2tunnel_runtime::udp::Config::new(
            l2tunnel_core::Duplex::Half,
            crate::udp::CoverProfile::QuicLike,
            crate::udp::Protection::ChaCha20Poly1305,
            1500,
            false,
        )?;
        let settings = crate::rolling::Settings::from_json(include_bytes!("test-policy.json"))?;
        let r = l2tunnel_runtime::rolling::Config::for_udp(
            c.runtime(),
            p,
            4,
            settings.delivery(c.max_packet)?,
        )?;
        let observer = crate::rolling::Observer::new(
            c,
            r,
            crate::rolling::Carrier::Udp,
            crate::rolling::Cover::QuicLike,
            l2tunnel_core::ConfigDigest([0xff; 32]),
        );
        let before = observer.snapshot();
        for action in [
            crate::local::Action::Status {},
            crate::local::Action::DrainProxy {},
            crate::local::Action::DrainOpenVpn {},
            crate::local::Action::SwitchCompression {
                compression: crate::local::Compression::Lz4,
            },
        ] {
            let status = matches!(action, crate::local::Action::Status {});
            let response = response(
                &observer,
                crate::local::Request {
                    version: crate::local::VERSION,
                    action,
                },
                Compression::None,
            );
            assert_eq!(response.ok, status);
            assert_eq!(observer.snapshot(), before);
            let bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
            assert!(bytes.len() < 8192);
            let decoded: crate::local::Response =
                serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            assert_eq!(decoded.state.and_then(|s| s.rolling), Some(before.clone()));
        }
        Ok(())
    }
}
