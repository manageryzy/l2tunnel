//! Startup-only native raw selection; retained TCP/UDP paths remain unchanged.
use super::*;
use crate::raw_packet as client;
pub(super) const OPTIONS: &[&str] = &["--raw-policy", "--raw-mark"];
pub(super) const HELP: &str = "Experimental raw packet runtime: --carrier raw-packet --raw-policy JSON_FILE --raw-mark NONZERO_U32. Explicit IPv4 tuples, system traffic and frame records only; existing TLS/member credentials remain required. The first configured peer/local tuple must match --remote/--listen. No fallback, hot reload, real congestion controller or clean drain. Optional --control-socket provides actual bounded status. Requires separately configured owned-lab raw permissions/mark/RST fencing; native qualification remains separate.";
pub(super) fn selection(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<(&str, u32)>> {
    if options.get("--carrier").map(String::as_str) != Some("raw-packet") {
        if OPTIONS.iter().any(|key| options.contains_key(*key)) {
            return Err(input("raw options require explicit --carrier raw-packet"));
        }
        return Ok(None);
    }
    if options.get("--traffic").is_some_and(|v| v != "system")
        || options
            .get("--record-profile")
            .is_some_and(|v| v != "frame")
        || [
            "--proxy-policy",
            "--quic-application-id",
            "--aligned-channels",
        ]
        .iter()
        .chain(UDP_OPTIONS)
        .chain(&ACTIVE_OPTIONS[1..])
        .chain(standalone::OPTIONS)
        .chain(packed_frontend::OPTIONS)
        .any(|key| options.contains_key(*key))
    {
        return Err(input(
            "raw packet requires system/frame and no proxy/active/UDP/QUIC/aligned/packed/standalone options",
        ));
    }
    config.session()?;
    let mark = required(options, "--raw-mark")?
        .parse::<u32>()
        .map_err(|_| input("raw mark must be nonzero u32"))?;
    if mark == 0 {
        return Err(input("raw mark must be nonzero u32"));
    }
    Ok(Some((required(options, "--raw-policy")?, mark)))
}
#[cfg(target_os = "linux")]
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    path: &str,
    mark: u32,
) -> io::Result<()> {
    let settings = client::Settings::from_json(&bounded_file(path, client::MAX_POLICY_BYTES)?)?;
    settings.runtime_config(config)?;
    let (local, peer) = settings.forward();
    let key = if command == "connect" {
        "--remote"
    } else {
        "--listen"
    };
    let declared: SocketAddr = required(options, key)?
        .parse()
        .map_err(|_| input("raw remote/listen requires explicit IPv4:PORT"))?;
    if declared != SocketAddr::V4(if command == "connect" { peer } else { local }) {
        return Err(input(
            "raw remote/listen differs from first configured tuple",
        ));
    }
    let device = DeviceSpec::parse(options, config)?;
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    let opener = |raw, role| l2tunnel_raw_io::open_packet_marked(raw, role, mark);
    let session = match command {
        "connect" => {
            let tls =
                ClientTls::from_der_roots(&[bounded_file(required(options, "--ca")?, 65536)?])
                    .map_err(auth_error)?;
            let member =
                MemberKey::from_pkcs8(&bounded_file(required(options, "--identity")?, 4096)?)
                    .map_err(auth_error)?;
            client::begin_client_with(
                &settings,
                config,
                &tls,
                required(options, "--server-name")?,
                &member,
                opener,
            )?
            .await?
        }
        "serve" => {
            let tls = ServerTls::from_der(
                &[bounded_file(required(options, "--cert")?, 65536)?],
                &bounded_file(required(options, "--key")?, 65536)?,
            )
            .map_err(auth_error)?;
            let public: [u8; 32] = bounded_file(required(options, "--allow-key")?, 32)?
                .try_into()
                .map_err(|_| input("allow-key must contain exactly 32 raw bytes"))?;
            let allow = MemberAllowlist::new(&[MemberPublicKey(public)]).map_err(auth_error)?;
            client::begin_server_with(&settings, config, &tls, &allow, opener)?.await?
        }
        _ => return Err(input("unsupported raw packet command")),
    };
    let observer = session.observer();
    let device = device.open(config)?;
    println!(
        "Authenticated {:?} raw packet runtime {:?}; native qualification and congestion control unavailable",
        config.layer, config.duplex
    );
    println!(
        "{}",
        serde_json::to_string(
            &serde_json::json!({"event":"raw_packet_authenticated","state":observer.snapshot()})
        )
        .map_err(io::Error::other)?
    );
    let finished = observer.clone();
    let result = serve(session.run(device), observer, api, config.compression).await;
    println!("{}",serde_json::to_string(&serde_json::json!({"event":"raw_packet_terminal","state":finished.snapshot(),"error_kind":result.as_ref().err().map(|e|format!("{:?}",e.kind()))})).map_err(io::Error::other)?);
    result
}
#[cfg(unix)]
pub(crate) fn response(
    observer: &client::Observer,
    request: crate::local::Request,
    compression: Compression,
) -> crate::local::Response {
    use crate::local::{self, Action, Response, Snapshot};
    let raw = observer.snapshot();
    let ok = matches!(request.action, Action::Status {});
    Response {
        version: local::VERSION,
        ok,
        code: if ok { "ok" } else { "unsupported" }.into(),
        state: Some(Snapshot {
            epoch: 1,
            phase: raw.phase.clone(),
            compression: match compression {
                Compression::None => local::Compression::Off,
                Compression::Lz4IfSmaller => local::Compression::Lz4,
            },
            active: None,
            proxy: None,
            openvpn_drain: None,
            raw_packet: Some(raw),
            rolling: None,
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
        tokio::select! {result=run=>result,result=&mut service=>Err(result.err().unwrap_or_else(||io::Error::other("raw status service stopped")))}
    } else {
        run.await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn values() -> BTreeMap<String, String> {
        [
            ("--layer", "tun"),
            ("--carrier", "raw-packet"),
            ("--raw-policy", "missing.json"),
            ("--raw-mark", "77"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
    }
    #[test]
    fn explicit_selection_rejects_downgrades_and_incompatible_options_before_io() -> io::Result<()>
    {
        let valid = values();
        let config = configuration(&valid)?;
        assert_eq!(selection(&valid, config)?, Some(("missing.json", 77)));
        for (key, value) in [
            ("--carrier", "tcp"),
            ("--traffic", "active"),
            ("--record-profile", "packed"),
            ("--udp-peer", "127.0.0.1:2"),
            ("--fec", "none"),
            ("--raw-mark", "0"),
            ("--raw-mark", "4294967296"),
            ("--active-policies", "missing.json"),
            ("--proxy-policy", "missing.json"),
        ] {
            let mut v = valid.clone();
            v.insert(key.into(), value.into());
            assert!(selection(&v, config).is_err(), "{key}");
        }
        let mut retained = BTreeMap::new();
        retained.insert("--layer".into(), "tun".into());
        assert!(selection(&retained, config)?.is_none());
        Ok(())
    }
}
