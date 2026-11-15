//! Explicit measured Linux selection through the common proxy local service.
use super::*;
use crate::proxy_measured as client;

#[cfg(target_os = "linux")]
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    path: &str,
) -> io::Result<()> {
    let settings = client::Settings::from_json(&bounded_file(path, client::MAX_POLICY_BYTES)?)?;
    client::runtime_config(config, &settings)?;
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
            let tls = tls_frontend::client(options)?;
            let member =
                MemberKey::from_pkcs8(&bounded_file(required(options, "--identity")?, 4096)?)
                    .map_err(auth_error)?;
            client::connect(
                address,
                &tls,
                required(options, "--server-name")?,
                &member,
                config,
                &settings,
            )
            .await?
        }
        "serve" => {
            let address: SocketAddr = required(options, "--listen")?
                .parse()
                .map_err(|_| input("listen requires IP:PORT"))?;
            let tls = ServerTls::from_der(
                &[bounded_file(required(options, "--cert")?, 65536)?],
                &bounded_file(required(options, "--key")?, 65536)?,
            )
            .map_err(auth_error)?;
            let public: [u8; 32] = bounded_file(required(options, "--allow-key")?, 32)?
                .try_into()
                .map_err(|_| input("allow-key must contain exactly 32 raw bytes"))?;
            let allow = MemberAllowlist::new(&[MemberPublicKey(public)]).map_err(auth_error)?;
            let listener = TcpListener::bind(address).await?;
            client::accept(&listener, &tls, &allow, config, &settings).await?
        }
        _ => return Err(input("unsupported proxy command")),
    };
    let digest = l2tunnel_runtime::proxy::measured::session_config(session.config())?
        .digest
        .0;
    let device = device.open(config)?;
    let (handle, control) = client::control_channel();
    println!(
        "Authenticated TUN {:?}; measured relay-target proxy over retained TCP/TLS; immutable route policy; forwarding packet device",
        config.duplex
    );
    super::serve_measured(
        session.run(device, control),
        handle,
        config.duplex,
        digest,
        api,
        Duration::from_secs(5),
    )
    .await
    .map(|_| ())
}
