//! Explicit native-drain CLI; legacy factory and output remain separate.
use super::*;
use crate::openvpn::{self as client, drain};
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    settings: drain::Settings,
) -> io::Result<()> {
    let specification = DeviceSpec::parse(options, config)?;
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    let admission = client::keys::read(Path::new(required(options, "--admission-key-file")?))?;
    let session = match command {
        "connect" => {
            let tls =
                ClientTls::from_der_roots(&[bounded_file(required(options, "--ca")?, 65536)?])
                    .map_err(auth_error)?;
            let member =
                MemberKey::from_pkcs8(&bounded_file(required(options, "--identity")?, 4096)?)
                    .map_err(auth_error)?;
            drain::connect(
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
            drain::accept(&tls, &members, admission, cookie, config, settings).await?
        }
        _ => return Err(input("unsupported native standalone command")),
    };
    let device = specification.open(config)?;
    let (handle, run) = session.into_run(device)?;
    println!(
        "Authenticated {:?} {:?}; standalone OpenVPN-like native-drain; system FIFO; frame records; {:?}; forwarding packet device",
        config.layer, config.duplex, settings.transport.protection
    );
    drain::serve(
        run,
        handle,
        config.compression,
        api,
        Duration::from_millis(number(options, "--openvpn-stats-ms", 0)?),
        Duration::from_secs(5),
    )
    .await
}
