//! Narrow Windows foreground frontend; protocol/configuration ownership stays shared.
use l2tunnel_auth::{ClientSni, ClientTls, MemberKey};
use l2tunnel_client_core::{Compression, ConnectionConfig, service};
use l2tunnel_core::Duplex;
use l2tunnel_device::PacketLayer;
use l2tunnel_platform_windows::Config;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;

/// Supported foreground invocation and explicit capability limits.
pub const HELP: &str = "l2tunnel-windows connect --carrier tcp-tls --layer tun --remote IP:PORT --ca DER --server-name DNS --identity PKCS8 --wintun-dll ABSOLUTE_DLL --wintun-sha256 HEX64 --address IPV4/PREFIX [--mtu 1280..65519] [--duplex half|full] [--compression off|lz4] [--sni DNS] [--handshake-seconds 1..120]\nExplicit foreground Wintun L3 / retained TCP/TLS frame slice. Default half duplex, MTU 1500, compression off, no SNI. Ctrl+C cancels setup or aborts forwarding and releases owned handles. Requires a trusted, operator-pinned official Wintun DLL and permission to create an adapter. Only its unique adapter/address/MTU are owned; no default routes or DNS are changed. Windows service, named-pipe API, TAP L2, credential vault and other carriers are pending. Native Windows qualification is separate. Other commands: plan, --help, --version.";

/// One parsed command; parsing opens no sockets, credentials or devices.
pub enum Command {
    /// Display usage.
    Help,
    /// Display application version.
    Version,
    /// Display implementation capabilities without side effects.
    Plan,
    /// Explicit foreground connection request.
    Connect(Box<Plan>),
}

/// Validated frontend configuration, with private credential references.
pub struct Plan {
    /// Existing shared managed transport configuration.
    pub connection: ConnectionConfig,
    /// Validated platform-specific device inputs.
    pub device: Config,
    remote: SocketAddr,
    ca: PathBuf,
    identity: PathBuf,
    server_name: String,
    sni: ClientSni,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Parse bounded options and reject unsupported selections before I/O.
pub fn parse(args: &[String]) -> io::Result<Command> {
    match args {
        [command] if command == "--help" || command == "-h" => return Ok(Command::Help),
        [command] if command == "--version" => return Ok(Command::Version),
        [command] if command == "plan" => return Ok(Command::Plan),
        [command, ..] if command == "connect" => {}
        _ => return Err(invalid("unsupported command; use --help")),
    }
    if args.len() > 35
        || args
            .iter()
            .any(|arg| arg.len() > 4096 || arg.contains('\0'))
    {
        return Err(invalid("command exceeds argument bounds"));
    }
    let mut values = BTreeMap::new();
    const ALLOWED: &[&str] = &[
        "--carrier",
        "--layer",
        "--remote",
        "--ca",
        "--server-name",
        "--identity",
        "--wintun-dll",
        "--wintun-sha256",
        "--address",
        "--mtu",
        "--duplex",
        "--compression",
        "--sni",
        "--handshake-seconds",
    ];
    for pair in args[1..].chunks(2) {
        if pair.len() != 2
            || !ALLOWED.contains(&pair[0].as_str())
            || pair[1].is_empty()
            || pair[1].starts_with("--")
        {
            return Err(invalid("unknown option or missing value"));
        }
        if values.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err(invalid("duplicate option"));
        }
    }
    let get = |key| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| invalid("missing required option; use --help"))
    };
    if get("--carrier")? != "tcp-tls" || get("--layer")? != "tun" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this foreground slice requires explicit tcp-tls and tun; no fallback",
        ));
    }
    let remote: SocketAddr = get("--remote")?
        .parse()
        .map_err(|_| invalid("remote requires IP:PORT"))?;
    if remote.port() == 0 || remote.ip().is_unspecified() || remote.ip().is_multicast() {
        return Err(invalid(
            "remote must be a unicast endpoint with a nonzero port",
        ));
    }
    let server_name = get("--server-name")?;
    if server_name.len() > 253 || server_name.is_empty() || !server_name.is_ascii() {
        return Err(invalid("invalid TLS verification name"));
    }
    if server_name.parse::<std::net::IpAddr>().is_err() {
        ClientSni::named(server_name).map_err(|_| invalid("invalid TLS verification DNS name"))?;
    }
    let sni = values
        .get("--sni")
        .map(|name| ClientSni::named(name))
        .transpose()
        .map_err(|_| invalid("invalid TLS SNI name"))?
        .unwrap_or_default();
    let duplex = match values.get("--duplex").copied().unwrap_or("half") {
        "half" => Duplex::Half,
        "full" => Duplex::Full,
        _ => return Err(invalid("invalid duplex")),
    };
    let compression = match values.get("--compression").copied().unwrap_or("off") {
        "off" => Compression::None,
        "lz4" => Compression::Lz4IfSmaller,
        _ => return Err(invalid("invalid compression")),
    };
    let mtu: u16 = values
        .get("--mtu")
        .copied()
        .unwrap_or("1500")
        .parse()
        .map_err(|_| invalid("invalid MTU"))?;
    let seconds: u64 = values
        .get("--handshake-seconds")
        .copied()
        .unwrap_or("30")
        .parse()
        .map_err(|_| invalid("invalid handshake limit"))?;
    let (address, prefix) = get("--address")?
        .split_once('/')
        .ok_or_else(|| invalid("address requires IPV4/PREFIX"))?;
    let device = Config::new(
        PathBuf::from(get("--wintun-dll")?),
        sha256(get("--wintun-sha256")?)?,
        address
            .parse()
            .map_err(|_| invalid("invalid interface IPv4 address"))?,
        prefix.parse().map_err(|_| invalid("invalid IPv4 prefix"))?,
        mtu,
    )?;
    if let std::net::IpAddr::V4(remote_ip) = remote.ip() {
        let mask = u32::MAX << (32 - device.prefix());
        if u32::from(remote_ip) & mask == u32::from(device.address()) & mask {
            return Err(invalid(
                "outer peer must not lie in the new Wintun on-link subnet",
            ));
        }
    }
    let connection = ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: usize::from(mtu),
        compression,
        handshake_timeout: Duration::from_secs(seconds),
    };
    connection.session()?;
    Ok(Command::Connect(Box::new(Plan {
        connection,
        device,
        remote,
        ca: get("--ca")?.into(),
        identity: get("--identity")?.into(),
        server_name: server_name.to_owned(),
        sni,
    })))
}

fn sha256(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(invalid("Wintun SHA256 requires 64 hex digits"));
    }
    let mut output = [0; 32];
    for (out, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |byte: u8| {
            (byte as char)
                .to_digit(16)
                .map(|v| v as u8)
                .ok_or_else(|| invalid("invalid SHA256 hex digit"))
        };
        *out = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(output)
}

fn bounded_file(path: &Path, maximum: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path)
        .map_err(|error| io::Error::new(error.kind(), "credential file could not be opened"))?;
    if !file.metadata()?.is_file() {
        return Err(invalid("credential input must be a regular file"));
    }
    let mut contents = Zeroizing::new(Vec::new());
    file.take(maximum as u64 + 1)
        .read_to_end(&mut contents)
        .map_err(|error| io::Error::new(error.kind(), "credential file could not be read"))?;
    if contents.is_empty() || contents.len() > maximum {
        return Err(invalid("credential input exceeds bounds"));
    }
    Ok(contents)
}

impl Plan {
    /// Read bounded explicitly provisioned credentials and build the shared plan.
    /// The caller owns credential-file ACL provisioning; this is not a vault.
    pub fn prepare(self, attachment: service::Attachment) -> io::Result<service::Prepared> {
        let roots = bounded_file(&self.ca, 65_536)?;
        let tls = ClientTls::from_der_roots_with_sni(&[roots.to_vec()], self.sni)
            .map_err(|_| invalid("invalid TLS trust roots or naming policy"))?;
        let private = bounded_file(&self.identity, 4096)?;
        let member =
            MemberKey::from_pkcs8(&private).map_err(|_| invalid("invalid member identity"))?;
        service::Prepared::client(
            self.connection,
            service::Client {
                remote: self.remote,
                tls,
                server_name: self.server_name,
                member: Arc::new(member),
            },
            attachment,
            service::Options::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        let dll = if cfg!(windows) {
            "C:\\trusted\\wintun.dll"
        } else {
            "/trusted/wintun.dll"
        };
        [
            "connect",
            "--carrier",
            "tcp-tls",
            "--layer",
            "tun",
            "--remote",
            "127.0.0.1:443",
            "--ca",
            "ca.der",
            "--server-name",
            "tunnel.test",
            "--identity",
            "member.pk8",
            "--wintun-dll",
            dll,
            "--wintun-sha256",
            &"ab".repeat(32),
            "--address",
            "10.81.0.2/24",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn explicit_selection_and_bounds_reject_before_io() {
        assert!(matches!(parse(&args()), Ok(Command::Connect(_))));
        for (key, value) in [
            ("--carrier", "swift"),
            ("--layer", "tap"),
            ("--remote", "0.0.0.0:0"),
            ("--remote", "10.81.0.5:443"),
            ("--server-name", "bad/name"),
            ("--wintun-sha256", "bad"),
            ("--address", "10.81.0.2/33"),
        ] {
            let mut arguments = args();
            if let Some(index) = arguments.iter().position(|arg| arg == key) {
                arguments[index + 1] = value.into();
            }
            assert!(parse(&arguments).is_err(), "{key}");
        }
        for pair in [
            ["--duplex", "other"],
            ["--mtu", "1279"],
            ["--handshake-seconds", "121"],
            ["--control-pipe", "pipe"],
            ["--identity", "duplicate"],
        ] {
            let mut arguments = args();
            arguments.extend(pair.map(str::to_owned));
            assert!(parse(&arguments).is_err());
        }
    }
    #[test]
    fn credentials_never_open_attachment_on_parse_failure() -> io::Result<()> {
        let Command::Connect(plan) = parse(&args())? else {
            return Err(invalid("plan"));
        };
        let attachment = service::Attachment::new(PacketLayer::Ip, || {
            Err(io::Error::other("must not be opened"))
        });
        assert!(plan.prepare(attachment).is_err());
        Ok(())
    }
}
