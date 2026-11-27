//! Side-effect-free Windows configuration and Wintun validation.
use l2tunnel_auth::ClientSni;
use l2tunnel_client_core::{Compression, ConnectionConfig};
use l2tunnel_core::Duplex;
use l2tunnel_device::PacketLayer;
use l2tunnel_platform_windows::Config;
use std::{collections::BTreeMap, io, net::SocketAddr, path::PathBuf, time::Duration};

/// Accepted configuration syntax and explicit execution capability limits.
pub const HELP: &str = r"l2tunnel-windows daemon DAEMON_OPTIONS | service install DAEMON_OPTIONS | service install HOST_OPTIONS | service start | service install-start [ENCODED] | service uninstall | service run HOST_OPTIONS | service run-daemon DAEMON_OPTIONS | foreground HOST_OPTIONS | dpapi seal --input FILE --output FILE [--scope machine|user]
DAEMON_OPTIONS (recommended): --state-dir ABSOLUTE_DIR [--wintun-dll ABSOLUTE_DLL --wintun-sha256 HEX64] [--address IPV4/PREFIX] [--pipe \\.\pipe\NAME] [--skip-acl-check]
HOST_OPTIONS (legacy single-profile): --profile ABSOLUTE_DIR --wintun-dll ABSOLUTE_DLL --wintun-sha256 HEX64 --address IPV4/PREFIX [--pipe \\.\pipe\NAME]
`service start` automatically installs the multi-profile LocalSystem daemon service under %ProgramFiles%\l2tunnel if it is not registered yet; `service install-start` reinstalls from the current binary and restarts it. The installed service (LocalSystem, manual start) owns the Wintun L3 adapter, Windows IP routes, multi-profile store, Event Log + rotating service.log diagnostics, sleep/resume + network-change reconnect, and DPAPI secret unsealing, supporting UDP covers (quic-like/media-like/tls-like), openvpn-like, TCP/TLS 1.3 (tcp), and QUIC (quic) over local API v5 (default pipe \\.\pipe\l2tunnel). Use nonprivileged l2tunnelctl or l2tunnel-windows-gui. Other commands: plan, --help, --version.";

/// One parsed command; parsing opens no sockets, credentials or devices.
pub enum Command {
    /// Display usage.
    Help,
    /// Display application version.
    Version,
    /// Display implementation capabilities without side effects.
    Plan,
    /// Requested connection inputs; execution currently returns Unsupported.
    Connect(Box<Plan>),
}

/// Validated requested inputs; credential paths are references and are never opened here.
pub struct Plan {
    /// Requested shared transport settings, without an effective runtime binding.
    pub connection: ConnectionConfig,
    /// Validated platform-specific device inputs.
    pub device: Config,
    /// Requested stdin control; no service command execution is currently installed.
    pub control_stdin: bool,
    /// Requested outer peer address.
    pub remote: SocketAddr,
    /// Requested trust-root file; validation does not open it.
    pub ca: PathBuf,
    /// Requested member identity file; validation does not open it.
    pub identity: PathBuf,
    /// Requested TLS identity verification name, separate from SNI.
    pub server_name: String,
    /// Requested TLS SNI policy, without changing the identity trust anchor.
    pub sni: ClientSni,
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
        "--control",
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
            "the retained configuration validator accepts explicit tcp-tls and tun only; Common execution is pending",
        ));
    }
    let control_stdin = match values.get("--control").copied() {
        None => false,
        Some("stdin") => true,
        Some(_) => {
            return Err(invalid(
                "control requires explicit stdin; other transports are unsupported",
            ));
        }
    };
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
    let device = device_config(
        get("--wintun-dll")?,
        get("--wintun-sha256")?,
        get("--address")?,
        mtu,
        remote,
    )?;
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
        control_stdin,
        remote,
        ca: get("--ca")?.into(),
        identity: get("--identity")?.into(),
        server_name: server_name.to_owned(),
        sni,
    })))
}

/// Check device input shapes (absolute DLL, SHA-256 pin, address/prefix)
/// before a profile supplies the MTU and peer for [`device_config`].
pub(crate) fn device_shape(dll: &str, pin: &str, address: &str) -> io::Result<()> {
    let unspecified = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0));
    device_config(dll, pin, address, 1280, unspecified).map(drop)
}

/// Check only the IPv4/prefix address shape (for unpinned daemon options where
/// `wintun.dll` is discovered from the install directory on connect).
pub(crate) fn address_shape(address: &str) -> io::Result<()> {
    let placeholder_dll = if cfg!(windows) {
        r"C:\Program Files\l2tunnel\wintun.dll"
    } else {
        "/wintun.dll"
    };
    let placeholder_pin = "0".repeat(64);
    device_shape(placeholder_dll, &placeholder_pin, address)
}

pub(crate) fn device_config(
    dll: &str,
    pin: &str,
    address: &str,
    mtu: u16,
    remote: SocketAddr,
) -> io::Result<Config> {
    let (address, prefix) = address
        .split_once('/')
        .ok_or_else(|| invalid("address requires IPV4/PREFIX"))?;
    let device = Config::new(
        PathBuf::from(dll),
        sha256(pin)?,
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
    Ok(device)
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

impl Plan {
    /// Refuse execution before any credential, socket, stdin or native-device I/O.
    ///
    /// The former managed-frame service was removed. A parsed plan does not
    /// supply a current Common catalog or an authenticated runtime owner.
    pub fn check_runtime_support(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows Common client/service binding is not implemented; the obsolete managed TCP/TLS foreground path has been removed",
        ))
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
    fn stdin_control_is_explicit_and_other_transports_are_rejected() -> io::Result<()> {
        let Command::Connect(plan) = parse(&args())? else {
            return Err(invalid("plan"));
        };
        assert!(!plan.control_stdin);
        let mut arguments = args();
        arguments.extend(["--control".into(), "stdin".into()]);
        let Command::Connect(plan) = parse(&arguments)? else {
            return Err(invalid("plan"));
        };
        assert!(plan.control_stdin);
        for value in ["pipe", "auto", "off", "STDIN"] {
            let mut arguments = args();
            arguments.extend(["--control".into(), value.into()]);
            assert!(parse(&arguments).is_err());
        }
        arguments.extend(["--control".into(), "stdin".into()]);
        assert!(parse(&arguments).is_err());
        Ok(())
    }
    #[test]
    fn validated_request_refuses_execution_before_credential_or_device_io() -> io::Result<()> {
        let Command::Connect(plan) = parse(&args())? else {
            return Err(invalid("plan"));
        };
        // The fixture uses nonexistent credential and DLL paths. Refusal is a
        // capability result, not a file-open or platform-constructor failure.
        let error = plan.check_runtime_support().err().ok_or_else(|| {
            io::Error::other("pending Common service unexpectedly accepted execution")
        })?;
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("Common client/service"));
        Ok(())
    }
}
