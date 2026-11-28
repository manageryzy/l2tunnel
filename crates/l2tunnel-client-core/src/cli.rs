//! Shared strict CLI frontend; native privileges remain in the platform adapter.
use super::*;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
#[path = "proxy/cli.rs"]
mod proxy_frontend;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use proxy_frontend::{
    ServiceEvent as ProxyServiceEvent, ServicePresentation as ProxyServicePresentation,
    serve_shared_for_test as serve_shared_proxy_for_test,
};
#[cfg(target_os = "linux")]
#[path = "cli_daemon.rs"]
mod daemon;
#[cfg(any(unix, windows))]
#[path = "cli_groups.rs"]
mod groups;
#[path = "host_runtime_cli.rs"]
mod host_runtime;
#[cfg(unix)]
#[path = "secure_udp/cli.rs"]
pub(crate) mod secure_udp_frontend;
#[cfg(target_os = "linux")]
#[path = "cli_system_service.rs"]
mod system_service;
#[path = "cli_tls.rs"]
mod tls_frontend;

const HELP: &str = "l2tunnel connect|serve --record-profile common --common-transaction-plan PATH --carrier CARRIER. Use inspect-common-transaction-plan before startup. Select a native --device or Ethernet --vxlan-bind/--vxlan-peer/--vni attachment. keygen creates member keys. Current local commands: status, disconnect, reconnect, drain-proxy (API1), common-catalog and switch-common-configuration (API4). Without --state-dir, interface setup/routes belong to the caller; with --state-dir DIR the service creates owned devices and session routes on request (l2tunnelctl device/route). daemon --control-socket PATH --state-dir DIR runs the long-lived Linux service with stored profiles (l2tunnelctl profile ...; service connect --profile NAME); it starts idle unless a default profile is set. Legacy standalone entries are retired; Common active TUN credit and Windows service migration remain unfinished.";
fn input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
fn options(args: &[String], allowed: &[&str]) -> io::Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for pair in args.chunks(2) {
        if pair.len() != 2 || !allowed.contains(&pair[0].as_str()) || pair[1].starts_with("--") {
            return Err(input("unknown option or missing option value; use --help"));
        }
        let maximum = crate::secure_udp::common_status::CANONICAL_CHARACTERS;
        if pair[0] == "--configuration" && pair[1].len() > maximum {
            return Err(input(format!(
                "complete configuration exceeds{maximum} characters"
            )));
        }
        if parsed.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(input("duplicate option"));
        }
    }
    Ok(parsed)
}
fn required<'a>(options: &'a BTreeMap<String, String>, key: &str) -> io::Result<&'a str> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| input(format!("missing {key}")))
}
#[cfg(unix)]
fn bounded_file(path: &str, maximum: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut contents = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut contents)?;
    if contents.len() > maximum {
        return Err(input("identity/certificate file exceeds limit"));
    }
    Ok(contents)
}
fn new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn generate(options: &BTreeMap<String, String>) -> io::Result<()> {
    let private_path = Path::new(required(options, "--private")?);
    let public_path = Path::new(required(options, "--public")?);
    if private_path == public_path {
        return Err(input("private and public paths must differ"));
    }
    let private = MemberKey::generate_pkcs8().map_err(auth_error)?;
    let identity = MemberKey::from_pkcs8(&private).map_err(auth_error)?;
    // Exclusive creation never truncates an existing identity. Keep any partially
    // provisioned new file for explicit inspection if the second creation fails.
    let mut private_file = new_file(private_path)?;
    private_file.write_all(&private)?;
    private_file.sync_all()?;
    let mut public_file = new_file(public_path)?;
    public_file.write_all(&identity.public_key().0)?;
    public_file.sync_all()?;
    println!("Created member identity and raw public allowlist entry.");
    Ok(())
}
#[cfg(any(test, target_os = "linux"))]
fn configuration(options: &BTreeMap<String, String>) -> io::Result<ConnectionConfig> {
    let layer = match required(options, "--layer")? {
        "tap" => PacketLayer::Ethernet,
        "tun" => PacketLayer::Ip,
        _ => return Err(input("layer must be tap or tun")),
    };
    let duplex = match options
        .get("--duplex")
        .map(String::as_str)
        .unwrap_or("half")
    {
        "half" => Duplex::Half,
        "full" => Duplex::Full,
        _ => return Err(input("duplex must be half or full")),
    };
    let max_packet = options
        .get("--max-packet")
        .map(|v| v.parse::<usize>().map_err(|_| input("invalid max-packet")))
        .transpose()?
        .unwrap_or(1600);
    let compression = match options
        .get("--compression")
        .map(String::as_str)
        .unwrap_or("off")
    {
        "off" => Compression::None,
        "lz4" => Compression::Lz4IfSmaller,
        _ => return Err(input("compression must be off or lz4")),
    };
    let config = ConnectionConfig {
        layer,
        duplex,
        max_packet,
        compression,
        handshake_timeout: Duration::from_secs(30),
    };
    config.session()?;
    Ok(config)
}
/// Options `connect` or `serve` accept (stored profiles use the same set
/// minus [`local::SERVICE_OPTIONS`]).
fn run_options(command: &str) -> Vec<&'static str> {
    let mut allowed = if command == "serve" {
        vec!["--listen", "--cert", "--key", "--allow-key"]
    } else {
        vec![
            "--remote",
            "--ca",
            "--server-name",
            "--sni",
            "--server-pin",
            "--identity",
            "--tap-mac",
        ]
    };
    allowed.extend_from_slice(&[
        "--control-socket",
        "--state-dir",
        "--device",
        "--vxlan-bind",
        "--vxlan-peer",
        "--vni",
        "--layer",
        "--duplex",
        "--max-packet",
        "--compression",
        "--runtime-model",
        "--carrier",
        "--record-profile",
        "--traffic",
        "--proxy-policy",
        "--udp-bind",
        "--udp-peer",
        "--udp-cover",
        "--raw-policy",
        "--raw-mark",
    ]);
    #[cfg(unix)]
    allowed.extend_from_slice(secure_udp_frontend::OPTIONS);
    // Live tuning (docs/modules/live-tuning.md): choices on connect, limits on serve.
    allowed.extend_from_slice(if command == "serve" {
        &crate::secure_udp::live_tuning::SERVER_OPTIONS[..]
    } else {
        &crate::secure_udp::live_tuning::CLIENT_OPTIONS[..]
    });
    allowed
}
fn number<T: std::str::FromStr>(
    options: &BTreeMap<String, String>,
    key: &str,
    default: T,
) -> io::Result<T> {
    options
        .get(key)
        .map(|value| value.parse().map_err(|_| input(format!("invalid {key}"))))
        .transpose()
        .map(|value| value.unwrap_or(default))
}

#[cfg(target_os = "linux")]
async fn execute(command: &str, options: &BTreeMap<String, String>) -> io::Result<()> {
    if command == "daemon" {
        return daemon::run(options).await;
    }
    tls_frontend::preflight(command, options)?;
    let config = configuration(options)?;
    let selected = secure_udp_frontend::selection(command, options, config)?.ok_or_else(|| input(
        "legacy entry retired; select --record-profile common and an explicit --carrier with --common-transaction-plan",
    ))?;
    secure_udp_frontend::execute(command, options, config, selected).await
}

#[cfg(not(target_os = "linux"))]
async fn execute(_command: &str, _options: &BTreeMap<String, String>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Common native CLI service is not yet implemented on this platform",
    ))
}
#[cfg(any(unix, windows))]
async fn execute_api(command: &str, options: &BTreeMap<String, String>) -> io::Result<()> {
    use super::local::{self, Action, Request, VERSION};
    let action = match command {
        "status" => Action::Status {},
        "disconnect" => Action::Disconnect {},
        "reconnect" => Action::Reconnect {},
        "switch-swift-configuration" | "set-swift" => {
            return Err(input(
                "Swift-only local commands are retired; use switch-common-configuration --api-version 4 with a complete catalog value",
            ));
        }
        "switch-common-configuration" => {
            if number(options, "--api-version", VERSION)? != local::COMMON_VERSION {
                return Err(input(
                    "complete Common configuration requires explicit --api-version 4",
                ));
            }
            let request_key = required(options, "--request-key")?
                .parse::<u64>()
                .map_err(|_| input("invalid request key"))?;
            if request_key == 0 {
                return Err(input("request key must be nonzero"));
            }
            Action::SwitchCommonConfiguration {
                configuration: crate::secure_udp::common_status::CanonicalConfiguration::parse(
                    required(options, "--configuration")?,
                )?,
                request_key,
            }
        }
        "common-catalog" => {
            if number(options, "--api-version", VERSION)? != local::COMMON_VERSION {
                return Err(input("Common catalog requires explicit --api-version 4"));
            }
            let text = required(options, "--catalog")?;
            if text.len() != 64
                || !text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(input("catalog must be exact64 lowercase hex"));
            }
            let mut catalog = [0; 32];
            let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            for (byte, pair) in catalog.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
                *byte = nibble(pair[0]) * 16 + nibble(pair[1]);
            }
            let generation = required(options, "--generation")?
                .parse()
                .map_err(|_| input("invalid generation"))?;
            let offset = required(options, "--offset")?
                .parse()
                .map_err(|_| input("invalid offset"))?;
            let limit = required(options, "--limit")?
                .parse()
                .map_err(|_| input("invalid page limit"))?;
            if !(1..=crate::secure_udp::common_status::CATALOG_PAGE_LIMIT).contains(&limit) {
                return Err(input("page limit must be1..4"));
            }
            Action::CommonCatalog {
                generation,
                catalog,
                offset,
                limit,
            }
        }
        "drain-proxy" => Action::DrainProxy {},
        _ => return Err(input("unsupported local API command")),
    };
    let version = number(options, "--api-version", VERSION)?;
    if !local::supported_version(version) {
        return Err(input("api-version must be explicitly 1 or 4"));
    }
    let response = local::request(
        required(options, "--control-socket")?,
        &Request { version, action },
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string(&response).map_err(io::Error::other)?
    );
    if !response.ok {
        return Err(io::Error::other(format!(
            "operation rejected: {}",
            response.code
        )));
    }
    Ok(())
}
#[cfg(not(any(unix, windows)))]
async fn execute_api(_command: &str, _options: &BTreeMap<String, String>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native local API transport is not implemented on this platform",
    ))
}
/// Run the shared CLI. Does not change routes, bridges or existing qdiscs.
pub fn main_entry(args: impl IntoIterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.into_iter().collect();
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        println!("{HELP}");
        #[cfg(unix)]
        println!("\n{}", secure_udp_frontend::HELP);
        #[cfg(any(unix, windows))]
        println!("\n{}", groups::HELP);
        #[cfg(target_os = "linux")]
        println!("\n{}", system_service::HELP);
        return ExitCode::SUCCESS;
    }
    if args.as_slice() == ["--version"] {
        println!("l2tunnel {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.as_slice() == ["plan"] {
        println!(
            "Current production entries use Common compact Records with explicit original UDP, OpenVPN, raw TCP, retained TLS or genuine QUIC carriers. Algorithms remain explicit catalog configurations. Common active TUN credit, Windows service, complete Python mode parity and native qualification remain unfinished."
        );
        return ExitCode::SUCCESS;
    }
    #[cfg(any(unix, windows))]
    if groups::GROUPS.contains(&args[0].as_str()) {
        return groups::main(&args);
    }
    #[cfg(target_os = "linux")]
    if args[0] == "system-service" {
        return system_service::main(&args[1..]);
    }
    let command = &args[0];
    let mut allowed = match command.as_str() {
        "keygen" => vec!["--private", "--public"],
        "status" | "disconnect" | "reconnect" | "drain-proxy" => {
            vec!["--control-socket"]
        }
        "switch-swift-configuration" => vec!["--control-socket", "--configuration"],
        "switch-common-configuration" => {
            vec!["--control-socket", "--configuration", "--request-key"]
        }
        "common-catalog" => vec![
            "--control-socket",
            "--generation",
            "--catalog",
            "--offset",
            "--limit",
        ],
        "inspect-swift-transaction-plan" | "inspect-common-transaction-plan" => vec![
            "--traffic",
            "--proxy-policy",
            "--proxy-close",
            "--role",
            "--carrier",
            "--record-profile",
            "--duplex",
            "--compression",
            "--layer",
            "--max-packet",
            "--udp-bind",
            "--udp-peer",
            "--max-path-mtu",
            "--swift-transaction-plan",
            "--common-transaction-plan",
            "--raw-policy",
            "--maintained-policy",
            "--noise-profile",
            "--noise-private-key-file",
            "--noise-peer-key-file",
            "--noise-psk-file",
            "--identity",
            "--allow-key",
            "--udp-cover",
            "--ca",
            "--server-name",
            "--sni",
            "--server-pin",
            "--cert",
            "--key",
        ],
        "set-swift" => vec![
            "--control-socket",
            "--swift-forward-kbit",
            "--swift-reverse-kbit",
            "--swift-channels",
            "--swift-window",
            "--swift-repair-permille",
            "--path-mtu",
        ],
        "connect" | "serve" => run_options(command),
        #[cfg(target_os = "linux")]
        "daemon" => vec!["--control-socket", "--state-dir", "--runtime-model"],
        _ => {
            eprintln!("Unknown command. Use --help.");
            return ExitCode::from(2);
        }
    };
    let local_api = matches!(
        command.as_str(),
        "status"
            | "disconnect"
            | "reconnect"
            | "set-swift"
            | "switch-swift-configuration"
            | "switch-common-configuration"
            | "common-catalog"
            | "drain-proxy"
    );
    if local_api {
        allowed.push("--api-version");
    }
    let result = options(&args[1..], &allowed).and_then(|mut options| {
        tls_frontend::preflight(command, &options)?;
        if command == "keygen" {
            return generate(&options);
        }
        if command == "inspect-swift-transaction-plan" {
            return Err(input("Swift-only inspection is retired; use inspect-common-transaction-plan with the complete Common plan"));
        }
        if command == "inspect-common-transaction-plan" {
            if (command == "inspect-common-transaction-plan")
                != options.contains_key("--common-transaction-plan")
            {
                return Err(input(
                    "inspection command must match the explicit plan backend",
                ));
            }
            #[cfg(target_os = "linux")]
            return secure_udp_frontend::inspect(&options);
            #[cfg(not(target_os = "linux"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "generic transaction plan inspection CLI is implemented on Linux only",
            ));
        }
        if local_api {
            // One private IPC exchange needs I/O and timers, not a worker pool.
            return tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(execute_api(command, &options));
        }
        tls_frontend::report_requested(&options)?;
        let model = host_runtime::take(&mut options)?;
        let (runtime, observation) = host_runtime::build(model)?;
        if let Some(observation) = observation {
            let encoded = serde_json::to_string(&observation).map_err(io::Error::other)?;
            writeln!(io::stderr().lock(), "{encoded}")?;
        }
        runtime.block_on(execute(command, &options))
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("l2tunnel: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn option_validation_is_strict() -> io::Result<()> {
        for input in [
            vec!["--x"],
            vec!["--x", "one", "--x", "two"],
            vec!["--unknown", "x"],
            vec!["--x", "--y"],
        ] {
            assert!(
                options(
                    &input.into_iter().map(String::from).collect::<Vec<_>>(),
                    &["--x"]
                )
                .is_err()
            );
        }
        let parsed = options(&["--layer".into(), "tun".into()], &["--layer"])?;
        assert_eq!(configuration(&parsed)?.duplex, Duplex::Half);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn retired_base_datagram_entry_refuses_before_credential_or_socket_io() -> io::Result<()>
    {
        for carrier in ["udp", "quic"] {
            let mut options = BTreeMap::from([
                ("--layer".into(), "tun".into()),
                ("--duplex".into(), "full".into()),
                ("--carrier".into(), carrier.into()),
                ("--udp-bind".into(), "127.0.0.1:24440".into()),
                ("--udp-peer".into(), "127.0.0.1:24441".into()),
                ("--remote".into(), "127.0.0.1:24441".into()),
                ("--ca".into(), "/nonexistent/base-delivery28/ca".into()),
            ]);
            if carrier == "udp" {
                options.insert("--udp-cover".into(), "quic-like".into());
            } else {
                options.insert("--quic-application-id".into(), "71".repeat(16));
            }
            for mode in [None, Some("legacy")] {
                if let Some(mode) = mode {
                    options.insert("--delivery-window".into(), mode.into());
                }
                let error = execute("connect", &options)
                    .await
                    .err()
                    .ok_or_else(|| input("retired base datagram entry accepted"))?;
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert_eq!(
                    error.to_string(),
                    "legacy entry retired; select --record-profile common and an explicit --carrier with --common-transaction-plan"
                );
            }
        }
        Ok(())
    }
}
