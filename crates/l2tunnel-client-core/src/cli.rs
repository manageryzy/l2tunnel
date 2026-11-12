//! Shared strict CLI frontend; native privileges remain in the platform adapter.
use super::*;
#[cfg(target_os = "linux")]
use auth::MemberPublicKey;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
#[path = "proxy/cli.rs"]
mod proxy_frontend;
#[cfg(all(test, unix))]
pub(crate) use proxy_frontend::serve_for_test as serve_proxy_for_test;
#[cfg(all(test, unix))]
pub(crate) use proxy_frontend::serve_measured as serve_measured_for_test;
#[path = "packed_cli.rs"]
mod packed_frontend;
#[path = "raw_packet/cli.rs"]
mod raw_packet_frontend;
#[cfg(all(test, unix))]
pub(crate) use raw_packet_frontend::response as raw_packet_response_for_test;
#[path = "openvpn/cli.rs"]
mod standalone;

const HELP: &str = "l2tunnel serve --listen IP:PORT --device NAME --layer tap|tun --cert DER --key PKCS8 --allow-key RAW32 [--duplex half|full]\nl2tunnel connect --remote IP:PORT --device NAME --layer tap|tun --ca DER --server-name DNS --identity PKCS8 [--duplex half|full]\nl2tunnel keygen --private NEW_PKCS8_FILE --public NEW_RAW32_FILE\nOptions: --max-packet 40..65519 (default 1600); --compression off|lz4 (default off). Default carrier: TCP/TLS 1.3; no SNI. Default duplex: half (two carriers). Replace --device with --vxlan-bind IP:PORT --vxlan-peer IP:PORT --vni N for a point-to-point Ethernet VTEP. Optional --control-socket PATH exposes a private local service API. Commands: status --control-socket PATH; set-compression --control-socket PATH --compression off|lz4. Interface setup/routes belong to the caller.";
fn input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
fn options(args: &[String], allowed: &[&str]) -> io::Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for pair in args.chunks(2) {
        if pair.len() != 2 || !allowed.contains(&pair[0].as_str()) || pair[1].starts_with("--") {
            return Err(input("unknown option or missing option value; use --help"));
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
#[cfg(target_os = "linux")]
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
const UDP_OPTIONS: &[&str] = &[
    "--udp-bind",
    "--udp-peer",
    "--udp-reverse-bind",
    "--udp-reverse-peer",
    "--udp-cover",
    "--udp-protection",
    "--path-mtu",
    "--fec",
    "--fec-sources",
    "--fec-repairs",
    "--fec-flush-ms",
];
const UDP_HELP: &str = r#"UDP options: --carrier udp --udp-bind IP:PORT --udp-peer IP:PORT
  --udp-cover openvpn-like|quic-like --udp-protection aead|integrity (default aead)
  --path-mtu N (default 1500). These covers are custom resemblance profiles.
Half duplex also requires --udp-reverse-bind IP:PORT --udp-reverse-peer IP:PORT.
The forward pair always carries initiator to listener; reverse carries listener to initiator.
UDP retains authenticated TCP/TLS for bootstrap, recovery feedback and liveness.
UDP compression is fixed for the session; --control-socket is currently TCP-only.
Optional UDP repair: --fec none|cauchy (default none). Cauchy-only settings:
  --fec-sources N (default 4), --fec-repairs N (default 2), --fec-flush-ms N (default 5)."#;
fn udp_settings(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<super::udp::Settings>> {
    use super::udp::{CoverProfile, Endpoints, Protection, Settings};
    match options
        .get("--carrier")
        .map(String::as_str)
        .unwrap_or("tcp")
    {
        "tcp" => {
            if UDP_OPTIONS.iter().any(|key| options.contains_key(*key)) {
                return Err(input("UDP options require explicit --carrier udp"));
            }
            return Ok(None);
        }
        "udp" => {}
        "quic" | "openvpn-like" => return Ok(None),
        _ => {
            return Err(input(
                "implemented carriers are tcp, udp, quic and openvpn-like; raw TCP is not available",
            ));
        }
    }
    if options.contains_key("--control-socket") {
        return Err(input(
            "the current UDP runtime has fixed compression; local reload API is unsupported",
        ));
    }
    let address = |key| {
        required(options, key)?
            .parse::<SocketAddr>()
            .map_err(|_| input("UDP endpoint requires IP:PORT"))
    };
    let forward = Endpoints {
        local: address("--udp-bind")?,
        peer: address("--udp-peer")?,
    };
    let reverse = match (
        options.contains_key("--udp-reverse-bind"),
        options.contains_key("--udp-reverse-peer"),
    ) {
        (false, false) => None,
        (true, true) => Some(Endpoints {
            local: address("--udp-reverse-bind")?,
            peer: address("--udp-reverse-peer")?,
        }),
        _ => {
            return Err(input(
                "both reverse UDP endpoint options are required together",
            ));
        }
    };
    let cover = match required(options, "--udp-cover")? {
        "openvpn-like" => CoverProfile::OpenVpnLike,
        "quic-like" => CoverProfile::QuicLike,
        _ => {
            return Err(input(
                "UDP cover must be openvpn-like or quic-like (custom resemblance)",
            ));
        }
    };
    let protection = match options
        .get("--udp-protection")
        .map(String::as_str)
        .unwrap_or("aead")
    {
        "aead" => Protection::ChaCha20Poly1305,
        "integrity" => Protection::HmacSha256,
        _ => return Err(input("UDP protection must be aead or integrity")),
    };
    let path_mtu = options
        .get("--path-mtu")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| input("invalid path MTU"))
        })
        .transpose()?
        .unwrap_or(1500);
    let settings = Settings {
        forward,
        reverse,
        cover,
        protection,
        path_mtu,
        recovery: recovery_settings(options)?,
    };
    settings.validate(config.duplex)?;
    super::udp::runtime_config(config, settings)?;
    Ok(Some(settings))
}

fn recovery_settings(options: &BTreeMap<String, String>) -> io::Result<super::udp::RecoveryMode> {
    use super::udp::RecoveryMode;
    Ok(
        match options.get("--fec").map(String::as_str).unwrap_or("none") {
            "none" => {
                if ["--fec-sources", "--fec-repairs", "--fec-flush-ms"]
                    .iter()
                    .any(|key| options.contains_key(*key))
                {
                    return Err(input("FEC tuning requires --fec cauchy"));
                }
                RecoveryMode::SelectiveRepeat
            }
            "cauchy" => RecoveryMode::Cauchy {
                sources: number(options, "--fec-sources", 4)?,
                repairs: number(options, "--fec-repairs", 2)?,
                flush_after: Duration::from_millis(number(options, "--fec-flush-ms", 5)?),
            },
            _ => return Err(input("FEC must be none or cauchy")),
        },
    )
}

const QUIC_HELP: &str = "Genuine QUIC: --carrier quic --quic-application-id HEX32, explicit --udp-bind/--udp-peer and half-duplex reverse endpoint pair. --remote/--listen must match the forward peer/local. No TCP socket is used. Existing certificates/member authentication and --path-mtu/--fec options apply. QUIC always uses AEAD; --udp-cover/--udp-protection, active TUN and local reload are unsupported. ALPN is observable; this is not HTTP/3.";
fn quic_settings(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<super::quic::Settings>> {
    if options.get("--carrier").map(String::as_str) != Some("quic") {
        if options.contains_key("--quic-application-id") {
            return Err(input("QUIC application ID requires --carrier quic"));
        }
        return Ok(None);
    }
    if ["--udp-cover", "--udp-protection", "--control-socket"]
        .iter()
        .any(|key| options.contains_key(*key))
    {
        return Err(input(
            "genuine QUIC forbids custom cover, optional protection and local reload options",
        ));
    }
    let text = required(options, "--quic-application-id")?;
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(input(
            "QUIC application ID requires exactly 32 hexadecimal digits",
        ));
    }
    let mut application_id = [0; 16];
    for (index, byte) in application_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| input("invalid QUIC application ID"))?;
    }
    let address = |key| {
        required(options, key)?
            .parse::<SocketAddr>()
            .map_err(|_| input("QUIC endpoint requires IP:PORT"))
    };
    let forward = super::udp::Endpoints {
        local: address("--udp-bind")?,
        peer: address("--udp-peer")?,
    };
    let reverse = match (
        options.contains_key("--udp-reverse-bind"),
        options.contains_key("--udp-reverse-peer"),
    ) {
        (false, false) => None,
        (true, true) => Some(super::udp::Endpoints {
            local: address("--udp-reverse-bind")?,
            peer: address("--udp-reverse-peer")?,
        }),
        _ => {
            return Err(input(
                "both reverse QUIC endpoint options are required together",
            ));
        }
    };
    let settings = super::quic::Settings {
        forward,
        reverse,
        application_id,
        path_mtu: number(options, "--path-mtu", 1500)?,
        recovery: recovery_settings(options)?,
    };
    super::quic::runtime_config(config, settings)?;
    for (key, expected) in [("--remote", forward.peer), ("--listen", forward.local)] {
        if options.contains_key(key) && address(key)? != expected {
            return Err(input(
                "QUIC remote/listen must match the actual forward peer/local endpoint",
            ));
        }
    }
    Ok(Some(settings))
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

const ACTIVE_OPTIONS: &[&str] = &[
    "--traffic",
    "--mux-channels",
    "--max-flows",
    "--qos-dscp",
    "--flow-idle-ms",
    "--adaptive",
    "--active-stats-ms",
    "--active-policies",
];
const ACTIVE_HELP: &str = "Traffic: --traffic system|active (default system). Active requires TUN over TCP, uses per-flow credits and weighted DRR. Active-only options: --mux-channels N, --max-flows N, --qos-dscp D:W[,D:W...], --flow-idle-ms N (default 60000, 1..86400000), --adaptive off|on (default off, measured feedback). Unspecified DSCP weights are one. Optional --active-policies JSON_FILE authenticates a finite catalog and enables --control-socket for coordinated channel/weight changes. Command: set-active-policy --control-socket PATH --mux-channels N [--qos-dscp D:W,...]. Idle flow slots are retired after authenticated drain. This does not change endpoint TCP windows.";

fn dscp_weights(options: &BTreeMap<String, String>) -> io::Result<[u32; 64]> {
    let mut weights = [1; 64];
    if let Some(policy) = options.get("--qos-dscp") {
        let mut seen = [false; 64];
        for entry in policy.split(',') {
            let (dscp, weight) = entry
                .split_once(':')
                .ok_or_else(|| input("DSCP policy requires D:W entries"))?;
            let dscp: usize = dscp.parse().map_err(|_| input("invalid DSCP"))?;
            let weight: u32 = weight.parse().map_err(|_| input("invalid DSCP weight"))?;
            if dscp >= 64 || !(1..=1024).contains(&weight) || seen[dscp] {
                return Err(input(
                    "DSCP entries must be unique 0..63 with weights 1..1024",
                ));
            }
            seen[dscp] = true;
            weights[dscp] = weight;
        }
    }
    Ok(weights)
}

fn active_settings(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<super::active::Settings>> {
    let selected = options
        .get("--traffic")
        .map(String::as_str)
        .unwrap_or("system");
    if selected == "system" {
        if ACTIVE_OPTIONS[1..]
            .iter()
            .any(|key| options.contains_key(*key))
        {
            return Err(input("active policy options require --traffic active"));
        }
        return Ok(None);
    }
    if selected != "active" {
        return Err(input("traffic must be system or active"));
    }
    let stats_ms: u64 = number(options, "--active-stats-ms", 0)?;
    if stats_ms != 0 && !(100..=60_000).contains(&stats_ms) {
        return Err(input("active stats interval must be 0 or 100..60000 ms"));
    }
    if config.layer != PacketLayer::Ip
        || options.get("--carrier").is_some_and(|value| value != "tcp")
        || (options.contains_key("--control-socket") && !options.contains_key("--active-policies"))
        || options.contains_key("--vxlan-bind")
    {
        return Err(input(
            "active traffic requires TUN/TCP; a local control socket also requires --active-policies",
        ));
    }
    let mut settings = super::active::Settings::new(config.runtime(), config.duplex)?;
    settings.max_flows = number(options, "--max-flows", settings.max_flows)?;
    settings.channels = number(options, "--mux-channels", settings.channels)?;
    settings.adaptive = match options
        .get("--adaptive")
        .map(String::as_str)
        .unwrap_or("off")
    {
        "off" => false,
        "on" => true,
        _ => return Err(input("adaptive must be off or on")),
    };
    settings.idle_flow_timeout =
        std::time::Duration::from_millis(number(options, "--flow-idle-ms", 60_000)?);
    settings.dscp_weights = dscp_weights(options)?;
    l2tunnel_runtime::active::session_config(config.runtime(), settings)?;
    Ok(Some(settings))
}
const ALIGNED_HELP: &str = "Records: --record-profile frame|aligned|packed (default frame). Aligned requires explicit --carrier udp|quic, --fec cauchy, --compression off and system traffic; --aligned-channels 1..256 (default4). All native packets share the channel pool. TUN uses raw-IP aligned bodies; TAP/VXLAN use eligible header compression and exact fallback. No local reload or active TUN combination.";
fn aligned_settings(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<super::aligned::Settings>> {
    match options
        .get("--record-profile")
        .map(String::as_str)
        .unwrap_or("frame")
    {
        "frame" => {
            if options.contains_key("--aligned-channels") {
                return Err(input(
                    "aligned channel count requires --record-profile aligned",
                ));
            }
            Ok(None)
        }
        "aligned" => {
            if !matches!(
                options.get("--carrier").map(String::as_str),
                Some("udp" | "quic")
            ) || options.get("--fec").map(String::as_str) != Some("cauchy")
                || options
                    .get("--traffic")
                    .is_some_and(|mode| mode != "system")
                || options.contains_key("--control-socket")
                || ACTIVE_OPTIONS[1..]
                    .iter()
                    .any(|key| options.contains_key(*key))
            {
                return Err(input(
                    "aligned records require UDP/QUIC, explicit Cauchy, system traffic and no control/active options",
                ));
            }
            let settings = super::aligned::Settings {
                channels: number(options, "--aligned-channels", 4)?,
            };
            settings.validate(config, recovery_settings(options)?)?;
            if let Some(transport) = udp_settings(options, config)? {
                super::aligned::udp_config(config, transport, settings)?;
            }
            if let Some(transport) = quic_settings(options, config)? {
                super::aligned::quic_config(config, transport, settings)?;
            }
            Ok(Some(settings))
        }
        "packed" if !options.contains_key("--aligned-channels") => Ok(None),
        _ => Err(input(
            "record-profile must be frame, aligned or packed, with matching profile options",
        )),
    }
}
#[cfg(target_os = "linux")]
enum Connected {
    Tcp(Link),
    Active(Link, super::active::Settings),
    ActiveManaged(Link, super::active_managed::Config),
    Udp(l2tunnel_runtime::udp::Link, l2tunnel_runtime::udp::Config),
    Quic(l2tunnel_runtime::quic::Link, l2tunnel_runtime::quic::Config),
    AlignedUdp(
        l2tunnel_runtime::aligned::UdpLink,
        l2tunnel_runtime::udp::Config,
        l2tunnel_runtime::aligned::Config,
    ),
    AlignedQuic(
        l2tunnel_runtime::aligned::QuicLink,
        l2tunnel_runtime::quic::Config,
        l2tunnel_runtime::aligned::Config,
    ),
    PackedUdp(
        l2tunnel_runtime::packed::UdpLink,
        l2tunnel_runtime::udp::Config,
        l2tunnel_runtime::packed::Config,
    ),
    PackedQuic(
        l2tunnel_runtime::packed::QuicLink,
        l2tunnel_runtime::quic::Config,
        l2tunnel_runtime::packed::Config,
    ),
}
#[cfg(target_os = "linux")]
enum DeviceSpec {
    Native(String),
    Vxlan {
        bind: SocketAddr,
        peer: SocketAddr,
        vni: l2tunnel_vxlan::Vni,
    },
}
#[cfg(target_os = "linux")]
impl DeviceSpec {
    fn parse(options: &BTreeMap<String, String>, config: ConnectionConfig) -> io::Result<Self> {
        let vxlan = ["--vxlan-bind", "--vxlan-peer", "--vni"]
            .iter()
            .any(|key| options.contains_key(*key));
        match (options.get("--device"), vxlan) {
            (Some(name), false) => Ok(Self::Native(name.clone())),
            (None, true) if config.layer == PacketLayer::Ethernet => {
                let bind = required(options, "--vxlan-bind")?
                    .parse()
                    .map_err(|_| input("invalid VXLAN bind address"))?;
                let peer = required(options, "--vxlan-peer")?
                    .parse()
                    .map_err(|_| input("invalid VXLAN peer address"))?;
                let vni = required(options, "--vni")?
                    .parse()
                    .map_err(|_| input("invalid VNI integer"))?;
                let vni =
                    l2tunnel_vxlan::Vni::new(vni).map_err(|_| input("VNI outside 24-bit range"))?;
                if config.max_packet > 65499 {
                    return Err(input("VXLAN native frame exceeds UDP bound"));
                }
                Ok(Self::Vxlan { bind, peer, vni })
            }
            _ => Err(input(
                "select exactly one --device or complete Ethernet VXLAN configuration",
            )),
        }
    }
    fn open(
        self,
        config: ConnectionConfig,
    ) -> io::Result<Box<dyn l2tunnel_device::PacketDevice<Error = io::Error> + Send>> {
        match self {
            Self::Native(name) => Ok(Box::new(l2tunnel_platform_linux::TunTap::attach(
                &name,
                config.layer,
            )?)),
            Self::Vxlan { bind, peer, vni } => {
                Ok(Box::new(l2tunnel_platform_vxlan::VxlanDevice::bind(
                    bind,
                    l2tunnel_platform_vxlan::VxlanConfig {
                        peer,
                        vni,
                        max_frame_bytes: config.max_packet,
                        receive_budget: 32,
                    },
                )?))
            }
        }
    }
}
#[cfg(target_os = "linux")]
async fn execute(command: &str, options: &BTreeMap<String, String>) -> io::Result<()> {
    let config = configuration(options)?;
    if let Some((path, mark)) = raw_packet_frontend::selection(options, config)? {
        return raw_packet_frontend::execute(command, options, config, path, mark).await;
    }
    let packed = packed_frontend::settings(options, config)?;
    if let Some(path) = proxy_frontend::selection(options, config)? {
        return proxy_frontend::execute(command, options, config, path).await;
    }
    if let Some(settings) = standalone::settings(options, config, command)? {
        return standalone::execute(command, options, config, settings).await;
    }
    let transport = udp_settings(options, config)?;
    let quic = quic_settings(options, config)?;
    let active = active_settings(options, config)?;
    let aligned = aligned_settings(options, config)?;
    let managed_active = options
        .get("--active-policies")
        .map(|path| {
            let initial = active.ok_or_else(|| input("active catalog requires active traffic"))?;
            super::active_managed::catalog_from_json(
                &bounded_file(path, super::active_managed::MAX_CATALOG_BYTES)?,
                config,
                initial,
            )
        })
        .transpose()?;
    let device_spec = DeviceSpec::parse(options, config)?;
    let api = options
        .get("--control-socket")
        .map(super::local::Server::bind)
        .transpose()?;
    let link = match command {
        "connect" => {
            let remote = required(options, "--remote")?
                .parse()
                .map_err(|_| input("remote requires IP:PORT"))?;
            let roots = vec![bounded_file(required(options, "--ca")?, 65536)?];
            let tls = ClientTls::from_der_roots(&roots).map_err(auth_error)?;
            let identity =
                MemberKey::from_pkcs8(&bounded_file(required(options, "--identity")?, 4096)?)
                    .map_err(auth_error)?;
            let server_name = required(options, "--server-name")?;
            if let (Some(settings), Some(records)) = (quic, packed) {
                let (link, profile, records) = super::packed::connect_quic(
                    &roots,
                    server_name,
                    &identity,
                    config,
                    settings,
                    records,
                )
                .await?;
                Connected::PackedQuic(link, profile, records)
            } else if let (Some(settings), Some(records)) = (transport, packed) {
                let (link, profile, records) = super::packed::connect_udp(
                    remote,
                    &tls,
                    server_name,
                    &identity,
                    config,
                    settings,
                    records,
                )
                .await?;
                Connected::PackedUdp(link, profile, records)
            } else if let (Some(settings), Some(records)) = (quic, aligned) {
                let (link, profile, records) = super::aligned::connect_quic(
                    &roots,
                    server_name,
                    &identity,
                    config,
                    settings,
                    records,
                )
                .await?;
                Connected::AlignedQuic(link, profile, records)
            } else if let (Some(settings), Some(records)) = (transport, aligned) {
                let (link, profile, records) = super::aligned::connect_udp(
                    remote,
                    &tls,
                    server_name,
                    &identity,
                    config,
                    settings,
                    records,
                )
                .await?;
                Connected::AlignedUdp(link, profile, records)
            } else if let Some(settings) = quic {
                let (link, profile) =
                    super::quic::connect(&roots, server_name, &identity, config, settings).await?;
                Connected::Quic(link, profile)
            } else if let Some(settings) = transport {
                let (link, profile) =
                    super::udp::connect(remote, &tls, server_name, &identity, config, settings)
                        .await?;
                Connected::Udp(link, profile)
            } else if let Some(settings) = managed_active {
                Connected::ActiveManaged(
                    super::active_managed::connect(
                        remote,
                        &tls,
                        server_name,
                        &identity,
                        config,
                        &settings,
                    )
                    .await?,
                    settings,
                )
            } else if let Some(settings) = active {
                Connected::Active(
                    super::active::connect(remote, &tls, server_name, &identity, config, settings)
                        .await?,
                    settings,
                )
            } else {
                Connected::Tcp(connect(remote, &tls, server_name, &identity, config).await?)
            }
        }
        "serve" => {
            let address: SocketAddr = required(options, "--listen")?
                .parse()
                .map_err(|_| input("listen requires IP:PORT"))?;
            let certificate = bounded_file(required(options, "--cert")?, 65536)?;
            let key = bounded_file(required(options, "--key")?, 65536)?;
            let public = bounded_file(required(options, "--allow-key")?, 32)?;
            let public: [u8; 32] = public
                .try_into()
                .map_err(|_| input("allow-key must contain exactly 32 raw Ed25519 public bytes"))?;
            let certificates = vec![certificate];
            let tls = ServerTls::from_der(&certificates, &key).map_err(auth_error)?;
            let allowlist = MemberAllowlist::new(&[MemberPublicKey(public)]).map_err(auth_error)?;
            if let (Some(settings), Some(records)) = (quic, packed) {
                let listener = super::packed::QuicListener::bind(
                    &certificates,
                    &key,
                    config,
                    settings,
                    records,
                )?;
                println!("Listening on packed QUIC UDP {}", settings.forward.local);
                let (link, profile, records) = listener.accept(&allowlist).await?;
                Connected::PackedQuic(link, profile, records)
            } else if let (Some(settings), Some(records)) = (quic, aligned) {
                let listener = super::aligned::QuicListener::bind(
                    &certificates,
                    &key,
                    config,
                    settings,
                    records,
                )?;
                println!("Listening on aligned QUIC UDP {}", settings.forward.local);
                let (link, profile, records) = listener.accept(&allowlist).await?;
                Connected::AlignedQuic(link, profile, records)
            } else if let Some(settings) = quic {
                let listener = super::quic::Listener::bind(&certificates, &key, config, settings)?;
                println!("Listening on QUIC UDP {}", settings.forward.local);
                let (link, profile) = listener.accept(&allowlist).await?;
                Connected::Quic(link, profile)
            } else {
                let listener = TcpListener::bind(address).await?;
                println!("Listening on {}", listener.local_addr()?);
                if let (Some(settings), Some(records)) = (transport, packed) {
                    let (link, profile, records) = super::packed::accept_udp(
                        &listener, &tls, &allowlist, config, settings, records,
                    )
                    .await?;
                    Connected::PackedUdp(link, profile, records)
                } else if let (Some(settings), Some(records)) = (transport, aligned) {
                    let (link, profile, records) = super::aligned::accept_udp(
                        &listener, &tls, &allowlist, config, settings, records,
                    )
                    .await?;
                    Connected::AlignedUdp(link, profile, records)
                } else if let Some(settings) = transport {
                    let (link, profile) =
                        super::udp::accept(&listener, &tls, &allowlist, config, settings).await?;
                    Connected::Udp(link, profile)
                } else if let Some(settings) = managed_active {
                    Connected::ActiveManaged(
                        super::active_managed::accept(
                            &listener, &tls, &allowlist, config, &settings,
                        )
                        .await?,
                        settings,
                    )
                } else if let Some(settings) = active {
                    Connected::Active(
                        super::active::accept(&listener, &tls, &allowlist, config, settings)
                            .await?,
                        settings,
                    )
                } else {
                    Connected::Tcp(accept(&listener, &tls, &allowlist, config).await?)
                }
            }
        }
        _ => return Err(input("unsupported command")),
    };
    let device = device_spec.open(config)?;
    println!(
        "Authenticated {:?} {:?}; forwarding packet device",
        config.layer, config.duplex
    );
    let link = match link {
        Connected::ActiveManaged(link, settings) => {
            println!(
                "Carrier: tcp-tls; managed active TUN policy catalog; initial channels {}; {} targets",
                settings.initial.channels,
                if settings.initial.adaptive {
                    "measured adaptive"
                } else {
                    "static bootstrap"
                }
            );
            return run_active_managed(
                device,
                link,
                config.runtime(),
                settings,
                api,
                number(options, "--active-stats-ms", 0)?,
            )
            .await;
        }
        Connected::Active(link, settings) => {
            println!(
                "Carrier: tcp-tls; transparent TUN active credits; weighted DRR; CRC MUX channels {}; {} targets; compression fixed",
                settings.channels,
                if settings.adaptive {
                    "measured adaptive"
                } else {
                    "static bootstrap"
                }
            );
            return run_active(
                device,
                link,
                config.runtime(),
                settings,
                number(options, "--active-stats-ms", 0)?,
            )
            .await;
        }
        Connected::AlignedUdp(link, profile, records) => {
            println!(
                "Carrier: UDP with retained TCP/TLS bootstrap/control; record-profile aligned; CRC MUX channels {}; recovery {:?}; native {:?}",
                records.pipeline.flows.channels, profile.recovery, records.protocol.native_policy
            );
            return l2tunnel_runtime::aligned::run_udp(
                device,
                link,
                config.runtime(),
                profile,
                records,
            )
            .await;
        }
        Connected::PackedUdp(link, profile, records) => {
            println!(
                "Carrier: UDP with retained TCP/TLS; record-profile packed; channels {}; hold {} us; maximum units {}; work limit {}; recovery {:?}",
                records.pipeline.flows.channels,
                records.protocol.hold_micros,
                records.protocol.max_units,
                records.protocol.work_limit,
                profile.recovery
            );
            return l2tunnel_runtime::packed::run_udp(
                device,
                link,
                config.runtime(),
                profile,
                records,
            )
            .await;
        }
        Connected::PackedQuic(link, profile, records) => {
            println!(
                "Carrier: genuine QUIC; record-profile packed; channels {}; hold {} us; maximum units {}; work limit {}; recovery {:?}",
                records.pipeline.flows.channels,
                records.protocol.hold_micros,
                records.protocol.max_units,
                records.protocol.work_limit,
                profile.recovery
            );
            return l2tunnel_runtime::packed::run_quic(
                device,
                link,
                config.runtime(),
                profile,
                records,
            )
            .await;
        }
        Connected::AlignedQuic(link, profile, records) => {
            println!(
                "Carrier: genuine QUIC over UDP only; record-profile aligned; CRC MUX channels {}; recovery {:?}; native {:?}",
                records.pipeline.flows.channels, profile.recovery, records.protocol.native_policy
            );
            return l2tunnel_runtime::aligned::run_quic(
                device,
                link,
                config.runtime(),
                profile,
                records,
            )
            .await;
        }
        Connected::Tcp(link) => {
            println!("Carrier: tcp-tls; coordinated compression enabled");
            link
        }
        Connected::Udp(link, profile) => {
            println!(
                "Carrier: UDP with retained TCP/TLS bootstrap/control; cover {:?}; protection {:?}; recovery {:?}; compression fixed",
                profile.cover, profile.protection, profile.recovery
            );
            return l2tunnel_runtime::udp::run(device, link, config.runtime(), profile).await;
        }
        Connected::Quic(link, profile) => {
            println!(
                "Carrier: genuine QUIC over UDP only; retained authenticated control; AEAD; recovery {:?}; compression fixed",
                profile.recovery
            );
            return l2tunnel_runtime::quic::run(device, link, config.runtime(), profile).await;
        }
    };
    use l2tunnel_runtime::managed::{self, ManagedConfig, Role, TransactionSettings};
    let (handle, requests) = managed::channel();
    let runtime = managed::run_managed(
        device,
        link,
        config.runtime(),
        ManagedConfig {
            role: if command == "connect" {
                Role::Client
            } else {
                Role::Server
            },
            initial_mode: config.mode()?,
            transaction_settings: TransactionSettings::default(),
        },
        requests,
    );
    if let Some(api) = api {
        tokio::select! {
            result = runtime => result,
            result = api.serve(|request| local_action(handle.clone(), request)) => result,
        }
    } else {
        let _keep_control_alive = handle;
        runtime.await
    }
}
#[cfg(target_os = "linux")]
async fn run_active<D: l2tunnel_device::PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    config: RuntimeConfig,
    settings: super::active::Settings,
    stats_ms: u64,
) -> io::Result<()> {
    use l2tunnel_runtime::active;
    if stats_ms == 0 {
        return active::run(device, link, config, settings, None).await;
    }
    let (observer, reporter) = active::observations();
    let mut updates = observer.subscribe();
    let runtime = active::run(device, link, config, settings, Some(reporter));
    tokio::pin!(runtime);
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(stats_ms));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let floor = config.max_packet as u64 * settings.max_flows as u64;
    let mut peak = floor;
    let mut measured_growth = serde_json::Value::Null;
    let mut observing = true;
    loop {
        tokio::select! {
            result = &mut runtime => return result,
            changed = updates.changed(), if observing => {
                observing = changed.is_ok();
                let status = *updates.borrow_and_update();
                if let Some(status) = status
                    && status.adaptive && status.engine.target.bytes > peak
                        && status.feedback.rtt_micros.is_some()
                        && status.feedback.delivery_bytes_per_second.is_some()
                        && status.demanding_flows > 0 {
                        peak = status.engine.target.bytes;
                        measured_growth = serde_json::json!({
                            "target_bytes": peak, "floor_bytes": floor,
                            "rtt_micros": status.feedback.rtt_micros,
                            "delivery_bytes_per_second": status.feedback.delivery_bytes_per_second,
                            "demanding_flows": status.demanding_flows,
                            "native_delivered_packets": status.delivered,
                        });
                }
            }
            _ = interval.tick() => {
                if let Some(status) = observer.status() {
                    println!("{}", serde_json::json!({
                        "kind": "active_stats", "adaptive": status.adaptive,
                        "target_bytes": status.engine.target.bytes, "target_records": status.engine.target.records,
                        "floor_bytes": floor, "retired_flows": status.retired_flows,
                        "rtt_micros": status.feedback.rtt_micros,
                        "delivery_bytes_per_second": status.feedback.delivery_bytes_per_second,
                        "demanding_flows": status.demanding_flows,
                        "native_delivered_packets": status.delivered,
                        "observation_flushed": status.observation_flushed,
                        "measured_growth": measured_growth,
                    }));
                }
            }
        }
    }
}
#[cfg(target_os = "linux")]
async fn run_active_managed<D: l2tunnel_device::PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    runtime_config: RuntimeConfig,
    settings: super::active_managed::Config,
    api: Option<super::local::Server>,
    stats_ms: u64,
) -> io::Result<()> {
    use l2tunnel_runtime::active_management;
    let (handle, requests) = active_management::channel();
    let runtime = active_management::run(device, link, runtime_config, settings, requests);
    let observed = handle.clone();
    let diagnostics = async move {
        if stats_ms == 0 {
            return std::future::pending::<io::Result<()>>().await;
        }
        let mut interval = tokio::time::interval(Duration::from_millis(stats_ms));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Some(status) = observed.status() {
                println!(
                    "{}",
                    serde_json::json!({
                        "kind":"managed_active_stats", "epoch":status.epoch.0,
                        "channels":status.mode.channels, "phase":format!("{:?}", status.phase),
                        "admitting":status.admitting, "adaptive":status.traffic.adaptive,
                        "target_bytes":status.traffic.engine.target.bytes,
                        "retired_flows":status.traffic.retired_flows,
                        "native_delivered_packets":status.traffic.delivered,
                        "admitted_by_channel":status.admitted_by_channel,
                        "handed_by_channel":status.handed_by_channel,
                        "delivered_by_channel":status.delivered_by_channel,
                    })
                );
            }
        }
    };
    if let Some(api) = api {
        tokio::select! {
            result = runtime => result,
            result = diagnostics => result,
            result = api.serve(|request| active_local_action(handle.clone(), runtime_config.compression, request)) => result,
        }
    } else {
        let _keep_control_alive = handle;
        tokio::select! { result = runtime => result, result = diagnostics => result }
    }
}

#[cfg(unix)]
async fn active_local_action(
    handle: l2tunnel_runtime::active_management::ControlHandle,
    compression: Compression,
    request: super::local::Request,
) -> super::local::Response {
    use super::local::{
        Action, ActiveSnapshot, Compression as ApiCompression, Response, Snapshot, VERSION,
    };
    use l2tunnel_runtime::active_management::ControlError;
    let result = match request.action {
        Action::Status {} => Ok(()),
        Action::SwitchCompression { .. } | Action::DrainProxy {} | Action::DrainOpenVpn {} => {
            Err("unsupported")
        }
        Action::SwitchActivePolicy { policy } => match policy.mode() {
            Err(_) => Err("invalid_policy"),
            Ok(mode) => handle
                .switch_policy(mode)
                .await
                .map(|_| ())
                .map_err(|error| match error {
                    ControlError::Busy => "busy",
                    ControlError::NotCoordinator => "not_coordinator",
                    ControlError::Unsupported => "unsupported_policy",
                    ControlError::Aborted => "aborted",
                    ControlError::Closed => "closed",
                }),
        },
    };
    let state = handle.status().map(|status| Snapshot {
        epoch: status.epoch.0,
        phase: format!("{:?}", status.phase),
        compression: match compression {
            Compression::None => ApiCompression::Off,
            Compression::Lz4IfSmaller => ApiCompression::Lz4,
        },
        active: Some(ActiveSnapshot {
            policy: super::active_managed::Policy::from_mode(status.mode),
            admitting: status.admitting,
            running: status.traffic.running,
            digest: status
                .digest
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }),
        proxy: None,
        openvpn_drain: None,
        raw_packet: None,
    });
    Response {
        version: VERSION,
        ok: result.is_ok(),
        code: result.err().unwrap_or("ok").into(),
        state,
    }
}

#[cfg(not(target_os = "linux"))]
async fn execute(command: &str, options: &BTreeMap<String, String>) -> io::Result<()> {
    let config = configuration(options)?;
    if raw_packet_frontend::selection(options, config)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native raw packet CLI is implemented on Linux only",
        ));
    }
    packed_frontend::settings(options, config)?;
    if proxy_frontend::selection(options, config)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native proxy CLI is currently implemented on Linux only",
        ));
    }
    standalone::settings(options, config, command)?;
    udp_settings(options, config)?;
    quic_settings(options, config)?;
    active_settings(options, config)?;
    aligned_settings(options, config)?;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native device CLI is currently implemented on Linux only",
    ))
}
#[cfg(unix)]
async fn local_action(
    handle: l2tunnel_runtime::managed::ControlHandle,
    request: super::local::Request,
) -> super::local::Response {
    use super::local::{Action, Compression as ApiCompression, Response, Snapshot, VERSION};
    use l2tunnel_runtime::managed::ControlError;
    let result = match request.action {
        Action::Status {} => Ok(()),
        Action::SwitchCompression { compression } => handle
            .switch_compression(match compression {
                ApiCompression::Off => Compression::None,
                ApiCompression::Lz4 => Compression::Lz4IfSmaller,
            })
            .await
            .map(|_| ())
            .map_err(|error| match error {
                ControlError::Busy => "busy",
                ControlError::NotCoordinator => "not_coordinator",
                ControlError::Aborted => "aborted",
                ControlError::Closed => "closed",
            }),
        Action::SwitchActivePolicy { .. } | Action::DrainProxy {} | Action::DrainOpenVpn {} => {
            Err("unsupported")
        }
    };
    let code = result.err().unwrap_or("ok");
    let state = handle.status().map(|status| Snapshot {
        epoch: status.epoch.0,
        phase: format!("{:?}", status.phase),
        compression: match status.compression {
            Compression::None => ApiCompression::Off,
            Compression::Lz4IfSmaller => ApiCompression::Lz4,
        },
        active: None,
        proxy: None,
        openvpn_drain: None,
        raw_packet: None,
    });
    Response {
        version: VERSION,
        ok: result.is_ok(),
        code: code.into(),
        state,
    }
}
#[cfg(unix)]
async fn execute_api(command: &str, options: &BTreeMap<String, String>) -> io::Result<()> {
    use super::local::{self, Action, Compression as ApiCompression, Request, VERSION};
    let action = match command {
        "status" => Action::Status {},
        "drain-proxy" => Action::DrainProxy {},
        "drain-openvpn" => Action::DrainOpenVpn {},
        "set-compression" => Action::SwitchCompression {
            compression: match required(options, "--compression")? {
                "off" => ApiCompression::Off,
                "lz4" => ApiCompression::Lz4,
                _ => return Err(input("compression must be off or lz4")),
            },
        },
        "set-active-policy" => {
            let policy = super::active_managed::Policy {
                channels: required(options, "--mux-channels")?
                    .parse()
                    .map_err(|_| input("invalid MUX channel count"))?,
                dscp_weights: dscp_weights(options)?.to_vec(),
            };
            policy.mode()?;
            Action::SwitchActivePolicy { policy }
        }
        _ => return Err(input("unsupported local API command")),
    };
    let response = local::request(
        required(options, "--control-socket")?,
        &Request {
            version: VERSION,
            action,
        },
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
#[cfg(not(unix))]
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
        println!(
            "{HELP}\n\n{UDP_HELP}\n\n{QUIC_HELP}\n\n{ALIGNED_HELP}\n\n{ACTIVE_HELP}\nActive diagnostics: --active-stats-ms 0|100..60000 (default off)."
        );
        println!("\n{}", standalone::HELP);
        println!("\n{}", proxy_frontend::HELP);
        println!("\n{}", packed_frontend::HELP);
        println!("\n{}", raw_packet_frontend::HELP);
        return ExitCode::SUCCESS;
    }
    if args.as_slice() == ["--version"] {
        println!("l2tunnel {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.as_slice() == ["plan"] {
        println!(
            "Implemented with finite native evidence: TCP/TLS, TLS-bootstrapped protected UDP and genuine UDP-only QUIC on Linux TAP/TUN/VXLAN, paired half/full duplex, TCP compression epochs, UDP Cauchy/ARQ, measured active TUN credit/QoS and authenticated flow retirement. Broad hot switching, raw native TCP, complete Python mode parity, GUI and native non-Linux qualification remain unfinished."
        );
        return ExitCode::SUCCESS;
    }
    let command = &args[0];
    let mut allowed = match command.as_str() {
        "keygen" => vec!["--private", "--public"],
        "openvpn-keygen" => vec!["--admission", "--cookie"],
        "status" | "drain-proxy" | "drain-openvpn" => vec!["--control-socket"],
        "set-compression" => vec!["--control-socket", "--compression"],
        "set-active-policy" => vec!["--control-socket", "--mux-channels", "--qos-dscp"],
        "connect" => vec![
            "--remote",
            "--control-socket",
            "--device",
            "--vxlan-bind",
            "--vxlan-peer",
            "--vni",
            "--layer",
            "--ca",
            "--server-name",
            "--identity",
            "--duplex",
            "--max-packet",
            "--compression",
        ],
        "serve" => vec![
            "--listen",
            "--control-socket",
            "--device",
            "--vxlan-bind",
            "--vxlan-peer",
            "--vni",
            "--layer",
            "--cert",
            "--key",
            "--allow-key",
            "--duplex",
            "--max-packet",
            "--compression",
        ],
        _ => {
            eprintln!("Unknown command. Use --help.");
            return ExitCode::from(2);
        }
    };
    if matches!(command.as_str(), "connect" | "serve") {
        allowed.push("--carrier");
        allowed.push("--quic-application-id");
        allowed.push("--record-profile");
        allowed.push("--aligned-channels");
        allowed.push("--proxy-policy");
        allowed.extend_from_slice(UDP_OPTIONS);
        allowed.extend_from_slice(ACTIVE_OPTIONS);
        allowed.extend_from_slice(standalone::OPTIONS);
        allowed.extend_from_slice(packed_frontend::OPTIONS);
        allowed.extend_from_slice(raw_packet_frontend::OPTIONS);
    }
    let result = options(&args[1..], &allowed).and_then(|options| {
        if command == "keygen" {
            return generate(&options);
        }
        if command == "openvpn-keygen" {
            return standalone::generate(&options);
        }
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async {
                if matches!(
                    command.as_str(),
                    "status"
                        | "set-compression"
                        | "set-active-policy"
                        | "drain-proxy"
                        | "drain-openvpn"
                ) {
                    execute_api(command, &options).await
                } else {
                    execute(command, &options).await
                }
            })
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

    #[test]
    fn carrier_options_reject_downgrades_and_incomplete_profiles() -> io::Result<()> {
        let mut values = BTreeMap::from([
            ("--layer".into(), "tun".into()),
            ("--duplex".into(), "full".into()),
        ]);
        let config = configuration(&values)?;
        assert!(udp_settings(&values, config)?.is_none());
        values.insert("--udp-bind".into(), "127.0.0.1:24440".into());
        assert!(udp_settings(&values, config).is_err());
        values.insert("--carrier".into(), "udp".into());
        values.insert("--udp-peer".into(), "127.0.0.2:24440".into());
        assert!(udp_settings(&values, config).is_err());
        values.insert("--udp-cover".into(), "quic-like".into());
        let settings =
            udp_settings(&values, config)?.ok_or_else(|| input("missing UDP settings"))?;
        assert_eq!(
            settings.protection,
            super::super::udp::Protection::ChaCha20Poly1305
        );
        values.insert("--udp-protection".into(), "integrity".into());
        assert_eq!(
            udp_settings(&values, config)?
                .ok_or_else(|| input("missing UDP settings"))?
                .protection,
            super::super::udp::Protection::HmacSha256
        );
        for (key, value) in [
            ("--carrier", "raw-tcp"),
            ("--carrier", "tcp"),
            ("--udp-cover", "quic"),
            ("--udp-protection", "off"),
            ("--path-mtu", "575"),
            ("--control-socket", "/unused/private.sock"),
            ("--udp-reverse-bind", "127.0.0.1:24441"),
        ] {
            let mut bad = values.clone();
            bad.insert(key.into(), value.into());
            assert!(udp_settings(&bad, config).is_err());
        }
        let half = ConnectionConfig {
            duplex: Duplex::Half,
            ..config
        };
        assert!(udp_settings(&values, half).is_err());
        values.insert("--udp-reverse-bind".into(), "127.0.0.1:24441".into());
        values.insert("--udp-reverse-peer".into(), "127.0.0.2:24441".into());
        assert!(udp_settings(&values, half)?.is_some());
        assert!(udp_settings(&values, config).is_err());
        Ok(())
    }

    #[test]
    fn fec_selection_binds_profile_and_rejects_unused_or_unbounded_knobs() -> io::Result<()> {
        let mut values = BTreeMap::from([
            ("--layer".into(), "tun".into()),
            ("--duplex".into(), "full".into()),
            ("--carrier".into(), "udp".into()),
            ("--udp-cover".into(), "quic-like".into()),
            ("--udp-bind".into(), "127.0.0.1:24440".into()),
            ("--udp-peer".into(), "127.0.0.2:24440".into()),
        ]);
        let config = configuration(&values)?;
        let plain = udp_settings(&values, config)?.ok_or_else(|| input("missing UDP"))?;
        values.insert("--fec-repairs".into(), "2".into());
        assert!(udp_settings(&values, config).is_err());
        values.insert("--fec".into(), "cauchy".into());
        let coded = udp_settings(&values, config)?.ok_or_else(|| input("missing UDP"))?;
        let a = super::super::udp::runtime_config(config, plain)?;
        let b = super::super::udp::runtime_config(config, coded)?;
        assert_ne!(
            l2tunnel_runtime::udp::base_session_config(config.runtime(), a)?,
            l2tunnel_runtime::udp::base_session_config(config.runtime(), b)?
        );
        assert!(b.arq.max_source_bytes < a.arq.max_source_bytes);
        for (key, value) in [
            ("--fec", "unknown"),
            ("--fec-sources", "0"),
            ("--fec-sources", "17"),
            ("--fec-repairs", "0"),
            ("--fec-repairs", "17"),
            ("--fec-flush-ms", "0"),
            ("--fec-flush-ms", "200"),
            ("--fec-sources", "-1"),
            ("--carrier", "tcp"),
        ] {
            let mut bad = values.clone();
            bad.insert(key.into(), value.into());
            assert!(udp_settings(&bad, config).is_err(), "{key}={value}");
        }
        Ok(())
    }

    #[test]
    fn genuine_quic_is_explicit_bound_and_rejects_incompatible_options() -> io::Result<()> {
        let values = BTreeMap::from([
            ("--carrier".into(), "quic".into()),
            ("--layer".into(), "tun".into()),
            ("--duplex".into(), "full".into()),
            ("--udp-bind".into(), "192.0.2.1:24440".into()),
            ("--udp-peer".into(), "192.0.2.2:24440".into()),
            ("--remote".into(), "192.0.2.2:24440".into()),
            (
                "--quic-application-id".into(),
                "7a3820f113c842d6b6ac2784ee890311".into(),
            ),
        ]);
        let config = configuration(&values)?;
        assert!(udp_settings(&values, config)?.is_none());
        let settings = quic_settings(&values, config)?.ok_or_else(|| input("missing QUIC"))?;
        let profile = super::super::quic::runtime_config(config, settings)?;
        let mut changed = settings;
        changed.application_id[0] ^= 1;
        assert_ne!(
            l2tunnel_runtime::quic::base_session_config(config.runtime(), profile)?,
            l2tunnel_runtime::quic::base_session_config(
                config.runtime(),
                super::super::quic::runtime_config(config, changed)?
            )?
        );
        for (key, value) in [
            ("--quic-application-id", ""),
            ("--quic-application-id", "00000000000000000000000000000000"),
            ("--quic-application-id", "gggggggggggggggggggggggggggggggg"),
            ("--quic-application-id", "éééééééééééééééé"),
            ("--remote", "192.0.2.3:24440"),
            ("--listen", "192.0.2.3:24440"),
            ("--path-mtu", "1227"),
            ("--udp-cover", "quic-like"),
            ("--udp-protection", "integrity"),
            ("--control-socket", "/unused"),
            ("--udp-reverse-bind", "192.0.2.1:24441"),
            ("--carrier", "tcp"),
            ("--fec", "unknown"),
        ] {
            let mut bad = values.clone();
            bad.insert(key.into(), value.into());
            assert!(quic_settings(&bad, config).is_err(), "{key}={value}");
        }
        let mut absent = values.clone();
        absent.remove("--quic-application-id");
        assert!(quic_settings(&absent, config).is_err());
        Ok(())
    }

    #[test]
    fn aligned_selection_rejects_implicit_or_incompatible_profiles() -> io::Result<()> {
        let mut values = BTreeMap::from([
            ("--layer".into(), "tap".into()),
            ("--duplex".into(), "full".into()),
            ("--carrier".into(), "udp".into()),
            ("--udp-cover".into(), "quic-like".into()),
            ("--udp-bind".into(), "127.0.0.1:24440".into()),
            ("--udp-peer".into(), "127.0.0.2:24440".into()),
            ("--fec".into(), "cauchy".into()),
        ]);
        let config = configuration(&values)?;
        assert!(aligned_settings(&values, config)?.is_none());
        values.insert("--record-profile".into(), "frame".into());
        assert!(aligned_settings(&values, config)?.is_none());
        values.insert("--aligned-channels".into(), "4".into());
        assert!(aligned_settings(&values, config).is_err());
        values.insert("--record-profile".into(), "aligned".into());
        assert_eq!(
            aligned_settings(&values, config)?.map(|s| s.channels),
            Some(4)
        );
        for (key, value) in [
            ("--record-profile", "packed"),
            ("--carrier", "tcp"),
            ("--fec", "none"),
            ("--fec-repairs", "0"),
            ("--aligned-channels", "0"),
            ("--aligned-channels", "257"),
            ("--aligned-channels", "-1"),
            ("--compression", "lz4"),
            ("--traffic", "active"),
            ("--adaptive", "off"),
            ("--active-policies", "/unused.json"),
            ("--control-socket", "/unused.sock"),
            ("--mux-channels", "4"),
            ("--max-flows", "4"),
            ("--qos-dscp", "46:4"),
            ("--path-mtu", "575"),
        ] {
            let mut bad = values.clone();
            bad.insert(key.into(), value.into());
            assert!(
                aligned_settings(&bad, configuration(&bad)?).is_err(),
                "{key}={value}"
            );
        }
        for key in ["--carrier", "--fec", "--udp-peer", "--udp-cover"] {
            let mut bad = values.clone();
            bad.remove(key);
            assert!(aligned_settings(&bad, config).is_err(), "missing {key}");
        }
        values.remove("--udp-cover");
        values.insert("--carrier".into(), "quic".into());
        values.insert(
            "--quic-application-id".into(),
            "7a3820f113c842d6b6ac2784ee890311".into(),
        );
        assert!(aligned_settings(&values, config)?.is_some());
        values.insert("--aligned-channels".into(), "256".into());
        assert_eq!(
            aligned_settings(&values, config)?.map(|s| s.channels),
            Some(256)
        );
        values.insert("--quic-application-id".into(), "00".repeat(16));
        assert!(aligned_settings(&values, config).is_err());
        Ok(())
    }

    #[test]
    fn active_profile_has_strict_policy_and_no_implicit_fallback() -> io::Result<()> {
        let mut values = BTreeMap::from([("--layer".into(), "tun".into())]);
        let config = configuration(&values)?;
        assert!(active_settings(&values, config)?.is_none());
        values.insert("--qos-dscp".into(), "0:1,46:4".into());
        assert!(active_settings(&values, config).is_err());
        values.insert("--traffic".into(), "active".into());
        let settings = active_settings(&values, config)?.ok_or_else(|| input("missing active"))?;
        assert_eq!(settings.dscp_weights[46], 4);
        assert_eq!(settings.dscp_weights[1], 1);
        let mut idle_values = values.clone();
        idle_values.insert("--flow-idle-ms".into(), "100".into());
        let idle_settings = active_settings(&idle_values, config)?
            .ok_or_else(|| input("missing active idle settings"))?;
        assert_eq!(
            idle_settings.idle_flow_timeout,
            std::time::Duration::from_millis(100)
        );
        assert_ne!(
            l2tunnel_runtime::active::session_config(config.runtime(), settings)?,
            l2tunnel_runtime::active::session_config(config.runtime(), idle_settings)?
        );
        assert_ne!(
            l2tunnel_runtime::active::session_config(config.runtime(), settings)?,
            config.session()?
        );
        let baseline = super::super::active::Settings::new(config.runtime(), config.duplex)?;
        assert_ne!(
            l2tunnel_runtime::active::session_config(config.runtime(), settings)?,
            l2tunnel_runtime::active::session_config(config.runtime(), baseline)?
        );
        for (key, value) in [
            ("--traffic", "proxy"),
            ("--carrier", "udp"),
            ("--control-socket", "/unused"),
            ("--mux-channels", "0"),
            ("--max-flows", "0"),
            ("--adaptive", "true"),
            ("--active-stats-ms", "99"),
            ("--active-stats-ms", "60001"),
            ("--flow-idle-ms", "0"),
            ("--flow-idle-ms", "86400001"),
            ("--flow-idle-ms", "-1"),
            ("--qos-dscp", "46:1,46:2"),
            ("--qos-dscp", "64:1"),
            ("--qos-dscp", "0:0"),
            ("--qos-dscp", ""),
            ("--qos-dscp", "1:2:"),
            ("--qos-dscp", "-1:2"),
        ] {
            let mut bad = values.clone();
            bad.insert(key.into(), value.into());
            assert!(active_settings(&bad, config).is_err(), "{key}={value}");
        }
        assert!(
            active_settings(
                &values,
                ConnectionConfig {
                    layer: PacketLayer::Ethernet,
                    ..config
                }
            )
            .is_err()
        );
        values.insert("--active-policies".into(), "/unused/catalog.json".into());
        values.insert("--control-socket".into(), "/unused/private.sock".into());
        assert!(active_settings(&values, config)?.is_some());
        values.insert("--traffic".into(), "system".into());
        assert!(active_settings(&values, config).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn active_local_requests_wait_for_runtime_and_report_closed_or_busy() {
        use super::super::local::{Action, Request, VERSION};
        let (handle, receiver) = l2tunnel_runtime::active_management::channel();
        let valid = super::super::active_managed::Policy {
            channels: 2,
            dscp_weights: vec![1; 64],
        };
        for (action, code) in [
            (Action::DrainProxy {}, "unsupported"),
            (Action::DrainOpenVpn {}, "unsupported"),
            (
                Action::SwitchCompression {
                    compression: super::super::local::Compression::Off,
                },
                "unsupported",
            ),
            (
                Action::SwitchActivePolicy {
                    policy: super::super::active_managed::Policy {
                        channels: 0,
                        ..valid.clone()
                    },
                },
                "invalid_policy",
            ),
        ] {
            let response = active_local_action(
                handle.clone(),
                Compression::None,
                Request {
                    version: VERSION,
                    action,
                },
            )
            .await;
            assert!(!response.ok);
            assert_eq!(response.code, code);
            assert!(response.state.is_none());
        }
        let request = Request {
            version: VERSION,
            action: Action::SwitchActivePolicy { policy: valid },
        };
        let mut pending = Box::pin(active_local_action(
            handle.clone(),
            Compression::None,
            request.clone(),
        ));
        // Poll exactly once: enqueueing a request is never a successful switch.
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let busy = active_local_action(handle, Compression::None, request).await;
        assert!(!busy.ok);
        assert_eq!(busy.code, "busy");
        drop(receiver);
        let closed = pending.await;
        assert!(!closed.ok);
        assert_eq!(closed.code, "closed");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_profile_rejects_proxy_drain_without_submission() {
        use crate::local::{Action, Request, VERSION};
        let (handle, _control) = l2tunnel_runtime::managed::channel();
        for action in [Action::DrainProxy {}, Action::DrainOpenVpn {}] {
            let response = local_action(
                handle.clone(),
                Request {
                    version: VERSION,
                    action,
                },
            )
            .await;
            assert!(!response.ok);
            assert_eq!(response.code, "unsupported");
        }
    }
}
