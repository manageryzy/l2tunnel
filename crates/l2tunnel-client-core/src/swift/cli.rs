//! Explicit startup-only swift selection for the shared CLI.
use super::*;
use crate::swift as client;
pub(super) const OPTIONS: &[&str] = &[
    "--swift-forward-kbit",
    "--swift-reverse-kbit",
    "--swift-channels",
    "--swift-window",
    "--swift-repair-permille",
    "--swift-report-ms",
];
pub(super) const HELP: &str = "Swift stream: --record-profile swift --carrier udp --duplex full --udp-bind IP:PORT --udp-peer IP:PORT --swift-forward-kbit N --swift-reverse-kbit N with a native TAP/TUN --device. Budgets are IP kilobits per second, client-to-server then server-to-client, 64..10000000, and both peers must state both. Optional --path-mtu 576..9000 (default 1500), --swift-channels 1..64 (default 16), --swift-window 1..255 (default 64), --swift-repair-permille 0..1000 (default 0, retransmission only), --swift-report-ms 0|100..60000 (default 0, off). TCP/TLS authenticates and stays open as liveness; data uses paced ChaCha20-Poly1305 UDP with packed sources and requested retransmission, optionally sliding-window repairs. Connections are spread over the channels and each channel delivers in order. Predictable TCP/IPv4 headers are replaced by exact delta records. No compression, VXLAN, lanes, control socket or hot switching.";
pub(super) fn selection(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<client::Settings>> {
    if options.get("--record-profile").map(String::as_str) != Some("swift") {
        if OPTIONS.iter().any(|key| options.contains_key(*key)) {
            return Err(input("swift options require --record-profile swift"));
        }
        return Ok(None);
    }
    let allowed = [
        "--record-profile",
        "--carrier",
        "--udp-bind",
        "--udp-peer",
        "--path-mtu",
        "--remote",
        "--listen",
        "--device",
        "--layer",
        "--ca",
        "--server-name",
        "--identity",
        "--cert",
        "--key",
        "--allow-key",
        "--duplex",
        "--max-packet",
        "--compression",
    ];
    if options.get("--carrier").map(String::as_str) != Some("udp")
        || options
            .keys()
            .any(|key| !allowed.contains(&key.as_str()) && !OPTIONS.contains(&key.as_str()))
    {
        return Err(input(
            "swift requires explicit --carrier udp and accepts only its documented options",
        ));
    }
    let address = |key| {
        required(options, key)?
            .parse::<SocketAddr>()
            .map_err(|_| input(format!("{key} requires IP:PORT")))
    };
    let rate = |key| {
        required(options, key)?
            .parse::<u64>()
            .map_err(|_| input(format!("invalid {key}")))
    };
    let report = match number::<u64>(options, "--swift-report-ms", 0)? {
        0 => None,
        value @ 100..=60_000 => Some(Duration::from_millis(value)),
        _ => return Err(input("swift report interval must be 0 or 100..60000 ms")),
    };
    let settings = client::Settings {
        local: address("--udp-bind")?,
        peer: address("--udp-peer")?,
        path_mtu: number(options, "--path-mtu", 1500)?,
        forward_kbit: rate("--swift-forward-kbit")?,
        reverse_kbit: rate("--swift-reverse-kbit")?,
        channels: number(options, "--swift-channels", 16)?,
        window: number(options, "--swift-window", 64)?,
        repair_permille: number(options, "--swift-repair-permille", 0)?,
        report,
    };
    // Validate the complete policy before credential files or sockets.
    settings.session(config)?;
    Ok(Some(settings))
}
fn line(event: &str, snapshot: &client::Snapshot) -> String {
    serde_json::json!({
        "event": event,
        "elapsed_us": snapshot.elapsed_micros,
        "sources": snapshot.sender.sources,
        "repairs": snapshot.sender.repairs,
        "tail_repairs": snapshot.sender.tail_repairs,
        "retransmits": snapshot.sender.retransmits,
        "packed_bytes": snapshot.sender.packed_bytes,
        "rtt_us": snapshot.sender.smoothed_rtt_micros,
        "datagrams_sent": snapshot.datagrams_sent,
        "ip_bytes_sent": snapshot.ip_bytes_sent,
        "socket_drops": snapshot.socket_drops,
        "native_read": snapshot.native_read,
        "native_dropped": snapshot.native_dropped,
        "datagrams_received": snapshot.datagrams_received,
        "datagrams_rejected": snapshot.datagrams_rejected,
        "received_sources": snapshot.receiver.sources,
        "recovered": snapshot.receiver.recovered,
        "useful_repairs": snapshot.receiver.useful_repairs,
        "useless_repairs": snapshot.receiver.useless_repairs,
        "duplicates": snapshot.receiver.duplicates,
        "feedback": snapshot.receiver.feedback,
        "native_written": snapshot.native_written,
        "native_write_drops": snapshot.native_write_drops,
        "header_bytes_saved": snapshot.header_bytes_saved,
    })
    .to_string()
}
#[cfg(target_os = "linux")]
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    settings: client::Settings,
) -> io::Result<()> {
    let name = required(options, "--device")?;
    let session = match command {
        "connect" => {
            let address = required(options, "--remote")?
                .parse()
                .map_err(|_| input("remote requires IP:PORT"))?;
            let roots = vec![bounded_file(required(options, "--ca")?, 65536)?];
            let member =
                MemberKey::from_pkcs8(&bounded_file(required(options, "--identity")?, 4096)?)
                    .map_err(auth_error)?;
            let tls = ClientTls::from_der_roots(&roots).map_err(auth_error)?;
            let server = required(options, "--server-name")?;
            client::connect(address, &tls, server, &member, config, settings).await?
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
            let tls = ServerTls::from_der(&chain, &key).map_err(auth_error)?;
            let listener = TcpListener::bind(address).await?;
            client::accept(&listener, &tls, &allow, config, settings).await?
        }
        _ => return Err(input("unsupported swift command")),
    };
    let device = l2tunnel_platform_linux::TunTap::attach(name, config.layer)?;
    let effective = session.config();
    println!(
        "{}",
        serde_json::json!({
            "event": "swift_authenticated",
            "datagram_bytes": effective.codec.datagram_bytes,
            "symbol_bytes": effective.codec.symbol_bytes(),
            "channels": effective.channels,
            "window": effective.codec.window,
            "repair_permille": effective.codec.repair_numerator,
            "send_bytes_per_second": effective.send_bytes_per_second,
            "receive_buffer_bytes": session.receive_buffer()?,
        })
    );
    session
        .run(device, |snapshot| {
            println!("{}", line("swift_report", snapshot))
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options() -> BTreeMap<String, String> {
        [
            ("--layer", "tap"),
            ("--duplex", "full"),
            ("--carrier", "udp"),
            ("--record-profile", "swift"),
            ("--udp-bind", "127.0.0.1:24000"),
            ("--udp-peer", "127.0.0.1:24001"),
            ("--swift-forward-kbit", "100000"),
            ("--swift-reverse-kbit", "10000"),
            ("--device", "tap0"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect()
    }
    #[test]
    fn swift_cli_requires_exact_explicit_selection_and_leaves_defaults() -> io::Result<()> {
        let valid = options();
        let config = configuration(&valid)?;
        let settings = selection(&valid, config)?.ok_or_else(|| input("not selected"))?;
        assert_eq!((settings.window, settings.repair_permille), (64, 0));
        assert_eq!(settings.channels, 16);
        assert_eq!(settings.path_mtu, 1500);
        assert_eq!(settings.report, None);
        for (key, value) in [
            ("--carrier", "tcp"),
            ("--carrier", "quic"),
            ("--duplex", "half"),
            ("--compression", "lz4"),
            ("--fec", "cauchy"),
            ("--traffic", "active"),
            ("--control-socket", "/unused/private.sock"),
            ("--vni", "7"),
            ("--udp-cover", "quic-like"),
            ("--swift-forward-kbit", "1"),
            ("--swift-reverse-kbit", "x"),
            ("--swift-window", "0"),
            ("--swift-channels", "0"),
            ("--swift-channels", "65"),
            ("--swift-repair-permille", "1001"),
            ("--swift-report-ms", "5"),
            ("--path-mtu", "100"),
            ("--udp-peer", "[::1]:9"),
        ] {
            let mut bad = valid.clone();
            bad.insert(key.into(), value.into());
            let config = configuration(&bad)?;
            assert!(selection(&bad, config).is_err(), "{key} {value}");
        }
        for key in [
            "--udp-bind",
            "--udp-peer",
            "--swift-forward-kbit",
            "--swift-reverse-kbit",
        ] {
            let mut bad = valid.clone();
            bad.remove(key);
            assert!(selection(&bad, config).is_err(), "{key}");
        }
        // Without the profile nothing is selected and stray options are refused.
        let mut other = valid.clone();
        other.remove("--record-profile");
        assert!(selection(&other, config).is_err());
        for key in OPTIONS {
            other.remove(*key);
        }
        assert_eq!(selection(&other, config)?, None);
        Ok(())
    }
    #[test]
    fn report_line_is_one_json_object_with_stable_fields() -> io::Result<()> {
        let text = line("swift_report", &client::Snapshot::default());
        let value: serde_json::Value = serde_json::from_str(&text).map_err(io::Error::other)?;
        assert_eq!(value["event"], "swift_report");
        for field in ["sources", "ip_bytes_sent", "recovered", "native_written"] {
            assert_eq!(value[field], 0, "{field}");
        }
        assert!(!text.contains('\n'));
        Ok(())
    }
}
