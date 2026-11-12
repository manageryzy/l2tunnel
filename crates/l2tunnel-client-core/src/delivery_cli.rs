//! Explicit bandwidth-delay policy; local queues remain independent.
use super::{BTreeMap, ConnectionConfig, input, io, number};
use l2tunnel_flow_control::delivery_window;
use l2tunnel_runtime::managed::DeliveryConfig;

pub(super) const OPTIONS: &[&str] = &[
    "--delivery-window",
    "--forward-mbps",
    "--reverse-mbps",
    "--bootstrap-rtt-ms",
    "--bdp-headroom-percent",
    "--inflight-max-bytes",
    "--inflight-max-records",
];
pub(super) const HELP: &str = "Delivery window: --delivery-window bdp selects byte-based bandwidth x observed delivery-feedback RTT over system TCP/TLS frame or UDP/QUIC aligned/packed records. Aligned/packed require this policy. Requires --forward-mbps N --reverse-mbps N --bootstrap-rtt-ms N on both peers (same canonical directions). Optional --bdp-headroom-percent 100..400 (default125), --inflight-max-bytes (default4MiB,maximum64MiB), --inflight-max-records (default8192). Local queue stays64packets. TCP/TLS frame legacy/default remains available for measured comparisons; this does not control endpoint TCP cwnd.";

pub(super) fn required_settings(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<DeliveryConfig> {
    settings(options, config)?.ok_or_else(|| {
        input("aligned/packed require explicit --delivery-window bdp and bandwidth/RTT parameters")
    })
}

pub(super) fn settings(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<DeliveryConfig>> {
    match options.get("--delivery-window").map(String::as_str) {
        None | Some("legacy") => {
            if OPTIONS[1..].iter().any(|key| options.contains_key(*key)) {
                return Err(input("delivery parameters require --delivery-window bdp"));
            }
            return Ok(None);
        }
        Some("bdp") => {}
        _ => return Err(input("delivery-window must be legacy or bdp")),
    }
    let carrier = options.get("--carrier").map_or("tcp", String::as_str);
    let profile = options
        .get("--record-profile")
        .map_or("frame", String::as_str);
    if !matches!(
        (carrier, profile),
        ("tcp", "frame") | ("udp" | "quic", "aligned" | "packed")
    ) || options
        .get("--traffic")
        .is_some_and(|value| value != "system")
    {
        return Err(input(
            "BDP delivery window requires system TCP/TLS frame or UDP/QUIC aligned/packed records",
        ));
    }
    for key in ["--forward-mbps", "--reverse-mbps", "--bootstrap-rtt-ms"] {
        super::required(options, key)?;
    }
    let bootstrap: u64 = number(options, "--bootstrap-rtt-ms", 0)?;
    let bootstrap = bootstrap
        .checked_mul(1000)
        .ok_or_else(|| input("RTT overflow"))?;
    let direction = |key| -> io::Result<delivery_window::Config> {
        let mbps: u64 = number(options, key, 0)?;
        Ok(delivery_window::Config {
            target_bandwidth_bps: mbps
                .checked_mul(1_000_000)
                .ok_or_else(|| input("bandwidth overflow"))?,
            bootstrap_rtt_micros: bootstrap,
            min_rtt_micros: 1000,
            max_rtt_micros: 2_000_000,
            headroom_percent: number(options, "--bdp-headroom-percent", 125)?,
            minimum_bytes: (config.max_packet as u64)
                .checked_mul(2)
                .ok_or_else(|| input("packet budget overflow"))?,
            max_inflight_bytes: number(options, "--inflight-max-bytes", 4 * 1024 * 1024)?,
            max_records: number(options, "--inflight-max-records", 8192)?,
            max_packet_bytes: config.max_packet as u64,
            metadata_limit_bytes: 2 * 1024 * 1024,
            sample_ttl_micros: 4_000_000,
            flush_timeout_micros: 10_000_000,
        })
    };
    let selected = DeliveryConfig {
        forward: direction("--forward-mbps")?,
        reverse: direction("--reverse-mbps")?,
    };
    config.session_with_delivery(selected)?;
    Ok(Some(selected))
}

#[cfg(target_os = "linux")]
pub(super) fn report(delivery: DeliveryConfig) {
    println!(
        "Delivery: BDP; forward {} bps; reverse {} bps; bootstrap {} us; cap {} bytes/{} records; local queue 64 packets",
        delivery.forward.target_bandwidth_bps,
        delivery.reverse.target_bandwidth_bps,
        delivery.forward.bootstrap_rtt_micros,
        delivery.forward.max_inflight_bytes,
        delivery.forward.max_records,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_policy_is_explicit_canonical_and_bounded_before_io() -> io::Result<()> {
        let config = ConnectionConfig {
            layer: l2tunnel_device::PacketLayer::Ip,
            duplex: l2tunnel_core::Duplex::Half,
            max_packet: 1600,
            compression: l2tunnel_codec::Compression::None,
            handshake_timeout: std::time::Duration::from_secs(10),
        };
        let mut options = BTreeMap::new();
        assert!(settings(&options, config)?.is_none());
        options.insert("--forward-mbps".into(), "100".into());
        assert!(settings(&options, config).is_err());
        options.insert("--delivery-window".into(), "bdp".into());
        assert!(settings(&options, config).is_err());
        options.insert("--reverse-mbps".into(), "10".into());
        options.insert("--bootstrap-rtt-ms".into(), "70".into());
        let selected = settings(&options, config)?.ok_or_else(|| input("missing policy"))?;
        assert_eq!(selected.forward.target_bandwidth_bps, 100_000_000);
        assert_eq!(selected.reverse.target_bandwidth_bps, 10_000_000);
        assert_eq!(config.runtime().queue_packets, 64);
        for carrier in ["udp", "quic"] {
            for profile in ["aligned", "packed"] {
                let mut explicit = options.clone();
                explicit.insert("--carrier".into(), carrier.into());
                explicit.insert("--record-profile".into(), profile.into());
                assert_eq!(required_settings(&explicit, config)?, selected);
                explicit.remove("--delivery-window");
                assert!(required_settings(&explicit, config).is_err());
                explicit.insert("--delivery-window".into(), "legacy".into());
                assert!(required_settings(&explicit, config).is_err());
            }
        }
        for (key, value) in [
            ("--carrier", "udp"),
            ("--traffic", "active"),
            ("--inflight-max-records", "8193"),
            ("--inflight-max-bytes", "67108865"),
            ("--bdp-headroom-percent", "99"),
            ("--forward-mbps", "18446744073709551615"),
        ] {
            let mut bad = options.clone();
            bad.insert(key.into(), value.into());
            assert!(settings(&bad, config).is_err());
        }
        Ok(())
    }
}
