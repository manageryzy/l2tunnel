//! Strict opt-in packed profile; all geometry is derived by the shared client API.
use super::*;

pub(super) const OPTIONS: &[&str] = &[
    "--packed-channels",
    "--packed-hold-micros",
    "--packed-max-units",
    "--packed-work-limit",
];
pub(super) const HELP: &str = "Packed records: --record-profile packed; explicit --carrier udp|quic, --fec cauchy, --compression off and system traffic. --packed-channels 1..255 (default 4), --packed-hold-micros 1..1000 (default 1000), --packed-max-units 1..255 (default 4, further bounded by MTU), --packed-work-limit 1..255 (default 16). Requires explicit --delivery-window bdp with canonical forward/reverse bandwidth and bootstrap RTT. Requires matching peer settings; no local reload or active/proxy composition. All packets share the common channel pool.";

pub(super) fn settings(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<crate::packed::Settings>> {
    if options.get("--record-profile").map(String::as_str) != Some("packed") {
        if OPTIONS.iter().any(|key| options.contains_key(*key)) {
            return Err(input("packed options require --record-profile packed"));
        }
        return Ok(None);
    }
    if !matches!(
        options.get("--carrier").map(String::as_str),
        Some("udp" | "quic")
    ) || options.get("--fec").map(String::as_str) != Some("cauchy")
        || options.get("--traffic").is_some_and(|v| v != "system")
        || options.contains_key("--control-socket")
        || options.contains_key("--aligned-channels")
        || ACTIVE_OPTIONS[1..]
            .iter()
            .any(|key| options.contains_key(*key))
    {
        return Err(input(
            "packed requires explicit UDP/QUIC, Cauchy, system traffic and no control/active/aligned options",
        ));
    }
    let settings = crate::packed::Settings {
        channels: number(options, "--packed-channels", 4)?,
        delivery: delivery_frontend::required_settings(options, config)?,
        packing: l2tunnel_runtime::packed::Options {
            hold_micros: number(options, "--packed-hold-micros", 1000)?,
            max_units: number(options, "--packed-max-units", 4)?,
            work_limit: number(options, "--packed-work-limit", 16)?,
        },
    };
    settings.validate(config, recovery_settings(options)?)?;
    if let Some(transport) = udp_settings(options, config)? {
        crate::packed::udp_config(config, transport, settings)?;
    }
    if let Some(transport) = quic_settings(options, config)? {
        crate::packed::quic_config(config, transport, settings)?;
    }
    Ok(Some(settings))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn values() -> BTreeMap<String, String> {
        [
            ("--layer", "tun"),
            ("--duplex", "full"),
            ("--carrier", "udp"),
            ("--udp-bind", "127.0.0.1:2001"),
            ("--udp-peer", "127.0.0.1:2002"),
            ("--udp-cover", "quic-like"),
            ("--fec", "cauchy"),
            ("--compression", "off"),
            ("--record-profile", "packed"),
            ("--delivery-window", "bdp"),
            ("--forward-mbps", "100"),
            ("--reverse-mbps", "10"),
            ("--bootstrap-rtt-ms", "70"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }
    #[test]
    fn packed_cli_is_explicit_strict_and_preserves_other_record_defaults() -> io::Result<()> {
        let values = values();
        let config = configuration(&values)?;
        let selected =
            settings(&values, config)?.ok_or_else(|| input("missing packed selection"))?;
        assert_eq!(selected.channels, 4);
        assert_eq!(
            selected.packing,
            l2tunnel_runtime::packed::Options {
                hold_micros: 1000,
                max_units: 4,
                work_limit: 16
            }
        );
        assert!(aligned_settings(&values, config)?.is_none());
        for (key, value) in [
            ("--packed-channels", "0"),
            ("--packed-channels", "256"),
            ("--packed-channels", "-1"),
            ("--packed-hold-micros", "0"),
            ("--packed-hold-micros", "1001"),
            ("--packed-max-units", "0"),
            ("--packed-max-units", "255"),
            ("--packed-max-units", "256"),
            ("--packed-work-limit", "0"),
            ("--packed-work-limit", "256"),
            ("--aligned-channels", "4"),
            ("--carrier", "tcp"),
            ("--carrier", "openvpn-like"),
            ("--fec", "none"),
            ("--compression", "lz4"),
            ("--traffic", "proxy"),
            ("--traffic", "active"),
            ("--adaptive", "on"),
            ("--control-socket", "/unused-packed-test.sock"),
            ("--path-mtu", "575"),
        ] {
            let mut bad = values.clone();
            bad.insert(key.into(), value.into());
            assert!(
                settings(&bad, configuration(&bad)?).is_err(),
                "accepted {key}={value}"
            );
        }
        for key in [
            "--carrier",
            "--fec",
            "--delivery-window",
            "--forward-mbps",
            "--reverse-mbps",
            "--bootstrap-rtt-ms",
        ] {
            let mut bad = values.clone();
            bad.remove(key);
            assert!(settings(&bad, config).is_err());
        }
        for profile in [None, Some("frame"), Some("aligned")] {
            let mut ordinary = values.clone();
            ordinary.remove("--record-profile");
            if let Some(profile) = profile {
                ordinary.insert("--record-profile".into(), profile.into());
            }
            assert!(settings(&ordinary, config)?.is_none());
            for key in OPTIONS {
                let mut bad = ordinary.clone();
                bad.insert((*key).into(), "1".into());
                assert!(settings(&bad, config).is_err());
            }
        }
        let mut quic = values.clone();
        quic.insert("--carrier".into(), "quic".into());
        quic.remove("--udp-cover");
        quic.insert(
            "--quic-application-id".into(),
            "00112233445566778899aabbccddeeff".into(),
        );
        assert!(settings(&quic, config)?.is_some());
        Ok(())
    }
    #[tokio::test]
    async fn incompatible_profiles_fail_before_credentials_devices_or_local_api() -> io::Result<()>
    {
        for (key, value) in [
            ("--carrier", "tcp"),
            ("--carrier", "openvpn-like"),
            ("--traffic", "proxy"),
            ("--control-socket", "/unused-packed-test.sock"),
        ] {
            let mut options = values();
            options.insert(key.into(), value.into());
            let error = execute("connect", &options)
                .await
                .err()
                .ok_or_else(|| input("invalid selection succeeded"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("packed"), "{error}");
        }
        Ok(())
    }
}
