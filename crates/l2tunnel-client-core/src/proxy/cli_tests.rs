use super::*;

fn base() -> BTreeMap<String, String> {
    [
        ("--traffic", "proxy"),
        ("--proxy-policy", "/missing/policy"),
        ("--device", "tun0"),
        ("--layer", "tun"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}
#[test]
fn explicit_proxy_selection_rejects_all_ignored_or_conflicting_options_before_io() -> io::Result<()>
{
    let options = base();
    let config = configuration(&options)?;
    assert_eq!(selection(&options, config)?, Some("/missing/policy"));
    for key in UDP_OPTIONS
        .iter()
        .chain(&ACTIVE_OPTIONS[1..])
        .chain(standalone::OPTIONS)
        .chain(
            [
                "--aligned-channels",
                "--quic-application-id",
                "--vxlan-bind",
                "--vxlan-peer",
                "--vni",
            ]
            .iter(),
        )
    {
        let mut bad = options.clone();
        bad.insert((*key).into(), "unused".into());
        assert!(selection(&bad, config).is_err(), "accepted ignored {key}");
    }
    for (key, value) in [
        ("--carrier", "udp"),
        ("--carrier", "quic"),
        ("--carrier", "openvpn-like"),
        ("--record-profile", "aligned"),
        ("--traffic", "active"),
        ("--traffic", "system"),
    ] {
        let mut bad = options.clone();
        bad.insert(key.into(), value.into());
        assert!(selection(&bad, config).is_err());
    }
    for (key, value) in [
        ("--layer", "tap"),
        ("--compression", "lz4"),
        ("--max-packet", "100"),
    ] {
        let mut bad = options.clone();
        bad.insert(key.into(), value.into());
        assert!(selection(&bad, configuration(&bad)?).is_err());
    }
    let mut missing = options.clone();
    missing.remove("--proxy-policy");
    assert!(selection(&missing, config).is_err());
    let mut plain = options;
    plain.remove("--traffic");
    plain.remove("--proxy-policy");
    assert!(selection(&plain, config)?.is_none());
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn incompatible_proxy_cli_never_reads_missing_policy_or_identity() -> io::Result<()> {
    let mut options = base();
    options.insert("--carrier".into(), "quic".into());
    let result = super::super::execute("connect", &options).await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    Ok(())
}

#[test]
fn measured_selection_is_explicit_and_rejects_conflicts_before_io() -> io::Result<()> {
    let mut values = base();
    values.insert("--traffic".into(), "proxy-measured".into());
    let config = configuration(&values)?;
    assert!(selection(&values, config)?.is_some());
    for key in UDP_OPTIONS
        .iter()
        .chain(&ACTIVE_OPTIONS[1..])
        .chain(standalone::OPTIONS)
        .chain(packed_frontend::OPTIONS)
    {
        let mut bad = values.clone();
        bad.insert((*key).into(), "unused".into());
        assert!(selection(&bad, config).is_err(), "accepted {key}");
    }
    for (key, value) in [
        ("--carrier", "raw-tcp"),
        ("--carrier", "quic"),
        ("--carrier", "udp"),
        ("--record-profile", "packed"),
        ("--record-profile", "aligned"),
    ] {
        let mut bad = values.clone();
        bad.insert(key.into(), value.into());
        assert!(selection(&bad, config).is_err());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn incompatible_measured_cli_fails_before_any_external_io() -> io::Result<()> {
    for (key, value) in [
        ("--carrier", "udp"),
        ("--compression", "lz4"),
        ("--layer", "tap"),
        ("--adaptive", "on"),
        ("--record-profile", "packed"),
        ("--packed-channels", "4"),
    ] {
        let mut values = base();
        values.insert("--traffic".into(), "proxy-measured".into());
        values.insert(key.into(), value.into());
        let result = super::super::execute("connect", &values).await;
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput),
            "{key}"
        );
    }
    Ok(())
}
