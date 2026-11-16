//! Explicit measured selection consumes the maintained complete policy, never fixed fallback.
use super::*;
fn document() -> Value {
    json!({
        "version":1,"profile":"measured-relay-v1",
        "fixed":{"version":1,"channels":1,"time_wait_reset":"maintained","routes":[]},
        "allocation":{"target":{
            "initial":{"bytes":32768,"records":32},"minimum":{"bytes":2048,"records":1},
            "session_cap":{"bytes":1048576,"records":1024},"per_flow_cap":{"bytes":65536,"records":64},
            "policy_cap":{"bytes":1048576,"records":1024},"queue_allowance_bytes":65536,
            "queue_delay_target_micros":5000,"many_flow_step":{"bytes":2048,"records":1},
            "few_flow_threshold":4,"max_flows":16,"bootstrap_rtt_micros":1000,"recovery_rtts":2
        },"minimum_per_flow":{"bytes":2048,"records":1}},
        "ownership":{"pending_ttl_micros":20000,"probe_interval_micros":10000,"probe_timeout_micros":30000,
            "handoff_timeout_micros":50000,"emission_interval_micros":10000,"max_records_per_interval":8},
        "observation":{"report_interval_micros":10000,"sample_ttl_micros":40000,"demand_idle_micros":20000,
            "rate_interval_micros":10000,"rate_bins":4},
        "service":{"report_work_per_turn":4,"admission_work_per_turn":4,"callback_work_per_turn":4,
            "plan_interval_micros":10000,"status_interval_micros":20000}
    })
}
#[test]
fn measured_common_requires_retained_before_files_and_preserves_complete_policy() -> io::Result<()>
{
    let missing = Path::new("/not-read/measured-common");
    let mut selected = options(missing, missing);
    selected.insert("--traffic".into(), "proxy-measured".into());
    let connection = configuration(&selected)?;
    assert!(selection(&selected, connection, true, Carrier::OriginalUdp).is_err());
    assert_eq!(
        super::super::super::selection_for("connect", &selected, connection, true)
            .err()
            .map(|value| value.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    selected.insert("--proxy-close".into(), "retained".into());
    assert!(selection(
        &selected,
        connection,
        true,
        Carrier::OriginalUdp
    )?);
    for carrier in [Carrier::OpenVpn, Carrier::RawPacket] {
        assert!(selection(&selected, connection, true, carrier).is_err());
    }
    let mut half = connection;
    half.duplex = Duplex::Half;
    assert!(selection(&selected, half, true, Carrier::OriginalUdp).is_err());
    let mut wrong = selected.clone();
    wrong.insert("--proxy-close".into(), "legacy".into());
    assert!(selection(&wrong, connection, true, Carrier::OriginalUdp).is_err());
    let policy = document();
    let file = Temporary::new(&serde_json::to_vec(&policy).map_err(io::Error::other)?)?;
    selected.insert(
        "--proxy-policy".into(),
        file.path().to_string_lossy().into_owned(),
    );
    let Policy::Measured(measured_settings) = settings(&selected, connection)? else {
        return Err(input("measured policy became fixed"));
    };
    let actual = crate::proxy_measured::runtime_config(connection, &measured_settings)?;
    let expected = json!({"allocation":policy["allocation"],"ownership":policy["ownership"],"observation":policy["observation"],"service":policy["service"]});
    assert_eq!(measurement_policy(&actual), expected);
    assert_eq!(actual.fixed.mux.channels, 1);
    let mut invalid = policy.clone();
    invalid["ownership"]["silent_default"] = json!(1);
    let bad = Temporary::new(&serde_json::to_vec(&invalid).map_err(io::Error::other)?)?;
    selected.insert(
        "--proxy-policy".into(),
        bad.path().to_string_lossy().into_owned(),
    );
    assert!(settings(&selected, connection).is_err());
    selected.insert(
        "--proxy-policy".into(),
        file.path().to_string_lossy().into_owned(),
    );
    selected.insert("--traffic".into(), "proxy".into());
    assert!(
        settings(&selected, connection).is_err(),
        "measured JSON must not enter fixed parser"
    );
    Ok(())
}
