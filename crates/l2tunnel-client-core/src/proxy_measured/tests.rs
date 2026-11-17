use super::*;
use crate::{Compression, PacketLayer};
use l2tunnel_auth as auth;
use l2tunnel_core::Duplex;
use std::time::Duration;
type Failure = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), Failure>;
fn connection(duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    }
}
fn settings() -> io::Result<Settings> {
    Settings::from_json(&serde_json::to_vec(&policy_json())?)
}
fn policy_json() -> serde_json::Value {
    serde_json::json!({
        "version":1,"profile":"measured-relay-v1",
        "fixed":{"version":1,"channels":16,"time_wait_reset":"maintained","routes":[]},
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
fn strict_measured_policy_requires_and_bounds_every_nested_field() -> TestResult {
    fn visit(
        value: &serde_json::Value,
        root: &serde_json::Value,
        path: &mut Vec<String>,
    ) -> TestResult {
        if let Some(object) = value.as_object() {
            for key in object.keys() {
                let mut changed = root.clone();
                let mut parent = &mut changed;
                for part in path.iter() {
                    parent = &mut parent[part];
                }
                parent.as_object_mut().ok_or("object")?.remove(key);
                assert!(
                    Settings::from_json(&serde_json::to_vec(&changed)?).is_err(),
                    "missing {path:?}/{key}"
                );
            }
            let original = serde_json::to_string(value)?;
            let first = object.iter().next().ok_or("empty object")?;
            let duplicate = format!(
                "{{{}:{},{}",
                serde_json::to_string(first.0)?,
                serde_json::to_string(first.1)?,
                &original[1..]
            );
            let unknown = format!("{{\"unexpected\":0,{}", &original[1..]);
            for replacement in [duplicate, unknown] {
                let text = serde_json::to_string(root)?.replacen(&original, &replacement, 1);
                assert!(
                    Settings::from_json(text.as_bytes()).is_err(),
                    "accepted duplicate/unknown at {path:?}"
                );
            }
            for (key, child) in object {
                path.push(key.clone());
                visit(child, root, path)?;
                path.pop();
            }
        } else if value.is_number() {
            for bad in [
                serde_json::json!(-1),
                serde_json::json!(1.5),
                serde_json::json!("18446744073709551616"),
            ] {
                let mut changed = root.clone();
                let mut slot = &mut changed;
                for part in path.iter() {
                    slot = &mut slot[part];
                }
                *slot = bad;
                assert!(
                    Settings::from_json(&serde_json::to_vec(&changed)?).is_err(),
                    "numeric {path:?}"
                );
            }
        }
        Ok(())
    }
    let root = policy_json();
    visit(&root, &root, &mut Vec::new())?;
    let mut bytes = serde_json::to_vec(&root)?;
    bytes.resize(MAX_POLICY_BYTES, b' ');
    Settings::from_json(&bytes)?;
    bytes.push(b' ');
    assert!(Settings::from_json(&bytes).is_err());
    let mut routes = root;
    routes["fixed"]["routes"] = serde_json::json!(vec![
        serde_json::json!({"source":"10.0.0.0/24","destination":"10.1.0.0/24","ports":{"first":443,"last":443}});
        257
    ]);
    assert!(Settings::from_json(&serde_json::to_vec(&routes)?).is_err());
    Ok(())
}

#[test]
fn every_numeric_measured_policy_field_is_validated_or_authenticated() -> TestResult {
    fn visit(
        value: &serde_json::Value,
        root: &serde_json::Value,
        path: &mut Vec<String>,
        binding: auth::SessionConfig,
    ) -> TestResult {
        if let Some(object) = value.as_object() {
            for (key, child) in object {
                path.push(key.clone());
                visit(child, root, path, binding)?;
                path.pop();
            }
        } else if let Some(number) = value.as_u64() {
            let mut changed = root.clone();
            let mut slot = &mut changed;
            for part in path.iter() {
                slot = &mut slot[part];
            }
            *slot = serde_json::json!(number + 1);
            if let Ok(settings) = Settings::from_json(&serde_json::to_vec(&changed)?)
                && let Ok(config) = runtime_config(connection(Duplex::Full), &settings)
            {
                assert_ne!(
                    binding,
                    runtime::session_config(&config)?,
                    "unbound {path:?}"
                );
            }
        }
        Ok(())
    }
    let root = policy_json();
    let binding =
        runtime::session_config(&runtime_config(connection(Duplex::Full), &settings()?)?)?;
    visit(&root, &root, &mut Vec::new(), binding)
}
