//! Redacted diagnostic export (CL-16, DGUI-12), shared by the CLI and GUI.
//! The report is assembled from read-only version-5 queries: status, service
//! info, metrics, devices, routes, the retained event log and the results of
//! the operations those events name. No reply carries private keys, tokens or
//! user payload. Outer and inner IP addresses are replaced by `redacted`
//! unless the caller explicitly includes them. The file is written to an
//! explicit destination that must not exist yet, readable by its owner only.
use super::{
    EVENTS_LIMIT, EventBody, OperationAction, OperationReply, OperationRequest, ServiceId,
};
use serde_json::{Map, Value, json};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

/// Report format identifier.
pub const FORMAT: &str = "l2tunnel-diagnostics";
/// Report format version.
pub const FORMAT_VERSION: u16 = 1;
/// Most events copied from the service log (its ring holds 256).
pub const EVENT_LIMIT: usize = 256;
/// Most completed operations whose results are included.
pub const OPERATION_LIMIT: usize = 16;

async fn query(path: &Path, action: OperationAction) -> io::Result<OperationReply> {
    super::request_operation(path, &OperationRequest::new(action)).await
}

fn value<T: serde::Serialize>(item: &T) -> io::Result<Value> {
    serde_json::to_value(item).map_err(io::Error::other)
}

/// Collect one report from the service at `path`.
pub async fn collect(path: &Path, include_addresses: bool) -> io::Result<Value> {
    let status = query(path, OperationAction::Status {}).await?;
    if !status.ok {
        return Err(io::Error::other(format!("status refused: {}", status.code)));
    }
    let service: Option<ServiceId> = status.service;
    let mut report = Map::new();
    let mut unavailable = Vec::new();
    report.insert("format".into(), FORMAT.into());
    report.insert("format_version".into(), FORMAT_VERSION.into());
    report.insert("tool_version".into(), env!("CARGO_PKG_VERSION").into());
    report.insert(
        "collected_unix_ms".into(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
            .into(),
    );
    report.insert(
        "addresses".into(),
        if include_addresses {
            "included"
        } else {
            "redacted"
        }
        .into(),
    );
    report.insert("service".into(), value(&service)?);
    report.insert("status".into(), value(&status.status)?);
    let reads = [
        ("info", OperationAction::ServiceInfo {}),
        ("metrics", OperationAction::Metrics {}),
        ("devices", OperationAction::DeviceList {}),
        ("routes", OperationAction::RouteList {}),
    ];
    for (name, action) in reads {
        let reply = query(path, action).await?;
        if !reply.ok {
            unavailable.push(format!("{name}: {}", reply.code));
            continue;
        }
        let item = match name {
            "info" => value(&reply.info)?,
            "metrics" => value(&reply.metrics)?,
            "devices" => value(&reply.devices)?,
            _ => value(&reply.routes)?,
        };
        report.insert(name.into(), item);
    }
    // The retained event log, oldest first, without waiting.
    let mut events = Vec::new();
    let mut completed = Vec::new();
    let mut after = 0;
    while events.len() < EVENT_LIMIT {
        let reply = query(
            path,
            OperationAction::Events {
                after,
                limit: EVENTS_LIMIT,
                timeout_ms: 0,
                service,
            },
        )
        .await?;
        let Some(batch) = reply.events.filter(|_| reply.ok) else {
            unavailable.push(format!("events: {}", reply.code));
            break;
        };
        if batch.gap {
            report.insert("event_gap".into(), true.into());
        }
        let page = batch.events.len();
        for event in batch.events {
            if let EventBody::OperationCompleted { operation, .. } = &event.event {
                completed.push(*operation);
            }
            events.push(value(&event)?);
        }
        if page == 0 || batch.next <= after {
            break;
        }
        after = batch.next;
    }
    events.truncate(EVENT_LIMIT);
    report.insert("events".into(), Value::Array(events));
    let mut operations = Vec::new();
    for operation in completed.iter().rev().take(OPERATION_LIMIT).rev() {
        let reply = query(
            path,
            OperationAction::OperationGet {
                operation: *operation,
                service,
            },
        )
        .await?;
        if let (true, Some(state)) = (reply.ok, reply.operation) {
            operations.push(value(&state)?);
        }
    }
    report.insert("operations".into(), Value::Array(operations));
    report.insert("unavailable".into(), json!(unavailable));
    let mut report = Value::Object(report);
    if !include_addresses {
        redact(&mut report);
    }
    Ok(report)
}

/// Whether `text` is, or starts with, an IP address or socket address
/// (also `ADDRESS/LENGTH` prefixes).
fn address(text: &str) -> bool {
    let head = text.split('/').next().unwrap_or(text);
    head.parse::<IpAddr>().is_ok() || head.parse::<SocketAddr>().is_ok()
}

/// Replace every address-valued string in `value`.
pub fn redact(value: &mut Value) {
    match value {
        Value::String(text) if address(text) => *text = "redacted".into(),
        Value::Array(items) => items.iter_mut().for_each(redact),
        Value::Object(fields) => fields.values_mut().for_each(redact),
        _ => {}
    }
}

/// Write `report` to `destination`, which must not exist yet. On Unix the
/// file is created with mode 0600.
pub fn write_new(destination: &Path, report: &Value) -> io::Result<()> {
    use std::io::Write;
    let text = serde_json::to_vec_pretty(report).map_err(io::Error::other)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(destination)?;
    file.write_all(&text)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_redacted_everywhere_and_nothing_else() {
        let mut report = json!({
            "peer": "198.51.100.7:5121",
            "routes": [{"destination": "10.20.0.0/16", "gateway": "fd00::1", "device": "l2t0"}],
            "nested": {"local": "[fd00::2]:443", "carrier": "udp", "phase": "connected"},
            "count": 7
        });
        redact(&mut report);
        assert_eq!(
            report,
            json!({
                "peer": "redacted",
                "routes": [{"destination": "redacted", "gateway": "redacted", "device": "l2t0"}],
                "nested": {"local": "redacted", "carrier": "udp", "phase": "connected"},
                "count": 7
            })
        );
    }

    #[test]
    fn reports_are_written_only_to_new_private_files() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!("l2t-diag-{}", std::process::id()));
        std::fs::create_dir_all(&directory)?;
        let file = directory.join("report.json");
        write_new(&file, &json!({"format": FORMAT}))?;
        assert!(write_new(&file, &json!({})).is_err(), "never overwrites");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&file)?.permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(&directory)?;
        Ok(())
    }
}
