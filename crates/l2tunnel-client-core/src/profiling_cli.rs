//! Explicit bounded diagnostics for the ordinary managed TCP/TLS runtime.
use super::{BTreeMap, Duration, input, io};
use l2tunnel_runtime::managed::{ProfileHandle, ProfileSnapshot};
use std::future::Future;

pub(super) fn interval(options: &BTreeMap<String, String>) -> io::Result<Option<Duration>> {
    let Some(value) = options.get("--profile-ms") else {
        return Ok(None);
    };
    let millis: u64 = value
        .parse()
        .map_err(|_| input("invalid profile interval"))?;
    if millis == 0 {
        return Ok(None);
    }
    if !(100..=60_000).contains(&millis) {
        return Err(input("profile interval must be 0 or 100..60000 ms"));
    }
    if options.get("--carrier").is_some_and(|value| value != "tcp")
        || options
            .get("--traffic")
            .is_some_and(|value| value != "system")
        || options
            .get("--record-profile")
            .is_some_and(|value| value != "frame")
    {
        return Err(input(
            "profiling requires system traffic over TCP/TLS frame records",
        ));
    }
    Ok(Some(Duration::from_millis(millis)))
}

fn json(snapshot: &ProfileSnapshot) -> serde_json::Value {
    let timings: BTreeMap<_, _> = snapshot
        .timings
        .iter()
        .map(|(name, timing)| {
            (
                *name,
                serde_json::json!({"count": timing.count,
            "total_nanos": timing.total_nanos, "max_nanos": timing.max_nanos}),
            )
        })
        .collect();
    serde_json::json!({"event": "runtime_profile", "schema": 1,
        "runtime": "managed-tcp", "elapsed_nanos": snapshot.elapsed_nanos,
        "terminal": snapshot.terminal, "counters": snapshot.counters,
        "high_water": snapshot.high_water, "timings": timings})
}

pub(super) async fn observe(
    runtime: impl Future<Output = io::Result<()>>,
    profile: Option<ProfileHandle>,
) -> io::Result<()> {
    let Some(profile) = profile else {
        return runtime.await;
    };
    let mut snapshots = profile.subscribe();
    let mut observing = true;
    tokio::pin!(runtime);
    loop {
        tokio::select! {
            result = &mut runtime => {
                if let Some(snapshot) = profile.status() {
                    println!("{}", json(&snapshot));
                }
                return result;
            }
            changed = snapshots.changed(), if observing => {
                observing = changed.is_ok();
                if observing && let Some(snapshot) = snapshots.borrow_and_update().as_ref() {
                    println!("{}", json(snapshot));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiling_rejects_unsupported_paths_and_unbounded_intervals() -> io::Result<()> {
        let mut options = BTreeMap::new();
        assert_eq!(interval(&options)?, None);
        for value in ["-1", "99", "60001", "true", "18446744073709551616"] {
            options.insert("--profile-ms".into(), value.into());
            assert!(interval(&options).is_err());
        }
        options.insert("--profile-ms".into(), "100".into());
        assert_eq!(interval(&options)?, Some(Duration::from_millis(100)));
        for (key, value) in [
            ("--carrier", "udp"),
            ("--traffic", "active"),
            ("--traffic", "proxy-measured"),
            ("--record-profile", "rolling"),
        ] {
            options.insert(key.into(), value.into());
            assert!(interval(&options).is_err());
            options.remove(key);
        }
        Ok(())
    }
}
