//! Shared Common carrier parsing and exact original-input acquisition ownership.
//! Genuine authentication, setup cancellation and effective status are exercised
//! by service/tests/secure_udp_common_raw*.rs using the same public factories.
use super::*;
use common::Settings;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
type R<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn document(half: bool) -> serde_json::Value {
    serde_json::json!({"version":1,"profile":"raw-common-carrier-v1",
        "forward":{"local":"192.0.2.11:45001","peer":"192.0.2.12:45002"},
        "reverse":if half { serde_json::json!({"local":"192.0.2.11:45003","peer":"192.0.2.12:45004"}) } else {serde_json::Value::Null},
        "packet":{"mtu":576,"protection":"aead","queue_packets":8,"horizon_bytes":32768,
        "minimum_transfer_bytes":65536,"bytes_per_second":1048576,"packets_per_second":2048,
        "burst_bytes":16384,"burst_packets":32,"max_key_packets":1048576,"max_key_bytes":1073741824}})
}
#[test]
fn current_raw_policy_preserves_strict_nested_limits_and_refuses_retired_fields() -> R {
    let base = document(true);
    for path in [
        vec!["unknown"],
        vec!["forward", "unknown"],
        vec!["reverse", "unknown"],
        vec!["packet", "unknown"],
    ] {
        let mut value = base.clone();
        let mut at = &mut value;
        for key in &path[..path.len() - 1] {
            at = &mut at[*key];
        }
        at[path[path.len() - 1]] = serde_json::json!(1);
        assert!(Settings::from_json(&serde_json::to_vec(&value)?).is_err());
    }
    for key in ["version", "profile", "forward", "packet"] {
        let mut value = base.clone();
        value.as_object_mut().ok_or("object")?.remove(key);
        assert!(Settings::from_json(&serde_json::to_vec(&value)?).is_err());
    }
    let text = serde_json::to_string(&base)?;
    for duplicate in [
        format!("{{\"version\":1,{}", &text[1..]),
        text.replace("\"mtu\":576", "\"mtu\":576,\"mtu\":576"),
    ] {
        assert!(Settings::from_json(duplicate.as_bytes()).is_err());
    }
    for (key, value) in [
        ("mtu", serde_json::json!(575)),
        ("queue_packets", serde_json::json!(0)),
    ] {
        let mut value_document = base.clone();
        value_document["packet"][key] = value;
        assert!(Settings::from_json(&serde_json::to_vec(&value_document)?).is_err());
    }
    for key in ["recovery", "delivery", "channels"] {
        let mut value = base.clone();
        value[key] = serde_json::json!({});
        assert!(Settings::from_json(&serde_json::to_vec(&value)?).is_err());
    }
    let mut duplicate_tuple = base.clone();
    duplicate_tuple["reverse"] = duplicate_tuple["forward"].clone();
    assert!(Settings::from_json(&serde_json::to_vec(&duplicate_tuple)?).is_err());
    let mut maximum = serde_json::to_vec(&base)?;
    maximum.resize(MAX_POLICY_BYTES, b' ');
    assert_eq!(Settings::from_json(&maximum)?.duplex(), Duplex::Half);
    assert_eq!(
        Settings::from_json(&serde_json::to_vec(&document(false))?)?.duplex(),
        Duplex::Full
    );
    assert!(Settings::from_json(&vec![b' '; MAX_POLICY_BYTES + 1]).is_err());
    assert!(Settings::from_json(b"").is_err());
    Ok(())
}

struct Input(Arc<AtomicUsize>);
impl PacketIo for Input {
    fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
        Err(io::Error::other("setup must not poll input"))
    }
    fn send(&mut self, _: &[u8]) -> io::Result<()> {
        Err(io::Error::other("setup must not send input"))
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn acquire(
    half: bool,
    deadline: Instant,
    open: impl FnMut(RawConfig, Role) -> io::Result<Input>,
) -> io::Result<RawInputs<Input>> {
    let value = document(half);
    let decode = |value| serde_json::from_value(value).map_err(io::Error::other);
    let forward = decode(value["forward"].clone())?;
    let reverse: Option<Endpoints> =
        serde_json::from_value(value["reverse"].clone()).map_err(io::Error::other)?;
    let packet: Packet =
        serde_json::from_value(value["packet"].clone()).map_err(io::Error::other)?;
    inputs_for(forward, reverse, packet, Role::Client, deadline, open)
}
#[tokio::test(start_paused = true)]
async fn current_raw_original_cap_and_second_open_failure_release_exact_inputs() -> R {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut calls = 0;
    let failed = acquire(
        true,
        Instant::now() + Duration::from_secs(1),
        |config, role| {
            calls += 1;
            assert_eq!(role, Role::Client);
            assert_ne!(config.random_seed, 0);
            if calls == 2 {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(Input(drops.clone()))
            }
        },
    );
    assert!(matches!(failed,Err(e) if e.kind()==io::ErrorKind::PermissionDenied));
    assert_eq!(calls, 2);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let mut calls = 0;
    let expired = acquire(true, Instant::now(), |_, _| {
        calls += 1;
        Ok(Input(drops.clone()))
    });
    assert!(matches!(expired,Err(e) if e.kind()==io::ErrorKind::TimedOut));
    assert_eq!(calls, 0);
    let original = acquire(true, Instant::now() + Duration::from_secs(1), |_, _| {
        Ok(Input(drops.clone()))
    })?;
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    drop(original);
    assert_eq!(drops.load(Ordering::SeqCst), 3);
    Ok(())
}
#[tokio::test]
async fn current_raw_opener_time_cannot_extend_original_cap() -> R {
    let drops = Arc::new(AtomicUsize::new(0));
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = acquire(false, deadline, |_, _| {
        std::thread::sleep(Duration::from_millis(10));
        Ok(Input(drops.clone()))
    });
    assert!(matches!(result,Err(e) if e.kind()==io::ErrorKind::TimedOut));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    Ok(())
}
