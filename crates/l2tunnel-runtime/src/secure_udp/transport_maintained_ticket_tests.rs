//! Genuine QUIC owner plus actual maintained wrapper; no synthetic acceptance.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "l2tunnel-quic-ticket-{}-{}.bmetrics",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn identity(deadline: Instant) -> UserIdentity {
    UserIdentity {
        scope: l2tunnel::secure_record::Scope {
            epoch: security::Epoch(3),
            configuration: security::ConfigDigest([29; 32]),
        },
        number: security::PacketNumber(41),
        bytes: 9,
        deadline,
    }
}
#[tokio::test]
async fn actual_quic_ticket_preserves_acceptance_across_delayed_upper_take() -> TestResult {
    let (mut a, mut b) = wire::test_quic_pair().await?;
    let cap = a.setup_deadline().min(b.setup_deadline());
    a.select_final_records(cap)?;
    b.select_final_records(cap)?;
    let path = path();
    a.test_ticket_metrics(path.clone())?;
    let mut adapter = MaintainedIo::new(a)?.pop().ok_or("missing adapter")?;
    let id = identity(cap);
    assert!(matches!(
        adapter.try_user(id, &[0x80; 9], true)?,
        SendProgress::Pending
    ));
    tokio::time::sleep(Duration::from_millis(2)).await;
    // Poll the actual lower owner before the unchanged wrapper consumes its result.
    tokio::time::timeout_at(
        cap,
        std::future::poll_fn(|cx| adapter.carrier.poll_progress(cx)),
    )
    .await??;
    let lower = adapter.carrier.test_ticket_report()?;
    let pending = lower["pending"]
        .as_array()
        .ok_or("pending array")?
        .first()
        .ok_or("pending ticket")?;
    let accepted = pending["accepted_us"].as_u64().ok_or("actual acceptance")?;
    assert!(pending["result_us"].as_u64().is_some());
    assert_eq!(pending["observed_us"], serde_json::Value::Null);
    assert_eq!(pending["user"]["packet_number"], 41);
    assert_eq!(pending["user"]["epoch"], 3);
    tokio::time::sleep(Duration::from_millis(2)).await;
    tokio::time::timeout_at(
        cap,
        std::future::poll_fn(|cx| adapter.poll_ready(cx, false)),
    )
    .await??;
    assert!(adapter.receipt_ready());
    tokio::time::sleep(Duration::from_millis(2)).await;
    let (returned, result) = adapter.take_user()?.ok_or("actual receipt")?;
    assert_eq!(returned, id);
    assert!(matches!(result, SendProgress::Whole { .. }));
    assert!(adapter.take_user()?.is_none());
    let report = adapter.carrier.test_ticket_report()?;
    let row = &report["rows"][0];
    let last = &row["last"];
    assert_eq!(row["created"], 1);
    assert_eq!(row["completed"], 1);
    assert_eq!(last["accepted_us"], accepted);
    assert!(last["first_poll_us"].as_u64() > last["created_us"].as_u64());
    assert!(last["observed_us"].as_u64() > last["result_us"].as_u64());
    assert!(last["taken_us"].as_u64() > last["observed_us"].as_u64());
    assert_eq!(report["invalid"], false);
    // Actual acceptance does not promise remote delivery; this separately verifies it.
    let mut bytes = [0; 1072];
    b.recv(&mut bytes, cap).await?;
    drop(adapter);
    let terminal: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(terminal["quic"]["tickets"]["cutoff"], "carrier_drop");
    assert!(terminal["quic"]["tickets"]["stopped_us"].is_u64());
    std::fs::remove_file(path)?;
    Ok(())
}
#[tokio::test]
async fn actual_quic_unpolled_ticket_drop_is_censored_without_acceptance() -> TestResult {
    let (mut a, mut b) = wire::test_quic_pair().await?;
    let cap = a.setup_deadline().min(b.setup_deadline());
    a.select_final_records(cap)?;
    b.select_final_records(cap)?;
    let path = path();
    a.test_ticket_metrics(path.clone())?;
    let mut adapter = MaintainedIo::new(a)?.pop().ok_or("missing adapter")?;
    adapter.try_user(identity(cap), &[0x80; 9], true)?;
    tokio::time::sleep(Duration::from_millis(2)).await;
    drop(adapter);
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let row = &report["quic"]["tickets"]["rows"][0];
    assert_eq!(row["created"], 1);
    assert_eq!(row["censored"], 1);
    assert_eq!(row["completed"], 0);
    assert_eq!(row["failed"], 0);
    assert_eq!(row["last"]["accepted_us"], serde_json::Value::Null);
    assert_eq!(row["last"]["first_poll_us"], serde_json::Value::Null);
    assert_eq!(row["stages"][0]["censored"], 1);
    assert_eq!(row["stages"][1]["maximum_us"], serde_json::Value::Null);
    std::fs::remove_file(path)?;
    Ok(())
}
