//! Timestamping shares the legacy parser and precedes bounded event queue waits.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
#[tokio::test(start_paused = true)]
async fn authenticated_control_receipt_time_precedes_full_event_queue_wait() -> TestResult {
    let (mut writer, reader) = tokio::io::duplex(128);
    let (sender, mut events) = mpsc::channel(1);
    let start = Instant::now();
    sender.send((99, ControlEvent::Credit(0), start)).await?;
    let task = tokio::spawn(read_control_bound_timed(
        reader,
        1,
        sender,
        Duration::from_secs(1),
        8,
        *b"L2UC",
    ));
    tokio::time::advance(Duration::from_millis(10)).await;
    write_control_frame_bound(&mut writer, 3, &7u64.to_be_bytes(), *b"L2UC").await?;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(90)).await;
    tokio::task::yield_now().await;
    assert_eq!(events.recv().await.ok_or("missing sentinel")?.0, 99);
    let (lane, event, receipt) = events.recv().await.ok_or("missing original receipt")?;
    assert_eq!(lane, 1);
    assert!(matches!(event, ControlEvent::Credit(7)));
    assert_eq!(receipt.duration_since(start), Duration::from_millis(10));
    assert_eq!(start.elapsed(), Duration::from_millis(100));
    task.abort();
    let _ = task.await;
    Ok(())
}
#[tokio::test]
async fn timed_and_legacy_control_wrappers_reject_the_same_invalid_header() -> TestResult {
    let bad = std::io::Cursor::new(b"BAD!\x01\x03\x00\x08".to_vec());
    let (sender, _) = mpsc::channel(1);
    let legacy = read_control_bound(bad, 0, sender, Duration::from_secs(1), 8, *b"L2UC")
        .await
        .err()
        .ok_or("bad legacy header accepted")?;
    let bad = std::io::Cursor::new(b"BAD!\x01\x03\x00\x08".to_vec());
    let (sender, _) = mpsc::channel(1);
    let timed = read_control_bound_timed(bad, 0, sender, Duration::from_secs(1), 8, *b"L2UC")
        .await
        .err()
        .ok_or("bad timed header accepted")?;
    assert_eq!(legacy.kind(), timed.kind());
    assert_eq!(legacy.to_string(), timed.to_string());
    Ok(())
}
