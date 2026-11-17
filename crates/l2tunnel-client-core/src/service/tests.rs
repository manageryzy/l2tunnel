//! Real unprivileged TLS lifecycle and bounded replay regressions.
use super::*;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_core::Duplex;
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::time::timeout;
type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T = ()> = std::result::Result<T, Error>;
#[cfg(unix)]
mod secure_udp;
fn cfg(duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: 1600,
        compression: crate::Compression::None,
        handshake_timeout: Duration::from_secs(3),
    }
}
fn submit(error: SubmitError) -> io::Error {
    io::Error::other(format!("unexpected service result: {error:?}"))
}
async fn drive_once(run: &mut Pin<Box<Run>>) {
    std::future::poll_fn(|cx| {
        assert!(run.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}
#[tokio::test]
async fn dropping_full_terminal_history_keeps_capacity_and_latest_retired_results() -> Result {
    let (handle, run) = channel();
    // Seed the legal full-history teardown metadata. Actual TLS/device owner
    // release is independently covered by the lifecycle integration tests above.
    let original_capacity = {
        let mut state = handle.0.lock();
        for id in 1..=RETAINED as u64 {
            state.terminals.push_back(TerminalRecord {
                generation: OperationId(id),
                terminal: Terminal::Aborted,
                proxy_close_report: None,
            });
        }
        state.last_key = RETAINED as u64 + 1;
        state.snapshot.generation = Some(OperationId(state.last_key));
        state.snapshot.phase = Phase::Connected;
        state.terminals.capacity()
    };
    assert_eq!(original_capacity, RETAINED);
    drop(run);
    {
        let state = handle.0.lock();
        assert_eq!(state.terminals.len(), RETAINED);
        assert_eq!(
            state.terminals.capacity(),
            original_capacity,
            "teardown expanded bounded terminal storage"
        );
        assert_eq!(
            state
                .terminals
                .front()
                .map(|record| record.generation.value()),
            Some(2)
        );
        assert_eq!(
            state
                .terminals
                .back()
                .map(|record| record.generation.value()),
            Some(RETAINED as u64 + 1)
        );
    }
    assert_eq!(
        handle.wait_stopped(OperationId(1)).await,
        Err(SubmitError::Expired)
    );
    assert_eq!(
        handle.wait_stopped(OperationId(17)).await.map_err(submit)?,
        Terminal::Aborted
    );
    assert_eq!(
        handle
            .wait_stopped(OperationId(RETAINED as u64 + 1))
            .await
            .map_err(submit)?,
        Terminal::Aborted
    );
    Ok(())
}
