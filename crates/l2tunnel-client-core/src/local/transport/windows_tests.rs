//! Windows-only pipe endpoint tests. They need a Windows (or Windows-compatible)
//! host with an elevated or LocalSystem token, because the first instance must
//! be owned by LocalSystem or Administrators.
use super::super::{OperationAction, OperationRequest, Server, request_operation};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn unique() -> String {
    format!(
        r"\\.\pipe\l2tunnel-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

#[tokio::test]
async fn pipe_serves_v5_status_and_refuses_a_second_first_instance() -> io::Result<()> {
    let name = unique();
    let server = Server::bind(&name)?;
    // FILE_FLAG_FIRST_PIPE_INSTANCE: a second owner of the same name is refused.
    assert!(Server::bind(&name).is_err());
    let (handle, owner) = crate::service::channel();
    let serving = tokio::spawn(async move { server.serve_service(handle).await });
    let mut replies = Vec::new();
    for _ in 0..3 {
        replies.push(
            request_operation(&name, &OperationRequest::new(OperationAction::Status {})).await?,
        );
    }
    for reply in &replies {
        assert!(reply.ok, "{reply:?}");
        assert!(reply.status.is_some());
    }
    serving.abort();
    drop(owner);
    Ok(())
}

#[tokio::test]
async fn remote_device_and_missing_pipes_send_nothing() {
    for name in [r"\\server\pipe\l2tunnel", r"\\.\C:\x", "relative"] {
        let error = request_operation(name, &OperationRequest::new(OperationAction::Status {}))
            .await
            .err()
            .map(|error| error.kind());
        assert_eq!(error, Some(io::ErrorKind::NotFound), "{name}");
    }
    let error = request_operation(unique(), &OperationRequest::new(OperationAction::Status {}))
        .await
        .err()
        .map(|error| error.kind());
    assert_eq!(error, Some(io::ErrorKind::NotFound));
}
