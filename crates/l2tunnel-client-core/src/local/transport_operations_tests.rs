//! Real Unix-socket tests of version-5 dispatch and bounded concurrency.
use super::*;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncReadExt;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "l2t-ops-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
    fn socket(&self) -> PathBuf {
        self.0.join("api.sock")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn legacy_status() -> Request {
    Request {
        version: VERSION,
        action: Action::Status {},
    }
}

#[tokio::test]
async fn service_endpoint_serves_version5_and_legacy_side_by_side() -> io::Result<()> {
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let (handle, run) = crate::service::channel();
    let instance = handle.instance();
    let task = tokio::spawn(async move { server.serve_service(handle).await });
    let reply =
        request_operation(&path, &OperationRequest::new(OperationAction::Status {})).await?;
    assert!(reply.ok);
    assert_eq!(reply.service, Some(ServiceId(instance)));
    assert_eq!(
        reply.status.map(|status| status.phase),
        Some("disconnected".to_owned())
    );
    // Legacy requests keep their own dispatcher and reply type.
    let legacy = request(&path, &legacy_status()).await?;
    assert_eq!(legacy.version, VERSION);
    task.abort();
    let _cancelled = task.await;
    drop(run);
    Ok(())
}

#[tokio::test]
async fn handler_only_endpoint_refuses_version5_explicitly() -> io::Result<()> {
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let task = tokio::spawn(async move {
        server
            .serve(|request| async move {
                Response {
                    version: request.version,
                    ok: true,
                    code: "ok".into(),
                    state: None,
                }
            })
            .await
    });
    let reply =
        request_operation(&path, &OperationRequest::new(OperationAction::Status {})).await?;
    assert_eq!(
        (reply.ok, reply.code.as_str()),
        (false, "unsupported_version")
    );
    assert_eq!(reply.service, None);
    task.abort();
    let _cancelled = task.await;
    Ok(())
}

#[tokio::test]
async fn status_is_answered_while_another_request_is_held() -> io::Result<()> {
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let (release, released) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        server
            .serve(move |request| {
                let mut released = released.clone();
                async move {
                    if matches!(request.action, Action::Disconnect {}) {
                        let _ = released.wait_for(|value| *value).await;
                    }
                    Response {
                        version: request.version,
                        ok: true,
                        code: format!("{:?}", request.action),
                        state: None,
                    }
                }
            })
            .await
    });
    let held_path = path.clone();
    let held = tokio::spawn(async move {
        request(
            &held_path,
            &Request {
                version: VERSION,
                action: Action::Disconnect {},
            },
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let status = tokio::time::timeout(Duration::from_secs(2), request(&path, &legacy_status()))
        .await
        .map_err(|_| io::Error::other("status blocked behind a held request"))??;
    assert_eq!(status.code, "Status");
    assert!(!held.is_finished());
    let _ = release.send(true);
    let held = held.await.map_err(io::Error::other)??;
    assert_eq!(held.code, "Disconnect");
    task.abort();
    let _cancelled = task.await;
    Ok(())
}

#[tokio::test]
async fn connections_beyond_the_bound_are_closed_without_reply() -> io::Result<()> {
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let task = tokio::spawn(async move {
        server
            .serve(|request| async move {
                Response {
                    version: request.version,
                    ok: true,
                    code: "ok".into(),
                    state: None,
                }
            })
            .await
    });
    // Idle clients occupy every slot until their read bound expires.
    let mut idle = Vec::new();
    for _ in 0..CONCURRENT_CONNECTIONS {
        idle.push(UnixStream::connect(&path).await?);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut extra = UnixStream::connect(&path).await?;
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(2), extra.read(&mut byte))
        .await
        .map_err(|_| io::Error::other("excess connection was not closed"))?;
    assert!(matches!(read, Ok(0) | Err(_)));
    // Releasing the idle clients frees their slots for a real request.
    drop(idle);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(request(&path, &legacy_status()).await?.ok);
    task.abort();
    let _cancelled = task.await;
    Ok(())
}
