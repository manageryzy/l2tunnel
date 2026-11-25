use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "l2t-api-{}-{}",
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
fn response() -> Response {
    Response {
        version: VERSION,
        ok: true,
        code: "ok".into(),
        state: Some(Snapshot {
            epoch: 2,
            phase: "idle".into(),
            compression: Compression::Lz4,
            proxy: None,
            common: None,
        }),
    }
}
#[tokio::test]
async fn private_real_socket_requests_and_ownership_cleanup() -> io::Result<()> {
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o600
    );
    assert!(Server::bind(&path).is_err());
    let task = tokio::spawn(async move { server.serve(|_request| async { response() }).await });
    let result = request(
        &path,
        &Request {
            version: VERSION,
            action: Action::Status {},
        },
    )
    .await?;
    assert_eq!(result, response());
    task.abort();
    let _cancelled = task.await;
    assert!(!path.exists());
    Ok(())
}

#[tokio::test]
async fn explicit_common_version_is_not_retried_or_downgraded() -> io::Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    // A proxy backend explicitly refuses Common; transport must not resend a write.
    let task = tokio::spawn(async move {
        server
            .serve(move |request| {
                counted.fetch_add(1, Ordering::SeqCst);
                async move {
                    Response {
                        version: request.version,
                        ok: false,
                        code: "unsupported_version".into(),
                        state: None,
                    }
                }
            })
            .await
    });
    let result = request(
        &path,
        &Request {
            version: COMMON_VERSION,
            action: Action::Reconnect {},
        },
    )
    .await?;
    assert_eq!(result.version, COMMON_VERSION);
    assert_eq!(result.code, "unsupported_version");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.abort();
    let _cancelled = task.await;
    assert!(
        request(
            &path,
            &Request {
                version: 3,
                action: Action::Reconnect {}
            }
        )
        .await
        .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn actual_idle_service_wrong_version_ipc_preserves_key_and_owner_state() -> io::Result<()> {
    use crate::service;
    use std::sync::{Arc, atomic::AtomicUsize};
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let (handle, run) = service::channel();
    let owner = tokio::spawn(run);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let service = handle.clone();
    let task = tokio::spawn(async move {
        server
            .serve(move |request| {
                counted.fetch_add(1, Ordering::SeqCst);
                let service = service.clone();
                async move { service.lifecycle_request(request).await }
            })
            .await
    });
    let key = handle
        .next_key()
        .map_err(|value| io::Error::other(format!("{value:?}")))?;
    for version in [2, 3] {
        for action in [
            Action::Status {},
            Action::Disconnect {},
            Action::Reconnect {},
        ] {
            assert!(request(&path, &Request { version, action }).await.is_err());
            assert_eq!(
                handle
                    .next_key()
                    .map_err(|value| io::Error::other(format!("{value:?}")))?,
                key
            );
            let snapshot = handle.snapshot();
            assert_eq!(snapshot.phase, service::Phase::Disconnected);
            assert!(snapshot.generation.is_none());
            assert!(snapshot.operation.is_none());
            assert!(snapshot.runtime.is_none());
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let matching = request(
        &path,
        &Request {
            version: VERSION,
            action: Action::Status {},
        },
    )
    .await?;
    assert!(matching.ok);
    assert_eq!(matching.version, VERSION);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.abort();
    owner.abort();
    let _cancelled = task.await;
    let _cancelled = owner.await;
    assert!(!path.exists());
    Ok(())
}

#[tokio::test]
async fn reply_version_must_match_the_explicit_request() -> io::Result<()> {
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let task = tokio::spawn(async move { server.serve(|_request| async { response() }).await });
    let result = request(
        &path,
        &Request {
            version: COMMON_VERSION,
            action: Action::Status {},
        },
    )
    .await;
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    task.abort();
    let _cancelled = task.await;
    Ok(())
}
#[tokio::test]
async fn unsafe_parent_collision_and_replaced_path_are_preserved() -> io::Result<()> {
    let directory = Directory::new()?;
    let path = directory.socket();
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755))?;
    assert!(Server::bind(&path).is_err());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(&path, b"existing file")?;
    assert!(Server::bind(&path).is_err());
    assert_eq!(std::fs::read(&path)?, b"existing file");
    std::fs::remove_file(&path)?;
    let server = Server::bind(&path)?;
    std::fs::remove_file(&path)?;
    std::fs::write(&path, b"replacement")?;
    drop(server);
    assert_eq!(std::fs::read(&path)?, b"replacement");
    Ok(())
}
#[tokio::test]
async fn oversized_prefix_and_unknown_fields_are_rejected() -> io::Result<()> {
    let (mut write, mut read) = tokio::io::duplex(8);
    write.write_u32(u32::MAX).await?;
    assert!(
        read_json::<_, Request>(&mut read, REQUEST_LIMIT)
            .await
            .is_err()
    );
    for body in [
        br#"{"version":1,"action":{"command":"status"},"extra":true}"#.as_slice(),
        br#"{"version":1,"action":{"command":"run_shell"}}"#.as_slice(),
        br#"{"version":1,"action":{"command":"switch_compression","compression":"unknown"}}"#
            .as_slice(),
        br#"{"version":1,"action":{"command":"status","extra":true}}"#.as_slice(),
    ] {
        assert!(serde_json::from_slice::<Request>(body).is_err());
    }
    let too_large = Response {
        code: "x".repeat(RESPONSE_LIMIT + 1),
        ..response()
    };
    assert!(
        write_json(&mut write, &too_large, RESPONSE_LIMIT)
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn malformed_client_does_not_terminate_service() -> io::Result<()> {
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let task = tokio::spawn(async move { server.serve(|_request| async { response() }).await });
    let mut bad = UnixStream::connect(&path).await?;
    bad.write_u32(u32::MAX).await?;
    let result = request(
        &path,
        &Request {
            version: VERSION,
            action: Action::Status {},
        },
    )
    .await?;
    assert!(result.ok);
    assert!(
        request(
            &path,
            &Request {
                version: VERSION + 1,
                action: Action::Status {}
            }
        )
        .await
        .is_err()
    );
    task.abort();
    let _cancelled = task.await;
    Ok(())
}

#[test]
fn proxy_schema_is_strict_and_absent_proxy_preserves_legacy_bytes() -> io::Result<()> {
    for body in [
        r#"{"version":1,"action":{"command":"drain_proxy","extra":true}}"#,
        r#"{"version":1,"action":{"command":"drain_proxy","command":"status"}}"#,
    ] {
        assert!(serde_json::from_str::<Request>(body).is_err());
    }
    let legacy = serde_json::to_value(response()).map_err(io::Error::other)?;
    assert!(legacy["state"].get("proxy").is_none());
    let valid = r#"{"digest":"ab","drain_accepted":true,"runtime":null,"terminal":{"outcome":"failed","error":"bounded"}}"#;
    assert!(serde_json::from_str::<ProxySnapshot>(valid).is_ok());
    for bad in [
        valid.replace(
            "\"drain_accepted\":true",
            "\"drain_accepted\":true,\"drain_accepted\":false",
        ),
        valid.replace("\"digest\":\"ab\"", "\"digest\":\"ab\",\"extra\":1"),
        valid.replace(
            "\"error\":\"bounded\"",
            "\"error\":\"bounded\",\"error\":\"again\"",
        ),
        valid.replace("\"error\":\"bounded\"", "\"error\":\"bounded\",\"extra\":1"),
    ] {
        assert!(serde_json::from_str::<ProxySnapshot>(&bad).is_err());
    }
    for bad in [
        r#"{"outcome":"closed","report":{"local_user_records":0,"local_user_records":1}}"#,
        r#"{"outcome":"closed","report":{"extra":1}}"#,
    ] {
        assert!(serde_json::from_str::<ProxyTerminal>(bad).is_err());
    }
    let complete = ProxySnapshot {
        common: None,
        measured: None,
        digest: "ab".repeat(32),
        drain_accepted: true,
        runtime: Some(ProxyStatus {
            phase: "Closed".into(),
            flows: 0,
            active: 0,
            stopped: 0,
            retired: 0,
            queued_bytes: 0,
            queued_records: 0,
            transparent_admitted_bytes: 0,
            transparent_admitted_packets: 0,
            native_confirmed_packets: 0,
        }),
        terminal: Some(ProxyTerminal::Closed {
            report: ProxyCloseReport {
                local_user_records: 0,
                peer_user_records: 0,
                local_transparent_packets: 0,
                native_confirmed_packets: 0,
                clean_flows: 0,
                stopped_flows: 0,
                tls_lanes_closed: 2,
            },
        }),
    };
    let encoded = serde_json::to_string(&complete).map_err(io::Error::other)?;
    assert_eq!(
        serde_json::from_str::<ProxySnapshot>(&encoded).map_err(io::Error::other)?,
        complete
    );
    for bad in [
        encoded.replace("\"clean_flows\":0", "\"clean_flows\":0,\"clean_flows\":1"),
        encoded.replace("\"clean_flows\":0", "\"clean_flows\":0,\"extra\":1"),
        encoded.replace("\"flows\":0", "\"flows\":0,\"flows\":1"),
        encoded.replace("\"flows\":0", "\"flows\":0,\"extra\":1"),
    ] {
        assert!(serde_json::from_str::<ProxySnapshot>(&bad).is_err());
    }
    Ok(())
}
