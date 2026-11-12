use super::*;
use std::os::unix::fs::DirBuilderExt;
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
            active: None,
            proxy: None,
            openvpn_drain: None,
            raw_packet: None,
            rolling: None,
            #[cfg(unix)]
            swift: None,
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

#[tokio::test]
async fn active_policy_round_trips_real_socket_and_preserves_legacy_schema() -> io::Result<()> {
    assert_eq!(
        serde_json::to_string(&response())?,
        r#"{"version":1,"ok":true,"code":"ok","state":{"epoch":2,"phase":"idle","compression":"lz4"}}"#
    );
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let mut weights = vec![1; 64];
    weights[46] = 9;
    let policy = crate::active_managed::Policy {
        channels: 7,
        dscp_weights: weights,
    };
    let expected = policy.clone();
    let task = tokio::spawn(async move {
        server
            .serve(move |request| {
                let expected = expected.clone();
                async move {
                    assert_eq!(
                        request.action,
                        Action::SwitchActivePolicy {
                            policy: expected.clone()
                        }
                    );
                    let mut value = response();
                    if let Some(state) = &mut value.state {
                        state.active = Some(ActiveSnapshot {
                            policy: expected,
                            admitting: true,
                            running: true,
                            digest: "ab".repeat(32),
                        });
                    }
                    value
                }
            })
            .await
    });
    let value = request(
        &path,
        &Request {
            version: VERSION,
            action: Action::SwitchActivePolicy {
                policy: policy.clone(),
            },
        },
    )
    .await?;
    let actual = value
        .state
        .and_then(|state| state.active)
        .ok_or_else(|| io::Error::other("missing active snapshot"))?;
    assert_eq!(actual.policy, policy);
    assert!(actual.admitting && actual.running);
    task.abort();
    let _cancelled = task.await;
    assert!(!path.exists());
    Ok(())
}

#[test]
fn active_action_rejects_unknown_and_duplicate_nested_fields() {
    for body in [
        r#"{"version":1,"action":{"command":"switch_active_policy","policy":{"channels":1,"dscp_weights":[],"extra":true}}}"#,
        r#"{"version":1,"action":{"command":"switch_active_policy","policy":{"channels":1,"channels":2,"dscp_weights":[]}}}"#,
        r#"{"version":1,"action":{"command":"switch_active_policy","policy":{"channels":1,"dscp_weights":[]},"extra":true}}"#,
    ] {
        assert!(serde_json::from_str::<Request>(body).is_err());
    }
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
#[test]
fn native_drain_schema_bounds_and_legacy_response_bytes_remain_exact() -> io::Result<()> {
    use crate::openvpn::drain::{
        Binding, CarrierReport, CarrierStats, CloseReport, Failure, FailureKind, FenceCounters,
        PartialProgress, Snapshot as NativeSnapshot, Terminal,
    };
    let encode = |v: &Response| serde_json::to_vec(v).map_err(io::Error::other);
    assert_eq!(encode(&response())?,br#"{"version":1,"ok":true,"code":"ok","state":{"epoch":2,"phase":"idle","compression":"lz4"}}"#);
    for invalid in [
        r#"{"version":1,"action":{"command":"drain_open_vpn","extra":true}}"#,
        r#"{"version":1,"action":{"command":"drain_open_vpn","command":"status"}}"#,
    ] {
        assert!(serde_json::from_str::<Request>(invalid).is_err());
    }
    let request = Request {
        version: VERSION,
        action: Action::DrainOpenVpn {},
    };
    let serialized = serde_json::to_string(&request).map_err(io::Error::other)?;
    // Pin the explicit Rust enum spelling in the version-1 local schema.
    assert_eq!(
        serialized,
        r#"{"version":1,"action":{"command":"drain_open_vpn"}}"#
    );
    assert_eq!(
        serde_json::from_str::<Request>(&serialized).map_err(io::Error::other)?,
        request
    );
    let fence = FenceCounters {
        packets: u64::MAX,
        native_bytes: u64::MAX,
        sources: u64::MAX,
        source_bytes: u64::MAX,
    };
    let stats = CarrierStats {
        admitted_sources: u64::MAX,
        consumed_sources: u64::MAX,
        admitted_datagrams: u64::MAX,
        admitted_ip_bytes: u64::MAX,
        transmitted_datagrams: u64::MAX,
        tls_messages: u64::MAX,
    };
    let progress = PartialProgress {
        accepted: fence,
        sources_received: u64::MAX,
        source_bytes_received: u64::MAX,
        native_completed: u64::MAX,
        native_bytes_completed: u64::MAX,
        native_confirmed: u64::MAX,
        native_bytes_confirmed: u64::MAX,
        outbound_fragments: usize::MAX,
        outbound_bytes: usize::MAX,
        admission_in_flight: true,
        reassembly_messages: usize::MAX,
        reassembly_bytes: usize::MAX,
        pending_native_packets: usize::MAX,
        pending_native_bytes: usize::MAX,
    };
    for terminal in [
        Terminal::Closed {
            report: CloseReport {
                local: fence,
                peer: fence,
                carrier: CarrierReport::Paired([stats; 2]),
            },
        },
        Terminal::Failed {
            error: Failure {
                kind: FailureKind::Other,
                raw_os_error: Some(i32::MIN),
                diagnostic: "\0".repeat(512),
            },
            progress,
        },
        Terminal::Cancelled,
    ] {
        let mut r = response();
        r.state
            .as_mut()
            .ok_or_else(|| io::Error::other("state"))?
            .openvpn_drain = Some(NativeSnapshot {
            binding: Binding::Paired {
                pair: [255; 32],
                configs: [[255; 32]; 2],
            },
            drain_accepted: true,
            terminal: Some(terminal),
        });
        let bytes = encode(&r)?;
        assert!(bytes.len() < RESPONSE_LIMIT);
        assert_eq!(
            serde_json::from_slice::<Response>(&bytes).map_err(io::Error::other)?,
            r
        );
        let mut bad = serde_json::to_value(r).map_err(io::Error::other)?;
        bad["state"]["openvpn_drain"]["terminal"]["extra"] = true.into();
        assert!(serde_json::from_value::<Response>(bad).is_err());
    }
    Ok(())
}
