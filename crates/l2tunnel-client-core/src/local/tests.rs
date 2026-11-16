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
            #[cfg(unix)]
            secure_udp: None,
            transaction: None,
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
async fn explicit_version_two_is_not_retried_or_downgraded() -> io::Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    // A v1-only backend explicitly refuses v2; transport must not resend a write.
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
            version: SECURE_UDP_VERSION,
            action: Action::Reconnect {},
        },
    )
    .await?;
    assert_eq!(result.version, SECURE_UDP_VERSION);
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

fn complete_configuration()
-> io::Result<crate::secure_udp::transaction_status::CanonicalConfiguration> {
    use l2tunnel::swift_configuration::{Configuration, Descriptor, EnvelopeDigest};
    let (profile, _) = crate::secure_udp::profile::tests::fixture(
        l2tunnel_udp_control::Path {
            client: "127.0.0.1:41321".parse().map_err(io::Error::other)?,
            server: "127.0.0.1:41322".parse().map_err(io::Error::other)?,
        },
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_identity::MemberPublicKey([7; 32]),
    )?;
    let runtime = profile.runtime(l2tunnel_security::Role::Initiator);
    let descriptor = Descriptor::new(runtime.path_mtu, runtime.send, runtime.receive)
        .map_err(io::Error::other)?;
    crate::secure_udp::transaction_status::CanonicalConfiguration::from_configuration(
        Configuration::new(EnvelopeDigest::new([8; 32]), descriptor).map_err(io::Error::other)?,
    )
}

async fn rejected_frame(path: &Path, prefix: u32, body: &[u8]) -> io::Result<()> {
    let mut stream = UnixStream::connect(path).await?;
    stream.write_u32(prefix).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    let mut reply = [0; 1];
    let count = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut reply))
        .await
        .map_err(io::Error::other)??;
    assert_eq!(count, 0, "invalid request received an application reply");
    Ok(())
}

#[tokio::test]
async fn strict_v3_real_socket_frames_have_zero_handler_effects_and_keep_listener_alive()
-> io::Result<()> {
    use std::sync::{Arc, atomic::AtomicUsize};
    let directory = Directory::new()?;
    let path = directory.socket();
    let server = Server::bind(&path)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let configuration = complete_configuration()?;
    let expected = configuration.clone();
    let task = tokio::spawn(async move {
        server
            .serve(move |request| {
                counted.fetch_add(1, Ordering::SeqCst);
                if let Action::SwitchSwiftConfiguration { configuration } = &request.action {
                    assert_eq!(configuration, &expected);
                }
                async move {
                    Response {
                        version: request.version,
                        ok: true,
                        code: "ok".into(),
                        state: None,
                    }
                }
            })
            .await
    });
    let mut malformed = vec![
        br#"{"version":3,"version":3,"action":{"command":"status"}}"#.to_vec(),
        br#"{"version":3,"action":{"command":"status"},"extra":true}"#.to_vec(),
        br#"{"version":3,"action":{"command":"status","extra":true}}"#.to_vec(),
        br#"{"version":3,"action":{"command":"disconnect","command":"status"}}"#.to_vec(),
        br#"{"version":3,"action":{"command":"switch_swift_configuration","configuration":""}}"#.to_vec(),
        br#"{"version":3,"action":{"command":"switch_swift_configuration","configuration":"bad","extra":true}}"#.to_vec(),
        br#"{"version":3,"action":{"command":"status"}}{}"#.to_vec(),
        br#"{"version":5,"action":{"command":"reconnect"}}"#.to_vec(),
        vec![0xff],
    ];
    malformed.push(format!(r#"{{"version":3,"action":{{"command":"switch_swift_configuration","configuration":"{}","configuration":"{}"}}}}"#,
        configuration.as_str(), configuration.as_str()).into_bytes());
    malformed.push(format!(r#"{{"version":3,"action":{{"command":"switch_swift_configuration","configuration":"{}"}}}}"#,
        configuration.as_str().to_ascii_uppercase()).into_bytes());
    for body in malformed {
        rejected_frame(
            &path,
            u32::try_from(body.len()).map_err(io::Error::other)?,
            &body,
        )
        .await?;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    for (prefix, body) in [
        (0, b"".as_slice()),
        (u32::MAX, b"".as_slice()),
        (4097, b"".as_slice()),
        (16, b"{}".as_slice()),
    ] {
        rejected_frame(&path, prefix, body).await?;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    let complete = Request {
        version: TRANSACTION_VERSION,
        action: Action::SwitchSwiftConfiguration { configuration },
    };
    let mut body = serde_json::to_vec(&complete).map_err(io::Error::other)?;
    assert!(body.len() < REQUEST_LIMIT);
    body.resize(REQUEST_LIMIT, b' ');
    let mut exact = UnixStream::connect(&path).await?;
    exact.write_u32(4096).await?;
    exact.write_all(&body).await?;
    let reply: Response = read_json(&mut exact, RESPONSE_LIMIT).await?;
    assert!(reply.ok);
    assert_eq!(reply.version, TRANSACTION_VERSION);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let valid = request(
        &path,
        &Request {
            version: TRANSACTION_VERSION,
            action: Action::Status {},
        },
    )
    .await?;
    assert!(valid.ok);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    task.abort();
    let _cancelled = task.await;
    assert!(!path.exists());
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
    for version in [SECURE_UDP_VERSION, TRANSACTION_VERSION] {
        for action in [
            Action::Status {},
            Action::Disconnect {},
            Action::Reconnect {},
        ] {
            let reply = request(&path, &Request { version, action }).await?;
            assert_eq!(reply.version, version);
            assert!(!reply.ok);
            assert_eq!(reply.code, "unsupported_version");
            assert!(reply.state.is_none());
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
    assert_eq!(calls.load(Ordering::SeqCst), 6);
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
    assert_eq!(calls.load(Ordering::SeqCst), 7);
    task.abort();
    owner.abort();
    let _cancelled = task.await;
    let _cancelled = owner.await;
    assert!(!path.exists());
    Ok(())
}

#[derive(Clone, Copy)]
enum ReplyFailure {
    Refused,
    Mismatched,
    Lost,
    Malformed,
    Oversized,
}

#[tokio::test]
async fn v3_mutations_are_not_retried_after_refusal_reply_loss_or_invalid_reply() -> io::Result<()>
{
    use std::sync::{Arc, atomic::AtomicUsize};
    for mode in [
        ReplyFailure::Refused,
        ReplyFailure::Mismatched,
        ReplyFailure::Lost,
        ReplyFailure::Malformed,
        ReplyFailure::Oversized,
    ] {
        let directory = Directory::new()?;
        let path = directory.socket();
        let listener = UnixListener::bind(&path)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let effects = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let applied = effects.clone();
        let task: tokio::task::JoinHandle<io::Result<()>> = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await?;
                let incoming: Request = read_json(&mut stream, REQUEST_LIMIT).await?;
                counted.fetch_add(1, Ordering::SeqCst);
                assert_eq!(
                    incoming.version, TRANSACTION_VERSION,
                    "transport downgraded a request"
                );
                if matches!(incoming.action, Action::Status {}) {
                    let reply = Response {
                        version: TRANSACTION_VERSION,
                        ok: true,
                        code: format!("effects={}", applied.load(Ordering::SeqCst)),
                        state: None,
                    };
                    write_json(&mut stream, &reply, RESPONSE_LIMIT).await?;
                    continue;
                }
                assert_eq!(incoming.action, Action::Reconnect {});
                if !matches!(mode, ReplyFailure::Refused) {
                    applied.fetch_add(1, Ordering::SeqCst);
                }
                match mode {
                    ReplyFailure::Refused | ReplyFailure::Mismatched => {
                        let reply = Response {
                            version: if matches!(mode, ReplyFailure::Mismatched) {
                                SECURE_UDP_VERSION
                            } else {
                                TRANSACTION_VERSION
                            },
                            ok: false,
                            code: "unsupported_version".into(),
                            state: None,
                        };
                        write_json(&mut stream, &reply, RESPONSE_LIMIT).await?;
                    }
                    ReplyFailure::Lost => {}
                    ReplyFailure::Malformed => {
                        let body = br#"{"version":3,"ok":true,"code":"ok","state":null,"extra":1}"#;
                        stream
                            .write_u32(u32::try_from(body.len()).map_err(io::Error::other)?)
                            .await?;
                        stream.write_all(body).await?;
                    }
                    ReplyFailure::Oversized => {
                        stream.write_u32(8193).await?;
                    }
                }
            }
        });
        let result = request(
            &path,
            &Request {
                version: TRANSACTION_VERSION,
                action: Action::Reconnect {},
            },
        )
        .await;
        if matches!(mode, ReplyFailure::Refused) {
            let refused = result?;
            assert_eq!(refused.version, TRANSACTION_VERSION);
            assert!(!refused.ok);
            assert_eq!(refused.code, "unsupported_version");
        } else {
            assert!(result.is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let expected_effects = usize::from(!matches!(mode, ReplyFailure::Refused));
        assert_eq!(effects.load(Ordering::SeqCst), expected_effects);
        let observed = request(
            &path,
            &Request {
                version: TRANSACTION_VERSION,
                action: Action::Status {},
            },
        )
        .await?;
        assert_eq!(observed.code, format!("effects={expected_effects}"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(effects.load(Ordering::SeqCst), expected_effects);
        task.abort();
        let _cancelled = task.await;
    }
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
            version: SECURE_UDP_VERSION,
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
