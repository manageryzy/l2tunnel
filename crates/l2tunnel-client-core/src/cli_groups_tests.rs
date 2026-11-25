use super::*;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicU64, Ordering};

fn args(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}
fn parsed(text: &str) -> Command {
    parse(&args(text)).map_or_else(
        |Usage(message)| panic_free(message),
        |parsed| parsed.command,
    )
}
// Tests must not use panic!/unwrap; a usage error becomes an impossible command.
fn panic_free(message: String) -> Command {
    Command::Show(u64::MAX, Some(ServiceId(message.len() as u64)))
}

#[test]
fn grouped_commands_parse_strictly() {
    assert_eq!(
        parsed("service status --control-socket /s"),
        Command::Status
    );
    assert_eq!(
        parsed("service reconnect --control-socket /s --request-key 7 --watch 5"),
        Command::Submit {
            action: Submission::Reconnect,
            key: Some(7),
            watch: Some(5)
        }
    );
    assert_eq!(
        parsed("service disconnect --detach --control-socket /s"),
        Command::Submit {
            action: Submission::Disconnect,
            key: None,
            watch: None
        }
    );
    assert_eq!(
        parsed("operation watch 4 --timeout 9 --service 00000000000000aa"),
        Command::Watch(4, Some(ServiceId(0xaa)), 9)
    );
    assert_eq!(
        parsed("events --follow --after 3"),
        Command::Events {
            after: 3,
            limit: 32,
            timeout: 0,
            follow: true,
            service: None
        }
    );
    assert_eq!(
        parsed("events --after 3 --service 0000000000000001"),
        Command::Events {
            after: 3,
            limit: 32,
            timeout: 0,
            follow: false,
            service: Some(ServiceId(1))
        }
    );
    assert_eq!(
        parsed("profile inspect --anything x"),
        Command::Delegate("inspect-common-transaction-plan")
    );
    assert_eq!(
        parsed("key generate --private p"),
        Command::Delegate("keygen")
    );
    for bad in [
        "service",
        "service frobnicate",
        "service status extra",
        "service status --json --json",
        "service reconnect --request-key 0",
        "service reconnect --watch 5 --detach",
        "service reconnect --watch 999999",
        "operation watch",
        "operation watch 0",
        "operation show 1 2",
        "operation show 1 --service ABC",
        "events --limit 33",
        "config catalog --generation 1 --catalog 00 --offset 0 --limit 1",
        "config catalog --generation 1 --catalog 0000000000000000000000000000000000000000000000000000000000000000 --offset 0 --limit 5",
        "config switch --configuration zz",
        "service status --control-socket",
    ] {
        assert!(parse(&args(bad)).is_err(), "{bad}");
    }
}

#[test]
fn exit_contract_matches_the_design_table() {
    assert_eq!(refusal_exit("unsupported"), Exit::Unsupported);
    assert_eq!(refusal_exit("unsupported_version"), Exit::Unsupported);
    assert_eq!(refusal_exit("cancel_unsupported"), Exit::Unsupported);
    assert_eq!(refusal_exit("service_restarted"), Exit::Unknown);
    assert_eq!(refusal_exit("expired"), Exit::Unknown);
    assert_eq!(refusal_exit("closed"), Exit::Unreachable);
    for code in [
        "busy",
        "conflict",
        "state",
        "future_key",
        "unknown_operation",
        "invalid_configuration",
    ] {
        assert_eq!(refusal_exit(code), Exit::Failed, "{code}");
    }
    assert_eq!(
        result_exit(&OperationResult::Connected { generation: 1 }),
        Exit::Completed
    );
    assert_eq!(result_exit(&OperationResult::Aborted), Exit::Completed);
    assert_eq!(result_exit(&OperationResult::Cancelled), Exit::Failed);
    assert_eq!(result_exit(&OperationResult::OutcomeUnknown), Exit::Unknown);
    assert_eq!(
        result_exit(&OperationResult::Failed {
            error_kind: "timed_out".into()
        }),
        Exit::Failed
    );
    let codes: Vec<u8> = [
        Exit::Completed,
        Exit::Failed,
        Exit::Usage,
        Exit::Unreachable,
        Exit::Running,
        Exit::Unknown,
        Exit::Unsupported,
    ]
    .iter()
    .map(|exit| *exit as u8)
    .collect();
    assert_eq!(codes, vec![0, 1, 2, 3, 4, 5, 6]);
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "l2t-ctl-{}-{}",
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
async fn invoke(socket: &std::path::Path, text: &str) -> Exit {
    let mut list = args(text);
    list.extend(["--control-socket".to_owned(), socket.display().to_string()]);
    match parse(&list) {
        Ok(parsed) => run(parsed).await,
        Err(_) => Exit::Usage,
    }
}

#[tokio::test]
async fn grouped_cli_reports_exact_exit_classes_against_a_real_service() -> io::Result<()> {
    let directory = Directory::new()?;
    let path = directory.socket();
    // Unreachable before the service exists.
    assert_eq!(invoke(&path, "service status").await, Exit::Unreachable);
    let server = local::Server::bind(&path)?;
    let (handle, run_owner) = crate::service::channel();
    let served = handle.clone();
    let task = tokio::spawn(async move { server.serve_service(served).await });
    assert_eq!(
        invoke(&path, "service status --json").await,
        Exit::Completed
    );
    assert_eq!(invoke(&path, "events").await, Exit::Completed);
    // Info always answers; metrics are refused without a running session.
    assert_eq!(invoke(&path, "service info").await, Exit::Completed);
    assert_eq!(invoke(&path, "service info --json").await, Exit::Completed);
    assert_eq!(invoke(&path, "stats show").await, Exit::Failed);
    assert_eq!(invoke(&path, "stats watch --count 1").await, Exit::Failed);
    // Without --state-dir the service has no device/route host.
    assert_eq!(invoke(&path, "device list").await, Exit::Unsupported);
    assert_eq!(invoke(&path, "route list").await, Exit::Unsupported);
    assert_eq!(
        invoke(&path, "device create l2t0 --layer tun --detach").await,
        Exit::Unsupported
    );
    let stale = format!("events --service {:016x}", handle.instance() ^ 1);
    assert_eq!(invoke(&path, &stale).await, Exit::Unknown);
    // No retained plan: the service refuses the submission.
    assert_eq!(invoke(&path, "service reconnect").await, Exit::Failed);
    assert_eq!(invoke(&path, "operation show 9").await, Exit::Failed);
    let operation = handle.seed_pending_setup_for_test();
    let id = operation.value();
    // A watch deadline reports a still-running operation without cancelling it.
    assert_eq!(
        invoke(&path, &format!("operation watch {id} --timeout 0")).await,
        Exit::Running
    );
    assert_eq!(
        invoke(&path, &format!("operation show {id}")).await,
        Exit::Completed
    );
    let wrong = format!(
        "operation show {id} --service {:016x}",
        handle.instance() ^ 1
    );
    assert_eq!(invoke(&path, &wrong).await, Exit::Unknown);
    let finisher = {
        let handle = handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            handle.finish_for_test(operation, crate::service::Completed::OutcomeUnknown);
        })
    };
    assert_eq!(
        invoke(&path, &format!("operation watch {id} --timeout 10")).await,
        Exit::Unknown
    );
    let _ = finisher.await;
    assert_eq!(
        invoke(&path, &format!("operation cancel {id}")).await,
        Exit::Failed
    );
    task.abort();
    let _cancelled = task.await;
    drop(run_owner);

    // A handler-only endpoint answers version 5 as unsupported.
    let other = Directory::new()?;
    let path = other.socket();
    let server = local::Server::bind(&path)?;
    let task = tokio::spawn(async move {
        server
            .serve(|request| async move {
                local::Response {
                    version: request.version,
                    ok: true,
                    code: "ok".into(),
                    state: None,
                }
            })
            .await
    });
    assert_eq!(invoke(&path, "service status").await, Exit::Unsupported);
    task.abort();
    let _cancelled = task.await;
    Ok(())
}

#[test]
fn help_names_the_documented_windows_default_pipe() {
    assert!(HELP.contains(l2tunnel_platform_windows::local_pipe::DEFAULT_PIPE_NAME));
}

#[test]
fn info_and_stats_commands_parse_strictly() {
    assert_eq!(parsed("service info --control-socket /s"), Command::Info);
    assert_eq!(
        parsed("stats show --control-socket /s"),
        Command::Stats {
            watch: false,
            interval: 1,
            count: Some(1)
        }
    );
    assert_eq!(
        parsed("stats watch --interval 5 --count 3 --control-socket /s"),
        Command::Stats {
            watch: true,
            interval: 5,
            count: Some(3)
        }
    );
    for text in [
        "stats watch --interval 0",
        "stats watch --interval 61",
        "stats watch --count 0",
        "stats show --interval 2",
        "stats bogus",
        "service info extra",
    ] {
        assert!(parse(&args(text)).is_err(), "{text}");
    }
}

#[test]
fn stats_watch_rates_only_within_one_series() {
    use crate::local::{Metrics, WireCounters};
    let sample = |generation: u64, sampled_ms: u64, sent_bytes: u64| Metrics {
        generation,
        sampled_ms,
        carrier: "udp".into(),
        runtime_micros: None,
        wire: Some(WireCounters {
            sent_bytes,
            sent_packets: sent_bytes / 1000,
            ..WireCounters::default()
        }),
        device: None,
        selected_send_rate: None,
        selected_receive_rate: None,
        send_channels: None,
        receive_channels: None,
        rtt_micros: None,
        lanes: Vec::new(),
        channels: Vec::new(),
        flows: Vec::new(),
        unreported: Vec::new(),
    };
    let first = sample(1, 1_000, 0);
    assert!(super::stats::rate_line(None, &first).contains("new series"));
    let line = super::stats::rate_line(Some(&first), &sample(1, 2_000, 125_000));
    assert!(
        line.starts_with("sent 1000000 b/s · sent 125 pkt/s"),
        "{line}"
    );
    assert!(line.contains("device read — pkt/s"), "{line}");
    let restarted = super::stats::rate_line(Some(&first), &sample(2, 2_000, 5));
    assert!(restarted.contains("new series"));
}

#[test]
fn device_and_route_commands_parse_strictly() {
    use crate::local::{DeviceChange, DeviceLayer, RouteChange};
    assert_eq!(
        parsed("device list --control-socket /s"),
        Command::DeviceList
    );
    assert_eq!(parsed("route list --control-socket /s"), Command::RouteList);
    assert_eq!(
        parsed(
            "device create l2t0 --layer tap --mtu 1400 --addresses 10.88.0.2/24,fd00::2/64 --down --detach --control-socket /s"
        ),
        Command::Submit {
            action: Submission::Device(DeviceChange::Create {
                name: "l2t0".into(),
                layer: DeviceLayer::Tap,
                mtu: Some(1400),
                addresses: vec!["10.88.0.2/24".into(), "fd00::2/64".into()],
                up: false,
            }),
            key: None,
            watch: None,
        }
    );
    assert_eq!(
        parsed("route default on --device l2t0 --request-key 4 --control-socket /s"),
        Command::Submit {
            action: Submission::Route(RouteChange::Default {
                enabled: true,
                device: "l2t0".into(),
            }),
            key: Some(4),
            watch: Some(DEFAULT_WATCH_SECONDS),
        }
    );
    for text in [
        "device list extra",
        "device create l2t0",
        "device create l2t0 --layer tunnel",
        "device create bad/name --layer tun",
        "device create l2t0 --layer tun --addresses 10.0.0.1",
        "device configure l2t0 --up --down",
        "device delete",
        "device delete a b",
        "route add 10.0.0.0/8",
        "route add 10.0.0.0/33 --device l2t0",
        "route default maybe --device l2t0",
        "route bogus --device l2t0",
        "device create l2t0 --layer tun --gateway 1.2.3.4",
    ] {
        assert!(parse(&args(text)).is_err(), "{text}");
    }
}

#[test]
fn service_start_builds_the_shared_elevated_request() {
    let program = "/opt/l2t/l2tunnel-linux";
    let mut expected = local::elevate::StartRequest::new(PathBuf::from(program));
    expected.terminal = true;
    expected.wait = Duration::from_secs(9);
    assert_eq!(
        parsed(&format!("service start --program {program} --wait 9")),
        Command::Start(Box::new(expected.clone()))
    );
    expected.install = Some(Vec::new());
    assert_eq!(
        parsed(&format!(
            "service start --program {program} --wait 9 --install --json"
        )),
        Command::Start(Box::new(expected))
    );
    for refused in [
        "service start --program /p --wait 0",
        "service start --program /p --wait 601",
        "service start --program /p --address 10.0.0.1/24",
        "service start --program /p --install --address 10.0.0.1/24",
        "service start --program /p extra",
        "service start --program /p --request-key 3",
    ] {
        assert!(parse(&args(refused)).is_err(), "{refused}");
    }
}
