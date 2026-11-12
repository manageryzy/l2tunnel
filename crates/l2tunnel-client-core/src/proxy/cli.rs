//! Explicit proxy selection and local submission/result separation.
use super::*;
use crate::proxy as client;

pub(super) const HELP: &str = "Fixed-credit proxy: --traffic proxy --proxy-policy JSON_FILE; TUN, TCP/TLS, frame records and compression off only. Both peers require the same explicit route/channel/TIME-WAIT policy. Default TIME-WAIT remains maintained. Optional private --control-socket supports status and drain-proxy. Drain acknowledges submission promptly; query status for the actual terminal result. After termination only local status remains for five seconds. No adaptive window or reload is implied. Measured relay targets require explicit --traffic proxy-measured --proxy-policy JSON_FILE; the same TUN/TCP/frame/compression restrictions apply. Native window qualification and hot reload remain unavailable.";

pub(super) fn selection(
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<&str>> {
    if !matches!(
        options.get("--traffic").map(String::as_str),
        Some("proxy" | "proxy-measured")
    ) {
        if options.contains_key("--proxy-policy") {
            return Err(input(
                "--proxy-policy requires explicit --traffic proxy or proxy-measured",
            ));
        }
        return Ok(None);
    }
    if config.layer != PacketLayer::Ip
        || config.compression != Compression::None
        || options.get("--carrier").is_some_and(|v| v != "tcp")
        || options
            .get("--record-profile")
            .is_some_and(|v| v != "frame")
        || [
            "--aligned-channels",
            "--quic-application-id",
            "--vxlan-bind",
            "--vxlan-peer",
            "--vni",
        ]
        .iter()
        .chain(UDP_OPTIONS)
        .chain(&ACTIVE_OPTIONS[1..])
        .chain(standalone::OPTIONS)
        .chain(packed_frontend::OPTIONS)
        .any(|key| options.contains_key(*key))
    {
        return Err(input(
            "proxy requires TUN/TCP/frame/compression off and no active/adaptive/aligned/UDP/FEC/standalone options",
        ));
    }
    required(options, "--device")?;
    client::runtime_config(
        config,
        &client::Settings::new(client::RoutePolicy::new(Vec::new())?),
    )?;
    Ok(Some(required(options, "--proxy-policy")?))
}

#[cfg(target_os = "linux")]
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    path: &str,
) -> io::Result<()> {
    if options.get("--traffic").map(String::as_str) == Some("proxy-measured") {
        return measured_frontend::execute(command, options, config, path).await;
    }
    let settings = client::Settings::from_json(&bounded_file(path, client::MAX_POLICY_BYTES)?)?;
    client::runtime_config(config, &settings)?;
    let device = DeviceSpec::parse(options, config)?;
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    let session = match command {
        "connect" => {
            let address = required(options, "--remote")?
                .parse()
                .map_err(|_| input("remote requires IP:PORT"))?;
            let tls =
                ClientTls::from_der_roots(&[bounded_file(required(options, "--ca")?, 65536)?])
                    .map_err(auth_error)?;
            let member =
                MemberKey::from_pkcs8(&bounded_file(required(options, "--identity")?, 4096)?)
                    .map_err(auth_error)?;
            client::connect(
                address,
                &tls,
                required(options, "--server-name")?,
                &member,
                config,
                &settings,
            )
            .await?
        }
        "serve" => {
            let address: SocketAddr = required(options, "--listen")?
                .parse()
                .map_err(|_| input("listen requires IP:PORT"))?;
            let tls = ServerTls::from_der(
                &[bounded_file(required(options, "--cert")?, 65536)?],
                &bounded_file(required(options, "--key")?, 65536)?,
            )
            .map_err(auth_error)?;
            let public: [u8; 32] = bounded_file(required(options, "--allow-key")?, 32)?
                .try_into()
                .map_err(|_| input("allow-key must contain exactly 32 raw bytes"))?;
            let allow = MemberAllowlist::new(&[MemberPublicKey(public)]).map_err(auth_error)?;
            let listener = TcpListener::bind(address).await?;
            client::accept(&listener, &tls, &allow, config, &settings).await?
        }
        _ => return Err(input("unsupported proxy command")),
    };
    let digest = l2tunnel_runtime::proxy::session_config(session.config())?
        .digest
        .0;
    let device = device.open(config)?;
    let (handle, control) = client::control_channel();
    println!(
        "Authenticated TUN {:?}; fixed-credit proxy over retained TCP/TLS; immutable route policy; forwarding packet device",
        config.duplex
    );
    serve(
        session.run(device, control),
        handle,
        digest,
        api,
        Duration::from_secs(5),
    )
    .await
    .map(|_| ())
}

#[cfg(unix)]
mod service {
    use super::*;
    use crate::local::{
        self, Action, ProxyCloseReport, ProxySnapshot, ProxyStatus, ProxyTerminal, Response,
        Snapshot,
    };
    use std::sync::{Arc, Mutex};

    pub(super) enum RuntimeHandle {
        Fixed(client::Handle),
        Measured(crate::proxy_measured::Handle, Duplex),
    }
    impl RuntimeHandle {
        fn observed(
            &self,
        ) -> (
            Option<l2tunnel_runtime::proxy::Status>,
            Option<crate::proxy_measured::LocalSnapshot>,
        ) {
            match self {
                Self::Fixed(handle) => (handle.status(), None),
                Self::Measured(handle, lanes) => {
                    let status = handle.status();
                    let measured = crate::proxy_measured::LocalSnapshot::observed(
                        *lanes,
                        status.as_ref().map(|s| &s.measurement),
                    );
                    (status.map(|s| s.runtime), Some(measured))
                }
            }
        }
        fn request_drain(&self) -> io::Result<client::DrainWaiter> {
            match self {
                Self::Fixed(handle) => handle.request_drain(),
                Self::Measured(handle, _) => handle.request_drain(),
            }
        }
    }
    struct State {
        handle: RuntimeHandle,
        digest: String,
        accepted: bool,
        terminal: Option<ProxyTerminal>,
    }
    impl State {
        fn snapshot(&self) -> Snapshot {
            let (status, measured) = self.handle.observed();
            let status = status.map(|s| ProxyStatus {
                phase: format!("{:?}", s.phase),
                flows: s.flows,
                active: s.active,
                stopped: s.stopped,
                retired: s.retired,
                queued_bytes: s.queued_bytes,
                queued_records: s.queued_records,
                transparent_admitted_bytes: s.transparent_admitted_bytes,
                transparent_admitted_packets: s.transparent_admitted_packets,
                native_confirmed_packets: s.native_confirmed_packets,
            });
            Snapshot {
                epoch: 1,
                phase: status
                    .as_ref()
                    .map_or_else(|| "Starting".into(), |s| s.phase.clone()),
                compression: local::Compression::Off,
                active: None,
                openvpn_drain: None,
                raw_packet: None,
                rolling: None,
                #[cfg(unix)]
                swift: None,
                proxy: Some(ProxySnapshot {
                    digest: self.digest.clone(),
                    drain_accepted: self.accepted,
                    runtime: status,
                    terminal: self.terminal.clone(),
                    measured,
                }),
            }
        }
        fn action(&mut self, request: local::Request) -> Response {
            let result = match request.action {
                Action::Status {} => Ok("ok"),
                Action::DrainProxy {} if self.terminal.is_some() => Err("closed"),
                Action::DrainProxy {} if self.accepted => Ok("already_accepted"),
                Action::DrainProxy {} => match self.handle.request_drain() {
                    Ok(waiter) => {
                        self.accepted = true;
                        drop(waiter);
                        Ok("accepted")
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err("busy"),
                    Err(_) => Err("closed"),
                },
                Action::SwitchCompression { .. }
                | Action::SwitchActivePolicy { .. }
                | Action::DrainOpenVpn {} => Err("unsupported"),
            };
            Response {
                version: local::VERSION,
                ok: result.is_ok(),
                code: result.unwrap_or_else(|s| s).into(),
                state: Some(self.snapshot()),
            }
        }
    }
    fn terminal(result: &io::Result<client::CloseReport>) -> ProxyTerminal {
        match result {
            Ok(r) => ProxyTerminal::Closed {
                report: ProxyCloseReport {
                    local_user_records: r.local_user_records,
                    peer_user_records: r.peer_user_records,
                    local_transparent_packets: r.local_transparent_packets,
                    native_confirmed_packets: r.native_confirmed_packets,
                    clean_flows: r.clean_flows,
                    stopped_flows: r.stopped_flows,
                    tls_lanes_closed: r.tls_lanes_closed,
                },
            },
            Err(e) => ProxyTerminal::Failed {
                error: e.to_string().chars().take(256).collect(),
            },
        }
    }
    pub(super) async fn serve<F>(
        run: F,
        handle: RuntimeHandle,
        digest: [u8; 32],
        api: Option<local::Server>,
        grace: Duration,
    ) -> io::Result<client::CloseReport>
    where
        F: std::future::Future<Output = io::Result<client::CloseReport>>,
    {
        let state = Arc::new(Mutex::new(State {
            handle,
            digest: digest.iter().map(|b| format!("{b:02x}")).collect(),
            accepted: false,
            terminal: None,
        }));
        let result = if let Some(api) = api {
            let handler = Arc::clone(&state);
            let service = api.serve(move |request| {
                let response = match handler.lock() {
                    Ok(mut state) => state.action(request),
                    Err(_) => Response {
                        version: local::VERSION,
                        ok: false,
                        code: "internal_state".into(),
                        state: None,
                    },
                };
                std::future::ready(response)
            });
            tokio::pin!(service);
            let result = tokio::select! {
                result=run => result,
                result=&mut service => return Err(result.err().unwrap_or_else(||io::Error::other("proxy API unexpectedly stopped"))),
            };
            let outcome = terminal(&result);
            state
                .lock()
                .map_err(|_| io::Error::other("proxy API state lock"))?
                .terminal = Some(outcome.clone());
            println!(
                "{}",
                serde_json::to_string(&outcome).map_err(io::Error::other)?
            );
            // This fixed local-only grace starts after the actual runtime future returned.
            tokio::select! { _=tokio::time::sleep(grace) => {}, _=&mut service => {} }
            result
        } else {
            let result = run.await;
            println!(
                "{}",
                serde_json::to_string(&terminal(&result)).map_err(io::Error::other)?
            );
            result
        };
        drop(state);
        result
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn accepted_waiter_drop_is_not_terminal_and_retries_do_not_resubmit() -> io::Result<()> {
            let (handle, _control) = client::control_channel();
            let mut state = State {
                handle: RuntimeHandle::Fixed(handle),
                digest: "ab".repeat(32),
                accepted: false,
                terminal: None,
            };
            let request = || local::Request {
                version: local::VERSION,
                action: Action::DrainProxy {},
            };
            let unsupported = state.action(local::Request {
                version: local::VERSION,
                action: Action::DrainOpenVpn {},
            });
            assert!(!unsupported.ok);
            assert_eq!(unsupported.code, "unsupported");
            let first = state.action(request());
            assert_eq!(first.code, "accepted");
            assert!(first.ok);
            assert!(state.terminal.is_none());
            for _ in 0..8 {
                assert_eq!(state.action(request()).code, "already_accepted");
            }
            // Only the original command occupies the bounded queue, even though its waiter was dropped.
            assert_eq!(
                state.handle.request_drain().err().map(|e| e.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            assert!(
                state
                    .snapshot()
                    .proxy
                    .is_some_and(|s| s.drain_accepted && s.terminal.is_none())
            );
            Ok(())
        }
        #[test]
        fn terminal_error_is_bounded_and_never_a_clean_close() -> io::Result<()> {
            let result = Err(io::Error::other("λ".repeat(1000)));
            let ProxyTerminal::Failed { error } = terminal(&result) else {
                return Err(io::Error::other("failure became closure"));
            };
            assert_eq!(error.chars().count(), 256);
            Ok(())
        }
    }
}
#[cfg(unix)]
pub(crate) async fn serve<F>(
    run: F,
    handle: client::Handle,
    digest: [u8; 32],
    api: Option<crate::local::Server>,
    grace: Duration,
) -> io::Result<client::CloseReport>
where
    F: std::future::Future<Output = io::Result<client::CloseReport>>,
{
    service::serve(
        run,
        service::RuntimeHandle::Fixed(handle),
        digest,
        api,
        grace,
    )
    .await
}
#[cfg(unix)]
pub(crate) async fn serve_measured<F>(
    run: F,
    handle: crate::proxy_measured::Handle,
    lanes: Duplex,
    digest: [u8; 32],
    api: Option<crate::local::Server>,
    grace: Duration,
) -> io::Result<client::CloseReport>
where
    F: std::future::Future<Output = io::Result<client::CloseReport>>,
{
    service::serve(
        run,
        service::RuntimeHandle::Measured(handle, lanes),
        digest,
        api,
        grace,
    )
    .await
}
#[path = "../proxy_measured/cli.rs"]
#[cfg(target_os = "linux")]
mod measured_frontend;
#[cfg(all(test, unix))]
pub(crate) use serve as serve_for_test;

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
