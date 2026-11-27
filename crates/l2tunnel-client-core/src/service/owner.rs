use super::*;
use prepared::{Endpoint, Transport};
use std::task::Poll;
mod common;
mod proxy;
pub(super) struct Active {
    runtime: RunFuture,
    backend: ObservedBackend,
    generation: OperationId,
}
fn cancelled(shared: &Shared, id: OperationId) -> bool {
    shared
        .lock()
        .entries
        .iter()
        .any(|e| e.accepted.operation == id && e.cancel)
}
pub(super) fn finish(shared: &Shared, id: OperationId, result: Completed) {
    let mut state = shared.lock();
    let failed = matches!(result, Completed::Failed(_))
        || (state.backend.is_none()
            && matches!(state.snapshot.terminal, Some(Terminal::Failed(_))));
    state.snapshot.operation = None;
    if state.backend.is_none() {
        state.snapshot.listening = None;
    }
    // A device or route change never changes the session phase.
    let host_change = state.entries.iter().any(|entry| {
        entry.accepted.operation == id
            && matches!(
                entry.fingerprint,
                Fingerprint::Host(_) | Fingerprint::Profile(_)
            )
    });
    state.snapshot.phase = if host_change {
        state.snapshot.phase
    } else if matches!(&state.backend, Some(ObservedBackend::Proxy(backend)) if backend.awaiting_release())
    {
        Phase::Failed
    } else if state.backend.is_some() {
        Phase::Connected
    } else if failed {
        Phase::Failed
    } else {
        Phase::Disconnected
    };
    if let Some(entry) = state
        .entries
        .iter_mut()
        .find(|e| e.accepted.operation == id)
    {
        if let Some(record) = &mut entry.setup {
            record.complete(&result, entry.accepted, Instant::now());
        }
        entry.result = Some(result);
    }
    drop(state);
    shared.changed();
}
fn stopped(shared: &Shared, active: &mut Option<Active>, terminal: Terminal) -> &'static str {
    let generation = active.as_ref().map(|a| a.generation);
    let observation = active.as_ref().and_then(|a| a.backend.observe());
    let reason = recovery::classify_stop_reason(observation.as_ref(), terminal);
    let proxy_close_report = observation
        .as_ref()
        .and_then(Observation::proxy)
        .and_then(|frame| match (&frame.terminal, terminal) {
            (Some(local::ProxyTerminal::Closed { report }), Terminal::Closed) if frame.released => {
                Some(report.clone())
            }
            _ => None,
        });
    // Managed branches and the inline base UDP runtime own their I/O futures
    // without spawned children. Drop every original socket/device owner before
    // publishing release or reconnect.
    drop(active.take());
    // Routes and SOCKS5 listeners belong to this session; release them on end.
    shared.socks.stop_listener();
    if generation.is_some()
        && let Some(host) = shared.host.get()
    {
        host.session_ended();
    }
    let mut state = shared.lock();
    state.backend = None;
    state.snapshot.runtime = observation;
    if let Some(observation) = &mut state.snapshot.runtime {
        observation.record_service_terminal(terminal);
    }
    state.snapshot.listening = None;
    if let Some(generation) = generation {
        if state.terminals.len() == RETAINED {
            state.terminals.pop_front();
        }
        state.terminals.push_back(TerminalRecord {
            generation,
            terminal,
            proxy_close_report,
        });
        state.snapshot.terminal = Some(terminal);
        state.terminal_reason = Some(reason.to_owned());
    }
    if state.snapshot.operation.is_none() {
        state.snapshot.phase = match terminal {
            Terminal::Failed(_) => Phase::Failed,
            _ => Phase::Disconnected,
        };
    }
    drop(state);
    shared.changed();
    reason
}
fn failed(error: io::Error) -> Completed {
    #[cfg(test)]
    eprintln!("shared service setup failed: {error:?}");
    Completed::Failed(Failure { kind: error.kind() })
}
fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "original accepted service setup deadline",
    )
}
fn check(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(expired())
    } else {
        Ok(())
    }
}
// Keep the existing one setup allocation at the selected backend boundary.
// A single async dispatch union otherwise retains the largest unused backend's
// poll scratch while Common eagerly constructs its actual reserved Driver.
type SetupFuture = Pin<Box<dyn Future<Output = io::Result<Active>> + Send>>;

fn begin_setup(shared: &Shared, accepted: Accepted) -> io::Result<Instant> {
    let deadline = accepted.deadline.ok_or_else(expired)?;
    check(deadline)?;
    shared.lock().snapshot.phase = Phase::Authenticating;
    shared.changed();
    Ok(deadline)
}

pub(super) fn establish(shared: Arc<Shared>, plan: Prepared, accepted: Accepted) -> SetupFuture {
    // Every selected future performs its original cap/phase transition on first
    // poll. Selection itself starts no I/O, attachment or authentication work.
    macro_rules! selected {
        ($deadline:ident, $setup:expr) => {
            Box::pin(async move {
                let $deadline = begin_setup(&shared, accepted)?;
                let result = tokio::time::timeout_at($deadline, $setup)
                    .await
                    .map_err(|_| expired())?;
                check($deadline)?;
                result
            }) as SetupFuture
        };
    }
    match plan.data.transport.clone() {
        #[cfg(unix)]
        Transport::ProxyCommon(profile) => selected!(
            deadline,
            proxy::common(&shared, &plan, accepted, deadline, profile)
        ),
        #[cfg(unix)]
        Transport::ProxyCommonMaintained(profile) => selected!(
            deadline,
            proxy::maintained::common(&shared, &plan, accepted, deadline, profile)
        ),
        #[cfg(unix)]
        Transport::ProxyCommonRaw {
            profile,
            raw,
            opener,
        } => selected!(
            deadline,
            proxy::raw::common(&shared, &plan, accepted, deadline, profile, raw, opener)
        ),
        Transport::SecureUdpCommon(profile) => selected!(
            deadline,
            common::establish(&shared, &plan, accepted, deadline, profile)
        ),
        #[cfg(any(unix, windows))]
        Transport::SecureUdpCommonMaintained(profile) => selected!(
            deadline,
            common::maintained::establish(&shared, &plan, accepted, deadline, profile)
        ),
        #[cfg(unix)]
        Transport::SecureUdpCommonRaw {
            profile,
            raw,
            opener,
        } => selected!(
            deadline,
            common::raw::establish(&shared, &plan, accepted, deadline, profile, raw, opener)
        ),
        #[cfg(any(unix, windows))]
        Transport::SecureUdpCommonCarrier { profile, outer } => selected!(
            deadline,
            common::carrier::establish(&shared, &plan, accepted, deadline, profile, *outer)
        ),
    }
}

async fn authenticate_selected_secure_udp(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    selected: crate::secure_udp::Settings,
    common: Option<&crate::secure_udp::common_transaction_profile::Profile>,
) -> io::Result<crate::secure_udp::Session> {
    use l2tunnel_runtime::secure_udp::establish;
    use l2tunnel_security::Role;
    let role = match &plan.data.endpoint {
        Endpoint::SecureClient(_) => Role::Initiator,
        Endpoint::SecureServer(_) => Role::Responder,
        #[cfg(any(unix, windows))]
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing explicit Noise credentials",
            ));
        }
    };
    let (local, peer) = match role {
        Role::Initiator => (selected.gate.path.client, selected.gate.path.server),
        Role::Responder => (selected.gate.path.server, selected.gate.path.client),
    };
    check(deadline)?;
    setup::stage(shared, accepted.operation, SetupStage::SocketBind);
    let socket = tokio::net::UdpSocket::bind(local).await.inspect_err(|_| {
        setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
    })?;
    if let Some(protect) = &plan.udp_socket_protector {
        protect(&socket).await.inspect_err(|_| {
            setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
        })?;
        check(deadline)?;
    }
    setup::stage(shared, accepted.operation, SetupStage::SocketConnect);
    if !(role == Role::Responder && selected.gate.path.is_dynamic_client()) {
        socket.connect(peer).await.inspect_err(|_| {
            setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
        })?;
    }
    check(deadline)?;
    if role == Role::Responder {
        shared.lock().snapshot.listening = Some(Listening {
            operation: accepted.operation,
            address: socket.local_addr()?,
        });
        shared.changed();
    }
    let mut entropy = establish::RuntimeEntropy::new();
    let mut observe = |value| setup::runtime(shared, accepted.operation, value);
    let session = match &plan.data.endpoint {
        Endpoint::SecureClient(credentials) => {
            if let Some(profile) = common {
                crate::secure_udp::connect_common_observed(
                    socket,
                    profile,
                    credentials.noise().attempt(),
                    credentials.member(),
                    credentials.admission(),
                    deadline,
                    &mut entropy,
                    &mut observe,
                )
                .await?
            } else {
                crate::secure_udp::connect_observed(
                    socket,
                    selected,
                    credentials.noise().attempt(),
                    credentials.member(),
                    credentials.admission(),
                    deadline,
                    &mut entropy,
                    &mut observe,
                )
                .await?
            }
        }
        Endpoint::SecureServer(server) => {
            // This owner survives cancellation and every reconnect of this plan.
            setup::stage(shared, accepted.operation, SetupStage::AdmissionOwner);
            let mut admission = server.admission.lock().await;
            check(deadline)?;
            if admission.is_none() {
                setup::stage(shared, accepted.operation, SetupStage::Configuration);
                *admission = Some(if let Some(profile) = common {
                    crate::secure_udp::Server::new_common(
                        profile,
                        server.credentials.noise().peers(role),
                        server.credentials.admission(),
                        server.credentials.cookie(),
                        Instant::now(),
                    )?
                } else {
                    crate::secure_udp::Server::new(
                        selected,
                        server.credentials.noise().peers(role),
                        server.credentials.admission(),
                        server.credentials.cookie(),
                        Instant::now(),
                    )?
                });
            }
            admission
                .as_mut()
                .ok_or_else(|| io::Error::other("missing retained admission owner"))?
                .accept_observed(
                    socket,
                    server.credentials.noise().attempt(),
                    deadline,
                    &mut entropy,
                    &mut observe,
                )
                .await?
        }
        #[cfg(any(unix, windows))]
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prepared endpoint/backend mismatch",
            ));
        }
    };
    check(deadline)?;
    Ok(session)
}
fn secure_udp_termination(
    reason: l2tunnel_runtime::secure_udp::transport::StopReason,
) -> io::Error {
    use l2tunnel_runtime::secure_udp::transport::StopReason;
    let kind = match reason {
        StopReason::Cancelled => io::ErrorKind::Interrupted,
        StopReason::LeaseExpired
        | StopReason::PeerTimeout
        | StopReason::NativeStall
        | StopReason::PolicyTimeout => io::ErrorKind::TimedOut,
        StopReason::Io(kind) => kind,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, "secure UDP runtime terminated")
}

// One commit point for cancellation, generation, profile and actual readiness.
// The helper is shared with a real-TLS late-cancel regression, not a test-only hook.
pub(super) fn publish_ready(
    shared: &Shared,
    session: Active,
    accepted: Accepted,
) -> Option<Active> {
    let state = shared.lock();
    if accepted
        .deadline
        .is_none_or(|deadline| Instant::now() >= deadline)
    {
        drop(state);
        drop(session);
        finish(shared, accepted.operation, failed(expired()));
        return None;
    }
    let cancelled = state
        .entries
        .iter()
        .any(|entry| entry.accepted.operation == accepted.operation && entry.cancel);
    if cancelled {
        drop(state);
        drop(session);
        finish(shared, accepted.operation, Completed::Cancelled);
        return None;
    }
    Some(commit_ready(shared, state, session, accepted))
}
fn commit_ready(
    shared: &Shared,
    mut state: events::StateGuard<'_>,
    session: Active,
    accepted: Accepted,
) -> Active {
    state.snapshot.listening = None;
    state.snapshot.runtime = session.backend.observe();
    state.backend = Some(session.backend.clone());
    state.snapshot.generation = Some(session.generation);
    state.connected_at = Some(Instant::now());
    state.snapshot.terminal = None;
    state.terminal_reason = None;
    state.snapshot.operation = None;
    state.snapshot.phase = Phase::Connected;
    if let Some(entry) = state
        .entries
        .iter_mut()
        .find(|entry| entry.accepted.operation == accepted.operation)
    {
        let result = Completed::Connected {
            generation: accepted.operation,
        };
        if let Some(record) = &mut entry.setup {
            record.complete(&result, entry.accepted, Instant::now());
        }
        entry.result = Some(result);
    }
    drop(state);
    shared.changed();
    session
}
pub(super) async fn run(shared: Arc<Shared>) -> io::Result<()> {
    let mut active: Option<Active> = None;
    loop {
        let job = shared.lock().queued.take();
        if let Some(Job { accepted, command }) = job {
            if cancelled(&shared, accepted.operation) {
                drop(command);
                finish(&shared, accepted.operation, Completed::Cancelled);
                continue;
            }
            match command {
                Command::Disconnect => {
                    shared.lock().recovery.cancel();
                    if let Some(session) = active.as_mut()
                        && matches!(session.backend, ObservedBackend::Proxy(_))
                        && let Err(error) = proxy::stop(session, accepted.deadline).await
                    {
                        proxy::retain_or_stop(&shared, &mut active, error.kind());
                        finish(&shared, accepted.operation, failed(error));
                        continue;
                    }
                    let _ = stopped(&shared, &mut active, Terminal::Aborted);
                    finish(&shared, accepted.operation, Completed::Aborted);
                }
                Command::Common(configuration) => {
                    let Some(session) = active.as_mut() else {
                        finish(&shared, accepted.operation, Completed::OutcomeUnknown);
                        continue;
                    };
                    let ObservedBackend::SecureUdpCommon(backend) = &session.backend else {
                        finish(&shared, accepted.operation, Completed::OutcomeUnknown);
                        continue;
                    };
                    let backend = backend.clone();
                    let apply = common::apply(&backend, configuration);
                    tokio::pin!(apply);
                    let result = tokio::select! {
                        result = &mut apply => result,
                        result = &mut session.runtime => {
                            let failure = Failure {
                                kind: result.err().map_or(io::ErrorKind::UnexpectedEof, |error| error.kind()),
                            };
                            stopped(&shared, &mut active, Terminal::Failed(failure));
                            Completed::OutcomeUnknown
                        }
                    };
                    finish(&shared, accepted.operation, result);
                }
                Command::ConnectionReuse(request) => {
                    let Some(session) = active.as_mut() else {
                        finish(&shared, accepted.operation, Completed::OutcomeUnknown);
                        continue;
                    };
                    let ObservedBackend::SecureUdpCommon(backend) = &session.backend else {
                        finish(&shared, accepted.operation, Completed::OutcomeUnknown);
                        continue;
                    };
                    let backend = backend.clone();
                    let Some(deadline) = accepted.deadline else {
                        finish(&shared, accepted.operation, Completed::OutcomeUnknown);
                        continue;
                    };
                    let apply = connection_reuse::apply(&backend, request, deadline);
                    tokio::pin!(apply);
                    let result = tokio::select! {
                        result = &mut apply => result,
                        result = &mut session.runtime => {
                            let failure = Failure {
                                kind: result.err().map_or(io::ErrorKind::UnexpectedEof, |error| error.kind()),
                            };
                            stopped(&shared, &mut active, Terminal::Failed(failure));
                            Completed::OutcomeUnknown
                        }
                    };
                    finish(&shared, accepted.operation, result);
                }
                Command::Connect(plan) | Command::Reconnect(plan) => {
                    shared.lock().recovery.cancel();
                    // An expired queued reconnect must not abort the still-live
                    // old generation before its original permission is checked.
                    if accepted
                        .deadline
                        .is_none_or(|deadline| Instant::now() >= deadline)
                    {
                        drop(plan);
                        finish(&shared, accepted.operation, failed(expired()));
                        continue;
                    }
                    if let Some(session) = active.as_mut()
                        && matches!(session.backend, ObservedBackend::Proxy(_))
                        && let Err(error) = proxy::stop(session, accepted.deadline).await
                    {
                        drop(plan);
                        proxy::retain_or_stop(&shared, &mut active, error.kind());
                        finish(&shared, accepted.operation, failed(error));
                        continue;
                    }
                    if active.is_some() {
                        let _ = stopped(&shared, &mut active, Terminal::Aborted);
                    }
                    let mut setup = establish(shared.clone(), plan, accepted);
                    let result = loop {
                        if cancelled(&shared, accepted.operation) {
                            break None;
                        }
                        tokio::select! {
                            result=&mut setup=>break Some(result),
                            ()=shared.wake.notified()=>{},
                        }
                    };
                    // Release partial setup owners before publishing cancellation.
                    drop(setup);
                    let result = match result {
                        None => Completed::Cancelled,
                        Some(Err(error)) => {
                            if cancelled(&shared, accepted.operation) {
                                Completed::Cancelled
                            } else {
                                failed(error)
                            }
                        }
                        Some(Ok(mut session)) => {
                            if matches!(session.backend, ObservedBackend::Proxy(_)) {
                                let ready = proxy::ready(&shared, &mut session, accepted).await;
                                let result = match ready {
                                    Ok(()) => match proxy::publish(&shared, session, accepted) {
                                        proxy::Publication::Ready(session) => {
                                            active = Some(session);
                                            continue;
                                        }
                                        proxy::Publication::Cancelled(session) => {
                                            active = Some(session);
                                            Completed::Cancelled
                                        }
                                        proxy::Publication::Expired(session) => {
                                            active = Some(session);
                                            failed(expired())
                                        }
                                    },
                                    Err(error) => {
                                        active = Some(session);
                                        if cancelled(&shared, accepted.operation) {
                                            Completed::Cancelled
                                        } else {
                                            failed(error)
                                        }
                                    }
                                };
                                let cleanup = proxy::stop(
                                    active.as_mut().ok_or_else(|| {
                                        io::Error::other("proxy cleanup lost owner")
                                    })?,
                                    accepted.deadline,
                                )
                                .await;
                                let result = match cleanup {
                                    Ok(()) => {
                                        stopped(&shared, &mut active, Terminal::Aborted);
                                        result
                                    }
                                    Err(error) => {
                                        proxy::retain_or_stop(&shared, &mut active, error.kind());
                                        failed(error)
                                    }
                                };
                                finish(&shared, accepted.operation, result);
                                continue;
                            }
                            if let Some(session) = publish_ready(&shared, session, accepted) {
                                active = Some(session);
                            }
                            continue;
                        }
                    };
                    finish(&shared, accepted.operation, result);
                }
                Command::Host(change) => {
                    let handle = Handle(shared.clone());
                    let result = match handle.host() {
                        Some(host) => {
                            let context = host::HostContext {
                                peer: handle.peer_address(),
                            };
                            host.apply(change, context).await
                        }
                        None => Err("no device/route host is attached to this service".into()),
                    };
                    finish(&shared, accepted.operation, Completed::Host(result));
                }
                Command::Stop => {
                    shared.lock().recovery.cancel();
                    if let Some(session) = active.as_mut()
                        && matches!(session.backend, ObservedBackend::Proxy(_))
                        && let Err(error) = proxy::stop(session, accepted.deadline).await
                    {
                        proxy::retain_or_stop(&shared, &mut active, error.kind());
                        finish(&shared, accepted.operation, failed(error));
                        continue;
                    }
                    let _ = stopped(&shared, &mut active, Terminal::Aborted);
                    // The process exits next: release session routes first.
                    if let Some(host) = shared.host.get() {
                        host.release().await;
                    }
                    finish(&shared, accepted.operation, Completed::Aborted);
                    if let Some(stop) = shared.stop.get() {
                        stop.send_replace(true);
                    }
                }
                Command::Profile(change) => {
                    let result = match shared.profiles.get() {
                        Some(store) => store.apply(change),
                        None => Err("no profile store is attached to this service".into()),
                    };
                    finish(&shared, accepted.operation, Completed::Profile(result));
                }
                Command::Apply(request) => {
                    let Some(session) = active.as_mut() else {
                        finish(
                            &shared,
                            accepted.operation,
                            Completed::Failed(Failure {
                                kind: io::ErrorKind::NotConnected,
                            }),
                        );
                        continue;
                    };
                    if let ObservedBackend::Proxy(backend) = &session.backend {
                        let result = proxy::apply(&shared, backend, &request);
                        finish(&shared, accepted.operation, result);
                        continue;
                    }
                    finish(
                        &shared,
                        accepted.operation,
                        Completed::Failed(Failure {
                            kind: io::ErrorKind::Unsupported,
                        }),
                    );
                }
            }
        } else if let Some(session) = active.as_mut() {
            if let ObservedBackend::Proxy(backend) = &session.backend {
                // An already expired operation may still own joining children.
                // Retry only its retained command; never create a new deadline.
                let _ = backend.drive_abort();
            }
            tokio::select! {
                ()=shared.wake.notified()=>{},
                result=&mut session.runtime=>{
                    if !shared.lock().claim_runtime_exit() {
                        // The accepted disconnect owns release. If its proxy path needs
                        // the driver's result, reuse this result without polling twice.
                        session.runtime = Box::pin(std::future::ready(result));
                        continue;
                    }
                    let clean = result.is_ok() && matches!(&session.backend,
                        ObservedBackend::Proxy(backend) if backend.clean_closed());
                    let terminal = if clean { Terminal::Closed } else {
                        Terminal::Failed(Failure { kind: result.err().map_or(io::ErrorKind::UnexpectedEof, |error| error.kind()) })
                    };
                    let reason = stopped(&shared, &mut active, terminal);
                    let scheduled = {
                        let mut state = shared.lock();
                        if let Some(role) = state.plan.as_ref().map(Prepared::role) {
                            state.recovery.schedule_on_stop(reason, role)
                        } else {
                            false
                        }
                    };
                    if scheduled {
                        shared.changed();
                    }
                },
            }
        } else {
            let next_retry = shared.lock().recovery.next_retry();
            if let Some((retry_at, _attempt, reason, role)) = next_retry {
                tokio::select! {
                    () = shared.wake.notified() => {
                        continue;
                    }
                    () = tokio::time::sleep_until(retry_at) => {}
                }
                let attempt_plan = {
                    let mut state = shared.lock();
                    if state.queued.is_some() {
                        None
                    } else if let (Some(_), Some(plan)) =
                        (state.recovery.take_due(), state.plan.clone())
                    {
                        let next_gen = state
                            .snapshot
                            .generation
                            .map_or(0, OperationId::value)
                            .max(1_000_000)
                            .saturating_add(1);
                        let accepted = Accepted {
                            operation: OperationId(next_gen),
                            deadline: Instant::now().checked_add(plan.setup_timeout()),
                        };
                        state.snapshot.phase = Phase::Authenticating;
                        state.snapshot.operation = None;
                        Some((plan, accepted))
                    } else {
                        None
                    }
                };
                let Some((plan, accepted)) = attempt_plan else {
                    continue;
                };
                shared.changed();
                let mut setup = establish(shared.clone(), plan, accepted);
                let result = loop {
                    if shared.lock().queued.is_some() {
                        break None;
                    }
                    tokio::select! {
                        result = &mut setup => break Some(result),
                        () = shared.wake.notified() => {},
                    }
                };
                drop(setup);
                match result {
                    None => {
                        // A user command arrived during automatic recovery; cancel and serve it.
                        shared.lock().recovery.cancel();
                        shared.changed();
                    }
                    Some(Ok(session)) => {
                        if matches!(session.backend, ObservedBackend::Proxy(_)) {
                            // Automatic recovery currently targets non-proxy Common sessions.
                            drop(session);
                            let mut state = shared.lock();
                            let exhausted = state.recovery.record_attempt_failure(reason, role);
                            if exhausted {
                                state.terminal_reason = Some("recovery_exhausted".into());
                            }
                            state.snapshot.phase = Phase::Failed;
                            drop(state);
                            shared.changed();
                        } else if let Some(ready) = publish_ready(&shared, session, accepted) {
                            shared.lock().recovery.mark_recovered();
                            shared.changed();
                            active = Some(ready);
                        }
                    }
                    Some(Err(_)) => {
                        let mut state = shared.lock();
                        state.snapshot.listening = None;
                        state.snapshot.phase = Phase::Failed;
                        let exhausted = state.recovery.record_attempt_failure(reason, role);
                        if exhausted {
                            state.terminal_reason = Some("recovery_exhausted".into());
                        }
                        drop(state);
                        shared.changed();
                    }
                }
            } else {
                shared.wake.notified().await;
            }
        }
    }
}
