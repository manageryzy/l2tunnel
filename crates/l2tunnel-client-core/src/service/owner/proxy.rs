use super::super::proxy_backend::Backend;
use super::*;
use l2tunnel_runtime::proxy as runtime;
use std::sync::Arc;

/// Authenticate through the existing factories without starting child I/O.
/// The service retains Active before its first poll so readiness cancellation
/// cannot drop a spawned JoinSet and misreport it as completed release.
pub(super) async fn fixed(
    shared: &Shared,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    settings: Arc<crate::proxy::Settings>,
) -> io::Result<Active> {
    let session = match &plan.data.endpoint {
        Endpoint::Client(client) => {
            crate::proxy::connect(
                client.remote,
                &client.tls,
                &client.server_name,
                &client.member,
                plan.data.connection,
                &settings,
            )
            .await?
        }
        Endpoint::Server(server) => {
            let listener = listen(shared, server, accepted, deadline).await?;
            crate::proxy::accept(
                &listener,
                &server.tls,
                &server.members,
                plan.data.connection,
                &settings,
            )
            .await?
        }
        #[cfg(unix)]
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prepared proxy endpoint mismatch",
            ));
        }
    };
    check(deadline)?;
    let requested = runtime::session_config(&crate::proxy::runtime_config(
        plan.data.connection,
        &settings,
    )?)?
    .digest;
    let effective = runtime::session_config(session.config())?.digest;
    if requested != effective {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy authenticated policy mismatch",
        ));
    }
    let device = plan.open()?;
    check(deadline)?;
    let (handle, control) = crate::proxy::control_channel();
    let backend = Arc::new(Backend::fixed(
        handle,
        requested,
        effective,
        session.config(),
    ));
    let observed = backend.clone();
    let runtime = Box::pin(async move {
        let result = session.run_service_owned(device, control).await;
        observed.finished(&result);
        result.map(|_| ())
    });
    Ok(Active {
        runtime,
        backend: ObservedBackend::Proxy(backend),
        generation: accepted.operation,
    })
}

pub(super) async fn measured(
    shared: &Shared,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    settings: Arc<crate::proxy_measured::Settings>,
) -> io::Result<Active> {
    let session = match &plan.data.endpoint {
        Endpoint::Client(client) => {
            crate::proxy_measured::connect(
                client.remote,
                &client.tls,
                &client.server_name,
                &client.member,
                plan.data.connection,
                &settings,
            )
            .await?
        }
        Endpoint::Server(server) => {
            let listener = listen(shared, server, accepted, deadline).await?;
            crate::proxy_measured::accept(
                &listener,
                &server.tls,
                &server.members,
                plan.data.connection,
                &settings,
            )
            .await?
        }
        #[cfg(unix)]
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prepared measured proxy endpoint mismatch",
            ));
        }
    };
    check(deadline)?;
    let requested = runtime::measured::session_config(&crate::proxy_measured::runtime_config(
        plan.data.connection,
        &settings,
    )?)?
    .digest;
    let effective = runtime::measured::session_config(session.config())?.digest;
    if requested != effective {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "measured proxy authenticated policy mismatch",
        ));
    }
    let device = plan.open()?;
    check(deadline)?;
    let (handle, control) = crate::proxy_measured::control_channel();
    let backend = Arc::new(Backend::measured(
        handle,
        requested,
        effective,
        &session.config().fixed,
    ));
    let observed = backend.clone();
    let runtime = Box::pin(async move {
        let result = session.run_service_owned(device, control).await;
        observed.finished(&result);
        result.map(|_| ())
    });
    Ok(Active {
        runtime,
        backend: ObservedBackend::Proxy(backend),
        generation: accepted.operation,
    })
}

async fn listen(
    shared: &Shared,
    server: &prepared::Server,
    accepted: Accepted,
    deadline: Instant,
) -> io::Result<TcpListener> {
    check(deadline)?;
    let listener = TcpListener::bind(server.listen).await?;
    check(deadline)?;
    shared.lock().snapshot.listening = Some(Listening {
        operation: accepted.operation,
        address: listener.local_addr()?,
    });
    shared.changed();
    Ok(listener)
}

pub(super) async fn ready(
    shared: &Shared,
    session: &mut Active,
    accepted: Accepted,
) -> io::Result<()> {
    let ObservedBackend::Proxy(backend) = &session.backend else {
        return Err(io::Error::other("non-proxy readiness owner"));
    };
    let deadline = accepted.deadline.ok_or_else(expired)?;
    loop {
        check(deadline)?;
        if cancelled(shared, accepted.operation) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "proxy setup cancelled",
            ));
        }
        let ready = std::future::poll_fn(|cx| {
            if let Poll::Ready(result) = session.runtime.as_mut().poll(cx) {
                return Poll::Ready(result.and_then(|()| {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "proxy stopped before readiness",
                    ))
                }));
            }
            if backend.ready() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        });
        tokio::pin!(ready);
        tokio::select! {
            result = &mut ready => { result?; check(deadline)?; return Ok(()); }
            () = shared.wake.notified() => {}
            () = tokio::time::sleep_until(deadline) => return Err(expired()),
        }
    }
}

/// Drive the SAME runtime until its children are actually joined. The original
/// operation cap remains finite; expiry returns while leaving Active retained.
pub(super) async fn stop(session: &mut Active, accepted: Option<Instant>) -> io::Result<()> {
    let ObservedBackend::Proxy(backend) = &session.backend else {
        return Ok(());
    };
    if backend.released() {
        return accepted.map_or(Ok(()), check);
    }
    let deadline = backend.begin_release(accepted)?;
    // Start the original abort even after expiry, but never poll a late cleanup
    // as though it could complete this expired operation successfully.
    let _ = backend.drive_abort();
    check(deadline)?;
    let release = std::future::poll_fn(|cx| {
        if let Err(error) = backend.drive_abort()
            && !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::BrokenPipe
            )
        {
            return Poll::Ready(Err(error));
        }
        if let Poll::Ready(result) = session.runtime.as_mut().poll(cx) {
            return Poll::Ready(match result {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(()),
                other => other,
            });
        }
        Poll::Pending
    });
    let result = tokio::time::timeout_at(deadline, release)
        .await
        .map_err(|_| expired())?;
    // A ready inner future may have crossed the cap during synchronous cleanup.
    check(deadline)?;
    result
}

pub(super) fn retain_releasing(shared: &Shared, session: &Active) {
    let mut state = shared.lock();
    state.backend = Some(session.backend.clone());
    state.snapshot.generation = Some(session.generation);
    state.snapshot.runtime = session.backend.observe();
    state.snapshot.listening = None;
    state.snapshot.phase = Phase::Failed;
    drop(state);
    shared.changed();
}

/// Readiness and cancellation are serialized with the same retained service
/// entry; failed publication returns the actual owner for observed cleanup.
pub(super) enum Publication {
    Ready(Active),
    Cancelled(Active),
    Expired(Active),
}
pub(super) fn publish(shared: &Shared, session: Active, accepted: Accepted) -> Publication {
    let state = shared.lock();
    if accepted
        .deadline
        .is_none_or(|deadline| Instant::now() >= deadline)
    {
        drop(state);
        Publication::Expired(session)
    } else if state
        .entries
        .iter()
        .any(|entry| entry.accepted.operation == accepted.operation && entry.cancel)
    {
        drop(state);
        Publication::Cancelled(session)
    } else {
        Publication::Ready(commit_ready(shared, state, session, accepted))
    }
}

pub(super) fn apply(
    shared: &Arc<Shared>,
    backend: &Backend,
    request: &local::Request,
) -> Completed {
    let response = match request.action {
        local::Action::DrainProxy {} => match backend.request_drain() {
            Ok(code) => Handle::proxy_status_from(Handle(shared.clone()).snapshot(), true, code),
            Err(error) => Handle::proxy_status_from(
                Handle(shared.clone()).snapshot(),
                false,
                if error.kind() == io::ErrorKind::WouldBlock {
                    "busy"
                } else {
                    "closed"
                },
            ),
        },
        _ => Handle::proxy_status_from(Handle(shared.clone()).snapshot(), false, "unsupported"),
    };
    if response.ok {
        Completed::Applied(response)
    } else {
        Completed::Rejected(response)
    }
}

pub(super) fn retain_or_stop(shared: &Shared, active: &mut Option<Active>, kind: io::ErrorKind) {
    if let Some(session) = active.as_ref()
        && matches!(&session.backend, ObservedBackend::Proxy(backend) if backend.awaiting_release())
    {
        retain_releasing(shared, session);
    } else {
        stopped(shared, active, Terminal::Failed(Failure { kind }));
    }
}
