#[cfg(unix)]
pub(super) mod maintained;
#[cfg(unix)]
pub(super) mod raw;
use super::super::proxy_backend::Backend;
use super::*;
#[cfg(unix)]
use l2tunnel_runtime::proxy as runtime;
use std::sync::Arc;

pub(super) async fn ready(
    shared: &Shared,
    session: &mut Active,
    accepted: Accepted,
) -> io::Result<()> {
    let ObservedBackend::Proxy(backend) = &session.backend else {
        return Err(io::Error::other("non-proxy readiness owner"));
    };
    let deadline = accepted.deadline.ok_or_else(expired)?;
    #[cfg(unix)]
    setup::stage(shared, accepted.operation, SetupStage::DriverReadiness);
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

/// Reuse the original Common authentication factory and the same proxy lifecycle.
/// The returned future is retained by Active before readiness starts child work.
#[cfg(unix)]
pub(super) async fn common(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    profile: Arc<crate::secure_udp::common_transaction_profile::Profile>,
) -> io::Result<Active> {
    let config = profile.proxy_config().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing explicit Common proxy policy",
        )
    })?;
    let measured = profile.proxy_measured_config().cloned();
    let digest = match &measured {
        Some(config) => runtime::measured::session_config(config)?.digest,
        None => runtime::session_config(&config)?.digest,
    };
    let CommonAuthenticated {
        parts,
        info,
        contract,
        requested,
        carrier,
    } = authenticate_common(shared, plan, accepted, deadline, &profile).await?;
    setup::stage(shared, accepted.operation, SetupStage::Attachment);
    let device = plan.open()?;
    check(deadline)?;
    let frame = ProxyCommonFrame {
        requested_configuration: requested,
        effective_configuration: l2tunnel_security::ConfigDigest(info.authenticated.configuration),
        requested_carrier: carrier,
        effective_carrier: info.authenticated.carrier,
        requested_cover: profile.settings().cover.appearance,
        effective_cover: None,
        compact_wire: Some(
            crate::secure_udp::common_status::CompactWireStatus::observe(
                profile.compact_wire(),
                None,
            )?,
        ),
        maintained_request: None,
        maintained: None,
        local_addr: info.local_addr,
        peer_addr: info.peer_addr,
        installed: false,
        running: false,
        epoch: None,
        liveness: Default::default(),
        hot_switch: false,
        socket_accepted_packets: 0,
        socket_accepted_ip_bytes: 0,
        graceful_close: profile.proxy_retirement(),
    };
    let observe = |backend: &Arc<Backend>| {
        let sink = backend.clone();
        let changed = shared.clone();
        move |snapshot: &l2tunnel_runtime::secure_udp::transport::CommonSnapshot| {
            sink.observe_common(snapshot);
            changed.changed();
        }
    };
    type Driver =
        Pin<Box<dyn std::future::Future<Output = io::Result<runtime::CloseReport>> + Send>>;
    let (backend, driver): (Arc<Backend>, Driver) = match measured {
        Some(config) => {
            let (handle, control) = crate::proxy_measured::control_channel();
            let backend = Arc::new(Backend::common_measured(
                handle,
                digest,
                &config.fixed,
                frame,
            ));
            let driver = runtime::common::run_measured(
                device,
                parts,
                contract,
                config,
                control,
                None,
                observe(&backend),
            );
            (backend, Box::pin(driver))
        }
        None => {
            let (handle, control) = crate::proxy::control_channel();
            let backend = Arc::new(Backend::common(handle, digest, &config, frame));
            let driver = runtime::common::run(
                device,
                parts,
                contract,
                config,
                control,
                None,
                observe(&backend),
            );
            (backend, Box::pin(driver))
        }
    };
    let observed = backend.clone();
    let runtime = Box::pin(async move {
        let result = driver.await;
        observed.finished(&result);
        result.map(|_| ())
    });
    Ok(Active {
        runtime,
        backend: ObservedBackend::Proxy(backend),
        generation: accepted.operation,
    })
}

// Release authentication polling and its large setup scratch before the same
// eager Common/Engine constructor runs. No new Driver, task or protocol owner.
#[cfg(unix)]
struct CommonAuthenticated {
    parts: l2tunnel_runtime::secure_udp::member::Parts,
    info: l2tunnel_runtime::secure_udp::member::Info,
    contract: l2tunnel_runtime::secure_udp::transport::CommonTransactionContract,
    requested: l2tunnel_security::ConfigDigest,
    carrier: [u8; 32],
}

#[cfg(unix)]
fn authenticate_common<'a>(
    shared: &'a Arc<Shared>,
    plan: &'a Prepared,
    accepted: Accepted,
    deadline: Instant,
    profile: &'a crate::secure_udp::common_transaction_profile::Profile,
) -> Pin<Box<dyn std::future::Future<Output = io::Result<CommonAuthenticated>> + Send + 'a>> {
    Box::pin(async move {
        let session = authenticate_selected_secure_udp(
            shared,
            plan,
            accepted,
            deadline,
            profile.settings(),
            Some(profile),
        )
        .await?;
        let info = session.info();
        setup::stage(shared, accepted.operation, SetupStage::Configuration);
        // A tuned session switches within the catalog both ends generated.
        let contract = match session.live_catalog() {
            Some(catalog) => profile
                .with_live_catalog(catalog.clone())?
                .runtime_contract(info.role)?,
            None => profile.runtime_contract(info.role)?,
        };
        let requested = profile.configuration()?;
        let carrier = profile.establish_config(info.role)?.binding.carrier;
        if info.peers != profile.peers()
            || info.authenticated.configuration != requested.0
            || info.authenticated.configuration != contract.expected_configuration().0
            || info.authenticated.carrier != carrier
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "actual Common authentication differs from explicit proxy plan",
            ));
        }
        check(deadline)?;
        let parts = session.into_parts();
        Ok(CommonAuthenticated {
            parts,
            info,
            contract,
            requested,
            carrier,
        })
    })
}
