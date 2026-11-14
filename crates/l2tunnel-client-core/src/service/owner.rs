use super::*;
use prepared::{Endpoint, Transport};
use std::task::Poll;
use tokio::net::TcpListener;
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
fn finish(shared: &Shared, id: OperationId, result: Completed) {
    let mut state = shared.lock();
    let failed = matches!(result, Completed::Failed(_))
        || (state.backend.is_none()
            && matches!(state.snapshot.terminal, Some(Terminal::Failed(_))));
    state.snapshot.operation = None;
    if state.backend.is_none() {
        state.snapshot.listening = None;
    }
    state.snapshot.phase = if state.backend.is_some() {
        Phase::Connected
    } else if failed {
        Phase::Failed
    } else {
        Phase::Disconnected
    };
    #[cfg(unix)]
    let mut result = result;
    #[cfg(unix)]
    if let Completed::Applied(response) | Completed::Rejected(response) = &mut result
        && response.version == local::TRANSACTION_VERSION
    {
        // Retain the completed reply from the same settled lifecycle snapshot.
        // Legacy replies preserve their existing projection and wire bytes.
        *response = Handle::transaction_status_from(
            Handle::snapshot_locked(&state),
            response.ok,
            &response.code,
        );
    }
    if let Some(entry) = state
        .entries
        .iter_mut()
        .find(|e| e.accepted.operation == id)
    {
        #[cfg(unix)]
        if let Some(record) = &mut entry.setup {
            record.complete(&result, entry.accepted, Instant::now());
        }
        entry.result = Some(result);
    }
    drop(state);
    shared.changed();
}
fn stopped(shared: &Shared, active: &mut Option<Active>, terminal: Terminal) {
    let generation = active.as_ref().map(|a| a.generation);
    let backend = active.as_ref().map(|a| a.backend.clone());
    // Managed branches and the inline base UDP runtime own their I/O futures
    // without spawned children. Drop every original socket/device owner before
    // publishing release or reconnect.
    drop(active.take());
    let mut state = shared.lock();
    state.backend = None;
    state.snapshot.runtime = backend.and_then(|backend| backend.observe());
    #[cfg(unix)]
    if let Some(observation) = &mut state.snapshot.runtime {
        observation.record_service_terminal(terminal);
    }
    state.snapshot.listening = None;
    if let Some(generation) = generation {
        if state.terminals.len() == RETAINED {
            state.terminals.pop_front();
        }
        state.terminals.push_back((generation, terminal));
        state.snapshot.terminal = Some(terminal);
    }
    drop(state);
    shared.changed();
}
fn failed(error: io::Error) -> Completed {
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
pub(super) async fn establish(
    shared: Arc<Shared>,
    plan: Prepared,
    accepted: Accepted,
) -> io::Result<Active> {
    let deadline = accepted.deadline.ok_or_else(expired)?;
    check(deadline)?;
    let config = plan.data.connection;
    shared.lock().snapshot.phase = Phase::Authenticating;
    shared.changed();
    let options = match &plan.data.transport {
        Transport::Managed(options) => *options,
        Transport::UdpFrame { settings, delivery } => {
            let setup = establish_udp(&shared, &plan, accepted, deadline, *settings, *delivery);
            let result = tokio::time::timeout_at(deadline, setup)
                .await
                .map_err(|_| expired())?;
            check(deadline)?;
            return result;
        }
        #[cfg(unix)]
        Transport::Swift(settings) => {
            let setup = establish_swift(&shared, &plan, accepted, deadline, *settings);
            let result = tokio::time::timeout_at(deadline, setup)
                .await
                .map_err(|_| expired())?;
            check(deadline)?;
            return result;
        }
        #[cfg(unix)]
        Transport::SecureUdpSwift(profile) => {
            let result = tokio::time::timeout_at(
                deadline,
                establish_secure_udp(&shared, &plan, accepted, deadline, **profile),
            )
            .await
            .map_err(|_| expired())?;
            check(deadline)?;
            return result;
        }
        #[cfg(unix)]
        Transport::SecureUdpTransaction(profile) => {
            let result = tokio::time::timeout_at(
                deadline,
                establish_secure_udp_transaction(
                    &shared,
                    &plan,
                    accepted,
                    deadline,
                    profile.clone(),
                ),
            )
            .await
            .map_err(|_| expired())?;
            check(deadline)?;
            return result;
        }
    };
    let setup = async {
        let (link, role) = match &plan.data.endpoint {
            Endpoint::Client(c) => {
                let link = match options.delivery {
                    Some(delivery) => {
                        crate::connect_with_delivery(
                            c.remote,
                            &c.tls,
                            &c.server_name,
                            &c.member,
                            config,
                            delivery,
                        )
                        .await?
                    }
                    None => {
                        crate::connect(c.remote, &c.tls, &c.server_name, &c.member, config).await?
                    }
                };
                (link, managed::Role::Client)
            }
            Endpoint::Server(s) => {
                check(deadline)?;
                let listener = TcpListener::bind(s.listen).await?;
                check(deadline)?;
                shared.lock().snapshot.listening = Some(Listening {
                    operation: accepted.operation,
                    address: listener.local_addr()?,
                });
                shared.changed();
                let link = match options.delivery {
                    Some(delivery) => {
                        crate::accept_with_delivery(&listener, &s.tls, &s.members, config, delivery)
                            .await?
                    }
                    None => crate::accept(&listener, &s.tls, &s.members, config).await?,
                };
                (link, managed::Role::Server)
            }
            #[cfg(unix)]
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "prepared endpoint/backend mismatch",
                ));
            }
        };
        check(deadline)?;
        let device = plan.open()?;
        check(deadline)?;
        let (control, requests) = managed::channel();
        let (profile, sink) = match options.profile_interval {
            Some(interval) => {
                let (handle, sink) = managed::profiling_channel(interval)?;
                (Some(handle), Some(sink))
            }
            None => (None, None),
        };
        let managed_config = managed::ManagedConfig {
            role,
            initial_mode: match options.delivery {
                Some(delivery) => config.mode_with_delivery(delivery)?,
                None => config.mode()?,
            },
            transaction_settings: managed::TransactionSettings::default(),
        };
        let mut runtime: RunFuture = Box::pin(async move {
            match options.delivery {
                Some(delivery) => {
                    managed::run_managed_with_delivery(
                        device,
                        link,
                        config.runtime(),
                        managed_config,
                        requests,
                        delivery,
                        sink,
                    )
                    .await
                }
                None => {
                    managed::run_managed_with_profile(
                        device,
                        link,
                        config.runtime(),
                        managed_config,
                        requests,
                        sink,
                    )
                    .await
                }
            }
        });
        // A constructed future or successful authentication is insufficient.
        // Poll the real actor until it has published a live runtime observation.
        std::future::poll_fn(|cx| match runtime.as_mut().poll(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "managed runtime ended during readiness",
            ))),
            Poll::Pending if control.status().is_some_and(|status| status.running) => {
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        })
        .await?;
        check(deadline)?;
        Ok(Active {
            runtime,
            backend: ObservedBackend::Managed { control, profile },
            generation: accepted.operation,
        })
    };
    let result = tokio::time::timeout_at(deadline, setup)
        .await
        .map_err(|_| expired())?;
    check(deadline)?;
    result
}
/// Full publishes exactly the first lane; half publishes both fixed lanes. The
/// default empty snapshot or a partially populated one is not readiness.
pub(super) fn lanes_ready(
    duplex: l2tunnel_core::Duplex,
    lanes: l2tunnel_runtime::udp::Snapshot,
) -> bool {
    match duplex {
        l2tunnel_core::Duplex::Full => lanes.lanes[0].is_some() && lanes.lanes[1].is_none(),
        l2tunnel_core::Duplex::Half => lanes.lanes.iter().all(Option::is_some),
    }
}
/// Existing public UDP factories under the already accepted absolute deadline.
/// The runtime keeps every reader/writer inline, so dropping it releases the
/// bootstrap TLS streams, UDP sockets and device before any later publication.
async fn establish_udp(
    shared: &Shared,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    settings: crate::udp::Settings,
    delivery: managed::DeliveryConfig,
) -> io::Result<Active> {
    let config = plan.data.connection;
    let (link, effective) = match &plan.data.endpoint {
        Endpoint::Client(c) => {
            crate::udp::connect(
                c.remote,
                &c.tls,
                &c.server_name,
                &c.member,
                config,
                settings,
                delivery,
            )
            .await?
        }
        Endpoint::Server(s) => {
            check(deadline)?;
            let listener = TcpListener::bind(s.listen).await?;
            check(deadline)?;
            shared.lock().snapshot.listening = Some(Listening {
                operation: accepted.operation,
                address: listener.local_addr()?,
            });
            shared.changed();
            crate::udp::accept(&listener, &s.tls, &s.members, config, settings, delivery).await?
        }
        #[cfg(unix)]
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prepared endpoint/backend mismatch",
            ));
        }
    };
    check(deadline)?;
    let device = plan.open()?;
    check(deadline)?;
    let (observer, reporter) = l2tunnel_runtime::udp::observations();
    let mut runtime: RunFuture = Box::pin(l2tunnel_runtime::udp::run_observed_inline(
        device,
        link,
        config.runtime(),
        effective,
        Some(reporter),
        delivery,
    ));
    // Authentication and a constructed future are insufficient: wait for the
    // actual runtime to publish every required physical lane.
    std::future::poll_fn(|cx| match runtime.as_mut().poll(cx) {
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "UDP runtime ended during readiness",
        ))),
        Poll::Pending if lanes_ready(config.duplex, observer.status()) => Poll::Ready(Ok(())),
        Poll::Pending => Poll::Pending,
    })
    .await?;
    check(deadline)?;
    Ok(Active {
        runtime,
        backend: ObservedBackend::UdpFrame(Arc::new(UdpBackend {
            observer,
            requested: settings,
            effective,
            delivery,
        })),
        generation: accepted.operation,
    })
}
/// Existing swift factories. The acceptor's operation deadline covers its
/// listening period; each TCP connection keeps the original handshake bound.
/// The runtime owns the retained TLS stream, UDP socket and device inline.
#[cfg(unix)]
async fn establish_swift(
    shared: &Shared,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    settings: crate::swift::Settings,
) -> io::Result<Active> {
    let config = plan.data.connection;
    let session = match &plan.data.endpoint {
        Endpoint::Client(c) => {
            crate::swift::connect(
                c.remote,
                &c.tls,
                &c.server_name,
                &c.member,
                config,
                settings,
            )
            .await?
        }
        Endpoint::Server(s) => {
            check(deadline)?;
            let listener = TcpListener::bind(s.listen).await?;
            shared.lock().snapshot.listening = Some(Listening {
                operation: accepted.operation,
                address: listener.local_addr()?,
            });
            shared.changed();
            crate::swift::accept(&listener, &s.tls, &s.members, config, settings).await?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prepared endpoint/backend mismatch",
            ));
        }
    };
    check(deadline)?;
    let device = plan.open_readable()?;
    // Observe at least once a second so status stays fresh without printing.
    let session = session.observe_every(std::time::Duration::from_secs(1));
    let (switcher, requests) = l2tunnel_runtime::swift::switcher();
    let backend = Arc::new(SwiftBackend {
        requested: settings,
        effective: session.config(),
        receive_buffer: session.receive_buffer()?,
        counters: Mutex::new(l2tunnel_runtime::swift::Snapshot::default()),
        switcher,
        connection: config,
        client: matches!(plan.data.endpoint, Endpoint::Client(_)),
        generation: accepted.operation.value(),
    });
    let sink = backend.clone();
    let mut runtime: RunFuture = Box::pin(session.run(device, Some(requests), move |snapshot| {
        *sink
            .counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = *snapshot;
    }));
    // Authentication alone is insufficient: the runtime must have registered
    // its socket and device and still be running after its first poll.
    std::future::poll_fn(|cx| match runtime.as_mut().poll(cx) {
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "swift runtime ended during readiness",
        ))),
        Poll::Pending => Poll::Ready(Ok(())),
    })
    .await?;
    check(deadline)?;
    Ok(Active {
        runtime,
        backend: ObservedBackend::Swift(backend),
        generation: accepted.operation,
    })
}
/// Shared original-socket authentication; the selected profile owns all settings.
#[cfg(unix)]
async fn authenticate_secure_udp(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    selected: crate::secure_udp::Settings,
) -> io::Result<crate::secure_udp::Session> {
    use l2tunnel_runtime::secure_udp::establish;
    use l2tunnel_security::Role;
    let role = match &plan.data.endpoint {
        Endpoint::SecureClient(_) => Role::Initiator,
        Endpoint::SecureServer(_) => Role::Responder,
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
    setup::stage(shared, accepted.operation, SetupStage::SocketConnect);
    socket.connect(peer).await.inspect_err(|_| {
        setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
    })?;
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
        Endpoint::SecureServer(server) => {
            // This owner survives cancellation and every reconnect of this plan.
            setup::stage(shared, accepted.operation, SetupStage::AdmissionOwner);
            let mut admission = server.admission.lock().await;
            check(deadline)?;
            if admission.is_none() {
                setup::stage(shared, accepted.operation, SetupStage::Configuration);
                *admission = Some(crate::secure_udp::Server::new(
                    selected,
                    server.credentials.noise().peers(role),
                    server.credentials.admission(),
                    server.credentials.cookie(),
                    Instant::now(),
                )?);
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
/// Same accepted setup operation, with one fixed original UDP owner and gate.
#[cfg(unix)]
async fn establish_secure_udp(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    profile: crate::secure_udp::profile::Profile,
) -> io::Result<Active> {
    use l2tunnel_runtime::secure_udp::transport;
    let session =
        authenticate_secure_udp(shared, plan, accepted, deadline, profile.settings()).await?;
    let info = session.info();
    setup::stage(shared, accepted.operation, SetupStage::Configuration);
    let configuration = profile.configuration(info.peers)?;
    let role = info.role;
    let parts = session.into_parts();
    setup::stage(shared, accepted.operation, SetupStage::Attachment);
    let device = plan.open_readable().inspect_err(|_| {
        setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
    })?;
    check(deadline)?;
    let (switcher, requests) = transport::channel();
    let backend = Arc::new(SecureUdpBackend {
        requested: profile,
        info,
        counters: Mutex::new(None),
        switcher,
        generation: accepted.operation.value(),
    });
    let sink = backend.clone();
    let changed = shared.clone();
    let resolver: transport::Resolver =
        Box::new(move |policy| profile.resolve(policy, role, info.peers));
    let mut runtime: RunFuture = Box::pin(async move {
        let stopped = transport::run(
            device,
            parts,
            configuration,
            profile.runtime(role),
            Some(requests),
            resolver,
            std::future::pending::<()>(),
            move |snapshot| {
                *sink
                    .counters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(snapshot.clone());
                changed.changed();
            },
        )
        .await?;
        let kind = match stopped.reason {
            transport::StopReason::Cancelled => io::ErrorKind::Interrupted,
            transport::StopReason::LeaseExpired
            | transport::StopReason::PeerTimeout
            | transport::StopReason::NativeStall
            | transport::StopReason::PolicyTimeout => io::ErrorKind::TimedOut,
            transport::StopReason::Io(kind) => kind,
            _ => io::ErrorKind::InvalidData,
        };
        Err(io::Error::new(kind, "secure UDP runtime terminated"))
    });
    setup::stage(shared, accepted.operation, SetupStage::DriverReadiness);
    std::future::poll_fn(|cx| match runtime.as_mut().poll(cx) {
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "secure UDP runtime ended during readiness",
        ))),
        Poll::Pending
            if backend
                .counters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .is_some_and(|snapshot| snapshot.running) =>
        {
            Poll::Ready(Ok(()))
        }
        Poll::Pending => Poll::Pending,
    })
    .await
    .inspect_err(|_| {
        setup::reason(
            shared,
            accepted.operation,
            SetupFailureReason::ReadinessEnded,
        );
    })?;
    check(deadline)?;
    Ok(Active {
        runtime,
        backend: ObservedBackend::SecureUdp(backend),
        generation: accepted.operation,
    })
}
/// Select the generic runtime through the same authenticated setup and service actor.
#[cfg(unix)]
async fn establish_secure_udp_transaction(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    profile: Arc<crate::secure_udp::transaction_profile::Profile>,
) -> io::Result<Active> {
    use l2tunnel_runtime::secure_udp::transport;
    let session =
        authenticate_secure_udp(shared, plan, accepted, deadline, profile.settings()).await?;
    let info = session.info();
    setup::stage(shared, accepted.operation, SetupStage::Configuration);
    let contract = profile.runtime_contract(info.role)?;
    if info.peers != profile.peers()
        || info.authenticated.configuration != contract.expected_configuration().0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "actual authentication differs from the complete transaction plan",
        ));
    }
    let parts = session.into_parts();
    setup::stage(shared, accepted.operation, SetupStage::Attachment);
    let device = plan.open_readable().inspect_err(|_| {
        setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
    })?;
    check(deadline)?;
    let (switcher, requests) = transport::transaction_channel();
    let backend = Arc::new(SecureUdpTransactionBackend {
        requested: profile,
        info,
        counters: Mutex::new(None),
        switcher,
        generation: accepted.operation.value(),
    });
    let sink = backend.clone();
    let changed = shared.clone();
    let mut runtime: RunFuture = Box::pin(async move {
        let stopped = transport::run_transaction(
            device,
            parts,
            contract,
            Some(requests),
            std::future::pending::<()>(),
            move |snapshot| {
                *sink
                    .counters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(snapshot.clone());
                changed.changed();
            },
        )
        .await?;
        Err(secure_udp_termination(stopped.reason))
    });
    setup::stage(shared, accepted.operation, SetupStage::DriverReadiness);
    std::future::poll_fn(|cx| match runtime.as_mut().poll(cx) {
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "generic secure UDP runtime ended during readiness",
        ))),
        Poll::Pending
            if backend
                .counters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .is_some_and(|snapshot| snapshot.running) =>
        {
            Poll::Ready(Ok(()))
        }
        Poll::Pending => Poll::Pending,
    })
    .await
    .inspect_err(|_| {
        setup::reason(
            shared,
            accepted.operation,
            SetupFailureReason::ReadinessEnded,
        );
    })?;
    check(deadline)?;
    Ok(Active {
        runtime,
        backend: ObservedBackend::SecureUdpTransaction(backend),
        generation: accepted.operation,
    })
}

#[cfg(unix)]
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

#[cfg(unix)]
async fn apply_secure_udp_transaction(
    shared: &Arc<Shared>,
    backend: &SecureUdpTransactionBackend,
    configuration: l2tunnel::swift_configuration::Configuration,
) -> Completed {
    use l2tunnel_runtime::secure_udp::transport::SwitchError;
    let handle = Handle(shared.clone());
    match backend.switcher.switch(configuration).await {
        Ok(epoch) => {
            let actual = backend
                .counters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if actual
                .as_ref()
                .is_none_or(|snapshot| snapshot.epoch != epoch || snapshot.current != configuration)
            {
                return Completed::OutcomeUnknown;
            }
            drop(actual);
            Completed::Applied(handle.transaction_status(true, "ok"))
        }
        Err(SwitchError::Busy) => Completed::Rejected(handle.transaction_status(false, "busy")),
        Err(SwitchError::NotCoordinator) => {
            Completed::Rejected(handle.transaction_status(false, "not_coordinator"))
        }
        Err(SwitchError::Rejected) => {
            Completed::Rejected(handle.transaction_status(false, "rejected"))
        }
        Err(SwitchError::Invalid) => {
            Completed::Rejected(handle.transaction_status(false, "invalid_configuration"))
        }
        Err(SwitchError::Closed) => Completed::OutcomeUnknown,
    }
}

/// Negotiate the requested swift values over the live session. The reply is
/// built only after the runtime reported the committed epoch or a refusal.
#[cfg(unix)]
async fn apply_swift(
    shared: &Arc<Shared>,
    swift: &SwiftBackend,
    request: &local::Request,
) -> Completed {
    let handle = Handle(shared.clone());
    let local::Action::SetSwiftPolicy { policy: change } = &request.action else {
        return Completed::Rejected(handle.swift_status(false, "unsupported"));
    };
    let Some(mut next) = handle
        .snapshot()
        .runtime
        .as_ref()
        .and_then(Observation::swift)
        .map(SwiftFrame::current)
    else {
        return Completed::Rejected(handle.swift_status(false, "closed"));
    };
    let size = |value: Option<u64>, current: usize| {
        value.map_or(Some(current), |value| usize::try_from(value).ok())
    };
    let sizes = (
        size(change.channels, next.channels),
        size(change.window, next.window),
        size(change.path_mtu, next.path_mtu),
        change
            .repair_permille
            .map_or(Some(next.repair_permille), |value| {
                u32::try_from(value).ok()
            }),
    );
    let (Some(channels), Some(window), Some(path_mtu), Some(repair_permille)) = sizes else {
        return Completed::Rejected(handle.swift_status(false, "invalid_policy"));
    };
    next.forward_kbit = change.forward_kbit.unwrap_or(next.forward_kbit);
    next.reverse_kbit = change.reverse_kbit.unwrap_or(next.reverse_kbit);
    (
        next.channels,
        next.window,
        next.path_mtu,
        next.repair_permille,
    ) = (channels, window, path_mtu, repair_permille);
    let policy = match next.session(swift.connection).and_then(|_| next.policy()) {
        Ok(policy) => policy,
        Err(_) => return Completed::Rejected(handle.swift_status(false, "invalid_policy")),
    };
    use l2tunnel_runtime::swift::SwitchError;
    match swift.switcher.switch(policy).await {
        Ok(epoch) => {
            // The runtime publishes counters periodically; make the reply
            // show the epoch it just committed.
            {
                let mut counters = swift
                    .counters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                counters.policy_epoch = epoch;
                counters.policy = Some(policy);
            }
            Completed::Applied(handle.swift_status(true, "ok"))
        }
        Err(SwitchError::Busy) => Completed::Rejected(handle.swift_status(false, "busy")),
        Err(SwitchError::NotCoordinator) => {
            Completed::Rejected(handle.swift_status(false, "not_coordinator"))
        }
        Err(SwitchError::Rejected) => Completed::Rejected(handle.swift_status(false, "rejected")),
        Err(SwitchError::Invalid) => {
            Completed::Rejected(handle.swift_status(false, "invalid_policy"))
        }
        Err(SwitchError::Closed) => Completed::OutcomeUnknown,
    }
}
#[cfg(unix)]
async fn apply_secure_udp(
    shared: &Arc<Shared>,
    backend: &SecureUdpBackend,
    request: &local::Request,
) -> Completed {
    use l2tunnel_runtime::secure_udp::transport::SwitchError;
    let handle = Handle(shared.clone());
    let local::Action::SetSwiftPolicy { policy: change } = &request.action else {
        return Completed::Rejected(handle.secure_udp_status(false, "unsupported"));
    };
    let mut next = match backend.requested.initial_policy() {
        Ok(initial) => backend
            .counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|snapshot| snapshot.committed.policy)
            .unwrap_or(initial),
        Err(_) => return Completed::Rejected(handle.secure_udp_status(false, "invalid_policy")),
    };
    let convert = |value: Option<u64>, current: u64| value.unwrap_or(current);
    let converted = (
        u16::try_from(convert(change.path_mtu, u64::from(next.path_mtu))),
        u32::try_from(convert(change.forward_kbit, u64::from(next.forward_kbit))),
        u32::try_from(convert(change.reverse_kbit, u64::from(next.reverse_kbit))),
        u8::try_from(convert(change.channels, u64::from(next.channels))),
        u8::try_from(convert(change.window, u64::from(next.window))),
        u16::try_from(convert(
            change.repair_permille,
            u64::from(next.repair_permille),
        )),
    );
    let (
        Ok(path_mtu),
        Ok(forward_kbit),
        Ok(reverse_kbit),
        Ok(channels),
        Ok(window),
        Ok(repair_permille),
    ) = converted
    else {
        return Completed::Rejected(handle.secure_udp_status(false, "invalid_policy"));
    };
    (
        next.path_mtu,
        next.forward_kbit,
        next.reverse_kbit,
        next.channels,
        next.window,
        next.repair_permille,
    ) = (
        path_mtu,
        forward_kbit,
        reverse_kbit,
        channels,
        window,
        repair_permille,
    );
    if backend.requested.with_policy(&next).is_err() {
        return Completed::Rejected(handle.secure_udp_status(false, "invalid_policy"));
    }
    match backend.switcher.switch(next).await {
        Ok(epoch) => {
            if let Some(snapshot) = backend
                .counters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                snapshot.committed.epoch = l2tunnel_swift::policy::Epoch(epoch);
                snapshot.committed.policy = Some(next);
            }
            Completed::Applied(handle.secure_udp_status(true, "ok"))
        }
        Err(SwitchError::Busy) => Completed::Rejected(handle.secure_udp_status(false, "busy")),
        Err(SwitchError::NotCoordinator) => {
            Completed::Rejected(handle.secure_udp_status(false, "not_coordinator"))
        }
        Err(SwitchError::Rejected) => {
            Completed::Rejected(handle.secure_udp_status(false, "rejected"))
        }
        Err(SwitchError::Invalid) => {
            Completed::Rejected(handle.secure_udp_status(false, "invalid_policy"))
        }
        Err(SwitchError::Closed) => Completed::OutcomeUnknown,
    }
}
// One commit point for cancellation, generation, profile and actual readiness.
// The helper is shared with a real-TLS late-cancel regression, not a test-only hook.
pub(super) fn publish_ready(
    shared: &Shared,
    session: Active,
    accepted: Accepted,
) -> Option<Active> {
    let mut state = shared.lock();
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
    state.snapshot.listening = None;
    state.snapshot.runtime = session.backend.observe();
    state.backend = Some(session.backend.clone());
    state.snapshot.generation = Some(session.generation);
    state.snapshot.terminal = None;
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
        #[cfg(unix)]
        if let Some(record) = &mut entry.setup {
            record.complete(&result, entry.accepted, Instant::now());
        }
        entry.result = Some(result);
    }
    drop(state);
    shared.changed();
    Some(session)
}
pub(super) fn classify_apply(response: local::Response) -> Completed {
    if response.ok && response.code == "ok" {
        Completed::Applied(response)
    } else if !response.ok
        && matches!(
            response.code.as_str(),
            "busy" | "not_coordinator" | "aborted" | "unsupported" | "unsupported_version"
        )
    {
        Completed::Rejected(response)
    } else {
        // Future adapter uncertainty or acceptance-only codes cannot silently
        // become a definitive no-commit rejection or successful completion.
        Completed::OutcomeUnknown
    }
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
                    stopped(&shared, &mut active, Terminal::Aborted);
                    finish(&shared, accepted.operation, Completed::Aborted);
                }
                #[cfg(unix)]
                Command::Transaction(configuration) => {
                    let Some(session) = active.as_mut() else {
                        finish(&shared, accepted.operation, Completed::OutcomeUnknown);
                        continue;
                    };
                    let ObservedBackend::SecureUdpTransaction(backend) = &session.backend else {
                        finish(&shared, accepted.operation, Completed::OutcomeUnknown);
                        continue;
                    };
                    let backend = backend.clone();
                    let apply = apply_secure_udp_transaction(&shared, &backend, configuration);
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
                    if active.is_some() {
                        stopped(&shared, &mut active, Terminal::Aborted);
                    }
                    let mut setup = Box::pin(establish(shared.clone(), plan, accepted));
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
                        Some(Ok(session)) => {
                            if let Some(session) = publish_ready(&shared, session, accepted) {
                                active = Some(session);
                            }
                            continue;
                        }
                    };
                    finish(&shared, accepted.operation, result);
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
                    #[cfg(unix)]
                    if let ObservedBackend::Swift(swift) = &session.backend {
                        let swift = swift.clone();
                        let change = apply_swift(&shared, &swift, &request);
                        tokio::pin!(change);
                        let result = tokio::select! {
                            result = &mut change => result,
                            result = &mut session.runtime => {
                                let failure = Failure {
                                    kind: result.err().map_or(io::ErrorKind::UnexpectedEof, |e| e.kind()),
                                };
                                stopped(&shared, &mut active, Terminal::Failed(failure));
                                Completed::OutcomeUnknown
                            }
                        };
                        finish(&shared, accepted.operation, result);
                        continue;
                    }
                    #[cfg(unix)]
                    if let ObservedBackend::SecureUdp(secure) = &session.backend {
                        let secure = secure.clone();
                        let change = apply_secure_udp(&shared, &secure, &request);
                        tokio::pin!(change);
                        let result = tokio::select! {
                            result = &mut change => result,
                            result = &mut session.runtime => {
                                let failure = Failure { kind: result.err().map_or(io::ErrorKind::UnexpectedEof, |error| error.kind()) };
                                stopped(&shared, &mut active, Terminal::Failed(failure));
                                Completed::OutcomeUnknown
                            }
                        };
                        finish(&shared, accepted.operation, result);
                        continue;
                    }
                    // Submission already rejects apply on a datagram backend; this
                    // keeps the owner total without sending any protocol input.
                    let Some(control) = session.backend.managed().cloned() else {
                        finish(
                            &shared,
                            accepted.operation,
                            Completed::Failed(Failure {
                                kind: io::ErrorKind::Unsupported,
                            }),
                        );
                        continue;
                    };
                    let apply = crate::session_control::Control::managed(control).request(request);
                    tokio::pin!(apply);
                    let result = tokio::select! {
                        response=&mut apply=>classify_apply(response),
                        result=&mut session.runtime=>{
                            let failure=Failure{kind:result.err().map_or(io::ErrorKind::UnexpectedEof,|e|e.kind())};
                            stopped(&shared,&mut active,Terminal::Failed(failure));Completed::OutcomeUnknown
                        },
                    };
                    finish(&shared, accepted.operation, result);
                }
            }
        } else if let Some(session) = active.as_mut() {
            tokio::select! {
                ()=shared.wake.notified()=>{},
                result=&mut session.runtime=>{
                    let failure=Failure{kind:result.err().map_or(io::ErrorKind::UnexpectedEof,|e|e.kind())};
                    stopped(&shared,&mut active,Terminal::Failed(failure));
                    shared.lock().snapshot.phase=Phase::Failed;shared.changed();
                },
            }
        } else {
            shared.wake.notified().await;
        }
    }
}
