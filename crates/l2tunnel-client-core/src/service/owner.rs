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
    if let Some(entry) = state
        .entries
        .iter_mut()
        .find(|e| e.accepted.operation == id)
    {
        entry.result = Some(result);
    }
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
    let options = match plan.data.transport {
        Transport::Managed(options) => options,
        Transport::UdpFrame { settings, delivery } => {
            let setup = establish_udp(&shared, &plan, accepted, deadline, settings, delivery);
            let result = tokio::time::timeout_at(deadline, setup)
                .await
                .map_err(|_| expired())?;
            check(deadline)?;
            return result;
        }
        #[cfg(unix)]
        Transport::Swift(settings) => {
            let setup = establish_swift(&shared, &plan, accepted, deadline, settings);
            let result = tokio::time::timeout_at(deadline, setup)
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
    };
    check(deadline)?;
    let device = plan.open_readable()?;
    // Observe at least once a second so status stays fresh without printing.
    let session = session.observe_every(std::time::Duration::from_secs(1));
    let backend = Arc::new(SwiftBackend {
        requested: settings,
        effective: session.config(),
        receive_buffer: session.receive_buffer()?,
        counters: Mutex::new(l2tunnel_runtime::swift::Snapshot::default()),
    });
    let sink = backend.clone();
    let mut runtime: RunFuture = Box::pin(session.run(device, move |snapshot| {
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
        entry.result = Some(Completed::Connected {
            generation: accepted.operation,
        });
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
