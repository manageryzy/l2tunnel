//! Presentation only: the shared Run owns every connection, task and lifecycle.
use super::*;
use crate::service as lifecycle;
use lifecycle::{Completed, OperationId, Phase, ProxyProfile, Terminal};
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(crate) struct Presentation {
    pub duplex: Duplex,
    pub profile: ProxyProfile,
    pub grace: Duration,
}
#[derive(Clone, Debug)]
pub(crate) enum Event {
    Ready {
        generation: OperationId,
        duplex: Duplex,
        profile: ProxyProfile,
    },
    Terminal {
        generation: OperationId,
        outcome: crate::local::ProxyTerminal,
    },
}
fn submit(error: lifecycle::SubmitError) -> io::Error {
    io::Error::other(format!("proxy service: {error:?}"))
}
fn ready(snapshot: &lifecycle::Snapshot, generation: OperationId, profile: ProxyProfile) -> bool {
    snapshot.generation == Some(generation)
        && snapshot
            .runtime
            .as_ref()
            .and_then(lifecycle::Observation::proxy)
            .is_some_and(|frame| {
                frame.requested_profile == profile
                    && frame.effective_profile == profile
                    && frame.requested_digest == frame.effective_digest
                    && !frame.released
                    && !frame.releasing
                    && frame.runtime.as_ref().is_some_and(|status| {
                        status.phase == l2tunnel_runtime::proxy::Phase::Forwarding
                    })
            })
}
fn released_idle(snapshot: &lifecycle::Snapshot) -> bool {
    snapshot.operation.is_none()
        && matches!(snapshot.phase, Phase::Disconnected | Phase::Failed)
        && match snapshot.runtime.as_ref() {
            Some(lifecycle::Observation::Proxy(frame)) => frame.released && !frame.releasing,
            // A failed/cancelled pre-actor setup has no runtime observation.
            // Its completed operation drops partial owners before publication;
            // a retained historical generation does not create a new owner.
            None => true,
            _ => false,
        }
}
fn outcome(
    handle: &lifecycle::Handle,
    generation: OperationId,
    terminal: Terminal,
) -> io::Result<crate::local::ProxyTerminal> {
    Ok(match terminal {
        Terminal::Closed => crate::local::ProxyTerminal::Closed {
            report: handle
                .proxy_close_report(generation)
                .map_err(submit)?
                .ok_or_else(|| io::Error::other("actual proxy close report absent"))?,
        },
        Terminal::Aborted => crate::local::ProxyTerminal::Failed {
            error: format!("{:?}", io::ErrorKind::Interrupted),
        },
        Terminal::Failed(failure) => crate::local::ProxyTerminal::Failed {
            error: format!("{:?}", failure.kind),
        },
    })
}
fn emit_terminal(
    handle: &lifecycle::Handle,
    generation: OperationId,
    terminal: Terminal,
    emit: &mut impl FnMut(Event),
) {
    match outcome(handle, generation, terminal) {
        Ok(outcome) => emit(Event::Terminal {
            generation,
            outcome,
        }),
        Err(error) => eprintln!(
            "proxy terminal projection unavailable for generation {}: {error}",
            generation.value()
        ),
    }
}
fn result(terminal: Terminal) -> io::Result<()> {
    match terminal {
        Terminal::Closed => Ok(()),
        Terminal::Aborted => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "proxy locally aborted",
        )),
        Terminal::Failed(failure) => Err(io::Error::new(failure.kind, "proxy runtime stopped")),
    }
}
/// Drive the one shared owner. The local observation grace never cancels live ownership.
pub(crate) async fn serve(
    handle: lifecycle::Handle,
    run: lifecycle::Run,
    accepted: lifecycle::Accepted,
    api: Option<crate::local::Server>,
    presentation: Presentation,
    mut emit: impl FnMut(Event),
) -> io::Result<()> {
    let local = handle.clone();
    let ipc = async {
        match &api {
            // Versions 1/4 keep lifecycle_request; version 5 adds operations.
            Some(api) => api.serve_service(local.clone()).await,
            None => std::future::pending::<io::Result<()>>().await,
        }
    };
    let mut changes = handle.subscribe();
    let mut serving = api.is_some();
    let mut tracking = true;
    let mut after = accepted.operation.value().saturating_sub(1);
    let mut live = None;
    let mut idle: Option<(Instant, io::Result<()>)> = None;
    tokio::pin!(run, ipc);
    loop {
        let snapshot = handle.snapshot();
        let may_exit = live.is_none() && released_idle(&snapshot);
        if !serving
            && may_exit
            && let Some((_, result)) = idle.take()
        {
            return result;
        }
        let grace_at = idle.as_ref().map_or_else(Instant::now, |value| value.0);
        let stopped = async {
            match live {
                Some(generation) => handle.wait_stopped(generation).await,
                None => std::future::pending().await,
            }
        };
        let next = async {
            if tracking {
                handle.wait_next(after).await
            } else {
                std::future::pending().await
            }
        };
        tokio::select! {
            value = &mut run => return value,
            value = next => match value {
                Ok((operation, completed)) => {
                    after = operation.value();
                    match completed {
                        Completed::Connected { generation } => {
                            if let Some(previous) = live.take() {
                                // owner::run records stopped before replacement
                                // establish/commit_ready; this retained lookup is
                                // immediately ready and cannot need Run polling.
                                match handle.wait_stopped(previous).await {
                                    Ok(terminal) => emit_terminal(&handle, previous, terminal, &mut emit),
                                    Err(error) => eprintln!("proxy prior terminal observation unavailable: {error:?}"),
                                }
                            }
                            live = Some(generation);
                            idle = None;
                            if ready(&handle.snapshot(), generation, presentation.profile) {
                                emit(Event::Ready { generation, duplex: presentation.duplex, profile: presentation.profile });
                            } else {
                                eprintln!("proxy readiness projection unavailable for generation {}", generation.value());
                            }
                        }
                        Completed::Aborted => {
                            if let Some(generation) = live.take() {
                                // Disconnect records stopped before publishing
                                // Completed::Aborted, so this cannot suspend Run.
                                match handle.wait_stopped(generation).await {
                                    Ok(terminal) => {
                                        emit_terminal(&handle, generation, terminal, &mut emit);
                                        idle = Some((Instant::now() + presentation.grace, result(terminal)));
                                    }
                                    Err(error) => {
                                        eprintln!("proxy aborted terminal observation unavailable: {error:?}");
                                        idle = Some((Instant::now() + presentation.grace, Err(submit(error))));
                                    }
                                }
                            }
                        }
                        Completed::Failed(failure) => {
                            if live.is_none() {
                                idle = Some((Instant::now() + presentation.grace, Err(io::Error::new(failure.kind, "proxy setup failed"))));
                            }
                        }
                        Completed::Cancelled => {
                            if live.is_none() {
                                idle = Some((Instant::now() + presentation.grace, Err(io::Error::new(io::ErrorKind::Interrupted, "proxy setup cancelled"))));
                            }
                        }
                        Completed::Applied(_) | Completed::Rejected(_) | Completed::OutcomeUnknown => {},
                        #[cfg(unix)]
                        Completed::Common { .. } | Completed::ConnectionReuse { .. } => {},
                        // Device/route changes leave the session lifecycle as it is.
                        Completed::Host(_) | Completed::Profile(_) => {},
                    }
                }
                Err(error) => {
                    // Lost presentation history is not permission to drop the actual owner.
                    eprintln!("proxy operation observation stopped: {error:?}");
                    tracking = false;
                }
            },
            value = stopped => {
                if let Some(generation) = live.take() {
                    match value {
                        Ok(terminal) => {
                            emit_terminal(&handle, generation, terminal, &mut emit);
                            idle = Some((Instant::now() + presentation.grace, result(terminal)));
                        }
                        Err(error) => {
                            eprintln!("proxy terminal observation unavailable: {error:?}; retaining shared owner");
                            idle = Some((Instant::now() + presentation.grace, Err(submit(error))));
                        }
                    }
                }
            },
            value = &mut ipc, if serving => {
                serving = false;
                eprintln!("proxy local API stopped: {value:?}; retaining shared runtime ownership");
            },
            value = changes.changed() => {
                if value.is_err() { return Err(io::Error::other("proxy service observation closed")); }
            },
            () = tokio::time::sleep_until(grace_at), if idle.is_some() && may_exit => {
                // Recheck after wake: submission publishes pending setup before its first poll.
                if live.is_none() && released_idle(&handle.snapshot()) {
                    return idle.take().ok_or_else(|| io::Error::other("proxy grace result absent"))?.1;
                }
            },
        }
    }
}
