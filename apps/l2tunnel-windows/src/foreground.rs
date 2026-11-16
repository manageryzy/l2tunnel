//! Portable foreground presentation of the existing shared service owner.
//!
//! This module neither creates a device nor implements authentication. Prepared
//! factories retain those boundaries; cancellation observes actual owner release.
use crate::{input::Command, staging::Staging};
use l2tunnel_client_core::{
    Compression, ConnectionConfig,
    service::{self, Completed, Handle, OperationId, Phase, Prepared, SubmitError, Terminal},
};
use std::{
    cell::{Cell, RefCell},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

/// Final local foreground outcome. An abort does not claim a peer drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// Cancelled before a live generation was published.
    Cancelled,
    /// Original live device and transport owners were released locally.
    Aborted,
    /// The shared service reported its explicit clean terminal outcome.
    Closed,
}

/// Fixed-size effective observation copied from the actual managed runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Managed {
    /// The actual managed actor's latest running flag.
    pub running: bool,
    /// Actual locally active authenticated configuration generation.
    pub epoch: u64,
    /// Actual locally active negotiated compressor.
    pub compression: Compression,
    /// Native packets admitted by the runtime.
    pub admitted: u64,
    /// Admitted packets fully written and flushed to TLS.
    pub flushed: u64,
    /// Peer packets accepted by the local packet device.
    pub delivered: u64,
    /// Authenticated cumulative peer-native delivery feedback.
    pub peer_delivered: u64,
}

/// Bounded non-secret projection; it retains no packet, credential or OS owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Status {
    /// Existing shared service lifecycle state.
    pub phase: Phase,
    /// Current accepted operation identity, when present.
    pub operation: Option<u64>,
    /// Current or last actual live runtime generation.
    pub generation: Option<u64>,
    /// Actual bound listener address, never the requested wildcard address.
    pub listening: Option<SocketAddr>,
    /// Actual runtime observation, absent before runtime initialization.
    pub managed: Option<Managed>,
    /// Existing authoritative local generation termination, when observed.
    pub terminal: Option<Terminal>,
}

/// Requested settings remain separate from authenticated effective observations.
#[derive(Clone, Debug)]
pub(crate) enum Event {
    /// Caller-selected configuration; this is no authentication or readiness proof.
    Requested(ConnectionConfig),
    /// Existing service observation with actual managed runtime counters.
    Status(Status),
    /// Real shared operation acceptance, never a readiness claim.
    Accepted { action: Action, operation: u64 },
    /// Real retained shared completion, after unused staged devices are cleared.
    Completed { operation: u64, result: Completion },
    /// Exact old generation release observed before any replacement device setup.
    Terminal { generation: u64, result: Terminal },
    /// Platform work has no invented service operation or generation.
    DevicePreparing,
    /// A staged device still awaits authentication and service attachment.
    DeviceReady,
    /// Bounded local error; peer/provider strings and credentials are excluded.
    Failed { kind: io::ErrorKind },
    /// A conflicting command is not queued as a future lifecycle mutation.
    Rejected {
        command: Command,
        reason: SubmitError,
    },
}

/// Fixed-size projection of shared lifecycle results, excluding unrelated
/// configuration DTOs. It carries observations and makes no state transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Completion {
    Connected { generation: OperationId },
    Aborted,
    Cancelled,
    Failed(service::Failure),
    Unexpected,
}

impl From<&Completed> for Completion {
    fn from(result: &Completed) -> Self {
        match result {
            Completed::Connected { generation } => Self::Connected {
                generation: *generation,
            },
            Completed::Aborted => Self::Aborted,
            Completed::Cancelled => Self::Cancelled,
            Completed::Failed(failure) => Self::Failed(*failure),
            _ => Self::Unexpected,
        }
    }
}

/// Labels existing shared API submissions; not a frontend lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Connect,
    Disconnect,
    Reconnect,
}

fn status(handle: &Handle) -> Status {
    let snapshot = handle.snapshot();
    let managed = snapshot
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.managed());
    Status {
        phase: snapshot.phase,
        operation: snapshot.operation.map(OperationId::value),
        generation: snapshot.generation.map(OperationId::value),
        listening: snapshot.listening.map(|listener| listener.address),
        managed: managed.map(|runtime| Managed {
            running: runtime.running,
            epoch: runtime.epoch.0,
            compression: runtime.compression,
            admitted: runtime.admitted,
            flushed: runtime.flushed,
            delivered: runtime.delivered,
            peer_delivered: runtime.peer_delivered,
        }),
        terminal: snapshot.terminal,
    }
}

fn service_error(error: SubmitError) -> io::Error {
    io::Error::other(format!("foreground service request: {error:?}"))
}

fn terminal(result: Terminal) -> io::Result<Outcome> {
    match result {
        Terminal::Aborted => Ok(Outcome::Aborted),
        Terminal::Closed => Ok(Outcome::Closed),
        Terminal::Failed(failure) => Err(io::Error::new(
            failure.kind,
            "foreground managed runtime failed",
        )),
    }
}

fn clear(staging: Option<&Staging>) {
    if let Some(staging) = staging {
        staging.clear();
    }
}

async fn completed(
    handle: &Handle,
    operation: OperationId,
    staging: Option<&Staging>,
    receipt: &Cell<Option<OperationId>>,
    emit: &impl Fn(Event),
) -> io::Result<Completed> {
    let result = handle.wait(operation).await.map_err(service_error)?;
    // Authentication can fail before Attachment takes the preopened owner.
    clear(staging);
    receipt.set(None);
    emit(Event::Completed {
        operation: operation.value(),
        result: Completion::from(&result),
    });
    emit(Event::Status(status(handle)));
    Ok(result)
}

/// Always attempt the existing disconnect; State means there is no live backend.
/// A previous failed terminal still proves release and allows an explicit retry.
async fn release(
    handle: &Handle,
    receipt: &Cell<Option<OperationId>>,
    emit: &impl Fn(Event),
) -> io::Result<()> {
    match handle.disconnect(handle.next_key().map_err(service_error)?) {
        Ok(accepted) => {
            receipt.set(Some(accepted.operation));
            emit(Event::Accepted {
                action: Action::Disconnect,
                operation: accepted.operation.value(),
            });
            match completed(handle, accepted.operation, None, receipt, emit).await? {
                Completed::Aborted => {}
                _ => return Err(io::Error::other("unexpected foreground disconnect outcome")),
            }
        }
        Err(SubmitError::State) => {}
        Err(error) => return Err(service_error(error)),
    }
    if let Some(generation) = handle.snapshot().generation {
        let result = handle
            .wait_stopped(generation)
            .await
            .map_err(service_error)?;
        emit(Event::Terminal {
            generation: generation.value(),
            result,
        });
    }
    emit(Event::Status(status(handle)));
    Ok(())
}

/// Cancel the actual accepted setup if any, then release any surviving backend.
/// A cancelled queued reconnect alone does not prove the old generation stopped.
async fn stop(
    handle: &Handle,
    staging: Option<&Staging>,
    receipt: &Cell<Option<OperationId>>,
    emit: &impl Fn(Event),
) -> io::Result<()> {
    if let Some(staging) = staging {
        staging.abandon().await;
    }
    // Run may finish before the disposable continuation observes completion.
    // The retained accepted ID ensures its authoritative result is still emitted.
    if let Some(operation) = receipt.get().or(handle.snapshot().operation) {
        match handle.cancel(operation) {
            Ok(()) | Err(SubmitError::State | SubmitError::Unsupported) => {}
            Err(error) => return Err(service_error(error)),
        }
        completed(handle, operation, staging, receipt, emit).await?;
    }
    release(handle, receipt, emit).await?;
    clear(staging);
    Ok(())
}

async fn connect(
    handle: &Handle,
    plan: &Prepared,
    staging: Option<&Staging>,
    submitted: &Cell<bool>,
    receipt: &Cell<Option<OperationId>>,
    emit: &impl Fn(Event),
) -> io::Result<()> {
    // Release both the old native device and socket before invoking the next
    // blocking constructor. Reconnect therefore exposes two shared operations.
    release(handle, receipt, emit).await?;
    if let Some(staging) = staging {
        emit(Event::DevicePreparing);
        staging.prepare().await?;
        emit(Event::DeviceReady);
    }
    let key = handle.next_key().map_err(service_error)?;
    let (action, accepted) = if submitted.get() {
        (Action::Reconnect, handle.reconnect(plan.clone(), key))
    } else {
        (Action::Connect, handle.connect(plan.clone(), key))
    };
    let accepted = accepted.map_err(service_error)?;
    submitted.set(true);
    receipt.set(Some(accepted.operation));
    emit(Event::Accepted {
        action,
        operation: accepted.operation.value(),
    });
    match completed(handle, accepted.operation, staging, receipt, emit).await? {
        Completed::Connected { .. } => Ok(()),
        Completed::Failed(failure) => Err(io::Error::new(
            failure.kind,
            "foreground managed setup failed",
        )),
        Completed::Cancelled => Ok(()),
        _ => Err(io::Error::other("unexpected foreground setup outcome")),
    }
}

type Pending<'a> = Pin<Box<dyn Future<Output = io::Result<()>> + 'a>>;

async fn input(
    controls: &mut Option<mpsc::Receiver<io::Result<Command>>>,
) -> Option<io::Result<Command>> {
    match controls {
        Some(controls) => controls.recv().await,
        None => std::future::pending().await,
    }
}

/// One retained shared owner and at most one inline local request continuation.
/// The observer must be finite. Input closure is a foreground lifetime boundary.
/// Platform setup is joined on cancellation; it cannot outlive the foreground.
/// Only explicit reconnect input attempts another generation after a failure.
pub(crate) async fn controlled(
    plan: Prepared,
    requested: ConnectionConfig,
    staging: Option<Staging>,
    mut controls: Option<mpsc::Receiver<io::Result<Command>>>,
    cancellation: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(Event),
) -> io::Result<Outcome> {
    let observer = RefCell::new(observe);
    let emit = |event| (observer.borrow_mut())(event);
    let interactive = controls.is_some();
    let staging = staging.as_ref();
    let (handle, owner) = service::channel();
    let submitted = Cell::new(false);
    let receipt = Cell::new(None);
    let mut changes = handle.subscribe();
    let mut owner = Box::pin(owner);
    let mut owner_ended = false;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tokio::pin!(cancellation);
    emit(Event::Requested(requested));
    let mut previous = status(&handle);
    emit(Event::Status(previous.clone()));
    let mut pending: Option<Pending<'_>> = Some(Box::pin(connect(
        &handle, &plan, staging, &submitted, &receipt, &emit,
    )));
    let result = loop {
        // Avoid starting platform work when termination is already observable.
        // After this check normal select fairness prevents status input from
        // starving Run or the single request continuation.
        let cancelled = tokio::select! {
            biased;
            reason = &mut cancellation => Some(reason),
            () = std::future::ready(()) => None,
        };
        if let Some(reason) = cancelled {
            break reason;
        }
        if controls
            .as_ref()
            .is_some_and(|input| input.is_closed() && input.is_empty())
        {
            break Ok(());
        }
        tokio::select! {
            // Fair polling keeps Run and lifetime termination responsive even
            // during a continuous stream of status requests.
            reason = &mut cancellation => break reason,
            result = &mut owner => {
                owner_ended = true;
                break result.and_then(|()| Err(io::Error::other("foreground service owner ended")));
            },
            result = async { match &mut pending {
                Some(pending) => pending.await,
                None => std::future::pending().await,
            }} => {
                drop(pending.take());
                clear(staging);
                if let Err(error) = result {
                    emit(Event::Failed { kind: error.kind() });
                    if !interactive { break Err(error); }
                }
            },
            command = input(&mut controls) => match command {
                None => break Ok(()),
                Some(Err(error)) => break Err(error),
                Some(Ok(Command::Status)) => emit(Event::Status(status(&handle))),
                Some(Ok(Command::Disconnect)) => {
                    // The staging guard retains an unfinished platform worker;
                    // stop joins it asynchronously while status stays available.
                    // Accepted shared operations remain owned by the same Run.
                    drop(pending.take());
                    pending = Some(Box::pin(stop(&handle, staging, &receipt, &emit)));
                },
                Some(Ok(Command::Reconnect)) if pending.is_some() => {
                    emit(Event::Rejected { command: Command::Reconnect, reason: SubmitError::Busy });
                },
                Some(Ok(Command::Reconnect)) => {
                    pending = Some(Box::pin(connect(&handle, &plan, staging, &submitted, &receipt, &emit)));
                },
            },
            changed = changes.changed() => {
                if changed.is_err() {
                    break Err(io::Error::new(io::ErrorKind::BrokenPipe, "foreground service observation closed"));
                }
            },
            _ = interval.tick() => {},
        }
        let current = status(&handle);
        if current.operation.is_none() && current.phase == Phase::Failed {
            clear(staging);
        }
        if current != previous {
            emit(Event::Status(current.clone()));
            previous = current.clone();
        }
        if !interactive
            && pending.is_none()
            && let Some(end) = current.terminal
        {
            break terminal(end).map(|_| ());
        }
    };
    // No input thread owns any of these resources. A blocked stdin read cannot
    // delay tunnel cleanup or make a later command create another generation.
    drop(controls);
    drop(pending);
    let cleanup = if owner_ended {
        Ok(())
    } else {
        tokio::select! {
            result = stop(&handle, staging, &receipt, &emit) => result,
            result = &mut owner => result,
        }
    };
    let snapshot = handle.snapshot();
    let outcome = if snapshot.terminal == Some(Terminal::Closed) {
        Outcome::Closed
    } else if snapshot.generation.is_some() {
        Outcome::Aborted
    } else {
        Outcome::Cancelled
    };
    drop(owner);
    if let Some(staging) = staging {
        staging.abandon().await;
    }
    emit(Event::Status(status(&handle)));
    result?;
    cleanup?;
    Ok(outcome)
}

#[cfg(test)]
async fn run(
    plan: Prepared,
    requested: ConnectionConfig,
    cancellation: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(Event),
) -> io::Result<Outcome> {
    controlled(plan, requested, None, None, cancellation, observe).await
}

#[cfg(test)]
#[path = "foreground_tests.rs"]
mod tests;
