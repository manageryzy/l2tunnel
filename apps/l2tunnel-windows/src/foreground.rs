//! Portable foreground presentation of the existing shared service owner.
//!
//! This module neither creates a device nor implements authentication. Prepared
//! factories retain those boundaries; cancellation observes actual owner release.
use l2tunnel_client_core::{
    Compression, ConnectionConfig,
    service::{self, Completed, Handle, OperationId, Phase, Prepared, SubmitError, Terminal},
};
use std::{future::Future, io, net::SocketAddr, time::Duration};
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

async fn disconnect(handle: &Handle, generation: OperationId) -> io::Result<Outcome> {
    match handle.disconnect(handle.next_key().map_err(service_error)?) {
        Ok(accepted) => match handle
            .wait(accepted.operation)
            .await
            .map_err(service_error)?
        {
            Completed::Aborted => {}
            Completed::Failed(failure) => {
                return Err(io::Error::new(failure.kind, "foreground disconnect failed"));
            }
            _ => return Err(io::Error::other("unexpected foreground disconnect outcome")),
        },
        // Runtime failure may have released the generation immediately before
        // submission. Its retained terminal is authoritative in that race.
        Err(SubmitError::State) => {}
        Err(error) => return Err(service_error(error)),
    }
    terminal(
        handle
            .wait_stopped(generation)
            .await
            .map_err(service_error)?,
    )
}

async fn lifecycle(
    handle: &Handle,
    operation: OperationId,
    cancellation: impl Future<Output = io::Result<()>>,
) -> io::Result<Outcome> {
    tokio::pin!(cancellation);
    let mut cancelled = None;
    let completed = tokio::select! {
        completed = handle.wait(operation) => completed.map_err(service_error)?,
        reason = &mut cancellation => {
            cancelled = Some(reason);
            match handle.cancel(operation) {
                Ok(()) | Err(SubmitError::State) => {},
                Err(error) => return Err(service_error(error)),
            }
            // State can mean readiness won the race. Always read the retained
            // result, then abort a live generation through the same service.
            handle.wait(operation).await.map_err(service_error)?
        },
    };
    let generation = match completed {
        Completed::Connected { generation } => generation,
        Completed::Cancelled => {
            if let Some(reason) = cancelled {
                reason?;
            }
            return Ok(Outcome::Cancelled);
        }
        Completed::Failed(failure) => {
            return Err(io::Error::new(
                failure.kind,
                "foreground managed setup failed",
            ));
        }
        _ => return Err(io::Error::other("unexpected foreground setup outcome")),
    };
    if let Some(reason) = cancelled {
        let outcome = disconnect(handle, generation).await?;
        reason?;
        return Ok(outcome);
    }
    tokio::select! {
        result = handle.wait_stopped(generation) => terminal(result.map_err(service_error)?),
        reason = &mut cancellation => {
            let outcome = disconnect(handle, generation).await?;
            reason?;
            Ok(outcome)
        },
    }
}

/// Drive one prepared managed foreground session and its existing shared owner.
/// The observer must perform finite work; no unbounded event queue is allocated.
/// Cancellation-source errors still release established owners before returning.
/// Dropping this future drops Run and its inline managed socket/device owners.
pub(crate) async fn run(
    plan: Prepared,
    requested: ConnectionConfig,
    cancellation: impl Future<Output = io::Result<()>>,
    mut observe: impl FnMut(Event),
) -> io::Result<Outcome> {
    let (handle, owner) = service::channel();
    let accepted = handle
        .connect(plan, handle.next_key().map_err(service_error)?)
        .map_err(service_error)?;
    observe(Event::Requested(requested));
    let mut previous = status(&handle);
    observe(Event::Status(previous.clone()));
    let mut changes = handle.subscribe();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut owner = Box::pin(owner);
    let result = {
        let lifecycle = lifecycle(&handle, accepted.operation, cancellation);
        tokio::pin!(lifecycle);
        loop {
            tokio::select! {
                result = &mut owner => {
                    break result.and_then(|()| Err(io::Error::other("foreground service owner ended")));
                },
                result = &mut lifecycle => break result,
                changed = changes.changed() => {
                    if changed.is_err() {
                        break Err(io::Error::new(io::ErrorKind::BrokenPipe, "foreground service observation closed"));
                    }
                },
                _ = interval.tick() => {},
            }
            let current = status(&handle);
            if current != previous {
                observe(Event::Status(current.clone()));
                previous = current;
            }
        }
    };
    // The callback sees final closure only after the sole runtime owner drops.
    drop(owner);
    observe(Event::Status(status(&handle)));
    result
}

#[cfg(test)]
#[path = "foreground_tests.rs"]
mod tests;
