//! Windows endpoint of the shared local API transport: the local API named
//! pipe (docs/modules/windows-local-service.md, WLS-02).
//!
//! Access control is the kernel's: the proposed DACL and
//! `PIPE_REJECT_REMOTE_CLIENTS` are applied by
//! `l2tunnel_platform_windows::local_pipe` when each instance is created, so
//! [`Listener::authorize`] has nothing further to check. Clients refuse a pipe
//! that LocalSystem or Administrators do not own.
use super::CONCURRENT_CONNECTIONS;
use l2tunnel_platform_windows::local_pipe::{
    create_local_api_pipe, is_pipe_busy, open_local_api_pipe, validate_pipe_name,
};
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};
use tokio::time::Instant;

/// Accepted server-side connection.
pub(super) type ServerStream = NamedPipeServer;

/// Served instances plus one listening instance plus one just-connected
/// instance that is being handed to the serve loop or refused.
const MAX_INSTANCES: usize = CONCURRENT_CONNECTIONS + 2;
/// How long a client retries while every instance is busy. Nothing is sent
/// while retrying, so expiry is reported as an unreachable service.
const BUSY_LIMIT: Duration = Duration::from_secs(5);
const BUSY_RETRY: Duration = Duration::from_millis(20);

type Connecting = Pin<Box<dyn Future<Output = (NamedPipeServer, io::Result<()>)> + Send>>;

fn connecting(server: NamedPipeServer) -> Connecting {
    Box::pin(async move {
        let connected = server.connect().await;
        (server, connected)
    })
}

/// Owner of the pipe name: always exactly one instance waiting for a client.
pub(super) struct Listener {
    name: String,
    // Only the serve loop polls; the lock is never held across an await.
    pending: Mutex<Option<Connecting>>,
}
impl Listener {
    /// Create the first instance; fails if any process already created `path`.
    pub(super) fn bind(path: &Path) -> io::Result<Self> {
        let name = path.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "pipe name must be Unicode")
        })?;
        validate_pipe_name(name)?;
        let first = create_local_api_pipe(name, true, MAX_INSTANCES)?;
        Ok(Self {
            name: name.to_owned(),
            pending: Mutex::new(Some(connecting(first))),
        })
    }
    /// Poll the listening instance. A connected instance is returned after
    /// its successor is created, so a listening instance always exists. A
    /// per-instance connect failure (for example a client that closed before
    /// the connection completed) yields `None`; failing to create the next
    /// instance ends the server.
    pub(super) fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<NamedPipeServer>>> {
        let Ok(mut slot) = self.pending.lock() else {
            return Poll::Ready(Err(io::Error::other("local API pipe state poisoned")));
        };
        if slot.is_none() {
            match create_local_api_pipe(&self.name, false, MAX_INSTANCES) {
                Ok(server) => *slot = Some(connecting(server)),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        let Some(pending) = slot.as_mut() else {
            return Poll::Ready(Err(io::Error::other("local API pipe has no instance")));
        };
        let (server, connected) = ready!(pending.as_mut().poll(cx));
        *slot = None;
        match create_local_api_pipe(&self.name, false, MAX_INSTANCES) {
            Ok(next) => *slot = Some(connecting(next)),
            Err(error) => return Poll::Ready(Err(error)),
        }
        Poll::Ready(Ok(connected.ok().map(|()| server)))
    }
    /// The DACL already restricted who could open the instance.
    pub(super) fn authorize(&self, _stream: &NamedPipeServer) -> io::Result<bool> {
        Ok(true)
    }
}

/// Open `path` (a local pipe name), retrying briefly while every instance is
/// busy, and require a LocalSystem- or Administrators-owned pipe.
pub(super) async fn connect(path: &Path) -> io::Result<NamedPipeClient> {
    let name = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "local API pipe name must be Unicode",
        )
    })?;
    let started = Instant::now();
    loop {
        match open_local_api_pipe(name) {
            Err(error) if is_pipe_busy(&error) => {
                if started.elapsed() >= BUSY_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "local API pipe busy; nothing was sent",
                    ));
                }
                tokio::time::sleep(BUSY_RETRY).await;
            }
            result => return result,
        }
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
