//! Private, bounded local API transport; wire types live in the portable schema.
//!
//! One shared serve loop, framing, bound and dispatch serve both platform
//! endpoints: a private Unix socket (`unix`) or the Windows local API named
//! pipe (`windows`, docs/modules/windows-local-service.md). Only binding,
//! accepting, peer authorization and client connection differ per platform.
use super::framing::*;
use super::*;
use l2tunnel_runtime::initialization_timing::{
    Outcome as TimingOutcome, Owner as TimingOwner, Stage as TimingStage, Timing,
};
use platform::{Listener, ServerStream};
use std::future::Future;
use std::io;
use std::path::Path;
#[cfg(all(test, unix))]
use std::path::PathBuf;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
#[cfg(all(test, unix))]
use tokio::io::AsyncWriteExt;
#[cfg(all(test, unix))]
use tokio::net::UnixStream;
use tokio::time::Instant;

#[cfg(unix)]
#[path = "transport/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "transport/windows.rs"]
mod platform;

/// Listener owning exactly one private local API endpoint: a Unix socket
/// path, or on Windows the local API named pipe.
pub struct Server {
    listener: Listener,
}
impl Server {
    /// Unix: bind only inside an existing private directory owned by the
    /// effective UID. Windows: `path` is a pipe name `\\.\pipe\NAME`; the
    /// first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, the
    /// proposed DACL and `PIPE_REJECT_REMOTE_CLIENTS`, and must be owned by
    /// LocalSystem or Administrators. Call inside a Tokio runtime.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            listener: Listener::bind(path.as_ref())?,
        })
    }
    /// Serve authenticated local requests, at most [`CONCURRENT_CONNECTIONS`]
    /// at a time inside this task; further connections are closed without a
    /// reply. Disconnect does not undo a handler's submitted peer transaction.
    /// Slow/malformed clients are isolated. A version-5 request receives an
    /// explicit `unsupported_version` reply; use [`Self::serve_service`].
    pub async fn serve<F, Fut>(&self, mut handler: F) -> io::Result<()>
    where
        F: FnMut(Request) -> Fut + Send,
        Fut: Future<Output = Response> + Send,
    {
        self.serve_incoming(move |incoming| {
            let legacy = match incoming {
                Incoming::Legacy(request) => Some(handler(request)),
                Incoming::Operations(_) => None,
            };
            async move {
                match legacy {
                    Some(future) => Outgoing::Legacy(Box::new(future.await)),
                    None => Outgoing::Operations(Box::new(OperationReply::code(
                        false,
                        "unsupported_version",
                        None,
                    ))),
                }
            }
        })
        .await
    }
    /// Serve versions 1/4 through `lifecycle_request` and version 5 through
    /// `operations_request` of the one retained service.
    pub async fn serve_service(&self, handle: crate::service::Handle) -> io::Result<()> {
        self.serve_incoming(move |incoming| {
            let handle = handle.clone();
            async move {
                match incoming {
                    Incoming::Legacy(request) => {
                        Outgoing::Legacy(Box::new(handle.lifecycle_request(request).await))
                    }
                    Incoming::Operations(request) => {
                        Outgoing::Operations(Box::new(handle.operations_request(request).await))
                    }
                }
            }
        })
        .await
    }
    async fn serve_incoming<'f, F, Fut>(&'f self, mut handler: F) -> io::Result<()>
    where
        F: FnMut(Incoming) -> Fut + Send,
        Fut: Future<Output = Outgoing> + Send + 'f,
    {
        let mut timing = Timing::from_environment(TimingOwner::LocalApi, Instant::now());
        let mut tasks: Vec<Pin<Box<dyn Future<Output = Step> + Send + 'f>>> =
            Vec::with_capacity(CONCURRENT_CONNECTIONS);
        loop {
            let wake = std::future::poll_fn(|cx| {
                let mut ready = None;
                for (index, task) in tasks.iter_mut().enumerate() {
                    if let Poll::Ready(step) = task.as_mut().poll(cx) {
                        ready = Some((index, step));
                        break;
                    }
                }
                if let Some((index, step)) = ready {
                    // Never poll a completed future again.
                    drop(tasks.swap_remove(index));
                    return Poll::Ready(Wake::Step(step));
                }
                self.listener.poll_accept(cx).map(Wake::Accepted)
            })
            .await;
            match wake {
                Wake::Accepted(stream) => {
                    // `None`: a pipe instance failed before any request was read.
                    let Some(mut stream) = stream? else {
                        continue;
                    };
                    let accepted_at = Instant::now();
                    if tasks.len() >= CONCURRENT_CONNECTIONS {
                        // Bounded local service: refuse without reading.
                        continue;
                    }
                    let authorized = self.listener.authorize(&stream).inspect_err(|_| {
                        timing.accepted_at(accepted_at);
                        timing.end_request_at(Instant::now(), TimingOutcome::Failed);
                    })?;
                    if !authorized {
                        timing.accepted_at(accepted_at);
                        timing.end_request_at(Instant::now(), TimingOutcome::Failed);
                        continue;
                    }
                    tasks.push(Box::pin(async move {
                        let incoming = tokio::time::timeout(
                            Duration::from_secs(5),
                            read_frame(&mut stream, REQUEST_LIMIT),
                        )
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .and_then(|bytes| decode_request(&bytes));
                        Step::Read {
                            stream,
                            incoming,
                            accepted_at,
                            read_at: Instant::now(),
                        }
                    }));
                }
                Wake::Step(Step::Read {
                    mut stream,
                    incoming,
                    accepted_at,
                    read_at,
                }) => {
                    let Some(incoming) = incoming else {
                        timing.accepted_at(accepted_at);
                        timing.end_request_at(read_at, TimingOutcome::Failed);
                        continue;
                    };
                    let limit = match &incoming {
                        Incoming::Legacy(request) => response_limit(request.version),
                        Incoming::Operations(_) => COMMON_RESPONSE_LIMIT,
                    };
                    let future = handler(incoming);
                    tasks.push(Box::pin(async move {
                        let outgoing = future.await;
                        let handled_at = Instant::now();
                        // A disconnected or non-reading client cannot block the API.
                        let reply = tokio::time::timeout(Duration::from_secs(5), async {
                            match &outgoing {
                                Outgoing::Legacy(response) => {
                                    write_json(&mut stream, response.as_ref(), limit).await
                                }
                                Outgoing::Operations(reply) => {
                                    write_json(&mut stream, reply.as_ref(), limit).await
                                }
                            }
                        })
                        .await;
                        Step::Done {
                            accepted_at,
                            read_at,
                            handled_at,
                            replied_at: Instant::now(),
                            success: matches!(reply, Ok(Ok(()))),
                        }
                    }));
                }
                Wake::Step(Step::Done {
                    accepted_at,
                    read_at,
                    handled_at,
                    replied_at,
                    success,
                }) => {
                    // Replay the request's original timestamps as one unit so
                    // concurrent requests keep single-request accounting.
                    timing.accepted_at(accepted_at);
                    timing.enter_at(TimingStage::ApiHandler, read_at);
                    timing.enter_at(TimingStage::ApiReply, handled_at);
                    timing.replied_at(replied_at, success);
                }
            }
        }
    }
}
/// Connections served at once by one [`Server`].
pub const CONCURRENT_CONNECTIONS: usize = 8;
enum Outgoing {
    // Boxed: Common/proxy observations make both reply types large.
    Legacy(Box<Response>),
    Operations(Box<OperationReply>),
}
enum Step {
    Read {
        stream: ServerStream,
        incoming: Option<Incoming>,
        accepted_at: Instant,
        read_at: Instant,
    },
    Done {
        accepted_at: Instant,
        read_at: Instant,
        handled_at: Instant,
        replied_at: Instant,
        success: bool,
    },
}
enum Wake {
    Accepted(io::Result<Option<ServerStream>>),
    Step(Step),
}
/// Submit a local operation. A timeout has unknown remote outcome; query status
/// before retrying a mode change, because an accepted transaction is not rolled back.
pub async fn request(path: impl AsRef<Path>, request: &Request) -> io::Result<Response> {
    if !supported_version(request.version) {
        return Err(invalid("unsupported local API version"));
    }
    tokio::time::timeout(Duration::from_secs(65), async {
        let mut stream = platform::connect(path.as_ref()).await?;
        write_json(&mut stream, request, REQUEST_LIMIT).await?;
        let response: Response = read_json(&mut stream, response_limit(request.version)).await?;
        if response.version != request.version {
            return Err(invalid("unsupported local API response version"));
        }
        Ok(response)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "local request timeout; remote outcome unknown",
        )
    })?
}

/// Submit one version-5 request. The overall deadline covers the request's
/// own long-poll bound plus ten seconds. A timeout after a submission means
/// the outcome is unknown; retry with the same request key or read status.
pub async fn request_operation(
    path: impl AsRef<Path>,
    request: &OperationRequest,
) -> io::Result<OperationReply> {
    let deadline = Duration::from_millis(u64::from(request.action.hold_ms()) + 10_000);
    tokio::time::timeout(deadline, async {
        let mut stream = platform::connect(path.as_ref()).await?;
        write_json(&mut stream, request, REQUEST_LIMIT).await?;
        let reply: OperationReply = read_json(&mut stream, COMMON_RESPONSE_LIMIT).await?;
        if reply.version != OPERATIONS_VERSION {
            return Err(invalid("unsupported local API response version"));
        }
        Ok(reply)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "local request timeout; outcome unknown",
        )
    })?
}

#[cfg(all(test, unix))]
#[path = "transport_operations_tests.rs"]
mod operations_tests;
#[cfg(all(test, unix))]
#[path = "tests.rs"]
mod tests;
