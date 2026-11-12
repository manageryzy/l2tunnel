//! Opt-in native-prefix drain with retained authenticated carrier ownership.
use super::{KeyBundle, carrier, invalid};
use crate::ConnectionConfig;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_device::PacketDevice;
use l2tunnel_runtime::openvpn::drain as runtime;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::UdpSocket, time::Instant};
#[cfg(unix)]
mod local;
#[cfg(unix)]
pub(crate) use local::serve;
mod status;
pub use status::*;

/// Explicit native-drain selection; legacy factories remain separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Exact fixed endpoints and standalone transport bounds.
    pub transport: super::Settings,
    /// Original native/carrier close allowance, 1 ms through 120 s.
    pub drain_timeout: Duration,
}
fn profiles(
    connection: ConnectionConfig,
    settings: Settings,
    client: bool,
) -> io::Result<super::Profiles> {
    super::profiles_with_base(connection, settings.transport, client, |device| {
        runtime::DrainConfig {
            device,
            drain_timeout: settings.drain_timeout,
        }
        .base_session_config()
    })
}
/// Validate the entire opt-in profile before credential or native device I/O.
pub fn runtime_config(
    connection: ConnectionConfig,
    settings: Settings,
) -> io::Result<runtime::DrainConfig> {
    Ok(runtime::DrainConfig {
        device: profiles(connection, settings, true)?.native,
        drain_timeout: settings.drain_timeout,
    })
}
fn check_deadline(expires: Instant) -> io::Result<()> {
    if Instant::now() >= expires {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "native client original setup deadline",
        ))
    } else {
        Ok(())
    }
}
async fn within<T>(
    expires: Instant,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    check_deadline(expires)?;
    let value = tokio::time::timeout_at(expires, operation)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "native client original setup deadline",
            )
        })??;
    check_deadline(expires)?;
    Ok(value)
}
fn native_config(
    config: carrier::Config,
    settings: Settings,
) -> io::Result<carrier::NativeDrainConfig> {
    carrier::NativeDrainConfig::new(config, settings.drain_timeout).map_err(io::Error::other)
}
/// Authenticate genuine native-profile full or paired lanes under one setup deadline.
pub async fn connect(
    tls: &ClientTls,
    name: &str,
    member: &MemberKey,
    admission: KeyBundle,
    connection: ConnectionConfig,
    settings: Settings,
) -> io::Result<Session> {
    let expires = super::deadline(connection)?;
    let profile = profiles(connection, settings, true)?;
    let config = runtime::DrainConfig {
        device: profile.native,
        drain_timeout: settings.drain_timeout,
    };
    within(expires, async {
        let first = UdpSocket::bind(settings.transport.forward.local).await?;
        check_deadline(expires)?;
        let first_config = native_config(profile.first, settings)?;
        let [forward, reverse] = admission.secrets();
        match (profile.second, settings.transport.reverse) {
            (None, None) => {
                let value = carrier::client_connect_native(
                    first,
                    first_config,
                    carrier::ClientCredentials {
                        tls,
                        server_name: name,
                        member,
                        admission: forward,
                    },
                )
                .await
                .map_err(io::Error::other)?;
                check_deadline(expires)?;
                let binding = Binding::full(*value.info());
                Ok(Session {
                    link: runtime::DrainingLink::full(value, first_config, config)?,
                    config,
                    binding,
                })
            }
            (Some(second), Some(endpoints)) => {
                let second_socket = UdpSocket::bind(endpoints.local).await?;
                check_deadline(expires)?;
                let configs = [first_config, native_config(second, settings)?];
                let value = carrier::client_pair_native(
                    [first, second_socket],
                    configs,
                    carrier::ClientPairCredentials {
                        tls,
                        server_name: name,
                        member,
                        admissions: [forward, reverse],
                    },
                )
                .await
                .map_err(io::Error::other)?;
                check_deadline(expires)?;
                let binding = Binding::paired(*value.info());
                Ok(Session {
                    link: runtime::DrainingLink::paired(value, configs, config)?,
                    config,
                    binding,
                })
            }
            _ => Err(invalid("native client lane invariant")),
        }
    })
    .await
}
/// Accept only actual TLS/member success, with independent server cookie secrets.
pub async fn accept(
    tls: &ServerTls,
    members: &MemberAllowlist,
    admission: KeyBundle,
    cookie: KeyBundle,
    connection: ConnectionConfig,
    settings: Settings,
) -> io::Result<Session> {
    let expires = super::deadline(connection)?;
    let profile = profiles(connection, settings, false)?;
    if admission.overlaps(&cookie) {
        return Err(invalid("cookie keys must be independent of admission keys"));
    }
    let config = runtime::DrainConfig {
        device: profile.native,
        drain_timeout: settings.drain_timeout,
    };
    within(expires, async {
        let first = UdpSocket::bind(settings.transport.forward.local).await?;
        check_deadline(expires)?;
        let first_config = native_config(profile.first, settings)?;
        let [forward, reverse] = admission.secrets();
        let [forward_cookie, reverse_cookie] = cookie.secrets();
        match (profile.second, settings.transport.reverse) {
            (None, None) => {
                let value = carrier::server_accept_native(
                    first,
                    first_config,
                    carrier::ServerCredentials {
                        tls,
                        members,
                        admission: forward,
                        cookie: forward_cookie,
                    },
                )
                .await
                .map_err(io::Error::other)?;
                check_deadline(expires)?;
                let binding = Binding::full(*value.info());
                Ok(Session {
                    link: runtime::DrainingLink::full(value, first_config, config)?,
                    config,
                    binding,
                })
            }
            (Some(second), Some(endpoints)) => {
                let second_socket = UdpSocket::bind(endpoints.local).await?;
                check_deadline(expires)?;
                let configs = [first_config, native_config(second, settings)?];
                let value = carrier::server_pair_native(
                    [first, second_socket],
                    configs,
                    carrier::ServerPairCredentials {
                        tls,
                        members,
                        admissions: [forward, reverse],
                        cookies: [forward_cookie, reverse_cookie],
                    },
                )
                .await
                .map_err(io::Error::other)?;
                check_deadline(expires)?;
                let binding = Binding::paired(*value.info());
                Ok(Session {
                    link: runtime::DrainingLink::paired(value, configs, config)?,
                    config,
                    binding,
                })
            }
            _ => Err(invalid("native server lane invariant")),
        }
    })
    .await
}
/// Authenticated original owners and their exact device/configuration binding.
pub struct Session {
    link: runtime::DrainingLink,
    config: runtime::DrainConfig,
    binding: Binding,
}
impl Session {
    /// Exact authenticated device and original native-drain allowance.
    pub fn config(&self) -> &runtime::DrainConfig {
        &self.config
    }
    /// Actual accepted full session or actual two-lane join identity.
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    /// Retain the direct native actor without spawning a detached task.
    pub fn into_run<D>(self, device: D) -> io::Result<(Handle, Run)>
    where
        D: PacketDevice<Error = io::Error> + Send + 'static,
    {
        self.config.validate()?;
        if device.layer() != self.config.device.native.layer {
            return Err(invalid("native client device layer mismatch"));
        }
        let (request, signal) = runtime::shutdown_request();
        let state = Arc::new(Mutex::new(State {
            request: Some(request),
            snapshot: Snapshot {
                binding: self.binding,
                drain_accepted: false,
                terminal: None,
            },
        }));
        // Construct outside the future: cancellation is observable even without a first poll.
        let completion = Completion(state.clone());
        let future = Box::pin(runtime::run_draining(
            device,
            self.link,
            self.config,
            signal,
        ));
        Ok((Handle(state), Run { future, completion }))
    }
}
struct State {
    request: Option<runtime::ShutdownRequest>,
    snapshot: Snapshot,
}
/// Single locally submitted stop or an idempotent retry; neither proves completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acceptance {
    /// The original timestamped request was submitted.
    Accepted,
    /// The same request is still active; no new deadline was created.
    AlreadyAccepted,
}
/// Bounded shared request/status handle for CLI and future GUI callers.
#[derive(Clone)]
pub struct Handle(Arc<Mutex<State>>);
impl Handle {
    /// Submit at most once, recording the original runtime timestamp before returning.
    pub fn request_drain(&self) -> io::Result<Acceptance> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("native client state poisoned"))?;
        if state.snapshot.terminal.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "native client closed",
            ));
        }
        if state.snapshot.drain_accepted {
            return Ok(Acceptance::AlreadyAccepted);
        }
        let request = state.request.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "native request unavailable")
        })?;
        request.request()?;
        state.snapshot.drain_accepted = true;
        Ok(Acceptance::Accepted)
    }
    /// Local acceptance and actual terminal only; no invented live peer/queue phase.
    pub fn snapshot(&self) -> io::Result<Snapshot> {
        Ok(self
            .0
            .lock()
            .map_err(|_| io::Error::other("native client state poisoned"))?
            .snapshot
            .clone())
    }
}
type RunFuture = Pin<
    Box<dyn Future<Output = Result<runtime::NativeDrainReceipt, runtime::NativeDrainError>> + Send>,
>;
/// Retained actor. Dropping even an unpolled Run cancels all original owners.
pub struct Run {
    // Field order drops the original future/owners before publishing cancellation.
    future: RunFuture,
    completion: Completion,
}
impl Future for Run {
    type Output = Result<runtime::NativeDrainReceipt, runtime::NativeDrainError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                let terminal = match &result {
                    Ok(receipt) => Terminal::Closed {
                        report: CloseReport::from(*receipt),
                    },
                    Err(error) => Terminal::Failed {
                        error: Failure::from_error(&error.reason),
                        progress: PartialProgress::from(error.progress),
                    },
                };
                self.completion.record(terminal);
                Poll::Ready(result)
            }
        }
    }
}
struct Completion(Arc<Mutex<State>>);
impl Completion {
    fn record(&self, terminal: Terminal) {
        if let Ok(mut state) = self.0.lock()
            && state.snapshot.terminal.is_none()
        {
            state.snapshot.terminal = Some(terminal);
            state.request = None;
        }
    }
}
impl Drop for Completion {
    fn drop(&mut self) {
        self.record(Terminal::Cancelled);
    }
}
#[cfg(test)]
mod tests;
