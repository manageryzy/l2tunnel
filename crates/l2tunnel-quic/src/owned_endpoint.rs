//! Endpoint-scoped driver ownership; transport clocks/I/O remain maintained Quinn.
use super::{EndpointLimits, Error};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, TokioRuntime};
use std::{
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Instant,
};
use tokio::task::JoinSet;

#[derive(Debug)]
struct Drivers {
    state: Mutex<State>,
    limit: usize,
    shutdown: Arc<tokio::sync::Notify>,
    progress: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    endpoint_first: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    endpoint_polled: std::sync::atomic::AtomicBool,
}
#[derive(Debug)]
struct State {
    tasks: JoinSet<()>,
    closed: bool,
    endpoint_registered: bool,
    connections: usize,
}
impl Drivers {
    fn new(limit: usize) -> Self {
        Self {
            state: Mutex::new(State {
                tasks: JoinSet::new(),
                closed: false,
                endpoint_registered: false,
                connections: 0,
            }),
            limit,
            shutdown: Arc::new(tokio::sync::Notify::new()),
            progress: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            endpoint_first: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            endpoint_polled: std::sync::atomic::AtomicBool::new(false),
        }
    }
}
/// References from Quinn runtime tasks cannot retain this application lifetime.
pub(super) struct Owner(Arc<Lifetime>);
impl Clone for Owner {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
struct Lifetime(Arc<Drivers>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        // Poisoning cannot authorize a leaked endpoint. Recover only the owned
        // shutdown latch; no shared protocol state is reused.
        let mut state = match self.0.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.closed = true;
        drop(state);
        self.0.shutdown.notify_waiters();
    }
}
#[derive(Debug)]
struct OwnedRuntime(Arc<Drivers>);
impl Runtime for OwnedRuntime {
    fn new_timer(&self, at: Instant) -> Pin<Box<dyn AsyncTimer>> {
        TokioRuntime.new_timer(at)
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        TokioRuntime.wrap_udp_socket(socket)
    }
    fn now(&self) -> Instant {
        TokioRuntime.now()
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let Ok(mut state) = self.0.state.lock() else {
            return;
        };
        while state.tasks.try_join_next().is_some() {}
        if !state.closed && state.tasks.len() < self.0.limit {
            let endpoint = !state.endpoint_registered;
            state.endpoint_registered = true;
            if !endpoint {
                let Some(count) = state.connections.checked_add(1) else {
                    return;
                };
                state.connections = count;
            }
            state.tasks.spawn(Driver {
                future: Some(future),
                drivers: self.0.clone(),
                endpoint,
                final_polled: false,
                notice: Box::pin(self.0.shutdown.clone().notified_owned()),
            });
        }
        // Runtime::spawn has no error channel. Dropping an excess driver makes
        // the maintained endpoint/connection fail closed, without extra tasks.
    }
}
struct Driver {
    future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    drivers: Arc<Drivers>,
    endpoint: bool,
    final_polled: bool,
    notice: Pin<Box<dyn Future<Output = ()> + Send>>,
}
impl Future for Driver {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let _ = this.notice.as_mut().poll(cx);
        let closed = match this.drivers.state.lock() {
            Ok(state) => state.closed,
            Err(_) => return Poll::Ready(()),
        };
        #[cfg(test)]
        if closed
            && !this.endpoint
            && this
                .drivers
                .endpoint_first
                .load(std::sync::atomic::Ordering::SeqCst)
            && !this
                .drivers
                .endpoint_polled
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            this.notice = Box::pin(this.drivers.progress.clone().notified_owned());
            let _ = this.notice.as_mut().poll(cx);
            if !this
                .drivers
                .endpoint_polled
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Poll::Pending;
            }
        }
        if !closed || !this.final_polled {
            let Some(future) = this.future.as_mut() else {
                return Poll::Ready(());
            };
            let result = future.as_mut().poll(cx);
            if !closed {
                return result;
            }
            this.final_polled = true;
            #[cfg(test)]
            if this.endpoint {
                this.drivers
                    .endpoint_polled
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                this.drivers.progress.notify_waiters();
            }
        }
        if !this.endpoint {
            return Poll::Ready(());
        }
        // Quinn connection drivers transmit CONNECTION_CLOSE directly through
        // their retained socket. Keep the endpoint alive until each has had its
        // one final nonblocking poll and dropped; no PTO or new task is awaited.
        this.notice = Box::pin(this.drivers.progress.clone().notified_owned());
        let _ = this.notice.as_mut().poll(cx);
        match this.drivers.state.lock() {
            Ok(state) if state.connections != 0 => Poll::Pending,
            _ => Poll::Ready(()),
        }
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        // Drop the actual Quinn driver/socket references before allowing the
        // endpoint task to finish, even when Tokio cancels this wrapper.
        drop(self.future.take());
        if !self.endpoint {
            let mut state = match self.drivers.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(count) = state.connections.checked_sub(1) {
                state.connections = count;
            } else {
                state.closed = true;
            }
            drop(state);
            self.drivers.progress.notify_waiters();
        }
    }
}
#[cfg(test)]
impl Owner {
    pub(super) fn force_endpoint_first(&self) {
        self.0
            .0
            .endpoint_first
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EndpointOwner")
    }
}
/// Bind one socket and its own finite driver set inside the current Tokio runtime.
pub(super) fn bind(
    local: SocketAddr,
    server: Option<quinn::ServerConfig>,
    limits: EndpointLimits,
) -> Result<(quinn::Endpoint, Owner), Error> {
    tokio::runtime::Handle::try_current()
        .map_err(|_| Error::Configuration("QUIC requires Tokio runtime"))?;
    let limit = limits
        .max_connections
        .checked_add(limits.pending_connections)
        .and_then(|n| n.checked_add(1))
        .ok_or(Error::Configuration("QUIC driver capacity overflow"))?;
    let drivers = Arc::new(Drivers::new(limit));
    let owner = Owner(Arc::new(Lifetime(drivers.clone())));
    let socket = std::net::UdpSocket::bind(local)?;
    socket.set_nonblocking(true)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        server,
        socket,
        Arc::new(OwnedRuntime(drivers)),
    )?;
    Ok((endpoint, owner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counted(Arc<AtomicUsize>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn pending(drops: Arc<AtomicUsize>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let guard = Counted(drops);
        Box::pin(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        })
    }
    #[tokio::test]
    async fn bounded_driver_set_rejects_excess_and_post_abandonment_spawns() -> io::Result<()> {
        let drivers = Arc::new(Drivers::new(1));
        let owner = Owner(Arc::new(Lifetime(drivers.clone())));
        let runtime = OwnedRuntime(drivers.clone());
        let drops = Arc::new(AtomicUsize::new(0));
        runtime.spawn(pending(drops.clone()));
        runtime.spawn(pending(drops.clone()));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            drivers
                .state
                .lock()
                .map_err(|_| io::Error::other("test lock"))?
                .tasks
                .len(),
            1
        );
        let retained = owner.clone();
        drop(owner);
        assert!(
            !drivers
                .state
                .lock()
                .map_err(|_| io::Error::other("test lock"))?
                .closed
        );
        drop(retained);
        assert!(
            drivers
                .state
                .lock()
                .map_err(|_| io::Error::other("test lock"))?
                .closed
        );
        runtime.spawn(pending(drops.clone()));
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while drops.load(Ordering::SeqCst) != 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(io::Error::other)?;
        Ok(())
    }
    #[tokio::test]
    async fn endpoint_first_teardown_polls_each_inner_driver_exactly_once() -> io::Result<()> {
        let drivers = Arc::new(Drivers::new(2));
        drivers.endpoint_first.store(true, Ordering::SeqCst);
        let owner = Owner(Arc::new(Lifetime(drivers.clone())));
        let runtime = OwnedRuntime(drivers.clone());
        let endpoint_polls = Arc::new(AtomicUsize::new(0));
        let connection_polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        for count in [endpoint_polls.clone(), connection_polls.clone()] {
            let guard = Counted(drops.clone());
            runtime.spawn(Box::pin(std::future::poll_fn(move |_| {
                let _guard = &guard;
                count.fetch_add(1, Ordering::SeqCst);
                Poll::<()>::Pending
            })));
        }
        drop(owner);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while drops.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(io::Error::other)?;
        assert_eq!(endpoint_polls.load(Ordering::SeqCst), 1);
        assert_eq!(connection_polls.load(Ordering::SeqCst), 1);
        assert!(drivers.endpoint_polled.load(Ordering::SeqCst));
        Ok(())
    }
}
