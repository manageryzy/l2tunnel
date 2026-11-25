//! Service-owned bounded RFC 1928 / RFC 1929 SOCKS5 entry (`DGUI-08`).
//!
//! Runs inside the client service while a TCP-proxy profile is connected,
//! enforcing client IP/CIDR allowlists, optional username/password auth, a
//! strict concurrent flow ceiling, live per-flow byte accounting, and automatic
//! listener teardown whenever the session ends or the service drops.
use super::{Handle, ObservedBackend};
use crate::local::{
    Role, SOCKS_FLOW_LIMIT, SocksAuthMode, SocksCidr, SocksFlow, SocksFlows, SocksSettings,
    SocksStatus, bounded_text,
};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Most recently ended flows kept alongside active flows for diagnostics.
const RECENT_FLOW_LIMIT: usize = 32;
/// Maximum time allowed for the RFC 1928/1929 handshake before closing.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time allowed for upstream TCP connect.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-direction copy buffer size (bounded, fixed allocation per open flow).
const RELAY_BUFFER_BYTES: usize = 16 * 1024;

struct FlowRecord {
    id: u64,
    client: String,
    target: String,
    started: Instant,
    sent_bytes: Arc<AtomicU64>,
    received_bytes: Arc<AtomicU64>,
    state: String,
    error: Option<String>,
}

impl FlowRecord {
    fn snapshot(&self) -> SocksFlow {
        SocksFlow {
            id: self.id,
            client: self.client.clone(),
            target: self.target.clone(),
            sent_bytes: self.sent_bytes.load(Ordering::Relaxed),
            received_bytes: self.received_bytes.load(Ordering::Relaxed),
            state: self.state.clone(),
            age_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            error: self.error.clone(),
        }
    }
}

struct RunningListener {
    listening: SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl RunningListener {
    fn shutdown(self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

struct Inner {
    settings: SocksSettings,
    password: Option<String>,
    listener: Option<RunningListener>,
    last_error: Option<String>,
    next_flow_id: u64,
    total_flows: u64,
    rejected_clients: u64,
    failed_connects: u64,
    active: BTreeMap<u64, FlowRecord>,
    recent: VecDeque<SocksFlow>,
}

impl Inner {
    fn new() -> Self {
        Self {
            settings: SocksSettings::default(),
            password: None,
            listener: None,
            last_error: None,
            next_flow_id: 1,
            total_flows: 0,
            rejected_clients: 0,
            failed_connects: 0,
            active: BTreeMap::new(),
            recent: VecDeque::with_capacity(RECENT_FLOW_LIMIT),
        }
    }

    fn finish_flow(&mut self, id: u64, state: &str, error: Option<String>) {
        if let Some(mut record) = self.active.remove(&id) {
            record.state = state.into();
            record.error = error.map(|msg| bounded_text(&msg));
            let snapshot = record.snapshot();
            if self.recent.len() == RECENT_FLOW_LIMIT {
                self.recent.pop_front();
            }
            self.recent.push_back(snapshot);
        }
    }
}

/// Service-owned SOCKS5 state, stored inside `service::Shared`.
#[derive(Clone)]
pub(super) struct SocksService {
    inner: Arc<Mutex<Inner>>,
}

impl SocksService {
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::new())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Stop any running SOCKS5 listener (called on session end, disable, or service drop).
    pub(super) fn stop_listener(&self) {
        let running = {
            let mut inner = self.lock();
            inner.settings.enabled = false;
            inner.listener.take()
        };
        if let Some(running) = running {
            running.shutdown();
        }
    }

    /// Snapshot of current status and counters (never exposes password plaintext).
    pub(super) fn status(&self, proxy_active: bool) -> SocksStatus {
        let inner = self.lock();
        let listening = inner
            .listener
            .as_ref()
            .map(|running| running.listening.to_string());
        SocksStatus {
            proxy_active,
            listening,
            settings: inner.settings.redacted(inner.password.is_some()),
            active_flows: u32::try_from(inner.active.len()).unwrap_or(u32::MAX),
            total_flows: inner.total_flows,
            rejected_clients: inner.rejected_clients,
            failed_connects: inner.failed_connects,
            last_error: inner.last_error.clone(),
        }
    }

    /// Bounded snapshot of active and recently ended flows.
    pub(super) fn flows(&self) -> SocksFlows {
        let inner = self.lock();
        let total_active = u32::try_from(inner.active.len()).unwrap_or(u32::MAX);
        let mut flows: Vec<SocksFlow> = inner
            .active
            .values()
            .map(FlowRecord::snapshot)
            .take(SOCKS_FLOW_LIMIT)
            .collect();
        let remaining = SOCKS_FLOW_LIMIT.saturating_sub(flows.len());
        flows.extend(inner.recent.iter().rev().take(remaining).cloned());
        SocksFlows {
            flows,
            total_active,
        }
    }

    /// Validate and apply new settings, binding or stopping the listener as requested.
    pub(super) async fn apply(
        &self,
        settings: SocksSettings,
        proxy_active: bool,
        allow_ephemeral_port: bool,
    ) -> Result<SocksStatus, (&'static str, SocksStatus)> {
        let existing_password = self.lock().password.clone();
        let (bind_addr, cidrs) =
            match settings.validate(existing_password.is_some(), allow_ephemeral_port) {
                Ok(parsed) => parsed,
                Err(reason) => {
                    let mut inner = self.lock();
                    inner.last_error = Some(bounded_text(&reason));
                    drop(inner);
                    return Err(("invalid_settings", self.status(proxy_active)));
                }
            };
        if settings.enabled && !proxy_active {
            let mut inner = self.lock();
            inner.last_error = Some("SOCKS5 needs a connected TCP-proxy profile".into());
            drop(inner);
            return Err(("not_proxy_profile", self.status(proxy_active)));
        }

        // Stop any existing listener first so rebinding the same port succeeds cleanly.
        let previous = self.lock().listener.take();
        if let Some(running) = previous {
            running.shutdown();
            // Yield once so the aborted listener task drops its socket cleanly.
            tokio::task::yield_now().await;
        }

        let effective_password = match settings.auth_mode {
            SocksAuthMode::None => None,
            SocksAuthMode::UserPass => settings.password.clone().or(existing_password),
        };
        let effective_auth = match settings.auth_mode {
            SocksAuthMode::None => AuthConfig::None,
            SocksAuthMode::UserPass => AuthConfig::UserPass {
                username: settings.username.clone().unwrap_or_default(),
                password: effective_password.clone().unwrap_or_default(),
            },
        };

        let mut stored = settings.clone();
        stored.password = None;
        stored.password_set = effective_password.is_some();

        if !settings.enabled {
            let mut inner = self.lock();
            inner.settings = stored;
            inner.password = effective_password;
            inner.last_error = None;
            drop(inner);
            return Ok(self.status(proxy_active));
        }

        let listener = match TcpListener::bind(bind_addr).await {
            Ok(listener) => listener,
            Err(error) => {
                let mut inner = self.lock();
                stored.enabled = false;
                inner.settings = stored;
                inner.password = effective_password;
                inner.last_error = Some(bounded_text(&format!("bind {bind_addr}: {error}")));
                drop(inner);
                return Err(("bind_failed", self.status(proxy_active)));
            }
        };
        let listening = listener.local_addr().unwrap_or(bind_addr);
        let (stop_tx, stop_rx) = watch::channel(false);
        let service = self.clone();
        let max_flows = usize::from(settings.max_flows);
        let task = tokio::spawn(accept_loop(
            listener,
            service,
            Arc::new(cidrs),
            Arc::new(effective_auth),
            max_flows,
            stop_rx,
        ));

        {
            let mut inner = self.lock();
            inner.settings = stored;
            inner.password = effective_password;
            inner.last_error = None;
            inner.listener = Some(RunningListener {
                listening,
                stop: stop_tx,
                task,
            });
        }
        Ok(self.status(proxy_active))
    }
}

#[derive(Clone)]
enum AuthConfig {
    None,
    UserPass { username: String, password: String },
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn accept_loop(
    listener: TcpListener,
    service: SocksService,
    cidrs: Arc<Vec<SocksCidr>>,
    auth: Arc<AuthConfig>,
    max_flows: usize,
    mut stop: watch::Receiver<bool>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    continue;
                };
                if !cidrs.iter().any(|cidr| cidr.contains(peer.ip())) {
                    let mut inner = service.lock();
                    inner.rejected_clients = inner.rejected_clients.saturating_add(1);
                    drop(inner);
                    drop(stream);
                    continue;
                }
                let service = service.clone();
                let auth = Arc::clone(&auth);
                let stop_child = stop.clone();
                tasks.spawn(async move {
                    handle_client(stream, peer, service, auth, max_flows, stop_child).await;
                });
            }
        }
    }
    tasks.abort_all();
}

enum TargetAddr {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    fn display(&self) -> String {
        match self {
            Self::Socket(addr) => addr.to_string(),
            Self::Domain(host, port) => format!("{host}:{port}"),
        }
    }
}

async fn send_reply(stream: &mut TcpStream, rep: u8, bound: SocketAddr) -> io::Result<()> {
    let mut buf = Vec::with_capacity(22);
    buf.push(0x05);
    buf.push(rep);
    buf.push(0x00);
    match bound.ip() {
        IpAddr::V4(v4) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&buf).await
}

async fn negotiate(stream: &mut TcpStream, auth: &AuthConfig) -> io::Result<TargetAddr> {
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not SOCKS5 version",
        ));
    }
    let nmethods = usize::from(greeting[1]);
    let mut methods = vec![0_u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let wanted = match auth {
        AuthConfig::None => 0x00,
        AuthConfig::UserPass { .. } => 0x02,
    };
    if !methods.contains(&wanted) {
        let _ = stream.write_all(&[0x05, 0xff]).await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no acceptable SOCKS5 auth method",
        ));
    }
    stream.write_all(&[0x05, wanted]).await?;

    if let AuthConfig::UserPass { username, password } = auth {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x01 {
            let _ = stream.write_all(&[0x01, 0x01]).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid RFC 1929 auth version",
            ));
        }
        let mut user_buf = vec![0_u8; usize::from(header[1])];
        stream.read_exact(&mut user_buf).await?;
        let mut pass_len = [0_u8; 1];
        stream.read_exact(&mut pass_len).await?;
        let mut pass_buf = vec![0_u8; usize::from(pass_len[0])];
        stream.read_exact(&mut pass_buf).await?;
        let ok = constant_time_eq(&user_buf, username.as_bytes())
            && constant_time_eq(&pass_buf, password.as_bytes());
        if !ok {
            let _ = stream.write_all(&[0x01, 0x01]).await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid SOCKS5 credentials",
            ));
        }
        stream.write_all(&[0x01, 0x00]).await?;
    }

    let mut req = [0_u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 request version",
        ));
    }
    let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    if req[1] != 0x01 {
        let _ = send_reply(stream, 0x07, unspecified).await;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only SOCKS5 CONNECT is supported",
        ));
    }
    let target = match req[3] {
        0x01 => {
            let mut body = [0_u8; 6];
            stream.read_exact(&mut body).await?;
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[4], body[5]]);
            TargetAddr::Socket(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0_u8; usize::from(len[0])];
            stream.read_exact(&mut domain).await?;
            let mut port_bytes = [0_u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let host = String::from_utf8(domain).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 domain name")
            })?;
            TargetAddr::Domain(host, u16::from_be_bytes(port_bytes))
        }
        0x04 => {
            let mut body = [0_u8; 18];
            stream.read_exact(&mut body).await?;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&body[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([body[16], body[17]]);
            TargetAddr::Socket(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => {
            let _ = send_reply(stream, 0x08, unspecified).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported SOCKS5 address type",
            ));
        }
    };
    Ok(target)
}

async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    service: SocksService,
    auth: Arc<AuthConfig>,
    max_flows: usize,
    mut stop: watch::Receiver<bool>,
) {
    let target = match tokio::time::timeout(HANDSHAKE_TIMEOUT, negotiate(&mut client, &auth)).await
    {
        Ok(Ok(target)) => target,
        _ => return,
    };

    let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let allocated = {
        let mut inner = service.lock();
        if inner.active.len() >= max_flows {
            inner.failed_connects = inner.failed_connects.saturating_add(1);
            None
        } else {
            let id = inner.next_flow_id;
            inner.next_flow_id = inner.next_flow_id.saturating_add(1);
            inner.total_flows = inner.total_flows.saturating_add(1);
            let sent = Arc::new(AtomicU64::new(0));
            let received = Arc::new(AtomicU64::new(0));
            inner.active.insert(
                id,
                FlowRecord {
                    id,
                    client: peer.to_string(),
                    target: bounded_text(&target.display()),
                    started: Instant::now(),
                    sent_bytes: Arc::clone(&sent),
                    received_bytes: Arc::clone(&received),
                    state: "connecting".into(),
                    error: None,
                },
            );
            Some((id, sent, received))
        }
    };
    let Some((flow_id, sent_bytes, received_bytes)) = allocated else {
        let _ = send_reply(&mut client, 0x01, unspecified).await;
        return;
    };

    let connect_result = match &target {
        TargetAddr::Socket(addr) => {
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(*addr)).await
        }
        TargetAddr::Domain(host, port) => {
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), *port))).await
        }
    };

    let mut upstream = match connect_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            let rep = match error.kind() {
                io::ErrorKind::ConnectionRefused => 0x05,
                io::ErrorKind::PermissionDenied => 0x02,
                io::ErrorKind::HostUnreachable => 0x04,
                io::ErrorKind::NetworkUnreachable => 0x03,
                io::ErrorKind::TimedOut => 0x06,
                _ => 0x01,
            };
            let _ = send_reply(&mut client, rep, unspecified).await;
            let mut inner = service.lock();
            inner.failed_connects = inner.failed_connects.saturating_add(1);
            inner.finish_flow(flow_id, "refused", Some(error.to_string()));
            return;
        }
        Err(_) => {
            let _ = send_reply(&mut client, 0x06, unspecified).await;
            let mut inner = service.lock();
            inner.failed_connects = inner.failed_connects.saturating_add(1);
            inner.finish_flow(flow_id, "refused", Some("connect timed out".into()));
            return;
        }
    };

    let bound = upstream.local_addr().unwrap_or(unspecified);
    if send_reply(&mut client, 0x00, bound).await.is_err() {
        service.lock().finish_flow(flow_id, "closed", None);
        return;
    }
    if let Some(record) = service.lock().active.get_mut(&flow_id) {
        record.state = "open".into();
    }

    let (mut client_read, mut client_write) = client.split();
    let (mut up_read, mut up_write) = upstream.split();

    let c_to_u = pump(&mut client_read, &mut up_write, &sent_bytes);
    let u_to_c = pump(&mut up_read, &mut client_write, &received_bytes);

    let outcome = tokio::select! {
        _ = stop.changed() => Ok(()),
        result = async {
            let (a, b) = tokio::join!(c_to_u, u_to_c);
            a.and(b)
        } => result,
    };

    let mut inner = service.lock();
    match outcome {
        Ok(()) => inner.finish_flow(flow_id, "closed", None),
        Err(error) => inner.finish_flow(flow_id, "failed", Some(error.to_string())),
    }
}

async fn pump<R, W>(reader: &mut R, writer: &mut W, counter: &AtomicU64) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0_u8; RELAY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..read]).await?;
        counter.fetch_add(read as u64, Ordering::Relaxed);
    }
}

impl Handle {
    /// Whether this service can currently run SOCKS5 (client role with a connected TCP-proxy backend).
    pub(super) fn socks_unavailable(&self) -> Option<&'static str> {
        let state = self.0.lock();
        let role = state
            .plan
            .as_ref()
            .map_or(Role::Unconfigured, super::Prepared::role);
        if role == Role::Server {
            return Some("client role only");
        }
        if matches!(state.backend, Some(ObservedBackend::Proxy(_))) {
            None
        } else {
            Some("SOCKS5 needs a connected TCP-proxy profile")
        }
    }

    /// Read current SOCKS5 status and settings.
    pub(super) fn socks_status(&self) -> SocksStatus {
        let proxy_active = self.socks_unavailable().is_none();
        self.0.socks.status(proxy_active)
    }

    /// Read bounded active and recent SOCKS5 flows.
    pub(super) fn socks_flows(&self) -> SocksFlows {
        self.0.socks.flows()
    }

    /// Apply new SOCKS5 settings on this service.
    pub(super) async fn socks_set(
        &self,
        settings: SocksSettings,
    ) -> Result<SocksStatus, (&'static str, SocksStatus)> {
        let proxy_active = self.socks_unavailable().is_none();
        let role = {
            let state = self.0.lock();
            state
                .plan
                .as_ref()
                .map_or(Role::Unconfigured, super::Prepared::role)
        };
        if role == Role::Server {
            return Err(("unsupported", self.0.socks.status(false)));
        }
        self.0.socks.apply(settings, proxy_active, cfg!(test)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start_echo_server() -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Ok((addr, task))
    }

    async fn socks_connect_v4(
        proxy: SocketAddr,
        target: SocketAddr,
        auth: Option<(&str, &str)>,
    ) -> io::Result<(TcpStream, u8)> {
        let mut stream = TcpStream::connect(proxy).await?;
        match auth {
            None => {
                stream.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut resp = [0_u8; 2];
                stream.read_exact(&mut resp).await?;
                assert_eq!(resp, [0x05, 0x00]);
            }
            Some((user, pass)) => {
                stream.write_all(&[0x05, 0x01, 0x02]).await?;
                let mut resp = [0_u8; 2];
                stream.read_exact(&mut resp).await?;
                assert_eq!(resp, [0x05, 0x02]);
                let mut sub = vec![0x01, user.len() as u8];
                sub.extend_from_slice(user.as_bytes());
                sub.push(pass.len() as u8);
                sub.extend_from_slice(pass.as_bytes());
                stream.write_all(&sub).await?;
                let mut auth_resp = [0_u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "auth rejected",
                    ));
                }
            }
        }
        let IpAddr::V4(v4) = target.ip() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected ipv4"));
        };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&v4.octets());
        req.extend_from_slice(&target.port().to_be_bytes());
        stream.write_all(&req).await?;
        let mut reply = [0_u8; 10];
        stream.read_exact(&mut reply).await?;
        Ok((stream, reply[1]))
    }

    #[tokio::test]
    async fn socks5_forwards_tcp_counts_bytes_enforces_auth_and_allowlist() -> io::Result<()> {
        let (echo_addr, echo_task) = start_echo_server().await?;
        let service = SocksService::new();

        // Refused when proxy profile is not active.
        let denied = service
            .apply(
                SocksSettings {
                    enabled: true,
                    listen_port: 0,
                    ..SocksSettings::default()
                },
                false,
                true,
            )
            .await;
        assert!(matches!(denied, Err(("not_proxy_profile", _))));

        // Start with no-auth on ephemeral loopback port.
        let status = service
            .apply(
                SocksSettings {
                    enabled: true,
                    listen_host: "127.0.0.1".into(),
                    listen_port: 0,
                    allowed_clients: vec!["127.0.0.1/32".into()],
                    ..SocksSettings::default()
                },
                true,
                true,
            )
            .await
            .map_err(|(code, _)| io::Error::other(code))?;
        let proxy_addr: SocketAddr = status
            .listening
            .as_deref()
            .ok_or_else(|| io::Error::other("missing listening addr"))?
            .parse()
            .map_err(io::Error::other)?;

        // Forward payload through SOCKS5 and verify live flow accounting.
        let (mut client, rep) = socks_connect_v4(proxy_addr, echo_addr, None).await?;
        assert_eq!(rep, 0x00);
        let payload = b"hello over socks5 tcp proxy";
        client.write_all(payload).await?;
        let mut echoed = vec![0_u8; payload.len()];
        client.read_exact(&mut echoed).await?;
        assert_eq!(echoed, payload);

        let flows = service.flows();
        assert_eq!(flows.total_active, 1);
        assert_eq!(flows.flows[0].state, "open");
        assert_eq!(flows.flows[0].sent_bytes, payload.len() as u64);
        assert_eq!(flows.flows[0].received_bytes, payload.len() as u64);
        drop(client);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(service.flows().total_active, 0);
        assert_eq!(service.flows().flows[0].state, "closed");

        // Reconfigure with username/password auth and verify good vs bad password.
        let status = service
            .apply(
                SocksSettings {
                    enabled: true,
                    listen_host: "127.0.0.1".into(),
                    listen_port: 0,
                    auth_mode: SocksAuthMode::UserPass,
                    username: Some("demo".into()),
                    password: Some("s3cr3t".into()),
                    allowed_clients: vec!["127.0.0.1/32".into()],
                    ..SocksSettings::default()
                },
                true,
                true,
            )
            .await
            .map_err(|(code, _)| io::Error::other(code))?;
        assert!(status.settings.password.is_none());
        assert!(status.settings.password_set);
        let proxy_addr: SocketAddr = status
            .listening
            .as_deref()
            .ok_or_else(|| io::Error::other("missing listening addr"))?
            .parse()
            .map_err(io::Error::other)?;
        assert!(
            socks_connect_v4(proxy_addr, echo_addr, Some(("demo", "wrong")))
                .await
                .is_err()
        );
        let (stream, rep) =
            socks_connect_v4(proxy_addr, echo_addr, Some(("demo", "s3cr3t"))).await?;
        assert_eq!(rep, 0x00);
        drop(stream);

        // Restrict allowlist to 10.0.0.0/8 so loopback client is rejected.
        let status = service
            .apply(
                SocksSettings {
                    enabled: true,
                    listen_host: "127.0.0.1".into(),
                    listen_port: 0,
                    allowed_clients: vec!["10.0.0.0/8".into()],
                    ..SocksSettings::default()
                },
                true,
                true,
            )
            .await
            .map_err(|(code, _)| io::Error::other(code))?;
        let proxy_addr: SocketAddr = status
            .listening
            .as_deref()
            .ok_or_else(|| io::Error::other("missing listening addr"))?
            .parse()
            .map_err(io::Error::other)?;
        let mut rejected = TcpStream::connect(proxy_addr).await?;
        let _ = rejected.write_all(&[0x05, 0x01, 0x00]).await;
        let mut byte = [0_u8; 1];
        assert_eq!(rejected.read(&mut byte).await.unwrap_or(0), 0);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(service.status(true).rejected_clients >= 1);

        // Teardown stops listener cleanly.
        service.stop_listener();
        assert!(service.status(false).listening.is_none());
        echo_task.abort();
        Ok(())
    }
}
