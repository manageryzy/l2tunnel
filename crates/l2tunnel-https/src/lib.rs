//! Verified TLS 1.3 + real HTTP/2 POST streaming on the original reliable I/O.
//! No native/runtime/CLI qualification, physical flush or clean-drain promise.
mod body;
mod setup;
use l2tunnel_auth::{SessionConfig, SessionInfo, https_request::Request};
use l2tunnel_core::ConfigDigest;
use ring::digest::{SHA256, digest};
pub use setup::{ClientTls, ServerTls, client_full, client_half, server_full, server_half};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
use zeroize::Zeroizing;

/// Directional lane profile, included in every request/member/config proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Duplex {
    /// One bidirectional exchange.
    Full,
    /// Two original connections, client bulk on 0 and server bulk on 1.
    Half,
}
/// Fixed bounded HTTP profile with validated operator target and lifetime limits.
#[derive(Clone)]
pub struct Config {
    request: Request,
    max_record: usize,
    operation: Duration,
    lease: Duration,
    duplex: Duplex,
    session: SessionConfig,
}
impl Config {
    /// Validate before any I/O and bind all profile settings to existing config.
    pub fn new(
        authority: &str,
        path: &str,
        base: SessionConfig,
        duplex: Duplex,
        max_record: usize,
        operation: Duration,
        lease: Duration,
    ) -> io::Result<Self> {
        if !(8..=16384).contains(&max_record)
            || !(Duration::from_millis(10)..=Duration::from_secs(60)).contains(&operation)
            || lease < operation
            || lease > Duration::from_secs(3600)
            || !operation.as_nanos().is_multiple_of(1_000_000)
            || !lease.as_nanos().is_multiple_of(1_000_000)
        {
            return Err(invalid("HTTPS bounds"));
        }
        Request::new(authority, path, ConfigDigest([0; 32])).map_err(io::Error::other)?;
        let mut policy = Vec::from(b"l2tunnel/https-h2-profile/v1\0".as_slice());
        policy.extend_from_slice(&base.digest.0);
        policy.push(match base.layer {
            l2tunnel_device::PacketLayer::Ethernet => 1,
            l2tunnel_device::PacketLayer::Ip => 2,
        });
        policy.push(if duplex == Duplex::Full { 1 } else { 2 });
        policy.extend_from_slice(&(max_record as u32).to_be_bytes());
        policy.extend_from_slice(&(operation.as_millis() as u64).to_be_bytes());
        policy.extend_from_slice(&(lease.as_millis() as u64).to_be_bytes());
        for value in [authority, path] {
            policy.extend_from_slice(&(value.len() as u64).to_be_bytes());
            policy.extend_from_slice(value.as_bytes());
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(digest(&SHA256, &policy).as_ref());
        let profile = ConfigDigest(hash);
        let request = Request::new(authority, path, profile).map_err(io::Error::other)?;
        Ok(Self {
            request,
            max_record,
            operation,
            lease,
            duplex,
            session: SessionConfig {
                digest: profile,
                ..base
            },
        })
    }
    /// Exact complete authenticated configuration used by this carrier.
    pub fn session_config(&self) -> SessionConfig {
        self.session
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
pub(crate) struct Lane<I> {
    body: body::Body<body::FlushIo<tokio_rustls::TlsStream<I>>>,
    info: SessionInfo,
    root: Zeroizing<[u8; 32]>,
}
/// Local ownership/staging observation; no peer delivery or native qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Configured one- or two-lane profile.
    pub duplex: Duplex,
    /// Number of original TLS/HTTP owners still retained.
    pub original_lanes: usize,
    /// One local record remains partly unstaged into HTTP DATA.
    pub pending_outgoing_record: bool,
    /// One complete incoming record awaits explicit consumption.
    pub complete_incoming_record: bool,
    /// Consumed HTTP body bytes whose receive credit has not been released.
    pub receive_bytes_held: usize,
    /// An original lease or partial-operation deadline has elapsed.
    pub deadline_elapsed: bool,
}
/// A single owner retaining all original TLS/h2 drivers and bounded records.
/// Caller must poll progress; no tasks are spawned or detached.
pub struct Session<I> {
    lanes: Option<Vec<Lane<I>>>,
    config: Config,
    client: bool,
    lease: Pin<Box<Sleep>>,
    operation: Option<Pin<Box<Sleep>>>,
    out: Option<(Vec<u8>, usize)>,
    header: [u8; 4],
    head: usize,
    incoming: Vec<u8>,
    read: usize,
    ready: bool,
}
impl<I: AsyncRead + AsyncWrite + Unpin> Session<I> {
    pub(crate) fn new(mut lanes: Vec<Lane<I>>, config: Config, client: bool) -> Self {
        for l in &mut lanes {
            l.body.hold = true;
        }
        let lease = Box::pin(tokio::time::sleep(config.lease));
        Self {
            lanes: Some(lanes),
            config,
            client,
            lease,
            operation: None,
            out: None,
            header: [0; 4],
            head: 0,
            incoming: Vec::new(),
            read: 0,
            ready: false,
        }
    }
    /// Original authenticated session identities, in canonical lane order.
    pub fn info(&self) -> impl Iterator<Item = &SessionInfo> {
        self.lanes.iter().flatten().map(|l| &l.info)
    }
    /// Whether a terminal error dropped all original owners.
    pub fn stopped(&self) -> bool {
        self.lanes.is_none()
    }
    /// Observe bounded local state; queued HTTP DATA is lease-bounded and is
    /// never reported as delivered. Complete unconsumed records keep h2 credit
    /// until consumption or the original session lease expires.
    pub fn status(&self) -> Status {
        Status {
            duplex: self.config.duplex,
            original_lanes: self.lanes.as_ref().map_or(0, Vec::len),
            pending_outgoing_record: self.out.is_some(),
            complete_incoming_record: self.ready,
            receive_bytes_held: self.lanes.iter().flatten().map(|l| l.body.held).sum(),
            deadline_elapsed: self.expired(),
        }
    }
    /// Stage one bounded record; completion means HTTP staging, not peer delivery.
    pub fn stage_record(&mut self, record: &[u8]) -> io::Result<()> {
        self.check_time()?;
        if self.stopped() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        if self.out.is_some() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        if record.is_empty() || record.len() > self.config.max_record {
            return Err(invalid("HTTPS record length"));
        }
        let mut data = Vec::with_capacity(record.len() + 4);
        data.extend_from_slice(&(record.len() as u32).to_be_bytes());
        data.extend_from_slice(record);
        self.out = Some((data, 0));
        self.arm();
        Ok(())
    }
    /// Current complete record, whose h2 receive capacity remains held.
    pub fn record(&self) -> Option<&[u8]> {
        self.ready.then_some(self.incoming.as_slice())
    }
    /// Release h2 receive capacity only after the caller consumes the record.
    pub fn consume_record(&mut self) -> io::Result<()> {
        self.check_time()?;
        if !self.ready {
            return Err(invalid("no HTTPS record"));
        }
        let i = self.receive_lane();
        self.lanes
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?[i]
            .body
            .release()?;
        self.ready = false;
        self.head = 0;
        self.read = 0;
        self.incoming.clear();
        if self.out.is_none() {
            self.operation = None;
        }
        Ok(())
    }
    fn expired(&self) -> bool {
        let now = Instant::now();
        now >= self.lease.deadline() || self.operation.as_ref().is_some_and(|t| now >= t.deadline())
    }
    fn stop(&mut self) {
        self.lanes = None;
        self.out = None;
        self.incoming.clear();
        self.ready = false;
    }
    fn check_time(&mut self) -> io::Result<()> {
        if self.expired() {
            self.stop();
            Err(io::Error::from(io::ErrorKind::TimedOut))
        } else {
            Ok(())
        }
    }
    fn send_lane(&self) -> usize {
        if self.config.duplex == Duplex::Half && !self.client {
            1
        } else {
            0
        }
    }
    fn receive_lane(&self) -> usize {
        if self.config.duplex == Duplex::Half && self.client {
            1
        } else {
            0
        }
    }
    fn arm(&mut self) {
        if self.operation.is_none() {
            self.operation = Some(Box::pin(tokio::time::sleep(self.config.operation)));
        }
    }
    /// Drive bounded control, data and deadlines on every original connection.
    /// A ready result reports progress only; readiness is not a graceful-close fence.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check_time() {
            return Poll::Ready(Err(e));
        }
        let deadline = self.operation.as_ref().map_or(self.lease.deadline(), |t| {
            t.deadline().min(self.lease.deadline())
        });
        let result = self.turn(cx);
        if Instant::now() >= deadline {
            self.stop();
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::TimedOut)));
        }
        if let Err(e) = self.check_time() {
            return Poll::Ready(Err(e));
        }
        if matches!(result, Poll::Ready(Err(_))) {
            self.stop();
        }
        result
    }
    fn turn(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::future::Future;
        if self.lease.as_mut().poll(cx).is_ready()
            || self
                .operation
                .as_mut()
                .is_some_and(|t| t.as_mut().poll(cx).is_ready())
        {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::TimedOut)));
        }
        let send = self.send_lane();
        let receive = self.receive_lane();
        let lanes = self
            .lanes
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        for lane in lanes.iter_mut() {
            lane.body.driver.poll(cx)?;
        }
        // Half's opposite body stays control-only. Any application byte is terminal.
        if lanes.len() == 2 {
            let wrong = 1 - receive;
            let mut byte = [0];
            let mut b = ReadBuf::new(&mut byte);
            if let Poll::Ready(result) = Pin::new(&mut lanes[wrong].body).poll_read(cx, &mut b) {
                result?;
                if !b.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "wrong HTTPS bulk lane",
                    )));
                }
            }
        }
        let mut progress = false;
        if let Some((data, offset)) = &mut self.out
            && let Poll::Ready(n) = Pin::new(&mut lanes[send].body).poll_write(cx, &data[*offset..])
        {
            let n = n?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            *offset += n;
            progress = true;
            if *offset == data.len() {
                self.out = None;
            }
        }
        if !self.ready {
            if self.head < 4 {
                let mut b = ReadBuf::new(&mut self.header[self.head..]);
                if let Poll::Ready(result) =
                    Pin::new(&mut lanes[receive].body).poll_read(cx, &mut b)
                {
                    result?;
                    let n = b.filled().len();
                    self.head += n;
                    progress |= n > 0;
                    if self.head == 4 {
                        let n = u32::from_be_bytes(self.header) as usize;
                        if n == 0 || n > self.config.max_record {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "HTTPS record bound",
                            )));
                        }
                        self.incoming.resize(n, 0);
                    }
                }
            }
            if self.head == 4 {
                let mut b = ReadBuf::new(&mut self.incoming[self.read..]);
                if let Poll::Ready(result) =
                    Pin::new(&mut lanes[receive].body).poll_read(cx, &mut b)
                {
                    result?;
                    let n = b.filled().len();
                    self.read += n;
                    progress |= n > 0;
                    self.ready = self.read == self.incoming.len();
                }
            }
        }
        if self.head > 0 && !self.ready {
            self.arm();
        } else if self.out.is_none() {
            self.operation = None;
        }
        if progress {
            cx.waker().wake_by_ref();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests;
