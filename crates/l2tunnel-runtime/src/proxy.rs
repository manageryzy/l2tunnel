//! Explicit fixed-credit TUN proxy over the original authenticated TLS lanes.
//! All transparent and proxy records share bounded scheduling; native TCP state
//! remains in the maintained pure proxy table. No implicit client selection.

use super::{Compression, Duplex, RuntimeConfig, invalid};
use l2tunnel_auth::{AuthenticatedConnection, SessionConfig};
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::{PacketDevice, PacketLayer};
use l2tunnel_packet::{Classification, FlowKey};
use l2tunnel_tcp_proxy::{self as proxy, Millis, Window, session};
use std::{io, time::Duration};

mod actor;
mod arbiter;
mod config;
/// Explicit measured-profile actor over the same bounded retained-lane machinery.
/// Client selection and native advertised-window qualification are separate gates.
pub mod measured;
#[path = "proxy/io.rs"]
mod transport;
pub(crate) use transport::control_interval;
mod wire;
pub use config::{
    Config, DeliveryPolicy, IpPrefix, MemoryBound, MuxPolicy, NativePolicy, PortRange, RelayPolicy,
    RoutePolicy, RouteRule, Timeouts, session_config,
};

/// Original authenticated TLS streams with a fixed verified proxy profile.
pub struct Link {
    inner: super::Link,
    binding: SessionConfig,
    originator: bool,
    logical: [u8; 16],
}
fn checked(connection: &AuthenticatedConnection, config: &Config) -> io::Result<bool> {
    checked_bound(connection, session_config(config)?)
}
fn checked_bound(connection: &AuthenticatedConnection, binding: SessionConfig) -> io::Result<bool> {
    if connection.info().config != binding
        || connection.profile() != l2tunnel_auth::TlsIoProfile::TcpTls
    {
        return Err(invalid("proxy authenticated profile mismatch"));
    }
    Ok(connection.info().peer_member.is_none())
}
impl Link {
    /// Retain one mutually authenticated full-duplex ordinary TCP/TLS connection.
    pub fn full(connection: AuthenticatedConnection, config: &Config) -> io::Result<Self> {
        let originator = checked(&connection, config)?;
        if config.duplex != Duplex::Full {
            return Err(invalid("proxy full/half mismatch"));
        }
        let logical = connection.info().session_id;
        let binding = connection.info().config;
        Ok(Self {
            inner: super::Link::full(connection),
            binding,
            originator,
            logical,
        })
    }
}
/// Prove the existing first/second authenticated pair and retain both physical lanes.
pub async fn client_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    config: &Config,
) -> io::Result<Link> {
    if config.duplex != Duplex::Half || !checked(&first, config)? || !checked(&second, config)? {
        return Err(invalid("proxy client pair role/profile"));
    }
    let logical = first.info().session_id;
    let binding = first.info().config;
    let inner = super::client_pair(first, second).await?;
    Ok(Link {
        inner,
        binding,
        originator: true,
        logical,
    })
}
/// Accept the existing pairing proof without replacing either authenticated TLS object.
pub async fn server_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    config: &Config,
) -> io::Result<Link> {
    if config.duplex != Duplex::Half || checked(&first, config)? || checked(&second, config)? {
        return Err(invalid("proxy server pair role/profile"));
    }
    let logical = first.info().session_id;
    let binding = first.info().config;
    let inner = super::server_pair(first, second).await?;
    Ok(Link {
        inner,
        binding,
        originator: false,
        logical,
    })
}
/// Observable lifecycle; only Closed represents a completed session drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Validating all retained Start/Ready records.
    Starting,
    /// Native admission is active.
    Forwarding,
    /// New proxy ownership is frozen; existing owned TCP work still progresses.
    Quiescing,
    /// Exact final fences and TLS close are in progress.
    Closing,
    /// Exact drain and every original TLS direction completed.
    Closed,
    /// Explicit abnormal failure; retained ownership is not reported as delivered.
    Failed,
}
/// Bounded local counters; no application-consumption guarantee.
#[derive(Clone, Debug)]
pub struct Status {
    /// Current phase.
    pub phase: Phase,
    /// Lifetime proxy owners allocated.
    pub flows: usize,
    /// Currently active proxy owners.
    pub active: usize,
    /// Explicit terminal flow failures/refusals.
    pub stopped: usize,
    /// Pure-table clean retirements.
    pub retired: usize,
    /// Framed common-arbiter bytes still retained.
    pub queued_bytes: usize,
    /// Common-arbiter records still retained.
    pub queued_records: usize,
    /// Original transparent bytes admitted to the reliable writer.
    pub transparent_admitted_bytes: u64,
    /// Original transparent packets admitted to the reliable writer.
    pub transparent_admitted_packets: u64,
    /// Peer transparent packets actually accepted by this native device.
    pub native_confirmed_packets: u64,
    /// Bounded terminal diagnostic, never key material.
    pub failure: Option<String>,
}
/// Successful session closure with explicit abnormal-flow attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseReport {
    /// Final locally handed user-record count.
    pub local_user_records: u64,
    /// Exact remote final user-record count.
    pub peer_user_records: u64,
    /// Original transparent packets handed locally.
    pub local_transparent_packets: u64,
    /// Remote transparent packets actually written to TUN.
    pub native_confirmed_packets: u64,
    /// Lifetime clean retired proxy flows.
    pub clean_flows: usize,
    /// Rejected/abnormally stopped flows, not falsely counted as clean streams.
    pub stopped_flows: usize,
    /// Original physical TLS connections closed in both directions.
    pub tls_lanes_closed: usize,
}
type Reply = tokio::sync::oneshot::Sender<Result<CloseReport, String>>;
/// One queued local command, one active drain reply and coalesced read-only status.
#[derive(Clone)]
pub struct Handle {
    sender: tokio::sync::mpsc::Sender<Reply>,
    status: tokio::sync::watch::Receiver<Option<Status>>,
}
/// Runtime-owned bounded administrative input.
pub struct Control {
    receiver: tokio::sync::mpsc::Receiver<Reply>,
    status: StatusSink,
}
enum StatusSink {
    Fixed(tokio::sync::watch::Sender<Option<Status>>),
    Measured(tokio::sync::watch::Sender<Option<measured::Status>>),
}
/// Await one finite session drain result; dropping this waiter cannot assert success.
pub struct DrainWaiter(tokio::sync::oneshot::Receiver<Result<CloseReport, String>>);
impl DrainWaiter {
    /// Wait for the runtime's exact close proof or explicit failure.
    pub async fn wait(self) -> io::Result<CloseReport> {
        self.0
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)
    }
}
impl Handle {
    /// Latest bounded snapshot, without issuing network traffic.
    pub fn status(&self) -> Option<Status> {
        self.status.borrow().clone()
    }
    /// Queue one request; saturation returns WouldBlock and does not renew a deadline.
    pub fn request_drain(&self) -> io::Result<DrainWaiter> {
        request_drain(&self.sender)
    }
}
fn request_drain(sender: &tokio::sync::mpsc::Sender<Reply>) -> io::Result<DrainWaiter> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    sender.try_send(tx).map_err(|e| {
        io::Error::new(
            match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe,
            },
            "proxy drain command unavailable",
        )
    })?;
    Ok(DrainWaiter(rx))
}
/// Create the bounded command channel; retaining Handle owns the local controller.
pub fn control_channel() -> (Handle, Control) {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let (status, snapshot) = tokio::sync::watch::channel(None);
    (
        Handle {
            sender,
            status: snapshot,
        },
        Control {
            receiver,
            status: StatusSink::Fixed(status),
        },
    )
}

/// Forward fixed-credit proxy and transparent TUN records on retained TLS.
/// Returns success only after exact fences, native writes and every TLS task close.
/// Dropping the future aborts its owned tasks; it never reports delivery success.
pub async fn run<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    config: Config,
    control: Control,
) -> io::Result<CloseReport> {
    actor::run(device, link, config, control).await
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
