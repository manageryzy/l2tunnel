//! Explicit measured TUN proxy policy and original authenticated lane ownership.
use crate::{ConnectionConfig, proxy};
use l2tunnel_auth::{self as auth, ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_core::Duplex;
use l2tunnel_device::PacketDevice;
use l2tunnel_flow_control::Credit;
use l2tunnel_runtime::proxy::measured as runtime;
use l2tunnel_tcp_proxy::{Window, adaptive, measurement};
use serde::Deserialize;
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener, TcpStream};

/// Actual shared close proof and finite drain waiter.
pub use proxy::{CloseReport, DrainWaiter};
/// Exact bounded measured runtime handles and copied observations.
pub use runtime::{
    Control, FlowSnapshot, Handle, ServicePolicy, Snapshot, Status, control_channel,
};
/// Maximum entire untrusted JSON policy, before any parser allocation.
pub const MAX_POLICY_BYTES: usize = 65_536;
/// Exact separately authenticated public profile identifier.
pub const PROFILE: &str = "measured-relay-v1";
#[cfg(unix)]
mod status;
#[cfg(unix)]
pub use status::{
    AckRate, Aggregate, AppliedTargets, Capabilities, Carrier, LaneMode, LocalSnapshot, Profile,
    ServiceLatency, TargetPhase, UdpCover,
};

/// Explicit operator settings; no measured field is inferred from an omitted key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Existing authoritative route/channel/TIME-WAIT policy.
    pub fixed: proxy::Settings,
    /// Exact allocation, immutable measurement ownership and observation policy.
    pub measured: measurement::MeasuredConfig,
    /// Exact bounded common-actor work and planning/status cadence.
    pub service: ServicePolicy,
}
impl Settings {
    /// Parse a strict bounded document. Complete connection-dependent bounds are
    /// checked by [`runtime_config`] before socket/device setup in every factory.
    pub fn from_json(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(invalid("measured policy input bound"));
        }
        let value: Document = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid strict measured policy JSON"))?;
        if value.version != 1 || value.profile != PROFILE {
            return Err(invalid("measured policy version/profile"));
        }
        Ok(Self {
            fixed: proxy::Settings::from_document(value.fixed)?,
            measured: measurement::MeasuredConfig {
                allocation: value.allocation.into(),
                ownership: value.ownership.into(),
                observation: value.observation.into(),
            },
            service: value.service.into(),
        })
    }
}
fn invalid(text: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, text)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u16,
    profile: String,
    fixed: proxy::Document,
    allocation: Allocation,
    ownership: Ownership,
    observation: Observation,
    service: Service,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Amount {
    bytes: u64,
    records: u64,
}
impl From<Amount> for Credit {
    fn from(v: Amount) -> Self {
        Self {
            bytes: v.bytes,
            records: v.records,
        }
    }
}
impl From<Amount> for Window {
    fn from(v: Amount) -> Self {
        Self {
            bytes: v.bytes,
            records: v.records,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Allocation {
    target: Target,
    minimum_per_flow: Amount,
}
impl From<Allocation> for adaptive::Config {
    fn from(v: Allocation) -> Self {
        Self {
            target: v.target.into(),
            minimum_per_flow: v.minimum_per_flow.into(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    initial: Amount,
    minimum: Amount,
    session_cap: Amount,
    per_flow_cap: Amount,
    policy_cap: Amount,
    queue_allowance_bytes: u64,
    queue_delay_target_micros: u64,
    many_flow_step: Amount,
    few_flow_threshold: usize,
    max_flows: usize,
    bootstrap_rtt_micros: u64,
    recovery_rtts: u64,
}
impl From<Target> for adaptive::TargetConfig {
    fn from(v: Target) -> Self {
        Self {
            initial: v.initial.into(),
            minimum: v.minimum.into(),
            session_cap: v.session_cap.into(),
            per_flow_cap: v.per_flow_cap.into(),
            policy_cap: v.policy_cap.into(),
            queue_allowance_bytes: v.queue_allowance_bytes,
            queue_delay_target_micros: v.queue_delay_target_micros,
            many_flow_step: v.many_flow_step.into(),
            few_flow_threshold: v.few_flow_threshold,
            max_flows: v.max_flows,
            bootstrap_rtt_micros: v.bootstrap_rtt_micros,
            recovery_rtts: v.recovery_rtts,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    pending_ttl_micros: u64,
    probe_interval_micros: u64,
    probe_timeout_micros: u64,
    handoff_timeout_micros: u64,
    emission_interval_micros: u64,
    max_records_per_interval: u16,
}
impl From<Ownership> for measurement::OwnerConfig {
    fn from(v: Ownership) -> Self {
        Self {
            pending_ttl_micros: v.pending_ttl_micros,
            probe_interval_micros: v.probe_interval_micros,
            probe_timeout_micros: v.probe_timeout_micros,
            handoff_timeout_micros: v.handoff_timeout_micros,
            emission_interval_micros: v.emission_interval_micros,
            max_records_per_interval: v.max_records_per_interval,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    report_interval_micros: u64,
    sample_ttl_micros: u64,
    demand_idle_micros: u64,
    rate_interval_micros: u64,
    rate_bins: u8,
}
impl From<Observation> for measurement::ObservationConfig {
    fn from(v: Observation) -> Self {
        Self {
            report_interval_micros: v.report_interval_micros,
            sample_ttl_micros: v.sample_ttl_micros,
            demand_idle_micros: v.demand_idle_micros,
            rate_interval_micros: v.rate_interval_micros,
            rate_bins: v.rate_bins,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Service {
    report_work_per_turn: u16,
    admission_work_per_turn: u16,
    callback_work_per_turn: u16,
    plan_interval_micros: u64,
    status_interval_micros: u64,
}
impl From<Service> for ServicePolicy {
    fn from(v: Service) -> Self {
        Self {
            report_work_per_turn: v.report_work_per_turn,
            admission_work_per_turn: v.admission_work_per_turn,
            callback_work_per_turn: v.callback_work_per_turn,
            plan_interval_micros: v.plan_interval_micros,
            status_interval_micros: v.status_interval_micros,
        }
    }
}

/// Validate the exact complete measured policy before any socket or device I/O.
pub fn runtime_config(
    connection: ConnectionConfig,
    settings: &Settings,
) -> io::Result<runtime::Config> {
    let value = runtime::Config {
        fixed: proxy::runtime_config(connection, &settings.fixed)?,
        measured: settings.measured,
        service: settings.service,
    };
    value.validate()?;
    Ok(value)
}
/// Immutable configuration inseparable from the actual authenticated lane owners.
pub struct Session {
    link: runtime::Link,
    config: runtime::Config,
}
impl Session {
    /// Exact measured configuration bound in both peers' member authentication.
    pub fn config(&self) -> &runtime::Config {
        &self.config
    }
    /// Run the real measured actor; success requires actual native/TLS close proof.
    /// Dropping this future is abnormal and never creates a terminal-success report.
    pub async fn run<D: PacketDevice<Error = io::Error>>(
        self,
        device: D,
        control: Control,
    ) -> io::Result<CloseReport> {
        runtime::run(device, self.link, self.config, control).await
    }
    /// Shared-service ownership: failure returns only after actual I/O children join.
    /// The service retains this future during late cleanup; drop is not a join proof.
    pub(crate) async fn run_service_owned<D: PacketDevice<Error = io::Error>>(
        self,
        device: D,
        control: Control,
    ) -> io::Result<CloseReport> {
        runtime::run_service_owned(device, self.link, self.config, control).await
    }
}
/// Authenticate and retain one or two measured lanes under one setup deadline.
pub async fn connect(
    address: SocketAddr,
    tls: &ClientTls,
    name: &str,
    member: &MemberKey,
    connection: ConnectionConfig,
    settings: &Settings,
) -> io::Result<Session> {
    let config = runtime_config(connection, settings)?;
    proxy::remote(address)?;
    let binding = runtime::session_config(&config)?;
    let end = proxy::deadline(connection.handshake_timeout)?;
    proxy::within(end, async {
        let lane = async || {
            let stream = TcpStream::connect(address).await?;
            stream.set_nodelay(true)?;
            auth::client_connect(stream, tls, name, member, binding, proxy::remaining(end)?)
                .await
                .map_err(proxy::auth_error)
        };
        let first = lane().await?;
        let link = match connection.duplex {
            Duplex::Full => runtime::Link::full(first, &config)?,
            Duplex::Half => {
                let second = lane().await?;
                proxy::remaining(end)?;
                runtime::client_pair(first, second, &config).await?
            }
        };
        Ok(Session { link, config })
    })
    .await
}
/// Accept first TCP connection through final paired proof under the original deadline.
pub async fn accept(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    connection: ConnectionConfig,
    settings: &Settings,
) -> io::Result<Session> {
    let config = runtime_config(connection, settings)?;
    let binding = runtime::session_config(&config)?;
    let end = proxy::deadline(connection.handshake_timeout)?;
    proxy::within(end, async {
        let lane = async || {
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true)?;
            auth::server_accept(stream, tls, allowlist, binding, proxy::remaining(end)?)
                .await
                .map_err(proxy::auth_error)
        };
        let first = lane().await?;
        let link = match connection.duplex {
            Duplex::Full => runtime::Link::full(first, &config)?,
            Duplex::Half => {
                let second = lane().await?;
                proxy::remaining(end)?;
                runtime::server_pair(first, second, &config).await?
            }
        };
        Ok(Session { link, config })
    })
    .await
}

#[cfg(test)]
mod tests;
