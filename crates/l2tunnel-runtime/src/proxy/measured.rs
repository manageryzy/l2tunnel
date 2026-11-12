//! Explicit measured proxy profile and actual retained authenticated lanes.
//!
//! Measurement work shares the existing actor's native and wire admission policy.
//! Only authenticated version-two records reach the Controller; native TCP window
//! advertisement remains owned by the maintained TCP stack.
use super::{Duplex, SessionConfig, invalid};
use l2tunnel_auth::AuthenticatedConnection;
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use l2tunnel_tcp_proxy::{Millis, measurement, session};
use std::io;

#[cfg(test)]
pub(super) mod config_tests;
/// Exact structural version-two user envelopes; parsing never authenticates data.
pub mod envelope;
mod ledger;
mod state;
pub(super) use ledger::{Id, Ledger};
pub(super) use state::State;
pub use state::{FlowSnapshot, Snapshot};

const DOMAIN: &[u8] = b"l2tunnel/tun-tcp-proxy-adaptive/v1/fixed-rings/measured-relay\0";
const MAX_MICROS: u64 = 120_000_000;
/// Bounded actor scheduling, authenticated before any native input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServicePolicy {
    /// Lifetime flow rows considered for due reports per turn, in 1..=64.
    pub report_work_per_turn: u16,
    /// Common source-admission attempts per turn, in 1..=64.
    pub admission_work_per_turn: u16,
    /// Exact full-write callbacks processed per turn, in 1..=64.
    pub callback_work_per_turn: u16,
    /// Positive planning cadence, in 1ms..=120s.
    pub plan_interval_micros: u64,
    /// Positive bounded snapshot cadence, in 1ms..=120s.
    pub status_interval_micros: u64,
}
/// Immutable measured profile; fixed proxy defaults remain a separate profile.
#[derive(Clone, Debug)]
pub struct Config {
    /// Exact existing TUN, ring, route, MUX, lane and close policy.
    pub fixed: super::Config,
    /// Actual-table allocation, bounded record ownership and observation policy.
    pub measured: measurement::MeasuredConfig,
    /// Negotiated bounded actor service geometry.
    pub service: ServicePolicy,
}
/// Checked retained components and transient status/plan copies; TLS and allocator
/// internals remain outside this explicit component accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryBound {
    /// Existing fixed actor's explicit payload and metadata bound.
    pub fixed: super::MemoryBound,
    /// Actual Controller's live, shadow and fixed derived-view allocations.
    pub controller: measurement::ObservationMemory,
    /// Maximum immutable admitted token slots, covering every lifetime flow.
    pub token_slots: usize,
    /// All possible measurement copies, including 24+48 bytes per user envelope.
    /// This fits inside existing common caps and is not extra queue credit.
    pub all_measurement_copy_bytes: usize,
    /// Fixed immutable proof bytes, in addition to token/ordinal metadata.
    pub immutable_proof_bytes: usize,
    /// Complete bounded handoff ledger including its fixed proof arrays.
    pub handoff_bytes: usize,
    /// Bounded service timers and copied lifetime snapshot rows.
    pub service_bytes: usize,
    /// Base, Controller, handoff and service storage.
    pub base_and_controller_bytes: usize,
}
impl Config {
    /// Validate exact duration conversion and both actual table-role geometries.
    /// Empty validation tables have no native legs and convey no session authority.
    pub fn validate(&self) -> io::Result<MemoryBound> {
        let fixed = self.fixed.validate()?;
        let poll = self.fixed.runtime.poll_interval;
        if !poll.subsec_nanos().is_multiple_of(1000) {
            return Err(invalid("measured poll interval must be exact microseconds"));
        }
        let poll: u64 = poll.as_micros().try_into().map_err(io::Error::other)?;
        let s = self.service;
        let o = self.measured.observation;
        let b = self.measured.ownership;
        if [
            s.report_work_per_turn,
            s.admission_work_per_turn,
            s.callback_work_per_turn,
        ]
        .into_iter()
        .any(|n| !(1..=64).contains(&n))
            || [s.plan_interval_micros, s.status_interval_micros]
                .into_iter()
                .any(|n| !(1000..=MAX_MICROS).contains(&n))
            || [
                o.report_interval_micros,
                o.rate_interval_micros,
                b.probe_interval_micros,
                s.plan_interval_micros,
                s.status_interval_micros,
            ]
            .into_iter()
            .any(|n| poll == 0 || poll > n)
        {
            return Err(invalid("measured service policy"));
        }
        let n = self.fixed.relay.max_flows;
        let slots = n
            .checked_mul(2)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| invalid("measured slot overflow"))?;
        let scan = |count: usize, work: u16| -> io::Result<u64> {
            u64::try_from(count.div_ceil(usize::from(work)))
                .ok()
                .and_then(|v| v.checked_mul(poll))
                .ok_or_else(|| invalid("measured service arithmetic"))
        };
        if scan(n, s.report_work_per_turn)? > o.report_interval_micros
            || scan(slots, s.callback_work_per_turn)? >= b.handoff_timeout_micros
        {
            return Err(invalid("measured service cannot cover configured slots"));
        }
        let first = session::Table::new(self.fixed.table([1; 16], true, 1), Millis(0))
            .map_err(io::Error::other)?;
        let second = session::Table::new(self.fixed.table([1; 16], false, 1), Millis(0))
            .map_err(io::Error::other)?;
        let controller = self.measured.validate(&first).map_err(io::Error::other)?;
        if self.measured.validate(&second).map_err(io::Error::other)? != controller {
            return Err(invalid("measured role geometry differs"));
        }
        let all_measurement_copy_bytes = n
            .checked_mul(304)
            .and_then(|v| v.checked_add(128))
            .ok_or_else(|| invalid("measured copy arithmetic"))?;
        let immutable_proof_bytes = slots
            .checked_mul(104)
            .ok_or_else(|| invalid("measured proof arithmetic"))?;
        let handoff_bytes = Ledger::bytes(slots)?;
        let service_bytes = State::storage_bytes(n)?;
        let base_and_controller_bytes = fixed
            .payload_bytes
            .checked_add(controller.retained_bytes)
            .and_then(|v| v.checked_add(controller.scratch_bytes))
            .and_then(|v| v.checked_add(controller.view_bytes))
            .and_then(|v| v.checked_add(handoff_bytes))
            .and_then(|v| v.checked_add(service_bytes))
            .filter(|v| *v <= 268_435_456)
            .ok_or_else(|| invalid("measured aggregate memory bound"))?;
        Ok(MemoryBound {
            fixed,
            controller,
            token_slots: slots,
            all_measurement_copy_bytes,
            immutable_proof_bytes,
            handoff_bytes,
            service_bytes,
            base_and_controller_bytes,
        })
    }
    /// Bounded canonical authentication input, independent of Debug/JSON order.
    pub fn canonical_bytes(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(&super::session_config(&self.fixed)?.digest.0);
        bytes.extend_from_slice(&[1, envelope::VERSION, measurement::wire::VERSION, 1]);
        let a = self.measured.allocation;
        let t = a.target;
        let b = self.measured.ownership;
        let o = self.measured.observation;
        let s = self.service;
        let words = [
            t.initial.bytes,
            t.initial.records,
            t.minimum.bytes,
            t.minimum.records,
            t.session_cap.bytes,
            t.session_cap.records,
            t.per_flow_cap.bytes,
            t.per_flow_cap.records,
            t.policy_cap.bytes,
            t.policy_cap.records,
            t.queue_allowance_bytes,
            t.queue_delay_target_micros,
            t.many_flow_step.bytes,
            t.many_flow_step.records,
            t.few_flow_threshold.try_into().map_err(io::Error::other)?,
            t.max_flows.try_into().map_err(io::Error::other)?,
            t.bootstrap_rtt_micros,
            t.recovery_rtts,
            a.minimum_per_flow.bytes,
            a.minimum_per_flow.records,
            b.pending_ttl_micros,
            b.probe_interval_micros,
            b.probe_timeout_micros,
            b.handoff_timeout_micros,
            b.emission_interval_micros,
            u64::from(b.max_records_per_interval),
            o.report_interval_micros,
            o.sample_ttl_micros,
            o.demand_idle_micros,
            o.rate_interval_micros,
            u64::from(o.rate_bins),
            u64::from(s.report_work_per_turn),
            u64::from(s.admission_work_per_turn),
            u64::from(s.callback_work_per_turn),
            s.plan_interval_micros,
            s.status_interval_micros,
            44,
            4,
            24,
            48,
            104,
            56,
            2,
            1,
            1,
            1,
            104,
        ];
        for word in words {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        Ok(bytes)
    }
}
/// Exact separate profile; does not change the fixed-credit digest or TLS verifier.
pub fn session_config(config: &Config) -> io::Result<SessionConfig> {
    let hash = ring::digest::digest(&ring::digest::SHA256, &config.canonical_bytes()?);
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.as_ref());
    Ok(SessionConfig {
        layer: PacketLayer::Ip,
        digest: ConfigDigest(digest),
    })
}
/// Real retained authenticated lane owners for the explicit measured actor.
pub struct Link {
    inner: super::Link,
}
impl Link {
    /// Retain one actual mutually authenticated ordinary TCP/TLS connection.
    pub fn full(connection: AuthenticatedConnection, config: &Config) -> io::Result<Self> {
        let binding = session_config(config)?;
        let originator = super::checked_bound(&connection, binding)?;
        if config.fixed.duplex != Duplex::Full {
            return Err(invalid("measured full/half mismatch"));
        }
        let logical = connection.info().session_id;
        Ok(Self {
            inner: super::Link {
                inner: super::super::Link::full(connection),
                binding,
                originator,
                logical,
            },
        })
    }
    /// Exact already-verified configuration bound to every retained lane.
    pub const fn binding(&self) -> SessionConfig {
        self.inner.binding
    }
    /// Actual authenticated role; never an unchecked caller assertion.
    pub const fn role(&self) -> session::Role {
        if self.inner.originator {
            session::Role::Originator
        } else {
            session::Role::Acceptor
        }
    }
    /// Shared first-lane logical identity, distinct from each physical lane session.
    pub const fn logical_session(&self) -> [u8; 16] {
        self.inner.logical
    }
}
/// Complete the actual existing pairing proof and retain both original TLS objects.
pub async fn client_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    config: &Config,
) -> io::Result<Link> {
    let binding = session_config(config)?;
    if config.fixed.duplex != Duplex::Half
        || !super::checked_bound(&first, binding)?
        || !super::checked_bound(&second, binding)?
    {
        return Err(invalid("measured client pair role/profile"));
    }
    let logical = first.info().session_id;
    let inner = super::super::client_pair(first, second).await?;
    Ok(Link {
        inner: super::Link {
            inner,
            binding,
            originator: true,
            logical,
        },
    })
}
/// Accept pairing with exact member/config/server agreement before owning both lanes.
pub async fn server_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    config: &Config,
) -> io::Result<Link> {
    let binding = session_config(config)?;
    if config.fixed.duplex != Duplex::Half
        || super::checked_bound(&first, binding)?
        || super::checked_bound(&second, binding)?
    {
        return Err(invalid("measured server pair role/profile"));
    }
    let logical = first.info().session_id;
    let inner = super::super::server_pair(first, second).await?;
    Ok(Link {
        inner: super::Link {
            inner,
            binding,
            originator: false,
            logical,
        },
    })
}
/// Coalesced local observation; only the actual actor publishes lifecycle results.
#[derive(Clone, Debug)]
pub struct Status {
    /// Existing native ownership, queue and closure facts.
    pub runtime: super::Status,
    /// Actual Controller and immutable full-write handoff facts.
    pub measurement: Snapshot,
}
/// One bounded drain-command producer and one coalesced observation subscription.
#[derive(Clone)]
pub struct Handle {
    sender: tokio::sync::mpsc::Sender<super::Reply>,
    status: tokio::sync::watch::Receiver<Option<Status>>,
}
/// Runtime-owned command receiver; no second measurement command queue exists.
pub struct Control(super::Control);
impl Handle {
    /// Latest copied actual observation, with no network/measurement side effects.
    pub fn status(&self) -> Option<Status> {
        self.status.borrow().clone()
    }
    /// Submit finite drain; acceptance is distinct from the waiter's actual result.
    pub fn request_drain(&self) -> io::Result<super::DrainWaiter> {
        super::request_drain(&self.sender)
    }
}
/// Allocate one command slot and one replaceable bounded lifetime snapshot.
pub fn control_channel() -> (Handle, Control) {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let (status, snapshot) = tokio::sync::watch::channel(None);
    (
        Handle {
            sender,
            status: snapshot,
        },
        Control(super::Control {
            receiver,
            status: super::StatusSink::Measured(status),
        }),
    )
}
/// Run the actual common proxy actor with measured relay target allocation.
/// Admitted measurements retain ownership through full write/flush and the original
/// drain deadline. This API does not claim exact native advertised-window settings.
pub async fn run<D: l2tunnel_device::PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    config: Config,
    control: Control,
) -> io::Result<super::CloseReport> {
    config.validate()?;
    super::actor::run_profile(
        device,
        link.inner,
        config.fixed.clone(),
        control.0,
        Some(config),
    )
    .await
}
