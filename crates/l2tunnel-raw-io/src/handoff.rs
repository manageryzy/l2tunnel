//! Opt-in checked bridge freeze and transfer of the original packet I/O owner.
//!
//! These capabilities prove local stream/packet ownership only. A TLS manager
//! must separately authenticate the transition, freeze rustls, quarantine early
//! phase packets and retain an old-prefix responder before real phase activation.
use crate::{Counters, PacketIo};
use l2tunnel_raw_tcp::handoff::{BootstrapSnapshot, QuiescentTcp, StreamProgress};
use l2tunnel_raw_tcp::{Config, Status};
use std::io;
use std::time::Duration;

mod driver;
/// Typed from-birth raw TLS pairing and retained private exporter ownership.
pub mod pairing;
mod records;
mod stream;
mod tls_owner;
pub use driver::{SwitchDriver, bridge_switchable};
pub use records::{
    AttachError, DirectionLimits, MAX_DIRECTION_BYTES, MAX_DIRECTION_RECORDS, MAX_IO_SLICES,
    MAX_POLL_BYTES, MAX_RECORD_PAYLOAD, RecordDirection, RecordFault, RecordFaultKind, RecordIo,
    RecordLimits, RecordProgress, RecordStatus,
};
pub use stream::{SwitchHandle, TrackedStream};
pub use tls_owner::{
    MessageError, MessageLimits, MessageProgress, MessageStatus, Setup, SetupFailure, StartError,
    StartFailure, TlsMessageOwner, begin_client, begin_server, message_session_config,
};

/// Immutable finite work and transition limits, validated before allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwitchLimits {
    /// Operations in each receive/poll/send pass; 1..=1024, also checked by the engine.
    pub work_limit: usize,
    /// Maximum accepted remaining handoff interval; 1..=30 seconds.
    pub max_handoff_duration: Duration,
}
impl Default for SwitchLimits {
    fn default() -> Self {
        Self {
            work_limit: 32,
            max_handoff_duration: Duration::from_secs(30),
        }
    }
}
impl SwitchLimits {
    fn validate(self) -> io::Result<()> {
        if !(1..=1024).contains(&self.work_limit)
            || !(Duration::from_secs(1)..=Duration::from_secs(30))
                .contains(&self.max_handoff_duration)
        {
            return Err(invalid("switch driver limits"));
        }
        Ok(())
    }
}
/// Exact original bytes accepted/consumed by the stream endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EndpointProgress {
    /// Bytes accepted from the caller into the outgoing finite bridge.
    pub written: u64,
    /// Bytes actually consumed by the caller from the incoming finite bridge.
    pub read: u64,
}
/// Checked driver totals, distinct from saturating retained-driver diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BridgeProgress {
    /// Original bytes read from the caller bridge.
    pub outbound_read: u64,
    /// Ordered original bytes written to the caller bridge.
    pub inbound_written: u64,
    /// Complete packets received from the packet adapter, including rejects.
    pub raw_received_packets: u64,
    /// Complete IP bytes received from the packet adapter, including rejects.
    pub raw_received_bytes: u64,
    /// Packets removed from the engine, possibly still retained across WouldBlock.
    pub raw_popped_packets: u64,
    /// Bytes removed from the engine, possibly still retained across WouldBlock.
    pub raw_popped_bytes: u64,
    /// Packets actually accepted by atomic PacketIo::send; not peer receipt.
    pub raw_sent_packets: u64,
    /// Bytes actually accepted by atomic PacketIo::send; not peer receipt.
    pub raw_sent_bytes: u64,
    /// Malformed, foreign, over-MTU or queue-excess packets discarded before engine admission.
    pub discarded_packets: u64,
}
/// Observable local lifecycle; only the returned result transfers ownership.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SwitchState {
    /// The driver has not entered run; a handoff request is rejected.
    #[default]
    NotStarted,
    /// The original maintained TCP bridge remains active.
    Running,
    /// Endpoint polls are frozen and the original fixed deadline applies.
    Frozen,
    /// The driver committed and returned unique handoff ownership.
    Handoff,
    /// The retained TCP FIN/ACK path completed; no handoff was produced.
    Clean,
    /// The driver failed or was cancelled; no rollback is allowed after freeze.
    Failed,
}
/// Coalesced diagnostic observation, never an authenticated drain capability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SwitchStatus {
    /// Current local state.
    pub state: SwitchState,
    /// Time since the driver's start at the last published driver turn.
    pub elapsed: Duration,
    /// Actual endpoint progress; immutable after freeze.
    pub endpoint: EndpointProgress,
    /// Last published exact driver progress.
    pub driver: BridgeProgress,
    /// Last maintained state, absent before the driver starts.
    pub engine: Option<Status>,
    /// Fixed absolute handoff deadline since driver start, if accepted.
    pub deadline: Option<Duration>,
}
/// Immutable local bridge proof, created only with a successful unique transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeProof {
    endpoint: EndpointProgress,
    driver: BridgeProgress,
    engine: StreamProgress,
}
impl BridgeProof {
    /// Endpoint totals captured atomically when both directions froze.
    pub fn endpoint(&self) -> EndpointProgress {
        self.endpoint
    }
    /// Exact physical-I/O and duplex totals at the transfer boundary.
    pub fn driver(&self) -> BridgeProgress {
        self.driver
    }
    /// Original maintained stream totals from its construction.
    pub fn engine(&self) -> StreamProgress {
        self.engine
    }
}
/// Original I/O plus unique logical capability and its matching local proof.
///
/// No public constructor or Clone can manufacture another transferable owner.
/// This is not an authenticated peer barrier, real TLS freeze or native delivery proof.
#[must_use]
pub struct HandoffParts<I: PacketIo> {
    inner: Box<OwnedHandoff<I>>,
}
struct OwnedHandoff<I: PacketIo> {
    io: I,
    tcp: QuiescentTcp,
    proof: BridgeProof,
}
impl<I: PacketIo> HandoffParts<I> {
    /// Inspect the maintained logical boundary without moving its capability.
    pub fn snapshot(&self) -> &BootstrapSnapshot {
        self.inner.tcp.snapshot()
    }
    /// Inspect the exact bridge and atomic-send equalities.
    pub fn proof(&self) -> &BridgeProof {
        &self.inner.proof
    }
    /// Transfer the original I/O, unique TCP capability and matching proof once.
    pub fn into_parts(self) -> (I, QuiescentTcp, BridgeProof) {
        let OwnedHandoff { io, tcp, proof } = *self.inner;
        (io, tcp, proof)
    }
}
/// Actual driver completion; a request/status alone is never this result.
#[must_use]
pub enum SwitchExit<I: PacketIo> {
    /// Original maintained TCP orderly close, with retained-driver-compatible counters.
    Clean(Counters),
    /// Original packet owner transferred without FIN/RST or a replacement socket.
    Handoff(HandoffParts<I>),
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn aborted(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, message)
}
fn exhausted() -> io::Error {
    io::Error::other("switch driver exact counter exhausted")
}
fn reserve(current: u64, possible: usize) -> io::Result<u64> {
    current
        .checked_add(u64::try_from(possible).map_err(|_| exhausted())?)
        .ok_or_else(exhausted)
}
fn charged(ceiling: u64, possible: usize, actual: usize) -> u64 {
    // All callers use maintained fixed buffers/atomic I/O where actual <= possible.
    ceiling - (possible - actual) as u64
}
fn geometry(config: Config) -> io::Result<()> {
    l2tunnel_raw_tcp::IpConfig::from(config)
        .validate()
        .map_err(io::Error::other)
}
