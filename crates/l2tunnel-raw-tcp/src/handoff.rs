//! Checked stream accounting and one-owner logical TCP quiescence.
//!
//! This module neither authenticates a stream nor proves physical packet sends.
//! A separate I/O owner must drain every packet removed through `pop_packet` and
//! prove its bridge counters before treating the capability as a native handoff.
use super::{Config, IpConfig, Millis, ReadOutcome, Role, Status, TcpEngine, TimeWaitResetPolicy};
use std::fmt;

/// Direction of a checked stream counter, independent of raw packet numbering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamSide {
    /// Original bytes admitted to the maintained send ring.
    Send,
    /// Ordered bytes consumed from the maintained receive ring.
    Receive,
}
/// Exact lifetime stream progress from the original engine construction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StreamProgress {
    /// Original bytes accepted by the maintained send ring, including unacknowledged bytes.
    pub send_admitted: u64,
    /// Ordered bytes copied out of the maintained receive ring.
    pub receive_consumed: u64,
}
/// Explicit tracked operation failure; counter rejection precedes stream mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The existing maintained engine rejected the operation.
    Engine(super::Error),
    /// The maximum possible progress cannot fit the remaining absolute counter.
    CounterExhausted(StreamSide),
}
impl From<super::Error> for Error {
    fn from(error: super::Error) -> Self {
        Self::Engine(error)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tracked raw TCP: {self:?}")
    }
}
impl std::error::Error for Error {}

/// A consume rejection returns the original tracked owner without polling it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    /// The requested time is outside the maintained engine's checked domain.
    Time,
    /// The owner was not polled at this exact injected time.
    StalePoll,
    /// Engine-owned ingress or egress packets still need processing or transmission.
    QueuedPacket,
    /// One direction lacks a positive post-handshake stream prefix.
    EmptyPrefix,
    /// Maintained state, rings, assembler, acknowledgments or timers are not quiescent.
    NotQuiescent,
    /// The first packet-phase contract does not preserve negotiated timestamps.
    UnsupportedOption,
}
impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "raw TCP handoff: {self:?}")
    }
}
impl std::error::Error for HandoffError {}

/// Read-only logical bootstrap boundary; this value alone is not a capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapSnapshot {
    /// Original fixed tuple, queue dimensions and maintained bootstrap policy.
    pub config: IpConfig,
    /// Original handshake role, unchanged across transfer.
    pub role: Role,
    /// Exact injected time of the last maintained poll and successful consume.
    pub polled_at: Millis,
    /// Checked complete stream totals, never saturating diagnostic counters.
    pub progress: StreamProgress,
    /// Authoritative maintained sequence/window state; emission is not physical send.
    pub tcp: smoltcp::socket::tcp::QuiescentSnapshot,
}
/// Unique logical quiescent capability, with no public constructor or cloning.
///
/// Dropping this object performs no I/O. Its producer does not prove TLS freeze,
/// authenticated peer barriers, empty external queues, or actual native delivery.
#[derive(Debug)]
#[must_use]
pub struct QuiescentTcp {
    snapshot: BootstrapSnapshot,
}
impl QuiescentTcp {
    /// Inspect the fixed logical boundary without duplicating its capability.
    pub fn snapshot(&self) -> &BootstrapSnapshot {
        &self.snapshot
    }
}

/// Exclusive opt-in owner tracking the original maintained connection from birth.
///
/// There is no adoption or mutable inner-engine accessor that can bypass totals.
/// The fixed engine allocation also keeps owner-returning failures small.
pub struct TrackedEngine {
    inner: Box<TcpEngine>,
    role: Role,
    progress: StreamProgress,
}
impl fmt::Debug for TrackedEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackedEngine")
            .field("role", &self.role)
            .field("progress", &self.progress)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}
impl TrackedEngine {
    /// Checked inline and fixed heap metadata for one original owner.
    ///
    /// Counts this value, the boxed `TcpEngine`, and its one maintained
    /// `SocketStorage` element. Payload rings/packet buffers, queue descriptors,
    /// allocator rounding and control blocks require separate accounting.
    /// Inline bytes may already be present in a caller's aggregate `size_of`;
    /// adding this whole value there is conservative, not exact process RSS.
    pub fn fixed_metadata_bytes() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<TcpEngine>())?
            .checked_add(std::mem::size_of::<smoltcp::iface::SocketStorage<'static>>())
    }
    /// Construct an original IPv4 maintained owner with zero exact counters.
    pub fn new(config: Config, role: Role, now: Millis) -> Result<Self, Error> {
        Self::new_ip(config.into(), role, now)
    }
    /// Construct an original same-family IPv4/IPv6 maintained owner.
    pub fn new_ip(config: IpConfig, role: Role, now: Millis) -> Result<Self, Error> {
        Ok(Self {
            inner: Box::new(TcpEngine::new_ip(config, role, now)?),
            role,
            progress: StreamProgress::default(),
        })
    }
    /// Preserve the existing pre-first-poll TIME-WAIT policy selection contract.
    pub fn set_time_wait_reset_policy(&mut self, policy: TimeWaitResetPolicy) -> Result<(), Error> {
        Ok(self.inner.set_time_wait_reset_policy(policy)?)
    }
    /// Admit one complete packet through the existing authoritative parser and bounds.
    pub fn ingest(&mut self, packet: &[u8]) -> Result<(), Error> {
        Ok(self.inner.ingest(packet)?)
    }
    /// Poll the maintained engine with the same checked time and finite work limit.
    pub fn poll(&mut self, now: Millis, work_limit: usize) -> Result<(), Error> {
        Ok(self.inner.poll(now, work_limit)?)
    }
    /// Transfer one exact packet to the caller, who must retain it until actual send.
    /// An empty engine queue does not prove a previously removed packet was sent.
    pub fn pop_packet(&mut self) -> Option<Vec<u8>> {
        self.inner.pop_packet()
    }
    /// Admit original bytes after checking the entire caller slice's counter bound.
    /// Only actual accepted progress is charged; zero/partial sends preserve remainder ownership.
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let maximum = count(bytes.len(), StreamSide::Send)?;
        let ceiling = self
            .progress
            .send_admitted
            .checked_add(maximum)
            .ok_or(Error::CounterExhausted(StreamSide::Send))?;
        let accepted = self.inner.write(bytes)?;
        // Maintained send_slice returns at most the supplied slice length.
        // Preflight makes this exact post-operation assignment infallible.
        self.progress.send_admitted = ceiling - (maximum - accepted as u64);
        Ok(accepted)
    }
    /// Consume ordered bytes after checking maximum possible returned progress.
    /// Overflow leaves both the caller buffer and maintained receive ring unchanged.
    pub fn read(&mut self, output: &mut [u8]) -> Result<ReadOutcome, Error> {
        let possible = self.inner.status().receive_bytes.min(output.len());
        let maximum = count(possible, StreamSide::Receive)?;
        let ceiling = self
            .progress
            .receive_consumed
            .checked_add(maximum)
            .ok_or(Error::CounterExhausted(StreamSide::Receive))?;
        let result = self.inner.read(output)?;
        if let ReadOutcome::Data(consumed) = result {
            // recv_slice cannot exceed the readable bytes or supplied buffer.
            self.progress.receive_consumed = ceiling - (maximum - consumed as u64);
        }
        Ok(result)
    }
    /// Request ordinary retained TCP FIN; this makes packet-phase consume unavailable.
    pub fn close(&mut self) {
        self.inner.close();
    }
    /// Request the existing maintained reset behavior; consume cannot hide the abort.
    pub fn abort(&mut self) {
        self.inner.abort();
    }
    /// Inspect maintained ownership without reading time or changing state.
    pub fn status(&self) -> Status {
        self.inner.status()
    }
    /// Inspect actual accepted/consumed lifetime bytes without mutating the owner.
    pub fn progress(&self) -> StreamProgress {
        self.progress
    }
    /// Consume only after an exact-time poll, positive duplex prefixes and full logical drain.
    ///
    /// Failure returns the original owner without polling, closing or changing it.
    /// Success drops only in-memory maintained state; no FIN/RST or other I/O occurs.
    /// The caller still owes external bridge/physical-send and authenticated TLS proofs.
    pub fn try_into_quiescent(self, now: Millis) -> Result<QuiescentTcp, (Self, HandoffError)> {
        match self.snapshot(now) {
            Ok(snapshot) => Ok(QuiescentTcp { snapshot }),
            Err(error) => Err((self, error)),
        }
    }
    fn snapshot(&self, now: Millis) -> Result<BootstrapSnapshot, HandoffError> {
        let time = super::time(now).map_err(|_| HandoffError::Time)?;
        if !self.inner.polled || now != self.inner.last_time {
            return Err(HandoffError::StalePoll);
        }
        let status = self.inner.status();
        if status.incoming_packets != 0 || status.outgoing_packets != 0 {
            return Err(HandoffError::QueuedPacket);
        }
        if self.progress.send_admitted == 0 || self.progress.receive_consumed == 0 {
            return Err(HandoffError::EmptyPrefix);
        }
        if status.close_reason.is_some() || status.peer_fin {
            return Err(HandoffError::NotQuiescent);
        }
        let tcp = self
            .inner
            .endpoint()
            .quiescent_snapshot(time)
            .ok_or(HandoffError::NotQuiescent)?;
        if tcp.timestamps_enabled {
            return Err(HandoffError::UnsupportedOption);
        }
        Ok(BootstrapSnapshot {
            config: self.inner.config,
            role: self.role,
            polled_at: now,
            progress: self.progress,
            tcp,
        })
    }
}
fn count(length: usize, side: StreamSide) -> Result<u64, Error> {
    u64::try_from(length).map_err(|_| Error::CounterExhausted(side))
}

#[cfg(test)]
mod tests;
