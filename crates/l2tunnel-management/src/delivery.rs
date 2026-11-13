//! Fixed-context reliable control delivery. Authenticate the management record
//! class before admission; these APIs do not establish peer identity.
use crate::{Ingress, LaneId, Role, SessionId};
use l2tunnel_recovery::{
    ACK_PACKET_BYTES, ArqConfig, EndpointRole, RecoveryContext, RecoveryEngine, RecoveryError,
    Retained, SelectiveRepeat,
};
use std::{fmt, time::Duration};

/// Independent control retention, retry and charged service bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Opaque control-source size, retention and finite retry policy.
    pub recovery: ArqConfig,
    /// Positive service refill interval, at most one second.
    pub interval: Duration,
    /// Complete packets per interval, including receipts, within 2..=4096.
    pub packets_per_interval: u32,
    /// Complete wire bytes per interval, including retries and receipts.
    pub bytes_per_interval: usize,
    /// Fixed negotiated protection, appearance and underlay bytes per packet.
    pub wire_overhead: usize,
}

/// Immutable physical control binding, separate from any data policy epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Full authenticated logical session identity.
    pub session: SessionId,
    /// Selected authenticated physical lane.
    pub lane: LaneId,
    /// This endpoint's authenticated role.
    pub local_role: Role,
    /// Fixed control grammar epoch; never changed by a data-profile switch.
    pub control_epoch: u64,
}

/// One encoded attempt admitted to a bounded carrier send slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Emission {
    /// Recovery bytes written into the caller's output prefix.
    pub bytes: usize,
    /// Exact charged wire bytes including the configured outer overhead.
    pub wire_bytes: usize,
}

/// Saturating diagnostics, never used to decide protocol progress.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Attempts emitted, including feedback and retries.
    pub emitted_packets: u64,
    /// Exact charged outer bytes emitted.
    pub emitted_wire_bytes: u64,
}

/// Typed service failure; a refused admission does not change its original expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid, overflowing or unbounded local settings.
    Settings,
    /// Caller did not authenticate this record as management control.
    Origin,
    /// Verified session, lane or role differs from the fixed binding.
    Binding,
    /// The original expiry has been reached.
    Expired,
    /// A successful operation already observed a later injected time.
    NonMonotonicTime,
    /// Output cannot hold the configured complete recovery packet.
    OutputTooSmall,
    /// The existing bounded recovery engine rejected the operation.
    Recovery(RecoveryError),
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "control delivery error: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<RecoveryError> for Error {
    fn from(value: RecoveryError) -> Self {
        Self::Recovery(value)
    }
}

/// Bounded reliable opaque control sources over already authenticated packets.
///
/// The caller preserves emitted attempts until carrier handoff or explicit
/// failure, supplies shared wire allowance, and authenticates exact received
/// bytes and their class. This type neither implements transaction semantics nor
/// records physical-send completion. Its fixed context has no data-epoch setter.
pub struct Service {
    settings: Settings,
    binding: Binding,
    recovery: SelectiveRepeat,
    max_packet: usize,
    max_charge: usize,
    ack_charge: usize,
    expires: Duration,
    last_now: Duration,
    refill_at: Duration,
    packets_left: u32,
    bytes_left: usize,
    source_emitted: bool,
    feedback_emitted: bool,
    shared_allowance: usize,
    statistics: Statistics,
}
impl Service {
    /// Validate all bounds before constructing a service with immutable expiry.
    pub fn new(
        settings: Settings,
        binding: Binding,
        now: Duration,
        expires: Duration,
    ) -> Result<Self, Error> {
        if settings.interval.is_zero()
            || settings.interval > Duration::from_secs(1)
            || !(2..=4096).contains(&settings.packets_per_interval)
            || settings.bytes_per_interval > 16 * 1024 * 1024
            || settings.recovery.send_bytes > 16 * 1024 * 1024
            || settings.recovery.receive_bytes > 16 * 1024 * 1024
            || settings.recovery.max_retries > 1024
            || binding.session.0 == [0; 16]
            || binding.control_epoch == 0
            || now >= expires
        {
            return Err(Error::Settings);
        }
        let refill_at = now.checked_add(settings.interval).ok_or(Error::Settings)?;
        let recovery = SelectiveRepeat::new(
            settings.recovery,
            RecoveryContext {
                session: u128::from_be_bytes(binding.session.0),
                epoch: binding.control_epoch,
                role: match binding.local_role {
                    Role::Client => EndpointRole::Initiator,
                    Role::Server => EndpointRole::Responder,
                },
            },
        )?;
        let max_packet = recovery.max_packet_bytes();
        let max_charge = max_packet
            .checked_add(settings.wire_overhead)
            .ok_or(Error::Settings)?;
        let ack_charge = ACK_PACKET_BYTES
            .checked_add(settings.wire_overhead)
            .ok_or(Error::Settings)?;
        if max_charge > 65_535
            || max_charge
                .checked_add(ack_charge)
                .is_none_or(|minimum| minimum > settings.bytes_per_interval)
        {
            return Err(Error::Settings);
        }
        Ok(Self {
            settings,
            binding,
            recovery,
            max_packet,
            max_charge,
            ack_charge,
            expires,
            last_now: now,
            refill_at: refill_at.min(expires),
            packets_left: settings.packets_per_interval,
            bytes_left: settings.bytes_per_interval,
            source_emitted: false,
            feedback_emitted: false,
            shared_allowance: usize::MAX,
            statistics: Statistics::default(),
        })
    }

    fn check(&self, now: Duration) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::NonMonotonicTime);
        }
        if now >= self.expires {
            return Err(Error::Expired);
        }
        Ok(())
    }

    /// Retain one exact control source, or return bounded backpressure.
    pub fn submit(&mut self, frame: &[u8], now: Duration) -> Result<u64, Error> {
        self.check(now)?;
        let source = self.recovery.submit(frame, now)?;
        self.last_now = now;
        Ok(source)
    }

    /// Admit only caller-verified control for this exact fixed peer context.
    pub fn receive(
        &mut self,
        verified: Ingress,
        packet: &[u8],
        now: Duration,
    ) -> Result<(), Error> {
        self.check(now)?;
        let Ingress::AuthenticatedManagement {
            session,
            lane,
            sender,
        } = verified
        else {
            return Err(Error::Origin);
        };
        if session != self.binding.session
            || lane != self.binding.lane
            || sender == self.binding.local_role
        {
            return Err(Error::Binding);
        }
        self.recovery.receive(packet, now)?;
        self.last_now = now;
        Ok(())
    }

    /// Admit one encoded attempt under both shared and reserved wire budgets.
    /// Insufficient output or allowance cannot consume a source attempt.
    pub fn poll(
        &mut self,
        now: Duration,
        shared_wire_allowance: usize,
        output: &mut [u8],
    ) -> Result<Option<Emission>, Error> {
        self.check(now)?;
        if output.len() < self.max_packet {
            return Err(Error::OutputTooSmall);
        }
        if now >= self.refill_at {
            let refill_at = now
                .checked_add(self.settings.interval)
                .ok_or(Error::Settings)?;
            self.refill_at = refill_at.min(self.expires);
            self.packets_left = self.settings.packets_per_interval;
            self.bytes_left = self.settings.bytes_per_interval;
            self.source_emitted = false;
            self.feedback_emitted = false;
        }
        self.last_now = now;
        self.shared_allowance = shared_wire_allowance;
        let feedback = if self.can_feedback() {
            self.recovery.poll_feedback(now, output)?
        } else {
            None
        };
        let bytes = if let Some(bytes) = feedback {
            self.feedback_emitted = true;
            bytes
        } else if self.can_source() {
            let Some(bytes) = self.recovery.poll_source(now, output)? else {
                return Ok(None);
            };
            self.source_emitted = true;
            bytes
        } else {
            return Ok(None);
        };
        let wire_bytes = bytes + self.settings.wire_overhead;
        self.packets_left -= 1;
        self.bytes_left -= wire_bytes;
        self.shared_allowance -= wire_bytes;
        self.statistics.emitted_packets = self.statistics.emitted_packets.saturating_add(1);
        self.statistics.emitted_wire_bytes = self
            .statistics
            .emitted_wire_bytes
            .saturating_add(wire_bytes as u64);
        Ok(Some(Emission { bytes, wire_bytes }))
    }

    /// Copy one complete ordered source; too-small output does not consume it.
    pub fn deliver(
        &mut self,
        output: &mut [u8],
        now: Duration,
    ) -> Result<Option<(u64, usize)>, Error> {
        self.check(now)?;
        let source = self.recovery.poll_delivered(output)?;
        self.last_now = now;
        Ok(source)
    }

    /// Next local service/receipt/retry wake, capped by immutable expiry.
    /// An increase of the caller's shared allowance is a separate poll trigger.
    pub fn deadline(&self) -> Duration {
        let source = self
            .recovery
            .source_deadline()
            .map(|at| self.admitted_deadline(at, self.can_source()));
        let feedback = self
            .recovery
            .feedback_deadline()
            .map(|at| self.admitted_deadline(at, self.can_feedback()));
        source
            .into_iter()
            .chain(feedback)
            .min()
            .unwrap_or(self.expires)
            .min(self.expires)
    }

    fn admitted_deadline(&self, at: Duration, admitted: bool) -> Duration {
        let at = at.max(self.last_now);
        if admitted { at } else { at.max(self.refill_at) }
    }

    fn can_source(&self) -> bool {
        let reserve_feedback = u32::from(!self.feedback_emitted);
        let charge = self.max_charge
            + if self.feedback_emitted {
                0
            } else {
                self.ack_charge
            };
        self.packets_left > reserve_feedback
            && self.bytes_left >= charge
            && self.shared_allowance >= charge
    }

    fn can_feedback(&self) -> bool {
        let reserve_source = !self.source_emitted && self.recovery.source_deadline().is_some();
        let charge = self.ack_charge + if reserve_source { self.max_charge } else { 0 };
        self.packets_left > u32::from(reserve_source)
            && self.bytes_left >= charge
            && self.shared_allowance >= charge
    }

    /// Local retention and pending receipts have all been discharged.
    pub fn drained(&self) -> bool {
        self.recovery.drained()
    }
    /// Exact current payload retention, excluding bounded allocator metadata.
    pub fn retained(&self) -> Retained {
        self.recovery.retained()
    }
    /// Saturating charged emission observations.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
}

#[cfg(test)]
mod tests;
