//! Transport-independent Swift policy negotiation with original deadlines.
//!
//! Authenticated ordered control, real directional drain facts and transport
//! completion are caller responsibilities. No token is removed merely by polling.

use crate::{
    control::{Message, Policy, Refusal},
    records::{self, RecordNumber},
};
use std::{collections::VecDeque, fmt};

/// Caller-injected monotonic microseconds, unrelated to packet numbers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Time(pub u64);
/// Logical policy epoch; the retained profile starts at zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Epoch(pub u64);
/// Complete canonical configuration digest, derived by the trusted resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest(pub [u8; 32]);
/// Local output custody identity; not transmitted and never a security counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct OutboundId(pub u64);
/// Fixed proposal authority established by the session owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authority {
    /// The one endpoint allowed to propose changes.
    Coordinator,
    /// Validates and responds to the coordinator.
    Participant,
}
/// Explicit finite transaction and retained-output bounds, without defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Original total transaction bound, positive injected microseconds.
    pub transaction_micros: u64,
    /// Uncompleted logical outputs, in 1..=64.
    pub max_outbound: usize,
}
/// Pure directional records and rate, excluding physical I/O configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Direction {
    /// Complete packing, recovery, channel and native-format policy.
    pub records: records::Config,
    /// IP-byte budget per second, in 8_000..=1_250_000_000.
    pub bytes_per_second: u64,
}
impl Direction {
    /// Check scalar bounds without changing a data path.
    pub fn validate(self) -> Result<(), Fault> {
        self.records.validate().map_err(|_| Fault::Configuration)?;
        if !(8_000..=1_250_000_000).contains(&self.bytes_per_second) {
            return Err(Fault::Configuration);
        }
        Ok(())
    }
}
/// Both local directions and their globally matching canonical digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// New local sending direction.
    pub send: Direction,
    /// New local receiving direction.
    pub receive: Direction,
    /// Full configuration, not merely the local record geometry.
    pub digest: Digest,
}
impl Resolved {
    /// Validate both directional bounds before agreement.
    pub fn validate(self) -> Result<(), Fault> {
        self.send.validate()?;
        self.receive.validate()
    }
}
/// Locally committed observation, never proof of simultaneous peer completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Committed {
    /// Committed logical Swift policy epoch.
    pub epoch: Epoch,
    /// Absent while the retained profile's startup policy holds.
    pub policy: Option<Policy>,
}
/// One owed exact control message, borrowed repeatedly until completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outbound {
    /// Local completion identity.
    pub id: OutboundId,
    /// Unchanged retained Swift wire message.
    pub message: Message,
}
/// Actual directional data-path facts, captured by one serialized owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// All packing queues empty and every sent source confirmed.
    pub send_drained: bool,
    /// Native receive records still await delivery.
    pub receive_deliverable: bool,
    /// No deliverable or incomplete old receive state remains.
    pub receive_drained: bool,
    /// Next full authenticated User number, never a cover/control number.
    pub next_number: RecordNumber,
}
/// Synchronous application boundary; failures end the session without rollback.
pub trait Hooks {
    /// Preserve the embedding data path's actual error.
    type Error;
    /// Read exact bounded engine drain and security-counter state.
    fn status(&self) -> Status;
    /// Replace the confirmed send engines and rate before admission resumes.
    fn replace_send(
        &mut self,
        now: Time,
        policy: Direction,
        feedback_from: RecordNumber,
    ) -> Result<(), Self::Error>;
    /// Replace delivered receive engines before the acknowledgement is owed.
    fn replace_receive(
        &mut self,
        policy: Direction,
        source_from: RecordNumber,
    ) -> Result<(), Self::Error>;
}
/// Session-ending protocol/configuration failure, without a rollback guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// Invalid local bounds or resolved direction.
    Configuration,
    /// Successful progress already observed a later injected time.
    NonMonotonicTime,
    /// The original transaction bound has expired.
    Deadline,
    /// Authenticated message or drain evidence does not fit this transaction.
    Protocol,
    /// Peers derived different complete configurations.
    Digest,
    /// Fixed outstanding-output retention is full.
    Capacity,
    /// Checked epoch, deadline or token arithmetic was exhausted.
    CounterExhausted,
    /// Completion names an unissued or non-front outstanding token.
    Ownership,
}
impl fmt::Display for Fault {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "Swift policy fault: {self:?}")
    }
}
impl std::error::Error for Fault {}
/// Distinguishes a coordinator fault from an actual hook application error.
#[derive(Debug, Eq, PartialEq)]
pub enum Error<E> {
    /// Protocol/configuration/deadline failed.
    Fault(Fault),
    /// The data path could not apply a directional replacement.
    Apply(E),
}
impl<E> From<Fault> for Error<E> {
    fn from(value: Fault) -> Self {
        Self::Fault(value)
    }
}
impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fault(error) => error.fmt(output),
            Self::Apply(error) => error.fmt(output),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for Error<E> {}
/// A local request refusal; does not claim that an ended session rolled back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    /// Another change or unconsumed local outcome exists.
    Busy,
    /// This endpoint cannot propose.
    NotCoordinator,
    /// Resolution, bounds or checked request arithmetic is invalid.
    Invalid,
}
impl fmt::Display for RequestError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "Swift policy request refused: {self:?}")
    }
}
impl std::error::Error for RequestError {}
/// A local request's known result; transport teardown is not represented as success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Both directions and owed transport outputs completed locally.
    Applied(Epoch),
    /// Peer refused before either direction changed.
    Rejected,
}
/// Local sending phase, independent of the peer's sending phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendPhase {
    /// Still forwarding old policy while waiting for agreement.
    Proposed,
    /// Agreement stopped admission; sent sources must confirm.
    Draining,
    /// Local barrier is owed/sent; await peer receive replacement.
    Barrier,
    /// Local send engines were replaced successfully.
    Done,
}
/// Local receiving phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceivePhase {
    /// Await the peer's drain barrier.
    Open,
    /// Deliver held records before installing the peer's new policy.
    Flushing {
        /// First authenticated source/repair number in the new epoch.
        first_number: RecordNumber,
    },
    /// Receive replacement succeeded and its acknowledgement is owed/completed.
    Done,
}
/// Read-only pending state; observation is never application evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Target logical policy epoch.
    pub epoch: Epoch,
    /// Original immutable total bound.
    pub deadline: Time,
    /// Exact proposed public policy.
    pub policy: Policy,
    /// Expected globally matching configuration digest.
    pub digest: Digest,
    /// Local send phase.
    pub send: SendPhase,
    /// Local receive phase.
    pub receive: ReceivePhase,
}
struct Change {
    pending: Pending,
    resolved: Resolved,
}

/// One bounded pure policy owner, shared by every compatible reliable transport.
pub struct Coordinator {
    authority: Authority,
    settings: Settings,
    committed: Committed,
    change: Option<Change>,
    output: VecDeque<Outbound>,
    next_output: Option<u64>,
    completed: u64,
    outcome: Option<Outcome>,
    last: Time,
}
impl Coordinator {
    /// Validate required bounds and allocate one bounded output ledger.
    pub fn new(
        authority: Authority,
        initial: Committed,
        settings: Settings,
        now: Time,
    ) -> Result<Self, Fault> {
        if settings.transaction_micros == 0 || !(1..=64).contains(&settings.max_outbound) {
            return Err(Fault::Configuration);
        }
        Ok(Self {
            authority,
            settings,
            committed: initial,
            change: None,
            output: VecDeque::with_capacity(settings.max_outbound),
            next_output: Some(1),
            completed: 0,
            outcome: None,
            last: now,
        })
    }
    /// Check time and the unchanged deadline before any effect or successful completion.
    pub fn check(&mut self, now: Time) -> Result<(), Fault> {
        if now < self.last {
            return Err(Fault::NonMonotonicTime);
        }
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            return Err(Fault::Deadline);
        }
        self.last = now;
        Ok(())
    }
    /// Start one proposal; dropping the embedding request future cannot cancel it.
    pub fn request(
        &mut self,
        now: Time,
        policy: Policy,
        resolved: Option<Resolved>,
    ) -> Result<(), RequestError> {
        if self.authority != Authority::Coordinator {
            return Err(RequestError::NotCoordinator);
        }
        if self.change.is_some() || self.outcome.is_some() || !self.output.is_empty() {
            return Err(RequestError::Busy);
        }
        let resolved = resolved
            .filter(|resolved| resolved.validate().is_ok())
            .ok_or(RequestError::Invalid)?;
        self.check(now).map_err(|_| RequestError::Invalid)?;
        if self.committed.policy == Some(policy) {
            self.outcome = Some(Outcome::Applied(self.committed.epoch));
            return Ok(());
        }
        let epoch = Epoch(
            self.committed
                .epoch
                .0
                .checked_add(1)
                .ok_or(RequestError::Invalid)?,
        );
        let deadline = Time(
            now.0
                .checked_add(self.settings.transaction_micros)
                .ok_or(RequestError::Invalid)?,
        );
        self.reserve(1).map_err(|_| RequestError::Invalid)?;
        self.push(Message::Propose {
            epoch: epoch.0,
            policy,
        })
        .map_err(|_| RequestError::Invalid)?;
        self.change = Some(Change {
            pending: Pending {
                epoch,
                deadline,
                policy,
                digest: resolved.digest,
                send: SendPhase::Proposed,
                receive: ReceivePhase::Open,
            },
            resolved,
        });
        Ok(())
    }
    /// Receive one authenticated, ordered, once-delivered logical message.
    pub fn receive<H: Hooks>(
        &mut self,
        now: Time,
        message: Message,
        mut resolve: impl FnMut(&Policy) -> Option<Resolved>,
        hooks: &mut H,
    ) -> Result<(), Error<H::Error>> {
        self.check(now)?;
        match message {
            Message::Propose { epoch, policy } => {
                if self.authority == Authority::Coordinator {
                    return Err(Fault::Protocol.into());
                }
                let refusal = |reason| Message::Reject { epoch, reason };
                let mut accepted = None;
                let reply = if let Some(change) = &self.change {
                    if change.pending.epoch.0 == epoch && change.pending.policy == policy {
                        Message::Accept {
                            epoch,
                            digest: change.resolved.digest.0,
                        }
                    } else {
                        refusal(Refusal::Busy)
                    }
                } else if self.committed.epoch.0.checked_add(1) != Some(epoch) {
                    refusal(Refusal::Epoch)
                } else if let Some(resolved) =
                    resolve(&policy).filter(|resolved| resolved.validate().is_ok())
                {
                    let deadline = Time(
                        now.0
                            .checked_add(self.settings.transaction_micros)
                            .ok_or(Fault::CounterExhausted)?,
                    );
                    accepted = Some(Change {
                        pending: Pending {
                            epoch: Epoch(epoch),
                            deadline,
                            policy,
                            digest: resolved.digest,
                            send: SendPhase::Draining,
                            receive: ReceivePhase::Open,
                        },
                        resolved,
                    });
                    Message::Accept {
                        epoch,
                        digest: resolved.digest.0,
                    }
                } else {
                    refusal(Refusal::Invalid)
                };
                if !self.output.iter().any(|output| output.message == reply) {
                    self.reserve(1)?;
                    self.push(reply)?;
                }
                if let Some(change) = accepted {
                    self.change = Some(change);
                }
            }
            Message::Accept { epoch, digest } => {
                let change = self.change.as_mut().ok_or(Fault::Protocol)?;
                if change.pending.epoch.0 != epoch || change.pending.send != SendPhase::Proposed {
                    return Err(Fault::Protocol.into());
                }
                if change.resolved.digest.0 != digest {
                    return Err(Fault::Digest.into());
                }
                change.pending.send = SendPhase::Draining;
            }
            Message::Reject { epoch, .. } => {
                let change = self.change.as_ref().ok_or(Fault::Protocol)?;
                if change.pending.epoch.0 != epoch || change.pending.send != SendPhase::Proposed {
                    return Err(Fault::Protocol.into());
                }
                self.change = None;
                self.outcome = Some(Outcome::Rejected);
            }
            Message::Barrier {
                epoch,
                first_number,
            } => {
                let change = self.change.as_mut().ok_or(Fault::Protocol)?;
                if change.pending.epoch.0 != epoch
                    || change.pending.send == SendPhase::Proposed
                    || change.pending.receive != ReceivePhase::Open
                {
                    return Err(Fault::Protocol.into());
                }
                change.pending.receive = ReceivePhase::Flushing {
                    first_number: RecordNumber(first_number),
                };
            }
            Message::BarrierAck {
                epoch,
                feedback_from,
            } => {
                let change = self.change.as_mut().ok_or(Fault::Protocol)?;
                if change.pending.epoch.0 != epoch || change.pending.send != SendPhase::Barrier {
                    return Err(Fault::Protocol.into());
                }
                hooks
                    .replace_send(now, change.resolved.send, RecordNumber(feedback_from))
                    .map_err(Error::Apply)?;
                change.pending.send = SendPhase::Done;
            }
        }
        Ok(())
    }
    /// Advance exact directional barriers and publish only completed local outcomes.
    pub fn progress<H: Hooks>(&mut self, now: Time, hooks: &mut H) -> Result<(), Error<H::Error>> {
        self.check(now)?;
        let Some(change) = &self.change else {
            return Ok(());
        };
        let status = hooks.status();
        let barrier = change.pending.send == SendPhase::Draining && status.send_drained;
        let flush = matches!(change.pending.receive, ReceivePhase::Flushing { .. })
            && !status.receive_deliverable;
        if flush && !status.receive_drained {
            return Err(Fault::Protocol.into());
        }
        if barrier {
            if self.output.len() == self.settings.max_outbound {
                return Ok(());
            }
            self.reserve(1)?;
            let epoch = self.change.as_ref().ok_or(Fault::Protocol)?.pending.epoch;
            self.push(Message::Barrier {
                epoch: epoch.0,
                first_number: status.next_number.0,
            })?;
            self.change.as_mut().ok_or(Fault::Protocol)?.pending.send = SendPhase::Barrier;
        }
        if flush {
            if self.output.len() == self.settings.max_outbound {
                return Ok(());
            }
            self.reserve(1)?;
            let change = self.change.as_ref().ok_or(Fault::Protocol)?;
            let ReceivePhase::Flushing { first_number } = change.pending.receive else {
                return Err(Fault::Protocol.into());
            };
            hooks
                .replace_receive(change.resolved.receive, first_number)
                .map_err(Error::Apply)?;
            let epoch = change.pending.epoch;
            self.push(Message::BarrierAck {
                epoch: epoch.0,
                feedback_from: hooks.status().next_number.0,
            })?;
            self.change.as_mut().ok_or(Fault::Protocol)?.pending.receive = ReceivePhase::Done;
        }
        if let Some(change) = &self.change
            && change.pending.send == SendPhase::Done
            && change.pending.receive == ReceivePhase::Done
            && self.output.is_empty()
        {
            self.committed = Committed {
                epoch: change.pending.epoch,
                policy: Some(change.pending.policy),
            };
            if self.authority == Authority::Coordinator {
                self.outcome = Some(Outcome::Applied(change.pending.epoch));
            }
            self.change = None;
        }
        Ok(())
    }
    fn reserve(&self, count: usize) -> Result<(), Fault> {
        if self
            .output
            .len()
            .checked_add(count)
            .is_none_or(|length| length > self.settings.max_outbound)
        {
            return Err(Fault::Capacity);
        }
        if count != 0 {
            let next = self.next_output.ok_or(Fault::CounterExhausted)?;
            next.checked_add(count as u64 - 1)
                .ok_or(Fault::CounterExhausted)?;
        }
        Ok(())
    }
    // Every call is preceded by reserve; the bounded loop never consumes an
    // unreserved identity. No peer value indexes the output ledger.
    fn push(&mut self, message: Message) -> Result<(), Fault> {
        let id = self.next_output.ok_or(Fault::CounterExhausted)?;
        self.output.push_back(Outbound {
            id: OutboundId(id),
            message,
        });
        self.next_output = id.checked_add(1);
        Ok(())
    }
    /// Borrow the front token repeatedly; encoding is not transport completion.
    pub fn outbound(&self) -> Option<Outbound> {
        self.output.front().copied()
    }
    /// Observe the bounded owed messages without releasing their custody.
    pub fn outstanding(&self) -> impl Iterator<Item = Outbound> + '_ {
        self.output.iter().copied()
    }
    /// Complete the exact front token after the adapter's real transport evidence.
    pub fn complete_outbound(&mut self, now: Time, id: OutboundId) -> Result<(), Fault> {
        self.check(now)?;
        if id.0 != 0 && id.0 <= self.completed {
            return Ok(());
        }
        if self.output.front().map(|output| output.id) != Some(id) {
            return Err(Fault::Ownership);
        }
        self.output.pop_front();
        self.completed = id.0;
        Ok(())
    }
    /// Original pending deadline; no retry or completion grants another interval.
    pub fn deadline(&self) -> Option<Time> {
        self.change.as_ref().map(|change| change.pending.deadline)
    }
    /// Admission continues before agreement and after successful local send replacement.
    pub fn admission_allowed(&self) -> bool {
        self.change.as_ref().is_none_or(|change| {
            matches!(change.pending.send, SendPhase::Proposed | SendPhase::Done)
        })
    }
    /// Last fully completed local policy observation.
    pub const fn committed(&self) -> Committed {
        self.committed
    }
    /// Observe the pending transaction without granting application authority.
    pub fn pending(&self) -> Option<Pending> {
        self.change.as_ref().map(|change| change.pending)
    }
    /// Consume a known local outcome; does not cancel pending or applied state.
    pub fn take_outcome(&mut self) -> Option<Outcome> {
        self.outcome.take()
    }
}

#[cfg(test)]
mod tests;
