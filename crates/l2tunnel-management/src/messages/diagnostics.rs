//! Read-only scalar observations; these never establish custody or alter expiry.

use super::*;

/// An unconfirmed outbound message at its original deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundExpiry {
    /// Original local retry identity.
    pub submission: SubmissionId,
    /// Original wire message identity in this stream and direction.
    pub message: u64,
    /// Original complete message length; no message bytes are exposed.
    pub length: usize,
    /// Total canonical fragments for the message.
    pub fragments: usize,
    /// Fragments submitted to the reliable delivery owner.
    pub submitted_fragments: usize,
    /// Sources still in the bounded confirmation sweep, including any ACKed
    /// sources whose confirmation has not yet been consumed by that sweep.
    pub source_custody: usize,
    /// First source still in that confirmation sweep.
    pub first_source: Option<u64>,
    /// Read-only receipt state at the last successful message observation.
    /// An error remains unknown, rather than being reported as a missing ACK.
    pub first_source_confirmed: Option<Result<bool, delivery::Error>>,
    /// Whether the peer's exact complete-message ACCEPTED receipt was consumed.
    pub semantic_accepted: bool,
}

/// A deadline that is due at the caller's observation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpiryKind {
    /// The immutable session limit is due.
    Session,
    /// An outgoing message still needs source or complete-message confirmation.
    Outbound(OutboundExpiry),
    /// Complete incoming bytes still await semantic acceptance.
    Held {
        /// Original incoming message identity.
        message: u64,
        /// Complete retained message length.
        length: usize,
    },
    /// Original incomplete-message arrival metadata has reached its deadline.
    Reassembly {
        /// Original incoming message identity, retained even after expiry releases payload.
        message: MessageId,
    },
}

/// A currently due candidate, not proof of the operation that returned an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiryCandidate {
    /// Original immutable deadline; retries and observation do not renew it.
    pub deadline: Duration,
    /// Custody associated with the due deadline.
    pub kind: ExpiryKind,
}

/// Allocation-free terminal inspection with injected time and no payload/digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpirySnapshot {
    /// Caller-supplied inspection time, which may follow the failing operation.
    pub observed_at: Duration,
    /// Last successful owner time observation, not a physical-send timestamp.
    pub last_successful_at: Duration,
    /// Retained terminal error, if a mutating operation recorded one.
    pub owner_error: Option<Error>,
    /// Original session limit, even if an earlier message limit is due.
    pub session_deadline: Duration,
    /// Due candidate in the owner's session/outbound/held/reassembly check order.
    /// Multiple limits may be due; a later inspection cannot identify the
    /// original failing operation from this candidate alone.
    pub candidate: Option<ExpiryCandidate>,
    /// Current custody after any earlier error handling, not historical peak usage.
    pub retained: Retained,
    /// Existing charged emissions; these are not physical-send receipts.
    pub emissions: delivery::Statistics,
}

impl Owner {
    /// Inspect existing scalar state without advancing time, consuming ACKs,
    /// allocating storage or changing a deadline. This is diagnostic only.
    pub fn expiry_snapshot(&self, now: Duration) -> ExpirySnapshot {
        let candidate = if now >= self.expires {
            Some(ExpiryCandidate {
                deadline: self.expires,
                kind: ExpiryKind::Session,
            })
        } else if let Some(entry) = self
            .outbound
            .iter()
            .find(|entry| !entry.confirmed && now >= entry.deadline)
        {
            let first_source = entry.sources.front().copied();
            Some(ExpiryCandidate {
                deadline: entry.deadline,
                kind: ExpiryKind::Outbound(OutboundExpiry {
                    submission: entry.ticket.submission,
                    message: entry.ticket.message,
                    length: entry.ticket.length,
                    fragments: entry.batch.fragments.len(),
                    submitted_fragments: entry.next_fragment,
                    source_custody: entry.sources.len(),
                    first_source,
                    first_source_confirmed: first_source
                        .map(|source| self.service.source_confirmed(source, self.last_now)),
                    semantic_accepted: entry.accepted,
                }),
            })
        } else if let Some(held) = self.held.as_ref().filter(|held| now >= held.deadline) {
            Some(ExpiryCandidate {
                deadline: held.deadline,
                kind: ExpiryKind::Held {
                    message: held.ticket.message,
                    length: held.ticket.length,
                },
            })
        } else {
            // expire_count releases reassembly payload before returning Expired;
            // its original bounded arrival ledger remains available afterwards.
            self.arrivals
                .earliest()
                .filter(|(_, deadline)| now >= *deadline)
                .map(|(message, deadline)| ExpiryCandidate {
                    deadline,
                    kind: ExpiryKind::Reassembly { message },
                })
        };
        ExpirySnapshot {
            observed_at: now,
            last_successful_at: self.last_now,
            owner_error: self.failed,
            session_deadline: self.expires,
            candidate,
            retained: self.retained(),
            emissions: self.statistics(),
        }
    }
}

/// Bounded live storage facts. Queue custody is not a missing-ACK assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferSnapshot {
    /// Exact authenticated per-stream binding, independent of data epochs.
    pub binding: delivery::Binding,
    /// Actual current payload/recovery ownership, including reserved completion bytes.
    pub retained: Retained,
    /// Exact immutable capacities and service policy; no inferred capacities.
    pub settings: Settings,
    /// Last successful observation; this getter does not advance the owner.
    pub last_successful_at: Duration,
    /// Actual sticky owner error, if any.
    pub owner_error: Option<Error>,
    /// Confirmed retry metadata awaiting explicit retirement.
    pub confirmed_metadata: usize,
    /// Unconfirmed messages without a consumed exact ACCEPTED receipt.
    pub awaiting_accepted: usize,
    /// Sources still queued for the bounded confirmation sweep, including ACKed sources.
    pub source_confirmation_custody: usize,
    /// Canonical fragments not yet submitted to recovery.
    pub remaining_fragments: usize,
    /// Exact complete incoming message held for semantic acceptance.
    pub held_message: Option<u64>,
    /// Its original nonrenewable deadline.
    pub held_deadline: Option<Duration>,
    /// A diagnostic sum exceeded its representable bound.
    pub counter_overflow: bool,
}
impl Owner {
    /// Read at most the configured 64 outbound entries, without ACK consumption,
    /// payload inspection, allocation, clock access or protocol progress.
    pub fn buffer_snapshot(&self) -> BufferSnapshot {
        let mut snapshot = BufferSnapshot {
            binding: self.binding,
            retained: self.retained(),
            settings: self.settings,
            last_successful_at: self.last_now,
            owner_error: self.failed,
            confirmed_metadata: 0,
            awaiting_accepted: 0,
            source_confirmation_custody: 0,
            remaining_fragments: 0,
            held_message: self.held.as_ref().map(|held| held.ticket.message),
            held_deadline: self.held.as_ref().map(|held| held.deadline),
            counter_overflow: false,
        };
        for entry in self.outbound.iter() {
            for (total, count) in [
                (
                    &mut snapshot.confirmed_metadata,
                    usize::from(entry.confirmed),
                ),
                (
                    &mut snapshot.awaiting_accepted,
                    usize::from(!entry.confirmed && !entry.accepted),
                ),
                (
                    &mut snapshot.source_confirmation_custody,
                    entry.sources.len(),
                ),
                (
                    &mut snapshot.remaining_fragments,
                    entry
                        .batch
                        .fragments
                        .len()
                        .saturating_sub(entry.next_fragment),
                ),
            ] {
                match total.checked_add(count) {
                    Some(value) => *total = value,
                    None => snapshot.counter_overflow = true,
                }
            }
        }
        snapshot
    }
}
