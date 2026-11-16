//! Direct typed final-encoder custody over the existing selected R0 owner.
use super::*;
use l2tunnel_recovery::{CompactPacketKind, CompactPollError};

/// Explicit complete external charge for each selected final packet arm.
/// Include protection/route/carrier/IP bytes here exactly once, excluding the
/// context-free algorithm body. No legacy Reliable envelope is emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactOverheads {
    /// Actual external bytes for source/retry data.
    pub data: usize,
    /// Actual external bytes for authenticated reliable-retiring feedback.
    pub feedback: usize,
}
impl CompactOverheads {
    fn for_kind(self, kind: CompactPacketKind) -> usize {
        match kind {
            CompactPacketKind::Data => self.data,
            CompactPacketKind::Feedback => self.feedback,
        }
    }
}

/// Caller encoder result and the actual same-owner physical output witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactOutput<T> {
    /// Value returned by the final encoder, not a physical-send acknowledgment.
    pub value: T,
    /// Exact body size, full charge and once-only physical custody.
    pub prepared: PreparedOutput,
}

/// Actual Reliable failure or transactional final-encoder refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactOutputError<E> {
    /// Recovery/configuration/custody preflight failed.
    Reliable(Error),
    /// Caller refused without consuming the offered recovery output.
    Encode(E),
}
impl<E> From<Error> for CompactOutputError<E> {
    fn from(error: Error) -> Self {
        Self::Reliable(error)
    }
}
impl<E: fmt::Display> fmt::Display for CompactOutputError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reliable(error) => fmt::Display::fmt(error, f),
            Self::Encode(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for CompactOutputError<E> {}

impl Reliable {
    /// Offer one source or feedback directly to the selected final encoder.
    /// Some commits the actual body and one full-wire debit, retaining its
    /// physical witness until `confirm_output` or `confirm_output_at`.
    /// None/errors commit neither.
    /// The callback must not report physical acceptance; it only encodes bytes.
    pub fn poll_compact_with<T, E>(
        &mut self,
        now: Duration,
        budget: &mut OutboundBudget,
        overheads: CompactOverheads,
        encode: impl FnOnce(CompactPacketView<'_>) -> Result<Option<T>, E>,
    ) -> Result<Option<CompactOutput<T>>, CompactOutputError<E>> {
        self.poll_compact_scoped(now, budget, overheads, OutputScope::Combined, encode)
    }

    /// Independent data opportunity, using the actual existing main output slot.
    pub fn poll_compact_data_with<T, E>(
        &mut self,
        now: Duration,
        budget: &mut OutboundBudget,
        overheads: CompactOverheads,
        encode: impl FnOnce(CompactPacketView<'_>) -> Result<Option<T>, E>,
    ) -> Result<Option<CompactOutput<T>>, CompactOutputError<E>> {
        self.poll_compact_scoped(now, budget, overheads, OutputScope::Data, encode)
    }

    /// Independent feedback opportunity in the existing feedback custody slot.
    pub fn poll_compact_feedback_with<T, E>(
        &mut self,
        now: Duration,
        budget: &mut OutboundBudget,
        overheads: CompactOverheads,
        encode: impl FnOnce(CompactPacketView<'_>) -> Result<Option<T>, E>,
    ) -> Result<Option<CompactOutput<T>>, CompactOutputError<E>> {
        self.poll_compact_scoped(now, budget, overheads, OutputScope::Feedback, encode)
    }

    /// Body maximum with full counters; excludes all final packet overheads.
    pub fn compact_send_max_body_bytes(&self) -> Result<usize, Error> {
        Ok(self.arq.compact()?.send_max_body_bytes()?)
    }
    /// Crossed peer body maximum with full counters.
    pub fn compact_receive_max_body_bytes(&self) -> Result<usize, Error> {
        Ok(self.arq.compact()?.receive_max_body_bytes()?)
    }
    /// Exact due context-free feedback bytes; observation grants no authority.
    pub fn compact_feedback_opportunity(&self) -> Result<Option<(Duration, usize)>, Error> {
        self.running()?;
        if self.independent_feedback.is_some()
            || self
                .pending_output
                .is_some_and(|output| output.kind == RecordKind::Feedback)
        {
            return Ok(None);
        }
        let owner = self.arq.compact()?;
        let Some(at) = owner.feedback_deadline() else {
            return Ok(None);
        };
        Ok(owner
            .feedback_body_bytes(at.max(self.now))?
            .map(|bytes| (at, bytes)))
    }

    /// Admit the externally authenticated algorithm union without reparsing or
    /// reconstructing a legacy envelope. Original arrival survives local retry.
    pub fn receive_compact_view_at(
        &mut self,
        view: CompactPacketView<'_>,
        received: Duration,
        observed: Duration,
    ) -> Result<(), Error> {
        self.check_time(observed)?;
        if received > observed {
            return Err(Error::NonMonotonicTime);
        }
        match self
            .arq
            .compact_mut()?
            .receive_view_at(view, received, observed)
        {
            Ok(()) => self.advance(observed),
            Err(
                error @ (RecoveryError::FeedbackAwaitingPhysical
                | RecoveryError::Capacity(_)
                | RecoveryError::SequenceWindow
                | RecoveryError::HistoryCapacity),
            ) => Err(error.into()),
            Err(error) => self.fail(error.into()),
        }
    }

    fn poll_compact_scoped<T, E>(
        &mut self,
        now: Duration,
        budget: &mut OutboundBudget,
        overheads: CompactOverheads,
        scope: OutputScope,
        encode: impl FnOnce(CompactPacketView<'_>) -> Result<Option<T>, E>,
    ) -> Result<Option<CompactOutput<T>>, CompactOutputError<E>> {
        self.check_time(now)?;
        let instance = self.physical_instance.ok_or(Error::InvalidConfig)?;
        self.arq.compact().map_err(Error::from)?;
        let blocked = match scope {
            OutputScope::Combined => self.pending_output().is_some(),
            OutputScope::Data => self.pending_data_output().is_some(),
            OutputScope::Feedback => {
                self.independent_feedback.is_some()
                    || self
                        .pending_output
                        .is_some_and(|output| output.kind == RecordKind::Feedback)
            }
        };
        if blocked {
            self.advance(now)?;
            return Ok(None);
        }
        let next = self.next_output.checked_add(1).ok_or(Error::Exhausted)?;
        let allow_feedback = !matches!(scope, OutputScope::Data);
        let allow_data = !matches!(scope, OutputScope::Feedback);
        let order = if self.prefer_feedback {
            [true, false]
        } else {
            [false, true]
        };
        let mut selected = None;
        for feedback in order {
            if (feedback && !allow_feedback) || (!feedback && !allow_data) {
                continue;
            }
            let owner = self.arq.compact().map_err(Error::from)?;
            let bytes = if feedback {
                owner.feedback_body_bytes(now)
            } else {
                owner.source_body_bytes(now)
            }
            .map_err(Error::from)?;
            if let Some(bytes) = bytes {
                let kind = if feedback {
                    CompactPacketKind::Feedback
                } else {
                    CompactPacketKind::Data
                };
                let charge = bytes
                    .checked_add(overheads.for_kind(kind))
                    .ok_or(Error::Exhausted)?;
                if budget.packets > 0 && budget.wire_bytes >= charge {
                    selected = Some((feedback, bytes, charge));
                    break;
                }
            }
        }
        let Some((feedback, bytes, charge)) = selected else {
            self.advance(now)?;
            return Ok(None);
        };
        let before = self.arq.statistics().retransmissions;
        let mut source = None;
        let offer = |view: CompactPacketView<'_>| {
            if let CompactPacketView::Data {
                source: identity, ..
            } = view
            {
                source = Some(identity);
            }
            encode(view)
        };
        let owner = self.arq.compact_mut().map_err(Error::from)?;
        let offered = if feedback {
            owner.poll_feedback_with(now, &mut self.scratch, offer)
        } else {
            owner.poll_source_with(now, offer)
        }
        .map_err(|error| match error {
            CompactPollError::Recovery(error) => CompactOutputError::Reliable(error.into()),
            CompactPollError::Encode(error) => CompactOutputError::Encode(error),
        })?;
        let Some(value) = offered else {
            return Ok(None);
        };
        let transmission = source
            .map(|source| {
                self.arq
                    .pending_transmission(source)
                    .ok_or(Error::OutputToken)
            })
            .transpose()
            .or_else(|error| self.fail(error))?;
        let emission = if feedback {
            Emission::Feedback
        } else if self.arq.statistics().retransmissions > before {
            Emission::Retry
        } else {
            Emission::Source
        };
        let prepared = PreparedOutput {
            instance,
            serial: self.next_output,
            transmission,
            prepared_at: now,
            bytes,
            wire_bytes: charge,
            kind: if feedback {
                RecordKind::Feedback
            } else {
                RecordKind::Source
            },
        };
        self.charge_exact(charge, emission, budget)?;
        self.now = now;
        if matches!(scope, OutputScope::Feedback) {
            self.independent_feedback = Some(prepared);
        } else {
            self.pending_output = Some(prepared);
        }
        self.next_output = next;
        Ok(Some(CompactOutput { value, prepared }))
    }
}
