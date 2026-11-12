//! Serialized drained final barriers. The caller owns external recovery drain.

use super::*;
use l2tunnel_flow_control::RetirementMode;

/// Finite retransmission policy for one serialized outgoing final barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetirementPolicy {
    /// Minimum injected interval between distinct queued Final attempts.
    pub retry_micros: u64,
    /// Total attempt limit, including the initial Final; must be positive.
    pub max_attempts: u32,
}

/// Caller observations after serializing external I/O and recovery for this flow.
/// Active cannot inspect these buffers. False zeros violate the barrier contract.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExternalDrain {
    /// Data/control outputs for this flow still owned outside the engine.
    pub pending_outputs: usize,
    /// External retry/repair records or native copies still retaining this flow.
    pub pending_recovery_records: usize,
}

pub(super) struct PendingRetirement {
    pub(super) key: FlowKey,
    pub(super) offset: FinalOffset,
    policy: RetirementPolicy,
    deadline: Micros,
    attempts: u32,
    exhausted: bool,
}

impl Active {
    /// Find an empty outgoing registration for an explicit all-flow drain.
    /// Sender release and external ownership must still be checked by the request.
    pub fn drained_candidate(&self) -> Result<Option<FlowKey>, Error> {
        if self.retiring.is_some() {
            return Ok(None);
        }
        Ok(self
            .pipeline
            .tun_flow_heads()?
            .find(|head| head.snapshot.queued.packets == 0)
            .map(|head| head.key))
    }

    /// Find a locally empty idle key; sender and external drain still need checking.
    /// Returns no candidate while another outgoing final barrier remains pending.
    pub fn idle_candidate(&self, now: Micros) -> Result<Option<FlowKey>, Error> {
        self.check_time(now)?;
        if self.retiring.is_some() {
            return Ok(None);
        }
        Ok(self
            .pipeline
            .idle_candidate(Duration::from_micros(now.0))?
            .map(|(key, _)| key))
    }

    /// Freeze one fully released idle flow and queue its exact drained Final.
    ///
    /// Both external counts must be truthful zeros after a caller-owned output and
    /// recovery barrier. The pipeline registration remains occupied until matching
    /// FinalAck, and the same key cannot enqueue more data. A repeated request for
    /// the same frozen key returns its original offset without restarting retries.
    pub fn request_idle_retirement(
        &mut self,
        key: &FlowKey,
        now: Micros,
        policy: RetirementPolicy,
        external: ExternalDrain,
    ) -> Result<FinalOffset, Error> {
        self.request_retirement(key, now, policy, external, true)
    }

    /// Freeze a fully released flow for a coordinated drain, without an idle wait.
    ///
    /// This uses the same serialized exact Final/FinalAck protocol and truthful
    /// external ownership proof as idle retirement. It does not discard packets,
    /// cancel unused peer reservations locally, or authorize an epoch change.
    pub fn request_drained_retirement(
        &mut self,
        key: &FlowKey,
        now: Micros,
        policy: RetirementPolicy,
        external: ExternalDrain,
    ) -> Result<FinalOffset, Error> {
        self.request_retirement(key, now, policy, external, false)
    }

    fn request_retirement(
        &mut self,
        key: &FlowKey,
        now: Micros,
        policy: RetirementPolicy,
        external: ExternalDrain,
        require_idle: bool,
    ) -> Result<FinalOffset, Error> {
        self.check_time(now)?;
        self.check_renewal()?;
        if external.pending_outputs != 0 || external.pending_recovery_records != 0 {
            return Err(Error::ExternalPending);
        }
        if let Some(pending) = &self.retiring {
            return if pending.key == *key {
                let offset = pending.offset;
                self.last_time = now;
                Ok(offset)
            } else {
                Err(Error::RetirementBusy)
            };
        }
        if policy.retry_micros == 0 || policy.max_attempts == 0 {
            return Err(Error::InvalidRetirementPolicy);
        }
        let deadline = Micros(
            now.0
                .checked_add(policy.retry_micros)
                .ok_or(Error::InvalidRetirementPolicy)?,
        );
        let state = self.pipeline.flow(key).ok_or(Error::UnknownFlow)?;
        if state.queued.packets != 0 {
            return Err(Error::Pipeline(PipelineError::Busy));
        }
        if require_idle
            && Duration::from_micros(now.0)
                .checked_sub(state.last_activity)
                .is_none_or(|age| age < self.config.pipeline.flows.idle_timeout)
        {
            return Err(Error::NotIdle);
        }
        let offset = self
            .sender
            .retire(FlowId(state.binding.id.0), RetirementMode::Drained)?;
        self.retiring = Some(PendingRetirement {
            key: *key,
            offset,
            policy,
            deadline,
            attempts: 1,
            exhausted: false,
        });
        self.queue_control(
            ControlKey::Final(offset.flow),
            Message::Final {
                offset,
                mode: RetirementMode::Drained,
            },
        )?;
        self.last_time = now;
        Ok(offset)
    }

    /// Advance the serialized final retry timer without consulting any clock.
    ///
    /// A Final already queued inside the engine consumes no additional attempt.
    /// Exhaustion is terminal for this session, leaves the flow frozen, and does
    /// not prevent receiving its late ACK or draining other existing payloads.
    pub fn poll_retirement(&mut self, now: Micros) -> Result<(), Error> {
        self.check_time(now)?;
        let Some(pending) = self.retiring.as_mut() else {
            self.last_time = now;
            return Ok(());
        };
        if pending.exhausted {
            return Err(Error::RetirementRetriesExhausted);
        }
        if now < pending.deadline
            || self
                .controls
                .contains_key(&ControlKey::Final(pending.offset.flow))
        {
            self.last_time = now;
            return Ok(());
        }
        if pending.attempts >= pending.policy.max_attempts {
            pending.exhausted = true;
            self.renewal_required = true;
            self.last_time = now;
            return Err(Error::RetirementRetriesExhausted);
        }
        let Some(deadline) = now.0.checked_add(pending.policy.retry_micros) else {
            self.renewal_required = true;
            return Err(Error::RenewalRequired);
        };
        pending.attempts += 1;
        pending.deadline = Micros(deadline);
        let offset = pending.offset;
        self.queue_control(
            ControlKey::Final(offset.flow),
            Message::Final {
                offset,
                mode: RetirementMode::Drained,
            },
        )?;
        self.last_time = now;
        Ok(())
    }

    pub(super) fn handle_final(
        &mut self,
        offset: FinalOffset,
        mode: RetirementMode,
    ) -> Result<(), Error> {
        self.check_scope(offset.scope, self.receive_scope)?;
        if mode != RetirementMode::Drained {
            return Err(Error::UnsupportedRetirement);
        }
        if let Some(cached) = self.cached_final
            && cached.flow == offset.flow
        {
            if cached != offset {
                return Err(Error::FinalMismatch);
            }
            return self.queue_control(
                ControlKey::FinalAck(offset.flow),
                Message::FinalAck { offset, mode },
            );
        }
        let Some(state) = self.incoming.get(&offset.flow) else {
            // Older uncached Finals are stale: never overwrite the exact latest
            // ACK, fabricate a conflicting ACK, recreate state, or close the session.
            return if self
                .highest_incoming
                .is_some_and(|last| offset.flow <= last)
            {
                Ok(())
            } else {
                Err(Error::UnknownFlow)
            };
        };
        if !state.pending.is_empty() {
            return Err(Error::Credit(CreditError::OutstandingRecords));
        }
        if state.released != offset.admitted {
            return Err(Error::FinalMismatch);
        }
        let key = state.key;
        self.receiver.retire(offset, RetirementMode::Drained)?;
        self.incoming.remove(&offset.flow);
        if let Some(key) = key {
            self.keys.remove(&key);
        }
        self.cancel_control(ControlKey::Grant(offset.flow));
        self.cancel_control(ControlKey::Release(offset.flow));
        if let Some(previous) = self.cached_final {
            self.cancel_control(ControlKey::FinalAck(previous.flow));
        }
        self.cached_final = Some(offset);
        self.queue_control(
            ControlKey::FinalAck(offset.flow),
            Message::FinalAck { offset, mode },
        )
    }

    pub(super) fn handle_final_ack(
        &mut self,
        offset: FinalOffset,
        mode: RetirementMode,
        _now: Micros,
    ) -> Result<(), Error> {
        self.check_scope(offset.scope, self.send_scope)?;
        if mode != RetirementMode::Drained {
            return Err(Error::UnsupportedRetirement);
        }
        if self
            .completed_final
            .is_some_and(|previous| previous.flow == offset.flow)
        {
            return if self.completed_final == Some(offset) {
                Ok(())
            } else {
                Err(Error::FinalMismatch)
            };
        }
        let Some(pending) = &self.retiring else {
            return if self
                .highest_outgoing
                .is_some_and(|last| offset.flow <= last)
                && !self.sender_contains_flow(offset.flow)
            {
                Ok(())
            } else {
                Err(Error::FinalMismatch)
            };
        };
        if pending.offset.flow != offset.flow {
            return if self
                .highest_outgoing
                .is_some_and(|last| offset.flow <= last)
                && !self.sender_contains_flow(offset.flow)
            {
                Ok(())
            } else {
                Err(Error::FinalMismatch)
            };
        }
        if pending.offset != offset {
            return Err(Error::FinalMismatch);
        }
        self.pipeline
            .retire_drained(&pending.key)
            .map_err(|_| Error::Invariant)?;
        self.retiring = None;
        self.completed_final = Some(offset);
        self.cancel_control(ControlKey::Final(offset.flow));
        Ok(())
    }

    fn sender_contains_flow(&self, flow: FlowId) -> bool {
        // A zero-byte preview can exhaust credit or retention, but only UnknownFlow
        // means absence. It never reserves a record or changes any counters.
        self.sender.preview_admit(flow, 0) != Err(CreditError::UnknownFlow)
    }

    fn cancel_control(&mut self, key: ControlKey) {
        if self.controls.remove(&key).is_some() {
            self.control_order.retain(|queued| *queued != key);
        }
    }
}
