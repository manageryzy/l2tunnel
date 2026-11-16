//! Causal order around the sole actual physical User witness. No crypto/recovery
//! state machine, packet queue, new clock or authentication proof is created.
use super::*;
use l2tunnel::{record_configuration as configuration, record_engine as engine};

impl Driver {
    pub(super) fn causal_time(&self, at: Instant) -> io::Result<l2tunnel::codec::CausalTime> {
        at.checked_duration_since(self.origin)
            .map(|elapsed| l2tunnel::codec::CausalTime::from_nanos(elapsed.as_nanos()))
            .ok_or_else(|| invalid("causal observation precedes retained clock origin"))
    }
    pub(super) fn research_physical_output(&self, scope: Scope) -> io::Result<bool> {
        let Some(runtime) = &self.common else {
            return Ok(false);
        };
        if runtime.contract.extra_wire_bytes() == 0 && runtime.contract.raw_outer().is_none() {
            return Ok(false);
        }
        let state = self.common_state()?;
        let Some(reader) = state.peer().reader(core::Epoch(scope.epoch.0)) else {
            return Ok(false);
        };
        Ok(
            common_actions::common_scope(core::Epoch(scope.epoch.0), reader.config)? == scope
                && matches!(
                    reader.config.descriptor().profile(),
                    configuration::Profile::Research { .. }
                ),
        )
    }
    pub(super) fn research_carrier_selected(&self) -> bool {
        self.common.as_ref().is_some_and(|runtime| {
            (runtime.contract.extra_wire_bytes() != 0 || runtime.contract.raw_outer().is_some())
                && runtime
                    .contract
                    .catalog()
                    .descriptors()
                    .iter()
                    .any(|d| matches!(d.profile(), configuration::Profile::Research { .. }))
        })
    }
    pub(super) fn retain_research_feedback(
        &mut self,
        opened: record::Opened,
        received: u64,
        observed: u64,
        original: Instant,
    ) -> io::Result<bool> {
        if !self.research_physical_output(opened.scope)? {
            return Ok(false);
        }
        let runtime = self
            .common
            .as_ref()
            .ok_or_else(|| protocol("Research runtime missing"))?;
        let Some(output) = &runtime.sealed else {
            return Ok(false);
        };
        if output.scope != opened.scope {
            return Ok(false);
        }
        let kind = output
            .carrier
            .as_ref()
            .map(|v| v.emission().kind)
            .or_else(|| output.fragment.as_ref().map(|v| v.emission().emission.kind));
        if !matches!(
            kind,
            Some(engine::EmissionKind::Source(_) | engine::EmissionKind::Repair)
        ) {
            return Ok(false);
        }
        let dependency = output.sealed.number.0;
        let deadline = output.deadline.min(self.common_original_cap()?);
        let order = self.causal_time(original)?;
        let owner::DataOwner::Common(state) = &mut self.owner else {
            return Err(protocol("Research feedback Bank missing"));
        };
        if state
            .entry(core::Epoch(opened.scope.epoch.0))?
            .retain_research_feedback_authenticated_until(
                engine::Tick(received),
                engine::Tick(observed),
                engine::Tick(deadline),
                opened.number.0,
                Some(order),
                self.buffers
                    .plain
                    .get(..opened.bytes)
                    .ok_or_else(|| protocol("Research authenticated feedback length"))?,
            )
            .map_err(protocol)?
        {
            return Ok(true);
        }
        if self
            .common
            .as_ref()
            .is_some_and(|runtime| runtime.pending_feedback.is_some())
        {
            return Err(protocol("bounded Research feedback custody is full"));
        }
        if received > observed || observed >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original Research feedback cap",
            ));
        }
        let runtime = self
            .common
            .as_mut()
            .ok_or_else(|| protocol("Research runtime missing"))?;
        runtime
            .feedback_input
            .get_mut(..opened.bytes)
            .ok_or_else(|| protocol("Research feedback slab capacity"))?
            .copy_from_slice(
                self.buffers
                    .plain
                    .get(..opened.bytes)
                    .ok_or_else(|| protocol("Research authenticated feedback length"))?,
            );
        runtime.pending_feedback = Some(common::PendingFeedback {
            encoding: common_fragments::FeedbackEncoding::Record,
            physical_dependency: Some(dependency),
            physical_arrival: Some(original),
            scope: opened.scope,
            number: opened.number.0,
            bytes: opened.bytes,
            received,
            deadline,
        });
        runtime.observation_dirty = true;
        Ok(true)
    }
    pub(super) fn research_feedback_before_receipt(
        &mut self,
        scope: Scope,
        number: u64,
        actual_accepted: Instant,
        accepted: u64,
        observed: u64,
    ) -> io::Result<()> {
        let Some(pending) = self.common.as_ref().and_then(|r| r.pending_feedback) else {
            return Ok(());
        };
        let Some(dependency) = pending.physical_dependency else {
            return Ok(());
        };
        if pending.scope != scope || dependency != number {
            return Err(protocol(
                "Research receipt differs from retained dependency",
            ));
        }
        if pending
            .physical_arrival
            .map_or(pending.received <= accepted, |arrival| {
                arrival <= actual_accepted
            })
        {
            // complete_common_carrier already took the exact sealed custody, so
            // retry cannot accidentally apply before an unknown physical fact.
            if !self.retry_common_feedback(observed)? {
                return Err(protocol("Research earlier feedback could not be ordered"));
            }
        }
        Ok(())
    }
}
