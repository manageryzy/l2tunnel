//! Selected fragments on the same Common Driver and physical custody path.
use super::*;
use l2tunnel::{record_bank, record_engine as engine};
use l2tunnel_reliable::OutboundBudget;

/// The existing dedicated feedback slab stores one exact authenticated encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FeedbackEncoding {
    Record,
    Fragment,
}

impl Driver {
    /// Reserve the exact complete group once, then obtain one physical plaintext.
    /// The caller still uses the sole maintained Records sealing path.
    pub(super) fn prepare_common_fragment(
        &mut self,
        epoch: core::Epoch,
        now: u64,
        number: u64,
        allow_data: bool,
        available: usize,
    ) -> io::Result<Option<(engine::Emission, record_bank::FragmentOutputToken, u64)>> {
        let actual = self.common_state()?.engine(epoch)?;
        let policy = actual
            .fragment_policy()
            .ok_or_else(|| protocol("fragment scheduler lacks actual selected owner"))?;
        let framing = if self.info.role == security::Role::Initiator {
            policy.forward.framing
        } else {
            policy.reverse.framing
        };
        let already_reserved = actual.pending_fragment_group().is_some();
        let cap = self.common_original_cap()?;
        let mut budget = OutboundBudget {
            packets: usize::from(framing.max_fragments),
            wire_bytes: available,
        };
        let before = budget;
        let owner::DataOwner::Common(state) = &mut self.owner;
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("fragment scheduler witnesses missing"))?;
        let mut entry = state.entry(epoch)?;
        let Some(group) = entry
            .reserve_fragment_group_until(
                engine::Tick(now),
                number,
                allow_data,
                engine::Tick(cap),
                &mut budget,
                &mut runtime.witnesses,
            )
            .map_err(protocol)?
        else {
            if budget != before {
                return Err(protocol(
                    "unreserved fragment output changed shared allowance",
                ));
            }
            return Ok(None);
        };
        if already_reserved {
            if budget != before {
                return Err(protocol("held fragment group charged twice"));
            }
        } else {
            if before.packets.checked_sub(budget.packets) != Some(group.packets)
                || before.wire_bytes.checked_sub(budget.wire_bytes) != Some(group.wire_bytes)
            {
                return Err(protocol(
                    "fragment reservation differs from exact whole group",
                ));
            }
            self.bucket.charge(group.wire_bytes)?;
        }
        let fragment = entry
            .poll_reserved_fragment(engine::Tick(now), number, &mut self.buffers.frame)
            .map_err(protocol)?
            .ok_or_else(|| protocol("reserved group lost actual fragment"))?;
        let token = entry
            .pending_fragment_output()
            .ok_or_else(|| protocol("fragment lost physical witness"))?;
        if token.emission() != fragment || fragment.emission.security_number != number {
            return Err(protocol(
                "fragment physical witness differs from actual emission",
            ));
        }
        Ok(Some((fragment.emission, token, group.deadline.0)))
    }

    /// A physical fact is routed exactly once to its original issuing generation.
    pub(super) fn confirm_common_output(
        &mut self,
        scope: Scope,
        observed: u64,
        accepted: u64,
        order: Option<l2tunnel::codec::CausalTime>,
        carrier: Option<record_bank::CarrierOutputToken>,
        fragment: Option<record_bank::FragmentOutputToken>,
    ) -> io::Result<()> {
        if carrier.is_some() && fragment.is_some() {
            return Err(protocol(
                "one physical write has two logical custody witnesses",
            ));
        }
        if carrier.is_none() && fragment.is_none() {
            return Ok(());
        }
        let mut entry = self.common_state_mut()?.entry(core::Epoch(scope.epoch.0))?;
        if let Some(token) = fragment {
            match order {
                Some(order) => entry.confirm_fragment_ordered_at(
                    engine::Tick(observed),
                    engine::Tick(accepted),
                    order,
                    token,
                ),
                None => {
                    entry.confirm_fragment_at(engine::Tick(observed), engine::Tick(accepted), token)
                }
            }
            .map_err(protocol)?;
        } else if let Some(token) = carrier {
            match order {
                Some(order) => entry.confirm_carrier_output_ordered_at(
                    engine::Tick(observed),
                    engine::Tick(accepted),
                    order,
                    token,
                ),
                None => entry.confirm_carrier_output_at(
                    engine::Tick(observed),
                    engine::Tick(accepted),
                    token,
                ),
            }
            .map_err(protocol)?;
        }
        Ok(())
    }

    /// Return false only when this exact generation has no selected fragment owner.
    pub(super) fn receive_common_fragment_at(
        &mut self,
        opened: record::Opened,
        received: u64,
        now: u64,
        original: Instant,
    ) -> io::Result<bool> {
        let order = self.causal_time(original)?;
        let epoch = core::Epoch(opened.scope.epoch.0);
        let state = self.common_state()?;
        let Some(reader) = state.peer().reader(epoch) else {
            return Ok(false);
        };
        if state.engine(epoch)?.fragment_policy().is_none() {
            return Ok(false);
        }
        if common_actions::record_scope(reader.scope) != opened.scope
            || !self.scope_registered(opened.scope)
        {
            return Err(protocol("fragment authenticated reader scope differs"));
        }
        let body = self
            .buffers
            .plain
            .get(..opened.bytes)
            .ok_or_else(|| protocol("authenticated fragment plaintext length"))?;
        let kind = state
            .engine(epoch)?
            .inspect_fragment_kind(body)
            .map_err(protocol)?;
        if reader.disposition == transaction::ReadDisposition::Staged
            && kind != engine::EmissionKind::Feedback
        {
            return Err(protocol(
                "staged fragment reader cannot admit native-producing data",
            ));
        }
        let width = usize::from(
            reader
                .config
                .descriptor()
                .local(common_contract::mg_role(self.info.role))
                .receive()
                .channels(),
        );
        let cap = self.common_original_cap()?;
        let owner::DataOwner::Common(state) = &mut self.owner;
        let accepted = state
            .entry(epoch)?
            .accept_fragment_authenticated_ordered_until(
                engine::Tick(received),
                engine::Tick(now),
                engine::Tick(cap),
                opened.number.0,
                order,
                &self.buffers.plain[..opened.bytes],
            );
        match accepted {
            Ok(status) => {
                let runtime = self
                    .common
                    .as_deref_mut()
                    .ok_or_else(|| protocol("fragment input observation owner"))?;
                runtime.observation_dirty = true;
                if status == engine::FragmentAdmission::Accepted {
                    runtime.native_work[(epoch.0 % 2) as usize] = width;
                }
                if status == engine::FragmentAdmission::Expired {
                    self.counters.rejected_packets =
                        self.counters.rejected_packets.saturating_add(1);
                }
            }
            Err(record_bank::Error::Engine(engine::Error::FragmentBusy)) => {
                if kind == engine::EmissionKind::Feedback {
                    self.retain_common_fragment_feedback(opened, received, now, cap, original)?;
                } else {
                    // The new fragment was not consumed. Existing complete-body
                    // and Rolling queue custody remain exact; the carrier is lossy.
                    let runtime = self
                        .common
                        .as_deref_mut()
                        .ok_or_else(|| protocol("fragment pressure owner"))?;
                    runtime.fragment_data_drops = runtime.fragment_data_drops.saturating_add(1);
                    runtime.observation_dirty = true;
                    self.counters.native_backpressure_drops =
                        self.counters.native_backpressure_drops.saturating_add(1);
                }
            }
            Err(error) => return Err(protocol(error)),
        }
        Ok(true)
    }

    fn retain_common_fragment_feedback(
        &mut self,
        opened: record::Opened,
        received: u64,
        now: u64,
        cap: u64,
        original: Instant,
    ) -> io::Result<()> {
        let policy = self
            .common_state()?
            .engine(core::Epoch(opened.scope.epoch.0))?
            .fragment_policy()
            .ok_or_else(|| protocol("fragment feedback selection missing"))?;
        let receive = if self.info.role == security::Role::Initiator {
            policy.reverse
        } else {
            policy.forward
        };
        let deadline = received
            .checked_add(receive.reassembly.feedback.max_lifetime_ticks)
            .ok_or_else(exhausted)?
            .min(cap);
        if received > now || now >= deadline {
            self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
            return Ok(());
        }
        if self.research_physical_output(opened.scope)?
            && self
                .common
                .as_deref()
                .is_some_and(|r| r.pending_feedback.is_some())
        {
            return Err(protocol(
                "bounded Research fragment feedback custody is full",
            ));
        }
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("fragment feedback retained owner missing"))?;
        if runtime.pending_feedback.is_some() {
            runtime.fragment_feedback_drops = runtime.fragment_feedback_drops.saturating_add(1);
            runtime.observation_dirty = true;
            self.counters.native_backpressure_drops =
                self.counters.native_backpressure_drops.saturating_add(1);
            return Ok(());
        }
        runtime
            .feedback_input
            .get_mut(..opened.bytes)
            .ok_or_else(|| protocol("fragment feedback retained capacity"))?
            .copy_from_slice(
                self.buffers
                    .plain
                    .get(..opened.bytes)
                    .ok_or_else(|| protocol("fragment feedback authenticated length"))?,
            );
        runtime.pending_feedback = Some(common::PendingFeedback {
            scope: opened.scope,
            number: opened.number.0,
            bytes: opened.bytes,
            received,
            deadline,
            encoding: FeedbackEncoding::Fragment,
            physical_dependency: None,
            physical_arrival: Some(original),
        });
        runtime.observation_dirty = true;
        Ok(())
    }

    /// Bounded actual completed-body retries, with independent feedback serviced first.
    pub(super) fn retry_common_fragment_inputs(&mut self, now: u64) -> io::Result<()> {
        for epoch in self.common_epochs().into_iter().flatten() {
            if self
                .common_state()?
                .engine(epoch)?
                .fragment_policy()
                .is_none()
            {
                continue;
            }
            let count = self
                .common_state_mut()?
                .entry(epoch)?
                .retry_fragment_inputs(engine::Tick(now))
                .map_err(protocol)?;
            if count != 0 {
                let width = usize::from(
                    self.common_state()?
                        .engine(epoch)?
                        .configuration()
                        .descriptor()
                        .local(common_contract::mg_role(self.info.role))
                        .receive()
                        .channels(),
                );
                let runtime = self
                    .common
                    .as_deref_mut()
                    .ok_or_else(|| protocol("fragment completion observation owner"))?;
                runtime.native_work[(epoch.0 % 2) as usize] = width;
                runtime.observation_dirty = true;
            }
        }
        Ok(())
    }

    /// Exact already-selected full-group wake cost; no independent sizing model.
    pub(super) fn common_fragment_wire_cost(
        &self,
        epoch: core::Epoch,
        logical_bytes: usize,
    ) -> io::Result<Option<usize>> {
        let Some(policy) = self.common_state()?.engine(epoch)?.fragment_policy() else {
            return Ok(None);
        };
        let framing = if self.info.role == security::Role::Initiator {
            policy.forward.framing
        } else {
            policy.reverse.framing
        };
        framing
            .geometry(logical_bytes)
            .map(|geometry| Some(geometry.wire_bytes()))
            .map_err(protocol)
    }
}
