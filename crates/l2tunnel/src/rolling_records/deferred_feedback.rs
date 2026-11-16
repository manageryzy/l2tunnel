//! Research feedback shares the selected generation's existing input buffers.
//! Actual physical completion orders this exact authenticated evidence; queued
//! feedback cannot acknowledge an unconfirmed source or create another clock.
use super::*;

impl Endpoint<crate::fec::research::Config> {
    /// Retain a complete authenticated feedback record in the existing selected
    /// ingress queue. False means no queue was selected; Busy consumes nothing.
    #[allow(clippy::too_many_arguments)] // Original arrival, cap and precise order remain independent.
    pub(crate) fn retain_feedback_until(
        &mut self,
        received: Tick,
        now: Tick,
        cap: Tick,
        number: u64,
        order: Option<codec::CausalTime>,
        bytes: &[u8],
    ) -> Result<bool, Error> {
        if self.ingress.is_none() {
            return Ok(false);
        }
        if received > now {
            return Err(Error::Time);
        }
        self.advance(now)?;
        let parsed = if self.compact_feedback_overhead.is_some() {
            crate::fec::research::wire::compact::inspect(
                self.send_config.scheduler,
                self.send_rolling_scope,
                bytes,
            )
        } else {
            crate::fec::research::wire::inspect(self.send_config.scheduler, bytes)
        };
        let crate::fec::research::wire::View::Feedback(feedback) =
            parsed.map_err(Error::Rolling)?
        else {
            return Err(Error::Identity);
        };
        if feedback.scope != self.send_rolling_scope {
            return Err(Error::Identity);
        }
        let deadline = Tick(
            received
                .0
                .checked_add(self.send_config.scheduler.recovery.job_ticks)
                .ok_or(Error::Arithmetic)?,
        )
        .min(cap);
        if now >= deadline {
            return self.fail(Error::Expired);
        }
        let owner = self.ingress.as_mut().ok_or(Error::Identity)?;
        let lease = owner.queue.acquire().ok_or(Error::Busy)?;
        lease
            .copy(
                ingress::Input {
                    kind: record_engine::EmissionKind::Feedback,
                    number: Some(number),
                    received,
                    order,
                    original_cap: cap,
                    deadline,
                },
                received.0,
                bytes,
            )
            .map_err(Error::Ingress)?;
        Ok(true)
    }

    // Visit only the initial bounded cohort. Nonmatching data retains its exact
    // FIFO order/buffer; feedback on either side keeps its original arrival/cap.
    pub(crate) fn feedback_at_completion(
        &mut self,
        now: Tick,
        accepted: Tick,
        order: Option<codec::CausalTime>,
        before: bool,
    ) -> Result<(), Error> {
        let Some(owner) = &mut self.ingress else {
            return Ok(());
        };
        if owner.deadline().is_some_and(|deadline| now >= deadline) {
            return self.fail(Error::Expired);
        }
        let count = owner.queue.len();
        for _ in 0..count {
            let front = owner.queue.front().ok_or(Error::Identity)?;
            let input = *front.metadata();
            let earlier = match (input.order, order) {
                (Some(arrived), Some(sent)) => arrived <= sent,
                _ => input.received <= accepted,
            };
            if input.kind != record_engine::EmissionKind::Feedback || earlier != before {
                owner.queue.rotate_front().map_err(Error::Ingress)?;
                continue;
            }
            if now >= input.deadline {
                return self.fail(Error::Expired);
            }
            let result = compact_wire::receive_feedback::<crate::fec::research::Config>(
                self.compact_feedback_overhead.is_some(),
                self.send_config.scheduler,
                self.send_rolling_scope,
                &mut self.sender,
                front.bytes(),
                rolling::Tick(input.received.0),
                rolling::Tick(now.0),
            )
            .map_err(Error::Rolling);
            if let Err(error) = result {
                return self.fail(error);
            }
            owner.queue.complete_front().map_err(Error::Ingress)?;
        }
        Ok(())
    }
}
