//! Strong exact native device receipts on the existing Common control owner.
use super::*;
use l2tunnel::{record_configuration::NativeWindow, record_engine as engine};

impl Driver {
    pub(super) fn configure_common_native_receipts(&mut self) -> io::Result<()> {
        if self.common.is_none() {
            return Ok(());
        }
        for epoch in self.common_epochs().into_iter().flatten() {
            let record = self.common_state()?.engine(epoch)?;
            let config = record.configuration();
            let send = config
                .descriptor()
                .local(common_contract::mg_role(self.info.role))
                .send();
            if matches!(send.common().native_window(), NativeWindow::Delivery(_)) {
                let scope = common_actions::common_scope(epoch, config)?;
                let channels = send.channels();
                self.control
                    .register_record_receipts(envelope_scope(scope), channels)?;
            }
        }
        Ok(())
    }
    pub(super) fn submit_common_native_receipts(&mut self, now: u64) -> io::Result<()> {
        if self.common.is_none() {
            return Ok(());
        }
        self.configure_common_native_receipts()?;
        for epoch in self.common_epochs().into_iter().flatten() {
            let record = self.common_state()?.engine(epoch)?;
            let Some(delivery) = record.pending_native_delivery() else {
                continue;
            };
            let scope = common_actions::common_scope(epoch, record.configuration())?;
            let id = delivery.identity();
            let accepted = self.submit(
                now,
                scope,
                control::Body::NativeReceipt {
                    lane: mg::LaneId(LANE),
                    receipt: control::NativeReceipt::Record {
                        channel: u16::from(id.channel.0),
                        record: id.record.0,
                    },
                },
                delivery.deadline().0.min(self.lease),
                true,
            )?;
            if accepted.is_some() {
                self.common_state_mut()?
                    .entry(epoch)?
                    .native_delivery_queued(delivery)
                    .map_err(protocol)?;
                let width = self
                    .common_state()?
                    .engine(epoch)?
                    .configuration()
                    .descriptor()
                    .local(common_contract::mg_role(self.info.role))
                    .receive()
                    .channels();
                self.common
                    .as_deref_mut()
                    .ok_or_else(|| protocol("native delivery lost runtime"))?
                    .native_work[(epoch.0 % 2) as usize] = usize::from(width);
            }
        }
        Ok(())
    }
    pub(super) fn receive_common_native_delivery(
        &mut self,
        now: u64,
        scope: Scope,
        lane: mg::LaneId,
        channel: u16,
        record: u64,
    ) -> io::Result<()> {
        if self.common.is_none() || lane != mg::LaneId(LANE) || !self.scope_registered(scope) {
            return Err(protocol("native delivery has no registered Common scope"));
        }
        let epoch = core::Epoch(scope.epoch.0);
        let owner = self.common_state()?.engine(epoch)?;
        if common_actions::common_scope(epoch, owner.configuration())? != scope {
            return Err(protocol("native delivery configuration differs"));
        }
        let id = l2tunnel_codec::aligned_receiver::RecordIdentity {
            channel: l2tunnel_codec::aligned_receiver::ChannelId(
                u8::try_from(channel).map_err(protocol)?,
            ),
            record: l2tunnel_codec::aligned_receiver::RecordId(record),
        };
        // This is the original whole control-message dispatch observation. It
        // is not a source ACK or an asserted remote clock/network RTT sample.
        self.common_state_mut()?
            .entry(epoch)?
            .accept_native_delivery(engine::Tick(now), engine::Tick(now), id)
            .map_err(protocol)
    }
}
