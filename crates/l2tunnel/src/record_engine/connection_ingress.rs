//! Original timing and actual classified raw ingress for the selected cohort.
use super::*;
use crate::connection_records as records;

/// Actual installed collection capabilities and separate local source-free facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionSnapshot {
    /// Actual independent endpoint count.
    pub owners: u16,
    /// False until authenticated drained/fenced slot reuse has a real consumer.
    pub flow_reuse: bool,
    /// Actual source-free events; no value claims peer delivery or reliable prefix.
    pub unreliable: records::UnreliableStatistics,
}

impl Engine {
    pub(super) fn requires_original_ingress_cap(&self) -> bool {
        matches!(&self.owner, Owner::Connections(owner) if owner.collection.configuration().send_unreliable.is_some())
    }

    pub(super) fn accept_connection_raw(
        &mut self,
        received: Tick,
        now: Tick,
        original_cap: Tick,
        body: &[u8],
    ) -> Result<(), Error> {
        let Owner::Connections(owner) = &self.owner else {
            return Err(Error::Invariant);
        };
        let (header, native) = owner
            .collection
            .decode_route(body)
            .map_err(Error::Connections)?;
        let receive = self
            .configuration
            .descriptor()
            .local(self.context.role)
            .receive();
        let layer = match receive.common().traffic().layer {
            l2tunnel_core::traffic::NetworkLayer::Tap => pipeline::PacketLayer::Ethernet,
            l2tunnel_core::traffic::NetworkLayer::Tun => pipeline::PacketLayer::Ip,
        };
        let classification =
            l2tunnel_packet::classify(layer, native, receive.common().pipeline().parse)
                .map_err(|error| Error::Pipeline(pipeline::PipelineError::Parse(error)))?;
        let Owner::Connections(owner) = &mut self.owner else {
            return Err(Error::Invariant);
        };
        if owner.inspect(body)? != EmissionKind::UnreliableNative {
            return Err(Error::Kind);
        }
        owner
            .collection
            .check_owner_claim(header.owner, classification.key)
            .map_err(Error::Connections)?;
        // A genuine authenticated route still cannot overwrite an existing
        // actual FlowTable binding, including a simultaneous-open conflict.
        if self
            .pipeline
            .flow(&classification.key)
            .is_some_and(|flow| flow.binding.channel != header.owner.index())
        {
            return Err(Error::Connections(records::Error::Binding));
        }
        owner.accept_raw(received, now, original_cap, body, classification)
    }

    /// Observe installed fixed-cohort capability, not a requested uninstalled tag.
    pub fn connection_snapshot(&self) -> Option<ConnectionSnapshot> {
        match &self.owner {
            Owner::Connections(owner) => Some(ConnectionSnapshot {
                owners: owner.collection.storage_usage().owners,
                flow_reuse: false,
                unreliable: owner.collection.unreliable_statistics(),
            }),
            _ => None,
        }
    }
}
