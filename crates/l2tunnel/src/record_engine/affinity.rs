//! Explicit decoded native-channel learning over the same actual outbound Pipeline.
use super::*;

impl Engine {
    pub(super) fn learn_reverse_affinity(
        &mut self,
        now: Tick,
        identity: ProfileIdentity,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let local = self.configuration.descriptor().local(self.context.role);
        if local.send().common().pipeline().flows.mapping
            != pipeline::Mapping::ConnectionRoundRobinLearned
        {
            return Ok(());
        }
        let receive = local.receive().common();
        let layer = match receive.traffic().layer {
            l2tunnel_core::traffic::NetworkLayer::Tap => pipeline::PacketLayer::Ethernet,
            l2tunnel_core::traffic::NetworkLayer::Tun => pipeline::PacketLayer::Ip,
        };
        let classification = l2tunnel_packet::classify(layer, bytes, receive.pipeline().parse)
            .map_err(|error| Error::Pipeline(pipeline::PipelineError::Parse(error)))?;
        let channel = u16::try_from(native_counts::identity_channel(identity))
            .map_err(|_| Error::Invariant)?;
        let connection = match identity {
            ProfileIdentity::Connection(identity) => Some(identity.owner),
            ProfileIdentity::UnreliableNative(identity) => Some(identity.owner),
            _ => None,
        };
        if let (Owner::Connections(owner), Some(id)) = (&self.owner, connection) {
            owner
                .collection
                .check_owner_claim(id, classification.key)
                .map_err(Error::Connections)?;
        }
        self.pipeline
            .learn_classified(classification, channel, duration(now))
            .map_err(Error::Pipeline)?;
        if let (Owner::Connections(owner), Some(id)) = (&mut self.owner, connection) {
            owner
                .collection
                .bind_received_owner(id, classification.key)
                .map_err(Error::Connections)?;
        }
        Ok(())
    }

    /// Retire one idle learned registration after actual complete Engine drain.
    ///
    /// At most work registrations are examined. Resume using the returned after
    /// cursor; no hidden scan state, flow eviction or recovery queue is created.
    /// A returned candidate was actually retired by this method. This differs
    /// from Pipeline::idle_step, which only observes and grants no drain proof.
    /// Original idle ages, native/physical custody and injected time remain binding.
    pub fn retire_affinity_idle(
        &mut self,
        now: Tick,
        after: Option<pipeline::FlowKey>,
        work: usize,
    ) -> Result<pipeline::IdleScan, Error> {
        self.healthy()?;
        if self
            .configuration
            .descriptor()
            .direction(self.context.role)
            .common()
            .pipeline()
            .flows
            .mapping
            != pipeline::Mapping::ConnectionRoundRobinLearned
        {
            return Ok(pipeline::IdleScan {
                after,
                examined: 0,
                candidate: None,
            });
        }
        self.tick(now)?;
        if !self.drained()? {
            return Err(Error::Pipeline(pipeline::PipelineError::Busy));
        }
        let scan = self
            .pipeline
            .idle_step(duration(now), after, work, None)
            .map_err(Error::Pipeline)?;
        if let Some((key, expected)) = scan.candidate {
            // The bounded scan above proves idle age without intervening work.
            // Retire the actual Pipeline binding and its passive ACK history together.
            let actual = self.retire_ingress_flow(now, &key)?;
            if actual != expected {
                return self.fail(Error::Invariant);
            }
        }
        Ok(scan)
    }
}

#[cfg(test)]
#[path = "affinity_tests.rs"]
mod tests;
