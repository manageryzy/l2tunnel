//! Maintained codec/recovery views for the actual shared Engine consumer.
use super::*;
use l2tunnel_codec::aligned_receiver::UnitWitness;

impl Collection {
    /// Exact complete immutable directional request; no admission authority.
    pub fn configuration(&self) -> Config {
        self.plan.config()
    }

    /// Check the actual routed grammar and authoritative selected inner parser.
    /// Raw eligibility still requires classification of its complete native body.
    pub fn inspect_authenticated(&self, packet: &[u8]) -> Result<route::Class, Error> {
        let (header, body) = route::decode(packet).map_err(Error::Route)?;
        if header.incarnation != self.slot(header.owner)?.incarnation {
            return Err(Error::Incarnation);
        }
        let slot = self.slot(header.owner)?;
        let expected = match header.class {
            route::Class::Source => RecordKind::Source,
            route::Class::Feedback => RecordKind::Feedback,
            route::Class::UnreliableNative => {
                if self.plan.config().receive_unreliable.is_none() {
                    return Err(Error::UnsupportedUnreliable);
                }
                return Ok(header.class);
            }
        };
        if slot.endpoint.inspect_peer(body).map_err(Error::Endpoint)? != expected {
            return Err(Error::Class);
        }
        Ok(header.class)
    }

    /// Inspect actual outgoing codec units, translating channel0 to its owner.
    /// No record/native count is synthesized from a source or route sequence.
    pub fn outgoing_units(
        &mut self,
        packet: &[u8],
        witnesses: &mut [UnitWitness],
    ) -> Result<usize, Error> {
        let (header, body) = route::decode(packet).map_err(Error::Route)?;
        if header.incarnation != self.slot(header.owner)?.incarnation {
            return Err(Error::Incarnation);
        }
        if header.class == route::Class::UnreliableNative {
            if self.plan.config().send_unreliable.is_none() {
                return Err(Error::UnsupportedUnreliable);
            }
            self.slot(header.owner)?;
            return Ok(0);
        }
        let channel = u8::try_from(header.owner.index()).map_err(|_| Error::Owner)?;
        let slot = self.slot_mut(header.owner)?;
        let expected = match header.class {
            route::Class::Source => RecordKind::Source,
            route::Class::Feedback => RecordKind::Feedback,
            route::Class::UnreliableNative => return Err(Error::Invariant),
        };
        if slot
            .endpoint
            .inspect_output(body)
            .map_err(Error::Endpoint)?
            != expected
        {
            return Err(Error::Class);
        }
        let count = slot
            .endpoint
            .outgoing_units(body, witnesses)
            .map_err(Error::Endpoint)?;
        let actual = witnesses.get_mut(..count).ok_or(Error::Invariant)?;
        if actual.iter().any(|unit| unit.identity.channel.0 != 0) {
            return Err(Error::Invariant);
        }
        for unit in actual {
            unit.identity.channel = aligned::ChannelId(channel);
        }
        Ok(count)
    }

    /// Earliest actual eligible feedback, with the exact routed body requirement.
    /// This reads maintained endpoint opportunities without time/dequeue mutation.
    pub fn feedback_opportunity(&self) -> Result<Option<(OwnerId, Duration, usize)>, Error> {
        let mut earliest: Option<(OwnerId, Duration, usize)> = None;
        for (index, slot) in self.slots.iter().enumerate() {
            let Some((at, bytes)) = slot
                .endpoint
                .feedback_opportunity()
                .map_err(Error::Endpoint)?
            else {
                continue;
            };
            let owner = self.owner(u16::try_from(index).map_err(|_| Error::Arithmetic)?)?;
            let bytes = bytes
                .checked_add(route::HEADER_BYTES)
                .ok_or(Error::Arithmetic)?;
            if earliest.is_none_or(|(_, current, _)| at < current) {
                earliest = Some((owner, at, bytes));
            }
        }
        Ok(earliest)
    }
}
