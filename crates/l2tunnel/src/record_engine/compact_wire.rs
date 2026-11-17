//! Explicit final-body selection on the existing owner; no alternate packet loop.
use super::*;

pub(super) fn maximums(
    profile: configuration::DirectionProfile<'_>,
    opposite: configuration::DirectionProfile<'_>,
) -> Result<(usize, usize), Error> {
    use configuration::DirectionProfile as D;
    let result = match (profile, opposite) {
        (D::Swift(send), D::Swift(_)) => {
            return Ok((send.codec.datagram_bytes, send.codec.datagram_bytes));
        }
        (D::Aligned(send), D::Aligned(receive)) => (
            send.recovery.compact_wire_maximum_data_bytes(),
            receive.recovery.compact_wire_maximum_feedback_bytes(),
        ),
        (D::Packed(send), D::Packed(receive)) => (
            send.base.recovery.compact_wire_maximum_data_bytes(),
            receive.base.recovery.compact_wire_maximum_feedback_bytes(),
        ),
        (D::AlignedCompact(send), D::AlignedCompact(receive)) => (
            send.recovery.compact_wire_maximum_data_bytes(),
            receive.recovery.compact_wire_maximum_feedback_bytes(),
        ),
        (D::PackedCompact(send), D::PackedCompact(receive)) => (
            send.base.recovery.compact_wire_maximum_data_bytes(),
            receive.base.recovery.compact_wire_maximum_feedback_bytes(),
        ),
        (D::PerConnectionCompact(send), D::PerConnectionCompact(receive)) => {
            let route = crate::connection_records::route::COMPACT_HEADER_BYTES;
            let data = send
                .compact
                .recovery
                .compact_wire_maximum_data_bytes()
                .map_err(|_| Error::Configuration)?
                .checked_add(route)
                .ok_or(Error::Arithmetic)?;
            let feedback = receive
                .compact
                .recovery
                .compact_wire_maximum_feedback_bytes()
                .map_err(|_| Error::Configuration)?
                .checked_add(route)
                .ok_or(Error::Arithmetic)?;
            let raw = send
                .unreliable
                .map_or(0, |policy| policy.max_bytes)
                .checked_add(crate::connection_records::route::COMPACT_UNRELIABLE_BYTES)
                .ok_or(Error::Arithmetic)?;
            return Ok((data.max(raw), feedback));
        }
        (
            D::Rolling { config: send, .. },
            D::Rolling {
                config: receive, ..
            },
        ) => {
            return Ok((
                send.compact_wire_maximum_data_bytes()
                    .map_err(Error::Rolling)?,
                receive
                    .compact_wire_maximum_feedback_bytes()
                    .map_err(Error::Rolling)?,
            ));
        }
        (
            D::Research { config: send, .. },
            D::Research {
                config: receive, ..
            },
        ) => {
            return Ok((
                send.compact_wire_maximum_data_bytes()
                    .map_err(Error::Rolling)?,
                receive
                    .compact_wire_maximum_feedback_bytes()
                    .map_err(Error::Rolling)?,
            ));
        }
        _ => return Err(Error::Configuration),
    };
    Ok((
        result.0.map_err(|_| Error::Configuration)?,
        result.1.map_err(|_| Error::Configuration)?,
    ))
}

impl Engine {
    /// Select context-free algorithm bodies before the first owner operation.
    /// The enclosing authenticated establishment must bind this choice. Legacy
    /// constructors retain their original encoding until explicitly selected.
    pub fn enable_compact_wire(&mut self, feedback_overhead: usize) -> Result<(), Error> {
        if self.last.is_none() && self.compact_feedback_overhead == Some(feedback_overhead) {
            return Ok(());
        }
        if self.last.is_some()
            || self.compact_feedback_overhead.is_some()
            || self
                .fragments
                .as_ref()
                .is_some_and(|state| state.compact_feedback_overhead() != Some(feedback_overhead))
        {
            return Err(Error::Configuration);
        }
        match &mut self.owner {
            Owner::Swift(_) => {}
            Owner::Aligned(endpoint) => endpoint
                .enable_compact_wire(feedback_overhead)
                .map_err(Error::Aligned)?,
            Owner::Packed(endpoint) => endpoint
                .enable_compact_wire(feedback_overhead)
                .map_err(Error::Aligned)?,
            Owner::Connections(owner) => owner
                .collection
                .enable_compact_wire(feedback_overhead)
                .map_err(Error::Connections)?,
            Owner::Rolling(endpoint) => endpoint
                .enable_compact_wire(feedback_overhead)
                .map_err(Error::Rolling)?,
            Owner::Research(endpoint) => endpoint
                .enable_compact_wire(feedback_overhead)
                .map_err(Error::Rolling)?,
        }
        self.compact_feedback_overhead = Some(feedback_overhead);
        Ok(())
    }

    /// Whether this actual owner was selected for compact final-body encoding.
    pub const fn is_compact_wire(&self) -> bool {
        self.compact_feedback_overhead.is_some()
    }

    /// Decode the actual selected independent-owner route before incarnation
    /// filtering. Authentication remains with the enclosing record owner.
    pub fn connection_route<'a>(
        &self,
        body: &'a [u8],
    ) -> Result<(crate::connection_records::route::Header, &'a [u8]), Error> {
        let Owner::Connections(owner) = &self.owner else {
            return Err(Error::Configuration);
        };
        owner
            .collection
            .decode_route(body)
            .map_err(Error::Connections)
    }

    /// Validate complete peer packet structure using the negotiated owner before
    /// granting feedback or authenticated-liveness authority. No state commits.
    pub fn inspect_peer(&self, body: &[u8]) -> Result<EmissionKind, Error> {
        match &self.owner {
            Owner::Aligned(endpoint) => endpoint
                .inspect_peer(body)
                .map(owner::emission_kind)
                .map_err(Error::Aligned),
            Owner::Packed(endpoint) => endpoint
                .inspect_peer(body)
                .map(owner::emission_kind)
                .map_err(Error::Aligned),
            Owner::Connections(owner) => owner.inspect(body),
            Owner::Swift(_) => self.inspect_swift_peer(body),
            Owner::Rolling(endpoint) => endpoint.inspect_peer(body).map_err(Error::Rolling),
            Owner::Research(endpoint) => endpoint.inspect_peer(body).map_err(Error::Rolling),
        }
    }

    fn inspect_swift_peer(&self, body: &[u8]) -> Result<EmissionKind, Error> {
        self.inspect_swift_direction(body, false)
    }

    pub(super) fn inspect_swift_direction(
        &self,
        body: &[u8],
        outgoing: bool,
    ) -> Result<EmissionKind, Error> {
        let local = self.configuration.descriptor().local(self.context.role);
        let (data, feedback) = if outgoing {
            (local.send(), local.receive())
        } else {
            (local.receive(), local.send())
        };
        let lead = *body.first().ok_or(Error::PacketSize)?;
        match lead & swift::KIND_MASK {
            swift::KIND_SOURCE | swift::KIND_REPAIR => {
                let (minimum, kind) = if lead & swift::KIND_MASK == swift::KIND_SOURCE {
                    (
                        swift::SOURCE_HEADER,
                        EmissionKind::Source(SourceForm::Swift),
                    )
                } else {
                    (swift::REPAIR_HEADER, EmissionKind::Repair)
                };
                if body.len() < minimum || u16::from(lead >> 2) >= data.channels() {
                    return Err(Error::PacketSize);
                }
                Ok(kind)
            }
            swift::KIND_FEEDBACK => {
                let mut rest = body;
                while !rest.is_empty() {
                    if rest.len() < swift::FEEDBACK_HEADER
                        || rest[0] & swift::KIND_MASK != swift::KIND_FEEDBACK
                        || u16::from(rest[0] >> 2) >= feedback.channels()
                    {
                        return Err(Error::Kind);
                    }
                    let requests = usize::from(rest[swift::FEEDBACK_HEADER - 1]);
                    if requests > swift::MAX_REQUESTS {
                        return Err(Error::PacketSize);
                    }
                    rest = rest
                        .get(swift::FEEDBACK_HEADER + 2 * requests..)
                        .ok_or(Error::PacketSize)?;
                }
                Ok(EmissionKind::Feedback)
            }
            _ => Err(Error::Kind),
        }
    }
}
