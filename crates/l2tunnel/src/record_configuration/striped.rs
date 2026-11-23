//! Additive CompleteV2 tag10. Every active field is part of the catalog commitment.
use super::*;
use crate::striped_records::Direction;
use fec::{GenerationId, mixed_datagram, striped_group::schedule::RecoveryTiming};

pub(super) const ACTIVE_BYTES: usize = (22 + 16) * 8;

pub(super) fn encode(direction: Direction, slot: &mut [u8]) -> Result<(), Error> {
    let mut writer = Writer::new(slot.get_mut(..ACTIVE_BYTES).ok_or(Error::Length)?);
    packed_fields::encode(
        &mut writer,
        direction.native_policy,
        direction.receiver,
        direction.packing,
    )?;
    for word in [
        u64::from(direction.profile.data_cells),
        u64::from(direction.profile.parity_cells),
        integer(direction.profile.max_wire_bytes)?,
        integer(direction.profile.max_body_bytes)?,
        direction.first.0,
        integer(direction.source_limit)?,
        integer(direction.expanded_limit)?,
        direction.hold_micros,
        direction.timing.gap_delay,
        direction.timing.gap_repeat,
        direction.timing.ack_delay,
        direction.timing.quiet,
        integer(direction.overhead_bytes)?,
        u64::from(direction.stream),
        direction.codec_stage_micros,
        direction.native_stall_micros,
    ] {
        writer.number(word)?;
    }
    writer.finish()
}

pub(super) fn decode(slot: &[u8]) -> Result<Direction, Error> {
    let mut reader = Reader::new(slot.get(..ACTIVE_BYTES).ok_or(Error::Length)?);
    let (native_policy, receiver, packing) = packed_fields::decode(&mut reader)?;
    let direction = Direction {
        native_policy,
        receiver,
        packing,
        profile: mixed_datagram::Profile {
            data_cells: checked(reader.number()?)?,
            parity_cells: checked(reader.number()?)?,
            max_wire_bytes: reader.size()?,
            max_body_bytes: reader.size()?,
        },
        first: GenerationId(reader.number()?),
        source_limit: reader.size()?,
        expanded_limit: reader.size()?,
        hold_micros: reader.number()?,
        timing: RecoveryTiming {
            gap_delay: reader.number()?,
            gap_repeat: reader.number()?,
            ack_delay: reader.number()?,
            quiet: reader.number()?,
        },
        overhead_bytes: reader.size()?,
        stream: checked(reader.number()?)?,
        codec_stage_micros: reader.number()?,
        native_stall_micros: reader.number()?,
    };
    reader.finish()?;
    Ok(direction)
}
