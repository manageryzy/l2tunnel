//! Context-free legacy ARQ bodies selected only by an established outer contract.
use super::*;

/// Complete u64 source identity in canonical unsigned base-128 encoding.
pub const ARQ_BODY_DATA_MAX_HEADER_BYTES: usize = 10;
/// Complete cumulative prefix and receipt bitmap, without context or kind.
pub const ARQ_BODY_FEEDBACK_MAX_HEADER_BYTES: usize = 20;

impl PacketView<'_> {
    /// Exact selective ACK coverage using the same predicate as receive retirement.
    /// This is syntax-only metadata; the receive owner must validate the ACK first.
    /// Data has no ACK coverage, and caller-created invalid views remain untrusted.
    pub fn acknowledges(self, source: SourceId) -> Option<bool> {
        match self {
            Self::Ack { prefix, bitmap } => Some(acknowledged(source, prefix, bitmap)),
            Self::Data { .. } => None,
        }
    }

    /// Exact context-free bytes; the enclosing union supplies the packet kind.
    pub fn body_encoded_len(self) -> Result<usize, RecoveryError> {
        match self {
            Self::Data { source, payload } => {
                if source.0 == u64::MAX {
                    return Err(RecoveryError::CounterExhausted);
                }
                if payload.len() > 65_535 {
                    return Err(RecoveryError::SourceTooLarge);
                }
                Ok(varint_len(source.0) + payload.len())
            }
            Self::Ack { prefix, bitmap } => {
                if bitmap & 1 != 0
                    || (bitmap != 0
                        && prefix
                            .checked_add(63 - u64::from(bitmap.leading_zeros()))
                            .is_none())
                {
                    return Err(RecoveryError::MalformedPacket);
                }
                Ok(varint_len(prefix) + varint_len(bitmap))
            }
        }
    }
    /// Serialize the chosen arm without session, epoch, profile or length duplicates.
    pub fn encode_body_into(self, output: &mut [u8]) -> Result<usize, RecoveryError> {
        let required = self.body_encoded_len()?;
        ensure_output(output, required)?;
        let mut position = 0;
        match self {
            Self::Data { source, payload } => {
                write_varint(source.0, output, &mut position);
                output[position..required].copy_from_slice(payload);
            }
            Self::Ack { prefix, bitmap } => {
                write_varint(prefix, output, &mut position);
                write_varint(bitmap, output, &mut position);
            }
        }
        Ok(required)
    }
}

/// Parse a canonical bounded body after the selected outer context/check/replay gate.
/// `feedback` is supplied by the validated enclosing union, not inferred from bytes.
pub fn inspect_body(
    feedback: bool,
    bytes: &[u8],
    maximum: usize,
) -> Result<PacketView<'_>, RecoveryError> {
    if !(1..=65_535).contains(&maximum) {
        return Err(RecoveryError::InvalidConfig);
    }
    let mut position = 0;
    let first = read_varint(bytes, &mut position)?;
    let view = if feedback {
        let bitmap = read_varint(bytes, &mut position)?;
        if position != bytes.len() {
            return Err(RecoveryError::MalformedPacket);
        }
        PacketView::Ack {
            prefix: first,
            bitmap,
        }
    } else {
        let payload = &bytes[position..];
        if payload.len() > maximum {
            return Err(RecoveryError::SourceTooLarge);
        }
        PacketView::Data {
            source: SourceId(first),
            payload,
        }
    };
    view.body_encoded_len()?;
    Ok(view)
}

impl SelectiveRepeat {
    /// Emit the actual source owner using the selected context-free representation.
    pub fn poll_source_body(
        &mut self,
        now: Duration,
        output: &mut [u8],
    ) -> Result<Option<usize>, RecoveryError> {
        self.0.poll_selected_body(now, output, false, true, true)
    }
    /// Emit the same due ACK state without the legacy context header.
    pub fn poll_feedback_body(
        &mut self,
        now: Duration,
        output: &mut [u8],
    ) -> Result<Option<usize>, RecoveryError> {
        self.0.poll_selected_body(now, output, true, false, true)
    }
    /// Accept a validated typed union through the existing bounded recovery state.
    pub fn receive_view(
        &mut self,
        view: PacketView<'_>,
        now: Duration,
    ) -> Result<(), RecoveryError> {
        self.0.receive_view(view, now)
    }
    /// Apply the same validated view and optionally return exact ACK boundaries.
    /// The output changes only after a successful ACK; data and all errors leave
    /// it untouched. Original validation and retention passes collect the scalars
    /// without allocating, reparsing, or scanning the send window again.
    pub fn receive_view_observed(
        &mut self,
        view: PacketView<'_>,
        now: Duration,
        observation: &mut Option<AckObservation>,
    ) -> Result<(), RecoveryError> {
        self.0.receive_view_observed(view, now, Some(observation))
    }
    /// Exact currently due body size; does not consume output or renew deadlines.
    pub fn body_packet_bytes(
        &self,
        now: Duration,
        feedback: bool,
    ) -> Result<Option<usize>, RecoveryError> {
        self.0.check_time(now)?;
        if feedback {
            if self.0.ack_at.is_none_or(|deadline| deadline > now) {
                return Ok(None);
            }
            let mut bitmap = 0;
            for source in self.0.received.keys() {
                if source.0 >= self.0.receive_prefix {
                    let offset = source.0 - self.0.receive_prefix;
                    if offset < 64 {
                        bitmap |= 1_u64 << offset;
                    }
                }
            }
            return PacketView::Ack {
                prefix: self.0.receive_prefix,
                bitmap,
            }
            .body_encoded_len()
            .map(Some);
        }
        if self.0.physical_confirmation
            && self.0.pending_transmissions >= self.0.config.send_records
        {
            return Ok(None);
        }
        let Some(source) = self.0.ready_source(now) else {
            return Ok(None);
        };
        let flight = self
            .0
            .sent
            .get(&source)
            .ok_or(RecoveryError::MalformedPacket)?;
        PacketView::Data {
            source,
            payload: &flight.payload,
        }
        .body_encoded_len()
        .map(Some)
    }
}

fn varint_len(value: u64) -> usize {
    ((64 - value.leading_zeros()).max(1) as usize).div_ceil(7)
}
fn write_varint(mut value: u64, output: &mut [u8], position: &mut usize) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        output[*position] = low | if value == 0 { 0 } else { 0x80 };
        *position += 1;
        if value == 0 {
            break;
        }
    }
}
fn read_varint(input: &[u8], position: &mut usize) -> Result<u64, RecoveryError> {
    let mut value = 0;
    for index in 0..10 {
        let byte = *input.get(*position).ok_or(RecoveryError::MalformedPacket)?;
        *position += 1;
        if index == 9 && byte > 1 {
            return Err(RecoveryError::MalformedPacket);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(RecoveryError::MalformedPacket);
            }
            return Ok(value);
        }
    }
    Err(RecoveryError::MalformedPacket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_body_full_width_round_trip_and_rejections() -> Result<(), RecoveryError> {
        for source in [0, 127, 128, 16_384, u64::MAX - 1] {
            let view = PacketView::Data {
                source: SourceId(source),
                payload: &[0, 255, 0],
            };
            let mut output = [0xa5; 32];
            let required = view.body_encoded_len()?;
            assert_eq!(
                view.encode_body_into(&mut output[..required - 1]),
                Err(RecoveryError::OutputTooSmall { required })
            );
            assert_eq!(output, [0xa5; 32]);
            let bytes = view.encode_body_into(&mut output)?;
            assert_eq!(inspect_body(false, &output[..bytes], 3)?, view);
        }
        for (prefix, bitmap) in [(0, 0), (127, 2), (128, 1_u64 << 63), (u64::MAX, 0)] {
            let view = PacketView::Ack { prefix, bitmap };
            let mut output = [0; 20];
            let bytes = view.encode_body_into(&mut output)?;
            assert_eq!(inspect_body(true, &output[..bytes], 3)?, view);
        }
        for bytes in [&[0x80, 0, 1][..], &[0xff; 11][..]] {
            assert!(inspect_body(false, bytes, 16).is_err());
        }
        for bytes in [&[0][..], &[0, 1][..], &[0, 0, 0][..]] {
            assert!(inspect_body(true, bytes, 16).is_err());
        }
        Ok(())
    }
}
