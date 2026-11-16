//! The current L2ARv2 codec for borrowed Compact descriptors.
use super::*;

impl CompactPacketView<'_> {
    /// Validate canonical fields and return their complete current L2ARv2 size.
    ///
    /// This checks wire representability, not a negotiated policy, peer identity,
    /// replay window or physical-send permission.
    pub fn legacy_encoded_len(self) -> Result<usize, RecoveryError> {
        match self {
            Self::Data {
                source,
                serial,
                payload,
            } => {
                if source.0 == u64::MAX || serial == 0 {
                    return Err(RecoveryError::CounterExhausted);
                }
                u32::try_from(payload.len()).map_err(|_| RecoveryError::SourceTooLarge)?;
                COMPACT_DATA_HEADER_BYTES
                    .checked_add(payload.len())
                    .ok_or(RecoveryError::SourceTooLarge)
            }
            Self::Feedback(feedback) => {
                let bitmap_bytes = usize::from(feedback.count).div_ceil(8);
                if feedback.bitmap.len() != bitmap_bytes
                    || feedback.start < feedback.prefix
                    || feedback
                        .start
                        .checked_add(u64::from(feedback.count))
                        .is_none()
                    || feedback.serial == 0
                    || (feedback.count > 0
                        && feedback.start == feedback.prefix
                        && feedback.bitmap[0] & 1 != 0)
                    || (feedback.count % 8 != 0
                        && feedback
                            .bitmap
                            .last()
                            .is_some_and(|last| *last >> (feedback.count % 8) != 0))
                {
                    return Err(RecoveryError::MalformedPacket);
                }
                Ok(COMPACT_FEEDBACK_HEADER_BYTES + bitmap_bytes)
            }
        }
    }

    /// Serialize the current L2ARv2 compatibility format without consuming custody.
    ///
    /// `context` identifies the sender. The caller supplies authenticated policy
    /// admission and the actual physical-send token separately. Invalid fields or
    /// insufficient output leave the complete output buffer unchanged.
    pub fn encode_legacy_into(
        self,
        context: RecoveryContext,
        mode: CompactRecovery,
        output: &mut [u8],
    ) -> Result<usize, RecoveryError> {
        let required = self.legacy_encoded_len()?;
        ensure_output(output, required)?;
        let (header, body) = output[..required].split_at_mut(self.header_bytes());
        self.write_legacy_header(context, mode, header);
        body.copy_from_slice(match self {
            Self::Data { payload, .. } => payload,
            Self::Feedback(feedback) => feedback.bitmap,
        });
        Ok(required)
    }

    // Feedback already builds its bitmap in the caller's output. Borrow the
    // disjoint header instead of allocating or copying another bitmap buffer.
    pub(super) fn encode_legacy_header(
        self,
        context: RecoveryContext,
        mode: CompactRecovery,
        header: &mut [u8],
    ) -> Result<(), RecoveryError> {
        self.legacy_encoded_len()?;
        ensure_output(header, self.header_bytes())?;
        self.write_legacy_header(context, mode, header);
        Ok(())
    }

    fn header_bytes(self) -> usize {
        match self {
            Self::Data { .. } => COMPACT_DATA_HEADER_BYTES,
            Self::Feedback(_) => COMPACT_FEEDBACK_HEADER_BYTES,
        }
    }

    fn write_legacy_header(self, context: RecoveryContext, mode: CompactRecovery, out: &mut [u8]) {
        let kind = match self {
            Self::Data { .. } => 1,
            Self::Feedback(_) => 2,
        };
        write_common(out, context, Profile::Selective, kind);
        out[4] = 2;
        out[5] = mode.code();
        match self {
            Self::Data {
                source,
                serial,
                payload,
            } => {
                out[32..40].copy_from_slice(&source.0.to_be_bytes());
                out[40..48].copy_from_slice(&serial.to_be_bytes());
                out[48..52].copy_from_slice(&(payload.len() as u32).to_be_bytes());
            }
            Self::Feedback(feedback) => {
                out[32..40].copy_from_slice(&feedback.prefix.to_be_bytes());
                out[40..48].copy_from_slice(&feedback.start.to_be_bytes());
                out[48..50].copy_from_slice(&feedback.count.to_be_bytes());
                out[50..52].fill(0);
                out[52..60].copy_from_slice(&feedback.echo.to_be_bytes());
                out[60..68].copy_from_slice(&feedback.receiver_delay_us.to_be_bytes());
                out[68..76].copy_from_slice(&feedback.serial.to_be_bytes());
            }
        }
    }
}

pub(super) fn parse_compact(
    packet: &[u8],
    context: RecoveryContext,
    config: CompactArqConfig,
) -> Result<CompactPacketView<'_>, RecoveryError> {
    if packet.len() < COMMON_HEADER_BYTES || packet.get(..4) != Some(b"L2AR") || packet[4] != 2 {
        return Err(RecoveryError::MalformedPacket);
    }
    if packet[5] != config.recovery.code() {
        return Err(RecoveryError::WrongProfile);
    }
    if packet[7] > 1
        || packet[7] == context.role.code()
        || u128::from_be_bytes(field(packet, 8)?) != context.session
        || u64::from_be_bytes(field(packet, 24)?) != context.epoch
    {
        return Err(RecoveryError::WrongContext);
    }
    match packet[6] {
        1 => {
            let source = u64::from_be_bytes(field(packet, 32)?);
            let serial = u64::from_be_bytes(field(packet, 40)?);
            let length = u32::from_be_bytes(field(packet, 48)?) as usize;
            if source == u64::MAX || serial == 0 {
                return Err(RecoveryError::CounterExhausted);
            }
            if length > config.bounds.max_source_bytes {
                return Err(RecoveryError::SourceTooLarge);
            }
            if packet.len() != COMPACT_DATA_HEADER_BYTES + length {
                return Err(RecoveryError::MalformedPacket);
            }
            Ok(CompactPacketView::Data {
                source: SourceId(source),
                serial,
                payload: &packet[COMPACT_DATA_HEADER_BYTES..],
            })
        }
        2 => {
            let count = u16::from_be_bytes(field(packet, 48)?);
            let required = COMPACT_FEEDBACK_HEADER_BYTES + usize::from(count).div_ceil(8);
            if packet.len() != required
                || required > config.maximum_feedback_bytes
                || field::<2>(packet, 50)? != [0, 0]
            {
                return Err(RecoveryError::MalformedPacket);
            }
            let view = CompactPacketView::Feedback(CompactFeedback {
                prefix: u64::from_be_bytes(field(packet, 32)?),
                start: u64::from_be_bytes(field(packet, 40)?),
                count,
                serial: u64::from_be_bytes(field(packet, 68)?),
                bitmap: &packet[COMPACT_FEEDBACK_HEADER_BYTES..],
                echo: u64::from_be_bytes(field(packet, 52)?),
                receiver_delay_us: u64::from_be_bytes(field(packet, 60)?),
            });
            view.legacy_encoded_len()?;
            Ok(view)
        }
        _ => Err(RecoveryError::MalformedPacket),
    }
}

#[cfg(test)]
mod tests;
