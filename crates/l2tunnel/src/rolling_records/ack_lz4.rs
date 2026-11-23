//! Optional wire-only representation of complete independent Packed ACK sources.
use super::*;
use packed_envelope::{AckLz4Config, AckLz4Table};
use std::sync::Mutex;

// Compact systematic discriminator followed by at most five bytes of u32 source ID.
const MAX_SOURCE_HEADER: usize = 6;

impl<P: RecoveryPolicy> DirectionConfig<P> {
    fn ack_lz4(self) -> Option<AckLz4Config> {
        self.scheduler
            .compresses_packed_acks()
            .then(|| AckLz4Config {
                packed: self.packing.envelope(),
                max_source_bytes: self.scheduler.recovery().max_payload,
                max_ack_bytes: self.receiver.body.independent_short_frame_bytes.min(128),
            })
    }
}

pub(super) struct Encoder {
    table: AckLz4Table,
    scratch: Vec<u8>,
    // The source ledger does not reuse an ID within the endpoint's epoch.
    cached: Option<(rolling::SourceId, Option<usize>)>,
}

pub(super) struct Storage {
    // Read-only budget and observation APIs share the exact immutable representation
    // used by prepare_output. Only the optional encoder cache needs synchronization.
    encoder: Option<Mutex<Encoder>>,
    pub(super) receive_packet: Vec<u8>,
}
impl Storage {
    pub(super) fn planned_bytes<P: RecoveryPolicy>(
        send: DirectionConfig<P>,
        receive: DirectionConfig<P>,
    ) -> Result<usize, Error> {
        let encoder = send
            .ack_lz4()
            .map(|cfg| {
                cfg.encode_scratch_len()
                    .map_err(Error::Envelope)?
                    .checked_add(AckLz4Table::planned_bytes())
                    .ok_or(Error::Arithmetic)
            })
            .transpose()?
            .unwrap_or(0);
        let receive = Self::receive_bytes(receive)?;
        encoder.checked_add(receive).ok_or(Error::Arithmetic)
    }
    fn receive_bytes<P: RecoveryPolicy>(receive: DirectionConfig<P>) -> Result<usize, Error> {
        receive
            .ack_lz4()
            .map(|cfg| {
                cfg.max_source_bytes
                    .checked_add(MAX_SOURCE_HEADER)
                    .ok_or(Error::Arithmetic)
            })
            .transpose()
            .map(Option::unwrap_or_default)
    }
    pub(super) fn new<P: RecoveryPolicy>(
        send: DirectionConfig<P>,
        receive: DirectionConfig<P>,
    ) -> Result<Self, Error> {
        let encoder = send
            .ack_lz4()
            .map(|cfg| {
                Ok::<_, Error>(Mutex::new(Encoder {
                    table: AckLz4Table::new().map_err(Error::Envelope)?,
                    scratch: bytes(cfg.encode_scratch_len().map_err(Error::Envelope)?)?,
                    cached: None,
                }))
            })
            .transpose()?;
        Ok(Self {
            encoder,
            receive_packet: bytes(Self::receive_bytes(receive)?)?,
        })
    }
    pub(super) fn usage(&mut self) -> Result<(usize, usize), Error> {
        let mut capacity = self.receive_packet.capacity();
        let mut allocations = usize::from(capacity != 0);
        if let Some(encoder) = &mut self.encoder {
            let encoder = encoder.get_mut().map_err(|_| Error::StorageInvariant)?;
            capacity = capacity
                .checked_add(encoder.table.capacity_bytes())
                .and_then(|n| n.checked_add(encoder.scratch.capacity()))
                .ok_or(Error::Arithmetic)?;
            allocations +=
                encoder.table.allocations() + usize::from(encoder.scratch.capacity() != 0);
        }
        Ok((capacity, allocations))
    }
}

impl<P: RecoveryPolicy> Endpoint<P> {
    pub(super) fn with_ack_wire_source<T>(
        &self,
        use_wire: impl FnOnce(scheduler::Output<'_>) -> Result<T, rolling::Error>,
    ) -> Result<Option<T>, Error> {
        let Some(encoder) = &self.ack_lz4.encoder else {
            return Ok(None);
        };
        let Some((id, original)) = P::pending_source_bytes(&self.sender) else {
            return Ok(None);
        };
        let mut guard = encoder.lock().map_err(|_| Error::StorageInvariant)?;
        let encoder = &mut *guard;
        let size = match encoder.cached {
            Some((cached_id, n)) if cached_id == id => n,
            _ => {
                let cfg = self.send_config.ack_lz4().ok_or(Error::Configuration)?;
                let n = cfg
                    .try_encode(
                        self.send_scope,
                        receiver::SourceId(u64::from(id.0)),
                        original,
                        &mut encoder.scratch,
                        &mut encoder.table,
                    )
                    .map_err(Error::Envelope)?;
                encoder.cached = Some((id, n));
                n
            }
        };
        let body = size.map_or(original, |n| &encoder.scratch[..n]);
        use_wire(scheduler::Output::Source {
            scope: self.send_rolling_scope,
            id,
            original: body,
        })
        .map(Some)
        .map_err(Error::Rolling)
    }

    /// Normalize the complete compact packet before any rolling receiver or queue mutates.
    /// All retained, previewed and FEC-coded originals consequently share the same identity.
    pub(super) fn restore_ack_packet(
        &self,
        packet: &[u8],
        scratch: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let recovery::View::Source { id, original, .. } =
            self.inspect_data(packet, false).map_err(Error::Rolling)?
        else {
            return Err(Error::Identity);
        };
        if original.first() != Some(&0) {
            return Ok(None);
        }
        let cfg = self.receive_config.ack_lz4().ok_or(Error::Configuration)?;
        let prefix = packet
            .len()
            .checked_sub(original.len())
            .ok_or(Error::Arithmetic)?;
        let (header, dst) = scratch
            .split_at_mut_checked(prefix)
            .ok_or(Error::StorageInvariant)?;
        let n = cfg
            .decode(
                self.receive_scope,
                receiver::SourceId(u64::from(id.0)),
                original,
                dst,
            )
            .map_err(Error::Envelope)?
            .ok_or(Error::Identity)?;
        header.copy_from_slice(&packet[..prefix]);
        Ok(Some(prefix + n))
    }
    pub(super) fn with_plain_output<T>(
        &self,
        id: rolling::SourceId,
        original: &[u8],
        visit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.compact_feedback_overhead.is_none() || original.first() != Some(&0) {
            return visit(original);
        }
        let cfg = self.send_config.ack_lz4().ok_or(Error::Configuration)?;
        if let Some((pending_id, plain)) = P::pending_source_bytes(&self.sender)
            && pending_id == id
            && let Some(encoder) = &self.ack_lz4.encoder
        {
            let matches = {
                let cache = encoder.lock().map_err(|_| Error::StorageInvariant)?;
                cache.cached == Some((id, Some(original.len())))
                    && cache.scratch.get(..original.len()) == Some(original)
            };
            if matches {
                return visit(plain);
            }
        }
        // Public packet inspection can also be called after its immutable sender
        // token has retired. Decode caller bytes independently of the current cache.
        let mut scratch = [0; rolling::MAX_PAYLOAD];
        let n = cfg
            .decode(
                self.send_scope,
                receiver::SourceId(u64::from(id.0)),
                original,
                &mut scratch,
            )
            .map_err(Error::Envelope)?
            .ok_or(Error::Identity)?;
        visit(&scratch[..n])
    }
}
