//! Explicit context-free final union over the existing Reliable owners.
use super::*;
use l2tunnel_recovery::{CompactPacketKind, CompactPacketView, inspect_body, inspect_compact_body};

impl ReliableConfig {
    /// Selected data union ceiling, excluding final protection and carrier bytes.
    pub fn compact_wire_maximum_data_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        let source = 10usize
            .checked_add(self.arq.max_source_bytes)
            .ok_or(Error::InvalidConfig)?;
        let direct = 1 + source;
        if self.repair_symbols == 0 {
            return Ok(direct);
        }
        // Kind, generation, symbol, source count, vector width, explicit row and vector.
        Ok(direct.max(1 + 10 + 5 + 2 + 3 + self.fec.block.max_sources + source + 2))
    }
    /// Selected strong-feedback union ceiling, with both complete u64 values.
    pub fn compact_wire_maximum_feedback_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        Ok(1 + l2tunnel_recovery::ARQ_BODY_FEEDBACK_MAX_HEADER_BYTES)
    }
    /// Largest selected packet body across data and strong feedback.
    pub fn compact_wire_maximum_packet_bytes(self) -> Result<usize, Error> {
        Ok(self
            .compact_wire_maximum_data_bytes()?
            .max(self.compact_wire_maximum_feedback_bytes()?))
    }
}
impl CompactReliableConfig {
    /// Selected data union ceiling retaining full source and transmission serials.
    pub fn compact_wire_maximum_data_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        Ok(1 + l2tunnel_recovery::COMPACT_BODY_DATA_MAX_HEADER_BYTES
            + self.arq().bounds().max_source_bytes)
    }
    /// Selected feedback ceiling for this data direction, emitted by its peer.
    pub fn compact_wire_maximum_feedback_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        Ok(
            1 + l2tunnel_recovery::COMPACT_BODY_FEEDBACK_MAX_HEADER_BYTES
                + self.arq().maximum_feedback_bytes()
                - l2tunnel_recovery::COMPACT_FEEDBACK_HEADER_BYTES,
        )
    }
    /// Largest selected source or feedback body for one symmetric policy.
    pub fn compact_wire_maximum_packet_bytes(self) -> Result<usize, Error> {
        Ok(self
            .compact_wire_maximum_data_bytes()?
            .max(self.compact_wire_maximum_feedback_bytes()?))
    }
}

impl Reliable {
    /// Select the context-free union before traffic. Complete policy and existing
    /// reserved backing stay intact; data uses the configured external overhead,
    /// while reliable-retiring feedback uses the explicit strong overhead.
    pub fn enable_compact_wire(&mut self, feedback_overhead: usize) -> Result<(), Error> {
        self.enable_compact_wire_with_overheads(self.outer_overhead(), feedback_overhead)
    }

    /// Select exact external data and strong-feedback charges without changing
    /// the authenticated recovery policy or allocating another recovery owner.
    pub fn enable_compact_wire_with_overheads(
        &mut self,
        data_overhead: usize,
        feedback_overhead: usize,
    ) -> Result<(), Error> {
        self.validate_compact_wire_selection(data_overhead, feedback_overhead)?;
        let (data, feedback, peer_data, peer_feedback) = match self.policies {
            compact::Policies::Legacy { send, receive } => (
                send.compact_wire_maximum_data_bytes()?,
                receive.compact_wire_maximum_feedback_bytes()?,
                receive.compact_wire_maximum_data_bytes()?,
                send.compact_wire_maximum_feedback_bytes()?,
            ),
            compact::Policies::Compact { send, receive } => (
                send.compact_wire_maximum_data_bytes()?,
                receive.compact_wire_maximum_feedback_bytes()?,
                receive.compact_wire_maximum_data_bytes()?,
                send.compact_wire_maximum_feedback_bytes()?,
            ),
        };
        self.maximum_packet = data.max(feedback);
        self.receive_maximum_packet = peer_data.max(peer_feedback);
        self.compact_wire = Some(CompactOverheads {
            data: data_overhead,
            feedback: feedback_overhead,
        });
        Ok(())
    }

    /// Validate selection without changing any owner, charge or packet ceiling.
    pub fn validate_compact_wire_selection(
        &self,
        data_overhead: usize,
        feedback_overhead: usize,
    ) -> Result<(), Error> {
        self.running()?;
        if self.compact_wire.is_some()
            || self.now != Duration::ZERO
            || self.arq.next_source_id()?.0 != 0
            || self.statistics != Statistics::default()
            || self.arq.statistics() != ArqStatistics::default()
            || !self.drained()
        {
            return Err(Error::InvalidConfig);
        }
        let (data, feedback, _peer_data, _peer_feedback) = match self.policies {
            compact::Policies::Legacy { send, receive } => (
                send.compact_wire_maximum_data_bytes()?,
                receive.compact_wire_maximum_feedback_bytes()?,
                receive.compact_wire_maximum_data_bytes()?,
                send.compact_wire_maximum_feedback_bytes()?,
            ),
            compact::Policies::Compact { send, receive } => (
                send.compact_wire_maximum_data_bytes()?,
                receive.compact_wire_maximum_feedback_bytes()?,
                receive.compact_wire_maximum_data_bytes()?,
                send.compact_wire_maximum_feedback_bytes()?,
            ),
        };
        if data.checked_add(data_overhead).is_none_or(|n| n > 65_535)
            || feedback
                .checked_add(feedback_overhead)
                .is_none_or(|n| n > 65_535)
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }

    pub(super) fn selected_inspect<'a>(
        &self,
        packet: &'a [u8],
        outgoing: bool,
    ) -> Result<StructuralRecord<'a>, Error> {
        let maximum = if outgoing {
            self.maximum_packet
        } else {
            self.receive_maximum_packet
        };
        if packet.len() > maximum {
            return Err(Error::Malformed);
        }
        let (&kind, body) = packet.split_first().ok_or(Error::Malformed)?;
        let sender = if outgoing {
            self.context
        } else {
            opposite_context(self.context)
        };
        let mut record = StructuralRecord {
            sender,
            kind: RecordKind::Feedback,
            source: None,
            fec: None,
        };
        match self.policies {
            compact::Policies::Compact { send, receive } => {
                let policy = if (kind == 1) == outgoing {
                    send
                } else {
                    receive
                };
                let view = inspect_compact_body(
                    match kind {
                        1 => CompactPacketKind::Data,
                        2 => CompactPacketKind::Feedback,
                        _ => return Err(Error::Malformed),
                    },
                    body,
                    policy.arq(),
                )?;
                if let CompactPacketView::Data {
                    source, payload, ..
                } = view
                {
                    record.kind = RecordKind::Source;
                    record.source = Some((source, payload));
                }
            }
            compact::Policies::Legacy { send, receive } => {
                let policy = if outgoing { send } else { receive };
                match kind {
                    1 => match inspect_body(false, body, policy.arq.max_source_bytes)? {
                        PacketView::Data { source, payload } => {
                            record.kind = RecordKind::Source;
                            record.source = Some((source, payload));
                        }
                        _ => return Err(Error::Malformed),
                    },
                    2 => {
                        inspect_body(true, body, policy.arq.max_source_bytes)?;
                    }
                    3 | 4 if policy.repair_symbols != 0 => {
                        let view = inspect_symbol(kind, body, policy.fec.block)?;
                        record.kind = if kind == 3 {
                            RecordKind::Systematic
                        } else {
                            RecordKind::Repair
                        };
                        if kind == 3 {
                            let bytes = original_source(view)?;
                            if let PacketView::Data { source, payload } =
                                inspect_body(false, bytes, policy.arq.max_source_bytes)?
                            {
                                record.source = Some((source, payload));
                            }
                        }
                        record.fec = Some(view);
                    }
                    _ => return Err(Error::Malformed),
                }
            }
        }
        Ok(record)
    }

    pub(super) fn receive_selected(
        &mut self,
        packet: &[u8],
        received: Duration,
        observed: Duration,
    ) -> Result<(), Error> {
        self.check_time(observed)?;
        if received > observed {
            return Err(Error::NonMonotonicTime);
        }
        let view = self
            .selected_inspect(packet, false)
            .or_else(|error| self.fail(error))?;
        let (&kind, body) = packet.split_first().ok_or(Error::Malformed)?;
        if let compact::Policies::Compact { send, receive } = self.policies {
            let arq = inspect_compact_body(
                if kind == 1 {
                    CompactPacketKind::Data
                } else {
                    CompactPacketKind::Feedback
                },
                body,
                if kind == 1 { receive.arq() } else { send.arq() },
            )?;
            return self.receive_compact_view_at(arq, received, observed);
        }
        match view.kind {
            RecordKind::Source => {
                self.ensure_restored(1, body.len())?;
                self.advance(observed)?;
                self.enqueue(body, false)?;
                self.pump()
            }
            RecordKind::Feedback => {
                self.arq
                    .receive_body(body, true, observed)
                    .or_else(|error| self.fail(error.into()))?;
                self.advance(observed)
            }
            RecordKind::Systematic | RecordKind::Repair => {
                self.receive_fec_view(view.fec.ok_or(Error::Malformed)?, observed)
            }
        }
    }

    pub(super) fn selected_overhead(&self, kind: RecordKind) -> usize {
        if kind == RecordKind::Feedback {
            self.compact_wire
                .map_or_else(|| self.outer_overhead(), |overheads| overheads.feedback)
        } else {
            self.outer_overhead()
        }
    }
}

pub(super) fn original_source(view: fec::SymbolView<'_>) -> Result<&[u8], Error> {
    let prefix: [u8; 2] = view
        .payload
        .get(..2)
        .ok_or(Error::Malformed)?
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let length = usize::from(u16::from_be_bytes(prefix));
    view.payload.get(2..2 + length).ok_or(Error::Malformed)
}
fn inspect_symbol(
    kind: u8,
    bytes: &[u8],
    config: fec::BlockConfig,
) -> Result<fec::SymbolView<'_>, Error> {
    let mut position = 0;
    let generation = fec::GenerationId(read(bytes, &mut position)?);
    let symbol =
        fec::SymbolId(u32::try_from(read(bytes, &mut position)?).map_err(|_| Error::Malformed)?);
    let count = usize::try_from(read(bytes, &mut position)?).map_err(|_| Error::Malformed)?;
    let width = usize::try_from(read(bytes, &mut position)?).map_err(|_| Error::Malformed)?;
    let end = position.checked_add(count).ok_or(Error::Malformed)?;
    let coefficients = bytes.get(position..end).ok_or(Error::Malformed)?;
    let payload = bytes.get(end..).ok_or(Error::Malformed)?;
    let view = fec::SymbolView {
        generation,
        symbol,
        kind: if kind == 3 {
            fec::SymbolKind::Systematic
        } else {
            fec::SymbolKind::Repair
        },
        source_count: count,
        coded_bytes: width,
        coefficients,
        payload,
    };
    view.validate(config)?;
    Ok(view)
}
pub(super) fn encode_symbol(
    view: fec::SymbolView<'_>,
    output: &mut [u8],
) -> Result<usize, fec::Error> {
    let values = [
        view.generation.0,
        u64::from(view.symbol.0),
        view.source_count as u64,
        view.coded_bytes as u64,
    ];
    let required = 1
        + values.into_iter().map(varint_len).sum::<usize>()
        + view.coefficients.len()
        + view.payload.len();
    if output.len() < required {
        return Err(fec::Error::OutputTooSmall { required });
    }
    output[0] = if view.kind == fec::SymbolKind::Systematic {
        3
    } else {
        4
    };
    let mut position = 1;
    for value in values {
        write(value, output, &mut position);
    }
    let end = position + view.coefficients.len();
    output[position..end].copy_from_slice(view.coefficients);
    output[end..required].copy_from_slice(view.payload);
    Ok(required)
}
fn varint_len(value: u64) -> usize {
    ((64 - value.leading_zeros()).max(1) as usize).div_ceil(7)
}
fn write(mut value: u64, out: &mut [u8], position: &mut usize) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        out[*position] = low | if value == 0 { 0 } else { 0x80 };
        *position += 1;
        if value == 0 {
            break;
        }
    }
}
fn read(input: &[u8], position: &mut usize) -> Result<u64, Error> {
    let mut value = 0;
    for index in 0..10 {
        let byte = *input.get(*position).ok_or(Error::Malformed)?;
        *position += 1;
        if index == 9 && byte > 1 {
            return Err(Error::Malformed);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(Error::Malformed);
            }
            return Ok(value);
        }
    }
    Err(Error::Malformed)
}

impl Reliable {
    pub(super) fn emit_compact_wire(
        &mut self,
        now: Duration,
        feedback: bool,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        let kind = if feedback {
            RecordKind::Feedback
        } else {
            RecordKind::Source
        };
        let overhead = self.selected_overhead(kind);
        let output_capacity = output.len();
        let before = self.arq.statistics().retransmissions;
        let mut admitted = None;
        let emitted = self
            .arq
            .compact_mut()?
            .poll_admitted_body_with(
                now,
                if feedback {
                    l2tunnel_recovery::CompactPacketKind::Feedback
                } else {
                    l2tunnel_recovery::CompactPacketKind::Data
                },
                &mut self.scratch,
                |body| {
                    let bytes = 1 + body;
                    let charge = bytes.checked_add(overhead).ok_or(Error::Exhausted)?;
                    if budget.packets == 0 || budget.wire_bytes < charge {
                        return Ok(false);
                    }
                    if output_capacity < bytes {
                        return Err(Error::OutputTooSmall { required: bytes });
                    }
                    admitted = Some((body, bytes, charge));
                    Ok(true)
                },
                |view| {
                    view.encode_compact_into(&mut output[1..])
                        .map(Some)
                        .map_err(Error::Arq)
                },
            )
            .map_err(|error| match error {
                l2tunnel_recovery::CompactPollError::Recovery(error) => Error::Arq(error),
                l2tunnel_recovery::CompactPollError::Encode(error) => error,
            })?;
        let Some(emitted) = emitted else {
            return Ok(None);
        };
        let Some((body, bytes, charge)) = admitted else {
            return self.fail(Error::Malformed);
        };
        if emitted != body {
            return self.fail(Error::Malformed);
        }
        output[0] = if feedback { 2 } else { 1 };
        let emission = if feedback {
            Emission::Feedback
        } else if self.arq.statistics().retransmissions > before {
            Emission::Retry
        } else {
            Emission::Source
        };
        self.advance(now)?;
        self.charge_exact(charge, emission, budget)?;
        Ok(Some(bytes))
    }
}
