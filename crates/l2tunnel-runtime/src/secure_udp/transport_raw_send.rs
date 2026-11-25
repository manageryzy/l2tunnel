//! Single final protection after exact raw metadata reservation on the original owner.
use super::*;
use raw_carrier::RawBacking;

impl Driver {
    /// Alternate the existing raw and upper management services when both are due.
    pub(super) fn send_raw_services<R: RawBacking>(
        &mut self,
        socket: &mut carrier::IoOwner<R>,
        now: u64,
    ) -> io::Result<bool> {
        let raw_first = self
            .common
            .as_deref()
            .ok_or_else(|| protocol("raw Common owner absent"))?
            .raw_control_turn;
        for raw in [raw_first, !raw_first] {
            let sent = if raw {
                self.send_raw_carrier_control(socket, now)?
            } else if let Some((bytes, cap)) = self.prepare_raw_management(socket, now)? {
                self.stage_carrier_control(socket, bytes, cap, performance::WireKind::Control)?;
                true
            } else {
                false
            };
            if sent {
                self.common
                    .as_deref_mut()
                    .ok_or_else(|| protocol("raw Common owner absent"))?
                    .raw_control_turn = !raw;
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Existing raw window and liveness obligations use the strong management owner.
    pub(super) fn send_raw_carrier_control<R: RawBacking>(
        &mut self,
        socket: &mut carrier::IoOwner<R>,
        now: u64,
    ) -> io::Result<bool> {
        let raw = socket
            .final_raw_mut()
            .ok_or_else(|| protocol("final raw owner absent"))?;
        let Some((metadata, control)) = raw.prepare_final_control()? else {
            return Ok(false);
        };
        let cost = metadata
            .payload_bytes()
            .checked_add(self.ip)
            .ok_or_else(exhausted)?;
        if cost > self.bucket.allowance() {
            raw.cancel_final()?;
            self.performance.blocked(now, self.bucket.ready_at(cost)?);
            return Ok(false);
        }
        let mut control_body = [0; 9];
        let bytes = control.encode(&mut control_body).map_err(protocol)?;
        let sealed = match self.records.seal_compact_with_carrier(
            record::compact::Kind::CarrierControl,
            self.records.control_scope(),
            meta(self.outer, cover::Phase::Established),
            &control_body[..bytes],
            &metadata.aad(),
            &mut self.buffers.seal,
            &mut self.buffers.wire,
        ) {
            Ok(sealed) => sealed,
            Err(error) => {
                raw.cancel_final()?;
                return Err(record_error(error));
            }
        };
        if sealed.bytes != metadata.payload_bytes() {
            return Err(protocol("raw control final size differs"));
        }
        self.counters.control_number = Some(sealed.number);
        self.counters.control_generation = Some(sealed.generation);
        let deadline = self
            .origin
            .checked_add(duration(self.lease))
            .ok_or_else(exhausted)?;
        self.stage_carrier_control(
            socket,
            sealed.bytes,
            deadline,
            performance::WireKind::Control,
        )?;
        Ok(true)
    }

    /// Retain one actual management body while raw output is busy, without repolling
    /// management, consuming another nonce, or renewing its original deadline.
    pub(super) fn prepare_raw_management<R: RawBacking>(
        &mut self,
        socket: &mut carrier::IoOwner<R>,
        now: u64,
    ) -> io::Result<Option<(usize, Instant)>> {
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("raw Common owner absent"))?;
        let credit = if runtime.raw_control.is_none() {
            self.due_credit_body(now)?
        } else {
            None
        };
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("raw Common owner absent"))?;
        if let Some((body, charge)) = credit {
            // Unreliable session credit uses the same single raw control slot.
            self.buffers.control_wire[..body.len()].copy_from_slice(&body);
            runtime.raw_control = Some(common::PendingRawControl {
                bytes: body.len(),
                wire_bytes: charge,
                deadline: self
                    .origin
                    .checked_add(self.control.expiry())
                    .ok_or_else(exhausted)?,
            });
        }
        if runtime.raw_control.is_none() {
            let Some(emission) = self
                .control
                .poll(
                    duration(now),
                    self.bucket.allowance(),
                    &mut self.buffers.control_wire,
                )
                .map_err(protocol)?
            else {
                return Ok(None);
            };
            runtime.raw_control = Some(common::PendingRawControl {
                bytes: emission.bytes,
                wire_bytes: emission.wire_bytes,
                deadline: self
                    .origin
                    .checked_add(self.control.expiry())
                    .ok_or_else(exhausted)?,
            });
        }
        let pending = runtime
            .raw_control
            .as_ref()
            .ok_or_else(|| protocol("raw management body lost"))?;
        if self
            .origin
            .checked_add(duration(now))
            .ok_or_else(exhausted)?
            >= pending.deadline
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original raw management body cap",
            ));
        }
        if pending.wire_bytes > self.bucket.allowance() {
            return Ok(None);
        }
        let capacity = self
            .records
            .capacity_for(record::compact::Kind::Control, pending.bytes)
            .map_err(record_error)?;
        if capacity.packet_bytes.checked_add(self.ip) != Some(pending.wire_bytes) {
            return Err(protocol("raw management exact charge differs"));
        }
        let raw = socket
            .final_raw_mut()
            .ok_or_else(|| protocol("final raw owner absent"))?;
        let Some(metadata) =
            raw.prepare_final(raw_compact::FinalKind::Control, capacity.packet_bytes)?
        else {
            return Ok(None);
        };
        let sealed = match self.records.seal_compact_with_carrier(
            record::compact::Kind::Control,
            self.records.control_scope(),
            meta(self.outer, cover::Phase::Established),
            &self.buffers.control_wire[..pending.bytes],
            &metadata.aad(),
            &mut self.buffers.seal,
            &mut self.buffers.wire,
        ) {
            Ok(sealed) => sealed,
            Err(error) => {
                raw.cancel_final()?;
                return Err(record_error(error));
            }
        };
        if sealed.bytes != capacity.packet_bytes {
            return Err(protocol("raw management size differs"));
        }
        self.counters.control_number = Some(sealed.number);
        self.counters.control_generation = Some(sealed.generation);
        let deadline = pending.deadline;
        runtime.raw_control = None;
        Ok(Some((sealed.bytes, deadline)))
    }
}
