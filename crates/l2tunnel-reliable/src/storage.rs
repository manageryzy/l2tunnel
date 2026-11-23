//! Complete actual nested backing inventory for one Reliable owner.
use crate::{ReliableConfig, backing};
use std::{alloc::Layout, fmt};
/// Heap-only construction allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Complete nested and wrapper heap budget.
    pub capacity_bytes: usize,
}
/// Actual retained requested backing, including idle slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original allowance.
    pub limit_bytes: usize,
    /// Nested and wrapper capacity counted once.
    pub capacity_bytes: usize,
    /// Successful explicit nonzero reservations.
    pub allocations: usize,
}
/// Construction errors distinct from existing protocol errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing scalar configuration or context rejection.
    Reliable(crate::Error),
    /// Actual nested recovery construction failure.
    Recovery(l2tunnel_recovery::storage::Error),
    /// Actual nested FEC failure.
    Fec(l2tunnel_fec::storage::Error),
    /// Checked layout or total overflow.
    Layout,
    /// Full plan exceeds the supplied budget.
    Limit {
        /// Required capacity.
        required: usize,
        /// Supplied budget.
        limit: usize,
    },
    /// Fallible wrapper reservation failed.
    Allocation,
    /// Observed backing differs from the inventory.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reliable storage error: {self:?}")
    }
}
impl std::error::Error for Error {}
/// Allocation-free exact nested construction plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    send: ReliableConfig,
    receive: ReliableConfig,
    bytes: usize,
    pub(crate) diagnostics: bool,
    pub(crate) arq: l2tunnel_recovery::storage::DuplexPlan,
    pub(crate) encoder: Option<l2tunnel_fec::storage::EncoderPlan>,
    pub(crate) decoder: Option<l2tunnel_fec::storage::DecoderPlan>,
}
impl Plan {
    /// Validate both complete directions before computing nested and wrapper layouts.
    pub fn for_duplex(send: ReliableConfig, receive: ReliableConfig) -> Result<Self, Error> {
        let maximum = send.maximum_packet().map_err(Error::Reliable)?;
        receive.validate().map_err(Error::Reliable)?;
        let arq = l2tunnel_recovery::storage::DuplexPlan::for_arq(send.arq, receive.arq)
            .map_err(Error::Recovery)?;
        let encoder = (send.repair_symbols != 0)
            .then(|| l2tunnel_fec::storage::EncoderPlan::for_encoder(send.fec.block))
            .transpose()
            .map_err(Error::Fec)?;
        let decoder = (receive.repair_symbols != 0)
            .then(|| l2tunnel_fec::storage::DecoderPlan::for_decoder(receive.fec))
            .transpose()
            .map_err(Error::Fec)?;
        let n = encoder.map_or(0, |_| send.fec.block.max_sources);
        let o = add(n, send.repair_symbols)?;
        let r = receive.max_restored_packets;
        let g = decoder.map_or(0, |_| receive.fec.max_generations);
        let bs = add(
            l2tunnel_recovery::DATA_HEADER_BYTES,
            send.arq.max_source_bytes,
        )?;
        let br = add(
            l2tunnel_recovery::DATA_HEADER_BYTES,
            receive.arq.max_source_bytes,
        )?;
        let scratch = bs
            .max(l2tunnel_recovery::ACK_PACKET_BYTES)
            .max(if decoder.is_some() {
                add(receive.fec.block.max_source_bytes, 2)?
            } else {
                0
            });
        let mut bytes = add(
            arq.capacity_bytes(),
            add(
                encoder.map_or(0, |p| p.capacity_bytes()),
                decoder.map_or(0, |p| p.capacity_bytes()),
            )?,
        )?;
        for charge in [
            array_bytes::<Vec<u8>>(n)?,
            mul(n, bs)?,
            array_bytes::<crate::Outgoing>(o)?,
            mul(o, maximum)?,
            array_bytes::<backing::RestoredSlot>(r)?,
            mul(r, br)?,
            array_bytes::<backing::DeadlineSlot>(g)?,
            array_bytes::<l2tunnel_fec::ExpiredGeneration>(g)?,
            scratch,
        ] {
            bytes = add(bytes, charge)?;
        }
        Ok(Self {
            send,
            receive,
            bytes,
            arq,
            encoder,
            decoder,
            diagnostics: false,
        })
    }
    /// Reserve the optional scalar summary and one cell per existing restored slot.
    /// Cells track actual refused sources; no new protocol queue is created.
    /// This changes no protocol allowance; the existing complete byte limit still applies.
    pub fn with_output_diagnostics(mut self) -> Result<Self, Error> {
        if !self.diagnostics {
            self.bytes = add(self.bytes, array_bytes::<crate::diagnostics::Snapshot>(1)?)?;
            self.bytes = add(
                self.bytes,
                array_bytes::<crate::diagnostics::restored::Cell>(
                    self.receive.max_restored_packets,
                )?,
            )?;
            self.diagnostics = true;
        }
        Ok(self)
    }
    /// Complete original send policy.
    pub fn send_config(&self) -> ReliableConfig {
        self.send
    }
    /// Complete original receive policy.
    pub fn receive_config(&self) -> ReliableConfig {
        self.receive
    }
    /// Full nested heap capacity, excluding inline Reliable.
    pub fn capacity_bytes(&self) -> usize {
        self.bytes
    }
}

/// Exact actual backing for the explicitly selected Compact R0 body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactPlan {
    send: crate::CompactReliableConfig,
    receive: crate::CompactReliableConfig,
    bytes: usize,
    pub(crate) arq: l2tunnel_recovery::storage::CompactPlan,
    pub(crate) scratch_bytes: usize,
    pub(crate) send_maximum: usize,
    pub(crate) receive_maximum: usize,
}
impl CompactPlan {
    /// Validate complete independent policies and reserve no unused FEC owner.
    pub fn for_duplex(
        send: crate::CompactReliableConfig,
        receive: crate::CompactReliableConfig,
    ) -> Result<Self, Error> {
        send.validate().map_err(Error::Reliable)?;
        receive.validate().map_err(Error::Reliable)?;
        let arq = l2tunnel_recovery::storage::CompactPlan::for_compact(send.arq(), receive.arq())
            .map_err(Error::Recovery)?;
        let source = add(
            l2tunnel_recovery::COMPACT_DATA_HEADER_BYTES,
            send.arq().bounds().max_source_bytes,
        )?;
        let peer_source = add(
            l2tunnel_recovery::COMPACT_DATA_HEADER_BYTES,
            receive.arq().bounds().max_source_bytes,
        )?;
        let scratch_bytes = source.max(receive.arq().maximum_feedback_bytes());
        let send_maximum =
            crate::compact::packet_maximum(scratch_bytes, send.outer_overhead_bytes())
                .map_err(Error::Reliable)?;
        let receive_maximum = crate::compact::packet_maximum(
            peer_source.max(send.arq().maximum_feedback_bytes()),
            receive.outer_overhead_bytes(),
        )
        .map_err(Error::Reliable)?;
        Ok(Self {
            send,
            receive,
            bytes: add(arq.capacity_bytes(), scratch_bytes)?,
            arq,
            scratch_bytes,
            send_maximum,
            receive_maximum,
        })
    }
    /// Exact sending requested policy.
    pub const fn send_config(&self) -> crate::CompactReliableConfig {
        self.send
    }
    /// Exact receiving requested policy.
    pub const fn receive_config(&self) -> crate::CompactReliableConfig {
        self.receive
    }
    /// Complete requested nested and scratch heap, excluding inline Reliable.
    pub const fn capacity_bytes(&self) -> usize {
        self.bytes
    }
    /// Exact complete local output maximum, excluding configured outer overhead.
    pub const fn send_max_packet_bytes(&self) -> usize {
        self.send_maximum
    }
    /// Exact complete peer output maximum, excluding configured outer overhead.
    pub const fn receive_max_packet_bytes(&self) -> usize {
        self.receive_maximum
    }
}

pub(crate) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Layout)
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Layout)
}
fn array_bytes<T>(n: usize) -> Result<usize, Error> {
    Layout::array::<T>(n)
        .map(|l| l.size())
        .map_err(|_| Error::Layout)
}
pub(crate) struct Allocation {
    limit: usize,
    used: usize,
    count: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
}
impl Allocation {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: 0,
            count: 0,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            attempts: 0,
        }
    }
    pub(crate) fn vec<T>(&mut self, n: usize) -> Result<Vec<T>, Error> {
        let bytes = array_bytes::<T>(n)?;
        let total = add(self.used, bytes)?;
        if total > self.limit {
            return Err(Error::Limit {
                required: total,
                limit: self.limit,
            });
        }
        #[cfg(test)]
        {
            self.attempts += 1;
            if self.fail_at == Some(self.attempts) {
                return Err(Error::Allocation);
            }
        }
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| Error::Allocation)?;
        if v.capacity() != n {
            return Err(Error::Invariant);
        }
        self.used = total;
        self.count += usize::from(bytes != 0);
        Ok(v)
    }
    pub(crate) fn usage(&self) -> Usage {
        Usage {
            limit_bytes: self.limit,
            capacity_bytes: self.used,
            allocations: self.count,
        }
    }
    #[cfg(test)]
    pub(crate) fn failing(limit: usize, fail_at: usize) -> Self {
        Self {
            fail_at: Some(fail_at),
            ..Self::new(limit)
        }
    }
}
