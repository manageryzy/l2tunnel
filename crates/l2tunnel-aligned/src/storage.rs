//! Exact fallible heap inventory for the actual duplex Aligned/Packed owner.
use super::{Config, Error as EndpointError, packed, receiver, sender};
use l2tunnel_codec::{aligned_storage as codec, packed_sender};
use l2tunnel_reliable::storage as reliable;
use std::{alloc::Layout, fmt};

/// Explicit complete endpoint heap allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum actual retained managed heap layout.
    pub capacity_bytes: usize,
}
/// Actual retained backing, including all idle nested buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original explicit construction limit.
    pub limit_bytes: usize,
    /// Complete actual managed heap capacity.
    pub capacity_bytes: usize,
    /// Successful nonzero explicit reservations.
    pub allocations: usize,
}
/// Fallible construction failures; no allocating fallback is selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing complete policy/context validation.
    Endpoint(EndpointError),
    /// Actual codec construction failure.
    Codec(codec::Error),
    /// Actual Reliable/ARQ/FEC construction failure.
    Reliable(reliable::Error),
    /// Checked layout cannot be represented.
    Layout,
    /// Complete capacity exceeds the explicit limit.
    Limit {
        /// Complete requested layout.
        required: usize,
        /// Supplied allowance.
        limit: usize,
    },
    /// Fallible endpoint reservation failed.
    Allocation,
    /// Actual capacities disagree with the plan.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aligned endpoint storage: {self:?}")
    }
}
impl std::error::Error for Error {}
/// Validated complete independent-direction inventory, without allocating owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    send: Config,
    receive: Config,
    send_packed: Option<packed::Config>,
    receive_packed: Option<packed::Config>,
    bytes: usize,
    pub(super) wrapper: usize,
    pub(super) sender: usize,
    pub(super) receiver: codec::ReceiverPlan,
    reliable: reliable::Plan,
}
impl Plan {
    /// Validate ordinary complete send then receive policy and all actual layouts.
    pub fn for_duplex(send: Config, receive: Config) -> Result<Self, Error> {
        send.validate().map_err(Error::Endpoint)?;
        receive.validate().map_err(Error::Endpoint)?;
        Self::build(send, receive, None, None)
    }
    /// Validate independent Packed policies without constructing unused halves.
    pub fn for_packed_duplex(send: packed::Config, receive: packed::Config) -> Result<Self, Error> {
        send.validate().map_err(Error::Endpoint)?;
        receive.validate().map_err(Error::Endpoint)?;
        Self::build(send.base, receive.base, Some(send), Some(receive))
    }
    fn build(
        send: Config,
        receive: Config,
        send_packed: Option<packed::Config>,
        receive_packed: Option<packed::Config>,
    ) -> Result<Self, Error> {
        let (sender, cell) = if let Some(packed) = send_packed {
            (
                (if send.native_policy == super::NativePolicy::IpHeaders {
                    codec::PackedSenderPlan::for_ip_config
                } else {
                    codec::PackedSenderPlan::for_config
                })(packed.sender())
                .map_err(Error::Codec)?
                .capacity_bytes(),
                array_bytes::<packed_sender::Sender>(1)?,
            )
        } else {
            (
                (if send.native_policy == super::NativePolicy::IpHeaders {
                    codec::SenderPlan::for_ip_config
                } else {
                    codec::SenderPlan::for_config
                })(super::sender_config(send))
                .map_err(Error::Codec)?
                .capacity_bytes(),
                array_bytes::<sender::Sender>(1)?,
            )
        };
        let receiver = (if receive.native_policy == super::NativePolicy::IpHeaders {
            codec::ReceiverPlan::for_ip_limits
        } else {
            codec::ReceiverPlan::for_limits
        })(receive.receiver)
        .map_err(Error::Codec)?;
        let reliable =
            reliable::Plan::for_duplex(send.recovery, receive.recovery).map_err(Error::Reliable)?;
        let symbols = receive_packed.map_or(Ok(0), |p| {
            multiply(usize::from(p.max_units), receive.receiver.body.symbol_bytes)
        })?;
        let wrapper = sum(&[
            cell,
            array_bytes::<u8>(send.recovery.arq.max_source_bytes)?,
            array_bytes::<u8>(receive.recovery.arq.max_source_bytes)?,
            array_bytes::<u8>(symbols)?,
        ])?;
        let bytes = sum(&[
            wrapper,
            sender,
            receiver.capacity_bytes(),
            reliable.capacity_bytes(),
        ])?;
        Ok(Self {
            send,
            receive,
            send_packed,
            receive_packed,
            bytes,
            wrapper,
            sender,
            receiver,
            reliable,
        })
    }
    /// Complete original send direction policy.
    pub fn send_config(&self) -> Config {
        self.send
    }
    /// Complete original receive direction policy.
    pub fn receive_config(&self) -> Config {
        self.receive
    }
    /// Explicit Packed send policy, absent for ordinary Aligned.
    pub fn send_packed(&self) -> Option<packed::Config> {
        self.send_packed
    }
    /// Explicit Packed receive policy, absent for ordinary Aligned.
    pub fn receive_packed(&self) -> Option<packed::Config> {
        self.receive_packed
    }
    /// Complete heap layouts, including nested Reliable exactly once.
    pub fn capacity_bytes(&self) -> usize {
        self.bytes
    }
    /// Actual nested ARQ/FEC/Reliable subset, not another charge.
    pub fn reliable_plan(&self) -> reliable::Plan {
        self.reliable
    }
}
fn array_bytes<T>(n: usize) -> Result<usize, Error> {
    Layout::array::<T>(n)
        .map(|l| l.size())
        .map_err(|_| Error::Layout)
}
fn multiply(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b)
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(Error::Layout)
}
pub(super) fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts
        .iter()
        .try_fold(0usize, |n, p| n.checked_add(*p).ok_or(Error::Layout))
}
pub(super) struct Allocation {
    limit: usize,
    used: usize,
    count: usize,
    #[cfg(test)]
    pub(super) fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
    #[cfg(test)]
    pub(super) trace: Option<std::rc::Rc<std::cell::RefCell<Vec<ConstructionEvent>>>>,
}
impl Allocation {
    pub(super) fn new(plan: &Plan, limits: Limits) -> Result<Self, Error> {
        if plan.bytes > limits.capacity_bytes {
            return Err(Error::Limit {
                required: plan.bytes,
                limit: limits.capacity_bytes,
            });
        }
        Ok(Self {
            limit: plan.wrapper,
            used: 0,
            count: 0,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            attempts: 0,
            #[cfg(test)]
            trace: None,
        })
    }
    pub(super) fn vec<T>(&mut self, n: usize) -> Result<Vec<T>, Error> {
        let used = sum(&[self.used, array_bytes::<T>(n)?])?;
        if used > self.limit {
            return Err(Error::Invariant);
        }
        if n == 0 {
            return Ok(Vec::new());
        }
        #[cfg(test)]
        {
            self.attempts += 1;
            if self.fail_at == Some(self.attempts) {
                return Err(Error::Allocation);
            }
        }
        let mut value = Vec::new();
        value.try_reserve_exact(n).map_err(|_| Error::Allocation)?;
        if value.capacity() != n {
            return Err(Error::Invariant);
        }
        self.used = used;
        self.count += 1;
        Ok(value)
    }
    pub(super) fn bytes(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        let mut v = self.vec(n)?;
        v.resize(n, 0);
        Ok(v)
    }
    pub(super) fn actual(&self) -> (usize, usize) {
        (self.used, self.count)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConstructionEvent {
    BeforeDrop { capacity_bytes: Option<usize> },
    AfterDrop,
    Transferred { capacity_bytes: usize },
}

// Temporary assembly guard. The same actual drop statements run in all builds;
// only the local observation around them exists in tests. Nothing is retained
// in a published Endpoint or invoked in a packet hot path.
#[derive(Default)]
pub(super) struct Construction {
    pub(super) sender: Option<packed::SenderOwner>,
    pub(super) recovery: Option<l2tunnel_reliable::Reliable>,
    pub(super) receiver: Option<receiver::Receiver>,
    pub(super) packed_symbols: Vec<u8>,
    pub(super) send_buffer: Vec<u8>,
    pub(super) receive_buffer: Vec<u8>,
    #[cfg(test)]
    pub(super) trace: Option<std::rc::Rc<std::cell::RefCell<Vec<ConstructionEvent>>>>,
}
impl Construction {
    #[cfg(test)]
    fn known_bytes(&self) -> Option<usize> {
        let sender = match self.sender.as_ref() {
            None => 0,
            Some(packed::SenderOwner::Aligned(cell)) => {
                cell.first()?.storage_usage()?.capacity_bytes.checked_add(
                    cell.capacity()
                        .checked_mul(std::mem::size_of::<sender::Sender>())?,
                )?
            }
            Some(packed::SenderOwner::Packed(cell)) => {
                cell.first()?.storage_usage()?.capacity_bytes.checked_add(
                    cell.capacity()
                        .checked_mul(std::mem::size_of::<packed_sender::Sender>())?,
                )?
            }
        };
        [
            sender,
            self.recovery
                .as_ref()
                .map_or(Some(0), |r| r.storage_usage().map(|u| u.capacity_bytes))?,
            self.receiver
                .as_ref()
                .map_or(Some(0), |r| r.storage_usage().map(|u| u.capacity_bytes))?,
            self.packed_symbols.capacity(),
            self.send_buffer.capacity(),
            self.receive_buffer.capacity(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
    }
    pub(super) fn transferred(&self, capacity: usize) {
        #[cfg(test)]
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push(ConstructionEvent::Transferred {
                capacity_bytes: capacity,
            });
        }
        #[cfg(not(test))]
        let _ = capacity;
    }
}
impl Drop for Construction {
    fn drop(&mut self) {
        let occupied = self.sender.is_some()
            || self.recovery.is_some()
            || self.receiver.is_some()
            || self.packed_symbols.capacity() != 0
            || self.send_buffer.capacity() != 0
            || self.receive_buffer.capacity() != 0;
        if !occupied {
            return;
        }
        #[cfg(test)]
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push(ConstructionEvent::BeforeDrop {
                capacity_bytes: self.known_bytes(),
            });
        }
        drop(self.sender.take());
        drop(self.recovery.take());
        drop(self.receiver.take());
        drop(std::mem::take(&mut self.packed_symbols));
        drop(std::mem::take(&mut self.send_buffer));
        drop(std::mem::take(&mut self.receive_buffer));
        #[cfg(test)]
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push(ConstructionEvent::AfterDrop);
        }
    }
}
