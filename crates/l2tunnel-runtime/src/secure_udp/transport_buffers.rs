//! Fallible fixed byte workspaces. No packet, clock or protocol state is owned here.

use std::{alloc::Layout, io};

/// Actual reusable driver workspaces; callers must preserve the admitted capacities.
pub(super) struct Buffers {
    pub(super) wire: Vec<u8>,
    pub(super) seal: Vec<u8>,
    pub(super) open: Vec<u8>,
    pub(super) plain: Vec<u8>,
    pub(super) control_wire: Vec<u8>,
    pub(super) control_input: Vec<u8>,
    pub(super) frame: Vec<u8>,
}
impl Buffers {
    pub(super) fn new(
        wire: usize,
        secure_packet: usize,
        plain: usize,
        control_packet: usize,
        control_message: usize,
        frame: usize,
    ) -> io::Result<Self> {
        Self::build(
            [
                wire,
                secure_packet,
                secure_packet,
                plain,
                control_packet,
                control_message,
                frame,
            ],
            &mut Allocation::new(),
        )
    }
    fn build(sizes: [usize; 7], allocation: &mut Allocation) -> io::Result<Self> {
        layout_bytes(&sizes)?;
        // Each local owns its allocation immediately; any later failure drops all locals.
        let wire = allocation.bytes(sizes[0], true)?;
        let seal = allocation.bytes(sizes[1], true)?;
        let open = allocation.bytes(sizes[2], true)?;
        let plain = allocation.bytes(sizes[3], true)?;
        let control_wire = allocation.bytes(sizes[4], true)?;
        let control_input = allocation.bytes(sizes[5], true)?;
        let frame = allocation.bytes(sizes[6], false)?;
        Ok(Self {
            wire,
            seal,
            open,
            plain,
            control_wire,
            control_input,
            frame,
        })
    }
    /// Retained backing layouts, including both security copies and empty frame capacity.
    pub(super) fn capacity_bytes(&self) -> usize {
        // All seven exact capacities and this sum were checked before allocation.
        self.wire.capacity()
            + self.seal.capacity()
            + self.open.capacity()
            + self.plain.capacity()
            + self.control_wire.capacity()
            + self.control_input.capacity()
            + self.frame.capacity()
    }
}

/// Complete reusable I/O inputs, including the oversized-datagram observation byte.
pub(super) struct Inputs {
    pub(super) native: Vec<u8>,
    pub(super) datagram: Vec<u8>,
}
impl Inputs {
    pub(super) fn new(native: usize, datagram: usize) -> io::Result<Self> {
        Self::build([native, datagram], &mut Allocation::new())
    }
    fn build(sizes: [usize; 2], allocation: &mut Allocation) -> io::Result<Self> {
        layout_bytes(&sizes)?;
        let native = allocation.bytes(sizes[0], true)?;
        let datagram = allocation.bytes(sizes[1], true)?;
        Ok(Self { native, datagram })
    }
    /// Actual retained byte-array layouts, independent of later receive lengths.
    pub(super) fn capacity_bytes(&self) -> usize {
        self.native.capacity() + self.datagram.capacity()
    }
}

// Validate every array and the complete sum before the first fallible allocation.
fn layout_bytes(sizes: &[usize]) -> io::Result<usize> {
    sizes.iter().try_fold(0usize, |total, size| {
        if *size == 0 {
            return Err(invalid("fixed runtime byte buffer is empty"));
        }
        let layout = Layout::array::<u8>(*size)
            .map_err(|_| invalid("fixed runtime byte layout exceeds bounds"))?;
        total
            .checked_add(layout.size())
            .ok_or_else(|| invalid("fixed runtime byte layout total overflows"))
    })
}

struct Allocation {
    attempts: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    layouts: [usize; 7],
}
impl Allocation {
    fn new() -> Self {
        Self {
            attempts: 0,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            layouts: [0; 7],
        }
    }
    fn bytes(&mut self, size: usize, initialized: bool) -> io::Result<Vec<u8>> {
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or_else(|| invalid("fixed runtime allocation counter overflows"))?;
        #[cfg(test)]
        {
            let index = self.attempts - 1;
            let layout = self
                .layouts
                .get_mut(index)
                .ok_or_else(|| invalid("unexpected fixed runtime allocation"))?;
            *layout = size;
            if self.fail_at == Some(self.attempts) {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "injected fixed runtime allocation failure",
                ));
            }
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "fixed runtime byte allocation failed",
            )
        })?;
        if bytes.capacity() != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixed runtime byte allocation capacity differs",
            ));
        }
        if initialized {
            bytes.resize(size, 0);
        }
        Ok(bytes)
    }
}
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

#[cfg(test)]
#[path = "transport_buffers_tests.rs"]
mod tests;
