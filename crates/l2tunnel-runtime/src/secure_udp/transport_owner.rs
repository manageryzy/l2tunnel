//! Exclusive data/control state selected by the existing sole I/O owner.

use super::{io, transactions};

// The current State has one explicitly charged, fallible reservation.
pub(super) enum DataOwner {
    Common(ReservedCommonState),
}

/// One fallibly reserved State; no mutation of the backing vector is exposed.
pub(super) struct StateCell<S> {
    values: Vec<S>,
}
pub(super) type ReservedCommonState = StateCell<transactions::CommonState>;
impl<S> StateCell<S> {
    pub(super) fn new(state: S) -> io::Result<Self> {
        std::alloc::Layout::array::<S>(1).map_err(io::Error::other)?;
        let mut values = Vec::new();
        values.try_reserve_exact(1).map_err(io::Error::other)?;
        if values.capacity() != 1 {
            return Err(io::Error::other("State cell capacity differs"));
        }
        values.push(state);
        Ok(Self { values })
    }
}
impl<S> std::ops::Deref for StateCell<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        // Only new constructs this private cell, always at immutable length one.
        &self.values[0]
    }
}
impl<S> std::ops::DerefMut for StateCell<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values[0]
    }
}
