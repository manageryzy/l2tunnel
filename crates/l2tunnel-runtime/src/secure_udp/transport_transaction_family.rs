//! Exact local canonical families for the one actual leased transaction State.

use super::common_engines;
use l2tunnel::{record_configuration as common, session::Ticket};
use l2tunnel_core::Epoch;
use l2tunnel_management::{session_control::Scope, transaction as tx};
use std::io;

mod sealed {
    pub trait Family {}
}

/// Runtime-private construction and exact-catalog contract; not authentication.
pub(super) trait Family: sealed::Family {
    type Value: tx::Configuration + Copy;
    type Envelope: Copy + Eq;
    type Catalog;
    type Bank: Backend<Self::Value>;

    fn initial(envelope: Self::Envelope, catalog: &Self::Catalog) -> io::Result<Self::Value>;
    fn supported(envelope: Self::Envelope, catalog: &Self::Catalog)
    -> io::Result<Vec<Self::Value>>;
    fn contains(envelope: Self::Envelope, catalog: &Self::Catalog, value: &Self::Value) -> bool;
}

/// The original opaque preparation remains tied to the actual virgin owner.
pub(super) trait Reservation<C: tx::Configuration> {
    fn matches(&self, intent: &tx::Preparation<C>) -> bool;
    fn identity(&self) -> tx::Identity;
    fn ticket(&self) -> Ticket;
    fn origin(&self) -> Scope;
    fn expires(&self) -> tx::Tick;
    fn config(&self) -> &C;
}

/// Storage lifecycle only; the State retains the sole real Peer and custody FSM.
pub(super) trait Backend<C: tx::Configuration> {
    type Prepared: Reservation<C>;

    fn identity(&self) -> tx::Identity;
    fn current(&self) -> &C;
    fn epoch(&self) -> Epoch;
    fn retained_limit(&self) -> usize;
    fn contains_epoch(&self, epoch: Epoch) -> bool;
    fn prepare(&mut self, intent: tx::Preparation<C>) -> io::Result<Self::Prepared>;
    fn cancel(&mut self, prepared: &mut Self::Prepared) -> io::Result<()>;
    fn stage(&mut self, prepared: &mut Self::Prepared, operation: tx::Operation) -> io::Result<()>;
    fn commit(&mut self, operation: tx::Operation) -> io::Result<()>;
    fn abort(&mut self, operation: tx::Operation) -> io::Result<()>;
    fn retire(&mut self, operation: tx::Operation) -> io::Result<()>;
}

/// Actual Common backend used by the current Driver.
pub(super) struct CommonFamily;
impl sealed::Family for CommonFamily {}
impl Family for CommonFamily {
    type Value = common::Configuration;
    type Envelope = common::EnvelopeDigest;
    type Catalog = common::Catalog;
    type Bank = common_engines::Bank;

    fn initial(envelope: Self::Envelope, catalog: &Self::Catalog) -> io::Result<Self::Value> {
        common::Configuration::new(envelope, catalog.initial()).map_err(invalid)
    }
    fn supported(
        envelope: Self::Envelope,
        catalog: &Self::Catalog,
    ) -> io::Result<Vec<Self::Value>> {
        catalog.configurations(envelope).map_err(invalid)
    }
    fn contains(envelope: Self::Envelope, catalog: &Self::Catalog, value: &Self::Value) -> bool {
        value.envelope() == envelope && catalog.descriptors().contains(value.descriptor())
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
