//! Exact local canonical families for the one actual leased transaction State.

use super::{common_engines, engines};
use l2tunnel::{record_configuration as common, session::Ticket, swift_configuration as swift};
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

pub(super) struct SwiftFamily;
impl sealed::Family for SwiftFamily {}
impl Family for SwiftFamily {
    type Value = swift::Configuration;
    type Envelope = swift::EnvelopeDigest;
    type Catalog = swift::Catalog;
    type Bank = engines::Bank;

    fn initial(envelope: Self::Envelope, catalog: &Self::Catalog) -> io::Result<Self::Value> {
        swift::Configuration::new(envelope, catalog.initial()).map_err(invalid)
    }
    fn supported(
        envelope: Self::Envelope,
        catalog: &Self::Catalog,
    ) -> io::Result<Vec<Self::Value>> {
        Ok(catalog.configurations(envelope))
    }
    fn contains(envelope: Self::Envelope, catalog: &Self::Catalog, value: &Self::Value) -> bool {
        value.envelope() == envelope && catalog.descriptors().contains(&value.descriptor())
    }
}

/// Compiled actual common backend; the selected common Driver is a later consumer.
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

impl Reservation<swift::Configuration> for engines::Prepared {
    fn matches(&self, intent: &tx::Preparation<swift::Configuration>) -> bool {
        Self::matches(self, intent)
    }
    fn identity(&self) -> tx::Identity {
        Self::identity(self)
    }
    fn ticket(&self) -> Ticket {
        Self::ticket(self)
    }
    fn origin(&self) -> Scope {
        Self::origin(self)
    }
    fn expires(&self) -> tx::Tick {
        Self::expires(self)
    }
    fn config(&self) -> &swift::Configuration {
        Self::config(self)
    }
}

impl Backend<swift::Configuration> for engines::Bank {
    type Prepared = engines::Prepared;

    fn identity(&self) -> tx::Identity {
        Self::identity(self)
    }
    fn current(&self) -> &swift::Configuration {
        Self::current(self)
    }
    fn epoch(&self) -> Epoch {
        Self::epoch(self)
    }
    fn retained_limit(&self) -> usize {
        self.usage().limit_bytes
    }
    fn contains_epoch(&self, epoch: Epoch) -> bool {
        self.engine(epoch).is_ok()
    }
    fn prepare(
        &mut self,
        intent: tx::Preparation<swift::Configuration>,
    ) -> io::Result<Self::Prepared> {
        Self::prepare(self, intent)
    }
    fn cancel(&mut self, prepared: &mut Self::Prepared) -> io::Result<()> {
        Self::cancel(self, prepared)
    }
    fn stage(&mut self, prepared: &mut Self::Prepared, operation: tx::Operation) -> io::Result<()> {
        Self::stage(self, prepared, operation)
    }
    fn commit(&mut self, operation: tx::Operation) -> io::Result<()> {
        Self::commit(self, operation)
    }
    fn abort(&mut self, operation: tx::Operation) -> io::Result<()> {
        Self::abort(self, operation)
    }
    fn retire(&mut self, operation: tx::Operation) -> io::Result<()> {
        Self::retire(self, operation)
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
