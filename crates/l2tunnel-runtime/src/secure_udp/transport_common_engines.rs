//! Exact leased intents over actual reserved common Bank generations.
//! No method supplies authentication, a physical fence or a second transaction FSM.

use super::common_contract;
use super::transaction_family::{Backend, Reservation as ReservationContract};
use l2tunnel::{
    record_bank as storage, record_configuration::Configuration as C, record_engine as records,
    session::Ticket,
};
use l2tunnel_core::Epoch;
use l2tunnel_management::{Role, session_control::Scope, transaction as tx};
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};

// Local ownership only; never a wire value, authentication proof or nonce.
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Eq, PartialEq)]
struct Intent {
    identity: tx::Identity,
    ticket: Ticket,
    origin: Scope,
    expires: tx::Tick,
    config: C,
}
impl Intent {
    fn from_preparation(preparation: &tx::Preparation<C>) -> Self {
        Self {
            identity: preparation.identity(),
            ticket: preparation.ticket(),
            origin: preparation.origin(),
            expires: preparation.expires(),
            config: *preparation.config(),
        }
    }
    fn operation_matches(self, operation: tx::Operation) -> bool {
        self.identity == operation.identity()
            && self.ticket == operation.ticket()
            && self.origin == operation.origin()
            && self.expires == operation.expires()
    }
}

#[derive(Clone, Copy)]
struct Generation {
    epoch: Epoch,
    config: C,
    engine: storage::GenerationId,
}
#[derive(Clone, Copy)]
struct Reservation {
    owner: u64,
    serial: u64,
    intent: Intent,
}
enum Secondary {
    Staged {
        generation: Generation,
        operation: tx::Operation,
    },
    Draining {
        generation: Generation,
        operation: tx::Operation,
    },
}
impl Secondary {
    fn generation(&self) -> &Generation {
        match self {
            Self::Staged { generation, .. } | Self::Draining { generation, .. } => generation,
        }
    }
}

/// The real readonly intent and actual virgin storage guard travel together.
pub(super) struct Prepared {
    owner: u64,
    serial: u64,
    intent: tx::Preparation<C>,
    storage: storage::Prepared,
    consumed: bool,
}
impl ReservationContract<C> for Prepared {
    fn matches(&self, intent: &tx::Preparation<C>) -> bool {
        !self.consumed && Intent::from_preparation(&self.intent) == Intent::from_preparation(intent)
    }
    fn identity(&self) -> tx::Identity {
        self.intent.identity()
    }
    fn ticket(&self) -> Ticket {
        self.intent.ticket()
    }
    fn origin(&self) -> Scope {
        self.intent.origin()
    }
    fn expires(&self) -> tx::Tick {
        self.intent.expires()
    }
    fn config(&self) -> &C {
        self.intent.config()
    }
}

/// Actual compiled common backend; selected Driver consumption remains required.
pub(super) struct Bank {
    owner: u64,
    identity: tx::Identity,
    current: Generation,
    secondary: Option<Secondary>,
    reservation: Option<Reservation>,
    next_serial: u64,
    geometry: records::Geometry,
    native: records::NativeLimits,
    ingress: Option<l2tunnel_pipeline::ack_coalescing::Policy>,
    rolling_ingress: Option<l2tunnel::rolling_records::IngressLimits>,
    rolling_fragments: Option<records::FragmentPolicy>,
    // One actual Bank in a fallibly reserved cell keeps its two inline Engine
    // extents out of the retained State. The selected Common entry constructs
    // this owner before polling its I/O continuation.
    storage: super::owner::StateCell<storage::Bank>,
}
impl Bank {
    // The selected common Driver will consume this exact constructor and its
    // typed accessors. Keep the real backend compiled before that next slice.
    #[allow(dead_code)]
    pub(super) fn new(
        identity: tx::Identity,
        epoch: Epoch,
        initial: C,
        geometry: records::Geometry,
        native: records::NativeLimits,
        limits: storage::storage::Limits,
        external_bytes: usize,
    ) -> io::Result<Self> {
        Self::new_with_ingress(
            identity,
            epoch,
            initial,
            geometry,
            native,
            limits,
            external_bytes,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)] // Existing exact owners plus explicit local ingress policy.
    pub(super) fn new_with_ingress(
        identity: tx::Identity,
        epoch: Epoch,
        initial: C,
        geometry: records::Geometry,
        native: records::NativeLimits,
        limits: storage::storage::Limits,
        external_bytes: usize,
        ingress: Option<l2tunnel_pipeline::ack_coalescing::Policy>,
    ) -> io::Result<Self> {
        Self::new_with_options(
            identity,
            epoch,
            initial,
            geometry,
            native,
            limits,
            external_bytes,
            ingress,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)] // Actual Bank inputs plus independent selected custody.
    pub(super) fn new_with_options(
        identity: tx::Identity,
        epoch: Epoch,
        initial: C,
        geometry: records::Geometry,
        native: records::NativeLimits,
        limits: storage::storage::Limits,
        external_bytes: usize,
        ingress: Option<l2tunnel_pipeline::ack_coalescing::Policy>,
        rolling_ingress: Option<l2tunnel::rolling_records::IngressLimits>,
    ) -> io::Result<Self> {
        Self::new_with_fragmentation(
            identity,
            epoch,
            initial,
            geometry,
            native,
            limits,
            external_bytes,
            ingress,
            rolling_ingress,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)] // Explicit complete immutable fragment policy.
    pub(super) fn new_with_fragmentation(
        identity: tx::Identity,
        epoch: Epoch,
        initial: C,
        geometry: records::Geometry,
        native: records::NativeLimits,
        limits: storage::storage::Limits,
        external_bytes: usize,
        ingress: Option<l2tunnel_pipeline::ack_coalescing::Policy>,
        rolling_ingress: Option<l2tunnel::rolling_records::IngressLimits>,
        rolling_fragments: Option<records::FragmentPolicy>,
    ) -> io::Result<Self> {
        if epoch.0 == 0 || identity.session.0 == [0; 16] || identity.local == identity.remote {
            return Err(invalid("invalid actual common engine Bank identity"));
        }
        tx::configuration_digest(&initial).map_err(io::Error::other)?;
        let plan = plan_with_fragmentation(
            initial,
            identity,
            epoch,
            geometry,
            native,
            ingress,
            rolling_ingress,
            rolling_fragments,
        )?;
        let plan =
            storage::storage::Plan::for_bank(plan, external_bytes).map_err(io::Error::other)?;
        let owner = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| invalid("common engine Bank owner identity exhausted"))?;
        let storage = storage::Bank::new_with(plan, limits, super::owner::StateCell::new)
            .map_err(io::Error::other)??;
        let engine = storage.initial();
        Ok(Self {
            owner,
            identity,
            current: Generation {
                epoch,
                config: initial,
                engine,
            },
            secondary: None,
            reservation: None,
            next_serial: 1,
            geometry,
            native,
            ingress,
            rolling_ingress,
            rolling_fragments,
            storage,
        })
    }

    #[allow(dead_code)] // Typed common Driver packet access is a required next consumer.
    pub(super) fn engine(&self, epoch: Epoch) -> io::Result<&records::Engine> {
        self.storage
            .engine(self.generation(epoch)?.engine)
            .map_err(io::Error::other)
    }
    #[allow(dead_code)] // No mutable Engine escape is introduced for the future Driver.
    pub(super) fn entry(&mut self, epoch: Epoch) -> io::Result<storage::Entry<'_>> {
        let engine = self.generation(epoch)?.engine;
        self.storage.entry(engine).map_err(io::Error::other)
    }
    #[allow(dead_code)] // Complete common Bank observation awaits selected Driver status.
    pub(super) fn usage(&self) -> storage::storage::Usage {
        self.storage.usage()
    }

    fn generation(&self, epoch: Epoch) -> io::Result<&Generation> {
        if epoch == self.current.epoch {
            return Ok(&self.current);
        }
        self.secondary
            .as_ref()
            .map(Secondary::generation)
            .filter(|g| g.epoch == epoch)
            .ok_or_else(|| invalid("common generation is absent or still virgin"))
    }
    fn validate_intent(&self, intent: Intent) -> io::Result<()> {
        let origin = Scope {
            epoch: self.current.epoch,
            digest: tx::configuration_digest(&self.current.config).map_err(io::Error::other)?,
        };
        let next = self
            .current
            .epoch
            .0
            .checked_add(1)
            .map(Epoch)
            .ok_or_else(|| invalid("common engine epoch exhausted"))?;
        if intent.identity != self.identity
            || intent.origin != origin
            || intent.ticket.epoch != next
            || intent.ticket.digest
                != tx::configuration_digest(&intent.config).map_err(io::Error::other)?
            || intent.config.envelope() != self.current.config.envelope()
            || intent.config.descriptor().duplex() != self.current.config.descriptor().duplex()
        {
            return Err(invalid(
                "common preparation differs from identity, origin or immutable envelope",
            ));
        }
        for sender in [Role::Client, Role::Server] {
            let old = self.current.config.descriptor().direction(sender);
            let new = intent.config.descriptor().direction(sender);
            if old.common().traffic().layer != new.common().traffic().layer
                || old.max_native() != new.max_native()
            {
                return Err(invalid(
                    "common preparation changes immutable native format",
                ));
            }
        }
        Ok(())
    }
    fn check_prepared(&self, prepared: &Prepared) -> io::Result<Reservation> {
        let reservation = self
            .reservation
            .ok_or_else(|| invalid("common Bank has no virgin reservation"))?;
        if prepared.consumed
            || prepared.owner != self.owner
            || reservation.owner != self.owner
            || reservation.serial != prepared.serial
            || reservation.intent != Intent::from_preparation(&prepared.intent)
        {
            return Err(invalid("foreign, stale or consumed common reservation"));
        }
        Ok(reservation)
    }
}

impl Backend<C> for Bank {
    type Prepared = Prepared;
    fn identity(&self) -> tx::Identity {
        self.identity
    }
    fn current(&self) -> &C {
        &self.current.config
    }
    fn epoch(&self) -> Epoch {
        self.current.epoch
    }
    fn retained_limit(&self) -> usize {
        self.storage.usage().limit_bytes
    }
    fn contains_epoch(&self, epoch: Epoch) -> bool {
        self.generation(epoch).is_ok()
    }

    fn prepare(&mut self, intent: tx::Preparation<C>) -> io::Result<Prepared> {
        if self.reservation.is_some() || self.secondary.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "common Bank retains another generation",
            ));
        }
        let exact = Intent::from_preparation(&intent);
        self.validate_intent(exact)?;
        let next = self
            .next_serial
            .checked_add(1)
            .ok_or_else(|| invalid("common reservation serial exhausted"))?;
        let plan = plan_with_fragmentation(
            exact.config,
            self.identity,
            exact.ticket.epoch,
            self.geometry,
            self.native,
            self.ingress,
            self.rolling_ingress,
            self.rolling_fragments,
        )?;
        let storage = self.storage.prepare(plan).map_err(io::Error::other)?;
        let serial = self.next_serial;
        self.reservation = Some(Reservation {
            owner: self.owner,
            serial,
            intent: exact,
        });
        self.next_serial = next;
        Ok(Prepared {
            owner: self.owner,
            serial,
            intent,
            storage,
            consumed: false,
        })
    }
    fn cancel(&mut self, prepared: &mut Prepared) -> io::Result<()> {
        self.check_prepared(prepared)?;
        self.storage
            .cancel(&mut prepared.storage)
            .map_err(io::Error::other)?;
        self.reservation = None;
        prepared.consumed = true;
        Ok(())
    }
    fn stage(&mut self, prepared: &mut Prepared, operation: tx::Operation) -> io::Result<()> {
        let reservation = self.check_prepared(prepared)?;
        if !reservation.intent.operation_matches(operation) || self.secondary.is_some() {
            return Err(invalid(
                "common Stage differs from actual reserved operation",
            ));
        }
        self.validate_intent(reservation.intent)?;
        self.storage
            .engine(self.current.engine)
            .map_err(io::Error::other)?;
        if self
            .storage
            .prepared_engine(&prepared.storage)
            .map_err(io::Error::other)?
            .configuration()
            != &reservation.intent.config
        {
            return Err(invalid("common virgin Engine differs from original target"));
        }
        let engine = self
            .storage
            .publish(&mut prepared.storage)
            .map_err(io::Error::other)?;
        self.secondary = Some(Secondary::Staged {
            generation: Generation {
                epoch: reservation.intent.ticket.epoch,
                config: reservation.intent.config,
                engine,
            },
            operation,
        });
        self.reservation = None;
        prepared.consumed = true;
        Ok(())
    }
    fn commit(&mut self, operation: tx::Operation) -> io::Result<()> {
        let Some(Secondary::Staged {
            generation,
            operation: expected,
        }) = &self.secondary
        else {
            return Err(invalid("common Bank has no staged generation to commit"));
        };
        if *expected != operation {
            return Err(invalid("common commit operation differs"));
        }
        self.storage
            .engine(generation.engine)
            .map_err(io::Error::other)?;
        self.storage
            .engine(self.current.engine)
            .map_err(io::Error::other)?;
        let next = *generation;
        let old = self.current;
        self.current = next;
        self.secondary = Some(Secondary::Draining {
            generation: old,
            operation,
        });
        Ok(())
    }
    fn abort(&mut self, operation: tx::Operation) -> io::Result<()> {
        let Some(Secondary::Staged {
            generation,
            operation: expected,
        }) = &self.secondary
        else {
            return Err(invalid(
                "common Bank cannot abort a promoted or absent generation",
            ));
        };
        if *expected != operation {
            return Err(invalid("common abort operation differs"));
        }
        self.storage
            .retire(generation.engine)
            .map_err(io::Error::other)?;
        self.secondary = None;
        Ok(())
    }
    fn retire(&mut self, operation: tx::Operation) -> io::Result<()> {
        let Some(Secondary::Draining {
            generation,
            operation: expected,
        }) = &self.secondary
        else {
            return Err(invalid("common Bank has no old generation to retire"));
        };
        if *expected != operation {
            return Err(invalid("common retirement operation differs"));
        }
        self.storage
            .retire(generation.engine)
            .map_err(io::Error::other)?;
        self.secondary = None;
        Ok(())
    }
}

#[cfg(test)]
fn plan(
    config: C,
    identity: tx::Identity,
    epoch: Epoch,
    geometry: records::Geometry,
    native: records::NativeLimits,
) -> io::Result<records::storage::Plan> {
    plan_with_ingress(config, identity, epoch, geometry, native, None)
}
#[cfg(test)]
fn plan_with_ingress(
    config: C,
    identity: tx::Identity,
    epoch: Epoch,
    geometry: records::Geometry,
    native: records::NativeLimits,
    ingress: Option<l2tunnel_pipeline::ack_coalescing::Policy>,
) -> io::Result<records::storage::Plan> {
    plan_with_options(config, identity, epoch, geometry, native, ingress, None)
}
#[cfg(test)]
#[allow(clippy::too_many_arguments)] // Exact existing plan inputs plus selected input custody.
fn plan_with_options(
    config: C,
    identity: tx::Identity,
    epoch: Epoch,
    geometry: records::Geometry,
    native: records::NativeLimits,
    ingress: Option<l2tunnel_pipeline::ack_coalescing::Policy>,
    rolling_ingress: Option<l2tunnel::rolling_records::IngressLimits>,
) -> io::Result<records::storage::Plan> {
    plan_with_fragmentation(
        config,
        identity,
        epoch,
        geometry,
        native,
        ingress,
        rolling_ingress,
        None,
    )
}
#[allow(clippy::too_many_arguments)] // Actual existing plan inputs plus selected fragment owners.
fn plan_with_fragmentation(
    config: C,
    identity: tx::Identity,
    epoch: Epoch,
    geometry: records::Geometry,
    native: records::NativeLimits,
    ingress: Option<l2tunnel_pipeline::ack_coalescing::Policy>,
    rolling_ingress: Option<l2tunnel::rolling_records::IngressLimits>,
    rolling_fragments: Option<records::FragmentPolicy>,
) -> io::Result<records::storage::Plan> {
    records::storage::Plan::for_engine_with_fragmentation(
        config,
        records::Context {
            session: u128::from_be_bytes(identity.session.0),
            epoch: epoch.0,
            role: identity.role,
        },
        geometry,
        native,
        ingress,
        rolling_ingress,
        common_contract::selected_fragment_policy(&config, rolling_fragments),
    )
    .map_err(io::Error::other)
}
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

#[cfg(test)]
#[path = "transport_common_engines_tests.rs"]
pub(super) mod tests;
