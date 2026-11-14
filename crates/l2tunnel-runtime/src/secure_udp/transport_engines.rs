//! Actual reserved duplex generations; management, native and proof authority stay external.

use l2tunnel::session::Ticket;
use l2tunnel::swift_configuration::Configuration as C;
use l2tunnel_core::Epoch;
use l2tunnel_management::{Role, session_control::Scope, transaction as tx};
use l2tunnel_swift::{records, storage};
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};

// Process-local ownership only: never serialized, authenticated or used as a nonce.
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

fn allocate_owner(next: &AtomicU64) -> io::Result<u64> {
    next.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        current.checked_add(1)
    })
    .map_err(|_| invalid("engine bank owner identity exhausted"))
}

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
    engine: storage::EngineId,
}
#[derive(Clone, Copy)]
struct Reservation {
    owner: u64,
    serial: u64,
    engine: storage::EngineId,
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

/// Non-Clone actual virgin reservation; retaining it grants no protocol authority.
pub(super) struct Prepared {
    owner: u64,
    serial: u64,
    engine: storage::EngineId,
    intent: tx::Preparation<C>,
    consumed: bool,
}
impl Prepared {
    pub(super) fn matches(&self, intent: &tx::Preparation<C>) -> bool {
        !self.consumed && Intent::from_preparation(&self.intent) == Intent::from_preparation(intent)
    }
    pub(super) fn identity(&self) -> tx::Identity {
        self.intent.identity()
    }
    pub(super) fn ticket(&self) -> Ticket {
        self.intent.ticket()
    }
    pub(super) fn origin(&self) -> Scope {
        self.intent.origin()
    }
    pub(super) fn expires(&self) -> tx::Tick {
        self.intent.expires()
    }
    pub(super) fn config(&self) -> &C {
        self.intent.config()
    }
}

/// One actual two-slot Set. Caller accounting includes metadata outside that Set.
/// No method proves current time, peer fences, physical writes or whole-message custody.
pub(super) struct Bank {
    owner: u64,
    identity: tx::Identity,
    current: Generation,
    secondary: Option<Secondary>,
    reservation: Option<Reservation>,
    next_serial: u64,
    storage: storage::Set,
}
impl Bank {
    pub(super) fn new(
        identity: tx::Identity,
        epoch: Epoch,
        initial: C,
        limits: storage::Limits,
        external_bytes: usize,
    ) -> io::Result<Self> {
        if epoch.0 == 0 || identity.session.0 == [0; 16] || identity.local == identity.remote {
            return Err(invalid("invalid actual engine bank identity"));
        }
        tx::configuration_digest(&initial).map_err(io::Error::other)?;
        let plan = plan(initial, identity.role)?;
        let owner = allocate_owner(&NEXT_OWNER)?;
        let mut storage = storage::Set::new(limits, external_bytes).map_err(io::Error::other)?;
        let engine = storage.prepare(plan).map_err(io::Error::other)?;
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
            storage,
        })
    }

    pub(super) fn prepare(&mut self, intent: tx::Preparation<C>) -> io::Result<Prepared> {
        if self.reservation.is_some() || self.secondary.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "engine bank retains another generation",
            ));
        }
        let exact = Intent::from_preparation(&intent);
        self.validate_intent(exact)?;
        let next = self
            .next_serial
            .checked_add(1)
            .ok_or_else(|| invalid("engine bank reservation serial exhausted"))?;
        let engine = self
            .storage
            .prepare(plan(exact.config, self.identity.role)?)
            .map_err(io::Error::other)?;
        let serial = self.next_serial;
        self.reservation = Some(Reservation {
            owner: self.owner,
            serial,
            engine,
            intent: exact,
        });
        self.next_serial = next;
        Ok(Prepared {
            owner: self.owner,
            serial,
            engine,
            intent,
            consumed: false,
        })
    }

    pub(super) fn cancel(&mut self, prepared: &mut Prepared) -> io::Result<()> {
        let reservation = self.check_prepared(prepared)?;
        self.storage
            .retire(reservation.engine)
            .map_err(io::Error::other)?;
        self.reservation = None;
        prepared.consumed = true;
        Ok(())
    }

    pub(super) fn stage(
        &mut self,
        prepared: &mut Prepared,
        operation: tx::Operation,
    ) -> io::Result<()> {
        let reservation = self.check_prepared(prepared)?;
        if !reservation.intent.operation_matches(operation) || self.secondary.is_some() {
            return Err(invalid(
                "actual staged operation differs from engine reservation",
            ));
        }
        self.validate_intent(reservation.intent)?;
        self.storage
            .engine(reservation.engine)
            .map_err(io::Error::other)?;
        self.storage
            .engine(self.current.engine)
            .map_err(io::Error::other)?;
        self.secondary = Some(Secondary::Staged {
            generation: Generation {
                epoch: reservation.intent.ticket.epoch,
                config: reservation.intent.config,
                engine: reservation.engine,
            },
            operation,
        });
        self.reservation = None;
        prepared.consumed = true;
        Ok(())
    }

    pub(super) fn commit(&mut self, operation: tx::Operation) -> io::Result<()> {
        let Some(Secondary::Staged {
            generation,
            operation: expected,
        }) = &self.secondary
        else {
            return Err(invalid("engine bank has no staged generation to commit"));
        };
        if *expected != operation {
            return Err(invalid("engine commit operation differs"));
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

    pub(super) fn abort(&mut self, operation: tx::Operation) -> io::Result<()> {
        let Some(Secondary::Staged {
            generation,
            operation: expected,
        }) = &self.secondary
        else {
            return Err(invalid(
                "engine bank cannot abort a promoted or absent generation",
            ));
        };
        if *expected != operation {
            return Err(invalid("engine abort operation differs"));
        }
        self.storage
            .retire(generation.engine)
            .map_err(io::Error::other)?;
        self.secondary = None;
        Ok(())
    }

    pub(super) fn retire(&mut self, operation: tx::Operation) -> io::Result<()> {
        let Some(Secondary::Draining {
            generation,
            operation: expected,
        }) = &self.secondary
        else {
            return Err(invalid("engine bank has no old generation to retire"));
        };
        if *expected != operation {
            return Err(invalid("engine retirement operation differs"));
        }
        self.storage
            .retire(generation.engine)
            .map_err(io::Error::other)?;
        self.secondary = None;
        Ok(())
    }

    pub(super) fn identity(&self) -> tx::Identity {
        self.identity
    }
    pub(super) fn current(&self) -> &C {
        &self.current.config
    }
    pub(super) fn epoch(&self) -> Epoch {
        self.current.epoch
    }
    pub(super) fn engine(&self, epoch: Epoch) -> io::Result<&records::Engine> {
        self.storage
            .engine(self.generation(epoch)?.engine)
            .map_err(io::Error::other)
    }
    pub(super) fn entry(&mut self, epoch: Epoch) -> io::Result<storage::Entry<'_>> {
        let engine = self.generation(epoch)?.engine;
        self.storage.entry(engine).map_err(io::Error::other)
    }
    pub(super) fn usage(&self) -> storage::Usage {
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
            .ok_or_else(|| invalid("engine generation is absent or still virgin"))
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
            .ok_or_else(|| invalid("engine epoch exhausted"))?;
        let old_native = self.current.config.descriptor().forward().records;
        let next_native = intent.config.descriptor().forward().records;
        if intent.identity != self.identity
            || intent.origin != origin
            || intent.ticket.epoch != next
            || intent.ticket.digest
                != tx::configuration_digest(&intent.config).map_err(io::Error::other)?
            || intent.config.envelope() != self.current.config.envelope()
            || next_native.layer != old_native.layer
            || next_native.max_native != old_native.max_native
        {
            return Err(invalid(
                "engine preparation differs from actual identity, origin or immutable format",
            ));
        }
        Ok(())
    }
    fn check_prepared(&self, prepared: &Prepared) -> io::Result<Reservation> {
        let reservation = self
            .reservation
            .ok_or_else(|| invalid("engine bank has no virgin reservation"))?;
        if prepared.consumed
            || prepared.owner != self.owner
            || reservation.owner != self.owner
            || reservation.serial != prepared.serial
            || reservation.engine != prepared.engine
            || reservation.intent != Intent::from_preparation(&prepared.intent)
        {
            return Err(invalid("foreign, stale or consumed engine reservation"));
        }
        Ok(reservation)
    }
}

fn plan(config: C, role: Role) -> io::Result<storage::Plan> {
    let other = match role {
        Role::Client => Role::Server,
        Role::Server => Role::Client,
    };
    storage::Plan::for_engine(
        config.descriptor().direction(role).records,
        config.descriptor().direction(other).records,
    )
    .map_err(io::Error::other)
}
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

#[cfg(test)]
#[path = "transport_engines_tests.rs"]
mod tests;
