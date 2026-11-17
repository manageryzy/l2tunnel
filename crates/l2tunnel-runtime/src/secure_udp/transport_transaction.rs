//! Actual leased Peer, reserved engine generations and bounded Control custody.
//! This owner performs no I/O and supplies no physical or authentication proof.

use super::super::control as control_owner;
use super::{
    TransactionSettings,
    transaction_family::{Backend, CommonFamily, Family, Reservation},
};
use l2tunnel_core::Epoch;
use l2tunnel_management::{
    self as mg, control_streams, delivery, session_control as sc, transaction as tx,
};
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

static NEXT_STATE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Progress {
    Idle,
    Blocked,
    Advanced,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct WorkId {
    owner: u64,
    serial: u64,
}

pub(super) struct ActionFor<C: tx::Configuration> {
    id: WorkId,
    operation: tx::Operation,
    event: tx::Event<C>,
    finished: bool,
}
impl<C: tx::Configuration> ActionFor<C> {
    pub(super) fn operation(&self) -> tx::Operation {
        self.operation
    }
    pub(super) fn event(&self) -> &tx::Event<C> {
        &self.event
    }
}

pub(super) enum Completion<'a> {
    Staged {
        admitted: &'a tx::Fence,
    },
    Drained {
        sent: &'a tx::Fence,
        delivered: &'a tx::Fence,
    },
    Applied,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    Retired {
        operation: tx::Operation,
        epoch: Epoch,
    },
    Aborted {
        operation: tx::Operation,
        attempt: u64,
    },
}

#[derive(Clone, Copy)]
enum WorkKind {
    Stage,
    Drain,
    Applied,
}
impl WorkKind {
    fn of<C: tx::Configuration>(event: &tx::Event<C>) -> Self {
        match event {
            tx::Event::Stage { .. } => Self::Stage,
            tx::Event::Drain { .. } => Self::Drain,
            _ => Self::Applied,
        }
    }
}
// Fixed inline Action custody avoids allocating during semantic admission.
#[allow(clippy::large_enum_variant)]
enum Work<C: tx::Configuration> {
    Ready(ActionFor<C>),
    Issued {
        serial: u64,
        operation: tx::Operation,
        kind: WorkKind,
    },
}

struct AwaitingAcceptance {
    incoming: control_owner::Incoming,
    envelope: Vec<u8>,
    deadline: Duration,
    operation: tx::Operation,
    terminal: bool,
}
struct Effect<C: tx::Configuration> {
    operation: tx::Operation,
    effects: tx::Effects<C>,
    incoming: Option<AwaitingAcceptance>,
    emergency: bool,
}
struct Output {
    frozen: control_owner::FrozenOutput,
    confirmed: bool,
    terminal_proof: bool,
}
#[derive(Clone, Copy)]
struct PendingAdmission {
    incoming: control_owner::Incoming,
    deadline: Duration,
    cap: tx::Tick,
}
struct Contract<F: Family> {
    identity: tx::Identity,
    envelope: F::Envelope,
    catalog: F::Catalog,
    settings: TransactionSettings,
    binding: delivery::Binding,
    session_expires: Duration,
}

pub(super) struct TransactionState<F: Family> {
    peer: tx::Peer<F::Value>,
    bank: F::Bank,
    contract: Contract<F>,
    operation: Option<tx::Operation>,
    prepared: Option<<F::Bank as Backend<F::Value>>::Prepared>,
    effect: Option<Effect<F::Value>>,
    work: Option<Work<F::Value>>,
    acceptance: Option<AwaitingAcceptance>,
    pending_admission: Option<PendingAdmission>,
    outputs: [Option<Output>; 3],
    outcome: Option<Outcome>,
    physical_terminal: Option<tx::Operation>,
    owner: u64,
    next_work: u64,
    now: Duration,
    phase_blocked: bool,
    failed: bool,
}

impl<F: Family> TransactionState<F> {
    #[allow(clippy::too_many_arguments)] // Every original contract owner is explicit.
    pub(super) fn new(
        identity: tx::Identity,
        epoch: Epoch,
        envelope: F::Envelope,
        catalog: F::Catalog,
        settings: TransactionSettings,
        transaction_binding: delivery::Binding,
        now: Duration,
        session_expires: Duration,
        bank: F::Bank,
    ) -> io::Result<Self> {
        settings.protocol.validate().map_err(invalid)?;
        let initial = F::initial(envelope, &catalog)?;
        let base_epoch = transaction_binding
            .control_epoch
            .checked_sub(control_streams::Stream::Transaction as u64)
            .filter(|value| *value > 0 && *value % 3 == 0)
            .map(|value| value / 3)
            .ok_or_else(|| invalid("transaction binding is not a derived epoch"))?;
        let expected = control_streams::delivery_binding(
            delivery::Binding {
                session: identity.session,
                lane: identity.lane,
                local_role: identity.role,
                control_epoch: base_epoch,
            },
            control_streams::Stream::Transaction,
        )
        .map_err(invalid)?;
        if expected != transaction_binding
            || bank.identity() != identity
            || bank.epoch() != epoch
            || bank.current() != &initial
            || settings.max_operation_ms == 0
            || settings.retained_bytes == 0
            || bank.retained_limit() > settings.retained_bytes
            || now >= session_expires
        {
            return Err(invalid(
                "transaction State differs from actual initial Bank or binding",
            ));
        }
        u64::try_from(settings.retained_bytes).map_err(invalid)?;
        let supported = F::supported(envelope, &catalog)?;
        let peer = tx::Peer::new_leased_directional(
            identity,
            epoch,
            initial,
            &supported,
            settings.protocol,
            tx::LeaseSettings {
                session_expires: tick(session_expires)?,
                max_operation_ms: settings.max_operation_ms,
                transaction_epoch: transaction_binding.control_epoch,
            },
            tick(now)?,
        )
        .map_err(invalid)?;
        let owner = NEXT_STATE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| invalid("transaction State owner identity exhausted"))?;
        Ok(Self {
            peer,
            bank,
            contract: Contract {
                identity,
                envelope,
                catalog,
                settings,
                binding: transaction_binding,
                session_expires,
            },
            operation: None,
            prepared: None,
            effect: None,
            work: None,
            acceptance: None,
            pending_admission: None,
            outputs: [None, None, None],
            outcome: None,
            physical_terminal: None,
            owner,
            next_work: 1,
            now,
            phase_blocked: false,
            failed: false,
        })
    }

    pub(super) fn propose(
        &mut self,
        owner: &mut control_owner::Owner,
        value: F::Value,
        cap: tx::Tick,
        mut sample: impl FnMut() -> io::Result<Duration>,
    ) -> io::Result<Progress> {
        let now = sample()?;
        self.check_owner(owner)?;
        self.observe_due(owner, now)?;
        self.cleanup_operation();
        if !self.can_start() {
            return Ok(Progress::Blocked);
        }
        if !F::contains(self.contract.envelope, &self.contract.catalog, &value) {
            return Err(invalid("target is outside the exact authenticated catalog"));
        }
        if owner.preview_transaction(&self.peer, now, cap)?.is_some() {
            return Ok(Progress::Blocked);
        }
        let intent = self
            .peer
            .preview_propose_until(&value, tick(now)?, cap)
            .map_err(invalid)?;
        let mut prepared = self.bank.prepare(intent)?;
        let result = (|| {
            let now = sample()?;
            self.observe_due(owner, now)?;
            if !self.can_start() {
                return Ok(None);
            }
            let intent = self
                .peer
                .preview_propose_until(&value, tick(now)?, cap)
                .map_err(invalid)?;
            if !prepared.matches(&intent) {
                return Err(protocol("target intent changed during allocation"));
            }
            if owner.preview_transaction(&self.peer, now, cap)?.is_some() {
                return Ok(None);
            }
            let effects = self
                .peer
                .propose_until(value, tick(now)?, cap)
                .map_err(protocol)?;
            Ok(Some(effects))
        })();
        match result {
            Ok(Some(effects)) => {
                self.prepared = Some(prepared);
                let operation = self
                    .peer
                    .operation()
                    .ok_or_else(|| protocol("proposal did not retain actual operation"))?;
                self.retain_operation(operation)?;
                self.effect = Some(Effect {
                    operation,
                    effects,
                    incoming: None,
                    emergency: false,
                });
                Ok(Progress::Advanced)
            }
            other => {
                self.bank.cancel(&mut prepared)?;
                match other {
                    Ok(None) => Ok(Progress::Blocked),
                    Err(error) => Err(error),
                    Ok(Some(_)) => unreachable_result(),
                }
            }
        }
    }

    pub(super) fn dispatch(
        &mut self,
        owner: &mut control_owner::Owner,
        sample: impl FnMut() -> io::Result<Duration>,
    ) -> io::Result<Progress> {
        self.dispatch_preparations(owner, true, sample)
    }

    /// Reuse the exact leased preview and original cap for immutable profiles.
    /// A forbidden fresh PREPARE is terminal Unsupported before allocation or
    /// Peer admission. The existing FSM has no follower policy-REJECT command;
    /// this must not fabricate one or silently replace its active generation.
    pub(super) fn dispatch_preparations(
        &mut self,
        owner: &mut control_owner::Owner,
        allow_preparation: bool,
        mut sample: impl FnMut() -> io::Result<Duration>,
    ) -> io::Result<Progress> {
        let now = sample()?;
        self.check_owner(owner)?;
        self.observe_due(owner, now)?;
        let cap = self
            .pending_admission
            .map(|pending| pending.cap)
            .or_else(|| self.peer.operation().map(tx::Operation::expires))
            .map_or_else(|| self.new_cap(now), Ok)?;
        let Some(view) = owner.preview_transaction(&self.peer, now, cap)? else {
            return Ok(if self.acceptance.is_some() || self.work.is_some() {
                Progress::Blocked
            } else {
                Progress::Idle
            });
        };
        if !allow_preparation && view.preparation().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "immutable Common proxy cannot prepare another generation",
            ));
        }
        let pending = PendingAdmission {
            incoming: view.incoming(),
            deadline: view.deadline(),
            cap,
        };
        if let Some(original) = self.pending_admission {
            if original.incoming != pending.incoming
                || original.deadline != pending.deadline
                || original.cap != cap
            {
                return Err(protocol(
                    "pending transaction identity changed before admission",
                ));
            }
        } else {
            self.pending_admission = Some(pending);
        }
        let kind = management_kind_for::<F::Value>(view.envelope())?;
        let intent = view.into_preparation();
        if !self.dispatch_capacity(kind, intent.is_some())? {
            return Ok(Progress::Blocked);
        }
        let mut prepared = intent.map(|intent| self.bank.prepare(intent)).transpose()?;
        let now = if prepared.is_some() {
            match sample() {
                Ok(now) => now,
                Err(error) => {
                    self.cancel_virgin(&mut prepared)?;
                    return Err(error);
                }
            }
        } else {
            now
        };
        let validation = (|| {
            self.observe_due(owner, now)?;
            if !self.dispatch_capacity(kind, prepared.is_some())? {
                return Ok(false);
            }
            let Some(view) = owner.preview_transaction(&self.peer, now, cap)? else {
                return Ok(false);
            };
            if view.incoming() != pending.incoming || view.deadline() != pending.deadline {
                return Err(protocol(
                    "actual pending message changed during target allocation",
                ));
            }
            match (prepared.as_ref(), view.preparation()) {
                (Some(prepared), Some(intent)) if prepared.matches(intent) => {}
                (None, None) => {}
                _ => {
                    return Err(protocol(
                        "actual first-PREPARE intent changed during allocation",
                    ));
                }
            }
            Ok(true)
        })();
        match validation {
            Ok(true) => {}
            other => {
                self.cancel_virgin(&mut prepared)?;
                return match other {
                    Ok(false) => Ok(Progress::Blocked),
                    Err(error) => Err(error),
                    Ok(true) => unreachable_result(),
                };
            }
        }
        let mut incoming = None;
        let dispatched = owner.dispatch_transaction(&mut self.peer, now, cap, &mut incoming);
        let dispatched = match dispatched {
            Ok(progress) => progress,
            Err(error) => {
                self.cancel_virgin(&mut prepared)?;
                return Err(error);
            }
        };
        if dispatched != control_owner::DispatchProgress::Dispatched {
            self.cancel_virgin(&mut prepared)?;
            return Ok(Progress::Blocked);
        }
        let incoming = incoming.ok_or_else(|| protocol("joint dispatch omitted actual effects"))?;
        let (actual, envelope, operation, effects) = incoming.into_parts();
        if actual != pending.incoming {
            return Err(protocol("joint dispatch substituted incoming custody"));
        }
        self.retain_operation(operation)?;
        if let Some(prepared) = prepared {
            if self.prepared.is_some() {
                return Err(protocol(
                    "second actual virgin preparation after joint dispatch",
                ));
            }
            self.prepared = Some(prepared);
        }
        let terminal = self.contract.identity.role == mg::Role::Client
            && matches!(
                effects.event,
                Some(tx::Event::Retired(_) | tx::Event::Aborted(_))
            );
        self.effect = Some(Effect {
            operation,
            effects,
            emergency: false,
            incoming: Some(AwaitingAcceptance {
                incoming: actual,
                envelope,
                deadline: pending.deadline,
                operation,
                terminal,
            }),
        });
        self.pending_admission = None;
        Ok(Progress::Advanced)
    }

    /// One bounded turn; original phase expiry precedes ordinary semantic work.
    pub(super) fn service(
        &mut self,
        owner: &mut control_owner::Owner,
        now: Duration,
    ) -> io::Result<Progress> {
        self.check_owner(owner)?;
        let mut advanced = self.observe_due(owner, now)?;
        advanced |= self.service_outputs(owner, now)?;
        advanced |= self.transfer_effect(owner, now)?;
        advanced |= self.accept(owner, now)?;
        if self.effect.is_none()
            && !self.phase_blocked
            && self.peer.phase() != tx::Phase::Failed
            && !self.current_output_retained(now)?
        {
            let operation = self.operation.or(self.peer.operation());
            let effects = self.peer.poll(tick(now)?).map_err(protocol)?;
            if effects.event.is_some() || effects.outbound.is_some() {
                let operation = operation
                    .or(self.peer.operation())
                    .ok_or_else(|| protocol("poll output lost original operation"))?;
                self.retain_operation(operation)?;
                self.effect = Some(Effect {
                    operation,
                    effects,
                    incoming: None,
                    emergency: false,
                });
                advanced = true;
            }
        }
        advanced |= self.service_outputs(owner, now)?;
        advanced |= self.transfer_effect(owner, now)?;
        advanced |= self.accept(owner, now)?;
        self.cleanup_operation();
        Ok(if advanced {
            Progress::Advanced
        } else if self.effect.is_some() || self.acceptance.is_some() {
            Progress::Blocked
        } else {
            Progress::Idle
        })
    }

    pub(super) fn take_action(&mut self) -> Option<ActionFor<F::Value>> {
        match self.work.take()? {
            Work::Ready(action) => {
                self.work = Some(Work::Issued {
                    serial: action.id.serial,
                    operation: action.operation,
                    kind: WorkKind::of(&action.event),
                });
                Some(action)
            }
            issued => {
                self.work = Some(issued);
                None
            }
        }
    }

    pub(super) fn interruption(
        &self,
        action: &ActionFor<F::Value>,
    ) -> Option<&tx::Event<F::Value>> {
        if !self.action_matches(action) {
            return None;
        }
        let effect = self
            .effect
            .as_ref()
            .filter(|effect| effect.operation == action.operation)?;
        effect
            .effects
            .event
            .as_ref()
            .filter(|event| matches!(event, tx::Event::Aborted(_) | tx::Event::Failed))
    }

    pub(super) fn complete_action(
        &mut self,
        owner: &mut control_owner::Owner,
        action: &mut ActionFor<F::Value>,
        completion: Completion<'_>,
        now: Duration,
    ) -> io::Result<Progress> {
        self.check_owner(owner)?;
        if !self.action_matches(action) {
            return Err(invalid("foreign or completed lifecycle Action"));
        }
        self.observe_due(owner, now)?;
        if matches!(completion, Completion::Cancelled) {
            if !matches!(
                action.event,
                tx::Event::Stage { .. } | tx::Event::Drain { .. }
            ) || self.interruption(action).is_none()
            {
                return Err(invalid(
                    "lifecycle cancellation lacks actual safe interruption",
                ));
            }
            if let Some(mut prepared) = self.prepared.take() {
                self.bank.cancel(&mut prepared)?;
            }
            self.finish_action(action);
            return Ok(Progress::Advanced);
        }
        let applied = matches!(completion, Completion::Applied)
            && !matches!(
                action.event,
                tx::Event::Stage { .. } | tx::Event::Drain { .. }
            );
        if !applied && (self.interruption(action).is_some() || self.effect.is_some()) {
            return Ok(Progress::Blocked);
        }
        let operation = action.operation;
        match (&action.event, completion) {
            (tx::Event::Stage { ticket, config }, Completion::Staged { admitted }) => {
                if !matches!(
                    self.peer.phase(),
                    tx::Phase::Staging | tx::Phase::FollowerStaging
                ) {
                    return Ok(Progress::Blocked);
                }
                if !self.normal_output_room()? {
                    return Ok(Progress::Blocked);
                }
                if admitted.counts().len()
                    != usize::from(self.peer.sender_channels(self.contract.identity.role))
                {
                    return Err(invalid("Stage fence has wrong actual local sender width"));
                }
                let prepared = self
                    .prepared
                    .as_mut()
                    .ok_or_else(|| protocol("Stage lost actual Prepared engine"))?;
                if prepared.identity() != self.contract.identity
                    || prepared.origin() != operation.origin()
                    || prepared.expires() != operation.expires()
                    || prepared.ticket() != *ticket
                    || prepared.config() != config
                    || self.peer.operation() != Some(operation)
                {
                    return Err(protocol(
                        "Stage Action differs from actual reserved operation",
                    ));
                }
                self.bank.stage(prepared, operation)?;
                self.prepared = None;
                let effects = self
                    .peer
                    .staged(admitted.clone(), tick(now)?)
                    .map_err(protocol)?;
                self.effect = Some(Effect {
                    operation,
                    effects,
                    incoming: None,
                    emergency: false,
                });
            }
            (tx::Event::Drain { local, peer }, Completion::Drained { sent, delivered }) => {
                if !matches!(
                    self.peer.phase(),
                    tx::Phase::Draining | tx::Phase::FollowerReady | tx::Phase::FollowerDraining
                ) {
                    return Ok(Progress::Blocked);
                }
                if !self.normal_output_room()? {
                    return Ok(Progress::Blocked);
                }
                if local != sent || peer != delivered {
                    return Err(invalid(
                        "Drain completion differs from actual independent fences",
                    ));
                }
                let effects = self
                    .peer
                    .confirm_drained(sent, delivered, tick(now)?)
                    .map_err(protocol)?;
                self.effect = Some(Effect {
                    operation,
                    effects,
                    incoming: None,
                    emergency: false,
                });
            }
            (tx::Event::Committed(_), Completion::Applied) => {
                self.bank.commit(operation)?;
                owner.advance_scope(sc::Scope {
                    epoch: self.peer.active_epoch(),
                    digest: tx::configuration_digest(self.peer.active_config())
                        .map_err(protocol)?,
                })?;
            }
            (tx::Event::Retired(epoch), Completion::Applied) => {
                if self.outcome.is_some() {
                    return Ok(Progress::Blocked);
                }
                self.bank.retire(operation)?;
                owner.retire_leased_draining(&self.peer, operation.origin(), now)?;
                self.physical_terminal = Some(operation);
                self.outcome = Some(Outcome::Retired {
                    operation,
                    epoch: *epoch,
                });
            }
            (tx::Event::Aborted(attempt), Completion::Applied) => {
                if self.outcome.is_some() {
                    return Ok(Progress::Blocked);
                }
                if let Some(mut prepared) = self.prepared.take() {
                    self.bank.cancel(&mut prepared)?;
                } else if self.bank.contains_epoch(operation.ticket().epoch)
                    && self.bank.epoch() == operation.origin().epoch
                {
                    self.bank.abort(operation)?;
                }
                self.physical_terminal = Some(operation);
                self.outcome = Some(Outcome::Aborted {
                    operation,
                    attempt: *attempt,
                });
            }
            (tx::Event::Uncertain(_), Completion::Applied) => {}
            (tx::Event::Failed, Completion::Applied) => {
                self.failed = true;
            }
            _ => return Err(invalid("completion does not match actual lifecycle event")),
        }
        self.finish_action(action);
        Ok(Progress::Advanced)
    }

    pub(super) fn operation_deadline(&self) -> Option<Duration> {
        self.operation
            .map(|operation| duration(operation.expires()))
    }

    pub(super) fn next_deadline(&self) -> Option<Duration> {
        if self.failed {
            return None;
        }
        let phase = (!self.phase_blocked)
            .then(|| self.peer.phase_deadline())
            .flatten()
            .map(duration);
        // A retained logical marker is transported by Owner; its already-due
        // Peer retry must not spin the parent while wire/semantic custody waits.
        let retry = (!self.phase_blocked
            && self.effect.is_none()
            && self.acceptance.is_none()
            && !self.current_output_retained(self.now).unwrap_or(false))
        .then(|| self.peer.next_deadline())
        .flatten()
        .map(duration);
        Some(self.contract.session_expires)
            .into_iter()
            .chain(
                self.operation
                    .map(|operation| duration(operation.expires())),
            )
            .chain(phase)
            .chain(retry)
            .chain(
                self.outputs
                    .iter()
                    .flatten()
                    .filter(|output| !output.confirmed)
                    .map(|output| output.frozen.deadline()),
            )
            .chain(self.acceptance.as_ref().map(|incoming| incoming.deadline))
            .chain(
                self.pending_admission
                    .map(|pending| pending.deadline.min(duration(pending.cap))),
            )
            .min()
    }
    pub(super) fn can_admit_data(&self) -> bool {
        !self.failed
            && self.work.is_none()
            && self.effect.is_none()
            && self.pending_admission.is_none()
            && self.peer.can_admit_data()
            && self.bank.epoch() == self.peer.active_epoch()
            && self.bank.current() == self.peer.active_config()
    }
    pub(super) fn peer(&self) -> &tx::Peer<F::Value> {
        &self.peer
    }
    pub(super) fn take_outcome(&mut self) -> Option<Outcome> {
        self.outcome.take()
    }
    pub(super) fn current(&self) -> &F::Value {
        self.bank.current()
    }
    pub(super) fn epoch(&self) -> Epoch {
        self.bank.epoch()
    }

    fn check_owner(&self, owner: &control_owner::Owner) -> io::Result<()> {
        if owner.transaction_binding()? != self.contract.binding {
            return Err(invalid("State borrowed a foreign Control owner"));
        }
        Ok(())
    }
    fn clock(&mut self, now: Duration) -> io::Result<()> {
        if self.failed {
            return Err(protocol("transaction State is terminal"));
        }
        if now < self.now {
            return Err(protocol("transaction State time moved backwards"));
        }
        let at = tick(now)?;
        if now >= self.contract.session_expires
            || self
                .operation
                .is_some_and(|operation| at >= operation.expires())
            || self
                .pending_admission
                .is_some_and(|pending| now >= pending.deadline || at >= pending.cap)
        {
            let _ = self.peer.poll(at);
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original transaction State operation/session cap",
            ));
        }
        self.now = now;
        Ok(())
    }
    fn observe_due(&mut self, owner: &mut control_owner::Owner, now: Duration) -> io::Result<bool> {
        self.clock(now)?;
        if !self
            .peer
            .phase_deadline()
            .is_some_and(|deadline| tick(now).is_ok_and(|at| at >= deadline))
        {
            self.phase_blocked = false;
            return Ok(false);
        }
        let mut advanced = self.service_outputs(owner, now)?;
        advanced |= self.transfer_effect(owner, now)?;
        if self.effect.is_some() {
            self.phase_blocked = true;
            return Ok(advanced);
        }
        let operation = self
            .operation
            .or(self.peer.operation())
            .ok_or_else(|| protocol("phase expiry has no original operation"))?;
        let effects = self.peer.poll(tick(now)?).map_err(protocol)?;
        self.retain_operation(operation)?;
        if effects.event.is_some() || effects.outbound.is_some() {
            self.effect = Some(Effect {
                operation,
                effects,
                incoming: None,
                emergency: true,
            });
            advanced = true;
        }
        self.phase_blocked = false;
        Ok(advanced)
    }
    fn can_start(&self) -> bool {
        self.operation.is_none()
            && self.peer.can_admit_data()
            && self.effect.is_none()
            && self.work.is_none()
            && self.acceptance.is_none()
            && self.pending_admission.is_none()
            && self.outcome.is_none()
            && self.prepared.is_none()
            && self.outputs.iter().all(Option::is_none)
    }
    fn new_cap(&self, now: Duration) -> io::Result<tx::Tick> {
        let at = tick(now)?;
        let end =
            at.0.checked_add(self.contract.settings.max_operation_ms)
                .map(tx::Tick)
                .ok_or_else(|| invalid("original operation cap overflow"))?;
        Ok(end.min(tick(self.contract.session_expires)?))
    }
    fn retain_operation(&mut self, operation: tx::Operation) -> io::Result<()> {
        if operation.identity() != self.contract.identity
            || self.operation.is_some_and(|prior| prior != operation)
        {
            return Err(protocol(
                "State actual operation changed before custody settled",
            ));
        }
        self.operation = Some(operation);
        Ok(())
    }
    fn cancel_virgin(
        &mut self,
        prepared: &mut Option<<F::Bank as Backend<F::Value>>::Prepared>,
    ) -> io::Result<()> {
        if let Some(mut target) = prepared.take() {
            self.bank.cancel(&mut target)?;
        }
        Ok(())
    }
    fn normal_output_room(&self) -> io::Result<bool> {
        if self.outputs[2].is_some()
            || self
                .outputs
                .iter()
                .flatten()
                .any(|output| output.frozen.token().is_none())
        {
            return Ok(false);
        }
        if self.outputs[..2].iter().any(Option::is_none) {
            return Ok(true);
        }
        for output in self.outputs[..2].iter().flatten() {
            if output.confirmed
                && current_output(
                    &self.peer,
                    self.contract.identity.role,
                    output,
                    tick(self.now)?,
                )?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn dispatch_capacity(&self, kind: mg::MessageKind, preparing: bool) -> io::Result<bool> {
        if self.effect.is_some()
            || self.acceptance.is_some()
            || self.phase_blocked
            || preparing && (self.outcome.is_some() || self.prepared.is_some())
        {
            return Ok(false);
        }
        if self.work.is_some() {
            let interrupted = kind == mg::MessageKind::Reject
                && matches!(
                    self.work,
                    Some(Work::Issued {
                        kind: WorkKind::Stage | WorkKind::Drain,
                        ..
                    })
                );
            let harmless = self.contract.identity.role == mg::Role::Server
                && !preparing
                && matches!(kind, mg::MessageKind::Prepare | mg::MessageKind::Barrier);
            if !interrupted && !harmless {
                return Ok(false);
            }
        }
        let outbound = match self.contract.identity.role {
            mg::Role::Client => {
                matches!(kind, mg::MessageKind::Barrier | mg::MessageKind::CommitAck)
            }
            mg::Role::Server => !preparing,
        };
        let cached_final = if self.contract.identity.role == mg::Role::Server
            && !preparing
            && self.peer.phase() == tx::Phase::Idle
        {
            if let Some(operation) = self.peer.operation() {
                let authority = self
                    .peer
                    .cached_retry_authority(tick(self.now)?)
                    .map_err(protocol)?;
                authority.is_some_and(|authority| {
                    authority.operation() == operation
                        && self.operation == Some(operation)
                        && authority.request().header.kind == kind
                        && matches!(
                            authority.reply_kind(),
                            mg::MessageKind::Retire | mg::MessageKind::Reject
                        )
                }) && self.current_output_retained(self.now)?
            } else {
                false
            }
        } else {
            false
        };
        Ok(!outbound || cached_final || self.normal_output_room()?)
    }
    fn action_matches(&self, action: &ActionFor<F::Value>) -> bool {
        !action.finished
            && action.id.owner == self.owner
            && matches!(self.work,
            Some(Work::Issued {serial,operation,..}) if serial==action.id.serial && operation==action.operation)
    }
    fn finish_action(&mut self, action: &mut ActionFor<F::Value>) {
        action.finished = true;
        self.work = None;
    }
    fn transfer_effect(
        &mut self,
        owner: &mut control_owner::Owner,
        now: Duration,
    ) -> io::Result<bool> {
        let Some(mut effect) = self.effect.take() else {
            return Ok(false);
        };
        let result = (|| {
            let mut advanced = false;
            if effect.effects.event.is_some() && self.work.is_none() {
                let next = self
                    .next_work
                    .checked_add(1)
                    .ok_or_else(|| invalid("lifecycle work identity exhausted"))?;
                if let Some(tx::Event::Stage { ticket, config }) = &effect.effects.event {
                    let prepared = self
                        .prepared
                        .as_ref()
                        .ok_or_else(|| protocol("Stage event has no actual prepared engine"))?;
                    if prepared.ticket() != *ticket || prepared.config() != config {
                        return Err(protocol("prepared engine differs from Stage event"));
                    }
                }
                let event = effect
                    .effects
                    .event
                    .take()
                    .ok_or_else(|| protocol("lifecycle event disappeared"))?;
                self.work = Some(Work::Ready(ActionFor {
                    id: WorkId {
                        owner: self.owner,
                        serial: self.next_work,
                    },
                    operation: effect.operation,
                    event,
                    finished: false,
                }));
                self.next_work = next;
                advanced = true;
            }
            if let Some(command) = effect.effects.outbound.as_ref()
                && self.retain_output(owner, command, now, effect.emergency)?
            {
                effect.effects.outbound = None;
                advanced = true;
            }
            if effect.effects.event.is_none()
                && effect.effects.outbound.is_none()
                && effect.incoming.is_some()
                && self.acceptance.is_none()
            {
                self.acceptance = effect.incoming.take();
                advanced = true;
            }
            Ok(advanced)
        })();
        if effect.effects.event.is_some()
            || effect.effects.outbound.is_some()
            || effect.incoming.is_some()
            || result.is_err()
        {
            self.effect = Some(effect);
        }
        result
    }
    fn retain_output(
        &mut self,
        owner: &mut control_owner::Owner,
        command: &[u8],
        now: Duration,
        emergency: bool,
    ) -> io::Result<bool> {
        for output in self.outputs.iter().flatten() {
            if current_output(&self.peer, self.contract.identity.role, output, tick(now)?)?
                && output.frozen.logical_matches(&self.peer, command)?
            {
                return Ok(true);
            }
        }
        if self
            .outputs
            .iter()
            .flatten()
            .any(|output| output.frozen.token().is_none())
        {
            return Ok(false);
        }
        let count = if emergency { 3 } else { 2 };
        let Some(slot) = self.outputs[..count].iter().position(Option::is_none) else {
            return Ok(false);
        };
        let frozen = owner.freeze_transaction(&self.peer, command, now)?;
        self.outputs[slot] = Some(Output {
            frozen,
            confirmed: false,
            terminal_proof: false,
        });
        Ok(true)
    }
    fn current_output_retained(&self, now: Duration) -> io::Result<bool> {
        for output in self.outputs.iter().flatten() {
            if current_output(&self.peer, self.contract.identity.role, output, tick(now)?)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn service_outputs(
        &mut self,
        owner: &mut control_owner::Owner,
        now: Duration,
    ) -> io::Result<bool> {
        let mut advanced = false;
        for i in 0..3 {
            let Some(mut output) = self.outputs[i].take() else {
                continue;
            };
            let result = (|| {
                let current =
                    current_output(&self.peer, self.contract.identity.role, &output, tick(now)?)?;
                if output.frozen.token().is_none() {
                    if !current {
                        owner.cancel_frozen(&self.peer, &mut output.frozen, now)?;
                        return Ok((true, true));
                    }
                    return match owner.submit_frozen(&mut output.frozen, now)? {
                        control_owner::Attempt::Blocked => Ok((false, false)),
                        control_owner::Attempt::Complete(_) => Ok((false, true)),
                    };
                }
                let final_ready = output.frozen.context().is_final_reply()
                    && self.physical_terminal == Some(output.frozen.operation());
                if !output.confirmed || final_ready && !output.terminal_proof {
                    let token = output
                        .frozen
                        .token()
                        .ok_or_else(|| protocol("admitted output lost token"))?;
                    let at = tick(now)?;
                    let peer = &mut self.peer;
                    if owner.with_confirmed(token, now, |proof| {
                        if final_ready {
                            peer.complete_confirmed(proof, output.frozen.envelope(), at)
                                .map_err(protocol)?;
                        }
                        Ok(())
                    })? == control_owner::Attempt::Complete(())
                    {
                        output.confirmed = true;
                        output.terminal_proof |= final_ready;
                        advanced = true;
                    }
                }
                if output.confirmed
                    && !current_output(
                        &self.peer,
                        self.contract.identity.role,
                        &output,
                        tick(now)?,
                    )?
                {
                    owner.retire(
                        output
                            .frozen
                            .token()
                            .ok_or_else(|| protocol("confirmed output lost token"))?,
                        now,
                    )?;
                    return Ok((true, true));
                }
                Ok((false, false))
            })();
            match result {
                Ok((drop_output, changed)) => {
                    advanced |= changed;
                    if !drop_output {
                        self.outputs[i] = Some(output);
                    }
                }
                Err(error) => {
                    self.outputs[i] = Some(output);
                    self.failed = true;
                    return Err(error);
                }
            }
        }
        Ok(advanced)
    }
    fn accept(&mut self, owner: &mut control_owner::Owner, now: Duration) -> io::Result<bool> {
        let Some(incoming) = self.acceptance.as_ref() else {
            return Ok(false);
        };
        if incoming.terminal && self.physical_terminal != Some(incoming.operation) {
            return Ok(false);
        }
        let at = tick(now)?;
        let peer = &mut self.peer;
        let result = owner.with_accepted(incoming.incoming, now, |proof| {
            if incoming.terminal {
                peer.complete_accepted(proof, &incoming.envelope, at)
                    .map_err(protocol)?;
            }
            Ok(())
        });
        match result {
            Ok(control_owner::Attempt::Complete(())) => {
                self.acceptance = None;
                Ok(true)
            }
            Ok(control_owner::Attempt::Blocked) => Ok(false),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
    fn cleanup_operation(&mut self) {
        if self.peer.operation().is_none()
            && self.effect.is_none()
            && self.work.is_none()
            && self.acceptance.is_none()
            && self.pending_admission.is_none()
            && self.prepared.is_none()
            && self.outputs.iter().all(Option::is_none)
        {
            self.operation = None;
            self.physical_terminal = None;
        }
    }
}

/// Same actual Peer/custody implementation over complete common values.
pub(super) type CommonState = TransactionState<CommonFamily>;
pub(super) type CommonAction = ActionFor<l2tunnel::record_configuration::Configuration>;

impl TransactionState<CommonFamily> {
    pub(super) fn engine(&self, epoch: Epoch) -> io::Result<&l2tunnel::record_engine::Engine> {
        self.bank.engine(epoch)
    }
    pub(super) fn entry(&mut self, epoch: Epoch) -> io::Result<l2tunnel::record_bank::Entry<'_>> {
        self.bank.entry(epoch)
    }
    pub(super) fn usage(&self) -> l2tunnel::record_bank::storage::Usage {
        self.bank.usage()
    }
}

fn current_output<C: tx::Configuration>(
    peer: &tx::Peer<C>,
    role: mg::Role,
    output: &Output,
    now: tx::Tick,
) -> io::Result<bool> {
    let Some(operation) = peer.operation() else {
        return Ok(false);
    };
    if operation != output.frozen.operation() {
        return Err(protocol("output belongs to another actual operation"));
    }
    let context = match peer.outbound_context(output.frozen.command()) {
        Ok(context) => context,
        Err(tx::Error::Custody) => return Ok(false),
        Err(error) => return Err(protocol(error)),
    };
    if context != output.frozen.context() {
        return Err(protocol("retained output context changed"));
    }
    if role == mg::Role::Server {
        let cached = peer
            .cached_retry_authority(now)
            .map_err(protocol)?
            .ok_or_else(|| protocol("current reply lost actual cached authority"))?;
        if cached.operation() != operation
            || cached.reply_request() != context.request()
            || cached.reply_kind() != context.kind()
        {
            return Err(protocol(
                "reply differs from actual cached logical authority",
            ));
        }
    }
    Ok(true)
}
fn management_kind_for<C: tx::Configuration>(bytes: &[u8]) -> io::Result<mg::MessageKind> {
    let envelope = sc::Envelope::decode(
        bytes,
        sc::Limits {
            max_frame_bytes: 65_536,
            max_management_bytes: 65_536 - sc::HEADER_BYTES,
            max_feedback_bytes: 1,
        },
    )
    .map_err(protocol)?;
    let sc::Body::Management(command) = envelope.body else {
        return Err(protocol("nonmanagement Transaction view"));
    };
    Ok(
        mg::Frame::decode(command, tx::configuration_limits::<C>().map_err(protocol)?)
            .map_err(protocol)?
            .header
            .kind,
    )
}
fn tick(now: Duration) -> io::Result<tx::Tick> {
    u64::try_from(now.as_millis())
        .map(tx::Tick)
        .map_err(invalid)
}
fn duration(at: tx::Tick) -> Duration {
    Duration::from_millis(at.0)
}
fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
fn protocol(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn unreachable_result<T>() -> io::Result<T> {
    Err(protocol("unreachable guarded transaction result"))
}

#[cfg(test)]
#[path = "transport_transaction_common_tests.rs"]
mod common_tests;
