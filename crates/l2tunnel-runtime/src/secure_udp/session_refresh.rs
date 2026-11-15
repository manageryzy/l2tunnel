//! Same-owner fresh-DH scheduling over explicitly selected reliable Lifecycle.
//!
//! Records and the maintained Noise exchange remain the authentication and key
//! state owners. This adapter retains their real guards and original message
//! custody; it owns no socket, packet counter, replay window or second FSM.

use super::{control, establish};
use l2tunnel::{cover, handshake as hs, secure_record as record, security};
use l2tunnel_management::{control_streams as streams, session_control as sc};
use std::{io, time::Duration};

use hs::refresh::{ConfirmationCache, Exchange, Selection};
use security::refresh::{self as sec, Activation, KeyEpoch, Prepared};
use streams::v2::{Lifecycle, LifecycleKind};

const OUTPUTS: usize = 4;
const NOISE_BYTES: usize = sec::REQUEST_BYTES + hs::MAX_FLIGHT_BYTES;
const HEADER_BYTES: usize = streams::v2::LIFECYCLE_HEADER_BYTES;

/// Explicit local scheduling limits, authenticated by the selected runtime contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Retry admission or observe actual whole-message confirmation at this cadence.
    pub retry_interval: Duration,
    /// Minimum interval between distinct locally initiated refresh attempts.
    pub min_attempt_interval: Duration,
    /// Maximum distinct local or remote refresh admissions during this session.
    pub max_attempts: u32,
    /// Maximum bounded scheduling steps per service invocation.
    pub work_per_turn: usize,
}

impl Settings {
    fn validate(self) -> io::Result<()> {
        if self.retry_interval.is_zero()
            || self.min_attempt_interval.is_zero()
            || self.max_attempts == 0
            || !(1..=4096).contains(&self.work_per_turn)
        {
            return Err(invalid("invalid explicit refresh scheduling limits"));
        }
        if micros(self.retry_interval)? == 0 || micros(self.min_attempt_interval)? == 0 {
            return Err(invalid(
                "refresh scheduling intervals need whole microseconds",
            ));
        }
        Ok(())
    }
}

/// Runtime-owned reusable provisioning, never an import from public session Info.
/// Each returned credential is consumed and independently checked by Admission.
pub trait Credentials: Send {
    /// Return the explicitly provisioned original own key, peer pin and optional PSK.
    fn provide(&mut self) -> io::Result<establish::Identity>;
}

impl<F> Credentials for F
where
    F: FnMut() -> io::Result<establish::Identity> + Send,
{
    fn provide(&mut self) -> io::Result<establish::Identity> {
        self()
    }
}

/// Caller-owned scratch, independent of any retained sealed User output.
pub(crate) struct Scratch<'a> {
    pub(crate) seal: &'a mut [u8],
    pub(crate) packet: &'a mut [u8],
}

/// Bounded non-secret observations, never authority to install or retire keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Distinct admissions, including an attempt whose credentials later fail.
    pub attempts: u32,
    /// Actual retained admitted target, if any.
    pub target: Option<KeyEpoch>,
    /// Immutable cap returned by the actual Records admission.
    pub original_deadline: Option<Duration>,
    /// Actual local activation result, absent before Records activates.
    pub activation: Option<Activation>,
    /// Actual nested peer activation was authenticated by Records.
    pub peer_activation: bool,
    /// Messages whose semantic custody has not yet been proved Confirmed.
    pub unconfirmed: usize,
    /// Targets actually retired by Records after all required local custody.
    pub completed: u64,
    /// Actual nested protected outputs, so the caller advances its outer metadata
    /// counter only after a successful inner seal (not for ordinary service work).
    pub protected_outputs: u64,
}

struct Output {
    bytes: Vec<u8>,
    length: usize,
    token: Option<control::Token>,
    confirmed: bool,
    retry_at: Duration,
}
impl Output {
    fn new(capacity: usize) -> io::Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        if bytes.capacity() != capacity {
            return Err(invalid("refresh output reservation differs from layout"));
        }
        bytes.resize(capacity, 0);
        Ok(Self {
            bytes,
            length: 0,
            token: None,
            confirmed: false,
            retry_at: Duration::ZERO,
        })
    }

    fn fill(&mut self, kind: LifecycleKind, bytes: &[u8], now: Duration) -> io::Result<()> {
        if self.length != 0 {
            return Err(invalid("refresh logical output already exists"));
        }
        self.length = Lifecycle { kind, bytes }
            .encode(&mut self.bytes, sc::MAX_LIFECYCLE_BYTES)
            .map_err(protocol)?;
        self.retry_at = now;
        Ok(())
    }

    fn clear(&mut self) {
        self.length = 0;
        self.token = None;
        self.confirmed = false;
        self.retry_at = Duration::ZERO;
    }
}

struct Received {
    bytes: [u8; NOISE_BYTES],
    length: usize,
}
impl Received {
    const fn new() -> Self {
        Self {
            bytes: [0; NOISE_BYTES],
            length: 0,
        }
    }
}

struct Operation {
    target: KeyEpoch,
    cap: Duration,
    activation: Option<Activation>,
    peer_activation: bool,
}

/// Actual exchange/key guards and fixed output custody for one selected session.
/// Managed output capacity excludes maintained-Noise allocations, inline Self,
/// the externally retained credential provider and the real Control/Records owners.
pub(crate) struct Controller {
    settings: Settings,
    selection: Selection,
    now: Duration,
    expires: Duration,
    next_attempt: Duration,
    attempts: u32,
    completed: u64,
    protected_outputs: u64,
    operation: Option<Operation>,
    exchange: Option<Exchange>,
    prepared: Option<Prepared>,
    confirmation: Option<ConfirmationCache>,
    received: [Received; 2],
    outputs: [Output; OUTPUTS],
    cursor: usize,
    seal_bytes: usize,
    packet_bytes: usize,
    failed: bool,
}

impl Controller {
    /// Reserve all four actual output slots before publishing this controller.
    /// Selection is checked again against the actual minted Admission, never
    /// accepted as authentication evidence for the supplied Records owner.
    pub(crate) fn new(
        settings: Settings,
        selection: Selection,
        records: &record::Records,
        now: Duration,
        session_expires: Duration,
    ) -> io::Result<Self> {
        settings.validate()?;
        micros(now)?;
        micros(session_expires)?;
        records.key_epoch().map_err(protocol)?;
        let s = selection.spec();
        let scope = records.control_scope();
        if now >= session_expires
            || scope.epoch != s.control_epoch
            || scope.configuration != s.control_digest
        {
            return Err(invalid("refresh context or original session cap differs"));
        }
        let capacity = records.capacity(88).map_err(protocol)?;
        let packet_bytes = capacity.packet_bytes.max(NOISE_BYTES);
        let output_bytes = packet_bytes
            .checked_add(HEADER_BYTES)
            .filter(|bytes| *bytes <= sc::MAX_LIFECYCLE_BYTES)
            .ok_or_else(|| invalid("refresh Lifecycle output does not fit"))?;
        Ok(Self {
            settings,
            selection,
            now,
            expires: session_expires,
            next_attempt: now,
            attempts: 0,
            completed: 0,
            protected_outputs: 0,
            operation: None,
            exchange: None,
            prepared: None,
            confirmation: None,
            received: [Received::new(), Received::new()],
            outputs: [
                Output::new(output_bytes)?,
                Output::new(output_bytes)?,
                Output::new(output_bytes)?,
                Output::new(output_bytes)?,
            ],
            cursor: 0,
            seal_bytes: capacity.seal_workspace_bytes,
            packet_bytes,
            failed: false,
        })
    }

    /// Actual retained managed heap, with all four output backing stores once.
    pub(crate) fn capacity_bytes(&self) -> usize {
        self.outputs
            .iter()
            .map(|output| output.bytes.capacity())
            .sum()
    }

    pub(crate) fn scratch_bytes(&self) -> (usize, usize) {
        (self.seal_bytes, self.packet_bytes)
    }

    pub(crate) fn status(&self) -> Status {
        Status {
            attempts: self.attempts,
            target: self.operation.as_ref().map(|operation| operation.target),
            original_deadline: self.operation.as_ref().map(|operation| operation.cap),
            activation: self
                .operation
                .as_ref()
                .and_then(|operation| operation.activation),
            peer_activation: self
                .operation
                .as_ref()
                .is_some_and(|operation| operation.peer_activation),
            unconfirmed: self
                .outputs
                .iter()
                .filter(|output| output.length != 0 && !output.confirmed)
                .count(),
            completed: self.completed,
            protected_outputs: self.protected_outputs,
        }
    }

    pub(crate) fn next_deadline(&self) -> Duration {
        let Some(operation) = &self.operation else {
            return self.expires;
        };
        let mut deadline = operation.cap.min(self.expires);
        if self
            .exchange
            .as_ref()
            .is_some_and(|exchange| exchange.is_complete() || exchange.next_flight().is_some())
            || (self.prepared.is_some()
                && self.outputs[2].confirmed
                && operation.activation.is_none())
        {
            deadline = deadline.min(self.now);
        }
        for output in &self.outputs {
            if output.length != 0 && !output.confirmed {
                deadline = deadline.min(output.retry_at);
            }
        }
        if let Some(activation) = operation.activation
            && operation.peer_activation
            && self.all_confirmed()
        {
            deadline = deadline.min(duration(activation.overlap_until));
        }
        deadline
    }

    fn check(&mut self, now: Duration) -> io::Result<hs::Time> {
        if self.failed {
            return Err(protocol("refresh controller is terminal"));
        }
        if now < self.now
            || now >= self.expires
            || self
                .operation
                .as_ref()
                .is_some_and(|operation| now >= operation.cap)
        {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original refresh time bound reached",
            ));
        }
        let time = hs::Time(micros(now)?);
        self.now = now;
        Ok(time)
    }

    fn preflight(&self, scratch: &Scratch<'_>) -> io::Result<()> {
        if scratch.seal.len() < self.seal_bytes || scratch.packet.len() < self.packet_bytes {
            return Err(invalid("refresh shared scratch is too small"));
        }
        Ok(())
    }

    fn admit(
        &mut self,
        admission: sec::Admission,
        now: Duration,
        credentials: &mut dyn Credentials,
        entropy: &mut impl hs::Entropy,
    ) -> io::Result<()> {
        // Only local begin applies a local start-rate timer. Network delay may
        // compress remote request arrival intervals without violating the
        // initiator's original timer; shared Control quotas still bound ingress.
        if self.operation.is_some()
            || self.attempts >= self.settings.max_attempts
            || admission.selection() != self.selection
        {
            return Err(protocol("refresh admission exceeds the selected contract"));
        }
        let cap = duration(admission.deadline());
        let target = admission.target();
        self.next_attempt = now
            .checked_add(self.settings.min_attempt_interval)
            .ok_or_else(|| invalid("refresh attempt interval overflows"))?;
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or_else(|| invalid("refresh attempt count exhausted"))?;
        self.operation = Some(Operation {
            target,
            cap,
            activation: None,
            peer_activation: false,
        });
        let identity = credentials
            .provide()
            .map_err(|error| io::Error::new(error.kind(), "refresh credentials unavailable"))?;
        self.exchange = Some(
            Exchange::new(
                admission,
                identity.local,
                identity.peer,
                identity.psk,
                hs::Time(micros(now)?),
                entropy,
            )
            .map_err(protocol)?,
        );
        Ok(())
    }

    /// Begin only through the actual initiator Records authority. False means
    /// no attempt was admitted; no selector/message identity is consumed then.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin(
        &mut self,
        records: &mut record::Records,
        control: &mut control::Owner,
        now: Duration,
        original_cap: Duration,
        outer: cover::PacketMeta,
        credentials: &mut dyn Credentials,
        entropy: &mut impl hs::Entropy,
        scratch: &mut Scratch<'_>,
    ) -> io::Result<bool> {
        let time = self.check(now)?;
        self.preflight(scratch)?;
        if self.operation.is_some()
            || now < self.next_attempt
            || self.attempts >= self.settings.max_attempts
        {
            return Ok(false);
        }
        let started = records
            .begin_refresh(time, hs::Time(micros(original_cap)?))
            .map_err(protocol)?;
        self.admit(started.admission, now, credentials, entropy)?;
        let sealed = records
            .seal_refresh_request(&started.request, time, outer, scratch.seal, scratch.packet)
            .map_err(protocol)?;
        // At most two protected outputs per checked u32 admission count.
        self.protected_outputs += 1;
        self.outputs[0].fill(LifecycleKind::Request, &scratch.packet[..sealed.bytes], now)?;
        self.service(records, control, now, outer, scratch)?;
        Ok(true)
    }

    /// Consume a real Gate-presented Lifecycle envelope. A parsed body alone
    /// cannot mint responder admission or prove fresh-key activation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch(
        &mut self,
        records: &mut record::Records,
        control: &mut control::Owner,
        incoming: control::Incoming,
        body: &[u8],
        now: Duration,
        responder_original_cap: Duration,
        credentials: &mut dyn Credentials,
        entropy: &mut impl hs::Entropy,
        scratch: &mut Scratch<'_>,
    ) -> io::Result<()> {
        let time = self.check(now)?;
        self.preflight(scratch)?;
        if incoming.stream != Some(streams::Stream::Lifecycle) {
            return Err(protocol("refresh dispatch is not Lifecycle custody"));
        }
        let frame = Lifecycle::decode(body, sc::MAX_LIFECYCLE_BYTES).map_err(protocol)?;
        match frame.kind {
            LifecycleKind::Request => {
                match records
                    .open_refresh_request(
                        frame.bytes,
                        time,
                        hs::Time(micros(responder_original_cap)?),
                        scratch.seal,
                    )
                    .map_err(protocol)?
                {
                    sec::RequestOutcome::New(admission) => {
                        self.admit(admission, now, credentials, entropy)?
                    }
                    sec::RequestOutcome::Duplicate => {}
                }
            }
            LifecycleKind::NoiseFlight => {
                if let Some(exchange) = &mut self.exchange {
                    exchange.read(time, frame.bytes).map_err(protocol)?;
                    self.remember(frame.bytes)?;
                    self.prepare_completed(records, time)?;
                } else if !self.received.iter().any(|received| {
                    received.length == frame.bytes.len()
                        && received.length != 0
                        && &received.bytes[..received.length] == frame.bytes
                }) {
                    return Err(protocol("uncached Noise flight after exchange handoff"));
                }
            }
            LifecycleKind::Activation => {
                records
                    .open_refresh_activation(frame.bytes, time, scratch.seal)
                    .map_err(protocol)?;
                self.operation
                    .as_mut()
                    .ok_or_else(|| protocol("activation has no admitted exchange"))?
                    .peer_activation = true;
            }
        }
        control.accepted(incoming, now)
    }

    fn remember(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.received.iter().any(|received| {
            received.length == bytes.len() && &received.bytes[..received.length] == bytes
        }) {
            return Ok(());
        }
        let received = self
            .received
            .iter_mut()
            .find(|received| received.length == 0)
            .ok_or_else(|| protocol("too many distinct authenticated Noise flights"))?;
        let target = received
            .bytes
            .get_mut(..bytes.len())
            .ok_or_else(|| protocol("authenticated Noise flight exceeds fixed bound"))?;
        target.copy_from_slice(bytes);
        received.length = bytes.len();
        Ok(())
    }

    fn prepare_completed(
        &mut self,
        records: &mut record::Records,
        now: hs::Time,
    ) -> io::Result<bool> {
        if !self.exchange.as_ref().is_some_and(Exchange::is_complete) {
            return Ok(false);
        }
        let completed = self
            .exchange
            .take()
            .ok_or_else(|| protocol("missing complete exchange"))?
            .finish_with_confirmation(now)
            .map_err(protocol)?;
        self.prepared = Some(
            records
                .prepare_refresh(completed.material, now)
                .map_err(protocol)?,
        );
        self.confirmation = Some(completed.confirmation);
        Ok(true)
    }

    /// Bounded custody/admission work. Physical Control emission remains solely
    /// with the existing Driver loop and the same crypto/socket owner.
    pub(crate) fn service(
        &mut self,
        records: &mut record::Records,
        control: &mut control::Owner,
        now: Duration,
        outer: cover::PacketMeta,
        scratch: &mut Scratch<'_>,
    ) -> io::Result<bool> {
        let time = self.check(now)?;
        self.preflight(scratch)?;
        let mut progress = false;
        for _ in 0..self.settings.work_per_turn {
            if !self.step(records, control, now, time, outer, scratch)? {
                break;
            }
            progress = true;
        }
        Ok(progress)
    }

    fn step(
        &mut self,
        records: &mut record::Records,
        control: &mut control::Owner,
        now: Duration,
        time: hs::Time,
        outer: cover::PacketMeta,
        scratch: &mut Scratch<'_>,
    ) -> io::Result<bool> {
        let Some(operation) = &self.operation else {
            return Ok(false);
        };
        let cap = operation.cap;
        // One immutable logical message per output. None retains the same bytes;
        // Some retains its exact token through all ARQ/whole-receipt retries.
        for offset in 0..OUTPUTS {
            let i = (self.cursor + offset) % OUTPUTS;
            let output = &mut self.outputs[i];
            if output.length == 0 || output.confirmed || now < output.retry_at {
                continue;
            }
            self.cursor = (i + 1) % OUTPUTS;
            output.retry_at = now
                .checked_add(self.settings.retry_interval)
                .ok_or_else(|| invalid("refresh retry deadline overflows"))?
                .min(cap);
            match output.token {
                None => {
                    output.token =
                        control.submit_lifecycle(&output.bytes[..output.length], now, cap)?;
                }
                Some(token) => {
                    if control.confirmed(token, now)? {
                        control.retire(token, now)?;
                        output.confirmed = true;
                    }
                }
            }
            return Ok(true);
        }
        if self.prepare_completed(records, time)? {
            return Ok(true);
        }
        if let Some(exchange) = &mut self.exchange
            && let Some(kind) = exchange.next_flight()
        {
            let i = if kind == hs::FlightKind::Confirmation {
                2
            } else {
                1
            };
            if self.outputs[i].length != 0 {
                return Err(protocol(
                    "Noise emitted a second logical flight in one slot",
                ));
            }
            let flight = exchange.write(time, scratch.packet).map_err(protocol)?;
            self.outputs[i].fill(
                LifecycleKind::NoiseFlight,
                &scratch.packet[..flight.bytes],
                now,
            )?;
            // Completion can occur on our final write as well as on read.
            // Install receive keys before this output may be admitted and
            // remotely confirmed, even with work_per_turn exactly one.
            self.prepare_completed(records, time)?;
            return Ok(true);
        }
        // Whole final-confirmation proof means the peer semantically read it.
        // dispatch prepares its real keys before accepting that message, so
        // new-key outer Control cannot overtake the material needed to open it.
        if let Some(prepared) = &self.prepared
            && self.outputs[2].confirmed
            && self
                .operation
                .as_ref()
                .is_some_and(|op| op.activation.is_none())
        {
            let activation = records.activate_refresh(prepared, time).map_err(protocol)?;
            self.operation
                .as_mut()
                .ok_or_else(|| protocol("missing active exchange"))?
                .activation = Some(activation);
            let sealed = records
                .seal_refresh_activation(time, outer, scratch.seal, scratch.packet)
                .map_err(protocol)?;
            self.protected_outputs += 1;
            self.outputs[3].fill(
                LifecycleKind::Activation,
                &scratch.packet[..sealed.bytes],
                now,
            )?;
            return Ok(true);
        }
        if let Some(operation) = &self.operation
            && let Some(activation) = operation.activation
            && operation.peer_activation
            && self.all_confirmed()
            && now >= duration(activation.overlap_until)
        {
            records
                .retire_refresh(operation.target, time)
                .map_err(protocol)?;
            self.completed = self
                .completed
                .checked_add(1)
                .ok_or_else(|| invalid("refresh completion counter exhausted"))?;
            self.clear();
            return Ok(true);
        }
        Ok(false)
    }

    fn all_confirmed(&self) -> bool {
        self.outputs
            .iter()
            .all(|output| output.length == 0 || output.confirmed)
    }

    /// Exact preactivation cancellation delegates the real rollback guard.
    /// An authenticated peer activation/new-key receive already forbids abort.
    pub(crate) fn abort(&mut self, records: &mut record::Records, now: Duration) -> io::Result<()> {
        let time = self.check(now)?;
        let target = self
            .operation
            .as_ref()
            .ok_or_else(|| invalid("no refresh to abort"))?
            .target;
        // A submitted logical message may still cause peer-visible effects;
        // this adapter does not discard its unresolved reliable custody.
        if self
            .outputs
            .iter()
            .any(|output| output.token.is_some() && !output.confirmed)
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "refresh message custody is unresolved",
            ));
        }
        records.abort_refresh(target, time).map_err(protocol)?;
        self.clear();
        Ok(())
    }

    fn clear(&mut self) {
        self.operation = None;
        self.exchange = None;
        self.prepared = None;
        self.confirmation = None;
        for received in &mut self.received {
            received.length = 0;
        }
        for output in &mut self.outputs {
            output.clear();
        }
    }
}

fn micros(time: Duration) -> io::Result<u64> {
    u64::try_from(time.as_micros()).map_err(|_| invalid("refresh time conversion overflows"))
}
fn duration(time: sec::Tick) -> Duration {
    Duration::from_micros(time.0)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn protocol(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
#[path = "session_refresh_tests.rs"]
mod tests;
