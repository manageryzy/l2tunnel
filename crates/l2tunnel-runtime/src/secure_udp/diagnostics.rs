//! Fixed-size setup observations, independent of protocol authority and error text.

use super::establish;
use l2tunnel_handshake as hs;
use l2tunnel_recovery::RecoveryError;
use l2tunnel_udp_control as gate;

/// Actual setup owner currently executing; authentication is not device readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Local carrier, credential and fixed-path construction.
    Configuration,
    /// Bounded return-path cookie admission.
    Admission,
    /// Maintained Noise exchange and reliable bootstrap custody.
    Noise,
    /// Existing-member possession proof and authenticated acceptance.
    Membership,
}

/// Static failure class, never inferred from a provider's formatted message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// Original caller operation deadline expired.
    OriginalDeadline,
    /// The original bootstrap or Noise lifetime expired.
    BootstrapDeadline,
    /// The member identity lifetime expired.
    MembershipDeadline,
    /// Finite Hello/Echo emissions were exhausted.
    AdmissionAttempts,
    /// Reliable bootstrap retransmissions were exhausted.
    BootstrapAttempts,
    /// Exact Joining-flight emissions were exhausted.
    JoiningAttempts,
    /// Trusted configuration or identity binding was rejected.
    Configuration,
    /// The explicitly supplied entropy source failed.
    Entropy,
    /// An actual cryptographic or member-allowlist verification rejected input.
    Authentication,
    /// An authenticated protocol/state/length contract was violated.
    Protocol,
    /// Selected appearance construction failed.
    Cover,
    /// Native I/O failed; its actual category remains the caller's error.
    LocalIo,
    /// A maintained cryptographic API or protection construction failed.
    Crypto,
    /// A bounded retention or sequence window was exhausted.
    Capacity,
    /// Counter or key-use space was exhausted.
    CounterExhausted,
    /// Injected monotonic time or its conversion was invalid.
    Clock,
    /// No more specific typed class was observed.
    Unknown,
}

/// Latest fixed-size observations; absent owners are unknown, never zero defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    /// Actual local setup stage.
    pub stage: Stage,
    /// A typed failure hint; operation completion remains the service's authority.
    pub reason: Option<Reason>,
    /// Per-attempt bootstrap accounting, once its owner exists.
    pub bootstrap: Option<establish::Statistics>,
    /// Current bootstrap-control counters and retained-byte gauges.
    pub control: Option<gate::ControlStatistics>,
    /// Cumulative retained server-admission accounting, not per-attempt counters.
    pub server_gate: Option<gate::GateStatistics>,
    /// Actual local Joining emission attempts, once constructed.
    pub member_attempts: Option<u32>,
}
impl Observation {
    /// An actual stage with no invented counters or failure classification.
    pub const fn new(stage: Stage) -> Self {
        Self {
            stage,
            reason: None,
            bootstrap: None,
            control: None,
            server_gate: None,
            member_attempts: None,
        }
    }
}

/// Synchronous bounded observation sink; it is never a protocol input.
pub type Observer<'a> = dyn FnMut(Observation) + Send + 'a;

pub(super) struct Reporter<'a, 'b> {
    sink: &'a mut Observer<'b>,
    current: Observation,
}
impl<'a, 'b> Reporter<'a, 'b> {
    pub(super) fn new(sink: &'a mut Observer<'b>) -> Self {
        Self::at(sink, Stage::Configuration)
    }
    pub(super) fn at(sink: &'a mut Observer<'b>, stage: Stage) -> Self {
        let mut result = Self {
            sink,
            current: Observation::new(stage),
        };
        result.publish();
        result
    }
    pub(super) fn stage(&mut self, stage: Stage) {
        self.current.stage = stage;
        self.current.reason = None;
        self.publish();
    }
    pub(super) fn bootstrap(
        &mut self,
        statistics: establish::Statistics,
        control: Option<gate::ControlStatistics>,
    ) {
        self.current.bootstrap = Some(statistics);
        self.current.control = control;
        self.publish();
    }
    pub(super) fn server(&mut self, statistics: gate::GateStatistics) {
        self.current.server_gate = Some(statistics);
        self.publish();
    }
    pub(super) fn member(&mut self, attempts: u32) {
        self.current.member_attempts = Some(attempts);
        self.publish();
    }
    pub(super) fn reason(&mut self, reason: Reason) {
        self.current.reason = Some(reason);
        self.publish();
    }
    pub(super) fn fail(&mut self, fallback: Reason) {
        if self.current.reason.is_none() {
            self.current.reason = Some(fallback);
        }
        self.publish();
    }
    pub(super) fn publish(&mut self) {
        (self.sink)(self.current);
    }
}

/// Classify an actual typed establishment error without formatting its contents.
pub fn establishment_reason(error: &establish::Error) -> Reason {
    match error {
        establish::Error::Configuration(_) => Reason::Configuration,
        establish::Error::Deadline => Reason::OriginalDeadline,
        establish::Error::Entropy => Reason::Entropy,
        establish::Error::Protocol | establish::Error::OutputTooSmall => Reason::Protocol,
        establish::Error::Gate(error) => match error {
            gate::Error::Expired => Reason::BootstrapDeadline,
            gate::Error::RetryExhausted => Reason::AdmissionAttempts,
            gate::Error::Recovery(error) => match error {
                RecoveryError::RetryExhausted { .. } => Reason::BootstrapAttempts,
                RecoveryError::InvalidConfig => Reason::Configuration,
                RecoveryError::Capacity(_) | RecoveryError::SequenceWindow => Reason::Capacity,
                RecoveryError::CounterExhausted => Reason::CounterExhausted,
                RecoveryError::NonMonotonicTime | RecoveryError::TimeOverflow => Reason::Clock,
                _ => Reason::Protocol,
            },
            gate::Error::Nonce => Reason::Entropy,
            gate::Error::Authentication => Reason::Authentication,
            gate::Error::Crypto => Reason::Crypto,
            gate::Error::Capacity => Reason::Capacity,
            gate::Error::CounterExhausted => Reason::CounterExhausted,
            gate::Error::TimeRegression | gate::Error::TimeOverflow => Reason::Clock,
            gate::Error::Configuration => Reason::Configuration,
            _ => Reason::Protocol,
        },
        establish::Error::Noise(error) => match error {
            hs::Error::Authentication => Reason::Authentication,
            hs::Error::Configuration => Reason::Configuration,
            hs::Error::Entropy => Reason::Entropy,
            hs::Error::Deadline => Reason::BootstrapDeadline,
            hs::Error::Crypto | hs::Error::Protection => Reason::Crypto,
            _ => Reason::Protocol,
        },
        establish::Error::Refresh(error) => refresh_reason(*error),
        establish::Error::Cover(_) => Reason::Cover,
        establish::Error::Io(_) => Reason::LocalIo,
    }
}

/// Classify selected initial custody without public metadata or error strings.
pub fn refresh_reason(error: hs::refresh::Error) -> Reason {
    use l2tunnel_security::refresh::Error as Refresh;
    match error {
        hs::refresh::Error::Credentials => Reason::Authentication,
        hs::refresh::Error::Handshake(error) => {
            establishment_reason(&establish::Error::Noise(error))
        }
        hs::refresh::Error::Security(error) => match error {
            Refresh::Configuration | Refresh::Context | Refresh::Mode | Refresh::Domains => {
                Reason::Configuration
            }
            Refresh::TimeRegression => Reason::Clock,
            Refresh::Deadline | Refresh::KeyExpired => Reason::OriginalDeadline,
            Refresh::EpochExhausted => Reason::CounterExhausted,
            Refresh::CopiesExhausted | Refresh::Allocation => Reason::Capacity,
            Refresh::Protection(error) => match error {
                l2tunnel_security::Error::Crypto => Reason::Crypto,
                l2tunnel_security::Error::CounterExhausted
                | l2tunnel_security::Error::KeyUsageExhausted => Reason::CounterExhausted,
                l2tunnel_security::Error::Authentication => Reason::Authentication,
                _ => Reason::Protocol,
            },
            _ => Reason::Protocol,
        },
    }
}
