//! Functional composition of the actual queue and existing record algorithms.
//!
//! Authentication, replay, connection pacing and physical device completion stay
//! with the caller. This explicit comparison owner is not a reserved runtime or
//! a mixed-generation transaction bank. It never selects a carrier or clock.

use crate::record_configuration as configuration;
use l2tunnel_aligned as aligned;
use l2tunnel_codec::aligned_receiver as receiver;
use l2tunnel_core::{ConfigDigest, traffic::TcpControl};
use l2tunnel_management::Role;
use l2tunnel_pipeline as pipeline;
use l2tunnel_reliable::OutboundBudget;
use l2tunnel_swift as swift;
use std::{fmt, time::Duration};

#[cfg(test)]
mod errors_tests;
mod native;
mod owner;
#[cfg(test)]
mod tests;
use owner::Owner;

/// Caller-injected monotonic microseconds, with no real-clock dependency.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Tick(pub u64);

/// Trusted local origin labels; this value confers no authentication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    /// Nonzero logical session identifier.
    pub session: u128,
    /// Nonzero negotiated record epoch.
    pub epoch: u64,
    /// Local role, used for exact global-direction projection.
    pub role: Role,
}

/// Full-wire bytes outside each directional record, supplied by the carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    /// Client-to-server protection and complete underlay overhead.
    pub forward_overhead_bytes: usize,
    /// Server-to-client protection and complete underlay overhead.
    pub reverse_overhead_bytes: usize,
}

/// Native custody policy to bind into the external authenticated envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLimits {
    /// Positive maximum age after the first native preparation.
    pub stall_micros: u64,
}

/// Actual original native identity; unrelated sequence spaces remain distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileIdentity {
    /// Swift native-only channel/record identity.
    Swift(swift::records::NativeIdentity),
    /// Aligned body identity; context records also occupy its record space.
    Aligned(receiver::RecordIdentity),
    /// Packed body identity, retaining its original ordered channel.
    Packed(receiver::RecordIdentity),
}

/// Actual source-producing branch, without authentication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceForm {
    /// Swift source or retransmission.
    Swift,
    /// Direct selective-repeat source.
    DirectArq,
    /// FEC systematic vector containing the original source.
    SystematicFec,
}

/// Actual outer record kind, checked against the maintained profile parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmissionKind {
    /// Original source copy from the named actual branch.
    Source(SourceForm),
    /// Recovery equation.
    Repair,
    /// Receiver feedback, serviced even with data disabled.
    Feedback,
}

/// Exact output metadata; retain it and the output bytes through WouldBlock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Emission {
    /// Initialized inner record bytes in the caller's output.
    pub bytes: usize,
    /// Actual producing branch.
    pub kind: EmissionKind,
    /// Complete wire charge, including the exact configured overhead once.
    pub wire_bytes: usize,
    /// Unchanged enclosing full-width security number.
    pub security_number: u64,
    /// Initialized native-unit witnesses; Swift has none available here.
    pub witnesses: usize,
}

/// Explicit capability refusal; representation does not install these owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    /// Actual Active/tunnel-credit owner is required.
    TunnelCredits,
    /// Actual TCP leg ownership is required.
    TcpProxy,
    /// Actual native delivery-window owner is required.
    NativeWindow,
}

/// Configuration, caller-contract or authoritative owner failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid complete configuration or local binding.
    Configuration,
    /// Exact overhead, path-MTU or burst geometry disagrees.
    Geometry,
    /// A represented capability has no actual owner in this composition.
    Unsupported(Capability),
    /// Injected time moved backwards or cannot fit the underlying time domain.
    Time,
    /// Checked local counter, deadline or byte arithmetic exhausted.
    Arithmetic,
    /// Caller output must hold the actual maximum before consuming an owner.
    Output {
        /// Minimum caller-owned buffer length.
        required: usize,
    },
    /// Caller witness space must hold the selected profile's maximum.
    Witnesses {
        /// Maximum selected-profile witness count.
        required: usize,
    },
    /// Native packet or authenticated record length is outside actual bounds.
    PacketSize,
    /// Claimed kind differs from the authoritative record grammar.
    Kind,
    /// Positive bounded native preparation work is required.
    Work,
    /// Original immutable native custody deadline expired.
    Expired,
    /// Local completion token is absent, stale or belongs to another handoff.
    Token,
    /// Actual queue or composed owner invariants disagree.
    Invariant,
    /// Actual common queue failure.
    Pipeline(pipeline::PipelineError),
    /// Actual maintained Swift record failure.
    Swift(swift::records::Error),
    /// Actual Swift backing failure.
    Storage(swift::storage::Error),
    /// Actual Aligned/Packed record failure.
    Aligned(aligned::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "common record engine: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Enqueue refusal retains the original caller allocation and bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct EnqueueError {
    /// Typed refusal, with no codec admission.
    pub kind: Error,
    /// Unchanged original packet.
    pub payload: Vec<u8>,
}
impl fmt::Display for EnqueueError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(output)
    }
}
impl std::error::Error for EnqueueError {}

/// Qualification of this explicitly selected comparison implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Qualification {
    /// Real queues and algorithms, without complete reserved/runtime qualification.
    Functional,
}

/// Local observations, never substitutes for transaction drain fences.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Original native packets actually admitted by the selected profile.
    pub admitted: u64,
    /// Actual numbered output records produced.
    pub emitted: u64,
    /// Native packets extracted/prepared before physical device acceptance.
    pub prepared: u64,
    /// Whole native writes acknowledged by the trusted caller exactly once.
    pub committed: u64,
}

/// Local, non-authenticating token for one immutable prepared native packet.
///
/// It is meaningful only with its issuing Engine. A future generation bank must
/// additionally bind its own unique set/generation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeToken {
    context: Context,
    digest: ConfigDigest,
    serial: u64,
    identity: ProfileIdentity,
}

/// Immutable metadata for the caller-owned output slot retained through I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedNative {
    token: NativeToken,
    bytes: usize,
    early: bool,
    deadline: Tick,
}
impl PreparedNative {
    /// Exact token to commit after whole-frame physical acceptance.
    pub const fn token(self) -> NativeToken {
        self.token
    }
    /// Original profile identity, separate from the local cursor.
    pub const fn identity(self) -> ProfileIdentity {
        self.token.identity
    }
    /// Exact initialized native bytes in the retained caller output slot.
    pub const fn bytes(self) -> usize {
        self.bytes
    }
    /// Whether the real receiver used its permitted early-delivery path.
    pub const fn early(self) -> bool {
        self.early
    }
    /// Original, nonrenewable latest completion time.
    pub const fn deadline(self) -> Tick {
        self.deadline
    }
}

/// Result of finite native preparation without a hidden adapter payload queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePreparation {
    /// No eligible native record on the visited channel.
    Idle,
    /// The maintained receiver consumed context/tombstone work.
    Progress,
    /// Actual new immutable bytes have been copied into the caller's slot.
    Ready(PreparedNative),
    /// A previous slot still has custody; this call did not overwrite output.
    AlreadyPending(PreparedNative),
}

enum NativeStep {
    Idle,
    Progress,
    Ready {
        identity: ProfileIdentity,
        bytes: usize,
        early: bool,
    },
}

/// One actual shared queue plus exactly one selected actual duplex record owner.
pub struct Engine {
    configuration: configuration::Configuration,
    context: Context,
    digest: ConfigDigest,
    pipeline: pipeline::Pipeline,
    owner: Owner,
    send_max: usize,
    receive_max: usize,
    native_max: usize,
    witnesses: usize,
    overhead: usize,
    receive_channels: u16,
    next_channel: u16,
    limits: NativeLimits,
    pending: Option<PreparedNative>,
    statistics: Statistics,
    last: Option<Tick>,
    failure: Option<Error>,
}

impl Engine {
    /// Compose actual existing owners for explicit functional comparisons.
    ///
    /// The caller must supply shared connection pacing/duplex allowance on every
    /// poll. This constructor grants no authentication or runtime capability.
    pub fn new_functional(
        configuration: configuration::Configuration,
        context: Context,
        geometry: Geometry,
        native_limits: NativeLimits,
    ) -> Result<Self, Error> {
        configuration.validate().map_err(|_| Error::Configuration)?;
        if context.session == 0 || context.epoch == 0 || native_limits.stall_micros == 0 {
            return Err(Error::Configuration);
        }
        let descriptor = configuration.descriptor();
        for (role, overhead) in [
            (Role::Client, geometry.forward_overhead_bytes),
            (Role::Server, geometry.reverse_overhead_bytes),
        ] {
            let view = descriptor.direction(role);
            match view.common().traffic().tcp {
                TcpControl::System => {}
                TcpControl::TunnelCredits => {
                    return Err(Error::Unsupported(Capability::TunnelCredits));
                }
                TcpControl::SplitTcpProxy => return Err(Error::Unsupported(Capability::TcpProxy)),
            }
            if !matches!(
                view.common().native_window(),
                configuration::NativeWindow::Disabled
            ) {
                return Err(Error::Unsupported(Capability::NativeWindow));
            }
            let (maximum, _, charge) = dimensions(view.profile())?;
            let wire = maximum.checked_add(overhead).ok_or(Error::Arithmetic)?;
            if charge.is_some_and(|actual| actual != overhead)
                || wire > descriptor.path_mtu()
                || wire > view.common().burst_bytes()
            {
                return Err(Error::Geometry);
            }
        }
        let local = descriptor.local(context.role);
        let (send_max, witnesses, _) = dimensions(local.send().profile())?;
        let (receive_max, _, _) = dimensions(local.receive().profile())?;
        let native_max = local.receive().max_native();
        let receive_channels = local.receive().channels();
        let pipeline =
            pipeline::Pipeline::new(local.send().common().pipeline()).map_err(Error::Pipeline)?;
        let owner = Owner::new(&configuration, context)?;
        let digest = configuration.digest().map_err(|_| Error::Configuration)?;
        let overhead = match context.role {
            Role::Client => geometry.forward_overhead_bytes,
            Role::Server => geometry.reverse_overhead_bytes,
        };
        Ok(Self {
            configuration,
            context,
            digest,
            pipeline,
            owner,
            send_max,
            receive_max,
            native_max,
            witnesses,
            overhead,
            receive_channels,
            next_channel: 0,
            limits: native_limits,
            pending: None,
            statistics: Statistics::default(),
            last: None,
            failure: None,
        })
    }

    /// Admit the original allocation to the actual common classifier/queue policy.
    pub fn enqueue(
        &mut self,
        now: Tick,
        payload: Vec<u8>,
    ) -> Result<pipeline::PacketMetadata, EnqueueError> {
        if let Err(kind) = self.advance(now) {
            return Err(EnqueueError { kind, payload });
        }
        self.pipeline
            .enqueue(payload, duration(now))
            .map_err(|error| EnqueueError {
                kind: Error::Pipeline(error.kind),
                payload: error.payload,
            })
    }

    /// Offer one actual selected MUX/DRR head to the maintained record algorithm.
    pub fn admit_one(
        &mut self,
        now: Tick,
    ) -> Result<Option<pipeline::Admitted<ProfileIdentity>>, Error> {
        self.advance(now)?;
        let next = self
            .statistics
            .admitted
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let owner = &mut self.owner;
        match self
            .pipeline
            .offer_front(|metadata, bytes| owner.offer(now, metadata.binding.channel, bytes))
        {
            Ok(Some(admitted)) => {
                self.statistics.admitted = next;
                Ok(Some(admitted))
            }
            Ok(None) => Ok(None),
            Err(pipeline::DequeueError::Pipeline(error)) => self.fail(Error::Pipeline(error)),
            Err(pipeline::DequeueError::Commit(error)) => self.fail(error),
        }
    }

    /// Produce one actual record under the caller's shared full-wire allowance.
    ///
    /// Retain emitted bytes and metadata through physical WouldBlock. Never
    /// repoll/reseal an already emitted security number as a resend operation.
    pub fn poll(
        &mut self,
        now: Tick,
        security_number: u64,
        allow_data: bool,
        output: &mut [u8],
        shared_budget: &mut OutboundBudget,
        unit_witnesses: &mut [receiver::UnitWitness],
    ) -> Result<Option<Emission>, Error> {
        self.advance(now)?;
        if output.len() < self.send_max {
            return Err(Error::Output {
                required: self.send_max,
            });
        }
        if unit_witnesses.len() < self.witnesses {
            return Err(Error::Witnesses {
                required: self.witnesses,
            });
        }
        let next = self
            .statistics
            .emitted
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        match self.owner.poll(
            now,
            security_number,
            allow_data,
            output,
            shared_budget,
            unit_witnesses,
            self.overhead,
        ) {
            Ok(Some(emission)) => {
                self.statistics.emitted = next;
                Ok(Some(emission))
            }
            Ok(None) => Ok(None),
            Err(error) => self.fail(error),
        }
    }

    /// Apply caller-authenticated, replay-checked, correctly scoped plaintext.
    ///
    /// Public kind labels do not establish authentication. On retryable receiver
    /// pressure retain the exact plaintext; malformed partial inputs are terminal.
    pub fn accept_authenticated(
        &mut self,
        now: Tick,
        security_number: u64,
        kind: EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        self.advance(now)?;
        if body.is_empty() || body.len() > self.receive_max {
            return self.fail(Error::PacketSize);
        }
        match self.owner.accept(now, security_number, kind, body) {
            Ok(()) => Ok(()),
            Err(Error::Aligned(error)) if error.is_backpressure() => Err(Error::Aligned(error)),
            Err(error) => self.fail(error),
        }
    }

    /// Service injected owner deadlines, including native custody while idle.
    pub fn tick(&mut self, now: Tick) -> Result<(), Error> {
        self.advance(now)?;
        match self.owner.tick(now) {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }

    /// Earliest actual owner or retained native deadline, without reading a clock.
    pub fn deadline(&self) -> Result<Option<Tick>, Error> {
        self.healthy()?;
        Ok(self
            .owner
            .deadline()?
            .into_iter()
            .chain(self.pending.map(|p| p.deadline))
            .min())
    }

    /// True only when actual queue, profile and native custody all drain.
    pub fn drained(&self) -> Result<bool, Error> {
        self.healthy()?;
        Ok(self.pipeline.usage().packets == 0 && self.pending.is_none() && self.owner.drained()?)
    }

    /// Exact complete requested policy, without clamping rates or directions.
    pub const fn configuration(&self) -> &configuration::Configuration {
        &self.configuration
    }
    /// Actual limited qualification of this constructor.
    pub const fn qualification(&self) -> Qualification {
        Qualification::Functional
    }
    /// Local observations; identities are never converted into native counts.
    pub const fn statistics(&self) -> Statistics {
        self.statistics
    }
    /// Exact common queue accounting, useful when a codec refuses a head.
    pub fn queue_usage(&self) -> pipeline::QueueUsage {
        self.pipeline.usage()
    }
    /// Actual original fatal error, retained for cleanup and observability.
    pub const fn failure(&self) -> Option<Error> {
        self.failure
    }

    fn healthy(&self) -> Result<(), Error> {
        self.failure.map_or(Ok(()), Err)
    }
    fn advance(&mut self, now: Tick) -> Result<(), Error> {
        self.healthy()?;
        if self.last.is_some_and(|last| now < last) {
            return self.fail(Error::Time);
        }
        if self.pending.is_some_and(|pending| now >= pending.deadline) {
            return self.fail(Error::Expired);
        }
        self.last = Some(now);
        Ok(())
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.failure.get_or_insert(error);
        Err(error)
    }
}

fn duration(now: Tick) -> Duration {
    Duration::from_micros(now.0)
}

fn dimensions(
    profile: configuration::DirectionProfile<'_>,
) -> Result<(usize, usize, Option<usize>), Error> {
    Ok(match profile {
        configuration::DirectionProfile::Swift(config) => (config.codec.datagram_bytes, 0, None),
        configuration::DirectionProfile::Aligned(config) => (
            config
                .recovery
                .maximum_packet_bytes()
                .map_err(|_| Error::Configuration)?,
            1,
            Some(config.recovery.outer_overhead_bytes),
        ),
        configuration::DirectionProfile::Packed(config) => (
            config
                .base
                .recovery
                .maximum_packet_bytes()
                .map_err(|_| Error::Configuration)?,
            usize::from(config.max_units),
            Some(config.base.recovery.outer_overhead_bytes),
        ),
    })
}
