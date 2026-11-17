//! Actual shared-queue composition of the existing record algorithms.
//!
//! Authentication, replay, connection pacing and physical device completion stay
//! with the caller. Functional and actually reserved constructors remain explicit;
//! neither is a mixed-generation runtime bank. No carrier or clock is selected.

use crate::record_configuration as configuration;
use crate::rolling_records;
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
/// Complete actual reserved backing of one common record Engine.
pub mod storage;

mod affinity;
mod buffer_diagnostics;
mod connection_ingress;
/// Same-owner retirement driven by opaque authenticated selected commands.
pub mod connection_reuse;
mod connections;
pub use buffer_diagnostics::{
    AdmissionBlock, AdmissionRefusal, CodecBufferSnapshot, RecoveryBufferSnapshot,
    StagedAdmissionSnapshot,
};
pub use connection_ingress::ConnectionSnapshot;
mod ingress;
pub use ingress::{IngressAdmission, IngressSnapshot};
mod carrier;
mod fragment;
pub use fragment::{
    FragmentAdmission, FragmentDirection, FragmentEmission, FragmentGroup, FragmentIngressSnapshot,
    FragmentOutputToken, FragmentPolicy, FragmentReceipt, FragmentStatistics, FragmentStorageError,
    ReassemblyPolicies,
};
mod native;
pub use carrier::CarrierOutputToken;
mod native_counts;
mod native_encoding;
pub use native_encoding::{NativeEncodingKind, NativeEncodingObservation, ObservedProfileIdentity};
mod native_window;
pub use native_counts::NativeCounts;
pub use native_window::NativeDelivery;
mod compact_wire;
mod wire_extent;
pub use wire_extent::{CodecCoverage, OutputExtent};
mod owner;
mod proxy_records;
#[cfg(test)]
pub(crate) mod rolling_tests;
#[cfg(test)]
mod storage_tests;
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
    /// Compact rolling body identity, separate from recovery source/repair IDs.
    Rolling(receiver::RecordIdentity),
    /// Actual packed-record identity from the selected research recovery owner.
    Research(receiver::RecordIdentity),
    /// Actual independently recovered connection body, retaining owner/incarnation.
    Connection(crate::connection_records::Identity),
    /// Source-free native ACK event, outside reliable native-prefix accounting.
    UnreliableNative(crate::connection_records::UnreliableIdentity),
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
    /// Complete native ACK bypassing recovery, still authenticated and fully budgeted.
    UnreliableNative,
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
    /// Actual authenticated drained/fenced fixed-owner reuse is not installed.
    FlowReuse,
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
    /// Independent native-byte delivery owner rejected a limit, clock or receipt.
    NativeWindow(crate::flow_control::delivery_window::Error),
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
    /// Reserved construction requires borrowed admission instead of an owned output Vec.
    OwnedOutput,
    /// Original immutable native custody deadline expired.
    Expired,
    /// Local completion token is absent, stale or belongs to another handoff.
    Token,
    /// Explicit fragment API/selected policy is required; no compatibility bypass.
    FragmentPolicy,
    /// This kind already retains a completed body; caller keeps its new plaintext.
    FragmentBusy,
    /// Maintained fragment geometry, parser or original-time refusal.
    Fragment(crate::codec::FragmentError),
    /// Actual queue or composed owner invariants disagree.
    Invariant,
    /// Actual common queue failure.
    Pipeline(pipeline::PipelineError),
    /// Actual selected bounded ACK-ingress failure.
    Ingress(pipeline::ack_coalescing::Error),
    /// The selected ingress path must not be bypassed by a compatibility enqueue.
    IngressPolicy,
    /// Actual maintained Swift record failure.
    Swift(swift::records::Error),
    /// Actual Swift backing failure.
    Storage(swift::storage::Error),
    /// Actual Aligned/Packed record failure.
    Aligned(aligned::Error),
    /// Actual selected Compact Aligned/Packed construction or reservation failure.
    AlignedStorage(aligned::storage::Error),
    /// Actual compact-record/rolling composition or backing failure.
    Rolling(rolling_records::Error),
    /// Actual independent-owner collection/custody failure.
    Connections(crate::connection_records::Error),
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
    /// Complete backing of this Engine; external/runtime/mixed-generation qualification stays separate.
    Reserved,
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
/// It is meaningful only with its issuing Engine. A generation Bank additionally
/// binds its own unique instance/slot/generation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeToken {
    context: Context,
    digest: ConfigDigest,
    serial: u64,
    identity: ProfileIdentity,
    rolling: Option<rolling_records::NativeToken>,
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
    ingress: Option<pipeline::ack_coalescing::Ingress>,
    owner: Owner,
    send_max: usize,
    receive_max: usize,
    native_max: usize,
    witnesses: usize,
    overhead: usize,
    compact_feedback_overhead: Option<usize>,
    receive_channels: u16,
    next_channel: u16,
    limits: NativeLimits,
    pending: Option<PreparedNative>,
    inline_pending: Option<(Emission, carrier::InlinePrepared)>,
    fragments: Option<fragment::State>,
    statistics: Statistics,
    last: Option<Tick>,
    failure: Option<Error>,
    usage: Option<storage::Usage>,
    native_counts: native_counts::Counts,
    native_window: Option<native_window::State>,
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
        let parameters = parameters(&configuration, context, geometry, native_limits)?;
        let pipeline = pipeline::Pipeline::new(
            configuration
                .descriptor()
                .local(context.role)
                .send()
                .common()
                .pipeline(),
        )
        .map_err(Error::Pipeline)?;
        let mut owner = Owner::new(&configuration, context)?;
        owner.enable_carrier_confirmation(&configuration)?;
        let native_window =
            native_window::Plan::new(&configuration, context.role, parameters.witnesses)?
                .map(native_window::State::new)
                .transpose()?;
        let mut engine = Self::assemble(
            configuration,
            context,
            native_limits,
            parameters,
            pipeline,
            owner,
            None,
            None,
        );
        engine.native_window = native_window;
        Ok(engine)
    }

    #[allow(clippy::too_many_arguments)] // Existing actual owners plus the optional real ingress owner.
    fn assemble(
        configuration: configuration::Configuration,
        context: Context,
        limits: NativeLimits,
        parameters: Parameters,
        pipeline: pipeline::Pipeline,
        owner: Owner,
        ingress: Option<pipeline::ack_coalescing::Ingress>,
        usage: Option<storage::Usage>,
    ) -> Self {
        let Parameters {
            digest,
            send_max,
            receive_max,
            native_max,
            witnesses,
            overhead,
            receive_channels,
        } = parameters;
        Self {
            configuration,
            context,
            digest,
            pipeline,
            ingress,
            owner,
            send_max,
            receive_max,
            native_max,
            witnesses,
            overhead,
            compact_feedback_overhead: None,
            receive_channels,
            next_channel: 0,
            limits,
            pending: None,
            inline_pending: None,
            fragments: None,
            statistics: Statistics::default(),
            last: None,
            failure: None,
            usage,
            native_counts: native_counts::Counts::default(),
            native_window: None,
        }
    }

    /// Admit the original allocation to the actual common classifier/queue policy.
    pub fn enqueue(
        &mut self,
        now: Tick,
        payload: Vec<u8>,
    ) -> Result<pipeline::PacketMetadata, EnqueueError> {
        if self.proxy_records() {
            return Err(EnqueueError {
                kind: Error::Unsupported(Capability::TcpProxy),
                payload,
            });
        }
        if self.ingress.is_some() || self.requires_original_ingress_cap() {
            return Err(EnqueueError {
                kind: Error::IngressPolicy,
                payload,
            });
        }
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
    /// Reserved construction requires `admit_borrowed`, without an output Vec.
    pub fn admit_one(
        &mut self,
        now: Tick,
    ) -> Result<Option<pipeline::Admitted<ProfileIdentity>>, Error> {
        self.advance(now)?;
        if self.usage.is_some() {
            return Err(Error::OwnedOutput);
        }
        let next = self
            .statistics
            .admitted
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let owner = &mut self.owner;
        let counts = &mut self.native_counts;
        let window = &mut self.native_window;
        let width = self
            .configuration
            .descriptor()
            .local(self.context.role)
            .send()
            .channels();
        match self.pipeline.offer_front(|metadata, bytes| {
            native_counts::offer(owner, counts, window.as_mut(), now, metadata, width, bytes)
        }) {
            Ok(Some(admitted)) => {
                self.statistics.admitted = next;
                Ok(Some(pipeline::Admitted {
                    packet: admitted.packet,
                    permit: admitted.permit.identity,
                }))
            }
            Ok(None) => Ok(None),
            Err(pipeline::DequeueError::Pipeline(error)) => self.fail(Error::Pipeline(error)),
            Err(pipeline::DequeueError::Commit(error)) => self.fail(error),
        }
    }

    /// Admit original borrowed bytes through the actual selected common queue.
    ///
    /// Reserved construction copies into its preallocated packet slab; legacy
    /// functional backing may allocate. Caller input storage stays external.
    pub fn enqueue_borrowed(
        &mut self,
        now: Tick,
        bytes: &[u8],
    ) -> Result<pipeline::PacketMetadata, Error> {
        if self.proxy_records() {
            return Err(Error::Unsupported(Capability::TcpProxy));
        }
        if self.ingress.is_some() || self.requires_original_ingress_cap() {
            return Err(Error::IngressPolicy);
        }
        self.advance(now)?;
        self.pipeline
            .enqueue_borrowed(bytes, duration(now))
            .map_err(Error::Pipeline)
    }

    /// Commit one actual selected head without allocating an owned payload result.
    pub fn admit_borrowed(
        &mut self,
        now: Tick,
    ) -> Result<Option<pipeline::Admission<ProfileIdentity>>, Error> {
        self.admit_borrowed_observed(now).map(|value| {
            value.map(|admitted| pipeline::Admission {
                metadata: admitted.metadata,
                permit: admitted.permit.identity,
            })
        })
    }

    /// Return exact encoding facts once with the actual committed Pipeline head.
    /// Refusal returns no observation. Packing, retry and output polling cannot
    /// create another admission sample; no state or allocation retains samples.
    pub fn admit_borrowed_observed(
        &mut self,
        now: Tick,
    ) -> Result<Option<pipeline::Admission<ObservedProfileIdentity>>, Error> {
        self.admit_borrowed_diagnosed(now, |_| {})
    }

    /// Preserve the same real admission and report only actual downstream refusals.
    /// An empty Pipeline emits no callback; the caller supplies observation time.
    pub fn admit_borrowed_diagnosed(
        &mut self,
        now: Tick,
        mut on_block: impl FnMut(AdmissionRefusal),
    ) -> Result<Option<pipeline::Admission<ObservedProfileIdentity>>, Error> {
        self.advance(now)?;
        let next = self
            .statistics
            .admitted
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let owner = &mut self.owner;
        let counts = &mut self.native_counts;
        let window = &mut self.native_window;
        let width = self
            .configuration
            .descriptor()
            .local(self.context.role)
            .send()
            .channels();
        match self.pipeline.offer_front_borrowed(|metadata, bytes| {
            native_counts::offer_diagnosed(
                owner,
                counts,
                window.as_mut(),
                now,
                metadata,
                width,
                bytes,
                &mut on_block,
            )
        }) {
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
        self.poll_with_feedback_overhead(
            now,
            security_number,
            allow_data,
            output,
            shared_budget,
            unit_witnesses,
            self.compact_feedback_overhead.unwrap_or(self.overhead),
        )
    }

    /// Poll with an exact stronger feedback overhead on an explicitly selected
    /// outer format. Existing callers retain their uniform wire charge.
    #[allow(clippy::too_many_arguments)]
    pub fn poll_with_feedback_overhead(
        &mut self,
        now: Tick,
        security_number: u64,
        allow_data: bool,
        output: &mut [u8],
        shared_budget: &mut OutboundBudget,
        unit_witnesses: &mut [receiver::UnitWitness],
        feedback_overhead: usize,
    ) -> Result<Option<Emission>, Error> {
        if feedback_overhead != self.overhead
            && !matches!(&self.owner, Owner::Swift(_))
            && self.compact_feedback_overhead != Some(feedback_overhead)
        {
            return Err(Error::Geometry);
        }
        if self.fragments.is_some() {
            return Err(Error::FragmentPolicy);
        }
        self.advance(now)?;
        if matches!(&self.owner, Owner::Connections(owner) if owner.has_output())
            && self.pending_carrier_output().is_none()
        {
            return self.fail(Error::Invariant);
        }
        if let Some(pending) = self.pending_carrier_output() {
            if let Err(error) = self.owner.tick(now) {
                return self.fail(error);
            }
            return Ok(Some(pending.emission()));
        }
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
            feedback_overhead,
        ) {
            Ok(Some(emission)) => {
                let pending = match &self.owner {
                    Owner::Swift(owner) => Some(
                        owner
                            .engine()
                            .pending_output()
                            .map(carrier::InlinePrepared::Swift),
                    ),
                    Owner::Aligned(endpoint) => Some(
                        endpoint
                            .pending_output()
                            .map(carrier::InlinePrepared::Reliable),
                    ),
                    Owner::Packed(endpoint) => Some(
                        endpoint
                            .pending_output()
                            .map(carrier::InlinePrepared::Reliable),
                    ),
                    _ => None,
                };
                if let Some(pending) = pending {
                    let Some(prepared) = pending else {
                        return self.fail(Error::Invariant);
                    };
                    let matches = match prepared {
                        carrier::InlinePrepared::Swift(p) => {
                            p.bytes() == emission.bytes
                                && p.number().0 == emission.security_number
                                && match p.kind() {
                                    swift::records::EmissionKind::Source => {
                                        emission.kind == EmissionKind::Source(SourceForm::Swift)
                                    }
                                    swift::records::EmissionKind::Repair => {
                                        emission.kind == EmissionKind::Repair
                                    }
                                    swift::records::EmissionKind::Feedback => {
                                        emission.kind == EmissionKind::Feedback
                                    }
                                }
                        }
                        carrier::InlinePrepared::Reliable(p) => {
                            p.bytes == emission.bytes && p.wire_bytes == emission.wire_bytes
                        }
                    };
                    if !matches {
                        return self.fail(Error::Invariant);
                    }
                    self.inline_pending = Some((emission, prepared));
                }
                if let Some(window) = &mut self.native_window {
                    window.capture(
                        unit_witnesses
                            .get(..emission.witnesses)
                            .ok_or(Error::Invariant)?,
                    )?;
                }
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
        self.accept_authenticated_at(now, now, security_number, kind, body)
    }

    /// Apply already authenticated plaintext with its original arrival time.
    /// Retrying physical-feedback pressure never reopens Records or renews time.
    /// Legacy families retain observation-time behavior; Compact samples arrival.
    pub fn accept_authenticated_at(
        &mut self,
        received: Tick,
        now: Tick,
        security_number: u64,
        kind: EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        self.accept_input(received, now, None, security_number, kind, body)
    }
    /// Retain the original caller operation/session cap for delayed authenticated input.
    pub fn accept_authenticated_until(
        &mut self,
        received: Tick,
        now: Tick,
        original_deadline: Tick,
        security_number: u64,
        kind: EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        self.accept_input(
            received,
            now,
            Some(original_deadline),
            security_number,
            kind,
            body,
        )
    }
    #[allow(clippy::too_many_arguments)] // Existing exact input plus optional retained caller cap.
    fn accept_input(
        &mut self,
        received: Tick,
        now: Tick,
        original_deadline: Option<Tick>,
        security_number: u64,
        kind: EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        if self.fragments.is_some() {
            return Err(Error::FragmentPolicy);
        }
        if received > now {
            return Err(Error::Time);
        }
        self.advance(now)?;
        if original_deadline.is_some_and(|deadline| now >= deadline) {
            return self.fail(Error::Expired);
        }
        if body.is_empty() || body.len() > self.receive_max {
            return self.fail(Error::PacketSize);
        }
        let result = if matches!(&self.owner, Owner::Connections(_))
            && kind == EmissionKind::UnreliableNative
        {
            match original_deadline {
                Some(cap) => self.accept_connection_raw(received, now, cap, body),
                None => Err(Error::IngressPolicy),
            }
        } else {
            match original_deadline {
                Some(cap) => {
                    self.owner
                        .accept_until(received, now, cap, security_number, kind, body)
                }
                None => self
                    .owner
                    .accept_at(received, now, security_number, kind, body),
            }
        };
        match result {
            Ok(()) => Ok(()),
            Err(Error::Aligned(error)) if error.is_backpressure() => Err(Error::Aligned(error)),
            Err(Error::Rolling(error)) if error.is_backpressure() => Err(Error::Rolling(error)),
            Err(Error::Connections(error)) if error.is_backpressure() => {
                Err(Error::Connections(error))
            }
            // A delayed authenticated route from an old incarnation is rejected
            // before nested mutation; it cannot poison the current flow owner.
            Err(Error::Connections(crate::connection_records::Error::Incarnation)) => Err(
                Error::Connections(crate::connection_records::Error::Incarnation),
            ),
            Err(error) => self.fail(error),
        }
    }

    /// Actual selected research owner status; absent for every other family.
    /// These committed local observations grant no peer authentication or drain authority.
    pub fn research_status(
        &self,
    ) -> Option<(
        crate::fec::research::SenderStatus,
        crate::fec::research::ReceiverStatus,
    )> {
        match &self.owner {
            Owner::Research(endpoint) => {
                Some((endpoint.sender_status(), endpoint.receiver_status()))
            }
            _ => None,
        }
    }

    /// Actual generation-owned Rolling input custody, absent for other families.
    pub fn rolling_ingress_status(&self) -> Option<rolling_records::IngressStatus> {
        match &self.owner {
            Owner::Rolling(endpoint) => endpoint.ingress_status(),
            Owner::Research(endpoint) => endpoint.ingress_status(),
            _ => None,
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

    /// Service actual rolling GF/copy/metadata work under explicit component caps.
    /// Other actual families retain their existing tick behavior and return None.
    pub fn step(
        &mut self,
        now: Tick,
        work: crate::fec::rolling::WorkBudget,
    ) -> Result<Option<rolling_records::Step>, Error> {
        self.advance(now)?;
        let result = match &mut self.owner {
            Owner::Rolling(endpoint) => endpoint.step(now, work).map(Some).map_err(Error::Rolling),
            Owner::Research(endpoint) => endpoint.step(now, work).map(Some).map_err(Error::Rolling),
            owner => owner.tick(now).map(|()| None),
        };
        match result {
            Ok(step) => Ok(step),
            Err(error) => self.fail(error),
        }
    }

    /// Earliest original expiry or actual rolling packing/tail/feedback trigger.
    pub fn wake_at(&self) -> Result<Option<Tick>, Error> {
        let deadline = self.deadline()?;
        Ok(match &self.owner {
            Owner::Rolling(endpoint) => deadline.into_iter().chain(endpoint.wake_at()).min(),
            Owner::Research(endpoint) => deadline.into_iter().chain(endpoint.wake_at()).min(),
            _ => deadline,
        })
    }

    /// Actual resumable rolling computation, separate from immutable I/O output.
    pub fn work_pending(&self) -> Result<bool, Error> {
        self.healthy()?;
        Ok(match &self.owner {
            Owner::Rolling(endpoint) => endpoint.work_pending(),
            Owner::Research(endpoint) => endpoint.work_pending(),
            _ => false,
        })
    }

    /// Earliest actual owner or retained native deadline, without reading a clock.
    pub fn deadline(&self) -> Result<Option<Tick>, Error> {
        self.healthy()?;
        Ok(self
            .owner
            .deadline()?
            .into_iter()
            .chain(self.pending.map(|p| p.deadline))
            .chain(self.ingress_expiry())
            .chain(self.fragments.as_ref().and_then(fragment::State::deadline))
            .chain(
                self.native_window
                    .as_ref()
                    .map(|w| w.deadline(self.last.unwrap_or(Tick(0))))
                    .transpose()?
                    .flatten(),
            )
            .min())
    }

    /// Earliest terminal custody cap, excluding recoverable receive-cache eviction
    /// and output service wakes. A retained outgoing packet may inherit this cap;
    /// once selected, its original cap must never be renewed by later observations.
    pub fn custody_deadline(&self) -> Result<Option<Tick>, Error> {
        self.healthy()?;
        Ok(self
            .owner
            .custody_deadline()?
            .into_iter()
            .chain(self.pending.map(|p| p.deadline))
            .chain(self.ingress_expiry())
            .chain(
                self.fragments
                    .as_ref()
                    .and_then(fragment::State::custody_deadline),
            )
            .chain(
                self.native_window
                    .as_ref()
                    .map(|w| w.deadline(self.last.unwrap_or(Tick(0))))
                    .transpose()?
                    .flatten(),
            )
            .min())
    }

    /// Receive-maintenance expiry and terminal custody caps, excluding output
    /// service opportunities. Retained output still permits these maintenance wakes.
    /// Use `custody_deadline` when assigning an outgoing packet's immutable cap.
    pub fn expiry_deadline(&self) -> Result<Option<Tick>, Error> {
        self.healthy()?;
        Ok(self
            .owner
            .expiry_deadline()?
            .into_iter()
            .chain(self.pending.map(|p| p.deadline))
            .chain(self.ingress_expiry())
            .chain(self.fragments.as_ref().and_then(fragment::State::deadline))
            .chain(
                self.native_window
                    .as_ref()
                    .map(|w| w.deadline(self.last.unwrap_or(Tick(0))))
                    .transpose()?
                    .flatten(),
            )
            .min())
    }

    /// Earliest genuine feedback deadline and complete inner body requirement.
    /// The caller adds its configured full-wire overhead and shares its existing
    /// allowance; this view grants no packet number or authentication authority.
    pub fn feedback_opportunity(&self) -> Result<Option<(Tick, usize)>, Error> {
        self.healthy()?;
        self.owner.feedback_opportunity()
    }

    /// True only when actual queue, profile and native custody all drain.
    pub fn drained(&self) -> Result<bool, Error> {
        self.healthy()?;
        Ok(self.pipeline.usage().packets == 0
            && self.ingress_empty()
            && self.pending.is_none()
            && self.owner.drained()?
            && self
                .native_window
                .as_ref()
                .map(|w| w.drained(self.last.unwrap_or(Tick(0))))
                .transpose()?
                .unwrap_or(true)
            && self.fragments.as_ref().is_none_or(fragment::State::drained))
    }

    /// Exact complete requested policy, without clamping rates or directions.
    pub const fn configuration(&self) -> &configuration::Configuration {
        &self.configuration
    }
    /// Actual limited qualification of this constructor.
    pub const fn qualification(&self) -> Qualification {
        if self.usage.is_some() {
            Qualification::Reserved
        } else {
            Qualification::Functional
        }
    }
    /// Local observations; identities are never converted into native counts.
    pub const fn statistics(&self) -> Statistics {
        self.statistics
    }
    /// Exact common queue accounting, useful when a codec refuses a head.
    pub fn queue_usage(&self) -> pipeline::QueueUsage {
        self.pipeline.usage()
    }
    /// Exact shared Aligned/Packed CompactARQ terminal evidence. Other families,
    /// including independent connection collections, are outside this snapshot.
    pub fn compact_retry_failure_snapshot(
        &self,
    ) -> Option<l2tunnel_recovery::CompactRetryFailureSnapshot> {
        match &self.owner {
            Owner::Aligned(owner) => owner.compact_retry_failure_snapshot(),
            Owner::Packed(owner) => owner.compact_retry_failure_snapshot(),
            _ => None,
        }
    }
    /// Actual selected Rolling/Research original lifetimes, without advancing owners.
    pub fn rolling_expiry_snapshot(&self) -> Option<rolling_records::expiry::Snapshot> {
        match &self.owner {
            Owner::Rolling(owner) => Some(owner.expiry_snapshot()),
            Owner::Research(owner) => Some(owner.expiry_snapshot()),
            _ => None,
        }
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
        if self
            .ingress_expiry()
            .is_some_and(|deadline| now >= deadline)
        {
            return self.fail(Error::Ingress(pipeline::ack_coalescing::Error::Expired));
        }
        if let Some(state) = &mut self.fragments
            && let Err(error) = state.tick(now)
        {
            return self.fail(error);
        }
        if let Some(window) = &mut self.native_window
            && let Err(error) = window.tick(now)
        {
            return self.fail(error);
        }
        self.last = Some(now);
        Ok(())
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.failure.get_or_insert(error);
        Err(error)
    }
}

#[derive(Clone, Copy)]
struct Parameters {
    digest: ConfigDigest,
    send_max: usize,
    receive_max: usize,
    native_max: usize,
    witnesses: usize,
    overhead: usize,
    receive_channels: u16,
}

fn parameters(
    configuration: &configuration::Configuration,
    context: Context,
    geometry: Geometry,
    native_limits: NativeLimits,
) -> Result<Parameters, Error> {
    parameters_with_fragmentation(configuration, context, geometry, native_limits, None)
}
fn parameters_with_fragmentation(
    configuration: &configuration::Configuration,
    context: Context,
    geometry: Geometry,
    native_limits: NativeLimits,
    fragments: Option<FragmentPolicy>,
) -> Result<Parameters, Error> {
    parameters_selected(
        configuration,
        context,
        geometry,
        native_limits,
        fragments,
        None,
    )
}
fn parameters_selected(
    configuration: &configuration::Configuration,
    context: Context,
    geometry: Geometry,
    native_limits: NativeLimits,
    fragments: Option<FragmentPolicy>,
    compact_feedback: Option<usize>,
) -> Result<Parameters, Error> {
    let local_overhead = match context.role {
        Role::Client => geometry.forward_overhead_bytes,
        Role::Server => geometry.reverse_overhead_bytes,
    };
    let feedback_delta = compact_feedback.map(|feedback| {
        (
            feedback >= local_overhead,
            feedback.abs_diff(local_overhead),
        )
    });
    if let Some(policy) = fragments {
        policy.validate(configuration, geometry)?;
    }
    configuration.validate().map_err(|_| Error::Configuration)?;
    if context.session == 0 || context.epoch == 0 || native_limits.stall_micros == 0 {
        return Err(Error::Configuration);
    }
    let descriptor = configuration.descriptor();
    if let configuration::Profile::Rolling { config, .. }
    | configuration::Profile::RollingCopies { config, .. } = descriptor.profile()
        && (config.geometry != geometry || config.native_stall_micros != native_limits.stall_micros)
    {
        return Err(Error::Geometry);
    }
    if let configuration::Profile::Research { config, .. } = descriptor.profile()
        && (config.geometry != geometry || config.native_stall_micros != native_limits.stall_micros)
    {
        return Err(Error::Geometry);
    }
    for (role, overhead) in [
        (Role::Client, geometry.forward_overhead_bytes),
        (Role::Server, geometry.reverse_overhead_bytes),
    ] {
        let compact_feedback = feedback_delta
            .map(|(add, delta)| {
                if add {
                    overhead.checked_add(delta)
                } else {
                    overhead.checked_sub(delta)
                }
                .ok_or(Error::Geometry)
            })
            .transpose()?;
        let view = descriptor.direction(role);
        match view.common().traffic().tcp {
            TcpControl::System => {}
            TcpControl::TunnelCredits => {
                return Err(Error::Unsupported(Capability::TunnelCredits));
            }
            TcpControl::SplitTcpProxy => {
                if fragments.is_some() || !proxy_records::supported(configuration) {
                    return Err(Error::Unsupported(Capability::TcpProxy));
                }
            }
        }
        native_window::validate(view)?;
        let opposite = descriptor.local(role).receive();
        let (maximum, _, charge) = dimensions(view.profile(), opposite.profile())?;
        let wire = if let Some(feedback) = compact_feedback {
            let (data, ack) = compact_wire::maximums(view.profile(), opposite.profile())?;
            data.checked_add(overhead)
                .ok_or(Error::Arithmetic)?
                .max(ack.checked_add(feedback).ok_or(Error::Arithmetic)?)
        } else {
            maximum.checked_add(overhead).ok_or(Error::Arithmetic)?
        };
        if charge.is_some_and(|actual| actual != overhead) {
            return Err(Error::Geometry);
        }
        if let Some(policy) = fragments {
            let selected = match role {
                Role::Client => policy.forward,
                Role::Server => policy.reverse,
            };
            let group = selected
                .framing
                .geometry(maximum)
                .map_err(Error::Fragment)?;
            if group.wire_bytes() > view.common().burst_bytes() {
                return Err(Error::Geometry);
            }
            if let Some(overhead) = compact_feedback {
                let (_, feedback) = compact_wire::maximums(view.profile(), opposite.profile())?;
                let mut framing = selected.framing;
                framing.outer_overhead_bytes = overhead;
                let group = framing.geometry(feedback).map_err(Error::Fragment)?;
                if group.wire_bytes() > view.common().burst_bytes()
                    || usize::from(selected.reassembly.feedback.max_fragments_per_message)
                        < group.fragments()
                    || selected.reassembly.feedback.max_message_bytes < feedback
                {
                    return Err(Error::Geometry);
                }
            }
        } else if wire > descriptor.path_mtu() || wire > view.common().burst_bytes() {
            return Err(Error::Geometry);
        }
    }
    let local = descriptor.local(context.role);
    let (mut send_max, witnesses, _) =
        dimensions(local.send().profile(), local.receive().profile())?;
    let (mut receive_max, _, _) = dimensions(local.receive().profile(), local.send().profile())?;
    if compact_feedback.is_some() {
        let (data, feedback) =
            compact_wire::maximums(local.send().profile(), local.receive().profile())?;
        send_max = data.max(feedback);
        let (data, feedback) =
            compact_wire::maximums(local.receive().profile(), local.send().profile())?;
        receive_max = data.max(feedback);
    }
    let native_max = local.receive().max_native();
    let receive_channels = local.receive().channels();
    let digest = configuration.digest().map_err(|_| Error::Configuration)?;
    let overhead = match context.role {
        Role::Client => geometry.forward_overhead_bytes,
        Role::Server => geometry.reverse_overhead_bytes,
    };
    Ok(Parameters {
        digest,
        send_max,
        receive_max,
        native_max,
        witnesses,
        overhead,
        receive_channels,
    })
}

fn duration(now: Tick) -> Duration {
    Duration::from_micros(now.0)
}

fn dimensions(
    profile: configuration::DirectionProfile<'_>,
    opposite: configuration::DirectionProfile<'_>,
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
        configuration::DirectionProfile::AlignedCompact(config) => {
            let configuration::DirectionProfile::AlignedCompact(peer) = opposite else {
                return Err(Error::Configuration);
            };
            let plan = aligned::compact_storage::Plan::for_duplex(*config, *peer)
                .map_err(Error::AlignedStorage)?;
            (
                plan.reliable_plan().send_max_packet_bytes(),
                1,
                Some(config.recovery.outer_overhead_bytes()),
            )
        }
        configuration::DirectionProfile::PackedCompact(config) => {
            let configuration::DirectionProfile::PackedCompact(peer) = opposite else {
                return Err(Error::Configuration);
            };
            let plan = aligned::compact_storage::Plan::for_packed_duplex(*config, *peer)
                .map_err(Error::AlignedStorage)?;
            (
                plan.reliable_plan().send_max_packet_bytes(),
                usize::from(config.max_units),
                Some(config.base.recovery.outer_overhead_bytes()),
            )
        }
        configuration::DirectionProfile::PerConnectionCompact(config) => {
            let configuration::DirectionProfile::PerConnectionCompact(peer) = opposite else {
                return Err(Error::Configuration);
            };
            let plan = connections::Connections::plan(*config, *peer)?;
            (
                plan.send_max_packet_bytes(),
                1,
                Some(plan.config().send_carrier_overhead_bytes),
            )
        }
        configuration::DirectionProfile::Rolling {
            config,
            overhead_bytes,
            ..
        } => (
            config
                .maximum_packet_bytes()
                .map_err(Error::Rolling)?
                .max(crate::fec::rolling::scheduler::FEEDBACK_BYTES),
            usize::from(config.packing.max_units),
            Some(overhead_bytes),
        ),
        configuration::DirectionProfile::Research {
            config,
            overhead_bytes,
            ..
        } => (
            config
                .maximum_packet_bytes()
                .map_err(Error::Rolling)?
                .max(crate::fec::research::wire::HEADER_BYTES),
            usize::from(config.packing.max_units),
            Some(overhead_bytes),
        ),
    })
}

#[cfg(test)]
mod bounded_feedback_tests;

#[cfg(test)]
mod fragment_tests;

#[cfg(test)]
mod research_tests;
