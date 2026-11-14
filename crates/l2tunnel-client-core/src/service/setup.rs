//! Operation-bound, fixed-size setup evidence; never authority for peer progress.
use super::*;
use l2tunnel_runtime::secure_udp::diagnostics;
use std::time::Duration;

/// Actual local setup stage, independent of authentication or readiness claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupStage {
    /// Accepted but no setup work has been polled.
    Accepted,
    /// Binding the original UDP socket.
    SocketBind,
    /// Connecting that same socket to the configured peer.
    SocketConnect,
    /// Acquiring or constructing the retained admission owner.
    AdmissionOwner,
    /// Validating the selected fixed public contract.
    Configuration,
    /// Driving return-path admission.
    Admission,
    /// Driving maintained Noise and bootstrap recovery.
    Noise,
    /// Driving the existing member proof/acceptance.
    Membership,
    /// Opening the deferred native attachment after authentication.
    Attachment,
    /// Driving the actual data/control runtime to its first running snapshot.
    DriverReadiness,
    /// Actual readiness publication after cancellation/deadline checks.
    ReadyPublication,
}
/// Local operation outcome; no peer-confirmed close is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupOutcome {
    /// The accepted operation has not completed.
    Pending,
    /// Actual runtime readiness was published.
    Ready,
    /// An actual setup operation failed.
    Failed,
    /// Explicit local cancellation won before readiness.
    Cancelled,
    /// The retained service owner was dropped during setup.
    OwnerClosed,
}
/// Static failure provenance, without provider strings or peer material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupFailureReason {
    /// Exact typed runtime classification observed before I/O conversion.
    Runtime(diagnostics::Reason),
    /// The original accepted operation deadline expired.
    OriginalDeadline,
    /// An actual local socket/provider operation failed.
    LocalIo,
    /// The runtime returned before its first running snapshot.
    ReadinessEnded,
    /// No more precise typed reason was observed; never infer authentication.
    Unknown,
}
/// Actual local error category and separately classified provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupFailure {
    /// Existing completion's actual category, without reinterpretation.
    pub kind: io::ErrorKind,
    /// Observed stage-specific provenance, not a peer rejection inference.
    pub reason: SetupFailureReason,
}
/// Fixed-size latest evidence retained with exactly one accepted operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupObservation {
    /// Exact retained operation; never a peer session identifier.
    pub operation: OperationId,
    /// Last actual stage reached by this operation.
    pub stage: SetupStage,
    /// Its actual local completion state.
    pub outcome: SetupOutcome,
    /// Present only for an actual failed completion.
    pub failure: Option<SetupFailure>,
    /// Sampled monotonic elapsed time; getters do not refresh it.
    pub elapsed_micros: u64,
    /// Original configured bound, unchanged by observation or retry.
    pub original_timeout_micros: u64,
    /// Actual optional runtime counters; absence is not an observed zero.
    pub runtime: Option<diagnostics::Observation>,
}
pub(super) struct Record {
    pub(super) observation: SetupObservation,
    origin: Instant,
    reason: Option<SetupFailureReason>,
}
fn micros(value: Duration) -> u64 {
    u64::try_from(value.as_micros()).unwrap_or(u64::MAX)
}
impl Record {
    pub(super) fn new(operation: OperationId, origin: Instant, timeout: Duration) -> Self {
        Self {
            observation: SetupObservation {
                operation,
                stage: SetupStage::Accepted,
                outcome: SetupOutcome::Pending,
                failure: None,
                elapsed_micros: 0,
                original_timeout_micros: micros(timeout),
                runtime: None,
            },
            origin,
            reason: None,
        }
    }
    fn sample(&mut self, now: Instant) {
        self.observation.elapsed_micros = micros(now.saturating_duration_since(self.origin));
    }
    pub(super) fn complete(&mut self, result: &Completed, accepted: Accepted, now: Instant) {
        if self.observation.outcome != SetupOutcome::Pending {
            return;
        }
        self.sample(now);
        match result {
            Completed::Connected { .. } => {
                self.observation.stage = SetupStage::ReadyPublication;
                self.observation.outcome = SetupOutcome::Ready;
            }
            Completed::Failed(failure) => {
                self.observation.outcome = SetupOutcome::Failed;
                let reason = self.reason.unwrap_or_else(|| {
                    if accepted.deadline.is_some_and(|deadline| now >= deadline) {
                        SetupFailureReason::OriginalDeadline
                    } else {
                        SetupFailureReason::Unknown
                    }
                });
                self.observation.failure = Some(SetupFailure {
                    kind: failure.kind,
                    reason,
                });
            }
            Completed::Cancelled => self.observation.outcome = SetupOutcome::Cancelled,
            _ => self.observation.outcome = SetupOutcome::OwnerClosed,
        }
    }
    pub(super) fn owner_closed(&mut self, now: Instant) {
        if self.observation.outcome == SetupOutcome::Pending {
            self.sample(now);
            self.observation.outcome = SetupOutcome::OwnerClosed;
        }
    }
}
fn update(shared: &Shared, id: OperationId, action: impl FnOnce(&mut Record)) {
    let mut state = shared.lock();
    let Some(entry) = state
        .entries
        .iter_mut()
        .find(|entry| entry.accepted.operation == id)
    else {
        return;
    };
    if entry.result.is_some() {
        return;
    }
    let Some(record) = &mut entry.setup else {
        return;
    };
    if record.observation.outcome != SetupOutcome::Pending {
        return;
    }
    action(record);
    record.sample(Instant::now());
    drop(state);
    shared.changed();
}
pub(super) fn stage(shared: &Shared, id: OperationId, stage: SetupStage) {
    update(shared, id, |record| {
        record.observation.stage = stage;
        record.reason = None;
    });
}
pub(super) fn reason(shared: &Shared, id: OperationId, reason: SetupFailureReason) {
    update(shared, id, |record| record.reason = Some(reason));
}
pub(super) fn runtime(shared: &Shared, id: OperationId, value: diagnostics::Observation) {
    update(shared, id, |record| {
        record.observation.stage = match value.stage {
            diagnostics::Stage::Configuration => SetupStage::Configuration,
            diagnostics::Stage::Admission => SetupStage::Admission,
            diagnostics::Stage::Noise => SetupStage::Noise,
            diagnostics::Stage::Membership => SetupStage::Membership,
        };
        if let Some(reason) = value.reason {
            record.reason = Some(SetupFailureReason::Runtime(reason));
        }
        record.observation.runtime = Some(value);
    });
}
